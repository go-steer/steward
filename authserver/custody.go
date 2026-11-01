// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VaultEndpoint is the Agent Identity credential vault's REST endpoint.
const VaultEndpoint = "https://agentidentitycredentials.googleapis.com/v1/"

// The vault renews a Google token only once it has expired or Google
// refuses it: its API reference says to set forceRefreshToken "only if
// the previous token was expired or invalid", and asked to force one that
// was still valid it asked for consent instead (kode-gopher's vault
// spike). So a token Google still accepts is used for as long as it lasts,
// and one too close to expiry to use is waited out, then retrieved again.

// accessMargin is sealAccess's: an access token stops a minute before the
// Google token inside it expires.
const accessMargin = time.Minute

// minAccessLife is the shortest access token worth issuing.
const minAccessLife = 15 * time.Second

// minRefreshTokenLife is the least life a vault token needs at refresh: an
// access token of at least minAccessLife, a minute before it expires.
const minRefreshTokenLife = accessMargin + minAccessLife

// exchangeAllowance is how long after sign-in an authorization code
// carrying a vault token can be exchanged for an access token of at least
// minAccessLife. Clients exchange within a second or two; one that waits
// longer (CodeTTL allows a minute) may get server_error at the exchange
// and start again, as it would at the redirect for a token held back.
const exchangeAllowance = 15 * time.Second

// minSignInTokenLife is the least life a vault token needs at sign-in.
const minSignInTokenLife = minRefreshTokenLife + exchangeAllowance

// maxExpiryWait is the longest a token too close to expiry to use is
// waited out. It covers minRefreshTokenLife, so a refresh does not fail
// just because the token is nearly spent: an active client's refresh lands
// when the Google token has a minute left (its access token stopped
// then), and waiting that minute is the only way to a fresh token that
// does not need the person. (It still fails if the vault's next token is
// short too.)
const maxExpiryWait = minRefreshTokenLife

// expirySkew is how long past tokeninfo's expiry a waited-out token is
// retrieved again: tokeninfo rounds expires_in down to the second.
const expirySkew = 3 * time.Second

// grant is a Google access token for a user, plus what the custody
// backend needs to mint the next one: the Google refresh token for sealed
// custody, nothing for the vault (Google holds the grant).
type grant struct {
	AccessToken string
	Expiry      time.Time
	Scopes      []string
	Secret      string
}

// consent is a detour the browser takes between sign-in and the end of
// the authorization request: the vault's own Google consent leg.
type consent struct {
	URL   string `json:"-"`
	Nonce string `json:"n"`
	UID   string `json:"u,omitempty"`
}

// Custody holds users' Google grants and mints Google access tokens from
// them. The implementations are *VaultCustody (the Agent Identity
// credential vault, the default in kode-gopher) and SealedCustody (the
// Google refresh token travels inside steward's own sealed refresh token).
// The interface is sealed: its methods beyond Name are unexported, so only
// this package implements it.
type Custody interface {
	// Name is "vault" or "sealed", for logs.
	Name() string

	// signInScopes and signInOffline shape the Google sign-in request.
	signInScopes(g *upstream) []string
	signInOffline() bool
	// begin runs at the callback once the user has signed in. It returns
	// either a grant, or a consent detour that comes back to continueURI
	// and then finish.
	begin(ctx context.Context, g *upstream, u User, signIn *googleTokens, continueURI string) (*grant, *consent, error)
	finish(ctx context.Context, g *upstream, u User, c consent, q url.Values, continueURI string) (*grant, error)
	// prepare runs at the token endpoint before the refresh token's
	// family is rotated, so custody work that can block for long (the
	// vault waiting out a nearly spent token) never holds the family
	// rotated. It returns the grant to issue, or nil for refresh to mint
	// one once the family is rotated. errReauth means the user must sign
	// in again (the family is still rotated first, and stays so); any
	// other error is a failure, answered before anything is rotated.
	prepare(ctx context.Context, g *upstream, u User, secret, continueURI string) (*grant, error)
	// refresh mints a fresh grant at the token endpoint, after the
	// rotation, when prepare returned none. errReauth means the user must
	// sign in again.
	refresh(ctx context.Context, g *upstream, u User, secret, continueURI string) (*grant, error)
}

// errWaitedConsent is the vault asking for consent to renew a token that
// expired while steward waited it out: not yet the grant gone (see grant).
var errWaitedConsent = errors.New("vault: asked for consent to renew a token that expired while it was waited out; try again")

// errReauth is a grant that cannot be renewed without the user.
var errReauth = errors.New("the Google grant is gone; sign in again")

// reauthError is a specific reason the user must sign in again; it
// matches errReauth, so a refresh answers invalid_grant (sign in) rather
// than server_error (retry).
type reauthError string

func (e reauthError) Error() string        { return string(e) }
func (e reauthError) Is(target error) bool { return target == errReauth }

// SealedCustody is the fallback: the Google refresh token travels inside
// steward's own sealed refresh token, held by the client. Sign-in asks
// Google for offline access and every configured Google scope.
type SealedCustody struct{}

var _ Custody = SealedCustody{}

// Name implements Custody.
func (SealedCustody) Name() string { return "sealed" }

func (SealedCustody) signInScopes(g *upstream) []string { return g.grantScopes() }

func (SealedCustody) signInOffline() bool { return true }

func (SealedCustody) begin(_ context.Context, g *upstream, _ User, t *googleTokens, _ string) (*grant, *consent, error) {
	granted := strings.Fields(t.Scope)
	if !g.hasScopes(granted) {
		return nil, nil, reauthError("not every Google scope was granted at consent")
	}
	if t.RefreshToken == "" {
		return nil, nil, reauthError("google returned no refresh token")
	}
	return &grant{AccessToken: t.AccessToken, Expiry: t.expiry, Scopes: granted, Secret: t.RefreshToken}, nil, nil
}

func (SealedCustody) finish(context.Context, *upstream, User, consent, url.Values, string) (*grant, error) {
	return nil, errors.New("sealed custody has no consent detour")
}

// prepare returns no grant: the Google refresh is quick, and runs after
// the rotation, so a replayed refresh token is refused before Google is
// asked (and a refresh token Google rotates is never lost to a refresh
// that is then refused).
func (SealedCustody) prepare(context.Context, *upstream, User, string, string) (*grant, error) {
	return nil, nil
}

func (SealedCustody) refresh(ctx context.Context, g *upstream, u User, secret, _ string) (*grant, error) {
	if secret == "" {
		return nil, errReauth
	}
	t, err := g.client.refresh(ctx, g.hc, secret)
	if errors.Is(err, errGoogleGrant) {
		return nil, errReauth
	}
	if err != nil {
		return nil, err
	}
	// Google includes a fresh ID token when it can. If the account's email
	// has changed since sign-in, the identity (and admission) sealed in the
	// refresh token is stale: sign in again.
	if t.IDToken != "" {
		if now, err := g.client.verifyIDToken(t.IDToken, time.Now()); err == nil && (now.Sub != u.Sub || now.Email != u.Email || now.Domain != u.Domain) {
			return nil, reauthError("the Google account's identity changed since sign-in")
		}
	}
	granted := strings.Fields(t.Scope)
	if t.Scope != "" && !g.hasScopes(granted) {
		return nil, reauthError("the refreshed Google token lacks a configured scope")
	}
	next := secret
	if t.RefreshToken != "" {
		next = t.RefreshToken
	}
	return &grant{AccessToken: t.AccessToken, Expiry: t.expiry, Scopes: granted, Secret: next}, nil
}

// VaultCustody keeps users' Google grants in the Agent Identity credential
// vault (agentidentitycredentials.googleapis.com). Sign-in only identifies
// the user (openid, email, online); the vault runs its own consent leg for
// the configured Google scopes.
//
// The vault trusts whatever user ID it is given and stores whichever
// account consented, so every token it returns is checked against the
// signed-in user's sub with Google's tokeninfo before use, and must carry
// every configured scope. Scopes are always sent in Google's canonical
// spelling, which the vault matches exactly. The vault's expireTime is
// ignored in favour of tokeninfo's. A token tokeninfo refuses is
// force-refreshed once; one Google still accepts never is, and one too
// close to expiry to use is waited out (up to 78 seconds, plus the vault
// and tokeninfo calls, during the token request or the sign-in callback)
// and retrieved again. At refresh the wait runs before the refresh
// token's family is rotated (prepare), so it never holds the family
// rotated, and it extends the response's write deadline past itself. A
// front end with a shorter timeout turns that request into a retry.
type VaultCustody struct {
	// AuthProvider is the full resource name,
	// projects/<p>/locations/<l>/authProviders/<name>. Required.
	AuthProvider string
	// Client calls the vault as the service's own identity (with
	// roles/agentidentity.user on the auth provider). Required.
	Client *http.Client
	// Endpoint replaces VaultEndpoint (tests).
	Endpoint string

	// sleeper replaces waiting out a nearly spent token (tests). A
	// pointer, so VaultCustody stays comparable.
	sleeper *sleeper
}

// sleeper waits out a nearly spent vault token in tests.
type sleeper struct {
	sleep func(ctx context.Context, d time.Duration) error
}

var _ Custody = (*VaultCustody)(nil)

// Name implements Custody.
func (*VaultCustody) Name() string { return "vault" }

func (*VaultCustody) signInScopes(*upstream) []string { return []string{ScopeOpenID, ScopeEmail} }

func (*VaultCustody) signInOffline() bool { return false }

func (v *VaultCustody) begin(ctx context.Context, g *upstream, u User, _ *googleTokens, continueURI string) (*grant, *consent, error) {
	r, err := v.retrieve(ctx, g, u.Sub, continueURI, "")
	if err != nil {
		return nil, nil, err
	}
	c := consentOf(r)
	if c == nil {
		// A consent request from grant comes from forcing a refresh of a
		// token Google refused, or retrieving one again once it expired:
		// the person is in the browser, so they are sent to it as well.
		var gr *grant
		if gr, c, err = v.grant(ctx, g, u, r, continueURI, minSignInTokenLife); (err != nil && !errors.Is(err, errWaitedConsent)) || c == nil {
			return gr, nil, err
		}
	}
	if c.URL == "" || c.Nonce == "" {
		return nil, nil, errors.New("vault: incomplete consent request")
	}
	return nil, c, nil
}

// consentOf is the consent leg the vault asks for in r, or nil.
func consentOf(r *vaultRetrieveResponse) *consent {
	c := r.URIConsentRequired
	if c == nil {
		return nil
	}
	return &consent{URL: c.AuthorizationURI, Nonce: c.ConsentNonce, UID: c.UID}
}

func (v *VaultCustody) finish(ctx context.Context, g *upstream, u User, c consent, q url.Values, continueURI string) (*grant, error) {
	if uid := q.Get("uuid"); c.UID != "" && uid != "" && uid != c.UID {
		return nil, errors.New("vault: consent callback is for another flow")
	}
	state := q.Get("user_id_validation_state")
	if state == "" {
		return nil, errors.New("vault: consent callback has no user_id_validation_state")
	}
	body := map[string]string{"userId": u.Sub, "consentNonce": c.Nonce, "userIdValidationState": state}
	if err := v.call(ctx, "finalize", body, nil); err != nil {
		return nil, err
	}
	r, err := v.retrieve(ctx, g, u.Sub, continueURI, "")
	if err != nil {
		return nil, err
	}
	if r.URIConsentRequired != nil {
		return nil, errors.New("vault: still asks for consent after finalize")
	}
	gr, again, err := v.grant(ctx, g, u, r, continueURI, minSignInTokenLife)
	if err != nil {
		return nil, err
	}
	if again != nil {
		// Consent just ran, and the grant it stored is already gone.
		return nil, errReauth
	}
	return gr, err
}

// prepare does all of a refresh's vault work, waiting out a nearly spent
// token included, before the family is rotated; the grant it returns, with
// every check (account, scopes, email, life) done, is the one issued.
func (v *VaultCustody) prepare(ctx context.Context, g *upstream, u User, secret, continueURI string) (*grant, error) {
	return v.refresh(ctx, g, u, secret, continueURI)
}

func (v *VaultCustody) refresh(ctx context.Context, g *upstream, u User, _, continueURI string) (*grant, error) {
	r, err := v.retrieve(ctx, g, u.Sub, continueURI, "")
	if err != nil {
		return nil, err
	}
	if r.URIConsentRequired != nil {
		return nil, errReauth
	}
	gr, c, err := v.grant(ctx, g, u, r, continueURI, minRefreshTokenLife)
	if err != nil {
		return nil, err
	}
	if c != nil {
		return nil, errReauth
	}
	return gr, nil
}

// grant turns a retrieve result into a grant. It checks the token is the
// signed-in user's and carries every configured scope, and takes the
// expiry from tokeninfo (the vault's expireTime can be wrong). need is the
// least life the token must have left to be used: minSignInTokenLife or
// minRefreshTokenLife.
//
// Only the vault or Google refusing is a reauthError (access_denied at
// sign-in, invalid_grant at refresh, which signs the person out). Per the
// vault's API reference, "pending" means "retry the RetrieveCredentials
// request after some time": the vault busy, like an answer with nothing
// usable in it, is a plain error, server_error, and a retry may work.
//
// A refresh is forced only for a token Google's tokeninfo refuses (400
// invalid_token: expired, on time or early, or revoked), the one case the
// vault's API reference allows: "Set this field only if the previous
// token was expired or invalid". A forced refresh "fetches a new token or
// initiates a new consent flow", so a consent request then is the grant
// gone: it is returned, for a sign-in to detour through and a refresh to
// refuse.
//
// A token Google still accepts is never forced: asked to, the vault asked
// for consent instead (kode-gopher's vault spike, docs/design-in-cluster.md).
// One with need left is used, and the access token stops a minute before
// it (sealAccess). One with less is waited out if it expires within
// maxExpiryWait, and the vault asked again: after a real expiry a plain
// retrieve brought a fresh token in the spike, and if the vault hands back
// the expired one, Google refuses it and it is forced. Consent then
// (errWaitedConsent) is not yet read as the grant gone: the vault may lag
// tokeninfo by a few seconds in counting the token expired. A refresh gets
// server_error, and the next request, which does not wait, forces the
// token again and reads consent as the grant gone; a sign-in, the person
// being in the browser, detours through consent as for any other. A short
// token waited out once, one a forced refresh brought, or one with longer
// than maxExpiryWait left is server_error.
func (v *VaultCustody) grant(ctx context.Context, g *upstream, u User, r *vaultRetrieveResponse, continueURI string, need time.Duration) (*grant, *consent, error) {
	var (
		forced string // the token whose refresh was forced, if any
		waited string // the token too short to use that was waited out
	)
	for {
		switch {
		case r.URIConsentRequired != nil && forced != "" && forced == waited:
			return nil, consentOf(r), errWaitedConsent
		case r.URIConsentRequired != nil:
			return nil, consentOf(r), nil
		case r.ConsentRejected != nil:
			return nil, nil, reauthError("vault: the user declined consent")
		case r.Pending != nil:
			return nil, nil, errors.New("vault: the grant is pending; try again")
		case r.Success == nil || r.Success.Token == "":
			return nil, nil, errors.New("vault: answered with neither a token nor a consent request")
		case forced != "" && r.Success.Token == forced:
			return nil, nil, errors.New("vault: a forced refresh returned the same token")
		}
		tok := r.Success.Token
		ti, err := g.client.tokenInfo(ctx, g.hc, tok)
		switch {
		case errors.Is(err, errGoogleToken) && forced == "":
			// Expired (on time, early, or while it was waited out) or
			// revoked: force a new one.
			forced = tok
			if r, err = v.retrieve(ctx, g, u.Sub, continueURI, tok); err != nil {
				return nil, nil, err
			}
			continue
		case errors.Is(err, errGoogleToken):
			// Refused before the forced refresh and after it.
			return nil, nil, reauthError("vault: Google refuses the force-refreshed token")
		case err != nil:
			return nil, nil, err
		case ti.Sub != u.Sub:
			// Someone other than the signed-in user consented. The vault
			// has no delete API, so this only refuses.
			return nil, nil, reauthError("vault: the stored Google grant belongs to a different account than the one signed in")
		case !g.hasScopes(ti.Scopes):
			return nil, nil, reauthError("vault: token lacks a configured Google scope")
		case ti.Email != "" && !strings.EqualFold(ti.Email, u.Email):
			// Same account, new address: the identity (and admission)
			// sealed at sign-in is stale. tokeninfo reports the email
			// because the vault is always asked for userinfo.email.
			return nil, nil, reauthError("vault: the Google account's email changed since sign-in")
		}
		left := time.Until(ti.Expiry)
		if left >= need {
			return &grant{AccessToken: tok, Expiry: ti.Expiry, Scopes: ti.Scopes}, nil, nil
		}
		if waited != "" || forced != "" || left > maxExpiryWait {
			// A fresh token is due only once this one expires, and
			// forcing it would ask for consent.
			return nil, nil, fmt.Errorf("vault: the Google token has %ds left, too little to use, and the vault renews it only once it expires; try again", int(left.Seconds()))
		}
		waited = tok
		if err := v.wait(ctx, left+expirySkew); err != nil {
			return nil, nil, fmt.Errorf("vault: waiting out a nearly spent token: %w", err)
		}
		if r, err = v.retrieve(ctx, g, u.Sub, continueURI, ""); err != nil {
			return nil, nil, err
		}
	}
}

// postWaitBudget is how long a request may still take after waiting out a
// nearly spent token: a vault retrieve or two, tokeninfo, the rotation,
// the allow-list and the response.
const postWaitBudget = 30 * time.Second

// wait sleeps for d, or until ctx is done. It first moves the response's
// write deadline past the wait (see extendWriteDeadline), so a server
// WriteTimeout shorter than the wait does not drop the answer to a
// request that went on to rotate a refresh token's family.
func (v *VaultCustody) wait(ctx context.Context, d time.Duration) error {
	extendWriteDeadline(ctx, d+postWaitBudget)
	if v.sleeper != nil {
		return v.sleeper.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// responseKey carries the response writer whose write deadline a long
// custody wait extends.
type responseKey struct{}

// withResponse lets custody work under ctx extend w's write deadline.
func withResponse(ctx context.Context, w http.ResponseWriter) context.Context {
	return context.WithValue(ctx, responseKey{}, w)
}

// extendWriteDeadline sets the write deadline of the response in ctx, if
// any, d from now. http.Server.WriteTimeout is a deadline set when the
// request is read, and over HTTP/1.1 it does not cancel the request: the
// handler runs on and its answer is lost. A writer that does not support
// it (a wrapper without Unwrap) is left as it is.
func extendWriteDeadline(ctx context.Context, d time.Duration) {
	if w, ok := ctx.Value(responseKey{}).(http.ResponseWriter); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
	}
}

type vaultRetrieveResponse struct {
	URIConsentRequired *struct {
		AuthorizationURI string `json:"authorizationUri"`
		ConsentNonce     string `json:"consentNonce"`
		UID              string `json:"uid"`
	} `json:"uriConsentRequired"`
	Success *struct {
		Token string `json:"token"`
	} `json:"success"`
	ConsentRejected *struct{} `json:"consentRejected"`
	Pending         *struct{} `json:"pending"`
}

// retrieve asks the vault for userID's token. forceRefresh, if set, is the
// spent token to replace.
func (v *VaultCustody) retrieve(ctx context.Context, g *upstream, userID, continueURI, forceRefresh string) (*vaultRetrieveResponse, error) {
	body := map[string]any{
		"userId":      userID,
		"scopes":      g.grantScopes(),
		"continueUri": continueURI,
	}
	if forceRefresh != "" {
		body["forceRefreshToken"] = forceRefresh
	}
	var r vaultRetrieveResponse
	if err := v.call(ctx, "retrieve", body, &r); err != nil {
		if forceRefresh != "" && strings.Contains(err.Error(), forceRefresh) {
			// The vault's error message quotes the token back: keep it
			// out of the error, which is logged.
			return nil, errors.New(strings.ReplaceAll(err.Error(), forceRefresh, "[token]"))
		}
		return nil, err
	}
	return &r, nil
}

func (v *VaultCustody) call(ctx context.Context, method string, body, out any) error {
	if v.Client == nil {
		return errors.New("vault: no Client")
	}
	ep := v.Endpoint
	if ep == "" {
		ep = VaultEndpoint
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep+v.AuthProvider+"/credentials:"+method, bytes.NewReader(b)) //nolint:gosec // G704: the operator-configured vault endpoint
	if err != nil {
		return fmt.Errorf("vault %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.Client.Do(req) //nolint:gosec // G704: as above
	if err != nil {
		return fmt.Errorf("vault %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("vault %s: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		return fmt.Errorf("vault %s: HTTP %d %s %s", method, resp.StatusCode, e.Error.Status, e.Error.Message)
	}
	if out == nil || len(bytes.TrimSpace(rb)) == 0 {
		return nil
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("vault %s: malformed response", method)
	}
	return nil
}
