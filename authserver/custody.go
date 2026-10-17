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

// minGoogleTokenLife is the least life a Google access token must have
// left to be sealed into an access token. A vault token closer to expiry
// than this is force-refreshed.
const minGoogleTokenLife = 5 * time.Minute

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
	// refresh mints a fresh grant at the token endpoint. errReauth means
	// the user must sign in again.
	refresh(ctx context.Context, g *upstream, u User, secret, continueURI string) (*grant, error)
}

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
		if now, err := g.client.verifyIDToken(t.IDToken, time.Now()); err == nil && (now.Sub != u.Sub || now.Email != u.Email) {
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
// ignored in favour of tokeninfo's, and a token with under 5 minutes left
// is force-refreshed once.
type VaultCustody struct {
	// AuthProvider is the full resource name,
	// projects/<p>/locations/<l>/authProviders/<name>. Required.
	AuthProvider string
	// Client calls the vault as the service's own identity (with
	// roles/agentidentity.user on the auth provider). Required.
	Client *http.Client
	// Endpoint replaces VaultEndpoint (tests).
	Endpoint string
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
	if c := r.URIConsentRequired; c != nil {
		if c.AuthorizationURI == "" || c.ConsentNonce == "" {
			return nil, nil, errors.New("vault: incomplete consent request")
		}
		return nil, &consent{URL: c.AuthorizationURI, Nonce: c.ConsentNonce, UID: c.UID}, nil
	}
	gr, err := v.grant(ctx, g, u, r, continueURI)
	return gr, nil, err
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
	return v.grant(ctx, g, u, r, continueURI)
}

func (v *VaultCustody) refresh(ctx context.Context, g *upstream, u User, _, continueURI string) (*grant, error) {
	r, err := v.retrieve(ctx, g, u.Sub, continueURI, "")
	if err != nil {
		return nil, err
	}
	if r.URIConsentRequired != nil {
		return nil, errReauth
	}
	return v.grant(ctx, g, u, r, continueURI)
}

// grant turns a retrieve result into a grant. It checks the token is the
// signed-in user's and carries every configured scope, takes the expiry
// from tokeninfo (the vault's expireTime can be wrong), and force-refreshes
// a token that is nearly spent.
func (v *VaultCustody) grant(ctx context.Context, g *upstream, u User, r *vaultRetrieveResponse, continueURI string) (*grant, error) {
	for attempt := 0; ; attempt++ {
		switch {
		case r.ConsentRejected != nil:
			return nil, reauthError("vault: the user declined consent")
		case r.Success == nil || r.Success.Token == "":
			return nil, reauthError("vault: no token (consent pending)")
		}
		tok := r.Success.Token
		ti, err := g.client.tokenInfo(ctx, g.hc, tok)
		if err != nil {
			return nil, err
		}
		if ti.Sub != u.Sub {
			// Someone other than the signed-in user consented. The vault
			// has no delete API, so this only refuses.
			return nil, reauthError("vault: the stored Google grant belongs to a different account than the one signed in")
		}
		if !g.hasScopes(ti.Scopes) {
			return nil, reauthError("vault: token lacks a configured Google scope")
		}
		if ti.Email != "" && !strings.EqualFold(ti.Email, u.Email) {
			// Same account, new address: the identity (and admission)
			// sealed at sign-in is stale.
			return nil, reauthError("vault: the Google account's email changed since sign-in")
		}
		if time.Until(ti.Expiry) >= minGoogleTokenLife {
			return &grant{AccessToken: tok, Expiry: ti.Expiry, Scopes: ti.Scopes}, nil
		}
		if attempt > 0 {
			return nil, errors.New("vault: force-refreshed token is still nearly expired")
		}
		if r, err = v.retrieve(ctx, g, u.Sub, continueURI, tok); err != nil {
			return nil, err
		}
		if r.URIConsentRequired != nil {
			return nil, errReauth
		}
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
