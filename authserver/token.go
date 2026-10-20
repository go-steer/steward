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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-steer/steward/allow"
)

// codePayload is a sealed authorization code. It carries the Google access
// token already minted at sign-in, so the token endpoint need not call
// Google.
type codePayload struct {
	Req         authRequest `json:"q"`
	User        User        `json:"u"`
	Token       string      `json:"t"`
	TokenExp    int64       `json:"te"`
	GoogleScope string      `json:"gs,omitempty"`
	Secret      string      `json:"g,omitempty"`
	JTI         string      `json:"j"`
	Exp         int64       `json:"e"`
}

// accessPayload is a sealed access token.
type accessPayload struct {
	Sub         string `json:"sub"`
	Email       string `json:"em,omitempty"`
	HD          string `json:"hd,omitempty"`
	ClientID    string `json:"c"`
	Aud         string `json:"aud"`
	Scope       string `json:"s"`
	Token       string `json:"t,omitempty"`
	TokenExp    int64  `json:"te,omitempty"`
	GoogleScope string `json:"gs,omitempty"`
	Exp         int64  `json:"e"`
	// Mode is modeWorkload for a client-credentials token, else empty.
	Mode string `json:"m,omitempty"`
	// SA is a workload's service account, if it has one.
	SA string `json:"sa,omitempty"`
	// SH is a tag of the workload's client secret, so rotating the secret
	// revokes the tokens minted with the old one.
	SH string `json:"sh,omitempty"`
}

// refreshPayload is a sealed refresh token. Secret is the Google refresh
// token under sealed custody, empty under the vault. Family and Gen place
// it in its rotation chain (see ReplayCache).
type refreshPayload struct {
	User     User   `json:"u"`
	ClientID string `json:"c"`
	Aud      string `json:"aud"`
	Scope    string `json:"s"`
	Secret   string `json:"g,omitempty"`
	Family   string `json:"f"`
	Gen      uint64 `json:"n,omitempty"`
	Exp      int64  `json:"e"`
}

// tokenError is an RFC 6749 section 5.2 error response.
type tokenError struct {
	Code string `json:"error"`
	Desc string `json:"error_description,omitempty"`
}

func invalidGrant(desc string) *tokenError { return &tokenError{Code: "invalid_grant", Desc: desc} }

func serverError(desc string) *tokenError { return &tokenError{Code: "server_error", Desc: desc} }

// openErr maps a failure to open an envelope to the token endpoint's
// answer: the keys being unavailable is the server's failure, anything
// else is the grant's.
func openErr(err error, desc string) *tokenError {
	if errors.Is(err, errKeys) {
		return serverError("the sealing keys are unavailable")
	}
	return invalidGrant(desc)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
		writeTokenError(w, &tokenError{Code: "invalid_request", Desc: "the body must be application/x-www-form-urlencoded"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, &tokenError{Code: "invalid_request", Desc: "malformed form body"})
		return
	}
	if r.PostForm.Get("grant_type") == "" {
		writeTokenError(w, &tokenError{Code: "invalid_request", Desc: "grant_type is required"})
		return
	}
	c, terr := s.authenticateClient(r)
	if terr != nil {
		writeTokenError(w, terr)
		return
	}
	var resp map[string]any
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		resp, terr = s.exchangeCode(r, c)
	case "refresh_token":
		resp, terr = s.refreshTokens(r.Context(), r, c)
	case "client_credentials":
		resp, terr = s.clientCredentials(r, c)
	default:
		terr = &tokenError{Code: "unsupported_grant_type", Desc: "authorization_code, refresh_token and client_credentials only"}
	}
	if terr != nil {
		writeTokenError(w, terr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// authenticateClient resolves the client and, for a confidential one,
// checks its secret (client_secret_basic or client_secret_post).
func (s *Server) authenticateClient(r *http.Request) (*client, *tokenError) {
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 section 2.3.1: Basic credentials are form-urlencoded.
		id, secret = formUnescape(id), formUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		return nil, &tokenError{Code: "invalid_client", Desc: "client_id is required"}
	}
	c, err := s.resolveClient(r.Context(), id)
	if clientUnavailable(err) {
		s.log.WarnContext(r.Context(), "authserver: could not resolve a client at the token endpoint", "err", err)
		return nil, serverError("the client couldn't be resolved right now")
	}
	if err != nil {
		// The reason may quote a client-supplied metadata document or a
		// dial error: it goes to the log, not to the caller.
		s.log.InfoContext(r.Context(), "authserver: unknown client at the token endpoint", "err", err)
		return nil, &tokenError{Code: "invalid_client", Desc: "unknown client"}
	}
	if c.Secret != "" && !secretMatches(secret, c.Secret) {
		return nil, &tokenError{Code: "invalid_client", Desc: "client authentication failed"}
	}
	return c, nil
}

// secretMatches compares digests in constant time, so neither the content
// nor the length of the secret leaks through timing.
func secretMatches(got, want string) bool {
	g, w := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

func formUnescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

func (s *Server) exchangeCode(r *http.Request, c *client) (map[string]any, *tokenError) {
	ctx := r.Context()
	f := r.PostForm
	var p codePayload
	if err := s.open(ctx, purposeCode, f.Get("code"), &p); err != nil {
		return nil, openErr(err, "invalid authorization code")
	}
	switch {
	case s.now().Unix() > p.Exp:
		return nil, invalidGrant("authorization code expired")
	case p.Req.ClientID != c.ID:
		return nil, invalidGrant("authorization code was issued to another client")
	case f.Get("redirect_uri") != "" && f.Get("redirect_uri") != p.Req.RedirectURI:
		return nil, invalidGrant("redirect_uri doesn't match the authorization request")
	case !pkceMatches(f.Get("code_verifier"), p.Req.Challenge):
		return nil, invalidGrant("PKCE verification failed")
	case (f.Get("resource") != "" && f.Get("resource") != p.Req.Resource) || len(f["resource"]) > 1:
		return nil, &tokenError{Code: "invalid_target", Desc: "resource doesn't match the authorization request"}
	}
	fresh, err := s.used.Claim(ctx, "code:"+p.JTI, time.Unix(p.Exp, 0))
	if err != nil {
		s.log.ErrorContext(ctx, "authserver: replay cache", "err", err)
		return nil, serverError("couldn't record the code's use")
	}
	if !fresh {
		s.log.WarnContext(ctx, "authserver: authorization code reused", "email", p.User.Email, "client", clientLabel(&p.Req))
		return nil, invalidGrant("authorization code already used")
	}
	g := &grant{AccessToken: p.Token, Expiry: time.Unix(p.TokenExp, 0), Scopes: strings.Fields(p.GoogleScope), Secret: p.Secret}
	resp, terr := s.issueTokens(ctx, p.User, c.ID, p.Req.Resource, p.Req.Scope, p.Req.Scope, rand.Text(), 0, s.now().Add(RefreshTTL), g)
	if terr != nil {
		// Nothing was handed out: let the client try the code again.
		s.undo(ctx, "release the authorization code", func(ctx context.Context) error { return s.used.Release(ctx, "code:"+p.JTI) })
	}
	return resp, terr
}

// undoTimeout bounds giving a claim or a rotation back.
const undoTimeout = 5 * time.Second

// undo gives back a replay-cache claim or rotation after a transient
// failure. It runs detached from the request's context: a client that went
// away mid-refresh must not leave its family rotated, or its retry would be
// taken for a replay and revoke the family. A failure is logged; the
// client's retry then needs a new sign-in.
func (s *Server) undo(ctx context.Context, what string, f func(context.Context) error) {
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), undoTimeout)
	defer cancel()
	if err := f(uctx); err != nil {
		s.log.WarnContext(ctx, "authserver: could not "+what, "err", err)
	}
}

// verifierRE is RFC 7636 section 4.1: 43 to 128 unreserved characters.
var verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func pkceMatches(verifier, challenge string) bool {
	if !verifierRE.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// refreshTokens rotates a refresh token: the old one is spent, the
// allow-list is checked again, and custody mints a fresh Google token.
func (s *Server) refreshTokens(ctx context.Context, r *http.Request, c *client) (map[string]any, *tokenError) {
	f := r.PostForm
	var p refreshPayload
	if err := s.open(ctx, purposeRefresh, f.Get("refresh_token"), &p); err != nil {
		return nil, openErr(err, "invalid refresh token")
	}
	switch {
	case s.now().Unix() > p.Exp:
		return nil, invalidGrant("refresh token expired")
	case p.ClientID != c.ID:
		return nil, invalidGrant("refresh token was issued to another client")
	case (f.Get("resource") != "" && f.Get("resource") != p.Aud) || len(f["resource"]) > 1:
		return nil, &tokenError{Code: "invalid_target", Desc: "resource doesn't match the original grant"}
	case p.Aud != s.cfg.Resource:
		return nil, invalidGrant("refresh token is for another resource")
	}
	// The grant keeps only the scopes the configuration still allows this
	// client: narrowing a client's (or the server's) scopes takes effect at
	// its next refresh, not after the refresh token's 30-day life, which
	// every refresh renews.
	allowed := s.allowedScopes(c)
	var kept []string
	for _, sc := range strings.Fields(p.Scope) {
		if slices.Contains(allowed, sc) {
			kept = append(kept, sc)
		}
	}
	if len(kept) == 0 {
		return nil, invalidGrant("none of the granted scopes is available any more")
	}
	grantScope := strings.Join(kept, " ")
	scope := grantScope
	if req := strings.Fields(f.Get("scope")); len(req) > 0 {
		// RFC 6749 section 6: a refresh may narrow the access token's
		// scope, never widen it; the new refresh token keeps the grant's.
		narrowed, terr := narrowScope(req, kept)
		if terr != nil {
			return nil, terr
		}
		scope = narrowed
	}
	if p.Family == "" {
		return nil, invalidGrant("invalid refresh token")
	}
	// One expiry for the family and the token that will carry it, so the
	// family is never forgotten before its newest token expires.
	exp := s.now().Add(RefreshTTL)
	release := func() {
		s.undo(ctx, "give back a refresh rotation", func(ctx context.Context) error { return s.used.Unrotate(ctx, p.Family, p.Gen) })
	}
	rotated, err := s.rotate(ctx, p.Family, p.Gen, exp)
	if err != nil {
		s.log.ErrorContext(ctx, "authserver: replay cache", "err", err)
		// The rotation may have been applied before the error (a
		// timeout after a write): Unrotate is conditional, so undo it.
		release()
		return nil, serverError("couldn't record the refresh token's use")
	}
	switch rotated {
	case RotateApplied:
	case RotateRefused:
		// Both refusals read the same to the client, so a thief cannot
		// tell whether the family is still alive.
		s.log.InfoContext(ctx, "authserver: refresh token presented again within the reuse grace; refused, family kept", "email", p.User.Email, "client", p.ClientID)
		return nil, invalidGrant("refresh token already used")
	default:
		s.log.WarnContext(ctx, "authserver: refresh token reused; its family is revoked", "email", p.User.Email, "client", p.ClientID)
		return nil, invalidGrant("refresh token already used")
	}
	// The family is rotated above, so two concurrent refreshes cannot both
	// use the token. A transient failure below (server_error) rotates it
	// back, or the client's retry would be refused as a replay and its user
	// signed out; a final refusal (invalid_grant: not allowed, or a grant
	// only the user can restore, errReauth) keeps it spent.
	if err := s.cfg.Admit.Admit(ctx, p.User.Email, p.User.Domain); err != nil {
		if errors.Is(err, allow.ErrNotAdmitted) {
			s.log.InfoContext(ctx, "authserver: refresh refused by the allow-list", "email", p.User.Email)
			return nil, invalidGrant("this account isn't allowed to use this server")
		}
		s.log.WarnContext(ctx, "authserver: could not check the allow-list at refresh", "email", p.User.Email, "err", err)
		release()
		return nil, serverError("couldn't check the allow-list")
	}
	g, err := s.cfg.Custody.refresh(ctx, s.google, p.User, p.Secret, s.ContinueURL())
	if errors.Is(err, errReauth) {
		s.log.InfoContext(ctx, "authserver: refresh needs a new sign-in", "custody", s.cfg.Custody.Name(), "email", p.User.Email, "reason", err)
		return nil, invalidGrant(err.Error())
	}
	if err != nil {
		s.log.WarnContext(ctx, "authserver: custody failed at refresh", "custody", s.cfg.Custody.Name(), "email", p.User.Email, "err", err)
		release()
		return nil, serverError("couldn't refresh the Google grant")
	}
	resp, terr := s.issueTokens(ctx, p.User, c.ID, p.Aud, scope, grantScope, p.Family, p.Gen+1, exp, g)
	if terr != nil {
		release()
	}
	return resp, terr
}

// rotate moves family on from gen through the replay cache, with the
// reuse grace if the cache supports one.
func (s *Server) rotate(ctx context.Context, family string, gen uint64, exp time.Time) (RotateResult, error) {
	if g, ok := s.used.(GraceReplayCache); ok && s.grace > 0 {
		return g.RotateGrace(ctx, family, gen, exp, s.now().Add(s.grace))
	}
	fresh, err := s.used.Rotate(ctx, family, gen, exp)
	if fresh {
		return RotateApplied, err
	}
	return RotateRevoked, err
}

// narrowScope checks that every requested scope was in the original grant.
func narrowScope(requested, granted []string) (string, *tokenError) {
	var out []string
	for _, sc := range requested {
		if !slices.Contains(granted, sc) {
			return "", &tokenError{Code: "invalid_scope", Desc: "a requested scope wasn't in the original grant"}
		}
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return strings.Join(out, " "), nil
}

// issueTokens seals a new access and refresh token pair: the access token
// with scope, the refresh token with grantScope (the same, unless a refresh
// narrowed the access token) at generation gen of family, expiring at
// refreshExp. The access token never outlives the Google token inside it.
func (s *Server) issueTokens(ctx context.Context, u User, clientID, aud, scope, grantScope, family string, gen uint64, refreshExp time.Time, g *grant) (map[string]any, *tokenError) {
	now := s.now()
	at, exp, terr := s.sealAccess(ctx, accessPayload{
		Sub: u.Sub, Email: u.Email, HD: u.Domain, ClientID: clientID, Aud: aud, Scope: scope,
		Token: g.AccessToken, TokenExp: g.Expiry.Unix(), GoogleScope: strings.Join(g.Scopes, " "),
	}, now)
	if terr != nil {
		return nil, terr
	}
	rt, err := s.seal(ctx, purposeRefresh, refreshPayload{
		User: u, ClientID: clientID, Aud: aud, Scope: grantScope, Secret: g.Secret,
		Family: family, Gen: gen, Exp: refreshExp.Unix(),
	})
	if err != nil {
		s.log.ErrorContext(ctx, "authserver: seal refresh token", "err", err)
		return nil, serverError("couldn't seal the refresh token")
	}
	return map[string]any{
		"access_token":  at,
		"token_type":    "Bearer",
		"expires_in":    int64(exp.Sub(now).Seconds()),
		"refresh_token": rt,
		"scope":         scope,
	}, nil
}

// sealAccess sets p's expiry, AccessTTL from now but never past a minute
// before the Google token inside it expires, and seals it.
func (s *Server) sealAccess(ctx context.Context, p accessPayload, now time.Time) (string, time.Time, *tokenError) {
	exp := now.Add(AccessTTL)
	if p.Token != "" {
		if limit := time.Unix(p.TokenExp, 0).Add(-time.Minute); limit.Before(exp) {
			exp = limit
		}
	}
	if !exp.After(now) {
		return "", time.Time{}, serverError("the Google access token is already spent")
	}
	p.Exp = exp.Unix()
	at, err := s.seal(ctx, purposeAccess, p)
	if err != nil {
		s.log.ErrorContext(ctx, "authserver: seal access token", "err", err)
		return "", time.Time{}, serverError("couldn't seal the access token")
	}
	return at, exp, nil
}

// cleanDesc keeps an error_description within RFC 6749's character set
// (%x20-21 / %x23-5B / %x5D-7E), whatever client-supplied text it quotes.
func cleanDesc(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c == '"':
			b[i] = '\''
		case c < 0x20 || c > 0x7e || c == '\\':
			b[i] = '?'
		}
	}
	return string(b)
}

func writeTokenError(w http.ResponseWriter, e *tokenError) {
	e.Desc = cleanDesc(e.Desc)
	code := http.StatusBadRequest
	switch e.Code {
	case "invalid_client":
		// A 401 carries a challenge (RFC 9110 section 15.5.2), however the
		// client tried to authenticate.
		code = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="steward"`)
	case "server_error":
		code = http.StatusInternalServerError
	}
	writeJSON(w, code, e)
}

// handleRegister is open Dynamic Client Registration (RFC 7591) for public
// clients. The client_id it returns is the sealed registration, so nothing
// is stored.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var m struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil || json.Unmarshal(b, &m) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": "malformed JSON"})
		return
	}
	if desc := checkRegistration(m.RedirectURIs, m.GrantTypes, m.ResponseTypes); desc != "" {
		code := "invalid_client_metadata"
		if strings.HasPrefix(desc, "redirect") {
			code = "invalid_redirect_uri"
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": cleanDesc(desc)})
		return
	}
	m.ClientName = clientName(m.ClientName)
	now := s.now()
	id, err := s.seal(r.Context(), purposeClient, dcrClient{RedirectURIs: m.RedirectURIs, Name: m.ClientName, IssuedAt: now.Unix()})
	if err != nil {
		s.log.ErrorContext(r.Context(), "authserver: seal DCR client", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Every DCR client is public: token_endpoint_auth_method is none,
	// whatever was asked for (RFC 7591 section 3.2.1 lets us say so).
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        now.Unix(),
		"client_name":                m.ClientName,
		"redirect_uris":              m.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

func checkRegistration(redirects, grants, responses []string) string {
	if len(redirects) == 0 || len(redirects) > 10 {
		return "redirect_uris needs 1 to 10 entries"
	}
	total := 0
	for _, u := range redirects {
		if len(u) > 2048 || !validRedirectURI(u) {
			return fmt.Sprintf("redirect URI %q isn't allowed (https, loopback http, or a private-use scheme)", truncate(u, 200))
		}
		total += len(u)
	}
	// The registration rides in the client_id, which rides in URLs.
	if total > 2048 {
		return "redirect_uris are too long together (2048 bytes at most)"
	}
	for _, g := range grants {
		if g != "authorization_code" && g != "refresh_token" {
			return fmt.Sprintf("grant type %q isn't supported", g)
		}
	}
	for _, rt := range responses {
		if rt != "code" {
			return fmt.Sprintf("response type %q isn't supported", rt)
		}
	}
	return ""
}
