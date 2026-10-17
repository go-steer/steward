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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/seal"
)

// authRequest is a client's validated authorization request. It rides
// through the consent page, Google sign-in and any vault consent inside
// sealed envelopes.
type authRequest struct {
	ClientID    string `json:"c"`
	ClientName  string `json:"cn,omitempty"`
	RedirectURI string `json:"r"`
	Challenge   string `json:"pc"`
	Resource    string `json:"aud"`
	Scope       string `json:"s"`
	State       string `json:"st,omitempty"`
}

// browserBound is an envelope tied to the browser that started the flow
// by a cookie, so a link or form from someone else's flow fails.
type browserBound struct {
	Req     authRequest `json:"q"`
	Browser string      `json:"b"`
	Exp     int64       `json:"e"`
	// Verifier is the PKCE verifier for Google sign-in (state only).
	Verifier string `json:"v,omitempty"`
}

// pendingConsent waits in a cookie while the browser is at the vault's
// consent leg.
type pendingConsent struct {
	Req     authRequest `json:"q"`
	User    User        `json:"u"`
	Consent consent     `json:"c"`
	Exp     int64       `json:"e"`
}

const (
	cookieBrowser = "steward_auth"
	cookieConsent = "steward_consent"
)

var challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// authError is an authorization failure. Before the redirect URI is
// trusted it is shown to the user; after, it goes back to the client.
type authError struct {
	code, desc string
}

// handleAuthorize validates the request and, for a pre-registered client,
// goes straight to Google sign-in. Any other client gets a consent page
// first: the MCP spec requires a proxy with one Google client to get the
// user's consent for each dynamically registered client, or a malicious
// one could ride a user's existing Google session.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := s.resolveClient(r.Context(), q.Get("client_id"))
	if clientUnavailable(err) {
		s.log.WarnContext(r.Context(), "authserver: could not resolve a client at the authorization endpoint", "err", err)
		s.authPage(w, http.StatusServiceUnavailable, "Try again", "Sign-in isn't available right now. Try again in a moment.")
		return
	}
	if err != nil {
		// The reason may quote a client-supplied metadata document or a
		// dial error (an internal-network oracle): log it, show none of it.
		s.log.InfoContext(r.Context(), "authserver: unknown client at the authorization endpoint", "err", err)
		s.authPage(w, http.StatusBadRequest, "Unknown client", "This sign-in link names a client this server doesn't recognize.")
		return
	}
	if c.static != nil && c.static.clientCredentials() {
		s.authPage(w, http.StatusBadRequest, "Unknown client", "This client signs in with its own credentials, not as a person.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(c.RedirectURIs) == 1 {
		redirectURI = c.RedirectURIs[0]
	}
	if !redirectAllowed(c, redirectURI) {
		s.authPage(w, http.StatusBadRequest, "Bad redirect", "The redirect URI isn't registered for this client.")
		return
	}
	req, aerr := s.validateAuthRequest(q, c, redirectURI)
	if aerr != nil {
		s.redirectError(w, r, redirectURI, q.Get("state"), aerr)
		return
	}
	browser := s.bindBrowser(w)
	if c.static != nil {
		s.toGoogle(w, r, req, browser)
		return
	}
	form, err := s.seal(r.Context(), purposeConsent, browserBound{Req: *req, Browser: browser, Exp: s.now().Add(AuthRequestTTL).Unix()})
	if err != nil {
		s.log.ErrorContext(r.Context(), "authserver: seal consent form", "err", err)
		s.authPage(w, http.StatusInternalServerError, "Error", "Couldn't start sign-in.")
		return
	}
	s.consentPage(w, c, redirectURI, form)
}

func (s *Server) validateAuthRequest(q url.Values, c *client, redirectURI string) (*authRequest, *authError) {
	if q.Get("response_type") != "code" {
		return nil, &authError{"unsupported_response_type", "only response_type=code is supported"}
	}
	if q.Get("code_challenge_method") != "S256" || !challengeRE.MatchString(q.Get("code_challenge")) {
		return nil, &authError{"invalid_request", "PKCE with code_challenge_method=S256 is required"}
	}
	resource := q.Get("resource")
	if resource == "" {
		resource = s.cfg.Resource
	}
	if resource != s.cfg.Resource || len(q["resource"]) > 1 {
		return nil, &authError{"invalid_target", "resource must be " + s.cfg.Resource}
	}
	scope, ok := s.grantScopes(strings.Fields(q.Get("scope")), s.allowedScopes(c))
	if !ok {
		return nil, &authError{"invalid_scope", "none of the requested scopes is available to this client"}
	}
	return &authRequest{
		ClientID:    c.ID,
		ClientName:  c.Name,
		RedirectURI: redirectURI,
		Challenge:   q.Get("code_challenge"),
		Resource:    resource,
		Scope:       scope,
		State:       q.Get("state"),
	}, nil
}

// grantScopes is what an authorization request is granted: the requested
// scopes the client may have, others dropped as RFC 6749 section 3.3
// allows; if that leaves none, the default scopes the client may have. ok
// is false if the client may have none of those either.
func (s *Server) grantScopes(requested, allowed []string) (string, bool) {
	var granted []string
	for _, sc := range requested {
		if slices.Contains(allowed, sc) && !slices.Contains(granted, sc) {
			granted = append(granted, sc)
		}
	}
	if len(granted) == 0 {
		for _, sc := range s.defaultScopes {
			if slices.Contains(allowed, sc) {
				granted = append(granted, sc)
			}
		}
	}
	return strings.Join(granted, " "), len(granted) > 0
}

// handleApprove is the consent page's form: Continue goes on to Google
// sign-in, Cancel returns access_denied to the client.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var b browserBound
	if s.open(r.Context(), purposeConsent, r.PostFormValue("request"), &b) != nil || s.now().Unix() > b.Exp || !s.sameBrowser(r, b.Browser) {
		s.authPage(w, http.StatusBadRequest, "Sign-in expired", "This sign-in page has expired or was opened in another browser. Start again from your client.")
		return
	}
	if r.PostFormValue("action") != "approve" {
		s.redirectError(w, r, b.Req.RedirectURI, b.Req.State, &authError{"access_denied", "the user declined"})
		return
	}
	s.toGoogle(w, r, &b.Req, b.Browser)
}

// toGoogle sends the browser to Google sign-in, carrying req in the sealed
// state.
func (s *Server) toGoogle(w http.ResponseWriter, r *http.Request, req *authRequest, browser string) {
	verifier := rand.Text() + rand.Text()
	state, err := s.seal(r.Context(), purposeState, browserBound{Req: *req, Browser: browser, Exp: s.now().Add(AuthRequestTTL).Unix(), Verifier: verifier})
	if err != nil {
		s.log.ErrorContext(r.Context(), "authserver: seal sign-in state", "err", err)
		s.authPage(w, http.StatusInternalServerError, "Error", "Couldn't start sign-in.")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	u := s.cfg.Google.authCodeURL(s.CallbackURL(), state, base64.RawURLEncoding.EncodeToString(sum[:]), s.cfg.Custody.signInScopes(s.google), s.cfg.Custody.signInOffline())
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// handleCallback is Google's redirect after sign-in.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var b browserBound
	if s.open(r.Context(), purposeState, q.Get("state"), &b) != nil || s.now().Unix() > b.Exp || !s.sameBrowser(r, b.Browser) {
		s.authPage(w, http.StatusBadRequest, "Sign-in expired", "This sign-in has expired or was started in another browser. Start again from your client.")
		return
	}
	s.clearCookie(w, cookieBrowser)
	req := &b.Req
	fail := func(code, desc string) {
		s.redirectError(w, r, req.RedirectURI, req.State, &authError{code, desc})
	}
	if e := q.Get("error"); e != "" {
		s.log.InfoContext(r.Context(), "authserver: Google sign-in returned an error", "error", e)
		fail("access_denied", "Google sign-in was cancelled or refused")
		return
	}
	ctx := r.Context()
	t, err := s.cfg.Google.exchange(ctx, s.google.hc, q.Get("code"), s.CallbackURL(), b.Verifier)
	if err != nil {
		s.log.WarnContext(ctx, "authserver: Google code exchange failed", "err", err)
		fail("server_error", "Google sign-in failed")
		return
	}
	u, err := s.cfg.Google.verifyIDToken(t.IDToken, s.now())
	if err != nil {
		s.log.WarnContext(ctx, "authserver: Google ID token refused", "err", err)
		fail("server_error", "Google sign-in failed")
		return
	}
	if err := s.cfg.Admit.Admit(ctx, u.Email, u.Domain); err != nil {
		if errors.Is(err, allow.ErrNotAdmitted) {
			s.log.InfoContext(ctx, "authserver: refused sign-in", "email", u.Email)
			fail("access_denied", "this account isn't allowed to use this server")
		} else {
			s.log.WarnContext(ctx, "authserver: could not check the allow-list", "email", u.Email, "err", err)
			fail("server_error", "couldn't check the allow-list")
		}
		return
	}
	g, c, err := s.cfg.Custody.begin(ctx, s.google, u, t, s.ContinueURL())
	if err != nil {
		s.log.WarnContext(ctx, "authserver: custody failed at sign-in", "custody", s.cfg.Custody.Name(), "email", u.Email, "err", err)
		fail(custodyError(err), grantFailed)
		return
	}
	if c != nil {
		s.toConsent(w, r, req, u, c)
		return
	}
	s.finishAuthorize(w, r, req, u, g)
}

// grantFailed is what the client hears when custody fails; the reason
// (which may quote Google's response) goes only to the log.
const grantFailed = "couldn't get a Google grant for this account (the server log has details)"

// custodyError is the OAuth error for a custody failure: access_denied for
// a grant only the user can repair (declined consent, another account's
// grant), server_error for Google or the vault failing, which a retry may
// fix. Google failing is not Google refusing.
func custodyError(err error) string {
	if errors.Is(err, errReauth) {
		return "access_denied"
	}
	return "server_error"
}

// toConsent parks the flow in a cookie and sends the browser to the
// vault's consent leg, which returns to ContinueURL.
func (s *Server) toConsent(w http.ResponseWriter, r *http.Request, req *authRequest, u User, c *consent) {
	p, err := s.seal(r.Context(), purposePending, pendingConsent{Req: *req, User: u, Consent: *c, Exp: s.now().Add(AuthRequestTTL).Unix()})
	if err != nil {
		s.log.ErrorContext(r.Context(), "authserver: seal pending consent", "err", err)
		s.redirectError(w, r, req.RedirectURI, req.State, &authError{"server_error", "couldn't start consent"})
		return
	}
	s.setCookie(w, cookieConsent, p)
	http.Redirect(w, r, c.URL, http.StatusSeeOther)
}

// handleConsentContinue is where the vault's consent leg returns.
func (s *Server) handleConsentContinue(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(s.cookieName(cookieConsent))
	var p pendingConsent
	if err != nil || s.open(r.Context(), purposePending, ck.Value, &p) != nil || s.now().Unix() > p.Exp {
		s.authPage(w, http.StatusBadRequest, "Sign-in expired", "This consent has expired or was started in another browser. Start again from your client.")
		return
	}
	s.clearCookie(w, cookieConsent)
	g, err := s.cfg.Custody.finish(r.Context(), s.google, p.User, p.Consent, r.URL.Query(), s.ContinueURL())
	if err != nil {
		s.log.WarnContext(r.Context(), "authserver: custody failed at consent", "custody", s.cfg.Custody.Name(), "email", p.User.Email, "err", err)
		s.redirectError(w, r, p.Req.RedirectURI, p.Req.State, &authError{custodyError(err), grantFailed})
		return
	}
	s.finishAuthorize(w, r, &p.Req, p.User, g)
}

// finishAuthorize issues the authorization code and returns the browser to
// the client.
func (s *Server) finishAuthorize(w http.ResponseWriter, r *http.Request, req *authRequest, u User, g *grant) {
	code, err := s.seal(r.Context(), purposeCode, codePayload{
		Req: *req, User: u,
		Token: g.AccessToken, TokenExp: g.Expiry.Unix(), GoogleScope: strings.Join(g.Scopes, " "), Secret: g.Secret,
		JTI: rand.Text(), Exp: s.now().Add(CodeTTL).Unix(),
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "authserver: seal authorization code", "err", err)
		s.redirectError(w, r, req.RedirectURI, req.State, &authError{"server_error", "couldn't issue a code"})
		return
	}
	s.log.InfoContext(r.Context(), "authserver: signed in", "email", u.Email, "client", clientLabel(req))
	redirectTo(w, r, req.RedirectURI, url.Values{"code": {code}, "state": {req.State}, "iss": {s.cfg.Issuer}})
}

func clientLabel(req *authRequest) string {
	if req.ClientName != "" {
		return req.ClientName
	}
	if seal.IsSealed(req.ClientID) {
		return "dynamically registered"
	}
	return req.ClientID
}

// bindBrowser sets a fresh random cookie and returns its hash, which the
// sealed flow state carries.
func (s *Server) bindBrowser(w http.ResponseWriter) string {
	v := rand.Text()
	s.setCookie(w, cookieBrowser, v)
	return hashCookie(v)
}

func (s *Server) sameBrowser(r *http.Request, want string) bool {
	ck, err := r.Cookie(s.cookieName(cookieBrowser))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashCookie(ck.Value)), []byte(want)) == 1
}

func hashCookie(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) cookiePath() string {
	if s.issuer.Path == "" {
		return "/"
	}
	return s.issuer.Path + "/"
}

// cookieName prefixes a flow cookie with __Host- where the browser allows
// it (https, Path=/), so a sibling subdomain cannot set or shadow it.
func (s *Server) cookieName(base string) string {
	if s.issuer.Scheme == "https" && s.issuer.Path == "" {
		return "__Host-" + base
	}
	return base
}

// setCookie sets a flow cookie. SameSite=Lax: it must ride the top-level
// redirects back from Google.
func (s *Server) setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure whenever the issuer is https; http only on loopback
		Name: s.cookieName(name), Value: value, Path: s.cookiePath(),
		MaxAge:   int(AuthRequestTTL.Seconds()),
		HttpOnly: true, Secure: s.issuer.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: as setCookie
		Name: s.cookieName(name), Value: "", Path: s.cookiePath(), MaxAge: -1,
		HttpOnly: true, Secure: s.issuer.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state string, e *authError) {
	v := url.Values{"error": {e.code}, "error_description": {cleanDesc(e.desc)}, "iss": {s.cfg.Issuer}}
	if state != "" {
		v.Set("state", state)
	}
	redirectTo(w, r, redirectURI, v)
}

func redirectTo(w http.ResponseWriter, r *http.Request, base string, params url.Values) {
	u, err := url.Parse(base)
	if err != nil {
		http.Error(w, "the redirect URI is malformed", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, vs := range params {
		if len(vs) > 0 && vs[0] != "" {
			q.Set(k, vs[0])
		}
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: base is a redirect URI checked against the client's registration
}

func pageHeaders(w http.ResponseWriter, code int) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(code)
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Service}}: {{.Title}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:34em;margin:4em auto;padding:0 1em;line-height:1.5}
.box{border:1px solid #ccc;border-radius:8px;padding:1em 1.5em}button{font-size:1em;padding:.5em 1.2em;margin-right:.5em}
code{background:#f3f3f3;padding:0 .3em}</style></head>
<body><div class="box"><h2>{{.Title}}</h2>
{{if .Form}}<p><b>{{.ClientName}}</b> wants to sign you in to <b>{{.Service}}</b>.</p>
<p>It will be able to use {{.Service}} <b>as you</b>, with the Google access you grant.</p>
<p>After sign-in you'll be sent back to <code>{{.RedirectHost}}</code>.</p>
<p>Only continue if you started this from your own client.</p>
<form method="post" action="authorize"><input type="hidden" name="request" value="{{.Form}}">
<button name="action" value="approve">Continue with Google</button><button name="action" value="deny">Cancel</button></form>
{{else}}<p>{{.Message}}</p>{{end}}</div></body></html>
`))

func (s *Server) authPage(w http.ResponseWriter, code int, title, msg string) {
	pageHeaders(w, code)
	_ = pageTmpl.Execute(w, map[string]string{"Service": s.cfg.ServiceName, "Title": title, "Message": msg})
}

func (s *Server) consentPage(w http.ResponseWriter, c *client, redirectURI, form string) {
	name := c.Name
	if name == "" {
		name = "An unnamed client"
	}
	if strings.HasPrefix(c.ID, "https://") {
		name += " (" + c.ID + ")"
	}
	host := redirectURI
	if u, err := url.Parse(redirectURI); err == nil && u.Host != "" {
		host = u.Scheme + "://" + u.Host
	}
	pageHeaders(w, http.StatusOK)
	_ = pageTmpl.Execute(w, map[string]string{"Service": s.cfg.ServiceName, "Title": "Sign in", "Form": form, "ClientName": name, "RedirectHost": host})
}
