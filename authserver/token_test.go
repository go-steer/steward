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

// Ported from kode-gopher internal/oauth token_test.go and e2e_test.go at
// 8b53617b7d4d0b08b158de64ab7416dc84a1281e.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// register is DCR for a public client redirecting to clientRedirect.
func (e *testEnv) register() string {
	e.t.Helper()
	resp, err := hc.Post(e.srv.URL+"/register", "application/json", strings.NewReader(`{"client_name":"t","redirect_uris":["`+clientRedirect+`"]}`))
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m struct {
		ClientID string `json:"client_id"`
	}
	if resp.StatusCode != http.StatusCreated || json.NewDecoder(resp.Body).Decode(&m) != nil {
		e.t.Fatalf("register: %s", resp.Status)
	}
	return m.ClientID
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeURL is a well-formed authorization request; set overrides or
// deletes (empty value) parameters.
func (e *testEnv) authorizeURL(clientID, verifier string, set map[string]string) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {clientRedirect},
		"code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"},
		"state": {"st"}, "resource": {e.as.Resource()}, "scope": {scopeRead},
	}
	for k, v := range set {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return e.srv.URL + "/authorize?" + q.Encode()
}

// codeWith signs in through a browser and returns the authorization code.
func (e *testEnv) codeWith(b *browser, clientID, verifier string, set map[string]string) string {
	e.t.Helper()
	loc, page := b.visit(e.authorizeURL(clientID, verifier, set))
	if loc == nil || loc.Query().Get("code") == "" {
		e.t.Fatalf("no code: redirect %v, page %q", loc, page)
	}
	if loc.Query().Get("state") != "st" || loc.Query().Get("iss") != e.srv.URL {
		e.t.Fatalf("redirect %v lacks state or iss", loc)
	}
	return loc.Query().Get("code")
}

func (e *testEnv) code(clientID, verifier string) string {
	return e.codeWith(newBrowser(e.t), clientID, verifier, nil)
}

type tokenResp struct {
	status  int
	header  http.Header
	Error   string `json:"error"`
	Desc    string `json:"error_description"`
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expires int64  `json:"expires_in"`
	Scope   string `json:"scope"`
}

func (e *testEnv) token(form url.Values, basicID, basicSecret string) tokenResp {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	r := tokenResp{status: resp.StatusCode, header: resp.Header}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	return r
}

func exchangeForm(clientID, code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"code_verifier": {verifier}, "redirect_uri": {clientRedirect}}
}

func refreshForm(clientID, rt string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {rt}}
}

// signIn runs the whole flow for a DCR client and returns its tokens.
func (e *testEnv) signIn(b *browser) (string, tokenResp) {
	e.t.Helper()
	id := e.register()
	v := rand.Text() + rand.Text()
	r := e.token(exchangeForm(id, e.codeWith(b, id, v, nil), v), "", "")
	if r.status != http.StatusOK {
		e.t.Fatalf("exchange: %+v", r)
	}
	return id, r
}

// whoamiFields checks the resource's "<identity> <kind> <scopes> <token>".
func whoamiFields(t *testing.T, got, identity, scopes string) {
	t.Helper()
	f := strings.Fields(got)
	if len(f) != 4 || f[0] != identity || f[1] != KindUser || f[2] != scopes || !strings.HasPrefix(f[3], "ya29.fake-") {
		t.Fatalf("whoami = %q, want %s user %s ya29.fake-...", got, identity, scopes)
	}
}

func TestE2EDCRVault(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	b := newBrowser(t)
	_, r := e.signIn(b)
	status, got, _ := e.call(r.Access)
	if status != http.StatusOK {
		t.Fatalf("resource: %d %s", status, got)
	}
	whoamiFields(t, got, alice.Email, scopeRead)
	if !b.sawPage {
		t.Error("a DCR client skipped the consent page")
	}
	if a := e.google.lastAuth; a.Get("access_type") == "offline" || strings.Contains(a.Get("scope"), ScopeCloudPlatform) {
		t.Errorf("vault custody sign-in asked Google for %q offline=%q; want identity only", a.Get("scope"), a.Get("access_type"))
	}
	if _, ok := e.vault.grantFor(alice.Sub); !ok {
		t.Error("vault holds no grant for alice after consent")
	}
}

func TestE2EPreregisteredSealed(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", Secret: "s3cret", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/callback"}}}
		c.OpenRegistration = false
	})
	e.google.signInAs = bob // admitted by group, not domain
	b := newBrowser(t)
	v := rand.Text() + rand.Text()
	code := e.codeWith(b, "cli", v, map[string]string{"scope": scopeRead + " " + scopeWrite + " openid"})
	r := e.token(exchangeForm("cli", code, v), "cli", "s3cret")
	if r.status != http.StatusOK || r.Scope != scopeRead+" "+scopeWrite {
		t.Fatalf("exchange: %+v", r)
	}
	_, got, _ := e.call(r.Access)
	whoamiFields(t, got, bob.Email, scopeRead+","+scopeWrite)
	if b.sawPage {
		t.Error("a pre-registered client got the consent page")
	}
	if a := e.google.lastAuth; a.Get("access_type") != "offline" || !strings.Contains(a.Get("scope"), ScopeCloudPlatform) {
		t.Errorf("sealed custody sign-in asked Google for %q offline=%q", a.Get("scope"), a.Get("access_type"))
	}
	// Closed registration: no DCR endpoint served.
	resp, err := hc.Post(e.srv.URL+"/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /register with closed registration = %d, want 404", resp.StatusCode)
	}
}

func TestE2ECIMD(t *testing.T) {
	t.Parallel()
	var docURL string
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"client_id": docURL, "client_name": "cimd-client", "redirect_uris": []string{clientRedirect},
			"token_endpoint_auth_method": "none",
		})
	}))
	t.Cleanup(doc.Close)
	docURL = doc.URL + "/client.json"
	e := newTestEnv(t, false, func(c *Config) { c.CIMDClient = doc.Client() })
	b := newBrowser(t)
	v := rand.Text() + rand.Text()
	r := e.token(exchangeForm(docURL, e.codeWith(b, docURL, v, nil), v), "", "")
	if r.status != http.StatusOK {
		t.Fatalf("exchange: %+v", r)
	}
	_, got, _ := e.call(r.Access)
	whoamiFields(t, got, alice.Email, scopeRead)
	if !b.sawPage {
		t.Error("a CIMD client skipped the consent page")
	}
}

func TestE2ENotAllowed(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	e.google.signInAs = mallory
	id := e.register()
	loc, _ := newBrowser(t).visit(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("sign-in by a user outside the allow-list: %v, want access_denied", loc)
	}
	if _, ok := e.vault.grantFor(mallory.Sub); ok {
		t.Error("a refused user reached the vault")
	}
	if !strings.Contains(e.log.String(), "refused sign-in") {
		t.Errorf("refusal not logged: %s", e.log.String())
	}
}

func TestE2EAllowListUnavailable(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	e.google.signInAs = bob // needs the group check
	e.groups.failNext = 1
	id := e.register()
	loc, _ := newBrowser(t).visit(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "server_error" {
		t.Fatalf("sign-in during a directory outage: %v, want server_error", loc)
	}
}

func TestE2EConsentDenied(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	b := newBrowser(t)
	b.deny = true
	id := e.register()
	loc, _ := b.visit(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "st" {
		t.Fatalf("declined consent: %v, want access_denied", loc)
	}
}

func TestE2EGoogleDenied(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id := e.register()
	b := newBrowser(t)
	resp, err := b.hc.Get(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := hiddenRequestRE.FindSubmatch(body)
	if m == nil {
		t.Fatal("no consent form")
	}
	b.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err = b.hc.PostForm(e.srv.URL+"/authorize", url.Values{"request": {html.UnescapeString(string(m[1]))}, "action": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	toGoogle, _ := url.Parse(resp.Header.Get("Location"))
	// The user cancels at Google: Google returns error=access_denied.
	cb := e.as.CallbackURL() + "?" + url.Values{"state": {toGoogle.Query().Get("state")}, "error": {"access_denied"}}.Encode()
	resp, err = b.hc.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc == nil || loc.Query().Get("error") != "access_denied" {
		t.Errorf("Google cancel: %v, want access_denied to the client", loc)
	}
}

func TestE2EVaultWrongAccount(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	e.vault.consentAs = bob // alice signs in but consents as bob
	id := e.register()
	loc, _ := newBrowser(t).visit(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("sign-in with another account's Google grant: %v, want access_denied", loc)
	}
	if !strings.Contains(e.log.String(), "different account") {
		t.Errorf("reason not logged: %s", e.log.String())
	}
}

func TestCodeExchange(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id := e.register()
	verifier := rand.Text() + rand.Text()
	code := e.code(id, verifier)
	other := e.register()

	bad := []struct {
		name string
		edit func(url.Values)
		want string
	}{
		{"no verifier", func(f url.Values) { f.Del("code_verifier") }, "invalid_grant"},
		{"wrong verifier", func(f url.Values) { f.Set("code_verifier", rand.Text()+rand.Text()) }, "invalid_grant"},
		{"plain verifier", func(f url.Values) { f.Set("code_verifier", challengeFor(verifier)) }, "invalid_grant"},
		{"other redirect", func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:2/callback") }, "invalid_grant"},
		{"other resource", func(f url.Values) { f.Set("resource", "https://evil.example/mcp") }, "invalid_target"},
		{"other client", func(f url.Values) { f.Set("client_id", other) }, "invalid_grant"},
		{"unknown client", func(f url.Values) { f.Set("client_id", "nope") }, "invalid_client"},
		{"garbage code", func(f url.Values) { f.Set("code", "st1.k1.AAAA") }, "invalid_grant"},
		{"access token as code", func(f url.Values) { f.Set("code", "not-a-code") }, "invalid_grant"},
		{"bad grant type", func(f url.Values) { f.Set("grant_type", "password") }, "unsupported_grant_type"},
		{"no client", func(f url.Values) { f.Del("client_id") }, "invalid_client"},
	}
	for _, tc := range bad {
		f := exchangeForm(id, code, verifier)
		tc.edit(f)
		if r := e.token(f, "", ""); r.Error != tc.want || r.Access != "" {
			t.Errorf("%s: error %q (HTTP %d), want %s", tc.name, r.Error, r.status, tc.want)
		}
	}

	// Failed attempts don't spend the code; the right one does.
	r := e.token(exchangeForm(id, code, verifier), "", "")
	if r.status != http.StatusOK || r.Access == "" || r.Refresh == "" || r.Scope != scopeRead {
		t.Fatalf("exchange: %+v", r)
	}
	if r.Expires <= 0 || r.Expires > int64(AccessTTL.Seconds()) {
		t.Errorf("expires_in = %d", r.Expires)
	}
	if r := e.token(exchangeForm(id, code, verifier), "", ""); r.Error != "invalid_grant" {
		t.Errorf("reused code: error %q, want invalid_grant", r.Error)
	}
	if !strings.Contains(e.log.String(), "authorization code reused") {
		t.Error("code reuse not logged")
	}
}

func TestCodeExpires(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id := e.register()
	v := rand.Text() + rand.Text()
	code := e.code(id, v)
	e.as.now = func() time.Time { return time.Now().Add(CodeTTL + time.Second) }
	if r := e.token(exchangeForm(id, code, v), "", ""); r.Error != "invalid_grant" || !strings.Contains(r.Desc, "expired") {
		t.Errorf("expired code: %+v", r)
	}
}

func TestConfidentialClient(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli:1", Secret: "s/3+cret", RedirectURIs: []string{clientRedirect}}}
	})
	verifier := rand.Text() + rand.Text()
	code := e.code("cli:1", verifier)
	f := exchangeForm("", code, verifier)
	f.Del("client_id")
	if r := e.token(f, "cli:1", "wrong"); r.status != http.StatusUnauthorized || r.Error != "invalid_client" || r.header.Get("WWW-Authenticate") == "" {
		t.Errorf("wrong Basic secret: %d %q, WWW-Authenticate %q", r.status, r.Error, r.header.Get("WWW-Authenticate"))
	}
	f2 := exchangeForm("cli:1", code, verifier)
	if r := e.token(f2, "", ""); r.Error != "invalid_client" {
		t.Errorf("no secret: error %q, want invalid_client", r.Error)
	}
	// Basic credentials are form-encoded (RFC 6749 section 2.3.1).
	if r := e.token(f, "cli:1", "s/3+cret"); r.status != http.StatusOK {
		t.Fatalf("Basic auth exchange: %d %q", r.status, r.Error)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, func(c *Config) {
		c.Clients = []StaticClient{{ID: "narrow", RedirectURIs: []string{clientRedirect}, Scopes: []string{scopeWrite}}}
		c.DefaultScopes = []string{scopeRead}
	})
	id := e.register()
	v := rand.Text() + rand.Text()
	redirects := []struct {
		name   string
		client string
		set    map[string]string
		want   string
	}{
		{"plain PKCE", id, map[string]string{"code_challenge_method": "plain", "code_challenge": v}, "invalid_request"},
		{"no PKCE", id, map[string]string{"code_challenge_method": "", "code_challenge": ""}, "invalid_request"},
		{"token response", id, map[string]string{"response_type": "token"}, "unsupported_response_type"},
		{"other resource", id, map[string]string{"resource": "https://evil.example/mcp"}, "invalid_target"},
		// The client may only have svc:write, and asks for nothing it may
		// have; the default (svc:read) is not its either.
		{"no scope available", "narrow", map[string]string{"scope": scopeRead}, "invalid_scope"},
	}
	for _, tc := range redirects {
		loc, page := newBrowser(t).visit(e.authorizeURL(tc.client, v, tc.set))
		if loc == nil || loc.Query().Get("error") != tc.want || loc.Query().Get("state") != "st" || loc.Query().Get("iss") != e.srv.URL {
			t.Errorf("%s: redirect %v page %q, want error=%s", tc.name, loc, page, tc.want)
		}
	}
	// Two resource parameters are refused (RFC 8707 allows several; one
	// resource is served here).
	u := e.authorizeURL(id, v, nil) + "&resource=" + url.QueryEscape(e.as.Resource())
	if loc, _ := newBrowser(t).visit(u); loc == nil || loc.Query().Get("error") != "invalid_target" {
		t.Errorf("two resources: %v, want invalid_target", loc)
	}
	// Without a trustworthy redirect, errors stay on the server's page.
	pages := []map[string]string{
		{"client_id": "unknown"},
		{"redirect_uri": "https://evil.example/cb"},
	}
	for _, set := range pages {
		resp, err := hc.Get(e.authorizeURL(id, v, set))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%v: HTTP %d, Location %q; want an error page", set, resp.StatusCode, resp.Header.Get("Location"))
		}
		if strings.Contains(string(body), "<script") {
			t.Errorf("%v: page has a script", set)
		}
	}
	// A loopback redirect may use any port.
	loc, _ := newBrowser(t).visit(e.authorizeURL(id, v, map[string]string{"redirect_uri": "http://127.0.0.1:1/callback"}))
	if loc == nil || loc.Query().Get("code") == "" {
		t.Errorf("loopback redirect on another port refused: %v", loc)
	}
	// No redirect_uri with exactly one registered: that one is used.
	loc, _ = newBrowser(t).visit(e.authorizeURL(id, v, map[string]string{"redirect_uri": ""}))
	if loc == nil || loc.Query().Get("code") == "" {
		t.Errorf("implicit single redirect refused: %v", loc)
	}
}

// The consent form only works in the browser that loaded it.
func TestConsentForgery(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id := e.register()
	resp, err := hc.Get(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := hiddenRequestRE.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatal("no consent form")
	}
	// The victim's browser has no binding cookie for this request.
	resp, err = hc.PostForm(e.srv.URL+"/authorize", url.Values{"request": {html.UnescapeString(m[1])}, "action": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("consent without the binding cookie: HTTP %d, want 400", resp.StatusCode)
	}
	// Nor does a callback carrying someone else's state.
	resp, err = hc.Get(e.as.CallbackURL() + "?state=st1.k1.AAAA&code=x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback with a forged state: HTTP %d, want 400", resp.StatusCode)
	}
	resp, err = hc.Get(e.as.ContinueURL() + "?user_id_validation_state=x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("consent continue without the pending cookie: HTTP %d, want 400", resp.StatusCode)
	}
}

func TestRefresh(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	e.google.signInAs = bob
	id, first := e.signIn(newBrowser(t))
	other := refreshForm(e.register(), first.Refresh)
	if r := e.token(other, "", ""); r.Error != "invalid_grant" {
		t.Errorf("refresh by another client: %q", r.Error)
	}
	wrongRes := refreshForm(id, first.Refresh)
	wrongRes.Set("resource", "https://evil.example/mcp")
	if r := e.token(wrongRes, "", ""); r.Error != "invalid_target" {
		t.Errorf("refresh for another resource: %q", r.Error)
	}
	widen := refreshForm(id, first.Refresh)
	widen.Set("scope", scopeWrite)
	if r := e.token(widen, "", ""); r.Error != "invalid_scope" {
		t.Errorf("refresh widening the scope: %q", r.Error)
	}

	second := e.token(refreshForm(id, first.Refresh), "", "")
	if second.status != http.StatusOK || second.Access == "" || second.Refresh == first.Refresh || second.Scope != scopeRead {
		t.Fatalf("refresh: %+v", second)
	}
	if status, got, _ := e.call(second.Access); status != http.StatusOK {
		t.Errorf("refreshed access token refused: %d %s", status, got)
	}
	third := e.token(refreshForm(id, second.Refresh), "", "")
	if third.status != http.StatusOK {
		t.Fatalf("second refresh: %+v", third)
	}
	// Reusing a rotated refresh token revokes its whole family (OAuth 2.1
	// section 4.3.1): the newest token in it stops working too.
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("reused refresh token: %q, want invalid_grant", r.Error)
	}
	if r := e.token(refreshForm(id, third.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("newest refresh token after a reuse revoked its family: %q, want invalid_grant", r.Error)
	}

	// Removed from the group: refused once the cached decision ages out.
	id2, fresh := e.signIn(newBrowser(t))
	e.groups.remove("kg-users@example.com", bob.Email)
	e.as.cfg.Admit = newAdmitter(t, e.groups)
	if r := e.token(refreshForm(id2, fresh.Refresh), "", ""); r.Error != "invalid_grant" || !strings.Contains(r.Desc, "allowed") {
		t.Errorf("refresh after removal from the allow-list: %+v", r)
	}
	// The refusal keeps the token spent: restoring the membership does not
	// revive it.
	e.groups.mu.Lock()
	e.groups.members["kg-users@example.com"][bob.Email] = true
	e.groups.mu.Unlock()
	e.as.cfg.Admit = newAdmitter(t, e.groups)
	if r := e.token(refreshForm(id2, fresh.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("refused refresh token used again: %+v", r)
	}
}

func TestRefreshNarrows(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) { c.DefaultScopes = nil })
	id, first := e.signIn(newBrowser(t))
	if first.Scope != scopeRead {
		t.Fatalf("granted %q", first.Scope)
	}
	n := refreshForm(id, first.Refresh)
	n.Set("scope", scopeRead+" "+scopeRead)
	if r := e.token(n, "", ""); r.status != http.StatusOK || r.Scope != scopeRead {
		t.Errorf("refresh with the same scope: %+v", r)
	}
}

func TestRefreshExpires(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id, first := e.signIn(newBrowser(t))
	e.as.now = func() time.Time { return time.Now().Add(RefreshTTL + time.Minute) }
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" || !strings.Contains(r.Desc, "expired") {
		t.Errorf("expired refresh token: %+v", r)
	}
}

func TestRefreshRevoked(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	e.google.revoked[alice.Sub] = true
	e.google.mu.Unlock()
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("refresh after Google revoked the grant: %q (HTTP %d), want invalid_grant", r.Error, r.status)
	}
}

func TestVaultRefresh(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id, first := e.signIn(newBrowser(t))
	second := e.token(refreshForm(id, first.Refresh), "", "")
	if second.status != http.StatusOK {
		t.Fatalf("vault refresh: %+v", second)
	}
	// A vault outage at refresh is transient: server_error, and the
	// refresh token survives for the retry.
	e.vault.mu.Lock()
	e.vault.failNext = 1
	e.vault.mu.Unlock()
	if r := e.token(refreshForm(id, second.Refresh), "", ""); r.Error != "server_error" || r.status != http.StatusInternalServerError {
		t.Fatalf("refresh during a vault outage: %+v", r)
	}
	if r := e.token(refreshForm(id, second.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry after the outage: %+v", r)
	}
}

func TestVaultRefreshesShortToken(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id := e.register()
	v := rand.Text() + rand.Text()
	e.code(id, v) // consent stores the grant
	e.vault.mu.Lock()
	e.vault.shortLife = true
	e.vault.mu.Unlock()
	r := e.token(exchangeForm(id, e.code(id, v), v), "", "")
	if r.status != http.StatusOK {
		t.Fatalf("exchange: %+v", r)
	}
	if e.vault.forced != 1 {
		t.Errorf("vault force-refreshes = %d, want 1 for a nearly spent token", e.vault.forced)
	}
	if r.Expires < int64((AccessTTL - time.Minute).Seconds()) {
		t.Errorf("expires_in = %d after force refresh", r.Expires)
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	ctx := context.Background()
	seal := func(p accessPayload) string {
		s, err := e.as.seal(ctx, purposeAccess, p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Now()
	good := accessPayload{Sub: "1", Email: "a@example.com", HD: "example.com", ClientID: "c", Aud: e.as.Resource(), Scope: scopeRead,
		Token: "ya29.x", TokenExp: now.Add(time.Hour).Unix(), GoogleScope: ScopeCloudPlatform, Exp: now.Add(time.Minute).Unix()}
	expired, otherAud, noSub, noEmail, noToken, oddMode := good, good, good, good, good, good
	expired.Exp = now.Add(-time.Minute).Unix()
	otherAud.Aud = "https://other.example/mcp"
	noSub.Sub = ""
	noEmail.Email = ""
	noToken.Token = ""
	oddMode.Mode = "admin"
	refresh, _ := e.as.seal(ctx, purposeRefresh, refreshPayload{Aud: e.as.Resource(), Exp: now.Add(time.Hour).Unix()})
	otherIssuer, _ := testKeys.Seal("https://elsewhere.example#access", good)

	p, err := e.as.Verify(ctx, seal(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "1" || p.Email != "a@example.com" || p.HD != "example.com" || p.ClientID != "c" || !p.HasScope(scopeRead) || p.HasScope(scopeWrite) || p.Workload || len(p.GoogleScopes) != 1 {
		t.Errorf("Principal = %+v", p)
	}
	ts, ok := p.TokenSource()
	if tok, _ := ts.Token(); !ok || tok.AccessToken != "ya29.x" {
		t.Errorf("TokenSource = %v, %v", tok, ok)
	}
	c := p.Caller()
	if c.Identity != "a@example.com" || c.Label(LabelSubject) != "1" || c.Label(LabelHD) != "example.com" || c.Label(LabelKind) != KindUser || c.Label(LabelScope) != scopeRead || c.Label(LabelClientID) != "c" {
		t.Errorf("Caller = %+v", c)
	}
	for name, tok := range map[string]string{
		"garbage": "abc", "a Google token": "ya29.abc", "expired": seal(expired), "other audience": seal(otherAud),
		"no subject": seal(noSub), "no email": seal(noEmail), "no Google token": seal(noToken), "unknown mode": seal(oddMode),
		"refresh token as access": refresh, "another issuer's": otherIssuer,
	} {
		if _, err := e.as.Verify(ctx, tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v, want ErrInvalidToken", name, err)
		}
	}
}

// Through purser's enforced middleware, every refused token is a 401.
func TestProtectedResource(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	for name, tok := range map[string]string{"none": "", "garbage": "abc", "a Google token": "ya29.abc"} {
		if status, _, h := e.call(tok); status != http.StatusUnauthorized || h.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d, challenge %q", name, status, h.Get("WWW-Authenticate"))
		}
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	get := func(path string) map[string]any {
		resp, err := hc.Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: no CORS", path)
		}
		return m
	}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		m := get(p)
		if m["issuer"] != e.srv.URL || m["registration_endpoint"] != e.srv.URL+"/register" || m["client_id_metadata_document_supported"] != true ||
			m["token_endpoint"] != e.srv.URL+"/token" || m["authorization_endpoint"] != e.srv.URL+"/authorize" {
			t.Errorf("%s: %v", p, m)
		}
		if got, _ := json.Marshal(m["code_challenge_methods_supported"]); string(got) != `["S256"]` {
			t.Errorf("%s: code_challenge_methods_supported = %s", p, got)
		}
		if got, _ := json.Marshal(m["scopes_supported"]); string(got) != `["svc:read","svc:write"]` {
			t.Errorf("%s: scopes_supported = %s", p, got)
		}
	}
	if e.as.MetadataURL() != e.srv.URL+"/.well-known/oauth-authorization-server" {
		t.Errorf("MetadataURL = %s", e.as.MetadataURL())
	}
	req, _ := http.NewRequest(http.MethodOptions, e.srv.URL+"/token", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("CORS preflight on /token: %d", resp.StatusCode)
	}
	for _, m := range []struct{ method, path string }{{http.MethodPost, "/.well-known/oauth-authorization-server"}, {http.MethodGet, "/token"}, {http.MethodGet, "/register"}} {
		req, _ := http.NewRequest(m.method, e.srv.URL+m.path, nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d, want 405", m.method, m.path, resp.StatusCode)
		}
	}
}

// A transient allow-list failure during refresh must not spend the refresh
// token: the client retries with the same one and succeeds.
func TestRefreshSurvivesTransientAllowListError(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	e.google.signInAs = bob
	id, first := e.signIn(newBrowser(t))
	form := refreshForm(id, first.Refresh)

	e.as.cfg.Admit = newAdmitter(t, e.groups) // force a group check
	e.groups.mu.Lock()
	e.groups.failNext = 1
	e.groups.mu.Unlock()
	if r := e.token(form, "", ""); r.Error != "server_error" {
		t.Fatalf("refresh during a directory outage: %q, want server_error", r.Error)
	}
	if r := e.token(form, "", ""); r.status != http.StatusOK || r.Access == "" {
		t.Errorf("retry with the same refresh token: %+v, want new tokens", r)
	}
	if r := e.token(form, "", ""); r.Error != "invalid_grant" {
		t.Errorf("third use after a successful refresh: %q, want invalid_grant", r.Error)
	}
}

// Vault grants only the user can repair are errReauth (a refresh says
// invalid_grant: sign in again), not transient (server_error: retry).
func TestPermanentVaultErrorsAreReauth(t *testing.T) {
	t.Parallel()
	for _, e := range []error{
		reauthError("vault: the user declined consent"),
		reauthError("vault: token lacks a configured Google scope"),
	} {
		if !errors.Is(e, errReauth) {
			t.Errorf("%v doesn't match errReauth", e)
		}
	}
	if errors.Is(errors.New("vault retrieve: HTTP 503"), errReauth) {
		t.Error("a transient vault error matches errReauth")
	}
}

// The Google token sealed inside steward's tokens never reaches a log, an
// error description or a response other than the resource's own.
func TestGoogleTokenNeverLeaks(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id, first := e.signIn(newBrowser(t))
	_ = e.token(refreshForm(id, first.Refresh), "", "")
	_ = e.token(refreshForm(id, first.Refresh), "", "") // a reuse, logged
	e.google.mu.Lock()
	minted := append([]string(nil), e.google.minted...)
	var refresh []string
	for rt := range e.google.refresh {
		refresh = append(refresh, rt)
	}
	e.google.mu.Unlock()
	if len(minted) == 0 || len(refresh) == 0 {
		t.Fatal("no Google tokens minted")
	}
	p, err := e.as.Verify(context.Background(), first.Access)
	if err != nil {
		t.Fatal(err)
	}
	printed := strings.Join([]string{e.log.String(), first.Access, first.Refresh, fmtAll(p)}, "\n")
	for _, secret := range append(minted, refresh...) {
		if strings.Contains(printed, secret) {
			t.Errorf("a Google token appears in logs, steward's tokens or a formatted Principal")
		}
	}
}
