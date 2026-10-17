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

// Regression tests for the adversarial review of the authorization server.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-steer/steward/seal"
)

// Narrowing a client's scopes takes effect at its users' next refresh, and
// at once for the scopes a live access token reports.
func TestScopesNarrowedByConfig(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
	})
	v := rand.Text() + rand.Text()
	code := e.codeWith(newBrowser(t), "cli", v, map[string]string{"scope": scopeRead + " " + scopeWrite})
	first := e.token(exchangeForm("cli", code, v), "", "")
	if first.Scope != scopeRead+" "+scopeWrite {
		t.Fatalf("granted %q", first.Scope)
	}
	e.as.static["cli"] = StaticClient{ID: "cli", RedirectURIs: []string{clientRedirect}, Scopes: []string{scopeRead}}
	p, err := e.as.Verify(context.Background(), first.Access)
	if err != nil || p.HasScope(scopeWrite) || !p.HasScope(scopeRead) {
		t.Errorf("live access token after narrowing: %v %v", p.Scopes, err)
	}
	second := e.token(refreshForm("cli", first.Refresh), "", "")
	if second.status != http.StatusOK || second.Scope != scopeRead {
		t.Errorf("refresh after narrowing: %+v, want scope %s", second, scopeRead)
	}
	e.as.static["cli"] = StaticClient{ID: "cli", RedirectURIs: []string{clientRedirect}, Scopes: []string{scopeWrite}}
	if r := e.token(refreshForm("cli", second.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("refresh with none of its scopes left: %+v", r)
	}
}

// A refresh may narrow the access token, but the new refresh token keeps
// the whole grant (RFC 6749 section 6).
func TestRefreshNarrowingIsNotPermanent(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
	})
	v := rand.Text() + rand.Text()
	code := e.codeWith(newBrowser(t), "cli", v, map[string]string{"scope": scopeRead + " " + scopeWrite})
	first := e.token(exchangeForm("cli", code, v), "", "")
	narrow := refreshForm("cli", first.Refresh)
	narrow.Set("scope", scopeRead)
	second := e.token(narrow, "", "")
	if second.status != http.StatusOK || second.Scope != scopeRead {
		t.Fatalf("narrowing refresh: %+v", second)
	}
	if p := mustClaim(t, e, second.Access); p.HasScope(scopeWrite) {
		t.Error("the narrowed access token has svc:write")
	}
	if r := e.token(refreshForm("cli", second.Refresh), "", ""); r.status != http.StatusOK || r.Scope != scopeRead+" "+scopeWrite {
		t.Errorf("refresh after a narrowing refresh: %+v, want the whole grant back", r)
	}
}

// Rotating a workload's secret revokes the tokens minted with the old one.
func TestClientCredentialsSecretRotationRevokes(t *testing.T) {
	t.Parallel()
	e, _ := newServiceEnv(t)
	r := e.token(ccForm(nil), "bot", "bot-secret")
	e.as.static["bot"] = StaticClient{ID: "bot", Secret: "rotated", ClientCredentials: true}
	if _, err := e.as.Verify(context.Background(), r.Access); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token minted with the old secret: %v, want ErrInvalidToken", err)
	}
}

// A CIMD fetch error, which may quote the client-supplied document or a
// dial error naming an internal address, reaches only the log.
func TestCIMDErrorsNotEchoed(t *testing.T) {
	t.Parallel()
	const planted = "Sign in again at https://evil.example/login"
	var docURL string
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"client_id": docURL, "redirect_uris": []string{clientRedirect}, "token_endpoint_auth_method": planted})
	}))
	t.Cleanup(doc.Close)
	docURL = doc.URL + "/c.json"
	e := newTestEnv(t, false, func(c *Config) { c.CIMDClient = doc.Client() })
	resp, err := hc.Get(e.authorizeURL(docURL, rand.Text()+rand.Text(), nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "evil.example") {
		t.Errorf("authorize page: %d, echoes the document: %v", resp.StatusCode, strings.Contains(string(body), "evil.example"))
	}
	r := e.token(exchangeForm(docURL, "x", "v"), "", "")
	if r.Error != "invalid_client" || strings.Contains(r.Desc, "evil") {
		t.Errorf("token endpoint: %+v", r)
	}
	if !strings.Contains(e.log.String(), "evil.example") {
		t.Error("the reason did not reach the log")
	}
}

func TestRefusalDoesNotNameTheAccount(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	e.google.signInAs = mallory
	loc, _ := newBrowser(t).visit(e.authorizeURL(e.register(), rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "access_denied" || strings.Contains(loc.String(), "mallory") {
		t.Errorf("refusal redirect %v names the account", loc)
	}
}

// A vault outage at sign-in is Google failing, not refusing: server_error.
func TestCallbackCustodyOutageIsServerError(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	e.vault.mu.Lock()
	e.vault.failNext = 1
	e.vault.mu.Unlock()
	loc, _ := newBrowser(t).visit(e.authorizeURL(e.register(), rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "server_error" {
		t.Errorf("vault outage at sign-in: %v, want server_error", loc)
	}
}

// Google cancelling at sign-in reaches the client as access_denied with a
// fixed description, not Google's raw value.
func TestGoogleErrorNotEchoed(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
	})
	b := newBrowser(t)
	b.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := b.hc.Get(e.authorizeURL("cli", rand.Text()+rand.Text(), nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	toGoogle, _ := url.Parse(resp.Header.Get("Location"))
	cb := e.as.CallbackURL() + "?" + url.Values{"state": {toGoogle.Query().Get("state")}, "error": {`"><script>x</script>`}}.Encode()
	resp, err = b.hc.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc == nil || loc.Query().Get("error") != "access_denied" || strings.Contains(loc.Query().Get("error_description"), "script") {
		t.Errorf("Google error: %v", loc)
	}
}

func TestTokenEndpointStrictness(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id := e.register()
	v := rand.Text() + rand.Text()
	code := e.code(id, v)
	f := exchangeForm(id, code, v)
	f["resource"] = []string{e.as.Resource(), e.as.Resource()}
	if r := e.token(f, "", ""); r.Error != "invalid_target" {
		t.Errorf("two resources at exchange: %+v", r)
	}
	for _, bad := range []string{strings.Repeat("v", 42), strings.Repeat("v", 129), strings.Repeat("v", 42) + "!", strings.Repeat("v", 42) + " "} {
		if pkceMatches(bad, challengeFor(bad)) {
			t.Errorf("verifier %q accepted", bad)
		}
	}
	if !pkceMatches(v, challengeFor(v)) || !pkceMatches(strings.Repeat("a.b_c~d-", 6), challengeFor(strings.Repeat("a.b_c~d-", 6))) {
		t.Error("a valid verifier refused")
	}
	r := e.token(exchangeForm(id, code, v), "", "")
	rf := refreshForm(id, r.Refresh)
	rf["resource"] = []string{e.as.Resource(), "https://evil.example/mcp"}
	if r := e.token(rf, "", ""); r.Error != "invalid_target" {
		t.Errorf("two resources at refresh: %+v", r)
	}
	if !secretMatches("s", "s") || secretMatches("s", "S") || secretMatches("", "s") {
		t.Error("secretMatches")
	}
}

func TestCleanDesc(t *testing.T) {
	t.Parallel()
	if got := cleanDesc("a \"b\" \\c\n\x7fé"); got != "a 'b' ?c????" {
		t.Errorf("cleanDesc = %q", got)
	}
}

func TestIsPublicSpecialRanges(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:a9fe:a9fe::1", "2001:0:4136:e378::1", "192.0.0.8", "198.18.0.1", "192.88.99.1", "240.0.0.1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Errorf("isPublic(%s) = true", a)
		}
	}
}

func TestCookieNames(t *testing.T) {
	t.Parallel()
	for issuer, want := range map[string]string{
		"https://svc.example.com":       "__Host-steward_auth",
		"https://svc.example.com/oauth": "steward_auth",
		"http://127.0.0.1:8080":         "steward_auth",
	} {
		c := goodConfig(t)
		c.Issuer = issuer
		if strings.HasPrefix(issuer, "http:") {
			c.Resource = "http://127.0.0.1:8080/mcp"
		}
		s, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.setCookie(rec, cookieBrowser, "v")
		if got := rec.Result().Cookies()[0].Name; got != want {
			t.Errorf("%s: cookie %q, want %q", issuer, got, want)
		}
	}
}

func TestNewRefusesUnsafeEndpoints(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(*Config){
		"http token URL":       func(c *Config) { c.Google.TokenURL = "http://oauth2.example/token" },
		"http tokeninfo URL":   func(c *Config) { c.Google.TokenInfoURL = "http://oauth2.example/tokeninfo" },
		"relative auth URL":    func(c *Config) { c.Google.AuthURL = "/auth" },
		"vault without client": func(c *Config) { c.Custody = &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/a"} },
		"nil vault":            func(c *Config) { var v *VaultCustody; c.Custody = v },
		"bad auth provider":    func(c *Config) { c.Custody = &VaultCustody{AuthProvider: "a/b", Client: hc} },
		"http vault endpoint": func(c *Config) {
			c.Custody = &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/a", Client: hc, Endpoint: "http://vault.example/v1/"}
		},
		"issuer with braces":  func(c *Config) { c.Issuer = "https://svc.example.com/{x}" },
		"issuer with escapes": func(c *Config) { c.Issuer = "https://svc.example.com/a%2Fb" },
	} {
		c := goodConfig(t)
		edit(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := goodConfig(t)
	c.Custody = &VaultCustody{AuthProvider: "projects/p/locations/us-central1/authProviders/a", Client: hc, Endpoint: "https://vault.example/v1/"}
	if _, err := New(c); err != nil {
		t.Errorf("a well-formed vault custody refused: %v", err)
	}
}

// An account renamed since sign-in must sign in again.
func TestIdentityChangeAtRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	renamed := map[string]string{"tokA": `{"sub":"111","email":"alice.new@example.com","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"3600"}`}
	v, g, _ := newScripted(t, renamed, tokA)
	if _, err := v.refresh(ctx, g, alice, "", ""); !errors.Is(err, errReauth) {
		t.Errorf("vault token for a renamed account: %v, want reauth", err)
	}
	same := map[string]string{"tokA": `{"sub":"111","email":"Alice@Example.com","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"3600"}`}
	v, g, _ = newScripted(t, same, tokA)
	if _, err := v.refresh(ctx, g, alice, "", ""); err != nil {
		t.Errorf("vault token, same email in another case: %v", err)
	}

	idTok := func(email string) string {
		b, _ := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "aud": testGoogleID, "sub": "111", "email": email, "hd": "example.com", "email_verified": true, "exp": 4102444800})
		return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	}
	for email, wantReauth := range map[string]bool{"alice.new@example.com": true, "alice@example.com": false} {
		body, _ := json.Marshal(map[string]any{"access_token": "a", "expires_in": 3600, "id_token": idTok(email)})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
		g := &upstream{client: &GoogleClient{ClientID: testGoogleID, TokenURL: srv.URL}, hc: srv.Client(), scopes: []string{ScopeCloudPlatform}}
		_, err := SealedCustody{}.refresh(ctx, g, alice, "r1", "")
		srv.Close()
		if errors.Is(err, errReauth) != wantReauth {
			t.Errorf("sealed refresh, ID token for %s: %v, reauth want %v", email, err, wantReauth)
		}
	}
}

// noRedirect is a browser that stops at every redirect, so a test sees the
// server's own answer.
func noRedirect(b *browser) *browser {
	b.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return b
}

// The consent form and Google's callback work only in the browser that
// started the flow.
func TestBrowserBinding(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id := e.register()
	a := noRedirect(newBrowser(t))
	resp, err := a.hc.Get(e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := hiddenRequestRE.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatal("no consent form")
	}
	form := url.Values{"request": {strings.ReplaceAll(m[1], "&#43;", "+")}, "action": {"approve"}}
	// Browser B, with a binding cookie of its own from its own flow.
	b := noRedirect(newBrowser(t))
	if resp, err := b.hc.Get(e.authorizeURL(id, rand.Text()+rand.Text(), nil)); err == nil {
		_ = resp.Body.Close()
	}
	for name, br := range map[string]*browser{"another browser": b, "no cookie": noRedirect(newBrowser(t))} {
		resp, err := br.hc.PostForm(e.srv.URL+"/authorize", form)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("consent from %s: %d %q, want a 400 page", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// Browser A approves and is sent to Google with a valid state.
	resp, err = a.hc.PostForm(e.srv.URL+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	toGoogle, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || toGoogle.Query().Get("state") == "" {
		t.Fatalf("approval: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Google signs A in; the callback carrying A's state and code is
	// replayed in browser B.
	resp, err = a.hc.Get(toGoogle.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	callback := resp.Header.Get("Location")
	resp, err = b.hc.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Errorf("A's callback in browser B: %d %q, want a 400 page", resp.StatusCode, resp.Header.Get("Location"))
	}
	// In A it completes.
	resp, err = a.hc.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc == nil || loc.Query().Get("code") == "" {
		t.Errorf("A's callback in A: %d %v", resp.StatusCode, loc)
	}
}

// A refresh token bound to another resource is refused, even sealed by
// this server.
func TestRefreshForAnotherResource(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id := e.register()
	rt, err := e.as.seal(context.Background(), purposeRefresh, refreshPayload{
		User: alice, ClientID: id, Aud: "https://elsewhere.example/mcp", Scope: scopeRead, Secret: "1//x", Family: "f", Exp: 4102444800,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.token(refreshForm(id, rt), "", ""); r.Error != "invalid_grant" {
		t.Errorf("refresh token for another resource: %+v", r)
	}
	noFamily, _ := e.as.seal(context.Background(), purposeRefresh, refreshPayload{User: alice, ClientID: id, Aud: e.as.Resource(), Scope: scopeRead, Exp: 4102444800})
	if r := e.token(refreshForm(id, noFamily), "", ""); r.Error != "invalid_grant" {
		t.Errorf("refresh token without a family: %+v", r)
	}
}

// The issuer is bound into every seal: a server at another issuer with the
// same keys and resource cannot mint tokens this one accepts.
func TestIssuerBoundIntoSeals(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	cfg := goodConfig(t)
	cfg.Issuer, cfg.Resource = "http://localhost:1", e.as.Resource()
	other, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := other.seal(context.Background(), purposeAccess, accessPayload{Sub: "1", Email: "a@example.com", ClientID: "https://client.example/c.json", Aud: e.as.Resource(),
		Scope: scopeRead, Token: "ya29.x", TokenExp: 4102444800, Exp: 4102444800})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verify(context.Background(), tok); err != nil {
		t.Fatalf("the minting server refuses its own token: %v", err)
	}
	if _, err := e.as.Verify(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("another issuer's token: %v, want ErrInvalidToken", err)
	}
}

// An access token never outlives the Google token inside it (less a
// minute).
func TestAccessCappedByGoogleToken(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
	})
	v := rand.Text() + rand.Text()
	code, err := e.as.seal(context.Background(), purposeCode, codePayload{
		Req:  authRequest{ClientID: "cli", RedirectURI: clientRedirect, Challenge: challengeFor(v), Resource: e.as.Resource(), Scope: scopeRead},
		User: alice, Token: "ya29.short", TokenExp: e.as.now().Add(4 * time.Minute).Unix(), Secret: "1//x", JTI: "j", Exp: e.as.now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := e.token(exchangeForm("cli", code, v), "", "")
	if r.status != http.StatusOK || r.Expires > int64((3*time.Minute).Seconds()) || r.Expires < int64((2*time.Minute).Seconds()) {
		t.Errorf("access token for a Google token with 4 minutes left: %+v, want about 3 minutes", r)
	}
}

// flakyKeys fails the calls it is told to, counting from 1.
type flakyKeys struct {
	mu    sync.Mutex
	calls int
	fail  map[int]bool
}

func (f *flakyKeys) Keyring(context.Context) (*seal.Keyring, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail[f.calls] {
		return nil, errors.New("key store hiccup")
	}
	return testKeys, nil
}

// A code whose tokens could not be sealed is given back: the client's
// retry with the same code works.
func TestCodeReleasedWhenIssuingFails(t *testing.T) {
	t.Parallel()
	keys := &flakyKeys{fail: map[int]bool{}}
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
		c.Keys = keys
	})
	v := rand.Text() + rand.Text()
	code := e.code("cli", v)
	keys.mu.Lock()
	keys.fail[keys.calls+2] = true // open the code, then fail sealing the access token
	keys.mu.Unlock()
	if r := e.token(exchangeForm("cli", code, v), "", ""); r.Error != "server_error" {
		t.Fatalf("exchange with a key-store hiccup: %+v", r)
	}
	if r := e.token(exchangeForm("cli", code, v), "", ""); r.status != http.StatusOK {
		t.Errorf("retry with the same code: %+v", r)
	}
}

// A grant only the user can repair keeps the refresh token spent.
func TestReauthKeepsRefreshSpent(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	e.google.revoked[alice.Sub] = true
	e.google.mu.Unlock()
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Fatalf("refresh after revocation: %+v", r)
	}
	e.google.mu.Lock()
	e.google.revoked[alice.Sub] = false
	e.google.mu.Unlock()
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("the same refresh token after Google restored the grant: %+v", r)
	}
}

func TestTokenEndpointRequestShape(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/token", strings.NewReader(`{"grant_type":"client_credentials"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&m)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Errorf("JSON body: %d %v", resp.StatusCode, m)
	}
	if r := e.token(url.Values{"client_id": {"x"}}, "", ""); r.Error != "invalid_request" {
		t.Errorf("no grant_type: %+v", r)
	}
	if r := e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"nope"}}, "", ""); r.status != http.StatusUnauthorized || r.header.Get("WWW-Authenticate") == "" {
		t.Errorf("unknown client by form: %d, challenge %q", r.status, r.header.Get("WWW-Authenticate"))
	}
}

func TestCIMDUnavailable(t *testing.T) {
	t.Parallel()
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	t.Cleanup(doc.Close)
	e := newTestEnv(t, false, func(c *Config) { c.CIMDClient = doc.Client() })
	id := doc.URL + "/c.json"
	if r := e.token(exchangeForm(id, "x", "v"), "", ""); r.Error != "server_error" {
		t.Errorf("token endpoint with the client's metadata host down: %+v", r)
	}
	resp, err := hc.Get(e.authorizeURL(id, "v", nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("authorize with the client's metadata host down: %d", resp.StatusCode)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	if got := truncate(strings.Repeat("a", 99)+"é", 100); got != strings.Repeat("a", 99) {
		t.Errorf("truncate split a character: %q", got)
	}
	if got := truncate("short", 100); got != "short" {
		t.Errorf("truncate(short) = %q", got)
	}
	if desc := checkRegistration([]string{"https://app.example/" + strings.Repeat("a", 1100), "https://app.example/" + strings.Repeat("b", 1100)}, nil, nil); !strings.Contains(desc, "too long") {
		t.Errorf("long redirect set: %q", desc)
	}
}

// Changing the caller's Config slices after New changes nothing.
func TestConfigNotAliased(t *testing.T) {
	t.Parallel()
	c := goodConfig(t)
	c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}, Scopes: []string{scopeRead}}}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Clients[0].Scopes[0] = scopeWrite
	c.Clients[0].RedirectURIs[0] = "https://evil.example/cb"
	if got := s.static["cli"]; got.Scopes[0] != scopeRead || got.RedirectURIs[0] != clientRedirect {
		t.Errorf("client after the caller's slices changed: %+v", got)
	}
}
