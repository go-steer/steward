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

// Partly ported from kode-gopher internal/oauth units_test.go at
// 8b53617b7d4d0b08b158de64ab7416dc84a1281e.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authtest"

	"github.com/go-steer/steward/seal"
)

func fmtAll(v any) string { return fmt.Sprintf("%v\n%+v\n%#v", v, v, v) }

func TestRedirects(t *testing.T) {
	t.Parallel()
	c := &client{RedirectURIs: []string{"http://127.0.0.1/cb", "https://app.example/cb", "com.example.app:/cb"}}
	allowed := map[string]bool{
		"http://127.0.0.1/cb":         true,
		"http://127.0.0.1:5555/cb":    true,
		"https://app.example/cb":      true,
		"com.example.app:/cb":         true,
		"http://127.0.0.1:5555/other": false,
		"http://localhost:5555/cb":    false, // a different loopback host
		"https://app.example:444/cb":  false, // only loopback ports float
		"https://app.example/cb?x=1":  false,
		"https://evil.example/cb":     false,
		"http://u@127.0.0.1:5555/cb":  false,
		"http://127.0.0.1:5555/cb#f":  false,
		"%zz":                         false,
	}
	for uri, want := range allowed {
		if got := redirectAllowed(c, uri); got != want {
			t.Errorf("redirectAllowed(%q) = %v, want %v", uri, got, want)
		}
	}
	valid := map[string]bool{
		"https://app.example/cb":   true,
		"http://localhost:8/cb":    true,
		"http://[::1]/cb":          true,
		"com.example.app:/cb":      true,
		"http://app.example/cb":    false,
		"https://app.example/#x":   false,
		"javascript:alert(1)":      false,
		"myapp:/cb":                false,
		"/relative":                false,
		"https:///no-host":         false,
		"file:///etc/passwd":       false,
		"data:text/html,<script>":  false,
		"vbscript.x:/cb":           true,
		"http://127.0.0.1.nip.io/": false,
		"%zz":                      false,
	}
	for uri, want := range valid {
		if got := validRedirectURI(uri); got != want {
			t.Errorf("validRedirectURI(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestIsPublic(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2001:4860:4860::8888": true,
		"10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false, "127.0.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fd00::1": false, "fe80::1": false, "::ffff:10.0.0.1": false, "224.0.0.1": false,
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestSSRFSafeClientRefusesLoopback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	resp, err := SSRFSafeClient(time.Second).Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("SSRF-safe client dialed loopback")
	}
}

func TestCacheTTL(t *testing.T) {
	t.Parallel()
	for cc, want := range map[string]time.Duration{
		"":                     cimdDefaultTTL,
		"max-age=60":           time.Minute,
		"public, max-age=9999": cimdMaxTTL,
		"no-store":             0,
		"max-age=60, no-cache": 0,
		"max-age=-5":           cimdDefaultTTL,
	} {
		if got := cacheTTL(cc); got != want {
			t.Errorf("cacheTTL(%q) = %v, want %v", cc, got, want)
		}
	}
}

func TestCIMDDocumentChecks(t *testing.T) {
	t.Parallel()
	var docURL string
	doc := map[string]any{}
	status := http.StatusOK
	body := ""
	cacheControl := "no-store"
	fetches := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		w.Header().Set("Cache-Control", cacheControl)
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	docURL = srv.URL + "/c.json"
	f := newCIMDFetcher(srv.Client())
	cases := []struct {
		name string
		doc  map[string]any
		ok   bool
	}{
		{"good", map[string]any{"client_id": docURL, "redirect_uris": []string{clientRedirect}, "client_name": strings.Repeat("n", 200)}, true},
		{"other client_id", map[string]any{"client_id": srv.URL + "/other.json", "redirect_uris": []string{clientRedirect}}, false},
		{"no redirects", map[string]any{"client_id": docURL}, false},
		{"bad redirect", map[string]any{"client_id": docURL, "redirect_uris": []string{"http://evil.example/cb"}}, false},
		{"confidential", map[string]any{"client_id": docURL, "redirect_uris": []string{clientRedirect}, "token_endpoint_auth_method": "client_secret_basic"}, false},
	}
	for _, tc := range cases {
		doc = tc.doc
		c, err := f.fetch(context.Background(), docURL)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err == nil && len(c.Name) > 100 {
			t.Errorf("%s: client name not truncated (%d)", tc.name, len(c.Name))
		}
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"404":       {http.StatusNotFound, "{}"},
		"not json":  {http.StatusOK, "<html>"},
		"too large": {http.StatusOK, strings.Repeat(" ", cimdMaxBytes+1)},
	} {
		status, body = tc.status, tc.body
		if _, err := f.fetch(context.Background(), docURL); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	status, body = http.StatusOK, ""
	for _, id := range []string{"http://x.example/c.json", "https://x.example", "https://x.example/", "https://u@x.example/c", "https://x.example/c#f"} {
		if _, err := f.fetch(context.Background(), id); err == nil {
			t.Errorf("CIMD client_id %q accepted", id)
		}
	}
	// A cacheable document is fetched once.
	doc = map[string]any{"client_id": docURL, "redirect_uris": []string{clientRedirect}}
	cacheControl = "max-age=60"
	before := fetches
	for range 3 {
		if _, err := f.fetch(context.Background(), docURL); err != nil {
			t.Fatal(err)
		}
	}
	if n := fetches - before; n != 1 {
		t.Errorf("a cacheable document was fetched %d times", n)
	}
	unreachable := newCIMDFetcher(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })})
	if _, err := unreachable.fetch(context.Background(), "https://x.example/c.json"); err == nil {
		t.Error("an unreachable document was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCIMDCacheBounded(t *testing.T) {
	t.Parallel()
	f := newCIMDFetcher(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Cache-Control", "max-age=600")
		_ = json.NewEncoder(rec).Encode(map[string]any{"client_id": r.URL.String(), "redirect_uris": []string{clientRedirect}})
		return rec.Result(), nil
	})})
	for i := range cimdMaxCached + 5 {
		if _, err := f.fetch(context.Background(), fmt.Sprintf("https://x.example/c%d.json", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.cache); n > cimdMaxCached {
		t.Errorf("CIMD cache holds %d documents, want at most %d", n, cimdMaxCached)
	}
}

func TestVerifyIDToken(t *testing.T) {
	t.Parallel()
	g := &GoogleClient{ClientID: testGoogleID}
	now := time.Unix(1_800_000_000, 0)
	enc := func(claims map[string]any) string {
		b, _ := json.Marshal(claims)
		return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	}
	base := func() map[string]any {
		return map[string]any{"iss": "https://accounts.google.com", "aud": testGoogleID, "sub": "1",
			"email": "A@Example.com", "email_verified": true, "hd": "Example.com", "exp": now.Unix() + 60}
	}
	u, err := g.verifyIDToken(enc(base()), now)
	if err != nil || u != (User{Sub: "1", Email: "a@example.com", Domain: "example.com"}) {
		t.Fatalf("verifyIDToken = %+v, %v", u, err)
	}
	multi := base()
	multi["aud"] = []string{"x", testGoogleID}
	if _, err := g.verifyIDToken(enc(multi), now); err != nil {
		t.Errorf("array aud: %v", err)
	}
	for name, edit := range map[string]func(map[string]any){
		"issuer":     func(c map[string]any) { c["iss"] = "https://evil.example" },
		"audience":   func(c map[string]any) { c["aud"] = "other.apps.googleusercontent.com" },
		"expired":    func(c map[string]any) { c["exp"] = now.Unix() },
		"no sub":     func(c map[string]any) { delete(c, "sub") },
		"unverified": func(c map[string]any) { c["email_verified"] = false },
		"no email":   func(c map[string]any) { delete(c, "email") },
	} {
		c := base()
		edit(c)
		if _, err := g.verifyIDToken(enc(c), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, bad := range []string{"not-a-jwt", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if _, err := g.verifyIDToken(bad, now); err == nil {
			t.Errorf("malformed token %q accepted", bad)
		}
	}
}

func goodConfig(t *testing.T) Config {
	return Config{Issuer: "https://svc.example.com/", Resource: "https://svc.example.com/mcp", Scopes: []string{scopeRead, scopeWrite},
		Google: GoogleClient{ClientID: "id", ClientSecret: "s"}, Custody: SealedCustody{}, Admit: newAdmitter(t, &fakeGroups{}), Keys: testKeys}
}

func TestNewValidates(t *testing.T) {
	t.Parallel()
	s, err := New(goodConfig(t))
	if err != nil || s.Resource() != "https://svc.example.com/mcp" || s.Issuer() != "https://svc.example.com" {
		t.Fatalf("New = %v, %v", s, err)
	}
	if got := s.Scopes(); !slices.Equal(got, []string{scopeRead, scopeWrite}) {
		t.Errorf("Scopes = %v", got)
	}
	if s.google.client.TokenURL != GoogleTokenURL || !slices.Equal(s.google.scopes, []string{ScopeCloudPlatform}) || s.cfg.ServiceName != "svc.example.com" {
		t.Errorf("defaults not applied: %+v %v %q", s.google.client, s.google.scopes, s.cfg.ServiceName)
	}
	for name, edit := range map[string]func(*Config){
		"http issuer":          func(c *Config) { c.Issuer = "http://svc.example.com" },
		"relative issuer":      func(c *Config) { c.Issuer = "/oauth" },
		"no issuer":            func(c *Config) { c.Issuer = "" },
		"issuer with query":    func(c *Config) { c.Issuer = "https://svc.example.com?x=1" },
		"bad issuer":           func(c *Config) { c.Issuer = "https://%zz" },
		"no resource":          func(c *Config) { c.Resource = "" },
		"http resource":        func(c *Config) { c.Resource = "http://svc.example.com/mcp" },
		"no google secret":     func(c *Config) { c.Google.ClientSecret = "" },
		"no custody":           func(c *Config) { c.Custody = nil },
		"no admitter":          func(c *Config) { c.Admit = nil },
		"no keys":              func(c *Config) { c.Keys = nil },
		"no scopes":            func(c *Config) { c.Scopes = nil },
		"bad scope":            func(c *Config) { c.Scopes = []string{"a b"} },
		"quote scope":          func(c *Config) { c.Scopes = []string{`a"b`} },
		"unknown default":      func(c *Config) { c.DefaultScopes = []string{"svc:admin"} },
		"short Google scope":   func(c *Config) { c.GoogleScopes = []string{"cloud-platform"} },
		"foreign Google scope": func(c *Config) { c.GoogleScopes = []string{"https://evil.example/auth/x"} },
		"duplicate client": func(c *Config) {
			c.Clients = []StaticClient{{ID: "a", RedirectURIs: []string{clientRedirect}}, {ID: "a", RedirectURIs: []string{clientRedirect}}}
		},
	} {
		c := goodConfig(t)
		edit(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A loopback issuer may be http; Google scopes drop openid and email
	// and de-duplicate.
	c := goodConfig(t)
	c.Issuer, c.Resource = "http://127.0.0.1:8080", "http://localhost:8080/mcp"
	c.GoogleScopes = []string{ScopeOpenID, ScopeEmail, ScopeCloudPlatform, ScopeCloudPlatform, "https://www.googleapis.com/auth/drive.readonly"}
	c.Scopes = []string{scopeRead, scopeRead}
	s, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.google.scopes, []string{ScopeCloudPlatform, "https://www.googleapis.com/auth/drive.readonly"}) || !slices.Equal(s.Scopes(), []string{scopeRead}) {
		t.Errorf("scopes = %v / %v", s.google.scopes, s.Scopes())
	}
}

// An issuer with a path places every endpoint and well-known document
// below it (RFC 8414 section 3.1), and the flow cookies with it.
func TestIssuerWithPath(t *testing.T) {
	t.Parallel()
	c := goodConfig(t)
	c.Issuer = "https://svc.example.com/oauth"
	c.OpenRegistration = true
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/.well-known/oauth-authorization-server/oauth", "/oauth/.well-known/openid-configuration",
		"/oauth/authorize", "/oauth/callback", "/oauth/consent/continue", "/oauth/token",
		"/.well-known/openid-configuration/oauth", "/oauth/register",
	}
	if got := s.Paths(); !slices.Equal(got, want) {
		t.Errorf("Paths = %v\nwant %v", got, want)
	}
	if s.MetadataURL() != "https://svc.example.com/.well-known/oauth-authorization-server/oauth" || s.CallbackURL() != "https://svc.example.com/oauth/callback" ||
		s.ContinueURL() != "https://svc.example.com/oauth/consent/continue" || s.cookiePath() != "/oauth/" {
		t.Errorf("URLs: %s %s %s %s", s.MetadataURL(), s.CallbackURL(), s.ContinueURL(), s.cookiePath())
	}
	h := s.Handler()
	for _, p := range want[:2] {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"issuer":"https://svc.example.com/oauth"`) {
			t.Errorf("GET %s: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("an endpoint outside the issuer's path answered %d", rec.Code)
	}
}

func TestMemoryReplayCache(t *testing.T) {
	t.Parallel()
	c := NewMemoryReplayCache()
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	if ok, err := c.Claim(ctx, "a", now.Add(time.Minute)); !ok || err != nil {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, _ := c.Claim(ctx, "a", now.Add(time.Minute)); ok {
		t.Error("second claim succeeded")
	}
	_ = c.Release(ctx, "a")
	if ok, _ := c.Claim(ctx, "a", now.Add(time.Minute)); !ok {
		t.Error("claim after release refused")
	}
	now = now.Add(time.Minute)
	if ok, _ := c.Claim(ctx, "a", now.Add(time.Minute)); !ok {
		t.Error("claim after expiry refused")
	}
	// Full of live claims: refuse rather than forget one.
	for i := range maxMemoryClaims {
		c.seen[fmt.Sprint(i)] = now.Add(time.Hour)
	}
	if ok, err := c.Claim(ctx, "new", now.Add(time.Minute)); ok || !errors.Is(err, errReplayFull) {
		t.Errorf("claim in a full cache: %v %v", ok, err)
	}
	now = now.Add(2 * time.Hour)
	if ok, err := c.Claim(ctx, "new", now.Add(time.Minute)); !ok || err != nil || len(c.seen) != 1 {
		t.Errorf("claim after the cache's claims expired: %v %v, %d left", ok, err, len(c.seen))
	}
}

// failingReplay is a replay cache that cannot answer.
type failingReplay struct{}

func (failingReplay) Claim(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("store down")
}
func (failingReplay) Release(context.Context, string) error { return nil }

func TestReplayCacheFailureIsServerError(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id, first := e.signIn(newBrowser(t))
	e.as.used = failingReplay{}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" {
		t.Errorf("refresh with the replay cache down: %+v", r)
	}
	v := "verifier-" + strings.Repeat("v", 40)
	e.as.used = NewMemoryReplayCache()
	code := e.code(id, v)
	e.as.used = failingReplay{}
	if r := e.token(exchangeForm(id, code, v), "", ""); r.Error != "server_error" {
		t.Errorf("exchange with the replay cache down: %+v", r)
	}
}

// failingKeys is a key provider that cannot answer.
type failingKeys struct{}

func (failingKeys) Keyring(context.Context) (*seal.Keyring, error) {
	return nil, errors.New("key store down")
}

// Keys being unavailable is the server failing, never a refusal of the
// client's grant or token.
func TestKeysUnavailable(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id, first := e.signIn(newBrowser(t))
	e.as.cfg.Keys = failingKeys{}
	if _, err := e.as.Verify(context.Background(), first.Access); !errors.Is(err, ErrUnavailable) || errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("Verify without keys: %v, want ErrUnavailable", err)
	}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" {
		t.Errorf("refresh without keys: %+v", r)
	}
	if r := e.token(exchangeForm(id, "st1.k1.x", "v"), "", ""); r.Error != "server_error" {
		t.Errorf("exchange without keys: %+v", r)
	}
	resp, err := http.Post(e.srv.URL+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+clientRedirect+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("register without keys: %d", resp.StatusCode)
	}
	resp, err = http.Get(e.authorizeURL(id, "v", nil))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("authorize without keys (a DCR client cannot be resolved): %d", resp.StatusCode)
	}
}

func TestRegister(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	for name, body := range map[string]string{
		"malformed":       `{`,
		"no redirects":    `{"redirect_uris":[]}`,
		"http redirect":   `{"redirect_uris":["http://evil.example/cb"]}`,
		"password grant":  `{"redirect_uris":["` + clientRedirect + `"],"grant_types":["password"]}`,
		"token response":  `{"redirect_uris":["` + clientRedirect + `"],"response_types":["token"]}`,
		"eleven redirect": `{"redirect_uris":[` + strings.Repeat(`"`+clientRedirect+`",`, 10) + `"` + clientRedirect + `"]}`,
	} {
		resp, err := http.Post(e.srv.URL+"/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&m)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || m["error"] == "" {
			t.Errorf("%s: %d %v", name, resp.StatusCode, m)
		}
	}
	resp, err := http.Post(e.srv.URL+"/register", "application/json", strings.NewReader(`{"client_name":"`+strings.Repeat("n", 300)+`","redirect_uris":["`+clientRedirect+`"],"token_endpoint_auth_method":"client_secret_basic"}`))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || m["token_endpoint_auth_method"] != "none" || len(m["client_name"].(string)) != 100 || !seal.IsSealed(m["client_id"].(string)) {
		t.Errorf("register: %d %v", resp.StatusCode, m)
	}
	// A DCR client ID from another issuer (or forged) is unknown.
	forged, _ := testKeys.Seal("https://elsewhere.example#client", dcrClient{RedirectURIs: []string{clientRedirect}})
	if r := e.token(exchangeForm(forged, "x", "v"), "", ""); r.Error != "invalid_client" {
		t.Errorf("a foreign DCR client ID: %+v", r)
	}
}

func TestLoadGoogleClient(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	if g, err := LoadGoogleClient(write("web.json", `{"web":{"client_id":"id","client_secret":"s"}}`)); err != nil || g.ClientID != "id" || g.ClientSecret != "s" {
		t.Errorf("web client: %+v %v", g, err)
	}
	if g, err := LoadGoogleClient(write("inst.json", `{"installed":{"client_id":"id2","client_secret":"s2"}}`)); err != nil || g.ClientID != "id2" {
		t.Errorf("installed client: %+v %v", g, err)
	}
	for name, body := range map[string]string{"malformed": `{`, "empty": `{}`, "no secret": `{"web":{"client_id":"id"}}`} {
		if _, err := LoadGoogleClient(write(name, body)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadGoogleClient(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file loaded")
	}
}

// The authenticator passes purser's conformance suite.
func TestAuthenticatorConformance(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	_, r := e.signIn(newBrowser(t))
	request := func(header string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		return req
	}
	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: e.as.Authenticator(),
		WantSource:    purser.AuthSourceOIDC,
		Valid: func() (*http.Request, purser.Caller) {
			return request("Bearer " + r.Access), purser.Caller{
				Identity: alice.Email,
				Labels: map[string]string{LabelSubject: alice.Sub, LabelHD: alice.Domain, LabelKind: KindUser,
					LabelScope: scopeRead, LabelClientID: mustClaim(t, e, r.Access).ClientID},
			}
		},
		Malformed: []authtest.MalformedCase{
			{Name: "refresh token", Request: func() *http.Request { return request("Bearer " + r.Refresh) }},
			{Name: "a Google token", Request: func() *http.Request { return request("Bearer ya29.x") }},
			{Name: "tampered", Request: func() *http.Request { return request("Bearer " + r.Access[:len(r.Access)-2] + "AA") }},
			{Name: "basic scheme", Request: func() *http.Request { return request("Basic Z29vZA==") }},
			{Name: "empty bearer", Request: func() *http.Request { return request("Bearer ") }},
		},
	})
	if !e.as.Authenticator().GatesCredentials() {
		t.Error("GatesCredentials = false")
	}
}

func mustClaim(t *testing.T, e *testEnv, tok string) Principal {
	t.Helper()
	p, err := e.as.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealedCustodyEdges(t *testing.T) {
	t.Parallel()
	g := &upstream{client: &GoogleClient{}, scopes: []string{ScopeCloudPlatform}}
	ctx := context.Background()
	if _, _, err := (SealedCustody{}).begin(ctx, g, alice, &googleTokens{Scope: ScopeOpenID, RefreshToken: "r"}, ""); err == nil {
		t.Error("sealed custody accepted a grant without cloud-platform")
	}
	if _, _, err := (SealedCustody{}).begin(ctx, g, alice, &googleTokens{Scope: ScopeCloudPlatform}, ""); err == nil {
		t.Error("sealed custody accepted a grant without a refresh token")
	}
	if _, err := (SealedCustody{}).finish(ctx, g, alice, consent{}, nil, ""); err == nil {
		t.Error("sealed custody finished a consent detour")
	}
	if _, err := (SealedCustody{}).refresh(ctx, g, alice, "", ""); !errors.Is(err, errReauth) {
		t.Errorf("sealed refresh without a secret: %v", err)
	}
	if SealedCustody.Name(SealedCustody{}) != "sealed" || (&VaultCustody{}).Name() != "vault" {
		t.Error("custody names")
	}
	if _, err := (&VaultCustody{}).retrieve(ctx, g, "1", "", ""); err == nil {
		t.Error("vault with no client answered")
	}
}

func TestGoogleTokenEndpointErrors(t *testing.T) {
	t.Parallel()
	for name, h := range map[string]http.HandlerFunc{
		"500":      func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"not json": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"no token": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"expires_in":3600}`)) },
		"cut short": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "50")
			_, _ = w.Write([]byte(`{`))
		},
	} {
		srv := httptest.NewServer(h)
		g := &GoogleClient{TokenURL: srv.URL, TokenInfoURL: srv.URL}
		if _, err := g.refresh(context.Background(), srv.Client(), "r"); err == nil || errors.Is(err, errGoogleGrant) {
			t.Errorf("token endpoint %s: %v", name, err)
		}
		if _, err := g.tokenInfo(context.Background(), srv.Client(), "t"); err == nil {
			t.Errorf("tokeninfo %s: accepted", name)
		}
		srv.Close()
	}
	g := &GoogleClient{TokenURL: "http://127.0.0.1:1", TokenInfoURL: "http://127.0.0.1:1"}
	if _, err := g.refresh(context.Background(), http.DefaultClient, "r"); err == nil {
		t.Error("unreachable token endpoint answered")
	}
	if _, err := g.tokenInfo(context.Background(), http.DefaultClient, "t"); err == nil {
		t.Error("unreachable tokeninfo answered")
	}
	bad := &GoogleClient{TokenURL: "http://\x7f", TokenInfoURL: "http://\x7f"}
	if _, err := bad.refresh(context.Background(), http.DefaultClient, "r"); err == nil {
		t.Error("malformed token URL answered")
	}
	if _, err := bad.tokenInfo(context.Background(), http.DefaultClient, "t"); err == nil {
		t.Error("malformed tokeninfo URL answered")
	}
}
