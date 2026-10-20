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

package httpauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/httpmw"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/googletoken"
)

const (
	clientID   = "123-abc.apps.googleusercontent.com"
	cloudScope = "https://www.googleapis.com/auth/cloud-platform"
)

var expiry = time.Now().Add(time.Hour).Truncate(time.Second)

// fakeGoogle answers tokeninfo and userinfo for one good token ("good",
// dana@cymbal.example) and one outsider ("outsider", eve@evil.example).
func fakeGoogle(t *testing.T) string {
	t.Helper()
	people := map[string][2]string{"good": {"dana@cymbal.example", "cymbal.example"}, "outsider": {"eve@evil.example", "evil.example"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.FormValue("access_token")
		if r.URL.Path == "/userinfo" {
			tok = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		p, ok := people[tok]
		if !ok {
			code := http.StatusBadRequest // tokeninfo: invalid_token
			if r.URL.Path == "/userinfo" {
				code = http.StatusUnauthorized
			}
			http.Error(w, "{}", code)
			return
		}
		if r.URL.Path == "/userinfo" {
			_ = json.NewEncoder(w).Encode(map[string]string{"email": p[0], "hd": p[1]})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"aud": clientID, "azp": clientID, "sub": "1001", "email": p[0], "email_verified": "true",
			"exp": strconv.FormatInt(expiry.Unix(), 10), "scope": "openid " + googletoken.EmailScope + " " + cloudScope,
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func authenticator(t *testing.T) *googletoken.Authenticator {
	t.Helper()
	base := fakeGoogle(t)
	v, err := googletoken.New(googletoken.Config{
		ClientIDs: []string{clientID}, RequiredScopes: []string{cloudScope},
		TokenInfoURL: base + "/tokeninfo", UserInfoURL: base + "/userinfo",
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := allow.Parse([]string{"@cymbal.example"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := googletoken.NewAuthenticator(v, list)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func protector(t *testing.T, resource string) *Protector {
	t.Helper()
	p, err := New(Options{
		Authenticator: authenticator(t), Resource: resource,
		Scopes: []string{"openid", "email", cloudScope}, ResourceName: "lookout",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func call(h http.Handler, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestProtectedRequest: a good token reaches the handler as the person,
// with the google-access-token verdict, the person's own token as a
// TokenSource carrying its expiry, and the verified Identity.
func TestProtectedRequest(t *testing.T) {
	t.Parallel()
	p := protector(t, "https://lookout.example.com/mcp")
	var (
		caller purser.Caller
		source purser.AuthSource
		tokVal string
		tokExp time.Time
		id     googletoken.Identity
		hasID  bool
	)
	h := p.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		caller, _ = purser.CallerFromContext(r.Context())
		source, _ = purser.AuthSourceFromContext(r.Context())
		if ts, ok := TokenSourceFromContext(r.Context()); ok {
			if tok, err := ts.Token(); err == nil {
				tokVal, tokExp = tok.AccessToken, tok.Expiry
			}
		}
		id, hasID = IdentityFromContext(r.Context())
	}))

	rec := call(h, "good")
	if rec.Code != http.StatusOK {
		t.Fatalf("good token: status %d", rec.Code)
	}
	if caller.Identity != "dana@cymbal.example" || source != purser.AuthSourceGoogleAccessToken {
		t.Errorf("caller %q, source %q", caller.Identity, source)
	}
	if tokVal != "good" || !tokExp.Equal(expiry) {
		t.Errorf("token source gave %q expiring %v, want the request's token expiring %v", tokVal, tokExp, expiry)
	}
	if !hasID || id.Email != "dana@cymbal.example" || id.HD != "cymbal.example" {
		t.Errorf("identity %+v, %v", id, hasID)
	}
}

func TestRefusedRequests(t *testing.T) {
	t.Parallel()
	p := protector(t, "https://lookout.example.com/mcp")
	ran := false
	h := p.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	want := `Bearer resource_metadata="https://lookout.example.com/.well-known/oauth-protected-resource/mcp", ` +
		`scope="openid email ` + cloudScope + `"`
	for _, tok := range []string{"", "nope", "outsider"} {
		rec := call(h, tok)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != want {
			t.Errorf("token %q: %d, challenge %q; want 401 with %q", tok, rec.Code, rec.Header().Get("WWW-Authenticate"), want)
		}
	}
	if ran {
		t.Error("the handler ran for a refused request")
	}
}

// TestAttachRefusesUnverified: the attaching layer acts only on a request
// purser verified as Google's. Reached any other way, it refuses rather
// than hand an unchecked header to the handler as the caller's token.
func TestAttachRefusesUnverified(t *testing.T) {
	t.Parallel()
	p := protector(t, "https://lookout.example.com/mcp")
	ran := false
	h := p.attach(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	if rec := call(h, "good"); rec.Code != http.StatusUnauthorized || ran {
		t.Errorf("no verdict: %d, handler ran %v", rec.Code, ran)
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer good")
	r = r.WithContext(purser.WithAuthSource(r.Context(), purser.AuthSourceBearer))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized || ran {
		t.Errorf("another source's verdict: %d, handler ran %v", rec.Code, ran)
	}
	// A Google verdict whose token no longer verifies (expired in
	// between) is refused too.
	r = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer nope")
	r = r.WithContext(purser.WithAuthSource(r.Context(), purser.AuthSourceGoogleAccessToken))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized || ran {
		t.Errorf("a token that no longer verifies: %d, handler ran %v", rec.Code, ran)
	}
}

// TestProxyAssertionRefused pins what purser does with an assertion header
// in front of an authenticator that cannot proxy: a 401, never a request
// that reaches the handler as the asserted identity.
func TestProxyAssertionRefused(t *testing.T) {
	t.Parallel()
	p := protector(t, "https://lookout.example.com/mcp")
	ran := false
	h := p.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer good")
	r.Header.Set(authn.HeaderAssertedCaller, "ceo@cymbal.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized || ran {
		t.Errorf("assertion header: %d, handler ran %v; want 401", rec.Code, ran)
	}
}

// TestAttachUnavailableIs503: if the second check in attach has to ask
// Google again (the cache entry was evicted) and Google cannot answer,
// that is a 503, not a 401: Google failing is not Google refusing.
func TestAttachUnavailableIs503(t *testing.T) {
	t.Parallel()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "{}", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	v, err := googletoken.New(googletoken.Config{ClientIDs: []string{clientID}, TokenInfoURL: down.URL, UserInfoURL: down.URL})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := allow.Parse([]string{"@cymbal.example"})
	a, err := googletoken.NewAuthenticator(v, list)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Authenticator: a, Resource: "https://lookout.example.com/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	h := p.attach(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer good")
	r = r.WithContext(purser.WithAuthSource(r.Context(), purser.AuthSourceGoogleAccessToken))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != retryAfter || ran {
		t.Errorf("Google down in attach: %d, Retry-After %q, handler ran %v; want 503", rec.Code, rec.Header().Get("Retry-After"), ran)
	}
}

func TestScopesMustBeScopeTokens(t *testing.T) {
	t.Parallel()
	a := authenticator(t)
	for _, bad := range []string{"", "two words", `quo"te`, `back\slash`, "café", "tab\there", "\x7f"} {
		if _, err := New(Options{Authenticator: a, Resource: "https://x.example/mcp", Scopes: []string{"openid", bad}}); err == nil {
			t.Errorf("accepted scope %q", bad)
		}
	}
	if _, err := New(Options{Authenticator: a, Resource: "https://x.example/mcp",
		Scopes: []string{"openid", "email", cloudScope, "a!#[]~"}}); err != nil {
		t.Errorf("refused valid scopes: %v", err)
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	for resource, wantPath := range map[string]string{
		"https://lookout.example.com/mcp":  "/.well-known/oauth-protected-resource/mcp",
		"https://lookout.example.com/mcp/": "/.well-known/oauth-protected-resource/mcp",
		"https://lookout.example.com":      "/.well-known/oauth-protected-resource",
		"https://lookout.example.com/a/b":  "/.well-known/oauth-protected-resource/a/b",
		"http://127.0.0.1:8080/mcp":        "/.well-known/oauth-protected-resource/mcp",
	} {
		p := protector(t, resource)
		if p.MetadataPath() != wantPath {
			t.Errorf("%s: MetadataPath %q, want %q", resource, p.MetadataPath(), wantPath)
		}
		if !strings.HasSuffix(p.MetadataURL(), wantPath) || !strings.Contains(p.Challenge(), p.MetadataURL()) {
			t.Errorf("%s: MetadataURL %q, challenge %q", resource, p.MetadataURL(), p.Challenge())
		}
	}

	p := protector(t, "https://lookout.example.com/mcp")
	rec := httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p.MetadataPath(), nil))
	var doc struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
		BearerMethods        []string `json:"bearer_methods_supported"`
		ResourceName         string   `json:"resource_name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if rec.Header().Get("Content-Type") != "application/json" || doc.Resource != "https://lookout.example.com/mcp" ||
		len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != googletoken.Issuer ||
		len(doc.ScopesSupported) != 3 || doc.BearerMethods[0] != "header" || doc.ResourceName != "lookout" {
		t.Errorf("metadata: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodHead, p.MetadataPath(), nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d with %d bytes", rec.Code, rec.Body.Len())
	}
	rec = httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p.MetadataPath(), nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", rec.Code)
	}
}

func TestMetadataWithoutOptionalFields(t *testing.T) {
	t.Parallel()
	p, err := New(Options{Authenticator: authenticator(t), Resource: "https://lookout.example.com/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Challenge(), "scope=") {
		t.Errorf("challenge names scopes nobody configured: %q", p.Challenge())
	}
	rec := httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p.MetadataPath(), nil))
	if body := rec.Body.String(); strings.Contains(body, "scopes_supported") || strings.Contains(body, "resource_name") {
		t.Errorf("metadata carries empty optional fields: %s", body)
	}
}

func TestNewRefuses(t *testing.T) {
	t.Parallel()
	a := authenticator(t)
	if _, err := New(Options{Resource: "https://x.example/mcp"}); err == nil {
		t.Error("accepted no Authenticator")
	}
	for _, bad := range []string{
		"",
		"/mcp",
		"lookout.example.com/mcp",
		"http://lookout.example.com/mcp", // the user's token over plaintext
		"http://10.0.0.1/mcp",
		"https://lookout.example.com/mcp?x=1",
		"https://lookout.example.com/mcp#frag",
		"https://user@lookout.example.com/mcp",
		"https://%zz/mcp",
	} {
		if _, err := New(Options{Authenticator: a, Resource: bad}); err == nil {
			t.Errorf("accepted Resource %q", bad)
		}
	}
	for _, ok := range []string{"http://localhost:8080/mcp", "http://127.0.0.1/mcp", "http://[::1]:9/mcp"} {
		if _, err := New(Options{Authenticator: a, Resource: ok}); err != nil {
			t.Errorf("refused loopback Resource %q: %v", ok, err)
		}
	}
}

// TestGatesCredentials: purser's bind policy can ask the Protector whether
// a non-loopback bind is safe, and it is.
func TestGatesCredentials(t *testing.T) {
	t.Parallel()
	p := protector(t, "https://lookout.example.com/mcp")
	if !p.GatesCredentials() {
		t.Error("GatesCredentials() = false")
	}
	if err := httpmw.CheckBind("0.0.0.0:8080", p); err != nil {
		t.Errorf("CheckBind refused a protected surface: %v", err)
	}
	var nilP *Protector
	if nilP.GatesCredentials() {
		t.Error("a nil Protector reports gating credentials")
	}
}

func TestFromContextOutsideProtectedRequest(t *testing.T) {
	t.Parallel()
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	if _, ok := TokenSourceFromContext(ctx); ok {
		t.Error("TokenSourceFromContext found a token outside a protected request")
	}
	if _, ok := IdentityFromContext(ctx); ok {
		t.Error("IdentityFromContext found an identity outside a protected request")
	}
}
