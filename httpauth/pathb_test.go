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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/httpmw"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/authserver"
	"github.com/go-steer/steward/internal/pathbtest"
	"github.com/go-steer/steward/seal"
)

const (
	scopeRead  = "svc:read"
	scopeWrite = "svc:write"
)

var dana = pathbtest.Person{Sub: "1001", Email: "dana@cymbal.example", HD: "cymbal.example"}

// asEnv is an authorization server on a test server, with the resource at
// /mcp served by whatever handler the test installs.
type asEnv struct {
	srv    *httptest.Server
	as     *authserver.Server
	signIn *pathbtest.SignIn
	mux    *http.ServeMux
}

func newASEnv(t *testing.T, keys seal.KeyProvider) *asEnv {
	t.Helper()
	e := &asEnv{signIn: pathbtest.NewSignIn(t, dana), mux: http.NewServeMux()}
	e.srv = httptest.NewServer(e.mux)
	t.Cleanup(e.srv.Close)
	list, _ := allow.Parse([]string{"@cymbal.example"})
	adm, err := allow.NewAdmitter(list, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil {
		keys = testKeys(t)
	}
	e.as, err = authserver.New(authserver.Config{
		Issuer: e.srv.URL, Resource: e.srv.URL + "/mcp", Scopes: []string{scopeRead, scopeWrite},
		Google: e.signIn.Google(), Custody: authserver.SealedCustody{}, Admit: adm, Keys: keys, OpenRegistration: true,
		Clients: []authserver.StaticClient{
			{ID: "ci", Secret: "ci-secret", ClientCredentials: true},
			{ID: "writer", Secret: "w-secret", ClientCredentials: true, Scopes: []string{scopeWrite}},
			{ID: "robot", Secret: "r-secret", ServiceAccount: pathbtest.RobotSA},
		},
		ServiceTokens: pathbtest.ServiceTokens{},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.as.Register(e.mux)
	return e
}

func testKeys(t *testing.T) *seal.Keyring {
	k, err := seal.NewKeyring(seal.Key{ID: "k1", Secret: []byte(strings.Repeat("k", seal.KeySize))})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// report writes what a protected handler sees.
var report = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	c, _ := purser.CallerFromContext(r.Context())
	src, _ := purser.AuthSourceFromContext(r.Context())
	tok, email, kind := "-", "-", "-"
	if ts, ok := TokenSourceFromContext(r.Context()); ok {
		t, err := ts.Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tok = t.AccessToken
	}
	if id, ok := IdentityFromContext(r.Context()); ok {
		email = id.Email
	}
	if p, ok := PrincipalFromContext(r.Context()); ok {
		kind = c.Label(authserver.LabelKind)
		if p.Workload != (kind == authserver.KindWorkload) {
			kind = "mismatch"
		}
	}
	_, _ = fmt.Fprintf(w, "%s %s %s %s %s", c.Identity, src, kind, email, tok)
})

func TestPathBPerson(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	p, err := New(Options{Authenticator: authenticator(t), AuthServer: e.as, Resource: e.as.Resource()})
	if err != nil {
		t.Fatal(err)
	}
	h := p.Middleware()(report)

	tok := pathbtest.PersonToken(t, e.srv.URL, e.as.Resource(), "")
	rec := call(h, tok)
	f := strings.Fields(rec.Body.String())
	if rec.Code != http.StatusOK || len(f) != 5 || f[0] != dana.Email || f[1] != string(purser.AuthSourceOIDC) || f[2] != authserver.KindUser || f[3] != dana.Email || !strings.HasPrefix(f[4], "ya29.signin-") {
		t.Errorf("a person's steward token: %d %q", rec.Code, rec.Body.String())
	}
	// The same Protector still takes Google tokens (Path A).
	if rec := call(h, "good"); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "dana@cymbal.example google-access-token - dana@cymbal.example good") {
		t.Errorf("a Google token: %d %q", rec.Code, rec.Body.String())
	}
	// Both callers are the same person, by the same labels.
	for _, tk := range []string{tok, "good"} {
		var got purser.Caller
		hh := p.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = purser.CallerFromContext(r.Context()) }))
		call(hh, tk)
		if got.Identity != dana.Email || got.Label("google.sub") != dana.Sub || got.Label("google.hd") != dana.HD {
			t.Errorf("caller for %.8s…: %+v", tk, got)
		}
	}
	for name, bad := range map[string]string{"forged": "st1.k1.AAAA", "garbage": "nope", "none": ""} {
		if rec := call(h, bad); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != p.Challenge() {
			t.Errorf("%s: %d, challenge %q", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestPathBWorkload(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	p, err := New(Options{AuthServer: e.as, Resource: e.as.Resource()})
	if err != nil {
		t.Fatal(err)
	}
	h := p.Middleware()(report)
	rec := call(h, pathbtest.ClientCredentials(t, e.srv.URL, "ci", "ci-secret"))
	if want := "client:ci oidc workload - -"; rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("a workload: %d %q, want %q", rec.Code, rec.Body.String(), want)
	}
	// Without a Google Authenticator, a Google token goes to the steward
	// verifier, which refuses it.
	if rec := call(h, "good"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a Google token with no Authenticator: %d", rec.Code)
	}
	if !p.GatesCredentials() {
		t.Error("GatesCredentials = false")
	}
}

func TestPathBRequiredScopes(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	p, err := New(Options{Authenticator: authenticator(t), AuthServer: e.as, Resource: e.as.Resource(), RequiredScopes: []string{scopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	h := p.Middleware()(report)
	rec := call(h, pathbtest.ClientCredentials(t, e.srv.URL, "writer", "w-secret"))
	want := fmt.Sprintf(`Bearer error="insufficient_scope", scope="svc:read", resource_metadata=%q`, p.MetadataURL())
	if rec.Code != http.StatusForbidden || rec.Header().Get("WWW-Authenticate") != want {
		t.Errorf("without svc:read: %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if rec := call(h, pathbtest.PersonToken(t, e.srv.URL, e.as.Resource(), scopeRead)); rec.Code != http.StatusOK {
		t.Errorf("with svc:read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(h, "good"); rec.Code != http.StatusOK {
		t.Errorf("a Google token is not held to service scopes: %d", rec.Code)
	}
}

func TestPathBMetadata(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	p, err := New(Options{Authenticator: authenticator(t), AuthServer: e.as, Resource: e.as.Resource(), ResourceName: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p.MetadataPath(), nil))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	servers, _ := json.Marshal(m["authorization_servers"])
	scopes, _ := json.Marshal(m["scopes_supported"])
	if string(servers) != `["`+e.srv.URL+`"]` || string(scopes) != `["svc:read","svc:write"]` || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("metadata: %s, CORS %q", rec.Body.String(), rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if want := fmt.Sprintf("Bearer resource_metadata=%q, scope=%q", p.MetadataURL(), "svc:read svc:write"); p.Challenge() != want {
		t.Errorf("challenge %q, want %q", p.Challenge(), want)
	}
	rec = httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, p.MetadataPath(), nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight: %d", rec.Code)
	}
	// Explicit Scopes win.
	p, _ = New(Options{AuthServer: e.as, Resource: e.as.Resource(), Scopes: []string{scopeRead}})
	if !strings.Contains(p.Challenge(), `scope="svc:read"`) {
		t.Errorf("explicit scopes ignored: %q", p.Challenge())
	}
}

func TestPathBNewRefuses(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	for name, o := range map[string]Options{
		"other resource":           {AuthServer: e.as, Resource: e.srv.URL + "/other"},
		"required without AS":      {Authenticator: authenticator(t), Resource: e.as.Resource(), RequiredScopes: []string{scopeRead}},
		"required not an AS scope": {AuthServer: e.as, Resource: e.as.Resource(), RequiredScopes: []string{"svc:admin"}},
		"bad required scope":       {AuthServer: e.as, Resource: e.as.Resource(), RequiredScopes: []string{"a b"}},
		"neither":                  {Resource: e.as.Resource()},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// failingKeys loses the keyring after the token was issued.
type failingKeys struct {
	k    *seal.Keyring
	fail bool
}

func (f *failingKeys) Keyring(context.Context) (*seal.Keyring, error) {
	if f.fail {
		return nil, errors.New("key store down")
	}
	return f.k, nil
}

// Keys being unavailable is a 503 from purser's middleware since purser
// v0.3.0 (purser#23; TestPathBKeysDownIs503). If they vanish between that
// layer and the attach layer, the attach layer answers 503 too, never a pass.
func TestPathBAttachRefusesUnverified(t *testing.T) {
	t.Parallel()
	keys := &failingKeys{k: testKeys(t)}
	e := newASEnv(t, keys)
	p, err := New(Options{AuthServer: e.as, Resource: e.as.Resource()})
	if err != nil {
		t.Fatal(err)
	}
	tok := pathbtest.ClientCredentials(t, e.srv.URL, "ci", "ci-secret")

	reached := false
	inner := p.attachAS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	// A request the AuthServer's middleware did not verify.
	rec := call(inner, tok)
	if rec.Code != http.StatusUnauthorized || reached {
		t.Errorf("unverified request through attachAS: %d, reached %v", rec.Code, reached)
	}
	// Verified as OIDC, but the token is bad.
	mw, _ := httpmw.NewCaller(httpmw.CallerOptions{Authenticator: fixedOIDC{}, Enforce: true})
	if rec := call(mw.Middleware()(inner), "st1.k1.AAAA"); rec.Code != http.StatusUnauthorized || reached {
		t.Errorf("bad token behind a lenient middleware: %d, reached %v", rec.Code, reached)
	}
	keys.fail = true
	if rec := call(mw.Middleware()(inner), tok); rec.Code != http.StatusServiceUnavailable || reached || rec.Header().Get("Retry-After") != retryAfter {
		t.Errorf("keys gone: %d, reached %v", rec.Code, reached)
	}
}

// fixedOIDC accepts any request as OIDC, to reach attachAS directly.
type fixedOIDC struct{}

func (fixedOIDC) Authenticate(*http.Request) (purser.Caller, error) {
	return purser.Caller{Identity: "x"}, nil
}
func (fixedOIDC) Source() purser.AuthSource { return purser.AuthSourceOIDC }

func TestPrincipalFromContextOutside(t *testing.T) {
	t.Parallel()
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Error("PrincipalFromContext outside a protected request reported one")
	}
	var nilP *Protector
	if nilP.GatesCredentials() {
		t.Error("a nil Protector gates credentials")
	}
}
