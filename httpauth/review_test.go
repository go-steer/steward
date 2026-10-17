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

// Regression tests for the adversarial review of Path B in httpauth.

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/authserver"
	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/internal/pathbtest"
)

// A workload never gets a person's token or identity, even when it has a
// service account whose token rides in its access token.
func TestWorkloadWithServiceAccountIsNoPerson(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	p, err := New(Options{Authenticator: authenticator(t), AuthServer: e.as, Resource: e.as.Resource()})
	if err != nil {
		t.Fatal(err)
	}
	var reached bool
	h := p.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		if _, ok := TokenSourceFromContext(r.Context()); ok {
			t.Error("a workload got a person's token source")
		}
		if _, ok := IdentityFromContext(r.Context()); ok {
			t.Error("a workload got a person's identity")
		}
		pr, ok := PrincipalFromContext(r.Context())
		if !ok || !pr.Workload || pr.ServiceAccount != pathbtest.RobotSA {
			t.Errorf("principal = %+v, %v", pr, ok)
			return
		}
		ts, ok := pr.TokenSource()
		if !ok {
			t.Fatal("the workload's service-account token is missing")
		}
		if tok, _ := ts.Token(); tok.AccessToken != "ya29.sa-"+pathbtest.RobotSA {
			t.Errorf("service-account token = %q", tok.AccessToken)
		}
	}))
	if rec := call(h, pathbtest.ClientCredentials(t, e.srv.URL, "robot", "r-secret")); rec.Code != http.StatusOK || !reached {
		t.Errorf("robot workload: %d %s", rec.Code, rec.Body.String())
	}
}

// For a person on Path B, the Identity carries the Google token's expiry
// and scopes, as on Path A: not the steward token's.
func TestPathBIdentityIsGoogles(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	p, err := New(Options{AuthServer: e.as, Resource: e.as.Resource()})
	if err != nil {
		t.Fatal(err)
	}
	h := p.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFromContext(r.Context())
		pr, _ := PrincipalFromContext(r.Context())
		if !ok || id.Subject != dana.Sub || id.Email != dana.Email || id.HD != dana.HD {
			t.Errorf("identity = %+v, %v", id, ok)
		}
		if !slices.Contains(id.Scopes, authserver.ScopeCloudPlatform) || slices.Contains(id.Scopes, scopeRead) {
			t.Errorf("identity scopes = %v, want the Google token's", id.Scopes)
		}
		// The Google token lives about an hour; the steward token 15 minutes.
		if !id.Expiry.After(pr.Expiry.Add(30*time.Minute)) || id.Expiry.After(time.Now().Add(time.Hour)) {
			t.Errorf("identity expiry %v, steward token %v: want the Google token's", id.Expiry, pr.Expiry)
		}
	}))
	if rec := call(h, pathbtest.PersonToken(t, e.srv.URL, e.as.Resource(), "")); rec.Code != http.StatusOK {
		t.Errorf("person: %d %s", rec.Code, rec.Body.String())
	}
}

// A steward token at a Protector that takes only Google tokens is refused
// locally: it never reaches Google's tokeninfo.
func TestSealedTokenNeverSentToGoogle(t *testing.T) {
	t.Parallel()
	var asked atomic.Int32
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		http.Error(w, "{}", http.StatusBadRequest)
	}))
	defer google.Close()
	v, err := googletoken.New(googletoken.Config{ClientIDs: []string{clientID}, TokenInfoURL: google.URL + "/tokeninfo", UserInfoURL: google.URL + "/userinfo"})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := allow.Parse([]string{"@cymbal.example"})
	a, err := googletoken.NewAuthenticator(v, list)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Authenticator: a, Resource: "https://svc.example/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	rec := call(p.Middleware()(report), "st1.k1.some-steward-token")
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != p.Challenge() {
		t.Errorf("steward token at a Path A resource: %d", rec.Code)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("Google was asked about a steward token %d times", n)
	}
}

// The challenge asks for the authorization server's default scopes, so
// generic clients request least privilege; the metadata lists them all.
// Explicit Scopes must be the server's.
func TestChallengeAsksForDefaultScopes(t *testing.T) {
	t.Parallel()
	e := newASEnv(t, nil)
	cfgScopes := func(defaults []string) *authserver.Server {
		t.Helper()
		list, _ := allow.Parse([]string{"@cymbal.example"})
		adm, _ := allow.NewAdmitter(list, nil)
		as, err := authserver.New(authserver.Config{
			Issuer: e.srv.URL, Resource: e.srv.URL + "/mcp", Scopes: []string{scopeRead, scopeWrite}, DefaultScopes: defaults,
			Google: e.signIn.Google(), Custody: authserver.SealedCustody{}, Admit: adm, Keys: testKeys(t),
		})
		if err != nil {
			t.Fatal(err)
		}
		return as
	}
	p, err := New(Options{AuthServer: cfgScopes([]string{scopeRead}), Resource: e.srv.URL + "/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.Challenge(), `scope="svc:read"`) {
		t.Errorf("challenge = %q, want the default scope only", p.Challenge())
	}
	rec := httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p.MetadataPath(), nil))
	if !strings.Contains(rec.Body.String(), `"scopes_supported":["svc:read","svc:write"]`) {
		t.Errorf("metadata = %s", rec.Body.String())
	}
	if _, err := New(Options{AuthServer: e.as, Resource: e.as.Resource(), Scopes: []string{"openid"}}); err == nil {
		t.Error("Scopes the authorization server does not have were accepted")
	}
}
