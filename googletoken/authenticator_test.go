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

package googletoken

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authtest"
	"github.com/go-steer/purser/httpmw"

	"github.com/go-steer/steward/allow"
)

func newAuthenticator(t *testing.T, members ...string) *Authenticator {
	t.Helper()
	good := info(clientID, "Dana@Cymbal.example", "true", now.Add(time.Hour))
	base, _ := fakeGoogle(t, map[string]map[string]string{
		"good":      good,
		"consumer":  with(good, "hd", "", "email", "lee@cymbal.example"),
		"outsider":  with(good, "hd", "evil.example", "email", "eve@evil.example"),
		"other-app": with(good, "aud", "999-other", "azp", "999-other"),
	})
	clock := now
	v := newVerifier(t, base, &clock)
	if len(members) == 0 {
		members = []string{"@cymbal.example"}
	}
	list, err := allow.Parse(members)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthenticator(v, list)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(header string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

// TestAuthenticatorConformance runs purser's contract suite, which every
// authn.Authenticator is expected to pass.
func TestAuthenticatorConformance(t *testing.T) {
	t.Parallel()
	a := newAuthenticator(t)
	authtest.RunAuthenticatorSuite(t, authtest.Subject{
		Authenticator: a,
		WantSource:    purser.AuthSourceGoogleAccessToken,
		Valid: func() (*http.Request, purser.Caller) {
			return request("Bearer good"), purser.Caller{
				Identity: "dana@cymbal.example",
				Labels:   map[string]string{LabelSubject: "1001", LabelHD: "cymbal.example"},
			}
		},
		Malformed: []authtest.MalformedCase{
			{Name: "unknown token", Request: func() *http.Request { return request("Bearer nope") }},
			{Name: "another app's token", Request: func() *http.Request { return request("Bearer other-app") }},
			{Name: "not admitted", Request: func() *http.Request { return request("Bearer outsider") }},
			{Name: "consumer account claiming the domain", Request: func() *http.Request { return request("Bearer consumer") }},
			{Name: "basic scheme", Request: func() *http.Request { return request("Basic Z29vZA==") }},
			{Name: "empty bearer", Request: func() *http.Request { return request("Bearer ") }},
			{Name: "scheme only", Request: func() *http.Request { return request("Bearer") }},
			{Name: "a JWT", Request: func() *http.Request { return request("Bearer eyJh.eyJi.sig") }},
		},
	})
}

func TestAuthenticatorAdmission(t *testing.T) {
	t.Parallel()
	a := newAuthenticator(t, "lee@cymbal.example")

	// Verified, but not on the list: ErrNotAdmitted, which is a credential
	// error to purser.
	_, err := a.Authenticate(request("Bearer good"))
	if !errors.Is(err, ErrNotAdmitted) || !errors.Is(err, purser.ErrUnauthenticated) {
		t.Errorf("unlisted account: %v, want ErrNotAdmitted wrapping ErrUnauthenticated", err)
	}
	// Listed by exact address, consumer account: admitted, no hd label.
	c, err := a.Authenticate(request("Bearer consumer"))
	if err != nil || c.Identity != "lee@cymbal.example" {
		t.Fatalf("listed consumer account: %+v, %v", c, err)
	}
	if _, ok := c.Labels[LabelHD]; ok {
		t.Errorf("consumer account got an hd label: %v", c.Labels)
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	for header, want := range map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "abc",
		"BEARER  abc ": "abc",
		"Bearer":       "",
		"Bearer   ":    "",
		"Basic abc":    "",
		"":             "",
		"abc":          "",
	} {
		got, ok := BearerToken(request(header))
		if got != want || ok != (want != "") {
			t.Errorf("BearerToken(%q) = %q, %v; want %q", header, got, ok, want)
		}
	}
}

func TestNewAuthenticatorRefuses(t *testing.T) {
	t.Parallel()
	v, err := New(Config{ClientIDs: []string{clientID}})
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := allow.Parse(nil)
	list, _ := allow.Parse([]string{"@cymbal.example"})
	if _, err := NewAuthenticator(nil, list); err == nil {
		t.Error("accepted a nil Verifier")
	}
	for _, l := range []*allow.List{nil, empty} {
		if _, err := NewAuthenticator(v, l); err == nil {
			t.Error("accepted an allow-list that admits no one")
		}
	}
}

// TestThroughCallerMiddleware is the integration the design rests on:
// inside purser's enforced CallerMiddleware, a good token reaches the
// handler as the person with the google-access-token verdict, and a bad
// one gets a 401 carrying the configured challenge.
func TestThroughCallerMiddleware(t *testing.T) {
	t.Parallel()
	const challenge = `Bearer resource_metadata="https://svc.example/.well-known/oauth-protected-resource/mcp"`
	mw, err := httpmw.NewCaller(httpmw.CallerOptions{Authenticator: newAuthenticator(t), Enforce: true, Challenge: challenge})
	if err != nil {
		t.Fatal(err)
	}
	if !mw.GatesCredentials() {
		t.Error("an enforced middleware over this authenticator does not report gating credentials")
	}
	var got purser.Caller
	var source purser.AuthSource
	h := mw.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = purser.CallerFromContext(r.Context())
		source, _ = purser.AuthSourceFromContext(r.Context())
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("Bearer good"))
	if rec.Code != http.StatusOK || got.Identity != "dana@cymbal.example" || source != purser.AuthSourceGoogleAccessToken {
		t.Errorf("good token: %d, %q, %q", rec.Code, got.Identity, source)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request("Bearer outsider"))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != challenge {
		t.Errorf("outsider: %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}
