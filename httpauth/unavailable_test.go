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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-steer/purser"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/authserver"
	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/internal/pathbtest"
)

// Outages through the whole Protector, as a consumer mounts it: since
// purser v0.3.0 (purser#23) an authenticator that cannot reach a verdict
// is a 503 with Retry-After, not a 401, so a client keeps its credential
// and retries instead of signing in again.

func TestSentinelsWrapPurserUnavailable(t *testing.T) {
	for name, err := range map[string]error{
		"googletoken.ErrUnavailable": googletoken.ErrUnavailable,
		"authserver.ErrUnavailable":  authserver.ErrUnavailable,
	} {
		if !errors.Is(err, purser.ErrUnavailable) || errors.Is(err, purser.ErrUnauthenticated) {
			t.Errorf("%s must wrap purser.ErrUnavailable and not purser.ErrUnauthenticated", name)
		}
	}
}

// TestPathAGoogleDownIs503: Google not answering tokeninfo.
func TestPathAGoogleDownIs503(t *testing.T) {
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
	rec := call(p.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true })), "good")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || rec.Header().Get("WWW-Authenticate") != "" || ran {
		t.Errorf("Google down: %d, Retry-After %q, WWW-Authenticate %q, handler ran %v; want 503 with Retry-After and no challenge",
			rec.Code, rec.Header().Get("Retry-After"), rec.Header().Get("WWW-Authenticate"), ran)
	}
}

// TestPathBKeysDownIs503: the sealing keys unavailable when a steward
// token arrives.
func TestPathBKeysDownIs503(t *testing.T) {
	t.Parallel()
	keys := &failingKeys{k: testKeys(t)}
	e := newASEnv(t, keys)
	p, err := New(Options{AuthServer: e.as, Resource: e.as.Resource()})
	if err != nil {
		t.Fatal(err)
	}
	tok := pathbtest.ClientCredentials(t, e.srv.URL, "ci", "ci-secret")
	keys.fail = true
	ran := false
	rec := call(p.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true })), tok)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || ran {
		t.Errorf("keys down: %d, Retry-After %q, handler ran %v; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"), ran)
	}
}
