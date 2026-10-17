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

// Ported from kode-gopher internal/oauth client_credentials_test.go at
// 8b53617b7d4d0b08b158de64ab7416dc84a1281e.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const runnerSA = "runner@proj-sa.iam.gserviceaccount.com"

// fakeMinter stands in for an IAM Credentials impersonator.
type fakeMinter struct {
	mu    sync.Mutex
	calls []string
	fail  bool
}

func (m *fakeMinter) Token(_ context.Context, sa string) (*oauth2.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, sa)
	if m.fail {
		return nil, errors.New("permission denied")
	}
	return &oauth2.Token{AccessToken: fmt.Sprintf("ya29.fake-sa-%d", len(m.calls)), Expiry: time.Now().Add(time.Hour)}, nil
}

// newServiceEnv has a client-credentials client "ci" with a service
// account, one "bot" without, a read-only one "reader", and a user client
// "cli" that also has a secret.
func newServiceEnv(t *testing.T) (*testEnv, *fakeMinter) {
	m := &fakeMinter{}
	e := newTestEnv(t, false, func(c *Config) {
		c.Clients = []StaticClient{
			{ID: "ci", Secret: "ci-secret", Name: "CI", ServiceAccount: runnerSA},
			{ID: "bot", Secret: "bot-secret", ClientCredentials: true},
			{ID: "reader", Secret: "reader-secret", ClientCredentials: true, Scopes: []string{scopeRead}},
			{ID: "cli", Secret: "cli-secret", RedirectURIs: []string{clientRedirect}},
		}
		c.ServiceTokens = m
	})
	return e, m
}

func ccForm(set map[string]string) url.Values {
	f := url.Values{"grant_type": {"client_credentials"}}
	for k, v := range set {
		f.Set(k, v)
	}
	return f
}

func TestClientCredentialsToken(t *testing.T) {
	t.Parallel()
	e, m := newServiceEnv(t)
	ctx := context.Background()

	// client_secret_basic, then client_secret_post with explicit scope and
	// resource.
	for _, r := range []tokenResp{
		e.token(ccForm(nil), "ci", "ci-secret"),
		e.token(ccForm(map[string]string{"client_id": "ci", "client_secret": "ci-secret", "scope": scopeRead, "resource": e.as.Resource()}), "", ""),
	} {
		if r.status != http.StatusOK || r.Access == "" || r.Refresh != "" || r.Scope != scopeRead || r.Expires <= 0 || r.Expires > int64(AccessTTL.Seconds()) {
			t.Fatalf("client_credentials = %d %+v; want an access token, no refresh token", r.status, r)
		}
		p, err := e.as.Verify(ctx, r.Access)
		if err != nil {
			t.Fatal(err)
		}
		if p.Subject != "client:ci" || !p.Workload || p.ServiceAccount != runnerSA || p.Email != "" {
			t.Errorf("verified as %+v", p)
		}
		ts, ok := p.TokenSource()
		if !ok {
			t.Fatal("a workload with a service account has no token source")
		}
		if tok, _ := ts.Token(); !strings.HasPrefix(tok.AccessToken, "ya29.fake-sa-") {
			t.Errorf("service account token = %q", tok.AccessToken)
		}
		c := p.Caller()
		if c.Identity != "client:ci" || c.Label(LabelKind) != KindWorkload || c.Label(LabelServiceAccount) != runnerSA || c.Label(LabelSubject) != "" {
			t.Errorf("Caller = %+v", c)
		}
	}
	if len(m.calls) != 2 || m.calls[0] != runnerSA {
		t.Errorf("minted for %v, want [%s %s]", m.calls, runnerSA, runnerSA)
	}

	// A workload with no service account: a caller, and no Google token.
	r := e.token(ccForm(map[string]string{"scope": scopeRead + " " + scopeWrite}), "bot", "bot-secret")
	if r.status != http.StatusOK || r.Scope != scopeRead+" "+scopeWrite {
		t.Fatalf("bot: %+v", r)
	}
	status, got, _ := e.call(r.Access)
	if status != http.StatusOK || got != "client:bot workload svc:read,svc:write -" {
		t.Errorf("resource as the bot: %d %q", status, got)
	}
	if p, _ := e.as.Verify(ctx, r.Access); p.ServiceAccount != "" {
		t.Errorf("bot has a service account: %+v", p)
	} else if _, ok := p.TokenSource(); ok {
		t.Error("a workload without a service account has a token source")
	}
	if len(m.calls) != 2 {
		t.Errorf("minted for a client without a service account: %v", m.calls)
	}

	for name, tc := range map[string]struct {
		form         url.Values
		id, secret   string
		status       int
		wantErrorFor string
	}{
		"wrong secret":   {ccForm(nil), "ci", "nope", http.StatusUnauthorized, "invalid_client"},
		"no secret":      {ccForm(map[string]string{"client_id": "ci"}), "", "", http.StatusUnauthorized, "invalid_client"},
		"user client":    {ccForm(nil), "cli", "cli-secret", http.StatusBadRequest, "unauthorized_client"},
		"public client":  {ccForm(map[string]string{"client_id": e.register()}), "", "", http.StatusBadRequest, "unauthorized_client"},
		"other resource": {ccForm(map[string]string{"resource": "https://elsewhere.example/mcp"}), "ci", "ci-secret", http.StatusBadRequest, "invalid_target"},
		"two resources":  {url.Values{"grant_type": {"client_credentials"}, "resource": {e.as.Resource(), e.as.Resource()}}, "ci", "ci-secret", http.StatusBadRequest, "invalid_target"},
	} {
		r := e.token(tc.form, tc.id, tc.secret)
		if r.status != tc.status || r.Error != tc.wantErrorFor || r.Access != "" {
			t.Errorf("%s: %d %q, want %d %q", name, r.status, r.Error, tc.status, tc.wantErrorFor)
		}
	}

	// Scopes the client may not have are dropped, not refused (the MCP
	// SDK's client asks for everything advertised); unknown ones too.
	for name, tc := range map[string]struct {
		id, secret, scope, want string
	}{
		"beyond its scope": {"reader", "reader-secret", scopeRead + " " + scopeWrite, scopeRead},
		"unknown scope":    {"ci", "ci-secret", "openid", scopeRead},
	} {
		r := e.token(ccForm(map[string]string{"scope": tc.scope}), tc.id, tc.secret)
		if r.status != http.StatusOK || r.Scope != tc.want {
			t.Errorf("%s: %d %q %q, want scope %q", name, r.status, r.Error, r.Scope, tc.want)
		}
	}
	if r := e.token(ccForm(map[string]string{"scope": scopeWrite}), "reader", "reader-secret"); r.status != http.StatusOK || r.Scope != scopeRead {
		t.Errorf("only a scope beyond the client's: %+v, want its default", r)
	}
}

func TestClientCredentialsNoScopeAvailable(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, func(c *Config) {
		c.DefaultScopes = []string{scopeRead}
		c.Clients = []StaticClient{{ID: "w", Secret: "s", ClientCredentials: true, Scopes: []string{scopeWrite}}}
	})
	if r := e.token(ccForm(nil), "w", "s"); r.Error != "invalid_scope" {
		t.Errorf("no default scope available: %+v", r)
	}
	if r := e.token(ccForm(map[string]string{"scope": scopeWrite}), "w", "s"); r.status != http.StatusOK || r.Scope != scopeWrite {
		t.Errorf("asking for its own scope: %+v", r)
	}
}

func TestClientCredentialsMintFails(t *testing.T) {
	t.Parallel()
	e, m := newServiceEnv(t)
	m.fail = true
	if r := e.token(ccForm(nil), "ci", "ci-secret"); r.status != http.StatusInternalServerError || r.Error != "server_error" {
		t.Errorf("mint failure: %d %q, want 500 server_error", r.status, r.Error)
	}
}

// Changing or removing a client, or narrowing its scopes, revokes its
// tokens.
func TestClientCredentialsRevokedByConfig(t *testing.T) {
	t.Parallel()
	e, _ := newServiceEnv(t)
	ctx := context.Background()
	r := e.token(ccForm(nil), "ci", "ci-secret")
	rw := e.token(ccForm(map[string]string{"scope": scopeRead + " " + scopeWrite}), "bot", "bot-secret")
	e.as.static["ci"] = StaticClient{ID: "ci", Secret: "ci-secret", ServiceAccount: "other@proj-sa.iam.gserviceaccount.com"}
	if _, err := e.as.Verify(ctx, r.Access); err == nil {
		t.Error("token still valid after the client's service account changed")
	}
	delete(e.as.static, "ci")
	if _, err := e.as.Verify(ctx, r.Access); err == nil {
		t.Error("token still valid after the client was removed")
	}
	e.as.static["bot"] = StaticClient{ID: "bot", Secret: "bot-secret", ClientCredentials: true, Scopes: []string{scopeRead}}
	if _, err := e.as.Verify(ctx, rw.Access); err == nil {
		t.Error("token still valid after the client's scopes were narrowed")
	}
	e.as.static["bot"] = StaticClient{ID: "bot", Secret: "bot-secret", RedirectURIs: []string{clientRedirect}}
	if _, err := e.as.Verify(ctx, rw.Access); err == nil {
		t.Error("token still valid after the client stopped being a workload")
	}
}

func TestClientCredentialsNoSignIn(t *testing.T) {
	t.Parallel()
	e, _ := newServiceEnv(t)
	loc, page := newBrowser(t).visit(e.authorizeURL("ci", strings.Repeat("v", 43), nil))
	if loc != nil || !strings.Contains(page, "own credentials") {
		t.Errorf("authorization request for a client-credentials client: redirect %v", loc)
	}
	var m map[string]any
	resp, err := hc.Get(e.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if g := fmt.Sprint(m["grant_types_supported"]); !strings.Contains(g, "client_credentials") {
		t.Errorf("grant_types_supported = %s, want client_credentials", g)
	}
}

func TestServiceClientConfig(t *testing.T) {
	t.Parallel()
	base := func() Config {
		return Config{
			Issuer: "https://svc.example.com", Resource: "https://svc.example.com/mcp", Scopes: []string{scopeRead},
			Google: GoogleClient{ClientID: "g", ClientSecret: "s"}, Custody: SealedCustody{},
			Admit: newAdmitter(t, &fakeGroups{}), Keys: testKeys,
		}
	}
	for name, tc := range map[string]struct {
		c      StaticClient
		minter ServiceTokens
	}{
		"no minter":       {StaticClient{ID: "ci", Secret: "s", ServiceAccount: runnerSA}, nil},
		"no secret":       {StaticClient{ID: "ci", ServiceAccount: runnerSA}, &fakeMinter{}},
		"cc no secret":    {StaticClient{ID: "ci", ClientCredentials: true}, nil},
		"redirect uris":   {StaticClient{ID: "ci", Secret: "s", ServiceAccount: runnerSA, RedirectURIs: []string{clientRedirect}}, &fakeMinter{}},
		"not an email":    {StaticClient{ID: "ci", Secret: "s", ServiceAccount: "runner"}, &fakeMinter{}},
		"unknown scope":   {StaticClient{ID: "ci", Secret: "s", ClientCredentials: true, Scopes: []string{"svc:admin"}}, nil},
		"bad redirect":    {StaticClient{ID: "u", RedirectURIs: []string{"http://evil.example/cb"}}, nil},
		"url id":          {StaticClient{ID: "https://x.example/c", RedirectURIs: []string{clientRedirect}}, nil},
		"sealed id":       {StaticClient{ID: "st1.k1.x", RedirectURIs: []string{clientRedirect}}, nil},
		"no redirect uri": {StaticClient{ID: "u"}, nil},
	} {
		cfg := base()
		cfg.Clients, cfg.ServiceTokens = []StaticClient{tc.c}, tc.minter
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted %+v", name, tc.c)
		}
	}

	path := filepath.Join(t.TempDir(), "clients.json")
	_ = os.WriteFile(path, []byte(`[{"client_id":"ci","client_secret":"s","service_account":"`+runnerSA+`"},{"client_id":"bot","client_secret":"s","client_credentials":true,"scopes":["svc:read"]}]`), 0o600)
	cs, err := LoadStaticClients(path)
	if err != nil || len(cs) != 2 || cs[0].ServiceAccount != runnerSA || !cs[1].ClientCredentials || cs[1].Scopes[0] != scopeRead {
		t.Errorf("LoadStaticClients = %+v, %v", cs, err)
	}
	_ = os.WriteFile(path, []byte(`[{"client_id":"ci","service_account":"`+runnerSA+`"}]`), 0o600)
	if _, err := LoadStaticClients(path); err == nil {
		t.Error("LoadStaticClients accepted a client-credentials client without a secret")
	}
	_ = os.WriteFile(path, []byte(`{`), 0o600)
	if _, err := LoadStaticClients(path); err == nil {
		t.Error("LoadStaticClients accepted malformed JSON")
	}
	if _, err := LoadStaticClients(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("LoadStaticClients read a missing file")
	}
}
