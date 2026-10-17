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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// scriptedVault answers retrieve and finalize from a script, one answer
// per call, and Google's tokeninfo for the tokens it hands out.
type scriptedVault struct {
	mu      sync.Mutex
	answers []string // JSON bodies (or "!503" for an outage)
	calls   []string
}

func (v *scriptedVault) handler(t *testing.T, info map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		defer v.mu.Unlock()
		v.calls = append(v.calls, r.URL.Path[strings.LastIndex(r.URL.Path, ":")+1:])
		if len(v.answers) == 0 {
			t.Errorf("unscripted vault call %s", r.URL.Path)
			http.Error(w, "unscripted", http.StatusInternalServerError)
			return
		}
		a := v.answers[0]
		v.answers = v.answers[1:]
		if a == "!503" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"status":"UNAVAILABLE"}}`))
			return
		}
		_, _ = w.Write([]byte(a))
	})
	mux.HandleFunc("POST /tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		body, ok := info[r.PostForm.Get("access_token")]
		if !ok {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	return mux
}

func newScripted(t *testing.T, info map[string]string, answers ...string) (*VaultCustody, *upstream, *scriptedVault) {
	v := &scriptedVault{answers: answers}
	srv := httptest.NewServer(v.handler(t, info))
	t.Cleanup(srv.Close)
	g := &upstream{client: &GoogleClient{TokenInfoURL: srv.URL + "/tokeninfo"}, hc: srv.Client(), scopes: []string{ScopeCloudPlatform}}
	return &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/kg", Client: srv.Client(), Endpoint: srv.URL + "/v1/"}, g, v
}

const (
	consentAnswer = `{"uriConsentRequired":{"authorizationUri":"https://consent.example/x","consentNonce":"n1","uid":"u1"}}`
	tokA          = `{"success":{"token":"tokA"}}`
	tokShort      = `{"success":{"token":"tokShort"}}`
)

var vaultInfo = map[string]string{
	"tokA":      `{"sub":"111","scope":"openid https://www.googleapis.com/auth/cloud-platform","expires_in":"3600"}`,
	"tokShort":  `{"sub":"111","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"30"}`,
	"tokBob":    `{"sub":"222","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"3600"}`,
	"tokNoCP":   `{"sub":"111","scope":"openid","expires_in":"3600"}`,
	"tokNoSub":  `{"scope":"openid","expires_in":"3600"}`,
	"tokBadExp": `{"sub":"111","scope":"openid","expires_in":"soon"}`,
}

func TestVaultCustodyEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	q := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	c1 := consent{Nonce: "n1", UID: "u1"}

	// begin: consent detour, incomplete consent, a token straight away.
	v, g, _ := newScripted(t, vaultInfo, consentAnswer)
	if gr, c, err := v.begin(ctx, g, alice, nil, "https://svc.example/continue"); err != nil || gr != nil || c == nil || c.URL != "https://consent.example/x" {
		t.Errorf("begin with consent: %v %+v %v", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"uriConsentRequired":{"authorizationUri":""}}`)
	if _, _, err := v.begin(ctx, g, alice, nil, ""); err == nil {
		t.Error("begin accepted an incomplete consent request")
	}
	v, g, _ = newScripted(t, vaultInfo, tokA)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || c != nil || gr.AccessToken != "tokA" {
		t.Errorf("begin with a stored grant: %+v %v %v", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, "!503")
	if _, _, err := v.begin(ctx, g, alice, nil, ""); err == nil || errors.Is(err, errReauth) || !strings.Contains(err.Error(), "UNAVAILABLE") {
		t.Errorf("begin during an outage: %v", err)
	}

	// finish: callback checks, then finalize and retrieve.
	v, g, _ = newScripted(t, vaultInfo)
	if _, err := v.finish(ctx, g, alice, c1, q("uuid", "other", "user_id_validation_state", "s"), ""); err == nil {
		t.Error("finish accepted another flow's callback")
	}
	if _, err := v.finish(ctx, g, alice, c1, q("uuid", "u1"), ""); err == nil {
		t.Error("finish accepted a callback without a validation state")
	}
	v, g, sv := newScripted(t, vaultInfo, "", tokA)
	if gr, err := v.finish(ctx, g, alice, c1, q("uuid", "u1", "user_id_validation_state", "s"), ""); err != nil || gr.AccessToken != "tokA" {
		t.Errorf("finish: %+v %v", gr, err)
	}
	if strings.Join(sv.calls, ",") != "finalize,retrieve" {
		t.Errorf("finish called %v", sv.calls)
	}
	v, g, _ = newScripted(t, vaultInfo, "!503")
	if _, err := v.finish(ctx, g, alice, c1, q("user_id_validation_state", "s"), ""); err == nil {
		t.Error("finish ignored a finalize failure")
	}
	v, g, _ = newScripted(t, vaultInfo, "", "!503")
	if _, err := v.finish(ctx, g, alice, c1, q("user_id_validation_state", "s"), ""); err == nil {
		t.Error("finish ignored a retrieve failure")
	}
	v, g, _ = newScripted(t, vaultInfo, "", consentAnswer)
	if _, err := v.finish(ctx, g, alice, c1, q("user_id_validation_state", "s"), ""); err == nil {
		t.Error("finish accepted a vault still asking for consent")
	}

	// refresh and grant: every way a stored grant is refused.
	for name, tc := range map[string]struct {
		answers []string
		reauth  bool
	}{
		"needs consent again": {[]string{consentAnswer}, true},
		"declined":            {[]string{`{"consentRejected":{}}`}, true},
		"pending":             {[]string{`{"pending":{}}`}, true},
		"another account":     {[]string{`{"success":{"token":"tokBob"}}`}, true},
		"no cloud-platform":   {[]string{`{"success":{"token":"tokNoCP"}}`}, true},
		"unknown to Google":   {[]string{`{"success":{"token":"tokGone"}}`}, false},
		"no sub":              {[]string{`{"success":{"token":"tokNoSub"}}`}, false},
		"bad expiry":          {[]string{`{"success":{"token":"tokBadExp"}}`}, false},
		"outage":              {[]string{"!503"}, false},
		"malformed":           {[]string{`{`}, false},
		"short, still short":  {[]string{tokShort, tokShort}, false},
		"short, then consent": {[]string{tokShort, consentAnswer}, true},
		"short, then outage":  {[]string{tokShort, "!503"}, false},
	} {
		v, g, _ := newScripted(t, vaultInfo, tc.answers...)
		gr, err := v.refresh(ctx, g, alice, "", "")
		if err == nil {
			t.Errorf("%s: refresh accepted %+v", name, gr)
			continue
		}
		if errors.Is(err, errReauth) != tc.reauth {
			t.Errorf("%s: %v, reauth=%v want %v", name, err, errors.Is(err, errReauth), tc.reauth)
		}
	}
	v, g, sv = newScripted(t, vaultInfo, tokShort, tokA)
	if gr, err := v.refresh(ctx, g, alice, "", ""); err != nil || gr.AccessToken != "tokA" || len(sv.calls) != 2 {
		t.Errorf("short token force-refreshed: %+v %v %v", gr, err, sv.calls)
	}

	unreachable := &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/kg", Client: http.DefaultClient, Endpoint: "http://127.0.0.1:1/v1/"}
	if _, err := unreachable.refresh(ctx, g, alice, "", ""); err == nil {
		t.Error("an unreachable vault answered")
	}
	bad := &VaultCustody{AuthProvider: "x", Client: http.DefaultClient, Endpoint: "http://\x7f/"}
	if _, err := bad.refresh(ctx, g, alice, "", ""); err == nil {
		t.Error("a malformed vault endpoint answered")
	}
	var asked string
	dflt := &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/kg", Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		asked = r.URL.String()
		return nil, errors.New("offline")
	})}}
	if _, err := dflt.refresh(ctx, g, alice, "", ""); err == nil || asked != VaultEndpoint+"projects/p/locations/l/authProviders/kg/credentials:retrieve" {
		t.Errorf("default endpoint: asked %q, err %v", asked, err)
	}
}

func TestSealedCustodyRefreshScopes(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"full scope, rotated": {`{"access_token":"a","expires_in":3600,"scope":"openid https://www.googleapis.com/auth/cloud-platform","refresh_token":"r2"}`, true},
		"no scope reported":   {`{"access_token":"a","expires_in":3600}`, true},
		"scope narrowed":      {`{"access_token":"a","expires_in":3600,"scope":"openid"}`, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
		g := &upstream{client: &GoogleClient{TokenURL: srv.URL}, hc: srv.Client(), scopes: []string{ScopeCloudPlatform}}
		gr, err := SealedCustody{}.refresh(context.Background(), g, alice, "r1", "")
		srv.Close()
		if (err == nil) != tc.ok {
			t.Errorf("%s: %+v %v", name, gr, err)
			continue
		}
		if err != nil && !errors.Is(err, errReauth) {
			t.Errorf("%s: %v, want reauth", name, err)
		}
		if err == nil && name == "full scope, rotated" && gr.Secret != "r2" {
			t.Errorf("%s: rotated refresh token not kept: %q", name, gr.Secret)
		}
		if err == nil && name == "no scope reported" && gr.Secret != "r1" {
			t.Errorf("%s: refresh token lost: %q", name, gr.Secret)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer srv.Close()
	g := &upstream{client: &GoogleClient{TokenURL: srv.URL}, hc: srv.Client(), scopes: []string{ScopeCloudPlatform}}
	if _, err := (SealedCustody{}).refresh(context.Background(), g, alice, "r1", ""); err == nil || errors.Is(err, errReauth) {
		t.Errorf("Google 502 at refresh: %v, want a transient error", err)
	}
}
