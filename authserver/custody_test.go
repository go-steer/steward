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
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// scriptedVault answers retrieve and finalize from a script, one answer
// per call, and Google's tokeninfo for the tokens it hands out.
type scriptedVault struct {
	mu      sync.Mutex
	answers []string // JSON bodies (or "!503" for an outage, "!400 <message>" for a refused call)
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
		if msg, ok := strings.CutPrefix(a, "!400 "); ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"status":"INVALID_ARGUMENT","message":"` + msg + `"}}`))
			return
		}
		_, _ = w.Write([]byte(a))
	})
	mux.HandleFunc("POST /tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		body, ok := info[r.PostForm.Get("access_token")]
		if !ok {
			http.Error(w, `{"error":"invalid_token","error_description":"Invalid Value"}`, http.StatusBadRequest)
			return
		}
		if code, err := strconv.Atoi(strings.TrimPrefix(body, "!")); err == nil {
			http.Error(w, "<html>not Google</html>", code)
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
	"tokShort2": `{"sub":"111","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"40"}`,
	"tokMid":    `{"sub":"111","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"240"}`,
	"tokBob":    `{"sub":"222","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"3600"}`,
	"tokNoCP":   `{"sub":"111","scope":"openid","expires_in":"3600"}`,
	"tokNoSub":  `{"scope":"openid","expires_in":"3600"}`,
	"tokBadExp": `{"sub":"111","scope":"openid","expires_in":"soon"}`,
	"tokProxy":  "!403", // tokeninfo answers 403: an egress proxy, not Google
	"tokMoved":  "!404",
	"tokDown":   "!502",
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

	// refresh and grant: every way a stored grant is refused (reauth:
	// invalid_grant, sign in again) or fails (a retry may work).
	for name, tc := range map[string]struct {
		answers []string
		reauth  bool
	}{
		"needs consent again": {[]string{consentAnswer}, true},
		"declined":            {[]string{`{"consentRejected":{}}`}, true},
		"another account":     {[]string{`{"success":{"token":"tokBob"}}`}, true},
		"no cloud-platform":   {[]string{`{"success":{"token":"tokNoCP"}}`}, true},
		"no sub":              {[]string{`{"success":{"token":"tokNoSub"}}`}, false},
		"bad expiry":          {[]string{`{"success":{"token":"tokBadExp"}}`}, false},
		"outage":              {[]string{"!503"}, false},
		"malformed":           {[]string{`{`}, false},
		"short, still short":  {[]string{tokShort, `{"success":{"token":"tokShort2"}}`}, false},
		"short, same token":   {[]string{tokShort, tokShort}, false},
		"short, then outage":  {[]string{tokShort, "!503"}, false},
		"short, then refused": {[]string{tokShort, `{"success":{"token":"tokGone"}}`}, false},
		// The vault busy is not the grant gone.
		"pending":             {[]string{`{"pending":{}}`}, false},
		"empty":               {[]string{`{}`}, false},
		"no token":            {[]string{`{"success":{}}`}, false},
		"short, then pending": {[]string{tokShort, `{"pending":{}}`}, false},
		// Google refusing the vault's token (tokeninfo 400) forces one
		// refresh; consent then, or Google refusing the new token too, is
		// a refusal. The same token back is the vault failing.
		"refused, then consent": {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer}, true},
		"refused twice":         {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokGone2"}}`}, true},
		"refused, same token":   {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokGone"}}`}, false},
		"refused, then outage":  {[]string{`{"success":{"token":"tokGone"}}`, "!503"}, false},
		"refused, then pending": {[]string{`{"success":{"token":"tokGone"}}`, `{"pending":{}}`}, false},
		"refused, then short":   {[]string{`{"success":{"token":"tokGone"}}`, tokShort}, false},
		"refused, then another": {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokBob"}}`}, true},
		"refused, then 502":     {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokDown"}}`}, false},
		// Anything else from tokeninfo is Google, or something in front
		// of it, failing.
		"tokeninfo 403": {[]string{`{"success":{"token":"tokProxy"}}`}, false},
		"tokeninfo 404": {[]string{`{"success":{"token":"tokMoved"}}`}, false},
		"tokeninfo 502": {[]string{`{"success":{"token":"tokDown"}}`}, false},
	} {
		v, g, sv := newScripted(t, vaultInfo, tc.answers...)
		gr, err := v.refresh(ctx, g, alice, "", "")
		if len(sv.calls) != len(tc.answers) {
			t.Errorf("%s: %d vault calls, want every scripted answer used (%d)", name, len(sv.calls), len(tc.answers))
		}
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
	// The vault will not force-refresh a token that is still valid, and
	// says so by asking for consent: not the grant gone. A forced refresh
	// that brings no better token, short of a refusal, leaves the valid one
	// in use if it has minLiveTokenLife left (tokMid, 4 min), and is a
	// plain error if not (tokShort, 30 s).
	for name, second := range map[string]string{
		"consent":       consentAnswer,
		"same token":    `{"success":{"token":"tokMid"}}`,
		"pending":       `{"pending":{}}`,
		"empty":         `{}`,
		"outage":        "!503",
		"refused":       `{"success":{"token":"tokGone"}}`,
		"still short":   tokShort,
		"tokeninfo 502": `{"success":{"token":"tokDown"}}`,
	} {
		v, g, sv := newScripted(t, vaultInfo, `{"success":{"token":"tokMid"}}`, second)
		if gr, err := v.refresh(ctx, g, alice, "", ""); err != nil || gr.AccessToken != "tokMid" || len(sv.calls) != 2 {
			t.Errorf("4 min token, then %s: %+v %v %v, want tokMid", name, gr, err, sv.calls)
		}
		v, g, _ = newScripted(t, vaultInfo, tokShort, second)
		if gr, err := v.refresh(ctx, g, alice, "", ""); err == nil || errors.Is(err, errReauth) {
			t.Errorf("30 s token, then %s: %+v %v, want a plain error", name, gr, err)
		}
	}
	for name, second := range map[string]string{
		"declined":        `{"consentRejected":{}}`,
		"another account": `{"success":{"token":"tokBob"}}`,
	} {
		v, g, _ := newScripted(t, vaultInfo, `{"success":{"token":"tokMid"}}`, second)
		if gr, err := v.refresh(ctx, g, alice, "", ""); !errors.Is(err, errReauth) {
			t.Errorf("4 min token, then %s: %+v %v, want reauth: a refusal wins", name, gr, err)
		}
	}
	v, g, sv = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, tokA)
	if gr, err := v.refresh(ctx, g, alice, "", ""); err != nil || gr.AccessToken != "tokA" || len(sv.calls) != 2 {
		t.Errorf("token Google refused force-refreshed: %+v %v %v", gr, err, sv.calls)
	}
	// At sign-in the person is in the browser: a grant gone behind a
	// refused token detours through consent; refused twice is access_denied.
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, consentAnswer)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || gr != nil || c == nil || c.URL != "https://consent.example/x" {
		t.Errorf("begin, Google refuses the vault's token, then consent: %+v %+v %v, want a consent detour", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, `{"uriConsentRequired":{"authorizationUri":""}}`)
	if _, c, err := v.begin(ctx, g, alice, nil, ""); err == nil || c != nil || errors.Is(err, errReauth) {
		t.Errorf("begin, refused then an incomplete consent request: %+v %v", c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokGone2"}}`)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); !errors.Is(err, errReauth) || custodyError(err) != "access_denied" {
		t.Errorf("begin, Google refuses the vault's token twice: %+v %+v %v, want access_denied", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, "", `{"success":{"token":"tokGone"}}`, consentAnswer)
	if _, err := v.finish(ctx, g, alice, c1, q("user_id_validation_state", "s"), ""); !errors.Is(err, errReauth) {
		t.Errorf("finish, Google refuses the fresh grant's token, then consent: %v, want reauth", err)
	}
	// A vault error that quotes the forced token back keeps it out of the
	// error, and so out of the log.
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, "!400 forceRefreshToken tokGone is not the latest token")
	if _, err := v.refresh(ctx, g, alice, "", ""); err == nil || strings.Contains(err.Error(), "tokGone") || !strings.Contains(err.Error(), "INVALID_ARGUMENT") {
		t.Errorf("forced refresh refused, quoting the token: %v", err)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"pending":{}}`)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err == nil || custodyError(err) != "server_error" {
		t.Errorf("begin, vault pending: %+v %+v %v, want server_error", gr, c, err)
	}

	unreachable := &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/kg", Client: hc, Endpoint: "http://127.0.0.1:1/v1/"}
	if _, err := unreachable.refresh(ctx, g, alice, "", ""); err == nil {
		t.Error("an unreachable vault answered")
	}
	bad := &VaultCustody{AuthProvider: "x", Client: hc, Endpoint: "http://\x7f/"}
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

// vaultOverride answers the vault's next retrieve calls with canned
// bodies, and hands every other call to the fake vault.
type vaultOverride struct {
	next http.RoundTripper

	mu        sync.Mutex
	retrieves []string
}

func (o *vaultOverride) RoundTrip(r *http.Request) (*http.Response, error) {
	o.mu.Lock()
	if !strings.HasSuffix(r.URL.Path, ":retrieve") || len(o.retrieves) == 0 {
		o.mu.Unlock()
		return o.next.RoundTrip(r)
	}
	body := o.retrieves[0]
	o.retrieves = o.retrieves[1:]
	o.mu.Unlock()
	if r.Body != nil {
		_ = r.Body.Close()
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// overrideVault makes e's vault answer its next retrieves with answers.
// Call it before any request is in flight.
func overrideVault(e *testEnv, answers ...string) {
	vc := e.as.cfg.Custody.(*VaultCustody)
	o := &vaultOverride{next: vc.Client.Transport, retrieves: answers}
	if o.next == nil {
		o.next = http.DefaultTransport
	}
	vc.Client = &http.Client{Transport: o}
}

// A nearly spent vault token whose forced refresh the vault declines (by
// asking for consent) at sign-in: with 4 minutes left it is used, and the
// code exchanges for an access token; with 30 seconds left the sign-in
// fails at the authorize redirect, before a code that could never be
// exchanged is issued. Neither is access_denied.
func TestVaultNearlySpentTokenAtSignIn(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		life int
		ok   bool
	}{{240, true}, {30, false}} {
		e := newTestEnv(t, false, nil)
		e.google.mu.Lock()
		tok := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, c.life)
		e.google.mu.Unlock()
		overrideVault(e, `{"success":{"token":"`+tok+`"}}`, consentAnswer)
		id, v := e.register(), rand.Text()+rand.Text()
		loc, _ := newBrowser(t).visit(e.authorizeURL(id, v, nil))
		if !c.ok {
			if loc == nil || loc.Query().Get("error") != "server_error" {
				t.Errorf("%d s left, refresh declined: %v, want server_error at the redirect", c.life, loc)
			}
			continue
		}
		if loc == nil || loc.Query().Get("code") == "" {
			t.Fatalf("%d s left, refresh declined: %v, want a code", c.life, loc)
		}
		if r := e.token(exchangeForm(id, loc.Query().Get("code"), v), "", ""); r.status != http.StatusOK || r.Expires > int64(c.life-60) {
			t.Errorf("%d s left: exchange %+v, want an access token that stops a minute before the Google token", c.life, r)
		}
	}
}

// A busy vault ("pending") at refresh is the vault failing, not refusing:
// server_error, and the refresh token survives for the retry, rather than
// invalid_grant, which signs the person out. At sign-in it is
// server_error, not access_denied.
func TestVaultPendingIsNotASignOut(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id, first := e.signIn(newBrowser(t))
	overrideVault(e, `{"pending":{}}`)
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" || r.status != http.StatusInternalServerError {
		t.Fatalf("refresh while the vault is pending: %+v, want server_error", r)
	}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry once the vault answers: %+v", r)
	}

	e = newTestEnv(t, false, nil)
	overrideVault(e, `{"pending":{}}`)
	loc, _ := newBrowser(t).visit(e.authorizeURL(e.register(), rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "server_error" {
		t.Errorf("sign-in while the vault is pending: %v, want server_error", loc)
	}
}

// Google's tokeninfo refusing the vault's token (400 invalid_token) is a
// refusal once a forced refresh has not cured it: access_denied at
// sign-in and invalid_grant at refresh, not server_error. A forced refresh
// that asks for consent sends a signing-in person through consent; one
// that cures it carries on.
func TestVaultTokenGoogleRefuses(t *testing.T) {
	t.Parallel()
	const dead, dead2 = `{"success":{"token":"ya29.revoked"}}`, `{"success":{"token":"ya29.revoked-too"}}`
	e := newTestEnv(t, false, nil)
	overrideVault(e, dead, dead2)
	loc, _ := newBrowser(t).visit(e.authorizeURL(e.register(), rand.Text()+rand.Text(), nil))
	if loc == nil || loc.Query().Get("error") != "access_denied" {
		t.Errorf("sign-in, Google refuses the vault's token: %v, want access_denied", loc)
	}
	if strings.Contains(e.log.String(), "ya29.revoked") {
		t.Error("the refused token reached the log")
	}

	// No grant stored for alice: the forced retrieve reaches the fake
	// vault, which asks for consent; sign-in goes through it and succeeds.
	e = newTestEnv(t, false, nil)
	overrideVault(e, dead)
	e.signIn(newBrowser(t))
	if _, ok := e.vault.grantFor(alice.Sub); !ok {
		t.Error("sign-in after a refused token did not go through consent")
	}

	e = newTestEnv(t, false, nil)
	id, first := e.signIn(newBrowser(t))
	overrideVault(e, dead, dead2)
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("refresh, Google refuses the vault's token: %+v, want invalid_grant", r)
	}

	e = newTestEnv(t, false, nil)
	id, first = e.signIn(newBrowser(t))
	overrideVault(e, dead) // the forced retrieve reaches the fake vault
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK || e.vault.forced != 1 {
		t.Errorf("refresh, a token Google refuses then a forced one: %+v, forced %d", r, e.vault.forced)
	}
}
