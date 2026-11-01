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
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-steer/steward/seal"
)

// scriptedVault answers retrieve and finalize from a script, one answer
// per call, and Google's tokeninfo for the tokens it hands out.
type scriptedVault struct {
	mu      sync.Mutex
	answers []string // JSON bodies (or "!503" for an outage, "!400 <message>" for a refused call)
	calls   []string
	forced  []string          // forceRefreshToken of each call ("" if none)
	waits   []time.Duration   // nearly spent tokens waited out
	info    map[string]string // tokeninfo answers, by token
	expire  bool              // a wait expires the tokens it outlasts
}

// sleep stands in for waiting out a nearly spent token: it records the
// wait and, if v.expire, expires every token with no more life than that.
func (v *scriptedVault) sleep(_ context.Context, d time.Duration) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.waits = append(v.waits, d)
	for tok, body := range v.info {
		var ti struct {
			ExpiresIn string `json:"expires_in"`
		}
		if json.Unmarshal([]byte(body), &ti) != nil {
			continue
		}
		if secs, err := strconv.Atoi(ti.ExpiresIn); err == nil && v.expire && time.Duration(secs)*time.Second <= d {
			delete(v.info, tok)
		}
	}
	return nil
}

func (v *scriptedVault) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ForceRefreshToken string `json:"forceRefreshToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		v.mu.Lock()
		defer v.mu.Unlock()
		v.calls = append(v.calls, r.URL.Path[strings.LastIndex(r.URL.Path, ":")+1:])
		v.forced = append(v.forced, body.ForceRefreshToken)
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
		v.mu.Lock()
		body, ok := v.info[r.PostForm.Get("access_token")]
		v.mu.Unlock()
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

// newScripted is a VaultCustody in front of a scripted vault whose
// tokeninfo answers from a copy of info. Waiting out a nearly spent token
// takes no time and, as it would, expires the tokens it outlasts.
func newScripted(t *testing.T, info map[string]string, answers ...string) (*VaultCustody, *upstream, *scriptedVault) {
	v := &scriptedVault{answers: answers, info: maps.Clone(info), expire: true}
	srv := httptest.NewServer(v.handler(t))
	t.Cleanup(srv.Close)
	g := &upstream{client: &GoogleClient{TokenInfoURL: srv.URL + "/tokeninfo"}, hc: srv.Client(), scopes: []string{ScopeCloudPlatform}}
	return &VaultCustody{AuthProvider: "projects/p/locations/l/authProviders/kg", Client: srv.Client(), Endpoint: srv.URL + "/v1/", sleeper: &sleeper{v.sleep}}, g, v
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
	"tok100":    `{"sub":"111","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"100"}`,
	"tok80":     `{"sub":"111","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"80"}`,
	"tokBob":    `{"sub":"222","scope":"https://www.googleapis.com/auth/cloud-platform","expires_in":"3600"}`,
	"tokNoCP":   `{"sub":"111","scope":"openid","expires_in":"3600"}`,
	"tokNoSub":  `{"scope":"openid","expires_in":"3600"}`,
	"tokBadExp": `{"sub":"111","scope":"openid","expires_in":"soon"}`,
	"tokProxy":  "!403", // tokeninfo answers 403: an egress proxy, not Google
	"tokProxy4": "!400", // a 400 that is not Google's invalid_token
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
		// A nearly spent token is waited out, then the vault asked again
		// (plainly): another short token, an outage or the vault busy is
		// a failure; consent, the grant gone. The expired token back is
		// force-refreshed, as is any token Google refuses.
		"short, still short":           {[]string{tokShort, `{"success":{"token":"tokShort2"}}`}, false},
		"short, then outage":           {[]string{tokShort, "!503"}, false},
		"short, then consent":          {[]string{tokShort, consentAnswer}, true},
		"short, then declined":         {[]string{tokShort, `{"consentRejected":{}}`}, true},
		"short, then refused, consent": {[]string{tokShort, `{"success":{"token":"tokGone"}}`, consentAnswer, consentAnswer}, true},
		"short, then refused, outage":  {[]string{tokShort, `{"success":{"token":"tokGone"}}`, "!503"}, false},
		// Consent to renew the token steward itself waited out is not
		// yet read as the grant gone (a vault judging expiry by its own
		// expireTime would answer so for a live grant).
		"short, expired back, consent":     {[]string{tokShort, tokShort, consentAnswer, tokShort}, false},
		"short, expired back, same token":  {[]string{tokShort, tokShort, tokShort}, false},
		"short, expired back, pending":     {[]string{tokShort, tokShort, `{"pending":{}}`}, false},
		"short, expired back, still short": {[]string{tokShort, tokShort, `{"success":{"token":"tokShort2"}}`}, false},
		// The vault busy is not the grant gone.
		"pending":             {[]string{`{"pending":{}}`}, false},
		"empty":               {[]string{`{}`}, false},
		"no token":            {[]string{`{"success":{}}`}, false},
		"short, then pending": {[]string{tokShort, `{"pending":{}}`}, false},
		// Google refusing the vault's token (tokeninfo 400) forces one
		// refresh; consent then, or Google refusing the new token too, is
		// a refusal. The same token back is the vault failing.
		"refused, then consent": {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, `{"success":{"token":"tokGone"}}`}, true},
		// Checked again: consent there too, the vault busy, or a token
		// Google refuses keep the verdict (or refuse); an outage is a
		// failure.
		"refused, consent, consent again": {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, consentAnswer}, true},
		"refused, consent, pending":       {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, `{"pending":{}}`}, true},
		"refused, consent, another gone":  {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, `{"success":{"token":"tokGone2"}}`}, true},
		"refused, consent, a short token": {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, tokShort}, true},
		"refused, consent, tokeninfo 502": {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, `{"success":{"token":"tokDown"}}`}, false},
		"refused, consent, outage":        {[]string{`{"success":{"token":"tokGone"}}`, consentAnswer, "!503"}, false},
		"refused twice":                   {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokGone2"}}`}, true},
		"refused, same token":             {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokGone"}}`}, false},
		"refused, then outage":            {[]string{`{"success":{"token":"tokGone"}}`, "!503"}, false},
		"refused, then pending":           {[]string{`{"success":{"token":"tokGone"}}`, `{"pending":{}}`}, false},
		"refused, then short":             {[]string{`{"success":{"token":"tokGone"}}`, tokShort}, false},
		"refused, then 400":               {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokProxy4"}}`}, false},
		"refused, then another":           {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokBob"}}`}, true},
		"refused, then 502":               {[]string{`{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokDown"}}`}, false},
		// Anything else from tokeninfo is Google, or something in front
		// of it, failing.
		"tokeninfo 403": {[]string{`{"success":{"token":"tokProxy"}}`}, false},
		// A 400 is Google refusing only with error invalid_token in it.
		"tokeninfo 400, not Google": {[]string{`{"success":{"token":"tokProxy4"}}`}, false},
		"tokeninfo 404":             {[]string{`{"success":{"token":"tokMoved"}}`}, false},
		"tokeninfo 502":             {[]string{`{"success":{"token":"tokDown"}}`}, false},
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
		// The error is logged: no token in it.
		for tok := range maps.Keys(vaultInfo) {
			if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "tokGone") {
				t.Errorf("%s: the error names a token: %v", name, err)
			}
		}
	}
	// A token Google still accepts is never force-refreshed: the vault
	// answers that with consent. At refresh one with minRefreshTokenLife
	// (75 s) left is used as it is; one with less is waited out, and the
	// vault asked again, plainly.
	for name, tc := range map[string]struct {
		answers []string
		want    string
		forced  []string
		waits   int
	}{
		"4 min token":                      {[]string{`{"success":{"token":"tokMid"}}`}, "tokMid", []string{""}, 0},
		"100 s token":                      {[]string{`{"success":{"token":"tok100"}}`}, "tok100", []string{""}, 0},
		"80 s token":                       {[]string{`{"success":{"token":"tok80"}}`}, "tok80", []string{""}, 0},
		"30 s token, then a fresh one":     {[]string{tokShort, tokA}, "tokA", []string{"", ""}, 1},
		"30 s token back expired, forced":  {[]string{tokShort, tokShort, tokA}, "tokA", []string{"", "", "tokShort"}, 1},
		"30 s token, then refused, forced": {[]string{tokShort, `{"success":{"token":"tokGone"}}`, tokA}, "tokA", []string{"", "", "tokGone"}, 1},
	} {
		v, g, sv := newScripted(t, vaultInfo, tc.answers...)
		gr, err := v.refresh(ctx, g, alice, "", "")
		if err != nil || gr.AccessToken != tc.want {
			t.Errorf("%s: %+v %v, want %s", name, gr, err, tc.want)
		}
		if !slices.Equal(sv.forced, tc.forced) || len(sv.waits) != tc.waits {
			t.Errorf("%s: forced %q, waits %v; want forced %q, %d waits", name, sv.forced, sv.waits, tc.forced, tc.waits)
		}
		// The wait is the token's life (30 s) and expirySkew, never more
		// than maxExpiryWait and expirySkew.
		for _, d := range sv.waits {
			if d < 29*time.Second || d > 30*time.Second+expirySkew {
				t.Errorf("%s: waited %v for a 30 s token", name, d)
			}
		}
	}
	// Waited out and still valid (Google and the vault disagree on the
	// time): a failure, and one wait only.
	v, g, sv = newScripted(t, vaultInfo, tokShort, tokShort)
	sv.expire = false
	if gr, err := v.refresh(ctx, g, alice, "", ""); err == nil || errors.Is(err, errReauth) || len(sv.waits) != 1 || !slices.Equal(sv.forced, []string{"", ""}) {
		t.Errorf("30 s token, still valid after the wait: %+v %v, waits %v forced %q", gr, err, sv.waits, sv.forced)
	}
	// Consent to a forced refresh, then a valid token on the plain retrieve
	// (another client of the person forced the same expired token first):
	// that token is used, at refresh and at sign-in.
	v, g, sv = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, consentAnswer, tokA)
	if gr, err := v.refresh(ctx, g, alice, "", ""); err != nil || gr.AccessToken != "tokA" || !slices.Equal(sv.forced, []string{"", "tokGone", ""}) {
		t.Errorf("refused, consent to the force, then a fresh token: %+v %v, forced %q", gr, err, sv.forced)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, consentAnswer, tokA)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || c != nil || gr == nil || gr.AccessToken != "tokA" {
		t.Errorf("begin, refused, consent to the force, then a fresh token: %+v %+v %v", gr, c, err)
	}
	// At sign-in a recheck that brings a token Google refuses, or a short
	// one, leaves the consent detour.
	for _, third := range []string{`{"success":{"token":"tokGone2"}}`, tokShort} {
		v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, consentAnswer, third)
		if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || gr != nil || c == nil {
			t.Errorf("begin, refused, consent to the force, then %s: %+v %+v %v, want the consent detour", third, gr, c, err)
		}
	}
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, consentAnswer, `{"success":{"token":"tokBob"}}`)
	if _, err := v.refresh(ctx, g, alice, "", ""); !errors.Is(err, errReauth) {
		t.Errorf("refused, consent to the force, then another account's token: %v, want reauth: the token is checked", err)
	}
	// The request ending during the (real) wait ends it: a failure, not a
	// sign-out, and no second retrieve.
	v, g, sv = newScripted(t, vaultInfo, tokShort)
	v.sleeper = nil
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	start := time.Now()
	if gr, err := v.refresh(cctx, g, alice, "", ""); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errReauth) || len(sv.calls) != 1 || time.Since(start) > 10*time.Second {
		t.Errorf("30 s token, request ended during the wait: %+v %v %v after %v", gr, err, sv.calls, time.Since(start))
	}
	// At sign-in the code is exchanged a moment later, so a token needs
	// minSignInTokenLife (90 s); one with less is waited out (up to 93 s).
	for _, tok := range []string{"tokMid", "tok100"} {
		v, g, sv = newScripted(t, vaultInfo, `{"success":{"token":"`+tok+`"}}`)
		if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || c != nil || gr.AccessToken != tok || len(sv.calls) != 1 {
			t.Errorf("begin, %s: %+v %+v %v %v", tok, gr, c, err, sv.calls)
		}
	}
	v, g, sv = newScripted(t, vaultInfo, `{"success":{"token":"tok80"}}`, tokA)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || c != nil || gr.AccessToken != "tokA" || len(sv.waits) != 1 || sv.waits[0] > 80*time.Second+expirySkew {
		t.Errorf("begin, tok80: %+v %+v %v, waits %v; want it waited out", gr, c, err, sv.waits)
	}
	// Longer than that is a failure at once; only a token handed back
	// short by a forced refresh reaches it at sign-in, as the sign-in
	// wait covers need.
	v, g, sv = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, `{"success":{"token":"tok80"}}`)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err == nil || custodyError(err) != "server_error" || len(sv.waits) != 0 {
		t.Errorf("begin, refused, then forced to tok80: %+v %+v %v, waits %v; want server_error at once", gr, c, err, sv.waits)
	}
	v, g, sv = newScripted(t, vaultInfo, tokShort, tokA)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || c != nil || gr.AccessToken != "tokA" || len(sv.waits) != 1 || !slices.Equal(sv.forced, []string{"", ""}) {
		t.Errorf("begin, 30 s token: %+v %+v %v, waits %v forced %q", gr, c, err, sv.waits, sv.forced)
	}
	// The person is in the browser: a grant that cannot renew once the
	// token expired is a consent detour.
	v, g, _ = newScripted(t, vaultInfo, tokShort, consentAnswer)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || gr != nil || c == nil || c.URL != "https://consent.example/x" {
		t.Errorf("begin, 30 s token, then consent: %+v %+v %v, want a consent detour", gr, c, err)
	}
	// So is consent to renew the token that was waited out, which at
	// refresh is not yet the grant gone.
	v, g, _ = newScripted(t, vaultInfo, tokShort, tokShort, consentAnswer, consentAnswer)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || gr != nil || c == nil || c.URL != "https://consent.example/x" {
		t.Errorf("begin, 30 s token back expired, then consent: %+v %+v %v, want a consent detour", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, "", tokShort, tokShort, consentAnswer, consentAnswer)
	if _, err := v.finish(ctx, g, alice, c1, q("user_id_validation_state", "s"), ""); err == nil || errors.Is(err, errReauth) {
		t.Errorf("finish, 30 s token back expired, then consent: %v, want a plain error", err)
	}
	// At refresh it is server_error once; the next refresh does not wait,
	// forces the expired token, and consent then is the grant gone.
	v, g, sv = newScripted(t, vaultInfo, tokShort, tokShort, consentAnswer, tokShort)
	if _, err := v.refresh(ctx, g, alice, "", ""); err == nil || errors.Is(err, errReauth) || custodyError(err) != "server_error" {
		t.Errorf("refresh, 30 s token back expired, then consent: %v, want server_error", err)
	}
	sv.mu.Lock()
	sv.answers = []string{tokShort, consentAnswer, tokShort}
	sv.mu.Unlock()
	if _, err := v.refresh(ctx, g, alice, "", ""); !errors.Is(err, errReauth) {
		t.Errorf("the next refresh, expired token forced, then consent: %v, want reauth", err)
	}
	sv.mu.Lock()
	if len(sv.waits) != 1 || !slices.Equal(sv.forced, []string{"", "", "tokShort", "", "", "tokShort", ""}) {
		t.Errorf("waits %v, forced %q; want one wait, and the expired token forced by both refreshes", sv.waits, sv.forced)
	}
	sv.mu.Unlock()
	v, g, sv = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, tokA)
	if gr, err := v.refresh(ctx, g, alice, "", ""); err != nil || gr.AccessToken != "tokA" || len(sv.calls) != 2 {
		t.Errorf("token Google refused force-refreshed: %+v %v %v", gr, err, sv.calls)
	}
	// At sign-in the person is in the browser: a grant gone behind a
	// refused token detours through consent; refused twice is access_denied.
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, consentAnswer, consentAnswer)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); err != nil || gr != nil || c == nil || c.URL != "https://consent.example/x" {
		t.Errorf("begin, Google refuses the vault's token, then consent: %+v %+v %v, want a consent detour", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, `{"uriConsentRequired":{"authorizationUri":""}}`, `{"uriConsentRequired":{"authorizationUri":""}}`)
	if _, c, err := v.begin(ctx, g, alice, nil, ""); err == nil || c != nil || errors.Is(err, errReauth) {
		t.Errorf("begin, refused then an incomplete consent request: %+v %v", c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, `{"success":{"token":"tokGone"}}`, `{"success":{"token":"tokGone2"}}`)
	if gr, c, err := v.begin(ctx, g, alice, nil, ""); !errors.Is(err, errReauth) || custodyError(err) != "access_denied" {
		t.Errorf("begin, Google refuses the vault's token twice: %+v %+v %v, want access_denied", gr, c, err)
	}
	v, g, _ = newScripted(t, vaultInfo, "", `{"success":{"token":"tokGone"}}`, consentAnswer, consentAnswer)
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
// bodies, and hands every other call to the fake vault, as it does a
// retrieve whose answer is "-".
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
	if body == "-" {
		return o.next.RoundTrip(r)
	}
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

// A nearly spent vault token at sign-in is never force-refreshed (the
// real vault, like the fake, would ask for consent). With 4 minutes left
// it is used, and the access token stops a minute before it; with 100
// seconds left too. With 80 seconds left (under minSignInTokenLife) it is
// waited out like any shorter one. With 30 seconds left it is
// waited out, and the vault's next token, a fresh one, goes in the code.
// The nearly spent token reaches no log.
func TestVaultNearlySpentTokenAtSignIn(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		life  int
		want  string // "code" (with the short token), "fresh" (a code with a fresh one) or an error
		waits int
	}{{240, "code", 0}, {100, "code", 0}, {80, "fresh", 1}, {30, "fresh", 1}} {
		e := newTestEnv(t, false, nil)
		e.signIn(newBrowser(t)) // the vault holds alice's grant
		e.google.mu.Lock()
		tok := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, c.life)
		e.google.mu.Unlock()
		overrideVault(e, `{"success":{"token":"`+tok+`"}}`)
		id, v := e.register(), rand.Text()+rand.Text()
		loc, _ := newBrowser(t).visit(e.authorizeURL(id, v, nil))
		e.vault.mu.Lock()
		forced, waits := e.vault.forced, len(e.vault.waits)
		e.vault.mu.Unlock()
		if forced != 0 || waits != c.waits {
			t.Errorf("%d s left: %d forced refreshes, %d waits; want none forced, %d waits", c.life, forced, waits, c.waits)
		}
		if strings.Contains(e.log.String(), tok) {
			t.Errorf("%d s left: the token reached the log", c.life)
		}
		if c.want != "code" && c.want != "fresh" {
			if loc == nil || loc.Query().Get("error") != c.want {
				t.Errorf("%d s left: %v, want %s at the redirect", c.life, loc, c.want)
			}
			continue
		}
		if loc == nil || loc.Query().Get("code") == "" {
			t.Fatalf("%d s left: %v, want a code", c.life, loc)
		}
		r := e.token(exchangeForm(id, loc.Query().Get("code"), v), "", "")
		switch {
		case r.status != http.StatusOK:
			t.Errorf("%d s left: exchange %+v", c.life, r)
		case c.want == "code" && r.Expires > int64(c.life-60):
			t.Errorf("%d s left: expires_in %d, want an access token that stops a minute before the Google token", c.life, r.Expires)
		case c.want == "fresh" && r.Expires < int64((AccessTTL-time.Minute).Seconds()):
			t.Errorf("%d s left: expires_in %d, want a fresh Google token's", c.life, r.Expires)
		}
	}
}

// An active client's refresh lands when the Google token has a minute
// left: its access token stopped then. The vault would answer a forced
// refresh with consent, so the token is waited out (about a minute, here
// no time at all) and the vault asked again, plainly, which renews it:
// the refresh succeeds with a fresh hour, and nothing is forced. A refresh
// with 4 minutes left uses the token as it is, forcing nothing. Neither
// signs the person out, and neither token reaches the log.
func TestVaultRefreshAcrossGoogleExpiry(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	mid := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 240)
	last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 60)
	e.google.mu.Unlock()

	overrideVault(e, `{"success":{"token":"`+mid+`"}}`)
	second := e.token(refreshForm(id, first.Refresh), "", "")
	if second.status != http.StatusOK || second.Expires > 180 || second.Expires < 170 {
		t.Fatalf("refresh with 4 minutes left: %+v, want an access token of about 3 minutes", second)
	}

	overrideVault(e, `{"success":{"token":"`+last+`"}}`)
	third := e.token(refreshForm(id, second.Refresh), "", "")
	if third.status != http.StatusOK || third.Expires < int64((AccessTTL-time.Minute).Seconds()) {
		t.Fatalf("refresh with a minute left: %+v, want a fresh Google token's access token", third)
	}
	e.vault.mu.Lock()
	forced, waits := e.vault.forced, e.vault.waits
	e.vault.mu.Unlock()
	if forced != 0 || len(waits) != 1 || waits[0] < 59*time.Second || waits[0] > time.Minute+expirySkew {
		t.Errorf("forced %d, waits %v; want none forced and one wait of about a minute", forced, waits)
	}
	if code, body, _ := e.call(third.Access); code != http.StatusOK || strings.Contains(body, last) || strings.Contains(body, mid) {
		t.Errorf("call with the renewed access token: %d %q", code, body)
	}
	if l := e.log.String(); strings.Contains(l, mid) || strings.Contains(l, last) {
		t.Error("a vault token reached the log")
	}
}

// The vault's wait runs before the refresh token's family is rotated. A
// client that gives up during it (its timeout, or a front end's, is
// shorter) leaves nothing rotated and nothing to give back, and its retry
// with the same refresh token works.
func TestVaultClientGivesUpDuringTheWait(t *testing.T) {
	t.Parallel()
	used := &countingReplay{ReplayCache: NewMemoryReplayCache()}
	e := newTestEnv(t, false, func(c *Config) { c.Replay = used })
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 60)
	e.google.mu.Unlock()
	overrideVault(e, `{"success":{"token":"`+last+`"}}`)
	vc := e.as.cfg.Custody.(*VaultCustody)
	waiting := make(chan struct{})
	vc.sleeper = &sleeper{func(ctx context.Context, _ time.Duration) error {
		close(waiting)
		<-ctx.Done()
		return ctx.Err()
	}}
	rotated, unrotated := used.counts()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/token", strings.NewReader(refreshForm(id, first.Refresh).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	done := make(chan error, 1)
	go func() {
		resp, err := hc.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-waiting:
	case err := <-done:
		cancel()
		t.Fatalf("the refresh answered (%v) without waiting out the nearly spent token", err)
	}
	if r, u := used.counts(); r != rotated || u != unrotated {
		t.Errorf("during the wait: %d rotations, %d give-backs; want none", r-rotated, u-unrotated)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the abandoned refresh answered")
	}
	// The server notices the client went away and ends the refresh.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(e.log.String(), "custody failed at refresh") {
		if time.Now().After(deadline) {
			t.Fatal("the server never ended the abandoned refresh")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r, u := used.counts(); r != rotated || u != unrotated {
		t.Errorf("after the client went away: %d rotations, %d give-backs; want none", r-rotated, u-unrotated)
	}
	vc.sleeper = &sleeper{e.vault.sleep}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry after giving up during the wait: %+v, want the refresh token still usable", r)
	}
}

// countingReplay counts Rotate and Unrotate calls. It embeds only
// ReplayCache, so the server uses plain Rotate and Unrotate.
type countingReplay struct {
	ReplayCache
	mu                 sync.Mutex
	rotates, unrotates int
}

func (c *countingReplay) Rotate(ctx context.Context, family string, gen uint64, exp time.Time) (bool, error) {
	c.mu.Lock()
	c.rotates++
	c.mu.Unlock()
	return c.ReplayCache.Rotate(ctx, family, gen, exp)
}

func (c *countingReplay) Unrotate(ctx context.Context, family string, gen uint64) error {
	c.mu.Lock()
	c.unrotates++
	c.mu.Unlock()
	return c.ReplayCache.Unrotate(ctx, family, gen)
}

func (c *countingReplay) counts() (rotates, unrotates int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rotates, c.unrotates
}

// Two processes of one client refresh with the same token while the
// vault's token is nearly spent. The first waits it out; the second,
// arriving during that wait, finds the family not yet rotated and
// refreshes (here the vault already has a fresh token for it). The first
// then loses the rotation race: within the reuse grace it is refused
// without revoking, so the second's tokens stay valid. (Without a grace
// it would revoke the family, as any concurrent refresh does.)
func TestVaultConcurrentRefreshDuringTheWait(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, func(c *Config) { c.RefreshReuseGrace = time.Minute })
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 60)
	e.google.mu.Unlock()
	overrideVault(e, `{"success":{"token":"`+last+`"}}`)
	vc := e.as.cfg.Custody.(*VaultCustody)
	waiting, held := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(held) }) }
	// A failed assertion must not leave the first refresh held: it is in
	// flight on e.srv, whose Close (a cleanup) waits for it.
	t.Cleanup(release)
	vc.sleeper = &sleeper{func(ctx context.Context, d time.Duration) error {
		close(waiting)
		select {
		case <-held:
		case <-ctx.Done():
			return ctx.Err()
		}
		return e.vault.sleep(ctx, d)
	}}
	firstDone := make(chan tokenResp, 1)
	go func() {
		// Not e.token: its t.Fatal must not run off the test's goroutine,
		// where it would leave firstDone empty.
		firstDone <- tokenOver(e.srv.URL, refreshForm(id, first.Refresh))
	}()
	select {
	case <-waiting:
	case r := <-firstDone:
		t.Fatalf("the first refresh answered (%+v) without waiting out the nearly spent token", r)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the first refresh to reach the wait")
	}
	// Off the test goroutine and awaited, so a refresh that blocks behind
	// the held one fails the test rather than hanging it.
	secondDone := make(chan tokenResp, 1)
	go func() { secondDone <- tokenOver(e.srv.URL, refreshForm(id, first.Refresh)) }()
	second := await(t, secondDone, "a refresh during the first one's wait")
	release()
	r1 := await(t, firstDone, "the first refresh")
	if second.status != http.StatusOK {
		t.Fatalf("a refresh during another's wait: %+v, want it to refresh: the family is not rotated during the wait", second)
	}
	if r1.Error != "invalid_grant" {
		t.Errorf("the waiting refresh, after the other rotated: %+v, want invalid_grant (refused within the grace)", r1)
	}
	if r := e.token(refreshForm(id, second.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("the second refresh's token afterwards: %+v, want the family kept", r)
	}
}

// tokenOver posts form to the token endpoint at base without failing the
// test, so it can run off the test's goroutine.
func tokenOver(base string, form url.Values) tokenResp {
	req, _ := http.NewRequest(http.MethodPost, base+PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return tokenResp{Error: "transport: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	r := tokenResp{status: resp.StatusCode, header: resp.Header}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	return r
}

// A server WriteTimeout shorter than the wait does not lose the answer:
// the wait moves the response's write deadline past it, and the token
// endpoint moves it again before rotating. Over HTTP/1.1 a write timeout
// does not cancel the request, so a lost answer to a refresh that went on
// to rotate its family would make the client's retry a replay; there the
// second extension alone saves the answer, so the HTTP/1.1 case passes
// without the wait's own. Over HTTP/2 a write timeout resets the stream
// (INTERNAL_ERROR), which cancels the request: without the wait's
// extension every waiting refresh fails. TestVaultWaitExtendsWriteDeadline
// pins that extension directly. The timeout is 2 s, half the wait: the
// TLS handshake runs under it too, and must beat it on a loaded machine.
// Each case really waits, about 4 seconds.
func TestVaultWaitOutlastsWriteTimeout(t *testing.T) {
	t.Parallel()
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP/1.1", true: "HTTP/2"}[h2], func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, false, nil)
			id, first := e.signIn(newBrowser(t))
			e.google.mu.Lock()
			last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 1)
			e.google.mu.Unlock()
			overrideVault(e, `{"success":{"token":"`+last+`"}}`)
			e.as.cfg.Custody.(*VaultCustody).sleeper = nil // a real wait
			ts := httptest.NewUnstartedServer(e.srv.Config.Handler)
			ts.Config.WriteTimeout = 2 * time.Second
			client := hc
			if h2 {
				ts.EnableHTTP2 = true
				ts.StartTLS()
				client = ts.Client()
			} else {
				ts.Start()
			}
			t.Cleanup(ts.Close)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+PathToken, strings.NewReader(refreshForm(id, first.Refresh).Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("refresh behind a 2 s WriteTimeout: %v, want the answer", err)
			}
			defer func() { _ = resp.Body.Close() }()
			var r tokenResp
			_ = json.NewDecoder(resp.Body).Decode(&r)
			if resp.StatusCode != http.StatusOK || r.Refresh == "" || resp.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
				t.Fatalf("refresh behind a 2 s WriteTimeout: %s %d %+v", resp.Proto, resp.StatusCode, r)
			}
			if r2 := e.token(refreshForm(id, r.Refresh), "", ""); r2.status != http.StatusOK {
				t.Errorf("the answered refresh token: %+v", r2)
			}
		})
	}
}

// A server ReadTimeout shorter than the wait does not cancel it: once a
// request's body is read (or it has none), net/http clears the read
// deadline for the background read that watches for the client going
// away (HTTP/1.1, connReader.startBackgroundRead in go1.26.10), and over
// HTTP/2 the timeout only closes the request body
// (http2stream.onReadTimeout). DESIGN.md says so; this pins it. The
// timeout is 2 s, half the wait, as in TestVaultWaitOutlastsWriteTimeout.
// Each case really waits, about 4 seconds.
func TestVaultWaitOutlastsReadTimeout(t *testing.T) {
	t.Parallel()
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP/1.1", true: "HTTP/2"}[h2], func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, false, nil)
			id, first := e.signIn(newBrowser(t))
			e.google.mu.Lock()
			last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 1)
			e.google.mu.Unlock()
			overrideVault(e, `{"success":{"token":"`+last+`"}}`)
			e.as.cfg.Custody.(*VaultCustody).sleeper = nil // a real wait
			ts := httptest.NewUnstartedServer(e.srv.Config.Handler)
			ts.Config.ReadTimeout = 2 * time.Second
			client := hc
			if h2 {
				ts.EnableHTTP2 = true
				ts.StartTLS()
				client = ts.Client()
			} else {
				ts.Start()
			}
			t.Cleanup(ts.Close)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+PathToken, strings.NewReader(refreshForm(id, first.Refresh).Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("refresh behind a 2 s ReadTimeout: %v, want the answer", err)
			}
			defer func() { _ = resp.Body.Close() }()
			var r tokenResp
			_ = json.NewDecoder(resp.Body).Decode(&r)
			if resp.StatusCode != http.StatusOK || r.Refresh == "" || resp.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
				t.Fatalf("refresh behind a 2 s ReadTimeout: %s %d %+v, want the wait to finish", resp.Proto, resp.StatusCode, r)
			}
			if took := time.Since(start); took < 3*time.Second {
				t.Errorf("refresh took %v: it did not wait out the nearly spent token", took)
			}
		})
	}
}

// At sign-in only the wait's own extension stands between a WriteTimeout
// shorter than the wait and the redirect: at the callback (the stored
// grant's token nearly spent) and at the consent return (the token after
// consent nearly spent). Over HTTP/1.1 the redirect would be lost, the
// sign-in with it. The WriteTimeout covers every request of the sign-in,
// so it is 2 s, half the wait: the requests that do not wait must still
// beat it on a loaded machine. Each case really waits, about 4 seconds.
func TestVaultSignInWaitOutlastsWriteTimeout(t *testing.T) {
	t.Parallel()
	for _, consent := range []bool{false, true} {
		t.Run(map[bool]string{false: "callback", true: "consent return"}[consent], func(t *testing.T) {
			t.Parallel()
			e := newTestEnvServer(t, false, nil, func(s *http.Server) { s.WriteTimeout = 2 * time.Second })
			e.google.mu.Lock()
			last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 1)
			e.google.mu.Unlock()
			if consent {
				// No grant stored: the callback's retrieve reaches the fake
				// vault, which asks for consent, and the one after consent
				// gets the nearly spent token.
				overrideVault(e, "-", `{"success":{"token":"`+last+`"}}`)
			} else {
				e.signIn(newBrowser(t)) // the vault holds alice's grant
				overrideVault(e, `{"success":{"token":"`+last+`"}}`)
			}
			e.as.cfg.Custody.(*VaultCustody).sleeper = nil // a real wait
			id, v := e.register(), rand.Text()+rand.Text()
			b := newBrowser(t)
			// A fresh connection per request: the client retries a GET that
			// fails on a reused connection, which would hide a lost answer.
			b.hc.Transport = &http.Transport{DisableKeepAlives: true}
			start := time.Now()
			loc, page := b.visit(e.authorizeURL(id, v, nil))
			if loc == nil || loc.Query().Get("code") == "" {
				t.Fatalf("sign-in behind a 2 s WriteTimeout: %v %q, want a code", loc, page)
			}
			if took := time.Since(start); took < 3*time.Second {
				t.Fatalf("sign-in took %v: it did not wait out the nearly spent token", took)
			}
			if r := e.token(exchangeForm(id, loc.Query().Get("code"), v), "", ""); r.status != http.StatusOK || r.Expires < int64((AccessTTL-time.Minute).Seconds()) {
				t.Errorf("exchange %+v, want a fresh Google token's access token", r)
			}
		})
	}
}

// slowKeys is a KeyProvider whose first keyring in a request marked with
// slowKeyring takes delay to come, as a seal.Reloader's first load from
// Secret Manager does.
type slowKeys struct {
	seal.KeyProvider
	delay time.Duration
}

// slowKeyring marks a request whose first keyring is slow. Its value is
// an *atomic.Bool, set once that keyring is asked for.
type slowKeyring struct{}

func (k slowKeys) Keyring(ctx context.Context) (*seal.Keyring, error) {
	if asked, ok := ctx.Value(slowKeyring{}).(*atomic.Bool); ok && asked.CompareAndSwap(false, true) {
		select {
		case <-time.After(k.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return k.KeyProvider.Keyring(ctx)
}

// deadlineRecorder records the write deadlines set on a response and
// passes them on.
type deadlineRecorder struct {
	http.ResponseWriter
	record func(time.Time)
}

func (d deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.record(t)
	return http.NewResponseController(d.ResponseWriter).SetWriteDeadline(t)
}

func (d deadlineRecorder) Unwrap() http.ResponseWriter { return d.ResponseWriter }

// Each endpoint that may wait records the server's WriteTimeout deadline
// before any other work, so slow work ahead of the wait (here the
// request's first keyring, which opens the sign-in state, the parked
// consent or the refresh token) cannot make that deadline look later
// than it is. Recorded late, it looks further off, and a wait plus
// postWaitBudget that does cross it is not extended. The WriteTimeout
// falls between the two: past the wait plus postWaitBudget counted from
// a record after the slow keyring, short of it counted from the
// request's start. No time passes in the wait itself.
func TestVaultWriteDeadlineRecordedFirst(t *testing.T) {
	t.Parallel()
	const (
		life  = 1 // the vault token's seconds left: the wait is life+expirySkew
		delay = 2 * time.Second
		// From the request's start, the wait ends after delay+life+expirySkew
		// (6 s) and its answer is due postWaitBudget later, past this.
		writeTimeout = life*time.Second + expirySkew + postWaitBudget + delay/2
	)
	for _, path := range []string{PathCallback, PathConsentContinue, PathToken} {
		t.Run(strings.TrimPrefix(path, "/"), func(t *testing.T) {
			t.Parallel()
			var (
				armed   atomic.Bool
				mu      sync.Mutex
				start   time.Time   // the request reached the handler
				set     []time.Time // write deadlines it set
				waitEnd time.Time   // when its wait would end
			)
			e := newTestEnvServer(t, false, func(c *Config) { c.Keys = slowKeys{c.Keys, delay} }, func(s *http.Server) {
				s.WriteTimeout = writeTimeout
				next := s.Handler
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !armed.Load() || r.URL.Path != path {
						next.ServeHTTP(w, r)
						return
					}
					mu.Lock()
					start, set = time.Now(), nil
					mu.Unlock()
					rec := deadlineRecorder{w, func(t time.Time) {
						mu.Lock()
						set = append(set, t)
						mu.Unlock()
					}}
					next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), slowKeyring{}, new(atomic.Bool))))
				})
			})
			e.google.mu.Lock()
			last := e.google.mint(alice, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, life)
			e.google.mu.Unlock()
			var id string
			var first tokenResp
			if path == PathConsentContinue {
				overrideVault(e, "-", `{"success":{"token":"`+last+`"}}`)
			} else {
				id, first = e.signIn(newBrowser(t)) // the vault holds alice's grant
				overrideVault(e, `{"success":{"token":"`+last+`"}}`)
			}
			e.as.cfg.Custody.(*VaultCustody).sleeper = &sleeper{func(ctx context.Context, d time.Duration) error {
				mu.Lock()
				waitEnd = time.Now().Add(d)
				mu.Unlock()
				return e.vault.sleep(ctx, d)
			}}
			armed.Store(true)
			if path == PathToken {
				if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
					t.Fatalf("refresh: %+v", r)
				}
			} else {
				cid, v := e.register(), rand.Text()+rand.Text()
				if loc, page := newBrowser(t).visit(e.authorizeURL(cid, v, nil)); loc == nil || loc.Query().Get("code") == "" {
					t.Fatalf("sign-in: %v %q, want a code", loc, page)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if start.IsZero() || waitEnd.IsZero() {
				t.Fatalf("no wait at %s (request started %v, wait ends %v)", path, start, waitEnd)
			}
			// The latest deadline set. (At /token the extension before the
			// rotation can come after the wait's and be earlier, because no
			// time passes in this wait; a real wait puts it later.)
			deadline := start.Add(writeTimeout)
			for _, d := range set {
				if d.After(deadline) {
					deadline = d
				}
			}
			// The extension is made just before the wait starts, a moment
			// before waitEnd is taken; the margin either way is about a
			// second.
			if want := waitEnd.Add(postWaitBudget - 300*time.Millisecond); deadline.Before(want) {
				t.Errorf("the answer is due %v after the request started, %v short of postWaitBudget after the wait (%d deadlines set)",
					deadline.Sub(start).Round(time.Millisecond), want.Sub(deadline).Round(time.Millisecond), len(set))
			}
		})
	}
}

// The wait itself moves the write deadline past the wait and
// postWaitBudget. The sign-in callback and the consent return rely on it
// alone; the token endpoint extends again before rotating, which is why
// the HTTP/1.1 case of TestVaultWaitOutlastsWriteTimeout passes without
// it.
func TestVaultWaitExtendsWriteDeadline(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), http.ServerContextKey, &http.Server{WriteTimeout: time.Second})
	w := &deadlineWriter{}
	ctx = withResponse(ctx, w)
	v := &VaultCustody{sleeper: &sleeper{func(context.Context, time.Duration) error { return nil }}}
	if err := v.wait(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(w.set) != 1 || time.Until(w.set[0]) < time.Minute+postWaitBudget-time.Second {
		t.Errorf("deadlines set %v, want one past the wait and postWaitBudget", w.set)
	}
}

// A refusal found in prepare (here the vault holding another account's
// grant) is answered only after the allow-list check: if that check
// fails, the answer is server_error and the rotation is given back, so
// the retry, with the directory and the vault answering properly, works.
// Ported from kode-gopher (TestVaultRefusalWaitsForTheAllowList, 69575ef).
func TestVaultRefusalWaitsForTheAllowList(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	e.google.signInAs, e.vault.consentAs = bob, bob // admitted by group
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	other := e.google.mint(mallory, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 3600)
	e.google.mu.Unlock()
	overrideVault(e, `{"success":{"token":"`+other+`"}}`)
	// A fresh admitter, so no membership it cached at sign-in answers for
	// the directory.
	e.as.cfg.Admit = newAdmitter(t, &fakeGroups{failNext: 1})
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" {
		t.Fatalf("refresh, the vault refusing and the allow-list failing: %+v, want server_error", r)
	}
	e.as.cfg.Admit = newAdmitter(t, e.groups)
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry: %+v, want the rotation given back", r)
	}
}

// A refusal found before the rotation (here the vault holding another
// account's grant) is still answered after it: the refresh token is spent,
// and presenting it again is a replay that revokes its family.
func TestVaultRefusalAtRefreshKeepsTheTokenSpent(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, false, nil)
	id, first := e.signIn(newBrowser(t))
	e.google.mu.Lock()
	other := e.google.mint(mallory, ScopeOpenID+" "+ScopeEmail+" "+ScopeCloudPlatform, 3600)
	e.google.mu.Unlock()
	overrideVault(e, `{"success":{"token":"`+other+`"}}`)
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Fatalf("refresh, the vault holds another account's grant: %+v, want invalid_grant", r)
	}
	// The vault answers properly again; the spent token is still a replay.
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" || !strings.Contains(e.log.String(), "refresh token reused") {
		t.Errorf("the refused refresh token presented again: %+v, want invalid_grant and the family revoked", r)
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

// deadlineWriter records SetWriteDeadline calls, as http.ResponseController
// makes them.
type deadlineWriter struct {
	http.ResponseWriter
	set []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.set = append(d.set, t)
	return nil
}

// The wait's write-deadline extension only ever moves a server's
// WriteTimeout deadline later: it sets none where the server has none,
// and never shortens a longer one.
func TestExtendWriteDeadline(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		srv    *http.Server
		extend bool
	}{
		"no server":              {nil, false},
		"no WriteTimeout":        {&http.Server{}, false},
		"a longer WriteTimeout":  {&http.Server{WriteTimeout: 10 * time.Minute}, false},
		"a shorter WriteTimeout": {&http.Server{WriteTimeout: time.Second}, true},
		"no response in the ctx": {&http.Server{WriteTimeout: time.Second}, false},
	} {
		ctx := context.Background()
		if tc.srv != nil {
			ctx = context.WithValue(ctx, http.ServerContextKey, tc.srv)
		}
		w := &deadlineWriter{}
		if name != "no response in the ctx" {
			ctx = withResponse(ctx, w)
		}
		extendWriteDeadline(ctx, time.Minute)
		if got := len(w.set) == 1; got != tc.extend {
			t.Errorf("%s: deadlines set %v, want extended=%v", name, w.set, tc.extend)
			continue
		}
		if tc.extend && time.Until(w.set[0]) < 59*time.Second {
			t.Errorf("%s: deadline %v, want a minute from now", name, w.set[0])
		}
	}
}
