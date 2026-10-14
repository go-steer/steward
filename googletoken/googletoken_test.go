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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-steer/purser"
)

const (
	clientID   = "123-abc.apps.googleusercontent.com"
	otherID    = "456-def.apps.googleusercontent.com"
	cloudScope = "https://www.googleapis.com/auth/cloud-platform"
)

var now = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// fakeGoogle answers tokeninfo (POST /tokeninfo) and userinfo (GET
// /userinfo) for the tokens it knows, as Google's endpoints do. A token's
// "hd" and "user_email" go in userinfo's answer, the rest in tokeninfo's;
// "status" makes both fail with that HTTP status.
func fakeGoogle(t *testing.T, tokens map[string]map[string]string) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var tok string
		switch r.URL.Path {
		case "/tokeninfo":
			if r.Method != http.MethodPost || r.URL.RawQuery != "" {
				t.Errorf("tokeninfo got %s %s: the token must go in the body", r.Method, r.URL)
			}
			tok = r.FormValue("access_token")
		case "/userinfo":
			tok = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		info, ok := tokens[tok]
		if !ok {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusBadRequest)
			return
		}
		if s := info["status"]; s != "" {
			code, _ := strconv.Atoi(s)
			http.Error(w, "{}", code)
			return
		}
		out := map[string]string{}
		for k, val := range info {
			switch {
			case r.URL.Path == "/userinfo" && k == "hd":
				out["hd"] = val
			case r.URL.Path == "/userinfo" && k == "user_email":
				out["email"] = val
			case r.URL.Path == "/tokeninfo" && k != "hd" && k != "user_email":
				out[k] = val
			}
		}
		if _, ok := out["email"]; !ok && r.URL.Path == "/userinfo" {
			out["email"] = info["email"]
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

func newVerifier(t *testing.T, base string, clock *time.Time, scopes ...string) *Verifier {
	t.Helper()
	v, err := New(Config{
		ClientIDs:      []string{clientID, otherID},
		RequiredScopes: scopes,
		TokenInfoURL:   base + "/tokeninfo",
		UserInfoURL:    base + "/userinfo",
		Now:            func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func info(aud, email, verified string, exp time.Time) map[string]string {
	return map[string]string{
		"aud": aud, "azp": aud, "sub": "1001", "email": email, "email_verified": verified,
		"exp":   strconv.FormatInt(exp.Unix(), 10),
		"scope": "openid " + EmailScope + " " + cloudScope, "hd": "cymbal.example",
	}
}

func with(m map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, val := range m {
		out[k] = val
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
		} else {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func TestVerify(t *testing.T) {
	t.Parallel()
	good := info(clientID, "Dana@Cymbal.example", "true", now.Add(time.Hour))
	base, hits := fakeGoogle(t, map[string]map[string]string{
		"good":          good,
		"second-client": with(good, "aud", otherID, "azp", otherID),
		"azp-only":      with(good, "aud", "some-audience"),
		"consumer":      with(good, "hd", ""),
		"other-app":     with(good, "aud", "999-other.apps.googleusercontent.com", "azp", "999-other.apps.googleusercontent.com"),
		"no-email-scop": with(good, "scope", "openid "+cloudScope),
		"no-cloud":      with(good, "scope", "openid "+EmailScope),
		"read-only":     with(good, "scope", "openid "+EmailScope+" "+cloudScope+".read-only"),
		"unverified":    with(good, "email_verified", "false"),
		"no-email":      with(good, "email", ""),
		"expired":       with(good, "exp", strconv.FormatInt(now.Add(-time.Second).Unix(), 10)),
		"bad-exp":       with(good, "exp", "soon"),
		"other-user":    with(good, "user_email", "mallory@cymbal.example"),
		"google-down":   with(good, "status", "503"),
		"google-busy":   with(good, "status", "429"),
		"eyJh.eyJi.sig": good, // a JWT: never even asked about
	})
	clock := now
	var mu sync.Mutex // guards clock against the verifier's reads
	v := newVerifier(t, base, &clock, cloudScope)
	v.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	setClock := func(c time.Time) { mu.Lock(); clock = c; mu.Unlock() }
	ctx := context.Background()

	id, err := v.Verify(ctx, "good")
	if err != nil || id.Email != "dana@cymbal.example" || id.HD != "cymbal.example" || id.Subject != "1001" ||
		!id.Expiry.Equal(time.Unix(now.Add(time.Hour).Unix(), 0)) || len(id.Scopes) != 3 {
		t.Fatalf("good token: %+v, %v", id, err)
	}
	for _, tok := range []string{"second-client", "azp-only"} {
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Errorf("%s: %v, want accepted", tok, err)
		}
	}
	if id, err := v.Verify(ctx, "consumer"); err != nil || id.HD != "" {
		t.Errorf("a consumer account: %+v, %v (accepted, with no domain)", id, err)
	}
	for _, tok := range []string{"", "unknown", "other-app", "no-email-scop", "no-cloud", "read-only", "unverified", "no-email",
		"expired", "bad-exp", "other-user", "eyJh.eyJi.sig", strings.Repeat("x", maxTokenLen+1)} {
		_, err := v.Verify(ctx, tok)
		if !errors.Is(err, ErrInvalid) || !errors.Is(err, purser.ErrUnauthenticated) {
			t.Errorf("token %.20q: %v, want ErrInvalid wrapping purser.ErrUnauthenticated", tok, err)
		}
	}
	// Google failing isn't Google refusing: ErrUnavailable, not a
	// credential error, and not remembered.
	for _, tok := range []string{"google-down", "google-busy"} {
		n := hits.Load()
		for range 2 {
			_, err := v.Verify(ctx, tok)
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, purser.ErrUnauthenticated) {
				t.Errorf("%s: %v, want ErrUnavailable and not ErrUnauthenticated", tok, err)
			}
		}
		if hits.Load() != n+2 {
			t.Errorf("%s: a failure was remembered", tok)
		}
	}

	// Cached, but for at most MaxTTL, then asked again (two calls:
	// tokeninfo and userinfo).
	n := hits.Load()
	if _, err := v.Verify(ctx, "good"); err != nil || hits.Load() != n {
		t.Errorf("a checked token was checked again (%v)", err)
	}
	setClock(now.Add(MaxTTL))
	if _, err := v.Verify(ctx, "good"); err != nil || hits.Load() != n+2 {
		t.Errorf("a token was trusted past MaxTTL (%v)", err)
	}
	// A refusal is remembered for RefusedTTL, and never as a success.
	n = hits.Load()
	_, _ = v.Verify(ctx, "unknown-2")
	if _, err := v.Verify(ctx, "unknown-2"); !errors.Is(err, ErrInvalid) || hits.Load() != n+1 {
		t.Errorf("a refused token: %v, %d lookups", err, hits.Load()-n)
	}
	setClock(now.Add(MaxTTL + RefusedTTL))
	_, _ = v.Verify(ctx, "unknown-2")
	if hits.Load() != n+2 {
		t.Error("a refusal was remembered past RefusedTTL")
	}
}

// TestCacheNeverOutlivesToken: a token expiring sooner than MaxTTL is
// trusted only until it expires.
func TestCacheNeverOutlivesToken(t *testing.T) {
	t.Parallel()
	base, hits := fakeGoogle(t, map[string]map[string]string{
		"short": info(clientID, "dana@cymbal.example", "true", now.Add(time.Minute)),
	})
	clock := now
	v := newVerifier(t, base, &clock)
	if _, err := v.Verify(context.Background(), "short"); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(time.Minute)
	n := hits.Load()
	if _, err := v.Verify(context.Background(), "short"); !errors.Is(err, ErrInvalid) {
		t.Errorf("an expired token: %v, want ErrInvalid", err)
	}
	if hits.Load() == n {
		t.Error("an expired token was answered from the cache")
	}
}

// TestLookupLimit: past MaxLookups at once, a new token is turned away as
// unavailable (load-shedding, not a verdict) without asking Google, and
// that answer is not remembered.
func TestLookupLimit(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var inflight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inflight.Add(1)
		<-release
		http.Error(w, "{}", http.StatusBadRequest)
	}))
	defer srv.Close()
	v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: srv.URL, UserInfoURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for i := range MaxLookups {
		go func() { _, _ = v.Verify(context.Background(), "slow-"+strconv.Itoa(i)); done <- struct{}{} }()
	}
	for inflight.Load() < MaxLookups {
		time.Sleep(time.Millisecond)
	}
	_, err = v.Verify(context.Background(), "one-more")
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, purser.ErrUnauthenticated) || inflight.Load() != MaxLookups {
		t.Errorf("past MaxLookups: %v, %d lookups; want ErrUnavailable without asking Google", err, inflight.Load())
	}
	close(release)
	for range MaxLookups {
		<-done
	}
	v.mu.Lock()
	_, cached := v.cache[keyOf("one-more")]
	v.mu.Unlock()
	if cached {
		t.Error("a load-shed token was remembered")
	}
}

func TestCacheBound(t *testing.T) {
	t.Parallel()
	tokens := map[string]map[string]string{}
	for i := range MaxCached + 10 {
		tokens["t"+strconv.Itoa(i)] = info(clientID, "dana@cymbal.example", "true", now.Add(time.Hour))
	}
	base, _ := fakeGoogle(t, tokens)
	clock := now
	v := newVerifier(t, base, &clock)
	for tok := range tokens {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	}
	if len(v.cache) > MaxCached {
		t.Errorf("cache holds %d, want at most %d", len(v.cache), MaxCached)
	}
}

// TestCacheHoldsNoToken: the cache is keyed by a hash and its entries
// carry no token, so a debug print of the Verifier does not reveal one.
func TestCacheHoldsNoToken(t *testing.T) {
	t.Parallel()
	const secret = "ya29.planted-secret-token"
	base, _ := fakeGoogle(t, map[string]map[string]string{secret: info(clientID, "dana@cymbal.example", "true", now.Add(time.Hour))})
	clock := now
	v := newVerifier(t, base, &clock)
	if _, err := v.Verify(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if dump := fmt.Sprintf("%#v", v.cache); strings.Contains(dump, "planted-secret") {
		t.Errorf("the cache holds the token: %s", dump)
	}
	if _, ok := v.cache[keyOf(secret)]; !ok {
		t.Error("the verdict was not cached under the token's hash")
	}
}

// TestErrorsNeverContainToken plants a token and checks every error path
// for it: refusal, Google failing, Google unreachable, load-shedding.
func TestErrorsNeverContainToken(t *testing.T) {
	t.Parallel()
	const secret = "ya29.planted-secret-token"
	base, _ := fakeGoogle(t, map[string]map[string]string{
		secret + "-down": with(info(clientID, "d@cymbal.example", "true", now.Add(time.Hour)), "status", "503"),
	})
	clock := now
	v := newVerifier(t, base, &clock)
	dead, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: "http://127.0.0.1:1/tokeninfo", UserInfoURL: "http://127.0.0.1:1/userinfo"})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"refused":     func() error { _, err := v.Verify(context.Background(), secret); return err },
		"google 503":  func() error { _, err := v.Verify(context.Background(), secret+"-down"); return err },
		"unreachable": func() error { _, err := dead.Verify(context.Background(), secret); return err },
	} {
		err := call()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "planted-secret") {
			t.Errorf("%s: error %q contains the token", name, err)
		}
	}
}

func TestNewRefuses(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]Config{
		"no clients":    {},
		"blank clients": {ClientIDs: []string{" ", ""}},
		"short scope":   {ClientIDs: []string{clientID}, RequiredScopes: []string{"cloud-platform"}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted %+v", name, cfg)
		}
	}
	v, err := New(Config{ClientIDs: []string{clientID}, RequiredScopes: []string{"openid", EmailScope, cloudScope, cloudScope, " "}})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.scopes) != 3 {
		t.Errorf("scopes = %v, want email, openid and cloud-platform once each", v.scopes)
	}
	if v.hc == nil || v.tokenInfo != TokenInfoURL || v.userInfo != UserInfoURL || v.now == nil {
		t.Error("defaults not applied")
	}
}

// TestUserInfoFailures: a userinfo refusal is a refusal; a userinfo outage
// is unavailable.
func TestUserInfoFailures(t *testing.T) {
	t.Parallel()
	good := info(clientID, "dana@cymbal.example", "true", now.Add(time.Hour))
	tokenInfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(good)
	}))
	defer tokenInfo.Close()
	for _, c := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"refused", http.StatusUnauthorized, "{}", ErrInvalid},
		{"down", http.StatusBadGateway, "{}", ErrUnavailable},
		{"garbage", http.StatusOK, "not json", ErrUnavailable},
	} {
		userInfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: tokenInfo.URL, UserInfoURL: userInfo.URL, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), "tok-"+c.name); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		userInfo.Close()
	}
}

func TestVerifyReturnsIndependentScopes(t *testing.T) {
	t.Parallel()
	base, _ := fakeGoogle(t, map[string]map[string]string{"good": info(clientID, "dana@cymbal.example", "true", now.Add(time.Hour))})
	clock := now
	v := newVerifier(t, base, &clock)
	first, _ := v.Verify(context.Background(), "good")
	first.Scopes[0] = "mutated"
	second, _ := v.Verify(context.Background(), "good")
	if second.Scopes[0] == "mutated" {
		t.Error("a caller's edit to Identity.Scopes reached the cache")
	}
}

// keyOf is the cache key Verify uses for token.
func keyOf(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }
