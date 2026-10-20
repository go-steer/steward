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

// Regression tests for the adversarial review of the first Path A PR:
// ways Google failing could be mistaken for Google refusing, or could
// wedge the Verifier.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-steer/purser"
)

// cached reports whether Verify left any verdict for token in the cache.
func cached(v *Verifier, token string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.cache[keyOf(token)]
	return ok
}

// TestTruncatedAnswerIsUnavailable: a 200 whose body is cut short of its
// Content-Length (the connection dropped, the timeout fired) is Google
// failing, not refusing, and is not cached. Caching it as a refusal would
// lock a valid token out for RefusedTTL.
func TestTruncatedAnswerIsUnavailable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"aud":"`))
	}))
	defer srv.Close()
	v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: srv.URL, UserInfoURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), "valid-token")
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalid) {
		t.Errorf("truncated answer: %v, want ErrUnavailable", err)
	}
	if cached(v, "valid-token") {
		t.Error("a truncated answer was cached")
	}
}

// TestCancelledMidAnswerIsUnavailable: the caller's context ending after
// Google sent its headers, while the body is still being read, is not a
// refusal and is not cached.
func TestCancelledMidAnswerIsUnavailable(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"aud":`))
		w.(http.Flusher).Flush()
		<-release
	}))
	defer srv.Close()
	defer close(release)
	// Cancel exactly when the headers are in and the body is not, so the
	// cancellation always lands while the answer is being read.
	hc := &http.Client{Transport: cancelAfterHeaders{next: http.DefaultTransport, cancel: cancel}}
	v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: srv.URL, UserInfoURL: srv.URL, HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ctx, "valid-token")
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalid) {
		t.Errorf("cancelled mid-answer: %v, want ErrUnavailable", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled mid-answer: %v, want context.Canceled still detectable", err)
	}
	if cached(v, "valid-token") {
		t.Error("a cancelled lookup was cached")
	}
}

// cancelAfterHeaders cancels the request's context as soon as the response
// headers have arrived.
type cancelAfterHeaders struct {
	next   http.RoundTripper
	cancel context.CancelFunc
}

func (c cancelAfterHeaders) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	c.cancel()
	return resp, err
}

// TestLenientFieldTypes: exp and email_verified as a number and a boolean
// verify the same as the strings Google sends today.
func TestLenientFieldTypes(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/userinfo" {
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "dana@cymbal.example", "hd": "cymbal.example"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"aud": clientID, "azp": clientID, "sub": "1001", "email": "dana@cymbal.example",
			"email_verified": true, "exp": now.Add(time.Hour).Unix(), "scope": EmailScope,
		})
	}))
	defer srv.Close()
	v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: srv.URL + "/tokeninfo", UserInfoURL: srv.URL + "/userinfo",
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Verify(context.Background(), "typed")
	if err != nil || !id.Expiry.Equal(time.Unix(now.Add(time.Hour).Unix(), 0)) {
		t.Errorf("number exp, boolean email_verified: %+v, %v", id, err)
	}
}

func TestLenientUnmarshal(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`"true"`:       "true",
		`true`:         "true",
		`false`:        "false",
		`1799999999`:   "1799999999",
		`"1799999999"`: "1799999999",
		`-1`:           "-1",
		`null`:         "",
		`{}`:           "",
		`[1]`:          "",
	} {
		var l lenient
		if err := json.Unmarshal([]byte(in), &l); err != nil || string(l) != want {
			t.Errorf("lenient(%s) = %q, %v; want %q", in, l, err, want)
		}
	}
	var l lenient
	if err := l.UnmarshalJSON([]byte(`not json`)); err == nil {
		t.Error("lenient accepted invalid JSON")
	}
}

// panicTransport panics on every request, as a broken caller-supplied
// transport might.
type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("transport bug") }

// TestPanicReleasesLookupSlot: a panic during a lookup must not keep its
// slot, or MaxLookups such panics would shed every token until restart.
func TestPanicReleasesLookupSlot(t *testing.T) {
	t.Parallel()
	v, err := New(Config{ClientIDs: []string{clientID}, HTTPClient: &http.Client{Transport: panicTransport{}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxLookups + 2 {
		func() {
			defer func() { _ = recover() }()
			_, _ = v.Verify(context.Background(), "t"+strconv.Itoa(i))
		}()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.lookups != 0 {
		t.Errorf("lookups = %d after panicking lookups, want 0", v.lookups)
	}
}

// TestLoggerReportsUnavailable: the optional Logger reports a Google
// outage (purser's middleware also logs it, as a 503). It must not carry
// the token, and a refusal must not be logged as an outage.
func TestLoggerReportsUnavailable(t *testing.T) {
	t.Parallel()
	const secret = "ya29.planted-secret-token"
	base, _ := fakeGoogle(t, map[string]map[string]string{
		secret: with(info(clientID, "dana@cymbal.example", "true", now.Add(time.Hour)), "status", "503"),
	})
	var buf bytes.Buffer
	v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: base + "/tokeninfo", UserInfoURL: base + "/userinfo",
		Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = v.Verify(context.Background(), "refused-token")
	if buf.Len() != 0 {
		t.Errorf("a refusal was logged as an outage: %s", buf.String())
	}
	_, _ = v.Verify(context.Background(), secret)
	out := buf.String()
	if !strings.Contains(out, "could not verify") || !strings.Contains(out, "HTTP 503") {
		t.Errorf("an outage was not logged: %q", out)
	}
	if strings.Contains(out, "planted-secret") {
		t.Errorf("the log line carries the token: %q", out)
	}
}

// TestOnlyGoogleVerdictsAreRefusals (steward#14): a non-200 answer is a
// refusal only when it is the endpoint's own verdict on the token,
// tokeninfo's 400 invalid_token or userinfo's 401. Any other status (an
// egress proxy's 403 or 407, a 404 from a moved endpoint) says nothing
// about the token: ErrUnavailable (a 503 behind purser), never cached.
func TestOnlyGoogleVerdictsAreRefusals(t *testing.T) {
	t.Parallel()
	good := info(clientID, "dana@cymbal.example", "true", now.Add(time.Hour))
	for _, c := range []struct {
		endpoint string
		status   int
		refusal  bool
	}{
		{"tokeninfo", http.StatusBadRequest, true},
		{"tokeninfo", http.StatusUnauthorized, false},
		{"tokeninfo", http.StatusForbidden, false},
		{"tokeninfo", http.StatusNotFound, false},
		{"tokeninfo", http.StatusProxyAuthRequired, false},
		{"tokeninfo", http.StatusTeapot, false},
		{"userinfo", http.StatusUnauthorized, true},
		{"userinfo", http.StatusBadRequest, false},
		{"userinfo", http.StatusForbidden, false},
		{"userinfo", http.StatusNotFound, false},
		{"userinfo", http.StatusProxyAuthRequired, false},
	} {
		name := c.endpoint + " " + strconv.Itoa(c.status)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.TrimPrefix(r.URL.Path, "/") == c.endpoint {
				http.Error(w, `<html>not Google</html>`, c.status)
				return
			}
			out := map[string]string{"email": good["email"], "hd": good["hd"]}
			if r.URL.Path == "/tokeninfo" {
				out = good
			}
			_ = json.NewEncoder(w).Encode(out)
		}))
		v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: srv.URL + "/tokeninfo", UserInfoURL: srv.URL + "/userinfo",
			Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		const tok = "ya29.valid-token"
		_, err = v.Verify(context.Background(), tok)
		srv.Close()
		if c.refusal {
			if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrUnavailable) || !cached(v, tok) {
				t.Errorf("%s: %v (cached %v), want ErrInvalid, cached", name, err, cached(v, tok))
			}
			continue
		}
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, purser.ErrUnavailable) || errors.Is(err, ErrInvalid) || errors.Is(err, purser.ErrUnauthenticated) {
			t.Errorf("%s: %v, want ErrUnavailable and not a credential error", name, err)
		}
		if cached(v, tok) {
			t.Errorf("%s: cached as a verdict", name)
		}
		if err != nil && (strings.Contains(err.Error(), tok) || !strings.Contains(err.Error(), "HTTP "+strconv.Itoa(c.status))) {
			t.Errorf("%s: error %q should name the status and not the token", name, err)
		}
	}
}

// TestCancelledClientIsNotAnOutage (steward#14): a lookup that failed
// because the client went away (its context cancelled) is logged at
// Debug, not Warn, as purser does; a deadline that ran out is still an
// outage at Warn.
func TestCancelledClientIsNotAnOutage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "{}", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	var buf bytes.Buffer
	v, err := New(Config{ClientIDs: []string{clientID}, TokenInfoURL: srv.URL, UserInfoURL: srv.URL,
		Logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(gone, "ya29.planted-secret-token"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled: %v, want ErrUnavailable", err)
	}
	if out := buf.String(); strings.Contains(out, "level=WARN") || !strings.Contains(out, "level=DEBUG") || strings.Contains(out, "planted-secret") {
		t.Errorf("a client that went away was logged as an outage, or not at Debug: %q", out)
	}
	buf.Reset()
	late, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	_, _ = v.Verify(late, "another-token")
	if out := buf.String(); !strings.Contains(out, "level=WARN") {
		t.Errorf("a deadline that ran out was not logged as an outage: %q", out)
	}
}

// TestCancelledClientGroupCheckIsNotAnOutage: the Authenticator's own
// Warn for a failed group check drops to Debug when the client went away.
func TestCancelledClientGroupCheckIsNotAnOutage(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	a := newGroupAuthenticator(t, groupChecker{fail: true}, nil)
	a.v.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Verified (and cached) while the client is there; the group check
	// fails either way.
	if _, err := a.Verify(request("Bearer good")); !errors.Is(err, ErrUnavailable) || !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("group check failure: %v, log %q, want ErrUnavailable at Warn", err, buf.String())
	}
	buf.Reset()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Verify(request("Bearer good").WithContext(gone)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled: %v, want ErrUnavailable", err)
	}
	if out := buf.String(); strings.Contains(out, "level=WARN") || !strings.Contains(out, "level=DEBUG") {
		t.Errorf("a client that went away was logged as an outage: %q", out)
	}
}
