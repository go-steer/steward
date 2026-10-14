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

// TestLoggerReportsUnavailable: behind purser's enforced middleware every
// failure is a plain 401, so the Logger line is how an operator tells a
// Google outage from bad tokens. It must not carry the token, and a
// refusal must not be logged as an outage.
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
