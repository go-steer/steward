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

// Regression tests for the second review round of the authorization
// server (refresh families, undo on a detached context, error
// classification).

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ctxReplay is a MemoryReplayCache whose undo operations fail on a done
// context, as a networked cache would, and which can fail a Rotate after
// applying it (a timeout after the write).
type ctxReplay struct {
	*MemoryReplayCache
	mu             sync.Mutex
	failAfterApply bool
	unrotated      int
}

func (c *ctxReplay) Unrotate(ctx context.Context, fam string, gen uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.unrotated++
	c.mu.Unlock()
	return c.MemoryReplayCache.Unrotate(ctx, fam, gen)
}

func (c *ctxReplay) Release(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.MemoryReplayCache.Release(ctx, id)
}

func (c *ctxReplay) Rotate(ctx context.Context, fam string, gen uint64, exp time.Time) (bool, error) {
	r, err := c.RotateGrace(ctx, fam, gen, exp, time.Time{})
	return r == RotateApplied, err
}

// RotateGrace overrides the embedded cache's too, as GraceReplayCache
// tells a wrapper to, or the server would skip the override.
func (c *ctxReplay) RotateGrace(ctx context.Context, fam string, gen uint64, exp, graceUntil time.Time) (RotateResult, error) {
	r, err := c.MemoryReplayCache.RotateGrace(ctx, fam, gen, exp, graceUntil)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAfterApply {
		c.failAfterApply = false
		return RotateRevoked, errors.New("timeout after write")
	}
	return r, err
}

// cancellingAdmitter cancels the request mid-refresh and fails, like a
// client going away while the directory is slow.
type cancellingGroups struct{ cancel context.CancelFunc }

func (g cancellingGroups) IsMember(context.Context, string, string) (bool, error) {
	g.cancel()
	return false, errors.New("context canceled")
}

// A client that goes away mid-refresh must not leave its family rotated:
// the undo runs on a detached context, and the retry works.
func TestUndoSurvivesCancelledRequest(t *testing.T) {
	t.Parallel()
	replay := &ctxReplay{MemoryReplayCache: NewMemoryReplayCache()}
	e := newTestEnv(t, true, func(c *Config) { c.Replay = replay })
	e.google.signInAs = bob // needs the group check
	id, first := e.signIn(newBrowser(t))

	c, _ := e.as.resolveClient(context.Background(), id)
	ctx, cancel := context.WithCancel(context.Background())
	e.as.cfg.Admit = newAdmitter(t, cancellingGroups{cancel: cancel})
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/token", nil)
	req.PostForm = refreshForm(id, first.Refresh)
	if _, terr := e.as.refreshTokens(ctx, req, c); terr == nil || terr.Code != "server_error" {
		t.Fatalf("refresh with a cancelled request: %+v", terr)
	}
	e.as.cfg.Admit = newAdmitter(t, e.groups)
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry after a cancelled refresh: %+v (the family stayed rotated)", r)
	}
}

// A Rotate that errors after applying is undone, so the retry works.
func TestRotateErrorIsUndone(t *testing.T) {
	t.Parallel()
	replay := &ctxReplay{MemoryReplayCache: NewMemoryReplayCache()}
	e := newTestEnv(t, true, func(c *Config) { c.Replay = replay })
	id, first := e.signIn(newBrowser(t))
	replay.mu.Lock()
	replay.failAfterApply = true
	replay.mu.Unlock()
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" {
		t.Fatalf("refresh with a failing cache: %+v", r)
	}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry after a Rotate error: %+v", r)
	}
}

// A refresh whose tokens could not be sealed rotates back.
func TestRefreshReleasedWhenIssuingFails(t *testing.T) {
	t.Parallel()
	keys := &flakyKeys{fail: map[int]bool{}}
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
		c.Keys = keys
	})
	v := rand.Text() + rand.Text()
	first := e.token(exchangeForm("cli", e.code("cli", v), v), "", "")
	keys.mu.Lock()
	keys.fail[keys.calls+2] = true // open the refresh token, then fail sealing the access token
	keys.mu.Unlock()
	if r := e.token(refreshForm("cli", first.Refresh), "", ""); r.Error != "server_error" {
		t.Fatalf("refresh with a key-store hiccup: %+v", r)
	}
	if r := e.token(refreshForm("cli", first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry with the same refresh token: %+v", r)
	}
}

// The token endpoint takes only a form body.
func TestTokenEndpointContentType(t *testing.T) {
	t.Parallel()
	e, _ := newServiceEnv(t)
	for ct, want := range map[string]int{
		"text/plain":                        http.StatusBadRequest,
		"":                                  http.StatusBadRequest,
		"application/x-www-form-urlencoded": http.StatusOK,
		"Application/X-WWW-Form-Urlencoded; charset=utf-8": http.StatusOK,
	} {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/token", strings.NewReader("grant_type=client_credentials"))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.SetBasicAuth("bot", "bot-secret")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Content-Type %q: %d, want %d", ct, resp.StatusCode, want)
		}
	}
}

// Setting, reading and clearing a flow cookie all use the same name,
// __Host- or __Secure- prefixed.
func TestCookieSetClearConsistent(t *testing.T) {
	t.Parallel()
	for _, issuer := range []string{"https://svc.example.com", "https://svc.example.com/oauth"} {
		c := goodConfig(t)
		c.Issuer = issuer
		s, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		set, clr := httptest.NewRecorder(), httptest.NewRecorder()
		s.setCookie(set, cookieConsent, "v")
		s.clearCookie(clr, cookieConsent)
		a, b := set.Result().Cookies()[0], clr.Result().Cookies()[0]
		if a.Name != b.Name || a.Path != b.Path || b.MaxAge >= 0 || !a.Secure || !a.HttpOnly {
			t.Errorf("%s: set %+v, clear %+v", issuer, a, b)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: a.Name, Value: "x"})
		if _, err := req.Cookie(s.cookieName(cookieConsent)); err != nil {
			t.Errorf("%s: the cookie set is not the cookie read", issuer)
		}
	}
}

// A CIMD host answering 429 is unavailable; one whose name does not
// resolve, or that the SSRF filter refuses, is an unknown client.
func TestCIMDErrorClassification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f429 := newCIMDFetcher(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusTooManyRequests)
		return rec.Result(), nil
	})})
	if _, err := f429.fetch(ctx, "https://x.example/c.json"); !errors.Is(err, errCIMDUnavailable) {
		t.Errorf("429: %v, want unavailable", err)
	}
	nx := newCIMDFetcher(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "x.example", IsNotFound: true}
	})})
	if _, err := nx.fetch(ctx, "https://x.example/c.json"); err == nil || errors.Is(err, errCIMDUnavailable) {
		t.Errorf("NXDOMAIN: %v, want an unknown client", err)
	}
	timeout := newCIMDFetcher(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.DNSError{Err: "timeout", Name: "x.example", IsTimeout: true}
	})})
	if _, err := timeout.fetch(ctx, "https://x.example/c.json"); !errors.Is(err, errCIMDUnavailable) {
		t.Errorf("DNS timeout: %v, want unavailable", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ssrf := newCIMDFetcher(nil)
	u, _ := url.Parse(srv.URL)
	if _, err := ssrf.fetch(ctx, "https://"+u.Host+"/c.json"); err == nil || errors.Is(err, errCIMDUnavailable) || !errors.Is(err, errNonPublic) {
		t.Errorf("loopback CIMD URL: %v, want refused as non-public and unknown", err)
	}
	badCert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer badCert.Close()
	untrusting := newCIMDFetcher(&http.Client{Transport: &http.Transport{}})
	if _, err := untrusting.fetch(ctx, badCert.URL+"/c.json"); err == nil || errors.Is(err, errCIMDUnavailable) {
		t.Errorf("untrusted certificate: %v, want an unknown client", err)
	}
}

// A person's token for a pre-registered client that has since been
// removed, or with none of its scopes still allowed, is refused.
func TestVerifyRemovedClientOrNoScopes(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
	})
	v := rand.Text() + rand.Text()
	r := e.token(exchangeForm("cli", e.code("cli", v), v), "", "")
	saved := e.as.static["cli"]
	e.as.static["cli"] = StaticClient{ID: "cli", RedirectURIs: []string{clientRedirect}, Scopes: []string{scopeWrite}}
	if _, err := e.as.Verify(context.Background(), r.Access); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token with none of its scopes still allowed: %v", err)
	}
	delete(e.as.static, "cli")
	if _, err := e.as.Verify(context.Background(), r.Access); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token for a removed client: %v", err)
	}
	e.as.static["cli"] = saved
	if _, err := e.as.Verify(context.Background(), r.Access); err != nil {
		t.Errorf("token for the restored client: %v", err)
	}
}

func TestIsPublicMoreRanges(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"::a9fe:a9fe", "::ffff:0:a9fe:a9fe", "0.1.2.3", "2001:2::1", "2001:db8::1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Errorf("isPublic(%s) = true", a)
		}
	}
}

// A zoned address is never public: Prefix.Contains is false for any zone,
// so without the check a zone slips a special-purpose address past every
// range (https://[64:ff9b::a9fe:a9fe%25eth0]/c.json reached NAT64).
func TestIsPublicZoned(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"64:ff9b::a9fe:a9fe%eth0", "2002:a9fe:a9fe::1%lo", "::a9fe:a9fe%x", "2001:db8::1%x", "2606:4700::1%1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Errorf("isPublic(%s) = true", a)
		}
	}
	if !isPublic(netip.MustParseAddr("2606:4700::1")) {
		t.Error("isPublic(2606:4700::1) = false")
	}
}

// Through the real dialer: the zone reaches the dialer's Control, which
// refuses before connecting, so this needs no network.
func TestCIMDZonedURLRefused(t *testing.T) {
	t.Parallel()
	_, err := newCIMDFetcher(nil).fetch(context.Background(), "https://[64:ff9b::a9fe:a9fe%251]/c.json")
	if !errors.Is(err, errNonPublic) || errors.Is(err, errCIMDUnavailable) {
		t.Errorf("zoned NAT64 CIMD URL: %v, want refused as non-public and unknown", err)
	}
}

func TestIsPublicDocumentationAndSiteLocal(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "3fff::1", "fec0::1", "100::1", "5f00::1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Errorf("isPublic(%s) = true", a)
		}
	}
}

// A CIMD host that redirects is an unknown client, not unavailable:
// redirects are never followed, so a retry cannot help.
func TestCIMDRedirectIsPermanent(t *testing.T) {
	t.Parallel()
	hc := SSRFSafeClient(time.Second)
	hc.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Location", "https://elsewhere.example/c.json")
		rec.WriteHeader(http.StatusFound)
		return rec.Result(), nil
	})
	_, err := newCIMDFetcher(hc).fetch(context.Background(), "https://x.example/c.json")
	if err == nil || errors.Is(err, errCIMDUnavailable) || !errors.Is(err, errRedirect) {
		t.Errorf("redirecting CIMD host: %v, want refused as a redirect and unknown", err)
	}
}

func TestDomainScopedAuthProvider(t *testing.T) {
	t.Parallel()
	c := goodConfig(t)
	c.Custody = &VaultCustody{AuthProvider: "projects/example.com:proj/locations/global/authProviders/a", Client: hc}
	if _, err := New(c); err != nil {
		t.Errorf("a domain-scoped project refused: %v", err)
	}
}
