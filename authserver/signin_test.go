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

// TestTwoSignInsOneBrowser, TestSignInFailureReasons and the cookie tests
// are ported from kode-gopher internal/oauth signin_test.go at
// fb8ea5ed622f7a0ee9da06ec415a704aad8fde92, adapted to steward's harness,
// its cookie names and the keys-unavailable case.

import (
	"context"
	"crypto/rand"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stopping is b's client, stopping at the first redirect. It shares b's
// cookie jar, so b itself still follows redirects.
func stopping(b *browser) *http.Client {
	c := *b.hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// consentForm loads the consent page in b and returns its sealed form.
func consentForm(t *testing.T, b *browser, u string) string {
	t.Helper()
	resp, err := stopping(b).Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := hiddenRequestRE.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("no consent form: HTTP %d %q", resp.StatusCode, body)
	}
	return html.UnescapeString(m[1])
}

// approve posts a consent form from b and returns the response, where it
// sends the browser (Google sign-in) and the page it stopped on.
func approve(t *testing.T, b *browser, srvURL, form string) (*http.Response, string, string) {
	t.Helper()
	resp, err := stopping(b).PostForm(srvURL+"/authorize", url.Values{"request": {form}, "action": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, resp.Header.Get("Location"), string(body)
}

// get opens u with c and returns the status and page.
func get(t *testing.T, c *http.Client, u string, cookies ...*http.Cookie) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// Two sign-ins started in one browser (a retry, a copied link opened
// alongside the client's tab, a prefetch) both complete.
func TestTwoSignInsOneBrowser(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id := e.register()
	b := newBrowser(t)
	v := rand.Text() + rand.Text()
	formA := consentForm(t, b, e.authorizeURL(id, v, nil))
	formB := consentForm(t, b, e.authorizeURL(id, v, nil))
	_, googleA, pageA := approve(t, b, e.srv.URL, formA)
	_, googleB, pageB := approve(t, b, e.srv.URL, formB)
	if googleA == "" || googleB == "" {
		t.Fatalf("consent refused: A %q, B %q", pageA, pageB)
	}
	// A finishes first; B's callback still finds the cookie.
	for _, g := range []string{googleA, googleB} {
		loc, page := b.visit(g)
		if loc == nil || loc.Query().Get("code") == "" {
			t.Errorf("sign-in %s: redirect %v, page %q", g, loc, page)
		}
	}
	// So does a pre-registered client's, which skips the consent page.
	e2 := newTestEnv(t, true, func(c *Config) {
		c.Clients = []StaticClient{{ID: "cli", RedirectURIs: []string{clientRedirect}}}
	})
	b2 := newBrowser(t)
	var toGoogle []string
	for range 2 {
		resp, err := stopping(b2).Get(e2.authorizeURL("cli", v, nil))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		toGoogle = append(toGoogle, resp.Header.Get("Location"))
	}
	for _, g := range toGoogle {
		if loc, page := b2.visit(g); loc == nil || loc.Query().Get("code") == "" {
			t.Errorf("pre-registered sign-in %s: redirect %v, page %q", g, loc, page)
		}
	}
}

// Each reason a flow can't continue is named on the page and in the log.
func TestSignInFailureReasons(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	id := e.register()
	v := rand.Text() + rand.Text()

	victim := newBrowser(t)
	form := consentForm(t, newBrowser(t), e.authorizeURL(id, v, nil))
	_, _, noCookie := approve(t, victim, e.srv.URL, form)

	// The victim has a sign-in of its own, so a cookie, but not this one.
	consentForm(t, victim, e.authorizeURL(id, v, nil))
	_, _, otherFlow := approve(t, victim, e.srv.URL, form)

	_, _, unreadable := approve(t, victim, e.srv.URL, "st1.k1.AAAA")

	old, err := e.as.seal(context.Background(), purposeConsent, browserBound{Req: authRequest{ClientID: id}, Exp: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	_, _, expired := approve(t, victim, e.srv.URL, old)

	// The Google callback reports the same way, including for a state
	// another browser's sign-in carries.
	_, callback := get(t, victim.hc, e.as.CallbackURL()+"?state=garbage&code=x")
	other := newBrowser(t)
	_, google, page := approve(t, other, e.srv.URL, consentForm(t, other, e.authorizeURL(id, v, nil)))
	toGoogle, err := url.Parse(google)
	if err != nil || toGoogle.Query().Get("state") == "" {
		t.Fatalf("other browser's approval: %q %q", google, page)
	}
	otherState := toGoogle.Query().Get("state")
	_, callbackOther := get(t, victim.hc, e.as.CallbackURL()+"?"+url.Values{"state": {otherState}, "code": {"x"}}.Encode())

	// So does the vault's consent leg, for its own cookie.
	_, contNoCookie := get(t, hc, e.as.ContinueURL()+"?user_id_validation_state=x")
	_, contUnreadable := get(t, hc, e.as.ContinueURL(), &http.Cookie{Name: cookieConsent, Value: "st1.k1.AAAA"})
	oldPending, err := e.as.seal(context.Background(), purposePending, pendingConsent{Req: authRequest{ClientID: id}, Exp: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	_, contExpired := get(t, hc, e.as.ContinueURL(), &http.Cookie{Name: cookieConsent, Value: oldPending})

	for name, tc := range map[string]struct {
		page string
		want *signInStop
	}{
		"no cookie":                  {noCookie, stopNoCookie},
		"other flow":                 {otherFlow, stopOtherFlow},
		"unreadable":                 {unreadable, stopUnreadable},
		"expired":                    {expired, stopExpired},
		"callback":                   {callback, stopUnreadable},
		"callback, other flow":       {callbackOther, stopOtherFlow},
		"vault consent, no cookie":   {contNoCookie, stopNoCookie},
		"vault consent, unreadable":  {contUnreadable, stopUnreadable},
		"vault consent, old pending": {contExpired, stopExpired},
	} {
		if !strings.Contains(tc.page, html.EscapeString(tc.want.page)) {
			t.Errorf("%s: page %q, want %q", name, tc.page, tc.want.page)
		}
	}
	log := e.log.String()
	for _, want := range []string{
		`step="consent page" reason="no cookie"`,
		`step="consent page" reason="another sign-in's cookie"`,
		`step="consent page" reason=unreadable`,
		`step="consent page" reason=expired`,
		`step="Google callback" reason=unreadable`,
		`step="Google callback" reason="another sign-in's cookie"`,
		`step="vault consent" reason="no cookie"`,
		`step="vault consent" reason=unreadable`,
		`step="vault consent" reason=expired`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %s:\n%s", want, log)
		}
	}
	// What the browser sent stays out of the log: the binding cookies and
	// the sealed form and state.
	u, _ := url.Parse(e.srv.URL)
	secrets := []string{form, otherState}
	for _, b := range []*browser{victim, other} {
		for _, c := range b.hc.Jar.Cookies(u) {
			secrets = append(secrets, c.Value)
		}
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(log, s) {
			t.Errorf("log contains %q", s)
		}
	}
}

// The sealing keys being unavailable is a 503 to retry, not a damaged
// link.
func TestSignInKeysUnavailable(t *testing.T) {
	t.Parallel()
	keys := &flakyKeys{fail: map[int]bool{}}
	e := newTestEnv(t, true, func(c *Config) { c.Keys = keys })
	id := e.register()
	b := newBrowser(t)
	form := consentForm(t, b, e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	keys.mu.Lock()
	keys.fail[keys.calls+1] = true
	keys.mu.Unlock()
	resp, loc, page := approve(t, b, e.srv.URL, form)
	if resp.StatusCode != http.StatusServiceUnavailable || loc != "" || !strings.Contains(page, html.EscapeString(stopKeys.page)) {
		t.Errorf("approve with the keys unavailable: %d %q %q", resp.StatusCode, loc, page)
	}
	// The same form works once the keys are back.
	if _, loc, page := approve(t, b, e.srv.URL, form); loc == "" {
		t.Fatalf("approve once the keys are back: %q", page)
	}
	keys.mu.Lock()
	keys.fail[keys.calls+1] = true
	keys.mu.Unlock()
	if status, page := get(t, b.hc, e.as.CallbackURL()+"?state=st1.k1.AAAA&code=x"); status != http.StatusServiceUnavailable {
		t.Errorf("callback with the keys unavailable: %d %q", status, page)
	}
	keys.mu.Lock()
	keys.fail[keys.calls+1] = true
	keys.mu.Unlock()
	if status, page := get(t, hc, e.as.ContinueURL(), &http.Cookie{Name: cookieConsent, Value: "st1.k1.AAAA"}); status != http.StatusServiceUnavailable {
		t.Errorf("vault consent with the keys unavailable: %d %q", status, page)
	}
}

// A malformed binding cookie isn't kept; approving the consent page renews
// the cookie for the Google leg; the callback leaves it in place.
func TestBindingCookieHygiene(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	n := len(rand.Text())
	for _, bad := range []string{"short", strings.Repeat("a", n), strings.Repeat("A", n+1), strings.Repeat("A", n-1) + "1"} {
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.AddCookie(&http.Cookie{Name: cookieBrowser, Value: bad})
		w := httptest.NewRecorder()
		if got := e.as.bindBrowser(w, r); got == hashCookie(bad) {
			t.Errorf("bindBrowser kept a malformed cookie %q", bad)
		}
		if set := w.Result().Cookies(); len(set) != 1 || !browserCookieRE.MatchString(set[0].Value) {
			t.Errorf("bindBrowser over %q set %v", bad, set)
		}
	}

	id := e.register()
	b := newBrowser(t)
	form := consentForm(t, b, e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	resp, google, page := approve(t, b, e.srv.URL, form)
	if google == "" {
		t.Fatalf("consent refused: %q", page)
	}
	var renewed *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieBrowser {
			renewed = c
		}
	}
	if renewed == nil || renewed.MaxAge != int(AuthRequestTTL.Seconds()) || !browserCookieRE.MatchString(renewed.Value) {
		t.Fatalf("approve didn't renew the binding cookie: %v", resp.Cookies())
	}
	// Google signs in; the callback must not clear the cookie.
	resp, err := stopping(b).Get(google)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	resp, err = stopping(b).Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("callback: %d %v", resp.StatusCode, loc)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieBrowser {
			t.Errorf("the callback touched the binding cookie: %+v", c)
		}
	}
	// The next sign-in in this browser keeps the same cookie.
	u, _ := url.Parse(e.srv.URL)
	before := b.hc.Jar.Cookies(u)
	consentForm(t, b, e.authorizeURL(id, rand.Text()+rand.Text(), nil))
	after := b.hc.Jar.Cookies(u)
	if len(before) != 1 || len(after) != 1 || before[0].Value != after[0].Value || before[0].Value != renewed.Value {
		t.Errorf("binding cookie before %v, after %v, want %s kept", before, after, renewed.Value)
	}
}

// bindBrowser keeps only a cookie under the issuer's prefixed name, so on
// https it never adopts one planted under the bare name, which anyone able
// to write cookies for the host could set; and it keeps none at all where
// a sibling subdomain could plant the prefixed one (an issuer with a path).
func TestBindingCookiePrefixes(t *testing.T) {
	t.Parallel()
	planted := strings.Repeat("A", len(rand.Text()))
	for issuer, want := range map[string]struct {
		name string
		keep bool
	}{
		"https://svc.example.com":       {"__Host-" + cookieBrowser, true},
		"https://svc.example.com/oauth": {"__Secure-" + cookieBrowser, false},
		"http://127.0.0.1:8080":         {cookieBrowser, true},
	} {
		c := goodConfig(t)
		c.Issuer = issuer
		if strings.HasPrefix(issuer, "http:") {
			c.Resource = "http://127.0.0.1:8080/mcp"
		}
		s, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, issuer+"/authorize", nil)
		if want.name != cookieBrowser {
			r.AddCookie(&http.Cookie{Name: cookieBrowser, Value: planted})
			w := httptest.NewRecorder()
			if got := s.bindBrowser(w, r); got == hashCookie(planted) {
				t.Errorf("%s: bindBrowser kept a cookie without the prefix", issuer)
			}
			set := w.Result().Cookies()
			if len(set) != 1 || set[0].Name != want.name || !set[0].Secure || !set[0].HttpOnly || set[0].Domain != "" {
				t.Errorf("%s: Set-Cookie %+v, want a Secure, host-only %s", issuer, set, want.name)
			}
		}
		r.AddCookie(&http.Cookie{Name: want.name, Value: planted})
		if kept := s.bindBrowser(httptest.NewRecorder(), r) == hashCookie(planted); kept != want.keep {
			t.Errorf("%s: bindBrowser kept the browser's %s cookie: %v, want %v", issuer, want.name, kept, want.keep)
		}
	}
}
