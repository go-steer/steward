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

// Package pathbtest helps tests drive steward's authorization server end
// to end: a fake Google sign-in, a browser that approves the consent page,
// and helpers that obtain access tokens over HTTP. Test-only; nothing here
// is part of steward's API.
package pathbtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/oauth2"

	"github.com/go-steer/steward/authserver"
)

// SignInClientID is the Google client ID the fake sign-in issues ID tokens
// for.
const SignInClientID = "steward-signin.apps.googleusercontent.com"

// RobotSA is a service account for client-credentials tests.
const RobotSA = "robot@test-project.iam.gserviceaccount.com"

// ServiceTokens is an authserver.ServiceTokens that mints
// "ya29.sa-<account>" for any service account.
type ServiceTokens struct{}

// Token implements authserver.ServiceTokens.
func (ServiceTokens) Token(_ context.Context, sa string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "ya29.sa-" + sa, Expiry: time.Now().Add(time.Hour)}, nil
}

// ClientRedirect is the redirect URI test clients register; it is never
// dialed.
const ClientRedirect = "http://127.0.0.1:1/callback"

// Person is who the fake signs in.
type Person struct {
	Sub, Email, HD string
}

// SignIn is Google's sign-in and token endpoints, signing everyone in as
// one Person, with the cloud-platform scope and a refresh token.
type SignIn struct {
	srv *httptest.Server
	as  Person

	mu     sync.Mutex
	codes  map[string]string // code -> challenge
	minted []string
}

// NewSignIn starts the fake.
func NewSignIn(t testing.TB, as Person) *SignIn {
	f := &SignIn{as: as, codes: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "gcode-" + rand.Text()
		f.mu.Lock()
		f.codes[code] = q.Get("code_challenge")
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound) //nolint:gosec // G710: a test fake standing in for Google
	})
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *SignIn) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if ch, ok := f.codes[r.PostForm.Get("code")]; !ok || ch != base64.RawURLEncoding.EncodeToString(sum[:]) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	delete(f.codes, r.PostForm.Get("code"))
	claims := map[string]any{"iss": "https://accounts.google.com", "aud": SignInClientID, "sub": f.as.Sub,
		"email": f.as.Email, "email_verified": true, "exp": 4102444800}
	if f.as.HD != "" {
		claims["hd"] = f.as.HD
	}
	b, _ := json.Marshal(claims)
	tok := "ya29.signin-" + rand.Text()
	f.minted = append(f.minted, tok)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": tok, "expires_in": 3599, "refresh_token": "1//r-" + rand.Text(),
		"scope":    authserver.ScopeOpenID + " " + authserver.ScopeEmail + " " + authserver.ScopeCloudPlatform,
		"id_token": "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig",
	})
}

// Google is the GoogleClient to configure the authorization server with.
func (f *SignIn) Google() authserver.GoogleClient {
	return authserver.GoogleClient{ClientID: SignInClientID, ClientSecret: "s", AuthURL: f.srv.URL + "/auth", TokenURL: f.srv.URL + "/token"}
}

// Minted lists every Google access token handed out.
func (f *SignIn) Minted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.minted...)
}

var hiddenRequestRE = regexp.MustCompile(`name="request" value="([^"]+)"`)

// client has its own transport: closing an httptest.Server closes
// http.DefaultTransport's idle connections, which breaks requests other
// parallel tests have in flight on it.
var client = &http.Client{Transport: &http.Transport{}}

// Browser returns an MCP SDK AuthorizationCodeFetcher that follows
// redirects like a user's browser, approving the consent page, until it
// reaches the client's redirect URI.
func Browser() auth.AuthorizationCodeFetcher {
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Transport: &http.Transport{}, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "127.0.0.1:1" {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	return func(_ context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		resp, err := hc.Get(args.URL)
		for err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusFound {
				loc, err := url.Parse(resp.Header.Get("Location"))
				if err != nil {
					return nil, err
				}
				q := loc.Query()
				if q.Get("error") != "" {
					return nil, fmt.Errorf("authorization error %s: %s", q.Get("error"), q.Get("error_description"))
				}
				return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
			}
			m := hiddenRequestRE.FindSubmatch(body)
			if m == nil {
				return nil, fmt.Errorf("sign-in stopped on a page: %s", body)
			}
			resp, err = hc.PostForm(resp.Request.URL.String(), url.Values{"request": {html.UnescapeString(string(m[1]))}, "action": {"approve"}})
		}
		return nil, err
	}
}

// PersonToken registers a client by DCR with the authorization server at
// issuer, signs the fake's person in for resource with the given scope
// (empty: none asked for), and returns the access token.
func PersonToken(t testing.TB, issuer, resource, scope string) string {
	t.Helper()
	resp, err := client.Post(issuer+"/register", "application/json", strings.NewReader(`{"redirect_uris":["`+ClientRedirect+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	_ = resp.Body.Close()
	verifier := rand.Text() + rand.Text()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {ClientRedirect},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {resource}, "state": {"s"},
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	res, err := Browser()(context.Background(), &auth.AuthorizationArgs{URL: issuer + "/authorize?" + q.Encode()})
	if err != nil {
		t.Fatal(err)
	}
	return Token(t, issuer, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {reg.ClientID}, "code": {res.Code},
		"code_verifier": {verifier}, "redirect_uri": {ClientRedirect},
	}, "", "")
}

// ClientCredentials returns a workload's access token.
func ClientCredentials(t testing.TB, issuer, id, secret string) string {
	t.Helper()
	return Token(t, issuer, url.Values{"grant_type": {"client_credentials"}}, id, secret)
}

// Token posts form to the token endpoint (with Basic credentials if id is
// set) and returns the access token.
func Token(t testing.TB, issuer string, form url.Values, id, secret string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		req.SetBasicAuth(id, secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tr struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tr)
	if tr.AccessToken == "" {
		t.Fatalf("token endpoint: %d %s", resp.StatusCode, tr.Error)
	}
	return tr.AccessToken
}
