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

package mcpauth

// End to end with the MCP SDK's own client: Path B sign-in through
// steward's authorization server (DCR and client credentials), and Path A
// Google tokens, on one protected endpoint. Adapted from kode-gopher
// internal/oauth e2e_test.go and client_credentials_test.go at
// 8b53617b7d4d0b08b158de64ab7416dc84a1281e.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/auth/extauth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/authserver"
	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/httpauth"
	"github.com/go-steer/steward/internal/pathbtest"
	"github.com/go-steer/steward/seal"
)

const (
	scopeRead  = "svc:read"
	scopeWrite = "svc:write"
)

// dana is who the fake Google signs in on Path B: the same account Path
// A's "dana-token" belongs to.
var dana = pathbtest.Person{Sub: "1001", Email: "dana@cymbal.example", HD: "cymbal.example"}

// pathBEnv is one MCP endpoint behind a Protector that accepts both Google
// tokens and steward's, with steward's authorization server mounted.
type pathBEnv struct {
	srv    *httptest.Server
	as     *authserver.Server
	signIn *pathbtest.SignIn
	seen   chan string // what whoami saw in the request headers
}

func newPathBEnv(t *testing.T, required ...string) *pathBEnv {
	t.Helper()
	e := &pathBEnv{signIn: pathbtest.NewSignIn(t, dana), seen: make(chan string, 16)}
	mux := http.NewServeMux()
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)

	keys, err := seal.NewKeyring(seal.Key{ID: "k1", Secret: []byte(strings.Repeat("k", seal.KeySize))})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := allow.Parse([]string{"@cymbal.example"})
	adm, err := allow.NewAdmitter(list, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.as, err = authserver.New(authserver.Config{
		Issuer:           e.srv.URL,
		Resource:         e.srv.URL + "/mcp",
		Scopes:           []string{scopeRead, scopeWrite},
		Google:           e.signIn.Google(),
		Custody:          authserver.SealedCustody{},
		Admit:            adm,
		Keys:             keys,
		OpenRegistration: true,
		Clients: []authserver.StaticClient{
			{ID: "ci", Secret: "ci-secret", ClientCredentials: true, Scopes: []string{scopeRead}},
			{ID: "writer", Secret: "w-secret", ClientCredentials: true, Scopes: []string{scopeWrite}},
			{ID: "robot", Secret: "r-secret", ServiceAccount: pathbtest.RobotSA},
		},
		ServiceTokens: pathbtest.ServiceTokens{},
	})
	if err != nil {
		t.Fatal(err)
	}

	base := fakeGoogle(t)
	v, err := googletoken.New(googletoken.Config{ClientIDs: []string{clientID}, TokenInfoURL: base + "/tokeninfo", UserInfoURL: base + "/userinfo"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := googletoken.NewAuthenticator(v, list)
	if err != nil {
		t.Fatal(err)
	}
	p, err := httpauth.New(httpauth.Options{Authenticator: a, AuthServer: e.as, Resource: e.srv.URL + "/mcp", RequiredScopes: required})
	if err != nil {
		t.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami"}, func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		e.seen <- req.Extra.Header.Get("Authorization")
		ti := req.Extra.TokenInfo
		email, tok, kind := "-", "-", "user"
		if id, ok := Identity(req); ok {
			email = id.Email
		}
		if ts, ok := TokenSource(req); ok {
			t, err := ts.Token()
			if err != nil {
				return nil, nil, err
			}
			tok = t.AccessToken
		}
		if pr, ok := Principal(req); ok && pr.Workload {
			kind = "workload"
			if ts, ok := pr.TokenSource(); ok {
				t, _ := ts.Token()
				kind += ":" + t.AccessToken
			}
		} else if !ok {
			kind = "google"
		}
		text := fmt.Sprintf("%s %s %s %s %s", ti.UserID, kind, email, strings.Join(ti.Scopes, ","), tok)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
	})
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux.Handle("/mcp", Middleware(p)(sdk))
	mux.Handle(p.MetadataPath(), p.MetadataHandler())
	e.as.Register(mux)
	return e
}

// ownClient is an HTTP client with its own transport: closing an
// httptest.Server closes http.DefaultTransport's idle connections, which
// breaks requests other parallel tests have in flight on it.
func ownClient() *http.Client { return &http.Client{Transport: &http.Transport{}} }

func (e *pathBEnv) whoami(t *testing.T, h auth.OAuthHandler) string {
	t.Helper()
	ctx := context.Background()
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: e.srv.URL + "/mcp", OAuthHandler: h, DisableStandaloneSSE: true, HTTPClient: ownClient()}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil || res.IsError {
		t.Fatalf("whoami: %v %v", err, res)
	}
	if hdr := <-e.seen; hdr != "" {
		t.Error("the tool saw the Authorization header")
	}
	return res.Content[0].(*mcp.TextContent).Text
}

// A generic MCP client discovers steward's authorization server from the
// resource's metadata, registers by DCR, signs in through Google, and calls
// a tool as the person, with the person's own Google token.
func TestE2EPathBDynamicClient(t *testing.T) {
	t.Parallel()
	e := newPathBEnv(t)
	h, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{
			Metadata: &oauthex.ClientRegistrationMetadata{ClientName: "dcr-client", RedirectURIs: []string{pathbtest.ClientRedirect}},
		},
		RedirectURL:              pathbtest.ClientRedirect,
		Client:                   ownClient(),
		AuthorizationCodeFetcher: pathbtest.Browser(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := e.whoami(t, h)
	f := strings.Fields(got)
	if len(f) != 5 || f[0] != "1001" || f[1] != "user" || f[2] != dana.Email || f[3] != scopeRead+","+scopeWrite || !strings.HasPrefix(f[4], "ya29.signin-") {
		t.Errorf("whoami = %q, want 1001 user %s %s,%s ya29.signin-...", got, dana.Email, scopeRead, scopeWrite)
	}
}

// A workload signs in with client credentials: no person, no person's
// token, its own subject. The SDK's client asks for every advertised
// scope; the server grants the one this client may have.
func TestE2EPathBClientCredentials(t *testing.T) {
	t.Parallel()
	e := newPathBEnv(t)
	h, err := extauth.NewClientCredentialsHandler(&extauth.ClientCredentialsHandlerConfig{
		Credentials: &oauthex.ClientCredentials{ClientID: "ci", ClientSecretAuth: &oauthex.ClientSecretAuth{ClientSecret: "ci-secret"}},
		HTTPClient:  ownClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := e.whoami(t, h), "client:ci workload - "+scopeRead+" -"; got != want {
		t.Errorf("whoami = %q, want %q", got, want)
	}

	// A workload with a service account: its token is the Principal's,
	// never the person's token source or identity.
	robot, err := extauth.NewClientCredentialsHandler(&extauth.ClientCredentialsHandlerConfig{
		Credentials: &oauthex.ClientCredentials{ClientID: "robot", ClientSecretAuth: &oauthex.ClientSecretAuth{ClientSecret: "r-secret"}},
		HTTPClient:  ownClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "client:robot workload:ya29.sa-" + pathbtest.RobotSA + " - " + scopeRead + "," + scopeWrite + " -"
	if got := e.whoami(t, robot); got != want {
		t.Errorf("whoami as a service-account workload = %q, want %q", got, want)
	}
}

// One endpoint takes both paths. The same person is the same session user
// on either: a session opened with a Google token (Path A) continues with
// a steward token for the same account (Path B), and a workload's token
// cannot use it.
func TestBothPathsOneEndpoint(t *testing.T) {
	t.Parallel()
	e := newPathBEnv(t)
	h := e.srv.Config.Handler

	// The metadata names steward's issuer, so generic clients sign in there.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	var meta struct {
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != e.srv.URL || strings.Join(meta.ScopesSupported, " ") != scopeRead+" "+scopeWrite {
		t.Errorf("metadata = %s", rec.Body.String())
	}

	rec = post(t, h, "dana-token", "", initialize)
	session := rec.Header().Get("Mcp-Session-Id")
	if rec.Code != http.StatusOK || session == "" {
		t.Fatalf("initialize with a Google token: %d %s", rec.Code, rec.Body.String())
	}
	const ping = `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	if rec := post(t, h, pathbtest.PersonToken(t, e.srv.URL, e.as.Resource(), ""), session, ping); rec.Code != http.StatusOK {
		t.Errorf("the same person with a steward token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(t, h, pathbtest.ClientCredentials(t, e.srv.URL, "ci", "ci-secret"), session, ping); rec.Code != http.StatusForbidden {
		t.Errorf("a workload using a person's session: %d, want 403", rec.Code)
	}
	if rec := post(t, h, "st1.k1.forged", session, ping); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Errorf("a forged steward token: %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// RequiredScopes refuses a steward token without them with the step-up
// challenge; a Google token is not checked against service scopes.
func TestRequiredScopes(t *testing.T) {
	t.Parallel()
	e := newPathBEnv(t, scopeRead)
	h := e.srv.Config.Handler
	rec := post(t, h, pathbtest.ClientCredentials(t, e.srv.URL, "writer", "w-secret"), "", initialize)
	if wa := rec.Header().Get("WWW-Authenticate"); rec.Code != http.StatusForbidden || !strings.Contains(wa, `error="insufficient_scope"`) || !strings.Contains(wa, `scope="svc:read"`) {
		t.Errorf("a token without svc:read: %d, challenge %q", rec.Code, wa)
	}
	if rec := post(t, h, pathbtest.ClientCredentials(t, e.srv.URL, "ci", "ci-secret"), "", initialize); rec.Code != http.StatusOK {
		t.Errorf("a token with svc:read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(t, h, "dana-token", "", initialize); rec.Code != http.StatusOK {
		t.Errorf("a Google token: %d %s", rec.Code, rec.Body.String())
	}
}

// Principal reads nothing from a request that did not come through
// Middleware, and TokenInfo builds nothing for a context without a caller.
func TestPrincipalOutsideMiddleware(t *testing.T) {
	t.Parallel()
	if _, ok := Principal(nil); ok {
		t.Error("Principal(nil) reported a principal")
	}
	if _, ok := Principal(&mcp.CallToolRequest{}); ok {
		t.Error("Principal of a bare request reported a principal")
	}
	if _, ok := TokenInfo(context.Background()); ok {
		t.Error("TokenInfo of a bare context reported one")
	}
}
