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

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/httpauth"
)

const clientID = "123-abc.apps.googleusercontent.com"

var expiry = time.Now().Add(time.Hour).Truncate(time.Second)

// people are the tokens fakeGoogle knows: token → sub, email.
var people = map[string][2]string{
	"dana-token":  {"1001", "dana@cymbal.example"},
	"dana-token2": {"1001", "dana@cymbal.example"}, // a refreshed token, same person
	"lee-token":   {"1002", "lee@cymbal.example"},
}

func fakeGoogle(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.FormValue("access_token")
		if r.URL.Path == "/userinfo" {
			tok = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		p, ok := people[tok]
		if !ok {
			http.Error(w, "{}", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/userinfo" {
			_ = json.NewEncoder(w).Encode(map[string]string{"email": p[1], "hd": "cymbal.example"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"aud": clientID, "azp": clientID, "sub": p[0], "email": p[1], "email_verified": "true",
			"exp": strconv.FormatInt(expiry.Unix(), 10), "scope": "openid " + googletoken.EmailScope,
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func protector(t *testing.T) *httpauth.Protector {
	t.Helper()
	base := fakeGoogle(t)
	v, err := googletoken.New(googletoken.Config{ClientIDs: []string{clientID},
		TokenInfoURL: base + "/tokeninfo", UserInfoURL: base + "/userinfo"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := allow.Parse([]string{"@cymbal.example"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := googletoken.NewAuthenticator(v, list)
	if err != nil {
		t.Fatal(err)
	}
	p, err := httpauth.New(httpauth.Options{Authenticator: a, Resource: "http://127.0.0.1/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// post sends one JSON-RPC message as a streamable-HTTP client would.
func post(t *testing.T, h http.Handler, token, session, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer "+token)
	if session != "" {
		r.Header.Set("Mcp-Session-Id", session)
		r.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

// TestSessionBoundToCaller is the reason this package exists: with a real
// SDK streamable handler behind Middleware, a session opened by one person
// cannot be used by another, even though both hold good, admitted tokens.
func TestSessionBoundToCaller(t *testing.T) {
	t.Parallel()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	h := Middleware(protector(t))(sdk)

	rec := post(t, h, "dana-token", "", initialize)
	session := rec.Header().Get("Mcp-Session-Id")
	if rec.Code != http.StatusOK || session == "" {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("initialize as dana: %d, session %q: %s", rec.Code, session, body)
	}

	const ping = `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	if rec := post(t, h, "lee-token", session, ping); rec.Code != http.StatusForbidden {
		t.Errorf("lee using dana's session: %d, want 403", rec.Code)
	}
	if rec := post(t, h, "dana-token", session, ping); rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Errorf("dana using her own session: %d: %s", rec.Code, body)
	}
	if rec := post(t, h, "unknown", session, ping); rec.Code != http.StatusUnauthorized {
		t.Errorf("an unknown token: %d, want 401", rec.Code)
	}
}

// TestToolSeesCurrentToken is the regression test for the adversarial
// review's high finding: in a stateful session the SDK runs every call
// with the initialize request's context, so a context accessor would hand
// a tool the token from initialize. TokenSource(req) must return the token
// that came with the call, and the raw Authorization header must not reach
// the tool.
func TestToolSeesCurrentToken(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		seen     string
		seenID   googletoken.Identity
		ctxToken string
		header   string
	)
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami"}, func(ctx context.Context, req *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		mu.Lock()
		defer mu.Unlock()
		if ts, ok := TokenSource(req); ok {
			if tok, err := ts.Token(); err == nil {
				seen = tok.AccessToken
			}
		}
		seenID, _ = Identity(req)
		// What the context accessor would have said: the stale token.
		if ts, ok := httpauth.TokenSourceFromContext(ctx); ok {
			if tok, err := ts.Token(); err == nil {
				ctxToken = tok.AccessToken
			}
		}
		header = req.Extra.Header.Get("Authorization")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
	})
	sdk := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	h := Middleware(protector(t))(sdk)

	rec := post(t, h, "dana-token", "", initialize)
	session := rec.Header().Get("Mcp-Session-Id")
	if rec.Code != http.StatusOK || session == "" {
		t.Fatalf("initialize: %d", rec.Code)
	}
	post(t, h, "dana-token", session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	rec = post(t, h, "dana-token2", session, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("tools/call: %d: %s", rec.Code, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen != "dana-token2" {
		t.Errorf("TokenSource(req) gave %q, want the call's own token %q", seen, "dana-token2")
	}
	if seenID.Email != "dana@cymbal.example" {
		t.Errorf("Identity(req) = %+v", seenID)
	}
	if header != "" {
		t.Errorf("the tool saw the raw Authorization header %q", header)
	}
	// Documents why TokenSource(req) exists: the context still carries
	// the session's first token.
	switch ctxToken {
	case "dana-token":
		// The SDK behavior this package works around.
	case "dana-token2":
		t.Log("the SDK now passes per-request context to calls; httpauth's warning can be relaxed")
	default:
		t.Errorf("the context carried token %q, want one of the session's", ctxToken)
	}
}

func TestAccessorsOutsideMiddleware(t *testing.T) {
	t.Parallel()
	for _, req := range []mcp.Request{nil, &mcp.CallToolRequest{}, &mcp.CallToolRequest{Extra: &mcp.RequestExtra{}}} {
		if _, ok := TokenSource(req); ok {
			t.Errorf("TokenSource(%#v) found a token", req)
		}
		if _, ok := Identity(req); ok {
			t.Errorf("Identity(%#v) found an identity", req)
		}
	}
}

func TestTokenInfo(t *testing.T) {
	t.Parallel()
	p := protector(t)
	var got *auth.TokenInfo
	h := Middleware(p)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = auth.TokenInfoFromContext(r.Context())
	}))
	if rec := post(t, h, "dana-token", "", "{}"); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got == nil || got.UserID != "1001" || !got.Expiration.Equal(expiry) ||
		got.Extra[ExtraEmail] != "dana@cymbal.example" || got.Extra[ExtraHD] != "cymbal.example" || len(got.Scopes) != 2 {
		t.Errorf("TokenInfo = %+v", got)
	}

	// Outside a protected request there is nothing to convert, and the
	// verifier refuses rather than invent a user.
	if _, ok := TokenInfo(context.Background()); ok {
		t.Error("TokenInfo found an identity outside a protected request")
	}
	if _, err := fromProtector(context.Background(), "x", httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Error("the verifier accepted a request that did not pass a Protector")
	}
}

// TestUserIDNeverEmpty: an empty UserID turns the SDK's session binding
// off, so a missing sub falls back to the email.
func TestUserIDNeverEmpty(t *testing.T) {
	t.Parallel()
	if got := tokenInfoFor(googletoken.Identity{Email: "dana@cymbal.example"}); got.UserID != "dana@cymbal.example" {
		t.Errorf("TokenInfo without sub: UserID %q, want the email", got.UserID)
	}
	if got := tokenInfoFor(googletoken.Identity{Subject: "1001", Email: "dana@cymbal.example"}); got.UserID != "1001" {
		t.Errorf("TokenInfo with sub: UserID %q, want the sub", got.UserID)
	}
}
