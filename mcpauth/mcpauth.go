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

// Package mcpauth serves an MCP server built on
// github.com/modelcontextprotocol/go-sdk behind an httpauth.Protector: it
// binds each session to the person who opened it, and gives each call the
// token that came with it.
//
// # Session binding
//
// The SDK's streamable HTTP handler refuses a session ID presented by a
// different user than the one who opened it (403), but only if it finds an
// auth.TokenInfo with a UserID on the request, and only the SDK's own
// auth.RequireBearerToken can put one there. Middleware therefore runs the
// Protector first (which verifies the token and admits the person) and then
// RequireBearerToken with a verifier that checks nothing itself: it
// converts the already-verified caller into a TokenInfo.
//
// # The token inside a tool handler: use TokenSource(req), not the context
//
// In a stateful session the SDK runs every call with a context derived from
// the session's first request (initialize). Context values the Protector
// attaches to a later request, including httpauth.TokenSourceFromContext,
// never reach the handler: it would see the token from initialize, which
// expires within the hour while the client keeps sending fresh ones. What
// the SDK does pass per call is the request's TokenInfo (req.Extra), so
// Middleware puts that request's token source and identity there, and
// TokenSource and Identity read them back. The person cannot change within
// a session (that is what the binding enforces), but the token does.
//
// Middleware also removes the Authorization header before the SDK sees the
// request, so the raw token is not in req.Extra.Header for a handler (or
// anything that logs headers) to pick up.
//
// # Both paths
//
// Behind a Protector with an authserver.Server, a request may carry
// steward's own token (Path B). A person reaches a tool exactly as on Path
// A: TokenSource and Identity, and a session UserID that is their Google
// sub on either path. A workload (client credentials) has no person: its
// UserID is "client:<id>", TokenSource and Identity report false, and
// Principal(req) gives the authserver.Principal, whose own TokenSource is
// its service account's token if it has one. For a Path B token,
// TokenInfo.Scopes are the granted service scopes; for Path A, the Google
// scopes.
//
// It is the only steward package that imports the MCP SDK.
package mcpauth

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/go-steer/steward/authserver"
	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/httpauth"
)

// Extra keys on the TokenInfo. ExtraEmail and ExtraHD are plain strings
// for anything that reads TokenInfo generically; the token source and
// identity are for TokenSource and Identity.
const (
	ExtraEmail = "email"
	ExtraHD    = "hd"

	extraTokenSource = "steward.token-source"
	extraIdentity    = "steward.identity"
	extraPrincipal   = "steward.principal"
)

// Middleware protects an MCP endpoint with p, binds each session to its
// caller, and carries each request's token to its calls. Mount
// p.MetadataHandler at p.MetadataPath separately.
func Middleware(p *httpauth.Protector) func(http.Handler) http.Handler {
	bind := auth.RequireBearerToken(fromProtector, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: p.MetadataURL(),
	})
	protect := p.Middleware()
	return func(next http.Handler) http.Handler {
		return protect(bind(stripAuthorization(next)))
	}
}

// stripAuthorization removes the bearer token from the request the SDK
// sees. Every layer that needs it (purser's middleware, the Protector,
// RequireBearerToken) has already run.
func stripAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.WithContext(r.Context())
		r2.Header = r.Header.Clone()
		r2.Header.Del("Authorization")
		next.ServeHTTP(w, r2)
	})
}

// fromProtector is an auth.TokenVerifier for requests that already passed
// a Protector: it checks nothing itself. A request that did not pass one
// has no Identity and is refused.
func fromProtector(_ context.Context, _ string, r *http.Request) (*auth.TokenInfo, error) {
	ti, ok := TokenInfo(r.Context())
	if !ok {
		return nil, auth.ErrInvalidToken
	}
	return ti, nil
}

// TokenInfo builds the SDK TokenInfo for a request that passed a
// Protector. For a person, UserID is Google's stable account ID (sub) on
// either path, falling back to the email if Google sent none, so that it
// is never empty: an empty UserID would turn the SDK's session binding
// off. For a workload it is authserver.WorkloadSubject of its client.
func TokenInfo(ctx context.Context) (*auth.TokenInfo, bool) {
	p, isPrincipal := httpauth.PrincipalFromContext(ctx)
	id, isPerson := httpauth.IdentityFromContext(ctx)
	var ti *auth.TokenInfo
	switch {
	case isPrincipal:
		// authserver.Verify refuses a token with no subject, so UserID is
		// never empty here either.
		ti = &auth.TokenInfo{
			UserID:     p.Subject,
			Scopes:     p.Scopes,
			Expiration: p.Expiry,
			Extra:      map[string]any{ExtraEmail: p.Email, ExtraHD: p.HD, extraPrincipal: p},
		}
		if isPerson {
			ti.Extra[extraIdentity] = id
		}
	case isPerson:
		ti = tokenInfoFor(id)
	default:
		return nil, false
	}
	if ts, ok := httpauth.TokenSourceFromContext(ctx); ok && isPerson {
		ti.Extra[extraTokenSource] = ts
	}
	return ti, true
}

func tokenInfoFor(id googletoken.Identity) *auth.TokenInfo {
	user := id.Subject
	if user == "" {
		user = id.Email
	}
	return &auth.TokenInfo{
		UserID:     user,
		Scopes:     id.Scopes,
		Expiration: id.Expiry,
		Extra:      map[string]any{ExtraEmail: id.Email, ExtraHD: id.HD, extraIdentity: id},
	}
}

// TokenSource returns the caller's own Google token for this call: the one
// that came with the HTTP request carrying it, not the one the session
// started with. Use it in tool handlers instead of
// httpauth.TokenSourceFromContext. ok is false for a request that did not
// come through Middleware, and for a workload (see Principal).
func TokenSource(req mcp.Request) (oauth2.TokenSource, bool) {
	ti := tokenInfoOf(req)
	if ti == nil {
		return nil, false
	}
	ts, ok := ti.Extra[extraTokenSource].(oauth2.TokenSource)
	return ts, ok
}

// Principal returns the authserver.Principal for this call, when it came
// with a steward access token (Path B): a person or a workload. ok is false
// for a Google token (Path A) and for a request that did not come through
// Middleware.
func Principal(req mcp.Request) (authserver.Principal, bool) {
	ti := tokenInfoOf(req)
	if ti == nil {
		return authserver.Principal{}, false
	}
	p, ok := ti.Extra[extraPrincipal].(authserver.Principal)
	return p, ok
}

// Identity returns the verified identity of the person behind this call,
// on either path. ok is false for a workload and for a request that did
// not come through Middleware.
func Identity(req mcp.Request) (googletoken.Identity, bool) {
	ti := tokenInfoOf(req)
	if ti == nil {
		return googletoken.Identity{}, false
	}
	id, ok := ti.Extra[extraIdentity].(googletoken.Identity)
	return id, ok
}

func tokenInfoOf(req mcp.Request) *auth.TokenInfo {
	if req == nil {
		return nil
	}
	extra := req.GetExtra()
	if extra == nil {
		return nil
	}
	return extra.TokenInfo
}
