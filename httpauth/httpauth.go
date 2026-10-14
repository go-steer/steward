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

// Package httpauth protects an HTTP resource with Google access tokens and
// hands each request the caller's own token.
//
// A Protector wraps a handler in two layers:
//
//  1. purser's httpmw.CallerMiddleware, built with Enforce and no Fallback,
//     around a googletoken.Authenticator. A request with a good token from
//     an admitted person reaches the handler as a purser.Caller with the
//     google-access-token verdict; anything else is a 401 whose challenge
//     names this resource's RFC 9728 metadata.
//  2. A layer that attaches the request's verified token as an
//     oauth2.TokenSource (TokenSourceFromContext) and its googletoken
//     Identity (IdentityFromContext), so the handler can call Google APIs
//     and GKE clusters as that person.
//
// The Protector also serves the RFC 9728 Protected Resource Metadata
// document, naming Google as the authorization server, which is how an
// MCP client that is not preconfigured learns where to sign in.
package httpauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/httpmw"

	"github.com/go-steer/steward/googletoken"
)

// WellKnownPrefix is where RFC 9728 places protected resource metadata:
// the resource's path is appended to it.
const WellKnownPrefix = "/.well-known/oauth-protected-resource"

// Options configures a Protector.
type Options struct {
	// Authenticator verifies and admits each request's token. Required.
	Authenticator *googletoken.Authenticator

	// Resource is the protected resource's absolute URL, exactly as clients
	// reach it, for example "https://lookout.example.com/mcp". It is the
	// "resource" in the metadata, and its path places the metadata
	// document. https is required, except for a loopback host. Required.
	Resource string

	// Scopes are advertised as scopes_supported in the metadata and in the
	// challenge: the Google scopes a client must request, such as
	// "openid", "email" and "https://www.googleapis.com/auth/cloud-platform".
	// They are advice to the client; the Authenticator's Verifier is what
	// enforces scopes.
	Scopes []string

	// ResourceName is a human-readable name for the metadata. Optional.
	ResourceName string

	// Logger receives purser's rejected-proxy-assertion audit line. Nil
	// means slog.Default(). Google outages are logged by the Verifier's
	// own Config.Logger.
	Logger *slog.Logger
}

// Protector protects a resource. It is immutable after New and safe for
// concurrent use.
type Protector struct {
	auth        *googletoken.Authenticator
	caller      *httpmw.CallerMiddleware
	resource    string
	metadataURL string
	metadata    []byte
	challenge   string
}

var _ httpmw.Gate = (*Protector)(nil)

// New builds a Protector from opts.
func New(opts Options) (*Protector, error) {
	if opts.Authenticator == nil {
		return nil, errors.New("httpauth: New: no Authenticator")
	}
	for _, s := range opts.Scopes {
		if !scopeToken(s) {
			return nil, fmt.Errorf("httpauth: New: Scopes %q is not an RFC 6749 scope token (printable ASCII, no space, quote or backslash)", s)
		}
	}
	u, err := url.Parse(opts.Resource)
	switch {
	case err != nil:
		return nil, fmt.Errorf("httpauth: New: Resource %q: %v", opts.Resource, err)
	case !u.IsAbs() || u.Host == "":
		return nil, fmt.Errorf("httpauth: New: Resource %q must be an absolute URL", opts.Resource)
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())):
		return nil, fmt.Errorf("httpauth: New: Resource %q must be https (http only for a loopback host): clients send the user's Google token to it", opts.Resource)
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return nil, fmt.Errorf("httpauth: New: Resource %q must have no query, fragment or userinfo", opts.Resource)
	}

	// RFC 9728 §3.1: the well-known path goes between the host and the
	// resource's path, so https://h/mcp is described at
	// https://h/.well-known/oauth-protected-resource/mcp.
	meta := *u
	meta.Path = WellKnownPrefix + strings.TrimSuffix(u.Path, "/")
	meta.RawPath = ""

	doc := map[string]any{
		"resource":                 opts.Resource,
		"authorization_servers":    []string{googletoken.Issuer},
		"bearer_methods_supported": []string{"header"},
	}
	if len(opts.Scopes) > 0 {
		doc["scopes_supported"] = opts.Scopes
	}
	if opts.ResourceName != "" {
		doc["resource_name"] = opts.ResourceName
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("httpauth: New: metadata: %v", err)
	}

	challenge := fmt.Sprintf("Bearer resource_metadata=%q", meta.String())
	if len(opts.Scopes) > 0 {
		challenge += fmt.Sprintf(", scope=%q", strings.Join(opts.Scopes, " "))
	}
	caller, err := httpmw.NewCaller(httpmw.CallerOptions{
		Authenticator: opts.Authenticator,
		Enforce:       true, // never a Fallback: see googletoken.Authenticator
		Challenge:     challenge,
		Logger:        opts.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("httpauth: New: %w", err)
	}
	return &Protector{
		auth:        opts.Authenticator,
		caller:      caller,
		resource:    opts.Resource,
		metadataURL: meta.String(),
		metadata:    body,
		challenge:   challenge,
	}, nil
}

// scopeToken reports whether s is an RFC 6749 §3.3 scope-token: one or
// more of %x21 / %x23-5B / %x5D-7E. Anything else would garble the
// challenge's quoted scope list.
func scopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Middleware returns the protecting middleware. Mount the protected
// handler behind it, and MetadataHandler at MetadataPath, outside it.
func (p *Protector) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return p.caller.Middleware()(p.attach(next))
	}
}

// attach adds the verified token's source and Identity to the context. It
// runs only behind the caller middleware, and only acts on a request that
// middleware verified as Google's, so it never trusts a header purser did
// not check.
func (p *Protector) attach(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if src, _ := purser.AuthSourceFromContext(r.Context()); src != purser.AuthSourceGoogleAccessToken {
			// Enforce means nothing else reaches here; refuse rather than
			// pass an unverified request through.
			p.unauthorized(w)
			return
		}
		token, _ := googletoken.BearerToken(r)
		// Usually answered from the Verifier's cache: the caller
		// middleware verified this exact token a moment ago. If the entry
		// was evicted in between, this asks Google again, and Google
		// failing is still not Google refusing.
		id, err := p.auth.Verify(r)
		if errors.Is(err, googletoken.ErrUnavailable) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "the token could not be verified right now", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			p.unauthorized(w)
			return
		}
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token, TokenType: "Bearer", Expiry: id.Expiry})
		ctx := context.WithValue(r.Context(), tokenSourceKey{}, ts)
		ctx = context.WithValue(ctx, identityKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Protector) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", p.challenge)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// GatesCredentials implements httpmw.Gate: every request that reaches the
// protected handler presented a verified token. It is what purser's
// CheckBind asks before a surface binds a non-loopback address.
func (p *Protector) GatesCredentials() bool { return p != nil && p.caller.GatesCredentials() }

// MetadataPath is the path at which to mount MetadataHandler.
func (p *Protector) MetadataPath() string {
	u, _ := url.Parse(p.metadataURL)
	return u.Path
}

// MetadataURL is the metadata document's absolute URL, as named in the
// challenge.
func (p *Protector) MetadataURL() string { return p.metadataURL }

// Challenge is the WWW-Authenticate value every 401 carries.
func (p *Protector) Challenge() string { return p.challenge }

// MetadataHandler serves the RFC 9728 Protected Resource Metadata
// document. It needs no authentication: a client reads it before it has a
// token.
func (p *Protector) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		if r.Method == http.MethodGet {
			_, _ = w.Write(p.metadata)
		}
	})
}

type (
	tokenSourceKey struct{}
	identityKey    struct{}
)

// TokenSourceFromContext returns the caller's own Google token as an
// oauth2.TokenSource, for a request that passed a Protector. It does not
// refresh: the client (for example Gemini Enterprise) holds the refresh
// token and sends a fresh access token on a later request. ok is false
// outside a protected request.
//
// Not for tool handlers in a stateful MCP session: the MCP SDK runs every
// call with the context of the session's first request, so this would
// return the token from initialize. Use mcpauth.TokenSource(req) there.
func TokenSourceFromContext(ctx context.Context) (ts oauth2.TokenSource, ok bool) {
	ts, ok = ctx.Value(tokenSourceKey{}).(oauth2.TokenSource)
	return ts, ok
}

// IdentityFromContext returns the verified googletoken.Identity of the
// caller, for a request that passed a Protector. ok is false outside a
// protected request.
func IdentityFromContext(ctx context.Context) (id googletoken.Identity, ok bool) {
	id, ok = ctx.Value(identityKey{}).(googletoken.Identity)
	return id, ok
}
