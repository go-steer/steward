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

// Package httpauth protects an HTTP resource and hands each request the
// caller's own Google token.
//
// A Protector accepts two kinds of bearer token, either or both:
//
//   - Google access tokens a client holds for the person (Path A, for
//     example from Gemini Enterprise), verified by a
//     googletoken.Authenticator.
//   - steward's own access tokens (Path B), issued by an
//     authserver.Server the service mounts, which carry the person's
//     Google access token sealed inside, or name a workload that signed in
//     with client credentials.
//
// A request is routed by its token's shape (steward's tokens start with
// seal.Prefix; a Google token never does) to one of two purser
// httpmw.CallerMiddleware instances, each built with Enforce and no
// Fallback around its authenticator. A request with a good token reaches
// the handler as a purser.Caller; anything else is a 401 whose challenge
// names this resource's RFC 9728 metadata. Behind it, a second layer
// attaches, for a person, the Google token as an oauth2.TokenSource
// (TokenSourceFromContext) and their googletoken.Identity
// (IdentityFromContext), the same on both paths, so the handler can call
// Google APIs and GKE clusters as that person; and, for a Path B token,
// the authserver.Principal (PrincipalFromContext), which is all a workload
// has.
//
// The Protector also serves the RFC 9728 Protected Resource Metadata
// document, naming the authorization server a client that is not
// preconfigured should sign in with: the steward authorization server when
// there is one, else Google.
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
	"slices"
	"strings"

	"golang.org/x/oauth2"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/httpmw"

	"github.com/go-steer/steward/authserver"
	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/seal"
)

// WellKnownPrefix is where RFC 9728 places protected resource metadata:
// the resource's path is appended to it.
const WellKnownPrefix = "/.well-known/oauth-protected-resource"

// Options configures a Protector.
type Options struct {
	// Authenticator verifies and admits Google access tokens (Path A).
	// At least one of Authenticator and AuthServer is required.
	Authenticator *googletoken.Authenticator

	// AuthServer verifies steward's own access tokens (Path B). Its
	// Resource must equal Resource. With an AuthServer, the metadata names
	// it as the authorization server. Its allow-list (Config.Admit) and the
	// Authenticator's are separate: give them the same entries, so the same
	// people get in on either path.
	AuthServer *authserver.Server

	// Resource is the protected resource's absolute URL, exactly as clients
	// reach it, for example "https://lookout.example.com/mcp". It is the
	// "resource" in the metadata, and its path places the metadata
	// document. https is required, except for a loopback host. Required.
	Resource string

	// Scopes are advertised as scopes_supported in the metadata and in the
	// challenge: the scopes a client should request. With an AuthServer
	// they must be among its scopes, and empty means its scopes in the
	// metadata and its DefaultScopes in the challenge (MCP clients request
	// what the challenge names, so configure the AuthServer's
	// DefaultScopes to have them ask for less). For Path A alone they are
	// Google scopes, such as "openid", "email" and
	// "https://www.googleapis.com/auth/cloud-platform". They are advice to
	// the client; RequiredScopes and the Authenticator's Verifier are what
	// enforce scopes.
	Scopes []string

	// RequiredScopes are service scopes every steward access token must
	// carry. A token without one is refused with 403 and
	// error="insufficient_scope", which starts a client's step-up flow.
	// Google access tokens (Path A) carry no service scopes and are not
	// checked against these. Each must be one of the AuthServer's scopes.
	RequiredScopes []string

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
	as          *authserver.Server
	caller      *httpmw.CallerMiddleware // Google tokens; nil without an Authenticator
	asCaller    *httpmw.CallerMiddleware // steward tokens; nil without an AuthServer
	required    []string
	resource    string
	metadataURL string
	metadata    []byte
	challenge   string
	stepUp      string
}

var _ httpmw.Gate = (*Protector)(nil)

// New builds a Protector from opts.
func New(opts Options) (*Protector, error) {
	if opts.Authenticator == nil && opts.AuthServer == nil {
		return nil, errors.New("httpauth: New: no Authenticator and no AuthServer: every request would be refused")
	}
	// scopes are advertised in the metadata; asked are what the challenge
	// tells a client to request (MCP clients request what it names).
	scopes, asked := opts.Scopes, opts.Scopes
	if opts.AuthServer != nil {
		if len(opts.Scopes) == 0 {
			scopes, asked = opts.AuthServer.Scopes(), opts.AuthServer.DefaultScopes()
		}
		for _, s := range opts.Scopes {
			if !slices.Contains(opts.AuthServer.Scopes(), s) {
				return nil, fmt.Errorf("httpauth: New: Scopes %q is not one of the AuthServer's scopes, which the metadata names as the place to sign in", s)
			}
		}
	}
	for _, s := range append(slices.Clone(scopes), opts.RequiredScopes...) {
		if !scopeToken(s) {
			return nil, fmt.Errorf("httpauth: New: scope %q is not an RFC 6749 scope token (printable ASCII, no space, quote or backslash)", s)
		}
	}
	if len(opts.RequiredScopes) > 0 {
		if opts.AuthServer == nil {
			return nil, errors.New("httpauth: New: RequiredScopes are service scopes, so they need an AuthServer")
		}
		for _, s := range opts.RequiredScopes {
			if !slices.Contains(opts.AuthServer.Scopes(), s) {
				return nil, fmt.Errorf("httpauth: New: RequiredScopes %q is not one of the AuthServer's scopes", s)
			}
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
	case opts.AuthServer != nil && opts.AuthServer.Resource() != opts.Resource:
		return nil, fmt.Errorf("httpauth: New: Resource %q is not the AuthServer's resource %q: its tokens would all be refused", opts.Resource, opts.AuthServer.Resource())
	}

	// RFC 9728 §3.1: the well-known path goes between the host and the
	// resource's path, so https://h/mcp is described at
	// https://h/.well-known/oauth-protected-resource/mcp.
	meta := *u
	meta.Path = WellKnownPrefix + strings.TrimSuffix(u.Path, "/")
	meta.RawPath = ""

	issuer := googletoken.Issuer
	if opts.AuthServer != nil {
		issuer = opts.AuthServer.Issuer()
	}
	doc := map[string]any{
		"resource":                 opts.Resource,
		"authorization_servers":    []string{issuer},
		"bearer_methods_supported": []string{"header"},
	}
	if len(scopes) > 0 {
		doc["scopes_supported"] = scopes
	}
	if opts.ResourceName != "" {
		doc["resource_name"] = opts.ResourceName
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("httpauth: New: metadata: %v", err)
	}

	challenge := fmt.Sprintf("Bearer resource_metadata=%q", meta.String())
	if len(asked) > 0 {
		challenge += fmt.Sprintf(", scope=%q", strings.Join(asked, " "))
	}
	p := &Protector{
		auth:        opts.Authenticator,
		as:          opts.AuthServer,
		required:    slices.Clone(opts.RequiredScopes),
		resource:    opts.Resource,
		metadataURL: meta.String(),
		metadata:    body,
		challenge:   challenge,
	}
	if len(p.required) > 0 {
		p.stepUp = fmt.Sprintf("Bearer error=\"insufficient_scope\", scope=%q, resource_metadata=%q", strings.Join(p.required, " "), meta.String())
	}
	if opts.Authenticator != nil {
		if p.caller, err = httpmw.NewCaller(httpmw.CallerOptions{
			Authenticator: opts.Authenticator,
			Enforce:       true, // never a Fallback: see googletoken.Authenticator
			Challenge:     challenge,
			Logger:        opts.Logger,
		}); err != nil {
			return nil, fmt.Errorf("httpauth: New: %w", err)
		}
	}
	if opts.AuthServer != nil {
		if p.asCaller, err = httpmw.NewCaller(httpmw.CallerOptions{
			Authenticator: opts.AuthServer.Authenticator(),
			Enforce:       true,
			Challenge:     challenge,
			Logger:        opts.Logger,
		}); err != nil {
			return nil, fmt.Errorf("httpauth: New: %w", err)
		}
	}
	return p, nil
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
		var google, steward http.Handler
		if p.caller != nil {
			google = p.caller.Middleware()(p.attach(next))
		}
		if p.asCaller != nil {
			steward = p.asCaller.Middleware()(p.attachAS(next))
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Routing by shape decides only which verifier looks at the
			// token; each one still verifies everything, and refuses what
			// it does not recognize.
			token, _ := googletoken.BearerToken(r)
			sealed := seal.IsSealed(token)
			switch {
			case steward != nil && (sealed || google == nil):
				steward.ServeHTTP(w, r)
			case sealed:
				// A steward token at a resource that takes only Google's:
				// refused here, never sent to Google's tokeninfo, since the
				// token never leaves the request.
				p.unauthorized(w)
			default:
				google.ServeHTTP(w, r)
			}
		})
	}
}

// attach adds the verified token's source and Identity to the context. It
// runs only behind the Google caller middleware, and only acts on a
// request that middleware verified as Google's, so it never trusts a
// header purser did not check.
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
			unavailable(w)
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

// attachAS is attach for steward's own tokens: it runs only behind the
// AuthServer's caller middleware, and acts only on a request that
// middleware verified. It enforces RequiredScopes, and attaches the
// Principal; for a person, also the Google token source and Identity, as
// on Path A.
func (p *Protector) attachAS(next http.Handler) http.Handler {
	authn := p.as.Authenticator()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if src, _ := purser.AuthSourceFromContext(r.Context()); src != authn.Source() {
			p.unauthorized(w)
			return
		}
		pr, err := authn.Verify(r)
		if errors.Is(err, authserver.ErrUnavailable) {
			unavailable(w)
			return
		}
		if err != nil {
			p.unauthorized(w)
			return
		}
		for _, s := range p.required {
			if !pr.HasScope(s) {
				w.Header().Set("WWW-Authenticate", p.stepUp)
				http.Error(w, "insufficient scope", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), principalKey{}, pr)
		if !pr.Workload {
			// A person always has their Google token: one without would
			// look like a workload downstream and run as the service, so it
			// is refused instead. (authserver.Verify refuses such a token
			// already; this keeps the default closed.)
			ts, ok := pr.TokenSource()
			var tok *oauth2.Token
			if ok {
				tok, _ = ts.Token()
			}
			if tok == nil {
				p.unauthorized(w)
				return
			}
			ctx = context.WithValue(ctx, tokenSourceKey{}, ts)
			ctx = context.WithValue(ctx, identityKey{}, googletoken.Identity{
				Subject: pr.Subject, Email: pr.Email, HD: pr.HD, Scopes: pr.GoogleScopes, Expiry: tok.Expiry,
			})
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	http.Error(w, "the token could not be verified right now", http.StatusServiceUnavailable)
}

func (p *Protector) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", p.challenge)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// GatesCredentials implements httpmw.Gate: every request that reaches the
// protected handler presented a verified token. It is what purser's
// CheckBind asks before a surface binds a non-loopback address.
func (p *Protector) GatesCredentials() bool {
	return p != nil && (p.caller != nil || p.asCaller != nil) &&
		(p.caller == nil || p.caller.GatesCredentials()) &&
		(p.asCaller == nil || p.asCaller.GatesCredentials())
}

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
// token. Browser-based clients may read it cross-origin.
func (p *Protector) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.as != nil {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "MCP-Protocol-Version")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
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
	principalKey   struct{}
)

// TokenSourceFromContext returns the caller's own Google token as an
// oauth2.TokenSource, for a request from a person that passed a Protector:
// the token they presented (Path A), or the one sealed in steward's token
// (Path B). It does not refresh: the client holds the refresh token and
// sends a fresh access token on a later request. ok is false outside a
// protected request, and for a workload, which has no person's token (see
// PrincipalFromContext).
//
// Not for tool handlers in a stateful MCP session: the MCP SDK runs every
// call with the context of the session's first request, so this would
// return the token from initialize. Use mcpauth.TokenSource(req) there.
func TokenSourceFromContext(ctx context.Context) (ts oauth2.TokenSource, ok bool) {
	ts, ok = ctx.Value(tokenSourceKey{}).(oauth2.TokenSource)
	return ts, ok
}

// IdentityFromContext returns the verified googletoken.Identity of the
// person behind a request that passed a Protector, on either path. ok is
// false outside a protected request, and for a workload.
func IdentityFromContext(ctx context.Context) (id googletoken.Identity, ok bool) {
	id, ok = ctx.Value(identityKey{}).(googletoken.Identity)
	return id, ok
}

// PrincipalFromContext returns the authserver.Principal behind a request
// that passed a Protector with a steward access token (Path B), person or
// workload. ok is false outside a protected request and for a Google token
// (Path A).
func PrincipalFromContext(ctx context.Context) (p authserver.Principal, ok bool) {
	p, ok = ctx.Value(principalKey{}).(authserver.Principal)
	return p, ok
}
