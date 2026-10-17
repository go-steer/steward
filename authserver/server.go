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

// Package authserver is steward's OAuth 2.1 authorization server (Path B):
// a service mounts it at an issuer URL in front of Google sign-in, so MCP
// clients that expect to discover an authorization server and register
// with it (Claude Code, gemini-cli, IDEs) can sign people in, and the
// service then acts as each person with their own Google access token.
//
// Clients register as pre-registered (static) clients, by Dynamic Client
// Registration (RFC 7591) or by a Client ID Metadata Document, then run
// the authorization code flow with PKCE (S256 only) and a resource
// indicator (RFC 8707) naming the protected resource. The user signs in
// with Google; the allow-list is checked; a Custody backend holds the
// user's Google grant (the Agent Identity credential vault, or the Google
// refresh token sealed inside steward's own refresh token). The client
// gets steward's own tokens, bound to the resource, with the user's
// Google access token sealed inside the access token. Pre-registered
// confidential clients may instead use the client-credentials grant, for
// workloads with no user.
//
// Everything handed out is sealed (package seal), so nothing is stored
// and any replica holding the keyring verifies any token. The one piece
// of state is a ReplayCache for spent authorization codes and rotated
// refresh tokens; the default is in memory, per replica.
//
// The protected resource verifies access tokens with Server.Verify, or
// with the purser authenticator from Server.Authenticator; httpauth's
// Protector does that for a resource that accepts both these tokens and
// Google's own (Path A). Nothing here imports the MCP SDK.
//
// Taken from gke-demos/kode-gopher internal/oauth at
// 8b53617b7d4d0b08b158de64ab7416dc84a1281e (docs/design-in-cluster.md
// section 3), generalized: service-defined scopes instead of one fixed
// scope, a configurable resource and Google scopes, an optional service
// account for client-credentials clients, steward's allow.Admitter, a
// pluggable replay cache and key provider, and slog. kode-gopher will not
// import steward; port fixes by hand in both directions.
package authserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-steer/steward/allow"
	"github.com/go-steer/steward/seal"
)

// Lifetimes.
const (
	// AuthRequestTTL bounds a sign-in, from the authorization request to
	// Google's callback (and the vault's consent leg).
	AuthRequestTTL = 10 * time.Minute
	// CodeTTL is an authorization code's life.
	CodeTTL = time.Minute
	// AccessTTL is an access token's longest life; it is shorter when the
	// Google token inside it expires sooner.
	AccessTTL = 15 * time.Minute
	// RefreshTTL is a refresh token's life, renewed by every refresh.
	RefreshTTL = 30 * 24 * time.Hour
)

// Envelope purposes, bound into each seal together with the issuer.
const (
	purposeClient  = "client"
	purposeConsent = "consent"
	purposeState   = "state"
	purposePending = "pending"
	purposeCode    = "code"
	purposeAccess  = "access"
	purposeRefresh = "refresh"
)

// Paths below the issuer.
const (
	PathAuthorize       = "/authorize"
	PathCallback        = "/callback"
	PathConsentContinue = "/consent/continue"
	PathToken           = "/token"
	PathRegister        = "/register"
)

// Well-known metadata documents.
const (
	wellKnownAS   = "/.well-known/oauth-authorization-server"
	wellKnownOIDC = "/.well-known/openid-configuration"
)

// Config is one deployment's authorization server. Nothing about the
// Google side is built in.
type Config struct {
	// Issuer is the server's public base URL, exactly as clients reach it,
	// for example "https://svc.example.com" (a path is allowed). https is
	// required, except for a loopback host. The endpoints sit below it:
	// Issuer+PathAuthorize, and so on. Required.
	Issuer string

	// Resource is the protected resource every token is bound to (RFC
	// 8707), for example "https://svc.example.com/mcp". A client may name
	// it in the resource parameter, or leave it out. Required.
	Resource string

	// Scopes are the service's own scopes, for example "svc:read" and
	// "svc:write". A client is granted the ones it asks for that exist (and
	// that a static client is allowed), others being dropped as RFC 6749
	// section 3.3 allows. At least one is required.
	Scopes []string

	// DefaultScopes are granted when a client asks for none of Scopes.
	// Empty means all of Scopes.
	DefaultScopes []string

	// Google is the service's own OAuth client at Google. Its redirect
	// URIs must include CallbackURL (and, under vault custody, the auth
	// provider's oauthcallback URL). Required.
	Google GoogleClient

	// GoogleScopes are the Google scopes held for each user beyond openid
	// and userinfo.email, spelled as Google's canonical URLs (the vault
	// matches stored grants by exact spelling). Empty means
	// ScopeCloudPlatform.
	GoogleScopes []string

	// Custody holds users' Google grants: *VaultCustody or SealedCustody.
	// Required.
	Custody Custody

	// Admit decides who may sign in, and is asked again at every refresh.
	// Required.
	Admit *allow.Admitter

	// Keys seals every token, code, sign-in state and DCR client ID.
	// Required.
	Keys seal.KeyProvider

	// Clients are pre-registered. They skip the consent page.
	Clients []StaticClient

	// ServiceTokens mints Google access tokens for client-credentials
	// clients that name a ServiceAccount. Required if any does.
	ServiceTokens ServiceTokens

	// OpenRegistration accepts DCR and CIMD clients. Off: only Clients.
	OpenRegistration bool

	// Replay remembers spent authorization codes and rotated refresh
	// tokens. Nil means an in-memory cache, which is per replica: with
	// several replicas, a code or a rotated refresh token could be used
	// once on each. Supply a shared one to close that.
	Replay ReplayCache

	// ServiceName names the service on the consent page. Empty means the
	// issuer's host.
	ServiceName string

	// HTTPClient calls Google's token and tokeninfo endpoints. Nil means a
	// client with a 30 s timeout.
	HTTPClient *http.Client

	// CIMDClient fetches Client ID Metadata Documents. Nil means
	// SSRFSafeClient. Tests on loopback replace it.
	CIMDClient *http.Client

	// Logger receives sign-ins, refusals and backend failures (never a
	// token). Nil means slog.Default().
	Logger *slog.Logger
}

// Server is the authorization server. It is immutable after New and safe
// for concurrent use.
type Server struct {
	cfg           Config
	issuer        *url.URL
	scopes        []string
	defaultScopes []string
	google        *upstream
	static        map[string]StaticClient
	// serviceClients: some client may use the client_credentials grant.
	serviceClients bool
	cimd           *cimdFetcher
	used           ReplayCache
	log            *slog.Logger
	now            func() time.Time
}

// New validates cfg and builds a Server.
func New(cfg Config) (*Server, error) {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	iss, err := checkURL("Issuer", cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if _, err := checkURL("Resource", cfg.Resource); err != nil {
		return nil, err
	}
	switch {
	case cfg.Google.ClientID == "" || cfg.Google.ClientSecret == "":
		return nil, errors.New("authserver: New: the Google client ID and secret are required")
	case cfg.Custody == nil:
		return nil, errors.New("authserver: New: a Custody backend is required")
	case cfg.Admit == nil:
		return nil, errors.New("authserver: New: an allow.Admitter is required")
	case cfg.Keys == nil:
		return nil, errors.New("authserver: New: a key provider is required")
	case len(cfg.Scopes) == 0:
		return nil, errors.New("authserver: New: at least one service scope is required")
	}
	scopes, err := checkScopes("Scopes", cfg.Scopes, nil)
	if err != nil {
		return nil, err
	}
	defaults := scopes
	if len(cfg.DefaultScopes) > 0 {
		if defaults, err = checkScopes("DefaultScopes", cfg.DefaultScopes, scopes); err != nil {
			return nil, err
		}
	}
	gscopes, err := checkGoogleScopes(cfg.GoogleScopes)
	if err != nil {
		return nil, err
	}
	cfg.Google.applyDefaults()
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = iss.Host
	}
	s := &Server{
		cfg:           cfg,
		issuer:        iss,
		scopes:        scopes,
		defaultScopes: defaults,
		google:        &upstream{client: &cfg.Google, hc: cfg.HTTPClient, scopes: gscopes},
		static:        map[string]StaticClient{},
		cimd:          newCIMDFetcher(cfg.CIMDClient),
		used:          cfg.Replay,
		log:           cfg.Logger,
		now:           time.Now,
	}
	if s.used == nil {
		s.used = NewMemoryReplayCache()
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	for _, c := range cfg.Clients {
		if _, dup := s.static[c.ID]; dup {
			return nil, fmt.Errorf("authserver: New: duplicate client %q", c.ID)
		}
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("authserver: New: %w", err)
		}
		if _, err := checkScopes("client "+c.ID+" Scopes", c.Scopes, scopes); err != nil {
			return nil, err
		}
		s.static[c.ID] = c
		s.serviceClients = s.serviceClients || c.clientCredentials()
		if c.ServiceAccount != "" && cfg.ServiceTokens == nil {
			return nil, fmt.Errorf("authserver: New: client %q has a service account, so ServiceTokens is required", c.ID)
		}
	}
	return s, nil
}

// checkURL requires an absolute https URL (http only for a loopback host)
// with no query, fragment or userinfo.
func checkURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || raw == "":
		return nil, fmt.Errorf("authserver: New: %s %q is not a URL", field, raw)
	case !u.IsAbs() || u.Host == "":
		return nil, fmt.Errorf("authserver: New: %s %q must be an absolute URL", field, raw)
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())):
		return nil, fmt.Errorf("authserver: New: %s %q must be https (http only for a loopback host)", field, raw)
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.ForceQuery:
		return nil, fmt.Errorf("authserver: New: %s %q must have no query, fragment or userinfo", field, raw)
	}
	return u, nil
}

// checkScopes requires RFC 6749 scope tokens with no duplicates, all in
// within when within is set.
func checkScopes(field string, scopes, within []string) ([]string, error) {
	var out []string
	for _, sc := range scopes {
		if !scopeToken(sc) {
			return nil, fmt.Errorf("authserver: New: %s %q is not an RFC 6749 scope token", field, sc)
		}
		if within != nil && !slices.Contains(within, sc) {
			return nil, fmt.Errorf("authserver: New: %s %q is not one of Scopes", field, sc)
		}
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out, nil
}

// scopeToken reports whether s is an RFC 6749 section 3.3 scope-token.
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

// Issuer is the issuer URL, as configured (no trailing slash).
func (s *Server) Issuer() string { return s.cfg.Issuer }

// Resource is the protected resource tokens are bound to.
func (s *Server) Resource() string { return s.cfg.Resource }

// Scopes are the service's scopes, as configured.
func (s *Server) Scopes() []string { return slices.Clone(s.scopes) }

// CallbackURL is where Google returns the browser after sign-in. Register
// it as a redirect URI of the Google OAuth client.
func (s *Server) CallbackURL() string { return s.cfg.Issuer + PathCallback }

// ContinueURL is where the vault's consent leg returns the browser.
func (s *Server) ContinueURL() string { return s.cfg.Issuer + PathConsentContinue }

// MetadataURL is the RFC 8414 authorization server metadata document's
// URL.
func (s *Server) MetadataURL() string { return s.wellKnown(wellKnownAS) }

// wellKnown places a well-known document for this issuer (RFC 8414
// section 3.1: the well-known path goes between the host and the issuer's
// path).
func (s *Server) wellKnown(doc string) string {
	u := *s.issuer
	u.Path = doc + s.issuer.Path
	u.RawPath = ""
	return u.String()
}

func (s *Server) purpose(p string) string { return s.cfg.Issuer + "#" + p }

// seal seals v for purpose under the current keyring.
func (s *Server) seal(ctx context.Context, purpose string, v any) (string, error) {
	kr, err := s.cfg.Keys.Keyring(ctx)
	if err != nil {
		return "", fmt.Errorf("keyring: %w", err)
	}
	return kr.Seal(s.purpose(purpose), v)
}

// errKeys is the keyring being unavailable, as distinct from an envelope
// that does not open.
var errKeys = errors.New("authserver: the sealing keys are unavailable")

// open opens an envelope sealed for purpose. It returns seal.ErrBadEnvelope
// for an envelope that does not open, or errKeys when there is no keyring
// to try.
func (s *Server) open(ctx context.Context, purpose, env string, v any) error {
	kr, err := s.cfg.Keys.Keyring(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "authserver: no keyring", "err", err)
		return errKeys
	}
	return kr.Open(s.purpose(purpose), env, v)
}

// Paths lists the URL paths the server answers, for a service that routes
// them onto its own mux one by one. Handler and Register cover them all.
func (s *Server) Paths() []string {
	p := s.issuer.Path
	paths := []string{
		wellKnownAS + p,
		p + wellKnownOIDC,
		p + PathAuthorize,
		p + PathCallback,
		p + PathConsentContinue,
		p + PathToken,
	}
	if p != "" {
		paths = append(paths, wellKnownOIDC+p)
	}
	if s.cfg.OpenRegistration {
		paths = append(paths, p+PathRegister)
	}
	return paths
}

// Register mounts the server's endpoints on mux, at the paths the issuer
// implies.
func (s *Server) Register(mux *http.ServeMux) {
	p := s.issuer.Path
	asm := cors(http.HandlerFunc(s.handleServerMetadata))
	mux.Handle(wellKnownAS+p, asm)
	mux.Handle(p+wellKnownOIDC, asm)
	if p != "" {
		mux.Handle(wellKnownOIDC+p, asm)
	}
	mux.HandleFunc("GET "+p+PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("POST "+p+PathAuthorize, s.handleApprove)
	mux.HandleFunc("GET "+p+PathCallback, s.handleCallback)
	mux.HandleFunc("GET "+p+PathConsentContinue, s.handleConsentContinue)
	mux.Handle(p+PathToken, cors(http.HandlerFunc(s.handleToken)))
	if s.cfg.OpenRegistration {
		mux.Handle(p+PathRegister, cors(http.HandlerFunc(s.handleRegister)))
	}
}

// Handler serves every endpoint. Mount it at the root of the issuer's
// host (it matches full paths), or use Register.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

func (s *Server) handleServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	grants := []string{"authorization_code", "refresh_token"}
	if s.serviceClients {
		grants = append(grants, "client_credentials")
	}
	m := map[string]any{
		"issuer":                                         s.cfg.Issuer,
		"authorization_endpoint":                         s.cfg.Issuer + PathAuthorize,
		"token_endpoint":                                 s.cfg.Issuer + PathToken,
		"scopes_supported":                               s.scopes,
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          grants,
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	}
	if s.cfg.OpenRegistration {
		m["registration_endpoint"] = s.cfg.Issuer + PathRegister
		m["client_id_metadata_document_supported"] = true
	}
	writeJSON(w, http.StatusOK, m)
}

// cors lets browser-based clients (MCP Inspector) call the metadata,
// token and registration endpoints. None of them use cookies.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ReplayCache remembers single-use IDs (authorization codes, rotated
// refresh tokens) until they would have expired anyway. Implementations
// must be safe for concurrent use. An error is a cache that could not
// answer; the token endpoint then answers server_error and spends
// nothing.
type ReplayCache interface {
	// Claim records id as used until exp, and reports whether it was
	// unused (or its earlier claim has expired).
	Claim(ctx context.Context, id string, exp time.Time) (bool, error)
	// Release forgets id, for a use that failed for a transient reason,
	// so the client's retry is not refused as a replay.
	Release(ctx context.Context, id string) error
}

// maxMemoryClaims bounds the in-memory replay cache (a claim is about a
// hundred bytes, and only a signed-in user's code or refresh can add
// one). Past it, expired claims are swept; if none have expired, a new
// claim is refused rather than an old one forgotten.
const maxMemoryClaims = 1 << 20

// MemoryReplayCache is the in-memory ReplayCache: per process, and
// forgotten on restart (a refresh token rotated just before a restart
// could be used once more).
type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplayCache returns an empty in-memory ReplayCache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: map[string]time.Time{}, now: time.Now}
}

var _ ReplayCache = (*MemoryReplayCache)(nil)

// errReplayFull is the in-memory cache refusing a claim it has no room
// for: refusing is safe, forgetting a claim is not.
var errReplayFull = errors.New("authserver: replay cache is full")

// Claim implements ReplayCache.
func (c *MemoryReplayCache) Claim(_ context.Context, id string, exp time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.seen[id]; ok && now.Before(e) {
		return false, nil
	}
	if len(c.seen) >= maxMemoryClaims {
		for k, e := range c.seen {
			if !now.Before(e) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= maxMemoryClaims {
			return false, errReplayFull
		}
	}
	c.seen[id] = exp
	return true, nil
}

// Release implements ReplayCache.
func (c *MemoryReplayCache) Release(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, id)
	return nil
}
