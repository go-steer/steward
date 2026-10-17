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

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-steer/steward/seal"
)

// client is an OAuth client resolved from its client_id.
type client struct {
	ID           string
	Name         string
	RedirectURIs []string
	// Secret is set only for pre-registered confidential clients.
	Secret string
	// static is set for a pre-registered client.
	static *StaticClient
}

// StaticClient is a pre-registered client, for example from a clients
// file (LoadStaticClients).
type StaticClient struct {
	// ID is the client_id: a plain string, not a URL and not an envelope.
	ID string `json:"client_id"`
	// Secret makes the client confidential: it must authenticate at the
	// token endpoint (client_secret_basic or client_secret_post).
	Secret string `json:"client_secret,omitempty"`
	// Name is shown in logs.
	Name string `json:"client_name,omitempty"`
	// RedirectURIs are where the client may receive codes. A user-facing
	// client needs at least one.
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// ClientCredentials makes this a client-credentials client (RFC 6749
	// section 4.4): a workload with no user, which gets access tokens with
	// its secret alone. It needs a secret and no redirect URIs, so it
	// cannot sign users in.
	ClientCredentials bool `json:"client_credentials,omitempty"`
	// ServiceAccount, for a client-credentials client, is a Google service
	// account whose access token (from Config.ServiceTokens) is sealed into
	// the client's access tokens, so the resource can act as that account.
	// Setting it implies ClientCredentials. Empty: the workload's tokens
	// carry no Google token, and the resource acts as itself.
	ServiceAccount string `json:"service_account,omitempty"`
	// Scopes limits the service scopes this client may be granted. Empty
	// means any of Config.Scopes.
	Scopes []string `json:"scopes,omitempty"`
}

func (c StaticClient) clientCredentials() bool { return c.ClientCredentials || c.ServiceAccount != "" }

// LoadStaticClients reads a JSON array of StaticClient.
func LoadStaticClients(path string) ([]StaticClient, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the clients file
	if err != nil {
		return nil, fmt.Errorf("authserver: read clients: %w", err)
	}
	var cs []StaticClient
	if err := json.Unmarshal(b, &cs); err != nil {
		return nil, fmt.Errorf("authserver: parse clients %s: %w", path, err)
	}
	for _, c := range cs {
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("authserver: clients %s: %w", path, err)
		}
	}
	return cs, nil
}

func (c StaticClient) validate() error {
	switch {
	case c.ID == "" || seal.IsSealed(c.ID) || strings.HasPrefix(c.ID, "https://") || strings.ContainsAny(c.ID, " \t\r\n"):
		return fmt.Errorf("client %q needs a plain client_id", c.ID)
	case !c.clientCredentials() && len(c.RedirectURIs) == 0:
		return fmt.Errorf("client %q needs redirect_uris (or client_credentials, for a workload)", c.ID)
	case c.clientCredentials() && (c.Secret == "" || len(c.RedirectURIs) > 0):
		return fmt.Errorf("client %q uses client credentials, so it needs a client_secret and no redirect_uris", c.ID)
	case c.ServiceAccount != "" && !strings.Contains(c.ServiceAccount, "@"):
		return fmt.Errorf("client %q: service_account %q isn't an email", c.ID, c.ServiceAccount)
	}
	for _, r := range c.RedirectURIs {
		if !validRedirectURI(r) {
			return fmt.Errorf("client %q: redirect URI %q isn't allowed (https, loopback http, or a private-use scheme)", c.ID, r)
		}
	}
	return nil
}

// dcrClient is a dynamically registered client, sealed into its own
// client_id so nothing is stored.
type dcrClient struct {
	RedirectURIs []string `json:"r"`
	Name         string   `json:"n,omitempty"`
	IssuedAt     int64    `json:"t"`
}

var errUnknownClient = errors.New("unknown client")

// resolveClient finds the client a client_id names: pre-registered, a
// sealed DCR registration, or a CIMD URL.
func (s *Server) resolveClient(ctx context.Context, id string) (*client, error) {
	if c, ok := s.static[id]; ok {
		return &client{ID: c.ID, Name: c.Name, RedirectURIs: c.RedirectURIs, Secret: c.Secret, static: &c}, nil
	}
	if !s.cfg.OpenRegistration {
		return nil, errUnknownClient
	}
	if seal.IsSealed(id) {
		var d dcrClient
		if err := s.open(ctx, purposeClient, id, &d); err != nil {
			if errors.Is(err, errKeys) {
				return nil, err
			}
			return nil, errUnknownClient
		}
		return &client{ID: id, Name: d.Name, RedirectURIs: d.RedirectURIs}, nil
	}
	if strings.HasPrefix(id, "https://") {
		return s.cimd.fetch(ctx, id)
	}
	return nil, errUnknownClient
}

// allowedScopes is what c may be granted.
func (s *Server) allowedScopes(c *client) []string {
	if c.static != nil && len(c.static.Scopes) > 0 {
		return c.static.Scopes
	}
	return s.scopes
}

// redirectAllowed reports whether uri is one of c's redirect URIs. The
// match is exact, except that a loopback redirect (RFC 8252 section 7.3)
// may use any port.
func redirectAllowed(c *client, uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	got, err := url.Parse(uri)
	if err != nil || got.Scheme != "http" || !isLoopbackHost(got.Hostname()) {
		return false
	}
	for _, r := range c.RedirectURIs {
		want, err := url.Parse(r)
		if err != nil || want.Scheme != "http" || !isLoopbackHost(want.Hostname()) {
			continue
		}
		if want.Hostname() == got.Hostname() && want.Path == got.Path && want.RawQuery == got.RawQuery && got.User == nil && got.Fragment == "" {
			return true
		}
	}
	return false
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

// validRedirectURI is the registration-time check: an absolute URI with no
// fragment, https unless it is a loopback or a private-use scheme (RFC 8252
// section 7.1, for example com.example.app:/cb).
func validRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		return isLoopbackHost(u.Hostname())
	case "javascript", "data", "file", "vbscript":
		return false
	}
	return strings.Contains(u.Scheme, ".")
}

// cimdFetcher fetches Client ID Metadata Documents: the client_id is an
// https URL serving the client's metadata. The URL is client-supplied, so
// the fetch only reaches public IPs, follows no redirects, and is size- and
// time-capped.
type cimdFetcher struct {
	hc *http.Client

	mu    sync.Mutex
	cache map[string]cimdEntry
}

type cimdEntry struct {
	c       *client
	expires time.Time
}

const (
	cimdMaxBytes   = 64 << 10
	cimdDefaultTTL = 5 * time.Minute
	cimdMaxTTL     = time.Hour
	cimdMaxCached  = 1024
)

func newCIMDFetcher(hc *http.Client) *cimdFetcher {
	if hc == nil {
		hc = SSRFSafeClient(5 * time.Second)
	}
	return &cimdFetcher{hc: hc, cache: map[string]cimdEntry{}}
}

func (f *cimdFetcher) fetch(ctx context.Context, id string) (*client, error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return nil, errors.New("client ID metadata document URL must be an https URL with a path")
	}
	f.mu.Lock()
	e, ok := f.cache[id]
	f.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.c, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil) //nolint:gosec // G704: a client-supplied URL, fetched with SSRFSafeClient
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.hc.Do(req) //nolint:gosec // G704: a client-supplied URL, fetched with SSRFSafeClient
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch client metadata: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	if len(b) > cimdMaxBytes {
		return nil, errors.New("client metadata document is too large")
	}
	var doc struct {
		ClientID                string   `json:"client_id"`
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, errors.New("parse client metadata: not JSON")
	}
	switch {
	case doc.ClientID != id:
		return nil, errors.New("client metadata client_id doesn't match its URL")
	case len(doc.RedirectURIs) == 0:
		return nil, errors.New("client metadata has no redirect_uris")
	case doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none":
		return nil, fmt.Errorf("client metadata token_endpoint_auth_method %q isn't supported (only none)", doc.TokenEndpointAuthMethod)
	}
	for _, r := range doc.RedirectURIs {
		if !validRedirectURI(r) {
			return nil, fmt.Errorf("client metadata redirect URI %q isn't allowed", r)
		}
	}
	name := doc.ClientName
	if len(name) > 100 {
		name = name[:100]
	}
	c := &client{ID: id, Name: name, RedirectURIs: doc.RedirectURIs}
	if ttl := cacheTTL(resp.Header.Get("Cache-Control")); ttl > 0 {
		now := time.Now()
		f.mu.Lock()
		if len(f.cache) >= cimdMaxCached {
			for k, e := range f.cache {
				if !now.Before(e.expires) {
					delete(f.cache, k)
				}
			}
			if len(f.cache) >= cimdMaxCached {
				clear(f.cache)
			}
		}
		f.cache[id] = cimdEntry{c: c, expires: now.Add(ttl)}
		f.mu.Unlock()
	}
	return c, nil
}

// cacheTTL reads max-age from Cache-Control, capped; no-store and no-cache
// mean do not cache.
func cacheTTL(cc string) time.Duration {
	ttl := cimdDefaultTTL
	for _, d := range strings.Split(cc, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache":
			return 0
		case strings.HasPrefix(d, "max-age="):
			n, err := strconv.Atoi(strings.TrimPrefix(d, "max-age="))
			if err == nil && n >= 0 {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	return min(ttl, cimdMaxTTL)
}

// SSRFSafeClient is an HTTP client for client-supplied URLs: it dials only
// public unicast addresses (checked on the resolved IP, so DNS cannot
// smuggle in a private one), uses no proxy, and follows no redirects.
func SSRFSafeClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !isPublic(ip) {
				return fmt.Errorf("refusing to dial non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects aren't followed")
		},
	}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}
