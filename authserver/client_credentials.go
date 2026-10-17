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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/oauth2"
)

// ServiceTokens mints Google access tokens for service accounts, for
// client-credentials clients that name one (for example by the IAM
// Credentials API's generateAccessToken, as the service's own identity).
type ServiceTokens interface {
	Token(ctx context.Context, serviceAccount string) (*oauth2.Token, error)
}

// modeWorkload marks an access token from the client-credentials grant.
const modeWorkload = "workload"

// clientCredentials is the client-credentials grant (RFC 6749 section
// 4.4) for pre-registered confidential clients. There is no user: the
// token's subject is the client, and it carries the client's service
// account's Google token if it has one. No refresh token is issued
// (section 4.4.3); the client asks again with its secret.
func (s *Server) clientCredentials(r *http.Request, c *client) (map[string]any, *tokenError) {
	ctx := r.Context()
	f := r.PostForm
	if c.static == nil || !c.static.clientCredentials() || c.Secret == "" {
		return nil, &tokenError{Code: "unauthorized_client", Desc: "this client may not use the client_credentials grant"}
	}
	// As for an authorization request: scopes the client may not have are
	// dropped (RFC 6749 section 3.3), since MCP clients ask for everything
	// the resource advertises; the response says what was granted.
	scope, ok := s.grantScopes(strings.Fields(f.Get("scope")), s.allowedScopes(c))
	if !ok {
		return nil, &tokenError{Code: "invalid_scope", Desc: "no scope is available to this client"}
	}
	if res := f.Get("resource"); (res != "" && res != s.cfg.Resource) || len(f["resource"]) > 1 {
		return nil, &tokenError{Code: "invalid_target", Desc: "resource must be " + s.cfg.Resource}
	}
	p := accessPayload{
		Sub: WorkloadSubject(c.ID), ClientID: c.ID, Aud: s.cfg.Resource, Scope: scope,
		Mode: modeWorkload, SA: c.static.ServiceAccount, SH: secretTag(c.Secret),
	}
	if sa := c.static.ServiceAccount; sa != "" {
		tok, err := s.cfg.ServiceTokens.Token(ctx, sa)
		if err != nil || tok == nil || tok.AccessToken == "" {
			s.log.WarnContext(ctx, "authserver: could not mint a token for a client's service account", "client", c.ID, "service_account", sa, "err", err)
			return nil, serverError("couldn't mint a token for the client's service account")
		}
		p.Token, p.TokenExp, p.Email = tok.AccessToken, tok.Expiry.Unix(), sa
		if tok.Expiry.IsZero() {
			p.TokenExp = s.now().Add(AccessTTL + 2*minGoogleTokenLife).Unix()
		}
	}
	now := s.now()
	at, exp, terr := s.sealAccess(ctx, p, now)
	if terr != nil {
		return nil, terr
	}
	return map[string]any{
		"access_token": at,
		"token_type":   "Bearer",
		"expires_in":   int64(exp.Sub(now).Seconds()),
		"scope":        scope,
	}, nil
}

// WorkloadSubject is a client-credentials token's subject: MCP sessions
// bind to it, and it is the workload's purser.Caller identity. The prefix
// keeps it apart from Google subs, which are numeric, and from emails.
func WorkloadSubject(clientID string) string { return "client:" + clientID }

// secretTag is a short digest of a client secret, sealed into a workload's
// tokens (inside the envelope, so it is never visible to the client).
func secretTag(secret string) string {
	sum := sha256.Sum256([]byte("steward-client-secret/" + secret))
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

// workloadCurrent reports whether a client-credentials token still matches
// the configuration: removing the client, rotating its secret, changing its
// service account, or narrowing its scopes revokes its tokens at once.
func (s *Server) workloadCurrent(p *accessPayload) bool {
	c, ok := s.static[p.ClientID]
	if !ok || !c.clientCredentials() || c.ServiceAccount != p.SA || p.Sub != WorkloadSubject(c.ID) ||
		subtle.ConstantTimeCompare([]byte(secretTag(c.Secret)), []byte(p.SH)) != 1 {
		return false
	}
	allowed := s.allowedScopes(&client{static: &c})
	for _, sc := range strings.Fields(p.Scope) {
		if !slices.Contains(allowed, sc) {
			return false
		}
	}
	return true
}
