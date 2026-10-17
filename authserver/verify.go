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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"

	"github.com/go-steer/steward/googletoken"
	"github.com/go-steer/steward/seal"
)

// ErrInvalidToken is an access token that is not one of this server's, is
// expired, is bound to another resource, or belongs to a workload whose
// configuration has changed. It wraps purser.ErrUnauthenticated.
var ErrInvalidToken = fmt.Errorf("authserver: invalid access token: %w", purser.ErrUnauthenticated)

// ErrUnavailable is the sealing keys being unavailable, so no token can be
// checked right now. It does not wrap purser.ErrUnauthenticated.
var ErrUnavailable = errors.New("authserver: tokens cannot be verified right now")

// Labels set on the purser.Caller for an access token.
const (
	// LabelSubject is Google's stable account ID (sub) for a person; the
	// same label googletoken sets for Path A.
	LabelSubject = googletoken.LabelSubject
	// LabelHD is a person's Workspace domain, absent for a consumer
	// account; the same label googletoken sets for Path A.
	LabelHD = googletoken.LabelHD
	// LabelClientID is the OAuth client the token was issued to.
	LabelClientID = "steward.client_id"
	// LabelScope is the token's granted service scopes, space-separated.
	LabelScope = "steward.scope"
	// LabelKind is KindUser or KindWorkload.
	LabelKind = "steward.kind"
	// LabelServiceAccount is a workload's service account, if it has one.
	LabelServiceAccount = "steward.service_account"
)

// Values of LabelKind.
const (
	KindUser     = "user"
	KindWorkload = "workload"
)

// Principal is who a verified access token belongs to.
//
// It holds the Google access token sealed inside the token, but only
// behind TokenSource: the field is unexported, and formatting a Principal
// prints a pointer, never the token.
type Principal struct {
	// Subject is Google's sub for a person, or WorkloadSubject(client)
	// for a workload.
	Subject string
	// Email is a person's verified address, lower-cased. Empty for a
	// workload (see ServiceAccount).
	Email string
	// HD is a person's Workspace domain, empty for a consumer account or a
	// workload.
	HD string
	// ClientID is the OAuth client the token was issued to.
	ClientID string
	// Scopes are the granted service scopes.
	Scopes []string
	// Expiry is when this access token expires.
	Expiry time.Time
	// Workload is set for a client-credentials token: there is no person.
	Workload bool
	// ServiceAccount is a workload's Google service account, if it has
	// one; TokenSource then gives that account's token.
	ServiceAccount string
	// GoogleScopes are the scopes of the Google token inside, as Google
	// reported them (empty when unknown, or for a workload).
	GoogleScopes []string

	google *oauth2.Token
}

// TokenSource returns the Google access token sealed in the access token:
// the person's own, or a workload's service account's. It does not refresh;
// the client refreshes steward's token, which mints a new Google one. ok
// is false for a workload with no service account.
func (p Principal) TokenSource() (oauth2.TokenSource, bool) {
	if p.google == nil {
		return nil, false
	}
	t := *p.google
	return oauth2.StaticTokenSource(&t), true
}

// HasScope reports whether the token was granted scope.
func (p Principal) HasScope(scope string) bool { return slices.Contains(p.Scopes, scope) }

// Caller is the purser.Caller for p. A person's Identity is their email,
// with LabelSubject and LabelHD as on Path A; a workload's is its
// WorkloadSubject. Both carry LabelClientID, LabelScope and LabelKind.
func (p Principal) Caller() purser.Caller {
	labels := map[string]string{
		LabelClientID: p.ClientID,
		LabelScope:    strings.Join(p.Scopes, " "),
	}
	if p.Workload {
		labels[LabelKind] = KindWorkload
		if p.ServiceAccount != "" {
			labels[LabelServiceAccount] = p.ServiceAccount
		}
		return purser.Caller{Identity: p.Subject, Labels: labels}
	}
	labels[LabelKind] = KindUser
	labels[LabelSubject] = p.Subject
	if p.HD != "" {
		labels[LabelHD] = p.HD
	}
	return purser.Caller{Identity: p.Email, Labels: labels}
}

// Verify checks an access token presented to the protected resource: it
// opens, is unexpired, is bound to Resource, and (for a workload) still
// matches its client's configuration. It returns ErrInvalidToken, or
// ErrUnavailable when the keys are.
func (s *Server) Verify(ctx context.Context, token string) (Principal, error) {
	if !seal.IsSealed(token) {
		return Principal{}, ErrInvalidToken
	}
	var p accessPayload
	if err := s.open(ctx, purposeAccess, token, &p); err != nil {
		if errors.Is(err, errKeys) {
			return Principal{}, ErrUnavailable
		}
		return Principal{}, ErrInvalidToken
	}
	exp := time.Unix(p.Exp, 0)
	if !s.now().Before(exp) || p.Aud != s.cfg.Resource || p.Sub == "" {
		return Principal{}, ErrInvalidToken
	}
	workload := p.Mode == modeWorkload
	switch {
	case workload && !s.workloadCurrent(&p):
		return Principal{}, ErrInvalidToken
	case !workload && (p.Mode != "" || p.Email == "" || p.Token == ""):
		return Principal{}, ErrInvalidToken
	}
	// A person's token keeps only the scopes the configuration still allows
	// its client (a workload's was refused above if it has any other).
	allowed := s.scopes
	if c, ok := s.static[p.ClientID]; ok {
		allowed = s.allowedScopes(&client{static: &c})
	}
	var scopes []string
	for _, sc := range strings.Fields(p.Scope) {
		if slices.Contains(allowed, sc) {
			scopes = append(scopes, sc)
		}
	}
	pr := Principal{
		Subject:        p.Sub,
		HD:             p.HD,
		ClientID:       p.ClientID,
		Scopes:         scopes,
		Expiry:         exp,
		Workload:       workload,
		ServiceAccount: p.SA,
		GoogleScopes:   strings.Fields(p.GoogleScope),
	}
	if !workload {
		pr.Email = p.Email
	}
	if p.Token != "" {
		pr.google = &oauth2.Token{AccessToken: p.Token, TokenType: "Bearer", Expiry: time.Unix(p.TokenExp, 0)}
	}
	return pr, nil
}

// Authenticator returns a purser authn.Authenticator for this server's
// access tokens presented as "Authorization: Bearer <token>". Use it with
// httpmw.CallerOptions{Enforce: true} and no Fallback, as for Path A.
func (s *Server) Authenticator() *Authenticator { return &Authenticator{s: s} }

// Authenticator is a purser authenticator for access tokens. Its verdict
// is purser.AuthSourceOIDC for every token, a person's or a workload's:
// the token is verified locally against the issuer's keys, audience and
// expiry included, as an OIDC token is. (purser has no source for "an
// authorization server's own sealed token"; OIDC is the nearest that is
// true, and a source is fixed per authenticator.) The verdict does not say
// whether a person is behind the request: branch on the Caller's
// LabelKind, or Principal.Workload, never on the source.
type Authenticator struct{ s *Server }

var (
	_ authn.Authenticator  = (*Authenticator)(nil)
	_ authn.CredentialGate = (*Authenticator)(nil)
)

// Authenticate implements authn.Authenticator.
func (a *Authenticator) Authenticate(r *http.Request) (purser.Caller, error) {
	p, err := a.Verify(r)
	if err != nil {
		return purser.Caller{}, err
	}
	return p.Caller(), nil
}

// Verify returns the Principal behind the request's bearer token, or the
// error Authenticate would return.
func (a *Authenticator) Verify(r *http.Request) (Principal, error) {
	token, ok := bearerToken(r)
	if !ok {
		return Principal{}, fmt.Errorf("authserver: no bearer token: %w", purser.ErrUnauthenticated)
	}
	return a.s.Verify(r.Context(), token)
}

// Source implements authn.Authenticator.
func (*Authenticator) Source() purser.AuthSource { return purser.AuthSourceOIDC }

// GatesCredentials implements authn.CredentialGate.
func (*Authenticator) GatesCredentials() bool { return true }

// bearerToken returns the token from an "Authorization: Bearer <token>"
// header, as googletoken.BearerToken does.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
