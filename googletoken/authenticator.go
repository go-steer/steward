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

package googletoken

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"

	"github.com/go-steer/steward/allow"
)

// Labels set on the purser.Caller for a verified, admitted token.
const (
	// LabelSubject is Google's stable account ID (sub).
	LabelSubject = "google.sub"
	// LabelHD is the account's Workspace domain, absent for a consumer
	// account.
	LabelHD = "google.hd"
)

// ErrNotAdmitted is a verified token whose account the allow-list does
// not admit. It wraps ErrInvalid, and so purser.ErrUnauthenticated: to the
// caller it is one more credential that does not get in.
var ErrNotAdmitted = fmt.Errorf("%w: account not admitted", ErrInvalid)

// Authenticator is a purser authn.Authenticator for Google access tokens
// presented as "Authorization: Bearer <token>". A request is
// authenticated when its token verifies and the allow-list admits the
// account; the Caller's Identity is the account's email, with LabelSubject
// and LabelHD.
//
// It never resolves a failed request to an identity: no token, a bad
// token, an unadmitted account and an unavailable Google are all errors.
// What happens next is purser's middleware's decision, and only one
// configuration keeps steward's "no fallback identity" rule: Enforce set
// and no Fallback, so every failure is a 401. With Enforce off, purser
// gives a failed request CallerOptions.Fallback, so a Fallback naming the
// service would serve unadmitted people as the service. Use
// httpmw.CallerOptions{Authenticator: a, Enforce: true}.
//
// Under Enforce an unavailable Google is also a 401: purser maps every
// authentication error to one. Configure Config.Logger on the Verifier so
// an outage is visible.
type Authenticator struct {
	v     *Verifier
	admit *allow.Admitter
}

var (
	_ authn.Authenticator  = (*Authenticator)(nil)
	_ authn.CredentialGate = (*Authenticator)(nil)
)

// NewAuthenticator builds an Authenticator. Both arguments are required;
// an empty allow-list admits no one, and is refused here because a
// surface that can admit no one is a configuration mistake, not a policy.
// A list with group entries needs a directory to look them up, and is
// refused here too: use NewAdmittingAuthenticator with an allow.Admitter.
func NewAuthenticator(v *Verifier, admit *allow.List) (*Authenticator, error) {
	if v == nil {
		return nil, errors.New("googletoken: NewAuthenticator: nil Verifier")
	}
	if admit.Empty() {
		return nil, errors.New("googletoken: NewAuthenticator: empty allow-list: it admits no one")
	}
	if len(admit.Groups()) > 0 {
		return nil, errors.New("googletoken: NewAuthenticator: the allow-list has group entries: use NewAdmittingAuthenticator with an allow.Admitter that can look them up")
	}
	a, err := allow.NewAdmitter(admit, nil)
	if err != nil {
		return nil, fmt.Errorf("googletoken: NewAuthenticator: %w", err)
	}
	return &Authenticator{v: v, admit: a}, nil
}

// NewAdmittingAuthenticator builds an Authenticator that admits through
// an allow.Admitter, which answers for group entries as well as emails
// and domains. A group lookup that fails is ErrUnavailable, never a
// refusal.
func NewAdmittingAuthenticator(v *Verifier, admit *allow.Admitter) (*Authenticator, error) {
	if v == nil {
		return nil, errors.New("googletoken: NewAdmittingAuthenticator: nil Verifier")
	}
	if admit == nil {
		return nil, errors.New("googletoken: NewAdmittingAuthenticator: nil Admitter")
	}
	return &Authenticator{v: v, admit: admit}, nil
}

// Authenticate implements authn.Authenticator.
func (a *Authenticator) Authenticate(r *http.Request) (purser.Caller, error) {
	id, err := a.Verify(r)
	if err != nil {
		return purser.Caller{}, err
	}
	labels := map[string]string{LabelSubject: id.Subject}
	if id.HD != "" {
		labels[LabelHD] = id.HD
	}
	return purser.Caller{Identity: id.Email, Labels: labels}, nil
}

// Verify returns the Identity behind the request's bearer token, verified
// and admitted, or the error Authenticate would return. It is what a
// later middleware calls to recover the token's expiry; for a request
// Authenticate already accepted, the answer comes from the cache.
func (a *Authenticator) Verify(r *http.Request) (Identity, error) {
	token, ok := BearerToken(r)
	if !ok {
		return Identity{}, fmt.Errorf("googletoken: no bearer token: %w", purser.ErrUnauthenticated)
	}
	id, err := a.v.Verify(r.Context(), token)
	if err != nil {
		return Identity{}, err
	}
	switch err := a.admit.Admit(r.Context(), id.Email, id.HD); {
	case errors.Is(err, allow.ErrNotAdmitted):
		return Identity{}, ErrNotAdmitted
	case err != nil:
		// The directory failing is not the directory refusing.
		err = fmt.Errorf("%w: allow-list group check: %v", ErrUnavailable, err)
		if a.v.log != nil {
			a.v.log.WarnContext(r.Context(), "googletoken: could not admit a verified account", "err", err)
		}
		return Identity{}, err
	}
	return id, nil
}

// Source implements authn.Authenticator.
func (*Authenticator) Source() purser.AuthSource { return purser.AuthSourceGoogleAccessToken }

// GatesCredentials implements authn.CredentialGate: every request this
// authenticator accepts presented a token it verified.
func (*Authenticator) GatesCredentials() bool { return true }

// BearerToken returns the token from an "Authorization: Bearer <token>"
// header. The scheme is case-insensitive (RFC 7235 §2.1); a missing
// header, another scheme or an empty token is not a bearer token.
func BearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
