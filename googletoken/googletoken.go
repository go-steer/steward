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

// Package googletoken verifies the Google OAuth access tokens a client
// presents on a person's behalf, such as the ones a Gemini Enterprise app
// sends to a Custom MCP Server.
//
// A Google access token is opaque: it is checked by asking Google, not by
// verifying a signature. A token is accepted only if Google's tokeninfo
// says it is unexpired, was issued to one of the service's own OAuth
// clients, carries every scope the service requires, and belongs to a
// verified email; and Google's userinfo answers for the same email and
// supplies the account's Workspace domain (hd).
//
// Verifier does that, with a bounded cache so that garbage tokens cannot
// turn into a flood of calls to Google. Authenticator wraps a Verifier and
// an allow.List as a purser authn.Authenticator, so a verified, admitted
// person reaches a service as a purser.Caller through purser's
// httpmw.CallerMiddleware.
//
// Moved from github.com/go-steer/supercargo internal/googleauth at
// 910d6384f2012bcf3648bee70863da484f8c1820 (supercargo#110), generalized to
// several client IDs and service-required scopes, with lookup-limit
// load-shedding reported as unavailable rather than invalid.
package googletoken

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-steer/purser"
)

// Google's endpoints.
const (
	TokenInfoURL = "https://oauth2.googleapis.com/tokeninfo" //nolint:gosec // G101: an endpoint, not a credential
	UserInfoURL  = "https://openidconnect.googleapis.com/v1/userinfo"
	// Issuer is Google's authorization server, the one a protected
	// resource names in its RFC 9728 metadata.
	Issuer = "https://accounts.google.com"
)

// EmailScope is always required: a token that cannot say whose it is
// identifies nobody.
const EmailScope = "https://www.googleapis.com/auth/userinfo.email"

// Limits.
const (
	// MaxCached bounds the token results remembered.
	MaxCached = 1024
	// MaxTTL bounds how long a verified token is trusted without asking
	// Google again, whatever its own expiry.
	MaxTTL = 10 * time.Minute
	// RefusedTTL is how long a refused token is refused without asking
	// Google again.
	RefusedTTL = 30 * time.Second
	// MaxLookups is how many lookups run at once. Past it, a token not in
	// the cache is turned away as unavailable without asking Google.
	MaxLookups = 8
	// maxTokenLen bounds what is ever sent to Google.
	maxTokenLen = 4096
	// maxBody bounds what is read from Google.
	maxBody = 64 << 10
)

// The statuses Google's endpoints answer a token they reject with: the
// only non-200 answers that are verdicts on the token. tokeninfo answers
// 400 {"error":"invalid_token"}, userinfo 401 (both checked against Google
// with a bogus token, 2026-10-20).
const (
	tokenInfoRefused = http.StatusBadRequest
	userInfoRefused  = http.StatusUnauthorized
)

// ErrInvalid is a token Google refused, or one that fails a check: not
// issued to this service, missing a scope, expired, unverified. It wraps
// purser.ErrUnauthenticated, so purser's middleware treats it as any
// other bad credential.
var ErrInvalid = fmt.Errorf("googletoken: invalid token: %w", purser.ErrUnauthenticated)

// ErrUnavailable is Google failing to answer (no response, 429, 5xx, or
// any other answer that is not Google's verdict on the token, such as an
// egress proxy's 403 or 407, or a 404 from a moved endpoint) or this
// Verifier shedding load (MaxLookups in flight). It is never cached.
// It wraps purser.ErrUnavailable and not purser.ErrUnauthenticated: the
// token may be fine and a retry may succeed, so purser's enforced
// middleware answers 503 with Retry-After rather than 401.
var ErrUnavailable = fmt.Errorf("googletoken: Google could not verify the token right now: %w", purser.ErrUnavailable)

// Identity is who a verified token belongs to.
type Identity struct {
	// Subject is Google's stable account ID (sub).
	Subject string
	// Email is the account's verified address, lower-cased.
	Email string
	// HD is the account's Workspace domain as Google asserts it,
	// lower-cased; empty for a consumer account, whatever its email.
	HD string
	// Scopes are the scopes the token carries.
	Scopes []string
	// Expiry is when the token itself expires (not when this result
	// stops being cached).
	Expiry time.Time
}

// Config configures a Verifier.
type Config struct {
	// ClientIDs are the service's own OAuth client IDs. A token issued to
	// any other client is refused: this is what keeps the service from
	// being used to replay a grant the user gave another app. Required.
	ClientIDs []string

	// RequiredScopes are scopes every token must carry, in addition to
	// EmailScope. Use Google's full scope URLs, as tokeninfo reports them
	// (for example "https://www.googleapis.com/auth/cloud-platform").
	RequiredScopes []string

	// HTTPClient calls Google. Nil means a client with a 10 s timeout. A
	// custom transport's errors are wrapped into ErrUnavailable as they
	// are, so a transport must not put request headers or bodies (which
	// carry the token) into its error text; net/http's own never does.
	HTTPClient *http.Client

	// Logger receives one warning per ErrUnavailable, without the token;
	// a Debug line instead when the caller's context was cancelled (the
	// client went away), which is no outage.
	// It is optional behind purser's middleware, which answers an
	// ErrUnavailable with 503 and logs it at Warn itself, through
	// CallerOptions.Logger or else slog.Default(): setting this as well
	// logs every outage twice. Nil means no logging.
	Logger *slog.Logger

	// TokenInfoURL and UserInfoURL replace Google's endpoints (tests).
	TokenInfoURL, UserInfoURL string

	// Now replaces time.Now (tests).
	Now func() time.Time
}

// Verifier checks Google access tokens. It is safe for concurrent use.
type Verifier struct {
	clients   []string
	scopes    []string
	hc        *http.Client
	tokenInfo string
	userInfo  string
	now       func() time.Time
	log       *slog.Logger

	mu      sync.Mutex
	cache   map[[sha256.Size]byte]entry
	lookups int
}

type entry struct {
	id      Identity
	until   time.Time
	refused bool
}

// New builds a Verifier from cfg.
func New(cfg Config) (*Verifier, error) {
	var clients []string
	for _, id := range cfg.ClientIDs {
		if id = strings.TrimSpace(id); id != "" {
			clients = append(clients, id)
		}
	}
	if len(clients) == 0 {
		return nil, errors.New("googletoken: New: no ClientIDs: every token would be refused, or, worse, a check on the issuing client would be skipped")
	}
	scopes := []string{EmailScope}
	for _, s := range cfg.RequiredScopes {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if !strings.HasPrefix(s, "https://") && s != "openid" {
			return nil, fmt.Errorf("googletoken: New: RequiredScopes %q: tokeninfo reports scopes as full URLs, so a short name would never match", s)
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	v := &Verifier{
		clients:   clients,
		scopes:    scopes,
		hc:        cfg.HTTPClient,
		tokenInfo: cfg.TokenInfoURL,
		userInfo:  cfg.UserInfoURL,
		now:       cfg.Now,
		cache:     map[[sha256.Size]byte]entry{},
	}
	if v.hc == nil {
		v.hc = &http.Client{Timeout: 10 * time.Second}
	}
	if v.tokenInfo == "" {
		v.tokenInfo = TokenInfoURL
	}
	if v.userInfo == "" {
		v.userInfo = UserInfoURL
	}
	if v.now == nil {
		v.now = time.Now
	}
	v.log = cfg.Logger
	return v, nil
}

// Verify checks token and returns whose it is. The error is ErrInvalid
// (possibly wrapped) for a token that does not hold, and ErrUnavailable
// (possibly wrapped) when it could not be checked. Neither error ever
// contains the token.
func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	id, err := v.verify(ctx, token)
	if err != nil && v.log != nil && errors.Is(err, ErrUnavailable) {
		logUnavailable(ctx, v.log, "googletoken: could not verify a token", err)
	}
	return id, err
}

// logUnavailable reports an ErrUnavailable at Warn, or at Debug when the
// caller's context was cancelled: the client went away mid-request, the
// lookup failed with it, and that is no outage. Canceled only: a deadline
// that ran out (DeadlineExceeded) is a dependency too slow to answer,
// which is the outage this line reports. purser's httpmw.CallerMiddleware
// draws the same line.
func logUnavailable(ctx context.Context, log *slog.Logger, msg string, err error) {
	if errors.Is(ctx.Err(), context.Canceled) {
		log.DebugContext(ctx, msg+"; the client had already gone", "err", err)
		return
	}
	log.WarnContext(ctx, msg, "err", err)
}

func (v *Verifier) verify(ctx context.Context, token string) (Identity, error) {
	// A JWT is an ID token, never an access token: refused before Google
	// is asked, so nothing depends on tokeninfo telling them apart.
	if token == "" || len(token) > maxTokenLen || strings.HasPrefix(token, "eyJ") && strings.Count(token, ".") == 2 {
		return Identity{}, ErrInvalid
	}
	key := sha256.Sum256([]byte(token))
	now := v.now()

	v.mu.Lock()
	if e, ok := v.cache[key]; ok && now.Before(e.until) {
		v.mu.Unlock()
		if e.refused {
			return Identity{}, ErrInvalid
		}
		return e.id.clone(), nil
	}
	if v.lookups >= MaxLookups {
		v.mu.Unlock()
		return Identity{}, fmt.Errorf("%w: too many lookups in flight", ErrUnavailable)
	}
	v.lookups++
	v.mu.Unlock()

	// The slot is released however lookup ends, including a panic in a
	// caller-supplied transport; otherwise MaxLookups such panics would
	// shed every new token until the process restarted.
	id, until, err := func() (Identity, time.Time, error) {
		defer func() {
			v.mu.Lock()
			v.lookups--
			v.mu.Unlock()
		}()
		return v.lookup(ctx, token, now)
	}()

	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case err == nil:
		v.remember(key, entry{id: id, until: until}, now)
	case errors.Is(err, ErrInvalid):
		// Google said no: say no again for a while without asking.
		v.remember(key, entry{refused: true, until: now.Add(RefusedTTL)}, now)
	}
	return id.clone(), err
}

func (id Identity) clone() Identity {
	id.Scopes = slices.Clone(id.Scopes)
	return id
}

// remember caches e under key, within MaxCached. Call with mu held.
func (v *Verifier) remember(key [sha256.Size]byte, e entry, now time.Time) {
	if len(v.cache) >= MaxCached {
		for k, old := range v.cache {
			if !now.Before(old.until) {
				delete(v.cache, k)
			}
		}
		// Still full of live entries: drop arbitrary ones. Losing a cached
		// verdict costs one more lookup, never a wrong answer.
		for k := range v.cache {
			if len(v.cache) < MaxCached {
				break
			}
			delete(v.cache, k)
		}
	}
	v.cache[key] = e
}

// lookup asks Google about token: tokeninfo for whom it was issued to and
// what it may do, userinfo for the account's domain.
func (v *Verifier) lookup(ctx context.Context, token string, now time.Time) (Identity, time.Time, error) {
	// POST, so the token travels in the body and not in a URL that a
	// proxy or server log might keep.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.tokenInfo,
		strings.NewReader(url.Values{"access_token": {token}}.Encode()))
	if err != nil {
		return Identity{}, time.Time{}, fmt.Errorf("%w: tokeninfo request: %w", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var info struct {
		Aud           string  `json:"aud"`
		Azp           string  `json:"azp"`
		Sub           string  `json:"sub"`
		Scope         string  `json:"scope"`
		Email         string  `json:"email"`
		EmailVerified lenient `json:"email_verified"`
		Exp           lenient `json:"exp"`
	}
	if err := v.fetch(req, "tokeninfo", tokenInfoRefused, &info); err != nil {
		return Identity{}, time.Time{}, err
	}
	exp, err := strconv.ParseInt(string(info.Exp), 10, 64)
	scopes := strings.Fields(info.Scope)
	switch {
	case err != nil, !time.Unix(exp, 0).After(now):
		return Identity{}, time.Time{}, ErrInvalid
	case !slices.Contains(v.clients, info.Aud) && !slices.Contains(v.clients, info.Azp):
		// Issued to someone else's client: never accepted here.
		return Identity{}, time.Time{}, ErrInvalid
	case slices.ContainsFunc(v.scopes, func(s string) bool { return !slices.Contains(scopes, s) }):
		return Identity{}, time.Time{}, ErrInvalid
	case info.Email == "" || info.EmailVerified != "true":
		return Identity{}, time.Time{}, ErrInvalid
	}

	// The domain: tokeninfo doesn't say, and an email alone doesn't show
	// that a company's Workspace holds the account.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, v.userInfo, nil)
	if err != nil {
		return Identity{}, time.Time{}, fmt.Errorf("%w: userinfo request: %w", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	var user struct {
		Email string `json:"email"`
		HD    string `json:"hd"`
	}
	if err := v.fetch(req, "userinfo", userInfoRefused, &user); err != nil {
		return Identity{}, time.Time{}, err
	}
	if !strings.EqualFold(user.Email, info.Email) {
		return Identity{}, time.Time{}, ErrInvalid
	}
	expiry := time.Unix(exp, 0)
	until := expiry
	if until.After(now.Add(MaxTTL)) {
		until = now.Add(MaxTTL)
	}
	return Identity{
		Subject: info.Sub,
		Email:   strings.ToLower(info.Email),
		HD:      strings.ToLower(user.HD),
		Scopes:  scopes,
		Expiry:  expiry,
	}, until, nil
}

// fetch sends req and decodes its JSON answer into out.
//
// Only refused, the status the endpoint answers a token it rejects with,
// is Google refusing (ErrInvalid, which Verify caches). Everything else
// is ErrUnavailable, never cached: no answer, 429, 5xx, any other status
// (an egress proxy's 403 or 407, a 404 from a moved endpoint: nothing
// Google said about the token), a body cut short (the client went away,
// the timeout fired, the connection dropped) and a 200 whose body does
// not parse. Treating any of those as a refusal would lock a person's
// valid token out for RefusedTTL and send their client to sign in again.
func (v *Verifier) fetch(req *http.Request, what string, refused int, out any) error {
	resp, err := v.hc.Do(req)
	if err != nil {
		// A *url.Error names the URL, never the body or headers, so the
		// token cannot leak through it.
		return fmt.Errorf("%w: %s: %w", ErrUnavailable, what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case refused:
		return ErrInvalid // an expired, revoked or malformed token
	default:
		return fmt.Errorf("%w: %s: HTTP %d", ErrUnavailable, what, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err == nil {
		err = req.Context().Err()
	}
	if err != nil {
		return fmt.Errorf("%w: %s: reading the answer: %w", ErrUnavailable, what, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %s: unreadable answer: %w", ErrUnavailable, what, err)
	}
	return nil
}

// lenient is a JSON string, number or boolean, kept as its text. Google's
// tokeninfo sends exp and email_verified as strings today; a change to a
// number or a boolean must not turn every token into a refusal.
type lenient string

func (l *lenient) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*l = lenient(s)
		return nil
	}
	var raw json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch t := string(raw); {
	case t == "true" || t == "false":
		*l = lenient(t)
	case len(t) > 0 && (t[0] == '-' || (t[0] >= '0' && t[0] <= '9')):
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		*l = lenient(n.String())
	default:
		*l = ""
	}
	return nil
}
