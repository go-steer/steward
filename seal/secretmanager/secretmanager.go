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

// Package secretmanager loads a seal.Keyring from a Google Secret Manager
// secret version, so the keys that seal steward's tokens live in Secret
// Manager and a rotation is a new secret version.
//
// It calls Secret Manager's REST API (versions:access) with a caller-
// supplied *http.Client, which carries the credentials (for example
// golang.org/x/oauth2/google.DefaultClient with Scope), so it brings in no
// Google Cloud SDK. The secret's payload is a keyring in
// seal.ParseKeyring's text form; its CRC32C is checked when Secret Manager
// reports one. No error ever quotes the payload.
//
// Use NewProvider for a seal.KeyProvider that re-reads the version every
// few minutes; name the version "latest" for a rotation to take effect
// without a restart.
package secretmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-steer/steward/seal"
)

// Endpoint is Secret Manager's global REST endpoint. A regional secret
// (projects/<p>/locations/<l>/secrets/...) is served from
// https://secretmanager.<l>.rep.googleapis.com/v1/, which Source uses for
// one unless Endpoint is set.
const Endpoint = "https://secretmanager.googleapis.com/v1/"

// Scope is the OAuth scope the client needs.
const Scope = "https://www.googleapis.com/auth/cloud-platform"

// maxPayload bounds the response read: a secret version is at most 64 KiB,
// base64 in JSON a third more.
const maxPayload = 128 << 10

// versionRE is a secret version's resource name, in Secret Manager's own
// ID charset, so nothing in it can change the URL it is put into.
var versionRE = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/(locations/([a-z0-9-]+)/)?secrets/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+$`)

// Source reads one secret version.
type Source struct {
	// Client calls Secret Manager, authorized with Scope as an identity
	// holding roles/secretmanager.secretAccessor on the secret. Required.
	Client *http.Client
	// Version is the secret version's resource name:
	// projects/<p>/secrets/<s>/versions/<v|latest>, or a regional
	// projects/<p>/locations/<l>/secrets/<s>/versions/<v>. Required.
	Version string
	// Endpoint replaces the endpoint the Version implies: Endpoint for a
	// global secret, the regional endpoint for a regional one (tests, or
	// a private endpoint).
	Endpoint string
}

// endpoint is the API base URL for s.
func (s Source) endpoint() string {
	if s.Endpoint != "" {
		return s.Endpoint
	}
	if m := versionRE.FindStringSubmatch(s.Version); m != nil && m[2] != "" {
		return "https://secretmanager." + m[2] + ".rep.googleapis.com/v1/"
	}
	return Endpoint
}

func (s Source) check() error {
	if s.Client == nil {
		return errors.New("secretmanager: no Client")
	}
	if !versionRE.MatchString(s.Version) {
		return fmt.Errorf("secretmanager: Version %q: want projects/<p>/secrets/<s>/versions/<v>", s.Version)
	}
	return nil
}

// Load fetches the version and parses it as a keyring. It is a
// seal.LoadFunc.
func (s Source) Load(ctx context.Context) (*seal.Keyring, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	ep := s.endpoint()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep+s.Version+":access", nil)
	if err != nil {
		return nil, fmt.Errorf("secretmanager: %w", err)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secretmanager: access %s: %w", s.Version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPayload+1))
	if err != nil {
		return nil, fmt.Errorf("secretmanager: access %s: %w", s.Version, err)
	}
	if resp.StatusCode != http.StatusOK {
		// Google's error body names the status and a message, never the
		// payload.
		var e struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return nil, fmt.Errorf("secretmanager: access %s: HTTP %d %s %s", s.Version, resp.StatusCode, e.Error.Status, e.Error.Message)
	}
	if len(body) > maxPayload {
		return nil, fmt.Errorf("secretmanager: access %s: response too large", s.Version)
	}
	var r struct {
		Payload struct {
			Data       string `json:"data"`
			DataCRC32C string `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("secretmanager: access %s: malformed response", s.Version)
	}
	data, err := base64.StdEncoding.DecodeString(r.Payload.Data)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("secretmanager: access %s: no payload", s.Version)
	}
	if r.Payload.DataCRC32C != "" {
		want, err := strconv.ParseUint(r.Payload.DataCRC32C, 10, 64)
		if err != nil || uint64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))) != want {
			return nil, fmt.Errorf("secretmanager: access %s: payload fails its CRC32C check", s.Version)
		}
	}
	kr, err := seal.ParseKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("secretmanager: %s: %w", s.Version, err)
	}
	return kr, nil
}

// NewProvider returns a seal.KeyProvider that loads the keyring from src
// and reloads it every interval (<= 0 means seal.DefaultReloadEvery).
// src is checked here, so a typo fails at startup; the first fetch
// happens on first use, so call Keyring once at startup to fail fast on
// access.
func NewProvider(src Source, every time.Duration, logger *slog.Logger) (*seal.Reloader, error) {
	if err := src.check(); err != nil {
		return nil, fmt.Errorf("secretmanager: NewProvider: %w", err)
	}
	return seal.NewReloader(src.Load, every, logger), nil
}
