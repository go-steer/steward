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

// Package seal turns small values into opaque, tamper-proof strings and
// back: AES-256-GCM envelopes under a keyring whose keys are named by ID,
// so a key is rotated without a database and any replica holding the
// keyring opens what another sealed.
//
// steward's authorization server (Path B) seals everything it hands out
// (access and refresh tokens, authorization codes, sign-in state,
// dynamically registered client IDs), so it stores nothing. Each envelope
// is bound to a purpose through the AEAD's associated data, so an
// envelope sealed for one use (an authorization code) never opens as
// another (an access token).
//
// An envelope is "st1.<key id>.<base64url(nonce || ciphertext)>": the
// value's JSON, so a change of encoding would be a new prefix. Open checks
// no time; a value that expires carries its own expiry, which the caller
// checks. The string is canonical (strict base64, no line breaks), so it
// may key a replay cache.
//
// # Rotation
//
// The first key in a Keyring seals; every key opens. With several
// replicas reloading on their own schedules, rotate in two steps so that
// no replica meets an envelope sealed with a key it does not have yet:
//
//  1. Add the new key second. Wait longer than the reload interval, so
//     every replica can open with it.
//  2. Move it first. Every replica now seals with it.
//  3. Drop the old key once everything it sealed has expired (for the
//     authorization server, the 30-day refresh-token lifetime).
//
// Nonces are random, 96 bits, so one key should seal fewer than 2^32
// envelopes; rotating renews that budget.
//
// A KeyProvider supplies the keyring. A *Keyring is one (static);
// Reloader re-reads one periodically, from a file (FileLoader) or from
// Secret Manager (package seal/secretmanager), so a rotation takes effect
// without a restart.
//
// Taken from gke-demos/kode-gopher internal/oauth (seal.go) at
// 8b53617b7d4d0b08b158de64ab7416dc84a1281e, with the envelope prefix and
// associated-data label renamed, the purpose made a caller-supplied
// string, key IDs restricted to a URL-safe charset, the associated data
// made unambiguous, decoding made strict, and key providers added.
// kode-gopher will not import steward; port fixes by hand in both
// directions.
package seal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Prefix starts every envelope, so a sealed value is told apart at a
// glance from anything else that shares its slot: a Google access token
// in an Authorization header, a CIMD URL or a pre-registered client ID.
const Prefix = "st1."

// KeySize is the length of every key: AES-256.
const KeySize = 32

// ErrBadEnvelope is every reason an envelope does not open: not one of
// ours, an unknown key, tampered, sealed for another purpose, or not the
// expected shape. The reasons are deliberately not told apart.
var ErrBadEnvelope = errors.New("seal: invalid or tampered envelope")

// Key is one sealing key.
type Key struct {
	// ID names the key inside every envelope it seals: 1 to 64 of
	// A-Z a-z 0-9 _ -, so an envelope is safe in a header, a URL and a
	// form, and the associated data is unambiguous.
	ID string
	// Secret is KeySize random bytes.
	Secret []byte
}

// maxKeyID bounds a key ID's length.
const maxKeyID = 64

// validKeyID reports whether id is a well-formed key ID.
func validKeyID(id string) bool {
	if id == "" || len(id) > maxKeyID {
		return false
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// Keyring seals and opens envelopes. It is immutable after NewKeyring and
// safe for concurrent use.
type Keyring struct {
	ids  []string
	aead map[string]cipher.AEAD
}

// NewKeyring builds a keyring from keys, the sealing key first. Errors
// name a key by its position, and by its ID only once the ID is known to
// be well-formed: a malformed "ID" may be a secret pasted in the wrong
// place.
func NewKeyring(keys ...Key) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("seal: keyring has no keys")
	}
	k := &Keyring{aead: map[string]cipher.AEAD{}}
	for i, key := range keys {
		if !validKeyID(key.ID) {
			return nil, fmt.Errorf("seal: key %d: bad id: want 1 to %d of A-Z a-z 0-9 _ -", i+1, maxKeyID)
		}
		if len(key.Secret) != KeySize {
			return nil, fmt.Errorf("seal: key %q is %d bytes, want %d", key.ID, len(key.Secret), KeySize)
		}
		if _, dup := k.aead[key.ID]; dup {
			return nil, fmt.Errorf("seal: duplicate key id %q", key.ID)
		}
		block, err := aes.NewCipher(key.Secret)
		if err != nil {
			return nil, fmt.Errorf("seal: key %q: %w", key.ID, err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("seal: key %q: %w", key.ID, err)
		}
		k.ids = append(k.ids, key.ID)
		k.aead[key.ID] = gcm
	}
	return k, nil
}

// ParseKeyring reads a keyring in text form: one key per line,
// "<id> <base64 of KeySize random bytes>", the sealing key first. Blank
// lines and lines starting with # are skipped. Generate a key with
// `head -c32 /dev/urandom | base64`. Errors name the line, never the key.
func ParseKeyring(text []byte) (*Keyring, error) {
	var keys []Key
	sc := bufio.NewScanner(bytes.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("seal: keyring line %d: want \"<id> <base64 key>\"", n)
		}
		if !validKeyID(f[0]) {
			return nil, fmt.Errorf("seal: keyring line %d: bad id: want 1 to %d of A-Z a-z 0-9 _ - (are the columns swapped?)", n, maxKeyID)
		}
		secret, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			return nil, fmt.Errorf("seal: keyring line %d: key is not base64", n)
		}
		if len(secret) != KeySize {
			return nil, fmt.Errorf("seal: keyring line %d: key is %d bytes, want %d", n, len(secret), KeySize)
		}
		keys = append(keys, Key{ID: f[0], Secret: secret})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("seal: keyring: %w", err)
	}
	return NewKeyring(keys...)
}

// LoadKeyring reads a keyring file in ParseKeyring's form.
func LoadKeyring(path string) (*Keyring, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the keyring file
	if err != nil {
		return nil, fmt.Errorf("seal: read keyring: %w", err)
	}
	k, err := ParseKeyring(b)
	if err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, path)
	}
	return k, nil
}

// SealingKeyID is the ID of the key that seals.
func (k *Keyring) SealingKeyID() string { return k.ids[0] }

// KeyIDs lists every key's ID, the sealing key first.
func (k *Keyring) KeyIDs() []string { return append([]string(nil), k.ids...) }

// Keyring implements KeyProvider: a keyring provides itself.
func (k *Keyring) Keyring(context.Context) (*Keyring, error) { return k, nil }

// Seal encrypts v's JSON under the sealing key. purpose is bound in as
// associated data: the envelope opens only with the same purpose.
func (k *Keyring) Seal(purpose string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	id := k.ids[0]
	gcm := k.aead[id]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plain, aad(purpose, id))
	return Prefix + id + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Open decrypts an envelope sealed for purpose into v. Every failure is
// ErrBadEnvelope.
func (k *Keyring) Open(purpose, s string, v any) error {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return ErrBadEnvelope
	}
	id, body, ok := strings.Cut(rest, ".")
	if !ok {
		return ErrBadEnvelope
	}
	gcm, ok := k.aead[id]
	if !ok {
		return ErrBadEnvelope
	}
	// Strict, and no line breaks (which the decoder would skip): one
	// value has one envelope string.
	if strings.ContainsAny(body, "\r\n") {
		return ErrBadEnvelope
	}
	ct, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(ct) < gcm.NonceSize() {
		return ErrBadEnvelope
	}
	plain, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], aad(purpose, id))
	if err != nil {
		return ErrBadEnvelope
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return ErrBadEnvelope
	}
	return nil
}

// aad binds the key ID and the purpose into the envelope. The ID comes
// first and cannot contain "/", so no two (id, purpose) pairs give the
// same bytes.
func aad(purpose, id string) []byte {
	return []byte("steward/" + id + "/" + purpose)
}

// IsSealed reports whether s looks like an envelope (it may still not
// open).
func IsSealed(s string) bool { return strings.HasPrefix(s, Prefix) }

// KeyProvider supplies the keyring to seal and open with. It is asked on
// every seal and open, so an implementation that fetches keys caches
// them (as Reloader does). It must be safe for concurrent use.
type KeyProvider interface {
	Keyring(ctx context.Context) (*Keyring, error)
}
