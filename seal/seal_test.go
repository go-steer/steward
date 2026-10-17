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

package seal

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(id string, b byte) Key {
	return Key{ID: id, Secret: []byte(strings.Repeat(string(b), KeySize))}
}

type payload struct{ V string }

// Ported from kode-gopher internal/oauth units_test.go TestKeyring.
func TestKeyring(t *testing.T) {
	t.Parallel()
	old, cur := key("old", 'o'), key("new", 'n')
	k1, _ := NewKeyring(old)
	k2, err := NewKeyring(cur, old)
	if err != nil {
		t.Fatal(err)
	}
	if k2.SealingKeyID() != "new" || strings.Join(k2.KeyIDs(), ",") != "new,old" {
		t.Errorf("SealingKeyID %q, KeyIDs %v", k2.SealingKeyID(), k2.KeyIDs())
	}
	sealedOld, _ := k1.Seal("access", payload{"a"})
	var p payload
	if err := k2.Open("access", sealedOld, &p); err != nil || p.V != "a" {
		t.Fatalf("rotated keyring can't open an old envelope: %v", err)
	}
	s, _ := k2.Seal("access", payload{"b"})
	if !strings.HasPrefix(s, "st1.new.") || !IsSealed(s) {
		t.Errorf("sealed as %q, want the first key under the st1. prefix", s[:8])
	}
	for name, bad := range map[string]func() error{
		"keyring without the sealing key": func() error { return k1.Open("access", s, &p) },
		"another purpose":                 func() error { return k2.Open("refresh", s, &p) },
		"tampered": func() error {
			b := []byte(s)
			b[len(b)-2] ^= 1
			return k2.Open("access", string(b), &p)
		},
		"no prefix":    func() error { return k2.Open("access", strings.TrimPrefix(s, Prefix), &p) },
		"no key id":    func() error { return k2.Open("access", Prefix+"nodot", &p) },
		"bad base64":   func() error { return k2.Open("access", Prefix+"new.!!!", &p) },
		"short":        func() error { return k2.Open("access", Prefix+"new.AAAA", &p) },
		"wrong shape":  func() error { var n int; return k2.Open("access", s, &n) },
		"a Google one": func() error { return k2.Open("access", "ya29.a0Af", &p) },
	} {
		if err := bad(); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("%s: %v, want ErrBadEnvelope", name, err)
		}
	}
	// The key ID is bound in: an envelope relabelled to another key that
	// happens to share the secret does not open.
	same, _ := NewKeyring(key("twin", 'n'), cur)
	if err := same.Open("access", strings.Replace(s, "st1.new.", "st1.twin.", 1), &p); err == nil {
		t.Error("an envelope relabelled to another key ID opened")
	}
	for _, id := range []string{"a.b", "", "a b", "x/k", "a\rb", "a&b=c", "a%2f", "café", "a b", "a\x00b", strings.Repeat("k", maxKeyID+1)} {
		if _, err := NewKeyring(Key{ID: id, Secret: cur.Secret}); err == nil {
			t.Errorf("NewKeyring accepted key ID %q", id)
		}
	}
	if _, err := NewKeyring(Key{ID: strings.Repeat("k", maxKeyID), Secret: cur.Secret}); err != nil {
		t.Errorf("a %d-character key ID refused: %v", maxKeyID, err)
	}
	if _, err := NewKeyring(Key{ID: "x", Secret: []byte("short")}); err == nil {
		t.Error("a short key accepted")
	}
	// A malformed ID may be a secret in the wrong field: never quoted.
	pasted := base64.StdEncoding.EncodeToString(cur.Secret)
	if _, err := NewKeyring(Key{ID: pasted, Secret: []byte("k1")}); err == nil || strings.Contains(err.Error(), pasted) {
		t.Errorf("NewKeyring error %v quotes a malformed ID", err)
	}
	if _, err := NewKeyring(cur, cur); err == nil {
		t.Error("duplicate key IDs accepted")
	}
	if _, err := NewKeyring(); err == nil {
		t.Error("an empty keyring accepted")
	}
	if _, err := k2.Seal("access", func() {}); err == nil {
		t.Error("sealed a value JSON cannot encode")
	}
	if got, err := k2.Keyring(context.Background()); got != k2 || err != nil {
		t.Errorf("a Keyring does not provide itself: %v, %v", got, err)
	}
}

// The associated data is unambiguous: two keys sharing a secret, where one
// ID could be read as the other plus a purpose suffix, cannot be played
// against each other. (With "/" now refused in IDs the pair cannot even be
// built, so this pins the layout directly.)
func TestAssociatedDataUnambiguous(t *testing.T) {
	t.Parallel()
	seen := map[string][2]string{}
	for _, pair := range [][2]string{{"code/x", "k"}, {"code", "x/k"}, {"code", "k"}, {"x/code", "k"}} {
		a := string(aad(pair[0], pair[1]))
		if prev, dup := seen[a]; dup {
			t.Errorf("aad%v and aad%v are both %q", prev, pair, a)
		}
		seen[a] = pair
	}
}

// One value has one envelope string: no line breaks, no non-canonical
// base64 tails.
func TestEnvelopeCanonical(t *testing.T) {
	t.Parallel()
	k, _ := NewKeyring(key("k", 'k'))
	s, _ := k.Seal("p", payload{"v"})
	var p payload
	for name, bad := range map[string]string{
		"newline":      s[:len(s)-4] + "\n" + s[len(s)-4:],
		"carriage ret": s[:len(s)-4] + "\r" + s[len(s)-4:],
	} {
		if err := k.Open("p", bad, &p); !errors.Is(err, ErrBadEnvelope) {
			t.Errorf("%s: %v, want ErrBadEnvelope", name, err)
		}
	}
	// Flip the low bits of the last character: with RawURLEncoding a
	// lenient decoder accepts the same bytes under a second spelling.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < 64; i++ {
		alt := s[:len(s)-1] + string(alphabet[i])
		if alt == s {
			continue
		}
		if err := k.Open("p", alt, &p); err == nil {
			t.Errorf("a second spelling %q of the envelope opened", alt[len(alt)-4:])
		}
	}
}

func TestEnvelopesDiffer(t *testing.T) {
	t.Parallel()
	k, _ := NewKeyring(key("k", 'k'))
	a, _ := k.Seal("p", payload{"same"})
	b, _ := k.Seal("p", payload{"same"})
	if a == b {
		t.Error("two seals of the same value are identical: the nonce is not random")
	}
}

func TestParseKeyring(t *testing.T) {
	t.Parallel()
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", KeySize)))
	k, err := ParseKeyring([]byte("# comment\n\nk2 " + b64 + "\n  k1 " + b64 + "  \n"))
	if err != nil || strings.Join(k.KeyIDs(), ",") != "k2,k1" {
		t.Fatalf("ParseKeyring = %v, %v", k, err)
	}
	for name, text := range map[string]string{
		"not base64": "k1 not-base64!\n",
		"one field":  "k1\n",
		"no keys":    "# only a comment\n",
		"too short":  "k1 " + base64.StdEncoding.EncodeToString([]byte("short")) + "\n",
		"long line":  "k1 " + strings.Repeat("A", 70_000) + "\n",
	} {
		if _, err := ParseKeyring([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An error names the line, never the key material: a short key, or the
	// columns swapped with an ID that is itself valid base64.
	secret := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 31)))
	if _, err := ParseKeyring([]byte("k1 " + secret + "\n")); err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("short key: error %v", err)
	}
	if _, err := ParseKeyring([]byte("# c\n" + b64 + " prod\n")); err == nil || strings.Contains(err.Error(), b64) || strings.Contains(err.Error(), "zzz") || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("swapped columns: error %v", err)
	}
	if _, err := ParseKeyring([]byte("k1 " + b64 + "\nk1 " + b64 + "\n")); err == nil {
		t.Error("duplicate IDs accepted")
	}
}

func TestLoadKeyring(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys")
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", KeySize)))
	if err := os.WriteFile(path, []byte("k1 "+b64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadKeyring(path); err != nil || k.SealingKeyID() != "k1" {
		t.Fatalf("LoadKeyring = %v, %v", k, err)
	}
	if k, err := FileLoader(path)(context.Background()); err != nil || k.SealingKeyID() != "k1" {
		t.Fatalf("FileLoader = %v, %v", k, err)
	}
	if err := os.WriteFile(path, []byte("k1 x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("bad keyring file: %v, want an error naming the file", err)
	}
	if _, err := LoadKeyring(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file loaded")
	}
}
