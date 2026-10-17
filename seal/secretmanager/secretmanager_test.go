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

package secretmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const version = "projects/p/secrets/steward-keys/versions/latest"

var keyLine = "k1 " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))) + "\n"

func crc(b []byte) string {
	return fmt.Sprint(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
}

// fakeSecretManager answers versions:access for version with payload and
// the CRC32C given (empty for none).
func fakeSecretManager(t *testing.T, payload []byte, crc32c string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/"+version+":access" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"status":"NOT_FOUND","message":"Secret not found"}}`))
			return
		}
		p := map[string]string{"data": base64.StdEncoding.EncodeToString(payload)}
		if crc32c != "" {
			p["dataCrc32c"] = crc32c
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": version, "payload": p})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLoad(t *testing.T) {
	t.Parallel()
	srv := fakeSecretManager(t, []byte(keyLine), crc([]byte(keyLine)))
	kr, err := Source{Client: srv.Client(), Version: version, Endpoint: srv.URL + "/v1/"}.Load(context.Background())
	if err != nil || kr.SealingKeyID() != "k1" {
		t.Fatalf("Load = %v, %v", kr, err)
	}
	noCRC := fakeSecretManager(t, []byte(keyLine), "")
	if _, err := (Source{Client: noCRC.Client(), Version: version, Endpoint: noCRC.URL + "/v1/"}).Load(context.Background()); err != nil {
		t.Errorf("payload without a CRC32C: %v", err)
	}
	regional := "projects/p/locations/europe-west1/secrets/s/versions/3"
	if !versionRE.MatchString(regional) {
		t.Errorf("regional version %q refused", regional)
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secret := []byte("k1 " + base64.StdEncoding.EncodeToString([]byte("too-short-a-key")) + "\n")
	cases := map[string]Source{
		"no client":     {Version: version},
		"bad version":   {Client: http.DefaultClient, Version: "steward-keys"},
		"bad crc":       srcFor(t, []byte(keyLine), "12345"),
		"garbled crc":   srcFor(t, []byte(keyLine), "x"),
		"empty":         srcFor(t, nil, ""),
		"not a keyring": srcFor(t, secret, ""),
	}
	nf := fakeSecretManager(t, []byte(keyLine), "")
	cases["not found"] = Source{Client: nf.Client(), Version: "projects/p/secrets/other/versions/1", Endpoint: nf.URL + "/v1/"}
	cases["unreachable"] = Source{Client: nf.Client(), Version: version, Endpoint: "http://127.0.0.1:1/v1/"}
	cases["malformed endpoint"] = Source{Client: nf.Client(), Version: version, Endpoint: "http://\x7f/"}
	for name, s := range cases {
		_, err := s.Load(ctx)
		if err == nil {
			t.Errorf("%s: loaded", name)
			continue
		}
		// No error quotes the payload.
		if strings.Contains(err.Error(), strings.TrimSpace(string(secret))) || strings.Contains(err.Error(), strings.TrimSpace(keyLine)) {
			t.Errorf("%s: error %q quotes the payload", name, err)
		}
	}
	if _, err := cases["not found"].Load(ctx); err == nil || !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("not found: %v, want Google's status", err)
	}
}

func TestLoadOddResponses(t *testing.T) {
	t.Parallel()
	for name, h := range map[string]http.HandlerFunc{
		"not json": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		// A valid answer padded past the bound, so only the size check
		// can refuse it.
		"too large": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":    strings.Repeat("n", maxPayload),
				"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(keyLine))},
			})
		},
		"bad b64": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"payload":{"data":"!!!"}}`))
		},
		"cut short": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"payload":`))
		},
	} {
		srv := httptest.NewServer(h)
		_, err := Source{Client: srv.Client(), Version: version, Endpoint: srv.URL + "/"}.Load(context.Background())
		srv.Close()
		if err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	var asked string
	dflt := Source{Version: version, Client: &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		asked = r.URL.String()
		return nil, errors.New("offline")
	})}}
	if _, err := dflt.Load(context.Background()); err == nil || asked != Endpoint+version+":access" {
		t.Errorf("default endpoint: asked %q, err %v", asked, err)
	}
}

type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func srcFor(t *testing.T, payload []byte, crc32c string) Source {
	srv := fakeSecretManager(t, payload, crc32c)
	return Source{Client: srv.Client(), Version: version, Endpoint: srv.URL + "/v1/"}
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	if _, err := NewProvider(Source{Version: version}, 0, nil); err == nil {
		t.Error("accepted a nil client")
	}
	if _, err := NewProvider(Source{Client: http.DefaultClient, Version: "projects/p/secrets/s"}, 0, nil); err == nil {
		t.Error("accepted a secret name without a version")
	}
	var asked string
	p, err := NewProvider(Source{Version: version, Client: &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		asked = r.URL.String()
		return nil, errors.New("offline")
	})}}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Keyring(context.Background()); err == nil || asked != Endpoint+version+":access" {
		t.Errorf("provider asked %q, err %v", asked, err)
	}
	srv := fakeSecretManager(t, []byte(keyLine), "")
	p, err = NewProvider(Source{Client: srv.Client(), Version: version, Endpoint: srv.URL + "/v1/"}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if kr, err := p.Keyring(context.Background()); err != nil || kr.SealingKeyID() != "k1" {
		t.Errorf("provider = %v, %v", kr, err)
	}
}

// A regional secret is read from its regional endpoint, and nothing that
// could change the URL passes as a version name.
func TestVersionAndEndpoint(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]string{
		version: Endpoint,
		"projects/p/locations/europe-west1/secrets/s/versions/3": "https://secretmanager.europe-west1.rep.googleapis.com/v1/",
	} {
		if got := (Source{Version: v}).endpoint(); got != want {
			t.Errorf("endpoint for %s = %s, want %s", v, got, want)
		}
	}
	if got := (Source{Version: version, Endpoint: "https://private.example/v1/"}).endpoint(); got != "https://private.example/v1/" {
		t.Errorf("explicit endpoint ignored: %s", got)
	}
	for _, v := range []string{
		"projects/p/secrets/s/versions/1?alt=media",
		"projects/p/secrets/s/versions/1#x",
		"projects/p/secrets/../versions/1",
		"projects/p/secrets/s%2F/versions/1",
		"projects/p/locations/EU/secrets/s/versions/1",
		"projects/p/secrets/s",
	} {
		if versionRE.MatchString(v) {
			t.Errorf("version %q accepted", v)
		}
	}
}
