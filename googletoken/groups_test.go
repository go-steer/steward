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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-steer/purser"

	"github.com/go-steer/steward/allow"
)

// groupChecker admits members of one group, or fails every lookup.
type groupChecker struct {
	members map[string]bool
	fail    bool
}

func (g groupChecker) IsMember(_ context.Context, group, member string) (bool, error) {
	if g.fail {
		return false, errors.New("directory unavailable")
	}
	return group == "eng@cymbal.example" && g.members[member], nil
}

func newGroupAuthenticator(t *testing.T, g groupChecker, logTo *bytes.Buffer) *Authenticator {
	t.Helper()
	good := info(clientID, "Dana@Cymbal.example", "true", now.Add(time.Hour))
	base, _ := fakeGoogle(t, map[string]map[string]string{
		"good":     good,
		"outsider": with(good, "hd", "evil.example", "email", "eve@evil.example"),
	})
	clock := now
	v := newVerifier(t, base, &clock)
	if logTo != nil {
		v.log = slog.New(slog.NewTextHandler(logTo, nil))
	}
	list, err := allow.Parse([]string{"group:eng@cymbal.example"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthenticator(v, list); err == nil {
		t.Error("NewAuthenticator accepted a list with group entries it cannot look up")
	}
	adm, err := allow.NewAdmitter(list, g)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAdmittingAuthenticator(v, adm)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAuthenticatorGroups(t *testing.T) {
	t.Parallel()
	a := newGroupAuthenticator(t, groupChecker{members: map[string]bool{"dana@cymbal.example": true}}, nil)
	if c, err := a.Authenticate(request("Bearer good")); err != nil || c.Identity != "dana@cymbal.example" {
		t.Errorf("group member: %+v, %v", c, err)
	}
	if _, err := a.Authenticate(request("Bearer outsider")); !errors.Is(err, ErrNotAdmitted) {
		t.Errorf("not a member: %v, want ErrNotAdmitted", err)
	}
}

// A failed group lookup is the directory failing, not refusing:
// ErrUnavailable, not a credential error, and logged without the token.
func TestAuthenticatorGroupCheckFails(t *testing.T) {
	t.Parallel()
	var logged bytes.Buffer
	a := newGroupAuthenticator(t, groupChecker{fail: true}, &logged)
	_, err := a.Verify(request("Bearer good"))
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, purser.ErrUnauthenticated) || errors.Is(err, ErrNotAdmitted) {
		t.Errorf("group check failure: %v, want ErrUnavailable only", err)
	}
	if !strings.Contains(logged.String(), "directory unavailable") || strings.Contains(logged.String(), "good") {
		t.Errorf("log = %q, want the failure and not the token", logged.String())
	}
	quiet := newGroupAuthenticator(t, groupChecker{fail: true}, nil)
	if _, err := quiet.Verify(request("Bearer good")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("group check failure, no logger: %v", err)
	}
}

func TestNewAdmittingAuthenticatorRefuses(t *testing.T) {
	t.Parallel()
	v, err := New(Config{ClientIDs: []string{clientID}})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := allow.Parse([]string{"@cymbal.example"})
	adm, err := allow.NewAdmitter(list, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdmittingAuthenticator(nil, adm); err == nil {
		t.Error("accepted a nil Verifier")
	}
	if _, err := NewAdmittingAuthenticator(v, nil); err == nil {
		t.Error("accepted a nil Admitter")
	}
}
