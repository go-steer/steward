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

package allow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGroups is a GroupChecker over a fixed membership table.
type fakeGroups struct {
	mu       sync.Mutex
	members  map[string]map[string]bool
	calls    int
	failNext int // fail this many calls (a directory outage)
}

func (f *fakeGroups) IsMember(_ context.Context, group, member string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNext > 0 {
		f.failNext--
		return false, errors.New("directory unavailable")
	}
	return f.members[group][member], nil
}

func TestParseGroups(t *testing.T) {
	t.Parallel()
	l, err := Parse([]string{" Group:Eng@Cymbal.example ", "group:ops@cymbal.example", "@shoes.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(l.Groups(), " "); got != "eng@cymbal.example ops@cymbal.example" {
		t.Errorf("Groups() = %q", got)
	}
	if l.Empty() {
		t.Error("a list with group entries reports Empty")
	}
	// Admits answers from the list alone: never through a group.
	if l.Admits("eng@cymbal.example", "cymbal.example") {
		t.Error("Admits admitted a group's own address")
	}
	only, _ := Parse([]string{"group:eng@cymbal.example"})
	if only.Empty() {
		t.Error("a group-only list reports Empty")
	}
	var nilList *List
	plain, _ := Parse([]string{"@shoes.example"})
	for _, x := range []*List{nilList, plain} {
		if x.Groups() != nil {
			t.Errorf("Groups() on %v = %v, want nil", x, x.Groups())
		}
	}
	for _, bad := range []string{"group:", "group:eng", "group:@cymbal.example", "group:eng@cymbal", "group:a@b@cymbal.example", "@a@cymbal.example"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("Parse accepted %q", bad)
		}
	}
}

func newTestAdmitter(t *testing.T, entries []string, g GroupChecker) *Admitter {
	t.Helper()
	l, err := Parse(entries)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAdmitter(l, g)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAdmitter(t *testing.T) {
	t.Parallel()
	groups := &fakeGroups{members: map[string]map[string]bool{"g@cymbal.example": {"bob@other.example": true}}}
	a := newTestAdmitter(t, []string{"@cymbal.example", "group:g@cymbal.example"}, groups)
	ctx := context.Background()
	if a.List() == nil {
		t.Fatal("List() = nil")
	}
	if err := a.Admit(ctx, "alice@cymbal.example", "cymbal.example"); err != nil || groups.calls != 0 {
		t.Errorf("domain member: %v, %d group checks", err, groups.calls)
	}
	// The hd claim counts, not the email's domain; the group is then asked.
	if err := a.Admit(ctx, "eve@cymbal.example", ""); !errors.Is(err, ErrNotAdmitted) {
		t.Errorf("consumer account with a matching email suffix: %v, want ErrNotAdmitted", err)
	}
	if err := a.Admit(ctx, "Bob@Other.example", "other.example"); err != nil {
		t.Errorf("group member: %v", err)
	}
	calls := groups.calls
	if err := a.Admit(ctx, "bob@other.example", ""); err != nil || groups.calls != calls {
		t.Errorf("cached group member: %v, %d new calls", err, groups.calls-calls)
	}
	if err := a.Admit(ctx, "mallory@gmail.example", ""); !errors.Is(err, ErrNotAdmitted) {
		t.Errorf("outsider: %v", err)
	}
	// A refusal is cached too.
	calls = groups.calls
	if err := a.Admit(ctx, "mallory@gmail.example", ""); !errors.Is(err, ErrNotAdmitted) || groups.calls != calls {
		t.Errorf("cached outsider: %v, %d new calls", err, groups.calls-calls)
	}
	if err := a.Admit(ctx, "not-an-address", ""); !errors.Is(err, ErrNotAdmitted) || groups.calls != calls {
		t.Errorf("no address: %v, %d calls", err, groups.calls-calls)
	}
}

// A failed group check is an error, not a refusal, and is not cached.
func TestAdmitterCheckFailureIsNotARefusal(t *testing.T) {
	t.Parallel()
	groups := &fakeGroups{members: map[string]map[string]bool{"g@cymbal.example": {"bob@other.example": true}}, failNext: 1}
	a := newTestAdmitter(t, []string{"group:g@cymbal.example"}, groups)
	err := a.Admit(context.Background(), "bob@other.example", "")
	if err == nil || errors.Is(err, ErrNotAdmitted) {
		t.Fatalf("directory outage: %v, want a non-refusal error", err)
	}
	if err := a.Admit(context.Background(), "bob@other.example", ""); err != nil {
		t.Errorf("retry after the outage: %v (the failure was cached?)", err)
	}
}

func TestAdmitterVerdictExpires(t *testing.T) {
	t.Parallel()
	groups := &fakeGroups{members: map[string]map[string]bool{"g@cymbal.example": {"bob@other.example": true}}}
	a := newTestAdmitter(t, []string{"group:g@cymbal.example"}, groups)
	now := time.Unix(1_800_000_000, 0)
	a.now = func() time.Time { return now }
	ctx := context.Background()
	if err := a.Admit(ctx, "bob@other.example", ""); err != nil {
		t.Fatal(err)
	}
	groups.mu.Lock()
	delete(groups.members["g@cymbal.example"], "bob@other.example")
	groups.mu.Unlock()
	now = now.Add(GroupVerdictTTL - time.Second)
	if err := a.Admit(ctx, "bob@other.example", ""); err != nil {
		t.Errorf("within the TTL: %v, want the cached admission", err)
	}
	now = now.Add(2 * time.Second)
	if err := a.Admit(ctx, "bob@other.example", ""); !errors.Is(err, ErrNotAdmitted) {
		t.Errorf("after removal and the TTL: %v, want ErrNotAdmitted", err)
	}
}

func TestAdmitterCacheBounded(t *testing.T) {
	t.Parallel()
	groups := &fakeGroups{members: map[string]map[string]bool{}}
	a := newTestAdmitter(t, []string{"group:g@cymbal.example"}, groups)
	now := time.Unix(1_800_000_000, 0)
	a.now = func() time.Time { return now }
	for i := range maxVerdicts + 10 {
		_ = a.Admit(context.Background(), fmt.Sprintf("u%d@other.example", i), "")
	}
	if n := len(a.verdicts); n > maxVerdicts {
		t.Errorf("verdict cache holds %d entries, want at most %d", n, maxVerdicts)
	}
	// Expired entries are swept before the cache is cleared.
	clear(a.verdicts)
	for i := range maxVerdicts {
		_ = a.Admit(context.Background(), fmt.Sprintf("v%d@other.example", i), "")
	}
	now = now.Add(GroupVerdictTTL)
	_ = a.Admit(context.Background(), "late@other.example", "")
	if n := len(a.verdicts); n != 1 {
		t.Errorf("after expiry the cache holds %d entries, want 1", n)
	}
}

func TestNewAdmitterRefuses(t *testing.T) {
	t.Parallel()
	empty, _ := Parse(nil)
	for _, l := range []*List{nil, empty} {
		if _, err := NewAdmitter(l, &fakeGroups{}); err == nil {
			t.Errorf("NewAdmitter(%v) accepted an empty list", l)
		}
	}
	groups, _ := Parse([]string{"group:g@cymbal.example"})
	if _, err := NewAdmitter(groups, nil); err == nil || !strings.Contains(err.Error(), "g@cymbal.example") {
		t.Errorf("group entries with no checker: %v", err)
	}
	plain, _ := Parse([]string{"@cymbal.example"})
	if _, err := NewAdmitter(plain, nil); err != nil {
		t.Errorf("no groups, no checker: %v", err)
	}
}
