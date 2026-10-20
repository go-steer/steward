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

// The refresh-token reuse grace: a second presentation of the generation a
// family has just moved away from is refused without revoking the family.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	graceLog  = "within the reuse grace"
	revokeLog = "its family is revoked"
)

// graceEnv is a test environment whose in-memory replay cache runs on a
// clock the test can move forward.
type graceEnv struct {
	*testEnv
	replay *MemoryReplayCache
	skew   *atomic.Int64 // nanoseconds the cache's clock runs ahead
}

// testGrace is the grace the tests turn on; by default there is none.
const testGrace = 10 * time.Second

func newGraceEnv(t *testing.T, mutate func(*Config)) *graceEnv {
	t.Helper()
	g := &graceEnv{replay: NewMemoryReplayCache(), skew: &atomic.Int64{}}
	g.replay.now = func() time.Time { return time.Now().Add(time.Duration(g.skew.Load())) }
	g.testEnv = newTestEnv(t, true, func(c *Config) {
		c.Replay = g.replay
		c.RefreshReuseGrace = testGrace
		if mutate != nil {
			mutate(c)
		}
	})
	return g
}

// tokenVia posts form to h's token endpoint: another replica.
func tokenVia(t *testing.T, h http.Handler, form url.Values) tokenResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	r := tokenResp{status: rec.Code, header: rec.Header()}
	_ = json.NewDecoder(rec.Body).Decode(&r)
	return r
}

// gateGroups holds the first membership lookup until release is closed,
// so a refresh can be held in flight after its rotation.
type gateGroups struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *gateGroups) IsMember(context.Context, string, string) (bool, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		<-g.release
	}
	return true, nil
}

// await receives from ch, failing the test rather than hanging if nothing
// comes (if the refresh stops reaching the gate, say).
func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func TestMemoryReplayCacheGrace(t *testing.T) {
	t.Parallel()
	c := NewMemoryReplayCache()
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	exp := now.Add(time.Hour)
	rotate := func(fam string, gen uint64) RotateResult {
		t.Helper()
		r, err := c.RotateGrace(ctx, fam, gen, exp, now.Add(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if rotate("f", 0) != RotateApplied || rotate("f", 1) != RotateApplied {
		t.Fatal("rotating a fresh family refused")
	}
	// The generation just rotated away, within the grace: refused, kept.
	if r := rotate("f", 1); r != RotateRefused {
		t.Errorf("the generation just rotated away, in the grace: %v, want RotateRefused", r)
	}
	if r := rotate("f", 1); r != RotateRefused {
		t.Errorf("presented a third time, in the grace: %v, want RotateRefused", r)
	}
	if r := rotate("f", 2); r != RotateApplied {
		t.Fatalf("the current generation after a refusal in the grace: %v (the family was revoked)", r)
	}
	// An older generation, in the grace: revoked.
	if r := rotate("f", 1); r != RotateRevoked {
		t.Errorf("a generation two behind, in the grace: %v, want RotateRevoked", r)
	}
	if r := rotate("f", 3); r != RotateRevoked {
		t.Errorf("the current generation after a replay: %v, want RotateRevoked", r)
	}

	// Past the grace: revoked.
	if rotate("g", 0) != RotateApplied {
		t.Fatal("rotating a fresh family refused")
	}
	now = now.Add(10 * time.Second)
	if r := rotate("g", 0); r != RotateRevoked {
		t.Errorf("the generation just rotated away, at the end of the grace: %v, want RotateRevoked", r)
	}
	if r := rotate("g", 1); r != RotateRevoked {
		t.Errorf("a revoked family, in a fresh grace: %v, want RotateRevoked", r)
	}

	// Unrotate forgets the undone rotation's grace: the generation before
	// was rotated away earlier, and is a replay again.
	if rotate("h", 0) != RotateApplied || rotate("h", 1) != RotateApplied {
		t.Fatal("rotating a fresh family refused")
	}
	_ = c.Unrotate(ctx, "h", 1)
	if r := rotate("h", 0); r != RotateRevoked {
		t.Errorf("the generation before an undone rotation: %v, want RotateRevoked", r)
	}

	// The zero graceUntil, and Rotate, grant none.
	if r, _ := c.RotateGrace(ctx, "i", 0, exp, time.Time{}); r != RotateApplied {
		t.Fatal("rotating a fresh family refused")
	}
	if r, _ := c.RotateGrace(ctx, "i", 0, exp, time.Time{}); r != RotateRevoked {
		t.Errorf("reuse after a rotation with no grace: %v, want RotateRevoked", r)
	}
	if ok, _ := c.Rotate(ctx, "j", 0, exp); !ok {
		t.Fatal("rotating a fresh family refused")
	}
	if ok, _ := c.Rotate(ctx, "j", 0, exp); ok {
		t.Error("Rotate accepted a reused generation")
	}
	if r := rotate("j", 1); r != RotateRevoked {
		t.Errorf("Rotate did not revoke: %v", r)
	}
	// Rotate honours no grace a RotateGrace recorded.
	if rotate("k", 0) != RotateApplied {
		t.Fatal("rotating a fresh family refused")
	}
	if ok, _ := c.Rotate(ctx, "k", 0, exp); ok {
		t.Error("Rotate accepted a reused generation")
	}
	if r := rotate("k", 1); r != RotateRevoked {
		t.Errorf("Rotate inside a recorded grace did not revoke: %v", r)
	}

	// A later generation than known (another replica rotated it) records a
	// grace too.
	if rotate("l", 0) != RotateApplied || rotate("l", 5) != RotateApplied {
		t.Fatal("rotating to a later generation refused")
	}
	if r := rotate("l", 5); r != RotateRefused {
		t.Errorf("the generation just rotated away, after a jump: %v, want RotateRefused", r)
	}

	// Full of live families: refused with an error, nothing forgotten.
	full := NewMemoryReplayCache()
	full.now = c.now
	for i := range maxMemoryEntries {
		full.families[fmt.Sprint(i)] = family{gen: 1, exp: exp}
	}
	if r, err := full.RotateGrace(ctx, "new", 0, exp, now.Add(time.Second)); r != RotateRevoked || !errors.Is(err, errReplayFull) {
		t.Errorf("RotateGrace in a full cache: %v %v", r, err)
	}
}

// Two processes sharing a client's token store refresh at once: the second
// presentation arrives while the first is still in flight, after its
// rotation. The second is refused and the family survives, so the first
// one's new tokens keep working.
func TestRefreshConcurrentWithinGrace(t *testing.T) {
	t.Parallel()
	e := newGraceEnv(t, nil)
	e.google.signInAs = bob // needs the group lookup the gate holds
	id, first := e.signIn(newBrowser(t))
	gate := &gateGroups{entered: make(chan struct{}), release: make(chan struct{})}
	e.as.cfg.Admit = newAdmitter(t, gate)

	winner := make(chan tokenResp, 1)
	go func() {
		// Not e.token: it calls t.Fatal, which must not run off the test's
		// goroutine.
		winner <- tokenVia(t, e.as.Handler(), refreshForm(id, first.Refresh))
	}()
	await(t, gate.entered, "the first refresh to reach the gate") // it has rotated the family and is held after
	loser := e.token(refreshForm(id, first.Refresh), "", "")
	close(gate.release)
	won := await(t, winner, "the first refresh")

	if loser.Error != "invalid_grant" {
		t.Errorf("second presentation during the first's refresh: %+v, want invalid_grant", loser)
	}
	if won.status != http.StatusOK {
		t.Fatalf("first refresh: %+v", won)
	}
	if status, got, _ := e.call(won.Access); status != http.StatusOK {
		t.Errorf("the winner's access token: %d %s", status, got)
	}
	if r := e.token(refreshForm(id, won.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("the winner's refresh token after a concurrent refresh: %+v (the family was revoked)", r)
	}
	if l := e.log.String(); !strings.Contains(l, graceLog) || strings.Contains(l, revokeLog) {
		t.Errorf("log does not record the refusal in the grace (and only that):\n%s", l)
	}
}

// Many goroutines refresh with the same token at once: exactly one wins,
// none revokes, and the winner's refresh token works.
func TestRefreshBurstWithinGrace(t *testing.T) {
	t.Parallel()
	e := newGraceEnv(t, nil)
	id, first := e.signIn(newBrowser(t))
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan tokenResp, n)
	for range n {
		wg.Go(func() {
			<-start
			results <- tokenVia(t, e.as.Handler(), refreshForm(id, first.Refresh))
		})
	}
	close(start)
	wg.Wait()
	close(results)
	var won []tokenResp
	for r := range results {
		switch {
		case r.status == http.StatusOK:
			won = append(won, r)
		case r.Error != "invalid_grant":
			t.Errorf("a losing refresh: %+v, want invalid_grant", r)
		}
	}
	if len(won) != 1 {
		t.Fatalf("%d refreshes won, want 1", len(won))
	}
	if r := e.token(refreshForm(id, won[0].Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("the winner's refresh token after a burst: %+v (the family was revoked)", r)
	}
}

// The grace is short: the same token presented after it revokes the family,
// as before, even if it was refused inside the grace first (a client that
// keeps the stale token instead of re-reading its store).
func TestRefreshReuseAfterGraceRevokes(t *testing.T) {
	t.Parallel()
	e := newGraceEnv(t, nil)
	id, first := e.signIn(newBrowser(t))
	second := e.token(refreshForm(id, first.Refresh), "", "")
	if second.status != http.StatusOK {
		t.Fatalf("refresh: %+v", second)
	}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("reuse inside the grace: %+v, want invalid_grant", r)
	}
	e.skew.Store(int64(testGrace + time.Second))
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("reuse after the grace: %+v, want invalid_grant", r)
	}
	if r := e.token(refreshForm(id, second.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("the newest refresh token after a reuse past the grace: %+v, want invalid_grant (family revoked)", r)
	}
	if !strings.Contains(e.log.String(), revokeLog) {
		t.Errorf("log does not record the revocation:\n%s", e.log)
	}
}

// Only the generation just rotated away is spared: an older one presented
// inside the grace still revokes the family.
func TestRefreshOlderGenerationInGraceRevokes(t *testing.T) {
	t.Parallel()
	e := newGraceEnv(t, nil)
	id, first := e.signIn(newBrowser(t))
	second := e.token(refreshForm(id, first.Refresh), "", "")
	third := e.token(refreshForm(id, second.Refresh), "", "")
	if second.status != http.StatusOK || third.status != http.StatusOK {
		t.Fatalf("refreshes: %+v %+v", second, third)
	}
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("a generation two behind, in the grace: %+v, want invalid_grant", r)
	}
	if r := e.token(refreshForm(id, third.Refresh), "", ""); r.Error != "invalid_grant" {
		t.Errorf("the newest refresh token after an older generation's reuse: %+v, want invalid_grant (family revoked)", r)
	}
}

// Replicas sharing one cache share the grace: the second presentation on
// another replica is refused without revoking, and the winner's token
// refreshes there.
func TestRefreshGraceAcrossReplicas(t *testing.T) {
	t.Parallel()
	e := newGraceEnv(t, nil)
	other, err := New(e.as.cfg)
	if err != nil {
		t.Fatal(err)
	}
	id, first := e.signIn(newBrowser(t))
	won := e.token(refreshForm(id, first.Refresh), "", "")
	if won.status != http.StatusOK {
		t.Fatalf("refresh: %+v", won)
	}
	if r := tokenVia(t, other.Handler(), refreshForm(id, first.Refresh)); r.Error != "invalid_grant" {
		t.Errorf("second presentation on another replica: %+v, want invalid_grant", r)
	}
	if r := tokenVia(t, other.Handler(), refreshForm(id, won.Refresh)); r.status != http.StatusOK {
		t.Errorf("the winner's refresh token on another replica: %+v (the family was revoked)", r)
	}
}

// graceless is a shared cache that predates GraceReplayCache: it embeds
// the interface, not the concrete cache, so RotateGrace is not promoted.
type graceless struct{ ReplayCache }

// A cache without GraceReplayCache gets no grace, and without
// RefreshReuseGrace (the default) there is none: every reuse revokes.
func TestRefreshWithoutGraceRevokes(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Config){
		"graceless cache": func(c *Config) {
			c.Replay = graceless{NewMemoryReplayCache()}
			c.RefreshReuseGrace = testGrace
		},
		"default, no grace": nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newTestEnv(t, true, mutate)
			id, first := e.signIn(newBrowser(t))
			second := e.token(refreshForm(id, first.Refresh), "", "")
			if second.status != http.StatusOK {
				t.Fatalf("refresh: %+v", second)
			}
			if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "invalid_grant" {
				t.Errorf("immediate reuse: %+v, want invalid_grant", r)
			}
			if r := e.token(refreshForm(id, second.Refresh), "", ""); r.Error != "invalid_grant" {
				t.Errorf("the newest refresh token after a reuse: %+v, want invalid_grant (family revoked)", r)
			}
		})
	}
}

// The winner of a concurrent refresh fails for a transient reason after
// the loser was refused in its grace: the rotation is given back, so the
// shared token refreshes again.
func TestRefreshGraceThenTransientFailure(t *testing.T) {
	t.Parallel()
	e := newGraceEnv(t, nil)
	e.google.signInAs = bob
	id, first := e.signIn(newBrowser(t))
	gate := &gateGroups{entered: make(chan struct{}), release: make(chan struct{})}
	e.as.cfg.Admit = newAdmitter(t, failAfter{gate})

	winner := make(chan tokenResp, 1)
	go func() { winner <- tokenVia(t, e.as.Handler(), refreshForm(id, first.Refresh)) }()
	await(t, gate.entered, "the first refresh to reach the gate")
	loser := e.token(refreshForm(id, first.Refresh), "", "")
	close(gate.release)
	won := await(t, winner, "the first refresh")
	if loser.Error != "invalid_grant" || won.Error != "server_error" {
		t.Fatalf("loser %+v, winner %+v: want invalid_grant, server_error", loser, won)
	}
	e.as.cfg.Admit = newAdmitter(t, e.groups)
	if r := e.token(refreshForm(id, first.Refresh), "", ""); r.status != http.StatusOK {
		t.Errorf("retry after the winner's transient failure: %+v", r)
	}
}

// failAfter waits at the gate, then fails the lookup.
type failAfter struct{ g *gateGroups }

func (f failAfter) IsMember(ctx context.Context, group, member string) (bool, error) {
	_, _ = f.g.IsMember(ctx, group, member)
	return false, errors.New("directory unavailable")
}

func TestRefreshReuseGraceConfig(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t, true, nil)
	if e.as.grace != 0 {
		t.Errorf("default grace %v, want none", e.as.grace)
	}
	cfg := e.as.cfg
	cfg.RefreshReuseGrace = -time.Second
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "RefreshReuseGrace") {
		t.Errorf("negative grace: %v, want an error", err)
	}
	cfg.RefreshReuseGrace = 3 * time.Second
	if s, err := New(cfg); err != nil || s.grace != 3*time.Second {
		t.Errorf("3s grace: err %v", err)
	}
	cfg.RefreshReuseGrace = maxRefreshReuseGrace
	if s, err := New(cfg); err != nil || s.grace != maxRefreshReuseGrace {
		t.Errorf("grace at the limit: err %v", err)
	}
	cfg.RefreshReuseGrace = maxRefreshReuseGrace + time.Second
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "RefreshReuseGrace") {
		t.Errorf("grace over the limit: %v, want an error", err)
	}
}
