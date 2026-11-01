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

// Tests for rotation IDs (RotationIDReplayCache): a refresh that gives
// its rotation back must never give back a concurrent refresh's, or the
// client's retry mints a second live branch of the family.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	errDropped = errors.New("connection reset before the write")
	errLost    = errors.New("timeout after the write")
)

// faultyReplay is one in-memory cache shared by several replicas over a
// network that fails: a rotation can fail without applying (dropped) or
// apply and then fail (its reply lost), and an undo fails on a done
// context, as a networked cache's would. It overrides every rotation
// method, as RotationIDReplayCache tells a wrapper to, and counts which
// ones the server called.
type faultyReplay struct {
	*MemoryReplayCache

	mu         sync.Mutex
	drop, lose int     // fail this many rotations, without and after applying
	twice      int     // deliver this many rotations twice (a client library's retry)
	pDrop      float64 // or fail each with these probabilities
	pLose      float64
	rng        *rand.Rand
	onCancel   string // on a done context: "apply" (then fail), or fail without applying
	calls      map[string]int
}

func newFaultyReplay() *faultyReplay {
	return &faultyReplay{MemoryReplayCache: NewMemoryReplayCache(), calls: map[string]int{}, rng: rand.New(rand.NewPCG(1, 2))}
}

func (c *faultyReplay) called(m string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[m]
}

// faults decides, under the lock, how this call fails.
func (c *faultyReplay) faults(ctx context.Context, method string) (drop, lose bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[method]++
	if err := ctx.Err(); err != nil {
		return c.onCancel != "apply", c.onCancel == "apply", err
	}
	switch {
	case c.drop > 0:
		c.drop--
		return true, false, errDropped
	case c.lose > 0:
		c.lose--
		return false, true, errLost
	case c.pDrop > 0 && c.rng.Float64() < c.pDrop:
		return true, false, errDropped
	case c.pLose > 0 && c.rng.Float64() < c.pLose:
		return false, true, errLost
	}
	return false, false, nil
}

func (c *faultyReplay) rotateVia(ctx context.Context, method string, f func() (RotateResult, error)) (RotateResult, error) {
	drop, lose, ferr := c.faults(ctx, method)
	if drop {
		return RotateRevoked, ferr
	}
	r, err := f()
	c.mu.Lock()
	again := c.twice > 0
	if again {
		c.twice--
	}
	c.mu.Unlock()
	if again {
		r, err = f()
	}
	if lose {
		return RotateRevoked, ferr
	}
	return r, err
}

func (c *faultyReplay) Rotate(ctx context.Context, fam string, gen uint64, exp time.Time) (bool, error) {
	r, err := c.rotateVia(ctx, "Rotate", func() (RotateResult, error) {
		ok, err := c.MemoryReplayCache.Rotate(ctx, fam, gen, exp)
		if ok {
			return RotateApplied, err
		}
		return RotateRevoked, err
	})
	return r == RotateApplied, err
}

func (c *faultyReplay) RotateGrace(ctx context.Context, fam string, gen uint64, exp, graceUntil time.Time) (RotateResult, error) {
	return c.rotateVia(ctx, "RotateGrace", func() (RotateResult, error) {
		return c.MemoryReplayCache.RotateGrace(ctx, fam, gen, exp, graceUntil)
	})
}

func (c *faultyReplay) RotateWithID(ctx context.Context, fam string, gen uint64, exp, graceUntil time.Time, rotation string) (RotateResult, error) {
	return c.rotateVia(ctx, "RotateWithID", func() (RotateResult, error) {
		return c.MemoryReplayCache.RotateWithID(ctx, fam, gen, exp, graceUntil, rotation)
	})
}

func (c *faultyReplay) Unrotate(ctx context.Context, fam string, gen uint64) error {
	if err := c.undoCall(ctx, "Unrotate"); err != nil {
		return err
	}
	return c.MemoryReplayCache.Unrotate(ctx, fam, gen)
}

func (c *faultyReplay) UnrotateWithID(ctx context.Context, fam string, gen uint64, rotation string) error {
	if err := c.undoCall(ctx, "UnrotateWithID"); err != nil {
		return err
	}
	return c.MemoryReplayCache.UnrotateWithID(ctx, fam, gen, rotation)
}

func (c *faultyReplay) undoCall(ctx context.Context, method string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[method]++
	return ctx.Err()
}

// graceOnly is a shared cache that implements GraceReplayCache but not
// RotationIDReplayCache: embedding the interface hides the rest.
type graceOnly struct{ GraceReplayCache }

// The regression: replica B's refresh has rotated the family and is still
// in flight when replica A's Rotate, with the same token, fails without
// applying. A gives back its rotation; it must not give back B's, or the
// client's retry on A rotates the family again and both B's new refresh
// token and the retry's are live: a rotated token has yielded tokens, and
// the family has two branches.
func TestRotateErrorKeepsConcurrentRotation(t *testing.T) {
	t.Parallel()
	for _, grace := range []time.Duration{0, testGrace} {
		t.Run(fmt.Sprintf("grace %v", grace), func(t *testing.T) {
			t.Parallel()
			c := newFaultyReplay()
			e := newTestEnv(t, true, func(cfg *Config) {
				cfg.Replay = c
				cfg.RefreshReuseGrace = grace
			})
			e.google.signInAs = bob // needs the group lookup the gate holds
			id, first := e.signIn(newBrowser(t))
			replicaA, err := New(e.as.cfg)
			if err != nil {
				t.Fatal(err)
			}
			gate := &gateGroups{entered: make(chan struct{}), release: make(chan struct{})}
			e.as.cfg.Admit = newAdmitter(t, gate)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate.release) }) }
			t.Cleanup(release) // a failed assertion must not leave B held

			winner := make(chan tokenResp, 1)
			go func() { winner <- tokenVia(t, e.as.Handler(), refreshForm(id, first.Refresh)) }()
			await(t, gate.entered, "replica B's refresh to reach the gate") // it has rotated the family

			c.mu.Lock()
			c.drop = 1
			c.mu.Unlock()
			if r := tokenVia(t, replicaA.Handler(), refreshForm(id, first.Refresh)); r.Error != "server_error" {
				t.Fatalf("replica A's refresh whose Rotate failed: %+v, want server_error", r)
			}
			release()
			won := await(t, winner, "replica B's refresh")
			if won.status != http.StatusOK {
				t.Fatalf("replica B's refresh: %+v", won)
			}

			// The client retries on replica A with the token B rotated.
			if r := tokenVia(t, replicaA.Handler(), refreshForm(id, first.Refresh)); r.status == http.StatusOK || r.Error != "invalid_grant" {
				t.Fatalf("retry with the token replica B rotated: status %d %q, want invalid_grant (a second branch of the family)", r.status, r.Error)
			}
			next := e.token(refreshForm(id, won.Refresh), "", "")
			switch {
			case grace > 0 && next.status != http.StatusOK:
				t.Errorf("replica B's refresh token after the retry in the grace: %+v (the family was revoked)", next)
			case grace == 0 && next.Error != "invalid_grant":
				t.Errorf("replica B's refresh token after a replay without a grace: %+v, want invalid_grant (family revoked)", next)
			}
			if n := c.called("Unrotate"); n != 0 {
				t.Errorf("Unrotate called %d times with a RotationIDReplayCache", n)
			}
		})
	}
}

// A Rotate cut short by the client going away has an unknown outcome. The
// server gives back its own rotation, detached from the request: if it
// applied, the retry works; if it did not and another refresh rotated the
// family, the retry is a replay. A cache without rotation IDs gets its
// generation-only Unrotate, detached too.
func TestRotateUnknownOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		applied bool
		legacy  bool
	}{{true, false}, {false, false}, {true, true}} {
		applied := tc.applied
		t.Run(fmt.Sprintf("applied %v, legacy %v", applied, tc.legacy), func(t *testing.T) {
			t.Parallel()
			c := newFaultyReplay()
			unrotate := "UnrotateWithID"
			e := newTestEnv(t, true, func(cfg *Config) {
				cfg.Replay = c
				if tc.legacy {
					cfg.Replay = graceless{c}
					unrotate = "Unrotate"
				}
			})
			id, first := e.signIn(newBrowser(t))
			var won tokenResp
			if applied {
				c.mu.Lock()
				c.onCancel = "apply"
				c.mu.Unlock()
			} else {
				// Another replica's refresh with the same token wins first.
				if won = e.token(refreshForm(id, first.Refresh), "", ""); won.status != http.StatusOK {
					t.Fatalf("the concurrent refresh: %+v", won)
				}
			}
			cl, err := e.as.resolveClient(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, PathToken, nil)
			req.PostForm = refreshForm(id, first.Refresh)
			if _, terr := e.as.refreshTokens(ctx, req, cl); terr == nil || terr.Code != "server_error" {
				t.Fatalf("refresh with a cancelled request: %+v, want server_error", terr)
			}
			if n := c.called(unrotate); n != 1 {
				t.Fatalf("%s called %d times, want once", unrotate, n)
			}
			retry := e.token(refreshForm(id, first.Refresh), "", "")
			if applied {
				if retry.status != http.StatusOK {
					t.Errorf("retry after a rotation whose reply was lost: %+v (the family stayed rotated)", retry)
				}
				return
			}
			if retry.status == http.StatusOK || retry.Error != "invalid_grant" {
				t.Errorf("retry with a token another refresh rotated: status %d %q, want invalid_grant", retry.status, retry.Error)
			}
		})
	}
}

// A cache client that delivers a rotation twice (retrying after a reply
// it lost, as network clients do) must not turn the refresh into a replay
// and sign the person out: RotateWithID is idempotent for its own ID.
func TestRotateRedelivered(t *testing.T) {
	t.Parallel()
	for _, grace := range []time.Duration{0, testGrace} {
		t.Run(fmt.Sprintf("grace %v", grace), func(t *testing.T) {
			t.Parallel()
			c := newFaultyReplay()
			e := newTestEnv(t, true, func(cfg *Config) {
				cfg.Replay = c
				cfg.RefreshReuseGrace = grace
			})
			id, first := e.signIn(newBrowser(t))
			c.mu.Lock()
			c.twice = 1
			c.mu.Unlock()
			second := e.token(refreshForm(id, first.Refresh), "", "")
			if second.status != http.StatusOK {
				t.Fatalf("refresh whose rotation was delivered twice: %+v", second)
			}
			if r := e.token(refreshForm(id, second.Refresh), "", ""); r.status != http.StatusOK {
				t.Errorf("its refresh token: %+v (the family was revoked)", r)
			}
		})
	}
}

// Every kind of cache gets its rotation given back after a lost reply and
// after a transient failure later in the refresh; each through its own
// methods. A cache without RotationIDReplayCache keeps the generation-only
// Unrotate, as before (racy under sharing, as ReplayCache.Unrotate says).
func TestUnrotateByCacheKind(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		wrap           func(*faultyReplay) ReplayCache
		grace          time.Duration
		rotate, unrote string
	}{
		{"rotation IDs", func(c *faultyReplay) ReplayCache { return c }, 0, "RotateWithID", "UnrotateWithID"},
		{"rotation IDs with grace", func(c *faultyReplay) ReplayCache { return c }, testGrace, "RotateWithID", "UnrotateWithID"},
		{"grace only", func(c *faultyReplay) ReplayCache { return graceOnly{c} }, testGrace, "RotateGrace", "Unrotate"},
		{"grace only, no grace set", func(c *faultyReplay) ReplayCache { return graceOnly{c} }, 0, "Rotate", "Unrotate"},
		{"neither", func(c *faultyReplay) ReplayCache { return graceless{c} }, testGrace, "Rotate", "Unrotate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newFaultyReplay()
			e := newTestEnv(t, true, func(cfg *Config) {
				cfg.Replay = tc.wrap(c)
				cfg.RefreshReuseGrace = tc.grace
			})
			e.google.signInAs = bob // needs the group check
			id, first := e.signIn(newBrowser(t))

			c.mu.Lock()
			c.lose = 1
			c.mu.Unlock()
			if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" {
				t.Fatalf("refresh whose rotation's reply was lost: %+v", r)
			}
			// A fresh admitter, so no membership it cached at sign-in
			// answers for the directory.
			e.as.cfg.Admit = newAdmitter(t, &fakeGroups{failNext: 1})
			if r := e.token(refreshForm(id, first.Refresh), "", ""); r.Error != "server_error" {
				t.Fatalf("refresh with the directory down: %+v", r)
			}
			e.as.cfg.Admit = newAdmitter(t, e.groups)
			second := e.token(refreshForm(id, first.Refresh), "", "")
			if second.status != http.StatusOK {
				t.Fatalf("retry after two given-back rotations: %+v", second)
			}
			if r := e.token(refreshForm(id, second.Refresh), "", ""); r.status != http.StatusOK {
				t.Errorf("the retry's refresh token: %+v", r)
			}
			if n := c.called(tc.rotate); n != 4 {
				t.Errorf("%s called %d times, want 4", tc.rotate, n)
			}
			if n := c.called(tc.unrote); n != 2 {
				t.Errorf("%s called %d times, want 2", tc.unrote, n)
			}
		})
	}
}

func TestMemoryReplayCacheRotationID(t *testing.T) {
	t.Parallel()
	c := NewMemoryReplayCache()
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()
	exp := now.Add(time.Hour)
	at := func(fam string) family {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.families[fam]
	}
	rotate := func(fam string, gen uint64, grace time.Duration, id string) RotateResult {
		t.Helper()
		var until time.Time
		if grace > 0 {
			until = now.Add(grace)
		}
		r, err := c.RotateWithID(ctx, fam, gen, exp, until, id)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Only the rotation's own ID gives it back, once.
	if r := rotate("a", 0, 0, "a1"); r != RotateApplied || at("a").gen != 1 || at("a").rot != "a1" {
		t.Fatalf("first rotation: %v %+v", r, at("a"))
	}
	// The same rotation delivered again is not a replay.
	if r := rotate("a", 0, 0, "a1"); r != RotateApplied || at("a").gen != 1 || at("a").revoked {
		t.Errorf("the same rotation again: %v %+v, want applied, unchanged", r, at("a"))
	}
	for _, id := range []string{"other", ""} {
		_ = c.UnrotateWithID(ctx, "a", 0, id)
		if at("a").gen != 1 {
			t.Errorf("UnrotateWithID(%q) gave back rotation a1", id)
		}
	}
	_ = c.UnrotateWithID(ctx, "a", 0, "a1")
	if f := at("a"); f.gen != 0 || f.rot != "" {
		t.Errorf("UnrotateWithID(a1): %+v, want generation 0 and no ID", f)
	}
	if r := rotate("a", 0, 0, "a2"); r != RotateApplied {
		t.Errorf("rotation after a give-back: %v", r)
	}
	_ = c.UnrotateWithID(ctx, "a", 0, "a1") // a1 was given back already
	if at("a").gen != 1 {
		t.Error("a given-back rotation's ID gave back the next rotation")
	}

	// The family moved on: neither an older rotation's ID nor, once the
	// newer rotation is given back, the older ID again moves it.
	if r := rotate("a", 1, 0, "a3"); r != RotateApplied {
		t.Fatalf("rotation to generation 3: %v", r)
	}
	_ = c.UnrotateWithID(ctx, "a", 0, "a2")
	_ = c.UnrotateWithID(ctx, "a", 1, "a2")
	if at("a").gen != 2 {
		t.Errorf("an older rotation's ID moved the family: %+v", at("a"))
	}
	_ = c.UnrotateWithID(ctx, "a", 1, "a3")
	_ = c.UnrotateWithID(ctx, "a", 0, "a2") // the family is at 1 again, but a2's rotation is not known to be the one
	if f := at("a"); f.gen != 1 {
		t.Errorf("after giving back a3 and trying a2: %+v, want generation 1", f)
	}

	// A refusal leaves the winner's ID; the loser's ID gives nothing back.
	if r := rotate("g", 0, 10*time.Second, "w"); r != RotateApplied {
		t.Fatal(r)
	}
	if r := rotate("g", 0, 10*time.Second, "l"); r != RotateRefused {
		t.Fatalf("second presentation in the grace: %v", r)
	}
	if r := rotate("g", 0, 10*time.Second, "w"); r != RotateApplied {
		t.Errorf("the winner's rotation delivered again in the grace: %v, want applied", r)
	}
	_ = c.UnrotateWithID(ctx, "g", 0, "l")
	if f := at("g"); f.gen != 1 || f.rot != "w" || f.grace.IsZero() {
		t.Errorf("the refused loser's give-back moved the family: %+v", f)
	}
	_ = c.UnrotateWithID(ctx, "g", 0, "w")
	if f := at("g"); f.gen != 0 || !f.grace.IsZero() {
		t.Errorf("the winner's give-back: %+v, want generation 0 and no grace", f)
	}

	// A revoked family stays revoked; the reuse that revoked it, and the
	// rotation before, give nothing back.
	if r := rotate("r", 0, 0, "r1"); r != RotateApplied {
		t.Fatal(r)
	}
	if r := rotate("r", 0, 0, "r2"); r != RotateRevoked {
		t.Fatalf("reuse without a grace: %v", r)
	}
	_ = c.UnrotateWithID(ctx, "r", 0, "r1")
	_ = c.UnrotateWithID(ctx, "r", 0, "r2")
	if f := at("r"); !f.revoked {
		t.Errorf("UnrotateWithID revived a revoked family: %+v", f)
	}

	// A zero graceUntil is Rotate: no grace recorded, none honoured.
	if r, _ := c.RotateGrace(ctx, "z", 0, exp, now.Add(10*time.Second)); r != RotateApplied {
		t.Fatal(r)
	}
	if r := rotate("z", 0, 0, "z1"); r != RotateRevoked {
		t.Errorf("RotateWithID without a grace, against a recorded one: %v, want revoked", r)
	}
	if r := rotate("z2", 0, 0, "z2"); r != RotateApplied || !at("z2").grace.IsZero() {
		t.Errorf("RotateWithID without a grace recorded one: %+v", at("z2"))
	}

	// Rotations without an ID record none, so no ID gives them back, and
	// Unrotate still gives back any rotation, clearing its ID.
	if ok, _ := c.Rotate(ctx, "p", 0, exp); !ok {
		t.Fatal("Rotate refused a new family")
	}
	_ = c.UnrotateWithID(ctx, "p", 0, "")
	if at("p").gen != 1 {
		t.Error("an empty ID gave back a rotation without one")
	}
	if r := rotate("p", 1, 0, "p2"); r != RotateApplied {
		t.Fatal(r)
	}
	_ = c.Unrotate(ctx, "p", 1)
	if f := at("p"); f.gen != 1 || f.rot != "" {
		t.Errorf("Unrotate of a rotation with an ID: %+v, want generation 1 and no ID", f)
	}
	if r, _ := c.RotateGrace(ctx, "p", 1, exp, time.Time{}); r != RotateApplied {
		t.Fatal(r)
	}
	_ = c.UnrotateWithID(ctx, "p", 1, "p2")
	if at("p").gen != 2 {
		t.Error("a given-back rotation's ID gave back a RotateGrace rotation")
	}

	// A later generation than the family's moves it on and records the ID.
	if r := rotate("p", 7, 0, "p8"); r != RotateApplied || at("p").gen != 8 || at("p").rot != "p8" {
		t.Errorf("rotation from a later generation: %+v", at("p"))
	}

	// Full of live families: refuse rather than forget one.
	full := NewMemoryReplayCache()
	full.now = c.now
	for i := range maxMemoryEntries {
		full.families[fmt.Sprint(i)] = family{gen: 1, exp: exp}
	}
	if r, err := full.RotateWithID(ctx, "new", 0, exp, time.Time{}, "n"); r != RotateRevoked || !errors.Is(err, errReplayFull) {
		t.Errorf("RotateWithID in a full cache: %v %v", r, err)
	}
}

// Many requests rotate the same generation at once, and every one but the
// winner gives its rotation back (each as a request whose Rotate failed
// without applying would): exactly one applies each round, and the
// family stays where the winner put it.
func TestMemoryReplayCacheRotationIDConcurrent(t *testing.T) {
	t.Parallel()
	c := NewMemoryReplayCache()
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	const rounds, n = 200, 8
	for gen := range uint64(rounds) {
		var wg sync.WaitGroup
		var applied atomic.Int32
		start := make(chan struct{})
		for i := range n {
			wg.Go(func() {
				id := fmt.Sprintf("%d-%d", gen, i)
				<-start
				r, err := c.RotateWithID(ctx, "f", gen, exp, time.Now().Add(time.Minute), id)
				if err != nil {
					t.Error(err)
					return
				}
				if r == RotateApplied {
					applied.Add(1)
					return
				}
				_ = c.UnrotateWithID(ctx, "f", gen, id)
			})
		}
		close(start)
		wg.Wait()
		if a := applied.Load(); a != 1 {
			t.Fatalf("generation %d: %d rotations applied, want 1", gen, a)
		}
		c.mu.Lock()
		f := c.families["f"]
		c.mu.Unlock()
		if f.gen != gen+1 || f.revoked {
			t.Fatalf("generation %d: family %+v after the losers' give-backs, want generation %d", gen, f, gen+1)
		}
	}
}

// Clients on two replicas sharing a cache that drops writes and loses
// replies refresh with one token at once and retry on server_error: the
// token yields tokens at most once, and the winner's refresh token works.
// (A lost reply exercises giving back a rotation that applied; a transient
// failure later in the refresh gives it back the same way.)
func TestRefreshStressSharedCache(t *testing.T) {
	t.Parallel()
	c := newFaultyReplay()
	e := newTestEnv(t, true, func(cfg *Config) {
		cfg.Replay = c
		cfg.RefreshReuseGrace = time.Minute
	})
	other, err := New(e.as.cfg)
	if err != nil {
		t.Fatal(err)
	}
	replicas := []http.Handler{e.as.Handler(), other.Handler()}
	const rounds, clients, tries = 30, 6, 4
	winners := 0
	for round := range rounds {
		c.mu.Lock()
		c.pDrop, c.pLose = 0, 0
		c.mu.Unlock()
		id, first := e.signIn(newBrowser(t))

		c.mu.Lock()
		c.pDrop, c.pLose = 0.3, 0.2
		c.mu.Unlock()
		var wg sync.WaitGroup
		var mu sync.Mutex
		var won []tokenResp
		start := make(chan struct{})
		for i := range clients {
			wg.Go(func() {
				<-start
				for try := range tries {
					r := tokenVia(t, replicas[(i+try)%2], refreshForm(id, first.Refresh))
					if r.status == http.StatusOK {
						mu.Lock()
						won = append(won, r)
						mu.Unlock()
					}
					if r.Error != "server_error" {
						return
					}
				}
			})
		}
		close(start)
		wg.Wait()

		c.mu.Lock()
		c.pDrop, c.pLose = 0, 0
		c.mu.Unlock()
		switch len(won) {
		case 0:
		case 1:
			winners++
			if r := e.token(refreshForm(id, won[0].Refresh), "", ""); r.status != http.StatusOK {
				t.Errorf("round %d: the winner's refresh token: %+v", round, r)
			}
		default:
			t.Fatalf("round %d: one refresh token yielded tokens %d times", round, len(won))
		}
	}
	if winners == 0 {
		t.Error("no round had a winner: the faults are too dense to test anything")
	}
}
