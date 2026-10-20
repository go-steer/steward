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

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ReplayCache is the server's one piece of state: it spends authorization
// codes, and tracks refresh-token families so that a rotated refresh token
// is never accepted again (OAuth 2.1 section 4.3.1).
//
// Every refresh token belongs to a family, started when its sign-in's code
// was exchanged, and carries a generation number. A refresh moves the
// family from the presented token's generation to the next. Presenting a
// generation the family has already moved past is a replay: one of the
// two holders of the token is not the client it was issued to, so the
// family is revoked and every token in it refused, and the user signs in
// again. Storage grows with live families (one per sign-in per client),
// not with refreshes. A cache that also implements GraceReplayCache spares
// the generation a family has only just moved away from: presented again
// within a few seconds, it is refused without revoking the family.
//
// A shared implementation (for a service running several replicas) must:
//
//   - be safe for concurrent use, and atomic per ID and per family (a
//     compare-and-set, a transaction or a script);
//   - keep every claim and every family until its exp, never evicting one
//     early: a forgotten family accepts any generation, which turns reuse
//     detection off, and a forgotten claim lets a code be used twice;
//   - keep a revocation until the family's exp;
//   - make an error mean "not applied", as far as it can tell; the server
//     follows a Rotate error with an Unrotate in case it was applied anyway.
//
// An error is a cache that could not answer; the token endpoint then
// answers server_error and spends nothing.
type ReplayCache interface {
	// Claim spends a single-use ID until exp. It reports false if the ID
	// was already spent (and that claim has not expired).
	Claim(ctx context.Context, id string, exp time.Time) (bool, error)
	// Release gives back a claim, after a use that failed for a transient
	// reason, so the client's retry is not refused as a replay.
	Release(ctx context.Context, id string) error
	// Rotate moves family from generation gen to gen+1 and sets its exp.
	// It reports false, and revokes the family until its current exp, if
	// the family is past gen; false also for a revoked family. An unknown
	// (or expired) family is created at gen+1. A family at an earlier
	// generation is moved to gen+1: with a cache that loses state (one per
	// replica, or one that restarts), another replica may have rotated it.
	Rotate(ctx context.Context, family string, gen uint64, exp time.Time) (bool, error)
	// Unrotate moves family back from gen+1 to gen, leaving its exp, after
	// a refresh that failed for a transient reason. It does nothing for a
	// family that has moved on, been revoked, expired or is unknown. A
	// GraceReplayCache also forgets the grace the undone rotation recorded.
	Unrotate(ctx context.Context, family string, gen uint64) error
}

// RotateResult is a GraceReplayCache's answer to a refresh.
type RotateResult int

const (
	// RotateRevoked refuses the refresh: the family was past the presented
	// generation and is now revoked, or was revoked already. It is the zero
	// value, so a result left unset refuses.
	RotateRevoked RotateResult = iota
	// RotateApplied moved the family to the next generation.
	RotateApplied
	// RotateRefused refuses the refresh and leaves the family as it is,
	// not revoked: the presented generation is the one the family last
	// moved away from, within that move's grace.
	RotateRefused
)

// GraceReplayCache is a ReplayCache that tells a concurrent refresh from a
// replay. Clients whose processes share one token store can present the
// same refresh token twice within milliseconds; with Rotate alone the
// second presentation revokes the family, and the first one's new token
// with it. When Config.Replay implements GraceReplayCache, the server
// calls RotateGrace instead of Rotate (unless Config.RefreshReuseGrace is
// negative), and a second presentation within the grace is refused
// without revoking, so the client can re-read its store and find the new
// token. Nothing is ever issued for a rotated generation either way.
//
// A shared implementation keeps one more value per family, the grace
// deadline of its last rotation, under the guarantees ReplayCache states:
// checked and set atomically with the generation, kept until the
// family's exp. Its Rotate neither records nor honours a grace.
//
// A wrapper that embeds a GraceReplayCache (a *MemoryReplayCache, say)
// and overrides Rotate must override RotateGrace too, or the server calls
// the embedded RotateGrace and skips the override.
type GraceReplayCache interface {
	ReplayCache
	// RotateGrace is Rotate, except that:
	//
	//   - a rotation (to gen+1, from any starting point Rotate allows)
	//     records graceUntil with the family;
	//   - presenting gen when the family is at gen+1, before the graceUntil
	//     that rotation recorded, is RotateRefused: the family is left as
	//     it is, not revoked;
	//   - any older generation, the same one at or after graceUntil, or any
	//     generation of a revoked family, is RotateRevoked, and the family
	//     is revoked as Rotate revokes it.
	//
	// graceUntil, like exp, is an absolute time from the server's clock;
	// the zero time grants no grace. An error is reported as by Rotate.
	RotateGrace(ctx context.Context, family string, gen uint64, exp, graceUntil time.Time) (RotateResult, error)
}

// maxMemoryEntries bounds each of the in-memory cache's two tables (an
// entry is about a hundred bytes, and only a signed-in user's code
// exchange or refresh adds one). Past it, expired entries are swept; if
// none have expired, the new one is refused rather than an old one
// forgotten.
const maxMemoryEntries = 1 << 20

// MemoryReplayCache is the in-memory ReplayCache: per process, and
// forgotten on restart. With several replicas each keeping its own, reuse
// detection is per replica: a stolen refresh token can go on being used on
// a replica that never saw the family revoked, and a code can be exchanged
// once on each (PKCE still binds it to its client's verifier). A service
// running replicas supplies a shared ReplayCache.
type MemoryReplayCache struct {
	mu       sync.Mutex
	codes    map[string]time.Time
	families map[string]family
	now      func() time.Time

	codesSwept, familiesSwept time.Time
}

// sweepEvery limits how often a full table is swept for expired entries,
// so a table full of live entries does not cost a full walk per request.
const sweepEvery = 10 * time.Second

type family struct {
	gen     uint64
	exp     time.Time
	revoked bool
	// grace is when the last rotation's grace runs out: until then,
	// presenting gen-1 is refused without revoking the family.
	grace time.Time
}

// NewMemoryReplayCache returns an empty in-memory ReplayCache. It is a
// GraceReplayCache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{codes: map[string]time.Time{}, families: map[string]family{}, now: time.Now}
}

var _ GraceReplayCache = (*MemoryReplayCache)(nil)

// errReplayFull is the in-memory cache refusing an entry it has no room
// for: refusing is safe, forgetting an entry is not.
var errReplayFull = errors.New("authserver: replay cache is full")

// Claim implements ReplayCache.
func (c *MemoryReplayCache) Claim(_ context.Context, id string, exp time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.codes[id]; ok && now.Before(e) {
		return false, nil
	}
	if len(c.codes) >= maxMemoryEntries {
		if now.Sub(c.codesSwept) >= sweepEvery {
			c.codesSwept = now
			for k, e := range c.codes {
				if !now.Before(e) {
					delete(c.codes, k)
				}
			}
		}
		if len(c.codes) >= maxMemoryEntries {
			return false, errReplayFull
		}
	}
	c.codes[id] = exp
	return true, nil
}

// Release implements ReplayCache.
func (c *MemoryReplayCache) Release(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.codes, id)
	return nil
}

// Rotate implements ReplayCache. It grants no grace and honours none a
// RotateGrace recorded: every reuse revokes, as ReplayCache states.
func (c *MemoryReplayCache) Rotate(_ context.Context, fam string, gen uint64, exp time.Time) (bool, error) {
	r, err := c.rotate(fam, gen, exp, time.Time{}, false)
	return r == RotateApplied, err
}

// RotateGrace implements GraceReplayCache.
func (c *MemoryReplayCache) RotateGrace(_ context.Context, fam string, gen uint64, exp, graceUntil time.Time) (RotateResult, error) {
	return c.rotate(fam, gen, exp, graceUntil, true)
}

// rotate is Rotate, and with honourGrace RotateGrace.
func (c *MemoryReplayCache) rotate(fam string, gen uint64, exp, graceUntil time.Time, honourGrace bool) (RotateResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if f, ok := c.families[fam]; ok && now.Before(f.exp) {
		if f.revoked {
			return RotateRevoked, nil
		}
		if gen < f.gen {
			if honourGrace && gen+1 == f.gen && now.Before(f.grace) {
				// The generation the family has only just moved away
				// from, most likely from a second process sharing the
				// client's token store: refuse it, keep the family.
				return RotateRefused, nil
			}
			// A generation the family has moved past: revoke.
			f.revoked = true
			c.families[fam] = f
			return RotateRevoked, nil
		}
		// gen == f.gen, or a later generation: only another replica (or
		// this one before a restart) can have minted it, since tokens are
		// sealed, so move on.
		c.families[fam] = family{gen: gen + 1, exp: exp, grace: graceUntil}
		return RotateApplied, nil
	}
	if len(c.families) >= maxMemoryEntries {
		if now.Sub(c.familiesSwept) >= sweepEvery {
			c.familiesSwept = now
			for k, f := range c.families {
				if !now.Before(f.exp) {
					delete(c.families, k)
				}
			}
		}
		if len(c.families) >= maxMemoryEntries {
			return RotateRevoked, errReplayFull
		}
	}
	c.families[fam] = family{gen: gen + 1, exp: exp, grace: graceUntil}
	return RotateApplied, nil
}

// Unrotate implements ReplayCache.
func (c *MemoryReplayCache) Unrotate(_ context.Context, fam string, gen uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.families[fam]; ok && !f.revoked && f.gen == gen+1 {
		// The grace was the undone rotation's: gen-1 was rotated away
		// before it, so presenting gen-1 is a replay again.
		f.gen, f.grace = gen, time.Time{}
		c.families[fam] = f
	}
	return nil
}
