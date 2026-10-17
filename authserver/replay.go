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
// not with refreshes.
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
	// family that has moved on, been revoked, expired or is unknown.
	Unrotate(ctx context.Context, family string, gen uint64) error
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
}

// NewMemoryReplayCache returns an empty in-memory ReplayCache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{codes: map[string]time.Time{}, families: map[string]family{}, now: time.Now}
}

var _ ReplayCache = (*MemoryReplayCache)(nil)

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

// Rotate implements ReplayCache.
func (c *MemoryReplayCache) Rotate(_ context.Context, fam string, gen uint64, exp time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if f, ok := c.families[fam]; ok && now.Before(f.exp) {
		if f.revoked {
			return false, nil
		}
		if gen < f.gen {
			// A generation the family has moved past: revoke.
			f.revoked = true
			c.families[fam] = f
			return false, nil
		}
		// gen == f.gen, or a later generation: only another replica (or
		// this one before a restart) can have minted it, since tokens are
		// sealed, so move on.
		c.families[fam] = family{gen: gen + 1, exp: exp}
		return true, nil
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
			return false, errReplayFull
		}
	}
	c.families[fam] = family{gen: gen + 1, exp: exp}
	return true, nil
}

// Unrotate implements ReplayCache.
func (c *MemoryReplayCache) Unrotate(_ context.Context, fam string, gen uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.families[fam]; ok && !f.revoked && f.gen == gen+1 {
		f.gen = gen
		c.families[fam] = f
	}
	return nil
}
