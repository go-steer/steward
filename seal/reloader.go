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
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// LoadFunc fetches the current keyring.
type LoadFunc func(ctx context.Context) (*Keyring, error)

// FileLoader loads the keyring file at path (ParseKeyring's form), for
// example a Secret Manager secret or a Kubernetes Secret mounted as a file.
func FileLoader(path string) LoadFunc {
	return func(context.Context) (*Keyring, error) { return LoadKeyring(path) }
}

// Reloader timings.
const (
	// DefaultReloadEvery is how long a loaded keyring is used before it
	// is loaded again.
	DefaultReloadEvery = 5 * time.Minute
	// LoadTimeout bounds one load. A load runs detached from the context
	// of the request that triggered it, so one client going away does not
	// fail the load for everyone else.
	LoadTimeout = 30 * time.Second
	// reloadRetry is how soon a failed reload is retried; until then the
	// previous keyring stays in use.
	reloadRetry = 30 * time.Second
)

// Reloader is a KeyProvider that loads the keyring and loads it again
// every so often, so a rotation takes effect without a restart. See the
// package doc for rotating safely across replicas.
//
// One load runs at a time, in the background. Until the first load
// succeeds, callers wait for it (or for their own context) and share its
// result, error included; call Keyring once at startup to fail fast on a
// misconfiguration. After that, a stale keyring is reloaded in the
// background while every caller goes on with the previous one, and a
// failed reload keeps the previous keyring (logged, retried 30 s later):
// a key store that is down for a minute must not sign everyone out. A
// LoadFunc that panics is a failed load.
type Reloader struct {
	load  LoadFunc
	every time.Duration
	log   *slog.Logger
	now   func() time.Time

	mu       sync.Mutex
	kr       *Keyring
	next     time.Time     // when kr is next reloaded
	inflight chan struct{} // closed when the running load finishes; nil if none
	lastErr  error         // the last failed first load, for its waiters
}

var _ KeyProvider = (*Reloader)(nil)

// NewReloader returns a Reloader over load. every <= 0 means
// DefaultReloadEvery. logger receives failed reloads; nil means no
// logging.
func NewReloader(load LoadFunc, every time.Duration, logger *slog.Logger) *Reloader {
	if every <= 0 {
		every = DefaultReloadEvery
	}
	return &Reloader{load: load, every: every, log: logger, now: time.Now}
}

// Keyring implements KeyProvider.
func (r *Reloader) Keyring(ctx context.Context) (*Keyring, error) {
	if r == nil || r.load == nil {
		return nil, errors.New("seal: Reloader has no LoadFunc")
	}
	r.mu.Lock()
	if r.kr != nil {
		kr := r.kr
		if r.inflight == nil && !r.now().Before(r.next) {
			r.startLoad(ctx)
		}
		r.mu.Unlock()
		return kr, nil
	}
	// No keyring yet: everyone waits for one load and shares its result.
	if r.inflight == nil {
		r.startLoad(ctx)
	}
	done := r.inflight
	r.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kr != nil {
		return r.kr, nil
	}
	return nil, r.lastErr
}

// startLoad runs one load in the background. Call with r.mu held and no
// load in flight.
func (r *Reloader) startLoad(ctx context.Context) {
	done := make(chan struct{})
	r.inflight = done
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), LoadTimeout)
	go func() {
		defer cancel()
		kr, err := r.safeLoad(lctx)
		r.mu.Lock()
		r.finish(lctx, kr, err)
		r.inflight = nil
		r.mu.Unlock()
		close(done)
	}()
}

// safeLoad runs the LoadFunc, turning a panic or a nil keyring into an
// error: the load runs on its own goroutine, where a panic would take the
// process down.
func (r *Reloader) safeLoad(ctx context.Context) (kr *Keyring, err error) {
	defer func() {
		if p := recover(); p != nil {
			kr, err = nil, fmt.Errorf("seal: LoadFunc panicked: %v", p)
		}
	}()
	kr, err = r.load(ctx)
	if err == nil && kr == nil {
		err = errors.New("seal: LoadFunc returned no keyring")
	}
	return kr, err
}

// finish records a load's result. Call with r.mu held.
func (r *Reloader) finish(ctx context.Context, kr *Keyring, err error) {
	if err == nil {
		r.kr, r.next, r.lastErr = kr, r.now().Add(r.every), nil
		return
	}
	if r.kr == nil {
		r.lastErr = fmt.Errorf("seal: load keyring: %w", err)
		return
	}
	if r.log != nil {
		r.log.WarnContext(ctx, "seal: could not reload the keyring; keeping the previous one", "err", err, "retry_in", reloadRetry)
	}
	r.next = r.now().Add(reloadRetry)
}
