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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLoad hands out the keyring it holds, or its error.
type fakeLoad struct {
	mu      sync.Mutex
	kr      *Keyring
	err     error
	panic   bool
	block   chan struct{}
	calls   atomic.Int32
	lastCtx context.Context
}

func (f *fakeLoad) load(ctx context.Context) (*Keyring, error) {
	f.calls.Add(1)
	f.mu.Lock()
	block := f.block
	f.lastCtx = ctx
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panic {
		panic("load exploded")
	}
	return f.kr, f.err
}

func (f *fakeLoad) set(kr *Keyring, err error) {
	f.mu.Lock()
	f.kr, f.err = kr, err
	f.mu.Unlock()
}

// syncBuffer is a log sink safe to write from the load goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// clock is a settable time source safe across goroutines.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClockedReloader(f *fakeLoad, logTo *syncBuffer) (*Reloader, *clock) {
	var log *slog.Logger
	if logTo != nil {
		log = slog.New(slog.NewTextHandler(logTo, nil))
	}
	r := NewReloader(f.load, 0, log)
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	r.now = c.now
	return r, c
}

// settle waits for any background load to finish.
func settle(t *testing.T, r *Reloader) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		idle := r.inflight == nil
		r.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("background load never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

// keyringAfterReload triggers a due reload, waits for it, and returns what
// the next caller gets.
func keyringAfterReload(t *testing.T, r *Reloader) *Keyring {
	t.Helper()
	if _, err := r.Keyring(context.Background()); err != nil {
		t.Fatal(err)
	}
	settle(t, r)
	kr, err := r.Keyring(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestReloaderRotates(t *testing.T) {
	t.Parallel()
	k1, _ := NewKeyring(key("k1", '1'))
	k2, _ := NewKeyring(key("k2", '2'), key("k1", '1'))
	f := &fakeLoad{kr: k1}
	r, c := newClockedReloader(f, nil)
	ctx := context.Background()
	if got, err := r.Keyring(ctx); got != k1 || err != nil {
		t.Fatalf("first load: %v, %v", got, err)
	}
	f.set(k2, nil)
	c.add(DefaultReloadEvery - time.Second)
	if got := keyringAfterReload(t, r); got != k1 || f.calls.Load() != 1 {
		t.Errorf("before the interval: %v after %d loads, want the cached keyring", got.KeyIDs(), f.calls.Load())
	}
	c.add(2 * time.Second)
	if got := keyringAfterReload(t, r); got != k2 {
		t.Errorf("after the interval: %v, want the rotated keyring", got.KeyIDs())
	}
}

// A failed reload keeps the previous keyring and retries soon; the first
// load's failure is the caller's.
func TestReloaderKeepsPreviousOnFailure(t *testing.T) {
	t.Parallel()
	k1, _ := NewKeyring(key("k1", '1'))
	k2, _ := NewKeyring(key("k2", '2'))
	f := &fakeLoad{err: errors.New("key store down")}
	logged := &syncBuffer{}
	r, c := newClockedReloader(f, logged)
	ctx := context.Background()
	if _, err := r.Keyring(ctx); err == nil || !strings.Contains(err.Error(), "key store down") {
		t.Fatalf("first load failure: %v, want it returned", err)
	}
	f.set(nil, nil)
	if _, err := r.Keyring(ctx); err == nil {
		t.Fatal("a LoadFunc returning no keyring was accepted")
	}
	f.set(k1, nil)
	if got, err := r.Keyring(ctx); got != k1 || err != nil {
		t.Fatalf("load after recovery: %v, %v", got, err)
	}
	f.set(nil, errors.New("key store down"))
	c.add(DefaultReloadEvery)
	if got := keyringAfterReload(t, r); got != k1 {
		t.Errorf("failed reload: %v; want the previous keyring", got.KeyIDs())
	}
	if !strings.Contains(logged.String(), "key store down") {
		t.Errorf("failed reload not logged: %q", logged.String())
	}
	f.set(nil, nil)
	c.add(reloadRetry)
	if got := keyringAfterReload(t, r); got != k1 {
		t.Errorf("reload returning nil replaced the keyring with %v", got)
	}
	f.set(k2, nil)
	c.add(reloadRetry - time.Second)
	if got := keyringAfterReload(t, r); got != k1 {
		t.Errorf("retried before reloadRetry: got %v", got.KeyIDs())
	}
	c.add(time.Second)
	if got := keyringAfterReload(t, r); got != k2 {
		t.Errorf("after reloadRetry: %v, want the new keyring", got.KeyIDs())
	}
}

// While a reload runs, callers go on with the previous keyring instead of
// queueing behind the key store, and only one load runs.
func TestReloaderDoesNotBlockOnReload(t *testing.T) {
	t.Parallel()
	k1, _ := NewKeyring(key("k1", '1'))
	k2, _ := NewKeyring(key("k2", '2'))
	f := &fakeLoad{kr: k1}
	r, c := newClockedReloader(f, nil)
	ctx := context.Background()
	if _, err := r.Keyring(ctx); err != nil {
		t.Fatal(err)
	}
	f.set(k2, nil)
	block := make(chan struct{})
	f.mu.Lock()
	f.block = block
	f.mu.Unlock()
	c.add(DefaultReloadEvery)
	if got, _ := r.Keyring(ctx); got != k1 {
		t.Errorf("triggering a reload: %v, want the previous keyring", got.KeyIDs())
	}
	for f.calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	for range 5 {
		if got, _ := r.Keyring(ctx); got != k1 {
			t.Errorf("during a reload: %v, want the previous keyring", got.KeyIDs())
		}
	}
	if n := f.calls.Load(); n != 2 {
		t.Errorf("%d loads in all for five callers during one reload, want 2", n)
	}
	close(block)
	settle(t, r)
	if got, _ := r.Keyring(ctx); got != k2 {
		t.Errorf("after the reload: %v", got.KeyIDs())
	}
}

// Concurrent first callers share one load; a caller whose context ends
// stops waiting without failing the load for the others, and the load does
// not run under that caller's context.
func TestReloaderFirstLoadShared(t *testing.T) {
	t.Parallel()
	k1, _ := NewKeyring(key("k1", '1'))
	block := make(chan struct{})
	f := &fakeLoad{kr: k1, block: block}
	r, _ := newClockedReloader(f, nil)

	gone, cancel := context.WithCancel(context.Background())
	quit := make(chan error)
	go func() { _, err := r.Keyring(gone); quit <- err }()
	for f.calls.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	var wg sync.WaitGroup
	got := make([]*Keyring, 8)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[i], _ = r.Keyring(context.Background()) }()
	}
	cancel()
	if err := <-quit; !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled waiter: %v, want context.Canceled", err)
	}
	close(block)
	wg.Wait()
	for i, kr := range got {
		if kr != k1 {
			t.Errorf("waiter %d got %v", i, kr)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("%d loads for nine first callers, want 1", n)
	}
	f.mu.Lock()
	lctx := f.lastCtx
	f.mu.Unlock()
	if _, ok := lctx.Deadline(); !ok {
		t.Error("the load ran without a timeout")
	}
}

func TestReloaderPanicIsAFailedLoad(t *testing.T) {
	t.Parallel()
	k1, _ := NewKeyring(key("k1", '1'))
	f := &fakeLoad{kr: k1, panic: true}
	r, c := newClockedReloader(f, nil)
	ctx := context.Background()
	if _, err := r.Keyring(ctx); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("first load panicked: %v, want an error", err)
	}
	f.mu.Lock()
	f.panic = false
	f.mu.Unlock()
	if _, err := r.Keyring(ctx); err != nil {
		t.Fatalf("after a panicking first load: %v", err)
	}
	f.mu.Lock()
	f.panic = true
	f.mu.Unlock()
	c.add(DefaultReloadEvery)
	if got := keyringAfterReload(t, r); got != k1 {
		t.Errorf("panicking reload: %v, want the previous keyring", got)
	}
}

func TestReloaderNoLoad(t *testing.T) {
	t.Parallel()
	var nilR *Reloader
	for _, r := range []*Reloader{nilR, NewReloader(nil, time.Minute, nil)} {
		if _, err := r.Keyring(context.Background()); err == nil {
			t.Error("a Reloader with no LoadFunc returned a keyring")
		}
	}
}
