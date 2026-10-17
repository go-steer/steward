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
	"time"
)

// ErrNotAdmitted is an account the allow-list does not admit. Any other
// error from Admitter.Admit is a check that failed, not a refusal.
var ErrNotAdmitted = errors.New("allow: account not admitted")

// GroupChecker answers whether member (an email address) is in group (a
// group's email address), directly or through nested groups. An error
// means it could not tell; it must never report a failed lookup as false.
type GroupChecker interface {
	IsMember(ctx context.Context, group, member string) (bool, error)
}

// Limits on the Admitter's verdict cache.
const (
	// GroupVerdictTTL is how long a group verdict (admitted or not) is
	// reused. Removing someone from a group takes effect within this.
	GroupVerdictTTL = 5 * time.Minute
	// maxVerdicts bounds the verdict cache.
	maxVerdicts = 4096
)

// Admitter answers for every kind of entry in a List: emails and domains
// from the list itself, groups by asking a GroupChecker. Group verdicts
// are cached per account for GroupVerdictTTL; a failed check is not
// cached. It is safe for concurrent use.
type Admitter struct {
	list   *List
	groups []string
	check  GroupChecker
	now    func() time.Time

	mu       sync.Mutex
	verdicts map[string]verdict
}

type verdict struct {
	admitted bool
	at       time.Time
}

// NewAdmitter pairs l with the GroupChecker its group entries need.
// checker may be nil only if l has no group entries. An empty list is
// refused: a surface that can admit no one is a configuration mistake.
func NewAdmitter(l *List, checker GroupChecker) (*Admitter, error) {
	if l.Empty() {
		return nil, errors.New("allow: NewAdmitter: empty allow-list: it admits no one")
	}
	groups := l.Groups()
	if len(groups) > 0 && checker == nil {
		return nil, fmt.Errorf("allow: NewAdmitter: the list has group entries (%s) but no GroupChecker to look them up", strings.Join(groups, ", "))
	}
	return &Admitter{list: l, groups: groups, check: checker, now: time.Now, verdicts: map[string]verdict{}}, nil
}

// List returns the list the Admitter answers for.
func (a *Admitter) List() *List { return a.list }

// Admit returns nil if the account with this email and Google-asserted
// Workspace domain hd is let in, ErrNotAdmitted if it is not, or another
// error if a group lookup failed (retryable, and not cached). Email and
// domain entries are tried first, so an account they admit never costs a
// directory call.
func (a *Admitter) Admit(ctx context.Context, email, hd string) error {
	if a.list.Admits(email, hd) {
		return nil
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if len(a.groups) == 0 || strings.LastIndexByte(email, '@') <= 0 {
		return ErrNotAdmitted
	}
	now := a.now()
	a.mu.Lock()
	v, ok := a.verdicts[email]
	a.mu.Unlock()
	if ok && now.Sub(v.at) < GroupVerdictTTL {
		return admitted(v.admitted)
	}
	in := false
	for _, g := range a.groups {
		member, err := a.check.IsMember(ctx, g, email)
		if err != nil {
			return fmt.Errorf("allow: check group %s: %w", g, err)
		}
		if member {
			in = true
			break
		}
	}
	a.mu.Lock()
	if len(a.verdicts) >= maxVerdicts {
		for k, v := range a.verdicts {
			if now.Sub(v.at) >= GroupVerdictTTL {
				delete(a.verdicts, k)
			}
		}
		if len(a.verdicts) >= maxVerdicts {
			clear(a.verdicts)
		}
	}
	a.verdicts[email] = verdict{admitted: in, at: now}
	a.mu.Unlock()
	return admitted(in)
}

func admitted(ok bool) error {
	if ok {
		return nil
	}
	return ErrNotAdmitted
}
