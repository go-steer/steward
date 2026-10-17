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

// Package allow decides which verified Google accounts are let in.
//
// It runs after a token has been verified, and knows nothing about
// tokens: it is given an account's email and the Workspace domain Google
// asserts for it (hd), and answers yes or no. An entry is an exact email
// address, "@domain" for every account of that Workspace domain, or
// "group:<group email>" for every member of a Google group, directly or
// through nested groups.
//
// A domain entry needs Google's word. A consumer Google account can carry
// any address that once received its verification mail (a help desk's,
// say), so "dana@example.com" alone proves nothing about example.com's
// Workspace; only hd == "example.com" does. The email suffix never admits.
//
// A group entry needs a directory. List.Admits answers from the list alone
// and never admits through a group; an Admitter pairs a List with a
// GroupChecker (CloudIdentityGroups, as the service's own identity) and
// answers for all three kinds. A failed group check is an error, never a
// "no": the directory not answering is not the directory refusing.
package allow

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// GroupPrefix marks a group entry: "group:eng@example.com".
const GroupPrefix = "group:"

// List is a set of admitted accounts. The zero value admits no one, as
// does a List parsed from no entries: an empty allow-list is a
// configuration that lets nobody in, never one that lets everybody in.
//
// A List is immutable after Parse and safe for concurrent use.
type List struct {
	emails  map[string]struct{}
	domains map[string]struct{}
	groups  map[string]struct{}
}

// Parse builds a List from entries: exact email addresses, "@domain", or
// "group:<group email>". Matching is case-insensitive and surrounding
// space is ignored. An entry that is none of these, such as "example.com"
// without the "@" (which would read as a domain and silently match
// nothing), is an error.
func Parse(entries []string) (*List, error) {
	l := &List{emails: map[string]struct{}{}, domains: map[string]struct{}{}, groups: map[string]struct{}{}}
	var errs []error
	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		group, isGroup := strings.CutPrefix(e, GroupPrefix)
		switch {
		case e == "":
			errs = append(errs, errors.New("allow: empty entry"))
		case strings.ContainsAny(e, " \t\r\n,"):
			errs = append(errs, fmt.Errorf("allow: %q: one address, @domain or group: entry each", raw))
		case isGroup && validEmail(group):
			l.groups[group] = struct{}{}
		case isGroup:
			errs = append(errs, fmt.Errorf("allow: %q: want group:<group email address>", raw))
		case strings.HasPrefix(e, "@") && validDomain(e[1:]):
			l.domains[e[1:]] = struct{}{}
		case validEmail(e):
			l.emails[e] = struct{}{}
		default:
			errs = append(errs, fmt.Errorf("allow: %q: want an email address, @domain or group:<group email>", raw))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return l, nil
}

// validEmail is a loose check: exactly one "@", a local part before it and
// a valid domain after it.
func validEmail(e string) bool {
	at := strings.IndexByte(e, '@')
	return at > 0 && at == strings.LastIndexByte(e, '@') && validDomain(e[at+1:])
}

// validDomain is a loose check: non-empty labels separated by dots, at
// least two of them. It exists to catch typos, not to validate DNS.
func validDomain(d string) bool {
	labels := strings.Split(d, ".")
	if len(labels) < 2 || strings.Contains(d, "@") {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
	}
	return true
}

// Admits reports whether the account with this email, whose Workspace
// domain Google asserts as hd (empty for a consumer account), is let in by
// an email or domain entry. It never admits through a group entry, which
// needs a directory lookup: use an Admitter for a list with groups.
func (l *List) Admits(email, hd string) bool {
	if l == nil {
		return false
	}
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at <= 0 {
		return false
	}
	if _, ok := l.emails[email]; ok {
		return true
	}
	hd = strings.ToLower(strings.TrimSpace(hd))
	if hd == "" || hd != email[at+1:] {
		return false
	}
	_, ok := l.domains[hd]
	return ok
}

// Empty reports whether the List has no entries, and so admits no one.
func (l *List) Empty() bool {
	return l == nil || len(l.emails)+len(l.domains)+len(l.groups) == 0
}

// Groups returns the group entries' addresses, lower-cased and sorted,
// without the "group:" prefix. Nil for a List without group entries.
func (l *List) Groups() []string {
	if l == nil || len(l.groups) == 0 {
		return nil
	}
	gs := make([]string, 0, len(l.groups))
	for g := range l.groups {
		gs = append(gs, g)
	}
	slices.Sort(gs)
	return gs
}
