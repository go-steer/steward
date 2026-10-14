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
// asserts for it (hd), and answers yes or no. An entry is either an exact
// email address or "@domain" for every account of that Workspace domain.
//
// A domain entry needs Google's word. A consumer Google account can carry
// any address that once received its verification mail (a help desk's,
// say), so "dana@example.com" alone proves nothing about example.com's
// Workspace; only hd == "example.com" does. The email suffix never admits.
package allow

import (
	"errors"
	"fmt"
	"strings"
)

// List is a set of admitted accounts. The zero value admits no one, as
// does a List parsed from no entries: an empty allow-list is a
// configuration that lets nobody in, never one that lets everybody in.
//
// A List is immutable after Parse and safe for concurrent use.
type List struct {
	emails  map[string]struct{}
	domains map[string]struct{}
}

// Parse builds a List from entries: exact email addresses, or "@domain".
// Matching is case-insensitive and surrounding space is ignored. An entry
// that is neither, such as "example.com" without the "@" (which would read
// as a domain and silently match nothing), is an error.
func Parse(entries []string) (*List, error) {
	l := &List{emails: map[string]struct{}{}, domains: map[string]struct{}{}}
	var errs []error
	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		switch at := strings.IndexByte(e, '@'); {
		case e == "":
			errs = append(errs, errors.New("allow: empty entry"))
		case strings.ContainsAny(e, " \t\r\n,"):
			errs = append(errs, fmt.Errorf("allow: %q: one address or @domain per entry", raw))
		case at == 0 && validDomain(e[1:]):
			l.domains[e[1:]] = struct{}{}
		case at > 0 && at == strings.LastIndexByte(e, '@') && validDomain(e[at+1:]):
			l.emails[e] = struct{}{}
		default:
			errs = append(errs, fmt.Errorf("allow: %q: want an email address or @domain", raw))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return l, nil
}

// validDomain is a loose check: non-empty labels separated by dots, at
// least two of them. It exists to catch typos, not to validate DNS.
func validDomain(d string) bool {
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
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
// domain Google asserts as hd (empty for a consumer account), is let in.
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

// Empty reports whether the List admits no one.
func (l *List) Empty() bool {
	return l == nil || len(l.emails)+len(l.domains) == 0
}
