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

// Ported from kode-gopher internal/oauth (units_test.go,
// groups_walk_test.go) at 8b53617b7d4d0b08b158de64ab7416dc84a1281e.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func TestCloudIdentityGroups(t *testing.T) {
	t.Parallel()
	var lookups atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/groups:lookup" && r.URL.Query().Get("groupKey.id") == "g@cymbal.example":
			lookups.Add(1)
			writeJSON(w, http.StatusOK, map[string]string{"name": "groups/abc"})
		case r.URL.Path == "/groups:lookup" && r.URL.Query().Get("groupKey.id") == "noname@cymbal.example":
			writeJSON(w, http.StatusOK, map[string]string{})
		case r.URL.Path == "/groups:lookup" && r.URL.Query().Get("groupKey.id") == "garbled@cymbal.example":
			_, _ = w.Write([]byte("{not json"))
		case r.URL.Path == "/groups/abc/memberships:checkTransitiveMembership":
			switch r.URL.Query().Get("query") {
			case "member_key_id == 'bob@other.example'":
				writeJSON(w, http.StatusOK, map[string]bool{"hasMembership": true})
			case "member_key_id == 'ghost@nowhere.example'":
				http.Error(w, "not found", http.StatusNotFound)
			case "member_key_id == 'down@other.example'":
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			default:
				writeJSON(w, http.StatusOK, map[string]bool{})
			}
		default:
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	ctx := context.Background()
	for member, want := range map[string]bool{"bob@other.example": true, "mallory@gmail.example": false, "ghost@nowhere.example": false} {
		got, err := c.IsMember(ctx, "G@Cymbal.example", member)
		if err != nil || got != want {
			t.Errorf("IsMember(%s) = %v, %v; want %v", member, got, err, want)
		}
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("group looked up %d times, want 1", n)
	}
	// Every failure is an error, never a "no".
	for _, tc := range []struct{ group, member string }{
		{"denied@cymbal.example", "bob@other.example"},
		{"noname@cymbal.example", "bob@other.example"},
		{"garbled@cymbal.example", "bob@other.example"},
		{"g@cymbal.example", "down@other.example"},
	} {
		if ok, err := c.IsMember(ctx, tc.group, tc.member); err == nil || ok {
			t.Errorf("IsMember(%s, %s) = %v, %v; want an error", tc.group, tc.member, ok, err)
		}
	}
	if _, err := (&CloudIdentityGroups{}).IsMember(ctx, "g@cymbal.example", "bob@other.example"); err == nil {
		t.Error("IsMember with no Client succeeded")
	}
	unreachable := &CloudIdentityGroups{Client: srv.Client(), Endpoint: "http://127.0.0.1:1/"}
	if _, err := unreachable.IsMember(ctx, "g@cymbal.example", "bob@other.example"); err == nil {
		t.Error("IsMember against an unreachable endpoint succeeded")
	}
	var asked string
	dflt := &CloudIdentityGroups{Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		asked = r.URL.String()
		return nil, errors.New("offline")
	})}}
	if _, err := dflt.IsMember(ctx, "g@cymbal.example", "bob@other.example"); err == nil || !strings.HasPrefix(asked, CloudIdentityEndpoint+"groups:lookup?") {
		t.Errorf("default endpoint: asked %q, err %v", asked, err)
	}
	bad := &CloudIdentityGroups{Client: srv.Client(), Endpoint: "http://\x7f/"}
	if _, err := bad.IsMember(ctx, "g@cymbal.example", "bob@other.example"); err == nil {
		t.Error("IsMember with a malformed endpoint succeeded")
	}
}

// fakeDirectory is Cloud Identity with the transitive call answering
// transitiveStatus, and counts of transitive and memberships.list calls.
// groups maps a group email to its members, which may be
// "group:<email>" (nested group), "ns:<email>" (a group from an external
// identity source) or "other:<id>" (a non-user membership). deny lists
// groups the caller can't read.
func fakeDirectory(t *testing.T, groups map[string][]string, deny map[string]bool, transitiveStatus int) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var transitiveCalls, listCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/groups:lookup":
			email := r.URL.Query().Get("groupKey.id")
			if _, ok := groups[email]; !ok {
				http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"name": "groups/" + email})
		case strings.HasSuffix(r.URL.Path, ":checkTransitiveMembership"):
			transitiveCalls.Add(1)
			http.Error(w, `{"error":{"message":"transitive unavailable"}}`, transitiveStatus)
		case strings.HasSuffix(r.URL.Path, "/memberships"):
			listCalls.Add(1)
			email := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/groups/"), "/memberships")
			if deny[email] {
				http.Error(w, `{"error":{"code":403}}`, http.StatusForbidden)
				return
			}
			if r.URL.Query().Get("view") != "FULL" {
				t.Errorf("memberships.list view = %q, want FULL", r.URL.Query().Get("view"))
			}
			var ms []map[string]any
			for _, m := range groups[email] {
				typ, id, ns := "USER", m, ""
				if g, ok := strings.CutPrefix(m, "group:"); ok {
					typ, id = "GROUP", g
				}
				if g, ok := strings.CutPrefix(m, "ns:"); ok {
					typ, id, ns = "GROUP", g, "identitysources/abc"
				}
				if g, ok := strings.CutPrefix(m, "other:"); ok {
					typ, id = "OTHER", g
				}
				ms = append(ms, map[string]any{"preferredMemberKey": map[string]string{"id": id, "namespace": ns}, "type": typ})
			}
			// Two pages, to exercise pageToken.
			if r.URL.Query().Get("pageToken") == "" && len(ms) > 1 {
				writeJSON(w, http.StatusOK, map[string]any{"memberships": ms[:1], "nextPageToken": "p2"})
				return
			}
			if r.URL.Query().Get("pageToken") == "p2" {
				ms = ms[1:]
			}
			writeJSON(w, http.StatusOK, map[string]any{"memberships": ms})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &transitiveCalls, &listCalls
}

// fakeStarterDirectory is Cloud Identity as a Business Starter customer
// sees it: checkTransitiveMembership is 403, groups:lookup and
// memberships.list work.
func fakeStarterDirectory(t *testing.T, groups map[string][]string, deny map[string]bool) (*httptest.Server, *atomic.Int32) {
	srv, transitive, _ := fakeDirectory(t, groups, deny, http.StatusForbidden)
	return srv, transitive
}

func TestGroupsWalkWithoutTransitive(t *testing.T) {
	t.Parallel()
	srv, transitive := fakeStarterDirectory(t, map[string][]string{
		"allowed@d.example": {"direct@d.example", "group:nested@d.example"},
		// nested points back at allowed: a cycle the walk must survive.
		"nested@d.example": {"group:allowed@d.example", "In@Other.Example"},
	}, nil)
	var logged bytes.Buffer
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/", Logger: slog.New(slog.NewTextHandler(&logged, nil))}
	ctx := context.Background()
	for member, want := range map[string]bool{
		"direct@d.example": true,
		"in@other.example": true, // through the nested group, other case
		"out@d.example":    false,
	} {
		got, err := c.IsMember(ctx, "allowed@d.example", member)
		if err != nil || got != want {
			t.Errorf("IsMember(%s) = %v, %v; want %v", member, got, err, want)
		}
	}
	if n := transitive.Load(); n != 1 {
		t.Errorf("checkTransitiveMembership called %d times, want 1 (then walk only)", n)
	}
	if !strings.Contains(logged.String(), "walking nested groups") {
		t.Errorf("fallback not logged: %q", logged.String())
	}
}

// A nested group that can't be resolved, listed before a direct member,
// mustn't lock the direct member out; a non-member gets an error (the walk
// was incomplete), not a "no".
func TestGroupsWalkBrokenNestedBeforeDirect(t *testing.T) {
	t.Parallel()
	srv, _ := fakeStarterDirectory(t, map[string][]string{
		// gone@ isn't a group the directory knows: lookup 404s.
		"allowed@d.example": {"group:gone@d.example", "direct@d.example"},
	}, nil)
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	ctx := context.Background()
	if ok, err := c.IsMember(ctx, "allowed@d.example", "direct@d.example"); err != nil || !ok {
		t.Errorf("direct member after a broken nested group = %v, %v; want true", ok, err)
	}
	ok, err := c.IsMember(ctx, "allowed@d.example", "out@d.example")
	if err == nil || ok || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("non-member with a broken nested group = %v, %v; want an incomplete-walk error", ok, err)
	}
}

func TestGroupsWalkGroupLimit(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{}
	var root []string
	for i := range walkMaxGroups + 5 {
		g := fmt.Sprintf("n%d@d.example", i)
		groups[g] = nil
		root = append(root, "group:"+g)
	}
	groups["allowed@d.example"] = append(root, "direct@d.example")
	srv, _ := fakeStarterDirectory(t, groups, nil)
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	ctx := context.Background()
	if ok, err := c.IsMember(ctx, "allowed@d.example", "direct@d.example"); err != nil || !ok {
		t.Errorf("direct member of a group past the limit = %v, %v; want true", ok, err)
	}
	if _, err := c.IsMember(ctx, "allowed@d.example", "out@d.example"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("non-member past the group limit: err = %v, want a limit error", err)
	}
}

// Only a 403 means "not this edition": a 500 is reported, and the
// transitive call is tried again next time.
func TestGroupsTransitiveServerErrorNoFallback(t *testing.T) {
	t.Parallel()
	srv, transitive, lists := fakeDirectory(t, map[string][]string{"allowed@d.example": {"in@d.example"}}, nil, http.StatusInternalServerError)
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	for i := range 2 {
		if _, err := c.IsMember(context.Background(), "allowed@d.example", "in@d.example"); err == nil {
			t.Errorf("call %d: no error from a 500", i)
		}
	}
	if transitive.Load() != 2 || lists.Load() != 0 {
		t.Errorf("transitive calls %d, list calls %d; want 2 and 0 (no fallback on a 500)", transitive.Load(), lists.Load())
	}
}

// One walk serves every user: membership lists are cached.
func TestGroupsWalkCachesLists(t *testing.T) {
	t.Parallel()
	srv, _, lists := fakeDirectory(t, map[string][]string{
		"allowed@d.example": {"group:nested@d.example"},
		"nested@d.example":  {"a@d.example", "b@d.example"},
	}, nil, http.StatusForbidden)
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	for _, m := range []string{"a@d.example", "b@d.example", "out@d.example"} {
		if _, err := c.IsMember(context.Background(), "allowed@d.example", m); err != nil {
			t.Fatalf("IsMember(%s): %v", m, err)
		}
	}
	// Two groups, two pages for the one with two members: 3 calls.
	if n := lists.Load(); n != 3 {
		t.Errorf("memberships.list called %d times for three users, want 3 (cached after the first walk)", n)
	}
}

// Non-user memberships never match, and a nested group from an external
// identity source can't be walked: an error for a non-member, not a no.
func TestGroupsWalkMemberTypes(t *testing.T) {
	t.Parallel()
	srv, _ := fakeStarterDirectory(t, map[string][]string{
		"allowed@d.example": {"other:out@d.example", "ns:ext@d.example"},
	}, nil)
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	ok, err := c.IsMember(context.Background(), "allowed@d.example", "out@d.example")
	if ok || err == nil || !strings.Contains(err.Error(), "external identity source") {
		t.Errorf("IsMember = %v, %v; want no match (OTHER) and an external-source error", ok, err)
	}
}

func TestGroupsWalkUnreadable(t *testing.T) {
	t.Parallel()
	srv, _ := fakeStarterDirectory(t, map[string][]string{
		"allowed@d.example": {"group:secret@d.example"},
		"secret@d.example":  {"in@d.example"},
		"locked@d.example":  {"in@d.example"},
	}, map[string]bool{"secret@d.example": true, "locked@d.example": true})
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	if ok, err := c.IsMember(context.Background(), "allowed@d.example", "in@d.example"); err == nil || ok {
		t.Errorf("IsMember with an unreadable nested group = %v, %v; want an error, not a no", ok, err)
	}
	if ok, err := c.IsMember(context.Background(), "locked@d.example", "in@d.example"); err == nil || ok {
		t.Errorf("IsMember with an unreadable root group = %v, %v; want an error, not a no", ok, err)
	}
}

func TestGroupsWalkDepthLimit(t *testing.T) {
	t.Parallel()
	groups := map[string][]string{}
	for i := 0; i <= walkMaxDepth; i++ {
		groups[fmt.Sprintf("g%d@d.example", i)] = []string{fmt.Sprintf("group:g%d@d.example", i+1)}
	}
	groups[fmt.Sprintf("g%d@d.example", walkMaxDepth+1)] = []string{"deep@d.example"}
	srv, _ := fakeStarterDirectory(t, groups, nil)
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	_, err := c.IsMember(context.Background(), "g0@d.example", "deep@d.example")
	if err == nil || !strings.Contains(err.Error(), "deeper than") {
		t.Errorf("IsMember past the depth limit: err = %v, want a depth error", err)
	}
}

func TestGroupsWalkPageError(t *testing.T) {
	t.Parallel()
	// A second page that fails: the list is an error, and nothing is cached.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/groups:lookup":
			writeJSON(w, http.StatusOK, map[string]string{"name": "groups/g"})
		case strings.HasSuffix(r.URL.Path, ":checkTransitiveMembership"):
			http.Error(w, "edition", http.StatusForbidden)
		case r.URL.Query().Get("pageToken") == "":
			calls.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"memberships": []any{}, "nextPageToken": "p2"})
		default:
			calls.Add(1)
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	c := &CloudIdentityGroups{Client: srv.Client(), Endpoint: srv.URL + "/"}
	if ok, err := c.IsMember(context.Background(), "g@d.example", "in@d.example"); err == nil || ok {
		t.Errorf("IsMember with a failing page = %v, %v; want an error", ok, err)
	}
}
