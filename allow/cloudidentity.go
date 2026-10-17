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

// CloudIdentityGroups is taken from gke-demos/kode-gopher internal/oauth
// (allow.go) at 8b53617b7d4d0b08b158de64ab7416dc84a1281e. kode-gopher
// will not import steward; port fixes by hand in both directions.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudIdentityEndpoint is the Cloud Identity API's base URL.
const CloudIdentityEndpoint = "https://cloudidentity.googleapis.com/v1/"

// CloudIdentityGroupsScope is the only scope CloudIdentityGroups needs.
const CloudIdentityGroupsScope = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"

// CloudIdentityGroups is a GroupChecker backed by the Cloud Identity
// Groups API, called as the service's own identity or a service account
// it impersonates (either needs the Groups Reader admin role). Users
// consent to no groups scope.
//
// groups.memberships.checkTransitiveMembership answers in one call, but
// only for Workspace Enterprise and Cloud Identity Premium customers;
// other editions (Business Starter, Standard, Plus) get 403. Then IsMember
// walks the group and its nested groups with memberships.list, which every
// edition has, and skips the transitive call for that group for an hour.
// Membership lists are cached for GroupVerdictTTL, so one walk serves
// every account checked against the same group.
//
// A walk that could not read part of the tree and did not find the member
// is an error, not a "no": the member might be in the part it could not
// read.
type CloudIdentityGroups struct {
	// Client calls Cloud Identity, authenticated with
	// CloudIdentityGroupsScope. Required.
	Client *http.Client
	// Endpoint replaces CloudIdentityEndpoint (tests).
	Endpoint string
	// Logger receives one line when a group falls back to the walk. Nil
	// means no logging.
	Logger *slog.Logger

	mu           sync.Mutex
	names        map[string]cached[string]       // group email -> groups/<id>
	lists        map[string]cached[[]membership] // groups/<id> -> direct members
	noTransitive map[string]time.Time            // groups/<id> -> when the transitive call got 403
}

var _ GroupChecker = (*CloudIdentityGroups)(nil)

type cached[T any] struct {
	v  T
	at time.Time
}

const (
	// walkMaxDepth and walkMaxGroups bound a membership walk against
	// runaway nesting.
	walkMaxDepth  = 10
	walkMaxGroups = 100
	// groupNameTTL bounds how long a group email -> name mapping is
	// trusted (a group deleted and recreated gets a new name).
	groupNameTTL = time.Hour
	// transitiveRetry is how long a group's 403 from
	// checkTransitiveMembership is remembered before trying it again.
	transitiveRetry = time.Hour
	// maxCIBody bounds what is read from Cloud Identity.
	maxCIBody = 1 << 20
)

// IsMember implements GroupChecker.
func (c *CloudIdentityGroups) IsMember(ctx context.Context, group, member string) (bool, error) {
	if c.Client == nil {
		return false, errors.New("allow: CloudIdentityGroups has no Client")
	}
	name, err := c.groupName(ctx, strings.ToLower(group))
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	at, walk := c.noTransitive[name]
	walk = walk && time.Since(at) < transitiveRetry
	c.mu.Unlock()
	if !walk {
		in, err := c.transitive(ctx, name, member)
		var se *statusError
		if !errors.As(err, &se) || se.code != http.StatusForbidden {
			return in, err
		}
		// Not this edition, or no rights (then the walk fails too, with
		// its own 403, not a false "no").
		if c.Logger != nil {
			c.Logger.Info("allow: checkTransitiveMembership answered 403; walking nested groups instead",
				"group", group, "for", transitiveRetry)
		}
		c.mu.Lock()
		if c.noTransitive == nil {
			c.noTransitive = map[string]time.Time{}
		}
		c.noTransitive[name] = time.Now()
		c.mu.Unlock()
	}
	return c.walk(ctx, name, member)
}

func (c *CloudIdentityGroups) transitive(ctx context.Context, name, member string) (bool, error) {
	q := url.Values{"query": {fmt.Sprintf("member_key_id == '%s'", strings.ReplaceAll(member, "'", ""))}}
	var r struct {
		HasMembership bool `json:"hasMembership"`
	}
	err := c.get(ctx, name+"/memberships:checkTransitiveMembership?"+q.Encode(), &r)
	var se *statusError
	if errors.As(err, &se) && se.code == http.StatusNotFound {
		// A member key the directory doesn't know isn't a member.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return r.HasMembership, nil
}

// walk looks for member in the group and, breadth first, in the groups
// nested in it. Each group's direct members are checked before its nested
// groups are expanded, and a nested group that can't be read is remembered
// rather than fatal: a match anywhere admits. Only if nothing matched does
// that failure become the answer, an error rather than a "no", since the
// member might be in the group that couldn't be read.
//
// Users and service accounts match by email. Other member types (devices,
// shared drives, customer-wide entries such as "everyone in the
// organization") aren't expanded and never match.
func (c *CloudIdentityGroups) walk(ctx context.Context, root, member string) (bool, error) {
	member = strings.ToLower(member)
	seen := map[string]bool{root: true}
	level := []string{root}
	var incomplete error
	for depth := 0; len(level) > 0; depth++ {
		if depth >= walkMaxDepth {
			incomplete = fmt.Errorf("group nesting deeper than %d levels", walkMaxDepth)
			break
		}
		var next []string
		for _, g := range level {
			members, err := c.members(ctx, g)
			if err != nil {
				if g == root {
					return false, err
				}
				incomplete = err
				continue
			}
			if directMember(members, member) {
				return true, nil
			}
			children, err := c.nestedGroups(ctx, members, seen)
			if err != nil {
				incomplete = err
			}
			next = append(next, children...)
		}
		level = next
	}
	if incomplete != nil {
		return false, fmt.Errorf("allow: not found, but the group walk was incomplete: %w", incomplete)
	}
	return false, nil
}

// directMember reports whether member (lower-cased) is a user or service
// account in members.
func directMember(members []membership, member string) bool {
	for _, m := range members {
		switch m.Type {
		case "USER", "SERVICE_ACCOUNT", "TYPE_UNSPECIFIED", "":
			if strings.ToLower(m.PreferredMemberKey.ID) == member {
				return true
			}
		}
	}
	return false
}

// nestedGroups resolves the groups in members that haven't been seen,
// marking them seen. A group it can't resolve, or past walkMaxGroups, is
// skipped and reported in the error; the others are still returned.
func (c *CloudIdentityGroups) nestedGroups(ctx context.Context, members []membership, seen map[string]bool) ([]string, error) {
	var next []string
	var skipped error
	for _, m := range members {
		if m.Type != "GROUP" {
			continue
		}
		id := strings.ToLower(m.PreferredMemberKey.ID)
		if m.PreferredMemberKey.Namespace != "" {
			skipped = fmt.Errorf("nested group %s is from an external identity source (namespace %s)", id, m.PreferredMemberKey.Namespace)
			continue
		}
		child, err := c.groupName(ctx, id)
		if err != nil {
			skipped = fmt.Errorf("nested group %s: %w", id, err)
			continue
		}
		if seen[child] {
			continue
		}
		if len(seen) >= walkMaxGroups {
			skipped = fmt.Errorf("more than %d nested groups", walkMaxGroups)
			continue
		}
		seen[child] = true
		next = append(next, child)
	}
	return next, skipped
}

type membership struct {
	PreferredMemberKey struct {
		ID        string `json:"id"`
		Namespace string `json:"namespace"`
	} `json:"preferredMemberKey"`
	Type string `json:"type"`
}

// members lists a group's direct memberships, all pages, cached for
// GroupVerdictTTL.
func (c *CloudIdentityGroups) members(ctx context.Context, name string) ([]membership, error) {
	c.mu.Lock()
	e, ok := c.lists[name]
	c.mu.Unlock()
	if ok && time.Since(e.at) < GroupVerdictTTL {
		return e.v, nil
	}
	var all []membership
	token := ""
	for {
		q := url.Values{"view": {"FULL"}, "pageSize": {"200"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var r struct {
			Memberships   []membership `json:"memberships"`
			NextPageToken string       `json:"nextPageToken"`
		}
		if err := c.get(ctx, name+"/memberships?"+q.Encode(), &r); err != nil {
			return nil, err
		}
		all = append(all, r.Memberships...)
		if r.NextPageToken == "" {
			break
		}
		token = r.NextPageToken
	}
	c.mu.Lock()
	if c.lists == nil {
		c.lists = map[string]cached[[]membership]{}
	}
	c.lists[name] = cached[[]membership]{v: all, at: time.Now()}
	c.mu.Unlock()
	return all, nil
}

func (c *CloudIdentityGroups) groupName(ctx context.Context, group string) (string, error) {
	c.mu.Lock()
	e, ok := c.names[group]
	c.mu.Unlock()
	if ok && time.Since(e.at) < groupNameTTL {
		return e.v, nil
	}
	var r struct {
		Name string `json:"name"`
	}
	if err := c.get(ctx, "groups:lookup?"+url.Values{"groupKey.id": {group}}.Encode(), &r); err != nil {
		return "", err
	}
	if r.Name == "" {
		return "", errors.New("allow: Cloud Identity group lookup returned no name")
	}
	c.mu.Lock()
	if c.names == nil {
		c.names = map[string]cached[string]{}
	}
	c.names[group] = cached[string]{v: r.Name, at: time.Now()}
	c.mu.Unlock()
	return r.Name, nil
}

func (c *CloudIdentityGroups) get(ctx context.Context, path string, out any) error {
	ep := c.Endpoint
	if ep == "" {
		ep = CloudIdentityEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("allow: cloud identity: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCIBody)).Decode(out); err != nil {
		return fmt.Errorf("allow: cloud identity: %w", err)
	}
	return nil
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("allow: cloud identity: HTTP %d: %s", e.code, e.body)
}
