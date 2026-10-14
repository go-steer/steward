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
	"strings"
	"testing"
)

func TestAdmits(t *testing.T) {
	t.Parallel()
	l, err := Parse([]string{" Dana@Cymbal.example ", "@shoes.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, email, hd string
		want            bool
	}{
		{"listed address, case-blind", "DANA@cymbal.example", "", true},
		{"listed address, any hd", "dana@cymbal.example", "cymbal.example", true},
		{"unlisted address", "lee@cymbal.example", "cymbal.example", false},
		{"domain with Google's word", "lee@shoes.example", "shoes.example", true},
		{"domain, hd case-blind", "Lee@Shoes.Example", "SHOES.example", true},
		// The reason a domain entry needs hd: a consumer account can carry
		// a company address.
		{"domain suffix, consumer account", "lee@shoes.example", "", false},
		{"domain suffix, another Workspace", "lee@shoes.example", "evil.example", false},
		{"hd listed, address elsewhere", "lee@evil.example", "shoes.example", false},
		{"subdomain is not the domain", "lee@eu.shoes.example", "eu.shoes.example", false},
		{"no address", "", "shoes.example", false},
		{"no local part", "@shoes.example", "shoes.example", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := l.Admits(c.email, c.hd); got != c.want {
				t.Errorf("Admits(%q, %q) = %v, want %v", c.email, c.hd, got, c.want)
			}
		})
	}
}

func TestEmptyAdmitsNoOne(t *testing.T) {
	t.Parallel()
	empty, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []*List{empty, {}, nil} {
		if !l.Empty() {
			t.Errorf("%v: Empty() = false", l)
		}
		if l.Admits("dana@cymbal.example", "cymbal.example") {
			t.Errorf("%v admitted someone", l)
		}
	}
	full, _ := Parse([]string{"@cymbal.example"})
	if full.Empty() {
		t.Error("a list with an entry reports Empty")
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",
		"   ",
		"cymbal.example", // a domain without "@" would silently match nothing
		"dana",
		"@",
		"@localhost",
		"dana@",
		"dana@cymbal",
		"dana@@cymbal.example",
		"a@b@cymbal.example",
		"dana@cymbal..example",
		"dana@cymbal.example, lee@cymbal.example",
		"dana @cymbal.example",
	} {
		if _, err := Parse([]string{"ok@cymbal.example", bad}); err == nil {
			t.Errorf("Parse accepted %q", bad)
		}
	}
	// Every bad entry is reported, not just the first.
	_, err := Parse([]string{"one", "two"})
	if err == nil || !strings.Contains(err.Error(), `"one"`) || !strings.Contains(err.Error(), `"two"`) {
		t.Errorf("Parse(two bad entries) = %v, want both named", err)
	}
}
