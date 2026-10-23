// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"net/http/httptest"
	"testing"
)

// --api-trusted-hosts names hosts: an entry matches its name in Host with any
// port or none, since a proxy on another port than 80 or 443 sends it, and an
// entry with a port matches that port only. Loopback still passes, and any
// other name, or a name that only contains a trusted one, still fails.
func TestTrustedHostsMatchNames(t *testing.T) {
	g := &Gateway{Addr: "127.0.0.1:8080", TrustedHosts: []string{"proxy.example", "pinned.example:8443", "[2001:db8::1]", "2001:db8::2"}}
	for _, c := range []struct {
		host string
		ok   bool
	}{
		{"proxy.example", true}, {"PROXY.Example:8443", true}, {"proxy.example:80", true},
		{"pinned.example:8443", true}, {"pinned.example", false}, {"pinned.example:443", false},
		{"[2001:db8::1]:8080", true}, {"[2001:db8::1]", true}, {"[2001:db8::2]:9000", true}, {"[2001:db8::3]:8080", false},
		{"localhost:8080", true}, {"127.0.0.1:8080", true}, {"[::1]:8080", true},
		{"evil.example", false}, {"evil.example:8080", false}, {"proxy.example.evil.example", false},
		{"evil.example:proxy.example", false}, {"", false},
		{"proxy.example.", true}, {"Proxy.Example.:443", true}, {"pinned.example.:8443", true}, {"pinned.example.:443", false},
		{"proxy.example..", false}, {".", false},
	} {
		r := httptest.NewRequest("GET", "/v1/sessions", nil)
		r.Host = c.host
		if why := g.guard(r); (why == "") != c.ok {
			t.Errorf("Host %q: %q, want ok=%v", c.host, why, c.ok)
		}
	}
}
