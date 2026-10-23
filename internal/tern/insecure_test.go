// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import "testing"

// TestGatewayAuthPolicy locks down the tokenless-gateway rules that back
// --api-insecure: a bearer token is always fine, no token is a local-only
// convenience on loopback, a non-loopback bind with no token is refused, and
// only the explicit Insecure opt-in lets that through.
func TestGatewayAuthPolicy(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		token    string
		insecure bool
		wantErr  bool
	}{
		{"token set, non-loopback ok", "0.0.0.0:8080", "a-very-long-token-1234", false, false},
		{"no token, loopback ok", "127.0.0.1:8080", "", false, false},
		{"no token, loopback v6 ok", "[::1]:8080", "", false, false},
		{"no token, non-loopback refused", "0.0.0.0:8080", "", false, true},
		{"no token, non-loopback with --api-insecure ok", "0.0.0.0:8080", "", true, false},
		{"insecure is a no-op when loopback", "127.0.0.1:8080", "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := &Gateway{Addr: c.addr, Token: c.token, Insecure: c.insecure}
			if err := g.checkAuthPolicy(); (err != nil) != c.wantErr {
				t.Fatalf("checkAuthPolicy(addr=%q token=%q insecure=%v) err=%v, wantErr=%v",
					c.addr, c.token, c.insecure, err, c.wantErr)
			}
		})
	}
}
