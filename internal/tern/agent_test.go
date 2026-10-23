// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import "testing"

// The agent scrubs TERN_* from a hosted shell's environment regardless of
// case (Windows env lookups are case-insensitive).
func TestChildEnvScrubsCaseInsensitive(t *testing.T) {
	t.Setenv("TERN_TOKEN", "x")
	t.Setenv("tern_relay_token", "y")
	t.Setenv("KEEP_ME", "z")
	var leaked, kept bool
	for _, kv := range childEnv() {
		if len(kv) >= 5 && (kv[:5] == "TERN_" || kv[:5] == "tern_") {
			leaked = true
		}
		if kv == "KEEP_ME=z" {
			kept = true
		}
	}
	if leaked {
		t.Fatal("childEnv leaked a TERN_* variable")
	}
	if !kept {
		t.Fatal("childEnv dropped an unrelated variable")
	}
}
