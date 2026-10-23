// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tern "github.com/ternimal/tern/internal/tern"
)

// The token files of tern mcp's config, and of the client's flags, are held
// to the rules of a token file: one other users can read is refused, naming
// the field or flag and the fix.
func TestTokenFilesMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.token")
	if err := os.WriteFile(open, []byte("token-0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil { // whatever the umask
		t.Fatal(err)
	}
	fp := strings.Repeat("ab", 32)
	for _, c := range []struct {
		tc    targetConfig
		field string
	}{
		{targetConfig{Addr: "127.0.0.1:1", Fingerprint: fp, TokenFile: open}, "token_file"},
		{targetConfig{Relay: "127.0.0.1:1", RelayFingerprint: fp, ID: "box1", Fingerprint: fp, RelayTokenFile: open, TokenEnv: "TERN_TEST_UNSET"}, "relay_token_file"},
	} {
		_, err := c.tc.build()
		if err == nil || !strings.Contains(err.Error(), c.field) || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("%s others can read: %v", c.field, err)
		}
	}

	withToken := tern.ConnString{Mode: "relay", Relay: "127.0.0.1:1", RelayFP: fp, RelayToken: "relay-token-0123456789", ID: "box1", FP: fp}
	to := filepath.Join(dir, "to")
	if err := os.WriteFile(to, []byte(withToken.Encode()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(to, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (targetConfig{ToFile: to, TokenFile: open}).build(); err == nil || !strings.Contains(err.Error(), "to_file") {
		t.Errorf("to_file with the relay token, others can read: %v", err)
	}
	for _, flags := range [][]string{{"--token-file", open, "--addr", "127.0.0.1:1", "--fingerprint", fp}, {"--to-file", to}} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		cf := addConnFlags(fs)
		t.Setenv("TERN_TOKEN", "agent-token-1234567")
		if err := fs.Parse(flags); err != nil {
			t.Fatal(err)
		}
		if _, err := cf.target(); err == nil || !strings.Contains(err.Error(), flags[0]) || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("%s others can read: %v", flags[0], err)
		}
	}
}

// tern mcp's config file names the agents it trusts and the policy it
// enforces: one other users could change is refused, one they may only read
// is used.
func TestConfigFileOthersCouldChange(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "mcp.json")
	body := `{"targets": {"web1": {"addr": "127.0.0.1:1", "fingerprint": "` + strings.Repeat("ab", 32) + `", "token_env": "TERN_TEST_TOKEN"}}}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o600, true}, {0o644, true}, {0o646, false}, {0o666, false}} {
		if err := os.Chmod(cfg, c.mode); err != nil {
			t.Fatal(err)
		}
		_, err := loadMCPConfig(cfg)
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("a config file of mode %04o: %v, want ok=%v", c.mode, err, c.ok)
		}
	}
}
