// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tern "github.com/ternimal/tern/internal/tern"
)

// A relative path in the config file is taken from the config file's
// directory, never from the working directory, which an MCP client sets to
// the project it has open: a tern1: file the project ships cannot choose
// the agent and fingerprint a target trusts.
func TestConfigPathsResolveFromConfigDir(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	cfgDir := filepath.Join(home, ".config", "tern")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, s string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	mine := tern.ConnString{Mode: "direct", Addr: "10.0.0.5:2222", FP: strings.Repeat("ab", 32)}.Encode()
	theirs := tern.ConnString{Mode: "direct", Addr: "203.0.113.66:2222", FP: strings.Repeat("cd", 32)}.Encode()
	write(filepath.Join(cfgDir, "web1.tern1"), mine+"\n", 0o600)
	write(filepath.Join(cfgDir, "web1.token"), "token-0123456789abcdef\n", 0o600)
	write(filepath.Join(repo, "web1.tern1"), theirs+"\n", 0o644)
	write(filepath.Join(repo, "web1.token"), "their-token-0123456789\n", 0o600)
	cfg := filepath.Join(cfgDir, "mcp.json")
	write(cfg, `{"targets": {
		"web1": {"to_file": "web1.tern1", "token_file": "web1.token"},
		"db1": {"addr": "10.0.0.6:2222", "fingerprint": "`+strings.Repeat("ef", 32)+`", "key": "keys/id_tern", "relay_token_file": "relay.token"}},
		"workspace": "work", "audit_log": "logs/audit.jsonl", "record_dir": "../rec"}`, 0o600)
	t.Chdir(repo) // as a plugin's server starts: in the opened project
	c, err := loadMCPConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := c.Targets["web1"].build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if tg.addr != "10.0.0.5:2222" || tg.token != "token-0123456789abcdef" {
		t.Errorf("web1 reaches %s with token %q, want the agent and token named next to the config", tg.addr, tg.token)
	}
	for name, got := range map[string]string{
		"workspace": c.Workspace, "audit_log": c.AuditLog, "record_dir": c.RecordDir,
		"key": c.Targets["db1"].Key, "relay_token_file": c.Targets["db1"].RelayTokenFile,
	} {
		want := map[string]string{
			"workspace": filepath.Join(cfgDir, "work"), "audit_log": filepath.Join(cfgDir, "logs", "audit.jsonl"),
			"record_dir": filepath.Join(home, ".config", "rec"), "key": filepath.Join(cfgDir, "keys", "id_tern"),
			"relay_token_file": filepath.Join(cfgDir, "relay.token"),
		}[name]
		if got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// configPath keeps an absolute path, expands ~/, and refuses what it cannot
// tie to the config file: ~/ with no home directory known and, on Windows,
// a path relative to a drive's working directory; a path from the root of
// a drive is taken on the config file's drive.
func TestConfigPathRules(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "x")
	if p, err := configPath(dir, abs); err != nil || p != abs {
		t.Errorf("an absolute path: %q %v", p, err)
	}
	if p, err := configPath(dir, ""); err != nil || p != "" {
		t.Errorf("no path: %q %v", p, err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for in, want := range map[string]string{"~": home, "~/x": filepath.Join(home, "x"), "~x": filepath.Join(dir, "~x")} {
		if p, err := configPath(dir, in); err != nil || p != want {
			t.Errorf("%s: %q %v, want %q", in, p, err, want)
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "") // Plan 9
	for _, in := range []string{"~/x", "~"} {
		if p, err := configPath(dir, in); err == nil || !strings.Contains(err.Error(), "the home directory, which is not known") {
			t.Errorf("%s with no home directory: %q %v", in, p, err)
		}
	}
	if runtime.GOOS == "windows" {
		if p, err := configPath(`C:\cfg`, `C:x`); err == nil {
			t.Errorf("a drive-relative path: %q", p)
		}
		if p, err := configPath(`D:\cfg`, `\keys\id`); err != nil || p != `D:\keys\id` {
			t.Errorf("a path from the root of the drive: %q %v", p, err)
		}
	}
}
