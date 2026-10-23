// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Without a home directory and $XDG_STATE_HOME, as under env -i or some
// service managers, tern mcp has no state directory: the state paths are
// empty, for tern mcp to refuse to start, rather than relative ones that
// would put the audit log or the terminal state file wherever it was started,
// outside every directory of tern's own. A relative $XDG_STATE_HOME counts as
// unset.
func TestStatePathNeedsAStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the state directory is LocalAppData on Windows")
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, xdg := range []string{"", "relative/state"} {
		t.Setenv("XDG_STATE_HOME", xdg)
		if p, a, s := statePath("x"), defaultAuditPath(), ptyStatePath(nil); p != "" || a != "" || s != "" {
			t.Errorf("XDG_STATE_HOME=%q: state paths %q, %q, %q", xdg, p, a, s)
		}
		for _, d := range ternDirs() {
			if !filepath.IsAbs(d) {
				t.Errorf("tern directory %q is relative", d)
			}
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if p := statePath("x"); p != filepath.Join(home, ".local", "state", "tern", "x") {
		t.Errorf("with HOME set the state path is %q", p)
	}
	t.Setenv("XDG_STATE_HOME", "relative/state")
	if p := statePath("x"); p != filepath.Join(home, ".local", "state", "tern", "x") {
		t.Errorf("a relative XDG_STATE_HOME gives %q", p)
	}
}

// tern mcp's path flags are absolute paths: ~ and a leading ~/ are the home
// directory, which must be known, and any other relative path is refused, as
// it would resolve in the directory an MCP client started tern mcp in, often
// the project it has open.
func TestPathFlagsAreAbsolute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the home directory is USERPROFILE on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, c := range []struct{ in, want string }{
		{"", ""}, {"/etc/tern/web1.token", "/etc/tern/web1.token"},
		{"~/.config/tern/id_tern", filepath.Join(home, ".config", "tern", "id_tern")}, {"~", home}, {"~/", home},
	} {
		if got, err := mcpPathFlag("key", c.in); err != nil || got != c.want {
			t.Errorf("--key %q = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, p := range []string{"id_tern", "./web1.tern1", "../keys/id_tern", "~user/x", "x/~/y", `~\x`} {
		if _, err := mcpPathFlag("to-file", p); err == nil || !strings.Contains(err.Error(), "--to-file") ||
			!strings.Contains(err.Error(), "is a relative path") || !strings.Contains(err.Error(), "give an absolute or ~/ path") {
			t.Errorf("--to-file %q: %v", p, err)
		}
	}
	for _, h := range []string{"", "relative-home"} {
		t.Setenv("HOME", h)
		for _, p := range []string{"~/.config/tern/web1.token", "~"} {
			if _, err := mcpPathFlag("token-file", p); err == nil ||
				!strings.Contains(err.Error(), fmt.Sprintf(`--token-file %q starts with ~, the home directory, which is not known`, p)) {
				t.Errorf("%s with HOME=%q: %v", p, h, err)
			}
		}
	}
}

// --max-output is at most 16 MiB, as a profile's limits.output_bytes is, and
// both it and --max-timeout must be more than zero.
func TestMCPLimitFlags(t *testing.T) {
	for _, c := range []struct {
		out     int
		timeout time.Duration
		ok      bool
	}{
		{256 << 10, 5 * time.Minute, true},
		{16 << 20, time.Second, true},
		{1, time.Second, true},
		{16<<20 + 1, time.Second, false},
		{1 << 31, time.Second, false},
		{0, time.Second, false},
		{-1, time.Second, false},
		{1, 0, false},
	} {
		if err := checkLimits(c.out, c.timeout); (err == nil) != c.ok {
			t.Errorf("--max-output %d --max-timeout %v: %v", c.out, c.timeout, err)
		}
	}
}

// On Windows ~\ is the home directory too, as ~/ is, in a flag and in the
// config file.
func TestHomeWithBackslashOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip(`~\ is a relative name elsewhere`)
	}
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	if got, err := mcpPathFlag("workspace", `~\tern-work`); err != nil || got != filepath.Join(home, "tern-work") {
		t.Errorf(`--workspace ~\tern-work = %q, %v`, got, err)
	}
	if got, err := configPath(`C:\cfg`, `~\keys\id_tern`); err != nil || got != filepath.Join(home, "keys", "id_tern") {
		t.Errorf(`config ~\keys\id_tern = %q, %v`, got, err)
	}
}
