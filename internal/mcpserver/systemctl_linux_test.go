// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package mcpserver

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Under readonly, none of the systemctl commands the model may run prints a
// command line of a process in a unit: a process in this test's own unit,
// started with secret-looking arguments, shows in none of them, while
// systemctl status, whose process tree would print it, is refused.
func TestReadonlySystemctlShowsNoCommandLines(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("no systemctl")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("not running under systemd")
	}
	unit := ownUnit()
	if unit == "" || strings.ContainsAny(unit, `*?[]\`) {
		t.Skipf("no systemd unit the readonly commands take holds this process (%q)", unit)
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 60; :", "redis-cli", "-a", "FakeArgvPass-QQ1", "--token", "FakeArgvTok-QQ2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(200 * time.Millisecond)

	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, argv := range [][]string{{"systemctl", "is-active", unit}, {"systemctl", "is-failed", unit}, {"systemctl", "show", "-p", unitProps, unit}} {
		var out RunOutput
		call(t, cs, "run", map[string]any{"argv": argv}, &out, false)
		t.Logf("%s: exit %d, %d bytes", strings.Join(argv[:2], " "), out.ExitCode, len(out.Output))
		if strings.Contains(out.Output, "FakeArgv") || strings.Contains(out.Output, "sleep 60") {
			t.Errorf("%q printed a command line: %q", argv, out.Output)
		}
		if argv[1] == "show" && !strings.Contains(out.Output, "Id="+unit) {
			t.Errorf("systemctl show printed no state of %s: %q", unit, out.Output)
		} else if argv[1] == "show" {
			t.Logf("systemctl show:\n%s", out.Output)
		}
	}
	if why := call(t, cs, "run", map[string]any{"argv": []string{"systemctl", "status", unit}}, nil, true); !strings.Contains(why, "allowlist") {
		t.Errorf("systemctl status: %s", why)
	}
}

// ownUnit returns the systemd unit this process runs in that the system
// manager knows: the first service in its cgroup path, or else the first
// scope.
func ownUnit() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	var scope string
	for _, line := range strings.Split(string(b), "\n") {
		_, path, ok := strings.Cut(line, "::")
		if !ok {
			continue
		}
		for _, seg := range strings.Split(path, "/") {
			switch {
			case strings.HasSuffix(seg, ".service"):
				return seg
			case strings.HasSuffix(seg, ".scope") && scope == "":
				scope = seg
			}
		}
	}
	return scope
}
