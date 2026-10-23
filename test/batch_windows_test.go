// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestWindowsBatchArgs: an argument with cmd.exe syntax in it is not handed
// to a batch file, where cmd.exe would run what follows a & as a second
// command; plain arguments still reach it.
func TestWindowsBatchArgs(t *testing.T) {
	a := startDirectAgent(t)
	bat := filepath.Join(t.TempDir(), "tbat.cmd")
	if err := os.WriteFile(bat, []byte("@echo ARGS=%*\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(arg string) (string, int) {
		args := append([]string{"run"}, a.dialArgs()...)
		return runClient(t, 20*time.Second, append(args, "--", bat, arg)...)
	}
	if out, code := run("web-1"); code != 0 || !strings.Contains(out, "ARGS=web-1") {
		t.Fatalf("a plain argument: exit %d\n%s", code, out)
	}
	out, code := run("web&echo INJECTED_7")
	if code == 0 || regexp.MustCompile(`(?m)^INJECTED_7`).MatchString(out) || !strings.Contains(out, "batch file") {
		t.Fatalf("an & argument reached cmd.exe: exit %d\n%s", code, out)
	}
}
