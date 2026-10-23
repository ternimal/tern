// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v %s", link, target, err, out)
	}
}

// On Windows a junction is a link every program follows, which needs no
// privilege to make and which Go reports as irregular: the look judges one
// as a link, in the workspace and under the home directory, and never reads
// into it. A download to where one under a rule's name leads is refused.
func TestLookFollowsJunctions(t *testing.T) {
	a := newFileAgent(t)
	ws, home, remote := t.TempDir(), t.TempDir(), longTempDir(t)
	t.Setenv("USERPROFILE", home)
	for _, d := range []string{"innocent", "vscode-user", "plain"} {
		os.MkdirAll(filepath.Join(ws, d), 0o700)
	}
	junction(t, filepath.Join(ws, ".vscode"), filepath.Join(ws, "innocent"))
	junction(t, filepath.Join(ws, "elsewhere"), filepath.Join(ws, "plain"))
	os.MkdirAll(filepath.Join(home, "AppData", "Roaming"), 0o700)
	junction(t, filepath.Join(home, "AppData", "Roaming", "Code"), filepath.Join(ws, "vscode-user"))
	defer func(open func(string) (lookDir, error)) { openLookDir = open }(openLookDir)
	var opened []string
	openLookDir = func(p string) (lookDir, error) {
		opened = append(opened, p)
		return os.Open(p)
	}
	out, cut := (&Server{wsReal: ws}).newLook().run()
	for _, d := range []string{"innocent", "vscode-user"} {
		if !slices.ContainsFunc(out, func(l ruleList) bool { return slices.Contains(l.rules, treeRule(filepath.Join(ws, d))) }) {
			t.Errorf("the junction to %s was not seen: %+v (stopped short %q)", d, out, cut)
		}
	}
	for _, j := range []string{".vscode", "elsewhere"} {
		if slices.Contains(opened, filepath.Join(ws, j)) {
			t.Errorf("the look read into the junction %s", j)
		}
	}
	os.WriteFile(filepath.Join(remote, "payload"), []byte(`{"tasks":[]}`+"\n"), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{pathRule(remote)}}, func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, local := range []string{filepath.Join("innocent", "tasks.json"), filepath.Join("vscode-user", "User", "settings.json")} {
		why := call(t, cs, "download", map[string]any{"remote": filepath.Join(remote, "payload"), "local": local}, nil, true)
		if !strings.Contains(why, "lies where") || !strings.Contains(why, "never creates") {
			t.Errorf("download to %s: %s", local, why)
		}
	}
	call(t, cs, "download", map[string]any{"remote": filepath.Join(remote, "payload"), "local": filepath.Join("plain", "x.json")}, nil, false)
}
