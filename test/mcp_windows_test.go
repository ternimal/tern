// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMCPWindowsJunction: a directory junction, which any user can make, is
// followed when the agent works out where a path really leads, so writing
// through one into a secret directory is refused, while reading an ordinary
// file through one still works.
func TestMCPWindowsJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are a Windows feature")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir()) // long names: the policy refuses 8.3 ones
	if err != nil {
		t.Fatal(err)
	}
	ssh, pub, docs := filepath.Join(dir, "home", ".ssh"), filepath.Join(dir, "pub"), filepath.Join(dir, "docs")
	for _, d := range []string{ssh, pub, docs} {
		os.MkdirAll(d, 0o755)
	}
	conf := filepath.Join(ssh, "config")
	os.WriteFile(conf, []byte("Host *\n"), 0o600)
	os.WriteFile(filepath.Join(docs, "notes.txt"), []byte("hello"), 0o600)
	for link, to := range map[string]string{"j": ssh, "d": docs} {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(pub, link), to).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v %s", err, out)
		}
	}
	a := startDirectAgent(t)
	pat := "/" + strings.ToLower(filepath.ToSlash(pub)) + "/**"
	sess, _ := startMCPConfig(t, map[string]any{
		"targets":  map[string]any{"box": target(a.addr, a.fp, "files")},
		"profiles": map[string]any{"files": map[string]any{"read_paths": []string{pat}, "write_paths": []string{pat}}},
	}, a.token, nil)
	for _, content := range []string{"ProxyCommand calc.exe\n", ""} {
		res := callTool(t, sess, "write_file", map[string]any{"path": filepath.Join(pub, "j", "config"), "content": content})
		if !res.IsError || !strings.Contains(resultText(res), "secret-path rule") {
			t.Fatalf("write through a junction into .ssh: %s", resultText(res))
		}
	}
	if b, _ := os.ReadFile(conf); string(b) != "Host *\n" {
		t.Fatalf("a refused write changed %s: %q", conf, b)
	}
	if res := callTool(t, sess, "read_file", map[string]any{"path": filepath.Join(pub, "d", "notes.txt")}); res.IsError || !strings.Contains(resultText(res), "hello") {
		t.Fatalf("read through an ordinary junction: %s", resultText(res))
	}
}
