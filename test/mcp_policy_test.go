// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// tern mcp answers initialize at once whatever links the workspace holds:
// links named like a rule into a long chain of relative links deep in a
// project, as a cloned repository can hold them, cost the chain once, and
// the look for links never makes startup wait past its time bound.
func TestMCPStartupWithManyLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	a := startDirectAgent(t)
	ws := t.TempDir()
	var segs []string
	for i := range 60 {
		segs = append(segs, fmt.Sprintf("d%d", i))
	}
	deep := filepath.Join(append([]string{ws, "c"}, segs...)...)
	os.MkdirAll(deep, 0o700)
	up := strings.Repeat("../", 60)
	for i := range 250 {
		os.Symlink(up+strings.Join(segs, "/")+fmt.Sprintf("/l%d", i+1), filepath.Join(deep, fmt.Sprintf("l%d", i)))
	}
	for i := range 30 {
		os.Symlink("c/"+strings.Join(segs, "/")+"/l0", filepath.Join(ws, fmt.Sprintf("token-%04d", i)))
	}
	cmd := exec.Command(bin["tern"], "mcp", "--addr", a.addr, "--fingerprint", a.fp, "--workspace", ws,
		"--audit-log", filepath.Join(t.TempDir(), "audit.jsonl"))
	cmd.Env = ternEnv("TERN_TOKEN="+a.token, "HOME="+t.TempDir())
	start := time.Now()
	sess := connectMCPWith(t, cmd, nil, "")
	took := time.Since(start)
	t.Logf("30 links into a 250-link chain 61 directories deep: initialize answered after %v", took)
	if took > 4*time.Second {
		t.Errorf("initialize answered after %v", took)
	}
	if res := callTool(t, sess, "list_targets", map[string]any{}); res.IsError {
		t.Errorf("list_targets: %s", resultText(res))
	}
}

// The files a config names for a target's login, or for the agent to trust,
// are tern's own wherever they are and whatever their names: with the home
// directory as the workspace, a token file, a relay token file and a key
// there are never uploaded.
func TestMCPConfigLoginFilesNeverUploaded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix paths on the agent")
	}
	a := startDirectAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(home, "web2.tok"), []byte("Web2AgentTokenFake0123456789abcdef\n"), 0o600)
	os.WriteFile(filepath.Join(home, "relay.txt"), []byte("RelayTokenFake0123456789abcdef\n"), 0o600)
	os.WriteFile(filepath.Join(home, "box.tok"), []byte(a.token+"\n"), 0o600)
	os.WriteFile(filepath.Join(home, "notes.txt"), []byte("notes\n"), 0o600)
	cfg := filepath.Join(home, ".config", "tern", "mcp.json")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	writeJSON(t, cfg, map[string]any{
		"targets": map[string]any{
			"box": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_file": "~/box.tok", "profile": "files"},
			"web2": map[string]any{"relay": "127.0.0.1:1", "relay_fingerprint": strings.Repeat("cd", 32), "id": "web2",
				"fingerprint": strings.Repeat("ab", 32), "token_file": "~/web2.tok", "relay_token_file": "~/relay.txt"},
		},
		"profiles":  map[string]any{"files": map[string]any{"read_paths": []string{remote + "/**"}, "write_paths": []string{remote + "/**"}}},
		"workspace": "~",
	})
	cmd := exec.Command(bin["tern"], "mcp", "--config", "~/.config/tern/mcp.json")
	cmd.Dir = t.TempDir()
	cmd.Env = ternEnv("HOME="+home, "XDG_STATE_HOME="+filepath.Join(home, ".local", "state"))
	sess := connectMCPWith(t, cmd, nil, "")
	for _, local := range []string{"box.tok", "web2.tok", "relay.txt"} {
		res := callTool(t, sess, "upload", map[string]any{"target": "box", "local": local, "remote": filepath.Join(remote, local)})
		if !res.IsError || !strings.Contains(resultText(res), "tern's own files") {
			t.Errorf("upload of %s: error=%v %s", local, res.IsError, resultText(res))
		}
		if _, err := os.Lstat(filepath.Join(remote, local)); err == nil {
			t.Errorf("%s reached the agent", local)
		}
	}
	if res := callTool(t, sess, "upload", map[string]any{"target": "box", "local": "notes.txt", "remote": filepath.Join(remote, "notes.txt")}); res.IsError {
		t.Errorf("an ordinary upload: %s", resultText(res))
	}
}

// Started as the Claude Code plugin starts it, in a project that is a git
// repository, tern mcp never lets downloads point the repository's config
// elsewhere: .git/commondir and a .git file are never created, so the next
// git command there, which a shell's prompt or an editor runs, runs nothing
// a download chose.
func TestMCPDownloadNeverRedirectsRepository(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("git with core.fsmonitor on Linux")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	a := startDirectAgent(t)
	home := t.TempDir()
	project := filepath.Join(home, "projects", "app")
	remote := t.TempDir()
	marker := filepath.Join(t.TempDir(), "RAN")
	os.MkdirAll(filepath.Join(home, ".config", "tern"), 0o700)
	os.MkdirAll(filepath.Join(project, "sub"), 0o700)
	for _, args := range [][]string{{"init", "-q", project}, {"-C", project, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "x"}} {
		if out, err := exec.Command(git, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	os.WriteFile(filepath.Join(remote, "commondir"), []byte("../.build-cache\n"), 0o644)
	os.WriteFile(filepath.Join(remote, "gitfile"), []byte("gitdir: ../.build-cache\n"), 0o644)
	os.WriteFile(filepath.Join(remote, "config"), []byte("[core]\n\trepositoryformatversion = 0\n\tfsmonitor = \"touch "+marker+"\"\n"), 0o644)
	os.WriteFile(filepath.Join(remote, "empty"), nil, 0o644)
	writeJSON(t, filepath.Join(home, ".config", "tern", "mcp.json"), map[string]any{
		"targets":   map[string]any{"box": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK", "profile": "logs"}},
		"profiles":  map[string]any{"logs": map[string]any{"read_paths": []string{remote + "/**"}}},
		"workspace": "~/projects/app",
	})
	cmd := exec.Command(bin["tern"], "mcp", "--config", "~/.config/tern/mcp.json")
	cmd.Dir = project
	cmd.Env = ternEnv("HOME="+home, "XDG_STATE_HOME="+filepath.Join(home, ".local", "state"), "TERN_E2E_TOK="+a.token)
	sess := connectMCPWith(t, cmd, nil, "")
	for _, d := range []struct{ remote, local string }{{"commondir", ".git/commondir"}, {"gitfile", "sub/.git"}} {
		res := callTool(t, sess, "download", map[string]any{"remote": filepath.Join(remote, d.remote), "local": d.local})
		if !res.IsError || !strings.Contains(resultText(res), "never creates") {
			t.Errorf("download to %s: error=%v %s", d.local, res.IsError, resultText(res))
		}
	}
	for _, local := range []string{".build-cache/config", ".build-cache/objects/.keep", ".build-cache/refs/.keep"} {
		remoteFile := "empty"
		if strings.HasSuffix(local, "config") {
			remoteFile = "config"
		}
		if res := callTool(t, sess, "download", map[string]any{"remote": filepath.Join(remote, remoteFile), "local": local}); res.IsError {
			t.Errorf("download to %s: %s", local, resultText(res))
		}
	}
	sess.Close()
	for _, dir := range []string{project, filepath.Join(project, "sub")} {
		out, _ := exec.Command(git, "-C", dir, "status", "--short").CombinedOutput()
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("git status in %s ran a downloaded config's command: %s", dir, out)
		}
	}
}

// A relative workspace in the config file is taken from the file's
// directory; for the usual ~/.config/tern/mcp.json that is tern's own, where
// the workspace tools never upload or create anything, and tern mcp says so
// at startup, with the ~/ path that was likely meant. ~ alone is the home
// directory.
func TestMCPRelativeWorkspaceInTernDirExplained(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the home directory comes from USERPROFILE on Windows")
	}
	a := startDirectAgent(t)
	home := t.TempDir()
	cfg := filepath.Join(home, ".config", "tern", "mcp.json")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	target := map[string]any{"box": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK"}}
	writeJSON(t, cfg, map[string]any{"targets": target, "workspace": "tern-work"})
	env := ternEnv("HOME="+home, "XDG_STATE_HOME="+filepath.Join(home, ".local", "state"), "TERN_E2E_TOK="+a.token)
	out, refused := runDaemon(t, "tern", env, "mcp", "--config", "~/.config/tern/mcp.json")
	want := fmt.Sprintf(`workspace "tern-work" is a relative path, taken from the config file's directory, so it names %s`, filepath.Join(home, ".config", "tern", "tern-work"))
	if !refused || !strings.Contains(out, want) || !strings.Contains(out, `"~/tern-work"`) {
		t.Errorf("refused=%v, want %q in:\n%s", refused, want, out)
	}
	if _, err := os.Lstat(filepath.Join(home, ".config", "tern", "tern-work")); err == nil {
		t.Error("a refused workspace was made")
	}
	writeJSON(t, cfg, map[string]any{"targets": target, "workspace": "~"})
	cmd := exec.Command(bin["tern"], "mcp", "--config", "~/.config/tern/mcp.json")
	cmd.Dir, cmd.Env = t.TempDir(), env
	sess := connectMCPWith(t, cmd, nil, "")
	if res := callTool(t, sess, "list_targets", map[string]any{}); res.IsError {
		t.Errorf("with ~ as the workspace: %s", resultText(res))
	}
}
