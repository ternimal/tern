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

	tern "github.com/ternimal/tern/internal/tern"
)

// Started as the Claude Code plugin starts it (--config ~/.config/tern/mcp.json,
// no shell, in the project the user opened, with a workspace there), tern mcp
// downloads a file the model may read on an agent into the project, but never
// to the places Claude Code and the other MCP clients run code from at their
// next start, nor to the instruction files they load; and no key travels:
// under tern's names it is neither uploaded nor read on the agent, and under
// any other name it is neither uploaded nor downloaded.
func TestMCPDownloadNeverCreatesClientSettings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix paths on the agent")
	}
	a := startDirectAgent(t)
	home := t.TempDir()
	project := filepath.Join(home, "projects", "app")
	remote := t.TempDir() // a directory on the agent the profile only reads
	os.MkdirAll(filepath.Join(home, ".config", "tern"), 0o700)
	os.MkdirAll(project, 0o700)
	os.WriteFile(filepath.Join(remote, "app.json"),
		[]byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch planted"}]}]}}`+"\n"), 0o644)
	writeJSON(t, filepath.Join(home, ".config", "tern", "mcp.json"), map[string]any{
		"targets": map[string]any{"box": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK",
			"profile": "logs"}},
		"profiles":  map[string]any{"logs": map[string]any{"read_paths": []string{remote + "/**"}, "write_paths": []string{remote + "/**"}}},
		"workspace": "~/projects/app",
	})
	cmd := exec.Command(bin["tern"], "mcp", "--config", "~/.config/tern/mcp.json")
	cmd.Dir = project
	cmd.Env = ternEnv("HOME="+home, "XDG_STATE_HOME="+filepath.Join(home, ".local", "state"), "TERN_E2E_TOK="+a.token)
	sess := connectMCPWith(t, cmd, nil, "")
	for _, local := range []string{".claude/settings.local.json", ".claude/settings.json", ".mcp.json", "CLAUDE.md",
		"AGENTS.md", ".vscode/tasks.json", ".cursor/mcp.json"} {
		res := callTool(t, sess, "download", map[string]any{"remote": filepath.Join(remote, "app.json"), "local": local})
		if !res.IsError || !strings.Contains(resultText(res), "never creates") {
			t.Errorf("download to %s: error=%v %s", local, res.IsError, resultText(res))
		}
		if _, err := os.Lstat(filepath.Join(project, local)); err == nil {
			t.Errorf("a download created %s in the project", local)
		}
	}
	if res := callTool(t, sess, "download", map[string]any{"remote": filepath.Join(remote, "app.json"), "local": "config/app.json"}); res.IsError {
		t.Errorf("an ordinary download: %s", resultText(res))
	}
	os.WriteFile(filepath.Join(project, "id_tern"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	os.WriteFile(filepath.Join(project, "deploy-key"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	for _, local := range []string{"id_tern", "deploy-key"} {
		res := callTool(t, sess, "upload", map[string]any{"local": local, "remote": filepath.Join(remote, local)})
		if !res.IsError || !strings.Contains(resultText(res), "never uploaded") {
			t.Errorf("upload of %s: error=%v %s", local, res.IsError, resultText(res))
		}
		if _, err := os.Lstat(filepath.Join(remote, local)); err == nil {
			t.Errorf("%s reached the agent", local)
		}
	}
	// On the agent, a key under the names tern keygen and the docs give it
	// is never read, and one under any other name is never downloaded.
	for _, name := range []string{"tern_id_ed25519", "id_tern", "renamed.txt"} {
		if _, err := tern.GenerateKeyFiles(filepath.Join(remote, name), "e2e"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tern_id_ed25519", "id_tern"} {
		res := callTool(t, sess, "read_file", map[string]any{"path": filepath.Join(remote, name)})
		if !res.IsError || !strings.Contains(resultText(res), "secret-path rule") {
			t.Errorf("read_file of the agent's %s: error=%v %s", name, res.IsError, resultText(res))
		}
	}
	res := callTool(t, sess, "download", map[string]any{"remote": filepath.Join(remote, "renamed.txt"), "local": "renamed.txt"})
	if !res.IsError || !strings.Contains(resultText(res), "holds a private key") {
		t.Errorf("download of a renamed key: error=%v %s", res.IsError, resultText(res))
	}
	if _, err := os.Lstat(filepath.Join(project, "renamed.txt")); err == nil {
		t.Error("a renamed key reached the workspace")
	}
}

// The files of the running tern mcp are its own wherever they are: with the
// config file, the audit log and the recordings directory inside the
// workspace, upload sends none of them and download creates nothing there.
func TestMCPOwnFilesNeverUploaded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix paths on the agent")
	}
	a := startDirectAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(remote, "x"), []byte("x\n"), 0o644)
	os.MkdirAll(filepath.Join(ws, "rec"), 0o700)
	os.WriteFile(filepath.Join(ws, "rec", "box-mcp-abcdefghijkl-1.cast"), []byte("{\"version\": 2}\n"), 0o600)
	cfg := filepath.Join(ws, "tern.json")
	writeJSON(t, cfg, map[string]any{
		"targets": map[string]any{"box": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK",
			"profile": "files"}},
		"profiles":   map[string]any{"files": map[string]any{"read_paths": []string{remote + "/**"}, "write_paths": []string{remote + "/**"}}},
		"workspace":  ws,
		"audit_log":  filepath.Join(ws, "logs", "audit.jsonl"),
		"record_dir": filepath.Join(ws, "rec"),
	})
	cmd := exec.Command(bin["tern"], "mcp", "--config", cfg)
	cmd.Env = ternEnv("TERN_E2E_TOK=" + a.token)
	sess := connectMCPWith(t, cmd, nil, "")
	for _, local := range []string{"tern.json", "logs/audit.jsonl", "rec/box-mcp-abcdefghijkl-1.cast"} {
		res := callTool(t, sess, "upload", map[string]any{"local": local, "remote": filepath.Join(remote, "sent")})
		if !res.IsError || !strings.Contains(resultText(res), "tern's own files") {
			t.Errorf("upload of %s: error=%v %s", local, res.IsError, resultText(res))
		}
	}
	if _, err := os.Lstat(filepath.Join(remote, "sent")); err == nil {
		t.Error("one of tern's own files reached the agent")
	}
	res := callTool(t, sess, "download", map[string]any{"remote": filepath.Join(remote, "x"), "local": "rec/x.cast"})
	if !res.IsError || !strings.Contains(resultText(res), "tern's own files") {
		t.Errorf("download into the recordings: error=%v %s", res.IsError, resultText(res))
	}
	os.WriteFile(filepath.Join(ws, "notes.txt"), []byte("notes\n"), 0o600)
	if res := callTool(t, sess, "upload", map[string]any{"local": "notes.txt", "remote": filepath.Join(remote, "notes.txt")}); res.IsError {
		t.Errorf("an ordinary upload: %s", resultText(res))
	}
}

// tern mcp refuses to start where it would take a file from, or put its own
// files in, the directory it was started in: a relative path in a path flag,
// a ~/ path without a home directory, and the audit log or terminal state
// file without a state directory. An empty --config is an error, not a fall
// back to the connection flags.
func TestMCPStartupNeedsItsDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the home and state directories come from USERPROFILE and LocalAppData on Windows")
	}
	a := startDirectAgent(t)
	var noHome []string
	for _, kv := range ternEnv("TERN_TOKEN=" + a.token) {
		if !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "XDG_") {
			noHome = append(noHome, kv)
		}
	}
	target := []string{"--addr", a.addr, "--fingerprint", a.fp}
	cfg := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, cfg, map[string]any{"targets": map[string]any{"box": map[string]any{"addr": a.addr, "fingerprint": a.fp,
		"token_env": "TERN_TOKEN"}}, "workspace": "~/tern-work"})
	for _, c := range []struct {
		env  []string
		args []string
		want string
	}{
		{noHome, []string{"mcp", "--config", "~/.config/tern/mcp.json"}, `--config "~/.config/tern/mcp.json" starts with ~, the home directory, which is not known`},
		{noHome, []string{"mcp", "--config", cfg, "--audit-log", "/dev/null"}, `"~/tern-work" starts with ~, the home directory, which is not known`},
		{noHome, append([]string{"mcp", "--workspace", "~/w", "--audit-log", "/dev/null"}, target...), `--workspace "~/w" starts with ~, the home directory, which is not known`},
		{noHome, append([]string{"mcp", "--key", "~/.config/tern/id_tern", "--audit-log", "/dev/null"}, target...), `--key "~/.config/tern/id_tern" starts with ~, the home directory`},
		{noHome, append([]string{"mcp"}, target...), "no place for the audit log"},
		{noHome, append([]string{"mcp", "--persist-ptys", "--audit-log", "/dev/null"}, target...), "no place for the state file"},
		{ternEnv("TERN_TO="+a.cs(t), "TERN_TOKEN="+a.token), []string{"mcp", "--config", ""}, "--config needs the path"},
	} {
		out, refused := runDaemon(t, "tern", c.env, c.args...)
		if !refused || !strings.Contains(out, c.want) {
			t.Errorf("tern %q: refused=%v, want %q in:\n%s", c.args, refused, c.want, out)
		}
	}
	// Every path flag takes an absolute or ~/ path; a relative one, which an
	// MCP client would resolve in the project it has open, is refused.
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, args := range [][]string{
		{"--to-file", "web1.tern1"}, {"--token-file", "web1.token"}, {"--relay-token-file", "./relay.token"},
		{"--key", "id_tern"}, {"-k", "keys/id_tern"}, {"--config", "tern.json"}, {"--workspace", "work"},
		{"--audit-log", "audit.jsonl"}, {"--record-dir", "rec"},
	} {
		flag := strings.TrimLeft(args[0], "-")
		if flag == "k" {
			flag = "key"
		}
		full := append(append([]string{"mcp"}, args...), "--audit-log", audit)
		if flag == "audit-log" {
			full = append([]string{"mcp"}, args...)
		}
		if flag != "config" {
			full = append(full, target...)
		}
		out, refused := runDaemon(t, "tern", ternEnv("TERN_TOKEN="+a.token), full...)
		if want := "--" + flag + ` "` + args[1] + `" is a relative path`; !refused || !strings.Contains(out, want) ||
			!strings.Contains(out, "give an absolute or ~/ path") {
			t.Errorf("tern %q: refused=%v, want %q in:\n%s", full, refused, want, out)
		}
	}
}

// A ~/ path in a flag is the home directory's, also for the files the
// connection flags name, so a token file there works as the plugin's setup
// gives it.
func TestMCPPathFlagsFromHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the home directory comes from USERPROFILE on Windows")
	}
	a := startDirectAgent(t)
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".config", "tern"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".config", "tern", "box.token"), []byte(a.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin["tern"], "mcp", "--addr", a.addr, "--fingerprint", a.fp, "--token-file", "~/.config/tern/box.token",
		"--audit-log", "~/audit.jsonl")
	cmd.Dir = t.TempDir()
	cmd.Env = ternEnv("HOME="+home, "USERPROFILE="+home)
	sess := connectMCPWith(t, cmd, nil, "")
	if res := callTool(t, sess, "run", map[string]any{"argv": []string{"echo", "via-home-token"}}); res.IsError || !strings.Contains(resultText(res), "via-home-token") {
		t.Fatalf("run with a token file from ~/: %s", resultText(res))
	}
	sess.Close()
	if _, err := os.Stat(filepath.Join(home, "audit.jsonl")); err != nil {
		t.Errorf("the audit log is not at ~/audit.jsonl: %v", err)
	}
}
