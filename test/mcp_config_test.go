// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPConfigTargets drives tern mcp with a config file naming two real
// agents: "a" on the readonly profile and "b" on an "ops" profile that adds
// shell mode and a writable directory, plus a local workspace. It covers
// target selection, shell mode, write_file, upload, download, and the ways a
// model might try to step outside what the profile or workspace allows.
func TestMCPConfigTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh and Unix paths on the agent")
	}
	a, b := startDirectAgent(t), startDirectAgent(t)
	area := t.TempDir() // b's readable and writable directory (agents run locally)
	ws := t.TempDir()   // the local workspace
	outside := t.TempDir()
	audit := filepath.Join(t.TempDir(), "audit.jsonl")

	cfg := map[string]any{
		"targets": map[string]any{
			"a": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK_A"},
			"b": map[string]any{"addr": b.addr, "fingerprint": b.fp, "token_env": "TERN_E2E_TOK_B", "profile": "ops"},
		},
		"profiles": map[string]any{
			"ops": map[string]any{
				"run":         map[string]any{"shell": true},
				"read_paths":  []string{area + "/**"},
				"write_paths": []string{area + "/**"},
			},
		},
		"workspace": ws,
	}
	cfgPath := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, cfgPath, cfg)
	cmd := exec.Command(bin["tern"], "mcp", "--config", cfgPath, "--audit-log", audit)
	cmd.Env = append(os.Environ(), "TERN_E2E_TOK_A="+a.token, "TERN_E2E_TOK_B="+b.token)
	sess := connectMCP(t, cmd)

	// The tool list is the union of what any target could use.
	tools, err := sess.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		// The ops target can change its host, so starting or stopping its
		// commands is not read-only; reading job output always is.
		readOnly := tl.Annotations != nil && tl.Annotations.ReadOnlyHint
		switch tl.Name {
		case "job_start", "job_cancel", "run":
			if readOnly {
				t.Errorf("%s must not be annotated read-only when a profile allows shell mode", tl.Name)
			}
		case "job_poll", "job_list":
			if !readOnly {
				t.Errorf("%s should be annotated read-only", tl.Name)
			}
		}
	}
	if got := strings.Join(names, ","); got != "agent_info,download,job_cancel,job_list,job_poll,job_start,list_sessions,list_targets,read_file,run,upload,write_file" {
		t.Fatalf("tools = %s", got)
	}

	var targets struct {
		Targets []struct {
			Name, Profile  string
			Default, Shell bool
			CanWrite       bool `json:"can_write"`
		} `json:"targets"`
	}
	structured(t, callTool(t, sess, "list_targets", map[string]any{}), &targets)
	if len(targets.Targets) != 2 || targets.Targets[0].Name != "a" || targets.Targets[1].Profile != "ops" ||
		!targets.Targets[1].Shell || !targets.Targets[1].CanWrite || targets.Targets[0].CanWrite || targets.Targets[0].Default {
		t.Fatalf("list_targets = %+v", targets)
	}

	mustDeny := func(tool string, args map[string]any, want string) {
		t.Helper()
		res := callTool(t, sess, tool, args)
		if !res.IsError || !strings.Contains(resultText(res), want) {
			t.Errorf("%s %v: want a denial mentioning %q, got error=%v %q", tool, args, want, res.IsError, resultText(res))
		}
	}
	type runOut struct {
		Target   string `json:"target"`
		ExitCode int    `json:"exit_code"`
		Output   string `json:"output"`
	}
	runOK := func(args map[string]any) runOut {
		t.Helper()
		res := callTool(t, sess, "run", args)
		if res.IsError {
			t.Fatalf("run %v: %s", args, resultText(res))
		}
		var o runOut
		structured(t, res, &o)
		return o
	}

	// With two targets and no default, a call must say which one.
	mustDeny("run", map[string]any{"argv": []string{"uptime"}}, "name a target")
	mustDeny("run", map[string]any{"target": "zz", "argv": []string{"uptime"}}, `unknown target "zz"`)
	if o := runOK(map[string]any{"target": "a", "argv": []string{"echo", "FROM_A"}}); o.Target != "a" || !strings.Contains(o.Output, "FROM_A") {
		t.Fatalf("run on a = %+v", o)
	}

	// Shell mode only where the profile allows it.
	if o := runOK(map[string]any{"target": "b", "shell": true, "argv": []string{"echo shell ok | tr a-z A-Z"}}); !strings.Contains(o.Output, "SHELL OK") {
		t.Fatalf("shell mode on b = %+v", o)
	}
	mustDeny("run", map[string]any{"target": "a", "shell": true, "argv": []string{"id"}}, "shell mode is not allowed")

	// write_file then read it back.
	content := "written through tern mcp\n"
	sum := sha256.Sum256([]byte(content))
	var w struct {
		Path, SHA256 string
		Bytes        int
	}
	// write_file does not create directories: the agent writes a temp file
	// beside the target, so the parent must already exist.
	if res := callTool(t, sess, "write_file", map[string]any{"target": "b", "path": area + "/notes/new.txt", "content": content}); !res.IsError {
		t.Fatal("writing into a missing directory should fail")
	}
	if err := os.MkdirAll(filepath.Join(area, "notes"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := callTool(t, sess, "write_file", map[string]any{"target": "b", "path": area + "/notes/new.txt", "content": content})
	structured(t, res, &w)
	if res.IsError || w.Bytes != len(content) || w.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("write_file = %+v %q", w, resultText(res))
	}
	if got, err := os.ReadFile(filepath.Join(area, "notes", "new.txt")); err != nil || string(got) != content {
		t.Fatalf("file on disk = %q, %v", got, err)
	}
	var back struct{ Content string }
	structured(t, callTool(t, sess, "read_file", map[string]any{"target": "b", "path": area + "/notes/new.txt"}), &back)
	if back.Content != content {
		t.Fatalf("read back %q", back.Content)
	}
	mustDeny("write_file", map[string]any{"target": "a", "path": "/tmp/x", "content": "x"}, "does not allow writing")
	mustDeny("write_file", map[string]any{"target": "b", "path": area + "/.ssh/authorized_keys", "content": "ssh-ed25519 AAAA"}, "secret-path rule")
	mustDeny("write_file", map[string]any{"target": "b", "path": area + "/../escape.txt", "content": "x"}, "outside the paths")
	mustDeny("write_file", map[string]any{"target": "b", "path": area + "/x", "content": "x", "mode": "4755"}, "no setuid")

	// upload from the workspace, then download into it.
	if err := os.WriteFile(filepath.Join(ws, "up.txt"), []byte("uploaded\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res = callTool(t, sess, "upload", map[string]any{"target": "b", "local": "up.txt", "remote": area + "/up.txt"})
	if res.IsError {
		t.Fatalf("upload: %s", resultText(res))
	}
	if got, _ := os.ReadFile(filepath.Join(area, "up.txt")); string(got) != "uploaded\n" {
		t.Fatalf("uploaded file = %q", got)
	}
	res = callTool(t, sess, "download", map[string]any{"target": "b", "remote": area + "/notes/new.txt", "local": "dl/new.txt"})
	if res.IsError {
		t.Fatalf("download: %s", resultText(res))
	}
	if got, _ := os.ReadFile(filepath.Join(ws, "dl", "new.txt")); string(got) != content {
		t.Fatalf("downloaded file = %q", got)
	}
	mustDeny("download", map[string]any{"target": "b", "remote": area + "/notes/new.txt", "local": "dl/new.txt"}, "never overwrite")
	mustDeny("download", map[string]any{"target": "b", "remote": "/etc/shadow", "local": "shadow"}, "secret-path rule")

	// The workspace cannot be left, by .., an absolute path or a symlink.
	if err := os.WriteFile(filepath.Join(outside, "private.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	mustDeny("upload", map[string]any{"target": "b", "local": "../" + filepath.Base(outside) + "/private.txt", "remote": area + "/stolen"}, "denied")
	mustDeny("upload", map[string]any{"target": "b", "local": "link/private.txt", "remote": area + "/stolen"}, "denied")
	mustDeny("upload", map[string]any{"target": "b", "local": filepath.Join(outside, "private.txt"), "remote": area + "/stolen"}, "relative to the workspace")
	mustDeny("download", map[string]any{"target": "b", "remote": area + "/up.txt", "local": "link/planted.txt"}, "denied")
	if _, err := os.Stat(filepath.Join(area, "stolen")); err == nil {
		t.Fatal("a file from outside the workspace reached the agent")
	}
	if _, err := os.Stat(filepath.Join(outside, "planted.txt")); err == nil {
		t.Fatal("a download escaped the workspace through a symlink")
	}

	sess.Close()
	log, _ := os.ReadFile(audit)
	if strings.Contains(string(log), "written through tern mcp") || strings.Contains(string(log), "uploaded") && strings.Contains(string(log), `"content"`) {
		t.Fatal("file contents must not be copied into the audit log, only their hash")
	}
	if !strings.Contains(string(log), hex.EncodeToString(sum[:])) {
		t.Fatal("the audit log should record the written content's hash")
	}
}

// TestMCPConfigRejectsInlineSecret checks that a token pasted into the config
// file is refused with a pointer to the *_env and *_file fields.
func TestMCPConfigRejectsInlineSecret(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, cfgPath, map[string]any{
		"targets": map[string]any{"a": map[string]any{"addr": "127.0.0.1:1", "fingerprint": "ab", "token": "s3cret-inline-token"}},
	})
	out, err := exec.Command(bin["tern"], "mcp", "--config", cfgPath).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "_env or *_file") {
		t.Fatalf("an inline secret must be refused, got err=%v\n%s", err, out)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startConfigMCP runs tern mcp with a config whose targets all reach agent a,
// each under its own profile, and connects a client asking for protocol
// version, or the latest for "".
func startConfigMCP(t *testing.T, a agent, targets map[string]string, profiles map[string]any, opts *mcp.ClientOptions, version string) (*mcp.ClientSession, string) {
	t.Helper()
	tg := map[string]any{}
	for name, profile := range targets {
		tg[name] = map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK", "profile": profile}
	}
	cfgPath := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, cfgPath, map[string]any{"targets": tg, "profiles": profiles})
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(bin["tern"], "mcp", "--config", cfgPath, "--audit-log", audit)
	cmd.Env = append(os.Environ(), "TERN_E2E_TOK="+a.token)
	return connectMCPWith(t, cmd, opts, version), audit
}

// TestMCPConfigPathFromHome starts tern mcp the way a plugin does: with no
// shell in between, so a config path that starts with ~/ reaches tern as
// written and tern expands it.
func TestMCPConfigPathFromHome(t *testing.T) {
	a := startDirectAgent(t)
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "tern")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(cfgDir, "mcp.json"), map[string]any{"targets": map[string]any{
		"box": map[string]any{"addr": a.addr, "fingerprint": a.fp, "token_env": "TERN_E2E_TOK"},
	}})
	cmd := exec.Command(bin["tern"], "mcp", "--config", "~/.config/tern/mcp.json",
		"--audit-log", filepath.Join(t.TempDir(), "audit.jsonl"))
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "TERN_E2E_TOK="+a.token)
	sess := connectMCPWith(t, cmd, nil, "")
	res := callTool(t, sess, "list_targets", map[string]any{})
	if res.IsError || !strings.Contains(resultText(res), "box") {
		t.Fatalf("list_targets: %s", resultText(res))
	}
}
