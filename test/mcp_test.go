// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// startMCP spawns `tern mcp` against agent a and connects an MCP client to it
// over stdio, the way Claude Code or Claude Desktop would.
func startMCP(t *testing.T, a agent, audit string, extra ...string) *mcp.ClientSession {
	t.Helper()
	args := append([]string{"mcp", "--addr", a.addr, "--fingerprint", a.fp, "--audit-log", audit}, extra...)
	cmd := exec.Command(bin["tern"], args...)
	cmd.Env = append(os.Environ(), "TERN_TOKEN="+a.token)
	return connectMCP(t, cmd)
}

// connectMCP runs cmd as an MCP server over stdio and connects a client.
func connectMCP(t *testing.T, cmd *exec.Cmd) *mcp.ClientSession {
	t.Helper()
	return connectMCPWith(t, cmd, nil, "")
}

// connectMCPWith is connectMCP with client options, such as an elicitation
// handler standing in for the user, and a protocol version to ask for, or ""
// for the latest.
func connectMCPWith(t *testing.T, cmd *exec.Cmd, opts *mcp.ClientOptions, version string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "tern-e2e", Version: "test"}, opts)
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("connect to tern mcp: %v\nstderr:\n%s", err, stderr.String())
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func callTool(t *testing.T, sess *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func structured(t *testing.T, res *mcp.CallToolResult, into any) {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("structured content %s: %v", raw, err)
	}
}

// TestMCPReadonly drives tern mcp end to end: the tool list, agent_info, an
// allowed command, a command the readonly policy denies, and the audit trail
// those calls leave. A clean protocol session also proves tern mcp keeps
// stdout free of anything but JSON-RPC.
func TestMCPReadonly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the readonly allowlist names Unix commands")
	}
	a := startDirectAgent(t)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	sess := startMCP(t, a, audit)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Errorf("tool %s should be annotated read-only in the readonly profile", tl.Name)
		}
	}
	if want := "agent_info,list_sessions,list_targets,read_file,run"; strings.Join(names, ",") != want {
		t.Fatalf("tools = %v, want %s in deterministic order", names, want)
	}

	var info struct {
		OS, Transport, Profile string
		AllowedCommands        []string `json:"allowed_commands"`
	}
	res := callTool(t, sess, "agent_info", map[string]any{})
	if res.IsError {
		t.Fatalf("agent_info failed: %s", resultText(res))
	}
	structured(t, res, &info)
	if info.OS != runtime.GOOS || info.Transport != "tls-pinned" || info.Profile != "readonly" || len(info.AllowedCommands) == 0 {
		t.Fatalf("agent_info = %+v", info)
	}

	var out struct {
		ExitCode int    `json:"exit_code"`
		Output   string `json:"output"`
		TimedOut bool   `json:"timed_out"`
	}
	res = callTool(t, sess, "run", map[string]any{"argv": []string{"echo", "MCP_OK_57"}})
	if res.IsError {
		t.Fatalf("allowed run failed: %s", resultText(res))
	}
	structured(t, res, &out)
	if out.ExitCode != 0 || !strings.Contains(out.Output, "MCP_OK_57") || out.TimedOut {
		t.Fatalf("run echo = %+v", out)
	}

	res = callTool(t, sess, "run", map[string]any{"argv": []string{"bash", "-c", "id"}})
	if !res.IsError || !strings.Contains(resultText(res), "denied: ") {
		t.Fatalf("bash -c must be denied with an explanation, got error=%v %q", res.IsError, resultText(res))
	}

	// Schema validation rejects malformed calls before they reach the handler:
	// argv must be a non-empty array of non-empty strings, timeout_s >= 0, and
	// unknown arguments are not accepted.
	for _, bad := range []map[string]any{
		{"argv": "uptime"},
		{"argv": nil},
		{"argv": []string{}},
		{"argv": []string{""}},
		{"argv": []string{"uptime"}, "timeout_s": -1},
		{"argv": []string{"uptime"}, "cwd": "/tmp"},
	} {
		res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "run", Arguments: bad})
		if err == nil && !res.IsError {
			t.Errorf("run %v must be rejected by the input schema", bad)
		}
	}
	// shell is a valid argument, but the readonly profile refuses shell mode.
	res = callTool(t, sess, "run", map[string]any{"argv": []string{"id"}, "shell": true})
	if !res.IsError || !strings.Contains(resultText(res), "shell mode is not allowed") {
		t.Fatalf("readonly must refuse shell mode, got error=%v %q", res.IsError, resultText(res))
	}

	sess.Close()
	// Every call is audited, including the six the schema rejected before they
	// reached a handler.
	phases := auditPhases(t, audit)
	want := []string{"agent_info:start", "agent_info:info", "run:start", "run:end", "run:denied"}
	for range 6 {
		want = append(want, "run:rejected")
	}
	want = append(want, "run:denied")
	if strings.Join(phases, " ") != strings.Join(want, " ") {
		t.Fatalf("audit phases = %v, want %v", phases, want)
	}
}

// TestMCPFilesAndRedaction covers read_file (allowed, paged, denied, path
// tricks), list_sessions, and secret redaction in both results and the audit
// log, against a real agent.
func TestMCPFilesAndRedaction(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /etc/os-release on the agent")
	}
	a := startDirectAgent(t)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	sess := startMCP(t, a, audit)

	type readOut struct {
		Path       string `json:"path"`
		Size       int64  `json:"size"`
		NextOffset int64  `json:"next_offset"`
		Content    string `json:"content"`
		Encoding   string `json:"encoding"`
		Truncated  bool   `json:"truncated"`
	}
	var whole, first, rest readOut
	res := callTool(t, sess, "read_file", map[string]any{"path": "/etc/os-release"})
	if res.IsError {
		t.Fatalf("read /etc/os-release: %s", resultText(res))
	}
	structured(t, res, &whole)
	if !strings.Contains(whole.Content, "ID=") || whole.Encoding != "utf8" || whole.Truncated || int64(len(whole.Content)) > whole.Size {
		t.Fatalf("read_file = %+v", whole)
	}
	structured(t, callTool(t, sess, "read_file", map[string]any{"path": "/etc/os-release", "max_bytes": 10}), &first)
	if !first.Truncated || first.NextOffset != 10 || len(first.Content) != 10 {
		t.Fatalf("first page = %+v", first)
	}
	structured(t, callTool(t, sess, "read_file", map[string]any{"path": "/etc/os-release", "offset": first.NextOffset}), &rest)
	if first.Content+rest.Content != whole.Content || rest.Truncated {
		t.Fatalf("pages do not reassemble the file: %q + %q", first.Content, rest.Content)
	}

	for _, p := range []string{"/etc/shadow", "/var/log/../../etc/shadow", "etc/os-release", "/root/x"} {
		if res := callTool(t, sess, "read_file", map[string]any{"path": p}); !res.IsError || !strings.Contains(resultText(res), "denied") {
			t.Errorf("read_file %q must be denied, got %q", p, resultText(res))
		}
	}

	var sessions struct {
		Sessions []string `json:"sessions"`
	}
	res = callTool(t, sess, "list_sessions", map[string]any{})
	structured(t, res, &sessions)
	if res.IsError || sessions.Sessions == nil {
		t.Fatalf("list_sessions should return an empty list, not null: %q", resultText(res))
	}

	var out struct {
		Output   string `json:"output"`
		Redacted int    `json:"redacted"`
	}
	res = callTool(t, sess, "run", map[string]any{"argv": []string{"echo", "DB_PASSWORD=hunter2", "AKIAIOSFODNN7EXAMPLE"}})
	structured(t, res, &out)
	if strings.Contains(out.Output, "hunter2") || strings.Contains(out.Output, "AKIAIOSFODNN7EXAMPLE") || out.Redacted != 2 {
		t.Fatalf("secrets must be redacted from output: %+v", out)
	}
	sess.Close()
	if b, _ := os.ReadFile(audit); strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secrets must be redacted from the audit log too:\n%s", b)
	}
}

// TestMCPRefusesInsecureTransport checks that an AI-facing server will not run
// over a connection a man in the middle could tamper with, unless overridden.
func TestMCPRefusesInsecureTransport(t *testing.T) {
	a := startDirectAgent(t)
	cmd := exec.Command(bin["tern"], "mcp", "--addr", a.addr, "--insecure-skip-fingerprint",
		"--audit-log", filepath.Join(t.TempDir(), "a.jsonl"))
	cmd.Env = append(os.Environ(), "TERN_TOKEN="+a.token)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "--allow-insecure-transport") {
		t.Fatalf("tern mcp with --insecure-skip-fingerprint must refuse to start, got err=%v\n%s", err, out)
	}
}

func auditPhases(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var phases []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e struct{ Tool, Phase, Client string }
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("audit line is not JSON: %q", sc.Text())
		}
		if e.Client != "tern-e2e/test" {
			t.Errorf("audit entry should name the calling client, got %q", e.Client)
		}
		phases = append(phases, e.Tool+":"+e.Phase)
	}
	return phases
}
