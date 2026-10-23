// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tern "github.com/ternimal/tern/internal/tern"
)

func TestAuditor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	a, err := OpenAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	code := 0
	for _, e := range []AuditEntry{
		{Phase: "start", Tool: "run", Target: "default", Args: map[string]any{"argv": []string{"uptime"}}},
		{Phase: "end", Tool: "run", Target: "default", ExitCode: &code},
		{Phase: "denied", Tool: "run", Target: "default", Reason: "nope"},
	} {
		if err := a.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("audit log mode %v, want 0600", fi.Mode().Perm())
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var seqs []uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line is not JSON: %q: %v", sc.Text(), err)
		}
		if e.TS == "" {
			t.Fatal("entry has no timestamp")
		}
		seqs = append(seqs, e.Seq)
	}
	if len(seqs) != 3 || seqs[0] != 1 || seqs[2] != 3 {
		t.Fatalf("want 3 entries with seq 1..3, got %v", seqs)
	}
}

// A refusal's reason quotes the command line, so it is redacted like Args.
func TestAuditReasonRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	token := "ghp_" + strings.Repeat("A", 36)
	a.Log(AuditEntry{Phase: "denied", Tool: "run", Reason: `"gh auth login --with-token ` + token + `" is not in the readonly allowlist`})
	a.Log(AuditEntry{Phase: "end", Tool: "run", Error: "exec: DB_PASSWORD=hunter2: not found"})
	a.Close()
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), token) || strings.Contains(string(b), "hunter2") {
		t.Errorf("the audit log holds a secret:\n%s", b)
	}
}

// What json.Marshal leaves raw though a person reading the log would not see
// it, or a terminal showing the log would act on it, is escaped: the model's
// arguments cannot make a logged command read as another, and each line
// still decodes to the exact values.
func TestAuditEscapesHidden(t *testing.T) {
	a := newStackAgent(t)
	srv, audit := stackServer(t, a, ProfileConfig{}, nil) // readonly: echo is allowed
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	arg := "ok \u202e\u2066 hidden \u2069\u202c \u009b2K\u009b1A tag\U000E0041 del\x7f done"
	call(t, cs, "run", map[string]any{"argv": []string{"echo", arg}}, nil, false)
	b, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{0x202e, 0x2066, 0x9b, 0xe0041, 0x7f} {
		if bytes.ContainsRune(b, r) {
			t.Errorf("the audit log holds a raw %U", r)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	for _, l := range lines {
		var e struct {
			Args struct{ Argv []string }
		}
		if err := json.Unmarshal(l, &e); err != nil || len(e.Args.Argv) != 2 || e.Args.Argv[1] != arg {
			t.Errorf("line does not decode to the argument: %s (%v)", l, err)
		}
	}
	if len(lines) != 2 {
		t.Errorf("want start and end, got %d lines", len(lines))
	}
}

// When the log every tool call is written to cannot be written, no tool acts
// and none hands back a result: cancelling a job, closing or resizing a
// terminal, and the listing and reading tools all fail, and the job, the
// terminal and its size stay as they were.
func TestUnwritableLogRefusesTools(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var job JobStartOutput
	call(t, cs, "job_start", map[string]any{"argv": []string{"sleep 30"}, "shell": true}, &job, false)
	var open PTYOpenOutput
	call(t, cs, "pty_open", map[string]any{}, &open, false)

	srv.audit.mu.Lock()
	srv.audit.f.Close() // every write fails from now on
	srv.audit.mu.Unlock()
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"job_cancel", map[string]any{"job_id": job.JobID}},
		{"pty_close", map[string]any{"pty_id": open.PTYID}},
		{"pty_resize", map[string]any{"pty_id": open.PTYID, "cols": 100, "rows": 40}},
		{"list_sessions", map[string]any{}},
		{"agent_info", map[string]any{}},
		{"list_targets", map[string]any{}},
		{"job_poll", map[string]any{"job_id": job.JobID}},
		{"job_list", map[string]any{}},
		{"pty_read", map[string]any{"pty_id": open.PTYID}},
		{"pty_list", map[string]any{}},
		{"run", map[string]any{"argv": []string{"echo hi"}, "shell": true}},
	} {
		if msg := call(t, cs, c.tool, c.args, nil, true); !strings.Contains(msg, "audit log unavailable") {
			t.Errorf("%s with the log unwritable: %q", c.tool, msg)
		}
	}
	if j := srv.lookupJob(job.JobID); j == nil {
		t.Error("the job is gone")
	} else if j.mu.Lock(); j.done || j.cancelled {
		j.mu.Unlock()
		t.Error("the job was cancelled without a log line")
	} else {
		j.mu.Unlock()
	}
	if !slices.Contains(a.sessions(t), open.Session) {
		t.Error("the terminal's session was ended without a log line")
	}
	if cols, rows := srv.lookupPTY(open.PTYID).size(); cols != defaultPTYCols || rows != defaultPTYRows {
		t.Errorf("the terminal was resized to %dx%d without a log line", cols, rows)
	}
}

// A pre-existing audit log open to others is narrowed to its owner.
func TestAuditorTightensExisting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("an existing audit log stayed %04o", fi.Mode().Perm())
	}
}

// With the log unwritable, no tool reaches the agent or changes the
// workspace before it refuses: agent_info and list_sessions do not connect,
// a shell-mode run or job does not probe the OS, and a download creates no
// directories.
func TestUnwritableLogReachesNothing(t *testing.T) {
	a := newStackAgent(t)
	var dials atomic.Int32
	ws := t.TempDir()
	srv, _ := stackServer(t, a, ProfileConfig{Run: RunConfig{Shell: true}, ReadPaths: []string{"/**"}}, func(c *Config) {
		d := c.Targets[0].Dial
		c.Targets[0].Dial = func(ctx context.Context) (*tern.Client, error) { dials.Add(1); return d(ctx) }
		c.Workspace = ws
	})
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	srv.audit.mu.Lock()
	srv.audit.f.Close() // every write fails from now on
	srv.audit.mu.Unlock()
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"agent_info", map[string]any{}},
		{"list_sessions", map[string]any{}},
		{"run", map[string]any{"argv": []string{"echo hi"}, "shell": true}},
		{"job_start", map[string]any{"argv": []string{"echo hi"}, "shell": true}},
		{"download", map[string]any{"remote": "/etc/hostname", "local": "made/by/download/h"}},
	} {
		before := dials.Load()
		if msg := call(t, cs, c.tool, c.args, nil, true); !strings.Contains(msg, "audit log unavailable") {
			t.Errorf("%s with the log unwritable: %q", c.tool, msg)
		}
		if n := dials.Load() - before; n != 0 {
			t.Errorf("%s reached the agent %d times with the log unwritable", c.tool, n)
		}
	}
	if _, err := os.Stat(filepath.Join(ws, "made")); err == nil {
		t.Error("a refused download created directories in the workspace")
	}
}

// Every argument is redacted in the log, whichever tool logs it: a pattern
// pty_read waits for, a path, a key name pty_send refuses.
func TestLogRedactsEveryArgument(t *testing.T) {
	a := newStackAgent(t)
	ws := t.TempDir()
	srv, audit := stackServer(t, a, everything, func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	const key = "AKIAIOSFODNN7EXAMPLE"
	var o PTYOpenOutput
	call(t, cs, "pty_open", map[string]any{}, &o, false)
	call(t, cs, "pty_read", map[string]any{"pty_id": o.PTYID, "until": "token " + key, "wait_ms": 1}, nil, false)
	call(t, cs, "pty_send", map[string]any{"pty_id": o.PTYID, "keys": []string{key}}, nil, true)
	call(t, cs, "read_file", map[string]any{"path": "/nonexistent/" + key}, nil, true)
	call(t, cs, "download", map[string]any{"remote": "/nonexistent/x", "local": "dir/" + key}, nil, true)
	log, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), key) {
		t.Errorf("the log holds the key:\n%s", log)
	}
	if !strings.Contains(string(log), "[REDACTED AWS KEY ID]") {
		t.Errorf("the log shows no redacted argument:\n%s", log)
	}
}

// An argument vector is redacted as the command line it makes, too: an
// option and its value given as two arguments, as they always are without a
// shell, or a client and its option, have the value replaced, in the audit
// log and in job_list; the arguments that hold no secret stay.
func TestRedactArgvAsCommandLine(t *testing.T) {
	const pw = "Hunter2xyzzyQ7"
	for _, c := range []struct{ in, want []string }{
		{[]string{"echo", "--db-password", pw}, []string{"echo", "--db-password", "[REDACTED]"}},
		{[]string{"mysql", "-uroot", "-p" + pw}, []string{"mysql", "-uroot", "[REDACTED]"}},
		{[]string{"redis-cli", "-a", pw, "ping"}, []string{"redis-cli", "-a", "[REDACTED]", "ping"}},
		{[]string{"sshpass", "-p", pw, "ssh", "host"}, []string{"sshpass", "-p", "[REDACTED]", "ssh", "host"}},
		{[]string{"ternd", "--relay-token", pw}, []string{"ternd", "--relay-token", "[REDACTED]"}},
		{[]string{"env", "DB_PASSWORD=" + pw, "app"}, []string{"env", "DB_PASSWORD=[REDACTED]", "app"}},
		{[]string{"ls", "-la", "/tmp"}, []string{"ls", "-la", "/tmp"}},
	} {
		if got := redactAll(c.in); !slices.Equal(got, c.want) {
			t.Errorf("redactAll(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Through the tools: run and refused commands alike.
	a := newStackAgent(t)
	srv, audit := stackServer(t, a, ProfileConfig{}, nil) // readonly: echo runs, the rest is refused
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	call(t, cs, "run", map[string]any{"argv": []string{"echo", "--db-password", pw}}, nil, false)
	for _, argv := range [][]string{{"mysql", "-uroot", "-p" + pw}, {"redis-cli", "-a", pw}, {"sshpass", "-p", pw, "ssh", "host"}} {
		call(t, cs, "run", map[string]any{"argv": argv}, nil, true)
	}
	log, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(log, []byte(pw)) || !bytes.Contains(log, []byte(`"--db-password","[REDACTED]"`)) {
		t.Errorf("the audit log:\n%s", log)
	}
}

// A refused command's reason quotes its command line, the arguments a shell
// would quote in quotes: it is built from the argument vector as redacted, so
// a password the argv field redacts is not in the reason either, whatever
// characters the password holds.
func TestRefusalReasonRedactedAsArgv(t *testing.T) {
	const pw = "Hunter2xyzzy!"
	a := newStackAgent(t)
	srv, audit := stackServer(t, a, ProfileConfig{}, nil) // readonly: all of these are refused
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, argv := range [][]string{
		{"mysql", "-uroot", "-p" + pw, "shop"},
		{"7z", "x", "backup.7z", "-p" + pw},
		{"mongosh", "-u", "admin", "-p" + pw},
		{"ipmitool", "-H", "bmc", "-U", "admin", "-P" + pw, "power", "status"},
		{"htpasswd", "-b", "/etc/nginx/.htpasswd", "bob", pw},
		{"net", "use", `\\srv\share`, pw},
		{"sshpass", "-p", pw, "ssh", "host"},
	} {
		call(t, cs, "run", map[string]any{"argv": argv}, nil, true)
	}
	log, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if strings.Contains(line, "Hunter2") {
			t.Errorf("the audit log holds the password: %s", line)
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil && strings.HasPrefix(e.Reason, `the command 7z x backup.7z "[REDACTED]" is not in the p allowlist`) {
			named = true
		}
	}
	if !named {
		t.Errorf("no reason names the refused 7z command:\n%s", log)
	}
}

// A call rejected by schema validation does not log its raw arguments:
// stdin and write_file content stay out of the audit log, and a secret in
// JSON-escaped quotes is still redacted, as is an option's value given as an
// argument of its own, as the command line the arguments make shows it.
func TestRejectedCallAuditKeepsNoContent(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	pol, _ := NewPolicy("readonly")
	srv, err := New(Config{Version: "test", AuditPath: audit, Targets: []TargetSpec{{
		Target: Target{Name: "t1"}, Policy: pol,
		Dial: func(context.Context) (*tern.Client, error) { return nil, errors.New("none") },
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	srv.MCP().Connect(ctx, st, nil)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "u", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	cs.CallTool(ctx, &mcp.CallToolParams{Name: "run", Arguments: map[string]any{
		"argv": []string{"cat"}, "stdin": "my-db-root-pass-Xyzzy42\n", "timeout_s": -1}})
	cs.CallTool(ctx, &mcp.CallToolParams{Name: "run", Arguments: map[string]any{
		"argv": []string{`DB_PASSWORD="Plugh99"`}, "timeout_s": -1}})
	for _, argv := range [][]string{{"echo", "--db-password", "Frobozz77"}, {"redis-cli", "-a", "Frobozz77", "ping"}, {"mysql", "-uroot", "-pFrobozz77"}} {
		cs.CallTool(ctx, &mcp.CallToolParams{Name: "job_start", Arguments: map[string]any{"argv": argv, "timeout_s": -1}})
		cs.CallTool(ctx, &mcp.CallToolParams{Name: "run", Arguments: map[string]any{"argv": argv, "timeout_s": -1}})
	}
	f, _ := os.Open(audit)
	defer f.Close()
	sc := bufio.NewScanner(f)
	rejected := 0
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, "Xyzzy42") || strings.Contains(l, "Plugh99") || strings.Contains(l, "Frobozz77") {
			t.Errorf("secret in audit log: %s", l)
		}
		if strings.Contains(l, `"phase":"rejected"`) {
			rejected++
		}
	}
	if rejected < 5 {
		t.Errorf("%d rejected calls logged", rejected)
	}
}

// Decoded arguments, as a rejected call's are, are redacted as typed ones:
// the strings of a list as an argument vector, in nested lists and maps too,
// and a list's other values each on its own.
func TestRedactArgsDecodedLists(t *testing.T) {
	const pw = "Frobozz77"
	got := redactArgs(map[string]any{
		"argv":   []any{"echo", "--db-password", pw},
		"nested": map[string]any{"argv": []any{"sshpass", "-p", pw, "ssh", "host"}},
		"mixed":  []any{"--token", pw, 3.0},
		"keys":   []any{"Enter", "C-c"},
	})
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), pw) {
		t.Errorf("redactArgs left the secret: %s", b)
	}
	m := got.(map[string]any)
	if s := fmt.Sprint(m["argv"]); s != "[echo --db-password [REDACTED]]" {
		t.Errorf("argv = %s", s)
	}
	if s := fmt.Sprint(m["keys"]); s != "[Enter C-c]" {
		t.Errorf("keys = %s", s)
	}
}
