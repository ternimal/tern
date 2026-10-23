// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tern "github.com/ternimal/tern/internal/tern"
)

// These tests run the whole stack in one process, so -race sees every
// goroutine: an MCP client, the server, the tern client, and a real agent
// whose terminals run /bin/sh, joined by loopback TCP connections that a test
// can cut.

const stackToken = "stack-test-token-0123456789"

type stackAgent struct {
	agent *tern.Agent
	fp    string

	mu    sync.Mutex
	conns []net.Conn
	down  bool
}

func newStackAgent(t *testing.T) *stackAgent {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	cert, err := tern.LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	return &stackAgent{
		agent: tern.NewAgent(tern.ServerTLSConfig(cert), &tern.AuthConfig{Token: stackToken}, "/bin/sh", time.Minute, ""),
		fp:    tern.CertFingerprint(cert),
	}
}

func (a *stackAgent) dial(ctx context.Context) (*tern.Client, error) {
	a.mu.Lock()
	down := a.down
	a.mu.Unlock()
	if down {
		return nil, errors.New("connection refused")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	cc, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	sc := <-accepted
	if sc == nil {
		cc.Close()
		return nil, errors.New("accept failed")
	}
	a.mu.Lock()
	a.conns = append(a.conns, sc, cc)
	a.mu.Unlock()
	go a.agent.Serve(sc, "stack")
	return tern.Dial(cc, tern.PinnedTLSConfig(a.fp), "", stackToken)
}

// cut drops every connection, as a network failure would; with down set,
// new ones are refused too.
func (a *stackAgent) cut(down bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.conns {
		c.Close()
	}
	a.conns, a.down = nil, down
}

// sessions lists the agent's sessions through a fresh connection.
func (a *stackAgent) sessions(t *testing.T) []string {
	t.Helper()
	cl, err := a.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	names, err := cl.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// stackServer builds a server with one target, "box", on agent a.
func stackServer(t *testing.T, a *stackAgent, prof ProfileConfig, edit func(*Config)) (*Server, string) {
	t.Helper()
	pols, err := BuildPolicies(map[string]ProfileConfig{"p": prof})
	if err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := Config{Version: "test", AuditPath: audit, Targets: []TargetSpec{{
		Target: Target{Name: "box", Mode: "direct", Endpoint: "loopback", Transport: "tls-pinned", ConnectArgs: []string{"--addr", "loopback"}},
		Policy: pols["p"],
		Dial:   a.dial,
	}}}
	if edit != nil {
		edit(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, audit
}

func stackClient(t *testing.T, srv *Server, version string, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "stack", Version: "1"}, opts).Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// call runs a tool and decodes its structured result into out, failing the
// test on a protocol error, or on a tool error unless wantErr says one is
// expected; it returns the error text.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, out any, wantErr bool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	text := resultText(res)
	if res.IsError != wantErr {
		t.Fatalf("%s %v: isError=%v %q", name, args, res.IsError, text)
	}
	if out != nil && !res.IsError {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s: %s: %v", name, b, err)
		}
	}
	return text
}

var everything = ProfileConfig{
	Run:        RunConfig{Shell: true},
	PTY:        true,
	ReadPaths:  []string{"/**"},
	WritePaths: []string{"/tmp/**", "/home/**"},
}

// TestEveryTool calls every tool, and reads the recording resource, with
// clients of both protocol versions on one server.
func TestEveryTool(t *testing.T) {
	a := newStackAgent(t)
	area := t.TempDir()
	srv, _ := stackServer(t, a, everything, func(c *Config) {
		c.Workspace, c.RecordDir = t.TempDir(), t.TempDir()
	})
	defer srv.Close()
	for _, version := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(version, func(t *testing.T) {
			cs := stackClient(t, srv, version, nil)
			if got := cs.InitializeResult().ProtocolVersion; got != version {
				t.Fatalf("negotiated %s", got)
			}
			tools, err := cs.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, tl := range tools.Tools {
				names = append(names, tl.Name)
			}
			want := []string{"agent_info", "download", "job_cancel", "job_list", "job_poll", "job_start", "list_sessions", "list_targets",
				"pty_close", "pty_list", "pty_open", "pty_read", "pty_resize", "pty_run", "pty_send", "read_file", "run", "upload", "write_file"}
			skill, err := os.ReadFile(filepath.Join("..", "..", "plugin", "skills", "ops", "SKILL.md"))
			if err != nil {
				t.Fatal(err)
			}
			for _, tl := range tools.Tools {
				// The plugin's skill tells Claude about every tool.
				if !strings.Contains(string(skill), "`"+tl.Name+"`") && !strings.Contains(string(skill), tl.Name+",") {
					t.Errorf("plugin/skills/ops/SKILL.md does not mention %s", tl.Name)
				}
				// A client shows the title, and reads a missing hint as
				// destructive: every tool spells out which it is.
				if a := tl.Annotations; tl.Title == "" || a == nil || !a.ReadOnlyHint && a.DestructiveHint == nil {
					t.Errorf("%s: title %q, annotations %+v", tl.Name, tl.Title, a)
				}
			}
			if !slices.Equal(names, want) {
				t.Fatalf("tools = %v", names)
			}

			call(t, cs, "list_targets", map[string]any{}, nil, false)
			call(t, cs, "agent_info", map[string]any{}, nil, false)
			call(t, cs, "list_sessions", map[string]any{}, nil, false)
			var run struct{ Output string }
			call(t, cs, "run", map[string]any{"argv": []string{"echo it-runs"}, "shell": true}, &run, false)
			if run.Output != "it-runs\n" {
				t.Fatalf("run = %q", run.Output)
			}
			f := filepath.Join(area, version+".txt")
			call(t, cs, "write_file", map[string]any{"path": f, "content": "written"}, nil, false)
			var rf struct{ Content string }
			call(t, cs, "read_file", map[string]any{"path": f}, &rf, false)
			if rf.Content != "written" {
				t.Fatalf("read_file = %q", rf.Content)
			}
			// Content that is not UTF-8 comes back base64, redacted all the same.
			bin := filepath.Join(area, version+".bin")
			if err := os.WriteFile(bin, []byte("caf\xe9\nDB_PASSWORD=hunter2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var rb struct {
				Content, Encoding string
				Redacted          int
			}
			call(t, cs, "read_file", map[string]any{"path": bin}, &rb, false)
			if dec, _ := base64.StdEncoding.DecodeString(rb.Content); rb.Encoding != "base64" || rb.Redacted != 1 || strings.Contains(string(dec), "hunter2") {
				t.Fatalf("read_file of binary content: %s %d %q", rb.Encoding, rb.Redacted, dec)
			}
			call(t, cs, "download", map[string]any{"remote": f, "local": version + ".txt"}, nil, false)
			call(t, cs, "upload", map[string]any{"local": version + ".txt", "remote": f + ".up"}, nil, false)
			var job struct {
				JobID string `json:"job_id"`
			}
			call(t, cs, "job_start", map[string]any{"argv": []string{"sleep 30"}, "shell": true}, &job, false)
			call(t, cs, "job_poll", map[string]any{"job_id": job.JobID}, nil, false)
			call(t, cs, "job_list", map[string]any{}, nil, false)
			call(t, cs, "job_cancel", map[string]any{"job_id": job.JobID}, nil, false)

			var open struct {
				PTYID  string `json:"pty_id"`
				Prompt string
				Watch  string
			}
			call(t, cs, "pty_open", map[string]any{}, &open, false)
			if open.Prompt != "$ " || !strings.HasPrefix(open.Watch, "tern connect --addr loopback --session mcp-") {
				t.Fatalf("pty_open = %+v", open)
			}
			var pr PTYRunOutput
			call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "echo hi-$((6*7)) DB_PASSWORD=hunter2"}, &pr, false)
			if pr.Output != "hi-42 DB_PASSWORD=[REDACTED]\n" || !pr.PromptDetected || !pr.EchoRemoved || pr.Prompt != "$ " || pr.Redacted != 1 {
				t.Fatalf("pty_run = %+v", pr)
			}
			call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "printf abc"}, &pr, false)
			if pr.Output != "abc" || !pr.PromptDetected {
				t.Fatalf("pty_run printf = %+v", pr)
			}
			var sent PTYSendOutput
			call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "text": "sleep 1; echo slept", "keys": []string{"Enter"}}, &sent, false)
			var rd PTYReadOutput
			call(t, cs, "pty_read", map[string]any{"pty_id": open.PTYID, "since": sent.Offset, "prompt": true}, &rd, false)
			if !rd.PromptDetected || !strings.Contains(rd.Data, "\nslept\n$ ") {
				t.Fatalf("pty_read prompt = %+v", rd)
			}
			call(t, cs, "pty_resize", map[string]any{"pty_id": open.PTYID, "cols": 100, "rows": 40}, nil, false)
			call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "stty size"}, &pr, false)
			if pr.Output != "40 100\n" {
				t.Fatalf("stty size = %q", pr.Output)
			}
			var list PTYListOutput
			call(t, cs, "pty_list", map[string]any{}, &list, false)
			if len(list.Terminals) == 0 {
				t.Fatal("pty_list is empty")
			}

			// The recording, redacted like the output.
			ctx := context.Background()
			tpl, err := cs.ListResourceTemplates(ctx, nil)
			if err != nil || len(tpl.ResourceTemplates) != 1 || tpl.ResourceTemplates[0].URITemplate != "tern://{target}/recording/{pty_id}" {
				t.Fatalf("templates = %+v %v", tpl, err)
			}
			res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "tern://box/recording/" + open.PTYID})
			if err != nil {
				t.Fatal(err)
			}
			cast := res.Contents[0].Text
			if !strings.Contains(cast, `"version":2`) || !strings.Contains(cast, "hi-42") || strings.Contains(cast, "hunter2") {
				t.Fatalf("recording:\n%.400s", cast)
			}
			if _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "tern://box/recording/pty_nope"}); err == nil {
				t.Fatal("an unknown recording must not be found")
			}
			call(t, cs, "pty_close", map[string]any{"pty_id": open.PTYID}, nil, false)
		})
	}
}

// TestPTYReconnectInProcess cuts the connection under a running command and
// checks the output arrives once, with the race detector on every goroutine.
func TestPTYReconnectInProcess(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open struct {
		PTYID string `json:"pty_id"`
	}
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	var pr PTYRunOutput
	call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "echo before-$((1+1))"}, &pr, false)
	var sent PTYSendOutput
	call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "text": "sleep 1; echo during-$((40+2))\r"}, &sent, false)
	// Cut once the shell has the command, not while the keystrokes may still
	// be in flight: input on a connection that drops is lost, as with ssh.
	var rd PTYReadOutput
	call(t, cs, "pty_read", map[string]any{"pty_id": open.PTYID, "since": sent.Offset, "until": `sleep 1; echo`, "wait_ms": 10000}, &rd, false)
	a.cut(false)
	call(t, cs, "pty_read", map[string]any{"pty_id": open.PTYID, "until": `during-42\s`, "wait_ms": 20000}, &rd, false)
	call(t, cs, "pty_read", map[string]any{"pty_id": open.PTYID}, &rd, false)
	if strings.Count(rd.Data, "before-2") != 1 || strings.Count(rd.Data, "during-42") != 1 || strings.Contains(rd.Data, "[tern:") {
		t.Fatalf("output after reconnecting:\n%s", rd.Data)
	}
	call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "echo again"}, &pr, false)
	if pr.Output != "again\n" {
		t.Fatalf("after reconnecting: %+v", pr)
	}
}

// TestPTYPersistence: with a state file, terminals outlive the server and the
// next one reattaches them under the same pty_id, state and all.
func TestPTYPersistence(t *testing.T) {
	a := newStackAgent(t)
	state := filepath.Join(t.TempDir(), "ptys.json")
	persist := func(c *Config) { c.PTYState = state }
	srv1, _ := stackServer(t, a, everything, persist)
	cs1 := stackClient(t, srv1, "", nil)
	var open struct {
		PTYID   string `json:"pty_id"`
		Session string
	}
	call(t, cs1, "pty_open", map[string]any{}, &open, false)
	var pr PTYRunOutput
	call(t, cs1, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "cd / && KEPT=yes"}, &pr, false)

	// A second server cannot take the state file while the first holds it.
	if _, _, err := openPTYStore(state); err == nil || !strings.Contains(err.Error(), "another tern mcp") {
		t.Fatalf("the state file was not locked: %v", err)
	}
	cs1.Close()
	srv1.Close()
	if !slices.Contains(a.sessions(t), open.Session) {
		t.Fatal("the session should have been left running")
	}

	srv2, _ := stackServer(t, a, everything, persist)
	defer srv2.Close()
	cs2 := stackClient(t, srv2, "", nil)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var list PTYListOutput
		call(t, cs2, "pty_list", map[string]any{}, &list, false)
		if len(list.Terminals) == 1 && list.Terminals[0].PTYID == open.PTYID && list.Terminals[0].Connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the terminal was not reattached: %+v", list)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Offsets continue where the last server left off: one it handed out is
	// not past the end, so a reader neither skips nor rereads unrelated bytes.
	var rd PTYReadOutput
	call(t, cs2, "pty_read", map[string]any{"pty_id": open.PTYID, "since": pr.NextOffset, "wait_ms": 2000, "idle_ms": 300}, &rd, false)
	if !strings.Contains(rd.Data, "reattached") {
		t.Fatalf("reading from the last offset %d did not start at the reattach: %+v", pr.NextOffset, rd)
	}
	call(t, cs2, "pty_run", map[string]any{"pty_id": open.PTYID, "command": `echo "$PWD:$KEPT"`}, &pr, false)
	if pr.Output != "/:yes\n" {
		t.Fatalf("state did not survive: %+v", pr)
	}
	call(t, cs2, "pty_close", map[string]any{"pty_id": open.PTYID}, nil, false)
	if slices.Contains(a.sessions(t), open.Session) {
		t.Fatal("pty_close must end the session even when terminals persist")
	}
	if b, _ := os.ReadFile(state); strings.Contains(string(b), open.PTYID) {
		t.Fatalf("a closed terminal stayed in the state file:\n%s", b)
	}
}

// TestPTYPersistenceSessionGone: a saved terminal whose session ended while
// tern mcp was not running is reported ended, not retried forever.
func TestPTYPersistenceSessionGone(t *testing.T) {
	a := newStackAgent(t)
	state := filepath.Join(t.TempDir(), "ptys.json")
	persist := func(c *Config) { c.PTYState = state }
	srv1, _ := stackServer(t, a, everything, persist)
	cs1 := stackClient(t, srv1, "", nil)
	var open struct {
		PTYID string `json:"pty_id"`
	}
	call(t, cs1, "pty_open", map[string]any{}, &open, false)
	cs1.Close()
	srv1.Close()
	// The session ends while no tern mcp runs.
	cl, _ := a.dial(context.Background())
	var sess string
	b, _ := os.ReadFile(state)
	var recs []ptyRecord
	json.Unmarshal(b, &recs)
	if len(recs) == 1 {
		sess = recs[0].Session
	}
	st, err := cl.OpenShell(tern.ShellOptions{Session: sess, Mode: "attach", Write: true})
	if err != nil {
		t.Fatal(err)
	}
	st.EndSession()
	st.CopyOutput(discard{})
	cl.Close()

	srv2, _ := stackServer(t, a, everything, persist)
	defer srv2.Close()
	cs2 := stackClient(t, srv2, "", nil)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var list PTYListOutput
		call(t, cs2, "pty_list", map[string]any{}, &list, false)
		if len(list.Terminals) == 1 && list.Terminals[0].Ended {
			if !strings.Contains(list.Terminals[0].EndReason, "while tern mcp was not running") {
				t.Fatalf("end reason = %q", list.Terminals[0].EndReason)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pty_list = %+v", list)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// A state file that names a session tern mcp did not open, such as one a
// person left running, reattaches nothing: the person's session keeps
// running untouched and the model has no pty_id for it. Nor does a record
// whose pty_id has a shape tern mcp never gives. The next save drops them.
func TestPlantedStateFileReachesNoSession(t *testing.T) {
	a := newStackAgent(t)
	cl, err := a.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st, err := cl.OpenShell(tern.ShellOptions{Session: "work", Mode: "new", Write: true, Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("echo person-output-$((6*7))\r"))
	time.Sleep(300 * time.Millisecond)
	st.Close()
	cl.Close()
	state := filepath.Join(t.TempDir(), "ptys.json")
	planted := `[{"pty_id":"pty_planted","target":"box","endpoint":"loopback","session":"work","attach_id":"planted","cols":80,"rows":24,"opened_at":"2026-01-01T00:00:00Z"},
{"pty_id":"pty_aaaaaaaaaaaaaaaaaaaaaaaaaa","target":"box","endpoint":"loopback","session":"work","attach_id":"planted","cols":80,"rows":24,"opened_at":"2026-01-01T00:00:01Z"},
{"pty_id":"pty_planted","target":"box","endpoint":"loopback","session":"mcp-aaaaaaaaaaaa","attach_id":"planted","cols":80,"rows":24,"opened_at":"2026-01-01T00:00:02Z"},
{"pty_id":"pty_bbbbbbbbbbbbbbbbbbbbbbbbbb","target":"box","endpoint":"loopback","session":"mcp-../../work","attach_id":"planted","cols":80,"rows":24,"opened_at":"2026-01-01T00:00:03Z"}]`
	if err := os.WriteFile(state, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, _ := stackServer(t, a, everything, func(c *Config) { c.PTYState = state })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var list PTYListOutput
	call(t, cs, "pty_list", map[string]any{}, &list, false)
	if len(list.Terminals) != 0 {
		t.Errorf("planted records reattached: %+v", list.Terminals)
	}
	for _, id := range []string{"pty_planted", "pty_aaaaaaaaaaaaaaaaaaaaaaaaaa", "pty_bbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "pty_run", Arguments: map[string]any{"pty_id": id, "command": "echo typed-by-the-model"}})
		if err != nil || !res.IsError {
			t.Errorf("pty_run on planted %s: %v %v", id, res, err)
		}
	}
	if !slices.Contains(a.sessions(t), "work") {
		t.Error("the person's session ended")
	}
	if b, _ := os.ReadFile(state); strings.Contains(string(b), `"work"`) || strings.Contains(string(b), "planted") {
		t.Errorf("the planted records stayed in the state file:\n%s", b)
	}
}

// The model cannot plant a state file through the workspace either: a
// download never creates a file in tern's own state or configuration
// directories, the default ones in a workspace that holds a home directory,
// or the ones this tern uses wherever they are.
func TestDownloadNeverWritesTernState(t *testing.T) {
	a := newStackAgent(t)
	home, remote := t.TempDir(), t.TempDir()
	xdg := filepath.Join(home, "elsewhere", "state")
	os.WriteFile(filepath.Join(remote, "x.json"), []byte(`[]`), 0o644)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{remote + "/**"}}, func(c *Config) {
		c.Workspace, c.TernDirs = home, []string{filepath.Join(xdg, "tern")}
	})
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, local := range []string{".local/state/tern/mcp-ptys-0123456789ab.json", ".config/tern/mcp.json",
		"elsewhere/state/tern/mcp-ptys-0123456789ab.json", "elsewhere/state/tern/recordings/x.cast"} {
		if why := call(t, cs, "download", map[string]any{"remote": remote + "/x.json", "local": local}, nil, true); !strings.Contains(why, "rule") || !strings.Contains(why, "never creates") {
			t.Errorf("download to %s: %s", local, why)
		}
		if _, err := os.Lstat(filepath.Join(home, local)); err == nil {
			t.Errorf("a download created %s", local)
		}
	}
	call(t, cs, "download", map[string]any{"remote": remote + "/x.json", "local": "elsewhere/state/other.json"}, nil, false)
}

// Session names a terminal gets are the ones a saved terminal may name.
func TestPTYSessionNames(t *testing.T) {
	for range 1000 {
		if s, id := newPTYSession(), newHandle("pty_"); !isPTYSession(s) || !isPTYID(id) {
			t.Fatalf("generated %q, %q do not pass", s, id)
		}
	}
	for _, s := range []string{"work", "mcp-", "mcp-AAAAAAAAAAAA", "mcp-aaaaaaaaaaa", "mcp-aaaaaaaaaaaaa", "mcp-aaaaaaaaaaa1",
		"mcp-../../aaaaa", "xmcp-aaaaaaaaaaaa", "mcp-aaaaaaaaaaa\n"} {
		if isPTYSession(s) {
			t.Errorf("%q passes as a session tern mcp names", s)
		}
	}
}

// TestPTYLimitsAndIdle: the profile caps open terminals, and one left unused
// past its idle time is closed, its session ended.
func TestPTYLimitsAndIdle(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Limits = Limits{Terminals: 1, TerminalIdleS: 60}
	srv, audit := stackServer(t, a, prof, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open struct {
		PTYID   string `json:"pty_id"`
		Session string
	}
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	if msg := call(t, cs, "pty_open", map[string]any{}, nil, true); !strings.Contains(msg, "too many open terminals") {
		t.Fatalf("second terminal: %q", msg)
	}
	srv.reapPTYs(time.Now().Add(59 * time.Second))
	if !slices.Contains(a.sessions(t), open.Session) {
		t.Fatal("closed before its idle time")
	}
	srv.reapPTYs(time.Now().Add(61 * time.Second))
	if slices.Contains(a.sessions(t), open.Session) {
		t.Fatal("an idle terminal's session was left running")
	}
	if b, _ := os.ReadFile(audit); !strings.Contains(string(b), "closed after 1m0s without use") {
		t.Fatal("the idle close is not audited")
	}
	call(t, cs, "pty_open", map[string]any{}, nil, false) // the slot is free again
}

// Closing a terminal ends its session on the agent even when the connection
// has just dropped, which can lose the request to end it.
func TestPTYCloseAfterCut(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for range 5 {
		var open struct {
			PTYID   string `json:"pty_id"`
			Session string
		}
		call(t, cs, "pty_open", map[string]any{}, &open, false)
		a.cut(false)
		call(t, cs, "pty_close", map[string]any{"pty_id": open.PTYID}, nil, false)
		deadline := time.Now().Add(5 * time.Second)
		for slices.Contains(a.sessions(t), open.Session) {
			if time.Now().After(deadline) {
				t.Fatalf("session %s still runs on the agent after pty_close", open.Session)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// pty_close ends the terminal and its session at once while what the model
// typed waits for a program that reads none of it, has filled the
// connection, and holds a pty_send blocked: it does not wait for that input,
// nor fall back to timeouts.
func TestPTYCloseWithInputBackedUp(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open struct {
		PTYID   string `json:"pty_id"`
		Session string
	}
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "text": "stty raw -echo; sleep 600\r"}, nil, false)
	time.Sleep(time.Second)
	text := strings.Repeat("y", maxSendBytes)
	blocked := false
	for i := 0; i < 20 && !blocked; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "pty_send", Arguments: map[string]any{"pty_id": open.PTYID, "text": text}})
		cancel()
		blocked = err != nil
	}
	if !blocked {
		t.Fatal("the typed input never backed up")
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "pty_close", Arguments: map[string]any{"pty_id": open.PTYID}}); err != nil {
		t.Fatalf("pty_close: %v", err)
	}
	if d := time.Since(start); d >= ptyEndWait {
		t.Errorf("pty_close took %v, as long as its fallback waits", d)
	}
	deadline := time.Now().Add(5 * time.Second)
	for slices.Contains(a.sessions(t), open.Session) {
		if time.Now().After(deadline) {
			t.Fatalf("session %s still runs on the agent after pty_close", open.Session)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Key names are short, and what they send counts toward the input cap, so a
// call cannot spend minutes unwrapping Alt prefixes or type past the cap.
func TestPTYSendKeyBounds(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open struct {
		PTYID string `json:"pty_id"`
	}
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	start := time.Now()
	long := strings.Repeat("M-", 32<<10) + "x"
	if msg := call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "keys": []string{long}}, nil, true); !strings.Contains(msg, "key name is at most") {
		t.Errorf("a 64 KiB key name: %q", msg)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("refusing a long key name took %s", d)
	}
	keys := make([]string, maxKeys)
	for i := range keys {
		keys[i] = "F12" // 5 bytes each
	}
	text := strings.Repeat("x", maxSendBytes-100)
	if msg := call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "text": text, "keys": keys}, nil, true); !strings.Contains(msg, "bytes of text and keys") {
		t.Errorf("text and keys over the cap: %q", msg)
	}
}

// TestPTYOpenConfirmation: with pty_open in confirm, opening a terminal asks.
func TestPTYOpenConfirmation(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Confirm = []string{"pty_open"}
	srv, _ := stackServer(t, a, prof, nil)
	defer srv.Close()
	answer := "decline"
	var asked []string
	handler := func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked = append(asked, req.Params.Message)
		return &mcp.ElicitResult{Action: answer, Content: map[string]any{"approve": answer == "accept"}}, nil
	}
	cs := stackClient(t, srv, "", &mcp.ClientOptions{ElicitationHandler: handler})
	if msg := call(t, cs, "pty_open", map[string]any{}, nil, true); !strings.Contains(msg, "declined") {
		t.Fatalf("declined open: %q", msg)
	}
	if len(a.sessions(t)) != 0 {
		t.Fatal("a declined terminal was opened")
	}
	answer = "accept"
	call(t, cs, "pty_open", map[string]any{}, nil, false)
	if len(asked) != 2 || !strings.Contains(asked[1], "open an interactive terminal") {
		t.Fatalf("asked %q", asked)
	}
}

// The watch and take_over commands quote each argument for a POSIX shell: a
// connect flag's value, such as a relay id from a tern1: string someone else
// handed out, reaches tern as it is when a person pastes the line, and runs
// nothing.
func TestWatchCommandQuoted(t *testing.T) {
	a := newStackAgent(t)
	marker := filepath.Join(t.TempDir(), "ran")
	fp := strings.Repeat("ab", 32)
	id := "box$(touch " + marker + ")`touch " + marker + "`;touch " + marker + " 'q' \"d\" \\ * -"
	args := []string{"--relay", "relay.example.net:443", "--relay-fingerprint", fp, "--id", id, "--fingerprint", fp}
	srv, _ := stackServer(t, a, everything, func(c *Config) { c.Targets[0].ConnectArgs = args })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open PTYOpenOutput
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	for line, last := range map[string]string{open.Watch: "--read-only", open.TakeOver: "--read-only=false"} {
		// The shell the line is pasted into has a tern that prints its
		// arguments, one per line.
		out, err := exec.Command("sh", "-c", `tern() { printf '%s\n' "$@"; }; `+line).Output()
		want := append(append([]string{"connect"}, args...), "--session", open.Session, last)
		if err != nil || string(out) != strings.Join(want, "\n")+"\n" {
			t.Errorf("%s\nreached tern as %q (%v)", line, out, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("pasting the line ran a command from the relay id")
	}
	// Plain values stay as they are, so the usual line reads plainly.
	if got := (Target{ConnectArgs: []string{"--addr", "[::1]:2222", "--fingerprint", "ab:cd"}}).ConnectCommand("--session", "mcp-x"); got != "tern connect --addr '[::1]:2222' --fingerprint ab:cd --session mcp-x" {
		t.Errorf("ConnectCommand = %s", got)
	}
}

// Error text reaches the model with what a person would not see escaped,
// here the real path an agent reports for a link into a secret directory,
// which holds invisible tag characters.
func TestErrorsEscapeHidden(t *testing.T) {
	a := newStackAgent(t)
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "home", ".ssh")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(secretDir, "id\U000E0049\U000E0047\U000E004E")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(logs, "app.log")); err != nil {
		t.Fatal(err)
	}
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{logs + "/**"}}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	msg := call(t, cs, "read_file", map[string]any{"path": filepath.Join(logs, "app.log")}, nil, true)
	if strings.ContainsFunc(msg, invisible) || !strings.Contains(msg, `.ssh/id\U000e0049\U000e0047\U000e004e`) {
		t.Errorf("the error the model reads: %q", msg)
	}
}

// What pty_send types is logged by its size, never itself or its hash: it may
// be a password typed at a prompt that does not echo it.
func TestPTYSendAuditsSize(t *testing.T) {
	a := newStackAgent(t)
	srv, audit := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open PTYOpenOutput
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	typed := "Tr0ub4dor-typed\r"
	call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "text": typed, "keys": []string{"Enter"}}, nil, false)
	b, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Tr0ub4dor") || strings.Contains(string(b), sha(typed)[:8]) || !strings.Contains(string(b), `"keys":["Enter"],"text_bytes":16}`) {
		t.Errorf("the audit log:\n%s", b)
	}
}

// Ended terminals past the number a target may have open are forgotten,
// oldest first, however many a model opens and ends.
func TestEndedTerminalsCapped(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Limits = Limits{Terminals: 2}
	srv, _ := stackServer(t, a, prof, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var ids []string
	for range 5 {
		var open PTYOpenOutput
		call(t, cs, "pty_open", map[string]any{}, &open, false)
		call(t, cs, "pty_send", map[string]any{"pty_id": open.PTYID, "text": "exit\r"}, nil, false)
		for deadline := time.Now().Add(10 * time.Second); !srv.lookupPTY(open.PTYID).isEnded(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the shell did not exit")
			}
		}
		ids = append(ids, open.PTYID)
	}
	var list PTYListOutput
	call(t, cs, "pty_list", map[string]any{}, &list, false)
	var kept []string
	for _, p := range list.Terminals {
		kept = append(kept, p.PTYID)
	}
	if !slices.Equal(kept, ids[3:]) {
		t.Errorf("kept %v of %v", kept, ids)
	}
}

// The janitor closes a terminal it found idle only if it is still unused as
// closing begins: a call that takes it in between keeps it.
func TestIdleCloseRechecksUse(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open PTYOpenOutput
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	p := srv.lookupPTY(open.PTYID)
	later := time.Now().Add(time.Hour)
	stillIdle := func() bool { return p.inUse == 0 && later.Sub(p.lastUsed) > p.idle }
	p.acquire() // a call takes the terminal after the janitor found it idle
	if srv.closePTYIf(p, true, stillIdle) || p.isEnded() {
		t.Fatal("a terminal in use was closed as idle")
	}
	p.release()
	if !srv.closePTYIf(p, true, stillIdle) || !p.isEnded() {
		t.Fatal("an unused terminal was not closed")
	}
}

// Output over the cap is cut where no secret is cut in part: one the cap
// would split is redacted whole.
func TestRunCapKeepsSecretsWhole(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{Run: RunConfig{Allow: [][]string{{"printf", "*"}}}, Limits: Limits{OutputBytes: 64}}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	tok := "ghp_" + strings.Repeat("A1b2C3d4E5", 4)
	var run RunOutput
	call(t, cs, "run", map[string]any{"argv": []string{"printf", strings.Repeat("x", 50) + " " + tok + "\n"}}, &run, false)
	if !run.Truncated || strings.Contains(run.Output, "A1b2") || run.Redacted != 1 {
		t.Errorf("run = %+v", run)
	}
}

// run without timeout_s waits 30 seconds, but never longer than the
// profile's timeout cap, as pty_run does.
func TestRunDefaultTimeoutCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep")
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{Run: RunConfig{Allow: [][]string{{"sleep", "*"}}}, Limits: Limits{TimeoutS: 1}}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var run RunOutput
	start := time.Now()
	call(t, cs, "run", map[string]any{"argv": []string{"sleep", "10"}}, &run, false)
	if d := time.Since(start); !run.TimedOut || d > 5*time.Second {
		t.Errorf("run without timeout_s under a 1 s cap: timed out %v after %s", run.TimedOut, d)
	}
}

// bash's bracketed paste leaves a partial line after the echoed command; a
// pty_run that times out must still say so.
func TestPTYRunTimeoutUnderBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses bash")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open struct {
		PTYID string `json:"pty_id"`
	}
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	var pr PTYRunOutput
	call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "exec env PS1='b$ ' bash --norc --noprofile -i"}, &pr, false)
	call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "sleep 3; echo m1", "timeout_s": 1}, &pr, false)
	if !pr.TimedOut {
		t.Fatalf("a run still going after its timeout was not reported timed out: %+v", pr)
	}
}

// A terminal a pty_run is waiting on is in use: the idle janitor must not
// close it during a pty_run allowed to wait longer than terminal_idle_s.
func TestPTYNotIdleDuringRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	a := newStackAgent(t)
	prof := everything
	prof.Limits = Limits{TerminalIdleS: 60, TimeoutS: 600}
	srv, _ := stackServer(t, a, prof, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var open struct {
		PTYID string `json:"pty_id"`
	}
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	done := make(chan PTYRunOutput, 1)
	go func() {
		var pr PTYRunOutput
		call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "sleep 2; echo finished", "timeout_s": 300}, &pr, false)
		done <- pr
	}()
	time.Sleep(time.Second)
	// The janitor's view 61 s into the run (lastUsed was set when it began).
	srv.reapPTYs(time.Now().Add(61 * time.Second))
	pr := <-done
	t.Logf("pty_run result: %+v", pr)
	if pr.Ended {
		t.Errorf("the terminal was closed as idle while pty_run was waiting on it")
	}
}

// agent_info checks the agent is reachable each time, although the OS it
// reports is probed once and cached.
func TestAgentInfoReachability(t *testing.T) {
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{}, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var info InfoOutput
	call(t, cs, "agent_info", map[string]any{}, &info, false)
	if !info.Reachable || info.OS == "unknown" {
		t.Fatalf("agent_info on a live agent: %+v", info)
	}
	a.cut(true) // the agent goes down
	call(t, cs, "agent_info", map[string]any{}, &info, false)
	if info.Reachable || info.Error == "" || info.OS == "unknown" {
		t.Fatalf("agent_info on a downed agent: reachable=%v error=%q os=%q", info.Reachable, info.Error, info.OS)
	}
}

// agent_info lists what no profile allows beside what this one does: the
// secret and persistence paths, and the read patterns that serve only files
// every user may read, but for those the profile's own read patterns cover
// whole. Listing /var/log again, or part of /etc, leaves /etc listed.
func TestAgentInfoListsExceptions(t *testing.T) {
	a := newStackAgent(t)
	for _, c := range []struct {
		prof  ProfileConfig
		world []string
	}{
		{ProfileConfig{}, []string{"/etc/**"}},
		{ProfileConfig{ReadPaths: []string{"/etc/**"}}, []string{}},
		{ProfileConfig{ReadPaths: []string{"/**"}}, []string{}},
		{ProfileConfig{ReadPaths: []string{"/e*/**"}}, []string{}},
		{ProfileConfig{ReadPaths: []string{"/var/log/**"}}, []string{"/etc/**"}},
		{ProfileConfig{ReadPaths: []string{"/etc/*"}}, []string{"/etc/**"}},
		{ProfileConfig{ReadPaths: []string{"/etc/nginx/**"}}, []string{"/etc/**"}},
	} {
		srv, _ := stackServer(t, a, c.prof, nil)
		cs := stackClient(t, srv, "", nil)
		var info InfoOutput
		call(t, cs, "agent_info", map[string]any{}, &info, false)
		if !slices.Equal(info.WorldReadableOnly, c.world) || !slices.Contains(info.NeverReadable, "/etc/shadow") ||
			!slices.Contains(info.NeverReadable, "**/.ssh/**") || !slices.Contains(info.NeverWritable, "**/*authorized_keys*") {
			t.Errorf("agent_info for %+v: world_readable_only %q, %d never readable, %d never writable",
				c.prof, info.WorldReadableOnly, len(info.NeverReadable), len(info.NeverWritable))
		}
		srv.Close()
	}
}
