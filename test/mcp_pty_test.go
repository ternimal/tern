// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"encoding/base64"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// termProfiles are the profiles the terminal tests use: term may open
// terminals freely, guarded must ask before anything is typed, and shellonly
// has shell mode but no terminals.
var termProfiles = map[string]any{
	"term":      map[string]any{"run": map[string]any{"shell": true}, "pty": true},
	"guarded":   map[string]any{"extends": "term", "confirm": []string{"run:shell"}},
	"shellonly": map[string]any{"run": map[string]any{"shell": true}},
}

// pick chooses the command for the agent's shell: sh, or cmd.exe on Windows,
// where ^ escapes a character, so "echo hi-^4^2" echoes as typed but prints
// hi-42, as "echo hi-$((6*7))" does in sh.
func pick(sh, cmd string) string {
	if runtime.GOOS == "windows" {
		return cmd
	}
	return sh
}

// humanCanAttach reports whether this host can run tern connect under a
// PTY, which Windows runners without a console cannot.
func humanCanAttach() bool {
	return runtime.GOOS != "windows" || os.Getenv("TERN_E2E_PTY") != ""
}

// needConPTY skips a terminal test on a Windows host that is not known to
// run ConPTY sessions, as hosted CI runners without a console are not; run
// them from a real Windows console or SSH session with TERN_E2E_PTY=1.
func needConPTY(t *testing.T) {
	t.Helper()
	if !humanCanAttach() {
		t.Skip("terminal test on Windows: set TERN_E2E_PTY=1 where ConPTY sessions work")
	}
}

// startMCPConfig runs tern mcp with config cfg, the token in TERN_E2E_TOK.
func startMCPConfig(t *testing.T, cfg map[string]any, token string, opts *mcp.ClientOptions) (*mcp.ClientSession, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "mcp.json")
	writeJSON(t, cfgPath, cfg)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(bin["tern"], "mcp", "--config", cfgPath, "--audit-log", audit)
	cmd.Env = append(os.Environ(), "TERN_E2E_TOK="+token)
	return connectMCPWith(t, cmd, opts, ""), audit
}

func target(addr, fp, profile string) map[string]any {
	return map[string]any{"addr": addr, "fingerprint": fp, "token_env": "TERN_E2E_TOK", "profile": profile}
}

type ptyOpen struct {
	PTYID                             string `json:"pty_id"`
	Session, Watch, Recording, Prompt string
	TakeOver                          string `json:"take_over"`
}

func openTerm(t *testing.T, sess *mcp.ClientSession, args map[string]any) ptyOpen {
	t.Helper()
	res := callTool(t, sess, "pty_open", args)
	if res.IsError {
		t.Fatalf("pty_open: %s", resultText(res))
	}
	var o ptyOpen
	structured(t, res, &o)
	return o
}

type ptyRun struct {
	Output         string
	Prompt         string
	PromptDetected bool  `json:"prompt_detected"`
	EchoRemoved    bool  `json:"echo_removed"`
	NextOffset     int64 `json:"next_offset"`
	Matched        bool
	Quiet          bool
	TimedOut       bool `json:"timed_out"`
}

// termCmd runs a command in terminal id and waits for the prompt to return.
func termCmd(t *testing.T, sess *mcp.ClientSession, id, command string) ptyRun {
	t.Helper()
	res := callTool(t, sess, "pty_run", map[string]any{"pty_id": id, "command": command, "timeout_s": 15})
	if res.IsError {
		t.Fatalf("pty_run %q: %s", command, resultText(res))
	}
	var r ptyRun
	structured(t, res, &r)
	if !r.PromptDetected || !r.EchoRemoved {
		t.Fatalf("pty_run %q: the prompt did not come back: %+v", command, r)
	}
	return r
}

// termRun runs a command in terminal id and waits for want in the output.
func termRun(t *testing.T, sess *mcp.ClientSession, id, command, want string) ptyRun {
	t.Helper()
	res := callTool(t, sess, "pty_run", map[string]any{"pty_id": id, "command": command, "until": want, "timeout_s": 15})
	if res.IsError {
		t.Fatalf("pty_run %q: %s", command, resultText(res))
	}
	var r ptyRun
	structured(t, res, &r)
	if !r.Matched || !regexp.MustCompile(want).MatchString(r.Output) {
		t.Fatalf("pty_run %q: want %q in %+v", command, want, r)
	}
	return r
}

type ptyRead struct {
	Data           string
	Encoding       string
	NextOffset     int64 `json:"next_offset"`
	PromptDetected bool  `json:"prompt_detected"`
	Matched        bool
	Ended          bool
	EndReason      string `json:"end_reason"`
	Connected      bool
}

func termRead(t *testing.T, sess *mcp.ClientSession, args map[string]any) ptyRead {
	t.Helper()
	res := callTool(t, sess, "pty_read", args)
	if res.IsError {
		t.Fatalf("pty_read: %s", resultText(res))
	}
	var r ptyRead
	structured(t, res, &r)
	return r
}

// TestMCPPTY drives a terminal end to end: state that carries over between
// commands, interrupting with a named key, text and raw output, resizing, a
// person watching live with tern connect --read-only, closing, the recording
// and the audit trail.
func TestMCPPTY(t *testing.T) {
	needConPTY(t)
	a := startDirectAgent(t)
	rec := t.TempDir()
	sess, audit := startMCPConfig(t, map[string]any{
		"targets": map[string]any{"box": target(a.addr, a.fp, "term")}, "profiles": termProfiles, "record_dir": rec,
	}, a.token, nil)

	o := openTerm(t, sess, map[string]any{})
	prompt := pick("$ ", ">")
	if !strings.HasPrefix(o.Session, "mcp-") || !strings.HasPrefix(o.PTYID, "pty_") || !strings.HasSuffix(o.Prompt, prompt) ||
		o.Watch != "tern connect --addr "+a.addr+" --fingerprint "+a.fp+" --session "+o.Session+" --read-only" ||
		strings.Contains(o.Watch+o.TakeOver, a.token) || !strings.HasSuffix(o.TakeOver, "--read-only=false") {
		t.Fatalf("pty_open = %+v", o)
	}

	// The output comes back without the echoed command and the prompt.
	if r := termCmd(t, sess, o.PTYID, pick("echo hi-$((6*7))", "echo hi-^4^2")); r.Output != "hi-42\n" || !strings.HasSuffix(r.Prompt, prompt) {
		t.Fatalf("pty_run = %+v", r)
	}
	// State carries over between commands.
	if r := termCmd(t, sess, o.PTYID, pick("cd / && TERN_PTY_VAR=kept", `cd C:\Windows & set TERN_PTY_VAR=kept`)); strings.TrimSpace(r.Output) != "" {
		t.Fatalf("pty_run = %+v", r)
	}
	want := pick("at:/:kept\n", "at:C:\\Windows:kept\n")
	if r := termCmd(t, sess, o.PTYID, pick(`echo "at:$PWD:$TERN_PTY_VAR"`, "echo at:%CD%:%TERN_PTY_VAR%")); r.Output != want {
		t.Fatalf("pty_run = %+v, want %q", r, want)
	}
	// until ends the wait as soon as it matches.
	termRun(t, sess, o.PTYID, pick("echo until-$((1+2)); sleep 20", "echo until-^3 & ping -n 20 127.0.0.1 >nul"), "until-3")
	callTool(t, sess, "pty_send", map[string]any{"pty_id": o.PTYID, "keys": []string{"C-c"}})
	termRead(t, sess, map[string]any{"pty_id": o.PTYID, "prompt": true})

	// A named key interrupts a running command.
	if res := callTool(t, sess, "pty_send", map[string]any{"pty_id": o.PTYID, "text": pick("sleep 30", "ping -n 30 127.0.0.1 >nul"), "keys": []string{"Enter"}}); res.IsError {
		t.Fatalf("pty_send: %s", resultText(res))
	}
	time.Sleep(300 * time.Millisecond)
	res := callTool(t, sess, "pty_send", map[string]any{"pty_id": o.PTYID, "keys": []string{"C-c"}})
	if res.IsError {
		t.Fatalf("pty_send C-c: %s", resultText(res))
	}
	var sent struct{ Offset int64 }
	structured(t, res, &sent)
	// The interrupted command may print a little more; wait for the prompt.
	if r := termRead(t, sess, map[string]any{"pty_id": o.PTYID, "since": sent.Offset, "prompt": true}); !r.PromptDetected {
		t.Fatalf("C-c did not bring the prompt back: %+v", r)
	}
	if r := termCmd(t, sess, o.PTYID, pick("echo after-$((1+1))", "echo after-^2")); r.Output != "after-2\n" {
		t.Fatalf("after C-c: %+v", r)
	}

	if runtime.GOOS != "windows" {
		// Text output drops escape sequences; raw output keeps them, base64
		// encoded, so no client shows them to a terminal by accident.
		if r := termCmd(t, sess, o.PTYID, `printf '\033[31mRED\033[0m\n'`); r.Output != "RED\n" {
			t.Fatalf("text output kept an escape sequence: %q", r.Output)
		}
		raw := termRead(t, sess, map[string]any{"pty_id": o.PTYID, "format": "raw"})
		if b, err := base64.StdEncoding.DecodeString(raw.Data); raw.Encoding != "base64" || err != nil || !strings.Contains(string(b), "\x1b[31mRED") {
			t.Fatalf("raw read = %q (%s)", raw.Data, raw.Encoding)
		}
	}

	if res := callTool(t, sess, "pty_resize", map[string]any{"pty_id": o.PTYID, "cols": 100, "rows": 40}); res.IsError {
		t.Fatalf("pty_resize: %s", resultText(res))
	}
	// Windows' ConPTY repaints the screen after a resize; let that settle so
	// the next command's output does not start inside the repaint.
	termRead(t, sess, map[string]any{"pty_id": o.PTYID, "idle_ms": 500, "wait_ms": 5000})
	size := regexp.MustCompile(pick(`^40 100\n$`, `(?s)Lines:\s+40\b.*Columns:\s+100\b`))
	if r := termCmd(t, sess, o.PTYID, pick("stty size", "mode con")); !size.MatchString(r.Output) {
		t.Fatalf("after resizing: %q", r.Output)
	}

	// A person watches: the replay shows what happened, then output is live.
	var viewer *ptyConn
	if humanCanAttach() {
		watch := strings.Fields(o.Watch)[1:]
		viewer = dialPTY(t, "tern", append(watch, "--token", a.token)...)
		if !viewer.waitFor("read-only", 15*time.Second) || !viewer.waitFor("hi-42", 10*time.Second) {
			t.Fatalf("the watcher did not attach read-only with the history:\n%s", viewer.buf.String())
		}
		termRun(t, sess, o.PTYID, pick("echo live-$((5*5))", "echo live-^2^5"), "live-25")
		if !viewer.waitFor("live-25", 10*time.Second) {
			t.Fatalf("the watcher did not see live output:\n%s", viewer.buf.String())
		}
	}

	var list struct {
		Terminals []struct {
			PTYID     string `json:"pty_id"`
			Connected bool
		}
	}
	structured(t, callTool(t, sess, "pty_list", map[string]any{}), &list)
	if len(list.Terminals) != 1 || list.Terminals[0].PTYID != o.PTYID || !list.Terminals[0].Connected {
		t.Fatalf("pty_list = %+v", list)
	}

	// Closing ends the session on the agent, for the watcher too.
	if res := callTool(t, sess, "pty_close", map[string]any{"pty_id": o.PTYID}); res.IsError {
		t.Fatalf("pty_close: %s", resultText(res))
	}
	if viewer != nil && !viewer.waitFor("session ended", 10*time.Second) {
		t.Fatalf("the watcher was not told the session ended:\n%s", viewer.buf.String())
	}
	if out, _ := runClient(t, 15*time.Second, append([]string{"list"}, a.dialArgs()...)...); strings.Contains(out, o.Session) {
		t.Fatalf("the session outlived pty_close:\n%s", out)
	}
	if res := callTool(t, sess, "pty_read", map[string]any{"pty_id": o.PTYID}); !res.IsError {
		t.Fatal("a closed terminal must be forgotten")
	}

	sess.Close()
	cast, _ := os.ReadFile(o.Recording)
	if !strings.HasPrefix(o.Recording, rec) || !strings.Contains(string(cast), "hi-42") || !strings.Contains(string(cast), `"version":2`) {
		t.Fatalf("recording %s:\n%.300s", o.Recording, cast)
	}
	log, _ := os.ReadFile(audit)
	for _, want := range []string{`"tool":"pty_open","target":"box"`, `"tool":"pty_run"`, `"tool":"pty_send"`, `"keys":["C-c"]`, `"tool":"pty_close"`, `"pty_id":"` + o.PTYID + `"`} {
		if !strings.Contains(string(log), want) {
			t.Errorf("audit log lacks %s", want)
		}
	}
}

// cutProxy forwards TCP connections to an agent and can cut them all at
// once, or refuse new ones for a while, as a flaky network would.
type cutProxy struct {
	ln       net.Listener
	mu       sync.Mutex
	conns    []net.Conn
	refusing bool
	accepted int
}

func startProxy(t *testing.T, to string) *cutProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cutProxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			refusing := p.refusing
			p.accepted++
			p.mu.Unlock()
			up, err := net.Dial("tcp", to)
			if refusing || err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close(); p.cut() })
	return p
}

func (p *cutProxy) addr() string { return p.ln.Addr().String() }

func (p *cutProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

func (p *cutProxy) refuse(on bool) {
	p.mu.Lock()
	p.refusing = on
	p.mu.Unlock()
}

// TestMCPPTYReconnect cuts the connection while a command is running. The
// terminal reconnects by itself, and the output produced meanwhile arrives
// exactly once: the agent's replay of what was already read is skipped.
func TestMCPPTYReconnect(t *testing.T) {
	needConPTY(t)
	a := startDirectAgent(t)
	px := startProxy(t, a.addr)
	sess, _ := startMCPConfig(t, map[string]any{
		"targets": map[string]any{"box": target(px.addr(), a.fp, "term")}, "profiles": termProfiles,
	}, a.token, nil)
	o := openTerm(t, sess, map[string]any{})
	termRun(t, sess, o.PTYID, pick("echo before-$((1+1))", "echo before-^2"), "before-2")

	during := pick("sleep 1; echo during-$((20+22))\r", "ping -n 2 127.0.0.1 >nul & echo during-^4^2\r")
	if res := callTool(t, sess, "pty_send", map[string]any{"pty_id": o.PTYID, "text": during}); res.IsError {
		t.Fatalf("pty_send: %s", resultText(res))
	}
	// Cut once the shell has the command: keystrokes still in flight on a
	// connection that drops are lost, as with ssh.
	if r := termRead(t, sess, map[string]any{"pty_id": o.PTYID, "until": pick("sleep 1; echo", "ping -n 2"), "wait_ms": 10000}); !r.Matched {
		t.Fatalf("the command never reached the shell: %q", r.Data)
	}
	px.cut()
	r := termRead(t, sess, map[string]any{"pty_id": o.PTYID, "until": "during-42\\s", "wait_ms": 20000})
	if !r.Matched {
		t.Fatalf("output from while the connection was down never arrived: %q", r.Data)
	}
	all := termRead(t, sess, map[string]any{"pty_id": o.PTYID})
	if strings.Count(all.Data, "before-2") != 1 || strings.Count(all.Data, "during-42") != 1 || strings.Contains(all.Data, "[tern:") {
		t.Fatalf("after reconnecting, output is duplicated or lost:\n%s", all.Data)
	}
	var list struct {
		Terminals []struct {
			Connected  bool
			Reconnects int
		}
	}
	structured(t, callTool(t, sess, "pty_list", map[string]any{}), &list)
	if len(list.Terminals) != 1 || list.Terminals[0].Reconnects < 1 {
		t.Fatalf("pty_list = %+v", list)
	}
	termRun(t, sess, o.PTYID, pick("echo again-$((3*3))", "echo again-^9"), "again-9")
}

// TestMCPPTYTakeover: when a person becomes the session's writer while the
// AI's connection is down, the AI comes back read-only. It can still read.
func TestMCPPTYTakeover(t *testing.T) {
	if !humanCanAttach() {
		t.Skip("the person taking over needs tern connect under a PTY; set TERN_E2E_PTY=1 from a real console")
	}
	a := startDirectAgent(t)
	px := startProxy(t, a.addr)
	sess, _ := startMCPConfig(t, map[string]any{
		"targets": map[string]any{"box": target(px.addr(), a.fp, "term")}, "profiles": termProfiles,
	}, a.token, nil)
	o := openTerm(t, sess, map[string]any{})
	termRun(t, sess, o.PTYID, pick("echo mine-$((2+2))", "echo mine-^4"), "mine-4")

	px.refuse(true)
	px.cut()
	time.Sleep(500 * time.Millisecond) // the agent notices the AI is gone
	human := dialPTY(t, "tern", "connect", "--addr", a.addr, "--fingerprint", a.fp, "--token", a.token, "--session", o.Session)
	if !human.waitFor("attached to session", 15*time.Second) || strings.Contains(strings.ToLower(human.buf.String()), "read-only") {
		t.Fatalf("the person should have become the writer:\n%s", human.buf.String())
	}
	px.refuse(false)

	deadline := time.Now().Add(20 * time.Second)
	for {
		res := callTool(t, sess, "pty_send", map[string]any{"pty_id": o.PTYID, "text": "echo nope\r"})
		if res.IsError && strings.Contains(resultText(res), "a person took over") {
			break
		}
		if !res.IsError || time.Now().After(deadline) {
			t.Fatalf("after a takeover the AI must not type: error=%v %q", res.IsError, resultText(res))
		}
		time.Sleep(500 * time.Millisecond)
	}
	human.write(pick("echo human-$((7*6))\r", "echo human-^4^2\r"))
	if r := termRead(t, sess, map[string]any{"pty_id": o.PTYID, "until": "human-42\\s", "wait_ms": 10000}); !r.Matched {
		t.Fatalf("the AI should still read the terminal: %q", r.Data)
	}
}

// TestMCPPTYClosedOnExit: the terminals tern mcp opened end when it exits.
func TestMCPPTYClosedOnExit(t *testing.T) {
	needConPTY(t)
	a := startDirectAgent(t)
	sess, _ := startMCPConfig(t, map[string]any{
		"targets": map[string]any{"box": target(a.addr, a.fp, "term")}, "profiles": termProfiles,
	}, a.token, nil)
	o := openTerm(t, sess, map[string]any{})
	list := append([]string{"list"}, a.dialArgs()...)
	if out, _ := runClient(t, 15*time.Second, list...); !strings.Contains(out, o.Session) {
		t.Fatalf("the agent does not list %s:\n%s", o.Session, out)
	}
	sess.Close()
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := runClient(t, 15*time.Second, list...)
		if !strings.Contains(out, o.Session) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the session outlived tern mcp:\n%s", out)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestMCPPTYPolicy: terminals need the pty opt-in, and where shell commands
// need approval, so does typing into a terminal.
func TestMCPPTYPolicy(t *testing.T) {
	needConPTY(t)
	a := startDirectAgent(t)
	user := &fakeUser{}
	cfg := map[string]any{"profiles": termProfiles, "targets": map[string]any{
		"plain": target(a.addr, a.fp, "shellonly"),
		"safe":  target(a.addr, a.fp, "guarded"),
	}}
	sess, audit := startMCPConfig(t, cfg, a.token, &mcp.ClientOptions{ElicitationHandler: user.handle})

	if res := callTool(t, sess, "pty_open", map[string]any{"target": "plain"}); !res.IsError || !strings.Contains(resultText(res), "does not allow interactive terminals") {
		t.Fatalf("pty_open without the opt-in: %q", resultText(res))
	}
	o := openTerm(t, sess, map[string]any{"target": "safe"})

	user.set("decline", false)
	declined := pick("echo declined-$((1+1))", "echo declined-^2")
	res := callTool(t, sess, "pty_run", map[string]any{"pty_id": o.PTYID, "command": declined})
	if !res.IsError || !strings.Contains(resultText(res), "declined") {
		t.Fatalf("a declined command must not be typed: %q", resultText(res))
	}
	if q := user.questions(); len(q) != 1 || !strings.Contains(q[0], declined) || !strings.Contains(q[0], o.Session) {
		t.Fatalf("the user should see the exact command and terminal: %q", q)
	}
	user.set("accept", true)
	termRun(t, sess, o.PTYID, pick("echo approved-$((2+2))", "echo approved-^4"), "approved-4")
	if all := termRead(t, sess, map[string]any{"pty_id": o.PTYID}); strings.Contains(all.Data, "declined") {
		t.Fatalf("the declined command reached the terminal:\n%s", all.Data)
	}

	// A client that cannot ask its user cannot type into a guarded terminal.
	bare, _ := startMCPConfig(t, cfg, a.token, nil)
	o2 := openTerm(t, bare, map[string]any{"target": "safe"})
	if res := callTool(t, bare, "pty_send", map[string]any{"pty_id": o2.PTYID, "text": "echo x\r"}); !res.IsError || !strings.Contains(resultText(res), "cannot ask the user") {
		t.Fatalf("got %q", resultText(res))
	}

	sess.Close()
	if log, _ := os.ReadFile(audit); strings.Count(string(log), `"phase":"confirm_requested"`) != 2 {
		t.Errorf("each typed command should have asked once:\n%s", log)
	}
}
