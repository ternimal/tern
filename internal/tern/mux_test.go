// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0"

func newTestAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	ac := &AuthConfig{Token: testToken}
	return NewAgent(ServerTLSConfig(cert), ac, "/bin/sh", time.Minute, ""), CertFingerprint(cert)
}

func dialTest(t *testing.T, a *Agent, fp string) *Client {
	t.Helper()
	sconn, cconn := loopbackPair(t)
	go a.Serve(sconn, "test")
	cl, err := Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return cl
}

// loopbackPair returns two connected TCP conns over the loopback interface.
// Real sockets are buffered and behave like production, unlike net.Pipe which
// is synchronous and can stall/short-read when the scheduler is starved.
func loopbackPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.c, client
}

func TestFullStackExec(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()

	var buf bytes.Buffer
	code, err := cl.Run([]string{"sh", "-c", "echo OK_$((2+3)); exit 4"}, nil, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 4 {
		t.Fatalf("exit = %d, want 4", code)
	}
	if !strings.Contains(buf.String(), "OK_5") {
		t.Fatalf("output %q missing OK_5", buf.String())
	}
}

func TestFullStackFileCopy(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()

	dir := t.TempDir()
	local := filepath.Join(dir, "src")
	remote := filepath.Join(dir, "remote")
	back := filepath.Join(dir, "back")
	payload := []byte("file-data-\x00\x01-123")
	os.WriteFile(local, payload, 0o644)

	if err := cl.CopyTo(local, remote); err != nil {
		t.Fatalf("CopyTo: %v", err)
	}
	if got, _ := os.ReadFile(remote); !bytes.Equal(got, payload) {
		t.Fatalf("remote mismatch: %q", got)
	}
	if err := cl.CopyFrom(remote, back); err != nil {
		t.Fatalf("CopyFrom: %v", err)
	}
	if got, _ := os.ReadFile(back); !bytes.Equal(got, payload) {
		t.Fatalf("back mismatch: %q", got)
	}
}

func TestFullStackLocalForward(t *testing.T) {
	// echo server that the agent will reach
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()

	// a free local port for the forward entrance
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	fwdAddr := tmp.Addr().String()
	tmp.Close()

	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	go cl.ForwardLocal(fwdAddr, echo.Addr().String())

	c := dialRetry(t, fwdAddr) // retry until the forward listener is up
	defer c.Close()
	c.Write([]byte("ping"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

func TestFullStackRemoteForward(t *testing.T) {
	// client-local target the agent's listener should reach back to
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()

	// free port for the agent-side listener (-R bind)
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	bind := tmp.Addr().String()
	tmp.Close()

	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	go cl.ForwardRemote(bind, echo.Addr().String())

	c := dialRetry(t, bind) // retry until the agent's -R listener is up
	defer c.Close()
	c.Write([]byte("pong"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("echo = %q", got)
	}
}

// dialRetry connects to addr, retrying until it succeeds or ~5s passes, so the
// test does not depend on a fixed sleep for a listener to come up (which flakes
// when the machine is under heavy load).
func dialRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", addr, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func waitFor(t *testing.T, c net.Conn, want string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var acc []byte
	for {
		typ, payload, err := readFrame(c)
		if err != nil {
			t.Fatalf("waiting for %q: %v (got %q)", want, err, acc)
		}
		if typ == frameData {
			acc = append(acc, payload...)
			if strings.Contains(string(acc), want) {
				return
			}
		}
		if typ == frameExit {
			t.Fatalf("waiting for %q: shell exited before match (got %q)", want, acc)
		}
	}
}

func TestSessionShareAndResume(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")

	// client 1: creates the session as a writer
	s1a, s1b := net.Pipe()
	go m.serveShell(s1b, streamHeader{Kind: "shell", Mode: "new", Session: "demo", Write: true, Cols: 80, Rows: 24}, "c1", nil)
	rep1, err := readReply(s1a)
	if err != nil || !rep1.OK {
		t.Fatalf("c1 reply: %+v %v", rep1, err)
	}
	writeFrame(s1a, frameData, []byte("echo MARK_$((7*7))\n"))
	waitFor(t, s1a, "MARK_49")

	// client 2: attaches read-only (share) and should replay the buffer (resume)
	s2a, s2b := net.Pipe()
	go m.serveShell(s2b, streamHeader{Kind: "shell", Mode: "attach", Session: "demo", Write: false, Cols: 80, Rows: 24}, "c2", nil)
	rep2, err := readReply(s2a)
	if err != nil || !rep2.OK {
		t.Fatalf("c2 reply: %+v %v", rep2, err)
	}
	if !rep2.Shared || !rep2.ReadOnly {
		t.Fatalf("c2 expected shared+read-only, got %+v", rep2)
	}
	waitFor(t, s2a, "MARK_49") // ring replay == resume

	// a live command from the writer reaches the shared viewer too
	writeFrame(s1a, frameData, []byte("echo LIVE_$((8*8))\n"))
	waitFor(t, s2a, "LIVE_64")

	if names := m.list(); len(names) != 1 || names[0] != "demo" {
		t.Fatalf("list = %v", names)
	}
}

func TestREST(t *testing.T) {
	a, fp := newTestAgent(t)
	dial := func(id string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}
	g := &Gateway{Token: "secret", Dial: dial}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	// unauthorized
	resp := post(t, srv.URL+"/v1/exec", "", `{"cmd":["echo","hi"]}`)
	if resp.StatusCode != 401 {
		t.Fatalf("no-auth exec = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// streaming exec
	resp = post(t, srv.URL+"/v1/exec", "secret", `{"cmd":["sh","-c","echo HELLO; exit 3"]}`)
	var out strings.Builder
	exit := -999
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if s, ok := m["stdout"].(string); ok {
			out.WriteString(s)
		}
		if e, ok := m["exit"].(float64); ok {
			exit = int(e)
		}
	}
	resp.Body.Close()
	if !strings.Contains(out.String(), "HELLO") || exit != 3 {
		t.Fatalf("exec stream out=%q exit=%d", out.String(), exit)
	}

	// long-running async job
	resp = post(t, srv.URL+"/v1/jobs", "secret", `{"cmd":["sh","-c","echo A; sleep 1; echo B"]}`)
	var created map[string]string
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	jobID := created["job"]
	if jobID == "" {
		t.Fatal("no job id")
	}

	deadline := time.Now().Add(6 * time.Second)
	for {
		r := get(t, srv.URL+"/v1/jobs/"+jobID, "secret")
		var st map[string]any
		json.NewDecoder(r.Body).Decode(&st)
		r.Body.Close()
		if st["status"] == "done" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job did not finish")
		}
		time.Sleep(150 * time.Millisecond)
	}
	r := get(t, srv.URL+"/v1/jobs/"+jobID+"/output", "secret")
	var od map[string]any
	json.NewDecoder(r.Body).Decode(&od)
	r.Body.Close()
	data, _ := od["data"].(string)
	if !strings.Contains(data, "A") || !strings.Contains(data, "B") {
		t.Fatalf("job output = %q", data)
	}

	// a cancelled job says so, without the stream's end as an error
	resp = post(t, srv.URL+"/v1/jobs", "secret", `{"cmd":["sh","-c","sleep 30"]}`)
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	req, _ := http.NewRequest("DELETE", srv.URL+"/v1/jobs/"+created["job"], nil)
	req.Header.Set("Authorization", "Bearer secret")
	if dr, err := http.DefaultClient.Do(req); err != nil || dr.StatusCode != 200 {
		t.Fatalf("cancel: %v", err)
	} else {
		dr.Body.Close()
	}
	for deadline := time.Now().Add(6 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		r := get(t, srv.URL+"/v1/jobs/"+created["job"], "secret")
		var st map[string]any
		json.NewDecoder(r.Body).Decode(&st)
		r.Body.Close()
		if st["status"] != "running" {
			if st["status"] != "cancelled" || st["error"] != nil {
				t.Fatalf("cancelled job status = %v", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the cancelled job kept running")
		}
	}

	// no sessions is an empty list, not null
	r = get(t, srv.URL+"/v1/sessions", "secret")
	var ss map[string]any
	json.NewDecoder(r.Body).Decode(&ss)
	r.Body.Close()
	if list, ok := ss["sessions"].([]any); !ok || len(list) != 0 {
		t.Fatalf("sessions = %#v, want []", ss["sessions"])
	}
}

func TestRESTSimpleRun(t *testing.T) {
	a, fp := newTestAgent(t)
	dial := func(id string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}
	g := &Gateway{Token: "secret", Dial: dial, RunTimeout: 10 * time.Second, MaxTimeout: time.Minute}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	// simple sync run: one JSON response with exit + output
	resp := post(t, srv.URL+"/v1/run", "secret", `{"cmd":["sh","-c","echo SIMPLE_$((9*9)); exit 5"]}`)
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if int(m["exit"].(float64)) != 5 {
		t.Fatalf("run response = %+v, want exit 5", m)
	}
	if !strings.Contains(m["output"].(string), "SIMPLE_81") {
		t.Fatalf("output = %q", m["output"])
	}
	if m["timed_out"].(bool) {
		t.Fatal("unexpected timeout")
	}

	// timeout path: a 5s command with timeout:1 returns promptly with timed_out
	start := time.Now()
	resp = post(t, srv.URL+"/v1/run", "secret", `{"cmd":["sh","-c","echo PRE; sleep 5"],"timeout":1}`)
	var tm map[string]any
	json.NewDecoder(resp.Body).Decode(&tm)
	resp.Body.Close()
	if to, _ := tm["timed_out"].(bool); !to {
		t.Fatalf("expected timed_out, got %+v", tm)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout was not enforced promptly")
	}
}

func TestRESTStdin(t *testing.T) {
	a, fp := newTestAgent(t)
	dial := func(id string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}
	g := &Gateway{Token: "secret", Dial: dial, RunTimeout: 10 * time.Second}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	resp := post(t, srv.URL+"/v1/run", "secret", `{"cmd":["cat"],"stdin":"hello-stdin-42"}`)
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if out, _ := m["output"].(string); !strings.Contains(out, "hello-stdin-42") {
		t.Fatalf("stdin was not fed to the command: output=%q", m["output"])
	}
}

func TestSessionRecording(t *testing.T) {
	dir := t.TempDir()
	m := newSessionManager("/bin/sh", time.Minute, dir)

	sa, sb := net.Pipe()
	go m.serveShell(sb, streamHeader{Kind: "shell", Mode: "new", Session: "rec", Write: true, Cols: 80, Rows: 24}, "rec", nil)
	rep, err := readReply(sa)
	if err != nil || !rep.OK {
		t.Fatalf("attach: %+v %v", rep, err)
	}
	writeFrame(sa, frameData, []byte("echo RECME_$((3*3))\n"))
	waitFor(t, sa, "RECME_9")
	writeFrame(sa, frameData, []byte("exit\n")) // end the shell -> session + recording close

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := filepath.Glob(filepath.Join(dir, "*.cast"))
		if len(files) == 1 {
			b, _ := os.ReadFile(files[0])
			if strings.Contains(string(b), `"version":2`) && strings.Contains(string(b), "RECME_9") {
				return // recorded header + output as asciicast
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("expected a .cast recording containing the session output")
}

// TestRunNilStdinClosesInput: with no stdin, a command that reads its input
// must see EOF right away instead of waiting forever.
func TestRunNilStdinClosesInput(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	done := make(chan int, 1)
	go func() {
		code, _ := cl.Run([]string{"cat"}, nil, io.Discard)
		done <- code
	}()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("cat exit = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cat with nil stdin never saw EOF")
	}
}

// TestReadOnlyClientCannotCreateSession: a viewer only joins; it must never
// end up as the writer of a session it created.
func TestReadOnlyClientCannotCreateSession(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	for _, c := range []struct{ name, mode string }{
		{"", modeAuto}, {"nope", modeAuto}, {"fresh", modeNew},
	} {
		if _, _, _, err := m.attach(c.name, c.mode, false, false, "", 80, 24); err == nil {
			t.Fatalf("read-only attach (%q, %s) succeeded; want an error", c.name, c.mode)
		}
	}
	if names := m.list(); len(names) != 0 {
		t.Fatalf("read-only attaches created sessions: %v", names)
	}
}

// TestAutoSessionNameSkipsTaken: an unnamed session must not collide with a
// name a client already chose in the sN form.
func TestAutoSessionNameSkipsTaken(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	named, _, _, err := m.attach("s1", modeNew, true, false, "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer named.close()
	auto, _, _, err := m.attach("", modeAuto, true, false, "", 80, 24)
	if err != nil {
		t.Fatalf("auto-named session after a client took s1: %v", err)
	}
	defer auto.close()
	if auto.name == "s1" {
		t.Fatal("auto-named session reused s1")
	}
}

// TestReconnectReclaimsOwnSeat: a writer that reconnects while the agent still
// holds its old (dead) attachment replaces that attachment and writes again,
// instead of coming back read-only behind its own stale slot.
func TestReconnectReclaimsOwnSeat(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	ps, a1, _, err := m.attach("seat", modeNew, true, false, "client-a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.close()
	if _, b, _, _ := m.attach("seat", modeAttach, true, false, "client-b", 80, 24); b.write {
		t.Fatal("second client should be read-only while A writes")
	}
	_, a2, _, err := m.attach("seat", modeAttach, true, false, "client-a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if !a2.write {
		t.Fatal("reconnecting writer came back read-only behind its own stale slot")
	}
	if _, open := <-a1.ch; open {
		t.Fatal("stale attachment was not closed")
	}
	if n := ps.clientCount(); n != 2 {
		t.Fatalf("clients = %d, want 2 (the stale one replaced)", n)
	}
}

// TestReclaimAfterTakeOverIsReadOnly: a person takes the session over (joins
// as a writer beside the old one) while the agent still holds the old
// writer's dead attachment; when that client comes back with its attach id it
// replaces its stale slot but returns read-only, not as a second writer. A
// writer that asks to co-drive again still may.
func TestReclaimAfterTakeOverIsReadOnly(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	ps, a1, _, err := m.attach("seat", modeNew, true, false, "client-a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.close()
	if _, b, _, _ := m.attach("seat", modeAttach, true, true, "client-b", 80, 24); !b.write {
		t.Fatal("a client that asks to co-drive should write")
	}
	_, a2, _, err := m.attach("seat", modeAttach, true, false, "client-a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if a2.write {
		t.Fatal("the old writer came back writing beside the person who took over")
	}
	if _, open := <-a1.ch; open {
		t.Fatal("stale attachment was not closed")
	}
	if n := ps.clientCount(); n != 2 {
		t.Fatalf("clients = %d, want 2 (the stale one replaced)", n)
	}
	if _, b2, _, _ := m.attach("seat", modeAttach, true, true, "client-b", 80, 24); !b2.write {
		t.Fatal("a co-driver that reconnects asking to co-drive should still write")
	}
}

// TestReturningWriterDoesNotStealSeat: once the agent has dropped a writer's
// old attachment and another client became the writer, the returning client
// joins read-only like anyone else; it does not co-drive uninvited.
func TestReturningWriterDoesNotStealSeat(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	ps, a1, _, err := m.attach("seat", modeNew, true, false, "client-a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.close()
	ps.detach(a1) // the agent noticed A's connection is gone
	if _, b, _, _ := m.attach("seat", modeAttach, true, false, "client-b", 80, 24); !b.write {
		t.Fatal("B should become the writer once A is gone")
	}
	if _, a2, _, _ := m.attach("seat", modeAttach, true, false, "client-a", 80, 24); a2.write {
		t.Fatal("returning client took write from the new writer")
	}
}

// TestAttachToClosedSessionFails: an attach that found the session just
// before it closed must fail, not join a session that will never send output.
func TestAttachToClosedSessionFails(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	ps, _, _, err := m.attach("gone", modeNew, true, false, "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	ps.close()
	m.mu.Lock()
	m.sessions["gone"] = ps // as if attach's lookup ran just before close
	m.mu.Unlock()
	if _, _, _, err := m.attach("gone", modeAttach, true, false, "", 80, 24); err == nil {
		t.Fatal("attached to a closed session")
	}
}

// TestSlowClientIsNotToldShellExited: a client dropped for falling behind gets
// no exit frame (so it reconnects and resumes), and the session lives on.
func TestSlowClientIsNotToldShellExited(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	sa, sb := net.Pipe()
	go m.serveShell(sb, streamHeader{Kind: "shell", Mode: "new", Session: "slow", Write: true, Cols: 80, Rows: 24}, "slow", nil)
	if rep, err := readReply(sa); err != nil || !rep.OK {
		t.Fatalf("attach: %+v %v", rep, err)
	}
	// Flood output without reading it until the agent drops this client.
	writeFrame(sa, frameData, []byte("yes TERN_FLOOD\n"))
	m.mu.Lock()
	ps := m.sessions["slow"]
	m.mu.Unlock()
	defer ps.close()
	deadline := time.Now().Add(20 * time.Second)
	for ps.clientCount() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the slow client was never dropped")
		}
		time.Sleep(20 * time.Millisecond)
	}
	sa.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		typ, _, err := readFrame(sa)
		if err != nil {
			break // stream closed without an exit frame: as intended
		}
		if typ == frameExit {
			t.Fatal("dropped client was sent an exit frame while the shell still runs")
		}
	}
	if names := m.list(); len(names) != 1 {
		t.Fatalf("session should outlive the dropped client, list = %v", names)
	}
}

// TestRESTClientGoneKillsCommand: when the HTTP client disconnects from
// /v1/exec or /v1/run, the agent must kill the command rather than let it run
// on unobserved.
func TestRESTClientGoneKillsCommand(t *testing.T) {
	a, fp := newTestAgent(t)
	g := &Gateway{Token: "secret", RunTimeout: 30 * time.Second, Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "gone")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	for _, route := range []string{"/v1/exec", "/v1/run"} {
		marker := filepath.Join(t.TempDir(), "still-ran")
		body := fmt.Sprintf(`{"cmd":["sh","-c","sleep 1.5; touch %s"]}`, marker)
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+route, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer secret")
		go func() {
			time.Sleep(300 * time.Millisecond)
			cancel() // the HTTP client disconnects mid-command
		}()
		if resp, err := http.DefaultClient.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		time.Sleep(2500 * time.Millisecond)
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: the command kept running after its HTTP client went away", route)
		}
	}
}

// TestGatewayRunDrainsInFlight: on shutdown Run waits for in-flight requests
// instead of returning while they still run.
func TestGatewayRunDrainsInFlight(t *testing.T) {
	a, fp := newTestAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	g := &Gateway{Addr: addr, Token: "secret", RunTimeout: 10 * time.Second, Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "drain")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan time.Time, 1)
	go func() {
		g.Run(ctx)
		runDone <- time.Now()
	}()
	dialRetry(t, addr).Close()

	body := make(chan string, 1)
	go func() { // no t.Fatal off the test goroutine: report through the channel
		req, _ := http.NewRequest("POST", "http://"+addr+"/v1/run", strings.NewReader(`{"cmd":["sh","-c","sleep 1.5; echo DRAINED"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			body <- "request failed: " + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body <- string(b)
	}()
	time.Sleep(300 * time.Millisecond) // let the request get in flight
	cancelAt := time.Now()
	cancel()
	select {
	case returned := <-runDone:
		if returned.Sub(cancelAt) < 700*time.Millisecond {
			t.Fatalf("Run returned %s after cancel, before the in-flight request finished", returned.Sub(cancelAt))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if b := <-body; !strings.Contains(b, "DRAINED") {
		t.Fatalf("in-flight request was cut off: %q", b)
	}
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func get(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// Closing a session must terminate the shell, not just the PTY, so the idle
// reaper does not leak the process and the pump goroutine blocked on its Read.
func TestShellTerminatedOnClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	sh, err := spawnShell("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan struct{})
	go func() { sh.Wait(); close(waited) }()
	sh.Close() // what sharedPTY.close() calls on reap
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not terminate the shell: Wait still blocked (process leak)")
	}
}

// A read-only viewer's size must not shrink the writer's PTY.
func TestResizeIgnoresViewers(t *testing.T) {
	m := newSessionManager("/bin/sh", time.Minute, "")
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	ps, w, _, err := m.attach("s", modeNew, true, false, "", 80, 24) // writer 80x24
	if err != nil {
		t.Fatal(err)
	}
	defer ps.close()
	_ = w
	if _, _, _, err := m.attach("s", modeAttach, false, false, "", 1, 1); err != nil { // viewer 1x1
		t.Fatal(err)
	}
	ps.mu.Lock()
	c, r := ps.lastCols, ps.lastRows
	ps.mu.Unlock()
	if c != 80 || r != 24 {
		t.Fatalf("PTY sized to %dx%d; a read-only 1x1 viewer shrank the writer", c, r)
	}
}
