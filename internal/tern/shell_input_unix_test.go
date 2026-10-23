// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// openStalledShell opens a writer's shell on a's session name and starts a
// foreground program there that reads no input, with the terminal raw, as
// editors, pagers and REPLs set it, so typed input backs up.
func openStalledShell(t *testing.T, a *Agent, fp, name string) (*Client, *ShellStream) {
	t.Helper()
	cl := dialTest(t, a, fp)
	sh, err := cl.OpenShell(ShellOptions{Session: name, Mode: modeNew, Write: true, Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	go sh.CopyOutput(io.Discard)
	sh.Write([]byte("stty raw -echo; sleep 30; stty sane\n"))
	time.Sleep(500 * time.Millisecond)
	return cl, sh
}

func session(a *Agent, name string) *sharedPTY {
	a.mgr.mu.Lock()
	defer a.mgr.mu.Unlock()
	return a.mgr.sessions[name]
}

// A writer's request to end the session is honoured although input it typed
// before it is still waiting for a program that does not read it.
func TestEndSessionBehindUnreadInput(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, sh := openStalledShell(t, a, fp, "end")
	defer cl.Close()
	// Input the program never reads, as much as fits the stream's window,
	// so the end request below still reaches the agent.
	for i := 0; i < 2; i++ {
		if _, err := sh.Write(bytes.Repeat([]byte("x"), 64<<10)); err != nil {
			t.Fatal(err)
		}
	}
	sh.EndSession()
	for i := 0; session(a, "end") != nil; i++ {
		if i == 100 {
			session(a, "end").close()
			t.Fatal("the session did not end")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A writer whose input backs up, more than the agent queues, still detaches
// when its connection ends, so the session's idle timeout starts.
func TestDisconnectBehindUnreadInput(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, sh := openStalledShell(t, a, fp, "gone")
	ps := session(a, "gone")
	defer ps.close()
	go sh.Write(bytes.Repeat([]byte("x"), 4<<20)) // blocks once the stream's window is full
	time.Sleep(time.Second)
	cl.Close()
	for i := 0; ps.clientCount() != 0; i++ {
		if i == 100 {
			t.Fatal("the writer was never detached")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// backUp types far more than the agent and the terminal hold into sh, whose
// program reads none of it, from a goroutine of its own: once this returns,
// the stream's window is full and that goroutine waits on it.
func backUp(t *testing.T, sh *ShellStream) {
	t.Helper()
	go sh.Write(bytes.Repeat([]byte("x"), 4<<20))
	time.Sleep(time.Second)
}

// within runs f and fails the test unless it returns within d.
func within(t *testing.T, d time.Duration, what string, f func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// A writer's request to end the session is acted on, and returns at once,
// while the input it typed before waits for a program that reads none and
// fills the stream, so that nothing more can be sent on it.
func TestEndSessionWhileInputBlocked(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, sh := openStalledShell(t, a, fp, "blocked")
	defer cl.Close()
	ps := session(a, "blocked")
	defer ps.close()
	backUp(t, sh)
	within(t, time.Second, "EndSession", sh.EndSession)
	for i := 0; session(a, "blocked") != nil; i++ {
		if i == 40 {
			t.Fatal("the session did not end")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A writer's resize is applied, and returns at once, while the input it typed
// before fills the stream.
func TestResizeWhileInputBlocked(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, sh := openStalledShell(t, a, fp, "sized")
	defer cl.Close()
	ps := session(a, "sized")
	defer ps.close()
	backUp(t, sh)
	within(t, time.Second, "Resize", func() error { return sh.Resize(100, 40) })
	for i := 0; ; i++ {
		ps.mu.Lock()
		c, r := ps.lastCols, ps.lastRows
		ps.mu.Unlock()
		if c == 100 && r == 40 {
			return
		}
		if i == 40 {
			t.Fatalf("the terminal is %dx%d, not the 100x40 asked for", c, r)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stacks counts the goroutines whose stack mentions fn.
func stacks(fn string) int {
	buf := make([]byte, 8<<20)
	n := 0
	for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
		if strings.Contains(g, fn) {
			n++
		}
	}
	return n
}

// Writers that leave while their input waits for a program that reads none
// leave nothing waiting on the terminal for them: one goroutine writes the
// session's input, however many writers come and go.
func TestDepartedWritersLeaveNothingBehind(t *testing.T) {
	a, fp := newTestAgent(t)
	cl0, _ := openStalledShell(t, a, fp, "crowd")
	ps := session(a, "crowd")
	defer ps.close()
	served := stacks("tern.(*sessionManager).serveShell(") // the first writer's attachment
	writing := stacks("tern.(*ptySession).Write")
	for i := 0; i < 8; i++ {
		cl := dialTest(t, a, fp)
		sh, err := cl.OpenShell(ShellOptions{Session: "crowd", Mode: modeAttach, Write: true, CoDrive: true, Cols: 80, Rows: 24})
		if err != nil {
			t.Fatal(err)
		}
		go sh.CopyOutput(io.Discard)
		backUp(t, sh)
		cl.Close()
	}
	cl0.Close()
	for i := 0; ps.clientCount() != 0; i++ {
		if i == 100 {
			t.Fatal("writers were never detached")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := stacks("tern.(*sessionManager).serveShell(") - (served - 1); n > 0 {
		t.Errorf("%d attachments of departed writers are still served", n)
	}
	// The session's feed waits on the program; nothing else may.
	if n := stacks("tern.(*ptySession).Write") - writing; n > 1 {
		t.Errorf("%d goroutines wait to write to the terminal", n)
	}
	if n := stacks("tern.writeQueued"); n != 0 {
		t.Errorf("%d writer goroutines of departed writers still wait on the terminal", n)
	}
}

// Ending a session whose input waits for a program that reads none leaves
// nothing waiting on the terminal: the write under way ends with it.
func TestEndedSessionLeavesNoWriteWaiting(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, sh := openStalledShell(t, a, fp, "ended")
	defer cl.Close()
	ps := session(a, "ended")
	defer ps.close()
	backUp(t, sh)
	writing := stacks("tern.(*ptySession).Write")
	if writing == 0 {
		t.Fatal("no write waits on the program: the test exercises nothing")
	}
	ps.close()
	for i := 0; stacks("tern.(*ptySession).Write") >= writing; i++ {
		if i == 40 {
			t.Fatal("a write to the ended session's terminal still waits")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// slowWriter blocks each Write until release is closed, and counts the
// writes it was given.
type slowWriter struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	n       int
}

func (w *slowWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	w.mu.Lock()
	w.n++
	w.mu.Unlock()
	return len(p), nil
}

// Once a command's input stops being wanted, nothing still queued for it is
// written, the write already under way aside.
func TestWriteQueuedStopsAtStop(t *testing.T) {
	extra := 0
	for trial := 0; trial < 100; trial++ {
		w := &slowWriter{release: make(chan struct{}), started: make(chan struct{})}
		q := make(chan []byte, inputQueueLen)
		stop := make(chan struct{})
		for i := 0; i < 10; i++ {
			q <- []byte(fmt.Sprint(i))
		}
		done := make(chan struct{})
		go func() { writeQueued(w, q, stop); close(done) }()
		<-w.started
		close(stop)
		close(w.release)
		<-done
		w.mu.Lock()
		extra += w.n - 1
		w.mu.Unlock()
	}
	if extra > 0 {
		t.Errorf("%d queued writes went out after stop over 100 trials", extra)
	}
}
