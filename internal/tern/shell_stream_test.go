// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// countingWriter counts the output a stream delivered and signals each write.
type countingWriter struct {
	mu    sync.Mutex
	n     int64
	text  strings.Builder
	first int // length of the first write, the agent's replay
	wrote chan struct{}
}

func newCountingWriter() *countingWriter { return &countingWriter{wrote: make(chan struct{}, 1)} }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.n == 0 {
		w.first = len(p)
	}
	w.n += int64(len(p))
	w.text.Write(p)
	w.mu.Unlock()
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (w *countingWriter) state() (int64, string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n, w.text.String(), w.first
}

// waitStable waits until w holds want and then receives nothing for a while.
func (w *countingWriter) waitStable(t *testing.T, want string) int64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-w.wrote:
		case <-time.After(300 * time.Millisecond):
			if n, text, _ := w.state(); strings.Contains(text, want) {
				return n
			}
		}
		if time.Now().After(deadline) {
			_, text, _ := w.state()
			t.Fatalf("waiting for %q, have %d bytes ending %q", want, len(text), text[max(0, len(text)-200):])
		}
	}
}

// TestShellStreamOffset checks the offset an attach reports: 0 for a new
// session, and for a later attach the position of its replay in the whole
// output, so that offset plus the replay's length is everything so far, even
// once the agent's ring has dropped old output.
func TestShellStreamOffset(t *testing.T) {
	a, fp := newTestAgent(t)
	c1 := dialTest(t, a, fp)
	defer c1.Close()
	st1, err := c1.OpenShell(ShellOptions{Session: "off", Mode: modeNew, AttachID: "one", Write: true, Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	if st1.Offset != 0 || st1.ReadOnly || st1.Session != "off" {
		t.Fatalf("new session stream = %+v", st1)
	}
	w1 := newCountingWriter()
	go st1.CopyOutput(w1)
	// More output than the agent's ring keeps, so the replay starts past 0.
	st1.Write([]byte("head -c 300000 /dev/zero | tr '\\\\0' x; echo; echo DONE_$((6*7))\n"))
	total := w1.waitStable(t, "DONE_42")
	if total <= ringMax {
		t.Fatalf("only %d bytes of output, need more than the ring's %d", total, ringMax)
	}

	c2 := dialTest(t, a, fp)
	defer c2.Close()
	st2, err := c2.OpenShell(ShellOptions{Session: "off", Mode: modeAttach, AttachID: "two"})
	if err != nil {
		t.Fatal(err)
	}
	if !st2.ReadOnly {
		t.Fatal("a second client should join read-only")
	}
	w2 := newCountingWriter()
	go st2.CopyOutput(w2)
	w2.waitStable(t, "DONE_42")
	_, _, replay := w2.state()
	if st2.Offset <= 0 || st2.Offset+int64(replay) != total {
		t.Fatalf("offset %d + replay %d != %d bytes of output", st2.Offset, replay, total)
	}
}

// TestShellStreamEndSession: a writer can end the session, killing its shell;
// a viewer's request is ignored.
func TestShellStreamEndSession(t *testing.T) {
	a, fp := newTestAgent(t)
	cw := dialTest(t, a, fp)
	defer cw.Close()
	w, err := cw.OpenShell(ShellOptions{Session: "end", Mode: modeNew, Write: true, Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	cv := dialTest(t, a, fp)
	defer cv.Close()
	v, err := cv.OpenShell(ShellOptions{Session: "end", Mode: modeAttach})
	if err != nil {
		t.Fatal(err)
	}
	viewerExited := make(chan bool, 1)
	go func() { viewerExited <- v.CopyOutput(newCountingWriter()) }()

	v.EndSession()
	time.Sleep(300 * time.Millisecond)
	if names := a.mgr.list(); len(names) != 1 {
		t.Fatalf("a viewer ended the session: %v", names)
	}
	writerExited := make(chan bool, 1)
	go func() { writerExited <- w.CopyOutput(newCountingWriter()) }()
	w.EndSession()
	for _, ch := range []chan bool{writerExited, viewerExited} {
		select {
		case exited := <-ch:
			if !exited {
				t.Fatal("a client was not told the session ended")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the session did not end")
		}
	}
	if names := a.mgr.list(); len(names) != 0 {
		t.Fatalf("session still listed: %v", names)
	}
}
