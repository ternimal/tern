// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

const ctrlC = 0x03 // what Ctrl-C reads as on a raw terminal

// shellSession is a running shell attached to a PTY on the agent. ptySession
// (shell_pty.go) is the only implementation; on iOS spawnShell always fails
// (shell_stub.go). Close must be idempotent: pump's exit watcher and
// sharedPTY.close both call it.
type shellSession interface {
	io.ReadWriteCloser
	Resize(cols, rows int) error
	Wait() error
}

// frameWriter serializes frames so writes from different goroutines never
// interleave on a stream.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (fw *frameWriter) write(typ byte, payload []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return writeFrame(fw.w, typ, payload)
}

// RunReconnectingShell opens an interactive shell and, when reconnect is true,
// automatically re-attaches to the same session (resuming with scrollback) if
// the connection drops, until the remote shell exits or ctx is cancelled.
// dial returns a fresh Client for each attempt. The local terminal stays in raw
// mode across reconnects, and one stdin reader is multiplexed onto whichever
// stream is currently live; Ctrl-C typed while no stream is live (waiting for
// a connection or between attempts) stops the loop. Each run sends one attach
// id with every attach, so a writer whose old connection the agent has not yet
// noticed is gone gets its seat back. Callers that authenticate with a key
// should PreloadKey first, so an encrypted key prompts for its passphrase
// before the terminal goes raw.
func RunReconnectingShell(ctx context.Context, dial func(context.Context) (*Client, error), session, mode string, write, coDrive, reconnect bool) error {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("raw mode: %w (an interactive shell needs a terminal)", err)
	}
	defer term.Restore(fd, old)
	defer rawModeLogs()()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	attachID := newAttachID()

	var mu sync.Mutex
	var cur *ShellStream // the live stream (nil between connects)
	live := func() *ShellStream { mu.Lock(); defer mu.Unlock(); return cur }
	setCur := func(st *ShellStream) { mu.Lock(); cur = st; mu.Unlock() }

	// stdin -> current stream (persists across reconnects)
	go func() {
		buf := make([]byte, ioBufSize)
		for {
			n, e := os.Stdin.Read(buf)
			if n > 0 {
				switch st := live(); {
				case st != nil && !st.ReadOnly:
					st.Write(buf[:n])
				case bytes.IndexByte(buf[:n], ctrlC) >= 0:
					// Ctrl-C while disconnected stops reconnecting, and a
					// read-only viewer, whose keys the agent ignores, leaves.
					cancel()
				}
			}
			if e != nil {
				return
			}
		}
	}()
	// resize watcher -> current stream
	go func() {
		lastC, lastR, _ := consoleSize()
		t := time.NewTicker(resizePollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c, r, ok := consoleSize()
				if ok && (c != lastC || r != lastR) {
					lastC, lastR = c, r
					if st := live(); st != nil {
						st.Resize(c, r)
					}
				}
			}
		}
	}()

	// wait sleeps for the current backoff (false if ctx ended first), then
	// doubles it up to ReconnectBackoffMax.
	backoff := time.Second
	wait := func() bool {
		fmt.Fprintf(os.Stderr, "\r\n[tern] disconnected; reconnecting in %s (Ctrl-C to quit)...\r\n", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return false
		}
		backoff = min(backoff*2, ReconnectBackoffMax)
		return true
	}

	first := true
	for {
		if ctx.Err() != nil {
			return nil
		}
		cl, derr := dialCancelable(ctx, dial)
		if derr != nil {
			if ctx.Err() != nil {
				return nil
			}
			if first || !reconnect {
				return derr
			}
			slog.Debug("reconnect failed", "err", derr)
			if !wait() {
				return nil
			}
			continue
		}

		cols, rows, _ := consoleSize()
		st, serr := cl.OpenShell(ShellOptions{Session: session, Mode: mode, AttachID: attachID, Write: write, CoDrive: coDrive, Cols: cols, Rows: rows})
		if serr != nil {
			cl.Close()
			if first {
				return serr
			}
			fmt.Fprint(os.Stderr, "\r\n[tern] session closed\r\n")
			return nil
		}
		if first {
			fmt.Fprintf(os.Stderr, "[tern] attached to session %q%s\r\n", st.Session, roText(st.ReadOnly))
			session, mode, first = st.Session, "attach", false
		} else {
			fmt.Fprintf(os.Stderr, "\r\n[tern] reconnected to %q%s\r\n", st.Session, roText(st.ReadOnly))
		}

		if c, r, ok := consoleSize(); ok {
			st.Resize(c, r)
		}
		setCur(st)
		connectedAt := time.Now()
		// SIGINT, SIGTERM or a viewer's Ctrl-C ends ctx: close the stream to
		// detach, leaving the session running on the agent.
		stop := context.AfterFunc(ctx, func() { st.Close() })
		shellExited := st.CopyOutput(os.Stdout)
		stop()
		setCur(nil)
		cl.Close()

		// Detaching comes first: closing the stream leaves the session
		// running on the agent, whatever the stream reported as it ended.
		if ctx.Err() != nil {
			fmt.Fprint(os.Stderr, "\r\n[tern] detached\r\n")
			return nil
		}
		if shellExited {
			fmt.Fprint(os.Stderr, "\r\n[tern] session ended\r\n")
			return nil
		}
		if !reconnect {
			fmt.Fprint(os.Stderr, "\r\n[tern] disconnected\r\n")
			return errors.New("connection lost")
		}
		// A connection that had been up a while redials at once. One that
		// died quickly (a flaky link, or a client the agent keeps dropping
		// for falling behind) waits first, so the loop cannot spin.
		if time.Since(connectedAt) >= stableConnection {
			backoff = time.Second
			continue
		}
		if !wait() {
			return nil
		}
	}
}

// dialCancelable runs dial but gives up as soon as ctx is done, even when dial
// itself does not watch ctx. A client that connects after that is closed
// rather than used.
func dialCancelable(ctx context.Context, dial func(context.Context) (*Client, error)) (*Client, error) {
	type result struct {
		cl  *Client
		err error
	}
	ch := make(chan result, 1)
	go func() {
		cl, err := dial(ctx)
		ch <- result{cl, err}
	}()
	select {
	case r := <-ch:
		if r.err == nil && ctx.Err() != nil {
			r.cl.Close()
			return nil, ctx.Err()
		}
		return r.cl, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.cl != nil {
				r.cl.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// newAttachID returns a random id that names this client process to the agent
// across its reconnects.
func newAttachID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("tern: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func roText(ro bool) string {
	if ro {
		return " [read-only] (Ctrl-C to leave)"
	}
	return ""
}

// consoleSize returns the controlling terminal's size. On Unix the size is
// readable from stdin, but on Windows it must come from the console output
// handle (GetConsoleScreenBufferInfo needs a screen buffer), so fall back to
// stdout. Returns ok=false when no size is available.
func consoleSize() (cols, rows int, ok bool) {
	if c, r, err := term.GetSize(int(os.Stdin.Fd())); err == nil && c > 0 {
		return c, r, true
	}
	if c, r, err := term.GetSize(int(os.Stdout.Fd())); err == nil && c > 0 {
		return c, r, true
	}
	return 0, 0, false
}
