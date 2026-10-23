// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"fmt"
	"io"
	"net"
)

// ShellOptions configures OpenShell.
type ShellOptions struct {
	Session  string // session name; "" lets the agent pick one when it creates the session
	Mode     string // "new", "attach" or "auto"
	AttachID string // names this client across its reconnects, so a writer gets its seat back
	Write    bool   // ask to type; a session that already has a writer still attaches read-only
	CoDrive  bool   // type even when another writer is attached
	Cols     int    // initial terminal size; 0 when unknown
	Rows     int
}

// ShellStream is one attachment to a shell session on the agent: the agent
// replays the session's recent output, then streams it live. It is safe to
// call Write, Resize and EndSession from several goroutines while one reads
// the output.
type ShellStream struct {
	Session  string // the session's name, as the agent resolved it
	ReadOnly bool   // the agent gave this client no write access
	// Offset is the position in the session's whole output of the first byte
	// this stream delivers, or -1 when the agent does not report it. A client
	// that reconnects uses it to skip output it already has.
	Offset int64

	st net.Conn
	fw *frameWriter
	c  *Client // sends resize and end on its control stream
}

// OpenShell attaches to, or creates, a shell session on the agent.
func (c *Client) OpenShell(o ShellOptions) (*ShellStream, error) {
	st, err := c.sess.Open()
	if err != nil {
		return nil, err
	}
	h := streamHeader{Kind: kindShell, Session: o.Session, Mode: o.Mode, Write: o.Write, Force: o.CoDrive, Attach: o.AttachID, Cols: o.Cols, Rows: o.Rows}
	if err := writeHeader(st, h); err != nil {
		st.Close()
		return nil, err
	}
	rep, err := readReply(st)
	if err != nil {
		st.Close()
		return nil, err
	}
	if !rep.OK {
		st.Close()
		return nil, fmt.Errorf("%s", CleanText(rep.Err))
	}
	s := &ShellStream{Session: rep.Session, ReadOnly: rep.ReadOnly, Offset: -1, st: st, fw: &frameWriter{w: st}, c: c}
	if rep.Offset != nil {
		s.Offset = *rep.Offset
	}
	return s, nil
}

// Write types p into the shell. The agent drops input from a read-only
// attachment.
func (s *ShellStream) Write(p []byte) (int, error) {
	for done := 0; done < len(p); {
		n := min(len(p)-done, ioBufSize)
		if err := s.fw.write(frameData, p[done:done+n]); err != nil {
			return done, err
		}
		done += n
	}
	return len(p), nil
}

// Resize reports this client's terminal size. The agent sizes the PTY to the
// smallest writer. Like EndSession, it goes on the connection's control
// stream, so it never waits behind input the shell has not read.
func (s *ShellStream) Resize(cols, rows int) error {
	return s.c.control(s.st, frameResize, encodeResize(uint16(cols), uint16(rows)))
}

// EndSession asks the agent to end the session and kill its shell, as typing
// exit would but whatever runs in it, and however much typed input the shell
// has not read yet. Only a writer can.
func (s *ShellStream) EndSession() error {
	return s.c.control(s.st, frameEnd, nil)
}

// CopyOutput writes the session's output to w until the shell exits, which
// returns true, or the stream ends without the agent saying so, which returns
// false: the connection dropped, or the agent dropped this client for falling
// behind, and the session is still there to reattach to.
func (s *ShellStream) CopyOutput(w io.Writer) bool {
	for {
		typ, payload, err := readFrame(s.st)
		if err != nil {
			return false
		}
		switch typ {
		case frameData:
			w.Write(payload)
		case frameExit:
			return true
		}
	}
}

// Close detaches from the session; the session itself lives on.
func (s *ShellStream) Close() error { return s.st.Close() }
