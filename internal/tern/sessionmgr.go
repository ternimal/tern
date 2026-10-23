// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// sessionManager owns named PTY sessions that outlive any single connection,
// which is what makes both reconnect/resume and multi-client sharing possible.
type sessionManager struct {
	shell     string
	idle      time.Duration // how long a session lingers after its last client leaves
	recordDir string        // if set, each session is recorded as an asciicast here

	mu       sync.Mutex
	seq      int
	sessions map[string]*sharedPTY
}

func newSessionManager(shell string, idle time.Duration, recordDir string) *sessionManager {
	return &sessionManager{shell: shell, idle: idle, recordDir: recordDir, sessions: make(map[string]*sharedPTY)}
}

type attachment struct {
	ch      chan []byte
	id      string // the client's per-process attach id ("" if it sent none)
	write   bool
	evicted bool // dropped for falling behind, not because the session ended
	cols    int
	rows    int
	offset  int64 // position in the session's output of the first byte sent to it
}

type sharedPTY struct {
	name string
	mgr  *sessionManager
	sh   shellSession

	typed    chan typedInput // writers' input on its way to the terminal (see feed)
	stopFeed chan struct{}   // closed by close: feed stops

	mu        sync.Mutex
	ring      []byte
	total     int64 // bytes of output so far; the ring holds the last of them
	clients   map[*attachment]struct{}
	reaper    *time.Timer
	closeOnce sync.Once
	rec       *Recorder
	lastCols  int
	lastRows  int
	closed    bool // set by close(); attach refuses a session that is going away
}

// attach creates or joins a session and returns an attachment to stream from.
// attachID identifies one client process across its reconnects (see below).
func (m *sessionManager) attach(name, mode string, write, force bool, attachID string, cols, rows int) (*sharedPTY, *attachment, []byte, error) {
	if err := ValidSessionName(name); err != nil {
		return nil, nil, nil, err
	}
	m.mu.Lock()
	ps := m.sessions[name]
	create := false
	switch mode {
	case modeNew:
		if ps != nil {
			m.mu.Unlock()
			return nil, nil, nil, fmt.Errorf("session %q already exists", name)
		}
		create = true
	case modeAttach:
		if ps == nil {
			m.mu.Unlock()
			return nil, nil, nil, fmt.Errorf("no such session %q", name)
		}
	default: // modeAuto
		create = ps == nil
	}

	if create && !write {
		// A viewer only joins: a session it created would have no writer.
		m.mu.Unlock()
		switch {
		case mode == modeNew:
			return nil, nil, nil, errors.New("a read-only client cannot create a session; drop --new to join an existing one")
		case name == "":
			return nil, nil, nil, errors.New("a read-only client only joins an existing session; name it with --session")
		default:
			return nil, nil, nil, fmt.Errorf("no such session %q (a read-only client only joins an existing one)", name)
		}
	}
	if create {
		if len(m.sessions) >= maxSessions {
			m.mu.Unlock()
			return nil, nil, nil, fmt.Errorf("too many sessions on this agent (max %d)", maxSessions)
		}
		if name == "" {
			// Pick the next free sN; a client may already have named one that way.
			for {
				m.seq++
				name = fmt.Sprintf("s%d", m.seq)
				if m.sessions[name] == nil {
					break
				}
			}
		}
		sh, err := spawnShell(m.shell)
		if err != nil {
			m.mu.Unlock()
			return nil, nil, nil, err
		}
		ps = &sharedPTY{name: name, mgr: m, sh: sh, clients: make(map[*attachment]struct{}),
			typed: make(chan typedInput, inputQueueLen), stopFeed: make(chan struct{})}
		ps.rec = NewRecorder(m.recordDir, name, cols, rows, 0)
		m.sessions[name] = ps
		go ps.pump()
		go ps.feed()
	}
	m.mu.Unlock()

	ps.mu.Lock()
	if ps.closed {
		// The session ended between the lookup above and here.
		ps.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("no such session %q", ps.name)
	}
	if ps.reaper != nil {
		ps.reaper.Stop()
		ps.reaper = nil
	}
	// A reconnecting client sends the attach id it used before. If the agent
	// still holds that client's old attachment (its connection died but the
	// keepalive has not noticed yet), the new attachment replaces it, so a
	// writer gets its seat back instead of coming back read-only behind its
	// own stale slot. It gets back only what it asks for now, never the right
	// to write beside another writer: when someone else became a writer
	// while it was away, as a person taking over a terminal an AI drove
	// does, it comes back read-only, however soon after the drop it returns
	// and whether or not the agent had noticed the drop yet.
	if attachID != "" {
		for other := range ps.clients {
			if other.id == attachID {
				other.evicted = true // its stream is dead: send it no exit frame
				delete(ps.clients, other)
				close(other.ch)
				break
			}
		}
	}
	// Single-writer by default: a client joining a session that already has a
	// writer attaches read-only, unless it explicitly asked to co-drive (force).
	// The session creator always writes (its client set is still empty here).
	if write && !force {
		for other := range ps.clients {
			if other.write {
				write = false
				break
			}
		}
	}
	att := &attachment{ch: make(chan []byte, attachChanBuf), id: attachID, write: write, cols: cols, rows: rows}
	snapshot := make([]byte, len(ps.ring))
	copy(snapshot, ps.ring)
	att.offset = ps.total - int64(len(snapshot))
	ps.clients[att] = struct{}{}
	ps.applySizeLocked()
	ps.mu.Unlock()

	return ps, att, snapshot, nil
}

// pump reads the PTY and fans output out to every attached client + the ring.
func (ps *sharedPTY) pump() {
	// Close the PTY when the shell process exits so the read below unblocks.
	// On Windows (ConPTY), the PTY read pipe does NOT return EOF when the
	// child process exits; it blocks until the pseudoconsole handle is
	// explicitly closed. ptySession.Close is sync.Once-guarded, so whichever
	// of this close and the one in ps.close() runs second is a no-op.
	go func() {
		ps.sh.Wait()
		ps.sh.Close()
	}()

	buf := make([]byte, pumpBufSize)
	for {
		n, err := ps.sh.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			ps.rec.Output(chunk)
			ps.mu.Lock()
			ps.total += int64(n)
			ps.ring = append(ps.ring, chunk...)
			if len(ps.ring) > ringMax {
				ps.ring = ps.ring[len(ps.ring)-ringMax:]
			}
			for att := range ps.clients {
				select {
				case att.ch <- chunk:
				default: // slow client: drop it rather than stall everyone
					att.evicted = true // no exit frame: it reconnects and resumes
					delete(ps.clients, att)
					close(att.ch)
				}
			}
			ps.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	ps.close()
}

// typedInput is a chunk of a writer's input on its way to the terminal.
type typedInput struct {
	att *attachment // the writer that typed it
	p   []byte
}

// feed writes the writers' input to the terminal, in the order it came. It
// is the one goroutine that writes there, so a program that reads none of
// its input holds up only it, however many writers come and go. What a
// writer typed is dropped once the writer has left (a write already under
// way aside), never typed after it, and once a write fails (the shell ended)
// the rest is dropped too, so no writer waits on a queue nobody drains.
func (ps *sharedPTY) feed() {
	failed := false
	for {
		select {
		case in := <-ps.typed:
			if failed || !ps.attached(in.att) {
				continue
			}
			if _, err := ps.sh.Write(in.p); err != nil {
				failed = true
			}
		case <-ps.stopFeed:
			return
		}
	}
}

// attached reports whether att is still one of the session's clients.
func (ps *sharedPTY) attached(att *attachment) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	_, ok := ps.clients[att]
	return ok
}

// endBy ends the session at att's request if att may: a writer that is still
// attached. It reports whether it did.
func (ps *sharedPTY) endBy(att *attachment) bool {
	ps.mu.Lock()
	_, ok := ps.clients[att]
	ok = ok && att.write
	ps.mu.Unlock()
	if ok {
		ps.close()
	}
	return ok
}

func (ps *sharedPTY) resize(att *attachment, cols, rows int) {
	ps.mu.Lock()
	att.cols, att.rows = cols, rows
	ps.applySizeLocked()
	ps.mu.Unlock()
}

// applySizeLocked sets the PTY to the smallest size among the writers that have
// reported one (tmux-style), so output fits every client that can type. A
// read-only viewer's size is ignored, so a tiny viewer window cannot shrink the
// writer's shell. If no writer has a size yet, viewers are used as a fallback.
func (ps *sharedPTY) applySizeLocked() {
	cols, rows := sizeAcross(ps.clients, true)
	if cols == 0 || rows == 0 {
		cols, rows = sizeAcross(ps.clients, false) // fallback: no writer has a size yet
	}
	if cols > 0 && rows > 0 && (cols != ps.lastCols || rows != ps.lastRows) {
		ps.lastCols, ps.lastRows = cols, rows
		ps.sh.Resize(cols, rows)
		ps.rec.Resize(cols, rows)
	}
}

// sizeAcross returns the smallest reported cols/rows among the attachments,
// considering only writers when writersOnly is set. Zero means none reported.
func sizeAcross(clients map[*attachment]struct{}, writersOnly bool) (cols, rows int) {
	for att := range clients {
		if writersOnly && !att.write {
			continue
		}
		if att.cols <= 0 || att.rows <= 0 {
			continue
		}
		if cols == 0 || att.cols < cols {
			cols = att.cols
		}
		if rows == 0 || att.rows < rows {
			rows = att.rows
		}
	}
	return cols, rows
}

func (ps *sharedPTY) detach(att *attachment) {
	ps.mu.Lock()
	if _, ok := ps.clients[att]; ok {
		delete(ps.clients, att)
		close(att.ch)
	}
	empty := len(ps.clients) == 0
	if empty && ps.reaper == nil && !ps.closed {
		idle := ps.mgr.idle
		if idle > 0 {
			ps.reaper = time.AfterFunc(idle, ps.close)
		}
	}
	ps.applySizeLocked()
	ps.mu.Unlock()
}

func (ps *sharedPTY) close() {
	ps.closeOnce.Do(func() {
		ps.mgr.mu.Lock()
		if ps.mgr.sessions[ps.name] == ps {
			delete(ps.mgr.sessions, ps.name)
		}
		ps.mgr.mu.Unlock()

		ps.sh.Close()
		close(ps.stopFeed)
		ps.rec.Close()

		ps.mu.Lock()
		ps.closed = true
		if ps.reaper != nil {
			ps.reaper.Stop()
			ps.reaper = nil
		}
		for att := range ps.clients {
			delete(ps.clients, att)
			close(att.ch)
		}
		ps.mu.Unlock()
	})
}

// endedFor reports whether att's output ended because the session ended,
// not because att detached or was dropped for falling behind. Read it once
// att.ch has been closed: close sets closed before it closes the channels.
func (ps *sharedPTY) endedFor(att *attachment) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.closed && !att.evicted
}

func (ps *sharedPTY) clientCount() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return len(ps.clients)
}

func (m *sessionManager) list() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.sessions))
	for name := range m.sessions {
		names = append(names, name)
	}
	return names
}
