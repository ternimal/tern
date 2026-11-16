// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	tern "github.com/ternimal/tern/internal/tern"
)

// Persistence. With Config.PTYState set, the terminals this server opened
// are listed in that file, which one tern mcp at a time holds, by a lock file
// beside it. At exit the terminals are left running on the agent instead of
// ended, and the next tern mcp with the same state file reattaches them under
// the same pty_ids. Only terminals listed there can be reattached, and only
// to sessions named as tern mcp names its own (see isPTYSession), so the
// model still cannot reach a session it did not open; nor can it write the
// file, which sits in tern's state directory, where the workspace tools never
// create a file nor upload one (see Config.TernDirs); a state file named by a
// relative path, which would land wherever tern mcp was started, is refused.
// The agent ends a session nobody reattaches within its --session-idle time,
// 10 minutes by default.

type ptyRecord struct {
	PTYID    string    `json:"pty_id"`
	Target   string    `json:"target"`
	Endpoint string    `json:"endpoint"`
	Session  string    `json:"session"`
	AttachID string    `json:"attach_id"`
	Cols     int       `json:"cols"`
	Rows     int       `json:"rows"`
	Prompt   string    `json:"prompt,omitempty"`
	OpenedAt time.Time `json:"opened_at"`
	// Next is the offset after the output this terminal had, where the next
	// tern mcp continues so offsets a client holds stay meaningful.
	Next int64 `json:"next,omitempty"`
}

type ptyStore struct {
	path   string
	lock   *os.File
	frozen bool // at shutdown: what was saved is what the next tern mcp gets
}

// openPTYStore takes the state file's lock and reads the terminals in it.
func openPTYStore(path string) (*ptyStore, []ptyRecord, error) {
	if !filepath.IsAbs(path) {
		return nil, nil, fmt.Errorf("the terminal state file %q is not an absolute path", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := lockFile(lf); err != nil {
		lf.Close()
		return nil, nil, fmt.Errorf("another tern mcp holds %s: %v", path, err)
	}
	st := &ptyStore{path: path, lock: lf}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return st, nil, nil
	case err != nil:
		lf.Close()
		return nil, nil, err
	}
	var recs []ptyRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		slog.Warn("the terminal state file is unreadable; starting without it", "file", path, "err", err)
		return st, nil, nil
	}
	return st, recs, nil
}

// save replaces the state file, owner-only, so a crash leaves the old one or
// the new one, never half of either.
func (st *ptyStore) save(recs []ptyRecord) error {
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	os.Remove(tmp)
	f, err := tern.CreateOwnerOnly(tmp, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, st.path)
}

// persisting reports whether terminals outlive this server.
func (s *Server) persisting() bool {
	s.ptyStoreMu.Lock()
	defer s.ptyStoreMu.Unlock()
	return s.ptyStore != nil
}

// openPTYStore loads the state file and reattaches the terminals in it that
// belong to a target of this config: same name, same agent.
func (s *Server) loadPTYStore() {
	st, recs, err := openPTYStore(s.cfg.PTYState)
	if err != nil {
		slog.Warn("terminals will not persist", "err", err)
		return
	}
	s.ptyStoreMu.Lock()
	s.ptyStore = st
	s.ptyStoreMu.Unlock()
	s.adoptRecords(recs)
	s.savePTYs()
}

// adoptRecords reattaches the saved terminals that belong to a target of
// this config: same name, same agent.
func (s *Server) adoptRecords(recs []ptyRecord) {
	for _, r := range recs {
		if !isPTYSession(r.Session) || !isPTYID(r.PTYID) {
			slog.Warn("dropping a saved terminal whose session or pty_id tern mcp did not name", "pty", r.PTYID, "session", r.Session)
			continue
		}
		t := s.tgts().byName[r.Target]
		if t == nil || t.Endpoint != r.Endpoint || !t.Policy.PTYAllowed() || s.lookupPTY(r.PTYID) != nil {
			slog.Info("dropping a saved terminal this config cannot reach", "pty", r.PTYID, "target", r.Target)
			continue
		}
		slog.Info("reattaching a saved terminal", "pty", r.PTYID, "target", r.Target, "session", r.Session)
		s.adoptPTY(t, r)
	}
}

// savePTYs writes the open terminals to the state file.
func (s *Server) savePTYs() {
	s.ptyStoreMu.Lock()
	defer s.ptyStoreMu.Unlock()
	s.savePTYsLocked(nil)
}

// savePTYsLocked writes the open terminals, and the records in extra that
// name none of them, to the state file, and reports whether it did; the
// caller holds ptyStoreMu. A terminal is saved with the endpoint of the agent
// it runs on, so a tern mcp whose config has since pointed the name at
// another agent drops it instead of reattaching there.
func (s *Server) savePTYsLocked(extra []ptyRecord) bool {
	if s.ptyStore == nil || s.ptyStore.frozen {
		return false
	}
	var recs []ptyRecord
	s.ptysMu.Lock()
	for _, p := range s.ptys {
		p.mu.Lock()
		live, cols, rows, prompt := !p.ended && !p.closing, p.cols, p.rows, p.prompt
		p.mu.Unlock()
		if live {
			next, _ := p.out.End()
			recs = append(recs, ptyRecord{
				PTYID: p.id, Target: p.target, Endpoint: p.tgt.Endpoint, Session: p.session,
				AttachID: p.attachID, Cols: cols, Rows: rows, Prompt: prompt, OpenedAt: p.opened, Next: next,
			})
		}
	}
	s.ptysMu.Unlock()
	for _, r := range extra {
		if !slices.ContainsFunc(recs, func(q ptyRecord) bool { return q.PTYID == r.PTYID }) {
			recs = append(recs, r)
		}
	}
	slices.SortFunc(recs, func(a, b ptyRecord) int { return a.OpenedAt.Compare(b.OpenedAt) })
	if err := s.ptyStore.save(recs); err != nil {
		slog.Warn("could not save the terminal state", "file", s.ptyStore.path, "err", err)
		return false
	}
	return true
}

// MovePTYState moves the terminals this server keeps to the state file at
// path, after a reload changed the targets the state file is named for, so a
// tern mcp started later with the reloaded config reattaches them. As at
// startup, the terminals an earlier tern mcp left in that file for these
// targets are reattached. When another tern mcp holds that file, or it cannot
// be written, the terminals stay where they are.
func (s *Server) MovePTYState(path string) {
	s.ptyStoreMu.Lock()
	st := s.ptyStore
	if st == nil || st.frozen || path == "" || path == st.path {
		s.ptyStoreMu.Unlock()
		return
	}
	next, recs, err := openPTYStore(path)
	if err != nil {
		s.ptyStoreMu.Unlock()
		slog.Warn("terminals stay in the state file of the targets tern mcp started with", "file", st.path, "err", err)
		return
	}
	old, oldLock := st.path, st.lock
	st.path, st.lock = next.path, next.lock
	// The new file gets this server's terminals and keeps the ones saved in
	// it, before the old file goes: a crash in between loses neither.
	if !s.savePTYsLocked(recs) {
		st.path, st.lock = old, oldLock
		s.ptyStoreMu.Unlock()
		next.lock.Close()
		return
	}
	// The old file goes while its lock is still held, so no tern mcp started
	// with the old config reattaches what this one keeps.
	os.Remove(old)
	oldLock.Close()
	s.ptyStoreMu.Unlock()
	if len(recs) > 0 {
		s.adoptRecords(recs)
		s.savePTYs()
	}
}

func (s *Server) freezePTYStore() {
	s.ptyStoreMu.Lock()
	defer s.ptyStoreMu.Unlock()
	if s.ptyStore != nil {
		s.ptyStore.frozen = true
	}
}

// closePTYStore releases the state file for the next tern mcp.
func (s *Server) closePTYStore() {
	s.ptyStoreMu.Lock()
	defer s.ptyStoreMu.Unlock()
	if s.ptyStore != nil {
		s.ptyStore.lock.Close()
		s.ptyStore = nil
	}
}
