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
	for _, r := range recs {
		if !isPTYSession(r.Session) || !isPTYID(r.PTYID) {
			slog.Warn("dropping a saved terminal whose session or pty_id tern mcp did not name", "pty", r.PTYID, "session", r.Session)
			continue
		}
		t := s.targets[r.Target]
		if t == nil || t.Endpoint != r.Endpoint || !t.Policy.PTYAllowed() || s.lookupPTY(r.PTYID) != nil {
			slog.Info("dropping a saved terminal this config cannot reach", "pty", r.PTYID, "target", r.Target)
			continue
		}
		slog.Info("reattaching a saved terminal", "pty", r.PTYID, "target", r.Target, "session", r.Session)
		s.adoptPTY(t, r)
	}
	s.savePTYs()
}

// savePTYs writes the open terminals to the state file.
func (s *Server) savePTYs() {
	s.ptyStoreMu.Lock()
	defer s.ptyStoreMu.Unlock()
	if s.ptyStore == nil || s.ptyStore.frozen {
		return
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
				PTYID: p.id, Target: p.target, Endpoint: s.targets[p.target].Endpoint, Session: p.session,
				AttachID: p.attachID, Cols: cols, Rows: rows, Prompt: prompt, OpenedAt: p.opened, Next: next,
			})
		}
	}
	s.ptysMu.Unlock()
	slices.SortFunc(recs, func(a, b ptyRecord) int { return a.OpenedAt.Compare(b.OpenedAt) })
	if err := s.ptyStore.save(recs); err != nil {
		slog.Warn("could not save the terminal state", "file", s.ptyStore.path, "err", err)
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
