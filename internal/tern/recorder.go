// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Recorder writes an asciicast v2 (asciinema) recording of a session's output.
// Only PTY output and resize events are recorded, never the raw input stream:
// text typed at no-echo prompts (passwords) is not captured, but anything the
// terminal echoes, such as a typed command line, is. The agent records its
// sessions with it, and tern mcp the terminals it opens. A nil *Recorder is a
// no-op.
type Recorder struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	start   time.Time
	pending []byte // an incomplete UTF-8 sequence held for the next output
	written int64
	limit   int64 // 0: no limit
	full    bool
}

// NewRecorder creates a recording for session name in dir, or returns nil if
// dir is empty or the file cannot be created. Past maxBytes of output, when
// maxBytes is not 0, the recording stops with a note saying so.
func NewRecorder(dir, name string, cols, rows int, maxBytes int64) *Recorder {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("recording disabled", "err", err)
		return nil
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	// O_EXCL with a random suffix: two session names that sanitize to the same
	// safeName within one second must not collide and truncate each other's
	// recording, and we never write through a pre-existing file or symlink.
	// Owner-only from creation: a recording holds all the terminal showed.
	rnd := make([]byte, 4)
	rand.Read(rnd)
	path := filepath.Join(dir, fmt.Sprintf("%s-%d-%x.cast", safeName(name), time.Now().Unix(), rnd))
	f, err := createOwnerOnly(path, 0)
	if err != nil {
		slog.Warn("recording disabled", "err", err)
		return nil
	}
	r := &Recorder{f: f, path: path, start: time.Now(), limit: maxBytes}
	hdr, _ := json.Marshal(map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": r.start.Unix()})
	f.Write(append(hdr, '\n'))
	slog.Info("recording session", "file", path)
	return r
}

// Path is the recording's file name.
func (r *Recorder) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Output records output. A UTF-8 sequence cut across two reads is joined
// first, since a JSON string cannot hold half a character.
func (r *Recorder) Output(p []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	data := append(r.pending, p...)
	cut := len(data)
	for i := len(data) - 1; i >= 0 && i >= len(data)-utf8.UTFMax; i-- {
		if utf8.RuneStart(data[i]) {
			if !utf8.FullRune(data[i:]) {
				cut = i
			}
			break
		}
	}
	r.pending = append([]byte(nil), data[cut:]...)
	r.eventLocked("o", data[:cut])
}

// Resize records a change of terminal size.
func (r *Recorder) Resize(cols, rows int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventLocked("r", []byte(fmt.Sprintf("%dx%d", cols, rows)))
}

func (r *Recorder) eventLocked(typ string, data []byte) {
	if r.full || len(data) == 0 {
		return
	}
	// The limit counts the file's bytes: escaped as JSON, a control byte
	// takes six.
	line, _ := json.Marshal([]any{time.Since(r.start).Seconds(), typ, string(data)})
	if r.limit > 0 && r.written+int64(len(line))+1 > r.limit {
		r.full = true
		line, _ = json.Marshal([]any{time.Since(r.start).Seconds(), "o", fmt.Sprintf("\r\n[tern: recording stopped at its %d byte limit]\r\n", r.limit)})
	}
	r.written += int64(len(line)) + 1
	r.f.Write(append(line, '\n'))
}

// Close writes any held bytes and closes the file.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventLocked("o", r.pending)
	r.pending = nil
	r.f.Close()
}

func safeName(s string) string {
	out := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			return c
		default:
			return '_'
		}
	}, s)
	if out == "" {
		return "session"
	}
	return out
}
