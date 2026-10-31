// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	tern "github.com/ternimal/tern/internal/tern"
)

// Auditor appends one JSON line per audit event. A command is logged before it
// runs ("start") and after ("end"), so a crash mid-run still leaves a record;
// if the start line cannot be written the call is refused.
type Auditor struct {
	mu  sync.Mutex
	f   *os.File
	seq uint64
}

// AuditEntry is one line of the audit log. Args never include stdin contents
// or other content, only their sizes, and known secrets in them are redacted
// as the line is written.
type AuditEntry struct {
	TS         string `json:"ts"`
	Seq        uint64 `json:"seq"`
	Phase      string `json:"phase"` // start | end | error | denied | rejected | info | confirm_requested | confirm_answered | replayed
	Client     string `json:"client,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Tool       string `json:"tool"`
	Target     string `json:"target"`
	Args       any    `json:"args,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Confirmed  bool   `json:"confirmed,omitempty"` // a human approved this exact action
	JobID      string `json:"job_id,omitempty"`
	PTYID      string `json:"pty_id,omitempty"`
	Recording  string `json:"recording,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Bytes      int    `json:"bytes,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

// OpenAuditor opens (creating if needed) the audit log at path, owner-only.
func OpenAuditor(path string) (*Auditor, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := tern.CreateOwnerOnly(path, os.O_APPEND)
	if errors.Is(err, fs.ErrExist) {
		f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err == nil {
			if rerr := tern.RestrictToOwner(path); rerr != nil {
				slog.Warn("could not restrict the audit log to the owner", "file", path, "err", rerr)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return &Auditor{f: f}, nil
}

// Log writes e as one line, stamping the time and sequence number.
func (a *Auditor) Log(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	e.Seq = a.seq
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	// Every argument is redacted here, whichever tool logged it: a path, a
	// pattern pty_read waits for or a key name can hold a secret as well as
	// a command line can. A reason or error can quote them, as a refused
	// command line does.
	e.Args = redactArgs(e.Args)
	e.Reason, _ = redact(e.Reason)
	e.Error, _ = redact(e.Error)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = a.f.Write(append(escapeJSONHidden(b), '\n'))
	return err
}

// redactArgs returns a copy of v, an entry's arguments or a call's decoded
// JSON ones, with known secrets redacted in every string it holds. The
// strings of a list are redacted as an argument vector (see redactAll), as
// the command line they make too, whether typed or decoded: an option and its
// value in two elements are found.
func redactArgs(v any) any {
	switch t := v.(type) {
	case string:
		s, _ := redact(t)
		return s
	case []string:
		return redactAll(t)
	case []any:
		out := make([]any, len(t))
		var strs []string
		var at []int // where in t each of strs is
		for i, x := range t {
			if s, ok := x.(string); ok {
				strs, at = append(strs, s), append(at, i)
				continue
			}
			out[i] = redactArgs(x)
		}
		for k, s := range redactAll(strs) {
			out[at[k]] = s
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = redactArgs(x)
		}
		return out
	}
	return v
}

// escapeJSONHidden escapes, in JSON text, what json.Marshal leaves raw though
// a person reading the log would not see it, or a terminal showing the log
// would act on it: DEL, C1 controls and invisible characters such as
// bidirectional overrides, which can make a logged command read as another.
// They occur only inside strings, where a \u escape keeps the value exact.
func escapeJSONHidden(b []byte) []byte {
	hide := func(r rune) bool { return r == 0x7f || r >= 0x80 && r <= 0x9f || invisible(r) }
	if !bytes.ContainsFunc(b, hide) {
		return b
	}
	out := make([]byte, 0, len(b)+64)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		switch {
		case !hide(r):
			out = append(out, b[:size]...)
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			out = fmt.Appendf(out, `\u%04x\u%04x`, r1, r2)
		default:
			out = fmt.Appendf(out, `\u%04x`, r)
		}
		b = b[size:]
	}
	return out
}

// Close closes the log file.
func (a *Auditor) Close() error { return a.f.Close() }
