// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// Two sessions whose names sanitize alike within one second get distinct
// recordings instead of one truncating the other.
func TestRecorderUniquePerSession(t *testing.T) {
	dir := t.TempDir()
	r1 := NewRecorder(dir, "a/b", 80, 24, 0)
	r2 := NewRecorder(dir, "a_b", 80, 24, 0) // sanitizes to the same safeName
	if r1 == nil || r2 == nil {
		t.Fatal("recorder not created")
	}
	r1.Close()
	r2.Close()
	casts, _ := filepath.Glob(filepath.Join(dir, "*.cast"))
	if len(casts) != 2 {
		t.Fatalf("got %d .cast files, want 2 distinct recordings", len(casts))
	}
}

// A character split across two PTY reads is recorded whole, not as two
// replacement characters, and a capped recording stops with a note.
func TestRecorderJoinsSplitCharacters(t *testing.T) {
	dir := t.TempDir()
	r := NewRecorder(dir, "utf8", 80, 24, 64)
	thai := []byte("สวัสดี")
	r.Output(thai[:4])
	r.Output(thai[4:])
	r.Output([]byte(strings.Repeat("x", 100)))
	r.Output([]byte("after the limit"))
	r.Close()
	data, err := os.ReadFile(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n")[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(line), &ev); err != nil || len(ev) != 3 {
			t.Fatalf("bad event %q", line)
		}
		out.WriteString(ev[2].(string))
	}
	if !strings.HasPrefix(out.String(), "สวัสดี") || strings.ContainsRune(out.String(), utf8.RuneError) {
		t.Fatalf("split character not joined: %q", out.String())
	}
	if !strings.Contains(out.String(), "recording stopped at its 64 byte limit") || strings.Contains(out.String(), "after the limit") {
		t.Fatalf("limit not applied: %q", out.String())
	}
}
