// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"os"
	"path/filepath"
	"testing"
)

// openBase returns a new directory that every user may search, as may every
// directory above it. t.TempDir makes 0700 directories, and TMPDIR may sit in
// a private home directory, so it looks for a base open all the way up.
func openBase(t *testing.T) string {
	t.Helper()
	for _, base := range []string{os.TempDir(), "/tmp", "/var/tmp", "/dev/shm"} {
		real, err := filepath.EvalSymlinks(base)
		if err != nil || !dirsOpenToAll(filepath.Join(real, "x")) {
			continue
		}
		dir, err := os.MkdirTemp(real, "tern-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Skip("no directory that every user may search to make test files in")
	return ""
}

// A file is reachable by every user only when every directory above it lets
// them search it: search alone (o+x) is enough, and one closed directory
// anywhere above keeps them out, whatever the file's own mode.
func TestDirsOpenToAll(t *testing.T) {
	base := openBase(t)
	mid := filepath.Join(base, "a")
	f := filepath.Join(mid, "b", "file")
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(mid, 0o755)
	os.Chmod(filepath.Dir(f), 0o755)
	os.WriteFile(f, []byte("x"), 0o644)
	for _, c := range []struct {
		mode os.FileMode
		open bool
	}{{0o755, true}, {0o711, true}, {0o701, true}, {0o750, false}, {0o700, false}, {0o744, false}} {
		os.Chmod(mid, c.mode)
		if got := dirsOpenToAll(f); got != c.open {
			t.Errorf("directory mode %04o above the file: %v, want %v", c.mode, got, c.open)
		}
	}
	os.Chmod(mid, 0o755)
	// Anything unexpected reads as closed: a relative path, a name that is
	// not there, a link where a directory should be.
	os.Symlink(filepath.Join(mid, "b"), filepath.Join(base, "link"))
	for _, p := range []string{"a/b/file", filepath.Join(base, "gone", "file"), filepath.Join(base, "link", "file")} {
		if dirsOpenToAll(p) {
			t.Errorf("%s reads as open", p)
		}
	}
	if !dirsOpenToAll("/file-at-the-root") {
		t.Error("a file right under / reads as closed")
	}
}

// The agent's download reply says whether the directories above the file are
// open to all, which a client checks before any content moves.
func TestDownloadReplyReportsClosedDirs(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := filepath.Join(openBase(t), "store")
	os.Mkdir(dir, 0o755)
	os.Chmod(dir, 0o755)
	f := filepath.Join(dir, "conf")
	os.WriteFile(f, []byte("x\n"), 0o644)
	os.Chmod(f, 0o644)
	read := func() (os.FileMode, bool) {
		t.Helper()
		var perm os.FileMode
		var open bool
		if _, _, err := cl.ReadFile(f, 0, 10, func(_ string, p os.FileMode, o bool) error { perm, open = p, o; return nil }); err != nil {
			t.Fatal(err)
		}
		return perm, open
	}
	if perm, open := read(); perm != 0o644 || !open {
		t.Errorf("open directory: mode %04o, open %v", perm, open)
	}
	os.Chmod(dir, 0o700)
	if perm, open := read(); perm != 0o644 || open {
		t.Errorf("closed directory: mode %04o, open %v", perm, open)
	}
}
