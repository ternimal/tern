// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// permOf returns the permission bits of p, not following a link.
func permOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// writeWithMode writes a file at p with exactly mode perm, whatever the umask.
func writeWithMode(t *testing.T, p, content string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
}

// A file of ours with a single name keeps its mode when a download or an
// upload rewrites it. A second name of a file of ours, a hard link another
// local user who may add names to the directory can make, is not taken for a
// file of ours: what is written there gets no more than a new file would, so
// a private download stays private and an upload's mode is not widened to
// the linked file's, and the linked file itself is left as it was.
func TestWriteOverSecondNameIsNotOurs(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "key.pem")
	writeWithMode(t, src, "private key\n", 0o600)

	// Control: a single-name file of ours keeps its mode.
	own := filepath.Join(dir, "own.txt")
	writeWithMode(t, own, "old\n", 0o644)
	if err := cl.CopyFrom(src, own); err != nil {
		t.Fatal(err)
	}
	if m := permOf(t, own); m != 0o644 {
		t.Errorf("a download over a single-name 0644 file of ours left it %04o", m)
	}

	link := func(target, name string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.Link(target, p); err != nil {
			t.Skipf("hard link: %v", err)
		}
		return p
	}

	notes := filepath.Join(dir, "notes.txt") // every user may read it
	writeWithMode(t, notes, "notes\n", 0o644)
	dst := link(notes, "copy.pem")
	if err := cl.CopyFrom(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "private key\n" {
		t.Fatalf("the download holds %q", b)
	}
	if m, want := permOf(t, dst), 0o644&newFileMode(0o600); m != want {
		t.Errorf("a 0600 download over a second name of a 0644 file of ours landed %04o, want %04o", m, want)
	}
	if b, _ := os.ReadFile(notes); string(b) != "notes\n" || permOf(t, notes) != 0o644 {
		t.Errorf("the linked file changed: %q, %04o", b, permOf(t, notes))
	}

	shared := filepath.Join(dir, "shared.txt") // every user may change it
	writeWithMode(t, shared, "shared\n", 0o666)
	script := link(shared, "deploy.sh")
	body := []byte("#!/bin/sh\necho deploy\n")
	if err := cl.WriteFile(script, bytes.NewReader(body), int64(len(body)), 0o700, nil); err != nil {
		t.Fatal(err)
	}
	if m, want := permOf(t, script), 0o666&newFileMode(0o700); m != want {
		t.Errorf("a 0700 upload over a second name of a 0666 file of ours landed %04o, want %04o", m, want)
	}
	if b, _ := os.ReadFile(shared); string(b) != "shared\n" || permOf(t, shared) != 0o666 {
		t.Errorf("the linked file changed: %q, %04o", b, permOf(t, shared))
	}
}

// fakeAccounts points privateGroup at account files of its own that show
// gid as the primary group of this user alone, named "me", with members
// listed in the group file as it gives them.
func fakeAccounts(t *testing.T, gid uint32, members string) {
	t.Helper()
	dir := t.TempDir()
	passwd, group := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, fmt.Appendf(nil, "me:x:%d:%d::/:/bin/sh\n", os.Getuid(), gid), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, fmt.Appendf(nil, "me:x:%d:%s\n", gid, members), 0o644); err != nil {
		t.Fatal(err)
	}
	passwdFile, groupFile = passwd, group
	t.Cleanup(func() { passwdFile, groupFile = "/etc/passwd", "/etc/group" })
}

// gidOf returns the group of p.
func gidOf(t *testing.T, p string) uint32 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Gid
}

// checkKept writes over files of ours in dir, a 0600 download and a 0600
// upload over 0644 files and a 0644 download over a 0600 file, and fails
// unless the 0644 files kept their mode when kept is set and got no more
// than a new file would otherwise; the 0600 file stays 0600 either way.
func checkKept(t *testing.T, cl *Client, dir, key, notes string, kept bool) {
	t.Helper()
	want := 0o644 & newFileMode(0o600)
	if kept {
		want = 0o644
	}
	down, up, private := filepath.Join(dir, "down.pem"), filepath.Join(dir, "up.pem"), filepath.Join(dir, "private.key")
	writeWithMode(t, down, "notes\n", 0o644)
	writeWithMode(t, up, "notes\n", 0o644)
	writeWithMode(t, private, "old key\n", 0o600)
	if err := cl.CopyFrom(key, down); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(down); string(b) != "private key\n" {
		t.Fatalf("the download holds %q", b)
	}
	body := []byte("private key\n")
	if err := cl.WriteFile(up, bytes.NewReader(body), int64(len(body)), 0o600, nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.CopyFrom(notes, private); err != nil {
		t.Fatal(err)
	}
	if m := permOf(t, down); m != want {
		t.Errorf("%s: a 0600 download over a 0644 file of ours landed %04o, want %04o", filepath.Base(dir), m, want)
	}
	if m := permOf(t, up); m != want {
		t.Errorf("%s: a 0600 upload over a 0644 file of ours landed %04o, want %04o", filepath.Base(dir), m, want)
	}
	if m := permOf(t, private); m != 0o600 {
		t.Errorf("%s: a 0644 download over a 0600 file of ours landed %04o", filepath.Base(dir), m)
	}
}

// A file of ours keeps its mode only in a directory no other user may add
// names to or rename names in. Where one may, through the other write bit,
// sticky or not, or the group write bit of a group that is not our own
// private group, that user could have moved a file of ours there from a
// directory of theirs, or renamed one over the name: what is written there
// gets no more than a new file would, so a private download or upload stays
// private, and a private file is not widened either way.
func TestWriteWhereOthersMayAddNamesIsNotOurs(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	src := t.TempDir()
	key, notes := filepath.Join(src, "key.pem"), filepath.Join(src, "notes.txt")
	writeWithMode(t, key, "private key\n", 0o600)
	writeWithMode(t, notes, "notes\n", 0o644)
	base := t.TempDir()
	gid := gidOf(t, base)
	// Only where tern reads ACLs can it tell that no ACL entry stands
	// behind the group write bit.
	aclsRead := runtime.GOOS == "linux" || runtime.GOOS == "android"
	for _, c := range []struct {
		name    string
		perm    os.FileMode
		members string // of the directory's group, which is ours alone without any
		kept    bool
	}{
		{"private", 0o700, "", true},
		{"others-read", 0o755, "", true},
		{"own-group-writes", 0o775, "", aclsRead},
		{"sticky-alone", 0o755 | os.ModeSticky, "", true},
		{"others-write", 0o777, "", false},
		{"others-write-sticky", 0o777 | os.ModeSticky, "", false},
		{"others-add-only", 0o703, "", false},
		{"shared-group-writes", 0o775, "other", false},
		{"shared-group-writes-sticky", 0o770 | os.ModeSticky, "other", false},
	} {
		fakeAccounts(t, gid, c.members)
		dir := filepath.Join(base, c.name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, c.perm); err != nil {
			t.Fatal(err)
		}
		checkKept(t, cl, dir, key, notes, c.kept)
	}
}

// setMode sets a status's mode, whose type differs between systems.
func setMode[M ~uint16 | ~uint32](m *M, mode uint32) { *m = M(mode) }

// A directory is open to other users when another user owns it, root
// aside, or its mode lets others write it, or its group, unless that is the
// user's own private group and the directory has no ACL. The sticky bit
// changes nothing.
func TestDirOpenToOthers(t *testing.T) {
	const self, other, mine, shared = 1000, 1001, 1000, 100
	private := func(gid uint32, uid int) bool { return gid == mine && uid == self }
	for _, c := range []struct {
		uid, gid  uint32
		mode      uint32
		acl, open bool
	}{
		{self, shared, 0o700, false, false},
		{self, shared, 0o755, false, false},
		{self, shared, 0o1755, false, false},
		{self, mine, 0o775, false, false},
		{self, mine, 0o1770, false, false},
		{0, shared, 0o755, false, false},
		{0, mine, 0o775, false, false},
		{other, shared, 0o700, false, true},
		{other, shared, 0o755, false, true},
		{other, mine, 0o775, false, true},
		{self, shared, 0o757, false, true},
		{self, shared, 0o703, false, true},
		{self, shared, 0o1777, false, true},
		{self, mine, 0o1777, false, true},
		{0, shared, 0o1777, false, true},
		{self, shared, 0o775, false, true},
		{self, shared, 0o1770, false, true},
		{self, mine, 0o775, true, true},
		{self, mine, 0o777, false, true},
	} {
		st := unix.Stat_t{Uid: c.uid, Gid: c.gid}
		setMode(&st.Mode, unix.S_IFDIR|c.mode)
		if got := dirOpenToOthers(&st, self, private, func() bool { return c.acl }); got != c.open {
			t.Errorf("uid %d gid %d mode %04o acl %v: open %v, want %v", c.uid, c.gid, c.mode, c.acl, got, c.open)
		}
	}
}
