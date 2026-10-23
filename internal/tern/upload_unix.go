// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// uploadTarget is the file an upload or a download writes: a name in a
// directory opened once, links on the way followed. All that comes after
// works relative to that open directory: the temporary file is created in it
// and renamed over the name there, and the path the reply reports as Real is
// the one the kernel has for the directory. So the file lands exactly where
// the client was told, however names on the way are swapped meanwhile. The
// last name is not followed: the rename replaces a link there.
type uploadTarget struct {
	dir     int         // the open directory
	base    string      // the target's name in it
	want    os.FileMode // the mode the client sent
	tmp     *os.File    // the temporary file, in dir
	tmpName string
	real    string // Real for the reply, or "unresolved: ..." (see realPathOf)
}

// openUploadTarget opens the directory rawDir, refuses a target that is a
// directory, and creates the temporary file. path is the path the client
// sent, for messages.
func openUploadTarget(path, rawDir, base string, want os.FileMode) (*uploadTarget, error) {
	var dir int
	err := ignoringEINTR(func() (err error) { dir, err = unix.Open(rawDir, dirOpenFlags, 0); return err })
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: rawDir, Err: err}
	}
	t := &uploadTarget{dir: dir, base: base, want: want}
	if real, err := realPathOf(dir); err != nil {
		t.real = "unresolved: " + err.Error()
	} else {
		t.real = filepath.Join(real, base)
	}
	var st unix.Stat_t
	if unix.Fstatat(dir, base, &st, 0) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		unix.Close(dir)
		return nil, fmt.Errorf("%s is a directory; name the file to write", path)
	}
	if err := t.createTemp(rawDir); err != nil {
		unix.Close(dir)
		return nil, err
	}
	return t, nil
}

// createTemp creates the temporary file, 0600, a new file of its own: never
// one already there, or a link.
func (t *uploadTarget) createTemp(rawDir string) error {
	prefix := "." + t.base + ".tern-"
	for range 10000 {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10)
		var fd int
		err := ignoringEINTR(func() (err error) {
			fd, err = unix.Openat(t.dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
			return err
		})
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return &os.PathError{Op: "createtemp", Path: filepath.Join(rawDir, name), Err: err}
		}
		t.tmp, t.tmpName = os.NewFile(uintptr(fd), name), name
		return nil
	}
	return &os.PathError{Op: "createtemp", Path: filepath.Join(rawDir, prefix+"*"), Err: fs.ErrExist}
}

// mode is the mode the file gets, judged by what is now under the target's
// name in the open directory: a regular file's mode is kept or narrowed (see
// keptMode), kept only when this user owns it, it has no other name, and no
// other user may add or rename names in the directory (see
// othersMayAddNames); for anything else, or nothing, the file gets a new
// file's mode.
func (t *uploadTarget) mode() os.FileMode {
	var st unix.Stat_t
	if unix.Fstatat(t.dir, t.base, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return newFileMode(t.want)
	}
	own := int(st.Uid) == os.Getuid() && st.Nlink == 1 && !othersMayAddNames(t.dir)
	return keptMode(os.FileMode(st.Mode&0o777), own, t.want)
}

// othersMayAddNames reports whether a user other than this one may add or
// rename names in the open directory dir, and so may have put a file of ours
// under the target's name: moved there from a directory of theirs, or
// renamed over the name. It judges the directory as dirOpenToOthers does,
// for this user, with privateGroup and carriesACL; one it cannot look at
// counts as open.
func othersMayAddNames(dir int) bool {
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil {
		return true
	}
	return dirOpenToOthers(&st, os.Getuid(), privateGroup, func() bool { return carriesACL(dir) })
}

// dirOpenToOthers judges a directory by its status, st, for the user uid:
// another user who owns it may give themselves the right to add names to it
// (root aside, who may anyway), and so may anyone the other write bit lets,
// or the group write bit, unless the group is the user's own private group,
// which private says, and acl says the directory has no ACL, whose mask the
// group bits would then show for the users and groups it lists. The sticky
// bit does not help: it keeps others from removing or renaming a name that
// is not theirs, not from adding one, as moving a file in does.
func dirOpenToOthers(st *unix.Stat_t, uid int, private func(gid uint32, uid int) bool, acl func() bool) bool {
	if int(st.Uid) != uid && st.Uid != 0 {
		return true
	}
	return st.Mode&0o002 != 0 || st.Mode&0o020 != 0 && (!private(st.Gid, uid) || acl())
}

// finish sets the temporary file's mode, closes it and renames it over the
// target. On failure it removes the temporary file, and the target is left
// as it was.
func (t *uploadTarget) finish() error {
	chmodErr := t.tmp.Chmod(t.mode())
	closeErr := t.tmp.Close()
	if err := errors.Join(chmodErr, closeErr); err != nil {
		t.removeTemp()
		return err
	}
	if err := ignoringEINTR(func() error { return unix.Renameat(t.dir, t.tmpName, t.dir, t.base) }); err != nil {
		t.removeTemp()
		return &os.LinkError{Op: "rename", Old: t.tmpName, New: t.base, Err: err}
	}
	return nil
}

// abort drops the temporary file, leaving the target as it was.
func (t *uploadTarget) abort() {
	t.tmp.Close()
	t.removeTemp()
}

func (t *uploadTarget) removeTemp() {
	ignoringEINTR(func() error { return unix.Unlinkat(t.dir, t.tmpName, 0) })
}

// close closes the directory.
func (t *uploadTarget) close() { unix.Close(t.dir) }

// ignoringEINTR runs f again for as long as a signal interrupts it.
func ignoringEINTR(f func() error) error {
	for {
		if err := f(); err != unix.EINTR {
			return err
		}
	}
}
