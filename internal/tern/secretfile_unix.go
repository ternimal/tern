// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// secretFileExposure says whether other local users could read or change the
// open file f at path, whose status is fi, which holds a secret; words say
// how to replace it.
func secretFileExposure(_ *os.File, fi fs.FileInfo, path string, words fileWords) (*secretFileError, error) {
	return secretFileProblem(path, fi, os.Getuid(), words), nil
}

// secretFileProblem judges a secret file by its status, fi, for the user
// uid: another owner could change it, and any group or other permission bit
// lets other users at it, as for a private key.
func secretFileProblem(path string, fi fs.FileInfo, uid int, words fileWords) *secretFileError {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != uid {
		return &secretFileError{path: path,
			problem: fmt.Sprintf("it is owned by uid %d, not by this user (uid %d)", st.Uid, uid),
			fix:     words.owner}
	}
	perm := fi.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	fix := "restrict it: chmod 600 " + ShellQuote(path)
	if perm&0o066 != 0 {
		fix = words.exposed + fix
	}
	return &secretFileError{path: path, problem: fmt.Sprintf("its permissions %04o give other users access to it", perm), fix: fix}
}

// aclState says whether a file has an ACL with entries beyond its mode.
type aclState int

const (
	noACL      aclState = iota // its mode says who may do what
	hasACL                     // its group bits are the ACL's mask, the most a named user or group may do
	aclUnknown                 // this system gives no way to tell here
)

// changeExposure says whether another local user could change the open file
// f at path, whose status is fi (see changeProblem), its ACL read through f;
// words say what to do about it.
func changeExposure(f *os.File, fi fs.FileInfo, path string, words fileWords) (*secretFileError, error) {
	return changeProblem(path, fi, os.Getuid(), privateGroup, fileACL(f), words), nil
}

// changeProblem judges a file by its status, fi, and acl, for the user uid:
// another user who owns it could change it (root aside, who may change any
// file), and so could anyone the other write bit lets, or the group write
// bit (see othersMayWrite). As ssh's StrictModes, it does not mind who may
// read the file.
func changeProblem(path string, fi fs.FileInfo, uid int, private func(gid uint32, uid int) bool, acl aclState, words fileWords) *secretFileError {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok && int(st.Uid) != uid && st.Uid != 0 {
		return &secretFileError{path: path,
			problem: fmt.Sprintf("it is owned by uid %d, not by this user (uid %d) or root", st.Uid, uid),
			fix:     words.owner}
	}
	switch othersMayWrite(fi, uid, private, acl) {
	case writeNone:
		return nil
	case writeACL:
		return &secretFileError{path: path,
			problem: fmt.Sprintf("its ACL lets other users change it (the group bits of its permissions %04o are the ACL's mask, the most a user or group it names may do)", fi.Mode().Perm()),
			fix:     words.exposed + "stop others changing it: chmod go-w " + ShellQuote(path)}
	}
	return &secretFileError{path: path,
		problem: fmt.Sprintf("its permissions %04o let other users change it", fi.Mode().Perm()),
		fix:     words.exposed + "stop others changing it: chmod go-w " + ShellQuote(path)}
}

// What othersMayWrite finds.
const (
	writeNone = iota // no one but its owner, and its group if that is the user's own private group
	writeMode        // the mode lets others write
	writeACL         // the group write bit, which with an ACL lets the users and groups it names write
)

// othersMayWrite says whether the mode of fi, a file or directory, and its
// ACL, acl, let users other than its owner, the user uid, write to it: the
// other write bit does, and so does the group write bit, unless the group is
// the user's own private group, which private says. A umask of 002 leaves
// new files group-writable on the systems that give each user such a group.
// The group bit is the group's alone only where the file has no ACL: with
// one it is the ACL's mask, which lets every user and group the ACL names
// write, and where the ACL cannot be read (on every system but Linux, and
// on Linux where an NFS, SMB or AFS server may keep one) it is taken to be
// that.
func othersMayWrite(fi fs.FileInfo, uid int, private func(gid uint32, uid int) bool, acl aclState) int {
	perm := fi.Mode().Perm()
	switch {
	case perm&0o002 != 0:
		return writeMode
	case perm&0o020 == 0:
		return writeNone
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || acl == aclUnknown || !private(st.Gid, uid) {
		return writeMode
	}
	if acl == hasACL {
		return writeACL
	}
	return writeNone
}

// maxPlaceLinks is the most symlinks placeExposure follows from a path, as
// the kernel's own limit on a path's links.
const maxPlaceLinks = 40

// placeExposure says whether another local user could have put the file at
// path, which was opened as the file whose status is fi, in its place, as
// ssh's StrictModes checks for authorized_keys. The directory holding it
// must be owned by this user or root, and others may not write to it (see
// othersMayWrite), unless it is sticky, as /tmp is, where others may add
// names but not replace this user's or root's; a symlink at the path must be
// owned by this user or root, who chose where it leads, and the same holds
// for each link it leads through, and for the directory holding each of
// them, up to the file itself, which must be the one that was opened. So a
// Kubernetes Secret or projected volume passes: its directory, a tmpfs, is
// root's and sticky, and its ..data and per-key links are root's; a
// ConfigMap volume's directory is root's but others may write it and it is
// not sticky, so a file there is refused. Directories above the one that
// holds a name are not looked at, nor how the name came to be: in a sticky
// directory, another user who may hard-link others' files (on macOS, the
// BSDs, or Linux with fs.protected_hardlinks=0) can have made the name first
// as a second name of a file of root's or this user's.
func placeExposure(path string, fi fs.FileInfo, words fileWords) (*secretFileError, error) {
	return placeProblem(path, fi, os.Getuid(), privateGroup, pathACL, words)
}

// placeProblem is placeExposure for the user uid, with private and acl
// telling the group write bits of directories (see othersMayWrite).
func placeProblem(path string, fi fs.FileInfo, uid int, private func(gid uint32, uid int) bool, acl func(string) aclState, words fileWords) (*secretFileError, error) {
	hop := path // the name being looked at: path, or where its links lead
	where := func() string {
		if hop == path {
			return "it"
		}
		return "it leads to " + hop + ", which"
	}
	for links := 0; ; links++ {
		dir, _ := splitUploadPath(hop)
		dfi, err := os.Stat(dir)
		if err != nil {
			return nil, err
		}
		shown := func() string { // dir as messages name it: where it is, links resolved
			if real, err := filepath.EvalSymlinks(dir); err == nil {
				if abs, err := filepath.Abs(real); err == nil {
					return abs
				}
			}
			return dir
		}
		dst, ok := dfi.Sys().(*syscall.Stat_t)
		if ok && int(dst.Uid) != uid && dst.Uid != 0 {
			return &secretFileError{path: path,
				problem: fmt.Sprintf("%s is in %s, a directory uid %d owns, not this user (uid %d) or root, who could put another file in its place", where(), shown(), dst.Uid, uid),
				fix:     words.exposed + "keep it in a directory only you and root can change"}, nil
		}
		if dfi.Mode()&fs.ModeSticky == 0 {
			var problem string
			switch othersMayWrite(dfi, uid, private, acl(dir)) {
			case writeMode:
				problem = fmt.Sprintf("%s is in %s, a directory whose permissions %04o let other users put another file in its place", where(), shown(), dfi.Mode().Perm())
			case writeACL:
				problem = fmt.Sprintf("%s is in %s, a directory whose ACL lets other users put another file in its place (the group bits of its permissions %04o are the ACL's mask)", where(), shown(), dfi.Mode().Perm())
			}
			if problem != "" {
				fix := words.exposed + "keep it in a directory only you and root can change"
				if ok && int(dst.Uid) == uid {
					fix += ", or stop others changing that one: chmod go-w " + ShellQuote(shown())
				}
				return &secretFileError{path: path, problem: problem, fix: fix}, nil
			}
		}
		lfi, err := os.Lstat(hop)
		if err != nil {
			return nil, err
		}
		if lfi.Mode()&fs.ModeSymlink == 0 {
			if !os.SameFile(lfi, fi) {
				return nil, fmt.Errorf("%s: the path changed while it was being opened", path)
			}
			return nil, nil
		}
		if lst, ok := lfi.Sys().(*syscall.Stat_t); ok && int(lst.Uid) != uid && lst.Uid != 0 {
			return &secretFileError{path: path,
				problem: fmt.Sprintf("%s is a symlink uid %d made, not this user (uid %d) or root, who chose where it leads", where(), lst.Uid, uid),
				fix:     "unless you made the link yourself, delete it and write the file in its place as this user"}, nil
		}
		if links == maxPlaceLinks {
			return nil, fmt.Errorf("%s: more than %d symlinks", path, maxPlaceLinks)
		}
		target, err := os.Readlink(hop)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(target, "/") {
			// From the link's directory as named, uncleaned, so a ".." in
			// it climbs from where that directory is, as the kernel
			// resolves it.
			target = strings.TrimSuffix(dir, "/") + "/" + target
		}
		hop = target
	}
}

// The account files privateGroup reads; tests point them elsewhere.
var passwdFile, groupFile = "/etc/passwd", "/etc/group"

// privateGroup reports whether gid is the private group of the user uid, as
// systems that give each user a group of their own make it: the user's
// primary group in passwdFile and no other account's, named as the user in
// groupFile, and with no other member listed there. A group or user known
// only to a directory service, so not found in these files, is not.
func privateGroup(gid uint32, uid int) bool {
	user, private := "", true
	err := eachRecord(passwdFile, func(f []string) {
		if len(f) < 4 {
			return
		}
		if g, err := strconv.ParseUint(f[3], 10, 32); err != nil || uint32(g) != gid {
			return
		}
		if u, err := strconv.Atoi(f[2]); err == nil && u == uid {
			user = f[0]
		} else {
			private = false // another account's primary group
		}
	})
	if err != nil || user == "" || !private {
		return false
	}
	named := false
	err = eachRecord(groupFile, func(f []string) {
		if len(f) < 4 {
			return
		}
		if g, err := strconv.ParseUint(f[2], 10, 32); err != nil || uint32(g) != gid {
			return
		}
		named = named || f[0] == user
		private = private && f[0] == user
		for _, m := range strings.Split(f[3], ",") {
			private = private && (m == "" || m == user)
		}
	})
	return err == nil && named && private
}

// eachRecord calls fn with the colon-separated fields of each line of the
// account file at path, comments and blank lines skipped.
func eachRecord(path string, fn func([]string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if line := sc.Text(); line != "" && !strings.HasPrefix(line, "#") {
			fn(strings.Split(line, ":"))
		}
	}
	return sc.Err()
}
