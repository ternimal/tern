// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// aclXattr is where Linux keeps a file's POSIX access ACL. A file has it only
// while its ACL holds more than its mode says: setting an ACL the mode can
// express removes it.
const aclXattr = "system.posix_acl_access"

// fdACL says whether the file or directory open as fd, other than with
// O_PATH, which the xattr calls refuse, has an ACL with entries beyond its
// mode, read through the descriptor, so the answer is about that very file.
func fdACL(fd int) aclState {
	return aclOf(func() error { _, err := unix.Fgetxattr(fd, aclXattr, nil); return err },
		func(st *unix.Statfs_t) error { return unix.Fstatfs(fd, st) })
}

// fileACL is fdACL for the open file f.
func fileACL(f *os.File) aclState {
	rc, err := f.SyscallConn()
	if err != nil {
		return aclUnknown
	}
	state := aclUnknown
	if err := rc.Control(func(fd uintptr) { state = fdACL(int(fd)) }); err != nil {
		return aclUnknown
	}
	return state
}

// pathACL is fdACL for the directory at path, looked up by name, which
// needs no permission to read the directory.
func pathACL(path string) aclState {
	return aclOf(func() error { _, err := unix.Getxattr(path, aclXattr, nil); return err },
		func(st *unix.Statfs_t) error { return unix.Statfs(path, st) })
}

// aclOf reads the answer of get, a look for the ACL attribute: none there is
// no ACL, the attribute there is one. A file system that keeps no ACLs, as
// ZFS by default, minix or FAT, says it does not support the look, and then
// the mode says all there is, unless statfs, which looks at the file
// system, finds one whose server may keep ACLs of its own that the mode
// need not show (see serverKeepsACLs). A look that failed otherwise, or a
// statfs that failed, does not tell.
func aclOf(get func() error, statfs func(*unix.Statfs_t) error) aclState {
	switch err := ignoringEINTR(get); {
	case err == nil:
		return hasACL
	case errors.Is(err, unix.ENODATA):
		return noACL
	case errors.Is(err, unix.EOPNOTSUPP):
		var st unix.Statfs_t
		if ignoringEINTR(func() error { return statfs(&st) }) == nil && !serverKeepsACLs(uint32(st.Type)) {
			return noACL
		}
	}
	return aclUnknown
}

// serverKeepsACLs reports whether the file system whose statfs type is
// magic is one whose server decides who may change a file by ACLs it may
// keep beyond the mode: NFS, whose version 4 ACLs are no POSIX ACLs, SMB
// (CIFS), whose server keeps Windows ACLs, and AFS, whose directories keep
// ACLs of their own.
func serverKeepsACLs(magic uint32) bool {
	switch magic {
	case unix.NFS_SUPER_MAGIC, unix.SMB_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC,
		unix.AFS_SUPER_MAGIC, unix.AFS_FS_MAGIC:
		return true
	}
	return false
}
