// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedBySelf reports whether the file described by fi, the Lstat of path, is
// owned by the current user, so that a TLS key a local attacker may have
// planted is not loaded.
func ownedBySelf(_ string, fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Getuid()
}

// umask is the file mode creation mask, read once at start: reading it means
// setting it, which is only safe before anything else creates files.
var umask = func() os.FileMode {
	m := syscall.Umask(0)
	syscall.Umask(m)
	return os.FileMode(m)
}()

// createOwnerOnly creates path, which must not exist yet, with mode 0600.
func createOwnerOnly(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|flag, 0o600)
}

// restrictToOwner sets mode 0600 on a regular file of ours that is open to
// others.
func restrictToOwner(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || !ownedBySelf(path, fi) || fi.Mode().Perm()&0o077 == 0 {
		return err
	}
	return os.Chmod(path, 0o600)
}
