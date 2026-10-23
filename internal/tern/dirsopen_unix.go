// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"os"
	"path/filepath"
)

// dirsOpenToAll reports whether every directory above real, an absolute path
// with its links resolved, lets every user search it (others may execute
// it). Only then can a user who is neither the file's owner nor in its group
// reach the file, whatever its own mode says: a 0644 file in a 0700
// directory, as systemd's credential store keeps them, is private. Each
// directory is looked at by name once the file is open, so only someone who
// may rename entries in a directory above it could change what is seen in
// between; anything that is not a directory reads as closed.
func dirsOpenToAll(real string) bool {
	if !filepath.IsAbs(real) {
		return false
	}
	for d := filepath.Dir(real); ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o001 == 0 {
			return false
		}
		if filepath.Dir(d) == d {
			return true
		}
	}
}
