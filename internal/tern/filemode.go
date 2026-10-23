// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import "os"

// newFileMode is the mode a new file written with mode want gets, as uploads
// and downloads write it: want less the umask, as open(2) would give it.
func newFileMode(want os.FileMode) os.FileMode { return want.Perm() &^ umask }

// keptMode is the mode of a file written with mode want, by renaming a new
// file into place, over a regular file with permission bits perm, which is
// ours when own is set: this user owns it and it has a single name. A file
// of ours keeps its mode, as cp leaves it, so rewriting a private file never
// widens it. Any other is narrowed to the new file's mode too: one another
// user owns, as a file planted in a shared directory is, or a second name
// of a file of ours, which another user who may add names to a directory
// can make there with a hard link to that file.
func keptMode(perm os.FileMode, own bool, want os.FileMode) os.FileMode {
	if own {
		return perm
	}
	return perm & newFileMode(want)
}
