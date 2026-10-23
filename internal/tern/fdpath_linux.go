// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// dirOpenFlags open a directory to work in by descriptor. O_PATH needs no
// read permission on it, so a directory others may write into but not list
// still takes uploads.
const dirOpenFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC

// fdPath returns the path the kernel reports for the open descriptor fd:
// where the file it names is now, whatever name it was opened by.
func fdPath(fd int) (string, error) {
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
}
