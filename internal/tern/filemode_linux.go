// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import "golang.org/x/sys/unix"

// carriesACL reports whether the open directory dir has an access ACL, or
// may have one: the kernel keeps one only when it lists more than the
// owner, group and others, and then shows its mask as the group bits. dir
// is open with O_PATH, which the xattr calls refuse, so the directory is
// opened again through it, by its "." entry, the same directory whatever
// names change meanwhile. One that cannot be opened so, or whose file system
// cannot say, counts as having one.
func carriesACL(dir int) bool {
	var fd int
	err := ignoringEINTR(func() (err error) {
		fd, err = unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		return err
	})
	if err != nil {
		return true
	}
	defer unix.Close(fd)
	return fdACL(fd) != noACL
}
