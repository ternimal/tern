// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || freebsd

package mcpserver

import "golang.org/x/sys/unix"

// systemMounts lists the mounted file systems' mount points as the kernel
// has them cached (MNT_NOWAIT), without asking any of them, so a dead network
// mount is listed like any other.
func systemMounts() []string {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]unix.Statfs_t, n+8) // room for mounts made in between
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil
	}
	out := make([]string, 0, n)
	for _, m := range buf[:n] {
		out = append(out, unix.ByteSliceToString(m.Mntonname[:]))
	}
	return out
}
