// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package tern

import "syscall"

// fdLimit is the process's limit on open file descriptors, which Go raises to
// the hard limit at start, or 0 when it cannot be read.
func fdLimit() uint64 {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0
	}
	return uint64(r.Cur)
}
