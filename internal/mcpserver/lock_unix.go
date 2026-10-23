// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package mcpserver

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive lock on f without waiting. Closing f, or the
// process ending, releases it.
func lockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
