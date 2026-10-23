// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/unix"
)

// pollableMaster returns a second descriptor for p's master side that reads
// and writes through the runtime's poller, or nil to use p as it is. The
// master go-pty opens is in blocking mode, where closing it interrupts no
// read or write under way: a write waiting for a program that reads none of
// its input then never returns, not even once the terminal is closed, and
// holds an OS thread for good. Closing this one ends the wait at once.
//
// Non-blocking is a mode of the open file both descriptors share, so p's own
// must no longer be read or written; go-pty still sizes and closes it.
func pollableMaster(p pty.Pty) (*os.File, error) {
	up, ok := p.(pty.UnixPty)
	if !ok {
		return nil, nil
	}
	fd, derr := -1, error(nil)
	if err := up.Control(func(m uintptr) { fd, derr = unix.FcntlInt(m, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return nil, err
	}
	if derr != nil {
		return nil, derr
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), up.Name()+" master"), nil
}
