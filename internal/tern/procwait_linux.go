// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// waitExitNoReap waits for pid, a child of this process, to exit, and leaves
// it unreaped: a zombie, whose pid and process group id no other process can
// take. It reports false if it could not wait that way (waitid is missing
// under some emulators), and the caller then just reaps.
func waitExitNoReap(pid int) bool {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != syscall.EINTR {
			return err == nil
		}
	}
}

// noReapWaits reports whether waitExitNoReap works here, so that a command's
// leader stays unreaped until its process says so: asked about a pid that is
// not its child, waitid fails with ECHILD where it does.
var noReapWaits = sync.OnceValue(func() bool {
	var info unix.Siginfo
	err := unix.Waitid(unix.P_PID, os.Getpid(), &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
	return err == unix.ECHILD
})
