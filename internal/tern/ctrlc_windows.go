// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"log/slog"
	"sync"

	"golang.org/x/sys/windows"
)

var (
	ctrlCMu      sync.Mutex
	setCtrlCProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
)

// shellCtrlC makes the shell about to be started handle Ctrl+C, and returns
// the function to call once it has started. Whether a process ignores Ctrl+C
// is inherited from its parent, and an agent started from an SSH session or
// with "start /b" often ignores it, so every shell would too: typing Ctrl+C in
// a session could then not stop a running command. The agent clears the flag
// only while it creates the shell and then sets it back, so its own handling
// of a Ctrl+C in its console does not change.
func shellCtrlC() (restore func()) {
	ctrlCMu.Lock()
	ignoring := false
	if peb := windows.RtlGetCurrentPeb(); peb != nil && peb.ProcessParameters != nil {
		ignoring = peb.ProcessParameters.ConsoleFlags&1 != 0
	}
	if ignoring {
		if r, _, err := setCtrlCProc.Call(0, 0); r == 0 {
			slog.Warn("could not enable Ctrl+C for the shell", "err", err)
		}
	}
	return func() {
		if ignoring {
			setCtrlCProc.Call(0, 1)
		}
		ctrlCMu.Unlock()
	}
}
