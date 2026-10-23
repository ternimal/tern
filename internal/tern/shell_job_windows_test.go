// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// childNamed opens the running child of process parent whose program is
// named exe, or returns 0 if there is none yet.
func childNamed(t *testing.T, parent uint32, exe string) windows.Handle {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snap)
	pe := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ParentProcessID != parent || !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), exe) {
			continue
		}
		h, oerr := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, pe.ProcessID)
		if oerr == nil {
			return h
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		t.Fatal(err)
	}
	return 0
}

// A terminal's shell runs in a job object with everything it starts, so
// ending the session also ends a program the shell left running, as one
// started with start does, which would outlive the shell and ternd
// otherwise.
func TestWindowsShellChildrenEndWithSession(t *testing.T) {
	if os.Getenv("TERN_E2E_PTY") == "" {
		t.Skip("needs ConPTY from a real console; set TERN_E2E_PTY=1 there to run it")
	}
	sh, err := spawnShell(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	go io.Copy(io.Discard, sh) // keep the console's output flowing
	shellPID := uint32(sh.(*ptySession).cmd.Process.Pid)
	if _, err := sh.Write([]byte("start \"\" ping -n 300 127.0.0.1\r\n")); err != nil {
		t.Fatal(err)
	}
	var child windows.Handle
	for deadline := time.Now().Add(20 * time.Second); child == 0 && time.Now().Before(deadline); {
		if child = childNamed(t, shellPID, "PING.EXE"); child == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if child == 0 {
		t.Fatal("the shell never started ping")
	}
	defer windows.CloseHandle(child)
	defer windows.TerminateProcess(child, 1) // if it outlived the session

	sh.Close()
	if ev, err := windows.WaitForSingleObject(child, 10_000); err != nil || ev != windows.WAIT_OBJECT_0 {
		t.Errorf("a program the shell started outlived the ended session (wait: %d, %v)", ev, err)
	}
}
