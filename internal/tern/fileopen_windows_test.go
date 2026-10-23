// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// A download of a path that leads to a named pipe, as a link or junction
// another user swaps in may make it, is refused as not a regular file, and
// the pipe's server, even one with the impersonation privilege a service
// account has, can neither act as the agent nor see whose it is.
func TestWindowsDownloadOfPipeGivesItsServerNothing(t *testing.T) {
	name := `\\.\pipe\tern-download-test-` + strconv.Itoa(os.Getpid())
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	type seen struct {
		level uint32
		err   error
	}
	server := make(chan seen, 1)
	go func() {
		// Impersonation belongs to the thread, which is never unlocked, so
		// it ends with this goroutine.
		runtime.LockOSThread()
		if err := windows.ConnectNamedPipe(pipe, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			server <- seen{err: err}
			return
		}
		if r, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe)); r == 0 {
			server <- seen{err: err}
			return
		}
		defer windows.RevertToSelf()
		var tok windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok); err != nil {
			server <- seen{err: err}
			return
		}
		defer tok.Close()
		var lvl, n uint32
		err := windows.GetTokenInformation(tok, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&lvl)), 4, &n)
		server <- seen{lvl, err}
	}()
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	if _, _, err := cl.ReadFile(name, 0, 64, nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a download of a named pipe: %v", err)
	}
	select {
	case s := <-server:
		if s.err == nil && s.level != windows.SecurityAnonymous {
			t.Errorf("the pipe's server got the agent's token at impersonation level %d", s.level)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the download never reached the pipe")
	}
}
