// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/windows"
)

// shellJob is the job object a terminal's shell runs in, with everything it
// starts: a program run with start or Start-Process outlives the shell
// otherwise, as Windows has no session to hang up. The job kills what is in
// it when the session ends, or when its handle closes because ternd exits.
type shellJob struct {
	job  windows.Handle
	once sync.Once
}

// prepareShell has the shell created suspended, so it starts nothing before
// it is in its job.
func prepareShell(c *pty.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
}

// containShell puts the suspended shell c started in a new job, then lets it
// run. On error the shell is still suspended, and the caller kills it.
func containShell(c *pty.Cmd) (*shellJob, error) {
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, err
	}
	// c.Process holds a handle to the shell until Wait, so its pid cannot
	// name another process yet.
	pid := uint32(c.Process.Pid)
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("open the shell process: %w", err)
	}
	err = windows.AssignProcessToJobObject(job, h)
	windows.CloseHandle(h)
	if err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("put the shell in a job object: %w", err)
	}
	if err := resumeProcess(pid); err != nil {
		windows.TerminateJobObject(job, 1)
		windows.CloseHandle(job)
		return nil, err
	}
	return &shellJob{job: job}, nil
}

// end kills the shell and everything it started that is still running.
func (j *shellJob) end() {
	if j == nil {
		return
	}
	j.once.Do(func() {
		windows.TerminateJobObject(j.job, 1)
		windows.CloseHandle(j.job)
	})
}
