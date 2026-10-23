// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// process is an exec'd command running in a job object of its own. Windows
// has no process groups, and killing the command's own process would leave
// what it started running, such as the program a cmd /c line runs; killing
// the job kills them all. The job is set to kill what is still in it when
// its last handle closes, so the agent dying ends its commands too.
type process struct {
	cmd    *exec.Cmd
	handle windows.Handle // the command's process, to wait for its exit

	mu     sync.Mutex
	job    windows.Handle
	closed bool // the command has ended and job is closed
}

// startCommand starts cmd in a new job object. The process is created
// suspended and only resumed once it is in the job, so it cannot start a
// child outside the job first.
func startCommand(cmd *exec.Cmd) (*process, error) {
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	p := &process{cmd: cmd, job: job}
	if err := p.enterJob(); err != nil {
		// Never run a command that cannot be killed: this one was created
		// suspended and is not in the job, or did not resume.
		cmd.Process.Kill()
		cmd.Wait()
		if p.handle != 0 {
			windows.CloseHandle(p.handle)
		}
		windows.CloseHandle(job)
		return nil, err
	}
	return p, nil
}

// newKillOnCloseJob creates a job object that kills the processes still in
// it when its last handle closes, so they end with ternd however it exits.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("set up job object: %w", err)
	}
	return job, nil
}

// enterJob puts the suspended process in the job, then lets it run.
func (p *process) enterJob() error {
	// os/exec keeps its own handle to the process until Wait, so its pid
	// cannot name another process yet and opening it by pid is safe.
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, uint32(p.cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open the new process: %w", err)
	}
	p.handle = h
	if err := windows.AssignProcessToJobObject(p.job, h); err != nil {
		return fmt.Errorf("put the new process in a job object: %w", err)
	}
	return resumeProcess(uint32(p.cmd.Process.Pid))
}

// resumeProcess resumes the threads of a process created suspended: os/exec
// closes the handle to its first thread, so they are found by process id.
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("list the new process's threads: %w", err)
	}
	defer windows.CloseHandle(snap)
	te := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, oerr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if oerr != nil {
			return fmt.Errorf("open the new process's thread: %w", oerr)
		}
		_, rerr := windows.ResumeThread(th)
		windows.CloseHandle(th)
		if rerr != nil {
			return fmt.Errorf("resume the new process: %w", rerr)
		}
		resumed++
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("list the new process's threads: %w", err)
	}
	if resumed == 0 {
		return errors.New("resume the new process: it has no thread")
	}
	return nil
}

// kill kills every process in the command's job.
func (p *process) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		windows.TerminateJobObject(p.job, 1)
	}
}

// wait waits for the command's process to exit, kills what is left in its
// job, so the command's background processes do not outlive it, and reaps
// the process, returning what cmd.Wait does. Call it once the command's
// output has ended.
func (p *process) wait() error {
	windows.WaitForSingleObject(p.handle, windows.INFINITE)
	p.mu.Lock()
	windows.TerminateJobObject(p.job, 1)
	windows.CloseHandle(p.job)
	p.closed = true
	p.mu.Unlock()
	windows.CloseHandle(p.handle)
	return p.cmd.Wait()
}
