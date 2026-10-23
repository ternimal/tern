// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"os/exec"
	"sync"
	"syscall"
)

// process is an exec'd command running in a session of its own, which makes
// it the leader of its own process group too, so the command and everything
// it starts, a `sh -c` pipeline and its background jobs, can be killed
// together (see kill), and it has no controlling terminal: it can never read
// from, write to or take over the terminal ternd itself may run on.
//
// Signals go to the group by number, and a number can be reused once the
// group's leader has been reaped and no other member is left. So the leader
// is reaped last: wait sees its exit without reaping it, and while it is a
// zombie its pid and its group's and session's id stay taken, so a kill can
// reach only the command's own processes. After the reap nothing is
// signalled by number.
type process struct {
	cmd *exec.Cmd

	mu     sync.Mutex
	reaped bool   // the leader has been (or is being) reaped: its pid is no longer ours to signal
	forget func() // tells the orphan reaper the leader is reaped (see startChild)
}

// startCommand starts cmd as the leader of a new session.
func startCommand(cmd *exec.Cmd) (*process, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	forget, err := startChild(func() (int, error) {
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		return cmd.Process.Pid, nil
	})
	if err != nil {
		return nil, err
	}
	return &process{cmd: cmd, forget: forget}, nil
}

// kill kills the command's whole process group, what else it started that
// can still be found (see killSession), and its leader should the leader
// have left the group, unless the leader has been reaped.
func (p *process) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reaped {
		return
	}
	pid := p.cmd.Process.Pid
	if noReapWaits() {
		// wait reaps the leader only after taking p.mu and saying so, so
		// it is unreaped now and its session's id is the command's alone.
		killSession(pid)
	}
	syscall.Kill(-pid, syscall.SIGKILL)
	// os.Process signals only a process it has not waited for, and on
	// Linux it signals through a pidfd, which a reused pid cannot fool.
	p.cmd.Process.Kill()
}

// wait waits for the command's leader to exit, kills what is left of its
// group and its session, so the command's background jobs do not outlive
// it, and reaps the leader, returning what cmd.Wait does. Call it once the
// command's output has ended: that is what keeps the leader unreaped while
// output flows.
func (p *process) wait() error {
	defer p.forget()
	pid := p.cmd.Process.Pid
	if waitExitNoReap(pid) {
		p.mu.Lock()
		// The leader is a zombie: the group's and session's id are still taken.
		killSession(pid)
		syscall.Kill(-pid, syscall.SIGKILL)
		p.reaped = true
		p.mu.Unlock()
		return p.cmd.Wait()
	}
	// No way to see the exit without reaping it here: reap first, and
	// leave what is left of the group alone. A kill that races with the
	// reap can still go out after it; it reaches another process only if
	// the group's id was freed and reused in that instant.
	err := p.cmd.Wait()
	p.mu.Lock()
	p.reaped = true
	p.mu.Unlock()
	return err
}
