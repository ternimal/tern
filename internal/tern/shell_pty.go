// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !ios

package tern

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/aymanbagabas/go-pty"
)

// ptySession adapts go-pty (linux, darwin, windows, android, *bsd) to
// shellSession. pty.Pty is itself an interface, so it is stored by value.
// Close is guarded by sync.Once so it is safe to call from both the
// process-exit watcher and the session manager.
type ptySession struct {
	pty       pty.Pty
	master    *os.File // when set, the terminal is read and written through it (see pollableMaster)
	cmd       *pty.Cmd
	cancel    context.CancelFunc
	job       *shellJob // Windows: the shell and what it started; nil elsewhere
	forget    func()    // tells the orphan reaper the shell is reaped (see startChild)
	closeOnce sync.Once
	closeErr  error
}

func (s *ptySession) Read(p []byte) (int, error) {
	if s.master != nil {
		return s.master.Read(p)
	}
	return s.pty.Read(p)
}

func (s *ptySession) Write(p []byte) (int, error) {
	if s.master != nil {
		return s.master.Write(p)
	}
	return s.pty.Write(p)
}

func (s *ptySession) Close() error {
	s.closeOnce.Do(func() {
		// Kill the shell before closing the PTY. Closing the PTY alone does not
		// reliably terminate the shell, so a session the idle reaper closes would
		// otherwise leak the process and the pump goroutine blocked on its Read.
		// On Windows the shell's job goes with it, and what it started.
		s.job.end()
		s.cancel()
		var masterErr error
		if s.master != nil {
			masterErr = s.master.Close() // ends a read or write that waits
		}
		s.closeErr = errors.Join(masterErr, s.pty.Close())
	})
	return s.closeErr
}

func (s *ptySession) Resize(cols, rows int) error { return s.pty.Resize(cols, rows) }

func (s *ptySession) Wait() error {
	defer s.forget()
	return s.cmd.Wait()
}

func spawnShell(shell string) (shellSession, error) {
	defer shellCtrlC()()
	p, err := pty.New()
	if err != nil {
		return nil, err
	}
	master, err := pollableMaster(p)
	if err != nil {
		p.Close()
		return nil, err
	}
	closePTY := func() {
		if master != nil {
			master.Close()
		}
		p.Close()
	}
	// CommandContext ties the shell's lifetime to ctx, so cancel() in Close
	// terminates it (go-pty kills the process on ctx cancellation).
	ctx, cancel := context.WithCancel(context.Background())
	c := p.CommandContext(ctx, shell)
	c.Env = childEnv() // don't expose the agent's own TERN_* secrets to the shell
	prepareShell(c)
	forget, err := startChild(func() (int, error) {
		if err := c.Start(); err != nil {
			return 0, err
		}
		return c.Process.Pid, nil
	})
	if err != nil {
		cancel()
		closePTY()
		return nil, err
	}
	job, err := containShell(c)
	if err != nil {
		// Never run a shell that cannot be ended with all it starts.
		c.Process.Kill()
		c.Wait()
		forget()
		cancel()
		closePTY()
		return nil, err
	}
	return &ptySession{pty: p, master: master, cmd: c, cancel: cancel, job: job, forget: forget}, nil
}
