// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// When the agent runs as process 1, as the entry point of a container
// without an init does, the processes its commands leave behind are handed
// to it as their parents end, and stay zombies unless it reaps them. Its own
// children, commands and shells, it reaps itself as they end; the reaper
// started by reapsOrphans takes the rest. Every child is started through
// startChild, which keeps the reaper from ever taking one of them for an
// orphan: their exit statuses belong to the code that waits for them.
var orphans struct {
	gate sync.RWMutex // read-held while a child starts, write-held while orphans are reaped
	mu   sync.Mutex
	kids map[int]int // pid -> children with that pid this process waits for itself
}

// orphanReapInterval is how often the reaper looks for orphans without a
// SIGCHLD saying one may have ended.
const orphanReapInterval = time.Minute

// startChild runs start, which starts one child process and returns its
// pid. Call the returned done once that child has been reaped.
func startChild(start func() (int, error)) (done func(), err error) {
	if !reapsOrphans() {
		if _, err := start(); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	orphans.gate.RLock()
	pid, err := start()
	if err == nil {
		orphans.mu.Lock()
		orphans.kids[pid]++
		orphans.mu.Unlock()
	}
	orphans.gate.RUnlock()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			orphans.mu.Lock()
			if orphans.kids[pid]--; orphans.kids[pid] <= 0 {
				delete(orphans.kids, pid)
			}
			orphans.mu.Unlock()
		})
	}, nil
}

// reapsOrphans reports whether this process reaps orphans, starting the
// reaper the first time it says so: it must be process 1, and /proc must be
// that of its own PID namespace, where the zombies are found.
var reapsOrphans = sync.OnceValue(func() bool {
	if os.Getpid() != 1 {
		return false
	}
	if self, err := os.Readlink("/proc/self"); err != nil || self != "1" {
		slog.Warn("running as process 1 without a /proc of this PID namespace: processes that commands leave behind are not reaped")
		return false
	}
	orphans.kids = map[int]int{}
	go reapOrphans()
	return true
})

// reapOrphans reaps orphans whenever a child may have ended, and every
// orphanReapInterval.
func reapOrphans() {
	ended := make(chan os.Signal, 1)
	signal.Notify(ended, unix.SIGCHLD)
	tick := time.NewTicker(orphanReapInterval)
	defer tick.Stop()
	for {
		reapOrphansOnce()
		select {
		case <-ended:
		case <-tick.C:
		}
	}
}

// reapOrphansOnce reaps every zombie child of this process that is not one
// of the children it started itself.
func reapOrphansOnce() {
	orphans.gate.Lock()
	defer orphans.gate.Unlock()
	procs, err := readProcs()
	if err != nil {
		return
	}
	for pid, pr := range procs {
		if pr.ppid != 1 || pr.state != 'Z' {
			continue
		}
		orphans.mu.Lock()
		_, mine := orphans.kids[pid]
		orphans.mu.Unlock()
		if !mine {
			var ws unix.WaitStatus
			unix.Wait4(pid, &ws, unix.WNOHANG, nil)
		}
	}
}
