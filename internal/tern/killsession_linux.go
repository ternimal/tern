// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"

	"golang.org/x/sys/unix"
)

// killRounds bounds how many times killSession looks again for processes
// that turned up while it was stopping those it had found.
const killRounds = 16

// killSession kills, besides the command's process group, the processes the
// command started that a kill of that group misses: every process still in
// the session the command leads, whatever its process group (job control
// moves background jobs to groups of their own), and every process descended
// from the command or from one of those, such as one that started a session
// of its own. It reaches no process that left both: one that started a
// session of its own and whose parent has ended, as a daemon does, belongs
// to init then. The processes found are stopped first, round after round
// until no new one turns up, so none can fork a child out of reach while the
// others die, and then all are killed, however the pass ends: a process
// left stopped would stay so for good. ternd waits for a pass under way
// before it exits, begins none after that, and kills what one it waited for
// in vain has stopped (see WaitKills). Under a /proc of another PID
// namespace there is no pass: the numbers it lists would name unrelated
// processes here (see ownProc).
//
// Call it while the leader is unreaped: until then no other process can
// have its pid as a session id, so everything in that session is the
// command's.
func killSession(leader int) {
	if !ownProc() {
		return
	}
	p := beginKill(func(pid int, start uint64) { signalProc(pid, start, unix.SIGKILL) })
	if p == nil {
		return
	}
	defer p.end()
	self := os.Getpid()
	for range killRounds {
		procs, err := readProcs()
		if err != nil {
			return
		}
		fresh := false
		for pid, pr := range sessionTree(procs, leader) {
			if pid == self || pid == 1 {
				continue
			}
			if start, ok := p.stopped[pid]; ok && start == pr.start {
				continue
			}
			if !p.stopping(pid, pr.start) {
				return // ternd is exiting, and kills what was stopped
			}
			fresh = true
			signalProc(pid, pr.start, unix.SIGSTOP)
		}
		if !fresh {
			return
		}
	}
}

// sessionTree returns the live processes in procs that are in the session
// leader leads, or are leader itself, or descend from one of those.
func sessionTree(procs map[int]procInfo, leader int) map[int]procInfo {
	children := map[int][]int{}
	queue := []int{leader}
	for pid, pr := range procs {
		children[pr.ppid] = append(children[pr.ppid], pid)
		if pr.sid == leader && pid != leader {
			queue = append(queue, pid)
		}
	}
	tree := map[int]procInfo{}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		pr, ok := procs[pid]
		if _, seen := tree[pid]; !ok || seen {
			continue
		}
		tree[pid] = pr
		queue = append(queue, children[pid]...)
	}
	for pid, pr := range tree {
		if pr.state == 'Z' || pr.state == 'X' { // ended: nothing left to signal
			delete(tree, pid)
		}
	}
	return tree
}
