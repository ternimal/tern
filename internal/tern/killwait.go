// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"sync"
	"time"
)

// killPasses holds the kill passes under way (see killSession), which stop
// a command's processes before they kill them: one cut short by ternd
// exiting would leave the processes it stopped stopped for good. So ternd
// lets them end before it exits, and kills what one still under way when it
// will wait no longer has stopped (see WaitKills).
var killPasses struct {
	sync.Mutex
	under  map[*killPass]struct{} // the passes under way
	idle   chan struct{}          // closed when the last pass under way ends
	closed bool                   // set by WaitKills: no pass begins, or stops a process, any more
}

// killPass is one kill pass: the processes it has stopped, each by pid with
// the start time that names it, and how it kills one.
type killPass struct {
	stopped map[int]uint64 // written under killPasses' lock
	kill    func(pid int, start uint64)
}

// beginKill registers a kill pass about to begin, which kills a process it
// stopped with kill, or returns nil once ternd is exiting: a pass begun then
// could be cut short, while a command whose pass never begins is only left
// running, as any command is when ternd exits (its process group is still
// killed; see process.kill).
func beginKill(kill func(pid int, start uint64)) *killPass {
	killPasses.Lock()
	defer killPasses.Unlock()
	if killPasses.closed {
		return nil
	}
	if len(killPasses.under) == 0 {
		killPasses.under = map[*killPass]struct{}{}
		killPasses.idle = make(chan struct{})
	}
	p := &killPass{stopped: map[int]uint64{}, kill: kill}
	killPasses.under[p] = struct{}{}
	return p
}

// stopping records that p is about to stop pid, which started at start, and
// reports whether it may. Once WaitKills has given up waiting, it records
// nothing more and says no: p must stop nothing more, and WaitKills kills
// what p recorded before.
func (p *killPass) stopping(pid int, start uint64) bool {
	killPasses.Lock()
	defer killPasses.Unlock()
	if killPasses.closed {
		return false
	}
	p.stopped[pid] = start
	return true
}

// end kills every process p stopped, and then registers that p has ended.
func (p *killPass) end() {
	for pid, start := range p.stopped {
		p.kill(pid, start)
	}
	killPasses.Lock()
	defer killPasses.Unlock()
	delete(killPasses.under, p)
	if len(killPasses.under) == 0 {
		close(killPasses.idle)
	}
}

// waitKills waits up to d for a moment with no kill pass under way, and
// then, if closing, lets no new pass begin. If closing and passes are still
// under way, they stop nothing more, and it kills every process they have
// stopped, so none is left stopped once the process exits. It reports
// whether that moment came; closing happens either way.
func waitKills(d time.Duration, closing bool) bool {
	deadline := time.Now().Add(d)
	for {
		killPasses.Lock()
		idle, busy := killPasses.idle, len(killPasses.under) > 0
		if !busy || time.Now().After(deadline) {
			type stoppedBy struct {
				p     *killPass
				pid   int
				start uint64
			}
			var left []stoppedBy
			if closing {
				killPasses.closed = true
				for p := range killPasses.under {
					for pid, start := range p.stopped {
						left = append(left, stoppedBy{p, pid, start})
					}
				}
			}
			killPasses.Unlock()
			for _, s := range left {
				s.p.kill(s.pid, s.start)
			}
			return !busy
		}
		killPasses.Unlock()
		t := time.NewTimer(time.Until(deadline))
		select {
		case <-idle:
		case <-t.C:
		}
		t.Stop()
	}
}

// WaitKills waits up to d for the kill passes under way to end, and lets no
// new one begin, so none is cut short in the middle by the process exiting;
// what one still under way after d has stopped, it kills. ternd calls it as
// it shuts down. It reports whether the passes ended.
func WaitKills(d time.Duration) bool { return waitKills(d, true) }
