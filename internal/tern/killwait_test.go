// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"sync"
	"testing"
	"time"
)

// reopenKills lets kill passes begin again after a test's closing wait.
func reopenKills(t *testing.T) {
	t.Cleanup(func() {
		killPasses.Lock()
		killPasses.closed = false
		killPasses.Unlock()
	})
}

func noKill(int, uint64) {}

// Shutting down, ternd waits for a kill pass under way to end, up to a
// bound, and then lets no new pass begin, so none is cut short between
// stopping a command's processes and killing them.
func TestWaitKills(t *testing.T) {
	if !waitKills(time.Second, false) {
		t.Fatal("a wait with no kill under way did not end at once")
	}
	p := beginKill(noKill)
	if p == nil {
		t.Fatal("a kill pass did not begin")
	}
	ended := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(ended)
		p.end()
	}()
	if !waitKills(5*time.Second, false) {
		t.Error("the wait gave up on a pass that ended")
	}
	select {
	case <-ended:
	default:
		t.Error("the wait ended while a pass was under way")
	}

	p = beginKill(noKill)
	if p == nil {
		t.Fatal("a kill pass did not begin")
	}
	if waitKills(50*time.Millisecond, false) {
		t.Error("a wait for a pass that does not end did not give up")
	}
	p.end()

	reopenKills(t)
	if !waitKills(time.Second, true) {
		t.Error("the closing wait gave up with no kill under way")
	}
	if p := beginKill(noKill); p != nil {
		p.end()
		t.Error("a kill pass began after ternd's shutdown wait")
	}
}

// A closing wait that gives up on a pass still under way kills every
// process the pass has stopped, so ternd exiting leaves none stopped, and
// the pass stops nothing more.
func TestClosingWaitKillsWhatAPassStopped(t *testing.T) {
	var mu sync.Mutex
	killed := map[int]uint64{}
	p := beginKill(func(pid int, start uint64) {
		mu.Lock()
		killed[pid] = start
		mu.Unlock()
	})
	if p == nil {
		t.Fatal("a kill pass did not begin")
	}
	for pid := 100; pid < 103; pid++ {
		if !p.stopping(pid, uint64(pid)*10) {
			t.Fatal("a pass under way may not stop a process")
		}
	}
	reopenKills(t)
	if waitKills(50*time.Millisecond, true) {
		t.Error("the closing wait did not give up on a pass that does not end")
	}
	mu.Lock()
	if len(killed) != 3 || killed[100] != 1000 || killed[101] != 1010 || killed[102] != 1020 {
		t.Errorf("the closing wait killed %v; want the 3 processes the pass stopped", killed)
	}
	mu.Unlock()
	if p.stopping(200, 2000) {
		t.Error("a pass may still stop a process after the closing wait gave up")
	}
	p.end() // the pass ends late: it kills what it stopped again
	if !waitKills(time.Second, false) {
		t.Error("a pass that ended is still counted")
	}
}
