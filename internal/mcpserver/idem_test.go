// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdempotency(t *testing.T) {
	c := newIdemCache()
	ctx := context.Background()
	var runs atomic.Int32
	fn := func() (any, error) { runs.Add(1); return "result", nil }

	if _, _, found := c.replay(ctx, "k1", "A"); found {
		t.Fatal("nothing stored yet")
	}
	if out, err := c.do(ctx, "k1", "A", fn); out != "result" || err != nil {
		t.Fatalf("first run = %v %v", out, err)
	}
	// A retry with the same key and action gets the stored result.
	if out, err, found := c.replay(ctx, "k1", "A"); !found || out != "result" || err != nil {
		t.Fatalf("replay = %v %v %v", out, err, found)
	}
	if out, _ := c.do(ctx, "k1", "A", fn); out != "result" || runs.Load() != 1 {
		t.Fatalf("do on a stored key must not run again: runs=%d", runs.Load())
	}
	// The same key for a different action is refused.
	if _, err, found := c.replay(ctx, "k1", "B"); !found || !errors.Is(err, errIdemMismatch) {
		t.Fatalf("mismatched replay = %v %v", err, found)
	}
	if _, err := c.do(ctx, "k1", "B", fn); !errors.Is(err, errIdemMismatch) || runs.Load() != 1 {
		t.Fatalf("mismatched do = %v runs=%d", err, runs.Load())
	}
	// Errors are stored too: a retry after a failure that may have half
	// happened does not run it again.
	boom := errors.New("connection lost after the command started")
	c.do(ctx, "k2", "A", func() (any, error) { return nil, boom })
	if _, err, _ := c.replay(ctx, "k2", "A"); !errors.Is(err, boom) {
		t.Fatalf("stored error = %v", err)
	}
	// Entries expire.
	c.now = func() time.Time { return time.Now().Add(idemTTL + time.Second) }
	if _, _, found := c.replay(ctx, "k1", "A"); found {
		t.Fatal("an expired entry must not replay")
	}
}

// TestIdempotencyConcurrent re-sends a call while the first is still running:
// it must wait and share the one result, not run a second time.
func TestIdempotencyConcurrent(t *testing.T) {
	c := newIdemCache()
	ctx := context.Background()
	var runs atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{})
	slow := func() (any, error) {
		runs.Add(1)
		close(started)
		<-release
		return "slow result", nil
	}
	var wg sync.WaitGroup
	results := make([]any, 3)
	wg.Add(1)
	go func() { defer wg.Done(); results[0], _ = c.do(ctx, "k", "A", slow) }()
	<-started
	wg.Add(2)
	go func() { defer wg.Done(); results[1], _ = c.do(ctx, "k", "A", slow) }()
	go func() { defer wg.Done(); results[2], _, _ = c.replay(ctx, "k", "A") }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if runs.Load() != 1 {
		t.Fatalf("ran %d times, want 1", runs.Load())
	}
	for i, r := range results {
		if r != "slow result" {
			t.Fatalf("caller %d got %v", i, r)
		}
	}
}

// TestIdempotencyAbandoned checks that a call that failed before it acted, or
// that its caller cancelled, is not replayed: a retry with the same key runs.
func TestIdempotencyAbandoned(t *testing.T) {
	c := newIdemCache()
	ctx := context.Background()
	var runs atomic.Int32
	ok := func() (any, error) { runs.Add(1); return "ran", nil }

	unreachable := beforeStart(errors.New("connect to web: connection refused"))
	if _, err := c.do(ctx, "k1", "A", func() (any, error) { return nil, unreachable }); err == nil || err.Error() != "connect to web: connection refused" {
		t.Fatalf("the failure must reach the caller unchanged: %v", err)
	}
	if _, _, found := c.replay(ctx, "k1", "A"); found {
		t.Fatal("a call that never started must not be replayed")
	}
	if out, _ := c.do(ctx, "k1", "A", ok); out != "ran" || runs.Load() != 1 {
		t.Fatalf("the retry must run: %v runs=%d", out, runs.Load())
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	c.do(cctx, "k2", "A", func() (any, error) { return nil, cctx.Err() })
	if _, _, found := c.replay(ctx, "k2", "A"); found {
		t.Fatal("a cancelled call must not be replayed")
	}
	// A result that arrived although the caller has gone is still stored.
	c.do(cctx, "k3", "A", ok)
	if out, _, found := c.replay(ctx, "k3", "A"); !found || out != "ran" {
		t.Fatalf("a finished call must be stored even if its caller cancelled: %v %v", out, found)
	}

	// A duplicate waiting on a call that is then abandoned runs it itself.
	release, started := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := c.do(ctx, "k4", "A", func() (any, error) {
			close(started)
			<-release
			return nil, beforeStart(errors.New("refused"))
		})
		first <- err
	}()
	<-started
	second := make(chan any, 1)
	go func() { out, _ := c.do(ctx, "k4", "A", ok); second <- out }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	if err := <-first; err == nil {
		t.Fatal("the first call should have failed")
	}
	if out := <-second; out != "ran" {
		t.Fatalf("the waiting duplicate should have run the call: %v", out)
	}
}
