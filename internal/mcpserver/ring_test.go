// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRingBuffer(t *testing.T) {
	r := newRingBuffer(8)
	r.Write([]byte("hello"))
	data, next, dropped := r.Read(0, 100)
	if string(data) != "hello" || next != 5 || dropped != 0 {
		t.Fatalf("read = %q %d %d", data, next, dropped)
	}
	// A reader resumes at its offset and sees only new bytes.
	r.Write([]byte(" world")) // 11 bytes written, cap 8: "hel" dropped
	data, next, dropped = r.Read(5, 100)
	if string(data) != " world" || next != 11 || dropped != 0 {
		t.Fatalf("resume = %q %d %d", data, next, dropped)
	}
	// A reader that fell behind the cap learns how much it missed.
	data, next, dropped = r.Read(0, 100)
	if string(data) != "lo world" || next != 11 || dropped != 3 {
		t.Fatalf("behind = %q %d %d", data, next, dropped)
	}
	// max bounds one read; an offset past the end is clamped.
	if data, next, _ = r.Read(3, 2); string(data) != "lo" || next != 5 {
		t.Fatalf("bounded = %q %d", data, next)
	}
	if data, next, _ = r.Read(99, 10); len(data) != 0 || next != 11 {
		t.Fatalf("past end = %q %d", data, next)
	}
	if end, closed := r.End(); end != 11 || closed {
		t.Fatalf("End = %d %v", end, closed)
	}
	r.Close()
	r.Write([]byte("ignored"))
	if end, closed := r.End(); end != 11 || !closed {
		t.Fatalf("after Close: End = %d %v", end, closed)
	}
}

// A closed buffer, as of a finished job or an ended terminal, holds the
// bytes readers can still see and no room for more.
func TestRingCloseShrinks(t *testing.T) {
	r := newRingBuffer(1 << 10)
	r.Write([]byte(strings.Repeat("x", 1900))) // kept as 1900 bytes until twice the cap
	r.Close()
	if len(r.buf) != 1<<10 || cap(r.buf) > 1<<10+64 {
		t.Errorf("a closed buffer holds %d bytes in %d", len(r.buf), cap(r.buf))
	}
	if data, next, dropped := r.Read(0, 4096); len(data) != 1<<10 || next != 1900 || dropped != 1900-1<<10 {
		t.Errorf("read after Close = %d bytes, next %d, dropped %d", len(data), next, dropped)
	}
	if before, after := r.Around(1000, 1500, 100); string(before) != strings.Repeat("x", 100) || string(after) != strings.Repeat("x", 100) {
		t.Errorf("Around after Close = %q, %q", before, after)
	}
}

func TestRingBufferWait(t *testing.T) {
	r := newRingBuffer(64)
	var wg sync.WaitGroup
	woke := make(chan time.Duration, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		r.Wait(context.Background(), 0)
		woke <- time.Since(start)
	}()
	time.Sleep(50 * time.Millisecond)
	r.Write([]byte("x"))
	wg.Wait()
	if d := <-woke; d < 40*time.Millisecond {
		t.Fatalf("Wait returned before data arrived (%v)", d)
	}
	// Close wakes a waiter that would otherwise wait for more data.
	done := make(chan struct{})
	go func() { r.Wait(context.Background(), 1); close(done) }()
	r.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the waiter")
	}
	// A cancelled context ends the wait.
	r2 := newRingBuffer(8)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r2.Wait(ctx, 0)
	if ctx.Err() == nil {
		t.Fatal("Wait returned before the context ended")
	}
}
