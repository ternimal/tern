// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// ringBuffer keeps the most recent bytes of a stream, addressed by absolute
// offset from the start of the stream, so a reader can resume where it left
// off and learn how much it missed when old bytes were dropped. Readers can
// wait for new bytes or for the end of the stream. Jobs and terminals keep
// their output in one.
type ringBuffer struct {
	mu      sync.Mutex
	buf     []byte // bytes [start, start+len(buf)) of the stream; only the last max are kept
	start   int64
	max     int
	closed  bool
	last    time.Time     // when bytes were last written
	changed chan struct{} // closed and replaced on every write and on Close
}

func newRingBuffer(max int) *ringBuffer {
	return &ringBuffer{max: max, changed: make(chan struct{})}
}

// Write appends p, dropping the oldest bytes beyond the cap. Writing after
// Close is ignored.
func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(p) == 0 {
		return len(p), nil
	}
	r.buf = append(r.buf, p...)
	r.last = time.Now()
	// Compact only when the buffer has grown to twice the cap, so dropping
	// old bytes costs O(1) a byte instead of a copy of the cap per write.
	if over := len(r.buf) - r.max; over > 0 && len(r.buf) >= 2*r.max {
		r.buf = append(r.buf[:0], r.buf[over:]...)
		r.start += int64(over)
	}
	r.notify()
	return len(p), nil
}

// Close marks the end of the stream and wakes every waiter. Nothing more is
// written, so the buffer shrinks to the bytes readers can still see: a
// finished job or an ended terminal holds its output, not room for more.
func (r *ringBuffer) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		start, buf := r.kept()
		r.start, r.buf = start, append([]byte(nil), buf...)
		r.notify()
	}
}

func (r *ringBuffer) notify() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// Read returns up to max bytes from offset since, the offset to continue
// from, and how many bytes before the returned data were dropped because the
// reader fell behind the cap.
func (r *ringBuffer) Read(since int64, max int) (data []byte, next, dropped int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, buf := r.kept()
	end := start + int64(len(buf))
	switch {
	case since < start:
		dropped, since = start-since, start
	case since > end:
		since = end
	}
	from := int(since - start)
	to := min(len(buf), from+max)
	return append([]byte(nil), buf[from:to]...), since + int64(to-from), dropped
}

// Around returns what is still kept of the n bytes before offset from and
// the n bytes after offset to, the output around the read [from, to), to
// redact it with.
func (r *ringBuffer) Around(from, to int64, n int) (before, after []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, buf := r.kept()
	end := start + int64(len(buf))
	if b := max(from-int64(n), start); b < from && from <= end {
		before = append([]byte(nil), buf[b-start:from-start]...)
	}
	if a := min(to+int64(n), end); to < a && to >= start {
		after = append([]byte(nil), buf[to-start:a-start]...)
	}
	return before, after
}

// safeStart returns where a read of the output from offset at may start
// showing it. Once older output has been dropped, the first bytes the buffer
// still holds may continue a line whose start is gone: the value of a
// name=value pair whose name was dropped, which redaction no longer
// recognizes, or the rest of an escape sequence, glued to what follows. So
// a read starts no earlier than just after the first line break in the first
// redactCtx bytes kept, and after the lines that go on with that line, blank
// or indented ones, as a YAML value on the line after its key or the
// arguments of a call that spans lines do; or than redactCtx bytes in when
// those do not end before that, where a secret's name would be out of
// redaction's reach anyway. With nothing dropped, it is at.
func (r *ringBuffer) safeStart(at int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, buf := r.kept()
	if start == 0 || at >= start+redactCtx {
		return at
	}
	safe := start + redactCtx
	head := buf[:min(len(buf), redactCtx)]
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		if j := continued(head, i+1); j < len(head) {
			safe = start + int64(j)
		}
	}
	return max(at, safe)
}

// continued returns where the lines of b from i on stop going on with the
// line before them: past each one that is blank or starts with a space or a
// tab. It returns len(b) when such a line runs past b's end.
func continued(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		j := i
		for j < len(b) && b[j] != '\n' {
			j++
		}
		if j == len(b) {
			return len(b)
		}
		i = j + 1
	}
	return i
}

// lineText counts the bytes of skipped output that were not just a line break.
func lineText(skipped []byte) int64 {
	return int64(len(bytes.TrimRight(skipped, "\r\n")))
}

// Before returns what is still kept of the n bytes before offset at.
func (r *ringBuffer) Before(at int64, n int) []byte {
	b, _ := r.BeforeLine(at, n)
	return b
}

// LookBack is what is still kept of the output before offset at as a parse
// looks back at it (see lookBack), and whether it starts a line.
func (r *ringBuffer) LookBack(at int64) ([]byte, bool) {
	b, lineStart := r.BeforeLine(at, aroundRead)
	return lookBack(b, at-int64(len(b))), lineStart
}

// Context returns the output around the read [from, to), of what is still
// kept, that it is cleaned and redacted with: up to aroundRead bytes on each
// side, those before as a parse looks back at them (see lookBack).
func (r *ringBuffer) Context(from, to int64) (before, after []byte) {
	before, after = r.Around(from, to, aroundRead)
	return lookBack(before, from-int64(len(before))), after
}

// BeforeLine is Before, and whether what it returns starts a line: it
// begins the output, or a line feed that is still kept comes right before
// it.
func (r *ringBuffer) BeforeLine(at int64, n int) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, buf := r.kept()
	b := max(at-int64(n), start)
	if b >= at || at > start+int64(len(buf)) {
		return nil, at == 0
	}
	lineStart := b == 0 || b > start && buf[b-start-1] == '\n'
	return append([]byte(nil), buf[b-start:at-start]...), lineStart
}

// kept returns the bytes readers see, the last max, and the offset of the
// first.
func (r *ringBuffer) kept() (int64, []byte) {
	if over := len(r.buf) - r.max; over > 0 {
		return r.start + int64(over), r.buf[over:]
	}
	return r.start, r.buf
}

// LastWrite reports when bytes were last written; zero before the first.
func (r *ringBuffer) LastWrite() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// End returns the offset just past the last byte written and whether the
// stream is closed.
func (r *ringBuffer) End() (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.start + int64(len(r.buf)), r.closed
}

// Wait blocks until there are bytes at or past offset since, the stream is
// closed, or ctx ends.
func (r *ringBuffer) Wait(ctx context.Context, since int64) {
	for {
		r.mu.Lock()
		ready := r.closed || r.start+int64(len(r.buf)) > since
		ch := r.changed
		r.mu.Unlock()
		if ready {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
	}
}
