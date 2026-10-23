// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Idempotency keys stop a re-sent call from acting twice. MCP 2026-07-28 has
// no stream resumption: when a response stream breaks, the client re-issues
// the request, and for run or write_file that would repeat the action. A call
// that carries an idempotency_key runs once; a later call with the same key
// and the same arguments gets the stored result, or waits for the first one
// if it is still running. The same key with different arguments is an error.
//
// Only an outcome from a call that may have acted is stored. A call that
// failed before it did anything, or that its caller cancelled, is forgotten,
// so a retry with the same key runs it anew rather than replaying a failure
// that no longer holds.

const (
	idemTTL        = 10 * time.Minute
	maxIdemEntries = 1024
	maxIdemKeyLen  = 128
)

var errIdemMismatch = errors.New("idempotency_key was already used for a different call")

// notStarted marks an error from before a call acted at all, such as an agent
// that could not be reached.
type notStarted struct{ error }

func (e notStarted) Unwrap() error { return e.error }

// beforeStart wraps err as a failure that happened before anything was done.
func beforeStart(err error) error {
	if err == nil {
		return nil
	}
	return notStarted{err}
}

type idemEntry struct {
	action    string
	done      chan struct{}
	out       any
	err       error
	abandoned bool      // set when done: the call did nothing to replay
	expires   time.Time // set when done
}

type idemCache struct {
	mu  sync.Mutex
	m   map[string]*idemEntry
	now func() time.Time
}

func newIdemCache() *idemCache {
	return &idemCache{m: map[string]*idemEntry{}, now: time.Now}
}

// evict drops expired entries, then the oldest finished ones past the cap.
// Call with mu held.
func (c *idemCache) evict() {
	now := c.now()
	var oldestKey string
	var oldest time.Time
	for k, e := range c.m {
		if e.expires.IsZero() {
			continue // still running
		}
		if now.After(e.expires) {
			delete(c.m, k)
			continue
		}
		if oldestKey == "" || e.expires.Before(oldest) {
			oldestKey, oldest = k, e.expires
		}
	}
	if len(c.m) > maxIdemEntries && oldestKey != "" {
		delete(c.m, oldestKey)
	}
}

// replay returns the stored result of an earlier call with key and the same
// action, waiting for it if it is still running. found is false when there is
// none, or the earlier call was abandoned, so the caller goes on and runs the
// call.
func (c *idemCache) replay(ctx context.Context, key, action string) (out any, err error, found bool) {
	c.mu.Lock()
	c.evict()
	e := c.m[key]
	c.mu.Unlock()
	if e == nil {
		return nil, nil, false
	}
	if e.action != action {
		return nil, errIdemMismatch, true
	}
	select {
	case <-e.done:
		if e.abandoned {
			return nil, nil, false
		}
		return e.out, e.err, true
	case <-ctx.Done():
		return nil, ctx.Err(), true
	}
}

// do runs fn once for key and action and stores its result. If another call
// claimed the key first, it waits for that one and returns its result, or
// runs fn itself if that call is abandoned.
func (c *idemCache) do(ctx context.Context, key, action string, fn func() (any, error)) (any, error) {
	for {
		c.mu.Lock()
		c.evict()
		e := c.m[key]
		if e == nil {
			e = &idemEntry{action: action, done: make(chan struct{})}
			c.m[key] = e
			c.mu.Unlock()
			return c.run(ctx, key, e, fn)
		}
		c.mu.Unlock()
		if e.action != action {
			return nil, errIdemMismatch
		}
		select {
		case <-e.done:
			if !e.abandoned {
				return e.out, e.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// run runs fn for the entry e that this call claimed, then stores the outcome,
// or drops the entry when fn failed before it acted or was cancelled.
func (c *idemCache) run(ctx context.Context, key string, e *idemEntry, fn func() (any, error)) (any, error) {
	out, err := fn()
	var ns notStarted
	c.mu.Lock()
	if err != nil && (errors.As(err, &ns) || ctx.Err() != nil) {
		e.abandoned = true
		if c.m[key] == e {
			delete(c.m, key)
		}
	} else {
		e.out, e.err, e.expires = out, err, c.now().Add(idemTTL)
	}
	c.mu.Unlock()
	close(e.done)
	return out, err
}
