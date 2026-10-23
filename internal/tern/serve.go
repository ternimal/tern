// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"context"
	"log/slog"
	"net"
	"time"
)

// ServeListener serves the connections ln accepts, as ternd does in direct
// mode, until ctx ends; it closes ln. Handshakes not yet authenticated are
// held to a PreAuthLimiter, and a peer that does not start its handshake
// within firstRecordTimeout is closed.
func (a *Agent) ServeListener(ctx context.Context, ln net.Listener) {
	a.serveListener(ctx, ln, new(PreAuthLimiter))
}

func (a *Agent) serveListener(ctx context.Context, ln net.Listener, lim *PreAuthLimiter) {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var retry time.Duration
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			retry = AcceptRetryDelay(retry)
			slog.Warn("accept failed", "err", err, "retry_in", retry)
			time.Sleep(retry)
			continue
		}
		retry = 0
		// The limiter places the connection before its goroutine starts, so
		// connections are taken no faster than it places them.
		t := lim.enter(raw)
		if t == nil {
			raw.Close()
			continue
		}
		go a.serveDirect(raw, t)
	}
}

// serveDirect serves a connection a listener accepted, once t, its place
// under the listener's limiter, holds a slot.
func (a *Agent) serveDirect(raw net.Conn, t *preAuthTicket) {
	if !t.wait() {
		raw.Close()
		return
	}
	conn, err := t.awaitFirstRecord(raw, a.Plaintext)
	if err != nil {
		t.done()
		raw.Close()
		return
	}
	a.ServeAdmitted(conn, raw.RemoteAddr().String(), t.done, t.cut())
}

// ServeRelay registers the agent with the relay under id and serves each
// client the relay pairs it with, registering again after every pairing,
// until ctx ends. At most maxRelayPending paired connections may be in their
// unauthenticated handshake at once, each for at most relayPairTimeout; while
// they all are, the agent waits before registering again, so a relay-token
// holder that pairs over and over and stays silent cannot pile them up.
func (a *Agent) ServeRelay(ctx context.Context, relayAddr, relayFP, relayToken, id string, insecure bool) {
	pending := make(chan struct{}, maxRelayPending)
	backoff := time.Second
	for {
		select {
		case pending <- struct{}{}:
		case <-ctx.Done():
			return
		}
		transport, err := RelayDialAgent(ctx, relayAddr, relayFP, relayToken, id, insecure)
		if err != nil {
			<-pending
			if ctx.Err() != nil {
				return
			}
			slog.Warn("relay registration failed", "relay", relayAddr, "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, ReconnectBackoffMax)
			continue
		}
		backoff = time.Second
		go a.servePaired(transport, "relay:"+id, relayPairTimeout, func() { <-pending })
	}
}

// servePaired serves a connection the relay paired, calling release once its
// handshake is over, passed or failed, or cut off after timeout. The cutoff
// closes transport and ends any wait of the handshake, such as one for a
// place to have its signature checked, so release comes then at the latest.
func (a *Agent) servePaired(transport net.Conn, label string, timeout time.Duration, release func()) {
	cut := make(chan struct{})
	cutoff := time.AfterFunc(timeout, func() {
		close(cut)
		transport.Close()
	})
	authDone := func() {
		cutoff.Stop()
		release()
	}
	conn, err := AwaitFirstRecord(transport, a.Plaintext)
	if err != nil {
		transport.Close()
		authDone()
		return
	}
	a.ServeAdmitted(conn, label, authDone, cut)
}
