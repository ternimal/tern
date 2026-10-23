// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"crypto/tls"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// hostileAgent returns a client logged in to an agent that does whatever the
// test does with the returned mux session.
func hostileAgent(t *testing.T) (*yamux.Session, *Client) {
	t.Helper()
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerTLSConfig(cert)
	sconn, cconn := loopbackPair(t)
	sess := make(chan *yamux.Session, 1)
	go func() {
		tc := tls.Server(sconn, cfg)
		bind, err := serverBind(tc, cfg)
		if err != nil {
			sess <- nil
			return
		}
		if _, ok := serverAuthenticate(tc, &AuthConfig{Token: testToken}, bind, authDeadline(), nil); !ok {
			sess <- nil
			return
		}
		s, _ := muxServer(tc)
		sess <- s
	}()
	cl, err := Dial(cconn, PinnedTLSConfig(CertFingerprint(cert)), "", testToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	s := <-sess
	if s == nil {
		t.Fatal("the agent side did not come up")
	}
	t.Cleanup(func() { s.Close() })
	return s, cl
}

func waitClosed(t *testing.T, cl *Client, why string) {
	t.Helper()
	select {
	case <-cl.sess.CloseChan():
	case <-time.After(5 * time.Second):
		t.Fatalf("the client kept the connection to an agent that %s", why)
	}
}

// An agent opens streams to a client only for the -R forwards it set up; one
// that opens any other is cut off, rather than given a goroutine per stream.
func TestClientDropsUnaskedStream(t *testing.T) {
	agent, cl := hostileAgent(t)
	// The client may drop the connection as soon as the new stream reaches
	// it, before this side's mux has finished sending it: OpenStream then
	// reports the session shut down, which is the outcome wanted.
	if _, err := agent.OpenStream(); err != nil && !errors.Is(err, yamux.ErrSessionShutdown) {
		t.Fatal(err)
	}
	waitClosed(t, cl, "opened a stream though no -R forward was set up")

	for name, h := range map[string]streamHeader{
		"another bind": {Kind: kindForwardR, Bind: "127.0.0.1:9"},
		"another kind": {Kind: kindShell, Bind: "127.0.0.1:1"},
	} {
		agent, cl := hostileAgent(t)
		cl.mu.Lock()
		cl.rforward["127.0.0.1:1"] = "127.0.0.1:2"
		cl.mu.Unlock()
		st, err := agent.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		writeHeader(st, h)
		waitClosed(t, cl, "opened a stream for "+name)
	}
}

// With an -R forward set up, streams an agent opens and never sends a header
// on hold at most maxInboundHeaders of the client's goroutines.
func TestClientCapsInboundHeaders(t *testing.T) {
	agent, cl := hostileAgent(t)
	cl.mu.Lock()
	cl.rforward["127.0.0.1:1"] = "127.0.0.1:2"
	cl.mu.Unlock()
	before := runtime.NumGoroutine()
	for range 2000 {
		if _, err := agent.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if grown := runtime.NumGoroutine() - before; grown > maxInboundHeaders+32 {
		t.Fatalf("2000 header-less streams grew the client by %d goroutines", grown)
	}
	if cl.sess.IsClosed() {
		t.Fatal("the client gave up a connection that only sent too many streams")
	}
}
