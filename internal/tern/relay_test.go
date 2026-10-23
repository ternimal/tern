// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestCatcher exercises the rtern code path: a Catcher listens, an agent dials
// in with the relay hello, and Catch pairs + Dials the agent as a client. We
// then run a command through the returned Client.
func TestCatcher(t *testing.T) {
	// --- relay cert (rtern side) ---
	relayCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	relayTLS := ServerTLSConfig(relayCert)
	relayFP := CertFingerprint(relayCert)

	// --- agent cert + auth ---
	agentCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	agentFP := CertFingerprint(agentCert)
	ac := &AuthConfig{Token: testToken}
	agent := NewAgent(ServerTLSConfig(agentCert), ac, "/bin/sh", time.Minute, "")

	// listen on loopback
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	relayToken := "relay-test-token-123"
	agentID := "test-box"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// the agent: dials the relay listener, proves the relay token, waits to be
	// paired, then serves as an agent over the inner connection
	go func() {
		conn, err := RelayDialAgent(ctx, ln.Addr().String(), relayFP, relayToken, agentID, false)
		if err != nil {
			return
		}
		agent.Serve(conn, "caught")
	}()

	cl, err := NewCatcher(ctx, ln, relayTLS, relayToken, agentID).Catch(ctx, agentFP, "", testToken, false, false)
	if err != nil {
		t.Fatalf("Catch: %v", err)
	}
	defer cl.Close()

	var buf bytes.Buffer
	code, err := cl.Run([]string{"sh", "-c", "echo CAUGHT_$((6*7))"}, nil, &buf)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "CAUGHT_42") {
		t.Fatalf("output %q missing CAUGHT_42", buf.String())
	}
}

// TestCatcherRejectsWrongID verifies that a Catcher skips agents whose id does
// not match wantID and keeps listening for the right one.
func TestCatcherRejectsWrongID(t *testing.T) {
	relayCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	relayTLS := ServerTLSConfig(relayCert)
	relayFP := CertFingerprint(relayCert)

	agentCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	agentFP := CertFingerprint(agentCert)
	ac := &AuthConfig{Token: testToken}
	agent := NewAgent(ServerTLSConfig(agentCert), ac, "/bin/sh", time.Minute, "")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	relayToken := "relay-test-token-456"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1st agent: wrong id -> should be rejected
	// 2nd agent: correct id -> should be caught
	go func() {
		for _, id := range []string{"wrong-box", "right-box"} {
			conn, err := RelayDialAgent(ctx, ln.Addr().String(), relayFP, relayToken, id, false)
			if err != nil {
				continue
			}
			agent.Serve(conn, "caught-"+id)
			return
		}
	}()

	cl, err := NewCatcher(ctx, ln, relayTLS, relayToken, "right-box").Catch(ctx, agentFP, "", testToken, false, false)
	if err != nil {
		t.Fatalf("Catch: %v", err)
	}
	defer cl.Close()

	var buf bytes.Buffer
	code, err := cl.Run([]string{"echo", "filtered"}, nil, &buf)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 0 || !strings.Contains(buf.String(), "filtered") {
		t.Fatalf("unexpected: exit=%d output=%q", code, buf.String())
	}
}

// TestRelayBackToBackClients: two client dials in a row (as `tern connect -L`
// does) must both reach the agent, although the agent re-registers with the
// relay only after each pairing.
func TestRelayBackToBackClients(t *testing.T) {
	relayPrefix := filepath.Join(t.TempDir(), "relay")
	relayCert, err := LoadOrCreateCert(relayPrefix) // created up front to learn its fingerprint
	if err != nil {
		t.Fatal(err)
	}
	relayFP := CertFingerprint(relayCert)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const token = "relay-test-token-789"
	go RunRelay(ctx, addr, relayPrefix, token)
	dialRetry(t, addr).Close()

	agent, agentFP := newTestAgent(t)
	go func() { // the ternd relay loop: register, serve the paired client, repeat
		for ctx.Err() == nil {
			tr, err := RelayDialAgent(ctx, addr, relayFP, token, "box", false)
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			go agent.Serve(tr, "relay:box")
			// Widen the re-registration gap, as a slow link would, so the
			// second client dial reliably lands in it.
			time.Sleep(300 * time.Millisecond)
		}
	}()

	for i := 0; i < 2; i++ {
		tr, err := RelayDialClient(ctx, addr, relayFP, token, "box", false)
		if err != nil {
			t.Fatalf("client dial %d: %v", i, err)
		}
		cl, err := Dial(tr, PinnedTLSConfig(agentFP), "", testToken)
		if err != nil {
			t.Fatalf("client %d auth: %v", i, err)
		}
		defer cl.Close()
	}
}

// TestCatcherHoldsSpare: like ternr, a Catcher holds a registration until
// it is needed. The spare an agent registers next to the one in use must wait
// open, not be paired and dropped, and the next Catch, as on a reconnect,
// pairs it.
func TestCatcherHoldsSpare(t *testing.T) {
	relayCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	relayFP := CertFingerprint(relayCert)
	agentCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	agentFP := CertFingerprint(agentCert)
	agent := NewAgent(ServerTLSConfig(agentCert), &AuthConfig{Token: testToken}, "/bin/sh", time.Minute, "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Each registration reports when it is paired, then serves as the agent.
	paired := make(chan int, 2)
	register := func(n int) {
		conn, err := RelayDialAgent(ctx, ln.Addr().String(), relayFP, "relay-test-token-123", "box", false)
		if err != nil {
			return
		}
		paired <- n
		agent.Serve(conn, "caught")
	}
	c := NewCatcher(ctx, ln, ServerTLSConfig(relayCert), "relay-test-token-123", "box")
	go register(1)
	go register(2)

	cl, err := c.Catch(ctx, agentFP, "", testToken, false, false)
	if err != nil {
		t.Fatalf("Catch: %v", err)
	}
	<-paired
	select {
	case n := <-paired:
		t.Fatalf("registration %d was paired too; a spare must wait", n)
	case <-time.After(500 * time.Millisecond):
	}
	cl.Close()

	cl2, err := c.Catch(ctx, agentFP, "", testToken, false, false)
	if err != nil {
		t.Fatalf("second Catch: %v", err)
	}
	defer cl2.Close()
	select {
	case <-paired:
	case <-time.After(5 * time.Second):
		t.Fatal("the held spare was not paired by the next Catch")
	}
	var buf bytes.Buffer
	if code, err := cl2.Run([]string{"sh", "-c", "echo SPARE"}, nil, &buf); err != nil || code != 0 || !strings.Contains(buf.String(), "SPARE") {
		t.Fatalf("Run through the spare: %d %v %q", code, err, buf.String())
	}
}

// flakyListener fails its first Accept, as when file descriptors run out.
type flakyListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

// TestCatcherSurvivesAcceptError: a passing Accept failure does not stop
// rtern from catching agents for good.
func TestCatcherSurvivesAcceptError(t *testing.T) {
	relayCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	agentCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	agent := NewAgent(ServerTLSConfig(agentCert), &AuthConfig{Token: testToken}, "/bin/sh", time.Minute, "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewCatcher(ctx, &flakyListener{Listener: ln}, ServerTLSConfig(relayCert), "relay-test-token-123", "box")
	go func() {
		if conn, err := RelayDialAgent(ctx, ln.Addr().String(), CertFingerprint(relayCert), "relay-test-token-123", "box", false); err == nil {
			agent.Serve(conn, "caught")
		}
	}()
	cl, err := c.Catch(ctx, CertFingerprint(agentCert), "", testToken, false, false)
	if err != nil {
		t.Fatalf("Catch after a failed Accept: %v", err)
	}
	cl.Close()
}

// TestRelayReapsDroppedRegistration: once an agent registers and then its
// connection dies before a client pairs, the relay must drop the registration
// (close the FD, free the goroutine and the map entry) instead of leaking it.
func TestRelayReapsDroppedRegistration(t *testing.T) {
	h := newRelayHub("x", nil)
	srv, cli := net.Pipe()

	done := make(chan struct{})
	go func() { h.handleAgent(srv, "id-1"); close(done) }()

	okb := make([]byte, 1)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli.Read(okb); err != nil || okb[0] != relayOK {
		t.Fatalf("expected relayOK, got %v err=%v", okb[0], err)
	}
	cli.Close() // the agent dies before any client pairs

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleAgent did not return after the agent connection dropped: registration leaked")
	}
	h.mu.Lock()
	_, present := h.agents["id-1"]
	h.mu.Unlock()
	if present {
		t.Fatal("dropped registration still in the map")
	}
}

// TestRelayConnectUnblocksOnContext: a relay that completes the TLS handshake
// but then never sends its challenge must not hang relayConnect forever; a
// cancelled context (an abandoned REST request, Ctrl-C) unblocks it.
func TestRelayConnectUnblocksOnContext(t *testing.T) {
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerTLSConfig(cert)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				s := tls.Server(raw, cfg)
				if s.Handshake() == nil {
					go io.Copy(io.Discard, s) // read, but never send a challenge
				}
				// hold the conn open until the test ends
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()

	res := make(chan error, 1)
	go func() {
		_, _, err := relayConnect(ctx, ln.Addr().String(), CertFingerprint(cert), "tok", RoleClient, "box", false)
		res <- err
	}()
	select {
	case err := <-res:
		if err == nil {
			t.Fatal("relayConnect returned no error against a stalled relay")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relayConnect hung on a stalled relay: the post-handshake read ignores the context")
	}
}
