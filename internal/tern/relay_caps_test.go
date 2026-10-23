// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const testRelayToken = "relay-test-token-123"

// startTestHub runs a relay hub, after setup, on a loopback port until the
// test ends, and returns it, its address and fingerprint, and a context that
// ends with the test.
func startTestHub(t *testing.T, setup ...func(*relayHub)) (h *relayHub, addr, fp string, ctx context.Context) {
	t.Helper()
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerTLSConfig(cert)
	h = newRelayHub(testRelayToken, agentCertFP(cfg))
	for _, f := range setup {
		f(h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.serve(ctx, ln, cfg)
	return h, ln.Addr().String(), CertFingerprint(cert), ctx
}

// startTestRelay is startTestHub for tests that need only the relay's
// address and fingerprint.
func startTestRelay(t *testing.T) (addr, fp string, ctx context.Context) {
	t.Helper()
	_, addr, fp, ctx = startTestHub(t)
	return addr, fp, ctx
}

// books reports what h holds: registrations and bridges, and how many it has
// taken in all.
func (h *relayHub) books() (regs, pipes int, seq uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.regs.root.n, h.pipes.root.n, h.seq
}

// TestRelayTokenNeverSent: the relay token never crosses the wire, so a relay
// that someone else's tern1: string names, or anyone who holds that relay's
// key, learns nothing to use with the relay the token is for: a relay that
// waits for a token gets nothing at all, and one that challenges gets a proof
// bound to its own certificate, to the TLS session it was sent over and to
// its challenge.
func TestRelayTokenNeverSent(t *testing.T) {
	const token = "the-victims-relay-token-0123456789"
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	fp := CertFingerprint(cert)
	certFP, _ := hex.DecodeString(fp)
	type heard struct{ sent, bind []byte }
	for _, challenges := range []bool{false, true} {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerTLSConfig(cert))
		if err != nil {
			t.Fatal(err)
		}
		challenge := bytes.Repeat([]byte{7}, challengeLen)
		got := make(chan heard, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				got <- heard{}
				return
			}
			defer c.Close()
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				got <- heard{}
				return
			}
			bind, _ := sessionBind(tc, certFP)
			if challenges {
				writeBlob(c, challenge)
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			var sent bytes.Buffer
			io.Copy(&sent, c) // all the client sends, until it gives up
			got <- heard{sent.Bytes(), bind}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_, err = RelayDialClient(ctx, ln.Addr().String(), fp, token, "box", false)
		cancel()
		ln.Close()
		if err == nil {
			t.Fatal("a relay that never answered was taken for one that did")
		}
		h := <-got
		if bytes.Contains(h.sent, []byte(token)) {
			t.Fatalf("challenges=%v: the relay received the token", challenges)
		}
		if !challenges {
			if len(h.sent) > 0 {
				t.Errorf("a relay that sent no challenge received %d bytes", len(h.sent))
			}
			continue
		}
		proof, err := readBlob(bytes.NewReader(h.sent), 64)
		if err != nil {
			t.Fatalf("no proof: %v", err)
		}
		if h.bind == nil || !hmac.Equal(proof, relayTokenProof(token, h.bind, challenge)) {
			t.Fatal("the proof is not bound to the certificate and session it was sent over")
		}
		if hmac.Equal(proof, relayTokenProof(token, certFP, challenge)) {
			t.Fatal("the proof would hold on another connection to a relay with this certificate")
		}
		other := sha256.Sum256([]byte("another relay's certificate"))
		if hmac.Equal(proof, relayTokenProof(token, append(other[:], h.bind[len(certFP):]...), challenge)) {
			t.Fatal("the proof would hold for another relay")
		}
	}
}

// A wrong relay token, a proof for another challenge or of another kind, and
// an agent id a shell could read as syntax are all refused at the hello.
func TestRelayHelloRefusals(t *testing.T) {
	_, addr, fp, ctx := startTestHub(t)
	if _, err := RelayDialAgent(ctx, addr, fp, "not-the-relay-token-0", "box", false); err == nil {
		t.Error("a registration with the wrong relay token was taken")
	}
	if _, err := RelayDialClient(ctx, addr, fp, testRelayToken, "box$(id)", false); err == nil {
		t.Error("a client asked for an id with shell syntax")
	}
	// proof answers a challenge on a connection to the relay whose
	// certificate has the fingerprint certFP and whose binding is bind.
	hello := func(proof func(certFP, bind, challenge []byte) []byte, id string) byte {
		t.Helper()
		c, err := tls.Dial("tcp", addr, PinnedTLSConfig(fp))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		bind, err := sessionBind(c, connCertFP(c))
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := readChallenge(c)
		if err != nil {
			t.Fatal(err)
		}
		writeBlob(c, proof(connCertFP(c), bind, challenge))
		c.Write([]byte{RoleAgent})
		writeBlob(c, []byte(id))
		var status [1]byte
		if _, err := io.ReadFull(c, status[:]); err != nil {
			t.Fatal(err)
		}
		return status[0]
	}
	good := func(_, bind, challenge []byte) []byte { return relayTokenProof(testRelayToken, bind, challenge) }
	if s := hello(good, "box-1"); s != relayOK {
		t.Fatalf("a good hello got status %d", s)
	}
	for _, id := range []string{"box$(touch x)", "box;id", "box`id`", "box one", "-box", "box'", "bóx"} {
		if s := hello(good, id); s != relayDeny {
			t.Errorf("id %q: status %d, want a refusal", id, s)
		}
	}
	replayed := func(_, bind, _ []byte) []byte {
		return relayTokenProof(testRelayToken, bind, bytes.Repeat([]byte{1}, challengeLen))
	}
	if s := hello(replayed, "box-2"); s != relayDeny {
		t.Errorf("a proof for another challenge got status %d", s)
	}
	agentProof := func(_, bind, challenge []byte) []byte { return tokenProof(testRelayToken, bind, challenge) }
	if s := hello(agentProof, "box-3"); s != relayDeny {
		t.Errorf("an agent-auth proof of the token got status %d", s)
	}
	certOnly := func(certFP, _, challenge []byte) []byte { return relayTokenProof(testRelayToken, certFP, challenge) }
	if s := hello(certOnly, "box-4"); s != relayDeny {
		t.Errorf("a proof bound to the certificate but not the session got status %d", s)
	}
}

// TestRelayPlaintextSession: with --insecure-skip-encryption on both ends a
// session through a relay works: the client binds its proof to its session
// with the agent, to nothing in plaintext as the agent does, never to its
// transport, which through a relay is the relay's own connection.
func TestRelayPlaintextSession(t *testing.T) {
	addr, relayFP, ctx := startTestRelay(t)
	a, _ := newTestAgent(t)
	a.Plaintext = true
	go a.ServeRelay(ctx, addr, relayFP, testRelayToken, "plain", false)
	tr, err := RelayDialClient(ctx, addr, relayFP, testRelayToken, "plain", false)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := Dial(tr, nil, "", testToken)
	if err != nil {
		t.Fatalf("plaintext login through the relay: %v", err)
	}
	defer cl.Close()
	var buf bytes.Buffer
	if code, err := cl.Run([]string{"sh", "-c", "echo PLAIN_OK"}, nil, &buf); err != nil || code != 0 || !strings.Contains(buf.String(), "PLAIN_OK") {
		t.Fatalf("run: %d %v %q", code, err, buf.String())
	}
}

// TestServeRelayBoundsPendingHandshakes: a relay-token holder that pairs with
// an agent over and over and stays silent cannot pile up unauthenticated
// handshakes on it: the agent registers again only while fewer than
// maxRelayPending are in flight, and serves real clients once they end.
func TestServeRelayBoundsPendingHandshakes(t *testing.T) {
	addr, relayFP, ctx := startTestRelay(t)
	a, agentFP := newTestAgent(t)
	go a.ServeRelay(ctx, addr, relayFP, testRelayToken, "box", false)

	var mu sync.Mutex
	var silent []net.Conn
	closeSilent := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range silent {
			c.Close()
		}
		silent = nil
	}
	defer closeSilent()
	hctx, hcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer hcancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for hctx.Err() == nil {
				c, resp, err := relayConnect(hctx, addr, relayFP, testRelayToken, RoleClient, "box", false)
				if err != nil {
					continue
				}
				if resp != relayOK {
					c.Close()
					time.Sleep(10 * time.Millisecond)
					continue
				}
				mu.Lock()
				silent = append(silent, c)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	n := len(silent)
	mu.Unlock()
	if n > maxRelayPending {
		t.Fatalf("%d silent pairings at once, past the cap of %d", n, maxRelayPending)
	}
	closeSilent()
	tr, err := RelayDialClient(ctx, addr, relayFP, testRelayToken, "box", false)
	if err != nil {
		t.Fatalf("after the silent pairings ended: %v", err)
	}
	cl, err := Dial(tr, PinnedTLSConfig(agentFP), "", testToken)
	if err != nil {
		t.Fatalf("after the silent pairings ended: %v", err)
	}
	cl.Close()
}

// TestPairingCutoffEndsSignatureWait: the cutoff of a paired connection's
// handshake also ends its wait for a place to have its signature checked,
// so the pending place it holds comes back at the cutoff, not at the end of
// the handshake's own, longer time, and its signature is never checked.
func TestPairingCutoffEndsSignatureWait(t *testing.T) {
	_, held := newSSHKey(t) // its checks hold the fast queue's places
	_, offered := newSSHKey(t)
	var running, offeredChecks atomic.Int32
	release := make(chan struct{})
	orig := verifyAuthSig
	verifyAuthSig = func(k ssh.PublicKey, data []byte, sig *ssh.Signature) error {
		switch {
		case bytes.Equal(k.Marshal(), held.Marshal()):
			running.Add(1)
			<-release
		case bytes.Equal(k.Marshal(), offered.Marshal()):
			offeredChecks.Add(1)
		}
		return errors.New("not checked here")
	}
	var holders sync.WaitGroup
	t.Cleanup(func() {
		close(release)
		holders.Wait()
		verifyAuthSig = orig
	})
	q := sigChecks.fast
	for range cap(q) {
		holders.Go(func() { checkSig(q, time.Now().Add(time.Minute), nil, held, nil, &ssh.Signature{}) })
	}
	for deadline := time.Now().Add(5 * time.Second); running.Load() < int32(cap(q)); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d checks are running", running.Load(), cap(q))
		}
	}

	a, fp := newTestAgent(t)
	_, listed := newSSHKey(t)
	a.Auth.Keys = keyMap(listed)
	sconn, cconn := loopbackPair(t)
	defer cconn.Close()
	const cutoff = time.Second
	released := make(chan time.Duration, 1)
	start := time.Now()
	go a.servePaired(sconn, "relay:box", cutoff, func() { released <- time.Since(start) })
	c := tls.Client(cconn, PinnedTLSConfig(fp))
	c.SetDeadline(time.Now().Add(time.Minute))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{methodPubkey})
	writeBlob(c, offered.Marshal())
	if _, err := readChallenge(c); err != nil {
		t.Fatal(err)
	}
	writeBlob(c, ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, 64)}))
	for sigCheckGoroutines() <= cap(q) {
		if time.Since(start) > cutoff/2 {
			t.Fatal("the paired handshake did not come to wait for a place in the queue")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case d := <-released:
		if d > cutoff+2*time.Second {
			t.Errorf("the pending place came back %s after the pairing, its cutoff is %s", d, cutoff)
		}
	case <-time.After(handshakeTimeout / 2):
		t.Fatalf("the pending place did not come back at the cutoff (%s)", cutoff)
	}
	if n := offeredChecks.Load(); n != 0 {
		t.Errorf("the signature of a handshake cut off was checked %d times", n)
	}
}

// TestRelayRenewsIdleRegistration: an unpaired registration is renewed after
// its idle limit, so what a vanished agent held does not outlive it, while a
// live agent registers again quietly and stays reachable.
func TestRelayRenewsIdleRegistration(t *testing.T) {
	const idle = relayRenewMin + 200*time.Millisecond // past it, the agent registers again at once
	h, addr, relayFP, ctx := startTestHub(t, func(h *relayHub) { h.idle = idle })
	a, agentFP := newTestAgent(t)
	go a.ServeRelay(ctx, addr, relayFP, testRelayToken, "box", false)
	time.Sleep(idle + 400*time.Millisecond)
	regs, _, seq := h.books()
	if seq < 2 || regs != 1 {
		t.Fatalf("%d registrations made, %d held; want it renewed, and held", seq, regs)
	}
	tr, err := RelayDialClient(ctx, addr, relayFP, testRelayToken, "box", false)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := Dial(tr, PinnedTLSConfig(agentFP), "", testToken)
	if err != nil {
		t.Fatal(err)
	}
	cl.Close()
}

// TestRelayCapsRegistrationsPerParty: one address cannot hold more than
// maxRelayRegsPerParty registrations; past it, its oldest gives way.
func TestRelayCapsRegistrationsPerParty(t *testing.T) {
	h, addr, relayFP, ctx := startTestHub(t)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := range maxRelayRegsPerParty + 1 {
		c, resp, err := relayConnect(ctx, addr, relayFP, testRelayToken, RoleAgent, fmt.Sprintf("box%d", i), false)
		if err != nil || resp != relayOK {
			t.Fatalf("registration %d: %v %d", i, err, resp)
		}
		conns = append(conns, c)
	}
	conns[0].SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conns[0].Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the oldest registration was kept: %v", err)
	}
	if regs, _, _ := h.books(); regs != maxRelayRegsPerParty {
		t.Fatalf("%d registrations held, want %d", regs, maxRelayRegsPerParty)
	}
	if c, resp, err := relayConnect(ctx, addr, relayFP, testRelayToken, RoleClient, "box0", false); err != nil || resp != relayNoAgent {
		t.Fatalf("the dropped registration still answers: %v %d", err, resp)
	} else {
		c.Close()
	}
}

// setRelayCaps sets the relay's total caps, which follow the file descriptor
// limit, to known values until the test ends.
func setRelayCaps(t *testing.T, regs, pipes int) {
	t.Helper()
	oldRegs, oldPipes := maxRelayRegs, maxRelayPipes
	maxRelayRegs, maxRelayPipes = regs, pipes
	t.Cleanup(func() { maxRelayRegs, maxRelayPipes = oldRegs, oldPipes })
}

// testReg and testPipe make a registration and a bridge from addr, an IP
// address and port, or any other name for a block of its own.
func testReg(id, addr string) *agentReg {
	r := &agentReg{id: id, path: testPath(addr), dropped: make(chan struct{})}
	r.entry.val = r
	return r
}

func testPipe(addr string) *relayPipe {
	return &relayPipe{path: testPath(addr), client: from("192.0.2.1:1"), agent: from("192.0.2.2:1")}
}

func testPath(addr string) []string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return addrPath(net.TCPAddrFromAddrPort(ap))
	}
	return []string{addr}
}

func dropped(r *agentReg) bool {
	select {
	case <-r.dropped:
		return true
	default:
		return false
	}
}

// A full relay makes room for a registration or a bridge by dropping the
// oldest of the party holding the most, never a light party's, and a party
// at its own bridge cap is refused.
func TestRelayHubFull(t *testing.T) {
	setRelayCaps(t, 1024, 1024)
	h := newRelayHub(testRelayToken, nil)
	reg := func(party string, n int) *agentReg {
		r := testReg(fmt.Sprintf("%s-%d", party, n), party)
		if !h.addReg(r) {
			t.Fatalf("registration %s refused", r.id)
		}
		return r
	}
	light := reg("light", 0) // the oldest of all, but alone
	var heavy []*agentReg
	for n := range 200 {
		heavy = append(heavy, reg("heavy", n))
	}
	for n := 0; h.regs.root.n < maxRelayRegs; n++ {
		reg(fmt.Sprintf("other-%d", n), 0)
	}
	newest := reg("newcomer", 0)
	if !dropped(heavy[0]) {
		t.Fatal("the heaviest party's oldest registration was kept")
	}
	if dropped(light) || dropped(newest) {
		t.Fatalf("a light party's registration dropped: %v; the newcomer dropped: %v", dropped(light), dropped(newest))
	}
	if h.regs.root.n != maxRelayRegs {
		t.Fatalf("%d registrations, want %d", h.regs.root.n, maxRelayRegs)
	}

	add := func(p *relayPipe) *relayPipe {
		evicted, ok := h.addPipe(p)
		if !ok {
			t.Fatal("a bridge was refused")
		}
		return evicted
	}
	add(testPipe("light"))
	first := testPipe("heavy")
	add(first)
	for range 199 {
		add(testPipe("heavy"))
	}
	for n := 0; h.pipes.root.n < maxRelayPipes; n++ {
		add(testPipe(fmt.Sprintf("other-%d", n)))
	}
	if evicted := add(testPipe("newcomer")); evicted != first {
		t.Fatal("a full relay did not make room with the heaviest party's oldest bridge")
	}

	// A party at its own bridge cap is refused, and the registration stays.
	h = newRelayHub(testRelayToken, nil)
	for range maxRelayPipesPerParty {
		h.addPipe(testPipe("pipe")) // net.Pipe's address
	}
	box := testReg("box", "x")
	h.addReg(box)
	srv, cli := net.Pipe()
	defer cli.Close()
	go h.handleClient(srv, "box")
	var status [1]byte
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(cli, status[:]); err != nil || status[0] != relayBusy {
		t.Fatalf("a party at its bridge cap got status %d (%v), want busy", status[0], err)
	}
	h.mu.Lock()
	kept := h.agents["box"] == box
	h.mu.Unlock()
	if !kept {
		t.Fatal("a refused client took the registration")
	}
}

// A full relay never closes an established bridge, nor drops an idle
// registration, for a newcomer whose party weighs as much: when every party
// holds one, as a relay-token holder can arrange with addresses spread over
// as many providers' blocks, the newcomer is refused instead, and the oldest
// (a long session, or an agent waiting for its client) stays.
func TestRelayFullKeepsEqualParties(t *testing.T) {
	const full = 64
	setRelayCaps(t, full, full)
	spread := func(i int) string { return fmt.Sprintf("[2001:%x::1]:1", 0x100+i) } // a /32 each
	h := newRelayHub(testRelayToken, nil)
	session := testPipe("198.51.100.7:1")
	if _, ok := h.addPipe(session); !ok {
		t.Fatal("a bridge was refused by an empty relay")
	}
	for i := range full - 1 {
		if _, ok := h.addPipe(testPipe(spread(i))); !ok {
			t.Fatal("a bridge was refused under the cap")
		}
	}
	for _, addr := range []string{spread(full), spread(0), "203.0.113.9:1"} {
		if evicted, ok := h.addPipe(testPipe(addr)); ok || evicted != nil {
			t.Fatalf("a client from %s got a bridge in a relay full of parties holding one each (one closed for it: %v)", addr, evicted != nil)
		}
	}
	if session.gone {
		t.Fatal("the oldest bridge was closed for a newcomer that weighs as much")
	}

	idle := testReg("box", "198.51.100.7:1")
	h.addReg(idle)
	for i := range full - 1 {
		h.addReg(testReg(fmt.Sprintf("x%d", i), spread(i)))
	}
	if newcomer := testReg("y", spread(full)); h.roomForReg(newcomer) || h.addReg(newcomer) {
		t.Fatal("a registration got a place in a relay full of parties holding one each")
	}
	if dropped(idle) {
		t.Fatalf("the idle agent's registration was dropped (%s) for a newcomer that weighs as much", idle.why)
	}
	// The agent itself registering again gives up its old place for the new.
	if again := testReg("box", "198.51.100.7:2"); !h.roomForReg(again) || !h.addReg(again) || !dropped(idle) {
		t.Fatal("an agent registering again under its own id found no room")
	}
}

// A relay-token holder with many /48s in one provider's /32 weighs as one
// party: a full relay makes room from its bridges and registrations, never
// from a lone client's or agent's, however many /48s it spreads over and
// however long the lone one has been there.
func TestRelayFullWeighsAddressBlocks(t *testing.T) {
	const full = 64
	setRelayCaps(t, full, full)
	inOne32 := func(i int) string { return fmt.Sprintf("[2001:db8:%x::1]:1", 1+i) }
	h := newRelayHub(testRelayToken, nil)
	session := testPipe("198.51.100.7:1")
	h.addPipe(session)
	for i := range full - 1 {
		h.addPipe(testPipe(inOne32(i)))
	}
	for i := range 4 * full {
		if evicted, _ := h.addPipe(testPipe(inOne32(full + i))); evicted == session {
			t.Fatalf("bridge %d from the /32 closed the lone session", i)
		}
	}
	evicted, ok := h.addPipe(testPipe("203.0.113.9:1"))
	if !ok || evicted == nil || evicted.path[0] != "2001:db8::/32" {
		t.Fatalf("a client from elsewhere: admitted %v, by closing a bridge of the /32: %v", ok, evicted != nil && evicted.path[0] == "2001:db8::/32")
	}
	if session.gone {
		t.Fatal("the lone session was closed")
	}

	idle := testReg("box", "198.51.100.7:1")
	h.addReg(idle)
	for i := range full - 1 {
		h.addReg(testReg(fmt.Sprintf("x%d", i), inOne32(i)))
	}
	for i := range 4 * full {
		h.addReg(testReg(fmt.Sprintf("y%d", i), inOne32(full+i)))
	}
	if dropped(idle) {
		t.Fatalf("the lone agent's registration was dropped: %s", idle.why)
	}
	if !h.addReg(testReg("other", "203.0.113.9:1")) {
		t.Fatal("an agent from elsewhere found no room")
	}
}
