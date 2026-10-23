// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Relay (ternr) protocol, spoken over a TLS connection to the relay that the
// agent/client pins via PinnedTLSConfig:
//
//	<- challenge:blob   (32 fresh random bytes)
//	-> proof:blob, role:1, id:blob
//	<- status:1   (relayOK | relayDeny | relayNoAgent | relayBusy)
//
// The proof is relayTokenProof: an HMAC keyed by the relay token over the
// binding of this TLS connection (the relay's certificate fingerprint and
// keying material exported from the session, see sessionBind) and the
// challenge. The token itself never crosses the wire, to the relay or anyone
// else, so a relay that someone else's tern1: string names learns nothing it
// could use on the relay the token is for, and a proof is worth nothing on any
// other connection. For an agent, relayOK means "registered"; it then blocks
// until:
//
//	<- paired:1   (relayPaired: a client arrived; begin the inner session)
//
// or until the relay, having held the registration unpaired for
// relayRegIdle, sends relayRenew and closes it, and the agent registers again.
// After pairing the relay copies raw bytes between the two connections. The
// inner TLS + auth runs end-to-end between client and agent, so the relay never
// sees shell plaintext and cannot impersonate the agent (it does not hold the
// private key for the certificate the client pins).
//
// RoleAgent and RoleClient are the role byte a peer sends in that hello.
const (
	RoleAgent  byte = 1
	RoleClient byte = 2
)

const (
	relayDeny    byte = 0
	relayOK      byte = 1
	relayNoAgent byte = 2
	relayBusy    byte = 3
	relayPaired  byte = 1
	relayRenew   byte = 2
)

// --- relay server (ternr) ---

type agentReg struct {
	entry    partyEntry[*agentReg]
	id       string
	path     []string // the agent's address blocks
	conn     net.Conn
	taken    chan struct{} // closed by a client handler that takes ownership
	quiesced chan struct{} // closed by the agent handler once its death-watcher has stopped
	dropped  chan struct{} // closed when the relay lets it go unpaired
	why      string        // why it was dropped, set before dropped is closed
}

// relayPipe is a bridge between a client and the agent it was paired with,
// booked against the client's address.
type relayPipe struct {
	entry         partyEntry[*relayPipe]
	path          []string // the client's address blocks
	client, agent net.Conn
	gone          bool // out of the books
}

type relayHub struct {
	token  string
	certFP []byte        // the relay's certificate fingerprint, which proofs are bound to with each session
	idle   time.Duration // how long an unpaired registration waits before it is renewed
	lim    PreAuthLimiter

	mu     sync.Mutex
	agents map[string]*agentReg  // the registration for each id: the newest wins
	regs   partyTree[*agentReg]  // unpaired registrations, by the agent's address
	pipes  partyTree[*relayPipe] // bridges, by the client's address
	seq    uint64
}

func newRelayHub(token string, certFP []byte) *relayHub {
	return &relayHub{
		token:  token,
		certFP: certFP,
		idle:   relayRegIdle,
		agents: make(map[string]*agentReg),
	}
}

// CheckRelayToken refuses a relay token too short to resist guessing or too
// long for a relay to read.
func CheckRelayToken(token string) error {
	switch {
	case len(token) < 16:
		return errors.New("the relay token is too short; use at least 16 characters (generate one with: tern genkey)")
	case len(token) > maxRelayToken:
		return fmt.Errorf("the relay token is too long; use at most %d characters", maxRelayToken)
	}
	return nil
}

// CheckRelayID refuses an agent id that is empty, longer than maxRelayID, or
// holds anything but ASCII letters, digits and . _ - @ : +, starting with a
// letter or digit. Ids end up in commands that people paste into a shell,
// where none of these can change what the command does.
func CheckRelayID(id string) error {
	switch {
	case id == "":
		return errors.New("the agent id is empty")
	case len(id) > maxRelayID:
		return fmt.Errorf("the agent id is longer than %d characters", maxRelayID)
	case !isAlnum(id[0]):
		return fmt.Errorf("the agent id %q must start with a letter or digit", id)
	}
	for i := 1; i < len(id); i++ {
		if c := id[i]; !isAlnum(c) && !strings.ContainsRune("._-@:+", rune(c)) {
			return fmt.Errorf("the agent id %q may hold only letters, digits and . _ - @ : +", id)
		}
	}
	return nil
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// RunRelay starts the relay server and blocks until ctx is cancelled. It
// returns an error only if setup fails (bad token, cert, listen); later
// Accept errors are logged and retried after a short pause. token gates use of
// the relay (prevents open-relay abuse); see CheckRelayToken.
func RunRelay(ctx context.Context, addr, certPrefix, token string) error {
	if err := CheckRelayToken(token); err != nil {
		return err
	}
	cert, err := LoadOrCreateCert(certPrefix)
	if err != nil {
		return err
	}
	ln, err := ListenTCP(addr)
	if err != nil {
		return err
	}
	cfg := ServerTLSConfig(cert)
	slog.Info("relay listening", "addr", addr, "fingerprint", CertFingerprint(cert))
	newRelayHub(token, agentCertFP(cfg)).serve(ctx, ln, cfg)
	return nil
}

// serve runs the relay on ln, presenting cfg, until ctx ends; it closes ln.
func (h *relayHub) serve(ctx context.Context, ln net.Listener, cfg *tls.Config) {
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
				return // shutting down
			}
			retry = AcceptRetryDelay(retry)
			slog.Warn("relay accept failed", "err", err, "retry_in", retry)
			time.Sleep(retry)
			continue
		}
		retry = 0
		// Unauthenticated handshakes, per source; placed before the
		// connection's goroutine starts, as in Agent.serveListener.
		t := h.lim.enter(raw)
		if t == nil {
			raw.Close()
			continue
		}
		go h.serveConn(raw, cfg, t)
	}
}

// serveConn serves a connection the relay accepted, once t, its place under
// the relay's limiter, holds a slot.
func (h *relayHub) serveConn(raw net.Conn, cfg *tls.Config, t *preAuthTicket) {
	if !t.wait() {
		raw.Close()
		return
	}
	first, err := t.awaitFirstRecord(raw, false)
	if err != nil {
		t.done()
		raw.Close()
		return
	}
	h.handle(tls.Server(first, cfg), t.done)
}

func (h *relayHub) handle(conn *tls.Conn, done func()) {
	// Bound the unauthenticated TLS handshake + hello so a slow-loris peer cannot
	// pin a goroutine/FD on this internet-facing listener. Cleared once the peer
	// has proved the relay token (connections are long-lived).
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	role, id, err := relayReadHello(conn, h.token, h.certFP)
	done() // the unauthenticated part is over
	if err != nil {
		slog.Debug("relay hello refused", "remote", conn.RemoteAddr().String(), "err", err)
		conn.Write([]byte{relayDeny})
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	switch role {
	case RoleAgent:
		h.handleAgent(conn, id)
	case RoleClient:
		h.handleClient(conn, id)
	default:
		conn.Write([]byte{relayDeny})
		conn.Close()
	}
}

// relayReadHello runs the relay's side of the hello on a new connection: it
// completes the TLS handshake, sends a fresh challenge, then reads the proof
// of token, bound to the relay's certificate fingerprint certFP and to this
// TLS session, the role and the agent id.
func relayReadHello(conn *tls.Conn, token string, certFP []byte) (byte, string, error) {
	if err := conn.Handshake(); err != nil {
		return 0, "", err
	}
	bind, err := sessionBind(conn, certFP)
	if err != nil {
		return 0, "", err
	}
	challenge := make([]byte, challengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return 0, "", err
	}
	if err := writeBlob(conn, challenge); err != nil {
		return 0, "", err
	}
	proof, err := readBlob(conn, 64)
	if err != nil {
		return 0, "", err
	}
	var r [1]byte
	if _, err := io.ReadFull(conn, r[:]); err != nil {
		return 0, "", err
	}
	idb, err := readBlob(conn, maxRelayID)
	if err != nil {
		return 0, "", err
	}
	if !hmac.Equal(proof, relayTokenProof(token, bind, challenge)) {
		return 0, "", errors.New("bad relay token")
	}
	id := string(idb)
	if err := CheckRelayID(id); err != nil {
		return 0, "", err
	}
	return r[0], id, nil
}

func (h *relayHub) handleAgent(conn net.Conn, id string) {
	remote := conn.RemoteAddr().String()
	reg := &agentReg{
		id:       id,
		path:     addrPath(conn.RemoteAddr()),
		conn:     conn,
		taken:    make(chan struct{}),
		quiesced: make(chan struct{}),
		dropped:  make(chan struct{}),
	}
	reg.entry.val = reg

	h.mu.Lock()
	room := h.roomForReg(reg)
	h.mu.Unlock()
	if !room {
		conn.Write([]byte{relayBusy})
		conn.Close()
		slog.Warn("agent registration refused: the relay is full", "id", id, "remote", remote)
		return
	}

	// Acknowledge before publishing the registration: once reg is in the map a
	// client may take it (close reg.taken, then wait for reg.quiesced), so every
	// path past the insert must reach the select below. A failed write here
	// leaves nothing behind for a client to wait on.
	if _, err := conn.Write([]byte{relayOK}); err != nil {
		conn.Close()
		return
	}

	h.mu.Lock()
	ok := h.addReg(reg)
	h.mu.Unlock()
	if !ok { // another registration took the last place in between
		conn.Close()
		slog.Warn("agent registration dropped: the relay is full", "id", id, "remote", remote)
		return
	}
	slog.Info("agent registered", "id", id, "remote", remote)

	// Watch the parked connection. A registered-but-unpaired agent sends
	// nothing (it waits for relayPaired), so a byte or a read error both mean it
	// is gone. Without this the registration -- a goroutine, a map entry and the
	// FD -- would leak until the relay restarts, which a relay-token holder could
	// repeat to exhaust it. On pairing we kick this read with a past deadline and
	// wait for it to return, so the conn is never read by two goroutines at once.
	var paired atomic.Bool
	dead := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		var b [1]byte
		_, err := conn.Read(b[:])
		var ne net.Error
		if paired.Load() && errors.As(err, &ne) && ne.Timeout() {
			return // our own kick: the byte stream is untouched for the pipe
		}
		close(dead)
	}()

	takeover := func() {
		paired.Store(true)
		conn.SetReadDeadline(time.Now()) // kick the watcher's blocked Read
		<-watcherDone
		conn.SetReadDeadline(time.Time{}) // clear it for the pipe
		close(reg.quiesced)               // the client handler may now pipe conn
	}

	idle := time.NewTimer(h.idle)
	defer idle.Stop()
	select {
	case <-dead:
		// Claim the drop under the lock. If a client already took us out of
		// the books it is mid-takeover, so hand the conn off to it instead.
		if h.unregister(reg) {
			slog.Info("agent registration dropped (connection closed before pairing)", "id", id)
			conn.Close()
			return
		}
	case <-idle.C:
		// Unpaired for long: ask the agent to register again, which a live one
		// does at once, and let go of what a vanished one held.
		if h.unregister(reg) {
			slog.Debug("agent registration renewed", "id", id)
			conn.Write([]byte{relayRenew})
			conn.Close()
			return
		}
	case <-reg.taken:
	case <-reg.dropped:
	}
	// Not ours to drop any more. Either a client took the registration (it
	// closes reg.taken and waits for reg.quiesced: hand the conn over) or the
	// relay dropped it, for a newer one for the same id or to make room
	// (reg.dropped is closed and nobody will ever close reg.taken: waiting on
	// it alone would park this goroutine and the conn forever). The two are
	// exclusive: both take reg out of the books, which happens once.
	select {
	case <-reg.taken:
		takeover()
	case <-reg.dropped:
		slog.Info("agent registration dropped", "id", id, "why", reg.why)
		conn.Close()
	}
}

// addReg publishes reg as the registration for its id, dropping the one it
// replaces, and makes room for it: a party at its cap gives up its own
// oldest registration, and a full relay one of a party heavier than reg's
// (partyTree.displace). It reports false, publishing nothing, when the relay
// is full and holds no heavier party: an idle registration is never dropped
// for a newcomer that weighs as much. h.mu is held.
func (h *relayHub) addReg(reg *agentReg) bool {
	if old := h.agents[reg.id]; old != nil {
		h.dropReg(old, "replaced by a newer registration")
	}
	if party := h.regs.nodes[partyKey(reg.path)]; party != nil && party.n >= maxRelayRegsPerParty {
		h.dropReg(party.first.val, "too many registrations from its address")
	} else if h.regs.root.n >= maxRelayRegs {
		victim := h.regs.displace(reg.path)
		if victim == nil {
			return false
		}
		h.dropReg(victim.val, "the relay is full")
	}
	h.seq++
	h.agents[reg.id] = reg
	h.regs.add(&reg.entry, reg.path, h.seq, false, time.Time{})
	return true
}

// roomForReg reports whether addReg would find room for reg. h.mu is held.
func (h *relayHub) roomForReg(reg *agentReg) bool {
	if h.agents[reg.id] != nil || h.regs.root.n < maxRelayRegs ||
		h.regs.count(partyKey(reg.path)) >= maxRelayRegsPerParty {
		return true // it frees a place itself, or one is free
	}
	return h.regs.displace(reg.path) != nil
}

// dropReg lets an unpaired registration go; its handler closes the
// connection. h.mu is held.
func (h *relayHub) dropReg(reg *agentReg, why string) {
	if h.removeReg(reg) {
		reg.why = why
		close(reg.dropped)
	}
}

// unregister takes reg out of the books unless a client took it or the relay
// dropped it first, and reports whether it did.
func (h *relayHub) unregister(reg *agentReg) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.removeReg(reg)
}

// removeReg takes reg out of the books, reporting whether it was in them.
// h.mu is held.
func (h *relayHub) removeReg(reg *agentReg) bool {
	if h.agents[reg.id] != reg {
		return false
	}
	delete(h.agents, reg.id)
	h.regs.remove(&reg.entry)
	return true
}

func (h *relayHub) handleClient(conn net.Conn, id string) {
	remote := conn.RemoteAddr().String()
	path := addrPath(conn.RemoteAddr())

	h.mu.Lock()
	if h.pipes.count(partyKey(path)) >= maxRelayPipesPerParty {
		h.mu.Unlock()
		conn.Write([]byte{relayBusy})
		conn.Close()
		slog.Warn("client refused: too many bridges from its address", "id", id, "remote", remote)
		return
	}
	reg := h.agents[id]
	var p, evicted *relayPipe
	if reg != nil {
		p = &relayPipe{path: path, client: conn, agent: reg.conn}
		var ok bool
		if evicted, ok = h.addPipe(p); !ok {
			h.mu.Unlock()
			conn.Write([]byte{relayBusy})
			conn.Close()
			slog.Warn("client refused: the relay is full", "id", id, "remote", remote)
			return
		}
		h.removeReg(reg)
	}
	h.mu.Unlock()

	if reg == nil {
		conn.Write([]byte{relayNoAgent})
		conn.Close()
		slog.Warn("no agent for client", "id", id, "remote", remote)
		return
	}
	if evicted != nil {
		slog.Warn("relay full: closing a bridge of the address block holding the most", "remote", evicted.client.RemoteAddr().String())
		evicted.client.Close()
		evicted.agent.Close()
	}
	defer h.removePipe(p)

	close(reg.taken) // tell the agent handler to stop its watcher and hand off
	<-reg.quiesced   // wait until it has, so we are the only reader of reg.conn

	if _, err := conn.Write([]byte{relayOK}); err != nil {
		reg.conn.Close()
		conn.Close()
		return
	}
	if _, err := reg.conn.Write([]byte{relayPaired}); err != nil {
		reg.conn.Close()
		conn.Close()
		return
	}
	slog.Info("bridged", "id", id, "remote", remote)
	pipe(conn, reg.conn)
	slog.Debug("bridge closed", "id", id)
}

// addPipe books p. A full relay makes room by taking a bridge of a party
// heavier than p's (partyTree.displace), which it returns for the caller to
// close; when it holds no heavier party it books nothing and reports false,
// so an established bridge is never closed for a newcomer that weighs as
// much. h.mu is held.
func (h *relayHub) addPipe(p *relayPipe) (evicted *relayPipe, ok bool) {
	if h.pipes.root.n >= maxRelayPipes {
		victim := h.pipes.displace(p.path)
		if victim == nil {
			return nil, false
		}
		evicted = victim.val
		h.unbookPipe(evicted)
	}
	p.entry.val = p
	h.seq++
	h.pipes.add(&p.entry, p.path, h.seq, false, time.Time{})
	return evicted, true
}

// removePipe takes p out of the books once its bridge is over.
func (h *relayHub) removePipe(p *relayPipe) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unbookPipe(p)
}

// unbookPipe takes p out of the books unless it is out already; h.mu is held.
func (h *relayHub) unbookPipe(p *relayPipe) {
	if p.gone {
		return
	}
	p.gone = true
	h.pipes.remove(&p.entry)
}

// --- agent/client sides of the relay handshake ---

func relayConnect(ctx context.Context, relayAddr, relayFP, relayToken string, role byte, id string, insecure bool) (net.Conn, byte, error) {
	if err := CheckRelayID(id); err != nil {
		return nil, 0, err
	}
	d := &net.Dialer{Timeout: DialTimeout}
	raw, err := d.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, 0, err
	}
	outer := tls.Client(raw, ClientTLSConfig(relayFP, insecure))
	// Bound the handshake + hello + status read so a silent or black-holing
	// relay cannot pin this goroutine and its FD forever; the caller's ctx
	// (a cancelled REST request, Ctrl-C) also unblocks it. Cleared on success:
	// an agent's wait-for-pairing read that follows is long-lived.
	raw.SetDeadline(time.Now().Add(handshakeTimeout))
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if err := outer.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, 0, fmt.Errorf("tls handshake: %w", err)
	}
	slog.Debug("relay connected", "relay", relayAddr, "role", role, "id", id)
	// Answer the relay's challenge with a proof bound to the certificate this
	// connection reached and to its TLS session; the token itself is never
	// sent.
	bind, err := sessionBind(outer, connCertFP(outer))
	if err != nil {
		outer.Close()
		return nil, 0, err
	}
	challenge, err := readChallenge(outer)
	if err != nil {
		outer.Close()
		return nil, 0, fmt.Errorf("relay hello: %w", err)
	}
	var hello bytes.Buffer
	writeBlob(&hello, relayTokenProof(relayToken, bind, challenge))
	hello.WriteByte(role)
	writeBlob(&hello, []byte(id))
	if _, err := outer.Write(hello.Bytes()); err != nil {
		outer.Close()
		return nil, 0, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(outer, resp[:]); err != nil {
		outer.Close()
		return nil, 0, err
	}
	if !stop() { // ctx already fired: raw was closed, do not hand back a dead conn
		return nil, 0, ctx.Err()
	}
	raw.SetDeadline(time.Time{})
	return outer, resp[0], nil
}

// RelayDialClient connects to the relay and asks to be bridged to agent id.
// The returned conn is the transport to hand to Dial. An agent holds one
// registration at a time and re-registers right after each pairing, so a dial
// that lands in that gap (two connects back to back, concurrent REST requests)
// sees no agent; it is retried briefly before giving up.
func RelayDialClient(ctx context.Context, relayAddr, relayFP, relayToken, id string, insecure bool) (net.Conn, error) {
	wait := relayNoAgentRetryMin
	for attempt := 0; ; attempt++ {
		outer, resp, err := relayConnect(ctx, relayAddr, relayFP, relayToken, RoleClient, id, insecure)
		if err != nil {
			return nil, err
		}
		switch resp {
		case relayOK:
			return outer, nil
		case relayNoAgent:
			outer.Close()
			if attempt >= relayNoAgentRetries {
				return nil, fmt.Errorf("no agent registered as %q on the relay", id)
			}
			slog.Debug("no agent registered yet; retrying", "id", id, "in", wait)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			wait *= 2
		case relayBusy:
			outer.Close()
			return nil, errors.New("the relay is full, or holds too many connections from this address; try again later")
		default:
			outer.Close()
			return nil, errors.New("relay rejected client (bad relay token?)")
		}
	}
}

// Catcher is rtern's relay side. Like ternr it accepts agent registrations,
// answers each with "registered" and holds it, waiting; Catch pairs one held
// registration at a time and dials the agent through it as a client. Holding,
// rather than pairing every registration at once, keeps the spare an agent
// registers after each pairing quietly waiting for the next connection (a
// reconnect pairs it at once) instead of being dropped and retried.
type Catcher struct {
	held chan net.Conn // registered agents, told relayOK, not yet paired
	dead chan struct{} // closed when the listener is closed
	err  error         // why, once dead is closed
}

// NewCatcher starts accepting on ln until ctx ends. Agents registering with
// wantID (any id when it is empty) are held; anything else is refused.
func NewCatcher(ctx context.Context, ln net.Listener, serverTLS *tls.Config, relayToken, wantID string) *Catcher {
	return startCatcher(ctx, ln, serverTLS, relayToken, wantID, new(PreAuthLimiter))
}

// startCatcher is NewCatcher holding unauthenticated handshakes to lim.
func startCatcher(ctx context.Context, ln net.Listener, serverTLS *tls.Config, relayToken, wantID string, lim *PreAuthLimiter) *Catcher {
	c := &Catcher{held: make(chan net.Conn, maxCatchHeld), dead: make(chan struct{})}
	go c.accept(ctx, ln, serverTLS, relayToken, wantID, lim)
	go func() { // at the end, drop what is still held
		<-ctx.Done()
		for {
			select {
			case conn := <-c.held:
				conn.Close()
			default:
				return
			}
		}
	}()
	return c
}

func (c *Catcher) accept(ctx context.Context, ln net.Listener, serverTLS *tls.Config, relayToken, wantID string, lim *PreAuthLimiter) {
	certFP := agentCertFP(serverTLS)
	// A TCP listener lets the loop notice ctx while blocked in Accept.
	deadliner, canPoll := ln.(interface{ SetDeadline(time.Time) error })
	if canPoll {
		defer deadliner.SetDeadline(time.Time{})
	}
	var retry time.Duration
	for ctx.Err() == nil {
		if canPoll {
			deadliner.SetDeadline(time.Now().Add(catchAcceptPoll))
		}
		raw, err := ln.Accept()
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout():
				continue
			case ctx.Err() != nil:
				return
			case errors.Is(err, net.ErrClosed):
				c.err = err
				close(c.dead)
				return
			}
			// Anything else, such as running out of file descriptors,
			// passes: wait and accept again, as ternr does.
			retry = AcceptRetryDelay(retry)
			slog.Warn("accept failed; retrying", "err", err, "in", retry)
			select {
			case <-time.After(retry):
			case <-ctx.Done():
				return
			}
			continue
		}
		retry = 0
		// Each registration gets its own goroutine, so a peer that is slow or
		// silent during the handshake cannot delay the real agent; the
		// limiter places it first, as in Agent.serveListener.
		t := lim.enter(raw)
		if t == nil {
			raw.Close()
			continue
		}
		go c.register(ctx, raw, serverTLS, certFP, relayToken, wantID, t)
	}
}

// register runs the relay hello for one connection, once t, its place under
// the limiter, holds a slot, and holds it if it is the wanted agent;
// firstRecordTimeout, handshakeTimeout and ctx bound the hello.
func (c *Catcher) register(ctx context.Context, raw net.Conn, serverTLS *tls.Config, certFP []byte, relayToken, wantID string, t *preAuthTicket) {
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if !t.wait() {
		raw.Close()
		return
	}
	first, err := t.awaitFirstRecord(raw, false)
	if err != nil {
		t.done()
		raw.Close()
		return
	}
	conn := tls.Server(first, serverTLS)
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	role, id, herr := relayReadHello(conn, relayToken, certFP)
	t.done() // the unauthenticated part is over
	if herr != nil || role != RoleAgent || (wantID != "" && id != wantID) {
		conn.Write([]byte{relayDeny})
		conn.Close()
		return
	}
	if _, err := conn.Write([]byte{relayOK}); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // registered: it may wait any time to be paired
	slog.Debug("agent registered", "id", id, "remote", raw.RemoteAddr().String())
	// Hold the newest: when full, an older registration is likelier dead.
	for {
		select {
		case c.held <- conn:
			return
		default:
		}
		select {
		case old := <-c.held:
			old.Close() // the agent behind it registers again
		default:
		}
	}
}

// Catch pairs a held registration, waiting for one if none is held, and
// dials the agent through it, pinning agentFP and authenticating with keyFile
// or token; the auth is end-to-end with the agent. A registration that fails
// is dropped and the next one is tried.
func (c *Catcher) Catch(ctx context.Context, agentFP, keyFile, token string, insecure, skipEnc bool) (*Client, error) {
	innerTLS := ClientTLSConfig(agentFP, insecure)
	if skipEnc {
		innerTLS = nil // plaintext end-to-end; the agent must also skip encryption
	}
	for {
		var conn net.Conn
		select {
		case conn = <-c.held:
		case <-c.dead:
			return nil, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if _, err := conn.Write([]byte{relayPaired}); err != nil {
			conn.Close() // the agent left while it waited
			continue
		}
		conn.SetDeadline(time.Now().Add(handshakeTimeout))
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		cl, err := Dial(conn, innerTLS, keyFile, token)
		stop()
		if err != nil {
			conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			slog.Warn("caught agent but dial failed", "err", err)
			continue
		}
		conn.SetDeadline(time.Time{})
		return cl, nil
	}
}

// RelayDialAgent registers this agent with the relay under id and blocks until a
// client is paired (or ctx is cancelled). The returned conn is the transport to
// hand to Agent.Serve. A registration the relay asks to renew is made again.
func RelayDialAgent(ctx context.Context, relayAddr, relayFP, relayToken, id string, insecure bool) (net.Conn, error) {
	for {
		// insecure (from the agent's --insecure-dangerous) skips verifying the
		// relay when no relay fingerprint is given (see ClientTLSConfig); it is
		// off by default so the agent pins the relay.
		outer, resp, err := relayConnect(ctx, relayAddr, relayFP, relayToken, RoleAgent, id, insecure)
		if err != nil {
			return nil, err
		}
		if resp == relayBusy {
			outer.Close()
			return nil, errors.New("the relay is full; it refused the registration")
		}
		if resp != relayOK {
			outer.Close()
			return nil, errors.New("relay rejected agent registration (bad relay token, or rtern is waiting for a different --id?)")
		}
		registered := time.Now()
		// Unblock the wait-for-pairing read if ctx is cancelled.
		stop := context.AfterFunc(ctx, func() { outer.Close() })
		var p [1]byte
		_, rerr := io.ReadFull(outer, p[:])
		if !stop() { // ctx fired: outer is closed
			return nil, ctx.Err()
		}
		if rerr != nil {
			outer.Close()
			return nil, fmt.Errorf("registration dropped: %w", rerr)
		}
		switch p[0] {
		case relayPaired:
			return outer, nil
		case relayRenew:
			outer.Close()
			slog.Debug("the relay asked to register again", "relay", relayAddr)
			if wait := relayRenewMin - time.Since(registered); wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		default:
			outer.Close()
			return nil, errors.New("unexpected relay signal")
		}
	}
}
