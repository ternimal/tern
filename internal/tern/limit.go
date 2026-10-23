// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"cmp"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

// PreAuthLimiter caps the unauthenticated handshakes in flight on a listener
// anyone may reach. A source, an IPv4 address or an IPv6 /64, holds at most
// maxPreAuthPerSource of them, and the /56 and /48 around an IPv6 source a few
// sources' worth, since one party often holds a whole IPv6 prefix. A
// connection over its source's cap takes the place of that source's
// handshake whose peer has sent nothing for longest since the agent began
// to read from it, once that is silentGrace (see silentOf); with none such,
// it waits a little for one of that source's slots, so a burst from one
// client, such as a REST gateway starting many jobs, is served rather than
// refused; past the waiting room it is closed at once. Over its source's
// cap a newcomer never takes the place of a handshake under way from its
// own source, one whose ClientHello has begun to come, however fast they
// come; a full listener or a full prefix makes room by the rules below.
//
// A full listener never turns a newcomer away, so peers flooding it can only
// push each other out, never lock the others out: it closes another
// handshake to make room, the oldest of the source holding the most within
// the address block holding the most at every level above it (see
// partyTree), so that a peer with many addresses in one block weighs as one,
// unless one has sent nothing for silentGrace, which goes first. Every
// admission costs a few heap steps however full the listener is, and an
// accept loop takes it before it starts the connection's goroutine (enter),
// so a listener never holds more connections than the limiter has places
// for, however fast they come.
type PreAuthLimiter struct {
	max     int              // the cap on handshakes in flight in all; 0 means preAuthMax
	waitMax int              // the cap on connections waiting in all; 0 means preAuthWaitMax
	grace   time.Duration    // 0 means silentGrace
	clock   func() time.Time // nil means time.Now; tests step it, as some clocks tick too coarsely to tell a tight loop's entries apart

	mu      sync.Mutex
	groups  map[string]*preAuthGroup // sources, and the IPv6 prefixes above them
	flight  partyTree[*preAuthSlot]  // handshakes in flight
	total   int                      // handshakes in flight
	waiting int                      // connections waiting for a slot
	seq     uint64                   // admissions so far, which order handshakes by age
}

// preAuthGroup is what one source, or one IPv6 prefix, holds.
type preAuthGroup struct {
	held    int              // handshakes in flight
	waiters []*preAuthWaiter // for a source: connections waiting for one of its slots, in order
}

// preAuthSlot is one handshake in flight.
type preAuthSlot struct {
	entry partyEntry[*preAuthSlot]
	conn  net.Conn
	path  []string      // its address blocks, widest first
	keys  []string      // its groups: its source, then for IPv6 its /56 and /48
	freed bool          // given back, or taken by a newcomer
	cut   chan struct{} // closed when a newcomer takes it (see preAuthTicket.cut)
	// reading is when the connection's goroutine began to read the
	// ClientHello, zero until then (see preAuthTicket.reading); spoke, that
	// some of it has come (see preAuthTicket.spoke).
	reading time.Time
	spoke   bool
}

type preAuthWaiter struct {
	conn net.Conn
	slot chan *preAuthSlot // the slot handed over to it
}

// preAuthTicket is a connection's place under a PreAuthLimiter: a handshake
// slot, or a place in its source's waiting room until wait has it served.
type preAuthTicket struct {
	l          *PreAuthLimiter
	path, keys []string
	src        *preAuthGroup  // the source whose waiting room it is in, if any
	w          *preAuthWaiter // its place there
	s          *preAuthSlot   // its slot, once it has one
}

// preAuthPrefixCaps caps an IPv6 source's /56 and /48.
var preAuthPrefixCaps = [...]int{maxPreAuthPer56, maxPreAuthPer48}

// preAuthMax caps the handshakes in flight on one listener and preAuthWaitMax
// the connections waiting for a slot.
var preAuthMax, preAuthWaitMax = preAuthCaps(fdLimit())

// preAuthCaps sizes the caps on handshakes in flight and on connections
// waiting for a slot for a file descriptor limit: a quarter and an eighth of
// it, at most 4096 and maxPreAuthWaitingTotal, so that both together leave
// most descriptors to authenticated sessions and what they open.
func preAuthCaps(limit uint64) (held, wait int) {
	return fdShare(limit, 4, 16, 4096), fdShare(limit, 8, 8, maxPreAuthWaitingTotal)
}

// fdShare is a 1/div share of a file descriptor limit, but at least lo and
// at most hi.
func fdShare(limit, div, lo, hi uint64) int {
	return int(min(max(limit/div, lo), hi))
}

// Admit takes a handshake slot for conn, waiting up to preAuthWait when its
// source has none free, and returns the function that gives the slot back
// once the handshake is over, or false when conn should be closed. While the
// handshake runs, a newcomer may take its slot; the limiter then closes conn,
// and closes cut, so that a handshake waiting on anything but conn stops (see
// Agent.ServeAdmitted). An accept loop uses enter instead, which never waits.
func (l *PreAuthLimiter) Admit(conn net.Conn) (done func(), cut <-chan struct{}, ok bool) {
	t := l.enter(conn)
	if t == nil || !t.wait() {
		return nil, nil, false
	}
	return t.done, t.cut(), true
}

// enter decides at once what becomes of conn: it takes a handshake slot,
// first closing another handshake when it needs the room, or a place in its
// source's waiting room, or it is refused (nil) because that waiting room or
// the listener's is full. It never waits, so an accept loop calls it before
// it starts conn's goroutine, and so cannot hold more connections than the
// limiter has places for, however fast they come.
func (l *PreAuthLimiter) enter(conn net.Conn) *preAuthTicket {
	path := addrPath(conn.RemoteAddr())
	t := &preAuthTicket{l: l, path: path, keys: capKeys(path)}
	l.mu.Lock()
	if l.groups == nil {
		l.groups = map[string]*preAuthGroup{}
	}
	if src := l.groups[t.keys[0]]; src != nil && src.held >= maxPreAuthPerSource {
		// Over its source's cap: take the place of one of the source's
		// handshakes that has sent nothing for the grace, if there is one.
		// The source, and so every block and cap it counts in, holds as many
		// as before, so no total moves.
		now := l.now()
		if e := l.silentOf(t.keys[0], now); e != nil {
			evicted := l.evict(e)
			t.s = l.hold(conn, path, t.keys, now)
			l.mu.Unlock()
			evicted.Close()
			return t
		}
		defer l.mu.Unlock()
		if len(src.waiters) >= maxPreAuthWaiting || l.waiting >= l.waitCap() {
			return nil
		}
		t.src, t.w = src, &preAuthWaiter{conn: conn, slot: make(chan *preAuthSlot, 1)}
		src.waiters = append(src.waiters, t.w)
		l.waiting++
		return t
	}
	now := l.now()
	evicted := l.makeRoom(t.keys, now)
	t.s = l.hold(conn, path, t.keys, now)
	l.mu.Unlock()
	if evicted != nil {
		evicted.Close()
	}
	return t
}

// wait waits, when t is in a waiting room, up to preAuthWait for one of its
// source's slots, and reports whether t holds a slot.
func (t *preAuthTicket) wait() bool {
	w := t.w
	if w == nil {
		return t.s != nil
	}
	t.w = nil
	timer := time.NewTimer(preAuthWait)
	defer timer.Stop()
	select {
	case t.s = <-w.slot:
		return true
	case <-timer.C:
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case t.s = <-w.slot: // handed one just as the wait ran out
		return true
	default:
	}
	t.src.waiters = slices.DeleteFunc(t.src.waiters, func(o *preAuthWaiter) bool { return o == w })
	l.waiting--
	l.forget(t.keys)
	return false
}

// cut returns a channel closed once a newcomer takes t's slot, as the
// limiter closes its connection: a handshake waiting on anything but the
// connection, such as a place in a signature check queue (see checkSig),
// so stops at once, and the limiter's caps bound those waits too. It is nil,
// never closed, while t holds no slot.
func (t *preAuthTicket) cut() <-chan struct{} {
	if t.s == nil {
		return nil
	}
	return t.s.cut
}

// reading records that the goroutine serving t's connection begins to read
// the peer's ClientHello. Only from then on does the peer's silence count
// when a newcomer from its source needs a slot (see silentOf): a handshake
// whose goroutine has not run yet, on a busy agent or just after it was
// handed a waiter's slot, may have its whole ClientHello waiting in the
// socket, unread.
func (t *preAuthTicket) reading() {
	s := t.s
	if s == nil {
		return
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if !s.freed && s.reading.IsZero() {
		s.reading = l.now()
	}
}

// spoke records that the first bytes of the peer's ClientHello came, so a
// newcomer from its source no longer takes its slot (see silentOf): tern's
// own ClientHello is too long for one TCP segment, and on a slow or lossy
// link its rest may come a retransmission later. Reading the rest is still
// bounded by firstRecordTimeout.
func (t *preAuthTicket) spoke() {
	s := t.s
	if s == nil {
		return
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if !s.freed {
		s.spoke = true
	}
}

// started records that t's peer started its handshake: its ClientHello
// arrived, so it is no longer among the silent ones a full listener, or a
// newcomer from its own source, closes first.
func (t *preAuthTicket) started() {
	s := t.s
	if s == nil {
		return
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if !s.freed {
		l.flight.heard(&s.entry)
	}
}

// done gives t's slot back once the handshake is over, passed or failed. It
// is safe to call more than once, and after a newcomer took the slot. A
// connection waiting on the slot's source takes it over in place, so the
// totals never move and nothing can slip in between to push them past a cap.
func (t *preAuthTicket) done() {
	s := t.s
	if s == nil {
		return
	}
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if s.freed {
		return
	}
	l.unhold(s)
	if src := l.groups[s.keys[0]]; src != nil && len(src.waiters) > 0 {
		w := src.waiters[0]
		src.waiters = src.waiters[1:]
		l.waiting--
		w.slot <- l.hold(w.conn, s.path, s.keys, l.now()) // the same source, so the same blocks
		return
	}
	l.forget(s.keys)
}

// makeRoom takes a slot away from a handshake when admitting one more with
// keys would pass a cap other than its source's: one in its own /56 or /48
// when that prefix is full, else, on a full listener, anyone's, the one
// partyTree.victim picks. It returns the evicted handshake's conn, for the
// caller to close. l.mu is held.
func (l *PreAuthLimiter) makeRoom(keys []string, now time.Time) net.Conn {
	grace := cmp.Or(l.grace, silentGrace)
	for i, k := range keys[1:] {
		if g := l.groups[k]; g != nil && g.held >= preAuthPrefixCaps[i] {
			return l.evict(l.flight.victim(l.flight.nodes[k], grace, now))
		}
	}
	if l.total < l.totalCap() {
		return nil
	}
	return l.evict(l.flight.victim(&l.flight.root, grace, now))
}

// silentOf returns the handshake of the source key whose peer has sent
// nothing for longest since its goroutine began to read (see
// preAuthTicket.reading), if that is at least the grace, or nil. Behind a
// proxy, or on a loopback address, every peer shares one source, and a peer
// that only opens connections and sends nothing would otherwise keep every
// other waiting for that source's slots. A handshake whose ClientHello has
// begun to come is never chosen (see preAuthTicket.spoke): a source that
// connects again and again closes only its own connections that do nothing,
// not a client's that is under way; nor is one whose ClientHello the agent
// has not begun to read. A source holds at most maxPreAuthPerSource
// handshakes. l.mu is held.
func (l *PreAuthLimiter) silentOf(key string, now time.Time) *partyEntry[*preAuthSlot] {
	nd := l.flight.nodes[key]
	if nd == nil {
		return nil
	}
	grace := cmp.Or(l.grace, silentGrace)
	var silent *partyEntry[*preAuthSlot]
	for e := nd.first; e != nil; e = e.next[nd.level] {
		s := e.val
		if e.quiet && !s.spoke && !s.reading.IsZero() && now.Sub(s.reading) >= grace &&
			(silent == nil || s.reading.Before(silent.val.reading)) {
			silent = e
		}
	}
	return silent
}

func (l *PreAuthLimiter) now() time.Time {
	if l.clock != nil {
		return l.clock()
	}
	return time.Now()
}

// totalCap is the most handshakes l lets be in flight at once.
func (l *PreAuthLimiter) totalCap() int {
	if l.max > 0 {
		return l.max
	}
	return preAuthMax
}

// waitCap is the most connections l lets wait for a slot at once.
func (l *PreAuthLimiter) waitCap() int {
	if l.waitMax > 0 {
		return l.waitMax
	}
	return preAuthWaitMax
}

// hold records a handshake in flight for conn, whose peer has sent nothing
// yet; l.mu is held.
func (l *PreAuthLimiter) hold(conn net.Conn, path, keys []string, now time.Time) *preAuthSlot {
	s := &preAuthSlot{conn: conn, path: path, keys: keys, cut: make(chan struct{})}
	s.entry.val = s
	l.seq++
	l.flight.add(&s.entry, path, l.seq, true, now)
	for _, k := range keys {
		g := l.groups[k]
		if g == nil {
			g = &preAuthGroup{}
			l.groups[k] = g
		}
		g.held++
	}
	l.total++
	return s
}

// unhold drops s from the books; l.mu is held.
func (l *PreAuthLimiter) unhold(s *preAuthSlot) {
	s.freed = true
	l.flight.remove(&s.entry)
	for _, k := range s.keys {
		if g := l.groups[k]; g != nil {
			g.held--
		}
	}
	l.total--
}

// evict takes the slot of e's handshake away, closing its cut, and returns
// its conn, or nil for no e; l.mu is held.
func (l *PreAuthLimiter) evict(e *partyEntry[*preAuthSlot]) net.Conn {
	if e == nil {
		return nil
	}
	s := e.val
	l.unhold(s)
	l.forget(s.keys)
	close(s.cut) // once: a slot taken is out of the tree, and done leaves it be
	return s.conn
}

// forget drops the groups of keys that hold and wait for nothing; l.mu is
// held.
func (l *PreAuthLimiter) forget(keys []string) {
	for _, k := range keys {
		if g := l.groups[k]; g != nil && g.held == 0 && len(g.waiters) == 0 {
			delete(l.groups, k)
		}
	}
}

// TLS record framing, for AwaitFirstRecord.
const (
	tlsRecordHeader     = 5
	tlsRecordHandshake  = 22
	tlsHandshakeHeader  = 4 // a handshake message's type and 24-bit length
	tlsClientHello      = 1 // its type
	maxTLSRecordPayload = 1 << 14
	// maxHelloRecords is the most records a ClientHello may be split over.
	// tern's client sends it in one; RFC 8446 lets a client split it, as
	// some TLS stacks and proxies do, mostly in two or three.
	maxHelloRecords = 32
)

// AwaitFirstRecord waits up to firstRecordTimeout for the TLS records that
// hold a peer's whole ClientHello, at most 16 KiB of it in at most
// maxHelloRecords records, or with plain for its first byte, and returns a
// conn that reads them again first. A peer that connects and then stays
// silent, or sends part of a ClientHello and stalls, so gives its handshake
// slot back in seconds, not at the handshake timeout; until its ClientHello
// is in, a full listener counts its handshake as one that has sent nothing
// (see preAuthTicket.started). conn's read deadline is cleared.
func AwaitFirstRecord(conn net.Conn, plain bool) (net.Conn, error) {
	return awaitFirstRecord(conn, plain, firstRecordTimeout, nil)
}

// awaitFirstRecord is AwaitFirstRecord for t's connection, keeping t's
// books as it reads: it records when its goroutine begins to read (see
// reading), when the first bytes come (see spoke) and, once the ClientHello
// is in, that its handshake started (see started).
func (t *preAuthTicket) awaitFirstRecord(conn net.Conn, plain bool) (net.Conn, error) {
	t.reading()
	c, err := awaitFirstRecord(conn, plain, firstRecordTimeout, t.spoke)
	if err == nil {
		t.started()
	}
	return c, err
}

// awaitFirstRecord is AwaitFirstRecord with its timeout; it calls spoke, if
// not nil, once the first bytes come.
func awaitFirstRecord(conn net.Conn, plain bool, timeout time.Duration, spoke func()) (net.Conn, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var r io.Reader = conn
	if spoke != nil {
		r = &firstBytes{r: conn, spoke: spoke}
	}
	var buf []byte
	if plain {
		buf = make([]byte, 1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
	} else {
		var err error
		if buf, err = readClientHello(r); err != nil {
			return nil, err
		}
	}
	conn.SetReadDeadline(time.Time{})
	return &replayConn{Conn: conn, pending: buf}, nil
}

// firstBytes reads from r, calling spoke once a read returns any bytes.
type firstBytes struct {
	r     io.Reader
	spoke func()
}

func (f *firstBytes) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if n > 0 && f.spoke != nil {
		f.spoke()
		f.spoke = nil
	}
	return n, err
}

// readClientHello reads the TLS records that carry a whole ClientHello from
// r and returns them as read. The first must be a handshake record and the
// message in it a ClientHello; the rest of it may come in more handshake
// records, none of them empty, as long as they carry at most
// maxTLSRecordPayload bytes in all, as one record at most could.
func readClientHello(r io.Reader) ([]byte, error) {
	var raw, hello []byte // the records as read; the handshake bytes they carry
	need := tlsHandshakeHeader
	for records := 0; len(hello) < need; records++ {
		if records == maxHelloRecords {
			return nil, errors.New("the peer split its ClientHello over too many records")
		}
		start := len(raw)
		raw = append(raw, make([]byte, tlsRecordHeader)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return nil, err
		}
		hdr := raw[start:]
		size := int(binary.BigEndian.Uint16(hdr[3:]))
		switch {
		case records == 0 && (hdr[0] != tlsRecordHandshake || size == 0 || size > maxTLSRecordPayload):
			return nil, errors.New("the peer did not start a TLS handshake")
		case hdr[0] != tlsRecordHandshake || size == 0:
			return nil, errors.New("the rest of the peer's ClientHello is not in the records that follow it")
		case len(hello)+size > maxTLSRecordPayload:
			return nil, errors.New("the peer's ClientHello is too long")
		}
		start = len(raw)
		raw = append(raw, make([]byte, size)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return nil, err
		}
		hello = append(hello, raw[start:]...)
		if hello[0] != tlsClientHello {
			return nil, errors.New("the peer's first handshake message is not a ClientHello")
		}
		if len(hello) >= tlsHandshakeHeader {
			need = tlsHandshakeHeader + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
			if need > maxTLSRecordPayload {
				return nil, errors.New("the peer's ClientHello is too long")
			}
		}
	}
	return raw, nil
}

// replayConn reads pending before what is left on its Conn.
type replayConn struct {
	net.Conn
	pending []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
