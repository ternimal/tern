// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// addrConn is a connection that only knows its remote address, and whether it
// was closed.
type addrConn struct {
	net.Conn
	addr   net.Addr
	closed atomic.Bool
}

func (c *addrConn) RemoteAddr() net.Addr { return c.addr }
func (c *addrConn) Close() error         { c.closed.Store(true); return nil }

func from(s string) *addrConn {
	return &addrConn{addr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s))}
}

// steppingClock is a clock that moves on a millisecond each time it is read,
// so that connections entered in a tight loop have distinct, growing ages
// even where the system clock ticks too coarsely to tell them apart.
func steppingClock() func() time.Time {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Millisecond)
		return now
	}
}

// books reports what l holds: handshakes, waiting connections and groups.
func (l *PreAuthLimiter) books() (total, waiting, groups int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, l.waiting, len(l.groups)
}

// held reports how many handshakes the group key holds.
func (l *PreAuthLimiter) held(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if g := l.groups[key]; g != nil {
		return g.held
	}
	return 0
}

func TestPreAuthLimiterPerSource(t *testing.T) {
	l := PreAuthLimiter{grace: time.Hour} // handshakes under way: none silent for long
	var dones []func()
	for i := range maxPreAuthPerSource {
		done, _, ok := l.Admit(from(fmt.Sprintf("192.0.2.1:%d", 1000+i)))
		if !ok {
			t.Fatalf("handshake %d from one source refused under its cap", i)
		}
		dones = append(dones, done)
	}
	// Over its source's cap, a connection waits for a slot...
	got := make(chan func(), 1)
	go func() {
		d, _, ok := l.Admit(from("[::ffff:192.0.2.1]:9999")) // the same source, IPv4-mapped
		if !ok {
			d = nil
		}
		got <- d
	}()
	// ...while another source goes straight in.
	start := time.Now()
	d2, _, ok := l.Admit(from("192.0.2.2:1000"))
	if !ok || time.Since(start) > time.Second {
		t.Fatal("another source was held up by a full one")
	}
	d2()
	d2() // a second call must not free a slot it does not hold
	select {
	case <-got:
		t.Fatal("admitted with no slot free")
	case <-time.After(200 * time.Millisecond):
	}
	dones[0]()
	select {
	case d := <-got:
		if d == nil {
			t.Fatal("a waiting connection was refused when a slot came free")
		}
		d()
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting connection did not get the freed slot")
	}
	for _, d := range dones[1:] {
		d()
	}
	if total, waiting, groups := l.books(); total != 0 || waiting != 0 || groups != 0 {
		t.Fatalf("slots leaked: total %d, waiting %d, groups %d", total, waiting, groups)
	}
}

// Past the waiting room, a connection is closed at once.
func TestPreAuthLimiterWaitingRoom(t *testing.T) {
	l := PreAuthLimiter{grace: time.Hour} // handshakes under way: none silent for long
	var dones []func()
	for i := range maxPreAuthPerSource {
		d, _, _ := l.Admit(from(fmt.Sprintf("192.0.2.1:%d", 1000+i)))
		dones = append(dones, d)
	}
	finished := make(chan bool, maxPreAuthWaiting)
	for i := range maxPreAuthWaiting {
		go func() {
			d, _, ok := l.Admit(from(fmt.Sprintf("192.0.2.1:%d", 2000+i)))
			if ok {
				d()
			}
			finished <- ok
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		_, w, _ := l.books()
		if w == maxPreAuthWaiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d waiting, want %d", w, maxPreAuthWaiting)
		}
	}
	start := time.Now()
	if _, _, ok := l.Admit(from("192.0.2.1:9999")); ok || time.Since(start) > time.Second {
		t.Fatal("a connection past the waiting room was not refused at once")
	}
	for _, d := range dones {
		d()
	}
	for range maxPreAuthWaiting {
		if !<-finished {
			t.Fatal("a waiting connection was refused while slots came free")
		}
	}
}

// handClock is a clock a test moves by hand.
type handClock struct {
	mu  sync.Mutex
	now time.Time
}

func newHandClock() *handClock { return &handClock{now: time.Unix(1_700_000_000, 0)} }

func (c *handClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *handClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Over its source's cap, a newcomer takes the place of the handshake of that
// source whose peer has sent nothing for longest since the agent began to
// read from it, once that is the grace, at once: behind a proxy, or on a
// loopback address, every client shares one source, and connections that
// only sit there would otherwise keep every client waiting. The newcomers do
// not get the places of handshakes under way, so a source that connects
// again and again closes only its own idle connections; once none is silent
// for long, a newcomer waits for a slot.
func TestPreAuthLimiterSourceSilentGiveWay(t *testing.T) {
	const grace = 20 * time.Millisecond
	clk := newHandClock()
	l := &PreAuthLimiter{max: 1024, waitMax: 1024, grace: grace, clock: clk.read}
	const silent = 10
	var held []*addrConn
	for i := range maxPreAuthPerSource {
		c := from(fmt.Sprintf("192.0.2.1:%d", 1000+i))
		tk := l.enter(c)
		if tk == nil || tk.s == nil {
			t.Fatalf("handshake %d refused under its source's cap", i)
		}
		tk.reading()
		if i >= silent {
			tk.started()
		}
		held = append(held, c)
		clk.add(time.Millisecond) // the first are the longest silent
	}
	other := from("192.0.2.2:1000")
	l.enter(other).reading()
	clk.add(grace)
	var newcomers []*preAuthTicket
	for i := range silent {
		tk := l.enter(from(fmt.Sprintf("192.0.2.1:%d", 2000+i)))
		if tk == nil || tk.s == nil {
			t.Fatalf("newcomer %d did not take a silent handshake's place at once", i)
		}
		if !held[i].closed.Load() {
			t.Errorf("newcomer %d did not take the place of the longest silent handshake", i)
		}
		tk.reading()
		newcomers = append(newcomers, tk)
	}
	for i, c := range held[silent:] {
		if c.closed.Load() {
			t.Errorf("handshake %d, under way, was closed for a newcomer of its source", silent+i)
		}
	}
	if other.closed.Load() {
		t.Error("another source's handshake was closed")
	}
	if total, waiting, _ := l.books(); total != maxPreAuthPerSource+1 || waiting != 0 {
		t.Errorf("total %d, waiting %d; want %d and 0", total, waiting, maxPreAuthPerSource+1)
	}
	// The newcomers have not been silent for the grace yet: the next one
	// waits for a slot rather than closing one of them.
	clk.add(grace - time.Millisecond)
	tk := l.enter(from("192.0.2.1:3000"))
	if tk == nil || tk.s != nil || tk.w == nil {
		t.Fatal("a newcomer with no handshake of its source silent for long did not wait")
	}
	for _, nt := range newcomers {
		if nt.s.conn.(*addrConn).closed.Load() {
			t.Error("a handshake silent for less than the grace was closed")
		}
	}
	l.checkBooks(t)
}

// A handshake whose ClientHello the agent has not begun to read is never
// closed for a newcomer of its source, however long ago it got its slot: on
// a busy agent, or when a waiter has just been handed a slot, its whole
// ClientHello may be waiting in the socket, unread. Its silence counts from
// when its goroutine begins to read, and not at all once part of its
// ClientHello has come: the rest of a ClientHello too long for one TCP
// segment may come a retransmission later.
func TestPreAuthLimiterSourceSilenceCountsFromReading(t *testing.T) {
	const grace = 20 * time.Millisecond
	clk := newHandClock()
	l := &PreAuthLimiter{max: 1024, waitMax: 1024, grace: grace, clock: clk.read}
	var tks []*preAuthTicket
	for i := range maxPreAuthPerSource {
		tks = append(tks, l.enter(from(fmt.Sprintf("192.0.2.1:%d", 1000+i))))
	}
	waiter := l.enter(from("192.0.2.1:2000"))
	if waiter == nil || waiter.w == nil {
		t.Fatal("a connection over its source's cap did not wait")
	}
	clk.add(time.Hour)
	tks[0].done() // the waiter is handed the slot; its goroutine has not run yet
	if !waiter.wait() {
		t.Fatal("the waiter was not handed the slot given back")
	}
	clk.add(time.Hour)
	if nt := l.enter(from("192.0.2.1:3000")); nt == nil || nt.s != nil {
		t.Fatal("a newcomer took the slot of a handshake the agent had not begun to read")
	}
	// The one handed the slot begins to read, another too, and the first
	// bytes of the other's ClientHello come.
	waiter.reading()
	tks[1].reading()
	tks[1].spoke()
	clk.add(grace - time.Millisecond)
	if nt := l.enter(from("192.0.2.1:3001")); nt == nil || nt.s != nil {
		t.Fatal("a newcomer took the slot of a handshake read from for less than the grace")
	}
	clk.add(time.Millisecond)
	nt := l.enter(from("192.0.2.1:3002"))
	if nt == nil || nt.s == nil {
		t.Fatal("a newcomer did not take the slot of a handshake silent for the grace since it was read from")
	}
	if !waiter.s.freed || tks[1].s.freed {
		t.Fatal("the newcomer took another slot than the silent one's")
	}
	clk.add(time.Hour)
	if nt := l.enter(from("192.0.2.1:3003")); nt == nil || nt.s != nil {
		t.Fatal("a newcomer took the slot of a handshake whose ClientHello had begun to come")
	}
	for i, tk := range tks[1:] {
		if tk.s.conn.(*addrConn).closed.Load() {
			t.Fatalf("handshake %d, not silent since it was read from, was closed", 1+i)
		}
	}
	l.checkBooks(t)
}

// However many newcomers a source sends, none of them closes one of that
// source's handshakes whose ClientHello is in: past the waiting room they are
// refused, as any connection is, and the handshakes under way go on.
func TestPreAuthLimiterSourceSparesHandshakesUnderWay(t *testing.T) {
	l := &PreAuthLimiter{max: 1024, waitMax: 1024, grace: time.Nanosecond, clock: steppingClock()}
	var held []*addrConn
	for i := range maxPreAuthPerSource {
		c := from(fmt.Sprintf("192.0.2.1:%d", 1000+i))
		l.enter(c).started()
		held = append(held, c)
	}
	waited, refused := 0, 0
	for i := range 2000 {
		switch tk := l.enter(from(fmt.Sprintf("192.0.2.1:%d", 5000+i))); {
		case tk == nil:
			refused++
		case tk.s != nil:
			t.Fatalf("newcomer %d took a slot from a source whose handshakes are all under way", i)
		default:
			waited++
		}
	}
	for i, c := range held {
		if c.closed.Load() {
			t.Fatalf("handshake %d, under way, was closed for a newcomer of its source", i)
		}
	}
	if waited != maxPreAuthWaiting || refused != 2000-maxPreAuthWaiting {
		t.Errorf("%d waited and %d were refused; want %d and %d", waited, refused, maxPreAuthWaiting, 2000-maxPreAuthWaiting)
	}
	l.checkBooks(t)
}

func TestPreAuthLimiterIPv6Prefix(t *testing.T) {
	var l PreAuthLimiter
	for i := range 8 {
		l.Admit(from(fmt.Sprintf("[2001:db8::%x]:443", i+1)))
	}
	l.Admit(from("[2001:db8:0:1::1]:443"))
	if a, b := l.held("2001:db8::/64"), l.held("2001:db8:0:1::/64"); a != 8 || b != 1 {
		t.Fatalf("one source per /64: got %d and %d, want 8 and 1", a, b)
	}
	if n := l.held("2001:db8::/48"); n != 9 {
		t.Fatalf("the /48 holds %d, want 9", n)
	}
}

// One party with a whole IPv6 prefix is held to a few sources' worth: past
// its /56's or /48's cap, a newcomer from it takes the place of that
// prefix's oldest handshake, and no one else's.
func TestPreAuthLimiterIPv6Aggregates(t *testing.T) {
	var l PreAuthLimiter
	bystander := from("192.0.2.7:1")
	l.Admit(bystander)
	var party []*addrConn
	// 16 /64s in one /48, four in each of four /56s, 64 handshakes each.
	for s := range 16 {
		for i := range maxPreAuthPerSource {
			c := from(fmt.Sprintf("[2001:db8:7:%x%02x::1]:%d", s/4, s%4, 1000+i))
			if _, _, ok := l.Admit(c); !ok {
				t.Fatalf("source %d handshake %d refused", s, i)
			}
			party = append(party, c)
		}
	}
	for s := range 4 {
		if n := l.held(fmt.Sprintf("2001:db8:7:%x00::/56", s)); n > maxPreAuthPer56 {
			t.Errorf("/56 number %d holds %d, over its cap of %d", s, n, maxPreAuthPer56)
		}
	}
	if n := l.held("2001:db8:7::/48"); n != maxPreAuthPer48 {
		t.Errorf("the /48 holds %d, want its cap of %d", n, maxPreAuthPer48)
	}
	closed := 0
	for _, c := range party {
		if c.closed.Load() {
			closed++
		}
	}
	if want := len(party) - maxPreAuthPer48; closed != want {
		t.Errorf("%d of the party's handshakes were closed, want %d", closed, want)
	}
	if bystander.closed.Load() {
		t.Error("a party over its prefix's cap pushed out someone else's handshake")
	}
}

// A full listener still admits a newcomer at once: the oldest handshake of
// the party holding the most is closed to make room, and the total stays put.
func TestPreAuthLimiterTotal(t *testing.T) {
	// None of them silent for long, so the weight of each party decides.
	l := PreAuthLimiter{max: 8 * maxPreAuthPerSource, grace: time.Hour}
	early := from("192.0.2.50:1") // older than the flood, but light
	if _, _, ok := l.Admit(early); !ok {
		t.Fatal("refused on an empty listener")
	}
	var flood []*addrConn
	for n := range l.max - 1 {
		c := from(fmt.Sprintf("198.51.100.%d:%d", n/maxPreAuthPerSource, 1000+n%maxPreAuthPerSource))
		if _, _, ok := l.Admit(c); !ok {
			t.Fatalf("handshake %d refused under the total cap", n)
		}
		flood = append(flood, c)
	}
	// The flood's first seven sources hold 64 each and its last 63: each
	// newcomer takes the place of the oldest handshake among those holding 64.
	for i, src := range []string{"203.0.113.9:1", "203.0.113.10:1"} {
		start := time.Now()
		if _, _, ok := l.Admit(from(src)); !ok || time.Since(start) > time.Second {
			t.Fatalf("newcomer %d was not admitted at once to a full listener", i)
		}
		if victim := flood[i*maxPreAuthPerSource]; !victim.closed.Load() {
			t.Errorf("newcomer %d did not take the place of the oldest handshake of the heaviest party", i)
		}
	}
	closed := 0
	for _, c := range flood {
		if c.closed.Load() {
			closed++
		}
	}
	if closed != 2 || early.closed.Load() {
		t.Errorf("%d flood handshakes closed (want 2); the light early one closed: %v", closed, early.closed.Load())
	}
	if total, _, _ := l.books(); total != l.max {
		t.Fatalf("total %d, want %d", total, l.max)
	}
}

// The total never passes its cap: a slot freed at a full source goes to the
// connection waiting on it in place, so a newcomer arriving in between finds
// the listener still full and makes room instead of squeezing in.
func TestPreAuthLimiterNeverOvershoots(t *testing.T) {
	// Handshakes under way, none silent for long, so source A's newcomers
	// wait for its slots.
	l := PreAuthLimiter{max: maxPreAuthPerSource + maxPreAuthPer48, grace: time.Hour}
	var dones []func()
	for i := range maxPreAuthPerSource { // source A, full
		d, _, _ := l.Admit(from(fmt.Sprintf("192.0.2.1:%d", 1000+i)))
		dones = append(dones, d)
	}
	const waiters = 100
	got := make(chan func(), waiters)
	for i := range waiters {
		go func() {
			d, _, ok := l.Admit(from(fmt.Sprintf("192.0.2.1:%d", 5000+i)))
			if !ok {
				d = nil
			}
			got <- d
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, w, _ := l.books(); w == waiters {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the waiters did not queue")
		}
	}
	// A heavier party, a /48, fills the rest, so newcomers take its places.
	for s := range 4 {
		for i := range maxPreAuthPerSource {
			d, _, ok := l.Admit(from(fmt.Sprintf("[2001:db8:1:%x%02x::1]:%d", s/2, s%2, 1000+i)))
			if !ok {
				t.Fatal("the /48 was refused")
			}
			dones = append(dones, d)
		}
	}
	if total, _, _ := l.books(); total != l.max {
		t.Fatalf("total %d, want the cap %d", total, l.max)
	}

	var peak atomic.Int64
	watch := func() {
		if total, _, _ := l.books(); int64(total) > peak.Load() {
			peak.Store(int64(total))
		}
	}
	stop := make(chan struct{})
	var hammer sync.WaitGroup
	var mu sync.Mutex
	var newcomers []func()
	for g := range 4 {
		hammer.Add(1)
		go func() {
			defer hammer.Done()
			for n := 0; n < 25; n++ {
				select {
				case <-stop:
					return
				default:
				}
				if d, _, ok := l.Admit(from(fmt.Sprintf("203.0.%d.%d:1", 113+g, n+1))); ok {
					mu.Lock()
					newcomers = append(newcomers, d)
					mu.Unlock()
				}
				watch()
			}
		}()
	}
	for _, d := range dones[:maxPreAuthPerSource] { // A's handshakes end, among newcomers
		d()
		watch()
		time.Sleep(time.Millisecond)
	}
	close(stop)
	hammer.Wait()
	if len(newcomers) == 0 {
		t.Fatal("no newcomer came in while A's handshakes ended")
	}
	// Each waiter that got a slot gives it back, which serves the next.
	for range waiters {
		select {
		case d := <-got:
			if d == nil {
				t.Fatal("a waiter was refused")
			}
			d()
			watch()
		case <-time.After(3 * time.Second):
			t.Fatal("a waiter was never served")
		}
	}
	if p := peak.Load(); p > int64(l.max) {
		t.Fatalf("the total reached %d, past its cap of %d", p, l.max)
	}
	for _, d := range dones[maxPreAuthPerSource:] {
		d()
	}
	for _, d := range newcomers {
		d()
	}
	if total, waiting, groups := l.books(); total != 0 || waiting != 0 || groups != 0 {
		t.Fatalf("slots leaked: total %d, waiting %d, groups %d", total, waiting, groups)
	}
}

// TestAwaitFirstRecord: a TLS handshake goes through the record read ahead
// of it untouched, while a peer that does not start one is let go quickly.
func TestAwaitFirstRecord(t *testing.T) {
	const timeout = 200 * time.Millisecond
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "srv"))
	if err != nil {
		t.Fatal(err)
	}

	sconn, cconn := loopbackPair(t)
	go func() {
		c := tls.Client(cconn, PinnedTLSConfig(CertFingerprint(cert)))
		if c.Handshake() == nil {
			c.Write([]byte("ping"))
		}
	}()
	first, err := AwaitFirstRecord(sconn, false)
	if err != nil {
		t.Fatalf("a ClientHello was not taken: %v", err)
	}
	srv := tls.Server(first, ServerTLSConfig(cert))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(srv, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("the handshake after the record read ahead failed: %q %v", buf, err)
	}
	srv.Close()

	for name, send := range map[string][]byte{"silent": nil, "half a header": {22, 3}} {
		sconn, cconn := loopbackPair(t)
		cconn.Write(send)
		start := time.Now()
		if _, err := awaitFirstRecord(sconn, false, timeout, nil); !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 2*time.Second {
			t.Errorf("%s: %v after %s, want a timeout after %s", name, err, time.Since(start), timeout)
		}
		sconn.Close()
		cconn.Close()
	}

	sconn, cconn = loopbackPair(t)
	defer sconn.Close()
	defer cconn.Close()
	cconn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	if _, err := awaitFirstRecord(sconn, false, timeout, nil); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a request that is not TLS was not refused at once: %v", err)
	}

	// Part of a ClientHello may be followed by the rest in more records, but
	// only until the first-record timeout: a peer that sends part and stalls
	// keeps its slot no longer than one that sends nothing.
	for name, record := range map[string][]byte{
		"a one-byte record":         {22, 3, 1, 0, 1, 1},
		"a sliver of a ClientHello": {22, 3, 1, 0, 6, 1, 0, 1, 0, 3, 3},
	} {
		sconn, cconn := loopbackPair(t)
		cconn.Write(record)
		start := time.Now()
		if _, err := awaitFirstRecord(sconn, false, timeout, nil); !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 2*time.Second {
			t.Errorf("%s: %v after %s, want a timeout after %s", name, err, time.Since(start), timeout)
		}
		sconn.Close()
		cconn.Close()
	}

	// What cannot become a ClientHello within bounds is refused at once.
	tooLong := append([]byte{22, 3, 1, 0, 4, 1, 0, 0x3f, 0xfc, 22, 3, 1, 0x3f, 0xfd}, make([]byte, 0x3ffd)...)
	var tooMany []byte
	tooMany = append(tooMany, 22, 3, 1, 0, 4, 1, 0, 0, 200)
	for range maxHelloRecords {
		tooMany = append(tooMany, 22, 3, 1, 0, 1, 0)
	}
	for name, records := range map[string][]byte{
		"a handshake message, not the hello":   {22, 3, 1, 0, 4, 2, 0, 0, 0},
		"a ClientHello said to pass 16 KiB":    {22, 3, 1, 0, 4, 1, 0, 0x40, 0x00},
		"records carrying more than 16 KiB":    tooLong,
		"an empty record after the first":      {22, 3, 1, 0, 1, 1, 22, 3, 1, 0, 0},
		"an alert after part of the hello":     {22, 3, 1, 0, 1, 1, 21, 3, 1, 0, 2, 2, 40},
		"more records than a hello may take":   tooMany,
		"a first record that is not handshake": {23, 3, 3, 0, 4, 1, 0, 0, 0},
	} {
		sconn, cconn := loopbackPair(t)
		go cconn.Write(records)
		start := time.Now()
		if _, err := awaitFirstRecord(sconn, false, 2*time.Second, nil); err == nil || errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > time.Second {
			t.Errorf("%s: %v after %s, want a refusal at once", name, err, time.Since(start))
		}
		sconn.Close()
		cconn.Close()
	}

	psrv, pcli := loopbackPair(t)
	defer psrv.Close()
	defer pcli.Close()
	pcli.Write([]byte{methodTokenHMAC})
	c, err := awaitFirstRecord(psrv, true, timeout, nil)
	if err != nil {
		t.Fatalf("a plaintext session's first byte was not taken: %v", err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != methodTokenHMAC {
		t.Errorf("the first byte was not read again: %v %v", b, err)
	}
}

// splitHello is a client connection that sends its first record, the
// ClientHello, split over n handshake records, as RFC 8446 allows, and with
// a delay the records after the first that much later, as over a slow or
// lossy link.
type splitHello struct {
	net.Conn
	n     int
	delay time.Duration
	sent  bool
}

func (c *splitHello) Write(p []byte) (int, error) {
	if c.sent || len(p) < tlsRecordHeader || p[0] != tlsRecordHandshake {
		return c.Conn.Write(p)
	}
	c.sent = true
	size := int(p[3])<<8 | int(p[4])
	body, rest := p[tlsRecordHeader:tlsRecordHeader+size], p[tlsRecordHeader+size:]
	var out []byte
	first := 0 // the length of the first record
	for i := range c.n {
		part := body[i*len(body)/c.n : (i+1)*len(body)/c.n]
		out = append(out, tlsRecordHandshake, p[1], p[2], byte(len(part)>>8), byte(len(part)))
		out = append(out, part...)
		if i == 0 {
			first = len(out)
		}
	}
	if c.delay > 0 {
		if _, err := c.Conn.Write(out[:first]); err != nil {
			return 0, err
		}
		time.Sleep(c.delay)
		out = out[first:]
	}
	if _, err := c.Conn.Write(append(out, rest...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// stalledHandshake is a client connection that sends what a TLS client
// writes, its ClientHello, and then reads nothing until it is closed: a
// handshake under way that holds its slot.
type stalledHandshake struct {
	net.Conn
	gone chan struct{}
	once sync.Once
}

func (c *stalledHandshake) Read([]byte) (int, error) { <-c.gone; return 0, net.ErrClosed }

func (c *stalledHandshake) Close() error {
	c.once.Do(func() { close(c.gone) })
	return c.Conn.Close()
}

// A client whose ClientHello is still coming, its first record read and the
// rest a retransmission later, is not closed for a newcomer of its own
// source past that source's cap, as one that sent nothing would be: the
// newcomer waits, and the client's handshake goes through.
func TestSameSourceNewcomerSparesClientHelloStillComing(t *testing.T) {
	a, fp := newTestAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lim := new(PreAuthLimiter)
	go a.serveListener(ctx, ln, lim)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for range maxPreAuthPerSource - 1 {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		sc := &stalledHandshake{Conn: raw, gone: make(chan struct{})}
		conns = append(conns, sc)
		go tls.Client(sc, PinnedTLSConfig(fp)).Handshake()
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		lim.mu.Lock()
		quiet := lim.flight.quiet != nil
		lim.mu.Unlock()
		if lim.held("127.0.0.1") == maxPreAuthPerSource-1 && !quiet {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the handshakes under way did not all start: %d held", lim.held("127.0.0.1"))
		}
	}
	const late = 300 * time.Millisecond
	res := make(chan error, 1)
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			res <- err
			return
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		cl, err := Dial(&splitHello{Conn: raw, n: 2, delay: late}, PinnedTLSConfig(fp), "", testToken)
		if err == nil {
			cl.Close()
		}
		res <- err
	}()
	time.Sleep(late / 3) // its first record is in, the rest is not
	newcomer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, newcomer)
	if err := <-res; err != nil {
		t.Fatalf("a client whose ClientHello came in two records %s apart was closed for a newcomer of its source: %v", late, err)
	}
}

// A ClientHello split over several records, as some TLS stacks and proxies
// send it, is read whole and the handshake goes through.
func TestAwaitFirstRecordSplitHello(t *testing.T) {
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "srv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{2, 3, maxHelloRecords} {
		sconn, cconn := loopbackPair(t)
		go func() {
			c := tls.Client(&splitHello{Conn: cconn, n: n}, PinnedTLSConfig(CertFingerprint(cert)))
			if c.Handshake() == nil {
				c.Write([]byte("ping"))
			}
		}()
		first, err := awaitFirstRecord(sconn, false, 5*time.Second, nil)
		if err != nil {
			t.Fatalf("a ClientHello in %d records was not taken: %v", n, err)
		}
		srv := tls.Server(first, ServerTLSConfig(cert))
		srv.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(srv, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%d records: the handshake after them failed: %q %v", n, buf, err)
		}
		srv.Close()
	}
}

// Whatever a peer sends first, readClientHello either refuses it or returns
// exactly the bytes it read, which hold a whole ClientHello of at most
// 16 KiB in at most maxHelloRecords records.
func FuzzReadClientHello(f *testing.F) {
	f.Add([]byte{22, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{22, 3, 1, 0, 1, 1, 22, 3, 1, 0, 3, 0, 0, 0})
	f.Add([]byte{22, 3, 1, 0, 6, 1, 0, 0, 2, 7, 7, 21, 3, 1, 0, 2, 2, 40})
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := readClientHello(bytes.NewReader(in))
		if err != nil {
			return
		}
		if !bytes.Equal(got, in[:len(got)]) {
			t.Fatalf("returned %x, not what was read from %x", got, in)
		}
		var hello []byte
		records := 0
		for rest := got; len(rest) > 0; records++ {
			size := int(rest[3])<<8 | int(rest[4])
			if rest[0] != tlsRecordHandshake || size == 0 {
				t.Fatalf("took a record of type %d and size %d", rest[0], size)
			}
			hello = append(hello, rest[tlsRecordHeader:tlsRecordHeader+size]...)
			rest = rest[tlsRecordHeader+size:]
		}
		need := tlsHandshakeHeader + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
		if hello[0] != tlsClientHello || len(hello) < need || len(hello) > maxTLSRecordPayload || records > maxHelloRecords {
			t.Fatalf("took %d records carrying %d bytes for a hello of type %d and %d bytes", records, len(hello), hello[0], need)
		}
	})
}

// floodSources returns the loopback addresses a flood comes from, or skips
// the test where only 127.0.0.1 can be dialled from.
func floodSources(t *testing.T) []string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 9)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial from a second loopback address: %v", err)
	}
	c.Close()
	var srcs []string
	for i := range 8 {
		srcs = append(srcs, fmt.Sprintf("127.0.0.%d", 2+i))
	}
	return srcs
}

// silentFlood keeps maxPreAuthPerSource silent connections open to addr from
// each of 8 loopback addresses, dialling again soon after the server closes
// one, until the test ends: enough to fill a listener whose cap is 512.
func silentFlood(t *testing.T, addr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	for _, src := range floodSources(t) {
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
		for range maxPreAuthPerSource {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ctx.Err() == nil {
					c, err := d.DialContext(ctx, "tcp", addr)
					if err == nil {
						stop := context.AfterFunc(ctx, func() { c.Close() })
						c.Read(make([]byte, 1))
						stop()
						c.Close()
					}
					select {
					case <-time.After(10 * time.Millisecond):
					case <-ctx.Done():
					}
				}
			}()
		}
	}
	time.Sleep(time.Second) // let the flood fill the listener
}

// floodCap is the listener cap the flood tests run with, which 8 sources of
// 64 fill exactly.
const floodCap = 8 * maxPreAuthPerSource

// A flood from a few addresses does not lock a valid client out of the
// agent: with 8 sources holding 64 silent connections each, which fill its
// listener, a newcomer still gets in.
func TestPreAuthFloodAgent(t *testing.T) {
	a, fp := newTestAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.serveListener(ctx, ln, &PreAuthLimiter{max: floodCap})
	silentFlood(t, ln.Addr().String())

	for i := range 3 {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cl, err := Dial(c, PinnedTLSConfig(fp), "", testToken)
		if err != nil {
			t.Fatalf("connection %d during the flood: %v", i, err)
		}
		cl.Close()
	}
}

// The same flood leaves a relay open to agents and clients.
func TestPreAuthFloodRelay(t *testing.T) {
	_, addr, relayFP, ctx := startTestHub(t, func(h *relayHub) { h.lim.max = floodCap })
	a, agentFP := newTestAgent(t)
	go a.ServeRelay(ctx, addr, relayFP, testRelayToken, "box", false)
	silentFlood(t, addr)

	for i := range 3 {
		tr, err := RelayDialClient(ctx, addr, relayFP, testRelayToken, "box", false)
		if err != nil {
			t.Fatalf("client %d during the flood: %v", i, err)
		}
		cl, err := Dial(tr, PinnedTLSConfig(agentFP), "", testToken)
		if err != nil {
			t.Fatalf("client %d auth during the flood: %v", i, err)
		}
		cl.Close()
	}
}

// The same flood leaves rtern's Catcher open to the agent it waits for.
func TestPreAuthFloodCatcher(t *testing.T) {
	relayCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	a, agentFP := newTestAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := startCatcher(ctx, ln, ServerTLSConfig(relayCert), testRelayToken, "box", &PreAuthLimiter{max: floodCap})
	silentFlood(t, ln.Addr().String())

	go func() {
		if conn, err := RelayDialAgent(ctx, ln.Addr().String(), CertFingerprint(relayCert), testRelayToken, "box", false); err == nil {
			a.Serve(conn, "caught")
		}
	}()
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	cl, err := c.Catch(cctx, agentFP, "", testToken, false, false)
	if err != nil {
		t.Fatalf("the agent was not caught during the flood: %v", err)
	}
	cl.Close()
}

// TestCatcherSilentFlood: past its cap, a newcomer from a source takes the
// place of that source's oldest connection that has sent nothing for the
// grace, which is closed at once, and such connections do not keep an agent
// at another address from registering.
func TestCatcherSilentFlood(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	relayCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	agentCert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	agent := NewAgent(ServerTLSConfig(agentCert), &AuthConfig{Token: testToken}, "/bin/sh", time.Minute, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewCatcher(ctx, ln, ServerTLSConfig(relayCert), testRelayToken, "box")
	sourceGivesWay(t, ln.Addr().String())

	start := time.Now()
	go func() {
		conn, err := RelayDialAgent(ctx, ln.Addr().String(), CertFingerprint(relayCert), testRelayToken, "box", false)
		if err == nil {
			agent.Serve(conn, "caught")
		}
	}()
	cl, err := c.Catch(ctx, CertFingerprint(agentCert), "", testToken, false, false)
	if err != nil {
		t.Fatalf("Catch: %v", err)
	}
	cl.Close()
	if d := time.Since(start); d > handshakeTimeout/2 {
		t.Fatalf("the agent took %s to be caught; it waited out the flood", d)
	}
}

// sourceGivesWay fills the per-source cap of the server at addr from one
// source, 127.0.0.2, with connections that send nothing, lets them sit past
// the grace, and fails unless one more from that source makes the server
// close one of the silent ones at once, and only one, not the newcomer: the
// way the server keeps its books of when it began to read each one decides
// that. The connections close when the test ends; the test is skipped where
// only 127.0.0.1 can be dialled from.
func sourceGivesWay(t *testing.T, addr string) {
	t.Helper()
	flooder := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}, Timeout: 5 * time.Second}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := flooder.Dial("tcp", probe.Addr().String())
	probe.Close()
	if err != nil {
		t.Skipf("cannot dial from a second loopback address: %v", err)
	}
	c.Close()

	var silent []net.Conn
	t.Cleanup(func() {
		for _, s := range silent {
			s.Close()
		}
	})
	closed := make(chan int, maxPreAuthPerSource+1)
	dial := func() {
		s, err := flooder.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		i := len(silent)
		silent = append(silent, s)
		go func() {
			s.Read(make([]byte, 1)) // returns once the server closes it
			closed <- i
		}()
	}
	for range maxPreAuthPerSource {
		dial()
	}
	time.Sleep(200 * time.Millisecond) // all of them silent past the grace
	select {
	case i := <-closed:
		t.Fatalf("connection %d was closed under its source's cap", i)
	default:
	}
	dial()
	select {
	case i := <-closed:
		if i == maxPreAuthPerSource {
			t.Fatal("the newcomer was closed, not one of the silent connections")
		}
	case <-time.After(time.Second):
		t.Fatal("no silent connection was closed for a newcomer from their source")
	}
	select {
	case i := <-closed:
		t.Fatalf("connection %d was closed too", i)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDirectSilentFlood is TestCatcherSilentFlood for ternd's direct
// listener: past its cap, a newcomer from a source takes the place of that
// source's oldest connection that has sent nothing for the grace, which is
// closed at once, and a client at another address still gets in at once.
func TestDirectSilentFlood(t *testing.T) {
	a, fp := newTestAgent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.serveListener(ctx, ln, new(PreAuthLimiter))
	sourceGivesWay(t, ln.Addr().String())

	start := time.Now()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := Dial(c, PinnedTLSConfig(fp), "", testToken)
	if err != nil {
		t.Fatalf("a client at another address: %v", err)
	}
	cl.Close()
	if d := time.Since(start); d > handshakeTimeout/2 {
		t.Fatalf("the client took %s to get in; it waited out the flood", d)
	}
}

// TestRelaySilentFlood is TestCatcherSilentFlood for ternr's hub: the same
// give-way, and an agent and a client at another address still register and
// pair at once.
func TestRelaySilentFlood(t *testing.T) {
	h, addr, relayFP, ctx := startTestHub(t)
	sourceGivesWay(t, addr)

	start := time.Now()
	a, agentFP := newTestAgent(t)
	go a.ServeRelay(ctx, addr, relayFP, testRelayToken, "box", false)
	for regs, _, _ := h.books(); regs == 0; regs, _, _ = h.books() {
		if time.Since(start) > handshakeTimeout/2 {
			t.Fatal("the agent did not register; it waited out the flood")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tr, err := RelayDialClient(ctx, addr, relayFP, testRelayToken, "box", false)
	if err != nil {
		t.Fatalf("a client at another address: %v", err)
	}
	cl, err := Dial(tr, PinnedTLSConfig(agentFP), "", testToken)
	if err != nil {
		t.Fatalf("the client's auth through the relay: %v", err)
	}
	cl.Close()
	if d := time.Since(start); d > handshakeTimeout/2 {
		t.Fatalf("the agent and client took %s to get through; they waited out the flood", d)
	}
}

// floodListener hands out connections from srcs in turn as fast as it is
// asked, left in all, and records the most it had handed out still open when
// it was asked for another.
type floodListener struct {
	srcs    []net.Addr
	left    int
	open    atomic.Int64
	peak    int64 // only Accept, which the accept loop calls in turn, uses it
	drained chan struct{}
	closed  chan struct{}
	stop    sync.Once
}

func (l *floodListener) Accept() (net.Conn, error) {
	if l.left == 0 {
		close(l.drained)
		<-l.closed
		return nil, net.ErrClosed
	}
	l.peak = max(l.peak, l.open.Load())
	l.left--
	l.open.Add(1)
	return &floodConn{addr: l.srcs[l.left%len(l.srcs)], l: l, gone: make(chan struct{})}, nil
}

func (l *floodListener) Close() error   { l.stop.Do(func() { close(l.closed) }); return nil }
func (l *floodListener) Addr() net.Addr { return l.srcs[0] }

// floodConn sends nothing: a read waits until it is closed.
type floodConn struct {
	net.Conn
	addr net.Addr
	l    *floodListener
	gone chan struct{}
	once sync.Once
}

func (c *floodConn) RemoteAddr() net.Addr            { return c.addr }
func (c *floodConn) Read([]byte) (int, error)        { <-c.gone; return 0, net.ErrClosed }
func (c *floodConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *floodConn) SetDeadline(time.Time) error     { return nil }
func (c *floodConn) SetReadDeadline(time.Time) error { return nil }

func (c *floodConn) Close() error {
	c.once.Do(func() {
		close(c.gone)
		c.l.open.Add(-1)
	})
	return nil
}

// A listener takes connections no faster than its limiter places them: a
// flood of connections that send nothing, from thousands of /48s, never has
// more of them open than the limiter has places for, however fast they come:
// the accept loop places each with the limiter before it starts the
// connection's goroutine, so none piles up open while admissions lag.
func TestListenerTakesNoMoreThanItPlaces(t *testing.T) {
	a, _ := newTestAgent(t)
	const full = 64
	l := &floodListener{left: 50000, drained: make(chan struct{}), closed: make(chan struct{})}
	for i := range 6000 {
		l.srcs = append(l.srcs, &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("2001:db8:%x::1", i)), Port: 1})
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		a.serveListener(ctx, l, &PreAuthLimiter{max: full})
		close(served)
	}()
	select {
	case <-l.drained:
	case <-time.After(time.Minute):
		t.Fatal("the flood was not taken in a minute")
	}
	cancel()
	<-served
	if l.peak > full {
		t.Fatalf("%d connections were open at once under a limiter with %d places", l.peak, full)
	}
}

// A full listener closes a handshake whose peer has sent nothing for the
// grace before any other, whoever holds how many and since when: every real
// client sends its ClientHello as soon as it connects, so a flood of
// connections that send nothing, from however many parties, cannot push out
// a client whose handshake is under way.
func TestPreAuthLimiterClosesLongSilentFirst(t *testing.T) {
	const full = 64
	l := &PreAuthLimiter{max: full, grace: time.Nanosecond, clock: steppingClock()}
	spread := func(i int) *addrConn { return from(fmt.Sprintf("[2001:%x::1]:1", 0x100+i)) } // a provider's /32 each
	client := from("198.51.100.7:1")
	l.enter(client).started() // the oldest, and alone in its block, like all the others
	for i := range 10 * full {
		l.enter(spread(i))
	}
	if client.closed.Load() {
		t.Fatal("connections that sent nothing pushed out a handshake under way")
	}
	if total, _, _ := l.books(); total != full {
		t.Fatalf("total %d, want %d", total, full)
	}
}

// A handshake whose ClientHello has not been read yet is not closed for a
// heavier block's: a flood that sends its ClientHellos at once from one /32
// pushes out its own handshakes, not the client's, whether the client's is
// fresh or has waited past the grace to be read, as it may on a server the
// flood keeps busy. Silence only decides among blocks that weigh the same.
func TestPreAuthLimiterSparesSilentHandshakesOfLighterBlocks(t *testing.T) {
	for _, grace := range []time.Duration{time.Hour, time.Nanosecond} {
		const full = 64
		l := &PreAuthLimiter{max: full, grace: grace, clock: steppingClock()}
		client := from("198.51.100.7:1") // not started yet
		l.enter(client)
		for i := range 10 * full {
			l.enter(from(fmt.Sprintf("[2001:db8:%x::1]:1", 1+i))).started()
		}
		if client.closed.Load() {
			t.Fatalf("grace %s: a handshake not started yet was closed for a heavier block that sent its ClientHellos", grace)
		}
	}
}

// A full listener weighs a peer by the address blocks it holds, not only by
// its addresses: one with thousands of /48s in one provider's /32 carries
// that /32's weight, so its newcomers push out its own handshakes, never a
// lone client's, however long that one has been in flight.
func TestPreAuthLimiterWeighsAddressBlocks(t *testing.T) {
	for _, started := range []bool{false, true} { // the flood sends nothing, or a ClientHello
		const full = 512
		l := &PreAuthLimiter{max: full, grace: time.Hour}
		lone := from("198.51.100.7:1")
		if tk := l.enter(lone); started {
			tk.started()
		}
		for i := range 6000 {
			if tk := l.enter(from(fmt.Sprintf("[2001:db8:%x::1]:1", 1+i))); started {
				tk.started()
			}
		}
		if lone.closed.Load() {
			t.Fatalf("started %v: 6000 /48s in one /32 pushed out a lone client", started)
		}
		if total, _, _ := l.books(); total != full {
			t.Fatalf("started %v: total %d, want %d", started, total, full)
		}
	}
}

// checkBooks checks l's books against each other under its lock: the tree
// against the handshakes in it, each group's count against the handshakes
// it holds, and the caps.
func (l *PreAuthLimiter) checkBooks(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	held := map[string]int{}
	caps := map[string]int{}
	total := 0
	for _, e := range checkTree(t, &l.flight) {
		s := e.val
		if s.freed {
			t.Error("a handshake given back is still in the tree")
		}
		for i, k := range s.keys {
			held[k]++
			caps[k] = maxPreAuthPerSource
			if i > 0 {
				caps[k] = preAuthPrefixCaps[i-1]
			}
		}
		total++
	}
	if total != l.total || total > l.totalCap() {
		t.Errorf("total %d, %d handshakes in the trees, cap %d", l.total, total, l.totalCap())
	}
	waiting := 0
	for k, g := range l.groups {
		if g.held != held[k] {
			t.Errorf("group %s counts %d, holds %d", k, g.held, held[k])
		}
		if g.held == 0 && len(g.waiters) == 0 {
			t.Errorf("an empty group %s was kept", k)
		}
		waiting += len(g.waiters)
	}
	for k, n := range held {
		if l.groups[k] == nil {
			t.Errorf("group %s holding %d is missing", k, n)
		}
		if n > caps[k] {
			t.Errorf("group %s holds %d, past its cap of %d", k, n, caps[k])
		}
	}
	if waiting != l.waiting || waiting > l.waitCap() {
		t.Errorf("waiting %d, %d queued, cap %d", l.waiting, waiting, l.waitCap())
	}
}

// checkTree checks a partyTree's blocks against each other and returns the
// entries it holds.
func checkTree[T any](t *testing.T, tr *partyTree[T]) []*partyEntry[T] {
	t.Helper()
	var entries []*partyEntry[T]
	blocks := 0
	var walk func(nd *partyNode[T], level int) int
	walk = func(nd *partyNode[T], level int) int {
		n := 0
		for i, kid := range nd.kids {
			blocks++
			if kid.parent != nd || kid.at != i || tr.nodes[kid.key] != kid {
				t.Errorf("block %s is out of place", kid.key)
			}
			if i > 0 && nd.kids.Less(i, (i-1)/2) {
				t.Errorf("the blocks within %q are out of order", nd.key)
			}
			n += walk(kid, level+1)
		}
		if level == 0 {
			return n
		}
		listed := 0
		var prev uint64
		for e := nd.first; e != nil; e = e.next[level-1] {
			if e.seq <= prev || e.nodes[level-1] != nd {
				t.Errorf("block %s lists an entry out of order or not its own", nd.key)
			}
			prev = e.seq
			listed++
			if len(nd.kids) == 0 {
				entries = append(entries, e)
				n++
			}
		}
		if listed != nd.n || n != nd.n {
			t.Errorf("block %s counts %d, lists %d, holds %d below", nd.key, nd.n, listed, n)
		}
		return n
	}
	if n := walk(&tr.root, 0); n != tr.root.n {
		t.Errorf("the tree counts %d, holds %d", tr.root.n, n)
	}
	if blocks != len(tr.nodes) {
		t.Errorf("%d blocks in the tree, %d in its map", blocks, len(tr.nodes))
	}
	quiet := 0
	var prev *partyEntry[T]
	for e := tr.quiet; e != nil; e = e.qnext {
		if !e.quiet || e.qprev != prev || prev != nil && (e.seq <= prev.seq || e.since.Before(prev.since)) {
			t.Error("the quiet list is out of order or holds an entry that is not quiet")
		}
		prev = e
		quiet++
	}
	if prev != tr.last {
		t.Error("the quiet list ends elsewhere than its last entry")
	}
	for _, e := range entries {
		if e.quiet {
			quiet--
		}
	}
	if quiet != 0 {
		t.Errorf("the quiet list and the quiet entries differ by %d", quiet)
	}
	return entries
}

// The books stay consistent under concurrent use, and are empty at the end:
// handshakes from sources sharing blocks at every level come and go, wait
// for a slot, are read from, start (some once part of their ClientHello
// came) or stay silent, are closed to make room on a full listener, past a
// prefix's cap or for a newcomer of their source, and give their slots
// back, now and then twice.
func TestPreAuthLimiterBooksStayConsistent(t *testing.T) {
	l := &PreAuthLimiter{max: 200, waitMax: 300, grace: time.Millisecond}
	addrs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.1", "203.0.113.1"}
	for p32 := range 2 {
		for p48 := range 2 {
			for p56 := range 3 {
				for p64 := range 2 {
					addrs = append(addrs, fmt.Sprintf("2001:%x:%x:%x%02x::1", 0xdb8+p32, p48, p56, p64))
				}
			}
		}
	}
	stop := make(chan struct{})
	var checker sync.WaitGroup
	checker.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				l.checkBooks(t)
			}
		}
	})
	var wg sync.WaitGroup
	var admitted, evicted atomic.Int64
	deadline := time.Now().Add(3 * time.Second)
	for w := range 400 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(w), 3))
			for time.Now().Before(deadline) {
				ip := netip.MustParseAddr(addrs[r.IntN(len(addrs))])
				c := &addrConn{addr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(1+r.IntN(60000))))}
				tk := l.enter(c)
				if tk == nil || !tk.wait() {
					time.Sleep(100 * time.Microsecond)
					continue
				}
				admitted.Add(1)
				tk.reading()
				if r.IntN(3) > 0 {
					time.Sleep(time.Duration(r.IntN(2000)) * time.Microsecond)
					if r.IntN(2) == 0 {
						tk.spoke()
					}
					tk.started()
				}
				time.Sleep(time.Duration(r.IntN(2000)) * time.Microsecond)
				if c.closed.Load() {
					evicted.Add(1)
				}
				tk.done()
				if r.IntN(8) == 0 {
					tk.done()
				}
			}
		})
	}
	wg.Wait()
	close(stop)
	checker.Wait()
	l.checkBooks(t)
	t.Logf("%d admitted, %d of them closed to make room", admitted.Load(), evicted.Load())
	if total, waiting, groups := l.books(); total+waiting+groups != 0 {
		t.Fatalf("books not empty at the end: total %d, waiting %d, groups %d", total, waiting, groups)
	}
	if len(l.flight.nodes) != 0 || l.flight.quiet != nil {
		t.Fatalf("the tree still holds %d blocks, quiet entries %v", len(l.flight.nodes), l.flight.quiet != nil)
	}
}

// The caps follow the file descriptor limit and leave most of it to
// authenticated sessions: a flood at every cap of a listener and its waiting
// room takes at most half the limit, and with a relay's books at most three
// quarters, as do a REST gateway's connections and commands (whose caps are
// fixed, so from a limit of 1024): an authenticated command still finds
// descriptors for its pipes.
func TestPreAuthCapsFitTheFileLimit(t *testing.T) {
	for _, limit := range []uint64{256, 1024, 4096} {
		held, wait := preAuthCaps(limit)
		regs, pipes := relayCaps(limit)
		if n := held + wait; n > int(limit)/2 {
			t.Errorf("limit %d: %d handshakes and %d waiting take %d descriptors", limit, held, wait, n)
		}
		if n := held + wait + regs + 2*pipes; n > int(limit)*3/4 {
			t.Errorf("limit %d: a relay at its caps takes %d descriptors", limit, n)
		}
		if n := apiConnCap(limit) + maxRunningCommands + maxRunningJobs; limit >= 1024 && n > int(limit)*3/4 {
			t.Errorf("limit %d: a REST gateway at its caps takes %d descriptors", limit, n)
		}
	}
	if held, wait := preAuthCaps(1 << 20); held != 4096 || wait != maxPreAuthWaitingTotal {
		t.Errorf("a generous limit: caps %d and %d", held, wait)
	}
}
