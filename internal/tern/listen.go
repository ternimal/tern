// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ListenTCP listens on addr (host:port). A loopback address takes the same
// port on the other loopback address too: 127.0.0.1 also holds [::1], ::1
// also holds 127.0.0.1, and "localhost" listens on both. A client that dials
// "localhost" may reach either one, and most try ::1 first, so a port held
// on only one of them would leave the other to any local user, who would
// then get the connections meant for this listener, with the bearer tokens
// and data they carry. Another host name is looked up once and listens on
// every address it names, a client that dials the name being free to reach
// any, so another local user cannot take the connections that reach one
// left free: one that names loopback addresses only, as
// localhost.localdomain and ip6-localhost usually do, also beside 127.0.0.1
// or ::1 on the other as above; one that names loopback and other addresses
// at once is refused, as is one that names more than maxNameAddrs. Of these
// addresses, one this system does not have now, as an IPv6 address it does
// not have until duplicate address detection is over, is held all the same
// on Linux (see listenAbsent), where any local user could otherwise take its
// port first; elsewhere it is passed over with a warning. At least one
// address a name gives must be here. If the port on one of these addresses
// is taken, ListenTCP fails rather than leave it so; on a system with no
// IPv6 at all there is nothing to hold. On Windows every socket also takes
// its port exclusively (see listenOne).
func ListenTCP(addr string) (net.Listener, error) {
	b, err := resolveBind(addr)
	if err != nil {
		return nil, err
	}
	return b.listen()
}

// lookupIPAddr looks a host name up; tests replace it.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// maxNameAddrs is the most addresses ListenTCP listens on for one host name,
// each a socket and a goroutine.
const maxNameAddrs = 16

// bindAddrs is where ListenTCP listens for an address, decided once, so
// whoever asks whether that is loopback (the REST gateway's Host check, its
// warnings) gets the answer the listener was built on.
type bindAddrs struct {
	addr string // as given
	port string
	// hosts are the IP addresses that take the port, as net takes them (an
	// IPv6 one with its zone), the first choosing the port when it is 0.
	// With none, addr is left to net as it is: a wildcard or malformed one.
	hosts []string
	// spare is how many of hosts, at the end, are not what addr names but
	// the other loopback address held beside 127.0.0.1 or ::1, which a
	// system that has none lets go.
	spare    int
	name     string // the host name addr gives, when it gives a name rather than an address
	loopback bool   // every one of hosts is a loopback address
}

var (
	loopback4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	loopback6 = netip.IPv6Loopback()
)

// isLocalhost reports whether host names "localhost" itself, in any case and
// with or without the root's trailing dot. Such a name is loopback without a
// lookup.
func isLocalhost(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), "localhost")
}

// resolveBind works out where ListenTCP listens for addr (see ListenTCP).
func resolveBind(addr string) (*bindAddrs, error) {
	b := &bindAddrs{addr: addr}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return b, nil // net reports a malformed address; no host is every address
	}
	b.port = port
	var named []netip.Addr // what host names, as written for a literal
	switch a, perr := netip.ParseAddr(host); {
	case isLocalhost(host):
		b.hosts = []string{loopback4.String()}
		b.loopback = true
		b.addSpare(loopback6)
		return b, nil
	case perr == nil:
		if a.Unmap().IsUnspecified() {
			return b, nil // a wildcard: net's own
		}
		named = []netip.Addr{a}
		b.hosts = []string{host}
	default:
		b.name = host
		found, err := lookupIPAddr(context.Background(), host)
		if err != nil {
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: err}
		}
		var loop, other []netip.Addr
		for _, ia := range found {
			a, ok := netip.AddrFromSlice(ia.IP)
			if !ok {
				continue
			}
			a = a.Unmap().WithZone(ia.Zone)
			switch {
			case slices.Contains(loop, a) || slices.Contains(other, a):
			case a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "":
				// Without its interface no socket can listen on it, nor a
				// client dial it.
			case a.IsLoopback():
				loop = append(loop, a)
			default:
				other = append(other, a)
			}
		}
		switch {
		case len(loop) > 0 && len(other) > 0:
			return nil, fmt.Errorf("listen %s: %s names loopback and other addresses (%s), and a client that dials it could reach either; give the address to listen on", addr, host, joinAddrs(append(loop, other...)))
		case len(loop) == 0 && len(other) == 0:
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: &net.DNSError{Err: "no suitable address", Name: host}}
		case len(loop)+len(other) > maxNameAddrs:
			return nil, fmt.Errorf("listen %s: %s names %d addresses, more than the %d ListenTCP takes for one name; give the address to listen on", addr, host, len(loop)+len(other), maxNameAddrs)
		}
		// Every address the name gives, a client that dials it being free
		// to reach any; IPv4 first, as net would pick and as "localhost"
		// does.
		addrs := loop
		if len(other) > 0 {
			addrs = other
		}
		for _, a := range addrs {
			if a.Is4() {
				named = append(named, a)
			}
		}
		for _, a := range addrs {
			if !a.Is4() {
				named = append(named, a)
			}
		}
		for _, a := range named {
			b.hosts = append(b.hosts, a.String())
		}
	}
	b.loopback = true
	for _, a := range named {
		b.loopback = b.loopback && a.IsLoopback()
	}
	for _, a := range named {
		switch a.WithZone("").Unmap() {
		case loopback4:
			b.addSpare(loopback6)
		case loopback6:
			b.addSpare(loopback4)
		}
	}
	return b, nil
}

// addSpare holds a beside what b's address names, unless it is held already.
func (b *bindAddrs) addSpare(a netip.Addr) {
	for _, h := range b.hosts {
		if have, err := netip.ParseAddr(h); err == nil && have.WithZone("").Unmap() == a {
			return
		}
	}
	b.hosts = append(b.hosts, a.String())
	b.spare++
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// listen listens where b says.
func (b *bindAddrs) listen() (net.Listener, error) {
	if len(b.hosts) == 0 {
		return listenOne(b.addr)
	}
	n, perr := strconv.Atoi(b.port)
	ephemeral := b.port == "" || (perr == nil && n == 0)
	for attempt := 0; ; attempt++ {
		lns, retry, err := b.listenAll()
		switch {
		case err == nil && len(lns) == 1:
			return lns[0], nil
		case err == nil:
			return newMultiListener(lns), nil
		case ephemeral && retry && attempt < 16:
			continue // the port the system picked is taken on another address: pick again
		}
		return nil, err
	}
}

// holdAbsent is listenAbsent; tests replace it.
var holdAbsent = listenAbsent

// listenAll takes the port on each of b's hosts, or on none: when one is
// taken it lets go of the rest and reports, in retry, whether the port was
// in use there, which a port the system picked may be. A spare address, or
// one of several a name gives, that this system does not have now is held
// all the same where it can be (see listenAbsent), and passed over with a
// warning where it cannot; but at least one that the host names must be
// here.
func (b *bindAddrs) listenAll() (lns []net.Listener, retry bool, err error) {
	named := len(b.hosts) - b.spare
	port := b.port
	here := 0         // of lns, those on an address this system has
	var gone error    // why an address the host names cannot be listened on here
	var left []string // addresses passed over with nothing holding the port
	fail := func(err error) ([]net.Listener, bool, error) {
		for _, ln := range lns {
			ln.Close()
		}
		return nil, addrInUse(err), err
	}
	for i, h := range b.hosts {
		if i == named && here == 0 {
			return fail(gone) // none of what the host names is here
		}
		hp := net.JoinHostPort(h, port)
		ln, err := listenOne(hp)
		absent := err != nil && addrNotHere(err) && (i >= named || b.name != "")
		if absent {
			if gone == nil {
				gone = err
			}
			if ln, err = holdAbsent(hp); errors.Is(err, errors.ErrUnsupported) {
				left = append(left, h)
				continue
			}
		}
		switch {
		case err == nil:
			if len(lns) == 0 {
				port = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			}
			lns = append(lns, ln)
			if !absent {
				here++
			}
			continue
		case familyUnavailable(err) && (i >= named || b.name != ""):
			// No such address family here at all, so nobody can listen
			// there either: a spare address, or one of several a name
			// gives.
			if gone == nil {
				gone = err
			}
			continue
		case len(lns) == 0:
			return nil, false, err // the port itself, as net reports it
		case i >= named:
			return fail(fmt.Errorf("listen %s: the same port on the other loopback address is taken (%w), and a client that dials \"localhost\" could reach whoever holds it instead; use a free port", b.addr, err))
		}
		return fail(fmt.Errorf("listen %s: the same port on %s, which %s also names, is taken (%w), and a client that dials %s could reach whoever holds it instead; use a free port", b.addr, h, b.name, err, b.name))
	}
	if here == 0 {
		return fail(gone)
	}
	for _, h := range left {
		slog.Warn("listen: an address this system does not have now is left without a listener; once the system has it, another local user could listen there and get the connections that reach it",
			"addr", b.addr, "unheld", h)
	}
	return lns, false, nil
}

// multiListener accepts the connections of several listeners, such as
// those of a loopback port on both 127.0.0.1 and ::1, as one listener. Its
// address is the first one's.
type multiListener struct {
	lns   []net.Listener
	conns chan accepted // unbuffered: each listener accepts one at a time, when asked
	done  chan struct{}
	once  sync.Once

	mu       sync.Mutex
	deadline time.Time
}

type accepted struct {
	conn net.Conn
	err  error
}

func newMultiListener(lns []net.Listener) *multiListener {
	m := &multiListener{lns: lns, conns: make(chan accepted), done: make(chan struct{})}
	for _, ln := range m.lns {
		go m.run(ln)
	}
	return m
}

func (m *multiListener) run(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			// Closed, by Close or from outside: never go on holding only
			// some of the addresses.
			m.Close()
			return
		}
		select {
		case m.conns <- accepted{c, err}:
		case <-m.done:
			if c != nil {
				c.Close()
			}
			return
		}
	}
}

// Accept waits for a connection on any of the addresses. Errors other than
// the listener closing, such as running out of file descriptors, pass
// through as a plain listener would return them.
func (m *multiListener) Accept() (net.Conn, error) {
	m.mu.Lock()
	deadline := m.deadline
	m.mu.Unlock()
	var expired <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, m.opError(os.ErrDeadlineExceeded)
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		expired = t.C
	}
	select {
	case <-m.done:
		return nil, m.opError(net.ErrClosed)
	default:
	}
	select {
	case a := <-m.conns:
		return a.conn, a.err
	case <-m.done:
		return nil, m.opError(net.ErrClosed)
	case <-expired:
		return nil, m.opError(os.ErrDeadlineExceeded)
	}
}

func (m *multiListener) opError(err error) error {
	return &net.OpError{Op: "accept", Net: "tcp", Addr: m.Addr(), Err: err}
}

// Close closes every listener.
func (m *multiListener) Close() error {
	err := net.ErrClosed
	m.once.Do(func() {
		close(m.done)
		var errs []error
		for _, ln := range m.lns {
			errs = append(errs, ln.Close())
		}
		err = errors.Join(errs...)
	})
	return err
}

func (m *multiListener) Addr() net.Addr { return m.lns[0].Addr() }

// Addrs lists the addresses it listens on.
func (m *multiListener) Addrs() []net.Addr {
	as := make([]net.Addr, len(m.lns))
	for i, ln := range m.lns {
		as[i] = ln.Addr()
	}
	return as
}

// SetDeadline sets when a waiting Accept gives up with a timeout error, as
// on a *net.TCPListener; the zero time waits for ever.
func (m *multiListener) SetDeadline(t time.Time) error {
	m.mu.Lock()
	m.deadline = t
	m.mu.Unlock()
	return nil
}
