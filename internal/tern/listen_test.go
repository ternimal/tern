// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// needIPv6Loopback skips a test on a system where nothing can listen on ::1.
func needIPv6Loopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	ln.Close()
}

// takenBeside fails unless, once ln holds it, another socket cannot listen
// on the same port at host.
func takenBeside(t *testing.T, ln net.Listener, host string) {
	t.Helper()
	addr := net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	if l, err := net.Listen("tcp", addr); err == nil {
		l.Close()
		t.Errorf("another socket listened on %s beside the listener on %s", addr, ln.Addr())
	}
}

// A listener on one loopback address holds the same port on the other, so
// another local user cannot listen there and get the connections of a
// client that dials "localhost", which may reach either address; on
// "localhost" it listens on both.
func TestListenTCPHoldsBothLoopbacks(t *testing.T) {
	needIPv6Loopback(t)
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0", "LocalHost.:0"} {
		ln, err := ListenTCP(addr)
		if err != nil {
			t.Fatalf("ListenTCP(%q): %v", addr, err)
		}
		takenBeside(t, ln, "127.0.0.1")
		takenBeside(t, ln, "::1")
		port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
		for _, host := range []string{"127.0.0.1", "::1"} {
			acceptsFrom(t, ln, net.JoinHostPort(host, port))
		}
		ln.Close()
		// Closed, it frees both.
		for _, host := range []string{"127.0.0.1", "::1"} {
			l, err := net.Listen("tcp", net.JoinHostPort(host, port))
			if err != nil {
				t.Errorf("after Close, %s:%s is still held: %v", host, port, err)
				continue
			}
			l.Close()
		}
	}
}

// acceptsFrom dials addr and fails unless ln accepts that connection.
func acceptsFrom(t *testing.T, ln net.Listener, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	got := make(chan result, 1)
	go func() {
		s, err := ln.Accept()
		if err == nil {
			_, err = io.ReadFull(s, make([]byte, 1))
		}
		got <- result{s, err}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("accept from %s: %v", addr, r.err)
		}
		c.Close() // the client closes first, so the port is not left in TIME_WAIT
		r.conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatalf("the listener on %s never accepted the connection to %s", ln.Addr(), addr)
	}
}

// A loopback port whose other address another socket already holds is
// refused, rather than listening beside it.
func TestListenTCPRefusesHalfTakenLoopback(t *testing.T) {
	needIPv6Loopback(t)
	pairs := [][2]string{{"::1", "127.0.0.1"}, {"127.0.0.1", "::1"}, {"::1", "localhost"}, {"127.0.0.1", "localhost"}}
	for _, p := range pairs {
		held, err := net.Listen("tcp", net.JoinHostPort(p[0], "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := strconv.Itoa(held.Addr().(*net.TCPAddr).Port)
		if ln, err := ListenTCP(net.JoinHostPort(p[1], port)); err == nil {
			ln.Close()
			t.Errorf("ListenTCP(%s) listened while another socket held %s", net.JoinHostPort(p[1], port), held.Addr())
		}
		held.Close()
	}
}

// Other addresses are left alone: a wildcard or a non-loopback address is
// one plain listener.
func TestListenTCPOtherAddressesSingle(t *testing.T) {
	ln, err := ListenTCP("127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 unavailable: %v", err)
	}
	defer ln.Close()
	if _, ok := ln.(*net.TCPListener); !ok {
		t.Errorf("ListenTCP(127.0.0.2:0) = %T, want a plain TCP listener", ln)
	}
}

// fakeHosts makes ListenTCP look host names up in names for the rest of the
// test, and counts the lookups.
func fakeHosts(t *testing.T, names map[string][]string) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	old := lookupIPAddr
	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		n.Add(1)
		var out []net.IPAddr
		for _, s := range names[host] {
			ip, zone, _ := strings.Cut(s, "%")
			out = append(out, net.IPAddr{IP: net.ParseIP(ip), Zone: zone})
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return out, nil
	}
	t.Cleanup(func() { lookupIPAddr = old })
	return &n
}

// A host name that names loopback addresses only, as localhost.localdomain,
// ip6-localhost or ip6-loopback usually do, is a loopback bind like
// "localhost": the port is held on every address it names and on both
// 127.0.0.1 and ::1, or a local user could listen on the one left free and
// get the connections, and bearer tokens, of clients that dial the name.
func TestListenTCPLoopbackNamesHoldEveryAddress(t *testing.T) {
	needIPv6Loopback(t)
	fakeHosts(t, map[string][]string{
		"both.test":     {"::1", "127.0.0.1"},
		"v6.test":       {"::1"},
		"v4.test":       {"127.0.0.1"},
		"mapped.test":   {"::ffff:127.0.0.1"},
		"twice.test":    {"127.0.0.1", "127.0.0.1", "::1"},
		"Upper.TEST":    {"::1"},
		"trailing.dot.": {"::1"},
	})
	for _, name := range []string{"both.test", "v6.test", "v4.test", "mapped.test", "twice.test", "Upper.TEST", "trailing.dot."} {
		ln, err := ListenTCP(net.JoinHostPort(name, "0"))
		if err != nil {
			t.Fatalf("ListenTCP(%s:0): %v", name, err)
		}
		takenBeside(t, ln, "127.0.0.1")
		takenBeside(t, ln, "::1")
		port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
		for _, host := range []string{"127.0.0.1", "::1"} {
			acceptsFrom(t, ln, net.JoinHostPort(host, port))
		}
		ln.Close()
	}
	// A port another socket holds on one of them is refused.
	for _, held := range []string{"127.0.0.1", "::1"} {
		other, err := net.Listen("tcp", net.JoinHostPort(held, "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := strconv.Itoa(other.Addr().(*net.TCPAddr).Port)
		for _, name := range []string{"both.test", "v6.test", "v4.test"} {
			if ln, err := ListenTCP(net.JoinHostPort(name, port)); err == nil {
				ln.Close()
				t.Errorf("ListenTCP(%s:%s) listened while another socket held %s", name, port, other.Addr())
			}
		}
		other.Close()
	}
}

// What ListenTCP makes of an address, which the REST gateway's Host check
// and warnings go by: every spelling of a loopback address, and a name that
// names loopback addresses only, is loopback; a wildcard, another address,
// or a name for one, is not; a name for loopback and other addresses at
// once is refused, a client that dials it being free to reach either.
func TestResolveBindDecidesLoopback(t *testing.T) {
	many := []string{}
	for i := range maxNameAddrs + 1 {
		many = append(many, "192.0.2."+strconv.Itoa(i+1))
	}
	fakeHosts(t, map[string][]string{
		"loop.test":   {"::1", "127.0.0.1"},
		"lan.test":    {"2001:db8::5", "192.0.2.5", "2001:db8::6", "192.0.2.6"},
		"zoned.test":  {"fe80::1", "fe80::2%eth0", "192.0.2.5"},
		"mixed.test":  {"127.0.0.1", "192.0.2.5"},
		"debian.test": {"127.0.1.1"},
		"many.test":   many,
		"local.test":  {"fe80::1"},
	})
	for _, c := range []struct {
		addr     string
		loopback bool
		hosts    string // where it listens, the first choosing the port
	}{
		{"localhost:8080", true, "127.0.0.1 ::1"},
		{"Localhost:8080", true, "127.0.0.1 ::1"},
		{"LOCALHOST:8080", true, "127.0.0.1 ::1"},
		{"localhost.:8080", true, "127.0.0.1 ::1"},
		{"127.0.0.1:8080", true, "127.0.0.1 ::1"},
		{"[::1]:8080", true, "::1 127.0.0.1"},
		{"[::1%lo]:8080", true, "::1%lo 127.0.0.1"},
		{"[::ffff:127.0.0.1]:8080", true, "::ffff:127.0.0.1 ::1"},
		{"127.0.0.2:8080", true, "127.0.0.2"},
		{"loop.test:8080", true, "127.0.0.1 ::1"},
		{"debian.test:8080", true, "127.0.1.1"},
		{"lan.test:8080", false, "192.0.2.5 192.0.2.6 2001:db8::5 2001:db8::6"}, // every one, IPv4 first
		{"zoned.test:8080", false, "192.0.2.5 fe80::2%eth0"},                    // fe80::1 has no interface
		{"192.0.2.1:8080", false, "192.0.2.1"},
		{"0.0.0.0:8080", false, ""},
		{"[::]:8080", false, ""},
		{":8080", false, ""},
	} {
		b, err := resolveBind(c.addr)
		if err != nil {
			t.Errorf("%s: %v", c.addr, err)
			continue
		}
		if b.loopback != c.loopback || strings.Join(b.hosts, " ") != c.hosts {
			t.Errorf("%s: loopback %v on %q, want %v on %q", c.addr, b.loopback, b.hosts, c.loopback, c.hosts)
		}
	}
	for _, addr := range []string{"mixed.test:8080", "nowhere.test:8080", "many.test:8080", "local.test:8080"} {
		if b, err := resolveBind(addr); err == nil {
			t.Errorf("%s: listens on %q, want an error", addr, b.hosts)
		}
	}
}

// localAddrs lists up to n of this system's own addresses that are not
// loopback, on interfaces that are up and running: first those that need no
// interface named, then IPv6 link-local ones, with theirs.
func localAddrs(n int) []string {
	ifs, _ := net.Interfaces()
	var plain, zoned []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagRunning == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, _ := ifi.Addrs()
		for _, a := range as {
			ipn, ok := a.(*net.IPNet)
			switch {
			case !ok || ipn.IP.IsLoopback() || ipn.IP.IsMulticast():
			case ipn.IP.IsLinkLocalUnicast() && ipn.IP.To4() == nil:
				zoned = append(zoned, ipn.IP.String()+"%"+strconv.Itoa(ifi.Index))
			case !ipn.IP.IsLinkLocalUnicast():
				plain = append(plain, ipn.IP.String())
			}
		}
	}
	out := append(plain, zoned...)
	return out[:min(n, len(out))]
}

// A host name that names several of this system's addresses, none of them
// loopback, is listened on at every one: a client that dials the name may
// reach any, and another local user who could listen on one left free
// would get its connections. One the system does not have does not stop it
// (see TestListenTCPHoldsAbsentAddresses and
// TestListenTCPWarnsOfAbsentAddressLeftUnheld).
func TestListenTCPNameHoldsEveryAddress(t *testing.T) {
	addrs := localAddrs(3)
	if len(addrs) < 2 {
		t.Skipf("this system has %d addresses that are not loopback, want 2", len(addrs))
	}
	fakeHosts(t, map[string][]string{"lan.test": append(addrs, "192.0.2.77")})
	ln, err := ListenTCP("lan.test:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, a := range addrs {
		takenBeside(t, ln, a)
		acceptsFrom(t, ln, net.JoinHostPort(a, port))
	}
}

// Where the port on an address a name gives cannot be held while this
// system does not have the address, as on every system but Linux, ListenTCP
// passes the address over, but says so, naming it, in a warning.
func TestListenTCPWarnsOfAbsentAddressLeftUnheld(t *testing.T) {
	here := localAddrs(1)
	if len(here) == 0 {
		t.Skip("this system has no address that is not loopback")
	}
	old := holdAbsent
	holdAbsent = func(string) (net.Listener, error) { return nil, errors.ErrUnsupported }
	t.Cleanup(func() { holdAbsent = old })
	installLogger(slog.LevelInfo)
	logs := &syncBuffer{}
	logOut.set(logs)
	defer logOut.set(os.Stderr)
	fakeHosts(t, map[string][]string{"lan.test": {here[0], "192.0.2.77"}})
	ln, err := ListenTCP("lan.test:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if s := logs.String(); !strings.Contains(s, "level=WARN") || !strings.Contains(s, "unheld=192.0.2.77") ||
		!strings.Contains(s, "another local user could listen there") {
		t.Errorf("no warning naming the address left without a listener: %q", s)
	}
}

// An address given outright that this system does not have is refused, as
// net refuses it, rather than held.
func TestListenTCPLiteralAbsentRefused(t *testing.T) {
	if ln, err := ListenTCP("192.0.2.77:0"); err == nil {
		ln.Close()
		t.Error("ListenTCP(192.0.2.77:0) listened on an address this system does not have")
	}
}

// The system's own loopback names, where it has any: each holds both
// loopback addresses.
func TestListenTCPSystemLoopbackNames(t *testing.T) {
	needIPv6Loopback(t)
	tried := 0
	for _, name := range []string{"localhost.localdomain", "ip6-localhost", "ip6-loopback", "localhost4", "localhost6"} {
		ips, err := net.LookupIP(name)
		if err != nil || len(ips) == 0 {
			continue
		}
		loop := true
		for _, ip := range ips {
			loop = loop && ip.IsLoopback()
		}
		if !loop {
			continue
		}
		tried++
		ln, err := ListenTCP(net.JoinHostPort(name, "0"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		takenBeside(t, ln, "127.0.0.1")
		takenBeside(t, ln, "::1")
		ln.Close()
	}
	if tried == 0 {
		t.Skip("no name here names loopback addresses only")
	}
}

// Closing the listener ends a waiting Accept with net.ErrClosed, and a
// deadline ends it with a timeout, as on a TCP listener, which the agent's
// and rtern's accept loops rely on.
func TestListenTCPCloseAndDeadline(t *testing.T) {
	needIPv6Loopback(t)
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d, ok := ln.(interface{ SetDeadline(time.Time) error })
	if !ok {
		t.Fatalf("%T has no SetDeadline", ln)
	}
	d.SetDeadline(time.Now().Add(50 * time.Millisecond))
	var ne net.Error
	if _, err := ln.Accept(); !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Accept past the deadline: %v, want a timeout", err)
	}
	d.SetDeadline(time.Time{})
	got := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	ln.Close()
	select {
	case err := <-got:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close: %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end a waiting Accept")
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept on a closed listener: %v", err)
	}
}
