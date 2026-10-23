// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// absentAddrs are addresses this system does not have: documentation ones
// (TEST-NET-1 and 2001:db8::/32), the IPv6 one only where IPv6 is on.
func absentAddrs(t *testing.T) []string {
	t.Helper()
	out := []string{"192.0.2.77"}
	if ln, err := net.Listen("tcp", "[::1]:0"); err == nil {
		ln.Close()
		out = append(out, "2001:db8::77")
	}
	for _, a := range out {
		if ln, err := net.Listen("tcp", net.JoinHostPort(a, "0")); err == nil {
			ln.Close()
			t.Skipf("%s can be listened on here without IP_FREEBIND (net.ipv4.ip_nonlocal_bind?)", a)
		}
	}
	return out
}

// heldThere fails unless a socket with IP_FREEBIND, as any local user may
// make, cannot take port on host: something holds it.
func heldThere(t *testing.T, host, port string) {
	t.Helper()
	ln, err := listenAbsent(net.JoinHostPort(host, port))
	if err == nil {
		ln.Close()
		t.Errorf("another socket took %s with IP_FREEBIND", net.JoinHostPort(host, port))
	} else if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("IP_FREEBIND on %s: %v, want the port in use", net.JoinHostPort(host, port), err)
	}
}

// Of the addresses a host name gives, one this system does not have now, as
// an IPv6 address it does not have until duplicate address detection is
// over, is held all the same with IP_FREEBIND, so another local user cannot
// take its port, before the address comes up or after; closing the
// listener lets go of it.
func TestListenTCPHoldsAbsentAddresses(t *testing.T) {
	here := localAddrs(1)
	if len(here) == 0 {
		t.Skip("this system has no address that is not loopback")
	}
	absent := absentAddrs(t)
	fakeHosts(t, map[string][]string{"lan.test": append(here, absent...)})
	ln, err := ListenTCP("lan.test:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, a := range absent {
		heldThere(t, a, port)
	}
	acceptsFrom(t, ln, net.JoinHostPort(here[0], port))
	ln.Close()
	for _, a := range absent {
		l, err := listenAbsent(net.JoinHostPort(a, port))
		if err != nil {
			t.Errorf("after Close, %s:%s is still held: %v", a, port, err)
			continue
		}
		l.Close()
	}
}

// A port another socket took first with IP_FREEBIND on an address a host
// name gives, before the system has the address, makes ListenTCP fail,
// naming the address, rather than serve beside it.
func TestListenTCPAbsentAddressTakenFirst(t *testing.T) {
	here := localAddrs(1)
	if len(here) == 0 {
		t.Skip("this system has no address that is not loopback")
	}
	for _, a := range absentAddrs(t) {
		taken, err := listenAbsent(net.JoinHostPort(a, "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := strconv.Itoa(taken.Addr().(*net.TCPAddr).Port)
		fakeHosts(t, map[string][]string{"lan.test": append(append([]string{}, here...), a)})
		ln, err := ListenTCP(net.JoinHostPort("lan.test", port))
		if err == nil {
			ln.Close()
			t.Errorf("ListenTCP(lan.test:%s) listened while another socket held [%s]:%s", port, a, port)
		} else if !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), "is taken") {
			t.Errorf("ListenTCP(lan.test:%s) with [%s]:%s taken: %v, want it named as taken", port, a, port, err)
		}
		taken.Close()
	}
}

// When none of the addresses a name gives is here, ListenTCP fails, as for
// an address given outright, and holds none of them after.
func TestListenTCPNameNoneHere(t *testing.T) {
	absent := absentAddrs(t)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(free.Addr().(*net.TCPAddr).Port)
	free.Close()
	fakeHosts(t, map[string][]string{"gone.test": absent})
	if ln, err := ListenTCP(net.JoinHostPort("gone.test", port)); err == nil {
		ln.Close()
		t.Fatalf("ListenTCP(gone.test:%s) listened with none of its addresses here", port)
	}
	for _, a := range absent {
		l, err := listenAbsent(net.JoinHostPort(a, port))
		if err != nil {
			t.Errorf("%s:%s is held after ListenTCP failed: %v", a, port, err)
			continue
		}
		l.Close()
	}
}
