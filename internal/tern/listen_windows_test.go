// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"net"
	"strconv"
	"testing"
)

// A listener takes its port to itself: no other socket can bind it, on its
// address or a more specific one, and it does not bind a port another socket
// already holds. Without SO_EXCLUSIVEADDRUSE, Windows lets a second socket
// bind 127.0.0.1 under a 0.0.0.0 listener and take its local connections.
func TestListenTCPExclusive(t *testing.T) {
	ln, err := ListenTCP("0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, addr := range []string{"127.0.0.1:" + port, "0.0.0.0:" + port} {
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close()
			t.Errorf("another socket bound %s under the listener", addr)
		}
	}
	ln.Close()

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port = strconv.Itoa(held.Addr().(*net.TCPAddr).Port)
	if l, err := ListenTCP("0.0.0.0:" + port); err == nil {
		l.Close()
		t.Error("the listener shared a port another socket held on 127.0.0.1")
	}
}
