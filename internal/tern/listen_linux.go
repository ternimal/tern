// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenAbsent listens on addr (host:port), whose host this system does not
// have now, with IP_FREEBIND, which lets a socket bind an address the system
// does not have: the port is held there before the address comes up, and a
// client that dials it then reaches this listener. Any local user may set
// IP_FREEBIND, so without it another one could take the port first, or once
// the address comes. Set at SOL_IP, it holds for IPv6 sockets too.
func listenAbsent(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}
