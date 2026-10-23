// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is winsock's SO_EXCLUSIVEADDRUSE.
const soExclusiveAddrUse = ^syscall.SO_REUSEADDR

// listenOne listens on one address (host:port), taking its port exclusively
// (SO_EXCLUSIVEADDRUSE): otherwise another local user could bind the same
// port on a more specific address, such as 127.0.0.1 under a 0.0.0.0
// listener, and take the connections meant for it. Binding a port another
// socket already holds fails instead of sharing it.
func listenOne(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}

// familyUnavailable reports whether a listen failed because this system has
// no such address family at all, as for ::1 on a system without IPv6, so no
// other process can listen there either.
func familyUnavailable(err error) bool {
	return errors.Is(err, windows.WSAEAFNOSUPPORT) || errors.Is(err, windows.WSAEPFNOSUPPORT) ||
		errors.Is(err, windows.WSAEPROTONOSUPPORT)
}

// addrNotHere reports whether a listen failed because the address is not
// this system's now, as an IPv6 address is not until duplicate address
// detection is over.
func addrNotHere(err error) bool { return errors.Is(err, windows.WSAEADDRNOTAVAIL) }

// addrInUse reports whether a listen failed because the port is taken;
// winsock reports a port another socket holds exclusively as access denied.
func addrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
