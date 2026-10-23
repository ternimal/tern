// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"errors"
	"net"
	"syscall"
)

// listenOne listens on one address (host:port).
func listenOne(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// familyUnavailable reports whether a listen failed because this system has
// no such address family at all, as for ::1 on a system without IPv6, so no
// other process can listen there either.
func familyUnavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

// addrNotHere reports whether a listen failed because the address is not
// this system's now, as an IPv6 address is not until duplicate address
// detection is over, a second or so after its link comes up.
func addrNotHere(err error) bool { return errors.Is(err, syscall.EADDRNOTAVAIL) }

// addrInUse reports whether a listen failed because the port is taken.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
