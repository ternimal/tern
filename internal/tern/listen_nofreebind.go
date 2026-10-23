// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package tern

import (
	"errors"
	"net"
)

// listenAbsent would hold the port on addr, whose host this system does not
// have now. Here a socket cannot bind such an address without privilege, so
// nobody else can listen there before the address comes up either, but
// anyone can once it has: the caller warns (see bindAddrs.listenAll).
func listenAbsent(string) (net.Listener, error) { return nil, errors.ErrUnsupported }
