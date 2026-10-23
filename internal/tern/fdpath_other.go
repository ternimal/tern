// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin && !windows

package tern

import (
	"errors"

	"golang.org/x/sys/unix"
)

// dirOpenFlags open a directory to work in by descriptor.
const dirOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC

// fdPath would return the path the kernel has for an open descriptor. This
// system offers no way to ask, and a path resolved by name can be swapped
// between the open and the lookup, so the path is reported as unresolved,
// which a client checking paths refuses; plain copies are unaffected.
func fdPath(int) (string, error) {
	return "", errors.New("this system cannot report the path of an open file")
}
