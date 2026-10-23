// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// dirOpenFlags open a directory to work in by descriptor.
const dirOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC

// fdPathBuf receives F_GETPATH's answer. It is a package variable, so it
// never moves while the kernel writes to it through the address fcntl gets
// as an integer.
var (
	fdPathMu  sync.Mutex
	fdPathBuf [unix.PathMax]byte
)

// fdPath returns the path the kernel reports for the open descriptor fd:
// where the file it names is now, whatever name it was opened by.
func fdPath(fd int) (string, error) {
	fdPathMu.Lock()
	defer fdPathMu.Unlock()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&fdPathBuf[0])))); err != nil {
		return "", err
	}
	n := bytes.IndexByte(fdPathBuf[:], 0)
	if n < 0 {
		return "", errors.New("the path of an open file is too long")
	}
	return string(fdPathBuf[:n]), nil
}
