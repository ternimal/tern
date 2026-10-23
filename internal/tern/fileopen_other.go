// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package tern

import (
	"io/fs"
	"os"
	"syscall"
)

// openRegular opens path for reading if it is a regular file. What path
// names is looked at first, so a device or FIFO named outright is refused
// without being opened. A name swapped after that look is still opened
// non-blocking, so a FIFO opens at once instead of waiting for a writer
// (which may never come, holding the goroutine and its file descriptor), and
// with O_NOCTTY, so a terminal never becomes ternd's controlling terminal;
// whatever was opened is refused unless fstat says it is a regular file, and
// one that is goes back to blocking reads, which some file systems need even
// for those.
func openRegular(path string) (*os.File, os.FileInfo, error) { return openChecked(path, false) }

// openRegularOrPipe is openRegular that also takes a pipe (a FIFO), such as
// the one a shell's <(...) names, which stays non-blocking (see readPipe).
func openRegularOrPipe(path string) (*os.File, os.FileInfo, error) { return openChecked(path, true) }

// openChecked is openRegular, taking a pipe too when pipes is set.
func openChecked(path string, pipes bool) (*os.File, os.FileInfo, error) {
	taken := func(m fs.FileMode) bool { return m.IsRegular() || pipes && m&fs.ModeNamedPipe != 0 }
	if fi, err := os.Stat(path); err != nil {
		return nil, nil, err
	} else if !taken(fi.Mode()) {
		return nil, nil, errNotRegular
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil && !taken(info.Mode()) {
		err = errNotRegular
	}
	if err == nil && info.Mode().IsRegular() {
		err = setBlocking(f)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
