// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// openRegular opens path for reading if it is a regular file. It first opens
// what path names with O_PATH, which runs no device's open, waits for no
// FIFO's writer and never makes a terminal ternd's controlling terminal, and
// refuses whatever fstat says is not a regular file. Only then is the file
// opened for reading, through that descriptor (/proc/self/fd/N), so it is
// the very file that was looked at however the name is swapped meanwhile.
// Without /proc it is opened by name again, non-blocking and never as a
// controlling terminal, and must still be that file.
func openRegular(path string) (*os.File, os.FileInfo, error) { return openChecked(path, false) }

// openRegularOrPipe is openRegular that also takes a pipe (a FIFO), such as
// the one a shell's <(...) names. A pipe is opened non-blocking, so the open
// waits for no writer and stays non-blocking (see readPipe).
func openRegularOrPipe(path string) (*os.File, os.FileInfo, error) { return openChecked(path, true) }

// openChecked is openRegular, taking a pipe too when pipes is set.
func openChecked(path string, pipes bool) (*os.File, os.FileInfo, error) {
	var pfd int
	err := ignoringEINTR(func() (err error) { pfd, err = unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0); return err })
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	typ := st.Mode & unix.S_IFMT
	pipe := pipes && typ == unix.S_IFIFO
	if typ != unix.S_IFREG && !pipe {
		return nil, nil, errNotRegular
	}
	flags := os.O_RDONLY | syscall.O_NOCTTY
	if pipe {
		flags |= syscall.O_NONBLOCK
	}
	f, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(pfd), flags, 0)
	byName := errors.Is(err, os.ErrNotExist)
	if byName {
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	info, err := f.Stat()
	if err == nil {
		if fst, ok := info.Sys().(*syscall.Stat_t); !ok || uint64(fst.Dev) != uint64(st.Dev) || fst.Ino != st.Ino {
			err = errors.New("the path changed while it was being opened")
		} else if !info.Mode().IsRegular() && !(pipe && info.Mode()&os.ModeNamedPipe != 0) {
			err = errNotRegular
		}
	}
	if err == nil && byName && !pipe {
		err = setBlocking(f)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
