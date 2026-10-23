// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// splitUploadPath splits p into the directory to resolve and the file name.
// The directory keeps its "..": after a link it climbs from the link's
// target, as the kernel resolves it, which cleaning first would change.
func splitUploadPath(p string) (dir, base string) {
	switch i := strings.LastIndexByte(p, '/'); i {
	case -1:
		return ".", p
	case 0:
		return "/", p[1:]
	default:
		return p[:i], p[i+1:]
	}
}

// realPathOf returns the path of the file open as fd, links resolved, as the
// kernel reports it for the descriptor: the file that was opened, never one
// its name was swapped for since. It checks that the path names that same
// file still, so a file deleted or moved meanwhile is an error, and so is a
// system that cannot report the path (see fdPath).
func realPathOf(fd int) (string, error) {
	p, err := fdPath(fd)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("the open file has no path here (%q)", p)
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return "", err
	}
	if err := unix.Stat(p, &named); err != nil || named.Dev != opened.Dev || named.Ino != opened.Ino {
		return "", errors.New("the path changed while it was being opened")
	}
	return p, nil
}

// openedRealPath returns the path the open file f really has, links
// resolved: the one the kernel reports for its descriptor, so a name swapped
// for a link to another file after the open cannot make it report a path
// that is not the file being read.
func openedRealPath(f *os.File) (string, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	var real string
	var rerr error
	if err := rc.Control(func(fd uintptr) { real, rerr = realPathOf(int(fd)) }); err != nil {
		return "", err
	}
	return real, rerr
}

// readPseudo reads a file that reports size 0, such as those under /proc, up
// to limit bytes, and refuses one still being read after maxTime. It reads
// the descriptor itself, non-blocking, and ends at what is there: some such
// files, as /proc/kmsg and tracing pipes do, wait until there is more to
// read, and an os.File waits for that in Go's poller, with which it
// registers every file that supports polling.
func readPseudo(f *os.File, limit int64, maxTime time.Duration) ([]byte, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var b []byte
	var rerr error
	err = rc.Control(func(fd uintptr) {
		if rerr = unix.SetNonblock(int(fd), true); rerr != nil {
			return
		}
		deadline := time.Now().Add(maxTime)
		buf := make([]byte, min(limit, 64<<10))
		for int64(len(b)) < limit {
			if time.Now().After(deadline) {
				b, rerr = nil, fmt.Errorf("file reports size 0 and was still being read after %v", maxTime)
				return
			}
			var n int
			err := ignoringEINTR(func() (err error) {
				n, err = unix.Read(int(fd), buf[:min(int64(len(buf)), limit-int64(len(b)))])
				return err
			})
			switch {
			case err == unix.EAGAIN: // nothing more there now
				return
			case err != nil:
				b, rerr = nil, &os.PathError{Op: "read", Path: f.Name(), Err: err}
				return
			case n == 0: // the end
				return
			}
			b = append(b, buf[:n]...)
		}
	})
	if err != nil {
		return nil, err
	}
	return b, rerr
}
