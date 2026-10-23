// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// checkKeyFileAccess refuses a key file another user owns or that has any
// group or other permission bit, as for a token file (see
// secretFileProblem), saying how to fix it.
func checkKeyFileAccess(path string, fi fs.FileInfo) error {
	if p := secretFileProblem(path, fi, os.Getuid(), agentKeyWords); p != nil {
		return &keyFileError{problem: p.problem, fix: p.fix}
	}
	return nil
}

// pipeKeyWait is the longest a client key given through a pipe may take to
// come whole, from the open to its writer closing the pipe: long enough for
// the command that writes it to ask for a passphrase or an approval first,
// as op read or gpg may. Tests shorten it.
var pipeKeyWait = 30 * time.Second

// readClientKey reads a client's private key from path, a regular file or a
// pipe, such as a shell's <(op read ...), refusing before it reads anything
// one ssh would refuse (see clientKeyProblem); pipe reports which it was, as
// a pipe can be read once only. A regular file is read as a token file is,
// within maxSecretFile; a pipe until its writer closes it, within
// maxSecretFile and pipeKeyWait (see readPipe).
func readClientKey(path string) (data []byte, pipe bool, err error) {
	f, fi, err := openRegularOrPipe(path)
	if errors.Is(err, errNotRegular) {
		return nil, false, fmt.Errorf("%s is not a regular file or a pipe", path)
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if p := clientKeyProblem(path, fi, os.Getuid()); p != nil {
		return nil, false, p
	}
	if fi.Mode().IsRegular() {
		data, err := readOpened(f, fi, path, maxSecretFile)
		return data, false, err
	}
	data, err = readPipe(f, path, maxSecretFile, pipeKeyWait)
	return data, true, err
}

// clientKeyProblem judges a client's private key by its status, fi, for the
// user uid, as ssh judges one: a key this user owns may have no group or
// other permission bit, as others could read it then (see
// secretFileProblem), while one another account owns, root's included, is
// taken as it is, its owner being free to use it anyway: a deploy key root
// keeps for a group (root:group 0640), or a Kubernetes secret volume's. A
// pipe must be this user's, or anyone could send any key through it; one
// that has no name, as a shell's <(...) has none on macOS, where it shows
// mode 0660, cannot be opened by anyone else, whatever its mode.
func clientKeyProblem(path string, fi fs.FileInfo, uid int) *secretFileError {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return secretFileProblem(path, fi, uid, clientKeyWords)
	}
	pipe := fi.Mode()&fs.ModeNamedPipe != 0
	switch {
	case int(st.Uid) == uid && pipe && st.Nlink == 0:
		return nil
	case int(st.Uid) == uid:
		return secretFileProblem(path, fi, uid, clientKeyWords)
	case pipe:
		return &secretFileError{path: path,
			problem: fmt.Sprintf("it is a pipe that uid %d made, not this user (uid %d), and any key could come through it", st.Uid, uid),
			fix:     "give the key in a file, or a pipe, of this user's"}
	}
	return nil
}

// readPipe reads what comes through the pipe f, the file at path, until its
// writer closes it, refusing more than max bytes or a wait of more than wait.
// It reads the descriptor itself, non-blocking, and waits for more with poll
// for a short while at a time, so a writer that is slow to start, or never
// closes the pipe, holds it no longer than wait, and an end that wakes no
// poll is still seen at the next read.
func readPipe(f *os.File, path string, max int64, wait time.Duration) ([]byte, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	b := make([]byte, 0, max) // never grown, so no copy of the key is left behind
	var rerr error
	err = rc.Control(func(fd uintptr) {
		if rerr = unix.SetNonblock(int(fd), true); rerr != nil {
			return
		}
		buf := make([]byte, 4<<10)
		defer clear(buf)
		for {
			var n int
			err := ignoringEINTR(func() (err error) { n, err = unix.Read(int(fd), buf); return err })
			switch {
			case err == nil && n == 0:
				return // its writer closed it
			case err == nil && int64(len(b)+n) > max:
				rerr = fmt.Errorf("%s sent more than the %d KiB tern reads of a key", path, max>>10)
				return
			case err == nil:
				b = append(b, buf[:n]...)
				continue
			case err != unix.EAGAIN:
				rerr = &os.PathError{Op: "read", Path: path, Err: err}
				return
			}
			left := time.Until(deadline)
			if left <= 0 {
				rerr = fmt.Errorf("%s is a pipe whose writer did not close it within %v", path, wait)
				return
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			ignoringEINTR(func() error {
				_, err := unix.Poll(fds, int(min(left, 100*time.Millisecond).Milliseconds())+1)
				return err
			})
		}
	})
	if err == nil {
		err = rerr
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}
