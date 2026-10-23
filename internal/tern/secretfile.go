// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// The most tern reads of a file it is given: a token, a tern1: string or a
// private key fits in maxSecretFile, an authorized_keys or tern mcp config
// file in maxListFile. A larger file is refused before it is read.
const (
	maxSecretFile = 64 << 10
	maxListFile   = 1 << 20
)

// secretFileError says why other local users could read or change a file
// tern reads, and how to fix that.
type secretFileError struct {
	path, problem, fix string
}

func (e *secretFileError) Error() string {
	if e.fix == "" {
		return e.path + ": " + e.problem
	}
	return e.path + ": " + e.problem + "; " + e.fix
}

// fileWords says, in the refusal of a file another user may have written or
// read, what to do about what it holds: owner for a file another user owns,
// and exposed, put in front of the way to restrict it, for a file others may
// read or change. Taking such a file over would keep what someone else put
// in it, or a secret they may know.
type fileWords struct{ owner, exposed string }

var (
	tokenWords = fileWords{
		owner:   "unless you wrote it yourself, delete it and write a new token as this user (tern genkey makes one)",
		exposed: "others may know the token in it: put a new one in it (tern genkey makes one) after you ",
	}
	clientKeyWords = fileWords{
		owner:   "unless you made it yourself, delete it and make a new key as this user with tern keygen",
		exposed: "others may have read the key: make a new one with tern keygen, or, if nobody else could have, ",
	}
	agentKeyWords = fileWords{
		owner:   "unless you put it there, delete it and its .crt, and a new pair is made",
		exposed: "others may have read the key: delete it and its .crt, and a new pair is made, or, if nobody else could have, ",
	}
	configWords = fileWords{
		owner:   "unless you wrote it yourself, delete it and write it again as this user",
		exposed: "make sure it holds only what you wrote, then ",
	}
	authorizedKeysWords = fileWords{
		owner:   "unless you wrote it yourself, delete it and write it again as this user",
		exposed: "make sure it lists only the keys you meant, then ",
	}
	certWords = fileWords{
		owner: "unless you put it there, delete it and its .key, and a new pair is made",
	}
)

// readCheckedFile reads the file at path, which must be a regular file of at
// most max bytes, through one open file. The open waits on nothing (see
// openRegular), so a FIFO or a device put at the path is refused at once,
// unread. check, when not nil, may refuse the open file before anything is
// read from it. No more is read than the size the file had when it was
// opened: a file of /proc that shows a size of 0, such as /proc/kmsg, reads
// as empty rather than waiting for data.
func readCheckedFile(path string, max int64, check func(*os.File, fs.FileInfo) error) ([]byte, error) {
	f, fi, err := openRegular(path)
	if errors.Is(err, errNotRegular) {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if check != nil {
		if err := check(f, fi); err != nil {
			return nil, err
		}
	}
	return readOpened(f, fi, path, max)
}

// readOpened reads f, the regular file at path, whose status is fi when it
// was opened, refusing it unread past max bytes; no more is read than that
// size.
func readOpened(f *os.File, fi fs.FileInfo, path string, max int64) ([]byte, error) {
	if fi.Size() > max {
		return nil, fmt.Errorf("%s holds %d bytes, more than the %d KiB tern reads of such a file", path, fi.Size(), max>>10)
	}
	return io.ReadAll(io.LimitReader(f, fi.Size()))
}

// readSecret reads a file that holds a secret, refusing, before it reads
// anything, one other local users could read or change (see
// secretFileExposure); words say how to replace the secret.
func readSecret(path string, words fileWords) ([]byte, error) {
	return readCheckedFile(path, maxSecretFile, func(f *os.File, fi fs.FileInfo) error {
		exposed, err := secretFileExposure(f, fi, path, words)
		if exposed != nil {
			return exposed
		}
		return err
	})
}

// checkUnchanged refuses the open file f at path, whose status is fi, when
// another local user could change it (see changeExposure), or could have put
// it where path leads (see placeExposure); why says what it holds that
// matters, and words what to do about it.
func checkUnchanged(f *os.File, fi fs.FileInfo, path, why string, words fileWords) error {
	p, err := changeExposure(f, fi, path, words)
	if p == nil && err == nil {
		p, err = placeExposure(path, fi, words)
	}
	if p != nil {
		p.problem = why + ", and " + p.problem
		return p
	}
	return err
}

// plainText is data, read from the file at path, as text, refusing what a
// Windows editor or shell may have saved in a form that would keep bytes no
// one typed: UTF-16 (Windows PowerShell 5.1 writes it with > and Out-File),
// whose NUL bytes would stay in a token, and a byte order mark, which would
// stay at its start.
func plainText(path string, data []byte) (string, error) {
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}), bytes.HasPrefix(data, []byte{0xfe, 0xff}), bytes.IndexByte(data, 0) >= 0:
		return "", fmt.Errorf("%s is UTF-16 text or holds NUL bytes: save it as plain ASCII or UTF-8 text", path)
	case bytes.HasPrefix(data, []byte("\xef\xbb\xbf")):
		return "", fmt.Errorf("%s starts with a byte order mark: save it as plain ASCII or UTF-8 text without one", path)
	}
	return string(data), nil
}

// ReadSecretFile reads a secret, such as a token, from the file at path,
// trailing whitespace trimmed. As ssh does with a private key, it refuses a
// file other local users could read or change: on Unix one with any group or
// other permission bit or another owner, on Windows one another account owns
// or whose ACL lets another account read, change or delete it; the error
// says how to fix it. Nothing is read from a refused file, nor from anything
// but a regular file (see readCheckedFile). An empty file is refused too: a
// file named but empty is a mistake, not a request to go without the
// secret.
func ReadSecretFile(path string) (string, error) {
	data, err := readSecret(path, tokenWords)
	if err != nil {
		return "", err
	}
	s, err := plainText(path, data)
	if err != nil {
		return "", err
	}
	if s = strings.TrimRight(s, " \t\r\n"); s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}

// ReadConnStringFile reads a tern1: connection string from the file at path.
// The string names the agent, and the relay, the client trusts, by address
// and fingerprint, so its file is held to the rules of ReadConfigFile:
// refused when another local user could change it. One that carries a relay
// token is a secret too, so its file is then held to the rules of a token
// file as well (see ReadSecretFile); one without may be read by others.
func ReadConnStringFile(path string) (string, error) {
	var exposed *secretFileError
	data, err := readCheckedFile(path, maxSecretFile, func(f *os.File, fi fs.FileInfo) error {
		if err := checkUnchanged(f, fi, path, "it holds a tern1: string, which names the agent this client trusts", configWords); err != nil {
			return err
		}
		var err error
		exposed, err = secretFileExposure(f, fi, path, tokenWords)
		return err
	})
	if err != nil {
		return "", err
	}
	s, err := plainText(path, data)
	if err != nil {
		return "", err
	}
	s = strings.TrimSpace(s)
	if exposed != nil {
		if c, err := DecodeConnString(s); err == nil && c.RelayToken != "" {
			exposed.problem = "it holds a tern1: string with the relay token, and " + exposed.problem
			return "", exposed
		}
	}
	return s, nil
}

// ReadConfigFile reads a file that says which agents to trust, such as tern
// mcp's config, at most maxListFile bytes of it, from a regular file only
// (see readCheckedFile). As its contents decide where the client connects
// and what it lets through, it is refused, before anything is read, when
// another local user could change it: on Unix one another user owns (root
// aside) or with the other write bit, or the group write bit unless its
// group is the user's own private group and it has no ACL (which only Linux
// lets tern read); on Windows one another account owns (SYSTEM and
// Administrators aside) or whose ACL lets another account change or delete
// it. It is refused too when another user could have put it where the path
// leads (see placeExposure): through a symlink, or, on Unix, the directory
// holding it. Others may read it.
func ReadConfigFile(path string) ([]byte, error) {
	data, err := readCheckedFile(path, maxListFile, func(f *os.File, fi fs.FileInfo) error {
		return checkUnchanged(f, fi, path, "it says which agents to trust", configWords)
	})
	if err != nil {
		return nil, err
	}
	if _, err := plainText(path, data); err != nil {
		return nil, err
	}
	return data, nil
}
