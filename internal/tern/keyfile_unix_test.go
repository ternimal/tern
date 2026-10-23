// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// exposeToOthers makes path readable by every local user.
func exposeToOthers(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// letOthersChange makes path writable by every local user.
func letOthersChange(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o646); err != nil {
		t.Fatal(err)
	}
}

// A client's private key is judged as ssh judges one: a key this user owns
// may have no group or other bit, but one another account owns, root's
// included, is taken whatever its mode (a deploy key root keeps for a group,
// a Kubernetes secret volume's). A pipe must be this user's; one with no
// name, as macOS shows a shell's <(...) (mode 0660, no link), is not held to
// its mode, but a named one is.
func TestClientKeyRule(t *testing.T) {
	const self, other = 1000, 1001
	pipe := func(uid uint32, mode fs.FileMode, named bool) fs.FileInfo {
		s := statOwned{mode: mode | fs.ModeNamedPipe}
		s.st.Uid = uid
		if named {
			s.st.Nlink = 1
		}
		return s
	}
	for _, c := range []struct {
		name string
		fi   fs.FileInfo
		want string // what the refusal says; "" when the key is taken
	}{
		{"own 0600", ownedBy(self, self, 0o600), ""},
		{"own 0400", ownedBy(self, self, 0o400), ""},
		{"own 0640", ownedBy(self, self, 0o640), "others may have read the key"},
		{"own 0604", ownedBy(self, self, 0o604), "others may have read the key"},
		{"own 0610", ownedBy(self, self, 0o610), "restrict it: chmod 600"},
		{"root's 0640", ownedBy(0, self, 0o640), ""},
		{"root's 0440", ownedBy(0, self, 0o440), ""},
		{"another's 0644", ownedBy(other, other, 0o644), ""},
		{"another's 0666", ownedBy(other, other, 0o666), ""},
		{"own pipe 0600", pipe(self, 0o600, true), ""},
		{"own unnamed pipe 0660", pipe(self, 0o660, false), ""},
		{"own named pipe 0644", pipe(self, 0o644, true), "others may have read the key"},
		{"another's pipe", pipe(other, 0o600, true), "a pipe that uid 1001 made"},
		{"root's unnamed pipe", pipe(0, 0o600, false), "a pipe that uid 0 made"},
	} {
		p := clientKeyProblem("/k/id", c.fi, self)
		switch {
		case c.want == "" && p != nil:
			t.Errorf("%s: %v, want taken", c.name, p)
		case c.want != "" && (p == nil || !strings.Contains(p.Error(), c.want)):
			t.Errorf("%s: %v, want refused saying %q", c.name, p, c.want)
		case c.want != "" && !strings.Contains(c.want, "pipe") && !strings.Contains(p.Error(), "chmod 600 /k/id"):
			t.Errorf("%s: %v, want the chmod fix", c.name, p)
		}
	}
}

// keyBytes makes an Ed25519 key with tern keygen's code and returns its
// private file's bytes.
func keyBytes(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "id")
	if _, err := GenerateKeyFiles(p, "t"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pipeKey returns a /dev/fd path for the read end of a new pipe, and the
// write end; both close when the test ends.
func pipeKey(t *testing.T) (string, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return fmt.Sprintf("/dev/fd/%d", r.Fd()), w
}

// A key given through a pipe, as a shell's <(op read ...) gives it, is read
// until its writer closes the pipe, however slowly it comes, and once only:
// a look at whether it is encrypted keeps it for the load that follows.
// Without a writer it reads as empty at once; a writer that never closes it
// is given up on after pipeKeyWait, and one that sends more than a key's
// cap is refused. A FIFO of this user's that others may open is refused,
// as a key file others may read is.
func TestClientKeyThroughPipe(t *testing.T) {
	if _, err := os.Stat("/dev/fd/0"); err != nil {
		t.Skipf("no /dev/fd here: %v", err)
	}
	key := keyBytes(t)
	write := func(w *os.File, parts ...[]byte) {
		for _, p := range parts {
			time.Sleep(100 * time.Millisecond)
			w.Write(p)
		}
		w.Close()
	}

	path, w := pipeKey(t)
	go write(w, key[:20], key[20:])
	if err := waitsNot(t, "a slow pipe", func() error { return PreloadKey(path) }); err != nil {
		t.Fatalf("a key that comes slowly through a pipe: %v", err)
	}
	if err := PreloadKey(path); err != nil {
		t.Errorf("the same path again, the key loaded: %v", err)
	}

	path, w = pipeKey(t)
	go write(w, key)
	if enc, err := KeyNeedsPassphrase(path); err != nil || enc {
		t.Fatalf("KeyNeedsPassphrase through a pipe: %v %v", enc, err)
	}
	if err := PreloadKey(path); err != nil {
		t.Errorf("the key KeyNeedsPassphrase read from a pipe, loaded after: %v", err)
	}
	if _, ok := pipeKeys[path]; ok {
		t.Error("what came through the pipe is still kept after the key loaded")
	}

	path, w = pipeKey(t)
	w.Close()
	start := time.Now()
	if err := waitsNot(t, "a pipe with no writer", func() error { return PreloadKey(path) }); err == nil || time.Since(start) > time.Second {
		t.Errorf("a pipe with no writer: %v after %v", err, time.Since(start))
	}

	defer func(old time.Duration) { pipeKeyWait = old }(pipeKeyWait)
	pipeKeyWait = 300 * time.Millisecond
	path, w = pipeKey(t)
	w.Write(key[:20])
	start = time.Now()
	err := waitsNot(t, "a pipe never closed", func() error { return PreloadKey(path) })
	if err == nil || !strings.Contains(err.Error(), "did not close it within") || time.Since(start) < pipeKeyWait {
		t.Errorf("a pipe never closed: %v after %v", err, time.Since(start))
	}

	path, w = pipeKey(t)
	go func() { w.Write(make([]byte, maxSecretFile+1)); w.Close() }()
	if err := waitsNot(t, "a pipe sending too much", func() error { return PreloadKey(path) }); err == nil || !strings.Contains(err.Error(), "more than the 64 KiB") {
		t.Errorf("a pipe sending more than %d bytes: %v", maxSecretFile, err)
	}

	fifo := filepath.Join(t.TempDir(), "id")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Chmod(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := waitsNot(t, "a FIFO others may open", func() error { return PreloadKey(fifo) }); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("a FIFO others may open: %v", err)
	}
	if err := os.Chmod(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// A reader of the test's own keeps what was written there once the
	// writer is gone, until PreloadKey reads it.
	keep, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	fw, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(key)
	fw.Close()
	if err := waitsNot(t, "a FIFO of this user's", func() error { return PreloadKey(fifo) }); err != nil {
		t.Errorf("a FIFO of this user's: %v", err)
	}
}
