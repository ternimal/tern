// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/unix"
)

// ctty returns this process's controlling terminal (tty_nr, 0 for none),
// from /proc/self/stat.
func ctty(t *testing.T) int {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	n, _ := strconv.Atoi(f[4])
	return n
}

// swapping keeps exchanging the names a and b, as another local user who
// may rename entries in their directory can, until the test ends.
func swapping(t *testing.T, a, b string) {
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			if unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE) != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		stop.Store(true)
		<-done
	})
}

// A file another local user can rename is downloaded while that user keeps
// swapping it with a link to a terminal whose master they hold. ternd, run
// as a service is, leads a session with no controlling terminal: had the
// download opened the terminal, it would have become ternd's controlling
// terminal, and a ^C typed on the master a SIGINT that ends ternd with every
// session it serves.
func TestDownloadOfSwappedTerminal(t *testing.T) {
	if os.Getenv("TERN_TEST_SESSION_LEADER") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "TERN_TEST_SESSION_LEADER=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // a session of its own, no terminal
		out, err := cmd.CombinedOutput()
		switch {
		case bytes.Contains(out, []byte("--- FAIL")):
			t.Fatalf("as a session leader with no terminal (%v):\n%s", err, out)
		case bytes.Contains(out, []byte("--- SKIP")):
			t.Skipf("skipped as a session leader:\n%s", out)
		case !bytes.Contains(out, []byte("--- PASS")):
			t.Fatalf("the session-leader run did not finish, killed by a signal? (%v):\n%s", err, out)
		}
		return
	}
	if ctty(t) != 0 {
		t.Skip("already has a controlling terminal")
	}
	p, err := pty.New()
	if err != nil {
		t.Skip(err)
	}
	defer p.Close()
	up, ok := p.(pty.UnixPty)
	if !ok {
		t.Skip("no Unix pty")
	}
	slave := up.Name()
	os.Chmod(slave, 0o666) // its owner lets others open it
	// Kept to the end of the run: closing a controlling terminal hangs it up.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	dir := t.TempDir()
	reg, lnk := filepath.Join(dir, "app.log"), filepath.Join(dir, "swap")
	if err := os.WriteFile(reg, []byte("log line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(slave, lnk); err != nil {
		t.Fatal(err)
	}
	swapping(t, reg, lnk)
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	refused := 0
	for i := 0; i < 1000 && ctty(t) == 0; i++ {
		if _, _, err := cl.ReadFile(reg, 0, 64, nil); err != nil && strings.Contains(err.Error(), "not a regular file") {
			refused++
		}
	}
	if n := ctty(t); n != 0 {
		up.Master().Write([]byte{0x03}) // ^C on the other user's side
		select {
		case s := <-sigs:
			t.Errorf("a download made %s ternd's controlling terminal; ^C on its master reached ternd as %v", slave, s)
		case <-time.After(2 * time.Second):
			t.Errorf("a download made %s ternd's controlling terminal (tty_nr %d)", slave, n)
		}
	}
	if refused == 0 {
		t.Error("no download met the terminal: the test exercised nothing")
	}
}

// A download refuses anything but a regular file, and never opens one to
// find out: opening a device can act on it. The name is swapped with a link
// to /dev/full meanwhile, and inotify counts the times the device is opened.
func TestDownloadNeverOpensSwappedDevice(t *testing.T) {
	const dev = "/dev/full"
	in, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Skip(err)
	}
	defer unix.Close(in)
	if _, err := unix.InotifyAddWatch(in, dev, unix.IN_OPEN); err != nil {
		t.Skip(err)
	}
	opens := func() int {
		n := 0
		buf := make([]byte, 64<<10)
		for {
			k, err := unix.Read(in, buf)
			if err != nil || k <= 0 {
				return n
			}
			for off := 0; off+unix.SizeofInotifyEvent <= k; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				if ev.Mask&unix.IN_OPEN != 0 {
					n++
				}
				off += unix.SizeofInotifyEvent + int(ev.Len)
			}
		}
	}
	dir := t.TempDir()
	reg, lnk := filepath.Join(dir, "app.log"), filepath.Join(dir, "swap")
	if err := os.WriteFile(reg, []byte("log line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dev, lnk); err != nil {
		t.Fatal(err)
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	opens() // anything else's, before the swapping starts
	swapping(t, reg, lnk)
	// inotify merges an event into an identical one still unread, so the
	// queue is drained after every download.
	n, refused := 0, 0
	for i := 0; i < 1000; i++ {
		if _, _, err := cl.ReadFile(reg, 0, 64, nil); err != nil && strings.Contains(err.Error(), "not a regular file") {
			refused++
		}
		n += opens()
	}
	if n > 0 {
		t.Errorf("the agent opened %s, a device a download refuses, %d times in 1000 downloads", dev, n)
	}
	if refused == 0 {
		t.Error("no download met the device: the test exercised nothing")
	}
}
