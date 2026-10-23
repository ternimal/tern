// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// raceFor bounds how long a test keeps a name swapping under the agent.
const raceFor = 5 * time.Second

// exchange swaps the names a and b at once, as another local user who owns
// the directory holding both can.
func exchange(t *testing.T, a, b string) {
	t.Helper()
	if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err != nil {
		t.Skipf("renameat2 RENAME_EXCHANGE: %v", err)
	}
}

// keepExchanging swaps a and b over and over until the returned stop is
// called, which reports how many swaps were made. It yields after each
// swap, so it never starves the agent and the client of a single CPU.
func keepExchanging(t *testing.T, a, b string) (stop func() int64) {
	exchange(t, a, b)
	var done atomic.Bool
	var n atomic.Int64
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for !done.Load() {
			if unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE) != nil {
				return
			}
			n.Add(1)
			runtime.Gosched()
		}
	}()
	stopped := false
	stop = func() int64 {
		if !stopped {
			stopped = true
			done.Store(true)
			<-finished
		}
		return n.Load()
	}
	t.Cleanup(func() { stop() })
	return stop
}

// sharedAndProtected builds the layout of a directory another local user
// controls, inside what a client may reach, next to a protected one it must
// never reach: shared/sub is a real directory and shared/lnk a link to
// protected, and that user can swap the two names at will.
func sharedAndProtected(t *testing.T) (sub, lnk, protected string) {
	shared := t.TempDir()
	protected = t.TempDir()
	sub, lnk = filepath.Join(shared, "sub"), filepath.Join(shared, "lnk")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, lnk); err != nil {
		t.Fatal(err)
	}
	return sub, lnk, protected
}

// The real path of an open file is where that file is, whatever happens to
// the name it was opened by: through a link that is then swapped away, after
// a rename, and not at all once the file is deleted.
func TestOpenedRealPathFollowsTheFile(t *testing.T) {
	sub, lnk, protected := sharedAndProtected(t)
	if err := os.WriteFile(filepath.Join(protected, "f"), []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("plain"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantProtected, _ := filepath.EvalSymlinks(filepath.Join(protected, "f"))

	f, _, err := openRegular(filepath.Join(lnk, "f")) // the protected file
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	exchange(t, sub, lnk) // the name it was opened by now leads to the plain file
	if real, err := openedRealPath(f); err != nil || real != wantProtected {
		t.Errorf("after the swap, Real = %q, %v; want %q, the file that was opened", real, err, wantProtected)
	}

	moved := filepath.Join(protected, "g")
	if err := os.Rename(filepath.Join(protected, "f"), moved); err != nil {
		t.Fatal(err)
	}
	wantMoved, _ := filepath.EvalSymlinks(moved)
	if real, err := openedRealPath(f); err != nil || real != wantMoved {
		t.Errorf("after a rename, Real = %q, %v; want %q", real, err, wantMoved)
	}

	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	if real, err := openedRealPath(f); err == nil {
		t.Errorf("a deleted file has Real %q; want an error, which reports it unresolved", real)
	}
}

// A download reports as Real the path of the file it sends. Another local
// user swapping a directory for a link to a protected tree, over and over,
// while the agent opens and resolves the path, never gets a client that
// refuses that tree to approve a path outside it and be sent a file inside.
func TestDownloadRealNamesTheFileSent(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	sub, lnk, protected := sharedAndProtected(t)
	private := []byte("protected content\n")
	if err := os.WriteFile(filepath.Join(protected, "app.log"), private, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "app.log"), []byte("plain log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	protectedReal, _ := filepath.EvalSymlinks(protected)
	check := func(real string, _ os.FileMode, _ bool) error {
		if strings.HasPrefix(real, "unresolved") || strings.HasPrefix(real, protectedReal+"/") {
			return errors.New("refused: " + real)
		}
		return nil
	}
	stop := keepExchanging(t, sub, lnk)
	var refused, plain int
	for i, end := 0, time.Now().Add(raceFor); i < 2000 && time.Now().Before(end); i++ {
		b, _, err := cl.ReadFile(filepath.Join(sub, "app.log"), 0, 1<<20, check)
		switch {
		case err != nil && strings.HasPrefix(err.Error(), "refused"):
			refused++
		case err != nil:
			t.Fatalf("read %d: %v", i, err)
		case bytes.Equal(b, private):
			t.Fatalf("read %d: the client approved a path outside %s and was sent a file inside it", i, protected)
		default:
			plain++
		}
	}
	t.Logf("%d swaps; %d reads refused, %d read the plain file", stop(), refused, plain)
	if plain == 0 {
		t.Error("no read was approved: the test exercised nothing")
	}
}

// An upload lands where the path it reported as Real says. Another local user
// swapping a directory for a link to a protected one, over and over, never
// gets an upload a client approved for outside that directory written into
// it.
func TestUploadLandsWhereRealSays(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	sub, lnk, protected := sharedAndProtected(t)
	protectedReal, _ := filepath.EvalSymlinks(protected)
	check := func(real string) error {
		if strings.HasPrefix(real, "unresolved") || strings.HasPrefix(real, protectedReal+"/") {
			return errors.New("refused: " + real)
		}
		return nil
	}
	content := []byte("[Unit]\nDescription=x\n")
	landed := filepath.Join(protected, "x.service")
	stop := keepExchanging(t, sub, lnk)
	var refused, failed, written int
	for i, end := 0, time.Now().Add(raceFor); i < 1000 && time.Now().Before(end); i++ {
		err := cl.WriteFile(filepath.Join(sub, "x.service"), bytes.NewReader(content), int64(len(content)), 0o644, check)
		switch {
		case err != nil && strings.HasPrefix(err.Error(), "refused"):
			refused++
		case err != nil:
			failed++
		default:
			written++
		}
		if _, err := os.Lstat(landed); err == nil {
			t.Fatalf("upload %d: an upload approved for outside %s was written into it", i, protected)
		}
	}
	t.Logf("%d swaps; %d uploads refused, %d failed, %d written", stop(), refused, failed, written)
	if written == 0 {
		t.Error("no upload was approved: the test exercised nothing")
	}
	// Working in the opened directory, an approved upload has nothing to
	// trip over: none fails because a name moved.
	if failed > 0 {
		t.Errorf("%d approved uploads failed", failed)
	}
	// A refused upload's temporary file goes once the agent sees the refusal.
	waitNoTemp(t, protected)
	if ents, _ := os.ReadDir(protected); len(ents) != 0 {
		t.Errorf("the protected directory holds %d entries", len(ents))
	}
}

// An upload works inside the directory it opened: the directory's name
// swapped for a link before the file is written changes nothing about where
// it lands, and Real names that directory.
func TestUploadStaysInOpenedDirectory(t *testing.T) {
	sub, lnk, protected := sharedAndProtected(t)
	subReal, _ := filepath.EvalSymlinks(sub)
	tg, err := openUploadTarget(sub+"/f", sub, "f", 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.close()
	if want := filepath.Join(subReal, "f"); tg.real != want {
		t.Errorf("Real = %q, want %q", tg.real, want)
	}
	exchange(t, sub, lnk) // the opened directory is now named lnk; sub leads to protected
	if _, err := tg.tmp.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tg.finish(); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(lnk, "f")); err != nil || string(b) != "data" {
		t.Errorf("the opened directory holds %q, %v; want the upload", b, err)
	}
	if ents, _ := os.ReadDir(protected); len(ents) != 0 {
		t.Errorf("the upload reached the directory swapped in: %d entries", len(ents))
	}
}

// A directory this user may write into but not list still takes uploads.
func TestUploadIntoUnlistableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := filepath.Join(t.TempDir(), "dropbox")
	if err := os.Mkdir(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	var real string
	check := func(r string) error { real = r; return nil }
	if err := cl.WriteFile(filepath.Join(dir, "in"), strings.NewReader("x"), 1, 0o600, check); err != nil {
		t.Fatalf("upload into a write-only directory: %v", err)
	}
	os.Chmod(dir, 0o700)
	if want, _ := filepath.EvalSymlinks(filepath.Join(dir, "in")); real != want {
		t.Errorf("Real = %q, want %q", real, want)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "in")); string(b) != "x" {
		t.Errorf("the file holds %q", b)
	}
}

// A download works inside the destination directory it opened: the
// directory's name swapped for a link to a protected one while the file is
// on its way changes nothing about where it lands.
func TestDownloadStaysInOpenedDirectory(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, gate := dialSlowed(t, a, fp)
	defer cl.Close()
	sub, lnk, protected := sharedAndProtected(t)
	content := bytes.Repeat([]byte("payload\n"), 500000)
	src := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cl.CopyFrom(src, filepath.Join(sub, "x.service")) }()
	holdOnTemp(t, gate, sub, ".x.service.tern-*", done)
	exchange(t, sub, lnk) // the opened directory is now named lnk; sub leads to protected
	gate.release()
	if err := <-done; err != nil {
		t.Fatalf("the download failed: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(lnk, "x.service")); err != nil || fi.Size() != int64(len(content)) {
		t.Errorf("the opened directory does not hold the download: %v", err)
	}
	if ents, _ := os.ReadDir(protected); len(ents) != 0 {
		t.Errorf("the download reached the directory swapped in: %d entries", len(ents))
	}
}

// accessEvents counts and drains the IN_ACCESS events waiting on the
// inotify descriptor in.
func accessEvents(in int) int {
	n := 0
	buf := make([]byte, 64<<10)
	for {
		k, err := unix.Read(in, buf)
		if err != nil || k <= 0 {
			return n
		}
		for off := 0; off+unix.SizeofInotifyEvent <= k; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			if ev.Mask&unix.IN_ACCESS != 0 {
				n++
			}
			off += unix.SizeofInotifyEvent + int(ev.Len)
		}
	}
}

// A download that a client checking paths refuses, on the reply's Real path
// or for its size, reads nothing of the file: reading some files acts, as
// /proc/kmsg hands each message to one reader only. A download it goes ahead
// with is read and sent.
func TestRefusedDownloadReadsNothing(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	allowed, outside := filepath.Join(dir, "allowed"), filepath.Join(dir, "outside")
	for _, d := range []string{allowed, outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(outside, "other.log")
	content := bytes.Repeat([]byte("a line of another file\n"), 4000)
	if err := os.WriteFile(other, content, 0o644); err != nil {
		t.Fatal(err)
	}
	in, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Skipf("inotify: %v", err)
	}
	defer unix.Close(in)
	if _, err := unix.InotifyAddWatch(in, other, unix.IN_ACCESS); err != nil {
		t.Skipf("inotify: %v", err)
	}
	// A name under the allowed directory that another local user swapped
	// for a link to the file outside.
	name := filepath.Join(allowed, "app.log")
	if err := os.Symlink(other, name); err != nil {
		t.Fatal(err)
	}
	allowedReal, _ := filepath.EvalSymlinks(allowed)
	inAllowed := func(real string, _ os.FileMode, _ bool) error {
		if !strings.HasPrefix(real, allowedReal+"/") {
			return errors.New("refused: " + real + " is outside the readable paths")
		}
		return nil
	}
	anywhere := func(string, os.FileMode, bool) error { return nil }
	if _, _, err := cl.ReadFile(name, 0, 64, inAllowed); err == nil || !strings.HasPrefix(err.Error(), "refused") {
		t.Fatalf("the client did not refuse the file outside: %v", err)
	}
	if _, _, err := cl.ReadTo(other, io.Discard, 100, anywhere); err == nil || !strings.Contains(err.Error(), "over the 100 byte limit") {
		t.Fatalf("the client did not refuse a file over its limit: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := accessEvents(in); n > 0 {
		t.Errorf("the agent read the file %d times for downloads the client refused", n)
	}
	b, size, err := cl.ReadFile(other, 0, 64, anywhere)
	if err != nil || !bytes.Equal(b, content[:64]) || size != int64(len(content)) {
		t.Fatalf("a download gone ahead with: %q, size %d, %v", b, size, err)
	}
	time.Sleep(100 * time.Millisecond)
	if accessEvents(in) == 0 {
		t.Error("no read of a file that was sent was seen: reads go unseen here")
	}
}
