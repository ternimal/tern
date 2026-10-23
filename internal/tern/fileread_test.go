// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A client that stops reading early (ReadFile takes a prefix, ReadTo refuses
// a file over its limit) must not leave the agent blocked on the stream with
// the file open until the stream times out.
func TestEarlyCloseReleasesFile(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 8<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if b, _, err := cl.ReadFile(big, 0, 10, nil); err != nil || len(b) != 10 {
			t.Fatalf("ReadFile = %d bytes, %v", len(b), err)
		}
	}
	if _, _, err := cl.ReadTo(big, io.Discard, 100, nil); err == nil {
		t.Fatal("ReadTo over the limit succeeded")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		n := strings.Count(string(buf[:runtime.Stack(buf, true)]), "tern.serveFile")
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d agent file streams still blocked after the client closed them", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Kernel files report size 0 but have content; the agent reports the size it
// actually read, also to a client that checks the reply first, which then
// refuses a file over its limit once that size is known.
func TestReadSizeZeroFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses /proc")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	anywhere := func(string, os.FileMode, bool) error { return nil }
	for _, check := range []ReadCheck{nil, anywhere} {
		b, size, err := cl.ReadFile("/proc/self/status", 0, 1<<20, check)
		if err != nil || len(b) == 0 || int64(len(b)) != size || !bytes.Contains(b, []byte("Name:")) {
			t.Fatalf("ReadFile(/proc/self/status) = %d bytes, size %d, %v (checked: %v)", len(b), size, err, check != nil)
		}
		if _, _, err := cl.ReadTo("/proc/self/status", io.Discard, 10, check); err == nil || !strings.Contains(err.Error(), "over the 10 byte limit") {
			t.Errorf("a size-0 file over the limit: %v (checked: %v)", err, check != nil)
		}
	}
}

// A file that reports size 0 is read only once the client, having checked
// the reply, says go ahead, as reading some such files acts on them: one
// written to while the client checks comes down with what was written then.
func TestSizeZeroFileReadAfterGoAhead(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	name := filepath.Join(t.TempDir(), "grows")
	if err := os.WriteFile(name, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	late := []byte("written while the client checked the reply\n")
	writeLate := func(string, os.FileMode, bool) error {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(late)
		return err
	}
	for try := range 20 {
		if err := os.Truncate(name, 0); err != nil {
			t.Fatal(err)
		}
		b, size, err := cl.ReadFile(name, 0, 1<<10, writeLate)
		if err != nil || !bytes.Equal(b, late) || size != int64(len(late)) {
			t.Fatalf("try %d: read %q (size %d, %v): the agent read the file before the client's go-ahead", try, b, size, err)
		}
	}
}

// A file downloads whole, an empty one as empty, whether or not the client
// checks the reply first and the agent waits for its go-ahead.
func TestDownloadWithOrWithoutCheck(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	empty, full := filepath.Join(dir, "empty"), filepath.Join(dir, "full")
	content := bytes.Repeat([]byte("a line of the file\n"), 30000) // more than a stream's window
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
	anywhere := func(string, os.FileMode, bool) error { return nil }
	for _, check := range []ReadCheck{nil, anywhere} {
		for _, f := range []struct {
			path string
			want []byte
		}{{empty, nil}, {full, content}} {
			b, size, err := cl.ReadFile(f.path, 0, int64(len(f.want))+10, check)
			if err != nil || !bytes.Equal(b, f.want) || size != int64(len(f.want)) {
				t.Errorf("ReadFile(%s) = %d bytes, size %d, %v (checked: %v)", filepath.Base(f.path), len(b), size, err, check != nil)
			}
			var buf bytes.Buffer
			n, _, err := cl.ReadTo(f.path, &buf, 1<<20, check)
			if err != nil || n != int64(len(f.want)) || !bytes.Equal(buf.Bytes(), f.want) {
				t.Errorf("ReadTo(%s) = %d, %d bytes, %v (checked: %v)", filepath.Base(f.path), n, buf.Len(), err, check != nil)
			}
		}
	}
	for _, src := range []string{empty, full} {
		dst := src + ".copy"
		if err := cl.CopyFrom(src, dst); err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(src)
		if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, want) {
			t.Errorf("the copy of %s holds %d bytes, %v", filepath.Base(src), len(got), err)
		}
	}
}
