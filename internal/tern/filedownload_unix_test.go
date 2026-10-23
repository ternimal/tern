// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A file that reports size 0 is read for what it holds now: one that would
// wait for more, as /proc/kmsg and tracing pipes do, and as a pipe does
// here, is not waited on, though Go's poller would wait on it. The read
// takes at most its limit, and refuses a file still being read when its
// time is up.
func TestReadPseudoEndsAtWhatIsThere(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close() // also ends a read that waits
	if _, err := w.Write([]byte("kernel message\n")); err != nil {
		t.Fatal(err)
	}
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := readPseudo(r, 1<<20, time.Minute)
		done <- result{b, err}
	}()
	select {
	case res := <-done:
		if res.err != nil || string(res.b) != "kernel message\n" {
			t.Fatalf("read %q, %v", res.b, res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read waited for more instead of ending at what was there")
	}
	if _, err := w.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if b, err := readPseudo(r, 4, time.Minute); err != nil || string(b) != "0123" {
		t.Errorf("a read limited to 4 bytes gave %q, %v", b, err)
	}
	if b, err := readPseudo(r, 1<<20, -time.Second); err == nil || !strings.Contains(err.Error(), "still being read") {
		t.Errorf("a read past its time gave %q, %v", b, err)
	}
}

// Downloading a FIFO (or any non-regular file) is refused instead of
// wedging the serving goroutine in os.Open forever.
func TestDownloadRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	sa, sb := loopbackPair(t)
	go serveFile(sb, streamHeader{Kind: kindFile, Op: fileRecv, Path: fifo})
	done := make(chan streamReply, 1)
	go func() { rep, _ := readReply(sa); done <- rep }()
	select {
	case rep := <-done:
		if rep.OK || !strings.Contains(rep.Err, "regular") {
			t.Fatalf("FIFO download not refused: %+v", rep)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveFile wedged on a FIFO download")
	}
	sa.Close()
}
