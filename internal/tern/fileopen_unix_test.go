// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A download opens what it sends without waiting on it: a path swapped for
// a FIFO after the agent checked it is refused at once, where opening the
// FIFO would wait for a writer that never comes.
func TestOpenRegularRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, _, err := openRegular(fifo)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Fatalf("opening a FIFO: %v", err)
		}
	case <-time.After(3 * time.Second):
		os.WriteFile(fifo, nil, 0) // let the open go on, so the goroutine ends
		t.Fatal("opening a FIFO waited for a writer")
	}

	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("content"), 0o600)
	f, info, err := openRegular(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, err := io.ReadAll(f); err != nil || string(b) != "content" || info.Size() != 7 {
		t.Fatalf("read %q, %v, size %d", b, err, info.Size())
	}
}
