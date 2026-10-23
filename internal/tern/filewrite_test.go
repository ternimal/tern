// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A destination ending in a separator names a directory: the agent refuses
// it instead of writing a file named after the directory inside it.
func TestUploadDirectoryPathRefused(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := filepath.Join(t.TempDir(), "uploads")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{dir + "/", dir + "/.", dir + "/.."} {
		err := cl.WriteFile(dst, bytes.NewReader([]byte("payload")), 7, 0o644, nil)
		if err == nil || !strings.Contains(err.Error(), "not a file path") {
			t.Errorf("WriteFile(%q) = %v, want a refusal", dst, err)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("the refused uploads left %d entries in %s", len(ents), dir)
	}
}

// A refused path check stops the upload before the agent writes anything,
// for an empty file too, where no content would make the agent wait.
func TestRefusedUploadLeavesFile(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	refuse := func(string) error { return errors.New("refused") }
	for _, content := range []string{"", "new content"} {
		err := cl.WriteFile(victim, strings.NewReader(content), int64(len(content)), 0o666, refuse)
		if err == nil || err.Error() != "refused" {
			t.Fatalf("WriteFile with a refusing check = %v", err)
		}
		b, _ := os.ReadFile(victim)
		info, _ := os.Stat(victim)
		if string(b) != "keep me" || info.Mode().Perm() != 0o600 {
			t.Errorf("a refused %d-byte write changed the file: %q %v", len(content), b, info.Mode())
		}
	}
	waitNoTemp(t, dir)

	// An accepted check writes as usual, an empty file included, and sees the
	// path the agent really writes.
	var seen string
	accept := func(real string) error { seen = real; return nil }
	for _, content := range []string{"", "fresh"} {
		if err := cl.WriteFile(victim, strings.NewReader(content), int64(len(content)), 0o600, accept); err != nil {
			t.Fatalf("WriteFile with an accepting check: %v", err)
		}
		if b, _ := os.ReadFile(victim); string(b) != content {
			t.Errorf("accepted write = %q, want %q", b, content)
		}
	}
	if want, _ := filepath.EvalSymlinks(victim); seen != want {
		t.Errorf("check saw %q, want %q", seen, want)
	}
}

// waitNoTemp fails if the agent leaves its temporary upload file in dir. The
// agent drops it once it sees the client close the stream, a moment after
// the client returns.
func waitNoTemp(t *testing.T, dir string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var left []string
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if strings.Contains(e.Name(), ".tern-") {
				left = append(left, e.Name())
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("temporary upload files left behind: %v", left)
		}
	}
}

// An upload resolves ".." after a link from the link's target, as the kernel
// does, rather than cleaning the path first.
func TestUploadDotDotAfterLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows resolves .. by name")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "x", "y"), 0o755)
	os.MkdirAll(filepath.Join(root, "a"), 0o755)
	if err := os.Symlink(filepath.Join(root, "x", "y"), filepath.Join(root, "a", "b")); err != nil {
		t.Fatal(err)
	}
	p := root + "/a/b/../c"
	if err := cl.WriteFile(p, strings.NewReader("data"), 4, 0o644, nil); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "data" {
		t.Errorf("reading back %s = %q, %v", p, b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "x", "c")); string(b) != "data" {
		t.Errorf("the write did not land in x/c, where the kernel resolves %s", p)
	}
}

// A failed upload must not truncate or replace the existing target.
func TestUploadFailureKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "important")
	os.WriteFile(target, []byte("ORIGINAL-CONTENT"), 0o644)

	sa, sb := loopbackPair(t)
	go serveFile(sb, streamHeader{Kind: kindFile, Op: fileSend, Path: target, Size: 100, FileMode: 0o644})
	if rep, err := readReply(sa); err != nil || !rep.OK {
		t.Fatalf("serveFile reply: %+v %v", rep, err)
	}
	sa.Write([]byte("short")) // fewer than the declared 100 bytes
	sa.Close()                // abort the upload
	time.Sleep(200 * time.Millisecond)

	if b, _ := os.ReadFile(target); string(b) != "ORIGINAL-CONTENT" {
		t.Fatalf("a failed upload changed the target: %q", b)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".important.tern-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp upload file left behind: %v", leftovers)
	}
}
