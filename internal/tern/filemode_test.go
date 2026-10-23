// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Rewriting a file keeps its mode, so an upload of a 0644 copy over a 0600
// file leaves it private; a new file gets the sent mode less the umask.
func TestUploadMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes only set the read-only attribute")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.conf")
	if err := os.WriteFile(secret, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cl.WriteFile(secret, bytes.NewReader([]byte("new")), 3, 0o644, nil); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(secret); fi.Mode().Perm() != 0o600 {
		t.Errorf("rewriting a 0600 file left it %04o", fi.Mode().Perm())
	}
	fresh := filepath.Join(dir, "fresh")
	if err := cl.WriteFile(fresh, bytes.NewReader([]byte("x")), 1, 0o666, nil); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0o666&^umask {
		t.Errorf("a new 0666 file is %04o under umask %04o", fi.Mode().Perm(), umask)
	}
}

// A download never writes through a file someone left beside the
// destination, such as a link another local user planted at <dst>.part: its
// temporary file is a new one of its own.
func TestDownloadIgnoresPlantedPart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a symlink")
	}
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("downloaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := os.Symlink(victim, dst+".part"); err != nil {
		t.Fatal(err)
	}
	if err := cl.CopyFrom(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep me" {
		t.Errorf("the download wrote through a planted link: victim now %q", b)
	}
	if b, _ := os.ReadFile(dst); string(b) != "downloaded" {
		t.Errorf("destination holds %q", b)
	}
	if fi, _ := os.Lstat(dst); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the destination is a link")
	}
}
