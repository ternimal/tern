// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// LoadOrCreateCert must refuse a key file a local attacker could have
// planted (too-open perms or a symlink) and must create keys 0600.
func TestLoadOrCreateCertFileHandling(t *testing.T) {
	// planted world-writable key -> refused
	d1 := t.TempDir()
	os.WriteFile(filepath.Join(d1, "a.key"), []byte("planted"), 0o666)
	os.WriteFile(filepath.Join(d1, "a.crt"), []byte("planted"), 0o666)
	if _, err := LoadOrCreateCert(filepath.Join(d1, "a")); err == nil && runtime.GOOS != "windows" {
		t.Fatal("loaded a world-accessible planted key")
	}

	// planted symlink at the key path -> refused
	if runtime.GOOS != "windows" {
		d2 := t.TempDir()
		victim := filepath.Join(d2, "victim")
		os.WriteFile(victim, []byte("x"), 0o600)
		os.Symlink(victim, filepath.Join(d2, "b.key"))
		os.WriteFile(filepath.Join(d2, "b.crt"), []byte("x"), 0o600)
		if _, err := LoadOrCreateCert(filepath.Join(d2, "b")); err == nil {
			t.Fatal("loaded a key through a planted symlink")
		}
	}

	// fresh create -> 0600 key, and a reload returns the same fingerprint
	d3 := t.TempDir()
	c1, err := LoadOrCreateCert(filepath.Join(d3, "c"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(d3, "c.key"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("created key mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	c2, err := LoadOrCreateCert(filepath.Join(d3, "c"))
	if err != nil {
		t.Fatalf("reload of our own cert failed: %v", err)
	}
	if CertFingerprint(c1) != CertFingerprint(c2) {
		t.Fatal("reload produced a different fingerprint")
	}
}
