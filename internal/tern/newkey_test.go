// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key the agent has just written is held to the checks a key it loads
// must pass. Where the file system leaves it open to other users, as FAT32
// and exFAT do, the new pair is removed and refused rather than served for
// the whole run while anyone can read the key; a private one is kept.
func TestNewKeyMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key")
	for _, p := range []string{cert, key} {
		f, err := CreateOwnerOnly(p, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	if err := checkNewKey(cert, key); err != nil {
		t.Fatalf("a private new key was refused: %v", err)
	}

	exposeToOthers(t, key)
	err := checkNewKey(cert, key)
	if err == nil {
		t.Fatal("a new key other users can read was accepted")
	}
	if msg := err.Error(); !strings.Contains(msg, "not private") || strings.Contains(msg, "a new pair is made") {
		t.Errorf("refusal %q: want why, without advice meant for a key someone else left", msg)
	}
	for _, p := range []string{cert, key} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s was left behind: %v", filepath.Base(p), err)
		}
	}
}

// tern keygen holds its new key to the same checks: where the file system
// leaves the key open to other users, as FAT32 and exFAT do, both files are
// removed and keygen fails; a private key is kept.
func TestKeygenNewKeyMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	if _, err := GenerateKeyFiles(filepath.Join(dir, "ok"), "c"); err != nil {
		t.Fatalf("a private new key was refused: %v", err)
	}
	orig := keygenCheck
	defer func() { keygenCheck = orig }()
	keygenCheck = func(pub, key string) error {
		exposeToOthers(t, key) // as FAT32 and exFAT leave every file
		return orig(pub, key)
	}
	prefix := filepath.Join(dir, "exposed")
	_, err := GenerateKeyFiles(prefix, "c")
	if err == nil {
		t.Fatal("keygen kept a new key other users can read")
	}
	if !strings.Contains(err.Error(), "not private") {
		t.Errorf("refusal %q does not say why", err)
	}
	for _, p := range []string{prefix, prefix + ".pub"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s was left behind: %v", filepath.Base(p), err)
		}
	}
}
