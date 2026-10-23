// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// ownerOnlyNow fails unless path already has the protected owner-only DACL.
func ownerOnlyNow(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.String()
	if !strings.HasPrefix(s, "D:P") || strings.Count(s, "(") != 1 || !strings.Contains(s, ";;;OW)") {
		t.Errorf("%s has DACL %s, want only the owner and nothing inherited", filepath.Base(path), s)
	}
}

// A private file is owner-only the moment it exists, before anything could
// tighten it, so no other local user can open it in between.
func TestCreateOwnerOnlyACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	f, err := CreateOwnerOnly(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ownerOnlyNow(t, path)
	if _, err := CreateOwnerOnly(path, 0); err == nil {
		t.Error("CreateOwnerOnly opened an existing file")
	}
}

func TestRecordingOwnerOnly(t *testing.T) {
	r := NewRecorder(t.TempDir(), "s", 80, 24, 0)
	if r == nil {
		t.Fatal("no recorder")
	}
	defer r.Close()
	ownerOnlyNow(t, r.Path())
}
