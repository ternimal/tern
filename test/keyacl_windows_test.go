// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tern "github.com/ternimal/tern/internal/tern"
	"golang.org/x/sys/windows"
)

// TestWindowsKeyFileACL checks that a freshly created private key on Windows
// is not readable by every local user: NTFS ignores the 0600 mode, and a file
// that inherited the directory ACL would grant BUILTIN\Users:(I)(RX). The key
// must get a protected DACL
// granting the owner only, given when the file is created (not set afterwards,
// when another local user could already hold it open), so no one else can copy
// the key and impersonate the agent.
//
// Both key-creation paths are checked: LoadOrCreateCert (the agent TLS key)
// and GenerateKeyFiles (tern keygen).
func TestWindowsKeyFileACL(t *testing.T) {
	cert := filepath.Join(t.TempDir(), "agent")
	if _, err := tern.LoadOrCreateCert(cert); err != nil {
		t.Fatalf("LoadOrCreateCert: %v", err)
	}
	assertOwnerOnly(t, cert+".key")

	key := filepath.Join(t.TempDir(), "id")
	if _, err := tern.GenerateKeyFiles(key, "acl-test"); err != nil {
		t.Fatalf("GenerateKeyFiles: %v", err)
	}
	assertOwnerOnly(t, key)
}

// assertOwnerOnly fails unless path has a protected DACL (inheritance disabled)
// that names no local-user groups, while the current process (the file's owner)
// can still read it.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control(%s): %v", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: DACL is not protected, inherited ACEs still apply (control=%#x)", path, control)
	}

	sddl := sd.String()
	t.Logf("%s DACL: %s", path, sddl)
	// BUILTIN\Users = S-1-5-32-545 (SDDL alias BU); Everyone = S-1-1-0 (alias WD);
	// Authenticated Users = S-1-5-11 (AU). An inherited ACE commonly grants
	// BUILTIN\Users read, so none of these may appear in the key's DACL.
	for _, bad := range []string{"S-1-5-32-545", "S-1-1-0", "S-1-5-11", ";BU)", ";WD)", ";AU)"} {
		if strings.Contains(sddl, bad) {
			t.Errorf("%s: DACL grants a local-user group (%s): %s", path, bad, sddl)
		}
	}

	// The owner must keep read access: the ACE grants full access to OWNER RIGHTS
	// and this process created (owns) the file. A wrong DACL would deny this open.
	f, err := os.Open(path)
	if err != nil {
		t.Errorf("%s: owner cannot read its own key: %v", path, err)
	} else {
		f.Close()
	}
}
