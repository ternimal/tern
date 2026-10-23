// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A token file only its owner can open is read; one whose ACL lets another
// account read it, change it or delete it is refused, as a key file is, with
// a line that fixes it.
func TestTokenFileACL(t *testing.T) {
	f := filepath.Join(t.TempDir(), "api.token")
	if err := writePrivateFile(f, []byte("token-0123456789abcdef\r\n")); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSecretFile(f); err != nil || s != "token-0123456789abcdef" {
		t.Fatalf("an owner-only token file: %q %v", s, err)
	}
	for _, ace := range []string{"(A;;FR;;;WD)", "(A;;FW;;;BU)", "(A;;SD;;;BU)"} {
		setDACL(t, f, "D:P(A;;FA;;;OW)"+ace)
		_, err := ReadSecretFile(f)
		if err == nil || !strings.Contains(err.Error(), "may read or change it") || !strings.Contains(err.Error(), "icacls") {
			t.Errorf("a token file granting %s: %v", ace, err)
		}
	}
	setDACL(t, f, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
	if _, err := ReadSecretFile(f); err != nil {
		t.Errorf("a token file only its owner, SYSTEM and Administrators may open: %v", err)
	}
}

// A secret file another account owns is refused with a new secret as the
// fix, never taking the file over, which would keep what that account put
// in it. A file that says what to trust may be owned by SYSTEM or
// Administrators, who may change any file anyway, and read by others, but
// not changed by them.
func TestFileOwnerAndChangeRules(t *testing.T) {
	check := func(sddl string, rule accessRule) error {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		return checkFileSecurity(`C:\t\it`, sd, rule)
	}
	for _, c := range []struct {
		sddl string
		rule accessRule
		ok   bool
		want string
	}{
		{"O:S-1-5-21-1-2-3-4242D:P(A;;FA;;;OW)", secretRule(tokenWords), false, "delete it and write a new token"},
		{"O:S-1-5-21-1-2-3-4242D:P(A;;FA;;;OW)", secretRule(clientKeyWords), false, "make a new key"},
		{"O:S-1-5-21-1-2-3-4242D:P(A;;FA;;;OW)", changeRule(configWords), false, "delete it and write it again"},
		{"O:SYD:P(A;;FA;;;OW)", secretRule(tokenWords), false, "delete it and write a new token"},
		{"O:SYD:P(A;;FA;;;OW)(A;;FR;;;BU)", changeRule(configWords), true, ""},
		{"O:BAD:P(A;;FA;;;OW)(A;;FR;;;WD)", changeRule(configWords), true, ""},
		{"O:BAD:P(A;;FA;;;OW)(A;;FW;;;BU)", changeRule(configWords), false, "may change it"},
		{"O:BAD:P(A;;FA;;;OW)(A;;SD;;;BU)", changeRule(configWords), false, "may change it"},
	} {
		err := check(c.sddl, c.rule)
		if (err == nil) != c.ok || err != nil && (!strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "takeown")) {
			t.Errorf("%s (%s): %v, want ok=%v naming %q", c.sddl, c.rule.verb, err, c.ok, c.want)
		}
	}
}

// A named pipe, or a device such as NUL, is refused as not a regular file
// whichever way tern reads a file it is given, at once.
func TestFileReadsRefusePipesAndDevices(t *testing.T) {
	for name, read := range fileReaders {
		pipe := `\\.\pipe\tern-secret-test-` + strconv.Itoa(os.Getpid())
		p, err := windows.UTF16PtrFromString(pipe)
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
			1, 4096, 4096, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{pipe, "NUL"} {
			done := make(chan error, 1)
			go func() { done <- read(path) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s(%s): %v, want refused as not a regular file", name, path, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s(%s): still waiting after 5 s", name, path)
			}
		}
		windows.CloseHandle(h)
	}
}

// giveLinkToLocalService makes LOCAL SERVICE the owner of the symbolic link
// at path itself, not of where it leads.
func giveLinkToLocalService(t *testing.T, path string) {
	t.Helper()
	setOwner(t, path, func(other *windows.SID) error {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(p, windows.WRITE_OWNER|windows.READ_CONTROL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, other, nil, nil, nil)
	})
	if o, err := linkOwner(path); err != nil || !o.IsWellKnown(windows.WinLocalServiceSid) {
		t.Fatalf("the link %s is owned by %v (%v), want LOCAL SERVICE", path, o, err)
	}
}

// symlink makes link a symbolic link to target, skipping the test where
// this account may not make one.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
}

// A file that says which agents to trust may be reached through symbolic
// links this user, SYSTEM or Administrators made: one at the path, absolute,
// relative (from the link's folder, a .. climbing from it) or rooted
// (\dir\file, from the root of the link's own drive, as Windows takes it),
// and a chain of them, up to 40 links. A link another account owns is
// refused, at the path or anywhere in the chain, naming where it is, and so
// are more than 40 links. A directory link or a junction on the way is not
// looked at.
func TestPlaceThroughSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "d")
	sub := filepath.Join(root, "sub")
	for _, dir := range []string{d, sub} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const cfg = `{"agents":{}}`
	real := filepath.Join(d, "cfg.json")
	if err := os.WriteFile(real, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	read := func(name, path, want string) {
		t.Helper()
		_, err := ReadConfigFile(path)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v, want it refused naming %q", name, err, want)
		}
	}
	read("a regular file", real, "")

	abs := filepath.Join(root, "abs.json")
	symlink(t, real, abs)
	read("an absolute link", abs, "")
	rel := filepath.Join(sub, "rel.json")
	symlink(t, `..\d\cfg.json`, rel)
	read(`a relative link ..\d\cfg.json`, rel, "")
	rooted := filepath.Join(sub, "rooted.json")
	symlink(t, strings.TrimPrefix(real, filepath.VolumeName(real)), rooted)
	if b, err := os.ReadFile(rooted); err != nil || string(b) != cfg {
		t.Fatalf("Windows does not open the rooted link: %q %v", b, err)
	}
	read(`a rooted link \...\d\cfg.json`, rooted, "")
	c2 := filepath.Join(root, "c2.json")
	symlink(t, "abs.json", c2)
	c3 := filepath.Join(sub, "c3.json")
	symlink(t, c2, c3)
	read("a chain of three", c3, "")
	prev := real
	for i := range 41 {
		l := filepath.Join(root, fmt.Sprintf("l%02d", i))
		symlink(t, prev, l)
		prev = l
	}
	read("41 links", prev, "more than 40 symbolic links")
	read("40 links", filepath.Join(root, "l39"), "")

	theirs := filepath.Join(root, "theirs.json")
	symlink(t, real, theirs)
	giveLinkToLocalService(t, theirs)
	read("a link LOCAL SERVICE owns", theirs, "it is a symbolic link owned by")
	via := filepath.Join(sub, "via.json")
	symlink(t, theirs, via)
	read("a link of ours to one LOCAL SERVICE owns", via, "it leads to "+theirs+", which is a symbolic link owned by")
	dl := filepath.Join(root, "dlink")
	symlink(t, d, dl)
	giveLinkToLocalService(t, dl)
	read("a directory link LOCAL SERVICE owns, on the way", filepath.Join(dl, "cfg.json"), "")
	j := filepath.Join(root, "junction")
	junction(t, j, d)
	read("a junction on the way", filepath.Join(j, "cfg.json"), "")
}
