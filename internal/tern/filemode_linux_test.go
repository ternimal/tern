// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// namedUserACL is the access ACL user::rwx user:uid:rwx group::r-x
// mask::rwx other::r-x in the form the kernel keeps it, as the extended
// attribute system.posix_acl_access.
func namedUserACL(uid uint32) []byte {
	const undefined = 0xffffffff
	b := binary.LittleEndian.AppendUint32(nil, 2) // the format's version
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{
		{0x01, 7, undefined}, // the owner
		{0x02, 7, uid},       // a named user
		{0x04, 5, undefined}, // the owning group
		{0x10, 7, undefined}, // the mask
		{0x20, 5, undefined}, // others
	} {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

// An ACL entry letting another user write a directory shows in its mode
// only as the group write bit, the ACL's mask: a file of ours there is not
// taken for one no one else could have put there, though the directory's
// group is our own private group. With the ACL gone, the directory is ours
// alone again and the file keeps its mode.
func TestWriteWhereACLLetsOthersAddNames(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	src := t.TempDir()
	key, notes := filepath.Join(src, "key.pem"), filepath.Join(src, "notes.txt")
	writeWithMode(t, key, "private key\n", 0o600)
	writeWithMode(t, notes, "notes\n", 0o644)
	dir := filepath.Join(t.TempDir(), "team")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeAccounts(t, gidOf(t, dir), "")
	if err := unix.Setxattr(dir, "system.posix_acl_access", namedUserACL(uint32(os.Getuid())+1), 0); err != nil {
		t.Skipf("this file system takes no ACL: %v", err)
	}
	if m := permOf(t, dir); m != 0o775 {
		t.Fatalf("with the ACL the directory is %04o, want 0775: its mask as the group bits", m)
	}
	checkKept(t, cl, dir, key, notes, false)
	if err := unix.Removexattr(dir, "system.posix_acl_access"); err != nil {
		t.Fatal(err)
	}
	checkKept(t, cl, dir, key, notes, true)
}
