// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readsOf counts the reads of the file at path while do runs, as inotify
// reports them.
func readsOf(t *testing.T, path string, do func()) int {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Skipf("inotify: %v", err)
	}
	defer unix.Close(fd)
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_ACCESS); err != nil {
		t.Fatal(err)
	}
	do()
	n := 0
	buf := make([]byte, 64<<10)
	for {
		m, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) {
			return n
		}
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off+unix.SizeofInotifyEvent <= m; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			if ev.Mask&unix.IN_ACCESS != 0 {
				n++
			}
			off += unix.SizeofInotifyEvent + int(ev.Len)
		}
	}
}

// setACL gives path a POSIX access ACL that lets the user uid read and write
// it, beside its owner (rw), group (rw) and others (r), as setfacl -m
// u:UID:rw would on a file whose mode is 0664. Its mask, rw, becomes the
// group bits of the mode. The test is skipped where the file system keeps no
// ACLs.
func setACL(t *testing.T, path string, uid uint32) {
	t.Helper()
	const undefined = 0xffffffff
	entries := []struct {
		tag, perm uint16
		id        uint32
	}{
		{0x01, 6, undefined}, // ACL_USER_OBJ rw
		{0x02, 6, uid},       // ACL_USER rw
		{0x04, 6, undefined}, // ACL_GROUP_OBJ rw
		{0x10, 6, undefined}, // ACL_MASK rw
		{0x20, 4, undefined}, // ACL_OTHER r
	}
	b := binary.LittleEndian.AppendUint32(nil, 2) // POSIX_ACL_XATTR_VERSION
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	if err := unix.Setxattr(path, aclXattr, b, 0); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("no ACLs on this file system: %v", err)
		}
		t.Fatal(err)
	}
}

// The group write bit of a file whose group is the user's own private group
// lets no one else change it, unless the file has a POSIX ACL: then it is the
// ACL's mask, and a user the ACL names may change it, so the file is
// refused, saying it is the ACL; clearing the group write bit clears the
// mask, and the file passes again. A directory holding such a file is held
// to the same rule.
func TestPrivateGroupWithACL(t *testing.T) {
	ownGroup(t, true)
	dir := filepath.Join(t.TempDir(), "share")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(f, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{f, dir} {
		if err := os.Chmod(p, map[bool]os.FileMode{true: 0o664, false: 0o775}[p == f]); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		if int(st.Gid) != os.Getgid() {
			t.Skipf("%s has group %d, not this user's %d", p, st.Gid, os.Getgid())
		}
		if pathACL(p) == aclUnknown {
			t.Skipf("this file system cannot say whether %s has an ACL", p)
		}
	}
	if _, err := ReadConfigFile(f); err != nil {
		t.Fatalf("0664 file, 0775 directory, private group, no ACL: %v", err)
	}
	other := uint32(os.Getuid() + 1)
	setACL(t, f, other)
	_, err := ReadConfigFile(f)
	if err == nil || !strings.Contains(err.Error(), "its ACL lets other users change it") || !strings.Contains(err.Error(), "chmod go-w "+ShellQuote(f)) {
		t.Errorf("a file whose ACL lets uid %d write: %v", other, err)
	}
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfigFile(f); err != nil {
		t.Errorf("the same file once chmod go-w cleared its mask: %v", err)
	}
	setACL(t, dir, other)
	if err := os.Chmod(dir, 0o775); err != nil { // the mask back to rwx
		t.Fatal(err)
	}
	_, err = ReadConfigFile(f)
	if err == nil || !strings.Contains(err.Error(), "a directory whose ACL lets other users put another file in its place") ||
		!strings.Contains(err.Error(), "chmod go-w "+ShellQuote(dir)) {
		t.Errorf("a directory whose ACL lets uid %d write: %v", other, err)
	}
}

// A look that finds no ACL attribute says the file has no ACL, and one that
// finds it says it has one. A file system that keeps no ACLs, which does
// not support the look, has none either, unless it is NFS, SMB or AFS,
// whose server may keep ACLs the mode does not show, or statfs cannot say
// which it is; any other failure tells nothing. Where nothing is told, the
// group write bit counts, and carriesACL takes it as an ACL too.
func TestACLOfAnswers(t *testing.T) {
	const zfs, minix3 = 0x2fc12fc1, unix.MINIX3_SUPER_MAGIC
	for _, c := range []struct {
		err    error
		magic  uint32
		fsErr  error
		want   aclState
		looked bool // statfs is asked
	}{
		{nil, 0, nil, hasACL, false},
		{unix.ENODATA, 0, nil, noACL, false},
		{unix.EOPNOTSUPP, minix3, nil, noACL, true},
		{unix.EOPNOTSUPP, zfs, nil, noACL, true},
		{unix.EOPNOTSUPP, unix.NFS_SUPER_MAGIC, nil, aclUnknown, true},
		{unix.EOPNOTSUPP, unix.SMB_SUPER_MAGIC, nil, aclUnknown, true},
		{unix.EOPNOTSUPP, unix.CIFS_SUPER_MAGIC, nil, aclUnknown, true},
		{unix.EOPNOTSUPP, unix.SMB2_SUPER_MAGIC, nil, aclUnknown, true},
		{unix.EOPNOTSUPP, unix.AFS_SUPER_MAGIC, nil, aclUnknown, true},
		{unix.EOPNOTSUPP, unix.AFS_FS_MAGIC, nil, aclUnknown, true},
		{unix.EOPNOTSUPP, minix3, unix.EIO, aclUnknown, true},
		{unix.EACCES, minix3, nil, aclUnknown, false},
		{unix.EIO, minix3, nil, aclUnknown, false},
	} {
		looked := false
		statfs := func(st *unix.Statfs_t) error {
			looked = true
			setMagic(&st.Type, c.magic)
			return c.fsErr
		}
		if got := aclOf(func() error { return c.err }, statfs); got != c.want || looked != c.looked {
			t.Errorf("a look that returned %v, on file system %#x (statfs %v): %d, want %d; statfs asked: %v",
				c.err, c.magic, c.fsErr, got, c.want, looked)
		}
	}
}

// setMagic puts the 32-bit file system magic number m in statfs's type
// field, which is an int64, an int32 or a uint32 by architecture, as the
// kernel would: wrapped to a negative number where the field is a signed 32
// bits.
func setMagic[T ~int32 | ~int64 | ~uint32](field *T, m uint32) { *field = T(m) }

// procfs keeps no ACLs and says so: the directory of this process there
// has none, by name and through a descriptor.
func TestNoACLWhereNoneAreKept(t *testing.T) {
	dir := "/proc/self/"
	if _, err := unix.Getxattr(dir, aclXattr, nil); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("%s: getxattr says %v, not that it keeps no ACLs", dir, err)
	}
	if got := pathACL(dir); got != noACL {
		t.Errorf("pathACL(%s): %d, want noACL", dir, got)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if got := fdACL(fd); got != noACL {
		t.Errorf("fdACL(%s): %d, want noACL", dir, got)
	}
}

// fileACL reads the ACL of the very file that was opened, through its
// descriptor: a name swapped since does not change the answer.
func TestFileACLThroughDescriptor(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("x"), 0o664); err != nil {
		t.Fatal(err)
	}
	setACL(t, f, uint32(os.Getuid()+1))
	opened, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(plain, f); err != nil {
		t.Fatal(err)
	}
	if got := fileACL(opened); got != hasACL {
		t.Errorf("the opened file, with an ACL, its name since given to one without: %d, want hasACL", got)
	}
	if got := pathACL(f); got != noACL {
		t.Errorf("the file now at the name, without an ACL: %d, want noACL", got)
	}
}

// A token, tern1: or config file that is refused for what others could do
// to it is refused before a byte of it is read; one that is not is read.
func TestRefusedFileIsNotRead(t *testing.T) {
	dir := t.TempDir()
	tlsKey := func(p string) error { _, err := LoadOrCreateCert(strings.TrimSuffix(p, ".key")); return err }
	for _, c := range []struct {
		name string
		mode os.FileMode
		read func(string) error
	}{
		{"token file others may read", 0o644, fileReaders["ReadSecretFile"]},
		{"key file others may read", 0o644, fileReaders["PreloadKey"]},
		{"tern1: file others may change", 0o666, fileReaders["ReadConnStringFile"]},
		{"config file others may change", 0o666, fileReaders["ReadConfigFile"]},
		{"authorized_keys others may change", 0o666, fileReaders["LoadAuthorizedKeys"]},
		{"TLS key others may read.key", 0o644, tlsKey},
	} {
		f := filepath.Join(dir, c.name)
		if err := os.WriteFile(f, []byte("anything\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, c.mode); err != nil {
			t.Fatal(err)
		}
		var err error
		if n := readsOf(t, f, func() { err = c.read(f) }); err == nil || n != 0 {
			t.Errorf("%s: %v, after %d reads of it", c.name, err, n)
		}
	}
	ok := filepath.Join(dir, "token")
	if err := writePrivateFile(ok, []byte("token-0123456789abcdef\n")); err != nil {
		t.Fatal(err)
	}
	var err error
	if n := readsOf(t, ok, func() { _, err = ReadSecretFile(ok) }); err != nil || n == 0 {
		t.Errorf("a private token file: %v, after %d reads of it", err, n)
	}
}
