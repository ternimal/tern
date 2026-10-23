// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A secret file another user owns is refused, whatever its mode: its owner
// could change it, and so the secret, at any time, so the fix is a new
// secret, never taking the file over. Any group or other bit is refused
// too, write or execute as well as read; one that lets others read or
// change the file says the secret may be known to them.
func TestSecretFileOwnerAndMode(t *testing.T) {
	f := filepath.Join(t.TempDir(), "it's a token")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if p := secretFileProblem(f, fi, os.Getuid(), tokenWords); p != nil {
		t.Fatalf("an owner-only file of this user: %v", p)
	}
	p := secretFileProblem(f, fi, os.Getuid()+1, tokenWords)
	if p == nil || strings.Contains(p.Error(), "chown") || !strings.Contains(p.Error(), "delete it and write a new token") {
		t.Errorf("a file another user owns: %v", p)
	}
	for _, c := range []struct {
		mode  os.FileMode
		known bool
	}{{0o640, true}, {0o604, true}, {0o620, true}, {0o602, true}, {0o666, true}, {0o610, false}, {0o601, false}} {
		if err := os.Chmod(f, c.mode); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(f)
		p := secretFileProblem(f, fi, os.Getuid(), tokenWords)
		if p == nil || !strings.Contains(p.Error(), "chmod 600 "+ShellQuote(f)) || strings.Contains(p.Error(), "may know") != c.known {
			t.Errorf("mode %04o: %v", c.mode, p)
		}
	}
}

// statOwned is the status of a file owned by uid, of group gid, with mode.
type statOwned struct {
	fs.FileInfo
	st   syscall.Stat_t
	mode fs.FileMode
}

func (s statOwned) Mode() fs.FileMode { return s.mode }
func (s statOwned) Sys() any          { return &s.st }

func ownedBy(uid, gid uint32, mode fs.FileMode) fs.FileInfo {
	s := statOwned{mode: mode}
	s.st.Uid, s.st.Gid = uid, gid
	return s
}

// A file that says what to trust (a tern1: string, tern mcp's config) is
// refused when another user could change it: another owner, root aside, or
// the other write bit, or the group write bit unless the group is the
// user's own private group and the file has no ACL, whose mask the group
// bits then are. Where the ACL cannot be read the group bit always counts.
// Any read bit is fine.
func TestFileOthersCouldChange(t *testing.T) {
	const self, other, mine, shared = 1000, 1001, 1000, 100
	private := func(gid uint32, uid int) bool { return gid == mine && uid == self }
	for _, c := range []struct {
		fi  fs.FileInfo
		acl aclState
		ok  bool
	}{
		{ownedBy(self, shared, 0o644), noACL, true},
		{ownedBy(self, shared, 0o600), noACL, true},
		{ownedBy(self, shared, 0o755), noACL, true},
		{ownedBy(0, shared, 0o644), noACL, true},
		{ownedBy(self, mine, 0o664), noACL, true},
		{ownedBy(0, mine, 0o664), noACL, true},
		{ownedBy(self, mine, 0o644), hasACL, true},
		{ownedBy(self, shared, 0o644), aclUnknown, true},
		{ownedBy(other, shared, 0o644), noACL, false},
		{ownedBy(other, mine, 0o600), noACL, false},
		{ownedBy(self, shared, 0o664), noACL, false},
		{ownedBy(self, shared, 0o646), noACL, false},
		{ownedBy(self, mine, 0o666), noACL, false},
		{ownedBy(0, shared, 0o664), noACL, false},
		{ownedBy(self, mine, 0o664), hasACL, false},
		{ownedBy(0, mine, 0o664), hasACL, false},
		{ownedBy(self, mine, 0o664), aclUnknown, false},
	} {
		st := c.fi.Sys().(*syscall.Stat_t)
		p := changeProblem("/cfg/mcp.json", c.fi, self, private, c.acl, configWords)
		if (p == nil) != c.ok {
			t.Errorf("uid %d gid %d mode %04o acl %d: %v, want ok=%v", st.Uid, st.Gid, c.fi.Mode(), c.acl, p, c.ok)
			continue
		}
		switch {
		case p == nil:
		case st.Uid != self && st.Uid != 0:
			if strings.Contains(p.Error(), "chown") || !strings.Contains(p.Error(), "delete it and write it again") {
				t.Errorf("owned by uid %d: %v", st.Uid, p)
			}
		case !strings.Contains(p.Error(), "chmod go-w /cfg/mcp.json"):
			t.Errorf("mode %04o: %v", c.fi.Mode(), p)
		case (c.acl == hasACL && st.Gid == mine) != strings.Contains(p.Error(), "ACL"):
			t.Errorf("mode %04o acl %d: %v, want the ACL named only when it is why", c.fi.Mode(), c.acl, p)
		}
	}
}

// ownGroup points the account files privateGroup reads at copies in which
// this user's primary group is their own private group, or, unless private,
// one that lists another member too, for the rest of the test.
func ownGroup(t *testing.T, private bool) {
	t.Helper()
	members := ""
	if !private {
		members = "someone"
	}
	gid := os.Getgid()
	fakeAccounts(t, uint32(gid), members)
	if gid == 0 || privateGroup(uint32(gid), os.Getuid()) != private {
		t.Skip("cannot make this user's group look as wanted")
	}
}

// The directory that holds a file that says what to trust, here an
// authorized_keys file, must not let others put another file in its place,
// as ssh's StrictModes requires: the other write bit, or the group write bit
// but for the user's own private group (with no ACL, on Linux, where the
// ACL can be read), refuses it, unless the directory is sticky, as /tmp is,
// where others cannot replace this user's files. The fix names the
// directory.
func TestPlaceDirectoryOthersMayWrite(t *testing.T) {
	_, pub := newSSHKey(t)
	for _, c := range []struct {
		mode    os.FileMode
		private bool
		ok      bool
	}{
		{0o700, false, true},
		{0o755, false, true},
		{0o775, true, runtime.GOOS == "linux"},
		{0o775, false, false},
		{0o757, false, false},
		{0o777, false, false},
		{0o777 | os.ModeSticky, false, true},
		{0o775 | os.ModeSticky, false, true},
	} {
		t.Run(fmt.Sprintf("%v/private=%v", c.mode, c.private), func(t *testing.T) {
			ownGroup(t, c.private)
			dir := filepath.Join(t.TempDir(), "keys")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			f := filepath.Join(dir, "authorized_keys")
			if err := writePrivateFile(f, ssh.MarshalAuthorizedKey(pub)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, c.mode); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(dir, 0o700)
			if st, err := os.Stat(dir); err != nil || int(st.Sys().(*syscall.Stat_t).Gid) != os.Getgid() {
				t.Skipf("%s is not of this user's group: %v", dir, err)
			}
			real := realDir(t, dir)
			_, err := LoadAuthorizedKeys(f)
			switch {
			case c.ok && err != nil:
				t.Errorf("refused: %v", err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), "keys that may log in") ||
				!strings.Contains(err.Error(), "is in "+real+", a directory whose permissions") ||
				!strings.Contains(err.Error(), "chmod go-w "+ShellQuote(real))):
				t.Errorf("taken, or refused without naming the directory and the fix: %v", err)
			}
		})
	}
}

// A symlink at the path, and each one it leads through, is followed with a
// look at the directory holding it: a Kubernetes Secret or projected volume
// (a sticky directory, a timestamped one inside, and ..data and per-file
// links) passes, and so does a link of this user's into a directory of
// theirs, but a link into a directory others may write is refused, naming
// where it leads, and so is the file of a ConfigMap volume, whose directory
// others may write and is not sticky. A ".." in a link's target climbs from
// where the link's directory really is, as the kernel resolves it.
func TestPlaceThroughSymlinks(t *testing.T) {
	_, pub := newSSHKey(t)
	keys := ssh.MarshalAuthorizedKey(pub)
	write := func(p string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(p, keys, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(p string, mode os.FileMode) {
		t.Helper()
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(p, 0o700) })
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()

	volume := func(name string, mode os.FileMode) string {
		t.Helper()
		v := filepath.Join(root, name)
		mkdir(v, mode)
		stamp := "..2026_10_22_00_00_00.000000001"
		mkdir(filepath.Join(v, stamp), 0o755)
		write(filepath.Join(v, stamp, "authorized_keys"), 0o444)
		link(stamp, filepath.Join(v, "..data"))
		link("..data/authorized_keys", filepath.Join(v, "authorized_keys"))
		return filepath.Join(v, "authorized_keys")
	}
	if _, err := LoadAuthorizedKeys(volume("secret", 0o777|os.ModeSticky)); err != nil {
		t.Errorf("a Kubernetes-like Secret volume: %v", err)
	}
	configMap := volume("configmap", 0o777)
	if _, err := LoadAuthorizedKeys(configMap); err == nil || !strings.Contains(err.Error(), "is in "+realDir(t, filepath.Dir(configMap))+", a directory whose permissions 0777") {
		t.Errorf("a Kubernetes-like ConfigMap volume: %v", err)
	}

	open := filepath.Join(root, "open")
	mkdir(open, 0o777)
	write(filepath.Join(open, "authorized_keys"), 0o644)
	safe := filepath.Join(root, "safe")
	mkdir(safe, 0o755)
	link(filepath.Join(open, "authorized_keys"), filepath.Join(safe, "authorized_keys"))
	_, err := LoadAuthorizedKeys(filepath.Join(safe, "authorized_keys"))
	if err == nil || !strings.Contains(err.Error(), "it leads to "+filepath.Join(open, "authorized_keys")+", which is in "+realDir(t, open)+", a directory whose permissions 0777") {
		t.Errorf("a link into a directory others may write: %v", err)
	}
	write(filepath.Join(root, "authorized_keys"), 0o644)
	link(filepath.Join(root, "authorized_keys"), filepath.Join(safe, "mine"))
	if _, err := LoadAuthorizedKeys(filepath.Join(safe, "mine")); err != nil {
		t.Errorf("a link of this user's to a file of theirs: %v", err)
	}

	// up/../authorized_keys from deep, where up leads to open/sub: the
	// kernel reaches open/authorized_keys, in a directory others may write,
	// not deep/authorized_keys, which a lexical ".." would look at.
	deep := filepath.Join(root, "deep")
	mkdir(deep, 0o755)
	mkdir(filepath.Join(open, "sub"), 0o755)
	link(filepath.Join(open, "sub"), filepath.Join(deep, "up"))
	write(filepath.Join(deep, "authorized_keys"), 0o644)
	link("up/../authorized_keys", filepath.Join(deep, "climb"))
	_, err = LoadAuthorizedKeys(filepath.Join(deep, "climb"))
	if err == nil || !strings.Contains(err.Error(), "which is in "+realDir(t, open)+", a directory whose permissions 0777") {
		t.Errorf("a link whose .. climbs from where a link leads: %v", err)
	}
}

// realDir is where the directory dir really is, as refusals name it.
func realDir(t *testing.T, dir string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// rootStickyDir returns a directory root owns that is sticky, as /tmp is, in
// which this user may make names, or skips the test.
func rootStickyDir(t *testing.T) string {
	t.Helper()
	for _, d := range []string{os.TempDir(), "/tmp", "/var/tmp", "/dev/shm"} {
		fi, err := os.Stat(d)
		if err == nil && fi.IsDir() && fi.Mode()&os.ModeSticky != 0 && fi.Sys().(*syscall.Stat_t).Uid == 0 && syscall.Access(d, 2) == nil {
			return d
		}
	}
	t.Skip("no sticky directory of root's to make a link in")
	return ""
}

// A directory another user owns may not hold the file, and a symlink at the
// path that another user made is refused, even in a directory that passes,
// as a sticky one does, where anyone may make a new name: its owner chose
// where it leads. Here the directory and the link are this user's, judged
// for another uid.
func TestPlaceOfAnotherUser(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	p, err := placeProblem(target, fi, uid+1, privateGroup, pathACL, authorizedKeysWords)
	if err != nil || p == nil || !strings.Contains(p.Error(), fmt.Sprintf("it is in %s, a directory uid %d owns, not this user (uid %d) or root", realDir(t, dir), uid, uid+1)) ||
		!strings.Contains(p.Error(), "keep it in a directory only you and root can change") {
		t.Errorf("a file in a directory another user owns: %v %v", p, err)
	}

	l := filepath.Join(rootStickyDir(t), fmt.Sprintf("tern-place-test-%d", os.Getpid()))
	if err := os.Symlink(target, l); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(l)
	if p, err := placeProblem(l, fi, uid, privateGroup, pathACL, authorizedKeysWords); p != nil || err != nil {
		t.Errorf("this user's own link: %v %v", p, err)
	}
	p, err = placeProblem(l, fi, uid+1, privateGroup, pathACL, authorizedKeysWords)
	if err != nil || p == nil || !strings.Contains(p.Error(), fmt.Sprintf("it is a symlink uid %d made, not this user (uid %d) or root", uid, uid+1)) ||
		!strings.Contains(p.Error(), "delete it") {
		t.Errorf("a link another user made: %v %v", p, err)
	}
}

// Links root made are followed as this user's are: /etc/localtime, where it
// is a link of root's, leads to its zone file through root's directories.
func TestPlaceRootLinks(t *testing.T) {
	const l = "/etc/localtime"
	lfi, err := os.Lstat(l)
	if err != nil || lfi.Mode()&os.ModeSymlink == 0 || lfi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Skipf("%s is not a link of root's here", l)
	}
	fi, err := os.Stat(l)
	if err != nil {
		t.Skip(err)
	}
	// Some images leave the zone directories writable by all; there the
	// link rightly fails, and this test has nothing to show.
	real, err := filepath.EvalSymlinks(l)
	if err != nil {
		t.Skip(err)
	}
	for d := filepath.Dir(real); ; d = filepath.Dir(d) {
		if dfi, err := os.Stat(d); err != nil || dfi.Mode().Perm()&0o022 != 0 && dfi.Mode()&os.ModeSticky == 0 {
			t.Skipf("%s, on the way to %s, is writable by others here", d, real)
		}
		if d == filepath.Dir(d) {
			break
		}
	}
	if p, err := placeExposure(l, fi, configWords); p != nil || err != nil {
		t.Errorf("%s: %v %v", l, p, err)
	}
}

// What the links lead to must be the file that was opened: a file put in
// its place since is not taken for it. The links followed are capped.
func TestPlaceMustBeTheOpenedFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, f); err != nil {
		t.Fatal(err)
	}
	if p, err := placeExposure(f, opened, configWords); p != nil || err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("a file put in the place of the opened one: %v %v", p, err)
	}

	now, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	prev := f
	for i := range maxPlaceLinks + 1 {
		l := filepath.Join(dir, fmt.Sprintf("l%d", i))
		if err := os.Symlink(prev, l); err != nil {
			t.Fatal(err)
		}
		prev = l
	}
	if p, err := placeExposure(prev, now, configWords); p != nil || err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Errorf("%d links: %v %v", maxPlaceLinks+1, p, err)
	}
	if p, err := placeExposure(filepath.Join(dir, fmt.Sprintf("l%d", maxPlaceLinks-1)), now, configWords); p != nil || err != nil {
		t.Errorf("%d links: %v %v", maxPlaceLinks, p, err)
	}
}

// A group is the user's private group when it is the user's primary group
// and no one else's, is named as the user, and lists no other member; one
// the account files do not show is not.
func TestPrivateGroup(t *testing.T) {
	dir := t.TempDir()
	passwdFile, groupFile = filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	t.Cleanup(func() { passwdFile, groupFile = "/etc/passwd", "/etc/group" })
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("passwd", "root:x:0:0:root:/root:/bin/sh\n# a comment\nalice:x:1000:1000::/home/alice:/bin/sh\n"+
		"bob:x:1001:1001::/home/bob:/bin/sh\ncarol:x:1002:100::/home/carol:/bin/sh\ndave:x:1003:1003::/home/dave:/bin/sh\n"+
		"eve:x:1004:1003::/home/eve:/bin/sh\nfrank:x:1005:1005::/home/frank:/bin/sh\n")
	write("group", "root:x:0:\nalice:x:1000:\nbob:x:1001:bob,mallory\nusers:x:100:carol\ndave:x:1003:\nstaff:x:1005:\n")
	for _, c := range []struct {
		gid  uint32
		uid  int
		want bool
	}{
		{1000, 1000, true},  // alice's own group
		{1000, 1001, false}, // not bob's primary group
		{1001, 1001, false}, // bob's group lists mallory
		{100, 1002, false},  // users: not named as carol
		{1003, 1003, false}, // eve's primary group too
		{1005, 1005, false}, // named staff, not frank
		{1006, 1006, false}, // in no account file
	} {
		if got := privateGroup(c.gid, c.uid); got != c.want {
			t.Errorf("gid %d for uid %d: private %v, want %v", c.gid, c.uid, got, c.want)
		}
	}
	passwdFile = filepath.Join(dir, "missing")
	if privateGroup(1000, 1000) {
		t.Error("a group was taken as private with no passwd file to show it")
	}
}

// waitsNot runs read and fails unless it returns within a few seconds.
func waitsNot(t *testing.T, name string, read func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- read() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: still waiting after 5 s", name)
		return nil
	}
}

// A FIFO someone made at the path of a file not written yet, or a device,
// is refused at once, without waiting for a writer or reading a byte,
// whichever way the file is read, but for a client key: there a pipe of
// this user's is taken, as ssh takes one, and one with no writer reads as
// empty at once (see TestClientKeyThroughPipe), while a device is refused.
func TestFileReadsRefuseFIFOAndDevices(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "agent.token")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	t.Cleanup(func() {
		// Lets go of any read that does wait, so the test can end.
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
	})
	for name, read := range fileReaders {
		key := name == "PreloadKey" || name == "KeyNeedsPassphrase"
		for _, p := range []string{fifo, "/dev/null"} {
			err := waitsNot(t, name+" "+p, func() error { return read(p) })
			switch {
			case key && p == fifo:
				if err != nil && strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s(%s): %v, want a pipe of this user's taken", name, p, err)
				}
			case err == nil || !strings.Contains(err.Error(), "not a regular file"):
				t.Errorf("%s(%s): %v, want refused as not a regular file", name, p, err)
			}
		}
	}
}

// The agent's TLS key is refused when its name is a symlink, even to a
// valid key of this user's, as one someone planted could be; a FIFO at the
// key's or the certificate's name is refused at once, unread.
func TestTLSFilesSymlinkAndFIFO(t *testing.T) {
	made := filepath.Join(t.TempDir(), "made")
	if _, err := LoadOrCreateCert(made); err != nil {
		t.Fatal(err)
	}
	crt, err := os.ReadFile(made + ".crt")
	if err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(made+".key", linked+".key"); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(linked+".crt", crt); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCert(linked); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("a key reached through a symlink: %v", err)
	}

	for _, ext := range []string{".key", ".crt"} {
		prefix := filepath.Join(t.TempDir(), "agent")
		if _, err := LoadOrCreateCert(prefix); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(prefix + ext); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(prefix+ext, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		t.Cleanup(func() {
			if w, err := os.OpenFile(prefix+ext, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
		})
		err := waitsNot(t, "LoadOrCreateCert with a FIFO "+ext, func() error { _, err := LoadOrCreateCert(prefix); return err })
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("a FIFO at the %s file: %v", ext, err)
		}
	}
}

// A TLS key pair made in a directory others may add files to, as a setgid
// team directory (2775) of a group the user shares with others is, is taken
// at the next start: its key is private and its certificate is one others
// cannot change, and where the certificate is does not matter, as it serves
// only with the key it matches. Another certificate put in its place is
// refused.
func TestTLSPairInTeamDirectoryReloads(t *testing.T) {
	ownGroup(t, false)
	other := filepath.Join(t.TempDir(), "other")
	if _, err := LoadOrCreateCert(other); err != nil {
		t.Fatal(err)
	}
	otherCrt, err := os.ReadFile(other + ".crt")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o775 | os.ModeSetgid, 0o777} {
		dir := filepath.Join(t.TempDir(), "team")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(dir); err != nil || fi.Mode()&(os.ModePerm|os.ModeSetgid) != mode {
			t.Fatalf("%s: %v %v, want %v", dir, fi.Mode(), err, mode)
		}
		prefix := filepath.Join(dir, "ternd-agent")
		made, err := LoadOrCreateCert(prefix)
		if err != nil {
			t.Fatal(err)
		}
		got, err := LoadOrCreateCert(prefix)
		if err != nil || CertFingerprint(got) != CertFingerprint(made) {
			t.Errorf("a pair made in a %v directory, loaded again: %v", mode, err)
		}
		if err := os.Remove(prefix + ".crt"); err != nil {
			t.Fatal(err)
		}
		if err := writePrivateFile(prefix+".crt", otherCrt); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateCert(prefix); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("another pair's certificate in a %v directory: %v", mode, err)
		}
	}
}

// Past maxSecretFile, a token, tern1: or key file is refused unread; a
// token up to it is read. No more is read than the file's size, so a file
// of /proc that shows a size of 0 reads as empty.
func TestSecretFileReadIsCapped(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := writePrivateFile(big, []byte(strings.Repeat("a", maxSecretFile+1))); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ReadSecretFile", "ReadConnStringFile", "PreloadKey"} {
		if err := fileReaders[name](big); err == nil || !strings.Contains(err.Error(), "more than the 64 KiB") {
			t.Errorf("%s of %d bytes: %v", name, maxSecretFile+1, err)
		}
	}
	most := filepath.Join(dir, "most")
	if err := writePrivateFile(most, []byte(strings.Repeat("b", maxSecretFile))); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSecretFile(most); err != nil || len(s) != maxSecretFile {
		t.Errorf("a token of %d bytes: %d bytes, %v", maxSecretFile, len(s), err)
	}
	if fi, err := os.Stat("/proc/self/environ"); err == nil && fi.Size() == 0 && fi.Sys().(*syscall.Stat_t).Uid == uint32(os.Getuid()) {
		if _, err := ReadSecretFile("/proc/self/environ"); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("a /proc file of size 0 was read: %v", err)
		}
	}
}
