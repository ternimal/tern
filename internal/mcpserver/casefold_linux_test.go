// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCaseFoldEndToEnd runs the file tools against a real case-insensitive
// directory, where ".\u017fsh", ".\u1e9eh" or ".s\u200dsh" open .ssh. Set
// TERN_TEST_CASEFOLD_DIR to a directory with the casefold attribute (chattr
// +F on ext4 or f2fs made with casefold) to work in a new directory there;
// without it the test makes one on a casefold tmpfs in a new user and mount
// namespace, and skips where the kernel or the sandbox does not allow that.
func TestCaseFoldEndToEnd(t *testing.T) {
	dir := os.Getenv("TERN_TEST_CASEFOLD_DIR")
	if mnt := os.Getenv("TERN_TEST_CASEFOLD_MOUNT"); mnt != "" {
		var err error
		if dir, err = mountCasefold(mnt); err != nil {
			t.Skipf("no casefold tmpfs: %v", err)
		}
	}
	if dir == "" {
		inCasefoldNamespace(t)
		return
	}
	dir, err := os.MkdirTemp(dir, "tern-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	home := filepath.Join(dir, "home")
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	const key = "not a real key, test data only\n"
	os.WriteFile(filepath.Join(ssh, "id_test"), []byte(key), 0o600)
	os.WriteFile(filepath.Join(home, ".pgpass"), []byte("db:5432:*:app:not-a-real-password\n"), 0o600)
	os.WriteFile(filepath.Join(home, "notes.txt"), []byte("hello\n"), 0o644)
	if b, err := os.ReadFile(filepath.Join(home, ".\u017fsh", "id_test")); err != nil || string(b) != key {
		t.Skipf("%s does not fold names: %v", dir, err)
	}
	ws := t.TempDir()
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{home + "/**"}, WritePaths: []string{home + "/**"}},
		func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)

	for _, alias := range []string{".\u017fsh/id_test", ".\u00dfh/id_test", ".\u1e9eh/id_test", ".SSH/id_test",
		".s\u200dsh/id_test", ".ss\ufe0fh/id_test", ".pgpa\u017fs"} {
		p := filepath.Join(home, alias)
		if why := call(t, cs, "read_file", map[string]any{"path": p}, nil, true); !strings.Contains(why, "secret-path rule") {
			t.Errorf("read_file %q: %s", alias, why)
		}
		if why := call(t, cs, "download", map[string]any{"remote": p, "local": "got"}, nil, true); !strings.Contains(why, "secret-path rule") {
			t.Errorf("download %q: %s", alias, why)
		}
	}
	for _, alias := range []string{".\u017fsh/authorized_keys", ".\u1e9eh/authorized_keys", "authorized_key\u017f", ".ba\u017fhrc"} {
		why := call(t, cs, "write_file", map[string]any{"path": filepath.Join(home, alias), "content": "ssh-ed25519 AAAA x\n"}, nil, true)
		if !strings.Contains(why, "rule") {
			t.Errorf("write_file %q: %s", alias, why)
		}
	}
	// A name that reads as ".." here would leave the allowed tree.
	os.MkdirAll(filepath.Join(home, "sub"), 0o700)
	if why := call(t, cs, "read_file", map[string]any{"path": filepath.Join(home, "sub", "..\u200d", "notes.txt")}, nil, true); !strings.Contains(why, "case-insensitive") {
		t.Errorf("read_file through a folded ..: %s", why)
	}
	for _, name := range []string{filepath.Join(ssh, "authorized_keys"), filepath.Join(home, "authorized_keys"), filepath.Join(home, ".bashrc")} {
		if _, err := os.Stat(name); err == nil {
			t.Errorf("%s was written", name)
		}
	}
	if names, _ := os.ReadDir(ws); len(names) != 0 {
		t.Errorf("the workspace holds %v", names)
	}
	// Other files still read, whatever their spelling.
	var r ReadOutput
	call(t, cs, "read_file", map[string]any{"path": filepath.Join(home, "note\u017f.txt")}, &r, false)
	if r.Content != "hello\n" {
		t.Errorf("read_file of an ordinary file = %q", r.Content)
	}
}

// inCasefoldNamespace runs TestCaseFoldEndToEnd again in a new user and
// mount namespace, where it may mount a casefold tmpfs, and reports its
// result as this test's.
func inCasefoldNamespace(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCaseFoldEndToEnd$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "TERN_TEST_CASEFOLD_MOUNT="+t.TempDir())
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err != nil && !errors.As(err, &exit):
		t.Skipf("no user namespace: %v", err)
	case strings.Contains(string(out), "--- SKIP: TestCaseFoldEndToEnd"):
		t.Skipf("in a new namespace: %s", strings.TrimSpace(string(out)))
	case err != nil || !strings.Contains(string(out), "--- PASS: TestCaseFoldEndToEnd"):
		t.Fatalf("in a new namespace: %v\n%s", err, out)
	}
}

// mountCasefold mounts a tmpfs that can fold names on mnt and returns a
// directory in it that does.
func mountCasefold(mnt string) (string, error) {
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "casefold"); err != nil {
		return "", err
	}
	dir := filepath.Join(mnt, "folded")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer f.Close()
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return "", err
	}
	const casefold = 0x40000000 // FS_CASEFOLD_FL in <linux/fs.h>
	return dir, unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags|casefold))
}
