// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// inheritsDACL fails unless path's DACL is inherited from its directory.
func inheritsDACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); strings.HasPrefix(s, "D:P") || !strings.Contains(s, ";ID;") {
		t.Errorf("%s has DACL %s, want the directory's", filepath.Base(path), s)
	}
}

// An upload over an owner-only file leaves it owner-only, and a new file
// uploaded with a private mode is owner-only from the start; one uploaded
// with an open mode gets its directory's DACL, as any new file there does.
func TestWindowsUploadKeepsPrivateDACL(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	upload := func(path string, mode os.FileMode) {
		t.Helper()
		if err := cl.WriteFile(path, bytes.NewReader([]byte("new")), 3, mode, nil); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != "new" {
			t.Fatalf("%s holds %q", path, b)
		}
	}
	private := filepath.Join(dir, "private.cfg")
	f, err := CreateOwnerOnly(private, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	upload(private, 0o644)
	ownerOnlyNow(t, private)

	fresh := filepath.Join(dir, "fresh.key")
	upload(fresh, 0o600)
	ownerOnlyNow(t, fresh)

	open := filepath.Join(dir, "open.txt")
	upload(open, 0o644)
	inheritsDACL(t, open)
}

// A download over an owner-only local file leaves it owner-only.
func TestWindowsDownloadKeepsPrivateDACL(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("downloaded"), 0o644)
	dst := filepath.Join(dir, "agent.key")
	f, err := CreateOwnerOnly(dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := cl.CopyFrom(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "downloaded" {
		t.Fatalf("destination holds %q", b)
	}
	ownerOnlyNow(t, dst)
}

// daclOf returns path's DACL in SDDL.
func daclOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// ownedByUs fails unless this process's user, or a group that owns what it
// creates, owns path.
func ownedByUs(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	self, err := ownerSIDs()
	if err != nil {
		t.Fatal(err)
	}
	if !anySID(self, owner) {
		t.Errorf("%s is owned by %s", filepath.Base(path), accountName(owner))
	}
}

// plantFile makes path as another local account would leave it in a shared
// directory: owned by LOCAL SERVICE, with the protected DACL in sddl.
func plantFile(t *testing.T, path, sddl string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, sddl)
	giveToLocalService(t, path)
}

// giveToLocalService makes LOCAL SERVICE the owner of path, as another
// local account owns what it made. Giving a file another owner takes
// SeRestorePrivilege, which an elevated administrator holds; without it the
// test is skipped.
func giveToLocalService(t *testing.T, path string) {
	t.Helper()
	setOwner(t, path, func(other *windows.SID) error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
			other, nil, nil, nil)
	})
}

// setOwner runs set with the SID of LOCAL SERVICE and SeRestorePrivilege
// enabled, on this thread only, impersonating ourselves; when set fails, as
// it does without the privilege, the test is skipped.
func setOwner(t *testing.T, path string, set func(other *windows.SID) error) {
	t.Helper()
	other, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		t.Fatal(err)
	}
	defer windows.RevertToSelf()
	var tok windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid); err != nil {
		t.Fatal(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	if err := set(other); err != nil {
		t.Skipf("cannot give %s another owner here (needs SeRestorePrivilege): %v", filepath.Base(path), err)
	}
}

// An upload or a download over a file another user planted, one giving
// everyone full control, does not keep that DACL: what is written is made as
// a new file would be, owner-only for a private mode and with the directory's
// DACL otherwise, so the planter can neither read a private file nor change
// a script the operator then runs.
func TestWindowsWriteOverPlantedFile(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	check := func(path string, private bool) {
		t.Helper()
		if s := daclOf(t, path); strings.Contains(s, ";;;WD)") {
			t.Errorf("%s kept the planter's DACL %s", filepath.Base(path), s)
		}
		ownedByUs(t, path)
		if private {
			ownerOnlyNow(t, path)
		} else {
			inheritsDACL(t, path)
		}
	}
	for _, c := range []struct {
		name string
		mode os.FileMode
	}{{"deploy.ps1", 0o644}, {"secret.key", 0o600}} {
		path := filepath.Join(dir, c.name)
		plantFile(t, path, "D:P(A;;FA;;;WD)")
		if err := cl.WriteFile(path, bytes.NewReader([]byte("new")), 3, c.mode, nil); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != "new" {
			t.Fatalf("%s holds %q", path, b)
		}
		check(path, c.mode == 0o600)
	}

	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "downloaded.ps1")
	plantFile(t, dst, "D:P(A;;FA;;;WD)")
	if err := cl.CopyFrom(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "downloaded" {
		t.Fatalf("destination holds %q", b)
	}
	check(dst, false)
}

// privateDir is a new folder only this user, SYSTEM and Administrators may
// change or add files to, as a user's profile folders are, so a test of
// what a write keeps in such a folder holds whatever TEMP is: a folder made
// under C:\ lets Users add files, and a write there keeps no DACL.
func privateDir(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;"+user.User.Sid.String()+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	return dir
}

// Rewriting a file of ours keeps its whole DACL even when the DACL is not
// protected: an explicit deny stays, and so do the entries it inherits from
// its directory. That holds for a deny of read to BUILTIN\Users too, a
// group we are in ourselves, which keeps us from reading the file but not,
// as its owner, its DACL.
func TestWindowsUploadKeepsOwnExplicitEntries(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	for _, ace := range []string{"(D;;FA;;;BG)", "(D;;FR;;;BU)"} {
		path := filepath.Join(privateDir(t), "own-deny.txt")
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		// The deny on top of what the file inherits.
		sd, err := windows.SecurityDescriptorFromString("D:" + ace)
		if err != nil {
			t.Fatal(err)
		}
		deny, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, deny, nil); err != nil {
			t.Fatal(err)
		}
		before := daclOf(t, path)
		if !strings.Contains(before, ace) || !strings.Contains(before, ";ID;") {
			t.Fatalf("setting up: DACL %s, want %s and inherited entries", before, ace)
		}
		// The entries, in order; the DACL's auto-inherited mark (D:AI) is
		// not kept, and Windows still treats the inherited entries as
		// inherited.
		entries := func(s string) string {
			_, e, _ := strings.Cut(s, "(")
			return e
		}
		for _, mode := range []os.FileMode{0o644, 0o600} {
			if err := cl.WriteFile(path, bytes.NewReader([]byte("new")), 3, mode, nil); err != nil {
				t.Fatal(err)
			}
			after := daclOf(t, path)
			if entries(after) != entries(before) || strings.HasPrefix(after, "D:P") {
				t.Errorf("an upload with mode %04o changed the DACL of a file of ours from %s to %s", mode, before, after)
			}
			ownedByUs(t, path)
		}
		// A download over the file keeps its entries too, and leaves no
		// temporary file behind.
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := cl.CopyFrom(src, path); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(ace, ";BU)") { // that deny keeps us from reading it, as intended
			if b, err := os.ReadFile(path); string(b) != "downloaded" {
				t.Errorf("after the download the file holds %q (%v)", b, err)
			}
		}
		if after := daclOf(t, path); entries(after) != entries(before) || strings.HasPrefix(after, "D:P") {
			t.Errorf("a download changed the DACL of a file of ours from %s to %s", before, after)
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".own-deny.txt.tern-*")); len(left) != 0 {
			t.Errorf("temporary files left behind: %v", left)
		}
	}
}

// The temporary file of a new file written with a private mode is
// owner-only from the moment it exists, which is how a download from a Unix
// agent of a 0600 file lands on a Windows client.
func TestWindowsTempForPrivateMode(t *testing.T) {
	dir := t.TempDir()
	tg, err := openUploadTarget(filepath.Join(dir, "x"), dir, "x", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.close()
	defer tg.abort()
	ownerOnlyNow(t, tg.tmp.Name())
	if !strings.HasPrefix(filepath.Base(tg.tmp.Name()), ".x.tern-") {
		t.Errorf("temporary file %s", tg.tmp.Name())
	}
}

// An upload or a download over a file of ours whose DACL lets another
// account change it, as a file BUILTIN\Administrators owns and INTERACTIVE
// may modify does when another user moves it next to the target, does not
// keep that DACL: what is written is made as a new file would be. Write,
// append, delete, re-permission and take-ownership access each count; a DACL
// that only lets others read is kept, as a file's mode is.
func TestWindowsWriteOverFileOthersMayChange(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := privateDir(t)
	for i, ace := range []string{
		"(A;;0x1301bf;;;IU)", // Modify for INTERACTIVE, as Public Documents gives
		"(A;;FA;;;WD)",
		"(A;;FW;;;BU)",
		"(A;;0x100004;;;BU)", // FILE_APPEND_DATA | SYNCHRONIZE
		"(A;;SD;;;BU)",       // DELETE: the file can be swapped
		"(A;;WD;;;BU)",       // WRITE_DAC
		"(A;;WO;;;AU)",       // WRITE_OWNER
		"(A;;GW;;;BU)",
	} {
		for _, mode := range []os.FileMode{0o644, 0o600} {
			path := filepath.Join(dir, fmt.Sprintf("moved-%d-%o.ps1", i, mode))
			if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			setDACL(t, path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)"+ace)
			if err := cl.WriteFile(path, bytes.NewReader([]byte("new")), 3, mode, nil); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(path); string(b) != "new" {
				t.Fatalf("%s holds %q", path, b)
			}
			if s := daclOf(t, path); strings.Contains(s, ace) {
				t.Errorf("an upload with mode %04o kept a DACL granting %s: %s", mode, ace, s)
			}
			ownedByUs(t, path)
			if mode == 0o600 {
				ownerOnlyNow(t, path)
			} else {
				inheritsDACL(t, path)
			}
		}
		// A download over such a file, too.
		src := filepath.Join(dir, fmt.Sprintf("src-%d", i))
		if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, fmt.Sprintf("dst-%d.ps1", i))
		if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		setDACL(t, dst, "D:P(A;;FA;;;OW)"+ace)
		if err := cl.CopyFrom(src, dst); err != nil {
			t.Fatal(err)
		}
		if s := daclOf(t, dst); strings.Contains(s, ace) {
			t.Errorf("a download kept a DACL granting %s: %s", ace, s)
		}
		inheritsDACL(t, dst)
	}

	// Others may read it, not change it: the DACL stays.
	path := filepath.Join(dir, "shared-read.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, "D:P(A;;FA;;;OW)(A;;FR;;;BU)")
	before := daclOf(t, path)
	if err := cl.WriteFile(path, bytes.NewReader([]byte("new")), 3, 0o600, nil); err != nil {
		t.Fatal(err)
	}
	// The entries, and protected; the auto-inherited mark (AI) is not kept.
	entries := func(s string) string {
		_, e, _ := strings.Cut(s, "(")
		return e
	}
	if after := daclOf(t, path); entries(after) != entries(before) || !strings.HasPrefix(after, "D:P") {
		t.Errorf("rewriting a file of ours others may only read changed its DACL from %s to %s", before, after)
	}
}

// A file of ours keeps its DACL, and its read-only attribute, only in a
// folder no other account may add files to or delete them from. Where one
// may, through an entry for it or by owning the folder, it could have moved
// a file of ours there from a folder of its own, or renamed one over the
// name: what is written is made as a new file would be, owner-only for a
// private mode, and owner-only too over a file of ours no other account may
// read, or whose protected DACL lets others only read it, so a private
// upload stays private and no file is widened; a read-only mode makes it
// read-only. Adding files, deleting
// them, re-permissioning the folder and taking it over each count; an entry
// that only lets others read and list the folder, or that reaches only
// what it holds, does not.
func TestWindowsWriteWhereOthersMayAddFiles(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid.String()
	const readable = "D:P(A;;FA;;;OW)(A;;FR;;;BU)" // a file of ours others may read
	entries := func(s string) string {
		_, e, _ := strings.Cut(s, "(")
		return e
	}
	write := func(path, sddl string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		setDACL(t, path, sddl)
	}
	check := func(dir string, shared bool) {
		t.Helper()
		name := filepath.Base(dir)
		up := filepath.Join(dir, "up.pem")
		write(up, readable)
		if err := cl.WriteFile(up, bytes.NewReader([]byte("new")), 3, 0o600, nil); err != nil {
			t.Fatal(err)
		}
		if shared {
			ownerOnlyNow(t, up)
		} else if s := daclOf(t, up); entries(s) != entries(readable) {
			t.Errorf("%s: a 0600 upload over a file of ours changed its DACL to %s", name, s)
		}

		down := filepath.Join(dir, "down.txt")
		write(down, readable)
		if err := cl.CopyFrom(src, down); err != nil {
			t.Fatal(err)
		}
		if s := daclOf(t, down); !shared && entries(s) != entries(readable) {
			t.Errorf("%s: a download over a file of ours changed its DACL to %s", name, s)
		} else if shared && strings.Contains(s, "(A;;FR;;;BU)") {
			t.Errorf("%s: a download kept the DACL of a file of ours: %s", name, s)
		} else if shared {
			ownerOnlyNow(t, down)
		}

		private := filepath.Join(dir, "private.cfg")
		write(private, "D:P(A;;FA;;;OW)")
		if err := cl.CopyFrom(src, private); err != nil {
			t.Fatal(err)
		}
		ownerOnlyNow(t, private)

		ro := filepath.Join(dir, "ro.txt")
		write(ro, "D:P(A;;FA;;;OW)")
		if err := cl.WriteFile(ro, bytes.NewReader([]byte("new")), 3, 0o444, nil); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(ro)
		if err != nil {
			t.Fatal(err)
		}
		if readOnly := fi.Mode().Perm()&0o200 == 0; readOnly != shared {
			t.Errorf("%s: a read-only upload over a writable file of ours left it read-only: %v", name, readOnly)
		}
		os.Chmod(ro, 0o644)
	}
	for _, c := range []struct {
		name, ace string
		shared    bool
	}{
		{"private", "", false},
		{"read-and-list", "(A;OICI;0x1200a9;;;BU)", false},
		{"what-it-holds", "(A;OICIIO;FA;;;BU)", false},
		{"add-file", "(A;;0x2;;;BU)", true},
		{"server-c", "(A;OICI;0x1200a9;;;BU)(A;CI;0x4;;;BU)(A;CI;0x2;;;BU)", true}, // made under C:\ on Windows Server
		{"client-c", "(A;OICI;0x1301bf;;;AU)", true},                               // made under C:\ on Windows 10 and 11
		{"delete-child", "(A;;0x40;;;BU)", true},
		{"write-dac", "(A;;WD;;;BU)", true},
		{"write-owner", "(A;;WO;;;AU)", true},
		{"generic-write", "(A;;GW;;;BU)", true},
		{"everyone-full", "(A;;FA;;;WD)", true},
	} {
		dir := filepath.Join(t.TempDir(), c.name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		setDACL(t, dir, "D:P(A;OICI;FA;;;"+me+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"+c.ace)
		check(dir, c.shared)
	}
	// A folder another account owns, whatever its DACL.
	dir := filepath.Join(t.TempDir(), "theirs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;"+me+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	giveToLocalService(t, dir)
	check(dir, true)
}

// In a folder others may add files to, as one made under C:\ on Windows
// Server, an upload or a download with an open mode over a file of ours
// whose DACL may let others less than the folder passes on is written
// owner-only, never with the folder's DACL, which would let Users read it:
// a protected DACL letting only its owner and one named account read it,
// and one that inherits the folder's with a deny entry of its own. A file
// of ours that inherits the folder's DACL, and has no deny, still gets it.
func TestWindowsSharedFolderRewriteNeverWider(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "server-c")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;"+user.User.Sid.String()+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x4;;;BU)(A;CI;0x2;;;BU)")
	addDeny := func(t *testing.T, path string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString("D:(D;;FR;;;BG)")
		if err != nil {
			t.Fatal(err)
		}
		deny, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, deny, nil); err != nil {
			t.Fatal(err)
		}
		if s := daclOf(t, path); !strings.Contains(s, "(D;;FR;;;BG)") || !strings.Contains(s, ";ID;") {
			t.Fatalf("setting up: DACL %s, want the deny and inherited entries", s)
		}
	}
	for _, c := range []struct {
		name      string
		restrict  func(t *testing.T, path string)
		ownerOnly bool
	}{
		{"named-reader", func(t *testing.T, p string) { setDACL(t, p, "D:P(A;;FA;;;OW)(A;;FR;;;LS)") }, true},
		{"own-deny", addDeny, true},
		{"inherited", func(*testing.T, string) {}, false},
	} {
		for _, op := range []string{"download", "upload"} {
			path := filepath.Join(dir, c.name+"-"+op+".txt")
			if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			c.restrict(t, path)
			before := daclOf(t, path)
			if op == "download" {
				err = cl.CopyFrom(src, path)
			} else {
				err = cl.WriteFile(path, bytes.NewReader([]byte("uploaded")), 8, 0o644, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != map[string]string{"download": "downloaded", "upload": "uploaded"}[op] {
				t.Errorf("%s over %s: the file holds %q (%v)", op, c.name, b, err)
			}
			ownedByUs(t, path)
			if s := daclOf(t, path); c.ownerOnly && strings.Contains(s, ";;;BU)") {
				t.Errorf("%s over %s (%s) let Users read it: %s", op, c.name, before, s)
			}
			if c.ownerOnly {
				ownerOnlyNow(t, path)
			} else {
				inheritsDACL(t, path)
			}
		}
	}
}

// A write over a read-only file fails on Windows, which will not replace
// it, and leaves neither the target changed nor the temporary copy behind,
// though the copy was made read-only too, which a plain delete refuses.
func TestWindowsFailedWriteOverReadOnlyLeavesNoTemp(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro.txt")
	if err := os.WriteFile(ro, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ro, 0o644)
	if err := cl.WriteFile(ro, bytes.NewReader([]byte("new")), 3, 0o644, nil); err == nil {
		t.Error("an upload replaced a read-only file")
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cl.CopyFrom(src, ro); err == nil {
		t.Error("a download replaced a read-only file")
	}
	if b, _ := os.ReadFile(ro); string(b) != "old" {
		t.Errorf("the read-only file now holds %q", b)
	}
	waitNoTemp(t, dir)
}

// An upload or a download to a name holding ':', a data stream of a file,
// is refused before anything is made there: no empty file named for what
// comes before the ':', no temporary file.
func TestWindowsWriteToStreamRefused(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	if err := cl.WriteFile(filepath.Join(dir, "up.txt:hidden"), bytes.NewReader([]byte("new")), 3, 0o644, nil); err == nil || !strings.Contains(err.Error(), "data stream") {
		t.Errorf("an upload to a stream: %v", err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("downloaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cl.CopyFrom(src, filepath.Join(dir, "down.txt:hidden")); err == nil || !strings.Contains(err.Error(), "data stream") {
		t.Errorf("a download to a stream: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Errorf("left in the directory: %s", e.Name())
	}
}

// junction makes link a junction to target, as any user may without a
// privilege, replacing the junction already there.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if _, err := os.Lstat(link); err == nil {
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
}

// An upload works inside the directory it opened: a junction on the path
// pointed elsewhere before the file is written changes nothing about where
// it lands, and Real names the directory it was opened as.
func TestWindowsUploadStaysInOpenedDirectory(t *testing.T) {
	base := t.TempDir()
	first, second, link := filepath.Join(base, "first"), filepath.Join(base, "second"), filepath.Join(base, "link")
	for _, d := range []string{first, second} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	junction(t, link, first)
	defer os.Remove(link)
	tg, err := openUploadTarget(filepath.Join(link, "f.ps1"), link, "f.ps1", 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.close()
	d, err := os.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	firstReal, err := openedRealPath(d)
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(firstReal, "f.ps1"); tg.real != want {
		t.Errorf("Real = %q, want %q", tg.real, want)
	}
	junction(t, link, second)
	if _, err := tg.tmp.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tg.finish(); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(first, "f.ps1")); err != nil || string(b) != "data" {
		t.Errorf("the opened directory holds %q, %v; want the upload", b, err)
	}
	if ents, _ := os.ReadDir(second); len(ents) != 0 {
		t.Errorf("the upload reached the directory the junction was pointed at: %d entries", len(ents))
	}
}

// A download works inside the destination directory it opened: another user
// pointing a junction on the path at a folder they cannot write while the
// file is on its way does not get it written there.
func TestWindowsDownloadStaysInOpenedDirectory(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, gate := dialSlowed(t, a, fp)
	defer cl.Close()
	base := t.TempDir()
	src := filepath.Join(base, "payload.ps1")
	if err := os.WriteFile(src, bytes.Repeat([]byte("Write-Output 'payload'\r\n"), 200000), 0o644); err != nil {
		t.Fatal(err)
	}
	theirs, adminOnly, link := filepath.Join(base, "theirs"), filepath.Join(base, "adminonly"), filepath.Join(base, "link")
	for _, d := range []string{theirs, adminOnly} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	junction(t, link, theirs)
	defer os.Remove(link)
	done := make(chan error, 1)
	go func() { done <- cl.CopyFrom(src, filepath.Join(link, "payload.ps1")) }()
	holdOnTemp(t, gate, theirs, ".payload.ps1.tern-*", done)
	junction(t, link, adminOnly)
	gate.release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(theirs, "payload.ps1")); err != nil || fi.Size() == 0 {
		t.Errorf("the download is not in the directory it opened: %v", err)
	}
	if ents, _ := os.ReadDir(adminOnly); len(ents) != 0 {
		t.Errorf("the download reached the folder the junction was pointed at: %d entries", len(ents))
	}
}
