// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// setDACL gives path the DACL in sddl, inherited entries dropped.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// A key file ternd made itself loads again; one other users may read, as a
// file made by hand in a shared directory usually is, is refused with a way
// to fix it.
func TestKeyFileACL(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "agent")
	if _, err := LoadOrCreateCert(prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCert(prefix); err != nil {
		t.Fatalf("ternd's own key was refused: %v", err)
	}

	setDACL(t, prefix+".key", "D:P(A;;FA;;;OW)(A;;FR;;;BU)")
	_, err := LoadOrCreateCert(prefix)
	if err == nil || !strings.Contains(err.Error(), "may read or change it") || !strings.Contains(err.Error(), "icacls") {
		t.Fatalf("a key BUILTIN\\Users may read: %v", err)
	}

	// Made by hand in a directory whose ACL lets everyone read what it holds.
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, shared, "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)")
	for _, ext := range []string{".crt", ".key"} {
		b, err := os.ReadFile(prefix + ext)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shared, "agent"+ext), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err = LoadOrCreateCert(filepath.Join(shared, "agent"))
	if err == nil || !strings.Contains(err.Error(), "/inheritance:r") {
		t.Fatalf("a key that inherits read access for everyone: %v", err)
	}
}

// The agent's certificate is made owner-only, as its key is, so a pair made
// in a folder whose ACL lets Authenticated Users change what it holds, as a
// folder made under C:\ does on Windows 10 and 11, is taken at the next
// start.
func TestTLSPairInSharedFolderReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)")
	prefix := filepath.Join(dir, "agent")
	if _, err := LoadOrCreateCert(prefix); err != nil {
		t.Fatal(err)
	}
	ownerOnlyNow(t, prefix+".crt")
	if _, err := LoadOrCreateCert(prefix); err != nil {
		t.Errorf("a pair made in a folder Authenticated Users may change was refused: %v", err)
	}
}

// exposeToOthers makes path readable by every local user.
func exposeToOthers(t *testing.T, path string) {
	t.Helper()
	setDACL(t, path, "D:P(A;;FA;;;OW)(A;;FR;;;WD)")
}

// letOthersChange makes path writable by every local user.
func letOthersChange(t *testing.T, path string) {
	t.Helper()
	setDACL(t, path, "D:P(A;;FA;;;OW)(A;;FW;;;BU)")
}

// Access that reads the key without asking for read access, executing it
// (an executable section mapped from the file shows its bytes), or that lets
// another user delete it, is refused like read access; access that shows
// only the DACL or attributes is not.
func TestKeyFileExecuteOrDeleteAccess(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "agent")
	if _, err := LoadOrCreateCert(prefix); err != nil {
		t.Fatal(err)
	}
	key := prefix + ".key"
	for _, ace := range []string{
		"(A;;FX;;;BU)",       // FILE_GENERIC_EXECUTE
		"(A;;0x100020;;;BU)", // FILE_EXECUTE | SYNCHRONIZE
		"(A;;GX;;;BU)",       // GENERIC_EXECUTE
		"(A;;SD;;;BU)",       // DELETE
		"(A;;WO;;;BU)",       // WRITE_OWNER
	} {
		setDACL(t, key, "D:P(A;;FA;;;OW)"+ace)
		if err := checkKeyFileSafe(key); err == nil {
			t.Errorf("a key granting BUILTIN\\Users %s was accepted", ace)
		}
	}
	for _, ace := range []string{"(A;;RC;;;BU)", "(A;;0x100080;;;BU)"} { // READ_CONTROL; read attributes
		setDACL(t, key, "D:P(A;;FA;;;OW)"+ace)
		if err := checkKeyFileSafe(key); err != nil {
			t.Errorf("a key granting BUILTIN\\Users only %s was refused: %v", ace, err)
		}
	}
}

// The fix printed for a key file names accounts so icacls takes them. For
// an entry whose SID has no account name, which icacls refuses even as
// *SID, it is a line that replaces the DACL instead, and that line works.
func TestKeyFileHintForUnnamedSID(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "it's")
	if _, err := LoadOrCreateCert(prefix); err != nil {
		t.Fatal(err)
	}
	key := prefix + ".key"
	setDACL(t, key, "D:P(A;;FA;;;OW)(A;;FR;;;S-1-5-21-1-2-3-4242)")
	err := checkKeyFileSafe(key)
	if err == nil {
		t.Fatal("a key readable by an unnamed SID was accepted")
	}
	msg := err.Error()
	if strings.Contains(msg, "icacls") {
		t.Fatalf("hint %q uses icacls, which cannot name that SID", msg)
	}
	_, line, ok := strings.Cut(msg, "in PowerShell: ")
	if !ok {
		t.Fatalf("no PowerShell line in %q", msg)
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", line)
	// Windows PowerShell started from PowerShell 7, as on a CI runner, would
	// inherit 7's module path and fail to load Set-Acl's module.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, rerr := cmd.CombinedOutput()
	if rerr != nil {
		t.Fatalf("running the printed line: %v\n%s", rerr, out)
	}
	if err := checkKeyFileSafe(key); err != nil {
		t.Errorf("after the printed line the key is still refused: %v", err)
	}
	ownerOnlyNow(t, key)
}

// runPowerShell runs line as a PowerShell command in the directory dir.
func runPowerShell(t *testing.T, dir, line string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", line)
	cmd.Dir = dir
	// Windows PowerShell started from PowerShell 7, as on a CI runner, would
	// inherit 7's module path and fail to load Set-Acl's module.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd.CombinedOutput()
}

// The fix printed for a key file is a PowerShell line with its path and
// account names in single quotes, each kind of single quote PowerShell knows
// doubled: pasted as printed it fixes the key and runs nothing that the key's
// directory name holds, in each of its forms (an icacls line dropping
// inherited entries, one removing an explicit entry, and the Set-Acl line
// for an account with no name).
func TestKeyFileHintsPasteSafeInPowerShell(t *testing.T) {
	const inject = "$(New-Item INJECTED)"
	names := []string{
		"a'" + inject + "'b",
		"c\u2018" + inject + "\u2018d",
		"e\u2019" + inject + "\u2019f",
		"g\u201a" + inject + "\u201ah",
		"i\u201b" + inject + "\u201bj",
		"k`" + inject + "\u201c\u201d\u201e;" + inject + "l",
	}
	forms := []struct {
		want string // in the printed line
		set  func(t *testing.T, dir, key string)
	}{
		{"/inheritance:r", func(t *testing.T, dir, key string) {
			// The key inherits read access for everyone from its directory.
			setDACL(t, dir, "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;WD)")
			sd, err := windows.SecurityDescriptorFromString("D:")
			if err != nil {
				t.Fatal(err)
			}
			empty, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(key, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, empty, nil); err != nil {
				t.Fatal(err)
			}
		}},
		{"/remove", func(t *testing.T, _, key string) { setDACL(t, key, "D:P(A;;FA;;;OW)(A;;FR;;;BU)") }},
		{"Set-Acl", func(t *testing.T, _, key string) { setDACL(t, key, "D:P(A;;FA;;;OW)(A;;FR;;;S-1-5-21-1-2-3-4242)") }},
	}
	for _, name := range names {
		for _, form := range forms {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			prefix := filepath.Join(dir, "agent")
			if _, err := LoadOrCreateCert(prefix); err != nil {
				t.Fatal(err)
			}
			key := prefix + ".key"
			form.set(t, dir, key)
			err := checkKeyFileSafe(key)
			if err == nil {
				t.Fatalf("%s: a key others may read was accepted", name)
			}
			_, line, ok := strings.Cut(err.Error(), "in PowerShell: ")
			if !ok || !strings.Contains(line, form.want) {
				t.Fatalf("%s: no %s line for PowerShell in %q", name, form.want, err)
			}
			run := t.TempDir()
			if out, err := runPowerShell(t, run, line); err != nil {
				t.Errorf("%s: running the printed line %q: %v\n%s", name, line, err, out)
			}
			if ents, _ := os.ReadDir(run); len(ents) != 0 {
				t.Errorf("%s: pasting %q ran something the path holds: %d new files", name, line, len(ents))
			}
			if err := checkKeyFileSafe(key); err != nil {
				t.Errorf("%s: after the printed line %q the key is still refused: %v", name, line, err)
			}
		}
	}
}
