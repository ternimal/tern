// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runArgv runs argv on the agent as a client would, returning its output and
// exit code, or the agent's refusal.
func runArgv(t *testing.T, cl *Client, argv ...string) (string, int, error) {
	t.Helper()
	var out bytes.Buffer
	code, err := cl.Run(argv, nil, &out)
	return out.String(), code, err
}

// A batch file is checked however its path is written: with no extension
// (Start adds .bat), relative, relative to a drive (C:deploy), with forward
// slashes, as a \\?\ or UNC path, or with an extension not in PATHEXT
// (deploy.v1 runs deploy.v1.bat). cmd.exe syntax in the program name itself
// is refused too. Plain arguments still reach the batch file.
func TestWindowsBatchPathForms(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir()) // long names: no ~ in the paths below
	if err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(dir, "tools")
	os.MkdirAll(tools, 0o755)
	for _, n := range []string{"deploy.bat", "deploy.v1.bat"} {
		if err := os.WriteFile(filepath.Join(tools, n), []byte("@echo ran %~nx0 [%*]\r\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(tools) // the agent's working directory, for the relative forms

	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	marker := filepath.Join(dir, "injected")
	forms := []string{
		filepath.Join(tools, "deploy"),
		`.\deploy`,
		`..\tools\deploy`,
		tools[:2] + "deploy",
		strings.ReplaceAll(filepath.Join(tools, "deploy"), `\`, "/"),
		`\\?\` + filepath.Join(tools, "deploy"),
		filepath.Join(tools, "deploy.v1"),
	}
	if _, err := os.Stat(`\\localhost\` + tools[:1] + `$` + tools[2:]); err == nil {
		forms = append(forms, `\\localhost\`+tools[:1]+`$`+tools[2:]+`\deploy`)
	}
	for _, name := range forms {
		os.Remove(marker)
		out, _, err := runArgv(t, cl, name, "x&echo.INJECTED>"+marker)
		if err == nil || !strings.Contains(err.Error(), "batch file") {
			t.Errorf("%s with an & argument: not refused (%v)\n%s", name, err, out)
		}
		if _, serr := os.Stat(marker); serr == nil {
			t.Errorf("%s: cmd.exe ran the injected command", name)
		}
		out, code, err := runArgv(t, cl, name, "web-1", "a b")
		if err != nil || code != 0 || !strings.Contains(out, `[web-1 "a b"]`) {
			t.Errorf("%s with plain arguments: exit %d, %v\n%s", name, code, err, out)
		}
	}
	if out, _, err := runArgv(t, cl, tools+`\a&echo.INJECTED&\..\deploy.bat`, "safe"); err == nil || strings.Contains(out, "INJECTED") {
		t.Errorf("cmd.exe syntax in a batch file's own path was not refused (%v)\n%s", err, out)
	}
}

// A shell-mode line, cmd /c and the line, runs as written: quotes in it
// reach cmd.exe as quotes, not as the \" Go writes for other programs.
func TestWindowsShellLineVerbatim(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a b.txt"), []byte("CONTENT OF A B"), 0o644)
	// A name no other folder has: misquoted, the rmdir below would act on
	// \<name>, at the root of the drive.
	const logs = "tern old logs 5c1e"
	os.MkdirAll(filepath.Join(dir, logs, "x"), 0o755)
	t.Chdir(dir) // the agent's working directory

	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	if out, code, err := runArgv(t, cl, "cmd", "/c", `type "a b.txt"`); err != nil || code != 0 || !strings.Contains(out, "CONTENT OF A B") {
		t.Errorf(`type "a b.txt": exit %d, %v: %q`, code, err, out)
	}
	if out, _, err := runArgv(t, cl, "cmd", "/c", `echo "x" & echo y`); err != nil || !strings.HasPrefix(out, `"x" `) || !strings.Contains(out, "\ny") {
		t.Errorf(`echo "x" & echo y: %v: %q`, err, out)
	}
	if out, code, err := runArgv(t, cl, "cmd", "/c", `rmdir /s /q "`+logs+`"`); err != nil || code != 0 {
		t.Errorf("rmdir /s /q %q: exit %d, %v: %q", logs, code, err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, logs)); err == nil {
		t.Errorf("rmdir /s /q %q left the folder it names", logs)
	}
}

// Cancelling a command kills what it started too: here the PowerShell a
// cmd /c line starts, which would otherwise write the marker.
func TestWindowsCancelKillsChildren(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "still-ran")
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	done := make(chan struct{})
	go func() {
		cl.Run([]string{"cmd", "/c", "powershell -NoProfile -Command Start-Sleep 3; Set-Content '" + marker + "' x"}, nil, io.Discard)
		close(done)
	}()
	time.Sleep(1500 * time.Millisecond)
	cl.Close() // what an MCP timeout, job_cancel, a REST cancel and Ctrl-C do
	<-done
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command's child outlived the cancelled command")
	}
}

// A command's background processes end with it, once its output has ended,
// as on Unix.
func TestWindowsBackgroundProcessEndsWithCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "still-ran")
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	// Start-Process starts a second PowerShell that does not inherit the
	// output (a process that holds it keeps the command going), and the
	// first exits at once.
	script := `Start-Process -WindowStyle Hidden -FilePath powershell -ArgumentList '-NoProfile -Command Start-Sleep 3; Set-Content "` + marker + `" x'`
	if out, code, err := runArgv(t, cl, "powershell", "-NoProfile", "-Command", script); err != nil || code != 0 {
		t.Fatalf("exit %d, %v: %s", code, err, out)
	}
	time.Sleep(4 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command's background process outlived it")
	}
}
