// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import "testing"

func TestCheckBatchArgs(t *testing.T) {
	for _, c := range []struct {
		goos, path string
		argv       []string
		refused    bool
	}{
		{"windows", `C:\npm\pm2.cmd`, []string{"pm2", "restart", "web&ver"}, true},
		{"windows", `C:\npm\pm2.CMD`, []string{"pm2", "restart", "web|calc"}, true},
		{"windows", `C:\x\deploy.bat`, []string{`C:\x\deploy.bat`, "%COMSPEC%"}, true},
		{"windows", `C:\x\deploy.bat. `, []string{`C:\x\deploy.bat. `, "a^b"}, true},
		{"windows", `C:\x\deploy.bat`, []string{`C:\x\deploy`, `say "hi"`}, true},
		{"windows", `C:\x\deploy.bat`, []string{`C:\x\deploy`, "line\r\nnext"}, true},
		{"windows", `C:\x\deploy.bat`, []string{`C:\x\deploy`, "web-1", "--port=80", "a b", `C:\dir\`}, false},
		// The program name goes on the command line too.
		{"windows", `C:\x\deploy.bat`, []string{`C:\x\a&calc&\..\deploy.bat`, "safe"}, true},
		{"windows", `C:\Program Files\x\deploy.bat`, []string{`C:\Program Files\x\deploy.bat`, "safe"}, false},
		// However the path to the batch file is written.
		{"windows", `C:deploy.bat`, []string{`C:deploy`, "a&b"}, true},
		{"windows", `C:/x/deploy.bat`, []string{`C:/x/deploy`, "a&b"}, true},
		{"windows", `\\?\C:\x\deploy.bat`, []string{`\\?\C:\x\deploy`, "a&b"}, true},
		{"windows", `\\host\share\deploy.bat`, []string{`\\host\share\deploy`, "a&b"}, true},
		{"windows", `C:\x\deploy.v1.bat`, []string{`C:\x\deploy.v1`, "a&b"}, true},
		{"windows", `C:\x\deploy.bat::$DATA`, []string{`C:\x\deploy.bat::$DATA`, "a&b"}, true},
		{"windows", `C:\x\DEPLOY~1.BAT`, []string{`C:\x\DEPLOY~1.BAT`, "a&b"}, true},
		// Not batch files.
		{"windows", `C:\Windows\System32\findstr.exe`, []string{"findstr", "a|b"}, false},
		{"windows", `C:\x\deploy.batx`, []string{`C:\x\deploy.batx`, "a&b"}, false},
		{"windows", `C:\x.bat\deploy.exe`, []string{`C:\x.bat\deploy`, "a&b"}, false},
		{"linux", "/usr/bin/x.cmd", []string{"x.cmd", "a&b"}, false},
	} {
		err := checkBatchArgs(c.goos, c.path, c.argv)
		if (err != nil) != c.refused {
			t.Errorf("checkBatchArgs(%s, %q, %q) = %v, refused want %v", c.goos, c.path, c.argv, err, c.refused)
		}
	}
}

func TestCmdShellLine(t *testing.T) {
	for _, c := range []struct {
		goos, path string
		argv       []string
		want       string
	}{
		{"windows", `C:\Windows\system32\cmd.exe`, []string{"cmd", "/c", `rmdir /s /q "old logs"`}, `cmd.exe /d /s /c "rmdir /s /q "old logs""`},
		{"windows", `C:\Windows\System32\CMD.EXE`, []string{`C:\Windows\System32\CMD.EXE`, "/C", `echo "x" & echo y`}, `cmd.exe /d /s /c "echo "x" & echo y"`},
		// Anything else keeps Go's quoting.
		{"windows", `C:\Windows\system32\cmd.exe`, []string{"cmd", "/k", "dir"}, ""},
		{"windows", `C:\Windows\system32\cmd.exe`, []string{"cmd", "/c", "echo", "x"}, ""},
		{"windows", `C:\tools\cmdx.exe`, []string{"cmdx", "/c", "dir"}, ""},
		{"linux", "/bin/cmd.exe", []string{"cmd.exe", "/c", "dir"}, ""},
	} {
		got, ok := cmdShellLine(c.goos, c.path, c.argv)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("cmdShellLine(%s, %q, %q) = %q, %v; want %q", c.goos, c.path, c.argv, got, ok, c.want)
		}
	}
}
