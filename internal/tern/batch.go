// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"fmt"
	"strings"
)

// cmdSyntax is what cmd.exe reads as syntax in a command line, quoted or
// not, instead of passing it on.
const cmdSyntax = "\"%!^&|<>()\r\n"

// checkBatchArgs refuses, on Windows, to run a batch file with cmd.exe syntax
// in its command line. Go quotes arguments for programs that split their
// command line the usual way, but every .bat and .cmd file runs under
// cmd.exe, which does not: a bare & in an argument would start a second
// command, so argv would no longer be the one command it names. path is the
// file that will run; argv is the command as given, whose first element goes
// on the command line too, where cmd.exe reads it as well.
func checkBatchArgs(goos, path string, argv []string) error {
	if goos != "windows" || !isBatchFile(path) {
		return nil
	}
	for i, a := range argv {
		if j := strings.IndexAny(a, cmdSyntax); j >= 0 {
			what := "argument"
			if i == 0 {
				what = "program name"
			}
			return fmt.Errorf("%s is a batch file, which cmd.exe runs, and cmd.exe would read the %q in %s %q as syntax; "+
				"run it in a shell command line with your own quoting instead", path, a[j], what, a)
		}
	}
	return nil
}

// isBatchFile reports whether Windows runs the file at path through cmd.exe:
// its name ends in .bat or .cmd, in any case, once the trailing dots and
// spaces Windows drops from a name are gone. A name with a stream in it,
// deploy.bat::$DATA, counts by either part.
func isBatchFile(path string) bool {
	name := winBase(path)
	file, _, _ := strings.Cut(name, ":")
	for _, n := range []string{name, file} {
		n = strings.ToLower(strings.TrimRight(n, ". "))
		if strings.HasSuffix(n, ".bat") || strings.HasSuffix(n, ".cmd") {
			return true
		}
	}
	return false
}

// winBase returns the last element of a Windows path, whatever the OS this
// runs on: what follows the last \ or /, or the drive in C:deploy.
func winBase(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	if len(path) >= 2 && path[1] == ':' {
		return path[2:]
	}
	return path
}

// cmdShellLine returns, on Windows, the command line that has cmd.exe run
// argv's line exactly as written, when argv is a shell command line: cmd.exe
// (path is the file that will run), /c, and the line, as a shell-mode run
// sends it. Go would otherwise quote the line for programs that split their
// command line the usual way, escaping each " as \", which cmd.exe does not
// read, so `rmdir /s /q "old logs"` would act on other folders than the
// one named. /s has cmd.exe drop exactly the outer quotes added here and run
// what is between them; /d skips the AutoRun commands in the registry, so
// nothing runs that the line does not say.
func cmdShellLine(goos, path string, argv []string) (string, bool) {
	if goos != "windows" || len(argv) != 3 || !strings.EqualFold(argv[1], "/c") ||
		!strings.EqualFold(strings.TrimRight(winBase(path), ". "), "cmd.exe") {
		return "", false
	}
	return `cmd.exe /d /s /c "` + argv[2] + `"`, true
}
