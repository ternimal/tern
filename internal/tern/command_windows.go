// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// newCommand builds the command serveExec runs for argv, with the file it
// will run settled first, so the checks below see that file. exec.Command
// looks up a bare name at once, but leaves a name with a directory in it,
// even only a drive as in C:deploy, as given, and Start adds the extension
// later (deploy runs deploy.bat). Path is set to the file found, the way
// Start finds it, so Start runs exactly the file checked.
func newCommand(argv []string) (*exec.Cmd, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	if filepath.Base(argv[0]) != argv[0] {
		path, err := lookExtensions(argv[0])
		if err != nil {
			return nil, err
		}
		cmd.Path = path
	}
	if err := checkBatchArgs(runtime.GOOS, cmd.Path, argv); err != nil {
		return nil, err
	}
	if line, ok := cmdShellLine(runtime.GOOS, cmd.Path, argv); ok {
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line}
	}
	return cmd, nil
}

// lookExtensions finds the file Start runs for a name with a directory in
// it: the name itself when its extension is in PATHEXT, and otherwise what
// LookPath finds, the name with the first PATHEXT extension that makes it a
// file (or the name itself when it names a file and has an extension).
func lookExtensions(name string) (string, error) {
	if ext := filepath.Ext(name); ext != "" {
		for _, e := range pathExts() {
			if strings.EqualFold(ext, e) {
				return name, nil
			}
		}
	}
	return exec.LookPath(name)
}

// pathExts is the PATHEXT list as os/exec reads it.
func pathExts() []string {
	x := os.Getenv("PATHEXT")
	if x == "" {
		return []string{".com", ".exe", ".bat", ".cmd"}
	}
	var exts []string
	for e := range strings.SplitSeq(strings.ToLower(x), ";") {
		if e == "" {
			continue
		}
		if e[0] != '.' {
			e = "." + e
		}
		exts = append(exts, e)
	}
	return exts
}
