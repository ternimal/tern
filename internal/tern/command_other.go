// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

import "os/exec"

// newCommand builds the command serveExec runs for argv.
func newCommand(argv []string) (*exec.Cmd, error) {
	return exec.Command(argv[0], argv[1:]...), nil
}
