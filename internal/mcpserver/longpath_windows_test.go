// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"testing"

	"golang.org/x/sys/windows"
)

// longTempDir is a new temporary directory under its long name. Where TEMP
// holds an 8.3 short name, as C:\Users\RUNNER~1 on a CI runner does, a path
// under t.TempDir() is one the tools refuse on a Windows agent (see
// windowsAlias), so tests that hand such paths to a tool take this one.
func longTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		t.Fatalf("long name of %s: %v", dir, err)
	}
	return windows.UTF16ToString(buf[:n])
}
