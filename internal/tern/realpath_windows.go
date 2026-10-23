// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// splitUploadPath splits p into the directory to open and the file name.
// Windows itself resolves ".." by name, so cleaning first changes nothing.
func splitUploadPath(p string) (dir, base string) {
	return filepath.Dir(p), filepath.Base(p)
}

// openedRealPath returns the path the open file f really has. Asking for the
// handle's final path also rules out a link swapped since it was opened.
func openedRealPath(f *os.File) (string, error) {
	return handlePath(windows.Handle(f.Fd()))
}

// handlePath is the path Windows reports for an open handle, with links,
// junctions and short names resolved, in DOS form; a network path keeps its
// \\server\share form, which path rules refuse.
func handlePath(h windows.Handle) (string, error) {
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			p := windows.UTF16ToString(buf[:n])
			if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
				return `\\` + rest, nil
			}
			return strings.TrimPrefix(p, `\\?\`), nil
		}
		buf = make([]uint16, n)
	}
}

// readPseudo reads a file that reports size 0 up to limit bytes. A file on a
// disk, the only kind a download opens here, ends where its data does, so
// maxTime is not needed.
func readPseudo(f *os.File, limit int64, _ time.Duration) ([]byte, error) {
	return io.ReadAll(io.LimitReader(f, limit))
}
