// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"os"

	"golang.org/x/sys/windows"
)

// openRegular opens path for reading if it is a regular file on a disk,
// refusing anything else before reading from it. The path is the client's,
// and another local user may swap a link or junction on it: a named pipe it
// then leads to is refused, as is a console or other device, and its server
// can neither act as this process nor learn whose it is: the open allows
// anonymous impersonation only, where by default a server may impersonate a
// client that has written to its pipe.
func openRegular(path string) (*os.File, os.FileInfo, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// As os.Open does, but for the quality of service: FILE_FLAG_BACKUP_SEMANTICS
	// opens a directory too, which is then refused as not a regular file.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS|
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if ft, err := windows.GetFileType(h); err != nil || ft != windows.FILE_TYPE_DISK {
		windows.CloseHandle(h)
		return nil, nil, errNotRegular
	}
	f := os.NewFile(uintptr(h), path)
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errNotRegular
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
