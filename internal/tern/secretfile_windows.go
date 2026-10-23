// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// secretFileExposure says whether other local users could read or change f,
// the open file at path that holds a secret, by the rules a key file is held
// to (see checkKeyFileAccess), read from the open file itself; words say how
// to replace the secret.
func secretFileExposure(f *os.File, _ fs.FileInfo, path string, words fileWords) (*secretFileError, error) {
	return fileSecurityProblem(f, path, secretRule(words))
}

// changeExposure says whether another local user could change f, the open
// file at path (see changeRule), read from the open file itself; words say
// what to do about it.
func changeExposure(f *os.File, _ fs.FileInfo, path string, words fileWords) (*secretFileError, error) {
	return fileSecurityProblem(f, path, changeRule(words))
}

// maxPlaceLinks is the most symbolic links placeExposure follows from a path.
const maxPlaceLinks = 40

// placeExposure says whether another account could have chosen the file at
// path, which was opened as the file whose status is fi, through a symbolic
// link: one at the path, and each one it leads through, must be owned by
// this process's user, a group that owns what it creates, SYSTEM or
// Administrators, who chose where it leads, and where the links end must be
// the file that was opened. A junction leads only to a directory, which is
// refused as not a regular file before this. The directory's ACL is not
// looked at.
func placeExposure(path string, fi fs.FileInfo, _ fileWords) (*secretFileError, error) {
	self, err := ownerSIDs()
	if err != nil {
		return nil, err
	}
	hop := path // the name being looked at: path, or where its links lead
	for links := 0; ; links++ {
		lfi, err := os.Lstat(hop)
		if err != nil {
			return nil, err
		}
		if lfi.Mode()&fs.ModeSymlink == 0 {
			if !os.SameFile(lfi, fi) {
				return nil, fmt.Errorf("%s: the path changed while it was being opened", path)
			}
			return nil, nil
		}
		owner, err := linkOwner(hop)
		if err != nil {
			return nil, err
		}
		if !anySID(self, owner) && !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			where := "it"
			if hop != path {
				where = "it leads to " + hop + ", which"
			}
			return &secretFileError{path: path,
				problem: fmt.Sprintf("%s is a symbolic link owned by %s, not by this user, who chose where it leads", where, accountName(owner)),
				fix:     "unless you made the link yourself, delete it and write the file in its place as this user"}, nil
		}
		if links == maxPlaceLinks {
			return nil, fmt.Errorf("%s: more than %d symbolic links", path, maxPlaceLinks)
		}
		target, err := os.Readlink(hop)
		if err != nil {
			return nil, err
		}
		switch {
		case filepath.IsAbs(target):
		case target != "" && os.IsPathSeparator(target[0]):
			// Rooted with no drive, \dir\file: from the root of the link's
			// own volume, as Windows resolves it.
			target = filepath.VolumeName(hop) + target
		default:
			target = filepath.Join(filepath.Dir(hop), target)
		}
		hop = target
	}
}

// linkOwner returns the owner of the link at path itself, not of what it
// leads to.
func linkOwner(path string) (*windows.SID, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

// fileSecurityProblem holds the owner and DACL of f, the open file at path,
// to rule.
func fileSecurityProblem(f *os.File, path string, rule accessRule) (*secretFileError, error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	err = checkFileSecurity(path, sd, rule)
	var kerr *keyFileError
	if errors.As(err, &kerr) {
		return &secretFileError{path: path, problem: kerr.problem, fix: kerr.fix}, nil
	}
	return nil, err
}
