// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownFileSecurity returns the owner and DACL of name in the open directory
// dir when it is a file of ours, both read from one open handle, so they
// describe the same file. Ours means owned by this process's user, or by a
// group that owns what the process creates, as BUILTIN\Administrators does
// for an elevated administrator (see ownerSIDs), with a single name, and
// with a DACL that lets nobody else change it (see othersMay). A link
// is not followed: its own owner and DACL are read. A file with more names
// is not ours: another user who can hard-link one of our files, with its own
// DACL, into a shared directory must not get that DACL passed on. Nor is a
// file others may change: moving a file keeps its DACL, and another user who
// may delete such a file can move it next to us, as Windows leaves dozens of
// files BUILTIN\Administrators owns that INTERACTIVE may change. Anything
// that cannot be read is not ours either. A file of ours may still have been
// moved there, which only the directory tells (see othersMayAddNames).
func ownFileSecurity(dir windows.Handle, name string) (*windows.SECURITY_DESCRIPTOR, bool) {
	// READ_CONTROL alone: CreateFile would also ask for SYNCHRONIZE and
	// FILE_READ_ATTRIBUTES, which a DACL denying read to a group we are in
	// refuses, even on a file we own; as owner we may always read its
	// security.
	h, err := openAt(dir, name, windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if err != nil {
		return nil, false
	}
	defer windows.CloseHandle(h)
	var info fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileStandardInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil ||
		info.Directory || info.NumberOfLinks != 1 {
		return nil, false
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, false
	}
	self, err := ownerSIDs()
	if err != nil || !anySID(self, owner) {
		return nil, false
	}
	dacl, _, err := sd.DACL()
	if err != nil || othersMay(dacl, owner, self, fileChanging) {
		return nil, false
	}
	return sd, true
}

// fileStandardInfo is FILE_STANDARD_INFO.
type fileStandardInfo struct {
	AllocationSize, EndOfFile int64
	NumberOfLinks             uint32
	DeletePending, Directory  bool
}

// umask has no Windows counterpart: there a mode only sets the read-only
// attribute.
const umask os.FileMode = 0

// ownerOnlySDDL is a protected DACL (D:P, so nothing is inherited from the
// directory) allowing full access (FA) to the file's owner (OW) only.
const ownerOnlySDDL = "D:P(A;;FA;;;OW)"

// createOwnerOnly creates path, which must not exist yet, handing CreateFile
// the owner-only DACL so the file never exists with the directory's
// inherited one, which on NTFS usually lets BUILTIN\Users read.
func createOwnerOnly(path string, flag int) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(ownerOnlySDDL)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	access := uint32(windows.GENERIC_WRITE)
	if flag&os.O_APPEND != 0 {
		access = windows.FILE_APPEND_DATA | windows.SYNCHRONIZE
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	h, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if err == windows.ERROR_FILE_EXISTS {
			err = fs.ErrExist
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// restrictToOwner replaces path's DACL with a protected one granting full
// access to the owner only, so a private key is not left readable by every
// local user through the directory's inherited ACL (NTFS grants BUILTIN\Users
// read by default). 0600 on Windows only toggles the read-only attribute, which
// does not restrict reads.
func restrictToOwner(path string) error {
	// D:P = protected DACL (drops inherited ACEs); (A;;FA;;;OW) = allow Full
	// Access to the object's owner.
	sd, err := windows.SecurityDescriptorFromString(ownerOnlySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
