// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tempFileSecurity returns the security descriptor for the temporary file
// an upload or a download writes and then renames over name in the open
// directory dir, or nil to inherit the directory's DACL. The rename keeps
// the temporary file's DACL, and one inherited from the directory, which on
// NTFS usually lets BUILTIN\Users read, would replace a private file's: so a
// target of ours (see ownFileSecurity) in a directory no other account may
// add files to or delete them from (see othersMayAddNames) passes its DACL
// on, protected (inheriting nothing, as an owner-only one) or not, explicit
// entries such as a deny included, as cp leaves a file's mode. Any other
// target is treated as a new file, as Unix narrows one another user owns: a
// file another user planted in a shared directory, moved there or renamed
// over the name must not hand its DACL to what we write. A new file written
// with a private mode (nothing for group or others) is created owner-only,
// as Unix would make it 0600, and so is one written over a file of ours that
// no other account may read, which Unix keeps private too, or whose DACL
// may let others less than the directory's would (see narrowerThanInherited),
// as Unix never widens such a file's mode; otherwise the file inherits the
// directory's DACL, as any new file there does.
func tempFileSecurity(dir windows.Handle, name string, mode os.FileMode) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, own := ownFileSecurity(dir, name)
	if own && !othersMayAddNames(dir) {
		dacl, err := daclOnly(sd)
		if err != nil {
			return nil, fmt.Errorf("copy the DACL of %s: %w", name, err)
		}
		return dacl, nil
	}
	if mode.Perm()&0o077 == 0 || own && (!readableByOthers(sd) || narrowerThanInherited(sd)) {
		return windows.SecurityDescriptorFromString(ownerOnlySDDL)
	}
	return nil, nil
}

// narrowerThanInherited reports whether sd, the owner and DACL of a file of
// ours, may let others less than the DACL its directory passes on to a new
// file: one that is protected inherits nothing from the directory, as a
// file restricted to its owner and one named reader does, and an explicit
// entry other than an allow, such as a deny, takes from what it inherits.
// A DACL that inherits, with only allows of its own, holds what the
// directory passed on when the file was made there, so a new file that
// inherits instead is no wider than it.
func narrowerThanInherited(sd *windows.SECURITY_DESCRIPTOR) bool {
	ctl, _, err := sd.Control()
	if err != nil || ctl&windows.SE_DACL_PROTECTED != 0 {
		return true
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return true
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return true
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 && ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return true
		}
	}
	return false
}

// fileChanging is the access to a file that lets whoever holds it change
// what it holds, delete or rename it, or give themselves that access.
const fileChanging = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// FILE_ADD_FILE and FILE_DELETE_CHILD, the access to a directory that lets
// whoever holds it add a file to it, by making one or moving one in, and
// delete or rename a file it holds, whoever's.
const (
	fileAddFile     = windows.FILE_WRITE_DATA
	fileDeleteChild = 0x40
)

// dirAddingNames is the access to a directory that lets whoever holds it
// add a file to it, delete or rename one it holds, or give themselves that
// access.
const dirAddingNames = fileAddFile | fileDeleteChild | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// othersMay reports whether dacl, the DACL of a file or a directory owned by
// owner, lets anyone but that owner, this process's user or a group that
// owns what it creates, SYSTEM or Administrators (see trustedSID) have any
// of access to it. A NULL DACL lets everyone have all of it, and an entry
// of a kind not looked into here is taken as letting them. Deny entries are
// passed over, which can only make the answer yes.
func othersMay(dacl *windows.ACL, owner *windows.SID, self []*windows.SID, access windows.ACCESS_MASK) bool {
	if dacl == nil {
		return true
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return true
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to what a directory holds, not to the object itself
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedCallbackACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
		default:
			return true
		}
		if ace.Mask&access != 0 && !trustedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)), owner, self) {
			return true
		}
	}
	return false
}

// othersMayAddNames reports whether an account but this process's user, a
// group that owns what it creates, SYSTEM or Administrators may add a file
// to the open directory dir, or delete or rename one it holds, and so may
// have put a file of ours under the target's name: moved it there from a
// folder of theirs, or renamed it over the name. Such an account may own the
// directory, and so give itself that access, or the directory's DACL may
// grant it (see dirAddingNames). dir is open only to add files, so its owner
// and DACL are read through a second handle, opened relative to it on the
// same directory whatever names change meanwhile; a directory whose owner
// and DACL cannot be read counts as one others may add to.
func othersMayAddNames(dir windows.Handle) bool {
	h, err := openAt(dir, "", windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	if err != nil {
		return true
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return true
	}
	self, err := ownerSIDs()
	if err != nil {
		return true
	}
	if !anySID(self, owner) && !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	dacl, _, err := sd.DACL()
	return err != nil || othersMay(dacl, owner, self, dirAddingNames)
}

// readableByOthers reports whether sd, the owner and DACL of a file of ours
// (see ownFileSecurity), lets an account other than those trustedSID names
// read the file or run it, which reads it too, as a key file must not (see
// keyFileExposing).
func readableByOthers(sd *windows.SECURITY_DESCRIPTOR) bool {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return true
	}
	self, err := ownerSIDs()
	if err != nil {
		return true
	}
	dacl, _, err := sd.DACL()
	return err != nil || othersMay(dacl, owner, self, keyFileExposing)
}

// dropTemp deletes f, a temporary file made by uploadTarget, through its own
// handle, and closes it. finish may have made it read-only, which a plain
// delete refuses: the delete ignores the attribute, or, on a file system
// that cannot, the attribute is cleared first.
func dropTemp(f *os.File) {
	h := windows.Handle(f.Fd())
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	if windows.SetFileInformationByHandle(h, windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags))) != nil {
		f.Chmod(0o600)
		del := uint32(1) // FILE_DISPOSITION_INFO.DeleteFile
		windows.SetFileInformationByHandle(h, windows.FileDispositionInfo,
			(*byte)(unsafe.Pointer(&del)), uint32(unsafe.Sizeof(del)))
	}
	f.Close()
}

// daclOnly returns a security descriptor holding sd's DACL, entries copied
// in order, inherited ones included, and protected or not as in sd. It has
// no owner, so a file created with it is owned as any file its creator
// makes. Given to NtCreateFile, the DACL is taken as it is: inherited
// entries keep their inherited mark, so a later change to the directory's
// entries still replaces them.
func daclOnly(sd *windows.SECURITY_DESCRIPTOR) (*windows.SECURITY_DESCRIPTOR, error) {
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return nil, err
	}
	abs, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := abs.SetDACL(dacl, true, false); err != nil {
		return nil, err
	}
	if err := abs.SetControl(windows.SE_DACL_PROTECTED, ctl&windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	return abs.ToSelfRelative()
}
