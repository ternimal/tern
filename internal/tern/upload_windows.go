// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// uploadTarget is the file an upload or a download writes: a name in a
// directory opened once, links and junctions on the way followed. All that
// comes after works relative to that open directory: what is under the name
// is looked at there, the temporary file is created in it and renamed over
// the name there, and the path the reply reports as Real is the one Windows
// has for the open directory. So the file lands exactly where the client was
// told, however names on the way are swapped meanwhile. The last name is not
// followed: the rename replaces a link there.
type uploadTarget struct {
	dir  windows.Handle // the open directory
	base string         // the target's name in it
	path string         // the path asked for, for messages
	want os.FileMode    // the mode sent
	tmp  *os.File       // the temporary file, in dir
	real string         // Real for the reply, or "unresolved: ..."
}

// openUploadTarget opens the directory rawDir, refuses a target that is a
// directory, and creates the temporary file, with the DACL the target must
// end up with (see tempFileSecurity). path is the path asked for. A name
// holding ':' is refused first: it names a data stream of a file, and the
// temporary file made for it would be a stream of a new, empty file named
// for what comes before the ':', left behind when the stream is removed.
func openUploadTarget(path, rawDir, base string, want os.FileMode) (*uploadTarget, error) {
	if strings.ContainsRune(base, ':') {
		return nil, fmt.Errorf("%s names a data stream of a file, not a file; name the file to write", path)
	}
	dir, err := openDir(rawDir)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: rawDir, Err: win32Err(err)}
	}
	t := &uploadTarget{dir: dir, base: base, path: path, want: want}
	if real, err := handlePath(dir); err != nil {
		t.real = "unresolved: " + err.Error()
	} else {
		t.real = filepath.Join(real, base)
	}
	if attrs, _, err := attrsAt(dir, base); err == nil && attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		windows.CloseHandle(dir)
		return nil, fmt.Errorf("%s is a directory; name the file to write", path)
	}
	if err := t.createTemp(rawDir); err != nil {
		windows.CloseHandle(dir)
		return nil, err
	}
	return t, nil
}

// createTemp creates the temporary file in the open directory, a new file of
// its own, never one already there or a link, with the DACL the target must
// end up with from the moment it exists. The handle has DELETE, so finish and
// abort rename and delete the file through it: a DACL that denies its creator
// something, as a deny entry for BUILTIN\Users that a target of ours passes
// on does, would refuse a later open by name.
func (t *uploadTarget) createTemp(rawDir string) error {
	sd, err := tempFileSecurity(t.dir, t.base, t.want)
	if err != nil {
		return err
	}
	prefix := "." + t.base + ".tern-"
	for range 10000 {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10)
		h, err := openAt(t.dir, name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE,
			windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, sd)
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			continue
		}
		if err != nil {
			return &os.PathError{Op: "createtemp", Path: filepath.Join(rawDir, name), Err: win32Err(err)}
		}
		t.tmp = os.NewFile(uintptr(h), filepath.Join(rawDir, name))
		return nil
	}
	return &os.PathError{Op: "createtemp", Path: filepath.Join(rawDir, prefix+"*"), Err: fs.ErrExist}
}

// mode is the mode the file gets, judged by what is now under the target's
// name in the open directory: a regular file keeps its read-only attribute
// when it is ours (see ownFileSecurity) and no other account may add files
// to the directory or delete them from it (see othersMayAddNames), as cp
// leaves a file's mode, and is narrowed to the mode sent otherwise; for
// anything else, or nothing, the file gets the mode a new one would.
func (t *uploadTarget) mode() os.FileMode {
	attrs, tag, err := attrsAt(t.dir, t.base)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag&reparseTagNameSurrogate != 0 {
		return newFileMode(t.want)
	}
	perm := os.FileMode(0o666)
	if attrs&windows.FILE_ATTRIBUTE_READONLY != 0 {
		perm = 0o444
	}
	_, own := ownFileSecurity(t.dir, t.base)
	return keptMode(perm, own && !othersMayAddNames(t.dir), t.want)
}

// finish sets the temporary file's mode and renames it over the target
// through its own handle, then closes it. On failure it deletes the
// temporary file, and the target is left as it was.
func (t *uploadTarget) finish() error {
	if err := t.tmp.Chmod(t.mode()); err != nil {
		dropTemp(t.tmp)
		return err
	}
	if err := renameAt(windows.Handle(t.tmp.Fd()), t.dir, t.base); err != nil {
		dropTemp(t.tmp)
		return &os.LinkError{Op: "rename", Old: t.tmp.Name(), New: t.path, Err: win32Err(err)}
	}
	return t.tmp.Close()
}

// win32Err turns an NTSTATUS error, as NtCreateFile and NtSetInformationFile
// return, into the Win32 error it stands for, so it reads as Windows's other
// file errors do.
func win32Err(err error) error {
	if st, ok := err.(windows.NTStatus); ok {
		return st.Errno()
	}
	return err
}

// abort drops the temporary file, leaving the target as it was.
func (t *uploadTarget) abort() {
	dropTemp(t.tmp)
}

// close closes the directory.
func (t *uploadTarget) close() { windows.CloseHandle(t.dir) }

// reparseTagNameSurrogate marks a reparse tag that names another file or
// directory, as a symbolic link or a junction does, unlike reparse points
// that only change how a file's own data is stored.
const reparseTagNameSurrogate = 0x20000000

// anonymousOnly is the quality of service asked of whatever an open reaches:
// a named pipe server there, which a link or junction another user swaps in
// could lead the open to, can neither act as this process nor learn whose
// it is (see openRegular).
var anonymousOnly = windows.SECURITY_QUALITY_OF_SERVICE{
	Length:              uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})),
	ImpersonationLevel:  windows.SecurityAnonymous,
	ContextTrackingMode: windows.SECURITY_STATIC_TRACKING,
}

// ntdllRtlFreeUnicodeString frees the name RtlDosPathNameToNtPathName makes.
var ntdllRtlFreeUnicodeString = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlFreeUnicodeString")

// openDir opens the directory path names, following links and junctions on
// the way, as the root that openAt and renameAt work in. It asks only for
// the right to add a file to it, which writing there takes anyway, so a
// directory this user may add files to but not list opens too. Anything but
// a directory on a disk is refused, and a named pipe the path may lead to
// learns nothing of this process (see anonymousOnly).
func openDir(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var nt windows.NTUnicodeString
	if err := windows.RtlDosPathNameToNtPathName(p, &nt, nil, nil); err != nil {
		return 0, err
	}
	defer ntdllRtlFreeUnicodeString.Call(uintptr(unsafe.Pointer(&nt)))
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: &nt, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityQoS: &anonymousOnly}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&h, fileAddFile, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE, 0, 0); err != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return 0, err
	}
	if ft, err := windows.GetFileType(h); err != nil || ft != windows.FILE_TYPE_DISK {
		windows.CloseHandle(h)
		return 0, windows.ERROR_DIRECTORY
	}
	return h, nil
}

// openAt opens, or with disposition FILE_CREATE creates, name in the open
// directory dir: the name is one entry of that directory, never a path, and
// a link or other reparse point there is opened itself, never followed.
// options are NtCreateFile's create options; sd, if not nil, is the security
// descriptor a new file gets.
func openAt(dir windows.Handle, name string, access, disposition, options uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: dir, ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: sd, SecurityQoS: &anonymousOnly}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&h, access, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT, 0, 0); err != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return 0, err
	}
	return h, nil
}

// fileAttributeTagInfo is FILE_ATTRIBUTE_TAG_INFO.
type fileAttributeTagInfo struct {
	FileAttributes, ReparseTag uint32
}

// attrsAt returns the attributes of name in the open directory dir, and its
// reparse tag when it is a reparse point, which is not followed. It asks for
// FILE_READ_ATTRIBUTES alone, which NTFS also grants to whoever may list the
// directory, whatever the file's own DACL says.
func attrsAt(dir windows.Handle, name string) (attrs, tag uint32, err error) {
	h, err := openAt(dir, name, windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, 0, nil)
	if err != nil {
		return 0, 0, err
	}
	defer windows.CloseHandle(h)
	var info fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return 0, 0, err
	}
	return info.FileAttributes, info.ReparseTag, nil
}

// fileRenameInformation is FILE_RENAME_INFORMATION, its file name running
// on past the struct.
type fileRenameInformation struct {
	ReplaceIfExists uint32 // a BOOLEAN, padded as the C struct is
	RootDirectory   windows.Handle
	FileNameLength  uint32 // in bytes, the terminating NUL aside
	FileName        [1]uint16
}

// renameAt renames the file h is open on, with DELETE access, to name in the
// open directory dir, replacing a file there. The new name is an entry of
// that directory, never a path that names on the way could redirect. It
// goes to NtSetInformationFile directly: SetFileInformationByHandle takes the
// name for a path.
func renameAt(h, dir windows.Handle, name string) error {
	n, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	size := int(unsafe.Offsetof(fileRenameInformation{}.FileName)) + 2*len(n)
	buf := make([]uint64, (size+7)/8) // 8-byte aligned, zeroed
	info := (*fileRenameInformation)(unsafe.Pointer(&buf[0]))
	info.ReplaceIfExists = 1
	info.RootDirectory = dir
	info.FileNameLength = uint32(2 * (len(n) - 1))
	copy(unsafe.Slice(&info.FileName[0], len(n)), n)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(info)), uint32(size), windows.FileRenameInformation)
}
