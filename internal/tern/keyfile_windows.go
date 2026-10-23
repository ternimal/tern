// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// keyFileExposing is the access to a key file that lets whoever holds it read
// the key, replace it, delete it, or give themselves that access. Execute
// access reads it too: a section mapped executable from the file shows its
// bytes. Delete access lets a user remove the key, so the agent cannot start
// again with it or makes a new one under another fingerprint.
const keyFileExposing = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.FILE_EXECUTE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.GENERIC_ALL

// The callback kinds of allow and deny entries, which add a condition to the
// plain ones and share their layout.
const (
	accessAllowedCallbackACEType = 9
	accessDeniedCallbackACEType  = 10
)

// checkKeyFileAccess is what Windows has for the Unix owner and mode checks.
// The file must be owned by this process's user, or by a group it makes the
// owner of what it creates (BUILTIN\Administrators for an elevated
// administrator, which is how ternd's own key files come out), and its DACL
// may let nobody else read, change or delete it, but SYSTEM and
// Administrators, who can read every file anyway. NTFS ignores the mode, and
// a key file made by hand in a directory others can write to inherits that
// directory's ACL, which usually lets BUILTIN\Users read it.
func checkKeyFileAccess(path string, _ fs.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkFileSecurity(path, sd, secretRule(agentKeyWords))
}

// readClientKey reads a client's private key from path, a regular file only
// here, refusing before it reads anything one ssh would refuse: the rule of
// a token file (see secretRule), except that, as Windows' OpenSSH allows,
// SYSTEM or Administrators may own it. pipe is always false.
func readClientKey(path string) (data []byte, pipe bool, err error) {
	rule := secretRule(clientKeyWords)
	rule.rootOwned = true
	data, err = readCheckedFile(path, maxSecretFile, func(f *os.File, _ fs.FileInfo) error {
		p, err := fileSecurityProblem(f, path, rule)
		if p != nil {
			return p
		}
		return err
	})
	return data, false, err
}

// accessRule is what checkFileSecurity holds a file to: no account but its
// owner, this process's user or a group that owns what it creates, SYSTEM or
// Administrators (see trustedSID) may hold any of access to it, which verb
// names in the refusal; it is owned by this process's user or such a group,
// or, when rootOwned, by SYSTEM or Administrators, who may change any file
// anyway; and words say what to do about what it holds.
type accessRule struct {
	access    windows.ACCESS_MASK
	verb      string
	rootOwned bool
	words     fileWords
}

// secretRule is the rule for a file holding a secret: a key or a token.
func secretRule(words fileWords) accessRule {
	return accessRule{access: keyFileExposing, verb: "read or change", words: words}
}

// changeRule is the rule for a file others may read but not change.
func changeRule(words fileWords) accessRule {
	return accessRule{access: fileChanging, verb: "change", rootOwned: true, words: words}
}

// checkFileSecurity holds sd, the owner and DACL of the file at path, to
// rule.
func checkFileSecurity(path string, sd *windows.SECURITY_DESCRIPTOR, rule accessRule) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	self, err := ownerSIDs()
	if err != nil {
		return err
	}
	root := rule.rootOwned && (owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	if !anySID(self, owner) && !root {
		return &keyFileError{
			problem: fmt.Sprintf("it is owned by %s, not by this user", accountName(owner)),
			fix:     rule.words.owner,
		}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return &keyFileError{problem: "it has a null DACL, which lets everyone " + rule.verb + " it", fix: rule.words.exposed + restrictHint(path, owner, nil, true)}
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to what a directory holds, not to this file
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedCallbackACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
		default:
			return &keyFileError{
				problem: fmt.Sprintf("its DACL holds an entry of a kind tern does not check (type %d)", ace.Header.AceType),
				fix:     restrictHint(path, owner, nil, true),
			}
		}
		if ace.Mask&rule.access == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trustedSID(sid, owner, self) {
			continue
		}
		inherited := ace.Header.AceFlags&windows.INHERITED_ACE != 0
		return &keyFileError{
			problem: fmt.Sprintf("%s may %s it", accountName(sid), rule.verb),
			fix:     rule.words.exposed + restrictHint(path, owner, sid, inherited),
		}
	}
	return nil
}

// ownerSIDs lists who a file this process creates may be owned by: its user,
// and any group in its token that may own objects, as BUILTIN\Administrators
// may for an elevated administrator.
func ownerSIDs() ([]*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sids := []*windows.SID{user.User.Sid}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_OWNER != 0 && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			sids = append(sids, g.Sid)
		}
	}
	return sids, nil
}

// trustedSID reports whether an entry for sid gives access to no one but a
// file's owner, this process's user or a group that owns what it creates,
// SYSTEM or Administrators: CREATOR OWNER and OWNER RIGHTS stand for the
// owner, and SYSTEM and Administrators can read and change every file anyway.
func trustedSID(sid, owner *windows.SID, self []*windows.SID) bool {
	return sid.Equals(owner) || anySID(self, sid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerSid) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func anySID(sids []*windows.SID, sid *windows.SID) bool {
	for _, s := range sids {
		if s.Equals(sid) {
			return true
		}
	}
	return false
}

// accountName names sid as DOMAIN\name, or as the SID when it has no name.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil:
		return sid.String()
	case domain == "":
		return account
	}
	return domain + `\` + account
}

// hasName reports whether sid resolves to an account name, which is what
// icacls takes: it refuses a SID it cannot name, even written as *SID.
func hasName(sid *windows.SID) bool {
	_, _, _, err := sid.LookupAccount("")
	return err == nil
}

// restrictHint tells the operator how to make path its owner's only: drop
// the entries it inherits and grant the owner full access, or remove the
// explicit entry for other. icacls can do neither for an account with no
// name, such as one deleted since or of a domain out of reach, so then the
// hint is a PowerShell line that replaces the whole DACL with full access
// for the owner alone. Every line is for PowerShell, with paths and names
// in single quotes (see psQuote), so it does what it says when pasted there
// whatever the path holds: a double-quoted string would run a $(...) in a
// directory name.
func restrictHint(path string, owner, other *windows.SID, inherited bool) string {
	if !hasName(owner) || (other != nil && !hasName(other)) {
		return fmt.Sprintf(`restrict it to its owner, in PowerShell: $s = New-Object Security.AccessControl.FileSecurity; $s.SetSecurityDescriptorSddlForm('%s', 'Access'); Set-Acl -LiteralPath %s -AclObject $s`,
			ownerOnlySDDL, psQuote(path))
	}
	if inherited || other == nil {
		return fmt.Sprintf(`restrict it to its owner, in PowerShell: icacls %s /inheritance:r /grant:r %s`,
			psQuote(path), psQuote(accountName(owner)+":F"))
	}
	return fmt.Sprintf(`restrict it to its owner, in PowerShell: icacls %s /remove %s`, psQuote(path), psQuote(accountName(other)))
}

// psQuote quotes s as a PowerShell single-quoted string, in which nothing is
// expanded: each single quote in s is doubled, the typographic ones too
// (U+2018, U+2019, U+201A, U+201B), which PowerShell also takes as single
// quotes, so none of them ends the string early.
func psQuote(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'', '\u2018', '\u2019', '\u201a', '\u201b':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}
