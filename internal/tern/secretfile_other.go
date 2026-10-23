// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package tern

import "os"

// fileACL would say whether f has an ACL with entries beyond its mode. Here
// tern has no call that reads one, so whether an ACL widens what the mode
// says cannot be told.
func fileACL(*os.File) aclState { return aclUnknown }

// pathACL is fileACL for the directory at path.
func pathACL(string) aclState { return aclUnknown }
