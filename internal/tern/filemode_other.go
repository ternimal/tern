// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package tern

// carriesACL reports whether the open directory dir may have an ACL. Here
// it always may: tern reads no ACLs on these systems (macOS, the BSDs), and
// an entry for another user need not show in the mode.
func carriesACL(dir int) bool { return true }
