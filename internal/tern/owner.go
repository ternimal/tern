// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import "os"

// CreateOwnerOnly creates path, which must not exist yet, for writing (flag
// may add os.O_APPEND). Only the current user can open it from the moment it
// exists: mode 0600 on Unix, and on Windows an owner-only DACL given at
// creation rather than set afterwards, by when another local user could
// already hold it open. Used for keys, recordings, audit logs and state.
func CreateOwnerOnly(path string, flag int) (*os.File, error) { return createOwnerOnly(path, flag) }

// RestrictToOwner limits an existing file, which may have been made open to
// others, to the current user: mode 0600 on Unix, a protected owner-only
// DACL on Windows.
func RestrictToOwner(path string) error { return restrictToOwner(path) }
