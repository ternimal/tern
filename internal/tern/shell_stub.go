// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build ios

package tern

import "errors"

// iOS sandboxes forbid fork/exec, so an agent cannot host a shell or run
// commands there. This stub only makes the package compile for GOOS=ios; there
// is no runnable iOS binary and no public library API yet.
func spawnShell(string) (shellSession, error) {
	return nil, errors.New("hosting a shell is not supported on iOS")
}
