// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package mcpserver

import "testing"

// longTempDir is t.TempDir(): only Windows has short names.
func longTempDir(t *testing.T) string { return t.TempDir() }
