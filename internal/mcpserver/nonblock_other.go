// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package mcpserver

// openNonblock is a no-op here: opening a file in a directory does not wait
// for anything.
const openNonblock = 0
