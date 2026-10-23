// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package mcpserver

import "syscall"

// openNonblock opens a workspace file without waiting: a FIFO would otherwise
// hold the open until a writer comes. A regular file reads as ever.
const openNonblock = syscall.O_NONBLOCK
