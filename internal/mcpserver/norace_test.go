// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !race

package mcpserver

// raceEnabled reports a build with the race detector, whose instrumentation
// changes what the memory a test allocates measures.
const raceEnabled = false
