// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin && !freebsd

package mcpserver

// systemMounts lists none here. On Windows a volume mounted in a folder is a
// junction, which the look never reads into; elsewhere the look's time bound
// is what keeps a dead mount from holding startup.
func systemMounts() []string { return nil }
