// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package tern

// dirsOpenToAll is always true on Windows, where access comes from ACLs that
// mode bits do not describe, so a client judges no Windows file by them.
func dirsOpenToAll(string) bool { return true }
