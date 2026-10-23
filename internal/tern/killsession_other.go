// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package tern

// killSession would kill the command's processes that left its process
// group. Here (macOS and the BSDs) there is no /proc to find them by, so a
// command is killed with its process group only.
func killSession(int) {}
