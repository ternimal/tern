// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package tern

// shellCtrlC is needed on Windows only, where processes inherit whether they
// ignore Ctrl+C.
func shellCtrlC() (restore func()) { return func() {} }
