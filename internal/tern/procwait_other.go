// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package tern

// waitExitNoReap would wait for pid to exit without reaping it. Here (macOS
// and the BSDs) golang.org/x/sys offers no waitid with WNOWAIT, so it reports
// false and the caller reaps at once.
func waitExitNoReap(int) bool { return false }

// noReapWaits reports that waitExitNoReap does not work here.
func noReapWaits() bool { return false }
