// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package tern

// startChild runs start, which starts one child process. Only on Linux does
// the agent run as a container's process 1 and reap orphans (see
// reap_linux.go); here there is nothing to keep track of.
func startChild(start func() (int, error)) (done func(), err error) {
	if _, err := start(); err != nil {
		return nil, err
	}
	return func() {}, nil
}

// reapsOrphans reports that this process does not reap orphans.
func reapsOrphans() bool { return false }
