// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !ios

package tern

import "github.com/aymanbagabas/go-pty"

// shellJob holds nothing outside Windows, where the shell runs in a session
// of its own on its terminal, as a login shell does.
type shellJob struct{}

func prepareShell(*pty.Cmd)                    {}
func containShell(*pty.Cmd) (*shellJob, error) { return nil, nil }
func (*shellJob) end()                         {}
