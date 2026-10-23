// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !ios

package tern

import (
	"os"

	"github.com/aymanbagabas/go-pty"
)

// pollableMaster returns nil: here the terminal is read and written as
// go-pty opened it (see ptyio_linux.go).
func pollableMaster(pty.Pty) (*os.File, error) { return nil, nil }
