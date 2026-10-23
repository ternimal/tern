// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix && !windows

package mcpserver

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("file locks are not supported on this platform")
}
