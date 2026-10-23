// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package tern

import "math"

// fdLimit reports no limit: Windows has no per-process cap on handles that a
// listener would reach first.
func fdLimit() uint64 { return math.MaxUint64 }
