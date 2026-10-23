// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
)

// maxMountInfo bounds how much of /proc/self/mountinfo is read.
const maxMountInfo = 16 << 20

// systemMounts lists the mount points this process sees, from
// /proc/self/mountinfo, which the kernel writes without asking any of them,
// so a dead network mount is listed like any other.
func systemMounts() []string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxMountInfo))
	return parseMountInfo(b)
}

// parseMountInfo returns the mount point of each line of mountinfo, its fifth
// field, with the octal escapes the kernel writes for spaces, tabs, line
// breaks and backslashes undone.
func parseMountInfo(b []byte) []string {
	var out []string
	for line := range bytes.Lines(b) {
		f := strings.Fields(string(line))
		if len(f) < 5 {
			continue
		}
		out = append(out, unescapeMount(f[4]))
	}
	return out
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
