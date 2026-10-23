// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"slices"
	"testing"
)

// /proc/self/mountinfo names each mount point in its fifth field, with the
// kernel's octal escapes for spaces, tabs, line breaks and backslashes.
func TestParseMountInfo(t *testing.T) {
	in := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"95 22 0:47 / /home/u/mnt/my\\040nas rw,nosuid shared:50 - fuse.sshfs u@h:/ rw\n" +
		"96 22 0:48 / /srv/a\\134b\\011c rw - nfs4 h:/x rw\nshort line\n"
	if got := parseMountInfo([]byte(in)); !slices.Equal(got, []string{"/", "/home/u/mnt/my nas", "/srv/a\\b\tc"}) {
		t.Errorf("mount points %q", got)
	}
	if got := systemMounts(); !slices.Contains(got, "/") {
		t.Errorf("this system's mount points %q hold no /", got)
	}
}
