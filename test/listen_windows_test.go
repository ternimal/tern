// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package e2e

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentPortNotShared: on Windows, a port another socket already holds,
// as when another local user bound 127.0.0.1 on it to take the connections
// meant for the agent, makes ternd fail to start instead of listening on
// 0.0.0.0 beside it while local clients reach the other socket.
func TestAgentPortNotShared(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port := held.Addr().(*net.TCPAddr).Port
	out, refused := runDaemon(t, "ternd", ternEnv("TERN_TOKEN="+genToken(t)),
		"--addr", fmt.Sprintf("0.0.0.0:%d", port), "--cert", filepath.Join(t.TempDir(), "agent"))
	if !refused || !strings.Contains(out, "listen") {
		t.Fatalf("ternd shared a port held on 127.0.0.1:\n%s", out)
	}
}
