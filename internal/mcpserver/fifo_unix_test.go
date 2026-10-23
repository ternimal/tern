// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// upload refuses a FIFO in the workspace at once, without opening it, which
// would wait for a writer; a link to one too. Nothing reaches the agent.
func TestUploadFIFORefusedAtOnce(t *testing.T) {
	a := newStackAgent(t)
	ws, remote := t.TempDir(), t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(ws, "pipe"), 0o600); err != nil {
		t.Skip(err)
	}
	os.Symlink("pipe", filepath.Join(ws, "lnk"))
	srv, _ := stackServer(t, a, ProfileConfig{WritePaths: []string{remote + "/**"}}, func(c *Config) { c.Workspace = ws })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	for _, local := range []string{"pipe", "lnk"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "upload", Arguments: map[string]any{"local": local, "remote": remote + "/x"}})
		cancel()
		if err != nil || !res.IsError || !strings.Contains(resultText(res), "not a regular file") {
			t.Errorf("upload of a FIFO as %s: %v %v", local, res, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("upload of a FIFO as %s took %v", local, d)
		}
	}
	if _, err := os.Stat(filepath.Join(remote, "x")); err == nil {
		t.Error("a FIFO upload reached the agent")
	}
}
