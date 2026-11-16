// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ternimal/tern/internal/mcpserver"
	tern "github.com/ternimal/tern/internal/tern"
)

// TestWatchMCPConfig runs the config reload end to end, through list_targets
// in one session: a target added to the file shows up, an edit that keeps the
// file's size and modification time is still seen, a file that does not
// parse leaves the running targets in place, and a removed target goes.
func TestWatchMCPConfig(t *testing.T) {
	poll, verify, settle := configPoll, configVerify, configSettle
	configPoll, configVerify, configSettle = 10*time.Millisecond, 50*time.Millisecond, time.Millisecond
	t.Cleanup(func() { configPoll, configVerify, configSettle = poll, verify, settle })

	dir := filepath.Join(t.TempDir(), ".config", "tern")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "web.token"), []byte("token-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "mcp.json")
	fp := strings.Repeat("ab", 32)
	entry := func(name, addr string) string {
		return `"` + name + `": {"addr": "` + addr + `", "fingerprint": "` + fp + `", "token_file": "web.token"}`
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"targets": {` + entry("web1", "10.0.0.5:2001") + `}}`)

	data, err := tern.ReadConfigFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseMCPConfig(cfg, data)
	if err != nil {
		t.Fatal(err)
	}
	specs, _, _, err := buildMCPTargets(c)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := mcpserver.New(mcpserver.Config{Version: "test", AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"), Targets: specs})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchMCPConfig(ctx, srv, cfg, sha256.Sum256(data), false)

	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "unit", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	targets := func() map[string]string { // name to endpoint, as list_targets shows them
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_targets", Arguments: map[string]any{}})
		if err != nil || res.IsError {
			t.Fatalf("list_targets: %v %+v", err, res)
		}
		var out mcpserver.TargetsOutput
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, e := range out.Targets {
			m[e.Name] = e.Endpoint
		}
		return m
	}
	waitFor := func(what string, ok func(map[string]string) bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(configPoll) {
			got := targets()
			if ok(got) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: targets are %v", what, got)
			}
		}
	}

	write(`{"targets": {` + entry("web1", "10.0.0.5:2001") + `, ` + entry("db1", "10.0.0.6:2001") + `}}`)
	waitFor("a target added to the file", func(m map[string]string) bool { return m["db1"] == "10.0.0.6:2001" })

	// The same size, and the modification time put back: only the content
	// tells the change.
	before, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write(`{"targets": {` + entry("web1", "10.0.0.5:2002") + `, ` + entry("db1", "10.0.0.6:2001") + `}}`)
	if err := os.Chtimes(cfg, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(cfg); after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("test setup: the edit changed the file's size or modification time")
	}
	waitFor("an edit with the same size and time", func(m map[string]string) bool { return m["web1"] == "10.0.0.5:2002" })

	write(`{"targets": {`)
	time.Sleep(20 * configPoll)
	if m := targets(); len(m) != 2 || m["web1"] != "10.0.0.5:2002" || m["db1"] != "10.0.0.6:2001" {
		t.Fatalf("a file that does not parse changed the targets to %v", m)
	}

	write(`{"targets": {` + entry("db1", "10.0.0.6:2001") + `}}`)
	waitFor("a target removed from the file", func(m map[string]string) bool {
		_, web := m["web1"]
		return !web && m["db1"] == "10.0.0.6:2001"
	})
}
