// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tern "github.com/ternimal/tern/internal/tern"
)

// TestAuditEveryCall checks that every tools/call leaves an audit trail,
// including calls that never reach a handler (unknown tool, schema failure),
// and that a handled call is not logged twice. The agent is unreachable on
// purpose: auditing must not depend on it.
func TestAuditEveryCall(t *testing.T) {
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	pol, _ := NewPolicy("readonly")
	srv, err := New(Config{
		Version:   "test",
		AuditPath: audit,
		Targets: []TargetSpec{{
			Target: Target{Name: "t1"},
			Policy: pol,
			Dial: func(context.Context) (*tern.Client, error) {
				return nil, errors.New("no agent in this test")
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "unit", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	call := func(name string, args any) {
		cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args}) // outcomes are checked in the log
	}
	call("no_such_tool", map[string]any{"x": 1})                                                     // rejected: unknown tool
	call("run", map[string]any{"argv": "uptime"})                                                    // rejected: schema
	call("run", map[string]any{"argv": []string{"bash", "-c", "id"}})                                // denied by policy
	call("run", map[string]any{"argv": []string{"uptime"}})                                          // allowed, agent unreachable
	call("read_file", map[string]any{"path": "/etc/shadow"})                                         // denied by policy
	call("run", map[string]any{"argv": []string{"echo"}, "token": "ghp_" + strings.Repeat("x", 36)}) // rejected, secret in raw args

	var got []string
	f, err := os.Open(audit)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.Client != "unit/1" || e.Target != "t1" {
			t.Errorf("entry %d lacks client or target: %+v", e.Seq, e)
		}
		if strings.Contains(sc.Text(), "ghp_xxxx") {
			t.Errorf("a secret reached the audit log: %s", sc.Text())
		}
		got = append(got, e.Tool+":"+e.Phase)
	}
	want := []string{
		"no_such_tool:rejected",
		"run:rejected",
		"run:denied",
		"run:start", "run:error",
		"read_file:denied",
		"run:rejected",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("audit trail\n got  %v\n want %v", got, want)
	}
}

// A job_start the policy allows whose connection then fails, because the
// agent cannot be reached, refuses the credentials or is not the agent
// pinned, still leaves its start and its error in the log, under the job's
// id.
func TestJobStartDialFailureLogged(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log.jsonl")
	pols, err := BuildPolicies(map[string]ProfileConfig{"p": {Run: RunConfig{Allow: [][]string{{"true"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Version: "test", AuditPath: log, Targets: []TargetSpec{{
		Target: Target{Name: "t1"},
		Policy: pols["p"],
		Dial: func(context.Context) (*tern.Client, error) {
			return nil, errors.New("tls: agent fingerprint mismatch")
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "unit", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "job_start", Arguments: map[string]any{"argv": []string{"true"}}}); err != nil || !res.IsError {
		t.Fatalf("job_start with no agent to reach: %+v %v", res, err)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e AuditEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.JobID == "" || e.Phase == "error" && !strings.Contains(e.Error, "fingerprint mismatch") {
			t.Errorf("log line %s", l)
		}
		got = append(got, e.Tool+":"+e.Phase)
	}
	if strings.Join(got, " ") != "job_start:start job_start:error" {
		t.Errorf("log %v", got)
	}
}
