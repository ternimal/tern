// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeUser stands in for the person answering confirmation forms.
type fakeUser struct {
	mu      sync.Mutex
	action  string
	approve bool
	asked   []string
}

func (u *fakeUser) set(action string, approve bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.action, u.approve, u.asked = action, approve, nil
}

func (u *fakeUser) questions() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.asked...)
}

func (u *fakeUser) handle(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.asked = append(u.asked, req.Params.Message)
	return &mcp.ElicitResult{Action: u.action, Content: map[string]any{"approve": u.approve}}, nil
}

// TestMCPConfirmation drives human confirmation end to end: the server asks
// through MCP elicitation, the client's user approves or declines, and only an
// approval lets the action happen.
//
// It runs twice: with protocol 2026-07-28 the server answers input_required
// and the client retries, and with 2025-11-25, which most clients still speak,
// the SDK turns the same result into an elicitation/create request.
func TestMCPConfirmation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh on the agent")
	}
	a := startDirectAgent(t)
	for _, version := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(version, func(t *testing.T) { testConfirmation(t, a, version) })
	}
}

func testConfirmation(t *testing.T, a agent, version string) {
	area := t.TempDir()
	user := &fakeUser{}
	profiles := map[string]any{"guarded": map[string]any{
		"run":         map[string]any{"shell": true, "confirm_unlisted": true},
		"confirm":     []string{"run:shell", "write_file"},
		"read_paths":  []string{area + "/**"},
		"write_paths": []string{area + "/**"},
	}}
	sess, audit := startConfigMCP(t, a, map[string]string{"g": "guarded"}, profiles,
		&mcp.ClientOptions{ElicitationHandler: user.handle}, version)
	if got := sess.InitializeResult().ProtocolVersion; got != version {
		t.Fatalf("negotiated protocol %s, want %s", got, version)
	}
	runOut := func(res *mcp.CallToolResult) string {
		t.Helper()
		var o struct{ Output string }
		structured(t, res, &o)
		return o.Output
	}
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(area, name)); return err == nil }

	// Allowlisted commands run without asking.
	user.set("accept", true)
	if res := callTool(t, sess, "run", map[string]any{"argv": []string{"echo", "plain"}}); res.IsError || len(user.questions()) != 0 {
		t.Fatalf("an allowlisted command must not ask: %q asked=%v", resultText(res), user.questions())
	}

	// Shell mode asks; with approval it runs.
	res := callTool(t, sess, "run", map[string]any{"shell": true, "argv": []string{"echo approved-$((6*7))"}})
	if res.IsError || !strings.Contains(runOut(res), "approved-42") {
		t.Fatalf("approved shell command: %q", resultText(res))
	}
	if q := user.questions(); len(q) != 1 || !strings.Contains(q[0], "echo approved-$((6*7))") || !strings.Contains(q[0], `"g"`) {
		t.Fatalf("the user should have been shown the exact command and target once: %q", q)
	}

	// Declined, it does not run.
	user.set("decline", false)
	res = callTool(t, sess, "run", map[string]any{"shell": true, "argv": []string{"echo nope > " + area + "/declined"}})
	if !res.IsError || !strings.Contains(resultText(res), "declined") || exists("declined") {
		t.Fatalf("a declined command must not run: %q", resultText(res))
	}

	// Accepting the form without ticking the box is not an approval.
	user.set("accept", false)
	res = callTool(t, sess, "run", map[string]any{"shell": true, "argv": []string{"echo nope > " + area + "/unticked"}})
	if !res.IsError || !strings.Contains(resultText(res), "did not approve") || exists("unticked") {
		t.Fatalf("an unticked approval must not run: %q", resultText(res))
	}

	// An unlisted command asks instead of failing, because of confirm_unlisted.
	user.set("accept", true)
	if res := callTool(t, sess, "run", map[string]any{"argv": []string{"touch", area + "/touched"}}); res.IsError || !exists("touched") || len(user.questions()) != 1 {
		t.Fatalf("an approved unlisted command should run: %q", resultText(res))
	}

	// A wrapper is refused outright: the user is not even asked.
	user.set("accept", true)
	if res := callTool(t, sess, "run", map[string]any{"argv": []string{"bash", "-c", "id"}}); !res.IsError || len(user.questions()) != 0 {
		t.Fatalf("a wrapper must be refused without asking: %q asked=%v", resultText(res), user.questions())
	}

	// write_file is in the confirm list.
	user.set("accept", true)
	if res := callTool(t, sess, "write_file", map[string]any{"path": area + "/w.txt", "content": "ok"}); res.IsError || !exists("w.txt") {
		t.Fatalf("approved write: %q", resultText(res))
	}
	user.set("decline", false)
	if res := callTool(t, sess, "write_file", map[string]any{"path": area + "/w2.txt", "content": "no"}); !res.IsError || exists("w2.txt") {
		t.Fatalf("a declined write must not happen: %q", resultText(res))
	}

	sess.Close()
	log, _ := os.ReadFile(audit)
	if n := strings.Count(string(log), `"phase":"confirm_requested"`); n != 6 {
		t.Errorf("confirm_requested entries = %d, want 6", n)
	}
	if n := strings.Count(string(log), `"confirmed":true`); n < 3 {
		t.Errorf("approved actions should be marked confirmed in the audit log (%d)", n)
	}
}

// TestMCPConfirmationNeedsAskingClient checks that a client that cannot show
// a form gets a clear refusal, not a prompt nobody will see.
func TestMCPConfirmationNeedsAskingClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh on the agent")
	}
	a := startDirectAgent(t)
	profiles := map[string]any{"guarded": map[string]any{"run": map[string]any{"shell": true}, "confirm": []string{"run:shell"}}}
	sess, _ := startConfigMCP(t, a, map[string]string{"g": "guarded"}, profiles, nil, "")
	if res := callTool(t, sess, "run", map[string]any{"shell": true, "argv": []string{"id"}}); !res.IsError || !strings.Contains(resultText(res), "cannot ask the user") {
		t.Fatalf("got %q", resultText(res))
	}
	if res := callTool(t, sess, "run", map[string]any{"argv": []string{"echo", "still fine"}}); res.IsError {
		t.Fatalf("calls that need no confirmation still work: %q", resultText(res))
	}
}
