// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMCPIdempotency re-sends calls with the same idempotency key, as a client
// does after a broken stream, and checks nothing runs twice.
func TestMCPIdempotency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh on the agent")
	}
	a := startDirectAgent(t)
	area := t.TempDir()
	profiles := map[string]any{"ops": map[string]any{
		"run":         map[string]any{"shell": true},
		"read_paths":  []string{area + "/**"},
		"write_paths": []string{area + "/**"},
	}}
	sess, audit := startConfigMCP(t, a, map[string]string{"o": "ops"}, profiles, nil, "")
	clock := func(key string) string {
		t.Helper()
		args := map[string]any{"shell": true, "argv": []string{"date +%s%N"}}
		if key != "" {
			args["idempotency_key"] = key
		}
		res := callTool(t, sess, "run", args)
		if res.IsError {
			t.Fatalf("run: %s", resultText(res))
		}
		var o struct{ Output string }
		structured(t, res, &o)
		return o.Output
	}
	first := clock("k-date")
	time.Sleep(20 * time.Millisecond)
	if again := clock("k-date"); again != first {
		t.Fatalf("a re-sent call ran again: %q then %q", first, again)
	}
	if fresh := clock(""); fresh == first {
		t.Fatal("without a key the command should run anew")
	}
	if res := callTool(t, sess, "run", map[string]any{"argv": []string{"uptime"}, "idempotency_key": "k-date"}); !res.IsError || !strings.Contains(resultText(res), "different call") {
		t.Fatalf("reusing a key for another call must be refused: %q", resultText(res))
	}

	// A replayed write does not write again: change the file in between and
	// the change survives the replay.
	f := filepath.Join(area, "f.txt")
	w := map[string]any{"path": f, "content": "first", "idempotency_key": "k-write"}
	if res := callTool(t, sess, "write_file", w); res.IsError {
		t.Fatalf("write: %s", resultText(res))
	}
	os.WriteFile(f, []byte("changed outside"), 0o644)
	if res := callTool(t, sess, "write_file", w); res.IsError {
		t.Fatalf("replayed write: %s", resultText(res))
	}
	if got, _ := os.ReadFile(f); string(got) != "changed outside" {
		t.Fatalf("the replay wrote again: %q", got)
	}
	sess.Close()
	if log, _ := os.ReadFile(audit); strings.Count(string(log), `"phase":"replayed"`) != 2 {
		t.Errorf("each replay should be audited:\n%s", log)
	}
}
