// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

type jobPoll struct {
	Data       string `json:"data"`
	NextOffset int64  `json:"next_offset"`
	Done       bool   `json:"done"`
	ExitCode   *int   `json:"exit_code"`
	TimedOut   bool   `json:"timed_out"`
	Cancelled  bool   `json:"cancelled"`
}

func pgrepCount(pattern string) int {
	out, _ := exec.Command("pgrep", "-f", pattern).Output()
	return len(strings.Fields(string(out)))
}

// TestMCPJobs covers background jobs: output read incrementally by offset,
// the exit code, cancellation killing the remote process, timeouts, and the
// policy applying to job_start as it does to run.
func TestMCPJobs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh and pgrep on the agent")
	}
	a := startDirectAgent(t)
	sess, _ := startConfigMCP(t, a, map[string]string{"ops": "ops"},
		map[string]any{"ops": map[string]any{"run": map[string]any{"shell": true}}}, nil, "")

	start := func(args map[string]any) string {
		t.Helper()
		res := callTool(t, sess, "job_start", args)
		if res.IsError {
			t.Fatalf("job_start %v: %s", args, resultText(res))
		}
		var o struct {
			JobID string `json:"job_id"`
		}
		structured(t, res, &o)
		return o.JobID
	}
	poll := func(id string, since int64) jobPoll {
		t.Helper()
		var p jobPoll
		structured(t, callTool(t, sess, "job_poll", map[string]any{"job_id": id, "since": since, "wait_ms": 2000}), &p)
		return p
	}
	waitDone := func(id string) (jobPoll, string, int) {
		t.Helper()
		var all strings.Builder
		var since int64
		for polls := 1; polls < 100; polls++ {
			p := poll(id, since)
			all.WriteString(p.Data)
			since = p.NextOffset
			if p.Done {
				return p, all.String(), polls
			}
		}
		t.Fatal("job did not finish")
		return jobPoll{}, "", 0
	}

	// Output arrives as the job runs, and the exit code is reported.
	id := start(map[string]any{"shell": true, "argv": []string{"for i in 1 2 3; do echo line$i; sleep 0.3; done; exit 7"}})
	last, out, polls := waitDone(id)
	if out != "line1\nline2\nline3\n" || last.ExitCode == nil || *last.ExitCode != 7 {
		t.Fatalf("job output %q exit %v", out, last.ExitCode)
	}
	if polls < 2 {
		t.Errorf("output should arrive over several polls, came in %d", polls)
	}

	// job_cancel kills the remote process, not just the call.
	marker := "sleep 31.7"
	id = start(map[string]any{"shell": true, "argv": []string{marker}})
	for i := 0; i < 50 && pgrepCount(marker) == 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if pgrepCount(marker) == 0 {
		t.Fatal("the job's process never started")
	}
	var c struct {
		Cancelled bool `json:"cancelled"`
	}
	structured(t, callTool(t, sess, "job_cancel", map[string]any{"job_id": id}), &c)
	if p := poll(id, 0); !c.Cancelled || !p.Done || !p.Cancelled || p.ExitCode != nil {
		t.Fatalf("after cancel: %+v %+v", c, p)
	}
	for i := 0; i < 50 && pgrepCount(marker) > 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if n := pgrepCount(marker); n > 0 {
		t.Fatalf("%d processes survived job_cancel", n)
	}

	// A job is killed at its timeout.
	id = start(map[string]any{"shell": true, "argv": []string{"sleep 20"}, "timeout_s": 1})
	if p, _, _ := waitDone(id); !p.TimedOut || p.ExitCode != nil {
		t.Fatalf("timed-out job = %+v", p)
	}

	// A line written in two halves is not split across polls, where
	// redaction would see neither half as a secret.
	id = start(map[string]any{"shell": true, "argv": []string{"printf 'DB_PASSWORD=hun'; sleep 0.05; printf 'ter2\\n'"}})
	if _, out, _ := waitDone(id); strings.Contains(out, "hun") || strings.Contains(out, "ter2") || !strings.Contains(out, "DB_PASSWORD") {
		t.Fatalf("a secret written in two halves leaked: %q", out)
	}

	if res := callTool(t, sess, "job_poll", map[string]any{"job_id": "job_nope"}); !res.IsError || !strings.Contains(resultText(res), "unknown or expired") {
		t.Errorf("unknown job: %q", resultText(res))
	}
	if res := callTool(t, sess, "job_start", map[string]any{"argv": []string{"bash", "-c", "id"}}); !res.IsError || !strings.Contains(resultText(res), "arbitrary commands") {
		t.Errorf("job_start must apply the run policy: %q", resultText(res))
	}
	var list struct {
		Jobs []struct {
			Running bool `json:"running"`
		} `json:"jobs"`
	}
	structured(t, callTool(t, sess, "job_list", map[string]any{}), &list)
	if len(list.Jobs) != 4 || list.Jobs[0].Running {
		t.Fatalf("job_list = %+v", list)
	}
}
