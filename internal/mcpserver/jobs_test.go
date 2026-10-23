// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWholeLines(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"a\nb\n", "a\nb\n"},
		{"a\nDB_PASSWORD=hun", "a\n"},
		{"no line break yet", "no line break yet"},
		{"สวัสดี"[:7], "สว"},     // stops before a cut Thai character
		{"\xe0", "\xe0"},         // a lone fragment still makes progress
		{"\x80\x80", "\x80\x80"}, // stray continuation bytes are passed on
		{"", ""},
	} {
		got, next := wholeLines([]byte(c.in), 100)
		if string(got) != c.want || next != 100-int64(len(c.in)-len(c.want)) {
			t.Errorf("wholeLines(%q) = %q, %d; want %q", c.in, got, next, c.want)
		}
	}
}

// A poll that a sequence still arriving holds back waits out its wait_ms
// for more output, rather than answering with nothing at once and having the
// caller ask again and again; once the sequence ends the text after it
// comes.
func TestJobPollWaitsWhileASequenceArrives(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the job is a sh script")
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, nil)
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)
	var job JobStartOutput
	call(t, cs, "job_start", map[string]any{"argv": []string{`printf 'start\n\033]0;'; head -c 40000 /dev/zero | tr '\0' x; sleep 2; printf '\007done\n'`}, "shell": true}, &job, false)
	var poll JobPollOutput
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(poll.Data, "start") && time.Now().Before(deadline); {
		call(t, cs, "job_poll", map[string]any{"job_id": job.JobID, "wait_ms": 200}, &poll, false)
	}
	since := poll.NextOffset
	start := time.Now()
	call(t, cs, "job_poll", map[string]any{"job_id": job.JobID, "since": since, "wait_ms": 600}, &poll, false)
	if took := time.Since(start); poll.NextOffset == since && took < 400*time.Millisecond {
		t.Errorf("a poll held back by a sequence still arriving answered after %v instead of waiting", took)
	}
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(poll.Data, "done") && time.Now().Before(deadline); {
		call(t, cs, "job_poll", map[string]any{"job_id": job.JobID, "since": since, "wait_ms": 1000}, &poll, false)
		if poll.NextOffset > since && !strings.Contains(poll.Data, "done") {
			since = poll.NextOffset
		}
	}
	if !strings.Contains(poll.Data, "done") {
		t.Errorf("the text after the sequence never came: %q", poll.Data)
	}
}
