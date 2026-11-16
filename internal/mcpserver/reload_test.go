// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	tern "github.com/ternimal/tern/internal/tern"
)

// noDial is a dialer stand-in: resolve and the target set never dial, so a
// reload can be tested without an agent.
func noDial(context.Context) (*tern.Client, error) { return nil, errors.New("no agent in this test") }

func spec(name, endpoint string, pol *Policy) TargetSpec {
	return TargetSpec{
		Target: Target{Name: name, Mode: "direct", Endpoint: endpoint, Transport: "tls-pinned", Fingerprint: "fp-" + name},
		Policy: pol,
		Dial:   noDial,
	}
}

func newReloadServer(t *testing.T, specs ...TargetSpec) *Server {
	t.Helper()
	srv, err := New(Config{
		Version:   "test",
		AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		Targets:   specs,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func mustResolve(t *testing.T, s *Server, name string) *targetState {
	t.Helper()
	st, err := s.resolve(name)
	if err != nil {
		t.Fatalf("resolve(%q): %v", name, err)
	}
	return st
}

// connectReload connects an in-memory client to srv.
func connectReload(t *testing.T, srv *Server) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "unit", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// callReload calls a tool and returns its text and whether it was refused.
func callReload(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return err.Error(), true
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func ptyPolicy(t *testing.T) *Policy {
	t.Helper()
	pols, err := BuildPolicies(map[string]ProfileConfig{"term": {Run: RunConfig{Shell: true}, PTY: true}}, SecretPathsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return pols["term"]
}

// fakePTY registers a terminal opened on the target named name, as openPTY
// would, but with no agent behind it: its goroutine has already finished.
func fakePTY(t *testing.T, srv *Server, name string) *ptyState {
	t.Helper()
	p := srv.newPTY(newHandle("pty_"), srv.tgts().byName[name], newPTYSession(), newHandle(""), 80, 24, time.Now(), time.Hour)
	close(p.done)
	srv.ptysMu.Lock()
	srv.ptys[p.id] = p
	srv.ptysMu.Unlock()
	return p
}

// TestSetTargetsAddUpdateRemove checks that a reload adds, changes and removes
// targets live: a new host resolves, a dropped host stops resolving, and the
// default follows the reloaded config.
func TestSetTargetsAddUpdateRemove(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	srv := newReloadServer(t, spec("web1", "10.0.0.1:2222", ro))

	if _, err := srv.resolve("db1"); err == nil {
		t.Fatal("db1 resolved before it was added")
	}

	// Add db1 alongside web1 and make it the default.
	if err := srv.SetTargets([]TargetSpec{
		spec("web1", "10.0.0.1:2222", ro),
		spec("db1", "10.0.0.9:2222", ro),
	}, "db1"); err != nil {
		t.Fatalf("SetTargets add: %v", err)
	}
	mustResolve(t, srv, "db1")
	mustResolve(t, srv, "web1")
	if st := mustResolve(t, srv, ""); st.Name != "db1" {
		t.Fatalf("default is %q, want db1", st.Name)
	}
	if names := srv.tgts().names; len(names) != 2 {
		t.Fatalf("names = %v, want 2", names)
	}

	// Drop web1; only db1 remains and it is the sole (implicit) default.
	if err := srv.SetTargets([]TargetSpec{spec("db1", "10.0.0.9:2222", ro)}, ""); err != nil {
		t.Fatalf("SetTargets remove: %v", err)
	}
	if _, err := srv.resolve("web1"); err == nil {
		t.Fatal("web1 resolved after it was removed")
	}
	if st := mustResolve(t, srv, ""); st.Name != "db1" {
		t.Fatalf("lone default is %q, want db1", st.Name)
	}
}

// TestSetTargetsRejectsBadSetAtomically checks that an invalid reload changes
// nothing: the live target set is kept when the new one does not validate.
func TestSetTargetsRejectsBadSetAtomically(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	srv := newReloadServer(t, spec("web1", "10.0.0.1:2222", ro))

	cases := []struct {
		name  string
		specs []TargetSpec
		def   string
	}{
		{"duplicate name", []TargetSpec{spec("web1", "a:1", ro), spec("web1", "b:2", ro)}, ""},
		{"nil policy", []TargetSpec{{Target: Target{Name: "x"}, Dial: noDial}}, ""},
		{"nil dialer", []TargetSpec{{Target: Target{Name: "x"}, Policy: ro}}, ""},
		{"unknown default", []TargetSpec{spec("web1", "a:1", ro)}, "nope"},
		{"no name", []TargetSpec{spec("", "a:1", ro)}, ""},
	}
	for _, c := range cases {
		if err := srv.SetTargets(c.specs, c.def); err == nil {
			t.Fatalf("%s: SetTargets accepted an invalid set", c.name)
		}
		mustResolve(t, srv, "web1")
		if names := srv.tgts().names; len(names) != 1 || names[0] != "web1" {
			t.Fatalf("%s: live set changed to %v", c.name, names)
		}
	}
}

// TestSetTargetsCarriesProbedOS checks that a reload keeps a target's probed OS
// when its connection is unchanged, and discards it when the endpoint changes.
func TestSetTargetsCarriesProbedOS(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	srv := newReloadServer(t, spec("web1", "10.0.0.1:2222", ro))

	st := mustResolve(t, srv, "web1")
	st.mu.Lock()
	st.osName, st.osDetail = "linux", "Debian"
	st.mu.Unlock()

	if err := srv.SetTargets([]TargetSpec{spec("web1", "10.0.0.1:2222", ptyPolicy(t))}, ""); err != nil {
		t.Fatalf("SetTargets same conn: %v", err)
	}
	if got := mustResolve(t, srv, "web1"); got.osName != "linux" || got.osDetail != "Debian" {
		t.Fatalf("probed OS not carried over: %q/%q", got.osName, got.osDetail)
	}

	if err := srv.SetTargets([]TargetSpec{spec("web1", "10.0.0.2:2222", ro)}, ""); err != nil {
		t.Fatalf("SetTargets new endpoint: %v", err)
	}
	if got := mustResolve(t, srv, "web1"); got.osName != "" {
		t.Fatalf("probed OS kept across an endpoint change: %q", got.osName)
	}
}

// TestSetTargetsConcurrent swaps the target set while callers resolve, to catch
// a data race between a reload and in-flight calls under go test -race.
func TestSetTargetsConcurrent(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	srv := newReloadServer(t, spec("web1", "10.0.0.1:2222", ro))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2000 {
			srv.resolve("web1")
			srv.resolve("")
			_ = srv.tgts().names
		}
	}()
	for range 2000 {
		srv.SetTargets([]TargetSpec{
			spec("web1", "10.0.0.1:2222", ro),
			spec("db1", "10.0.0.9:2222", ro),
		}, "")
	}
	<-done
}

// TestMayRegisterCoversUnusedProfile checks that a tool is registered for a
// profile the config defines even when no current target uses it, so a target
// added at reload under that profile finds its tools in place.
func TestMayRegisterCoversUnusedProfile(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	write, err := BuildPolicies(map[string]ProfileConfig{
		"rw": {Run: RunConfig{Allow: [][]string{{"true"}}}, WritePaths: []string{"/tmp/**"}},
	}, SecretPathsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Version:          "test",
		AuditPath:        filepath.Join(t.TempDir(), "audit.jsonl"),
		Targets:          []TargetSpec{spec("web1", "10.0.0.1:2222", ro)},
		RegisterPolicies: []*Policy{write["rw"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if !srv.mayRegister((*Policy).CanWrite) {
		t.Fatal("write tools would not register for a defined-but-unused write profile")
	}
	if srv.anyTarget((*Policy).CanWrite) {
		t.Fatal("anyTarget unexpectedly reports a write-capable target")
	}
}

// TestLiveTarget checks the rule every open job and terminal follows across a
// reload: the current policy while the name still reaches the same agent, and
// a refusal reason, with the original target, once it does not.
func TestLiveTarget(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	term := ptyPolicy(t)
	srv := newReloadServer(t, spec("web1", "10.0.0.1:2222", term))
	opened := mustResolve(t, srv, "web1")

	// Same agent, profile tightened: the new policy governs at once.
	srv.SetTargets([]TargetSpec{spec("web1", "10.0.0.1:2222", ro)}, "")
	if got, why := srv.liveTarget(opened); why != "" || got.Policy != ro {
		t.Fatalf("same agent: got policy %v, why %q; want the reloaded policy", got.Policy.Profile, why)
	}

	// Removed: the original target, and a reason.
	srv.SetTargets([]TargetSpec{spec("db1", "10.0.0.9:2222", ro)}, "")
	if got, why := srv.liveTarget(opened); got != opened || !strings.Contains(why, "no longer in the config") {
		t.Fatalf("removed: got %p (opened %p), why %q", got, opened, why)
	}

	// The name now leads to another agent: refused all the same.
	srv.SetTargets([]TargetSpec{spec("web1", "10.0.0.2:2222", term)}, "")
	if got, why := srv.liveTarget(opened); got != opened || !strings.Contains(why, "another agent") {
		t.Fatalf("re-pointed: got %p (opened %p), why %q", got, opened, why)
	}

	// Added back as it was: usable again.
	srv.SetTargets([]TargetSpec{spec("web1", "10.0.0.1:2222", term)}, "")
	if got, why := srv.liveTarget(opened); why != "" || got == opened {
		t.Fatalf("added back: why %q, got the opened target %v", why, got == opened)
	}
}

// TestReloadRemovedTargetJobPoll checks that a job whose target a reload
// removed can still be read: before reload existed a job's target could never
// disappear, and as no handler recovers a panic, the nil target job_poll
// then looked up took the whole server down.
func TestReloadRemovedTargetJobPoll(t *testing.T) {
	pols, err := BuildPolicies(map[string]ProfileConfig{"ops": {Run: RunConfig{Allow: [][]string{{"true"}}}}}, SecretPathsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	srv := newReloadServer(t, spec("web1", "10.0.0.1:2222", pols["ops"]))

	const id = "job_reloadtest"
	j := &job{id: id, target: "web1", tgt: srv.tgts().byName["web1"], started: time.Now(), out: newRingBuffer(1 << 10), cancel: func() {}, done: true, ended: time.Now()}
	j.out.Write([]byte("finished\n"))
	j.out.Close()
	srv.jobsMu.Lock()
	srv.jobs[id] = j
	srv.jobsMu.Unlock()

	if err := srv.SetTargets([]TargetSpec{spec("db1", "10.0.0.9:2222", pols["ops"])}, ""); err != nil {
		t.Fatal(err)
	}
	cs := connectReload(t, srv)
	if out, refused := callReload(t, cs, "job_poll", map[string]any{"job_id": id}); refused || !strings.Contains(out, "finished") {
		t.Fatalf("job_poll after its target was removed: refused %v, %q", refused, out)
	}
}

// TestStaleTerminalRefusesInput checks that after a reload removes a terminal's
// target, or points its name at another agent, nothing more is typed into
// the terminal, which can still be closed, and that closing it ends the
// session on the agent it was opened on, never on the one the name now leads
// to, which must not learn the session's name and attach ID.
func TestStaleTerminalRefusesInput(t *testing.T) {
	term := ptyPolicy(t)
	var mu sync.Mutex
	var dialed []string
	dialer := func(which string) func(context.Context) (*tern.Client, error) {
		return func(context.Context) (*tern.Client, error) {
			mu.Lock()
			dialed = append(dialed, which)
			mu.Unlock()
			return nil, errors.New("no agent in this test")
		}
	}
	first := spec("web1", "10.0.0.1:2222", term)
	first.Dial = dialer("first agent")
	srv := newReloadServer(t, first)
	cs := connectReload(t, srv)
	p := fakePTY(t, srv, "web1")

	srv.SetTargets([]TargetSpec{spec("db1", "10.0.0.9:2222", term)}, "")
	if out, refused := callReload(t, cs, "pty_send", map[string]any{"pty_id": p.id, "text": "id\n"}); !refused || !strings.Contains(out, "no longer in the config") {
		t.Fatalf("pty_send to a removed target: refused %v, %q", refused, out)
	}

	other := spec("web1", "10.0.0.2:2222", term)
	other.Dial = dialer("other agent")
	srv.SetTargets([]TargetSpec{other}, "")
	if out, refused := callReload(t, cs, "pty_run", map[string]any{"pty_id": p.id, "command": "id"}); !refused || !strings.Contains(out, "another agent") {
		t.Fatalf("pty_run on a re-pointed target: refused %v, %q", refused, out)
	}

	if out, refused := callReload(t, cs, "pty_close", map[string]any{"pty_id": p.id}); refused {
		t.Fatalf("pty_close on a re-pointed target was refused: %q", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 || dialed[0] != "first agent" || strings.Contains(strings.Join(dialed, ","), "other agent") {
		t.Fatalf("pty_close dialed %v; want only the agent the terminal was opened on", dialed)
	}
}

// TestMovePTYState checks that, with terminals persisting, a reload moves them
// to the state file named for the new targets: the new file has them, with
// the endpoint of the agent they run on, its lock is held, and the old file
// and its lock are let go.
func TestMovePTYState(t *testing.T) {
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	term := ptyPolicy(t)
	srv, err := New(Config{
		Version:   "test",
		AuditPath: filepath.Join(dir, "audit.jsonl"),
		Targets:   []TargetSpec{spec("web1", "10.0.0.1:2222", term)},
		PTYState:  oldPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if !srv.persisting() {
		t.Skip("terminal state files need file locks, which this platform lacks")
	}
	p := fakePTY(t, srv, "web1")
	srv.savePTYs()

	srv.SetTargets([]TargetSpec{spec("web1", "10.0.0.1:2222", term), spec("db1", "10.0.0.9:2222", term)}, "")
	srv.MovePTYState(newPath)

	b, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("new state file: %v", err)
	}
	var recs []ptyRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].PTYID != p.id || recs[0].Endpoint != "10.0.0.1:2222" {
		t.Fatalf("new state file holds %+v", recs)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old state file still there: %v", err)
	}
	if st, _, err := openPTYStore(newPath); err == nil {
		st.lock.Close()
		t.Fatal("the new state file's lock is not held")
	}
	st, _, err := openPTYStore(oldPath)
	if err != nil {
		t.Fatalf("the old state file's lock was not let go: %v", err)
	}
	st.lock.Close()
}
