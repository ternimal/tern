// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"strings"
	"testing"
	"time"
)

func TestBuildPolicies(t *testing.T) {
	pols, err := BuildPolicies(map[string]ProfileConfig{
		"ops": {
			Run:        RunConfig{Allow: [][]string{{"systemctl", "restart", "*"}}},
			ReadPaths:  []string{"/srv/app/**"},
			WritePaths: []string{"/srv/app/**", "/tmp/**"},
			Limits:     Limits{TimeoutS: 120, OutputBytes: 1 << 20},
		},
		"oncall": {Extends: "ops", Run: RunConfig{Shell: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ro, ops, oncall := pols["readonly"], pols["ops"], pols["oncall"]
	if !ro.RunReadOnly() || ro.CanWrite() || ro.ShellAllowed() {
		t.Fatal("readonly must stay read-only")
	}
	// Extending adds to the base and keeps it.
	if ok, _ := ops.CheckRun([]string{"systemctl", "restart", "nginx"}, false); !ok {
		t.Error("ops should allow its own pattern")
	}
	if ok, _ := ops.CheckRun([]string{"uptime"}, false); !ok {
		t.Error("ops should keep readonly's commands")
	}
	if _, ok, _ := ops.CheckRead("/srv/app/config.yml"); !ok {
		t.Error("ops should read its extra path")
	}
	if _, ok, _ := ops.CheckRead("/etc/os-release"); !ok {
		t.Error("ops should keep readonly's paths")
	}
	if ops.RunReadOnly() || !ops.CanWrite() || ops.ShellAllowed() {
		t.Error("ops adds commands and writes but not shell mode")
	}
	if ops.timeoutCap != 120*time.Second || ops.outputCap != 1<<20 {
		t.Error("ops limits not applied")
	}
	// A chain inherits everything, including limits, and adds shell mode.
	if !oncall.ShellAllowed() || oncall.timeoutCap != 120*time.Second {
		t.Error("oncall should inherit ops and add shell mode")
	}
	if ok, why := oncall.CheckRun([]string{"ps aux | grep nginx"}, true); !ok {
		t.Errorf("oncall should accept a shell command line: %s", why)
	}
	if ok, _ := oncall.CheckRun([]string{"ps", "aux"}, true); ok {
		t.Error("shell mode takes exactly one argv element")
	}
	if ok, _ := ops.CheckRun([]string{"id"}, true); ok {
		t.Error("ops has no shell mode")
	}
	// The base profile is not modified by building others.
	if len(ro.allow) != len(readonlyAllow) || len(ro.writeAllow) != 0 {
		t.Error("building profiles must not change readonly")
	}
}

func TestBuildPoliciesRejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]ProfileConfig
		want string
	}{
		{"redefine readonly", map[string]ProfileConfig{"readonly": {}}, "built in"},
		{"unknown parent", map[string]ProfileConfig{"a": {Extends: "nope"}}, "unknown profile"},
		{"cycle", map[string]ProfileConfig{"a": {Extends: "b"}, "b": {Extends: "a"}}, "cycle"},
		{"wrapper without opt-in", map[string]ProfileConfig{"a": {Run: RunConfig{Allow: [][]string{{"bash", "-c", "*"}}}}}, "allow_wrappers"},
		{"path as command", map[string]ProfileConfig{"a": {Run: RunConfig{Allow: [][]string{{"/bin/ls"}}}}}, "bare name"},
		{"wildcard command", map[string]ProfileConfig{"a": {Run: RunConfig{Allow: [][]string{{"*"}}}}}, "command name"},
		{"** in the middle", map[string]ProfileConfig{"a": {Run: RunConfig{Allow: [][]string{{"ls", "**", "x"}}}}}, "**"},
		{"relative path", map[string]ProfileConfig{"a": {ReadPaths: []string{"srv/**"}}}, "absolute"},
		{"dotdot path", map[string]ProfileConfig{"a": {WritePaths: []string{"/srv/../etc/**"}}}, ".."},
		{"timeout too long", map[string]ProfileConfig{"a": {Limits: Limits{TimeoutS: 1 << 40}}}, "timeout_s"},
		{"output too big", map[string]ProfileConfig{"a": {Limits: Limits{OutputBytes: 1 << 30}}}, "output_bytes"},
		{"pty without shell", map[string]ProfileConfig{"a": {PTY: true}}, "pty needs run.shell"},
		{"unknown confirm", map[string]ProfileConfig{"a": {Confirm: []string{"pty_send"}}}, "pty_open"},
	}
	for _, c := range cases {
		if _, err := BuildPolicies(c.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
	// An explicit opt-in allows a wrapper pattern.
	pols, err := BuildPolicies(map[string]ProfileConfig{"py": {Run: RunConfig{AllowWrappers: true, Allow: [][]string{{"python3", "/opt/tool.py", "**"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := pols["py"].CheckRun([]string{"python3", "/opt/tool.py", "--check"}, false); !ok {
		t.Errorf("opted-in wrapper pattern should run: %s", why)
	}
	if ok, _ := pols["py"].CheckRun([]string{"python3", "-c", "x"}, false); ok {
		t.Error("only the listed wrapper pattern may run")
	}
}

func TestCheckWrite(t *testing.T) {
	pols, _ := BuildPolicies(map[string]ProfileConfig{"w": {WritePaths: []string{"/srv/app/**", "/*:/deploy/**"}}})
	w := pols["w"]
	for _, p := range []string{"/srv/app/config.yml", "/srv/app/sub/x", `C:\deploy\app.ini`, "c:/DEPLOY/x"} {
		if _, ok, why := w.CheckWrite(p); !ok {
			t.Errorf("%s should be writable: %s", p, why)
		}
	}
	denied := []struct{ path, want string }{
		{"/srv/app/.ssh/authorized_keys", "secret-path rule"}, // persistence, even under a writable dir
		{"/srv/app/tls/server.KEY", "secret-path rule"},       // secret rules ignore case
		{"/srv/app/../../etc/motd", "outside the paths"},
		{"/etc/cron.d/x", "persistence-point rule"},
		{`C:\Windows\System32\config\SAM`, "secret-path rule"},
	}
	for _, c := range denied {
		if _, ok, why := w.CheckWrite(c.path); ok || !strings.Contains(why, c.want) {
			t.Errorf("CheckWrite(%q) = %v, %q; want denial mentioning %q", c.path, ok, why, c.want)
		}
	}
	ro, _ := NewPolicy("readonly")
	if _, ok, why := ro.CheckWrite("/tmp/x"); ok || !strings.Contains(why, "does not allow writing") {
		t.Errorf("readonly must not write: %v %q", ok, why)
	}
}

func TestWindowsPaths(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	allowed := []struct{ in, sent string }{
		{`C:\Windows\System32\drivers\etc\hosts`, "C:/Windows/System32/drivers/etc/hosts"},
		{`c:\windows\system32\DRIVERS\etc\HOSTS`, "C:/windows/system32/DRIVERS/etc/HOSTS"}, // matched without case
		{`D:/Windows/Logs/CBS/CBS.log`, "D:/Windows/Logs/CBS/CBS.log"},
	}
	for _, c := range allowed {
		sent, ok, why := ro.CheckRead(c.in)
		if !ok || sent != c.sent {
			t.Errorf("CheckRead(%q) = %q, %v, %q; want allowed as %q", c.in, sent, ok, why, c.sent)
		}
	}
	denied := []struct{ in, want string }{
		{`C:\Windows\System32\config\SAM`, "secret-path rule"},
		{`C:\WINDOWS\system32\CONFIG\sam`, "secret-path rule"},
		{`C:\Windows\Logs\..\System32\config\SAM`, "secret-path rule"}, // .. is resolved first
		{`C:\..\..\Windows\System32\config\SAM`, "secret-path rule"},   // cannot climb above the drive
		{`C:\Users\a\AppData\Roaming\Microsoft\Credentials\x`, "secret-path rule"},
		{`C:\Users\a\.ssh\id_ed25519`, "secret-path rule"},
		{`C:\Windows\Logs\x.log:hidden`, "alternate data streams"},
		{`\\server\share\x`, "UNC"},
		{`//server/share/x`, "UNC"},
		{`C:\Windows\Logs\CON`, "device name"},
		{`C:\Windows\Logs\nul.txt`, "device name"},
		{`C:\Windows\Logs\COM1`, "device name"},
		{`C:Windows\x`, "absolute"},
		{`C:\Users\a\notes.txt`, "outside the paths"},
	}
	for _, c := range denied {
		if _, ok, why := ro.CheckRead(c.in); ok || !strings.Contains(why, c.want) {
			t.Errorf("CheckRead(%q) = %v, %q; want denial mentioning %q", c.in, ok, why, c.want)
		}
	}
	// Bare-name rule for commands also catches Windows paths.
	if ok, _ := ro.CheckRun([]string{`C:\Windows\System32\cmd.exe`}, false); ok {
		t.Error("a Windows path as argv[0] must be denied")
	}
	if ok, _ := ro.CheckRun([]string{"ipconfig", "/all"}, false); !ok {
		t.Error("readonly includes Windows diagnostics")
	}
	if ok, _ := ro.CheckRun([]string{"powershell.exe", "-c", "x"}, false); ok {
		t.Error("powershell is a wrapper")
	}
}

// TestPTYDecisions: a terminal is a shell, so typing into one needs approval
// exactly when shell commands do, and opening one can be gated by itself.
func TestPTYDecisions(t *testing.T) {
	pols, err := BuildPolicies(map[string]ProfileConfig{
		"ops":     {Run: RunConfig{Shell: true}, PTY: true},
		"guarded": {Extends: "ops", Confirm: []string{"run:shell"}},
		"strict":  {Extends: "ops", Confirm: []string{"run", "pty_open"}},
		"inherit": {Extends: "ops"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		profile     string
		open, input Decision
	}{
		{"readonly", Deny, Deny},
		{"ops", Allow, Allow},
		{"guarded", Allow, Confirm},
		{"strict", Confirm, Confirm},
		{"inherit", Allow, Allow},
	} {
		p := pols[c.profile]
		if d, why := p.PTYOpenDecision(); d != c.open {
			t.Errorf("%s: open = %v (%s), want %v", c.profile, d, why, c.open)
		}
		if d, why := p.PTYInputDecision(); d != c.input {
			t.Errorf("%s: input = %v (%s), want %v", c.profile, d, why, c.input)
		}
	}
	if !pols["inherit"].PTYAllowed() || pols["readonly"].PTYAllowed() {
		t.Error("pty is inherited and off in readonly")
	}
}

// mustPol builds the profile p, failing the test if it is refused.
func mustPol(t *testing.T, p ProfileConfig) *Policy {
	t.Helper()
	pols, err := BuildPolicies(map[string]ProfileConfig{"p": p})
	if err != nil {
		t.Fatal(err)
	}
	return pols["p"]
}
