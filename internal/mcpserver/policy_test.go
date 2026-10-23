// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"slices"
	"strings"
	"testing"
)

// CheckRun is the tests' shorthand for RunDecision: whether argv runs without
// asking anyone, and why not.
func (p *Policy) CheckRun(argv []string, shell bool) (bool, string) {
	d, why := p.RunDecision(argv, shell)
	return d == Allow, why
}

func TestReadonlyPolicy(t *testing.T) {
	p, err := NewPolicy("readonly")
	if err != nil {
		t.Fatal(err)
	}
	allowed := [][]string{
		{"uptime"},
		{"df", "-h"},
		{"uname", "-a"},
		{"echo"},
		{"echo", "a", "b", "c"},
		{"ls", "/var/log"},
		{"systemctl", "is-active", "nginx"},
		{"systemctl", "is-failed", "user@1000.service"},
		{"systemctl", "show", "-p", unitProps, "nginx.service"},
		{"journalctl", "-u", "nginx", "-n", "50"},
		{"cat", "/etc/os-release"},
	}
	for _, argv := range allowed {
		if ok, why := p.CheckRun(argv, false); !ok {
			t.Errorf("%q should be allowed, denied: %s", argv, why)
		}
	}
	// Each of these is a way to escape a naive allowlist: a shell or
	// interpreter, an exec-style wrapper, a program with a shell escape, a path
	// that only looks like an allowed name, or extra arguments.
	denied := []struct {
		argv []string
		want string
	}{
		{nil, "empty"},
		{[]string{""}, "empty"},
		{[]string{"bash", "-c", "id"}, "arbitrary commands"},
		{[]string{"sh", "-c", "uptime; rm -rf /"}, "arbitrary commands"},
		{[]string{"env", "uptime"}, "arbitrary commands"},
		{[]string{"xargs", "rm"}, "arbitrary commands"},
		{[]string{"find", "/", "-exec", "sh", ";"}, "arbitrary commands"},
		{[]string{"awk", "BEGIN{system(\"id\")}"}, "arbitrary commands"},
		{[]string{"python3", "-c", "import os"}, "arbitrary commands"},
		{[]string{"git", "-c", "core.sshCommand=id", "fetch"}, "arbitrary commands"},
		{[]string{"BASH", "-c", "id"}, "arbitrary commands"},
		{[]string{"/bin/uptime"}, "bare command name"},
		{[]string{"./uptime"}, "bare command name"},
		{[]string{`C:\Windows\System32\cmd.exe`}, "bare command name"},
		{[]string{"rm", "-rf", "/tmp/x"}, "not in the readonly allowlist"},
		{[]string{"cat", "/etc/shadow"}, "not in the readonly allowlist"},
		{[]string{"uptime", "extra"}, "not in the readonly allowlist"},
		{[]string{"df", "-h", "/"}, "not in the readonly allowlist"},
		{[]string{"journalctl", "-u", "nginx"}, "not in the readonly allowlist"},
		{[]string{"uptime;id"}, "not in the readonly allowlist"},
		// systemctl status prints the command line of every process in
		// the unit; a glob names every unit, and show prints only the
		// properties listed.
		{[]string{"systemctl", "status", "nginx"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "status", "*"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "is-active", "*"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "is-failed", "ngin?"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "is-active", "user@[0-9]*.service"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "is-active", `nginx\x2a`}, "not in the readonly allowlist"},
		{[]string{"systemctl", "is-active", "--all"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "show", "nginx"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "show", "-p", "ExecStart", "nginx"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "show", "-p", unitProps + ",Environment", "nginx"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "show", "-p", unitProps, "*"}, "not in the readonly allowlist"},
		{[]string{"systemctl", "show", "-p", unitProps, "-H"}, "not in the readonly allowlist"},
	}
	for _, tc := range denied {
		ok, why := p.CheckRun(tc.argv, false)
		if ok {
			t.Errorf("%q should be denied", tc.argv)
			continue
		}
		if !strings.Contains(why, tc.want) {
			t.Errorf("%q: reason %q should mention %q", tc.argv, why, tc.want)
		}
	}
	if ok, why := p.CheckRun([]string{"uptime"}, true); ok || !strings.Contains(why, "shell mode") {
		t.Errorf("shell mode must be denied in readonly, got ok=%v why=%q", ok, why)
	}
	// A denial tells the model what it may run instead.
	if _, why := p.CheckRun([]string{"rm"}, false); !strings.Contains(why, "uptime") {
		t.Errorf("denial should list allowed commands: %q", why)
	}
}

// The properties readonly's systemctl show prints describe a unit's state:
// none holds a command line, the environment, credentials, the data a
// service reads on standard input, mount options or free text a service
// reports, nor the description, which systemd-run sets to the command line
// it runs. agent_info lists the command as the model must give it.
func TestUnitPropertiesHoldNoCommands(t *testing.T) {
	for _, prop := range strings.Split(unitProps, ",") {
		for _, bad := range []string{"Exec", "Environment", "Credential", "StandardInput", "Status", "Options", "LogExtraFields", "Command", "Description"} {
			if strings.Contains(prop, bad) {
				t.Errorf("systemctl show prints %s", prop)
			}
		}
	}
	ro, _ := NewPolicy("readonly")
	want := "systemctl show -p " + unitProps + " <unit>"
	if !slices.Contains(ro.AllowedCommands(), want) || slices.ContainsFunc(ro.AllowedCommands(), func(c string) bool { return strings.Contains(c, "status") }) {
		t.Errorf("allowed commands: %q", ro.AllowedCommands())
	}
}

func TestUnknownProfile(t *testing.T) {
	if _, err := NewPolicy("full"); err == nil {
		t.Fatal("an unknown profile must be an error, not a silent fallback")
	}
}

// Shells, interpreters and launchers that run what their arguments say are
// wrappers, refused in an allowlist unless allow_wrappers is set.
func TestIsWrapper(t *testing.T) {
	for _, w := range []string{"rbash", "mksh", "nodejs", "npx", "deno", "bun", "setpriv", "tmux", "screen",
		"systemd-nspawn", "make", "sqlite3", "conhost.exe", "winrs", "pcalua", "sc.exe"} {
		if !isWrapper(w) {
			t.Errorf("%s is not a wrapper", w)
		}
	}
	for _, c := range []string{"uptime", "df", "systemctl", "journalctl", "whoami"} {
		if isWrapper(c) {
			t.Errorf("%s is a wrapper", c)
		}
	}
}

// readonly: journalctl's -n takes an optional argument, so what follows it
// could be any option, --vacuum-*, --rotate, --flush, --setup-keys ...: the
// count slot takes none.
func TestReadonlyJournalctlTakesNoOption(t *testing.T) {
	ro, _ := NewPolicy("readonly")
	if !ro.RunReadOnly() {
		t.Fatal("readonly claims read-only")
	}
	for _, argv := range [][]string{
		{"journalctl", "-n", "--vacuum-time=1s"},
		{"journalctl", "-n", "--rotate"},
		{"journalctl", "-u", "x", "-n", "--vacuum-size=1"},
	} {
		if d, _ := ro.RunDecision(argv, false); d == Allow {
			t.Errorf("readonly allows %q", argv)
		}
	}
}
