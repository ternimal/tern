// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestResolveWriteMode covers the long flag and its -V alias, including an
// explicit false, which opts into co-driving.
func TestResolveWriteMode(t *testing.T) {
	for _, tc := range []struct {
		args           []string
		write, coDrive bool
	}{
		{nil, true, false},
		{[]string{"--read-only"}, false, false},
		{[]string{"-V"}, false, false},
		{[]string{"--read-only=false"}, true, true},
		{[]string{"-V=false"}, true, true},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		ro := fs.Bool("read-only", false, "")
		Alias(fs, "read-only", "V")
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		write, coDrive := ResolveWriteMode(fs, *ro)
		if write != tc.write || coDrive != tc.coDrive {
			t.Errorf("%v: got write=%v coDrive=%v, want %v %v", tc.args, write, coDrive, tc.write, tc.coDrive)
		}
	}
}

// TestShellQuote: a quoted value reaches the command as itself, whatever it
// holds, and plain values are left plain.
func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"box1":              "box1",
		"127.0.0.1:2222":    "127.0.0.1:2222",
		"[::1]:2222":        "'[::1]:2222'",
		"":                  "''",
		"it's":              `'it'\''s'`,
		"box$(touch x)":     "'box$(touch x)'",
		"ab:cd/ef_gh-ij@k%": "ab:cd/ef_gh-ij@k%",
		"--read-only=false": "--read-only=false",
		"=ls":               "'=ls'",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	marker := filepath.Join(t.TempDir(), "ran")
	for _, in := range []string{"box$(touch " + marker + ")", "`touch " + marker + "`", "a'b\"c;d|e&f", "*", "~", "=ls", "!x", "{a,b}"} {
		out, err := exec.Command("/bin/sh", "-c", "printf %s "+ShellQuote(in)).Output()
		if err != nil || string(out) != in {
			t.Errorf("%q came out as %q (%v)", in, out, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a quoted value ran as a command")
	}
}

func TestAcceptRetryDelay(t *testing.T) {
	d := AcceptRetryDelay(0)
	if d != acceptRetryMin {
		t.Fatalf("first delay = %s, want %s", d, acceptRetryMin)
	}
	for i := 0; i < 20; i++ {
		d = AcceptRetryDelay(d)
	}
	if d != acceptRetryMax {
		t.Fatalf("delay grew to %s, want the %s cap", d, acceptRetryMax)
	}
	if acceptRetryMax > 5*time.Second {
		t.Fatalf("accept retry cap %s is too long", acceptRetryMax)
	}
}

// TestResolveVersion: an -X version wins; an unset one falls back to the
// module version, which a test binary does not have, so it stays "dev".
func TestResolveVersion(t *testing.T) {
	if got := ResolveVersion("v9.9.9"); got != "v9.9.9" {
		t.Fatalf("ResolveVersion(v9.9.9) = %q", got)
	}
	if got := ResolveVersion("dev"); got == "" {
		t.Fatal("ResolveVersion(dev) returned an empty version")
	}
}

// TestCRLFWriter: log lines written while the terminal is raw get CR-LF line
// ends, so they do not staircase across the screen.
func TestCRLFWriter(t *testing.T) {
	var b strings.Builder
	n, err := crlfWriter{&b}.Write([]byte("a\nb\n"))
	if err != nil || n != 4 || b.String() != "a\r\nb\r\n" {
		t.Fatalf("got n=%d err=%v %q", n, err, b.String())
	}
}

// TestREADMEBanner keeps the banner in README.md identical to the one ternd
// prints, so the tagline cannot drift between the two.
func TestREADMEBanner(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "```\n"+Banner("")+"\n```") {
		t.Fatalf("README.md banner differs from Banner(\"\"):\n%s", Banner(""))
	}
}

func TestResolveSecret(t *testing.T) {
	t.Setenv("TERN_TEST_SECRET", "from-env")
	if s, ff, _ := ResolveSecret("token", "from-flag", "", "TERN_TEST_SECRET"); s != "from-flag" || !ff {
		t.Errorf("flag: got %q fromFlag=%v", s, ff)
	}
	f := filepath.Join(t.TempDir(), "s")
	// A token file must be private, which on Windows takes an owner-only
	// ACL rather than a mode.
	if err := writePrivateFile(f, []byte("from-file\n")); err != nil {
		t.Fatal(err)
	}
	if s, ff, _ := ResolveSecret("token", "", f, "TERN_TEST_SECRET"); s != "from-file" || ff {
		t.Errorf("file: got %q fromFlag=%v (want from-file, trimmed, not fromFlag)", s, ff)
	}
	if s, ff, _ := ResolveSecret("token", "", "", "TERN_TEST_SECRET"); s != "from-env" || ff {
		t.Errorf("env: got %q fromFlag=%v", s, ff)
	}
	if _, _, err := ResolveSecret("token", "x", f, "TERN_TEST_SECRET"); err == nil {
		t.Error("flag+file together should error")
	}
}

// Session names with control bytes are rejected; CleanText strips them.
func TestSessionNameAndCleanText(t *testing.T) {
	if err := ValidSessionName("\x1b]0;x\x07"); err == nil {
		t.Fatal("control-character session name accepted")
	}
	if ValidSessionName("demo-1") != nil {
		t.Fatal("ordinary session name rejected")
	}
	// CleanText removes the control bytes (ESC, BEL, CR) that drive a terminal;
	// printable leftovers like "[31m" are inert text.
	if got := CleanText("a\x1b[31mb\x07c\r"); got != "a[31mbc" {
		t.Fatalf("CleanText = %q, want %q", got, "a[31mbc")
	}
	m := newSessionManager("/bin/sh", time.Minute, "")
	if _, _, _, err := m.attach("\x1b]0;evil\x07", modeNew, true, false, "", 80, 24); err == nil {
		t.Fatal("agent accepted a session name with escape sequences")
	}
}
