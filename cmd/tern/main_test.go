// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	tern "github.com/ternimal/tern/internal/tern"
)

// An empty forward bind host must default to loopback, so ":port:..." does
// not silently listen on every interface; an explicit host is kept.
func TestForwardBindDefaultsLoopback(t *testing.T) {
	cases := []struct{ spec, wantListen string }{
		{"8080:example:80", "127.0.0.1:8080"},  // 3-field: loopback
		{":8080:example:80", "127.0.0.1:8080"}, // 4-field, empty host: loopback
		{"127.0.0.1:8080:example:80", "127.0.0.1:8080"},
		{"0.0.0.0:8080:example:80", "0.0.0.0:8080"}, // explicit wildcard kept
	}
	for _, c := range cases {
		gotL, _, err := parseLocalForward(c.spec)
		if err != nil {
			t.Fatalf("parseLocalForward(%q): %v", c.spec, err)
		}
		if gotL != c.wantListen {
			t.Errorf("parseLocalForward(%q) listen = %q, want %q", c.spec, gotL, c.wantListen)
		}
		gotB, _, err := parseRemoteForward(c.spec)
		if err != nil {
			t.Fatalf("parseRemoteForward(%q): %v", c.spec, err)
		}
		if gotB != c.wantListen {
			t.Errorf("parseRemoteForward(%q) bind = %q, want %q", c.spec, gotB, c.wantListen)
		}
	}
}

func TestBindHost(t *testing.T) {
	if bindHost("") != "127.0.0.1" {
		t.Error("empty bind host should default to loopback")
	}
	if bindHost("0.0.0.0") != "0.0.0.0" {
		t.Error("explicit bind host must be kept")
	}
}

// ternd prints a relay connection string without the relay token, which is
// the operator's secret; the client then takes it from TERN_RELAY_TOKEN, and
// a string that carries one uses its own.
func TestRelayTokenFromEnv(t *testing.T) {
	bare := tern.ConnString{Mode: "relay", Relay: "relay:7000", RelayFP: "c0ffee", ID: "box1", FP: "a1f2"}
	carrying := bare
	carrying.RelayToken = "token-in-the-string"
	for _, c := range []struct {
		cs        tern.ConnString
		env, want string
	}{
		{bare, "token-from-env-123", "token-from-env-123"},
		{carrying, "token-from-env-123", "token-in-the-string"},
		{bare, "", ""},
	} {
		t.Setenv("TERN_RELAY_TOKEN", c.env)
		t.Setenv("TERN_TO", c.cs.Encode())
		t.Setenv("TERN_TOKEN", "agent-token-1234567")
		cf := addConnFlags(flag.NewFlagSet("t", flag.ContinueOnError))
		tg, err := cf.target()
		if c.want == "" {
			if err == nil {
				t.Errorf("a string without a relay token and no TERN_RELAY_TOKEN was accepted")
			}
			continue
		}
		if err != nil {
			t.Errorf("target: %v", err)
		} else if tg.relayToken != c.want {
			t.Errorf("relay token = %q, want %q", tg.relayToken, c.want)
		}
	}
}

// The command tern mcp offers for watching a terminal carries a relay id from
// a tern1: string, which someone else may have handed out, as one quoted
// argument: pasted into a shell, it reaches tern as it is and runs nothing. A
// string that is refused outright is as safe.
func TestWatchCommandFromConnString(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	fp := strings.Repeat("ab", 32)
	id := "box$(touch " + marker + ")"
	cs := tern.ConnString{Mode: "relay", Relay: "relay.example.net:443", RelayFP: fp, RelayToken: "relay-token-0123456789", ID: id, FP: fp}
	t.Setenv("TERN_TO", cs.Encode())
	t.Setenv("TERN_TOKEN", "agent-token-0123456789")
	targets := []*target{{mode: "relay", relay: "relay.example.net:443", relayFP: fp, id: id, fp: fp}}
	if tg, err := addConnFlags(flag.NewFlagSet("mcp", flag.ContinueOnError)).target(); err == nil {
		targets = append(targets, tg)
	}
	for _, tg := range targets {
		watch := tg.info("default").ConnectCommand("--session", "mcp-abcdefghijkl", "--read-only")
		out, err := exec.Command("sh", "-c", `tern() { printf '%s\n' "$@"; }; `+watch).Output()
		want := "connect\n--relay\nrelay.example.net:443\n--relay-fingerprint\n" + fp + "\n--id\n" + id + "\n--fingerprint\n" + fp + "\n--session\nmcp-abcdefghijkl\n--read-only\n"
		if err != nil || string(out) != want {
			t.Errorf("%s\nreached tern as %q (%v)", watch, out, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("pasting the watch command ran a command from the relay id")
	}
}

// The help teaches secrets that stay off the command line, where other local
// users can read them: environment variables, files and keys, never a token
// value after a flag.
func TestUsageKeepsSecretsOffArgv(t *testing.T) {
	for _, want := range []string{"TERN_TOKEN", "--token-file", "TERN_RELAY_TOKEN", "--relay-token-file",
		"TERN_API_TOKEN", "--api-token-file", "--key"} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage does not mention %s", want)
		}
	}
	for _, flag := range []string{"--token", "--relay-token", "--api-token"} {
		for _, value := range []string{" T ", " T\n", " TOKEN", " SECRET", "=", " / TERN"} {
			if strings.Contains(usage, flag+value) {
				t.Errorf("usage shows %q, a secret on the command line", flag+value)
			}
		}
	}
}

// tern mcp tells the server where tern keeps its own state and
// configuration, the state directory in use and the default places, so a
// download never plants a file there.
func TestTernDirsHoldStateAndConfig(t *testing.T) {
	home, xdg := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_STATE_HOME", xdg)
	dirs := ternDirs()
	for _, want := range []string{filepath.Join(xdg, "tern"), filepath.Join(home, ".local", "state", "tern"), filepath.Join(home, ".config", "tern"),
		filepath.Dir(ptyStatePath(nil)), filepath.Dir(defaultAuditPath())} {
		if !slices.Contains(dirs, want) {
			t.Errorf("%s is not among %q", want, dirs)
		}
	}
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			t.Errorf("%s is not absolute", d)
		}
	}
}
