// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ternEnv is the test's environment with every TERN_* variable taken out, so
// one set where the tests run cannot change what they see, plus extra.
func ternEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "TERN_") {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// runDaemon runs a daemon binary that is expected to refuse to start, and
// returns its output and whether it exited by itself.
func runDaemon(t *testing.T, name string, env []string, args ...string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin[name], args...)
	cmd.Dir = t.TempDir()
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err != nil && ctx.Err() == nil
}

var liveToken = regexp.MustCompile(`TERN_TOKEN=[A-Za-z0-9+/=]{16,}`)

// TestZeroConfigNeedsTerminal: with no auth configured, ternd makes up a
// token only for a person at a terminal, where it shows it. With its output
// going anywhere else, such as a service's log, it refuses to start rather
// than write a live credential there.
func TestZeroConfigNeedsTerminal(t *testing.T) {
	for name, args := range map[string][]string{
		"direct": {"--addr", addr(freePort(t))},
		"relay":  {"--relay", "127.0.0.1:9", "--relay-fingerprint", strings.Repeat("00", 32), "--id", "box1"},
	} {
		args = append(args, "--cert", filepath.Join(t.TempDir(), "agent"))
		out, refused := runDaemon(t, "ternd", ternEnv("TERN_RELAY_TOKEN="+genToken(t)), args...)
		if !refused {
			t.Fatalf("%s: ternd started with no auth and no terminal:\n%s", name, out)
		}
		if !strings.Contains(out, "TERN_TOKEN") {
			t.Errorf("%s: the refusal does not say what to set:\n%s", name, out)
		}
		if liveToken.MatchString(out) {
			t.Errorf("%s: a token was printed:\n%s", name, out)
		}
	}
}

// TestZeroConfigOnTerminal: on a terminal, ternd with no auth configured
// still just runs, and the token it made up and shows works.
func TestZeroConfigOnTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ConPTY wraps the long connect line")
	}
	port := freePort(t)
	args := []string{"--addr", addr(port), "--cert", filepath.Join(t.TempDir(), "agent")}
	if s := agentShell(); s != "" {
		args = append(args, "--shell", s)
	}
	pc := dialPTY(t, "ternd", args...)
	re := regexp.MustCompile(`TERN_TOKEN=([A-Za-z0-9+/=]{16,}) tern connect --to (tern1:[A-Za-z0-9_-]+)`)
	var m []string
	for deadline := time.Now().Add(15 * time.Second); m == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		m = re.FindStringSubmatch(pc.buf.String())
	}
	if m == nil {
		t.Fatalf("no connect line with a token:\n%s", pc.buf.String())
	}
	waitListen(t, addr(port), 10*time.Second)
	out, code := runClient(t, 20*time.Second, append([]string{"run", m[2], "--token", m[1], "--"}, execArgv("ZERO_CONFIG_OK", 0)...)...)
	if code != 0 || !strings.Contains(out, "ZERO_CONFIG_OK") {
		t.Fatalf("the token ternd showed did not work (%d):\n%s", code, out)
	}
}

// TestDaemonsRefuseUnsafeID: an agent id ends up in commands people paste
// into a shell, so ternd and rtern refuse one with anything but letters,
// digits and . _ - @ : +, rather than print it.
func TestDaemonsRefuseUnsafeID(t *testing.T) {
	const id = "box$(touch pwned)"
	env := ternEnv("TERN_RELAY_TOKEN="+genToken(t), "TERN_TOKEN="+genToken(t))
	for name, args := range map[string][]string{
		"ternd": {"--relay", "127.0.0.1:9", "--relay-fingerprint", strings.Repeat("00", 32), "--id", id},
		"rtern": {"--addr", addr(freePort(t)), "--fingerprint", strings.Repeat("ab", 32), "--id", id},
	} {
		args = append(args, "--cert", filepath.Join(t.TempDir(), name))
		out, refused := runDaemon(t, name, env, args...)
		if !refused || !strings.Contains(out, "--id") {
			t.Errorf("%s took the id %q:\n%s", name, id, out)
		}
	}
}

// TestDaemonsRefuseBadRelayToken: ternd in relay mode, ternr and rtern all
// refuse to start with a relay token shorter than 16 characters or longer
// than a relay reads, rather than run with one that is easy to guess or that
// no relay takes.
func TestDaemonsRefuseBadRelayToken(t *testing.T) {
	for _, token := range []string{"short-token", strings.Repeat("x", 1025)} {
		env := ternEnv("TERN_RELAY_TOKEN="+token, "TERN_TOKEN="+genToken(t))
		for name, args := range map[string][]string{
			"ternd": {"--relay", "127.0.0.1:9", "--relay-fingerprint", strings.Repeat("00", 32), "--id", "box1"},
			"ternr": {"--addr", addr(freePort(t))},
			"rtern": {"--addr", addr(freePort(t)), "--fingerprint", strings.Repeat("ab", 32), "--id", "box1"},
		} {
			args = append(args, "--cert", filepath.Join(t.TempDir(), name))
			out, refused := runDaemon(t, name, env, args...)
			if !refused || !strings.Contains(out, "relay token is too") {
				t.Errorf("%s took a %d-character relay token:\n%s", name, len(token), out)
			}
		}
	}
}

// TestAPITokenNeedsTerminal: tern api with no bearer token set makes one up
// only for a person at a terminal. With its output going anywhere else it
// refuses to start, rather than write a live token to a service's log.
func TestAPITokenNeedsTerminal(t *testing.T) {
	a := startDirectAgent(t)
	args := append([]string{"api"}, a.dialArgs()...)
	args = append(args, "--api-addr", addr(freePort(t)))
	out, refused := runDaemon(t, "tern", ternEnv(), args...)
	if !refused {
		t.Fatalf("tern api started with no token and no terminal:\n%s", out)
	}
	if !strings.Contains(out, "TERN_API_TOKEN") {
		t.Errorf("the refusal does not say what to set:\n%s", out)
	}
	if regexp.MustCompile(`(?m)^\s+[A-Za-z0-9+/=]{32,}\s*$`).MatchString(out) {
		t.Errorf("a token was printed:\n%s", out)
	}
}
