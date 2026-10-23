// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestInsecureConnectSkipsFingerprint verifies the --insecure-skip-fingerprint escape hatch: a
// client may reach an agent without pinning its fingerprint and the exec still
// succeeds, proving the flag threads through to the TLS config. --insecure
// relaxes only the client's check of the agent identity; the client still
// authenticates to the agent with its token, so auth is unchanged.
func TestInsecureConnectSkipsFingerprint(t *testing.T) {
	a := startDirectAgent(t)
	args := []string{"run", "--insecure-skip-fingerprint", "--addr", a.addr, "--token", a.token, "--"}
	args = append(args, execArgv("INSECURE_OK_71", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code != 0 || !strings.Contains(out, "INSECURE_OK_71") {
		t.Fatalf("insecure connect failed (code=%d):\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "insecure") {
		t.Errorf("expected an --insecure-skip-fingerprint warning in the output:\n%s", out)
	}
}

// TestNoFingerprintStrictByDefault verifies the default stays fail-closed: no
// fingerprint and no --insecure-skip-fingerprint is an error, not a silent trust-on-first-use.
func TestNoFingerprintStrictByDefault(t *testing.T) {
	a := startDirectAgent(t)
	args := []string{"run", "--addr", a.addr, "--token", a.token, "--"}
	args = append(args, execArgv("SHOULD_NOT_RUN", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code == 0 {
		t.Fatalf("expected failure without a fingerprint, got success:\n%s", out)
	}
	if !strings.Contains(out, "fingerprint") {
		t.Errorf("expected a fingerprint-required error:\n%s", out)
	}
}

// TestInsecureRejectsExplicitFingerprint verifies --insecure-skip-fingerprint and --fingerprint
// are mutually exclusive: asking to both pin and skip pinning is a usage error,
// so --insecure-skip-fingerprint cannot silently defeat a fingerprint the user did supply.
func TestInsecureRejectsExplicitFingerprint(t *testing.T) {
	a := startDirectAgent(t)
	args := []string{"run", "--insecure-skip-fingerprint", "--addr", a.addr, "--fingerprint", a.fp, "--token", a.token, "--"}
	args = append(args, execArgv("SHOULD_NOT_RUN", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code == 0 {
		t.Fatalf("expected failure combining --insecure-skip-fingerprint with --fingerprint:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "insecure") {
		t.Errorf("expected a mutual-exclusion error mentioning insecure:\n%s", out)
	}
}

// TestSkipEncryptionPlaintext verifies --insecure-skip-encryption: with the
// agent in the matching plaintext mode, a client runs a command over a session
// with no TLS at all. The token is still required and checked.
func TestSkipEncryptionPlaintext(t *testing.T) {
	a := startDirectAgent(t, "--insecure-skip-encryption")
	args := []string{"run", "--insecure-skip-encryption", "--addr", a.addr, "--token", a.token, "--"}
	args = append(args, execArgv("PLAINTEXT_OK_83", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code != 0 || !strings.Contains(out, "PLAINTEXT_OK_83") {
		t.Fatalf("plaintext connect failed (code=%d):\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "plaintext") {
		t.Errorf("expected a plaintext warning in the output:\n%s", out)
	}
}

// TestSkipEncryptionNeedsBothEnds verifies the mode is symmetric: a plaintext
// client against a normal TLS agent fails the handshake rather than silently
// downgrading to cleartext.
func TestSkipEncryptionNeedsBothEnds(t *testing.T) {
	a := startDirectAgent(t) // a normal TLS agent
	args := []string{"run", "--insecure-skip-encryption", "--addr", a.addr, "--token", a.token, "--"}
	args = append(args, execArgv("SHOULD_NOT_RUN", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code == 0 {
		t.Fatalf("expected failure: a plaintext client against a TLS agent must not connect:\n%s", out)
	}
}

// TestSkipEncryptionThroughRelay: --insecure-skip-encryption works through a
// relay too, with the flags ternd prints for it. The client never binds its
// proof to the relay connection it was handed, which the plaintext agent
// knows nothing of.
func TestSkipEncryptionThroughRelay(t *testing.T) {
	r := startRelayServer(t)
	tok := genToken(t)
	dargs := []string{"--relay", r.addr, "--relay-fingerprint", r.fp, "--id", "plainbox",
		"--token", tok, "--cert", filepath.Join(t.TempDir(), "agent"), "--insecure-skip-encryption"}
	if s := agentShell(); s != "" {
		dargs = append(dargs, "--shell", s)
	}
	d := start(t, "ternd", []string{"TERN_RELAY_TOKEN=" + r.token}, dargs...)
	line := d.waitFor(t, regexp.MustCompile(`tern connect (--insecure-skip-encryption --relay-fingerprint \S+ --relay \S+ --id plainbox)`), 15*time.Second)
	args := append([]string{"run"}, strings.Fields(line)...)
	args = append(args, "--token", tok, "--relay-token", r.token, "--")
	args = append(args, execArgv("RELAY_PLAIN_OK_29", 0)...)
	out, code := runClient(t, 25*time.Second, args...)
	if code != 0 || !strings.Contains(out, "RELAY_PLAIN_OK_29") {
		t.Fatalf("plaintext through the relay failed (code=%d):\n%s", code, out)
	}
}

// TestInsecureDangerousPlaintext verifies the --insecure-dangerous shorthand:
// with it set on both ends, a client reaches the agent over a plaintext session
// and without a pinned fingerprint, proving the one flag turns on both
// skip-fingerprint and skip-encryption at once.
func TestInsecureDangerousPlaintext(t *testing.T) {
	a := startDirectAgent(t, "--insecure-dangerous")
	args := []string{"run", "--insecure-dangerous", "--addr", a.addr, "--token", a.token, "--"}
	args = append(args, execArgv("DANGEROUS_OK_95", 0)...)
	out, code := runClient(t, 20*time.Second, args...)
	if code != 0 || !strings.Contains(out, "DANGEROUS_OK_95") {
		t.Fatalf("--insecure-dangerous connect failed (code=%d):\n%s", code, out)
	}
}
