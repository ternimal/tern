// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fingerprint that is given is checked even when verification is turned
// off: someone who pinned the peer means it, whatever else they relaxed. Only
// with no fingerprint does insecure accept any peer.
func TestGivenFingerprintAlwaysChecked(t *testing.T) {
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "peer"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	right, wrong := CertFingerprint(cert), strings.Repeat("00", 32)
	for _, insecure := range []bool{false, true} {
		if err := ClientTLSConfig(wrong, insecure).VerifyConnection(cs); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
			t.Errorf("insecure=%v, wrong fingerprint: %v", insecure, err)
		}
		if err := ClientTLSConfig(right, insecure).VerifyConnection(cs); err != nil {
			t.Errorf("insecure=%v, right fingerprint: %v", insecure, err)
		}
	}
	if err := ClientTLSConfig("", true).VerifyConnection(cs); err != nil {
		t.Errorf("insecure with no fingerprint: %v", err)
	}
	if err := ClientTLSConfig("", false).VerifyConnection(cs); err == nil {
		t.Error("no fingerprint and not insecure passed")
	}
}

// ternd --insecure-dangerous --relay-fingerprint FP: the agent still pins the
// relay it was given and never registers with one that presents another
// certificate. Without a relay fingerprint the flag skips the check.
func TestAgentPinsGivenRelayFingerprint(t *testing.T) {
	_, addr, realFP, ctx := startTestHub(t)
	dial := func(fp string, insecure bool) error {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		_, err := RelayDialAgent(cctx, addr, fp, testRelayToken, "box", insecure)
		return err
	}
	for _, insecure := range []bool{false, true} {
		if err := dial(strings.Repeat("00", 32), insecure); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
			t.Errorf("insecure=%v, wrong relay fingerprint: %v", insecure, err)
		}
		// Registered, the agent waits to be paired until the deadline.
		if err := dial(realFP, insecure); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("insecure=%v, right relay fingerprint: %v", insecure, err)
		}
	}
	if err := dial("", true); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("insecure with no relay fingerprint: %v", err)
	}
}
