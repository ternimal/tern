// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tern "github.com/ternimal/tern/internal/tern"
)

// TestRelayTokenNotSentToForeignRelay: a tern1: string that names someone
// else's relay, and carries no relay token, gets the relay token from the
// environment used with it, as ternd prints such strings. The client must
// only ever prove that token, bound to the relay it reached, never send it:
// sent as is, TERN_RELAY_TOKEN would let whatever relay the string named
// take over the agents on the user's own relay.
func TestRelayTokenNotSentToForeignRelay(t *testing.T) {
	cert, err := tern.LoadOrCreateCert(filepath.Join(t.TempDir(), "other-relay"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tern.ServerTLSConfig(cert))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		// Challenge as a relay does, take whatever comes back, and refuse.
		c.Write(append([]byte{0, 32}, bytes.Repeat([]byte{7}, 32)...))
		var sent bytes.Buffer
		blob := func() {
			var n [2]byte
			if _, err := io.ReadFull(io.TeeReader(c, &sent), n[:]); err == nil {
				io.CopyN(&sent, c, int64(binary.BigEndian.Uint16(n[:])))
			}
		}
		blob()                // the proof
		io.CopyN(&sent, c, 1) // the role
		blob()                // the agent id
		c.Write([]byte{0})    // relayDeny
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.Copy(&sent, c) // anything after, until the client hangs up
		got <- sent.Bytes()
	}()

	const relayToken = "the-users-own-relay-token-6f1c2a9b"
	cs := tern.ConnString{Mode: "relay", Relay: ln.Addr().String(), RelayFP: tern.CertFingerprint(cert),
		ID: "shared-box", FP: strings.Repeat("ab", 32)}.Encode()
	out, refused := runDaemon(t, "tern", ternEnv("TERN_RELAY_TOKEN="+relayToken, "TERN_TOKEN="+genToken(t)),
		"run", "--to", cs, "--", "true")
	if !refused {
		t.Fatalf("tern run went through a relay that refused it:\n%s", out)
	}
	select {
	case sent := <-got:
		if len(sent) == 0 {
			t.Fatalf("the client sent the relay nothing:\n%s", out)
		}
		if bytes.Contains(sent, []byte(relayToken)) {
			t.Fatalf("the relay the string named received the relay token:\n%q", sent)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never heard from the client")
	}
}
