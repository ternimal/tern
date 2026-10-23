// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A client refuses a challenge of any size but challengeLen. On a plaintext
// connection the binding is empty, so a peer sending another agent's
// fingerprint followed by that agent's challenge would otherwise get a proof
// valid on that agent's TLS connection.
func TestClientRefusesLongChallenge(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []byte{methodTokenHMAC, methodPubkey} {
		c, s := net.Pipe()
		sent := make(chan []byte, 1)
		go func() {
			defer s.Close()
			var m [1]byte
			io.ReadFull(s, m[:])
			if m[0] == methodPubkey {
				readBlob(s, 4096) // the public key
			}
			writeBlob(s, make([]byte, 64)) // a fingerprint, then a challenge
			b, _ := readBlob(s, 4096)
			sent <- b
		}()
		err := clientHandshake(c, method, "a-token-of-sixteen+", signer, nil)
		c.Close()
		if err == nil || !strings.Contains(err.Error(), "64-byte challenge") {
			t.Errorf("method %d: a 64-byte challenge was accepted: %v", method, err)
		}
		if b := <-sent; len(b) > 0 {
			t.Errorf("method %d: the client sent a proof for it: %x", method, b)
		}
	}
}
