// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Both ends of a TLS connection bind proofs to the same bytes: the server's
// certificate fingerprint, then keying material of that session alone, so
// two connections to one server never share a binding.
func TestSessionBindPerConnection(t *testing.T) {
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "srv"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerTLSConfig(cert)
	var binds [][]byte
	for range 2 {
		sconn, cconn := loopbackPair(t)
		srv := make(chan []byte, 1)
		go func() {
			b, err := serverBind(tls.Server(sconn, cfg), cfg)
			if err != nil {
				t.Error(err)
			}
			srv <- b
		}()
		cli := tls.Client(cconn, PinnedTLSConfig(CertFingerprint(cert)))
		if err := cli.Handshake(); err != nil {
			t.Fatal(err)
		}
		b, err := sessionBind(cli, connCertFP(cli))
		if err != nil {
			t.Fatal(err)
		}
		if s := <-srv; !bytes.Equal(b, s) {
			t.Fatalf("the client binds to %x, the server to %x", b, s)
		}
		if !bytes.Equal(b[:32], agentCertFP(cfg)) || len(b) != 64 {
			t.Fatalf("the binding %x does not start with the certificate's fingerprint", b)
		}
		binds = append(binds, b)
	}
	if bytes.Equal(binds[0], binds[1]) {
		t.Fatal("two connections to one server share a binding")
	}
}

// Two agents that present the same certificate (one key copied to both):
// one that a client reaches forwards the other's challenge to the client and
// the client's answer back, hoping to be let in to the other as that client.
// The other refuses the answer, made for another TLS session, whether it
// proves a token or signs with a key.
func TestProofForwardedBetweenAgentsSharingACertIsRefused(t *testing.T) {
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "shared"))
	if err != nil {
		t.Fatal(err)
	}
	fp := CertFingerprint(cert)
	keyPath := filepath.Join(t.TempDir(), "id_victim")
	pubLine, err := GenerateKeyFiles(keyPath, "victim")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubLine))
	if err != nil {
		t.Fatal(err)
	}

	// The agent the forwarder wants in to.
	b := NewAgent(ServerTLSConfig(cert), &AuthConfig{Token: testToken, Keys: keyMap(pub)}, "/bin/sh", time.Minute, "")
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.ServeListener(ctx, bln)

	// The forwarder, holding the same certificate and key.
	aln, err := tls.Listen("tcp", "127.0.0.1:0", ServerTLSConfig(cert))
	if err != nil {
		t.Fatal(err)
	}
	defer aln.Close()
	verdict := make(chan byte, 1)
	go func() {
		for {
			c, err := aln.Accept()
			if err != nil {
				return
			}
			func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				up, err := tls.Dial("tcp", bln.Addr().String(), PinnedTLSConfig(fp))
				if err != nil {
					verdict <- 255
					return
				}
				defer up.Close()
				up.SetDeadline(time.Now().Add(10 * time.Second))
				var m [1]byte
				if _, err := io.ReadFull(c, m[:]); err != nil {
					verdict <- 255
					return
				}
				up.Write(m[:])
				if m[0] == methodPubkey {
					k, _ := readBlob(c, 4096)
					writeBlob(up, k)
				}
				challenge, err := readChallenge(up)
				if err != nil {
					verdict <- 255
					return
				}
				writeBlob(c, challenge) // the other agent's challenge, as its own
				answer, _ := readBlob(c, 4096)
				writeBlob(up, answer)
				var r [1]byte
				if _, err := io.ReadFull(up, r[:]); err != nil {
					r[0] = 0 // closed without an answer: refused
				}
				c.Write(r[:])
				verdict <- r[0]
			}()
		}
	}()

	for _, key := range []string{"", keyPath} {
		token := testToken
		if key != "" {
			token = ""
		}
		conn, err := net.Dial("tcp", aln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cl, err := Dial(conn, PinnedTLSConfig(fp), key, token)
		if err == nil {
			cl.Close()
			t.Errorf("key %q: the client logged in to the forwarder", key)
		}
		switch v := <-verdict; v {
		case 0:
		case 1:
			t.Errorf("key %q: the other agent let the forwarder in with the client's answer", key)
		default:
			t.Fatalf("key %q: the forwarder did not get as far as forwarding the answer", key)
		}
	}
}

// Two relays that present the same certificate: one that an agent registers
// with forwards the other's challenge to the agent and the agent's proof of
// the relay token back. The other refuses the proof, made for another TLS
// session, so the forwarder cannot register there in the agent's name.
func TestRelayProofForwardedBetweenRelaysSharingACertIsRefused(t *testing.T) {
	cert, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "relay"))
	if err != nil {
		t.Fatal(err)
	}
	fp := CertFingerprint(cert)
	cfg := ServerTLSConfig(cert)
	rln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go newRelayHub(testRelayToken, agentCertFP(cfg)).serve(ctx, rln, cfg)

	mln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer mln.Close()
	verdict := make(chan byte, 1)
	go func() {
		c, err := mln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		up, err := tls.Dial("tcp", rln.Addr().String(), PinnedTLSConfig(fp))
		if err != nil {
			verdict <- 255
			return
		}
		defer up.Close()
		up.SetDeadline(time.Now().Add(10 * time.Second))
		challenge, err := readChallenge(up)
		if err != nil {
			verdict <- 255
			return
		}
		writeBlob(c, challenge)
		proof, _ := readBlob(c, 64)
		var role [1]byte
		io.ReadFull(c, role[:])
		id, _ := readBlob(c, maxRelayID)
		writeBlob(up, proof)
		up.Write(role[:])
		writeBlob(up, id)
		var status [1]byte
		if _, err := io.ReadFull(up, status[:]); err != nil {
			status[0] = relayDeny
		}
		c.Write(status[:])
		verdict <- status[0]
	}()

	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	defer rcancel()
	if conn, err := RelayDialAgent(rctx, mln.Addr().String(), fp, testRelayToken, "box", false); err == nil {
		conn.Close()
		t.Error("the agent was registered through the forwarder")
	}
	switch v := <-verdict; v {
	case relayDeny:
	case 255:
		t.Fatal("the forwarder did not get as far as forwarding the proof")
	default:
		t.Fatalf("the other relay answered the forwarded proof with status %d", v)
	}
}
