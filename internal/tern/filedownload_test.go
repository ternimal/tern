// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// relayGate holds what a relay passes from the agent to the client while it
// is held.
type relayGate struct {
	mu   sync.Mutex
	held chan struct{} // while held: closed on release
}

func (g *relayGate) hold() {
	g.mu.Lock()
	if g.held == nil {
		g.held = make(chan struct{})
	}
	g.mu.Unlock()
}

func (g *relayGate) release() {
	g.mu.Lock()
	if g.held != nil {
		close(g.held)
		g.held = nil
	}
	g.mu.Unlock()
}

func (g *relayGate) wait() {
	g.mu.Lock()
	c := g.held
	g.mu.Unlock()
	if c != nil {
		<-c
	}
}

// dialSlowed connects a client to a through a relay that passes the agent's
// bytes on in 16 KiB pieces a millisecond apart, so a download of a few
// megabytes takes a moment, and holds them while the returned gate is held:
// a test can act while a download is on its way.
func dialSlowed(t *testing.T, a *Agent, fp string) (*Client, *relayGate) {
	t.Helper()
	sconn, fromAgent := loopbackPair(t)
	toClient, cconn := loopbackPair(t)
	go a.Serve(sconn, "test")
	g := new(relayGate)
	t.Cleanup(g.release)
	go func() {
		io.Copy(fromAgent, toClient)
		fromAgent.Close()
	}()
	go func() {
		defer toClient.Close()
		buf := make([]byte, 16<<10)
		for {
			n, err := fromAgent.Read(buf)
			if n > 0 {
				g.wait()
				if _, err := toClient.Write(buf[:n]); err != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				return
			}
		}
	}()
	cl, err := Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return cl, g
}

// holdOnTemp waits for a file matching pattern to appear in dir, as the
// temporary file of a download on its way does, and holds g. It fails if
// the download ends first (done) or nothing appears.
func holdOnTemp(t *testing.T, g *relayGate, dir, pattern string, done <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if m, _ := filepath.Glob(filepath.Join(dir, pattern)); len(m) > 0 {
			g.hold()
			select {
			case err := <-done:
				t.Fatalf("the download ended before it could be held: %v", err)
			default:
			}
			return
		}
		select {
		case err := <-done:
			t.Fatalf("the download ended before its temporary file was seen: %v", err)
		case <-time.After(2 * time.Millisecond):
		}
	}
	t.Fatalf("no temporary file %s appeared in %s", pattern, dir)
}

// A download that comes up short, here because the file shrank on the agent
// while it was being sent, fails and leaves the destination as it was, with
// no temporary file beside it.
func TestTruncatedDownloadLeavesNoTemp(t *testing.T) {
	a, fp := newTestAgent(t)
	cl, gate := dialSlowed(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "src.log")
	if err := os.WriteFile(src, bytes.Repeat([]byte("log line\n"), 400000), 0o644); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(dir, "dst")
	if err := os.Mkdir(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dstDir, "copy.log")
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cl.CopyFrom(src, dst) }()
	holdOnTemp(t, gate, dstDir, ".copy.log.tern-*", done)
	if err := os.Truncate(src, 100); err != nil {
		t.Fatal(err)
	}
	gate.release()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "download incomplete") {
		t.Fatalf("a short download: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Errorf("the destination now holds %d bytes", len(b))
	}
	if ents, _ := os.ReadDir(dstDir); len(ents) != 1 {
		t.Errorf("the destination directory holds %d entries, want the destination alone", len(ents))
	}
}

// A download destination must name a file: one ending in a separator, or in
// "." or "..", is refused before anything is written.
func TestDownloadDirectoryPathRefused(t *testing.T) {
	a, fp := newTestAgent(t)
	cl := dialTest(t, a, fp)
	defer cl.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dst + string(os.PathSeparator), filepath.Join(dst, "x") + string(os.PathSeparator) + ".", dst + string(os.PathSeparator) + ".."} {
		if err := cl.CopyFrom(src, p); err == nil || !strings.Contains(err.Error(), "not a file path") {
			t.Errorf("CopyFrom(%q) = %v, want a refusal", p, err)
		}
	}
	if ents, _ := os.ReadDir(dst); len(ents) != 0 {
		t.Errorf("the refused downloads left %d entries", len(ents))
	}
}

// A malicious agent must not get the client to create a setuid/setgid file.
func TestCopyFromStripsSetidBits(t *testing.T) {
	cert, _ := LoadOrCreateCert(filepath.Join(t.TempDir(), "evil"))
	cfg := ServerTLSConfig(cert)
	sconn, cconn := loopbackPair(t)
	go func() {
		srv := tls.Server(sconn, cfg)
		bind, err := serverBind(srv, cfg)
		if err != nil {
			return
		}
		if _, ok := serverAuthenticate(srv, &AuthConfig{Token: testToken}, bind, authDeadline(), nil); !ok {
			return
		}
		sess, _ := muxServer(srv)
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		readHeader(st)
		writeReply(st, streamReply{OK: true, Size: 2, FileMode: uint32(os.ModeSetuid | os.ModeSetgid | 0o777)})
		st.Write([]byte("hi"))
		time.Sleep(time.Second)
	}()
	cl, err := Dial(cconn, PinnedTLSConfig(CertFingerprint(cert)), "", testToken)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	dst := filepath.Join(t.TempDir(), "out")
	if err := cl.CopyFrom("/x", dst); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dst)
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("downloaded file kept special bits: %v", fi.Mode())
	}
}
