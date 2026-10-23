// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func runHandshake(t *testing.T, ac *AuthConfig, method byte, token string, signer ssh.Signer) (string, bool) {
	t.Helper()
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	clientErr := make(chan error, 1)
	go func() {
		clientErr <- clientHandshake(cConn, method, token, signer, nil)
	}()

	desc, ok := serverAuthenticate(sConn, ac, nil, authDeadline(), nil)
	if err := <-clientErr; ok && err != nil {
		t.Fatalf("server accepted but client errored: %v", err)
	}
	return desc, ok
}

// authDeadline is when an auth exchange a test starts now must be over.
func authDeadline() time.Time { return time.Now().Add(handshakeTimeout) }

// serverBind completes tc's handshake and returns what an agent presenting
// cfg binds proofs on tc to.
func serverBind(tc *tls.Conn, cfg *tls.Config) ([]byte, error) {
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return sessionBind(tc, agentCertFP(cfg))
}

func newSSHKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return signer, sshPub
}

func keyMap(pubs ...ssh.PublicKey) map[string]ssh.PublicKey {
	m := make(map[string]ssh.PublicKey)
	for _, p := range pubs {
		m[string(p.Marshal())] = p
	}
	return m
}

func TestPubkeyAuthSuccess(t *testing.T) {
	signer, pub := newSSHKey(t)
	ac := &AuthConfig{Keys: keyMap(pub)}
	desc, ok := runHandshake(t, ac, methodPubkey, "", signer)
	if !ok {
		t.Fatalf("expected success, got failure (%s)", desc)
	}
	if !strings.HasPrefix(desc, "pubkey SHA256:") {
		t.Fatalf("expected a fingerprint in desc, got %q", desc)
	}
}

// otherKeySigner offers one key and signs with another.
type otherKeySigner struct {
	ssh.Signer
	pub ssh.PublicKey
}

func (s otherKeySigner) PublicKey() ssh.PublicKey { return s.pub }

// countSigChecks makes verifyAuthSig count its calls until the test ends.
func countSigChecks(t *testing.T) *atomic.Int32 {
	var checks atomic.Int32
	orig := verifyAuthSig
	verifyAuthSig = func(k ssh.PublicKey, data []byte, sig *ssh.Signature) error {
		checks.Add(1)
		return orig(k, data, sig)
	}
	t.Cleanup(func() { verifyAuthSig = orig })
	return &checks
}

// With public-key auth on, the signature a peer sends is checked against the
// key it offers whether or not that key is listed, so how long an attempt
// takes does not tell which keys are.
func TestPubkeySignatureCheckedForEveryKey(t *testing.T) {
	checks := countSigChecks(t)
	signer, pub := newSSHKey(t)
	other, _ := newSSHKey(t)
	ac := &AuthConfig{Keys: keyMap(pub)}
	for _, c := range []struct {
		name   string
		signer ssh.Signer
		ok     bool
	}{
		{"an authorized key", signer, true},
		{"an unknown key", other, false},
		{"an authorized key signed by another", otherKeySigner{other, pub}, false},
	} {
		checks.Store(0)
		if _, ok := runHandshake(t, ac, methodPubkey, "", c.signer); ok != c.ok {
			t.Errorf("%s: accepted %v, want %v", c.name, ok, c.ok)
		}
		if n := checks.Load(); n != 1 {
			t.Errorf("%s: its signature was checked %d times, want once", c.name, n)
		}
	}
}

// Whether a key is listed is answered right for keys of every length and for
// a key that only shares a listed key's start.
func TestListedKeys(t *testing.T) {
	_, ed1 := newSSHKey(t)
	_, ed2 := newSSHKey(t)
	rsa1 := rsaPublicKey(t, 2048, 65537)
	ac := &AuthConfig{Keys: keyMap(ed1, rsa1)}
	for _, c := range []struct {
		name string
		blob []byte
		want bool
	}{
		{"a listed Ed25519 key", ed1.Marshal(), true},
		{"a listed RSA key", rsa1.Marshal(), true},
		{"another Ed25519 key", ed2.Marshal(), false},
		{"a listed key's start", ed1.Marshal()[:40], false},
		{"a listed key and more", append(ed1.Marshal(), 0), false},
		{"nothing", nil, false},
	} {
		if got := ac.listed(c.blob); got != c.want {
			t.Errorf("%s: listed %v, want %v", c.name, got, c.want)
		}
	}
}

// An agent spends nothing on a signature it could never accept: with no keys
// listed it checks none, and a key of a kind it does not take (DSA here, even
// one put on the list behind LoadAuthorizedKeys's back) is refused unchecked.
func TestPubkeySignatureNotCheckedWhenNoKeyCouldPass(t *testing.T) {
	checks := countSigChecks(t)
	signer, _ := newSSHKey(t)
	if _, ok := runHandshake(t, &AuthConfig{Token: "0123456789abcdef0"}, methodPubkey, "", signer); ok {
		t.Fatal("public-key auth passed on an agent with no keys")
	}
	if n := checks.Load(); n != 0 {
		t.Errorf("with no keys listed, %d signatures were checked", n)
	}
	dsaPub := dsaKey(t).pub
	ac := &AuthConfig{Keys: keyMap(dsaPub)}
	desc, ok := runHandshake(t, ac, methodPubkey, "", otherKeySigner{signer, dsaPub})
	if ok {
		t.Fatal("a DSA key was accepted")
	}
	if n := checks.Load(); n != 0 {
		t.Errorf("a DSA key's signature was checked %d times", n)
	}
	if !strings.Contains(desc, "ssh-dss keys are not accepted") {
		t.Errorf("the log does not say why: %q", desc)
	}
}

// testDSAKey is a DSA key in its ssh form, and in the PEM form of a private
// key file. Only its kind matters, so its numbers are random ones of the sizes
// an ssh-dss key has.
type testDSAKey struct {
	pub ssh.PublicKey
	pem []byte
}

func dsaKey(t *testing.T) testDSAKey {
	t.Helper()
	num := func(bits int) *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			t.Fatal(err)
		}
		return n.SetBit(n, bits-1, 1)
	}
	p, q, g := num(1024), num(160), big.NewInt(2)
	y, x := num(1000), num(150)
	pub, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", p, q, g, y}))
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}{0, p, q, g, y, x})
	if err != nil {
		t.Fatal(err)
	}
	return testDSAKey{pub, pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der})}
}

// rsaPublicKey returns an RSA public key with a modulus of exactly bits
// bits and exponent e. Only its size and exponent matter, so the modulus is
// a random odd number rather than a product of two primes.
func rsaPublicKey(t *testing.T, bits, e int) ssh.PublicKey {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	if err != nil {
		t.Fatal(err)
	}
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	pk, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: e})
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// Public-key auth takes Ed25519, ECDSA P-256/P-384/P-521 and RSA keys of
// 1024 to 8192 bits with the exponent 65537, and nothing else, so no key it
// takes costs more than a few milliseconds to check.
func TestAuthKeyKinds(t *testing.T) {
	ecdsaKey := func(c elliptic.Curve) ssh.PublicKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return pk
	}
	_, ed := newSSHKey(t)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sk, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKED25519, edPub, "ssh:"}))
	if err != nil {
		t.Fatal(err)
	}
	caSigner, _ := newSSHKey(t)
	cert := &ssh.Certificate{Key: ed, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		key  ssh.PublicKey
		ok   bool
		fast bool
	}{
		{"ed25519", ed, true, true},
		{"ecdsa P-256", ecdsaKey(elliptic.P256()), true, true},
		{"ecdsa P-384", ecdsaKey(elliptic.P384()), true, false},
		{"ecdsa P-521", ecdsaKey(elliptic.P521()), true, false},
		{"rsa 1024", rsaPublicKey(t, 1024, 65537), true, true},
		{"rsa 3072", rsaPublicKey(t, 3072, 65537), true, true},
		{"rsa 3073", rsaPublicKey(t, 3073, 65537), true, false},
		{"rsa 8192", rsaPublicKey(t, 8192, 65537), true, false},
		{"rsa 1023", rsaPublicKey(t, 1023, 65537), false, false},
		{"rsa 8193", rsaPublicKey(t, 8193, 65537), false, false},
		{"rsa 16384", rsaPublicKey(t, 16384, 65537), false, false},
		{"rsa e=3", rsaPublicKey(t, 2048, 3), false, false},
		{"rsa e=0xffffff", rsaPublicKey(t, 2048, 0xffffff), false, false},
		{"dsa", dsaKey(t).pub, false, false},
		{"sk-ssh-ed25519", sk, false, false},
		{"certificate", cert, false, false},
	} {
		q, err := sigQueue(c.key)
		if (err == nil) != c.ok {
			t.Errorf("%s: accepted %v (%v), want %v", c.name, err == nil, err, c.ok)
			continue
		}
		if c.ok && (q == sigChecks.fast) != c.fast {
			t.Errorf("%s: checked in the fast queue %v, want %v", c.name, q == sigChecks.fast, c.fast)
		}
	}
}

// An authorized_keys line with a key of a kind public-key auth does not take
// is skipped, so a refusal at auth never says whether such a key is listed.
func TestAuthorizedKeysSkipsKeysNotAccepted(t *testing.T) {
	_, plain := newSSHKey(t)
	line := func(k ssh.PublicKey) string { return string(ssh.MarshalAuthorizedKey(k)) }
	path := filepath.Join(t.TempDir(), "authorized_keys")
	notAccepted := line(dsaKey(t).pub) + line(rsaPublicKey(t, 16384, 65537)) +
		line(rsaPublicKey(t, 2048, 0xffffff))
	if err := os.WriteFile(path, []byte(notAccepted+line(plain)), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 || keys[string(plain.Marshal())] == nil {
		t.Fatalf("want only the Ed25519 key, got %d key(s)", len(keys))
	}
	if err := os.WriteFile(path, []byte(notAccepted), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthorizedKeys(path); err == nil {
		t.Fatal("expected an error when no key is of a kind tern accepts")
	}
}

// Arithmetic on the curve of Ed25519 (-x^2 + y^2 = 1 + d x^2 y^2 modulo
// p = 2^255-19), in math/big, to check ed25519SmallOrderY against.
var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, edP)
	}()
)

type edPoint struct{ x, y *big.Int }

// edDecode reads an Ed25519 public key as a verifier does: y, little-endian
// and reduced modulo p, and the x of the sign the top bit gives, which for
// x = 0 is either; ok is false for no point.
func edDecode(enc []byte) (pt edPoint, ok bool) {
	be := make([]byte, len(enc))
	for i, b := range enc {
		be[len(enc)-1-i] = b
	}
	sign := uint(be[0] >> 7)
	be[0] &= 0x7f
	y := new(big.Int).Mod(new(big.Int).SetBytes(be), edP)
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1))
	x2 := new(big.Int).Mul(u, new(big.Int).ModInverse(v.Mod(v, edP), edP))
	x := new(big.Int).ModSqrt(x2.Mod(x2, edP), edP)
	if x == nil {
		return edPoint{}, false
	}
	if x.Sign() != 0 && x.Bit(0) != sign {
		x.Sub(edP, x)
	}
	return edPoint{x, y}, true
}

func edAdd(a, b edPoint) edPoint {
	t := new(big.Int).Mul(edD, new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y)))
	xn := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x))
	yn := new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x))
	xd := new(big.Int).Add(big.NewInt(1), t)
	yd := new(big.Int).Sub(big.NewInt(1), t)
	x := xn.Mul(xn, new(big.Int).ModInverse(xd.Mod(xd, edP), edP))
	y := yn.Mul(yn, new(big.Int).ModInverse(yd.Mod(yd, edP), edP))
	return edPoint{x.Mod(x, edP), y.Mod(y, edP)}
}

func (a edPoint) identity() bool { return a.x.Sign() == 0 && a.y.Cmp(big.NewInt(1)) == 0 }

// edEncode is a's canonical encoding.
func (a edPoint) edEncode() [32]byte {
	var enc [32]byte
	a.y.FillBytes(enc[:])
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		enc[i], enc[j] = enc[j], enc[i]
	}
	enc[31] |= byte(a.x.Bit(0)) << 7
	return enc
}

// ed25519Blob is an ssh-ed25519 public key with the point enc.
func ed25519Blob(t *testing.T, enc []byte) ssh.PublicKey {
	t.Helper()
	pk, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name string
		Key  []byte
	}{ssh.KeyAlgoED25519, enc}))
	if err != nil {
		t.Fatalf("%x: %v", enc, err)
	}
	return pk
}

// An Ed25519 key that is a point of small order, in any of its encodings, is
// never taken: a signature by one needs no private key (for the identity a
// constant one holds for every message). authorized_keys skips it, a client
// refuses it, and offered to an agent it is refused unchecked, even if it is
// on the agent's list. Keys made from private keys are taken.
func TestAuthRefusesSmallOrderEd25519Keys(t *testing.T) {
	// The table holds every point of small order: each listed y, of either
	// sign, is a point whose eighth multiple is the identity, the eight such
	// points are all there, and the only listed y that has another encoding
	// below 2^255 (0 and 1, as p and p+1) has it listed too.
	var encs [][]byte
	raw := map[string]bool{} // the listed y as encoded, not reduced
	for _, y := range ed25519SmallOrderY {
		raw[new(big.Int).SetBytes(reverseBytes(y[:])).String()] = true
		for _, sign := range []byte{0, 0x80} {
			enc := y
			enc[31] |= sign
			pt, ok := edDecode(enc[:])
			if !ok {
				t.Fatalf("%x is not on the curve", enc)
			}
			acc := edPoint{big.NewInt(0), big.NewInt(1)}
			for range 8 {
				acc = edAdd(acc, pt)
			}
			if !acc.identity() {
				t.Fatalf("%x is not of small order", enc)
			}
			encs = append(encs, enc[:])
		}
	}
	var order8 edPoint
	for _, y := range ed25519SmallOrderY {
		pt, _ := edDecode(y[:])
		if dbl := edAdd(pt, pt); !edAdd(dbl, dbl).identity() { // not of order 4 or less
			order8 = pt
			break
		}
	}
	if order8.x == nil {
		t.Fatal("no point of order 8 listed")
	}
	acc := edPoint{big.NewInt(0), big.NewInt(1)}
	for k := range 8 {
		enc := acc.edEncode()
		if !ed25519SmallOrder(enc[:]) {
			t.Fatalf("%d times a point of order 8, %x, is not refused", k, enc)
		}
		acc = edAdd(acc, order8)
	}
	two255 := new(big.Int).Lsh(big.NewInt(1), 255)
	for v := range raw {
		y := mustInt(v)
		if y.Cmp(edP) >= 0 {
			continue
		}
		if alias := new(big.Int).Add(y, edP); alias.Cmp(two255) < 0 && !raw[alias.String()] {
			t.Fatalf("y = %s has a second encoding, %s, not listed", v, alias)
		}
	}
	if len(encs) != 14 {
		t.Fatalf("%d encodings, want 14", len(encs))
	}

	_, good := newSSHKey(t)
	line := func(k ssh.PublicKey) string { return string(ssh.MarshalAuthorizedKey(k)) }
	var lines strings.Builder
	checks := countSigChecks(t)
	for _, enc := range encs {
		pk := ed25519Blob(t, enc)
		if _, err := sigQueue(pk); err == nil {
			t.Fatalf("%x: a key of small order is taken", enc)
		}
		lines.WriteString(line(pk))
		// Listed behind LoadAuthorizedKeys's back, and offered with the
		// signature that holds for the identity: refused, unchecked.
		ac := &AuthConfig{Keys: keyMap(pk, good)}
		identity := make([]byte, ed25519.SignatureSize)
		identity[0] = 1 // R the identity, S zero
		desc, ok := offerKey(t, ac, pk.Marshal(), ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: identity}))
		if ok || !strings.Contains(desc, "small order") {
			t.Fatalf("%x: offered, accepted %v (%s)", enc, ok, desc)
		}
	}
	if n := checks.Load(); n != 0 {
		t.Errorf("%d signatures by keys of small order were checked", n)
	}
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(lines.String()+line(good)), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadAuthorizedKeys(path)
	if err != nil || len(keys) != 1 || keys[string(good.Marshal())] == nil {
		t.Fatalf("authorized_keys with %d keys of small order and one made from a private key: %d loaded, %v", len(encs), len(keys), err)
	}
	for range 1000 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if ed25519SmallOrder(pub) {
			t.Fatalf("a key made from a private key, %x, is refused", pub)
		}
	}
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i, c := range b {
		r[len(b)-1-i] = c
	}
	return r
}

func mustInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return n
}

// offerKey runs one public-key attempt offering the key blob with the
// signature sigBlob against ac, and returns the agent's verdict.
func offerKey(t *testing.T, ac *AuthConfig, blob, sigBlob []byte) (string, bool) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		c.Write([]byte{methodPubkey})
		writeBlob(c, blob)
		if _, err := readBlob(c, 256); err != nil {
			return
		}
		writeBlob(c, sigBlob)
		var b [1]byte
		io.ReadFull(c, b[:])
	}()
	return serverAuthenticate(s, ac, nil, authDeadline(), nil)
}

// The client refuses a key no agent accepts when it loads it, saying why,
// rather than leaving the agent to refuse it without a reason.
func TestClientRefusesKeyNotAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_dsa")
	if err := os.WriteFile(path, dsaKey(t).pem, 0o600); err != nil {
		t.Fatal(err)
	}
	err := PreloadKey(path)
	if err == nil || !strings.Contains(err.Error(), "ssh-dss keys are not accepted") {
		t.Fatalf("a DSA key was loaded, or refused without the reason: %v", err)
	}
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go io.Copy(io.Discard, s)
	if err := clientAuthenticate(c, nil, path, ""); err == nil {
		t.Fatal("a DSA key was used to authenticate")
	}
}

// A check of a key that is slow to check keeps its place for as long again
// as it took, so such checks take at most half the CPU; a fast key's check
// gives its place up at once.
func TestSlowSignatureChecksRest(t *testing.T) {
	const took = 40 * time.Millisecond
	orig := verifyAuthSig
	verifyAuthSig = func(ssh.PublicKey, []byte, *ssh.Signature) error {
		time.Sleep(took)
		return nil
	}
	defer func() { verifyAuthSig = orig }()
	_, pub := newSSHKey(t)
	for _, c := range []struct {
		name     string
		q        chan struct{}
		min, max time.Duration
	}{
		{"slow", sigChecks.slow, 2 * took, 10 * took},
		{"fast", sigChecks.fast, took, 2*took - took/4},
	} {
		start := time.Now()
		if !checkSig(c.q, time.Now().Add(time.Minute), nil, pub, nil, &ssh.Signature{}) {
			t.Fatalf("%s: the check failed", c.name)
		}
		if d := time.Since(start); d < c.min || d > c.max {
			t.Errorf("%s queue: a check that took %s held its place %s, want %s to %s", c.name, took, d, c.min, c.max)
		}
		if len(c.q) != 0 {
			t.Errorf("%s queue: the place was not given back", c.name)
		}
	}
}

// At most as many signature checks run at once as Go runs threads, in each
// of two queues: more wait their turn, a wait ends with the handshake it is
// for, and checks of keys slow to check never hold up those of fast ones.
func TestSignatureChecksQueue(t *testing.T) {
	_, held := newSSHKey(t) // its checks wait until release is closed
	release := make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	var running atomic.Int32
	orig := verifyAuthSig
	verifyAuthSig = func(k ssh.PublicKey, data []byte, sig *ssh.Signature) error {
		if bytes.Equal(k.Marshal(), held.Marshal()) {
			running.Add(1)
			<-release
			return errors.New("held")
		}
		return orig(k, data, sig)
	}
	var holders sync.WaitGroup
	t.Cleanup(func() {
		releaseAll()
		holders.Wait()
		verifyAuthSig = orig
	})
	q := sigChecks.slow
	for range 2 * cap(q) {
		holders.Go(func() { checkSig(q, time.Now().Add(time.Minute), nil, held, nil, &ssh.Signature{}) })
	}
	for deadline := time.Now().Add(5 * time.Second); running.Load() < int32(cap(q)); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d checks are running", running.Load(), cap(q))
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := running.Load(); n != int32(cap(q)) {
		t.Fatalf("%d checks run at once, want at most %d", n, cap(q))
	}

	start := time.Now()
	gaveUp := make(chan bool, 1)
	holders.Go(func() { gaveUp <- !checkSig(q, time.Now().Add(100*time.Millisecond), nil, held, nil, &ssh.Signature{}) })
	select {
	case ok := <-gaveUp:
		if !ok {
			t.Fatal("a check with no place free passed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a check with no place free did not give up at its deadline")
	}
	if d := time.Since(start); d < 90*time.Millisecond {
		t.Errorf("a check with no place free gave up after %s, before its deadline", d)
	}

	// A fast key's check does not wait for the slow ones.
	signer, fastPub := newSSHKey(t)
	msg := []byte("message")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { done <- checkSig(sigChecks.fast, time.Now().Add(time.Minute), nil, fastPub, msg, sig) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("a good signature failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a fast key's check waited for slow ones")
	}
	releaseAll()
	holders.Wait()
	if n := running.Load(); n != int32(2*cap(q)) {
		t.Errorf("%d of %d waiting checks ran once places came free", n, 2*cap(q))
	}
}

// A check whose handshake is over, as when the pre-auth limiter gives its
// slot to a newcomer, is never made, in either queue: one waiting for a
// place leaves the queue as soon as its cut is closed, long before its
// deadline, and one whose cut is closed already is not made, place free or
// not.
func TestSignatureCheckEndsWhenCut(t *testing.T) {
	_, held := newSSHKey(t) // its checks hold their places until released
	_, cutPub := newSSHKey(t)
	var running, cutChecks atomic.Int32
	release := make(chan struct{})
	orig := verifyAuthSig
	verifyAuthSig = func(k ssh.PublicKey, data []byte, sig *ssh.Signature) error {
		switch {
		case bytes.Equal(k.Marshal(), cutPub.Marshal()):
			cutChecks.Add(1)
		case bytes.Equal(k.Marshal(), held.Marshal()):
			running.Add(1)
			<-release
		}
		return errors.New("not checked here")
	}
	var holders sync.WaitGroup
	releaseAll := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() {
		releaseAll()
		holders.Wait()
		verifyAuthSig = orig
	})
	for _, c := range []struct {
		name string
		q    chan struct{}
	}{{"fast", sigChecks.fast}, {"slow", sigChecks.slow}} {
		over := make(chan struct{})
		close(over)
		for range 100 { // with places free, so that both ways in are taken
			if checkSig(c.q, time.Now().Add(time.Minute), over, cutPub, nil, &ssh.Signature{}) {
				t.Fatalf("%s queue: a check for a handshake that was over passed", c.name)
			}
		}

		running.Store(0)
		for range cap(c.q) {
			holders.Go(func() { checkSig(c.q, time.Now().Add(time.Minute), nil, held, nil, &ssh.Signature{}) })
		}
		for deadline := time.Now().Add(5 * time.Second); running.Load() < int32(cap(c.q)); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s queue: %d of %d checks are running", c.name, running.Load(), cap(c.q))
			}
		}
		cut := make(chan struct{})
		waited := make(chan time.Duration, 1)
		holders.Go(func() {
			start := time.Now()
			checkSig(c.q, time.Now().Add(time.Minute), cut, cutPub, nil, &ssh.Signature{})
			waited <- time.Since(start)
		})
		time.Sleep(50 * time.Millisecond)
		close(cut)
		select {
		case d := <-waited:
			if d > 5*time.Second {
				t.Errorf("%s queue: a check waited %s after its cut was closed", c.name, d)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s queue: a check waiting for a place did not leave when its cut was closed", c.name)
		}
		if c.q == sigChecks.fast {
			releaseAll() // the slow queue's turn needs places of its own
			holders.Wait()
			release = make(chan struct{})
			releaseAll = sync.OnceFunc(func() { close(release) })
		}
	}
	releaseAll()
	holders.Wait()
	if n := cutChecks.Load(); n != 0 {
		t.Errorf("%d checks were made for handshakes that were over", n)
	}
}

// sigCheckGoroutines counts the goroutines in checkSig: waiting for a place,
// checking, or resting.
func sigCheckGoroutines() int {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 2)
	return strings.Count(b.String(), "tern.checkSig(")
}

// pubkeyAttempt runs an unauthenticated public-key attempt from src to an
// agent at addr presenting fp, offering pub with sig, and returns the
// connection, still open, once sig is sent.
func pubkeyAttempt(t *testing.T, addr, fp string, src net.IP, pub ssh.PublicKey, sig []byte) net.Conn {
	t.Helper()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: src}, Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, PinnedTLSConfig(fp))
	c.SetDeadline(time.Now().Add(time.Minute))
	if err := c.Handshake(); err != nil {
		t.Fatalf("attempt from %s: %v", src, err)
	}
	c.Write([]byte{methodPubkey})
	writeBlob(c, pub.Marshal())
	if _, err := readChallenge(c); err != nil {
		t.Fatalf("attempt from %s: %v", src, err)
	}
	writeBlob(c, sig)
	return c
}

// A handshake that loses its slot under the pre-auth limiter, as those of a
// full listener, /56 or /48 do, leaves the signature check queue at once and
// is never checked, in either queue: the checks waiting are never more than
// the handshakes the limiter holds, whatever the peers send, and once places
// come free only theirs are made, besides those already under way.
func TestHandshakeLosingItsSlotLeavesSignatureQueue(t *testing.T) {
	probe := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 3, 1, 1)}, Timeout: 2 * time.Second}
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		c, err := probe.Dial("tcp", ln.Addr().String())
		ln.Close()
		if err != nil {
			t.Skipf("cannot dial from a second loopback address: %v", err)
		}
		c.Close()
	}
	// Checks wait at the gate until it is opened, holding their places.
	var gate atomic.Pointer[chan struct{}]
	shut := func() chan struct{} {
		g := make(chan struct{})
		gate.Store(&g)
		return g
	}
	var running, checked atomic.Int32
	orig := verifyAuthSig
	verifyAuthSig = func(ssh.PublicKey, []byte, *ssh.Signature) error {
		checked.Add(1)
		running.Add(1)
		defer running.Add(-1)
		<-*gate.Load()
		return errors.New("not checked here")
	}
	open := shut()
	t.Cleanup(func() {
		select {
		case <-open:
		default:
			close(open)
		}
		for deadline := time.Now().Add(20 * time.Second); sigCheckGoroutines() > 0 && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		verifyAuthSig = orig
	})
	if n := sigCheckGoroutines(); n != 0 {
		t.Fatalf("%d goroutines are in checkSig before the test", n)
	}

	a, fp := newTestAgent(t)
	_, listed := newSSHKey(t)
	a.Auth.Keys = keyMap(listed)
	_, edPub := newSSHKey(t) // not listed: its check is made all the same
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521Pub, err := ssh.NewPublicKey(&p521.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	junk := func(format string, blob []byte) []byte {
		return ssh.Marshal(&ssh.Signature{Format: format, Blob: blob})
	}
	for _, c := range []struct {
		name string
		pub  ssh.PublicKey
		sig  []byte
	}{
		{"fast", edPub, junk(ssh.KeyAlgoED25519, make([]byte, ed25519.SignatureSize))},
		{"slow", p521Pub, junk(ssh.KeyAlgoECDSA521, ssh.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(1)}))},
	} {
		q, err := sigQueue(c.pub)
		if err != nil {
			t.Fatal(err)
		}
		const held = 16
		n := 4 * (held + cap(q))
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		lim := &PreAuthLimiter{max: held}
		go a.serveListener(ctx, ln, lim)
		if c.name != "fast" {
			open = shut()
		}
		checked.Store(0)
		var conns []net.Conn
		for i := range n {
			conns = append(conns, pubkeyAttempt(t, ln.Addr().String(), fp, net.IPv4(127, 3, byte(1+i/250), byte(1+i%250)), c.pub, c.sig))
		}
		waiting := 0
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			total, _, _ := lim.books()
			if waiting = sigCheckGoroutines() - int(running.Load()); waiting >= total {
				break
			}
		}
		time.Sleep(100 * time.Millisecond) // and let any stragglers in
		total, _, _ := lim.books()
		waiting = sigCheckGoroutines() - int(running.Load())
		if waiting > total {
			t.Errorf("%s queue: after %d attempts, %d checks wait for a place while the limiter holds %d handshakes", c.name, n, waiting, total)
		}
		if r := int(running.Load()); r > cap(q) {
			t.Errorf("%s queue: %d checks under way, past its %d places", c.name, r, cap(q))
		}
		underWay := checked.Load()
		close(open)
		for deadline := time.Now().Add(20 * time.Second); sigCheckGoroutines() > 0; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s queue: %d goroutines still in checkSig", c.name, sigCheckGoroutines())
			}
		}
		if made := int(checked.Load() - underWay); made > total {
			t.Errorf("%s queue: %d checks made once places came free, for %d handshakes the limiter held", c.name, made, total)
		}
		t.Logf("%s queue: %d attempts, %d handshakes held, %d checks waiting, %d under way, %d made after", c.name, n, total, waiting, underWay, checked.Load()-underWay)
		for _, conn := range conns {
			conn.Close()
		}
		cancel()
	}
}

func TestPubkeyAuthUnauthorizedKey(t *testing.T) {
	clientSigner, _ := newSSHKey(t)
	_, otherPub := newSSHKey(t)
	ac := &AuthConfig{Keys: keyMap(otherPub)}
	if _, ok := runHandshake(t, ac, methodPubkey, "", clientSigner); ok {
		t.Fatal("expected failure for unauthorized key")
	}
}

func TestPubkeyAuthDisabled(t *testing.T) {
	signer, _ := newSSHKey(t)
	ac := &AuthConfig{Token: "0123456789abcdef0"}
	if _, ok := runHandshake(t, ac, methodPubkey, "", signer); ok {
		t.Fatal("expected failure when pubkey auth is disabled")
	}
}

func TestTokenAuth(t *testing.T) {
	ac := &AuthConfig{Token: "0123456789abcdef0"}
	if _, ok := runHandshake(t, ac, methodTokenHMAC, "0123456789abcdef0", nil); !ok {
		t.Fatal("expected success for correct token")
	}
	if _, ok := runHandshake(t, ac, methodTokenHMAC, "wrong-token-here!", nil); ok {
		t.Fatal("expected failure for wrong token")
	}
}

// TestRawTokenRefused: an agent takes a proof of the token only, never the
// token itself, so no client can be talked into sending it.
func TestRawTokenRefused(t *testing.T) {
	const token = "0123456789abcdef0"
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go io.Copy(io.Discard, c) // the agent's answer
	go func() {
		c.Write([]byte{1}) // a method byte that would send the raw token
		writeBlob(c, []byte(token))
	}()
	if _, ok := serverAuthenticate(s, &AuthConfig{Token: token}, nil, authDeadline(), nil); ok {
		t.Fatal("the agent accepted the raw token")
	}
}

func TestParsesRealOpenSSHAuthorizedKey(t *testing.T) {
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII3GTBNp1pA/aYTsStOGI+MSNMHyj4EQB7azGqYrD6YG tester@ternimal\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte("# a comment\n\n"+line), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

// TestAuthorizedKeysSkipsOptions: per-key options are not enforced, so a key
// restricted with from=/command=/restrict must not be granted full access.
func TestAuthorizedKeysSkipsOptions(t *testing.T) {
	_, plain := newSSHKey(t)
	_, restricted := newSSHKey(t)
	line := func(opts string, k ssh.PublicKey) string { return opts + string(ssh.MarshalAuthorizedKey(k)) }
	path := filepath.Join(t.TempDir(), "authorized_keys")

	data := line("", plain) + line(`from="203.0.113.1",command="/bin/false",restrict `, restricted)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 || keys[string(plain.Marshal())] == nil {
		t.Fatalf("want only the option-free key, got %d key(s)", len(keys))
	}

	// A file whose keys all carry options is an error, not an empty allow-list.
	if err := os.WriteFile(path, []byte(line("restrict ", restricted)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthorizedKeys(path); err == nil {
		t.Fatal("expected an error when every key carries options")
	}
}

// TestPreloadKeyIsReused: once loaded, a key is served from the cache, so an
// encrypted key prompts once and reconnects never read the file again.
func TestPreloadKeyIsReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_test")
	if _, err := GenerateKeyFiles(path, "t"); err != nil {
		t.Fatal(err)
	}
	if err := PreloadKey(path); err != nil {
		t.Fatalf("preload: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(path); err != nil {
		t.Fatalf("cached key was not reused: %v", err)
	}
}

func TestKeygenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "id")
	if _, err := GenerateKeyFiles(priv, "tester@tern"); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keys, err := LoadAuthorizedKeys(priv + ".pub")
	if err != nil {
		t.Fatalf("load authorized_keys: %v", err)
	}
	signer, err := loadSigner(priv)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	ac := &AuthConfig{Keys: keys}
	if _, ok := runHandshake(t, ac, methodPubkey, "", signer); !ok {
		t.Fatal("handshake with generated key pair failed")
	}
}

// Certificate lines in authorized_keys are skipped, not accepted as keys.
func TestAuthorizedKeysSkipsCertificates(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	plainPub, _, _ := ed25519.GenerateKey(rand.Reader)

	userSSH, _ := ssh.NewPublicKey(userPub)
	cert := &ssh.Certificate{Key: userSSH, CertType: ssh.UserCert, KeyId: "k",
		ValidBefore: ssh.CertTimeInfinity}
	cert.SignCert(rand.Reader, caSigner)

	plainSSH, _ := ssh.NewPublicKey(plainPub)
	path := filepath.Join(t.TempDir(), "ak")
	os.WriteFile(path, append(ssh.MarshalAuthorizedKey(plainSSH), ssh.MarshalAuthorizedKey(cert)...), 0o600)

	keys, err := LoadAuthorizedKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[string(plainSSH.Marshal())] == nil {
		t.Fatalf("want only the plain key, got %d key(s)", len(keys))
	}
	if keys[string(cert.Marshal())] != nil {
		t.Fatal("certificate was accepted as a key")
	}

	// a file with only a certificate line -> no usable keys
	only := filepath.Join(t.TempDir(), "certonly")
	os.WriteFile(only, ssh.MarshalAuthorizedKey(cert), 0o600)
	if _, err := LoadAuthorizedKeys(only); err == nil {
		t.Fatal("a certificate-only authorized_keys yielded usable keys")
	}
}

// The client proves the token with an HMAC and never puts it on the wire;
// the proof is bound to the agent's certificate.
func TestTokenHMACProofNotRawAndBound(t *testing.T) {
	secret := "a-real-reusable-token-abcdefgh"
	cert, _ := LoadOrCreateCert(filepath.Join(t.TempDir(), "a"))
	cfg := ServerTLSConfig(cert)
	sconn, cconn := loopbackPair(t)

	type cap struct {
		method byte
		proof  []byte
	}
	got := make(chan cap, 1)
	go func() {
		srv := tls.Server(sconn, cfg)
		if srv.Handshake() != nil {
			return
		}
		var m [1]byte
		srv.Read(m[:])
		challenge := make([]byte, 32)
		rand.Read(challenge)
		writeBlob(srv, challenge)
		proof, _ := readBlob(srv, 1024)
		srv.Write([]byte{1})
		got <- cap{m[0], proof}
	}()
	cli := tls.Client(cconn, PinnedTLSConfig(CertFingerprint(cert)))
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := clientAuthenticate(cli, connCertFP(cli), "", secret); err != nil {
		t.Fatal(err)
	}
	c := <-got
	if c.method != methodTokenHMAC {
		t.Fatalf("client used method %d, want methodTokenHMAC", c.method)
	}
	if bytes.Contains(c.proof, []byte(secret)) || len(c.proof) != 32 {
		t.Fatalf("proof leaks the token or is not a 32-byte MAC (len=%d)", len(c.proof))
	}
	// Same inputs but a different agent fingerprint (bind) -> different proof.
	a := tokenProof(secret, []byte("bind-A"), c.proof)
	b := tokenProof(secret, []byte("bind-B"), c.proof)
	if bytes.Equal(a, b) {
		t.Fatal("proof is not bound to the agent certificate")
	}
}

// RSA auth uses rsa-sha2-256; a legacy SHA-1 ssh-rsa signature is rejected.
func TestRSAAuthRejectsSHA1(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(rk)
	ac := &AuthConfig{Keys: keyMap(signer.PublicKey())}
	bind := []byte("bind-fingerprint")
	challenge := []byte("challenge-value-0123456789abcdef")

	// SHA-256 (what the client sends) is accepted.
	good, _ := signChallenge(signer, authMessage(challenge, bind))
	if !verifyWith(ac, signer.PublicKey(), challenge, bind, good) {
		t.Fatal("rsa-sha2-256 signature was rejected")
	}
	// Legacy SHA-1 ssh-rsa is rejected.
	bad, _ := signer.Sign(rand.Reader, authMessage(challenge, bind)) // defaults to ssh-rsa (SHA-1)
	if bad.Format != ssh.KeyAlgoRSA {
		t.Skipf("signer did not produce a SHA-1 ssh-rsa signature (%s); nothing to assert", bad.Format)
	}
	if verifyWith(ac, signer.PublicKey(), challenge, bind, bad) {
		t.Fatal("legacy SHA-1 ssh-rsa signature was accepted")
	}
}

// verifyWith mirrors the agent's accept rule: reject ssh-rsa, else Verify.
func verifyWith(ac *AuthConfig, pub ssh.PublicKey, challenge, bind []byte, sig *ssh.Signature) bool {
	if _, ok := ac.Keys[string(pub.Marshal())]; !ok {
		return false
	}
	if sig.Format == ssh.KeyAlgoRSA {
		return false
	}
	return pub.Verify(authMessage(challenge, bind), sig) == nil
}

// Keygen must not write through an existing path or a symlink.
func TestKeygenRefusesExistingAndSymlink(t *testing.T) {
	dir := t.TempDir()
	// existing private-key path -> refused, nothing overwritten
	p := filepath.Join(dir, "id")
	os.WriteFile(p, []byte("original"), 0o600)
	if _, err := GenerateKeyFiles(p, "c"); err == nil {
		t.Fatal("keygen overwrote an existing key file")
	}
	if b, _ := os.ReadFile(p); string(b) != "original" {
		t.Fatal("keygen clobbered the existing file")
	}
	if runtime.GOOS != "windows" {
		victim := filepath.Join(dir, "victim")
		os.WriteFile(victim, []byte("keep"), 0o600)
		link := filepath.Join(dir, "id2")
		os.Symlink(victim, link)
		if _, err := GenerateKeyFiles(link, "c"); err == nil {
			t.Fatal("keygen wrote through a symlink")
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Fatal("keygen wrote through the symlink to the target")
		}
	}
}

// A UTF-8 BOM must not hide the first authorized key.
func TestAuthorizedKeysSkipsBOM(t *testing.T) {
	_, pub := newSSHKey(t)
	path := filepath.Join(t.TempDir(), "ak")
	os.WriteFile(path, append([]byte("\xef\xbb\xbf"), ssh.MarshalAuthorizedKey(pub)...), 0o600)
	keys, err := LoadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("BOM-prefixed authorized_keys rejected: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1 (BOM hid the first key)", len(keys))
	}
}
