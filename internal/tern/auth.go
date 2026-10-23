// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// GenToken returns a fresh random auth token (24 random bytes, base64).
func GenToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("tern: crypto/rand failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Auth method selector, sent as the first byte of the post-TLS handshake;
// any other value is refused. No method sends the raw token: a token only
// ever crosses the wire as a proof.
const (
	methodPubkey    byte = 2
	methodTokenHMAC byte = 3 // client proves the token with an HMAC over a challenge

	// challengeLen is the size of the agent's or relay's fresh challenge. The
	// client accepts no other size: the binding before it is empty on a
	// plaintext connection, so a longer challenge could carry another agent's
	// binding (see sessionBind) and make this proof valid for that agent's
	// TLS connection.
	challengeLen = 32
)

// tokenAuthContext and relayAuthContext domain-separate the agent and relay
// token HMACs from each other and from any other use of a token as an HMAC
// key.
var (
	tokenAuthContext = []byte("tern-token-auth-v1")
	relayAuthContext = []byte("tern-relay-auth-v1")
)

// tokenProof is the client's response in HMAC token auth: HMAC-SHA256 keyed by
// the token over the TLS connection's binding (bind, see sessionBind) and a
// fresh challenge, so the raw token never crosses the wire and a proof cannot
// be replayed to a different agent or connection.
func tokenProof(token string, bind, challenge []byte) []byte {
	return proofMAC(tokenAuthContext, token, bind, challenge)
}

// relayTokenProof is how an agent or client proves the relay token to a relay
// (ternr or rtern): as tokenProof, over the binding of its TLS connection to
// the relay, so a relay never learns the token, and one named by someone
// else's tern1: string gets nothing it could replay to the relay the token is
// for.
func relayTokenProof(token string, bind, challenge []byte) []byte {
	return proofMAC(relayAuthContext, token, bind, challenge)
}

func proofMAC(context []byte, token string, bind, challenge []byte) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write(context)
	m.Write(bind)
	m.Write(challenge)
	return m.Sum(nil)
}

// authContext domain-separates signatures so a tern auth signature can never be
// replayed as a signature for another protocol made with the same key (and
// vice versa).
var authContext = []byte("tern-pubkey-auth-v1")

// authMessage is what the client signs and the agent verifies. bind is the
// TLS channel binding (see sessionBind), so a signature captured on one
// connection cannot be forwarded to authenticate on another.
func authMessage(challenge, bind []byte) []byte {
	m := make([]byte, 0, len(authContext)+len(bind)+len(challenge))
	m = append(m, authContext...)
	m = append(m, bind...)
	m = append(m, challenge...)
	return m
}

// connCertFP returns the SHA-256 of the peer's TLS leaf certificate (the client
// binds its proof to it, see sessionBind). Returns nil for a non-TLS conn,
// e.g. tests over net.Pipe.
func connCertFP(conn net.Conn) []byte {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
	return sum[:]
}

// agentCertFP returns the SHA-256 of the agent's own TLS leaf certificate, the
// agent side of the same channel binding; a relay binds proofs to its own
// certificate the same way.
func agentCertFP(cfg *tls.Config) []byte {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return nil
	}
	sum := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return sum[:]
}

// exporterLabel names the keying material exported from a TLS session
// (RFC 8446 section 7.5) that every auth proof is bound to.
const exporterLabel = "EXPORTER-tern-auth-v1"

// sessionBind returns what a proof made over tc, whose handshake is done, is
// bound to: certFP, the fingerprint of the certificate the server presents,
// then 32 bytes of keying material exported from tc's own TLS session, which
// only the two ends of that session can derive. A proof is so worth nothing
// on any other connection, even one to a server that holds the same
// certificate and key and forwards the challenge and the proof. Both ends
// compute it: the client with connCertFP, an agent or relay with
// agentCertFP. It fails for a session that cannot export keying material
// safely (TLS 1.2 without the extended master secret), which tern's own ends
// never negotiate.
func sessionBind(tc *tls.Conn, certFP []byte) ([]byte, error) {
	cs := tc.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("binding auth to the TLS session: %w", err)
	}
	bind := make([]byte, 0, len(certFP)+len(ekm))
	return append(append(bind, certFP...), ekm...), nil
}

// AuthConfig holds the credentials an agent accepts. At least one method must
// be enabled.
type AuthConfig struct {
	Token string                   // shared secret; token auth is off unless it is at least 16 chars
	Keys  map[string]ssh.PublicKey // keyed by string(pub.Marshal()); empty disables pubkey auth
}

// TokenEnabled reports whether token auth is active (token present and long enough).
func (a *AuthConfig) TokenEnabled() bool { return len(a.Token) >= 16 }

// PubkeyEnabled reports whether OpenSSH public-key auth is active.
func (a *AuthConfig) PubkeyEnabled() bool { return len(a.Keys) > 0 }

// listed reports whether blob, a public key in wire form, is one of a.Keys.
// It compares blob with every listed key of its length in full, so that the
// answer takes as long whichever it is; a key's length says only what kind
// of key it is, which the peer that offered it knows.
func (a *AuthConfig) listed(blob []byte) bool {
	found := 0
	for k := range a.Keys {
		if len(k) != len(blob) {
			continue
		}
		var diff byte
		for i := range len(blob) {
			diff |= k[i] ^ blob[i]
		}
		found |= subtle.ConstantTimeByteEq(diff, 0)
	}
	return found == 1
}

// Methods lists the enabled auth methods, for logging.
func (a *AuthConfig) Methods() []string {
	var m []string
	if a.TokenEnabled() {
		m = append(m, "token")
	}
	if a.PubkeyEnabled() {
		m = append(m, fmt.Sprintf("pubkey (%d key(s))", len(a.Keys)))
	}
	return m
}

// serverAuthenticate runs the handshake on an accepted (already TLS-wrapped)
// connection, which must be over by deadline or once cut is closed, and
// reports a short method description plus success.
func serverAuthenticate(conn net.Conn, a *AuthConfig, bind []byte, deadline time.Time, cut <-chan struct{}) (string, bool) {
	var method [1]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		return "", false
	}
	switch method[0] {
	case methodTokenHMAC:
		challenge := make([]byte, challengeLen)
		if _, err := rand.Read(challenge); err != nil {
			return "token", false
		}
		if err := writeBlob(conn, challenge); err != nil {
			return "token", false
		}
		proof, err := readBlob(conn, 1024)
		if err != nil {
			return "token", false
		}
		if a.TokenEnabled() && hmac.Equal(proof, tokenProof(a.Token, bind, challenge)) {
			conn.Write([]byte{1})
			return "token", true
		}
		conn.Write([]byte{0})
		return "token", false
	case methodPubkey:
		return serverAuthPubkey(conn, a, bind, deadline, cut)
	default:
		conn.Write([]byte{0})
		return fmt.Sprintf("unknown-method-%d", method[0]), false
	}
}

// Public-key auth takes Ed25519 keys, ECDSA keys on P-256, P-384 and P-521,
// and RSA keys with the public exponent 65537 and a modulus of
// minRSABits to maxRSABits bits. Every other kind (DSA, security keys,
// certificates, a larger or odd RSA key) is refused before its signature is
// looked at, by the agent and by LoadAuthorizedKeys alike, so no key that an
// agent would spend more than a few milliseconds checking can be listed,
// and an offered key of a kind that is refused could never have been listed:
// the refusal says nothing about which keys are.
const (
	minRSABits = 1024 // the least crypto/rsa verifies at all
	maxRSABits = 8192
	rsaKeyE    = 65537

	acceptedKeys = "ssh-ed25519, ecdsa-sha2-nistp256/384/521, and ssh-rsa with 1024 to 8192 bits and the exponent 65537"
)

// fastRSABits is the largest RSA modulus whose signature counts as fast to
// check (well under a millisecond, as for Ed25519 and P-256).
const fastRSABits = 3072

// sigChecks bounds the public-key signature checks running at once on an
// agent, in two queues: one for keys that are fast to check and one for the
// rest (P-384, P-521, RSA over fastRSABits bits, up to a few milliseconds
// each), each letting as many checks run as Go runs threads. A check in the
// slow queue then keeps its place for as long again as it took (see
// checkSig), so those checks take at most half the agent's CPU time. A flood
// of unauthenticated handshakes offering keys that are slow to check so waits
// its turn rather than taking the CPU from the sessions and handshakes
// already under way, and does not hold up the check of a fast key, such as
// the Ed25519 key `tern keygen` makes. The queue a check waits in depends only
// on the kind of key offered, never on whether it is listed.
var sigChecks = struct{ fast, slow chan struct{} }{
	make(chan struct{}, runtime.GOMAXPROCS(0)),
	make(chan struct{}, runtime.GOMAXPROCS(0)),
}

// checkAuthKey says why public-key auth does not take k, or returns nil.
func checkAuthKey(k ssh.PublicKey) error {
	_, err := sigQueue(k)
	return err
}

// sigQueue returns the queue a check of a signature by k waits in, or why
// public-key auth does not take k.
func sigQueue(k ssh.PublicKey) (chan struct{}, error) {
	switch k.Type() {
	case ssh.KeyAlgoED25519:
		ck, ok := k.(ssh.CryptoPublicKey)
		if !ok {
			return nil, errors.New("this Ed25519 key cannot be read")
		}
		pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("this Ed25519 key cannot be read")
		}
		if ed25519SmallOrder(pub) {
			return nil, errors.New("Ed25519 keys of small order are not accepted: a signature by one needs no private key")
		}
		return sigChecks.fast, nil
	case ssh.KeyAlgoECDSA256:
		return sigChecks.fast, nil
	case ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return sigChecks.slow, nil
	case ssh.KeyAlgoRSA:
		ck, ok := k.(ssh.CryptoPublicKey)
		if !ok {
			return nil, errors.New("this RSA key cannot be read")
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("this RSA key cannot be read")
		}
		if rk.E != rsaKeyE {
			return nil, fmt.Errorf("RSA keys with the public exponent %d are not accepted", rk.E)
		}
		switch bits := rk.N.BitLen(); {
		case bits < minRSABits || bits > maxRSABits:
			return nil, fmt.Errorf("%d-bit RSA keys are not accepted", bits)
		case bits <= fastRSABits:
			return sigChecks.fast, nil
		}
		return sigChecks.slow, nil
	}
	return nil, fmt.Errorf("%s keys are not accepted", k.Type())
}

// ed25519SmallOrderY holds the y coordinates of the eight points of small
// order on the curve of Ed25519 as an Ed25519 public key encodes them: 32
// bytes little-endian with the top bit, the sign of x, cleared. They are 1
// (order 1), p-1 (order 2), 0 (order 4) and the two of order 8, y8 and p-y8,
// for the field prime p = 2^255-19, and the encodings p and p+1 of 0 and 1
// that a decoder reduces modulo p; each with either sign is a point of small
// order (with x = 0 the sign bit is ignored).
var ed25519SmallOrderY = [...][ed25519.PublicKeySize]byte{
	{0x01},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// ed25519SmallOrder reports whether pub, a 32-byte Ed25519 public key, is a
// point of small order, in any of its encodings. Go's Ed25519 verifier, as
// most do, takes such a key, and a signature by it can be made without any
// private key: for the identity one constant signature holds for every
// message, for the others one of eight guesses often does. No key made from
// a private key is one of them; ssh-keygen and tern keygen never make one.
func ed25519SmallOrder(pub ed25519.PublicKey) bool {
	var y [ed25519.PublicKeySize]byte
	copy(y[:], pub)
	y[len(y)-1] &= 0x7f
	for _, s := range ed25519SmallOrderY {
		if y == s {
			return true
		}
	}
	return false
}

// verifyAuthSig checks a public-key auth signature; tests count its calls.
var verifyAuthSig = ssh.PublicKey.Verify

// checkSig checks sig, a signature of data by k, once a place in q is free,
// and reports whether it holds. It gives up, reporting false, when the
// handshake it is for is over: at deadline, or once cut is closed, as when
// the pre-auth limiter gives that handshake's slot to a newcomer (see
// preAuthTicket.cut). Such a check leaves the queue at once and is never
// made, so the checks waiting are never more than the handshakes the
// limiter holds; only one already under way, at most one per place in q,
// may still finish for a handshake that is over. In the slow queue it keeps
// its place for as long again as the check took before giving it to the
// next: checks run back to back would otherwise take a CPU whole, as each
// hands the CPU straight to the next one waiting, while a sleeping one
// leaves it to everything else.
func checkSig(q chan struct{}, deadline time.Time, cut <-chan struct{}, k ssh.PublicKey, data []byte, sig *ssh.Signature) bool {
	wait := time.NewTimer(time.Until(deadline))
	defer wait.Stop()
	select {
	case q <- struct{}{}:
	case <-wait.C:
		return false
	case <-cut:
		return false
	}
	defer func() { <-q }()
	select {
	case <-cut: // over just as the place came free
		return false
	default:
	}
	if !time.Now().Before(deadline) {
		return false
	}
	start := time.Now()
	ok := verifyAuthSig(k, data, sig) == nil
	if q == sigChecks.slow {
		time.Sleep(time.Since(start))
	}
	return ok
}

func serverAuthPubkey(conn net.Conn, a *AuthConfig, bind []byte, deadline time.Time, cut <-chan struct{}) (string, bool) {
	// Always run the full challenge/response even when the key is unknown, so
	// the message flow is the same either way (only the final accept/reject
	// byte differs).
	pubBlob, err := readBlob(conn, 4096)
	if err != nil {
		return "pubkey", false
	}
	challenge := make([]byte, challengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return "pubkey", false
	}
	if err := writeBlob(conn, challenge); err != nil {
		return "pubkey", false
	}
	sigBlob, err := readBlob(conn, 4096)
	if err != nil {
		return "pubkey", false
	}

	// With public-key auth on, the signature by a key of an accepted kind is
	// checked whether or not that key is listed, and whether it is listed is
	// found in the same time either way (see listed), so how long an attempt
	// takes does not tell a peer which keys are. A key of a kind that is
	// refused is never checked: none is listed (see sigQueue). With no keys
	// listed nothing is checked.
	ok, authorized := false, false
	offered, perr := ssh.ParsePublicKey(pubBlob)
	var kindErr error
	if perr == nil {
		var q chan struct{}
		if q, kindErr = sigQueue(offered); kindErr == nil && a.PubkeyEnabled() {
			authorized = a.listed(pubBlob)
			var sig ssh.Signature
			// Reject legacy SHA-1 RSA signatures (format "ssh-rsa"); require
			// rsa-sha2-256/512, which the tern client always sends.
			signed := ssh.Unmarshal(sigBlob, &sig) == nil && sig.Format != ssh.KeyAlgoRSA &&
				checkSig(q, deadline, cut, offered, authMessage(challenge, bind), &sig)
			ok = signed && authorized
		}
	}
	if ok {
		conn.Write([]byte{1})
	} else {
		conn.Write([]byte{0})
	}
	// Name the offered key in the log so a failure is diagnosable; only once
	// the answer is sent, so that building the name cannot shift its timing.
	desc := "pubkey"
	switch {
	case perr != nil:
	case kindErr != nil:
		desc = "pubkey " + ssh.FingerprintSHA256(offered) + " (" + kindErr.Error() + ")"
	case !a.PubkeyEnabled():
		desc = "pubkey " + ssh.FingerprintSHA256(offered) + " (public-key auth is off)"
	case !authorized:
		desc = "pubkey " + ssh.FingerprintSHA256(offered) + " (not authorized)"
	default:
		desc = "pubkey " + ssh.FingerprintSHA256(offered)
	}
	return desc, ok
}

// LoadAuthorizedKeys reads an OpenSSH authorized_keys file (same format as
// ~/.ssh/authorized_keys: "ssh-ed25519 AAAA... comment", one per line,
// '#' comments and blank lines allowed), a regular file of at most
// maxListFile bytes (see readCheckedFile). As ssh's StrictModes does, it
// refuses, before reading it, a file another user could change, or could
// have put in its place, who could then add a key of theirs (see
// changeExposure and placeExposure); others may read it. Per-key
// options (from=, command=, restrict, ...) are not supported, so a line that
// carries options is skipped with a warning instead of granting that key
// full access. A key of a kind public-key auth does not take (see sigQueue)
// is skipped with a warning too.
func LoadAuthorizedKeys(path string) (map[string]ssh.PublicKey, error) {
	data, err := readCheckedFile(path, maxListFile, func(f *os.File, fi fs.FileInfo) error {
		return checkUnchanged(f, fi, path, "it lists the keys that may log in", authorizedKeysWords)
	})
	if err != nil {
		return nil, err
	}
	keys := make(map[string]ssh.PublicKey)
	skipped := 0
	rest := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // a UTF-8 BOM would hide the first key
	for len(rest) > 0 {
		pub, comment, options, r, perr := ssh.ParseAuthorizedKey(rest)
		if perr != nil {
			break // no more parseable keys (trailing comments/blank lines)
		}
		rest = r
		// A certificate line parses here too, but tern does not check a
		// certificate's validity window, principals or critical options, so
		// accepting it as a plain key would silently ignore force-command,
		// source-address and expiry. Skip certificates rather than honour a key
		// the operator meant to restrict.
		if _, isCert := pub.(*ssh.Certificate); isCert || strings.HasSuffix(pub.Type(), "-cert-v01@openssh.com") {
			skipped++
			slog.Warn("authorized_keys: skipping a certificate line (certificates are not supported; add the plain key instead)",
				"file", path, "comment", comment)
			continue
		}
		if len(options) > 0 {
			skipped++
			names := make([]string, len(options)) // values may hold secrets: log names only
			for i, o := range options {
				names[i], _, _ = strings.Cut(o, "=")
			}
			slog.Warn("authorized_keys: skipping a key with options (per-key options are not supported)",
				"file", path, "key", ssh.FingerprintSHA256(pub), "comment", comment, "options", strings.Join(names, ","))
			continue
		}
		if err := checkAuthKey(pub); err != nil {
			skipped++
			slog.Warn("authorized_keys: skipping a key of a kind tern does not accept",
				"file", path, "key", ssh.FingerprintSHA256(pub), "comment", comment, "why", err.Error(), "accepted", acceptedKeys)
			continue
		}
		keys[string(pub.Marshal())] = pub
	}
	if len(keys) == 0 {
		if skipped > 0 {
			return nil, fmt.Errorf("no usable keys in %s: all %d are certificates, carry options or are of a kind tern does not accept", path, skipped)
		}
		return nil, fmt.Errorf("no valid keys found in %s", path)
	}
	return keys, nil
}

// clientAuthenticate picks the method from what the caller supplied: a key file
// means public-key auth, otherwise a token. bind is the binding of the TLS
// connection the proof is for (see sessionBind), empty in plaintext. An
// encrypted key prompts for its passphrase the first time it is loaded, so
// interactive callers load it with PreloadKey before the terminal is put into
// raw mode.
func clientAuthenticate(conn net.Conn, bind []byte, keyFile, token string) error {
	switch {
	case keyFile != "":
		signer, err := loadSigner(keyFile)
		if err != nil {
			return fmt.Errorf("load key %s: %w", keyFile, err)
		}
		slog.Debug("authenticating", "method", "pubkey", "key", ssh.FingerprintSHA256(signer.PublicKey()))
		return clientHandshake(conn, methodPubkey, "", signer, bind)
	case token != "":
		slog.Debug("authenticating", "method", "token-hmac")
		return clientHandshake(conn, methodTokenHMAC, token, nil, bind)
	default:
		return errors.New("no credentials: provide a key (pubkey auth) or a token")
	}
}

// signChallenge signs msg, using rsa-sha2-256 for RSA keys instead of the
// SHA-1 "ssh-rsa" default that ssh.Signer.Sign would produce; the agent rejects
// SHA-1 RSA signatures.
func signChallenge(signer ssh.Signer, msg []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		if as, ok := signer.(ssh.AlgorithmSigner); ok {
			return as.SignWithAlgorithm(rand.Reader, msg, ssh.KeyAlgoRSASHA256)
		}
	}
	return signer.Sign(rand.Reader, msg)
}

// readChallenge reads an agent's or relay's challenge, refusing any size but
// challengeLen.
func readChallenge(conn net.Conn) ([]byte, error) {
	challenge, err := readBlob(conn, 256)
	if err == nil && len(challenge) != challengeLen {
		err = fmt.Errorf("got a %d-byte challenge, not %d", len(challenge), challengeLen)
	}
	return challenge, err
}

func clientHandshake(conn net.Conn, method byte, token string, signer ssh.Signer, bind []byte) error {
	if _, err := conn.Write([]byte{method}); err != nil {
		return err
	}
	switch method {
	case methodTokenHMAC:
		challenge, err := readChallenge(conn)
		if err != nil {
			return err
		}
		if err := writeBlob(conn, tokenProof(token, bind, challenge)); err != nil {
			return err
		}
	case methodPubkey:
		if err := writeBlob(conn, signer.PublicKey().Marshal()); err != nil {
			return err
		}
		challenge, err := readChallenge(conn)
		if err != nil {
			return err
		}
		sig, err := signChallenge(signer, authMessage(challenge, bind))
		if err != nil {
			return err
		}
		if err := writeBlob(conn, ssh.Marshal(sig)); err != nil {
			return err
		}
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[0] != 1 {
		return errors.New("authentication rejected by agent")
	}
	return nil
}

// signers caches loaded private keys by path, so an encrypted key asks for its
// passphrase once per process and every later dial (reconnects included)
// reuses it. pipeKeys keeps what came through a pipe given as a key, which
// can be read only once, from the first read (KeyNeedsPassphrase's, say)
// until the key loads: at most one entry, of at most maxSecretFile bytes,
// for each key path the process is given.
var (
	signersMu sync.Mutex
	signers   = map[string]ssh.Signer{}
	pipeKeys  = map[string][]byte{}
)

// clientKey returns the private key at path, read by readClientKey, or as
// it came through the pipe path names when it was read before. signersMu
// must be held.
func clientKey(path string) ([]byte, error) {
	if data, ok := pipeKeys[path]; ok {
		return data, nil
	}
	data, pipe, err := readClientKey(path)
	if err == nil && pipe {
		pipeKeys[path] = data
	}
	return data, err
}

// PreloadKey loads the private key at path into the cache that later dials use.
// Interactive shells call it before putting the terminal into raw mode, so an
// encrypted key can prompt for its passphrase on a normal terminal.
func PreloadKey(path string) error {
	if _, err := loadSigner(path); err != nil {
		return fmt.Errorf("load key %s: %w", path, err)
	}
	return nil
}

// KeyNeedsPassphrase reports whether the OpenSSH private key at path is
// encrypted, without prompting. Callers whose stdin is not a terminal (such as
// tern mcp, where stdin carries the protocol) use it to fail with a clear
// message instead of attempting a prompt. The key is read as loadSigner
// reads it, and a key from a pipe is kept for loadSigner; other parse
// problems are left for PreloadKey to report.
func KeyNeedsPassphrase(path string) (bool, error) {
	signersMu.Lock()
	defer signersMu.Unlock()
	if _, ok := signers[path]; ok {
		return false, nil
	}
	data, err := clientKey(path)
	if err != nil {
		return false, err
	}
	_, err = ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing), nil
}

// loadSigner parses an OpenSSH private key (e.g. ~/.ssh/id_ed25519), prompting
// for a passphrase if the key is encrypted, and caches the result. As ssh
// does, it refuses, before reading it, a key of this user's that others
// could open, and takes one another account owns, or one through a pipe of
// this user's (see readClientKey). A key of a kind no agent accepts (see
// sigQueue) is refused here, with the reason, rather than at the agent with
// none.
func loadSigner(path string) (ssh.Signer, error) {
	signersMu.Lock()
	defer signersMu.Unlock()
	if s, ok := signers[path]; ok {
		return s, nil
	}
	data, err := clientKey(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		fmt.Fprintf(os.Stderr, "Enter passphrase for key %s: ", path)
		pass, rerr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if rerr != nil {
			return nil, rerr
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, pass)
	}
	if err != nil {
		return nil, err
	}
	if err := checkAuthKey(signer.PublicKey()); err != nil {
		return nil, fmt.Errorf("%v (tern takes %s); make an Ed25519 key with: tern keygen", err, acceptedKeys)
	}
	signers[path] = signer
	if kept, ok := pipeKeys[path]; ok {
		clear(kept)
		delete(pipeKeys, path)
	}
	return signer, nil
}

// keygenCheck is checkNewKey, which GenerateKeyFiles holds a new key pair
// to; tests make it see the key as a FAT32 or exFAT volume leaves it.
var keygenCheck = checkNewKey

// GenerateKeyFiles writes an OpenSSH-compatible Ed25519 private key to
// outPrefix and its public key to outPrefix+".pub", returning the public line.
// The new private key is held to the checks a key must pass to be used, as
// the agent's TLS key is: where the file system cannot keep it to its owner,
// as FAT32 and exFAT cannot, both files are removed and an error returned.
func GenerateKeyFiles(outPrefix, comment string) (pubLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	pubLine = strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		pubLine += " " + comment
	}
	pubLine += "\n"

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	privPEM := pem.EncodeToMemory(block)

	// O_EXCL on both files: never write the private key through a dangling
	// symlink and never truncate an existing file at either path.
	if err := writePrivateFile(outPrefix, privPEM); err != nil {
		return "", err
	}
	if err := writeNewFile(outPrefix+".pub", []byte(pubLine), 0o644); err != nil {
		os.Remove(outPrefix) // roll back the private key so the pair is all-or-nothing
		return "", err
	}
	// Both files were made here, exclusively, so removing them on a refusal
	// removes nothing of anyone else's.
	if err := keygenCheck(outPrefix+".pub", outPrefix); err != nil {
		return "", err
	}
	return pubLine, nil
}
