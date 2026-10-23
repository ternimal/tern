// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"
)

// Frame format for shell and exec streams (both directions), big-endian:
//
//	+--------+-------------------+----------------+
//	| type:1 | length:4 (uint32) | payload:length |
//	+--------+-------------------+----------------+
const (
	frameData   byte = 0 // payload: data bytes
	frameResize byte = 1 // control stream, for a shell: cols:2, rows:2 (uint16 big-endian)
	frameEOF    byte = 2 // no payload: sender closed its input
	frameExit   byte = 3 // payload: exit code (int32 big-endian; always 0 on shell streams)
	frameEnd    byte = 4 // control stream, no payload: end a shell's session (writers only), or kill an exec's command
)

// On the control stream (see kindControl) a frame's payload starts with the
// id (uint32 big-endian) of the stream the request is for.
const maxControlPayload = 4 + 4 // the stream id and a resize

const maxFrame = 1 << 20 // 1 MiB guard against oversized/garbage frames

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) { return readFrameMax(r, maxFrame) }

// readFrameMax reads a frame whose payload is at most max bytes.
func readFrameMax(r io.Reader, max uint32) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > max {
		return 0, nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return hdr[0], buf, nil
}

func encodeResize(cols, rows uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], cols)
	binary.BigEndian.PutUint16(b[2:], rows)
	return b
}

func decodeResize(b []byte) (cols, rows uint16, ok bool) {
	if len(b) != 4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(b[0:]), binary.BigEndian.Uint16(b[2:]), true
}

// --- length-prefixed blobs (uint16 length): handshakes and JSON stream headers ---

func writeBlob(w io.Writer, b []byte) error {
	if len(b) > 65535 {
		return fmt.Errorf("blob too long: %d", len(b))
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(b)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	_, err := w.Write(b)
	return err
}

func readBlob(r io.Reader, max int) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > max {
		return nil, fmt.Errorf("blob too long: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// --- TLS: self-signed cert persisted to disk, verified by the peer via pinning ---

// LoadOrCreateCert loads a cert/key pair from <prefix>.crt/.key, generating a
// fresh self-signed P-256 ECDSA key pair on first use.
func LoadOrCreateCert(prefix string) (tls.Certificate, error) {
	certFile := prefix + ".crt"
	keyFile := prefix + ".key"
	if _, err := os.Lstat(keyFile); err == nil {
		// The pair already exists: load it, but refuse a key a local attacker
		// could have planted or read (see readTLSKey), since loading it would
		// make us serve their certificate and let them hold the matching
		// private key, and a certificate another user owns or could change
		// (see changeExposure). Where the certificate is does not matter, as
		// nothing looked when the pair was made there: it serves only with
		// the key it matches, which tls.X509KeyPair checks, so another one
		// put in its place could only change the fingerprint clients pin,
		// and they would refuse it.
		keyPem, kerr := readTLSKey(keyFile)
		if kerr != nil {
			return tls.Certificate{}, fmt.Errorf("refusing to load the TLS key: %w", kerr)
		}
		certPem, cerr := readCheckedFile(certFile, maxListFile, func(f *os.File, fi fs.FileInfo) error {
			p, err := changeExposure(f, fi, certFile, certWords)
			if p != nil {
				p.problem = "it is the certificate clients pin, and " + p.problem
				return p
			}
			return err
		})
		if cerr != nil {
			return tls.Certificate{}, fmt.Errorf("refusing to load the TLS certificate: %w", cerr)
		}
		return tls.X509KeyPair(certPem, keyPem)
	} else if !os.IsNotExist(err) {
		return tls.Certificate{}, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tern"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})

	// Create exclusively: O_EXCL fails if the path already exists or is a planted
	// symlink, so we never write the private key through an attacker's link.
	// The certificate is made owner-only too, as on Unix (0600): on Windows
	// it would otherwise inherit its directory's ACL, which in a folder made
	// under C:\ on Windows 10 and 11 lets Authenticated Users change it, and
	// the next start would rightly refuse it.
	if err := writePrivateFile(certFile, certPem); err != nil {
		return tls.Certificate{}, err
	}
	if err := writePrivateFile(keyFile, keyPem); err != nil {
		return tls.Certificate{}, err
	}
	if err := checkNewKey(certFile, keyFile); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPem, keyPem)
}

// checkNewKey holds a key just written to the checks a key must pass to be
// loaded. A file system that cannot restrict access, as FAT32 and exFAT
// cannot, leaves the key readable by every local user however it was
// created, and the next start would refuse it anyway; so the new pair is
// removed and refused instead of being served while others can read the key.
func checkNewKey(certFile, keyFile string) error {
	err := checkKeyFileSafe(keyFile)
	if err == nil {
		return nil
	}
	os.Remove(keyFile)
	os.Remove(certFile)
	problem := err.Error()
	var kerr *keyFileError
	if errors.As(err, &kerr) {
		problem = kerr.problem // its fix is for a key someone left there
	}
	return fmt.Errorf("the new key %s is not private (%s), so it was removed: the file system there does not keep a file to its owner, as FAT32 and exFAT do not; keep the key on one that does", keyFile, problem)
}

// keyFileError is what is wrong with a key file, and how to fix it in place
// when that can be done.
type keyFileError struct {
	problem, fix string
}

func (e *keyFileError) Error() string {
	if e.fix == "" {
		return e.problem
	}
	return e.problem + "; " + e.fix
}

// writePrivateFile is writeNewFile for a private key, which only the current
// user can open from the moment it exists; see CreateOwnerOnly.
func writePrivateFile(path string, data []byte) error {
	f, err := createOwnerOnly(path, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Close())
}

// writeNewFile writes data to a file that must not already exist (O_EXCL), so a
// pre-planted file or symlink at path causes an error instead of being written
// through.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Close())
}

// readTLSKey reads a TLS key file, refusing one a local attacker could have
// planted or can read, before reading it: a symlink, a non-regular file, or
// one another user owns or others could open (see readSecret).
func readTLSKey(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", path)
	}
	return readSecret(path, agentKeyWords)
}

// checkKeyFileSafe refuses a TLS key file that a local attacker could have
// planted or can read: a symlink, a non-regular file, one not owned by the
// current user, or one others can open (see checkKeyFileAccess).
func checkKeyFileSafe(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("it is a symlink")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("it is not a regular file")
	}
	return checkKeyFileAccess(path, fi)
}

// CertFingerprint returns the hex SHA-256 of the leaf certificate's DER.
func CertFingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// ServerTLSConfig is the config a listener (agent or relay) presents.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// PinnedTLSConfig verifies the peer by the SHA-256 of its leaf certificate
// against a fingerprint supplied in advance. There is no trust-on-first-use:
// an empty or mismatched fingerprint fails the handshake, so a self-signed cert
// is safe against MITM as long as the fingerprint was obtained out of band.
func PinnedTLSConfig(fingerprint string) *tls.Config {
	want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	return &tls.Config{
		InsecureSkipVerify: true, // verification is done by pinning below
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("peer presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				return fmt.Errorf("fingerprint mismatch: expected %s, got %s", want, got)
			}
			return nil
		},
	}
}

// ClientTLSConfig is the config a client presents when reaching an agent or a
// relay. Normally it pins the peer by fingerprint via PinnedTLSConfig. When
// insecure is true and no fingerprint is given it DISABLES that check: the
// link is still encrypted but the peer is not authenticated, so anyone able
// to intercept the connection can impersonate the agent or relay, see and
// change what the session carries, and guess a weak token offline from the
// proof it receives. It logs the peer's real fingerprint so it can be pinned
// next time. This backs the client --insecure-skip-fingerprint flag and
// ternd's --insecure-dangerous, and must never be used in production. A
// fingerprint that is given is always checked, insecure or not: someone who
// pinned the peer means it, whatever else they relaxed.
func ClientTLSConfig(fingerprint string, insecure bool) *tls.Config {
	if !insecure || fingerprint != "" {
		return PinnedTLSConfig(fingerprint)
	}
	return &tls.Config{
		InsecureSkipVerify: true, // DANGEROUS: the peer is not authenticated
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				slog.Warn("INSECURE: TLS fingerprint verification is OFF; the connection is not authenticated and can be intercepted",
					"peer_fingerprint", hex.EncodeToString(sum[:]))
			}
			return nil
		},
	}
}
