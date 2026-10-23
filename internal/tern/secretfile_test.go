// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
)

// fixHint is what a refusal of a file others can read tells the operator to
// run.
func fixHint() string {
	if runtime.GOOS == "windows" {
		return "icacls"
	}
	return "chmod 600"
}

// fileReaders are the ways tern reads a file it is given: a token, a tern1:
// string, a config, a private key, an authorized_keys file.
var fileReaders = map[string]func(string) error{
	"ReadSecretFile":      func(p string) error { _, err := ReadSecretFile(p); return err },
	"ReadConnStringFile":  func(p string) error { _, err := ReadConnStringFile(p); return err },
	"ReadConfigFile":      func(p string) error { _, err := ReadConfigFile(p); return err },
	"PreloadKey":          PreloadKey,
	"KeyNeedsPassphrase":  func(p string) error { _, err := KeyNeedsPassphrase(p); return err },
	"LoadAuthorizedKeys":  func(p string) error { _, err := LoadAuthorizedKeys(p); return err },
	"ResolveSecret (api)": func(p string) error { _, _, err := ResolveSecret("api-token", "", p, "TERN_TEST_UNSET"); return err },
}

// changeFixHint is what a refusal of a file others can change tells the
// operator to run.
func changeFixHint() string {
	if runtime.GOOS == "windows" {
		return "icacls"
	}
	return "chmod go-w"
}

// A token file other local users could read or change is refused, as ssh
// refuses an unprotected private key, with the way to fix it, which starts
// with a new token since others may know this one; one only its owner can
// open is read, trailing whitespace trimmed.
func TestTokenFileMustBePrivate(t *testing.T) {
	f := filepath.Join(t.TempDir(), "api.token")
	if err := writePrivateFile(f, []byte("token-0123456789abcdef\n")); err != nil {
		t.Fatal(err)
	}
	if s, fromFlag, err := ResolveSecret("api-token", "", f, "TERN_TEST_UNSET"); err != nil || s != "token-0123456789abcdef" || fromFlag {
		t.Fatalf("an owner-only token file: %q %v %v", s, fromFlag, err)
	}
	exposeToOthers(t, f)
	_, _, err := ResolveSecret("api-token", "", f, "TERN_TEST_UNSET")
	if err == nil || !strings.Contains(err.Error(), "--api-token-file") || !strings.Contains(err.Error(), f) ||
		!strings.Contains(err.Error(), fixHint()) || !strings.Contains(err.Error(), "may know the token") {
		t.Fatalf("a token file others can read: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := writePrivateFile(empty, []byte(" \n")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveSecret("token", "", empty, "TERN_TEST_UNSET"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty token file: %v", err)
	}
}

// A tern1: string carries no secret unless it holds the relay token: a file
// others can read is read when it does not, and refused when it does.
func TestConnStringFileWithRelayTokenMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	plain := ConnString{Mode: "relay", Relay: "relay.example:7000", RelayFP: strings.Repeat("ab", 32), ID: "box1", FP: strings.Repeat("cd", 32)}
	withToken := plain
	withToken.RelayToken = "relay-token-0123456789"
	for name, c := range map[string]ConnString{"plain": plain, "token": withToken} {
		f := filepath.Join(dir, name)
		if err := writePrivateFile(f, []byte(c.Encode()+"\n")); err != nil {
			t.Fatal(err)
		}
		if s, err := ReadConnStringFile(f); err != nil || s != c.Encode() {
			t.Fatalf("%s, owner-only: %q %v", name, s, err)
		}
		exposeToOthers(t, f)
		s, err := ReadConnStringFile(f)
		switch {
		case name == "plain" && (err != nil || s != c.Encode()):
			t.Errorf("a string with no relay token, in a file others can read: %q %v", s, err)
		case name == "token" && (err == nil || !strings.Contains(err.Error(), "relay token") || !strings.Contains(err.Error(), fixHint())):
			t.Errorf("a string with the relay token, in a file others can read: %v", err)
		}
	}
}

// A tern1: string names the agent the client trusts, by address and
// fingerprint, so a file others could change is refused, with or without
// the relay token: another user could point the client at their own agent.
func TestConnStringFileOthersMayNotChange(t *testing.T) {
	dir := t.TempDir()
	plain := ConnString{Mode: "direct", Addr: "192.0.2.5:2222", FP: strings.Repeat("ab", 32)}
	withToken := ConnString{Mode: "relay", Relay: "relay.example:7000", RelayFP: strings.Repeat("ab", 32), ID: "box1", FP: strings.Repeat("cd", 32), RelayToken: "relay-token-0123456789"}
	for name, c := range map[string]ConnString{"plain": plain, "token": withToken} {
		f := filepath.Join(dir, name)
		if err := writePrivateFile(f, []byte(c.Encode()+"\n")); err != nil {
			t.Fatal(err)
		}
		letOthersChange(t, f)
		if _, err := ReadConnStringFile(f); err == nil || !strings.Contains(err.Error(), "names the agent") || !strings.Contains(err.Error(), changeFixHint()) {
			t.Errorf("%s, in a file others could change: %v", name, err)
		}
	}
}

// A config file may be read by others, but one they could change is
// refused before it is read.
func TestConfigFileOthersMayNotChange(t *testing.T) {
	f := filepath.Join(t.TempDir(), "mcp.json")
	if err := writePrivateFile(f, []byte(`{"targets":{}}`)); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadConfigFile(f); err != nil || string(b) != `{"targets":{}}` {
		t.Fatalf("a private config file: %q %v", b, err)
	}
	exposeToOthers(t, f)
	if _, err := ReadConfigFile(f); err != nil {
		t.Errorf("a config file others may read: %v", err)
	}
	letOthersChange(t, f)
	if _, err := ReadConfigFile(f); err == nil || !strings.Contains(err.Error(), "which agents to trust") || !strings.Contains(err.Error(), changeFixHint()) {
		t.Errorf("a config file others could change: %v", err)
	}
}

// A client's private key file of this user's is held to ssh's rule: one
// other local users could read is refused, before it is parsed, with a new
// key or a restricted file as the fix.
func TestClientKeyMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "id_mine")
	if _, err := GenerateKeyFiles(mine, "t"); err != nil {
		t.Fatal(err)
	}
	if err := PreloadKey(mine); err != nil {
		t.Fatalf("a private key file: %v", err)
	}
	open := filepath.Join(dir, "id_open")
	if _, err := GenerateKeyFiles(open, "t"); err != nil {
		t.Fatal(err)
	}
	exposeToOthers(t, open)
	for name, read := range map[string]func(string) error{
		"PreloadKey":         fileReaders["PreloadKey"],
		"KeyNeedsPassphrase": fileReaders["KeyNeedsPassphrase"],
	} {
		if err := read(open); err == nil || !strings.Contains(err.Error(), fixHint()) || !strings.Contains(err.Error(), "tern keygen") {
			t.Errorf("%s of a key file others can read: %v", name, err)
		}
	}
}

// An authorized_keys file says which keys may log in: as ssh's StrictModes
// does, one others could change is refused before it is read, with the fix,
// and one they may only read is used.
func TestAuthorizedKeysOthersMayNotChange(t *testing.T) {
	_, pub := newSSHKey(t)
	f := filepath.Join(t.TempDir(), "authorized_keys")
	if err := writePrivateFile(f, ssh.MarshalAuthorizedKey(pub)); err != nil {
		t.Fatal(err)
	}
	if keys, err := LoadAuthorizedKeys(f); err != nil || len(keys) != 1 {
		t.Fatalf("a private authorized_keys file: %d keys, %v", len(keys), err)
	}
	exposeToOthers(t, f)
	if keys, err := LoadAuthorizedKeys(f); err != nil || len(keys) != 1 {
		t.Errorf("an authorized_keys file others may read: %d keys, %v", len(keys), err)
	}
	letOthersChange(t, f)
	_, err := LoadAuthorizedKeys(f)
	if err == nil || !strings.Contains(err.Error(), "keys that may log in") || !strings.Contains(err.Error(), "lists only the keys you meant") ||
		!strings.Contains(err.Error(), changeFixHint()) {
		t.Errorf("an authorized_keys file others could change: %v", err)
	}
}

// A TLS key pair the agent made loads again. Its key is held to the rules
// of a secret file, so one others could read is refused, with a new pair
// as the fix; its certificate, which clients pin, may be read by others
// but one they could change is refused.
func TestTLSKeyAndCertRules(t *testing.T) {
	for _, c := range []struct {
		name  string
		spoil func(t *testing.T, prefix string)
		want  []string // what the refusal names; none: the pair loads
	}{
		{"as made", func(*testing.T, string) {}, nil},
		{"key others may read", func(t *testing.T, p string) { exposeToOthers(t, p+".key") }, []string{"TLS key", "a new pair is made", fixHint()}},
		{"certificate others may read", func(t *testing.T, p string) { exposeToOthers(t, p+".crt") }, nil},
		{"certificate others may change", func(t *testing.T, p string) { letOthersChange(t, p+".crt") }, []string{"TLS certificate", "certificate clients pin", changeFixHint()}},
	} {
		prefix := filepath.Join(t.TempDir(), "agent")
		made, err := LoadOrCreateCert(prefix)
		if err != nil {
			t.Fatal(err)
		}
		c.spoil(t, prefix)
		got, err := LoadOrCreateCert(prefix)
		switch {
		case c.want == nil && (err != nil || CertFingerprint(got) != CertFingerprint(made)):
			t.Errorf("%s: %v", c.name, err)
		case c.want != nil && err == nil:
			t.Errorf("%s: loaded", c.name)
		case c.want != nil:
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%s: %v, want it to name %q", c.name, err, w)
				}
			}
		}
	}
}

// Text as Windows tools may save it, UTF-16 (Windows PowerShell 5.1's >) or
// with a byte order mark, is refused, saying so, rather than read with the
// extra bytes in the token, the tern1: string or the config.
func TestTextFileEncodingRefused(t *testing.T) {
	dir := t.TempDir()
	utf16le := func(s string) []byte {
		b := []byte{0xff, 0xfe}
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u), byte(u>>8))
		}
		return b
	}
	tern1 := ConnString{Mode: "direct", Addr: "192.0.2.5:2222", FP: strings.Repeat("ab", 32)}.Encode()
	for _, c := range []struct {
		name, want string
		data       []byte
	}{
		{"bom.token", "byte order mark", []byte("\xef\xbb\xbftoken-0123456789abcdef\r\n")},
		{"utf16.token", "UTF-16", utf16le("token-0123456789abcdef\r\n")},
		{"zero.token", "NUL", []byte("token-0123\x00456789abcdef\n")}, // not nul.token: on Windows that names the NUL device
		{"bom.tern1", "byte order mark", []byte("\xef\xbb\xbf" + tern1)},
		{"utf16.tern1", "UTF-16", utf16le(tern1)},
		{"bom.json", "byte order mark", []byte("\xef\xbb\xbf{}")},
	} {
		f := filepath.Join(dir, c.name)
		if err := writePrivateFile(f, c.data); err != nil {
			t.Fatal(err)
		}
		read := fileReaders["ReadSecretFile"]
		switch filepath.Ext(c.name) {
		case ".tern1":
			read = fileReaders["ReadConnStringFile"]
		case ".json":
			read = fileReaders["ReadConfigFile"]
		}
		if err := read(f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %s", c.name, err, c.want)
		}
	}
}
