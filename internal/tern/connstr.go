// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

const connPrefix = "tern1:"

// ConnString is everything a client needs to reach an agent, in one string.
// It never carries the user's own credential (key or token for the agent);
// that is supplied separately. In relay mode it can carry the relay token,
// but ternd prints it without one, since that token is the operator's
// secret: the client then takes it from TERN_RELAY_TOKEN or a file.
type ConnString struct {
	Mode       string `json:"mode"` // "direct" | "relay"
	Addr       string `json:"addr,omitempty"`
	FP         string `json:"fp,omitempty"` // agent TLS fingerprint
	Relay      string `json:"relay,omitempty"`
	RelayFP    string `json:"relay_fp,omitempty"`
	RelayToken string `json:"relay_token,omitempty"`
	ID         string `json:"id,omitempty"`
}

// Encode renders the connection string (tern1:<base64url-json>).
func (c ConnString) Encode() string {
	b, _ := json.Marshal(c)
	return connPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// DecodeConnString parses a connection string produced by Encode.
func DecodeConnString(s string) (ConnString, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, connPrefix) {
		return ConnString{}, fmt.Errorf("not a tern connection string")
	}
	// Printed connection lines wrap, so a partial copy is the usual mistake.
	bad := func(err error) error {
		return fmt.Errorf("the tern1: connection string is damaged or cut short (copy it whole): %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, connPrefix))
	if err != nil {
		return ConnString{}, bad(err)
	}
	var c ConnString
	if err := json.Unmarshal(raw, &c); err != nil {
		return ConnString{}, bad(err)
	}
	// Reject control bytes in any field: these values flow into dial addresses
	// and into error messages printed to the terminal, where a crafted string
	// could otherwise inject escape sequences through Go's net error text.
	for _, v := range []string{c.Mode, c.Addr, c.FP, c.Relay, c.RelayFP, c.RelayToken, c.ID} {
		if v != CleanText(v) {
			return ConnString{}, fmt.Errorf("connection string contains control characters")
		}
	}
	// The rest also ends up in tern connect commands printed for a person to
	// run, so whoever wrote the string must not be able to slip shell syntax
	// into them: hold every field to what it can legitimately be.
	if c.Mode != "direct" && c.Mode != "relay" {
		return ConnString{}, fmt.Errorf("the tern1: connection string has an unknown mode %q", c.Mode)
	}
	for _, a := range []string{c.Addr, c.Relay} {
		if a != "" && !validDialAddr(a) {
			return ConnString{}, fmt.Errorf("the tern1: connection string has a malformed address %q", a)
		}
	}
	for _, fp := range []string{c.FP, c.RelayFP} {
		if strings.Trim(fp, "0123456789abcdefABCDEF:") != "" {
			return ConnString{}, fmt.Errorf("the tern1: connection string has a malformed fingerprint %q", fp)
		}
	}
	if c.ID != "" {
		if err := CheckRelayID(c.ID); err != nil {
			return ConnString{}, fmt.Errorf("the tern1: connection string has a bad id: %v", err)
		}
	}
	return c, nil
}

// validDialAddr reports whether a is a host:port made of letters, digits and
// . - _ : [ ], as host names, IP addresses (an IPv6 one in brackets) and
// ports are. A % may only start the zone of a bracketed IPv6 address, as in
// [fe80::1%eth0]:22, and the zone is letters, digits and . - _ only.
func validDialAddr(a string) bool {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	for i := 0; i < len(a); i++ {
		if c := a[i]; !isAlnum(c) && !strings.ContainsRune(".-_:%[]", rune(c)) {
			return false
		}
	}
	if strings.Contains(port, "%") {
		return false
	}
	if !strings.Contains(host, "%") {
		return true
	}
	ip, zone, _ := strings.Cut(host, "%")
	if !strings.HasPrefix(a, "[") || zone == "" || strings.ContainsAny(zone, ":%[]") {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// IsConnString reports whether s looks like a tern connection string.
func IsConnString(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), connPrefix) }
