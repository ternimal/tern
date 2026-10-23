// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"strings"
	"testing"
)

func TestConnStringRoundTrip(t *testing.T) {
	cases := []ConnString{
		{Mode: "direct", Addr: "host.example:2222", FP: "deadbeef"},
		{Mode: "direct", Addr: "[fe80::1%eth0]:2222", FP: "DE:AD:BE:EF"},
		{Mode: "relay", Relay: "relay.example:7000", RelayFP: "c0ffee", RelayToken: "tok/with+special_=chars", ID: "ops@box-1.example:2+x_y", FP: "a1f2"},
	}
	for _, in := range cases {
		s := in.Encode()
		if !IsConnString(s) {
			t.Fatalf("Encode() %q not recognized by IsConnString", s)
		}
		out, err := DecodeConnString(s)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out != in {
			t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
		}
	}
	if _, err := DecodeConnString("totally-not-a-conn-string"); err == nil {
		t.Fatal("expected an error decoding a non-conn-string")
	}
}

// Whoever writes a tern1: string must not be able to slip shell syntax into
// the tern connect commands made from it, which tern mcp hands a person to
// paste: an id, address, fingerprint or mode outside what each can be is
// refused.
func TestDecodeConnStringRefusesShellSyntax(t *testing.T) {
	good := ConnString{Mode: "relay", Relay: "relay.example:7000", RelayFP: "c0ffee", ID: "box1", FP: "a1f2"}
	for name, edit := range map[string]func(*ConnString){
		"id $()":        func(c *ConnString) { c.ID = "box$(touch /tmp/x)" },
		"id backtick":   func(c *ConnString) { c.ID = "box`id`" },
		"id ;":          func(c *ConnString) { c.ID = "box;id" },
		"id space":      func(c *ConnString) { c.ID = "box one" },
		"id quote":      func(c *ConnString) { c.ID = `box"` },
		"id flag":       func(c *ConnString) { c.ID = "-box" },
		"id non-ascii":  func(c *ConnString) { c.ID = "bøx" },
		"id too long":   func(c *ConnString) { c.ID = strings.Repeat("b", maxRelayID+1) },
		"relay $":       func(c *ConnString) { c.Relay = "relay.example:7000$(id)" },
		"relay no port": func(c *ConnString) { c.Relay = "relay.example" },
		"addr &":        func(c *ConnString) { c.Mode, c.Addr = "direct", "127.0.0.1:2222&id" },
		"fp $()":        func(c *ConnString) { c.FP = "a1$(id)" },
		"relay fp |":    func(c *ConnString) { c.RelayFP = "c0|id" },
		"mode":          func(c *ConnString) { c.Mode = "relay;id" },
	} {
		c := good
		edit(&c)
		if _, err := DecodeConnString(c.Encode()); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
	if _, err := DecodeConnString(good.Encode()); err != nil {
		t.Fatalf("a good string was refused: %v", err)
	}
}

// A % in an address only starts the zone of a bracketed IPv6 address;
// anywhere else, where a name resolver or a printed command could make
// something of it, the string is refused.
func TestDecodeConnStringPercentOnlyInZone(t *testing.T) {
	for _, addr := range []string{"[fe80::1%eth0]:2222", "[fe80::1%12]:22", "[fe80::1%en0.5]:22", "[::1]:22"} {
		if _, err := DecodeConnString(ConnString{Mode: "direct", Addr: addr, FP: "ab"}.Encode()); err != nil {
			t.Errorf("%s: refused: %v", addr, err)
		}
	}
	for _, addr := range []string{
		"host%41:22", "%2e%2e:22", "1.2.3.4%eth0:22", "host:22%", "host:%32%32",
		"[fe80::1%]:22", "[host%eth0]:22", "[1.2.3.4%eth0]:22", "[fe80::1%eth%0]:22",
	} {
		if _, err := DecodeConnString(ConnString{Mode: "direct", Addr: addr, FP: "ab"}.Encode()); err == nil {
			t.Errorf("%s: accepted", addr)
		}
	}
}

// A connection string with control bytes is rejected, so it cannot inject
// terminal escapes through a dial error printed to the terminal.
func TestDecodeConnStringRejectsControlBytes(t *testing.T) {
	good := ConnString{Mode: "direct", Addr: "127.0.0.1:2222", FP: "abc"}
	if _, err := DecodeConnString(good.Encode()); err != nil {
		t.Fatalf("a clean connection string was rejected: %v", err)
	}
	evil := ConnString{Mode: "direct", Addr: "127.0.0.1:2222\x1b]0;x\x07", FP: "abc"}
	if _, err := DecodeConnString(evil.Encode()); err == nil {
		t.Fatal("a connection string with control bytes was accepted")
	}
}
