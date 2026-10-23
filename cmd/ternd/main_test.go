// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"

	tern "github.com/ternimal/tern/internal/tern"
)

// The connect line quotes what came from the command line where a shell would
// read it as more than a word, so pasted it does just what it says.
func TestPrintConnectQuotes(t *testing.T) {
	for _, c := range []struct {
		cs        tern.ConnString
		plaintext bool
		want      string
	}{
		{tern.ConnString{Mode: "direct", Addr: "[::1]:2222"}, true,
			"tern connect --insecure-skip-encryption --addr '[::1]:2222'\n"},
		{tern.ConnString{Mode: "relay", Relay: "[2001:db8::1]:7000", RelayFP: "ab cd", ID: "box1"}, true,
			"tern connect --insecure-skip-encryption --relay-fingerprint 'ab cd' --relay '[2001:db8::1]:7000' --id box1\n"},
		{tern.ConnString{Mode: "direct", Addr: "127.0.0.1:2222", FP: "abcd"}, false,
			"tern connect --to tern1:"},
	} {
		var b bytes.Buffer
		printConnect(&b, "connect with", "", c.cs, "", c.plaintext)
		if !strings.Contains(b.String(), c.want) {
			t.Errorf("printed %q, want it to hold %q", b.String(), c.want)
		}
	}
}
