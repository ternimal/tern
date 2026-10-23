// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"fmt"
	"strings"
)

// namedKeys maps the key names pty_send takes to the bytes a terminal sends
// for them. Models do badly at writing raw control bytes; names fix that.
var namedKeys = map[string]string{
	"enter": "\r", "return": "\r", "tab": "\t", "esc": "\x1b", "escape": "\x1b",
	"backspace": "\x7f", "space": " ",
	"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
	"home": "\x1b[H", "end": "\x1b[F", "pgup": "\x1b[5~", "pageup": "\x1b[5~",
	"pgdn": "\x1b[6~", "pagedown": "\x1b[6~", "insert": "\x1b[2~", "delete": "\x1b[3~",
	"f1": "\x1bOP", "f2": "\x1bOQ", "f3": "\x1bOR", "f4": "\x1bOS",
	"f5": "\x1b[15~", "f6": "\x1b[17~", "f7": "\x1b[18~", "f8": "\x1b[19~",
	"f9": "\x1b[20~", "f10": "\x1b[21~", "f11": "\x1b[23~", "f12": "\x1b[24~",
}

// maxKeyName bounds a key name, which also bounds how many Alt prefixes
// keyBytes unwraps.
const maxKeyName = 32

const keyNames = "Enter, Tab, Esc, Backspace, Space, Up, Down, Left, Right, Home, End, PgUp, PgDn, " +
	"Insert, Delete, F1 to F12, C-a to C-z and C-@ C-[ C-\\ C-] C-^ C-_ for Ctrl, and M-x for Alt"

// keyBytes resolves a key name, ignoring case: a named key, C-x (also Ctrl-x,
// Ctrl+x or ^x) for Ctrl with a letter or one of @[\]^_?, or M-x (also Alt-x
// or Alt+x) for Alt, which sends Esc before the key.
func keyBytes(name string) (string, error) {
	low := strings.ToLower(name)
	if b, ok := namedKeys[low]; ok {
		return b, nil
	}
	for _, pre := range []string{"m-", "alt-", "alt+"} {
		if rest, ok := strings.CutPrefix(low, pre); ok && rest != "" {
			b, err := keyBytes(name[len(pre):])
			if err != nil && len(rest) == 1 {
				b, err = name[len(pre):], nil // a plain character, case kept: M-f, M-F, M-.
			}
			if err != nil {
				return "", err
			}
			return "\x1b" + b, nil
		}
	}
	for _, pre := range []string{"c-", "ctrl-", "ctrl+", "^"} {
		if rest, ok := strings.CutPrefix(low, pre); ok && len(rest) == 1 {
			switch c := rest[0]; {
			case c >= 'a' && c <= 'z':
				return string(rune(c - 'a' + 1)), nil
			case c == '@' || c == ' ':
				return "\x00", nil
			case c == '?':
				return "\x7f", nil
			case strings.IndexByte(`[\]^_`, c) >= 0:
				return string(rune(c - '@')), nil
			}
		}
	}
	return "", fmt.Errorf("unknown key %q; keys are %s", name, keyNames)
}
