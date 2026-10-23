// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVTText(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain\r\nlines\r\n", "plain\nlines\n"},
		{"\x1b[1;31mred\x1b[0m and \x1b[38;2;1;2;3mtrue\x1b[m", "red and true"},
		{"\x1b]0;title\x07\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "link"},
		{"\x1b]133;A\x1b\\$ \x1b]133;B\x07", "$ "},
		{"\x1bP1$r0m\x1b\\dcs\x1b_apc\x1b\\\x1b^pm\x1b\\\x1bXsos\x1b\\", "dcs"},
		{"\x1b(B\x1b)0\x1b7\x1b8\x1b=\x1b>ok", "ok"},
		{"\x1b[?2004h\x1b[?25l\x1b[>c\x1b[2 qmodes", "modes"},
		{"\u009b31mc1\u009d0;t\u009c", "c1"},     // 8-bit CSI, OSC and ST as characters
		{"10%\r20%\r100%\n", "100%\n"},           // progress bar
		{"abc\rX\n", "Xbc\n"},                    // CR overwrites, as on a screen
		{"ls\b \bs -la\n", "ls -la\n"},           // an edited command line
		{"$ ecoh\b\b\bcho hi\n", "$ echo hi\n"},  // retyped over the typo
		{"abcdef\x1b[3D\x1b[K\n", "abc\n"},       // erase to end of line
		{"abcdef\r\x1b[2K\x1b[1Gnew\n", "new\n"}, // erase the line, column 1
		{"abcdef\x1b[4D\x1b[2P\n", "abef\n"},     // delete characters
		{"abc\x1b[2D\x1b[2@\n", "a  bc\n"},       // insert blanks
		{"abcd\x1b[3D\x1b[2X\n", "a  d\n"},       // erase characters
		{"a\tb\n", "a       b\n"},                // tab stops
		{"x\x1b[5Cy\n", "x     y\n"},             // cursor forward pads
		{"p\x1b7q\x1b8Q\n", "pQ\n"},              // save and restore the cursor
		{"สวัสดี\n", "สวัสดี\n"},                 // combining marks stay with their letters
		{"日本\b\bX\n", "日X\n"},                    // a wide character is two columns
		{"bad\xffbyte\n", "bad�byte\n"},
		{"evil\u202egnp.exe\n", "evilgnp.exe\n"},     // bidi controls dropped
		{"bell\x07nul\x00del\x7f\n", "bellnuldel\n"}, // stray controls
		{"\x1b]0;never ended", ""},                   // an unterminated string hides only itself
		{"tail\x1b", "tail"},
	} {
		got, _ := vtText([]byte(c.in), 80, 24)
		if got != c.want {
			t.Errorf("vtText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVTTextIncomplete(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"done\n", 5},
		{"x\x1b[3", 1},
		{"x\x1b]0;tit", 1},
		{"x\x1b", 1},
		{"x\x1b]0;t\x1b", 1},
		{"สวั"[:4], 3},
		{"ok\x1b[0m", 6},
	} {
		if _, got := vtText([]byte(c.in), 80, 24); got != c.want {
			t.Errorf("incomplete(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestVTTextBounded: cursor moves stop at the terminal's width, so short
// input cannot expand into huge text.
func TestVTTextBounded(t *testing.T) {
	in := strings.Repeat("\x1b[9999Cx\x1b[9999@\n", 1000)
	got, _ := vtText([]byte(in), 120, 24)
	if len(got) > 130*1000 {
		t.Fatalf("%d bytes of input rendered as %d bytes of text", len(in), len(got))
	}
}

// Combining marks after a run of right halves whose wide characters were
// overwritten render in time bounded by the output's size: no mark searches
// the whole run for a character to join.
func TestVTCombiningAfterHalves(t *testing.T) {
	const run, marks = 64 << 10, 256 << 10
	var b strings.Builder
	b.WriteString(strings.Repeat("x", run+2))
	b.WriteString("一")
	for range run {
		b.WriteString("\x1b[3D一") // one column further left each time
	}
	for fwd := run + 4; fwd > 0; fwd -= 10000 {
		b.WriteString("\x1b[" + strconv.Itoa(min(fwd, 10000)) + "C")
	}
	b.WriteString(strings.Repeat("\u0301", marks)) // combining acute accents
	start := time.Now()
	vtText([]byte(b.String()), 500, 300)
	if d := time.Since(start); d > time.Second {
		t.Errorf("%d KiB rendered in %s", b.Len()>>10, d)
	}
	// A mark still joins the character before it, or the wide one whose
	// right half that is.
	for in, want := range map[string]string{"e\u0301": "e\u0301", "一\u0301": "一\u0301", "一x\b\b\u0301": "一\u0301x"} {
		if got, _ := vtText([]byte(in), 80, 24); got != want {
			t.Errorf("vtText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeyBytes(t *testing.T) {
	for name, want := range map[string]string{
		"Enter": "\r", "enter": "\r", "Tab": "\t", "Esc": "\x1b", "Up": "\x1b[A", "PgDn": "\x1b[6~",
		"F5": "\x1b[15~", "C-c": "\x03", "Ctrl+D": "\x04", "^z": "\x1a", "C-[": "\x1b", "C-@": "\x00",
		"C-\\": "\x1c", "C-?": "\x7f", "M-f": "\x1bf", "Alt+Left": "\x1b\x1b[D", "Backspace": "\x7f",
	} {
		if got, err := keyBytes(name); err != nil || got != want {
			t.Errorf("keyBytes(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, bad := range []string{"", "C-", "C-cc", "Hyper-x", "F13", "M-"} {
		if _, err := keyBytes(bad); err == nil || !strings.Contains(err.Error(), "Enter, Tab") {
			t.Errorf("keyBytes(%q) should fail with the list of keys, got %v", bad, err)
		}
	}
}

// conptyCapture is what Windows' ConPTY sent for a cmd.exe session on a real
// Windows Server 2022 agent: it moves to the next prompt with cursor jumps,
// not line breaks.
const conptyCapture = "\x1b[2J\x1b[m\x1b[HMicrosoft Windows [Version 10.0.20348.169]\x1b]0;C:\\Windows\\system32\\cmd.exe\a\x1b[?25h\x1b[?25l\r\n" +
	"(c) Microsoft Corporation. All rights reserved.\x1b[4;1Hadmin@winhost C:\\Users\\Administrator>\x1b]0;Administrator: C:\\Windows\\system32\\cmd.exe\a" +
	"\x1b[?25hecho hi-from-win\r\n\x1b[?25lhi-from-win\x1b[7;1Hadmin@winhost C:\\Users\\Administrator>\x1b[?25hcd C:\\Windows & set TVAR=kept\r\n\r\n" +
	"admin@winhost C:\\Windows>echo %CD%:%TVAR%\r\n\x1b[?25lC:\\Windows:kept\x1b[12;1Hadmin@winhost C:\\Windows>\x1b[?25hdir /b C:\\tern\r\n" +
	"\x1b[?25lagent.crt\r\nagent.key\r\nternd.exe\x1b[17;1Hadmin@winhost C:\\Windows>\x1b[?25h"

func TestVTTextRows(t *testing.T) {
	want := `Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

admin@winhost C:\Users\Administrator>echo hi-from-win
hi-from-win

admin@winhost C:\Users\Administrator>cd C:\Windows & set TVAR=kept

admin@winhost C:\Windows>echo %CD%:%TVAR%
C:\Windows:kept

admin@winhost C:\Windows>dir /b C:\tern
agent.crt
agent.key
ternd.exe

admin@winhost C:\Windows>`
	if got, _ := vtText([]byte(conptyCapture), 120, 32); got != want {
		t.Errorf("ConPTY session:\n%s\nwant:\n%s", got, want)
	}
	for _, c := range []struct {
		in, want string
		rows     int
	}{
		// A chunk from the middle of a session: its first jump only starts a line.
		{"echo hi-from-win\r\n\x1b[?25lhi-from-win\x1b[7;1Hadmin@winhost C:\\Users\\Administrator>\x1b[?25h", "echo hi-from-win\nhi-from-win\nadmin@winhost C:\\Users\\Administrator>", 32},
		{"\x1b[Ha\r\nb\r\nc\r\nd\x1b[3;1He", "a\nb\nc\ne", 3}, // the bottom row scrolls
		{"x\x1b[2By", "x\n\n y", 24},                          // down two rows, same column
		{"\x1b[Hone\r\ntwo\x1b[1;1HONE", "one\ntwo\nONE", 24}, // up: a new line
		{"abc\x1b[2Jdef", "abc\n   def", 24},                  // clearing the screen keeps the text
		{"\x1b[5d\x1b[3dup", "up", 24},                        // up from an unknown row
	} {
		if got, _ := vtText([]byte(c.in), 80, c.rows); got != c.want {
			t.Errorf("vtText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Output that keeps the cursor past a line it erased, or piles marks on one
// character, renders in time and space bounded by its size.
func TestVTBounded(t *testing.T) {
	long := strings.Repeat("x", 8192)
	for name, in := range map[string]string{
		"erase screen":    long + strings.Repeat("\x1b[2Ja", 4096),
		"erase line":      long + strings.Repeat("\x1b[2Ka", 50000),
		"restore cursor":  long + "\x1b7" + strings.Repeat("\x1b[2K\x1b8a", 30000),
		"combining marks": "a" + strings.Repeat("́", 128<<10),
		"pad every line":  strings.Repeat("\x1b[500Ca\n", 30000),
		"tabs":            strings.Repeat("1\t2\t3\t4\n", 10000),
		"jump down a lot": strings.Repeat("\x1b[1;1Hx\x1b[300;1Hy", 5000),
	} {
		start := time.Now()
		text, _ := vtText([]byte(in), 500, 300)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %d bytes took %s to render", name, len(in), d)
		}
		if limit := maxText(len(in), 500, 300) + len(textCutNote); len(text) > limit {
			t.Errorf("%s: %d bytes rendered to %d, over %d", name, len(in), len(text), limit)
		}
	}
	// Ordinary tab-separated output is not cut.
	in := strings.Repeat("1\t2\t3\t4\n", 1000)
	if text, _ := vtText([]byte(in), 120, 32); strings.Contains(text, "cut here") || strings.Count(text, "\n") != 1000 {
		t.Errorf("tabbed output was cut or lost lines")
	}
	// Padding every line to the width is cut, with a note.
	if text, _ := vtText([]byte(strings.Repeat("\x1b[500Ca\n", 30000)), 500, 32); !strings.HasSuffix(text, textCutNote) {
		t.Errorf("padded output was not cut")
	}
}

// Remote output must not make rendering quadratic: edits stay within a row.
func TestVTTextLinearOnLongLines(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(strings.Repeat("a", 128<<10))
	b.WriteString("\r")
	for b.Len() < 256<<10 {
		b.WriteString("\x1b[@")
	}
	start := time.Now()
	out, _ := vtText(b.Bytes(), 80, 24)
	el := time.Since(start)
	t.Logf("insert: %d bytes in -> %d out in %s", b.Len(), len(out), el)

	b.Reset()
	b.WriteString(strings.Repeat("a", 128<<10))
	for b.Len() < 256<<10 {
		b.WriteString("\x1b[1K")
	}
	start = time.Now()
	vtText(b.Bytes(), 80, 24)
	t.Logf("erase-left: %s", time.Since(start))
	if el > 2*time.Second {
		t.Errorf("vtText took %s on 256 KiB", el)
	}
}

// Alt with an uppercase letter keeps the shift.
func TestKeyAltKeepsShift(t *testing.T) {
	b, err := keyBytes("M-F")
	if err != nil {
		t.Fatal(err)
	}
	if b != "\x1bF" {
		t.Errorf("M-F sent %q, want ESC F", b)
	}
}
