// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// hiddenRune reports characters that must never reach a model or a person
// raw: controls, which a terminal or UI acts on, and invisible or
// bidirectional characters, which can hide or reorder text.
func hiddenRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

func FuzzVTText(f *testing.F) {
	for _, s := range []string{"plain\r\n", "\x1b[31mred\x1b[0m", "ab\rX\x1b[K\n", "\x1b]0;t\a$ ", "สวัสดี\b\bx",
		"\x1b[9999C\x1b[9999@x", "\x1b[5;1Hdown\x1b[1;1Hup", conptyCapture, "\x1bP\x1b\\", "\u009b2J", "\xff\xfe"} {
		f.Add([]byte(s), 80, 24)
	}
	f.Fuzz(func(t *testing.T, b []byte, cols, rows int) {
		cols, rows = cols%600, rows%400
		if cols < 0 {
			cols = -cols
		}
		if rows < 0 {
			rows = -rows
		}
		text, inc := vtText(b, cols, rows)
		if inc < 0 || inc > len(b) {
			t.Fatalf("incomplete %d out of range for %d bytes", inc, len(b))
		}
		if !utf8.ValidString(text) {
			t.Fatalf("invalid UTF-8 out: %q", text)
		}
		for _, r := range text {
			if r != '\n' && hiddenRune(r) {
				t.Fatalf("%U reached the text: %q", r, text)
			}
		}
		if limit := (len(b) + 1) * (max(cols, 1) + max(rows, 1) + 4); len(text) > limit {
			t.Fatalf("%d bytes rendered as %d", len(b), len(text))
		}
		// Cut where the renderer says, no escape sequence or character is
		// left unfinished. Only bytes that were invalid UTF-8 where they
		// stood may look unfinished once cut off from what followed.
		if _, again := vtText(b[:inc], cols, rows); again != inc && utf8.Valid(b[again:inc]) {
			t.Fatalf("cut at %d still ends unfinished at %d: %q", inc, again, b[again:inc])
		}
	})
}

// A read cleaned with the text around it comes out as the same text as the
// whole cleaned at once, wherever the read starts and ends: no escape
// sequence is removed twice, or in part, a CR and LF a read is cut between
// still make one line break, and nothing else changes. Reads start and end
// on characters, as pages do.
func FuzzCleanWindow(f *testing.F) {
	for _, s := range []string{"user=bob \x1b\x1b[mpassword=Hunter2xyzzy\n", "x\x1b]0;title\x07ok\r\n", "a\x1b[31\x18b",
		"\u009b31mAKIA\x1b(\x1b[1 2m", "\x1bP1$r\x1b\\z\x1b\x1bE", "\x1b[1\n2mq\v\u0085", "\r\x1bc"} {
		f.Add([]byte(s), uint16(3), uint16(9))
	}
	f.Fuzz(func(t *testing.T, b []byte, i, j uint16) {
		s := strings.ToValidUTF8(string(b), "�")
		cut := func(k uint16) int {
			n := int(k) % (len(s) + 1)
			for n > 0 && n < len(s) && !utf8.RuneStart(s[n]) {
				n--
			}
			return n
		}
		from, to := cut(i), cut(j)
		if from > to {
			from, to = to, from
		}
		b0, m, a := cleanWindow([]byte(s[:from]), []byte(s[from:to]), []byte(s[to:]))
		if whole := cleanOutput([]byte(s)); b0+m+a != whole {
			t.Fatalf("cleanWindow(%q) cut at [%d,%d) = %q %q %q, but the whole cleans to %q", s, from, to, b0, m, a, whole)
		}
	})
}

func FuzzRedactSplit(f *testing.F) {
	f.Add("DB_PASS", "WORD=hunter2 AKIAIOSFO", "DNN7EXAMPLE")
	f.Add("", "-----BEGIN RSA PRIVATE KEY-----\nabc", "\n-----END RSA PRIVATE KEY-----")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		parts, n := redactSplit([]string{a, b, c})
		want, wn := redact(a + b + c)
		if len(parts) != 3 || strings.Join(parts, "") != want || n != wn {
			t.Fatalf("redactSplit(%q, %q, %q) = %q (%d), want %q (%d)", a, b, c, parts, n, want, wn)
		}
	})
}

func FuzzConfirmDisplay(f *testing.F) {
	for _, s := range []string{"rm -rf /", "echo \x1b]0;\nrm -rf ~\n\a", "safe\u202etxt", "a\u200bb", "สวัสดี", "\xff", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		shown := show(s)
		for _, r := range shown {
			if hiddenRune(r) {
				t.Fatalf("show(%q) = %q holds %U", s, shown, r)
			}
		}
		if strings.HasPrefix(shown, `"`) {
			if back, err := strconv.Unquote(shown); err != nil || back != s {
				t.Fatalf("show(%q) = %q does not unquote to the value", s, shown)
			}
		} else if shown != s {
			t.Fatalf("show(%q) = %q changed an unquoted value", s, shown)
		}
		for _, line := range strings.Split(strings.TrimSuffix(preview("Data", []byte(s)), "\n"), "\n")[2:] {
			if !strings.HasPrefix(line, "  | ") {
				t.Fatalf("preview line %q is not marked", line)
			}
			for _, r := range line {
				if r != '\t' && hiddenRune(r) {
					t.Fatalf("preview of %q holds %U", s, r)
				}
			}
		}
	})
}

func FuzzKeyBytes(f *testing.F) {
	for _, s := range []string{"Enter", "C-c", "M-x", "Alt+Left", "^z", "F12", "c-", "M-", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if b, err := keyBytes(name); err == nil && b == "" {
			t.Fatalf("keyBytes(%q) gave nothing", name)
		}
	})
}

// noteOracle counts the notes the rule puts in s, valid UTF-8 that starts a
// line: one for each run of sequences whose hidden text the rule notes (see
// hide) with nothing shown between their notes, which go where the run of
// sequences that ESCs chain together began. Where each sequence begins and
// ends comes from the parser itself, run one character at a time; the rule
// is applied afterwards, to the whole of s, rather than as vtPlain applies
// it, with notes that wait for their line.
func noteOracle(s string, rule noteRule) int {
	type seq struct {
		kind     vtState // vtCSI, vtEscInter or vtString
		start    int     // where the character that began it is
		chain    int     // where the run of sequences it is in began: where its note goes
		endCur   int     // where the character that ended it ends
		after    int     // string: where its line after it is followed from
		params   []byte  // CSI: its parameter and intermediate bytes
		inter    int     // escape: its intermediate bytes
		ctl      bool    // CSI and escape: a control character was carried out inside it
		body     int     // string: its body's bytes
		nl       bool    // string: a line break among them
		complete bool    // CSI: it ended with a final byte
	}
	type event struct {
		at, end int
		lf, vis bool
	}
	var seqs []seq
	var events []event
	v := vt{width: 1, height: 1, mode: modeParse}
	open := -1 // the sequence being parsed, if any
	cur := 0   // where the last character fed ends
	closeOpen := func(complete bool) {
		if open >= 0 {
			seqs[open].endCur, seqs[open].after, seqs[open].complete = cur, cur, complete
			open = -1
		}
	}
	lenStart, chain := 0, 0 // where the sequence's length counts from, and where its run began
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if v.state != vtGround && i-lenStart > maxVTString {
			v.state = vtGround
			closeOpen(false)
		}
		switch {
		case v.state == vtGround:
			lenStart, chain = i, i
		case r == 0x1b:
			lenStart = i // an ESC begins a sequence of its own
		}
		prev := v.state
		if prev == vtGround && r >= 0x20 && r != 0x7f && !(r >= 0x80 && r <= 0x9f) && !unicode.IsSpace(r) && !invisible(r) {
			events = append(events, event{at: i, end: i + size, vis: true})
		} else if r == '\n' {
			events = append(events, event{at: i, end: i + size, lf: true})
		} else {
			events = append(events, event{at: i, end: i + size})
		}
		v.feed(r)
		cur = i + size
		next := v.state
		if open >= 0 {
			sq := &seqs[open]
			switch sq.kind {
			case vtCSI:
				switch {
				case next == vtCSI && (r >= 0x20 && r <= 0x3f):
					sq.params = append(sq.params, byte(r))
				case next == vtCSI && r < 0x20:
					sq.ctl = true
				case next == vtGround && r >= 0x40 && r <= 0x7e && prev == vtCSI:
					closeOpen(true)
				case next != vtCSI:
					closeOpen(false)
				}
			case vtEscInter:
				switch {
				case next == vtEscInter && r >= 0x20 && r <= 0x2f:
					sq.inter++
				case next == vtEscInter && r < 0x20:
					sq.ctl = true
				case next != vtEscInter:
					closeOpen(false)
				}
			case vtString:
				switch {
				case prev == vtString && next == vtString:
					sq.body += size
					sq.nl = sq.nl || r == '\n' || r == '\r' || r == 0x0b || r == 0x0c || r == 0x85 || r == 0x2028 || r == 0x2029
				case prev == vtString && next == vtStringEsc:
				case prev == vtString && next == vtGround && v.strLen > maxVTString:
					sq.body += size
					closeOpen(false)
				case prev == vtStringEsc:
					// The ESC ended it: what follows the ESC, a line feed
					// included, is its line's after it.
					closeOpen(false)
					sq.after = i
				default:
					closeOpen(false)
				}
			}
		}
		if open < 0 && next != vtGround && next != vtEsc && next != vtStringEsc && (prev != next || prev == vtEsc) {
			seqs = append(seqs, seq{kind: next, start: i, chain: chain})
			if next == vtEscInter {
				seqs[len(seqs)-1].inter = 1
			}
			open = len(seqs) - 1
		}
		i += size
	}
	closeOpen(false)
	plausible := regexp.MustCompile(`^[<=>?]?[0-9:;]*[ !"#$'*+,]{0,2}$`)
	var noted []int // where the notes go, as offsets in s
	for _, sq := range seqs {
		switch sq.kind {
		case vtCSI:
			if !sq.complete || len(sq.params) > maxCSIParams || !plausible.Match(sq.params) || sq.ctl {
				noted = append(noted, sq.chain)
			}
		case vtEscInter:
			if sq.inter > maxInter || sq.ctl {
				noted = append(noted, sq.chain)
			}
		case vtString:
			if sq.body == 0 {
				continue
			}
			if rule == noteFile || sq.nl || sq.body > hiddenNoteMin {
				noted = append(noted, sq.chain)
				continue
			}
			before := false // text on its line before it
			for _, e := range events {
				if e.at >= sq.start {
					break
				}
				switch {
				case e.lf:
					before = false
				case e.vis:
					before = true
				}
			}
			if before {
				noted = append(noted, sq.chain)
				continue
			}
			shows := true // what comes after it on its line decides
			for _, e := range events {
				if e.at < sq.after {
					continue
				}
				if e.lf {
					shows = false
				}
				if e.lf || e.vis || e.end >= sq.endCur+noteLook {
					break
				}
			}
			if shows {
				noted = append(noted, sq.chain)
			}
		}
	}
	// Notes with nothing shown between them are one: the text the whole
	// output makes from one note's place to the next, the characters that
	// made it from where the first one's run of sequences begins, shows
	// nothing. A carriage return makes a line break that a line feed after
	// it, or a line-moving escape such as RIS, shares.
	slices.Sort(noted)
	text, from := plainOrigins(s)
	shown := make([]bool, len(noted)+1) // shown[i]: something shows between notes i-1 and i
	for k := 0; k < len(text); {
		r, size := utf8.DecodeRuneInString(text[k:])
		if cleanRune(r) >= 0 {
			shown[sort.SearchInts(noted, int(from[k])+1)] = true
		}
		k += size
	}
	count := 0
	for i := range noted {
		if i == 0 || shown[i] {
			count++
		}
	}
	return count
}

func FuzzHiddenNotes(f *testing.F) {
	for _, s := range []string{
		"a\x1b]0;" + strings.Repeat("x", 300) + "\x07b", "a\x1b]0;x\ny\x07b", "a\x1bPq\r\x1b\\b", "\x1b]0;a\x1b]0;" + strings.Repeat("y", 300) + "\x07",
		"\u009dtitle x\u009c", "\x1b_" + strings.Repeat("z", 256) + "\x18rest", "\x1b]0;\x1b\nx\x07", "\x1b[1\x1b]2;" + strings.Repeat("q", 257),
		"\x1bX\x07\x07" + strings.Repeat("w", 300), "\x1b^\u0085\x1b\\", "echo hi\x1b]0; x #\x07\n", "\x1b]0;t\x07\n", "\x1b]0;t\x07echo\n",
		"x\r\x1b]0;t\x07\n", "echo hi\x1b[ ;./0 #~\n", "a\x1b[1;?2m", "a\x1b !!x", "\x1b]0;t\x07" + strings.Repeat("\x1b[0m", 300) + "\n",
		"\x1b]0;a\x07\x1b]0;b\x07c", "\x1b[31\x18", "\x1b]\x07x", "echo hi\x1b]0;x\x1b\n\n", "\x1b]0;x\x1b\necho hi\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		s = strings.ToValidUTF8(s, "�")
		if strings.Contains(s, "hidden in a terminal") {
			return
		}
		for _, rule := range []noteRule{noteOutput, noteFile} {
			got, _ := cleanRedact(rule, true, nil, []byte(s), nil)
			if n, want := strings.Count(got, hiddenNote), noteOracle(s, rule); n != want {
				t.Fatalf("rule %d notes %d sequences, the oracle %d: %q -> %q", rule, n, want, s, got)
			}
		}
	})
}

// pagePieces are what the paging fuzzers build files and output from:
// secrets, escape sequences that hide text and ones that do not, line
// breaks, and characters of every UTF-8 length.
var pagePieces = []string{
	"AKIAIOSFODNN7EXAMPLE", "password=Hunter2xyzzy", "ghp_" + strings.Repeat("Q", 18) + strings.Repeat("Z", 18),
	"\x1b[31m", "\x1b[0m", "\x1b]0;title\x07", "\x1b]0;" + strings.Repeat("H", 300) + "\x07", "\x1b]0;a\nb\x07",
	"\x1bP1$r\x1b\\", "\x1b", "\r", "\n", "\r\n", "\t", " ", "é", "中", "😀", "は", "word", "=", ":", "'", "\"",
	"db_password:\n  ", "  ", "\u200b", "\x1b[ ;x #~", "echo ", "\x1b(", "\x1b[1",
}

func buildPages(seed []byte) string {
	var b strings.Builder
	for _, c := range seed[:min(len(seed), 40)] {
		b.WriteString(pagePieces[int(c)%len(pagePieces)])
	}
	return b.String()
}

// Pages of a file, read one after another, hold the text the whole file
// read at once does, notes included, in the same encoding.
func FuzzFilePagesEqualWhole(f *testing.F) {
	f.Add([]byte{0, 3, 6, 7, 1, 11}, uint16(7))
	f.Add([]byte{5, 6, 10, 0}, uint16(3))
	f.Add([]byte{9, 7, 18, 17}, uint16(2))
	f.Fuzz(func(t *testing.T, seed []byte, lim uint16) {
		file := []byte(buildPages(seed))
		if len(file) == 0 {
			return
		}
		limit := int(lim%300) + 1
		whole := readPage(file, 0, 1<<20)
		var b strings.Builder
		for _, p := range readPages(t, file, limit) {
			if p.Encoding != whole.Encoding {
				t.Fatalf("a page (limit %d) is %s, the whole read %s\nfile %q", limit, p.Encoding, whole.Encoding, file)
			}
			b.WriteString(p.Content)
		}
		if b.String() != whole.Content {
			t.Fatalf("pages (limit %d) differ from the whole read\nfile  %q\npages %q\nwhole %q", limit, file, b.String(), whole.Content)
		}
	})
}

// Polls of a finished job's output, one after another, hold the text one
// whole poll does.
func FuzzJobPagesEqualWhole(f *testing.F) {
	f.Add([]byte{0, 3, 6, 7, 1, 11}, uint16(7))
	f.Add([]byte{17, 20, 20}, uint16(2))
	f.Fuzz(func(t *testing.T, seed []byte, lim uint16) {
		out := []byte(buildPages(seed))
		if len(out) == 0 {
			return
		}
		limit := int(lim%300) + 1
		if pages, whole := pollPages(t, out, limit); pages != whole {
			t.Fatalf("polls (limit %d) differ from the whole poll\nout   %q\npages %q\nwhole %q", limit, out, pages, whole)
		}
	})
}

// Pages of a UTF-16 file are text on code unit boundaries, show no part of
// a key the whole read hides, and hold the text the whole read does.
func FuzzUTF16PagesEqualWhole(f *testing.F) {
	f.Add([]byte{0, 17, 18, 12, 1, 13}, uint16(9), false, uint16(5))
	f.Add([]byte{14, 0, 15, 2, 11}, uint16(4), true, uint16(1))
	f.Fuzz(func(t *testing.T, seed []byte, lim uint16, bigEndian bool, off uint16) {
		text := buildPages(seed)
		if text == "" {
			return
		}
		file := utf16File(text, bigEndian)
		limit := int(lim%120) + 1
		whole := readPage(file, 0, 1<<20)
		pages := append(readPages(t, file, limit), readPage(file, int64(off)%int64(len(file)), limit))
		var b strings.Builder
		for i, p := range pages {
			if p.Encoding != "text" || p.Offset%2 != 0 || p.NextOffset%2 != 0 {
				t.Fatalf("UTF-16 page %+v", p)
			}
			for _, k := range []string{"IOSFODNN7EXAMPLE", "Hunter2xyzzy", "QQQQQQQQZZZZZZZZ"} {
				if strings.Contains(p.Content, k[:8]) && !strings.Contains(whole.Content, k[:8]) {
					t.Fatalf("a page shows part of a key the whole read hides\ntext %q\npage %q\nwhole %q", text, p.Content, whole.Content)
				}
			}
			if i < len(pages)-1 {
				b.WriteString(p.Content)
			}
		}
		if b.String() != whole.Content {
			t.Fatalf("UTF-16 pages (limit %d) differ from the whole read\ntext  %q\npages %q\nwhole %q", limit, text, b.String(), whole.Content)
		}
	})
}

// A rule's hints never keep it from text it matches.
func FuzzRedactionHints(f *testing.F) {
	for _, s := range []string{"AKIAIOSFODNN7EXAMPLE", "Key=x", "ſecret_key: x", "DB_PAſſWORD=x", "curl -u a:b x",
		"x --relay-token y", "AccountKey=x", `"keyName": "k", "value": "x"`, "redis-cli -a x", "smbclient -U a%b", "-passin pass:x",
		"pa\u017f\u017fword: a b", "Authorization: Digest a=\"b\", c=d", "-storepa\u017f\u017f x", "7Z x -px", "nmcli c password x",
		"SQLPLUS a/b@c", "net use \\\\a\\b c", "htpasswd -b f u p", "aws configure set aws_\u017fecret_access_key x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		folded := foldCase(s)
		for _, r := range redactions {
			if len(r.hint) > 0 && r.re.MatchString(s) && !slices.ContainsFunc(r.hint, func(h string) bool { return strings.Contains(folded, h) }) {
				t.Fatalf("%q matches %s, but holds none of its hints %q", s, r.re, r.hint)
			}
		}
	})
}
