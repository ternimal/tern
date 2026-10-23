// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Escape sequences, CSI (colors, cursor moves), OSC (titles, hyperlinks,
// shell-integration marks), DCS/SOS/PM/APC strings, charset designations and
// other two-byte escapes, in their 7-bit and 8-bit forms, are removed whole:
// dropping only the ESC byte leaves text like "[31m" behind, which can glue
// to a secret where redaction misses it, and sequences reaching a client UI
// could hide or spoof what a command printed. They are found by the
// terminal renderer's own parser (vtPlain), so text and a terminal agree on
// where every sequence ends, malformed ones included.

// invisible reports a character that shows nothing yet changes how text
// reads or carries text of its own, such as instructions to a model that a
// person never sees: format characters (zero-width and bidirectional
// controls, the byte-order mark, Unicode tag characters), variation
// selectors and the other default-ignorable characters such as the Hangul
// fillers, and the line and paragraph separators.
func invisible(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp,
		unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}

// cleanOutput turns raw command output into text that is safe to hand to a
// model and to display: valid UTF-8, no escape sequences, LF line endings, no
// control characters other than newline and tab, and nothing invisible, so a
// model reads what a person sees and a secret split by a zero-width character
// is still redacted. Where an escape sequence hid text, hiddenNote says so
// (see hide).
func cleanOutput(b []byte) string {
	p := vtPlain(noteOutput, true, strings.ToValidUTF8(string(b), "�"))
	text, _ := joinNotes(cleanSegs(p[0]), false)
	return text
}

// validText is b as valid UTF-8, each run of bytes that are not one
// replacement character, as vtPlain takes its parts.
func validText(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

// cleanSegs cleans a part of vtPlain's text as cleanRest does, in segments
// cut where its notes go: a note goes between each two.
func cleanSegs(p plainPart) []string {
	segs := make([]string, 0, len(p.notes)+1)
	last := 0
	for _, off := range p.notes {
		segs = append(segs, cleanRest(p.text[last:off]))
		last = off
	}
	return append(segs, cleanRest(p.text[last:]))
}

// joinNotes joins segments of text, between each two of which a note goes,
// with the notes. Notes with nothing between them make one: a run of
// sequences that each hide text is one place where text is hidden, noted
// once, so output that is all short hidden sequences cannot make the text
// many times longer than itself. led says that the text before the segments
// ends with a note, which their first note makes one with when nothing comes
// before it; joinNotes reports whether the text, so led on, ends with one.
func joinNotes(segs []string, led bool) (string, bool) {
	note := led && segs[0] == ""
	if len(segs) == 1 {
		return segs[0], note
	}
	var b strings.Builder
	b.WriteString(segs[0])
	for _, seg := range segs[1:] {
		if !note {
			b.WriteString(hiddenNote)
		}
		b.WriteString(seg)
		note = seg == ""
	}
	return b.String(), note
}

// cleanRest does the rest of cleanOutput's work on the text vtPlain made,
// whose escape sequences are gone and whose carriage returns are line
// breaks. It maps each character on its own, never two together, so it
// cannot join a secret to the text around it.
func cleanRest(s string) string { return strings.Map(cleanRune, s) }

// cleanRune is what cleanRest makes of r: r, a line break, or nothing (-1).
func cleanRune(r rune) rune {
	switch {
	case r == '\n' || r == '\t':
		return r
	case r == 0x0b || r == 0x0c || r == 0x85 || r == 0x2028 || r == 0x2029:
		return '\n' // vertical tab, form feed, NEL and the line and paragraph separators break the line, as on a terminal
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return -1 // other C0, DEL and C1 controls
	case invisible(r):
		return -1
	}
	return r
}

// cleanText is the text cleanOutput makes of s, without notes, and the
// offset in s of the character that made each byte of it.
func cleanText(s string) (string, []int32) {
	plain, from := plainOrigins(s)
	var b strings.Builder
	at := make([]int32, 0, len(plain))
	for i, r := range plain {
		if c := cleanRune(r); c >= 0 {
			b.WriteRune(c)
			for range utf8.RuneLen(c) {
				at = append(at, from[i])
			}
		}
	}
	return b.String(), at
}

// cleanWindow cleans a read and the output around it as cleanOutput would
// clean them as one text: an escape sequence that the read starts or ends
// inside is removed whole, rather than leaving a remnant such as "0m" that
// splits a secret where redaction misses it. Escape sequences are removed in
// one pass over the whole text, as in cleanOutput, never again in a part: a
// second pass could read what the first one left, such as a lone ESC now
// before a letter, as a sequence of its own and eat that letter. A note about
// hidden text goes in the part that holds the sequence's first byte.
func cleanWindow(before, mid, after []byte) (string, string, string) {
	p := vtPlain(noteOutput, true, validText(before), validText(mid), validText(after))
	b, led := joinNotes(cleanSegs(p[0]), false)
	m, led := joinNotes(cleanSegs(p[1]), led)
	a, _ := joinNotes(cleanSegs(p[2]), led)
	return b, m, a
}

// aroundRead is how much output on each side of a read is cleaned with it:
// as far as an escape sequence may reach, maxVTString bytes past where its
// length counts from and the rest of a character there, so that a sequence
// the read starts or ends inside is parsed whole, from its first byte, and
// so that the redactCtx bytes of text that redaction takes from each side
// are there however much of the output escape sequences hide.
const aroundRead = maxVTString + utf8.UTFMax

// cleanRedact cleans mid, a read of output or of a file, as cleanWindow does
// with the output around it, and redacts it with the last redactCtx bytes of
// the text before it and the first redactCtx bytes of the text after it (see
// redactWindow): of the text, not of the bytes, so a secret whose halves
// escape sequences keep apart in the bytes is found in a read as in the whole
// output. The notes about hidden text go in after redaction, so redaction
// sees the text on each side of a sequence joined, as a terminal shows it,
// and a note never splits a secret or is taken for part of one: one that
// falls inside a secret goes after its marker. rule says which hidden text is
// noted (see hide); before should reach far enough back to show the sequence
// a read starts after (see lookBack), and lineStart says whether it starts a
// line.
func cleanRedact(rule noteRule, lineStart bool, before, mid, after []byte) (string, int) {
	text, n, _ := cleanRedactNotes(rule, lineStart, before, 0, mid, after, -1)
	return text, n
}

// noteBudget is how long the text of a read of up to n bytes may grow with
// its notes, each of which counts len(hiddenNote) bytes toward it: as long as
// the read, or as long as an escape sequence may be, whichever is longer.
func noteBudget(n int) int { return max(n, maxVTString) }

// cleanRedactNotes is cleanRedact for a read whose notes count toward budget
// bytes, unless budget is negative: a read whose bytes, with its notes',
// would run past budget ends where the sequence that earns the first note
// that does so begins, and what follows is the text after it. A read keeps
// its first note, so it moves on. It returns the text, how many secrets it
// redacted, and how many bytes of mid the text covers.
//
// The first prefix bytes of before are those a look back read as text
// before its first ESC, CAN or SUB, not knowing what state the output was
// in there (see lookBack and textPrefix): they may be the hidden rest of a
// sequence begun before, whose text glues to what follows it in a way the
// whole output does not, as a CSI's parameters to a key that only hidden
// text comes between. Where their text is within reach of the read's
// redaction, the read is redacted again with the text before it taken from
// that ESC, CAN or SUB on, as if nothing came before.
func cleanRedactNotes(rule noteRule, lineStart bool, before []byte, prefix int, mid, after []byte, budget int) (string, int, int) {
	vp, vb, vm, covered := validText(before[:prefix]), validText(before[prefix:]), validText(mid), len(mid)
	if utf8.Valid(mid) {
		mid = nil // offsets in its text are its own: rawPrefix needs no bytes, and a large read's go
	}
	p := vtPlain(rule, lineStart, vp, vb, vm, validText(after))
	m, rest := p[2], p[3].text
	if j := noteCut(m, len(vp)+len(vb), budget); j > 0 {
		off := m.notes[j]
		covered = rawPrefix(mid, m.raws[j]-len(vp)-len(vb))
		rest = m.text[off:] + rest
		m = plainPart{text: m.text[:off], notes: m.notes[:j], raws: m.raws[:j]}
	}
	// The text before the read is redacted in its segments too, so the read
	// learns whether that text, as the whole output shows it, ends with a
	// note its first one makes one with (see joinNotes): a secret that runs on
	// from before it moves the notes inside it past its marker. The prefix
	// holds no sequence, so no note; it is a segment of its own so that the
	// pass without it starts from what the first pass left of the text after
	// it: a private key the first pass took whole, from its BEGIN line before
	// the read to its END line in the read, is not taken again as one cut off
	// with the rest of the read.
	pre, bsegs := cleanRest(p[0].text), cleanSegs(p[1])
	ctx := tailSegs(append([]string{pre}, bsegs...), redactCtx)
	bs, segs, after2, n := redactAround(ctx, cleanSegs(m), textHead(cleanRest(rest), redactCtx))
	if len(ctx) > len(bsegs) {
		if ctx[0] != "" {
			var k int
			_, segs, _, k = redactAround(bs[1:], segs, after2)
			n += k
		}
		bs = joinSegs(bs[:1], bs[1:])
	}
	_, led := joinNotes(bs, false)
	text, _ := joinNotes(segs, led)
	return text, n, covered
}

// textPrefix is how many bytes at the start of look, the output before a
// read as lookBack gives it, that look back read as text (see asText): those
// before its first ESC, CAN or SUB, when cut says it does not start the
// output. A look back with no ESC, CAN or SUB in it has none that can be
// told from the read: 0.
func textPrefix(look []byte, cut bool) int {
	if !cut {
		return 0
	}
	return max(bytes.IndexAny(look, "\x1b\x18\x1a"), 0)
}

// tailSegs keeps the last n bytes of the text of segs, segments between each
// two of which a note goes, or a little less so it starts on a character.
func tailSegs(segs []string, n int) []string {
	total := 0
	for i := len(segs) - 1; i >= 0; i-- {
		total += len(segs[i])
		if total > n {
			return append([]string{textTail(segs[i], n-(total-len(segs[i])))}, segs[i+1:]...)
		}
	}
	return segs
}

// textTail returns the last n bytes of s, or a little less, so it starts on
// a character.
func textTail(s string, n int) string {
	i := len(s) - n
	if i <= 0 {
		return s
	}
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

// textHead returns the first n bytes of s, or a little less, so it ends on a
// character.
func textHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// notesCover returns how many bytes of mid cleanRedactNotes covers, without
// cleaning or redacting it.
func notesCover(rule noteRule, lineStart bool, before, mid, after []byte, budget int) int {
	vb := validText(before)
	p := vtPlain(rule, lineStart, vb, validText(mid), validText(after))
	if j := noteCut(p[1], len(vb), budget); j > 0 {
		return rawPrefix(mid, p[1].raws[j]-len(vb))
	}
	return len(mid)
}

// noteCut returns the index of the first of m's notes, m being a read's part
// of vtPlain's text and pos where in the output it starts, that takes the
// read's bytes and its notes past budget, or 0 when none does or budget is
// negative. A note costs len(hiddenNote), but one that makes one with the
// note before it (see joinNotes) costs nothing and never cuts.
func noteCut(m plainPart, pos, budget int) int {
	if budget < 0 {
		return 0
	}
	cost := 0
	for j := range m.notes {
		if j > 0 && cleanRest(m.text[m.notes[j-1]:m.notes[j]]) == "" {
			continue
		}
		cost += len(hiddenNote)
		if j > 0 && m.raws[j]-pos+cost > budget {
			return j
		}
	}
	return 0
}

// rawPrefix returns how many bytes of b make the first n bytes of
// validText(b), n being where a character begins.
func rawPrefix(b []byte, n int) int {
	if utf8.Valid(b) {
		return n
	}
	i, j := 0, 0 // in b, and in its valid form
	for i < len(b) && j < n {
		if r, size := utf8.DecodeRune(b[i:]); r != utf8.RuneError || size > 1 {
			i, j = i+size, j+size
			continue
		}
		for i < len(b) {
			if r, size := utf8.DecodeRune(b[i:]); r != utf8.RuneError || size > 1 {
				break
			}
			i++
		}
		j += len("�")
	}
	return i
}

// asText returns b, output from a place a parse cannot know the state of,
// as a parse that a terminal reading all of the output agrees with reads it:
// from its first ESC, CAN or SUB on, after which every parser state is the
// same (see vt.write), b is as it is; before it, b is text, so that no
// sequence a parse could only guess at hides what follows, as a C1
// introducer in the body of a string begun before b would. There a C1
// control that begins a sequence becomes U+0080, which begins none, a
// carriage return a vertical tab, which breaks the line as it does but pairs
// with no line feed after it, and a backspace a NUL. Its length stays the
// same.
func asText(b []byte) []byte {
	k := bytes.IndexAny(b, "\x1b\x18\x1a")
	if k < 0 {
		k = len(b)
	}
	var out []byte
	set := func(i int, c byte) {
		if out == nil {
			out = bytes.Clone(b)
		}
		out[i] = c
	}
	for i := 0; i < k; i++ {
		switch c := b[i]; {
		case c == '\r':
			set(i, '\v')
		case c == '\b':
			set(i, 0)
		case c == 0xc2 && i+1 < k:
			switch b[i+1] {
			case 0x90, 0x98, 0x9b, 0x9d, 0x9e, 0x9f: // DCS, SOS, CSI, OSC, PM, APC
				set(i+1, 0x80)
				i++
			}
		}
	}
	if out == nil {
		return b
	}
	return out
}

// lookBack returns what a parse looks back at to learn the state output is
// in where a read starts, as far back as an escape sequence may reach: the
// last aroundRead bytes of before, the output before the read, which starts
// at offset start in the output, read as text up to their first ESC, CAN or
// SUB (see asText) unless they start the output.
func lookBack(before []byte, start int64) []byte {
	look := before[max(len(before)-aroundRead, 0):]
	if start+int64(len(before)-len(look)) > 0 {
		return asText(look)
	}
	return look
}

// seqHead returns how many bytes at the start of data finish an escape
// sequence or a UTF-8 character that look, the output before data as
// lookBack gives it, ends inside, as the terminal renderer reads them: all of
// data while the sequence does not end. They show nothing, so a page of
// output or of a file that would start there starts after them instead. data
// should reach past the page, so a sequence the page is all inside is seen to
// end.
func seqHead(look, data []byte) int {
	return vtHead(look[vtOpen(look):], data, 80, 24)
}

// seqTail returns where an escape sequence or a UTF-8 character that data,
// which starts outside any, ends inside begins, as the terminal renderer
// reads data from its start, or len(data). A page of output that more
// follows ends there, so the next page starts with it whole, and a note
// about what the sequence hid, which goes where it began (see hide), is in
// the page that holds all of it.
func seqTail(data []byte) int { return vtOpen(data) }

// hidden reports a character that escapeHidden escapes.
func hidden(r rune) bool {
	return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || r >= 0x80 && r <= 0x9f || invisible(r)
}

// escapeHidden makes what a person would not see in s visible: control
// characters other than newline and tab, and invisible characters, become \x,
// \u or \U escapes. It is for text from a remote host that a tool shows
// rather than returns as output, such as an agent's error message, where a
// path or a name that holds them stays recognizable instead of changing
// silently.
func escapeHidden(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if !strings.ContainsFunc(s, hidden) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !hidden(r):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r > 0xffff:
			fmt.Fprintf(&b, `\U%08x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// cutOutput cleans and redacts output that was capped at max bytes, given up
// to aroundRead bytes more of it after the cap: a secret, or an escape
// sequence, that the cap cuts is removed whole, never left in part.
func cutOutput(raw []byte, max int) (string, int) {
	text, n, _ := cutOutputNotes(raw, max)
	return text, n
}

// cutOutputNotes is cutOutput whose notes count toward the cap (see
// cleanRedactNotes); cut reports that output was left out for them.
func cutOutputNotes(raw []byte, max int) (text string, redacted int, cut bool) {
	data, rest := raw, []byte(nil)
	if len(raw) > max {
		data, rest = raw[:max], raw[max:]
		if cut := seqTail(data); cut > 0 {
			data, rest = raw[:cut], raw[cut:]
		}
	}
	text, redacted, covered := cleanRedactNotes(noteOutput, true, nil, 0, data, rest, noteBudget(max))
	return text, redacted, covered < len(data)
}

// cappedBuffer keeps the first max bytes written to it and records whether
// more arrived, so one noisy command cannot exhaust memory or the model's
// context.
type cappedBuffer struct {
	mu        sync.Mutex
	b         []byte
	max       int
	truncated bool
}

func newCappedBuffer(max int) *cappedBuffer { return &cappedBuffer{max: max} }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	room := max(c.max-len(c.b), 0)
	if n > room {
		c.truncated = true // bytes are being dropped
		p = p[:room]
	}
	c.b = append(c.b, p...)
	// Report the full length so the sender keeps streaming; the drop is ours.
	return n, nil
}

func (c *cappedBuffer) result() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.b...), c.truncated
}
