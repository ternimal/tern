// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// vtText renders terminal output as the text a person reads in a terminal's
// scrollback. A VT parser, not a pattern, removes escape sequences, so no
// remnant like "[31m" survives and an unterminated sequence hides nothing
// past the input. Within each line, carriage return, backspace, tab, line
// erasing and horizontal cursor moves are applied, which is how shells redraw
// an edited command line and programs draw progress bars. Cells know wide and
// combining characters. A jump down the screen becomes the line breaks it
// skips, which is how Windows' ConPTY moves to the next prompt; a jump up only
// starts a new line, since text cannot show it. Full-screen programs need the
// screen itself, not text.
//
// width and height are the terminal's size; cursor moves stop at its edges,
// as on a terminal, so output cannot grow much larger than its input, and
// past maxText(len(b), width, height) bytes it is cut, with a note. b may
// start anywhere in a session, so the row it starts on is unknown until a
// cursor jump names one. incomplete is where an escape sequence or UTF-8
// sequence that b ends inside begins, or len(b): a caller that reads output
// in chunks should start the next one there.
func vtText(b []byte, width, height int) (text string, incomplete int) {
	v := vt{width: max(width, 1), height: max(height, 1), max: maxText(len(b), width, height)}
	incomplete = v.write(b, 0)
	if v.state != vtGround {
		incomplete = min(incomplete, v.seqStart)
	}
	v.finish()
	return v.out.String(), incomplete
}

// vtNoted is vtText's text of data, and where in it hiddenNote goes: at the
// start of each line that holds text an escape sequence hid (see hide), as
// offsets in the text, for the caller to put in once the text is redacted.
// before and after are the output around data: before tells whether data's
// first line already shows text, and after settles a string near the end of
// data whose line goes on past it.
func vtNoted(data, before, after []byte, width, height int) (string, []int) {
	v := vt{width: max(width, 1), height: max(height, 1), max: maxText(len(data), width, height), lineVis: lineShows(before), withNotes: true}
	n := v.write(data, 0)
	if len(v.pending) > 0 {
		// The terminal shows nothing more; the rest only settles the note.
		v.mode = modeParse
		v.write(append(append([]byte(nil), data[n:]...), after...), n)
	}
	v.endInput()
	v.finish()
	return v.out.String(), v.noteAt
}

// lineShows reports whether before, the output before a read, shows a
// character other than a space on its last line, since its last line feed.
// A line before holds no line feed of may have begun earlier, with text: it
// counts as showing some, unless before is empty.
func lineShows(before []byte) bool {
	v := vt{width: 1, height: 1, mode: modeParse, lineVis: len(before) > 0}
	v.write(before, 0)
	return v.lineVis
}

// vtOpen returns where an escape sequence or a UTF-8 character that b ends
// inside begins, or len(b): vtText's incomplete, without rendering the text.
func vtOpen(b []byte) int {
	v := vt{width: 1, height: 1, mode: modeParse}
	incomplete := v.write(b, 0)
	if v.state != vtGround {
		incomplete = min(incomplete, v.seqStart)
	}
	return incomplete
}

// plainPart is one of vtPlain's parts: its text, and where in it, as
// offsets, hiddenNote goes, in ascending order; raws holds, for each note,
// where in the output the sequence that earned it began.
type plainPart struct {
	text  string
	notes []int
	raws  []int
}

// vtPlain returns parts of output, which follow one another, with what a
// terminal reads as escape sequences taken out: the text and the control
// characters stay as they are, line edits and cursor moves are not applied,
// a control character a terminal carries out inside a sequence stays, and
// the escapes that move to another line (NEL, IND, RI, RIS) leave a line
// break. A carriage return becomes a line break, one with a line feed right
// after it. A sequence, or a CR and LF, that one part ends inside goes on in
// the next, so the parts come out as the whole would. Each part must be
// valid UTF-8.
//
// What a sequence makes, a control character carried out inside it or a
// note about what it hid (see hide), goes in the part that holds the
// sequence's first byte, at the place in its text where the sequence began,
// and the line break of a carriage return in the part that holds the
// carriage return: a page that ends inside a sequence, which the next page
// starts after, shows all of it. rule says which hidden text is noted, and
// lineStart whether the output starts a line, which tells whether the text
// on a sequence's line before it shows anything.
func vtPlain(rule noteRule, lineStart bool, parts ...string) []plainPart {
	v := vt{width: 1, height: 1, mode: modePlain, rule: rule, lineVis: !lineStart, plain: make([]strings.Builder, len(parts))}
	pos := 0
	for i, p := range parts {
		v.part = i
		v.write([]byte(p), pos)
		pos += len(p)
	}
	if v.crPending {
		v.plain[v.crPart].WriteByte('\n')
	}
	v.endInput()
	out := make([]plainPart, len(parts))
	for i := range out {
		out[i].text = v.plain[i].String()
	}
	slices.SortFunc(v.notes, func(a, b vtNote) int {
		if a.part != b.part {
			return a.part - b.part
		}
		if a.off != b.off {
			return a.off - b.off
		}
		return a.raw - b.raw
	})
	for _, n := range v.notes {
		out[n.part].notes = append(out[n.part].notes, n.off)
		out[n.part].raws = append(out[n.part].raws, n.raw)
	}
	return out
}

// plainOrigins is vtPlain's text of s as one part, without notes, and the
// offset in s of the character that made each byte of the text: of a
// carriage return, for the line break it becomes.
func plainOrigins(s string) (string, []int32) {
	v := vt{width: 1, height: 1, mode: modePlain, plain: make([]strings.Builder, 1), origins: make([]int32, 0, len(s))}
	v.write([]byte(s), 0)
	if v.crPending {
		v.plain[0].WriteByte('\n')
		v.origins = append(v.origins, int32(v.crAt))
	}
	return v.plain[0].String(), v.origins
}

// plainRune adds r to vtPlain's text, a carriage return as a line break that
// waits to see whether a line feed follows, which it takes in.
func (v *vt) plainRune(r rune) {
	if v.crPending {
		v.crPending = false
		v.plain[v.crPart].WriteByte('\n')
		if v.origins != nil {
			v.origins = append(v.origins, int32(v.crAt))
		}
		if r == '\n' {
			return
		}
	}
	if r == '\r' {
		v.crPending, v.crPart, v.crAt = true, v.outPart, v.cur-v.size
		return
	}
	v.plain[v.outPart].WriteRune(r)
	if v.origins != nil {
		for range utf8.RuneLen(r) {
			v.origins = append(v.origins, int32(v.cur-v.size))
		}
	}
}

// write feeds b, which starts at offset pos in the output, to the terminal,
// and returns how much of it was taken: all of it but a UTF-8 character it
// ends inside, whose rest is still to come.
//
// An ESC ends the sequence being parsed, if any (in a string it may begin
// the ST that ends it), and begins a sequence of its own, whose length
// counts from the ESC, as on a terminal. So after an ESC, a CAN or a SUB
// every parser state is the same, and a parse that starts there, knowing
// nothing of the output before, agrees with one that read all of it (see
// asText). Where a sequence began, for cutting output and placing notes, is
// where the run of sequences that ESCs chain together began.
func (v *vt) write(b []byte, pos int) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 && !utf8.FullRune(b[i:]) {
			return i
		}
		if v.state != vtGround && pos+i-v.lenStart > maxVTString {
			v.seqEnded(false)
			v.state = vtGround // no sequence is that long: abandon it
		}
		v.outPart = v.markPart
		switch {
		case v.state == vtGround:
			v.seqStart, v.lenStart, v.markPart, v.markOff, v.outPart = pos+i, pos+i, v.part, 0, v.part
			if v.plain != nil {
				// A note goes after the line break of a carriage return
				// still waiting for its line feed, wherever that falls.
				v.markOff = v.plain[v.part].Len()
				if v.crPending && v.crPart == v.part {
					v.markOff++
				}
			}
		case r == 0x1b:
			v.lenStart = pos + i
		}
		v.cur, v.size = pos+i+size, size
		if r == '\n' {
			if v.state == vtStringEsc {
				// The ESC ended the string, and the line feed after it goes on
				// as a control of the escape the ESC began: the string is
				// settled with the line it ended on, before the line feed
				// begins another.
				v.seqEnded(true)
				v.state = vtEsc
			}
			v.newLine()
		}
		v.feed(r)
		if len(v.pending) > 0 && v.cur >= v.pending[0].deadline {
			v.expire()
		}
		i += size
	}
	return len(b)
}

// finish writes the unfinished last line, and the note when text was cut.
func (v *vt) finish() {
	v.flush(false)
	if v.cut {
		v.out.WriteString(textCutNote)
	}
}

// vtStream renders output that arrives in pieces, such as the events of a
// recording, as one terminal would show it: each piece's text is what it adds
// to the text so far, so a line shows with the piece that ends it, and the
// unfinished last line with close. With each piece's text come the offsets
// in it of the lines that hold hidden text (see vtNoted).
type vtStream struct {
	v       vt
	pos     int
	pending []byte // a UTF-8 character the last piece ended inside
	shown   int    // the text the pieces so far returned
	noted   int    // the notes they returned
}

// newVTStream starts a stream of size bytes in all for a terminal of width
// and height.
func newVTStream(width, height, size int) *vtStream {
	return &vtStream{v: vt{width: max(width, 1), height: max(height, 1), max: maxText(size, width, height), withNotes: true}}
}

func (s *vtStream) write(b []byte) (string, []int) {
	b = append(s.pending, b...)
	n := s.v.write(b, s.pos)
	s.pending, s.pos = append([]byte(nil), b[n:]...), s.pos+n
	return s.take()
}

// resize changes the terminal's size, as a recording's resize events do.
func (s *vtStream) resize(width, height int) {
	s.v.width, s.v.height = max(width, 1), max(height, 1)
}

func (s *vtStream) close() (string, []int) {
	s.v.endInput()
	s.v.finish()
	return s.take()
}

func (s *vtStream) take() (string, []int) {
	t := s.v.out.String()[s.shown:]
	var notes []int
	for ; s.noted < len(s.v.noteAt); s.noted++ {
		notes = append(notes, s.v.noteAt[s.noted]-s.shown)
	}
	s.shown = s.v.out.Len()
	return t, notes
}

const maxVTString = 64 << 10 // longest escape sequence or OSC, DCS, SOS, PM or APC string honored

// maxText bounds the text n bytes of output render to, the notes about
// hidden text in it included: four times n, room for tabs and short cursor
// moves, and a screenful of padding. Output that draws more than that, such
// as cursor moves repeated to pad every line to the full width, or short
// lines that each hide text, is cut.
func maxText(n, width, height int) int { return 4*n + max(width, 1)*max(height, 1) }

const textCutNote = "\n[the rendered text was cut here: the output moves the cursor, or hides text, far more than it writes]\n"

// maxCell bounds a cell's bytes, a character with its combining marks: more
// marks on one character are dropped, which no reader misses.
const maxCell = 32

// seqEnd returns where the escape sequence b starts with ends, or 0 when it
// does not end within b, as when b ends inside the character that would
// end it. As in write, a sequence is abandoned past maxVTString bytes from
// its own start, or from the ESC that began it, so a run of sequences that
// ESCs chain together ends where its last one does.
func seqEnd(b []byte, width, height int) int {
	v := vt{width: max(width, 1), height: max(height, 1), mode: modeParse}
	for i, lenStart := 0, 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 && !utf8.FullRune(b[i:]) {
			return 0
		}
		if i-lenStart > maxVTString {
			return i // no sequence is that long: abandoned here
		}
		if r == 0x1b {
			lenStart = i
		}
		v.feed(r)
		i += size
		if v.state == vtGround {
			return i
		}
	}
	return 0
}

// vtMode is what a vt makes of the output it parses.
type vtMode int

const (
	modeRender vtMode = iota // the text a person reads (vtText)
	modeParse                // nothing: it only tracks where sequences begin and end
	modePlain                // the text and control characters, escape sequences taken out
)

type vtState int

const (
	vtGround    vtState = iota
	vtEsc               // after ESC
	vtEscInter          // ESC and intermediate bytes, awaiting the final byte
	vtCSI               // control sequence: parameters, intermediates, final byte
	vtString            // OSC, DCS, SOS, PM or APC, until BEL (OSC only) or ST
	vtStringEsc         // ESC inside a string: ST if a backslash follows
)

type vt struct {
	width    int
	height   int
	row      int // the cursor's row, from 1; 0 until a jump shows it
	state    vtState
	seqStart int // where in the output the sequence being parsed began: the first of those ESCs chain together
	lenStart int // where its own length counts from: its first byte, or the ESC that began it
	params   []byte
	osc      bool // the current string is an OSC, which BEL may end
	strLen   int

	out      strings.Builder
	max      int      // the most text out may hold
	cut      bool     // text past max was dropped
	line     []string // one cell per column; "" is the right half of a wide character
	col      int
	savedCol int

	mode      vtMode
	plain     []strings.Builder // vtPlain's text, by part
	outPart   int               // vtPlain: the part what the character being fed makes goes in
	crPending bool              // vtPlain: a carriage return the next character may pair with
	crPart    int               // and the part it is in
	crAt      int               // and where it is in the output
	origins   []int32           // plainOrigins: where each byte of the text came from
	cur       int               // where in the output the character being fed ends
	size      int               // and its length

	// Text the output hides in escape sequences (see hide).
	rule      noteRule
	lineVis   bool        // the output's line, since its last line feed, has shown a character other than a space
	pending   []vtPending // short strings whose note waits to see what the rest of their line shows
	part      int         // vtPlain: the part being written
	markPart  int         // vtPlain: where in the text the sequence being parsed began
	markOff   int
	notes     []vtNote // vtPlain: where hidden text is noted
	lineNote  bool     // vtText: the current line holds hidden text
	withNotes bool     // vtNoted and vtStream: the caller puts the notes in, so they count toward max
	noteAt    []int    // vtText: the offsets in out of the lines that held some
	seqNoted  bool     // the string being parsed is noted already
	body      int      // the bytes of its body so far
	csiLen    int      // the parameter and intermediate bytes of the CSI being parsed
	inter     int      // its intermediate bytes, or those of the escape being parsed
	csiOdd    bool     // its bytes are not parameters and then intermediates programs use
	ctl       bool     // a control character was carried out inside the CSI or escape being parsed

	starts     []int // stringStarts: where each string sequence began
	wantStarts bool
}

// noteRule says which text that escape sequences hide is noted.
type noteRule int

const (
	// noteOutput is for command and terminal output, where a short title
	// alone on its line is how a shell names the window.
	noteOutput noteRule = iota
	// noteFile is for file contents, which have no reason to hold a title:
	// every string that hides text is noted.
	noteFile
)

// vtNote is where vtPlain notes hidden text: an offset in a part's text, and
// where in the output the sequence that hid it began.
type vtNote struct{ part, off, raw int }

// vtPending is a note that waits for the rest of its string's line.
type vtPending struct {
	deadline       int // where in the output it is due, if nothing settled it before
	part, off, raw int // vtPlain: where it goes, and where its sequence began
}

const (
	// hiddenNoteMin is how many bytes a string sequence in output may hide
	// without a note, when it hides no line break and its line shows nothing
	// else: a window title, as a shell sets one.
	hiddenNoteMin = 256
	// noteLook is how far past such a string its line is followed to see
	// whether it shows text; a line that goes on further counts as showing
	// some. Every read is cleaned with the output after it (see aroundRead),
	// far more than a string that short and this, so a page settles every
	// note it holds as the whole output does.
	noteLook = 1 << 10
	// maxCSIParams is how many parameter and intermediate bytes a control
	// sequence may hold before it is noted. The longest that programs write,
	// an SGR that sets attributes and true-color foreground, background and
	// underline colors at once, stays under it.
	maxCSIParams = 64
	// maxInter is how many intermediate bytes a sequence may hold, as
	// charset designations and DECSCUSR do, before it is noted.
	maxInter = 2
)

// usualInter reports an intermediate byte of the control sequences programs
// write (xterm's: space ! " # $ ' * + ,), as DECSCUSR's space, DECSTR's !
// and DECRQM's $ are. No program writes the others in one, % & ( ) - . /,
// from which a shell makes paths such as ./x and operators: a control
// sequence that holds one is noted.
func usualInter(b byte) bool {
	switch b {
	case ' ', '!', '"', '#', '$', '\'', '*', '+', ',':
		return true
	}
	return false
}

const hiddenNote = "[text hidden in a terminal escape sequence]"

// hide notes that the sequence being parsed hid text. A terminal shows none
// of a string sequence's body (OSC, DCS, SOS, PM, APC), nor of a control
// sequence's parameters, so neither does the text; but a reader of the text,
// unlike one of a terminal, would not know that a line of a script or a
// command is there: a shell that runs the same bytes reads it, so a file or
// output could hide a command from a model that reads it before running it.
// Noted are:
//
//   - in a file (noteFile), every string with a body;
//   - in output (noteOutput), a string that hides a line break or more than
//     hiddenNoteMin bytes, or whose line shows other text: before the string
//     since the line's last line feed, or after it before the next one,
//     followed up to noteLook bytes past its end. A line feed is what ends a
//     command line for a shell: a carriage return or a vertical tab does not.
//     A line that goes on past noteLook without a line feed, or output that
//     ends first, counts as showing text. A title alone on its line, as a
//     shell names the window, passes without a note;
//   - in both, a control sequence whose parameter and intermediate bytes are
//     not the shape real ones have (parameters, a private marker only
//     first, then at most maxInter of the intermediates programs use, see
//     usualInter), run past maxCSIParams bytes, or end without a final byte,
//     and an escape with more than maxInter intermediate bytes; and a
//     control sequence or an escape that a control character is carried out
//     inside, as a terminal does: no program writes one, and a line feed
//     there ends a shell's command line while the sequence hides what
//     follows it on the next one.
//
// vtPlain notes at the place in its text where the sequence began, in the
// part that holds its first byte; vtText marks the line it is on. The note
// is put in after redaction, which so sees the text around a sequence
// joined, as a terminal shows it, and the note cannot split a secret.
func (v *vt) hide() {
	switch v.mode {
	case modePlain:
		v.notes = append(v.notes, vtNote{v.markPart, v.markOff, v.seqStart})
	default:
		v.lineNote = true
	}
}

// seqEnded settles what the sequence being parsed hid, as it ends: complete,
// with its final byte or terminator, or not.
func (v *vt) seqEnded(complete bool) {
	switch v.state {
	case vtCSI:
		if !complete || v.csiOdd || v.ctl || v.csiLen > maxCSIParams {
			v.hide()
		}
	case vtEscInter:
		if v.inter > maxInter || v.ctl {
			v.hide()
		}
	case vtString, vtStringEsc:
		switch {
		case v.seqNoted || v.body == 0:
		case v.lineVis:
			v.hide()
		default:
			v.pending = append(v.pending, vtPending{deadline: v.cur + noteLook, part: v.markPart, off: v.markOff, raw: v.seqStart})
		}
		v.seqNoted = true
	}
}

// bodyByte counts r, a character in a string's body.
func (v *vt) bodyByte(r rune) {
	v.body += v.size
	if v.seqNoted {
		return
	}
	switch {
	case v.rule == noteFile,
		v.body > hiddenNoteMin,
		r == '\n' || r == '\r' || r == 0x0b || r == 0x0c || r == 0x85 || r == 0x2028 || r == 0x2029:
		v.hide()
		v.seqNoted = true
	}
}

// csiByte counts b, a parameter or intermediate byte of a control sequence.
func (v *vt) csiByte(b byte) {
	v.csiLen++
	switch {
	case b <= 0x2f: // an intermediate
		v.inter++
		v.csiOdd = v.csiOdd || v.inter > maxInter || !usualInter(b)
	case v.inter > 0: // a parameter after an intermediate
		v.csiOdd = true
	case b >= 0x3c && v.csiLen > 1: // a private marker after the first byte
		v.csiOdd = true
	}
}

// settle decides the notes that wait for their line: shown when the line
// shows text, dropped when it ends first.
func (v *vt) settle(shows bool) {
	if shows {
		for _, p := range v.pending {
			v.notePending(p)
		}
	}
	v.pending = v.pending[:0]
}

func (v *vt) notePending(p vtPending) {
	if v.mode == modePlain {
		v.notes = append(v.notes, vtNote{p.part, p.off, p.raw})
	} else {
		v.lineNote = true
	}
}

// expire notes the strings whose line went on noteLook bytes past them
// without showing text or ending.
func (v *vt) expire() {
	i := 0
	for ; i < len(v.pending) && v.cur >= v.pending[i].deadline; i++ {
		v.notePending(v.pending[i])
	}
	v.pending = append(v.pending[:0], v.pending[i:]...)
}

// newLine is a line feed: the line that ends showed no text after a string
// that waits for it.
func (v *vt) newLine() {
	v.lineVis = false
	if len(v.pending) > 0 {
		v.settle(false)
	}
}

// endInput settles what the output's end leaves open: a sequence it ends
// inside, and the notes that wait for a line it ends.
func (v *vt) endInput() {
	if v.state != vtGround {
		v.seqEnded(false)
	}
	v.settle(true)
}

func (v *vt) feed(r rune) {
	if v.state != vtGround && (r == 0x18 || r == 0x1a) {
		v.seqEnded(false)
		v.state = vtGround // CAN and SUB cancel any sequence, as on a terminal
		return
	}
	switch v.state {
	case vtEsc:
		v.escape(r)
		return
	case vtEscInter:
		switch {
		case r >= 0x20 && r <= 0x2f: // more intermediates
			v.inter++
		case r >= 0x30 && r <= 0x7e:
			v.seqEnded(true)
			v.state = vtGround // charset designation and the like: nothing to show
		case r == 0x1b:
			v.seqEnded(false)
			v.state = vtEsc // ESC abandons it and starts a sequence of its own
		case r < 0x20:
			v.ctl = true
			v.control(r)
		default:
			v.seqEnded(false)
			v.state = vtGround
		}
		return
	case vtCSI:
		switch {
		case r >= 0x30 && r <= 0x3f || r >= 0x20 && r <= 0x2f:
			v.csiByte(byte(r))
			if len(v.params) < 64 {
				v.params = append(v.params, byte(r))
			}
		case r >= 0x40 && r <= 0x7e:
			v.seqEnded(true)
			v.state = vtGround
			v.csi(byte(r))
		case r == 0x1b:
			v.seqEnded(false)
			v.state = vtEsc
		case r < 0x20:
			v.ctl = true
			v.control(r) // executed in the middle of a sequence, as terminals do
		default:
			v.seqEnded(false)
			v.state = vtGround // malformed: abandon it
		}
		return
	case vtString:
		v.strLen++
		switch {
		case r == 0x07 && v.osc, r == 0x9c:
			v.seqEnded(true)
			v.state = vtGround
		case r == 0x1b:
			v.state = vtStringEsc
		case v.strLen > maxVTString:
			v.bodyByte(r)
			v.seqEnded(true)
			v.state = vtGround
		default:
			v.bodyByte(r)
		}
		return
	case vtStringEsc:
		v.seqEnded(true)
		if r == '\\' {
			v.state = vtGround
			return
		}
		v.state = vtEsc // ESC ended the string and starts a sequence of its own
		v.escape(r)
		return
	}
	switch {
	case r == 0x1b:
		v.state = vtEsc
	case r == 0x9b:
		v.startCSI()
	case r == 0x9d:
		v.startString(true)
	case r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f:
		v.startString(false)
	case r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f:
		v.control(r)
	default:
		v.put(r)
	}
}

func (v *vt) escape(r rune) {
	v.state = vtGround
	switch {
	case r == '[':
		v.startCSI()
	case r == ']':
		v.startString(true)
	case r == 'P' || r == 'X' || r == '^' || r == '_':
		v.startString(false)
	case r >= 0x20 && r <= 0x2f:
		v.state, v.inter, v.ctl = vtEscInter, 1, false
	case r == 0x1b:
		v.state = vtEsc
	case v.mode != modeRender && r >= 0x20:
		if v.mode == modePlain && strings.ContainsRune("EDMc", r) {
			v.plainRune('\n') // NEL, IND, RI and RIS move to another line
		}
	case r == '7':
		v.savedCol = v.col
	case r == '8':
		v.col = min(v.savedCol, v.limit())
	case r == 'E' || r == 'D':
		v.flush(true) // next line, index
	case r == 'M':
		v.up(1, v.col) // reverse index
	case r == 'c':
		v.up(v.height, 0) // reset: the cursor goes home
		v.row = 1
	case r < 0x20:
		v.control(r)
	}
}

func (v *vt) startCSI() {
	v.state, v.params = vtCSI, v.params[:0]
	v.csiLen, v.inter, v.csiOdd, v.ctl = 0, 0, false, false
}

func (v *vt) startString(osc bool) {
	v.state, v.osc, v.strLen = vtString, osc, 0
	v.body, v.seqNoted = 0, false
	if v.wantStarts {
		v.starts = append(v.starts, v.lenStart) // its ESC or C1 introducer
	}
}

func (v *vt) control(r rune) {
	switch v.mode {
	case modeParse:
		return
	case modePlain:
		v.plainRune(r)
		return
	}
	switch r {
	case '\n', 0x0b, 0x0c, 0x85:
		v.flush(true)
	case '\r':
		v.col = 0
	case '\b':
		if v.col > 0 {
			v.col--
		}
	case '\t':
		v.col = min((v.col/8+1)*8, v.limit())
	}
}

// limit is the furthest column the cursor may move to: the terminal's width,
// or the end of a line that wrapped past it.
func (v *vt) limit() int { return max(len(v.line), v.width-1) }

func (v *vt) put(r rune) {
	if !unicode.IsSpace(r) && !invisible(r) {
		v.lineVis = true
		if len(v.pending) > 0 {
			v.settle(true)
		}
	}
	switch {
	case v.mode == modePlain:
		v.plainRune(r)
		return
	case v.mode == modeParse || invisible(r):
		return // invisible: it could hide or reorder text from the person reading it
	}
	w := runeWidth(r)
	if w == 0 {
		// A combining mark joins the character before the cursor: the cell
		// left of it, or the wide character whose right half that cell is.
		// No further: past a run of halves whose wide characters were
		// overwritten, a search for one would cost the run's length per mark.
		at := min(v.col, len(v.line))
		for i := at - 1; i >= 0 && i >= at-2; i-- {
			if v.line[i] != "" {
				if len(v.line[i]) < maxCell {
					v.line[i] += string(r)
				}
				return
			}
		}
		return
	}
	for len(v.line) < v.col+w {
		v.line = append(v.line, " ")
	}
	v.line[v.col] = string(r)
	if w == 2 {
		v.line[v.col+1] = ""
	}
	v.col += w
}

func (v *vt) csi(final byte) {
	if v.mode != modeRender {
		return
	}
	p := string(v.params)
	if p != "" && strings.ContainsAny(p[:1], "?<=>") {
		return // a private mode or query: nothing to show
	}
	n := func(i, def int) int {
		fields := strings.Split(p, ";")
		if i < len(fields) {
			if x, err := strconv.Atoi(fields[i]); err == nil && x > 0 {
				return min(x, 10000)
			}
		}
		return def
	}
	// Editing works within the screen row the cursor is on, as on a terminal,
	// so it costs at most the width however long the line has grown.
	rowStart := v.col / v.width * v.width
	rowEnd := min(rowStart+v.width, len(v.line)) // cells of this row that exist
	switch final {
	case 'K': // erase in line
		switch n(0, 0) {
		case 0:
			v.line = v.line[:min(v.col, len(v.line))]
		case 1:
			for i := rowStart; i <= v.col && i < len(v.line); i++ {
				v.line[i] = " "
			}
		case 2:
			v.line = v.line[:0]
			v.col %= v.width // the cursor stays where it was on the screen
		}
	case 'C', 'a': // forward
		v.col = min(v.col+n(0, 1), v.limit())
	case 'D': // back
		v.col = max(v.col-n(0, 1), 0)
	case 'G', '`': // to column
		v.col = min(n(0, 1)-1, v.limit())
	case 'P': // delete characters; the row's end fills with blanks
		if v.col < rowEnd {
			k := min(n(0, 1), rowEnd-v.col)
			copy(v.line[v.col:], v.line[v.col+k:rowEnd])
			if rowEnd == len(v.line) {
				v.line = v.line[:rowEnd-k]
			} else {
				for i := rowEnd - k; i < rowEnd; i++ {
					v.line[i] = " "
				}
			}
		}
	case '@': // insert blanks; the end of a full row drops off, as on a terminal
		if v.col < rowEnd {
			k := min(n(0, 1), v.width)
			end := rowEnd
			if rowEnd == len(v.line) { // the last row may grow to the full width
				end = min(rowEnd+k, rowStart+v.width)
				for len(v.line) < end {
					v.line = append(v.line, " ")
				}
			}
			k = min(k, end-v.col)
			copy(v.line[v.col+k:end], v.line[v.col:end-k])
			for i := v.col; i < v.col+k; i++ {
				v.line[i] = " "
			}
		}
	case 'X': // erase characters, up to the row's end
		for i := v.col; i < v.col+n(0, 1) && i < rowEnd; i++ {
			v.line[i] = " "
		}
	case 'H', 'f': // to row and column
		v.moveTo(n(0, 1), n(1, 1)-1)
	case 'd': // to row
		v.moveTo(n(0, 1), v.col)
	case 'B', 'e': // down
		v.down(n(0, 1), v.col)
	case 'E': // down, to column 1
		v.down(n(0, 1), 0)
	case 'A': // up
		v.up(n(0, 1), v.col)
	case 'F': // up, to column 1
		v.up(n(0, 1), 0)
	case 'J': // erase the screen: what it showed stays in the text
		if n(0, 0) >= 2 && len(v.line) > 0 {
			col := v.col
			v.flush(true)
			v.col = col % v.width // the cursor stays where it was on the screen
		}
	case 's':
		v.savedCol = v.col
	case 'u':
		v.col = min(v.savedCol, v.limit())
	}
}

// flush ends the current line; with newline it writes the line break too.
func (v *vt) flush(newline bool) {
	if v.lineNote {
		switch {
		case v.cut:
		case v.withNotes && v.used()+len(hiddenNote) > v.max:
			v.cut = true
		default:
			v.noteAt = append(v.noteAt, v.out.Len())
		}
		v.lineNote = false
	}
	for _, c := range v.line {
		if v.used()+len(c) > v.max {
			v.cut = true
		}
		if v.cut {
			break
		}
		v.out.WriteString(c)
	}
	if newline {
		if v.used() >= v.max {
			v.cut = true
		}
		if !v.cut {
			v.out.WriteByte('\n')
		}
		if v.row > 0 {
			v.row = min(v.row+1, v.height) // at the bottom, the screen scrolls
		}
	}
	v.line, v.col, v.savedCol = v.line[:0], 0, 0
}

// used is how much of max the text holds: its bytes, and its notes' when the
// caller puts them in.
func (v *vt) used() int {
	if v.withNotes {
		return v.out.Len() + len(v.noteAt)*len(hiddenNote)
	}
	return v.out.Len()
}

// moveTo jumps to row r and column col. A jump down writes the line breaks
// it skips. A jump up, or the first jump when the row is not known yet, only
// ends the current line, if it holds anything, and sets the row.
func (v *vt) moveTo(r, col int) {
	r = min(max(r, 1), v.height)
	switch {
	case v.row == 0 || r < v.row:
		if len(v.line) > 0 {
			v.flush(true)
		}
	case r > v.row:
		for skip := r - v.row; skip > 0; skip-- {
			v.flush(true)
		}
	}
	v.row = r
	v.col = min(max(col, 0), v.limit())
}

// down moves n rows down, keeping to column col; from an unknown row each
// row is a line break, and the bottom edge is at most height-1 rows away.
func (v *vt) down(n, col int) {
	if v.row > 0 {
		v.moveTo(v.row+n, col)
		return
	}
	for n = min(n, v.height-1); n > 0; n-- {
		v.flush(true)
	}
	v.col = min(max(col, 0), v.limit())
}

// up moves n rows up, which text can only show as a new line.
func (v *vt) up(n, col int) {
	if v.row > 0 {
		v.moveTo(max(v.row-n, 1), col)
		return
	}
	if len(v.line) > 0 {
		v.flush(true)
	}
	v.col = min(max(col, 0), v.limit())
}

// runeWidth is how many terminal columns r takes: 0 for combining and
// invisible characters, 2 for East Asian wide ones and most emoji, else 1.
func runeWidth(r rune) int {
	switch {
	case r == utf8.RuneError:
		return 1
	case unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf):
		return 0
	case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf && r != 0x303f,
		r >= 0xac00 && r <= 0xd7a3, r >= 0xf900 && r <= 0xfaff, r >= 0xfe30 && r <= 0xfe4f,
		r >= 0xff00 && r <= 0xff60, r >= 0xffe0 && r <= 0xffe6,
		r >= 0x1f300 && r <= 0x1f64f, r >= 0x1f900 && r <= 0x1f9ff, r >= 0x20000 && r <= 0x3fffd:
		return 2
	}
	return 1
}
