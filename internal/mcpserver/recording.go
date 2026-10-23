// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxCastBytes bounds a recording served as a resource; a longer one is cut
// to its most recent events.
const maxCastBytes = 8 << 20

// addRecordingResource serves each terminal's recording. Recordings hold the
// raw output, so the resource serves it as pty_read's text format does: as
// the text a person reads, redacted across the whole recording so a secret
// written in two reads is still found.
func (s *Server) addRecordingResource() {
	s.mcp.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "tern://{target}/recording/{pty_id}",
		Name:        "terminal-recording",
		Title:       "Terminal recording",
		Description: "The asciicast v2 recording of a terminal the pty tools opened, as the text a person reads " +
			"(escape sequences removed, line edits applied, so what they overwrote is not in it) with known " +
			"secrets removed; play it with asciinema. pty_list shows each terminal's target and pty_id.",
		MIMEType: "application/x-asciicast",
	}, s.readRecording)
}

func (s *Server) readRecording(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	e := AuditEntry{Tool: "resources/read", Args: map[string]any{"uri": uri}, Protocol: req.ProtocolVersion()}
	if ci := req.ClientInfo(); ci != nil {
		e.Client = ci.Name + "/" + ci.Version
	}
	target, id, ok := parseRecordingURI(uri)
	p := s.lookupPTY(id)
	if !ok || p == nil || p.target != target || p.rec.Path() == "" {
		e.Phase, e.Reason = "denied", "no such recording"
		s.logOrWarn(e)
		return nil, mcp.ResourceNotFoundError(uri)
	}
	e.Target, e.PTYID = p.target, p.id
	// Rendering a long recording costs seconds of CPU and hundreds of MiB:
	// one at a time, so a client asking for many at once cannot multiply it.
	select {
	case s.castSlot <- struct{}{}:
		defer func() { <-s.castSlot }()
	case <-ctx.Done():
		e.Phase, e.Error = "error", ctx.Err().Error()
		s.logOrWarn(e)
		return nil, ctx.Err()
	}
	data, cut, err := readCastTail(p.rec.Path(), 2*maxCastBytes)
	if err != nil {
		e.Phase, e.Error = "error", err.Error()
		s.logOrWarn(e)
		return nil, fmt.Errorf("read the recording: %v", err)
	}
	cast, n := redactCast(data, maxCastBytes, cut)
	e.Bytes, e.Reason = len(cast), fmt.Sprintf("%d redacted", n)
	if err := s.logInfo(e); err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{
		Cacheable: mcp.Cacheable{TTLMs: 0, CacheScope: "private"},
		Contents:  []*mcp.ResourceContents{{URI: uri, MIMEType: "application/x-asciicast", Text: cast}},
	}, nil
}

func parseRecordingURI(uri string) (target, id string, ok bool) {
	rest, ok := strings.CutPrefix(uri, "tern://")
	if !ok {
		return "", "", false
	}
	target, id, ok = strings.Cut(rest, "/recording/")
	return target, id, ok && target != "" && id != "" && !strings.Contains(id, "/")
}

// readCastTail reads a recording's header line and its last tail bytes of
// whole events, so serving a long recording costs a bounded amount of memory.
// cut reports that events before the tail were left out.
func readCastTail(path string, tail int64) (data []byte, cut bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() <= tail {
		data, err = io.ReadAll(f)
		return data, false, err
	}
	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	header, _, ok := bytes.Cut(head[:n], []byte("\n"))
	if !ok {
		return nil, false, fmt.Errorf("the recording has no header line")
	}
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, info.Size()-tail); err != nil && err != io.EOF {
		return nil, false, err
	}
	i := bytes.IndexByte(buf, '\n') // the first event may be cut: start after it
	if i < 0 {
		return nil, false, fmt.Errorf("the recording has an event over %d bytes", tail)
	}
	return append(append(header, '\n'), buf[i+1:]...), true, nil
}

// redactCast renders an asciicast's output events as the text a person
// reads, as one stream, and redacts that, then keeps the header and the most
// recent events that fit in max bytes; cut says earlier events were already
// left out. A line the recorder may still be writing is left out.
//
// Raw output can split a secret where redaction would miss it: grep --color
// puts \e[K inside a match, a line editor redraws what was typed with cursor
// moves and backspaces. In the rendered text the secret is whole again. Each
// event keeps the text it completes, so a line shows at the time it ended.
func redactCast(data []byte, max int, cut bool) (string, int) {
	text := string(data)
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[:i] // drop an unfinished last line
	}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return "", 0
	}
	header, events := lines[0], make([][]any, 0, len(lines)-1)
	var hdr struct{ Width, Height int }
	json.Unmarshal([]byte(header), &hdr)
	total := 0
	for _, l := range lines[1:] {
		var ev []any
		if json.Unmarshal([]byte(l), &ev) != nil || len(ev) != 3 {
			continue
		}
		if s, ok := ev[2].(string); ok {
			total += len(s)
		}
		events = append(events, ev)
	}
	term := newVTStream(intOr(hdr.Width, 80), intOr(hdr.Height, 24), total)
	var outputs []string
	var notes [][]int // where in each output hidden text is noted (see hide)
	for _, ev := range events {
		typ, _ := ev[1].(string)
		data, _ := ev[2].(string)
		switch typ {
		case "o":
			text, at := term.write([]byte(data))
			outputs, notes = append(outputs, text), append(notes, at)
		case "r":
			var cols, rows int
			if _, err := fmt.Sscanf(data, "%dx%d", &cols, &rows); err == nil {
				term.resize(cols, rows)
			}
		}
	}
	if len(outputs) > 0 {
		text, at := term.close() // the unfinished last line
		last := len(outputs) - 1
		for _, off := range at {
			notes[last] = append(notes[last], len(outputs[last])+off)
		}
		outputs[last] += text
	}
	outputs, notes, n := redactNoted(outputs, notes)
	if cut {
		// The first event kept may go on with a line, or an escape sequence,
		// that began in the events left out: shown on its own, its rest could
		// be a value whose name is gone, or a remnant such as "1m" glued to
		// a key. That first line goes too, with the blank or indented lines
		// that go on with it, once it has served as the context redaction
		// needs: a key whose value is on the next line.
		dropFirstLine(outputs, notes)
	}
	for i := range outputs {
		outputs[i] = strings.Join(splitNotes(outputs[i], notes[i]), hiddenNote)
	}
	encoded, k := make([]string, 0, len(events)), 0
	kept := make([][]any, 0, len(events))
	for _, ev := range events {
		if typ, _ := ev[1].(string); typ == "o" {
			text := outputs[k]
			k++
			if text == "" {
				continue // output that only moved the cursor or colored text
			}
			ev[2] = strings.ReplaceAll(text, "\n", "\r\n")
		}
		b, _ := json.Marshal(ev)
		encoded, kept = append(encoded, string(b)), append(kept, ev)
	}
	events = kept
	size, first := len(header)+1, len(encoded)
	for first > 0 && size+len(encoded[first-1])+1 <= max {
		first--
		size += len(encoded[first]) + 1
	}
	var b strings.Builder
	b.WriteString(header + "\n")
	if first > 0 || cut && len(events) > 0 {
		at := events[0][0]
		if first > 0 {
			at = events[first-1][0]
		}
		note, _ := json.Marshal([]any{at, "o", "\r\n[tern: the start of this recording was left out]\r\n"})
		b.WriteString(string(note) + "\n")
	}
	for _, l := range encoded[first:] {
		b.WriteString(l + "\n")
	}
	return b.String(), n
}

// redactNoted redacts outputs, which follow one another, as redactSplit
// does, with each one's notes, offsets in it, as places the redaction
// leaves: it returns the outputs redacted and where their notes are now.
func redactNoted(outputs []string, notes [][]int) ([]string, [][]int, int) {
	var parts []string
	var groups []int
	for i, o := range outputs {
		for _, seg := range splitNotes(o, notes[i]) {
			parts, groups = append(parts, seg), append(groups, i)
		}
	}
	res, n, _ := rewriteParts(parts, groups, redactions)
	out, at := make([]string, len(outputs)), make([][]int, len(outputs))
	k := 0
	for i := range outputs {
		var b strings.Builder
		for j := 0; j <= len(notes[i]); j++ {
			if j > 0 {
				at[i] = append(at[i], b.Len())
			}
			b.WriteString(res[k])
			k++
		}
		out[i] = b.String()
	}
	return out, at, n
}

// dropFirstLine removes the text of outputs, which follow one another, up to
// and including its first line break and the blank or indented lines that go
// on with that line (see continued), or its first redactCtx bytes when those
// do not end in them, where a secret's name would be out of redaction's
// reach anyway. notes, when given, are the outputs' notes, which it keeps up
// to date.
func dropFirstLine(outputs []string, notes [][]int) {
	var head []byte
	for _, o := range outputs {
		if len(head) >= redactCtx {
			break
		}
		head = append(head, o[:min(len(o), redactCtx-len(head))]...)
	}
	cut := len(head)
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		cut = continued(head, i+1)
	}
	for i, o := range outputs {
		if cut == 0 {
			return
		}
		k := min(cut, len(o))
		for k < len(o) && !utf8.RuneStart(o[k]) {
			k++
		}
		outputs[i] = o[k:]
		if notes != nil {
			notes[i] = notesAfter(notes[i], k)
		}
		cut -= min(k, cut)
	}
}
