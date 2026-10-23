// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ternimal/tern/internal/tern"
)

// Interactive terminals, the pty_* tools. Each is a shell in a tern session
// of its own on the agent, named mcp- and random letters, never chosen by the
// model, which this server drives as the writer over a connection of its own.
// All output goes into a ring buffer addressed by byte offset, so the model
// reads it in pieces and misses nothing between calls. A dropped connection
// is redialed and the session reattached; the agent replays its recent output
// and reports where that replay starts, so the bytes already read are skipped
// and any that were lost are noted in the output. A person can watch the
// session live with tern connect --read-only, or take it over. With
// persistence on, terminals outlive tern mcp: they are left running on the
// agent at exit and reattached by the next tern mcp with the same config.

const (
	maxPTYs              = 16 // on all targets together
	defaultPTYsPerTarget = 4
	defaultPTYIdle       = 10 * time.Minute // a terminal no call touches for this long is closed
	ptyKeepEnded         = 10 * time.Minute // an ended terminal stays readable this long
	ptyBuffer            = 1 << 20
	maxSendBytes         = 64 << 10
	maxKeys              = 64
	maxUntilLen          = 512
	maxPromptLen         = 200
	ptyAttachWait        = 10 * time.Second // how long input waits for a dropped connection to return
	ptyReadWait          = 10 * time.Second // default wait when a read has idle_ms, until or prompt
	ptyIdleFallback      = 1500 * time.Millisecond
	ptyPromptQuiet       = 250 * time.Millisecond // quiet before a prompt is believed
	ptyInputQuiet        = 3 * time.Second        // quiet on an unfinished line: probably waiting for input
	ptyOpenWait          = 3 * time.Second        // how long pty_open waits for the first prompt
	ptySettle            = 300 * time.Millisecond // quiet that ends pty_open's wait
	ptyRunTimeout        = 30 * time.Second
	ptyGraceMax          = time.Second // longest a read waits for a partial line to settle
	ptyRecordMax         = 64 << 20
	ptyReconnectMax      = 30 * time.Second
	ptyStable            = 10 * time.Second // a connection up this long resets the backoff
	ptyEndWait           = 2 * time.Second  // for the agent to end a session it was asked to
	defaultPTYCols       = 120
	defaultPTYRows       = 32
)

type ptyState struct {
	id, target, session, attachID string
	out                           *ringBuffer
	rec                           *tern.Recorder
	opened                        time.Time
	idle                          time.Duration // closed after this long unused
	runMu                         sync.Mutex    // one pty_run at a time
	ctx                           context.Context
	cancel                        context.CancelFunc
	done                          chan struct{} // closed when the terminal's goroutine has finished
	onEnd                         func()        // called once the terminal has ended

	// agentPos is the position in the agent's output of the next byte this
	// terminal expects, and adopting marks a terminal reattached after tern
	// mcp restarted, whose first replay is all new to it. Only the terminal's
	// own goroutine uses them.
	agentPos int64
	adopting bool

	mu         sync.Mutex
	stream     *tern.ShellStream // nil while connecting or reconnecting
	ready      chan struct{}     // closed while stream is set
	cols, rows int
	lastUsed   time.Time
	inUse      int    // calls using the terminal now
	prompt     string // the shell's prompt as last seen
	readOnly   bool   // a person took over the session: the agent ignores this server's input
	reconnects int
	closing    bool
	keep       bool // closing leaves the session running on the agent, for the next tern mcp
	exited     bool // the agent said the shell ended
	ended      bool
	endReason  string
	endedAt    time.Time
}

// newPTYSession names a new terminal's session on the agent: "mcp-" and 12
// random characters of lowercase base32, never chosen by the model.
func newPTYSession() string { return "mcp-" + newHandle("")[:12] }

// isPTYSession reports whether name has the form newPTYSession gives, the
// only sessions a saved terminal is reattached to: a state file that names
// any other session, such as one a person left running, reaches nothing.
func isPTYSession(name string) bool {
	rest, ok := strings.CutPrefix(name, "mcp-")
	return ok && len(rest) == 12 && isBase32Lower(rest)
}

// isPTYID reports whether id has the form of the pty_ids newHandle gives.
func isPTYID(id string) bool {
	rest, ok := strings.CutPrefix(id, "pty_")
	return ok && len(rest) == 26 && isBase32Lower(rest)
}

// isBase32Lower reports whether s is made of the characters newHandle uses.
func isBase32Lower(s string) bool {
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz234567") == ""
}

func (s *Server) newPTY(id, target, session, attachID string, cols, rows int, opened time.Time, idle time.Duration) *ptyState {
	p := &ptyState{
		id: id, target: target, session: session, attachID: attachID,
		out: newRingBuffer(ptyBuffer), opened: opened, idle: idle,
		done: make(chan struct{}), ready: make(chan struct{}),
		cols: cols, rows: rows, lastUsed: time.Now(), onEnd: s.ptyEnded,
	}
	p.ctx, p.cancel = context.WithCancel(s.base)
	p.rec = tern.NewRecorder(s.cfg.RecordDir, target+"-"+session, cols, rows, ptyRecordMax)
	return p
}

// openPTY creates the session on the agent, starts the goroutine that copies
// its output, and waits briefly for the shell's first prompt.
func (s *Server) openPTY(ctx context.Context, t *targetState, cols, rows int) (*ptyState, error) {
	perTarget, idle := t.Policy.PTYLimits()
	p := s.newPTY(newHandle("pty_"), t.Name, newPTYSession(), newHandle(""), cols, rows, time.Now(), idle)
	s.ptysMu.Lock()
	total, here := 0, 0
	for _, q := range s.ptys {
		if !q.isEnded() {
			total++
			if q.target == t.Name {
				here++
			}
		}
	}
	if total >= maxPTYs || here >= perTarget {
		s.ptysMu.Unlock()
		p.cancel()
		p.rec.Close()
		return nil, beforeStart(fmt.Errorf("too many open terminals (%d on %s, %d in all; the limits are %d and %d); close one with pty_close",
			here, t.Name, total, perTarget, maxPTYs))
	}
	s.ptys[p.id] = p
	s.ptysMu.Unlock()
	fail := func(err error) (*ptyState, error) {
		s.ptysMu.Lock()
		delete(s.ptys, p.id)
		s.ptysMu.Unlock()
		p.onEnd = nil
		p.end(err.Error())
		close(p.done) // its goroutine never started
		return nil, beforeStart(err)
	}
	cl, err := t.Dial(ctx)
	if err != nil {
		return fail(fmt.Errorf("connect to %s: %w", t.Name, err))
	}
	st, err := cl.OpenShell(tern.ShellOptions{Session: p.session, Mode: "new", AttachID: p.attachID, Write: true, Cols: cols, Rows: rows})
	if err != nil {
		cl.Close()
		return fail(fmt.Errorf("open a terminal on %s: %w", t.Name, err))
	}
	go s.runPTY(p, t, cl, st)
	s.savePTYs()
	p.settle(ctx)
	return p, nil
}

// adoptPTY takes over a terminal a previous tern mcp left running, from the
// state file. It reattaches in the background; until then it reads as not
// connected.
func (s *Server) adoptPTY(t *targetState, r ptyRecord) {
	_, idle := t.Policy.PTYLimits()
	p := s.newPTY(r.PTYID, t.Name, r.Session, r.AttachID, r.Cols, r.Rows, r.OpenedAt, idle)
	p.adopting, p.prompt = true, r.Prompt
	p.out.start = max(r.Next, 0) // continue the offsets the last tern mcp handed out
	s.ptysMu.Lock()
	s.ptys[p.id] = p
	s.ptysMu.Unlock()
	go func() {
		var backoff time.Duration // the first attempt is immediate
		cl, st, err := s.reattach(p, t, &backoff)
		if err != nil {
			p.end(err.Error())
			close(p.done)
			return
		}
		s.runPTY(p, t, cl, st)
	}()
}

// runPTY copies the terminal's output while connected, and reconnects when
// the connection drops, until the shell exits, the terminal is closed, or the
// session cannot be reattached.
func (s *Server) runPTY(p *ptyState, t *targetState, cl *tern.Client, st *tern.ShellStream) {
	defer close(p.done)
	backoff := time.Second
	for {
		w := p.resume(st)
		if !p.setStream(st) {
			// Closed while reconnecting: end the session it found, unless
			// tern mcp is leaving it running for the next one.
			p.mu.Lock()
			keep := p.keep
			p.mu.Unlock()
			if !keep {
				st.EndSession()
			}
			st.Close()
			cl.Close()
			p.end("closed")
			return
		}
		connected := time.Now()
		exited := st.CopyOutput(w)
		p.setStream(nil)
		st.Close()
		cl.Close()
		switch {
		case exited:
			p.mu.Lock()
			p.exited = true
			p.mu.Unlock()
			p.end("the shell exited")
			return
		case p.ctx.Err() != nil:
			p.end("closed")
			return
		}
		if time.Since(connected) >= ptyStable {
			backoff = time.Second
		}
		slog.Info("terminal connection lost; reconnecting", "pty", p.id, "target", p.target, "session", p.session)
		var err error
		if cl, st, err = s.reattach(p, t, &backoff); err != nil {
			p.end(err.Error())
			return
		}
	}
}

// reattach redials the agent and attaches to the session again, backing off
// between attempts, until it works, the terminal is closed, or the session is
// gone.
func (s *Server) reattach(p *ptyState, t *targetState, backoff *time.Duration) (*tern.Client, *tern.ShellStream, error) {
	for {
		select {
		case <-time.After(*backoff):
		case <-p.ctx.Done():
			return nil, nil, errors.New("closed")
		}
		*backoff = min(max(*backoff*2, time.Second), ptyReconnectMax)
		cl, err := t.Dial(p.ctx)
		if err != nil {
			slog.Debug("terminal reconnect failed", "pty", p.id, "err", err)
			continue
		}
		cols, rows := p.size()
		st, err := cl.OpenShell(tern.ShellOptions{Session: p.session, Mode: "attach", AttachID: p.attachID, Write: true, Cols: cols, Rows: rows})
		if err != nil {
			cl.Close()
			if strings.Contains(err.Error(), "no such session") {
				if p.adopting {
					return nil, nil, errors.New("the session ended on the agent while tern mcp was not running")
				}
				return nil, nil, errors.New("the session ended on the agent while the connection was down")
			}
			slog.Debug("terminal reattach failed", "pty", p.id, "err", err)
			continue
		}
		if !p.adopting {
			p.mu.Lock()
			p.reconnects++
			p.mu.Unlock()
		}
		return cl, st, nil
	}
}

// resume returns the writer for a newly attached stream. The agent first
// replays its recent output: what this terminal already has is skipped by the
// offset the agent reports, and output the agent no longer had is noted.
func (p *ptyState) resume(st *tern.ShellStream) io.Writer {
	w := &resumeWriter{p: p}
	switch {
	case p.adopting:
		p.adopting = false
		p.note("reattached after tern mcp restarted; what follows begins with the agent's replay of recent output")
		p.agentPos = max(st.Offset, 0)
	case st.Offset < 0: // an agent that does not report offsets
		if p.agentPos > 0 {
			w.dropFirst = true // its first write is the replay
			p.note("reconnected; this agent cannot tell what was missed, so output from while the connection was down may be lost")
		}
	case st.Offset > p.agentPos:
		p.note(fmt.Sprintf("reconnected; %d bytes of output from while the connection was down were lost", st.Offset-p.agentPos))
		p.agentPos = st.Offset
	default:
		w.skip = p.agentPos - st.Offset
	}
	return w
}

type resumeWriter struct {
	p         *ptyState
	skip      int64
	dropFirst bool
}

func (w *resumeWriter) Write(b []byte) (int, error) {
	n := len(b)
	if w.dropFirst {
		w.dropFirst = false
		return n, nil
	}
	if w.skip > 0 {
		k := min(w.skip, int64(len(b)))
		w.skip -= k
		b = b[k:]
	}
	if len(b) > 0 {
		w.p.out.Write(b)
		w.p.rec.Output(b)
		w.p.agentPos += int64(len(b))
	}
	return n, nil
}

// note writes a line from tern itself into the terminal's output.
func (p *ptyState) note(text string) {
	b := []byte("\r\n[tern: " + text + "]\r\n")
	p.out.Write(b)
	p.rec.Output(b)
}

// setStream records the live stream, or that there is none. It refuses a new
// stream once the terminal is closing, so the closer and a reconnect cannot
// miss each other.
func (p *ptyState) setStream(st *tern.ShellStream) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case st == nil:
		if p.stream != nil {
			p.stream, p.ready = nil, make(chan struct{})
		}
	case p.closing:
		return false
	default:
		p.stream, p.readOnly = st, st.ReadOnly
		close(p.ready)
	}
	return true
}

// liveStream returns the stream to type into, waiting a while for a dropped
// connection to come back.
func (p *ptyState) liveStream(ctx context.Context) (*tern.ShellStream, error) {
	timer := time.NewTimer(ptyAttachWait)
	defer timer.Stop()
	for {
		p.mu.Lock()
		st, ready, ended, closing, ro, reason := p.stream, p.ready, p.ended, p.closing, p.readOnly, p.endReason
		p.mu.Unlock()
		switch {
		case ended || closing:
			return nil, fmt.Errorf("the terminal has ended: %s", orDefault(reason, "closed"))
		case st != nil && ro:
			return nil, errors.New("this terminal is read-only for the AI now: a person took over the session while the connection was down; pty_read still works")
		case st != nil:
			return st, nil
		}
		select {
		case <-ready:
		case <-p.done:
		case <-timer.C:
			return nil, errors.New("the terminal's connection is down and reconnecting; try again shortly")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// end marks the terminal ended, wakes its readers and closes its recording.
func (p *ptyState) end(reason string) {
	p.mu.Lock()
	if p.ended {
		p.mu.Unlock()
		return
	}
	if p.closing {
		reason = "closed"
	}
	p.ended, p.endReason, p.endedAt = true, reason, time.Now()
	onEnd := p.onEnd
	p.mu.Unlock()
	p.out.Close()
	p.rec.Close()
	p.cancel()
	slog.Info("terminal ended", "pty", p.id, "target", p.target, "session", p.session, "reason", reason)
	if onEnd != nil {
		onEnd()
	}
}

func (p *ptyState) isEnded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ended
}

func (p *ptyState) size() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cols, p.rows
}

// acquire and release bracket a call using the terminal. A terminal in use,
// such as by a pty_run waiting minutes for its command, is never idle.
func (p *ptyState) acquire() {
	p.mu.Lock()
	p.inUse++
	p.lastUsed = time.Now()
	p.mu.Unlock()
}

func (p *ptyState) release() {
	p.mu.Lock()
	p.inUse--
	p.lastUsed = time.Now()
	p.mu.Unlock()
}

// closePTY ends the terminal. With endSession the session on the agent ends
// too, which a connection that is down is redialed once to do; failing that,
// or where the agent does not act on the request, the agent ends it after
// its idle time. Without endSession the session is left running, for
// persistence.
func (s *Server) closePTY(p *ptyState, endSession bool) {
	s.closePTYIf(p, endSession, nil)
}

// closePTYIf closes the terminal as closePTY does when cond is nil, or when
// the terminal is not closing yet and cond, judged under the terminal's lock
// as closing begins, holds; it reports whether this call began the close.
func (s *Server) closePTYIf(p *ptyState, endSession bool, cond func() bool) bool {
	p.mu.Lock()
	already := p.closing || p.ended
	if cond != nil && (already || !cond()) {
		p.mu.Unlock()
		return false
	}
	if !already {
		p.closing, p.keep = true, !endSession
	}
	st := p.stream
	p.mu.Unlock()
	if !already && endSession && st != nil {
		st.EndSession() // confirmed by the shell's exit, or redone below
	}
	p.cancel()
	if !endSession && st != nil {
		st.Close()
	}
	select {
	case <-p.done:
	case <-time.After(ptyEndWait):
		if st != nil {
			st.Close() // the agent ignored the request: just detach
		}
		select {
		case <-p.done:
		case <-time.After(ptyEndWait):
			slog.Warn("terminal did not stop", "pty", p.id)
		}
	}
	p.mu.Lock()
	exited := p.exited
	p.mu.Unlock()
	if !already && endSession && !exited {
		// Not connected, or the connection dropped before the agent said
		// the shell ended: the request may never have arrived, so dial the
		// agent and end the session there.
		if t := s.targets[p.target]; t != nil {
			s.endSession(p, t)
		}
	}
	p.end("closed")
	return !already
}

// endSession dials the agent to end a terminal's session while its own
// connection is down.
func (s *Server) endSession(p *ptyState, t *targetState) {
	ctx, cancel := context.WithTimeout(s.base, ptyEndWait)
	defer cancel()
	cl, err := t.Dial(ctx)
	if err != nil {
		return
	}
	defer cl.Close()
	cols, rows := p.size()
	st, err := cl.OpenShell(tern.ShellOptions{Session: p.session, Mode: "attach", AttachID: p.attachID, Write: true, Cols: cols, Rows: rows})
	if err != nil {
		return
	}
	defer st.Close()
	if !st.ReadOnly {
		st.EndSession()
		st.CopyOutput(io.Discard) // until the agent confirms
	}
}

// closeAllPTYs ends every terminal at shutdown, or with persistence detaches
// from them and leaves them running, recorded in the state file.
func (s *Server) closeAllPTYs() {
	keep := s.persisting()
	if keep {
		s.savePTYs()
		s.freezePTYStore() // what is saved now is what the next tern mcp gets
	}
	s.ptysMu.Lock()
	ptys := make([]*ptyState, 0, len(s.ptys))
	for _, p := range s.ptys {
		ptys = append(ptys, p)
	}
	s.ptysMu.Unlock()
	var wg sync.WaitGroup
	for _, p := range ptys {
		wg.Go(func() { s.closePTY(p, !keep) })
	}
	wg.Wait()
	s.closePTYStore()
}

// ptyJanitorTick is how often idle terminals are looked for.
var ptyJanitorTick = 30 * time.Second

// ptyJanitor closes terminals left idle and forgets ended ones after a while.
func (s *Server) ptyJanitor() {
	tick := time.NewTicker(ptyJanitorTick)
	defer tick.Stop()
	for {
		select {
		case <-s.base.Done():
			return
		case <-tick.C:
		}
		s.reapPTYs(time.Now())
	}
}

func (s *Server) reapPTYs(now time.Time) {
	var idle []*ptyState
	s.ptysMu.Lock()
	for id, p := range s.ptys {
		p.mu.Lock()
		ended, endedAt, last, inUse := p.ended, p.endedAt, p.lastUsed, p.inUse
		p.mu.Unlock()
		switch {
		case ended && now.Sub(endedAt) > ptyKeepEnded:
			delete(s.ptys, id)
		case !ended && inUse == 0 && now.Sub(last) > p.idle:
			idle = append(idle, p)
		}
	}
	s.ptysMu.Unlock()
	for _, p := range idle {
		// A call may have taken the terminal since: it is closed only if it
		// is still unused, decided as closing begins, under its lock, so a
		// call that takes it now finds it closing rather than losing it
		// midway.
		stillIdle := func() bool { return p.inUse == 0 && now.Sub(p.lastUsed) > p.idle }
		if s.closePTYIf(p, true, stillIdle) {
			s.logOrWarn(AuditEntry{Tool: "pty_close", Target: p.target, PTYID: p.id, Phase: "info", Reason: "closed after " + p.idle.String() + " without use"})
		}
	}
}

// ptyEnded runs when a terminal has ended: the ended terminals past the
// number a target may have open are forgotten, oldest first, so a model
// that opens terminals and ends their shells one after another cannot make
// this server keep them all, each with its output, for ptyKeepEnded.
func (s *Server) ptyEnded() {
	s.ptysMu.Lock()
	ended := map[string][]*ptyState{}
	for _, p := range s.ptys {
		if p.isEnded() {
			ended[p.target] = append(ended[p.target], p)
		}
	}
	var all []*ptyState
	for target, list := range ended {
		slices.SortFunc(list, func(a, b *ptyState) int { return a.endTime().Compare(b.endTime()) })
		keep := defaultPTYsPerTarget
		if t := s.targets[target]; t != nil {
			keep, _ = t.Policy.PTYLimits()
		}
		for len(list) > keep {
			delete(s.ptys, list[0].id)
			list = list[1:]
		}
		all = append(all, list...)
	}
	slices.SortFunc(all, func(a, b *ptyState) int { return a.endTime().Compare(b.endTime()) })
	for ; len(all) > maxPTYs; all = all[1:] {
		delete(s.ptys, all[0].id)
	}
	s.ptysMu.Unlock()
	s.savePTYs()
}

func (p *ptyState) endTime() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.endedAt
}

func (s *Server) lookupPTY(id string) *ptyState {
	s.ptysMu.Lock()
	defer s.ptysMu.Unlock()
	return s.ptys[id]
}

// --- prompts ---

// settle waits for the shell's first output to go quiet, as pty_open does,
// and remembers the prompt it ends with.
func (p *ptyState) settle(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, ptyOpenWait)
	defer cancel()
	p.out.Wait(ctx, 0)
	p.waitQuiet(ctx, ptySettle)
	p.promptNow()
}

// waitQuiet waits until output has been quiet for d, or ctx ends.
func (p *ptyState) waitQuiet(ctx context.Context, d time.Duration) {
	for ctx.Err() == nil {
		quiet := time.Since(p.out.LastWrite())
		if quiet >= d {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(d - quiet):
		}
	}
}

// promptNow returns the shell's prompt: the unfinished last line on screen
// once output has been quiet a moment, if it ends the way prompts do, as a
// shell's or a REPL's does. A line like "Password: " is a program asking for
// input, not the prompt to wait for when a command is done, so it is not
// taken. The prompt is remembered, so a call made while a command runs still
// knows what to wait for.
func (p *ptyState) promptNow() string {
	if last := p.out.LastWrite(); !last.IsZero() && time.Since(last) >= ptyPromptQuiet {
		end, _ := p.out.End()
		data, _, _ := p.out.Read(max(end-maxPromptBytes, 0), maxPromptBytes)
		cols, rows := p.size()
		text, _ := vtText(data, cols, rows)
		if line := lastLine(text); promptShape(line) != "" && len(line) <= maxPromptLen {
			p.setPrompt(line)
			return line
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prompt
}

func (p *ptyState) setPrompt(line string) {
	p.mu.Lock()
	p.prompt = line
	p.mu.Unlock()
}

func lastLine(text string) string {
	return text[strings.LastIndexByte(text, '\n')+1:]
}

// atPrompt reports whether text ends showing the prompt want: the same line,
// or, since a prompt often shows the working directory, a line that ends the
// way prompts do, in the same character as want: $ # > % and the like.
func atPrompt(text, want string) bool {
	last := lastLine(text)
	if want == "" || last == "" || len(last) > maxPromptLen {
		return false
	}
	if last == want {
		return true
	}
	shape := promptShape(want)
	return shape != "" && strings.HasSuffix(last, shape)
}

// promptShape is how prompt ends, its last character that is not a space and
// the spaces after it, if that character is one prompts end in.
func promptShape(prompt string) string {
	t := strings.TrimRight(prompt, " ")
	r, size := utf8.DecodeLastRuneInString(t)
	if size == 0 || !strings.ContainsRune("$#>%❯»λ", r) {
		return ""
	}
	return prompt[len(t)-size:]
}

// stripEcho removes the command line the terminal echoed back, which leads
// the output of a typed command. Nothing is removed unless every line of the
// command is there.
func stripEcho(text, command string) (string, bool) {
	rest := text
	for i, want := range strings.Split(strings.TrimRight(command, "\r\n"), "\n") {
		nl := strings.IndexByte(rest, '\n')
		if nl < 0 {
			return text, false
		}
		got, want := strings.TrimRight(rest[:nl], " "), strings.TrimRight(want, " \r")
		if got != want && (i == 0 || !strings.HasSuffix(got, want)) {
			return text, false // later lines follow a continuation prompt
		}
		rest = rest[nl+1:]
	}
	return rest, true
}

// --- reading ---

type ptyReadOpts struct {
	since       int64
	limit       int
	wait, idle  time.Duration
	inputIdle   time.Duration // quiet this long on an unfinished line also ends the wait
	until       *regexp.Regexp
	prompt      string // the wait ends when the terminal shows this prompt again
	cols, rows  int
	quietSince  time.Time // output before this does not count toward idle
	waitForData bool      // with nothing else to wait for: return once there is output
}

type ptyChunk struct {
	data           []byte
	next, dropped  int64
	matched, quiet bool
	prompt         bool // the terminal shows its prompt again
	final          bool // the terminal has ended and this is the last of its output
	more           bool // output past this chunk was already there
	full           bool // the read stopped at its size limit, not because a wait ended
}

// read waits as o says, then returns output from o.since. A chunk that more
// output may follow, unless the terminal went quiet, matched or showed its
// prompt, ends on a line, as job_poll's do, so a secret is not split across
// two reads where redaction would miss both halves; and never inside an
// escape sequence or a character, where the next read starts instead.
func (p *ptyState) read(ctx context.Context, o ptyReadOpts) ptyChunk {
	deadline := time.Now().Add(o.wait)
	// Matching until stops between windows once the wait is over, as when
	// the call is cancelled, so a costly pattern on a flood of output cannot
	// hold the read far past its wait.
	mctx, stopMatch := context.WithDeadline(ctx, deadline)
	defer stopMatch()
	var firstData time.Time
	// A read from inside an escape sequence or a character begun before since
	// starts after it: it shows nothing, and rendered on its own its rest
	// would show as text, such as "0m", which can split a secret where
	// redaction misses it. Where that sequence begins is learned as lookBack
	// reads the output before since, so a guess cannot hide text.
	look, _ := p.out.LookBack(o.since)
	open := look[vtOpen(look):]
	until := untilMatcher{re: o.until}
	for {
		data, next, dropped := p.out.Read(o.since, o.limit)
		end, closed := p.out.End()
		// A read that would start in a line whose start was dropped starts
		// after that line (see safeStart), and after the sequence or
		// character it would then start inside.
		skip, at := 0, next-int64(len(data))
		if safe := p.out.safeStart(at); safe > at {
			skip = int(min(safe-at, int64(len(data))))
			dropped += lineText(data[:skip])
			look, _ := p.out.LookBack(at + int64(skip))
			skip += vtHead(look[vtOpen(look):], data[skip:], o.cols, o.rows)
		} else {
			skip = vtHead(open, data, o.cols, o.rows)
		}
		c := ptyChunk{data: data[skip:], next: next, dropped: dropped, final: closed && next >= end, full: len(data) >= o.limit}
		now := time.Now()
		quietFor := now.Sub(laterOf(p.out.LastWrite(), o.quietSince))
		var text string
		if len(c.data) > 0 && (o.until != nil || o.prompt != "" || o.inputIdle > 0) {
			text, _ = vtText(c.data, o.cols, o.rows)
		}
		settled, done := false, false
		switch {
		case o.until != nil && len(c.data) > 0 && until.match(mctx, text, next-int64(len(c.data))):
			c.matched, settled, done = true, true, true
		case closed || len(data) >= o.limit:
			done = true
		case o.prompt != "" && quietFor >= ptyPromptQuiet && atPrompt(text, o.prompt):
			c.prompt, settled, done = true, true, true
		case o.idle > 0 && quietFor >= o.idle:
			c.quiet, settled, done = true, true, true
		case o.inputIdle > 0 && quietFor >= o.inputIdle && lastLine(text) != "":
			c.quiet, settled, done = true, true, true
		case o.waitForData && len(c.data) > 0:
			// Give a partial last line a moment to settle.
			if firstData.IsZero() {
				firstData = now
			}
			switch {
			case c.data[len(c.data)-1] == '\n' || quietFor >= lineGrace:
				settled, done = true, true
			case now.Sub(firstData) >= ptyGraceMax:
				done = true
			}
		case !now.Before(deadline):
			done = true
		}
		if done || ctx.Err() != nil {
			c = trimChunk(c, settled, o.cols, o.rows)
			if len(c.data) == 0 && len(data) >= o.limit && !c.final {
				o.since = c.next
				c = p.wholeSequence(o, c)
			}
			end, _ = p.out.End()
			c.more = c.next < end
			return c
		}
		spent := time.Since(now) // rendering and matching
		// Sleep until something could change: new output, the deadline, or a
		// quiet period running out.
		wait := deadline.Sub(now)
		for _, q := range []time.Duration{o.idle, o.inputIdle, promptQuiet(o.prompt)} {
			if q > quietFor {
				wait = min(wait, q-quietFor)
			}
		}
		if !firstData.IsZero() {
			wait = min(lineGrace-quietFor, ptyGraceMax-now.Sub(firstData))
		}
		wctx, cancel := context.WithTimeout(ctx, max(wait, time.Millisecond))
		if firstData.IsZero() {
			p.out.Wait(wctx, end)
		} else {
			<-wctx.Done() // waiting for quiet, not for more
		}
		cancel()
		if o.until != nil || o.prompt != "" {
			// Let a burst of output arrive before matching it again, and
			// spend at most a quarter of the wait on rendering and matching.
			time.Sleep(min(max(20*time.Millisecond, 3*spent), max(time.Until(deadline), 0)))
		}
	}
}

// vtHead returns how many bytes at the start of data finish open, the
// escape sequence or character that the output before a read ends inside,
// as vtText reads them: all of data while it does not end. A run of
// sequences that ESCs chain together may go on far past maxVTString, so
// all of data is looked at.
func vtHead(open, data []byte, cols, rows int) int {
	if len(open) == 0 || len(data) == 0 {
		return 0
	}
	end := seqEnd(append(open[:len(open):len(open)], data...), cols, rows)
	if end == 0 {
		return len(data)
	}
	return min(max(end-len(open), 0), len(data))
}

const (
	// maxUntilInsts bounds the program an until pattern compiles to. At
	// worst, matching takes about 6 ns per instruction per byte of text, and
	// a pattern a few hundred bytes long, such as (?:.{999}|x) forty times,
	// compiles to forty thousand instructions.
	maxUntilInsts = 1000
	// untilWindow is the most text matched in one go; a cancelled call stops
	// between windows, which overlap by untilTail.
	untilWindow = 16 << 10
	// untilTail is how far back in text already matched a new match may
	// start. It bounds the matches until is sure to find.
	untilTail = 4 << 10
)

// untilMatcher matches until against the text of a read as it grows: what
// was already matched without success is not matched again, but for its last
// untilTail bytes, so a costly pattern costs time in proportion to the
// output, not to the output again on every wake-up of the wait.
type untilMatcher struct {
	re      *regexp.Regexp
	base    int64 // the output offset the text starts at
	checked int   // the text before this was matched without success
}

func (m *untilMatcher) match(ctx context.Context, text string, base int64) bool {
	if base != m.base || len(text) < m.checked {
		m.base, m.checked = base, 0
	}
	// Windows start where lines do and end before a line break, where they
	// can, since ^ and $ also match at the ends of the text matched. Each
	// window starts at most untilTail before the last one ended, and is at
	// least three times that long, so every match no longer than untilTail
	// lies whole in one of them.
	from, to := lineStart(text, max(m.checked-untilTail, 0)), 0
	for {
		to = len(text)
		if to-from > untilWindow {
			to = from + untilWindow
			if i := strings.LastIndexByte(text[from+3*untilTail:to], '\n'); i >= 0 {
				to = from + 3*untilTail + i
			}
		}
		if m.re.MatchString(text[from:to]) {
			return true
		}
		if to == len(text) || ctx.Err() != nil {
			break
		}
		from = lineStart(text, to-untilTail)
	}
	// What was matched is done with, but for the last line, which may still
	// change; the lines before it are final.
	m.checked = min(to, len(text)-len(lastLine(text)))
	return false
}

// lineStart returns where the line that holds text[i] starts, if that is at
// most untilTail before i, else i.
func lineStart(text string, i int) int {
	lo := max(i-untilTail, 0)
	if j := strings.LastIndexByte(text[lo:i], '\n'); j >= 0 {
		return lo + j + 1
	}
	if lo == 0 {
		return 0
	}
	return i
}

// wholeSequence handles a read filled by one unfinished escape sequence,
// which trimming cuts to nothing: it moves the reader past that sequence,
// past the limit if need be, so it moves on instead of reading the sequence
// again forever. The sequence is followed from where it began: one begun
// at o.since is returned whole, and shows as nothing; one begun before it,
// which the read was all inside, is learned as lookBack reads the output
// before o.since, and the reader skips the rest of it, as what a read holds
// of it shows nothing. A run of sequences that ESCs chain together and goes
// on past what is read, or output that ends inside one, moves the reader
// past what is read of it.
func (p *ptyState) wholeSequence(o ptyReadOpts, c ptyChunk) ptyChunk {
	look, _ := p.out.LookBack(o.since)
	open := look[vtOpen(look):]
	want := o.limit + maxVTString + 16
	end, closed := p.out.End() // before the read: once closed, the read holds all there is
	data, next, _ := p.out.Read(o.since, want)
	start := next - int64(len(data))
	if start != o.since {
		return c // dropped since the read: the next one starts where the drop leaves it (see read)
	}
	e := seqEnd(append(open[:len(open):len(open)], data...), o.cols, o.rows)
	k := e - len(open)
	if e > 0 && k <= 0 {
		// The look back's sequence ended, or was given up, where the read
		// starts: what is read begins afresh, and the reader moves on.
		open = open[:0]
		e = seqEnd(data, o.cols, o.rows)
		k = e
	}
	switch {
	case e > 0 && k > 0:
	case e > 0 || len(data) < want && !closed:
		return c // still arriving: the next read sees it whole
	default:
		k = len(data)
	}
	out := ptyChunk{next: start + int64(k), dropped: c.dropped, full: true, final: closed && start+int64(k) >= end}
	if len(open) == 0 {
		out.data = data[:k]
	}
	return out
}

// promptQuiet is the quiet a prompt match needs, or 0 without a prompt.
func promptQuiet(prompt string) time.Duration {
	if prompt == "" {
		return 0
	}
	return ptyPromptQuiet
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// compileUntil compiles an until pattern. Output is matched as text, line by
// line, so ^ and $ also match at line breaks. A pattern whose program is too
// large to match in bounded time is refused.
func compileUntil(pattern string) (*regexp.Regexp, error) {
	pattern = "(?m)" + pattern
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("is not a valid regular expression: %v", err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, fmt.Errorf("is not a valid regular expression: %v", err)
	}
	if n := len(prog.Inst); n > maxUntilInsts {
		return nil, fmt.Errorf("is too complex: it compiles to %d instructions, more than %d; match a shorter or simpler part of the output", n, maxUntilInsts)
	}
	return regexp.Compile(pattern)
}

func trimChunk(c ptyChunk, settled bool, cols, rows int) ptyChunk {
	if c.final {
		return c
	}
	if !settled {
		c.data, c.next = wholeLines(c.data, c.next)
	}
	// Even all of it: an unfinished sequence shows nothing until it ends.
	if _, inc := vtText(c.data, cols, rows); inc < len(c.data) {
		c.next -= int64(len(c.data) - inc)
		c.data = c.data[:inc]
	}
	return c
}
