// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// childEnv returns the environment for spawned shells and exec'd commands with
// the agent's own TERN_* secrets removed (TERN_TOKEN, TERN_RELAY_TOKEN,
// TERN_API_TOKEN, ...), so a hosted shell cannot read them via the environment.
func childEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, kv := range src {
		// Case-insensitive: Windows env lookups are case-insensitive, so a
		// shell could otherwise read tern_token even though we only dropped
		// TERN_TOKEN.
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(strings.ToUpper(name), "TERN_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// Agent hosts sessions for authenticated clients. One Agent is shared across
// all connections so that named sessions survive client disconnects (resume)
// and can be joined by more than one client (share).
type Agent struct {
	TLS  *tls.Config
	Auth *AuthConfig
	mgr  *sessionManager

	// Plaintext accepts connections without TLS, for a client using
	// --insecure-skip-encryption. It backs the agent's own
	// --insecure-skip-encryption flag and must never be used in production:
	// the session, including the auth exchange, runs in cleartext.
	Plaintext bool
}

// NewAgent builds an agent that spawns shell and keeps idle sessions alive for
// idle after their last client detaches (0 = until the shell exits). When
// recordDir is non-empty, each session is recorded there as an asciicast.
func NewAgent(serverTLS *tls.Config, auth *AuthConfig, shell string, idle time.Duration, recordDir string) *Agent {
	// As a container's process 1, the agent inherits orphans from the start,
	// not only from its own commands.
	reapsOrphans()
	return &Agent{TLS: serverTLS, Auth: auth, mgr: newSessionManager(shell, idle, recordDir)}
}

// Serve runs one connection: inner TLS, auth, then a yamux session whose
// streams are dispatched by kind. It always closes transport.
func (a *Agent) Serve(transport net.Conn, label string) {
	a.ServeAdmitted(transport, label, func() {}, nil)
}

// ServeAdmitted is Serve for a connection admitted by a PreAuthLimiter: it
// calls authDone once the unauthenticated part is over, passed or failed.
// Closing cut, as the limiter does when it gives the connection's slot to a
// newcomer (see PreAuthLimiter.Admit), ends that part at once, also where it
// waits for something other than transport, a place to have its signature
// checked, and nothing more is checked for it. A nil cut is never closed.
func (a *Agent) ServeAdmitted(transport net.Conn, label string, authDone func(), cut <-chan struct{}) {
	defer transport.Close()
	conn, ok := a.handshake(transport, label, cut)
	authDone()
	if !ok {
		return
	}

	sess, err := muxServer(conn)
	if err != nil {
		slog.Debug("mux setup failed", "peer", label, "err", err)
		return
	}
	defer sess.Close()

	ctl := newControls()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go a.handleStream(st, sess, label, ctl)
	}
}

// handshake runs the inner TLS handshake and authentication under a deadline,
// so a stalled or slow-loris peer cannot pin a goroutine and its FD, and
// clears the deadline once the peer is in: the mux after it is long-lived.
// It is over too once cut is closed (see ServeAdmitted).
func (a *Agent) handshake(transport net.Conn, label string, cut <-chan struct{}) (net.Conn, bool) {
	deadline := time.Now().Add(handshakeTimeout)
	transport.SetDeadline(deadline)
	var conn net.Conn = transport
	var bind []byte // in plaintext there is no TLS session to bind the proof to
	if !a.Plaintext {
		tc := tls.Server(transport, a.TLS)
		if err := tc.Handshake(); err != nil {
			slog.Debug("tls handshake failed", "peer", label, "err", err)
			return nil, false
		}
		conn = tc
		var err error
		if bind, err = sessionBind(tc, agentCertFP(a.TLS)); err != nil {
			slog.Warn("auth failed", "peer", label, "err", err)
			return nil, false
		}
	}
	desc, ok := serverAuthenticate(conn, a.Auth, bind, deadline, cut)
	if !ok {
		slog.Warn("auth failed", "peer", label, "method", desc)
		return nil, false
	}
	transport.SetDeadline(time.Time{})
	slog.Info("authenticated", "peer", label, "method", desc)
	return conn, true
}

func (a *Agent) handleStream(st net.Conn, sess *yamux.Session, label string, ctl *controls) {
	// Bound the header read: after auth a client can open a stream and never send
	// a header, which would otherwise pin this goroutine forever. Each handler
	// clears the deadline once it knows the stream is meant to be long-lived.
	st.SetReadDeadline(time.Now().Add(handshakeTimeout))
	h, err := readHeader(st)
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	switch h.Kind {
	case kindShell:
		a.mgr.serveShell(st, h, label, ctl)
	case kindExec:
		serveExec(st, h, label, ctl)
	case kindForward:
		serveForward(st, h)
	case kindFile:
		serveFile(st, h)
	case kindRPC:
		a.serveRPC(st, h, sess, label)
	case kindControl:
		ctl.serve(st)
	default:
		st.Close()
	}
}

// --- control requests ---

// controls routes the control requests of one connection, which come on a
// stream of their own, to the streams they are for: a shell attachment's
// resize and end, an exec's end. Apart from those streams' input, a request
// never waits behind input the agent cannot take yet, such as a writer's
// typing into a program that reads none.
type controls struct {
	mu      sync.Mutex
	targets map[uint32]func(typ byte, payload []byte)
}

func newControls() *controls {
	return &controls{targets: make(map[uint32]func(byte, []byte))}
}

// add makes st, a stream of this connection, take control requests, which f
// handles, until the returned remove is called. A stream that is not one of
// a mux session's, as in tests, has no id to be named by and takes none.
func (c *controls) add(st net.Conn, f func(typ byte, payload []byte)) (remove func()) {
	s, ok := st.(*yamux.Stream)
	if c == nil || !ok {
		return func() {}
	}
	id := s.StreamID()
	c.mu.Lock()
	c.targets[id] = f
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.targets, id)
		c.mu.Unlock()
	}
}

// serve handles the control requests read from st until it ends. Each
// starts with the id of the stream it is for; one for a stream that is gone,
// or that takes none, is dropped.
func (c *controls) serve(st net.Conn) {
	defer st.Close()
	for {
		typ, payload, err := readFrameMax(st, maxControlPayload)
		if err != nil || len(payload) < 4 {
			return
		}
		c.mu.Lock()
		f := c.targets[binary.BigEndian.Uint32(payload)]
		c.mu.Unlock()
		if f != nil {
			f(typ, payload[4:])
		}
	}
}

// --- shell (interactive, shared, resumable) ---

func (m *sessionManager) serveShell(st net.Conn, h streamHeader, label string, ctl *controls) {
	ps, att, snapshot, err := m.attach(h.Session, h.Mode, h.Write, h.Force, h.Attach, h.Cols, h.Rows)
	if err != nil {
		writeReply(st, streamReply{Err: err.Error()})
		st.Close()
		return
	}
	// Resize and end come on the connection's control stream, from before
	// the reply on, however much input waits on this one.
	defer ctl.add(st, func(typ byte, payload []byte) {
		switch typ {
		case frameResize:
			if cols, rows, ok := decodeResize(payload); ok {
				ps.resize(att, int(cols), int(rows))
			}
		case frameEnd:
			// A writer could type exit; this ends the session whatever runs
			// in it. Viewers cannot.
			if ps.endBy(att) {
				slog.Info("shell session ended by client", "peer", label, "session", ps.name)
			}
		}
	})()
	writeReply(st, streamReply{OK: true, Session: ps.name, Shared: ps.clientCount() > 1, ReadOnly: !att.write, Offset: &att.offset})
	slog.Info("shell session", "peer", label, "session", ps.name, "write", att.write, "clients", ps.clientCount())

	// output: replay snapshot, then live output (all framed), then an exit
	// frame if the session ended. A client dropped for falling behind, or one
	// that detached, gets no exit frame: the first reconnects and resumes, and
	// neither reports the shell as gone while it still runs.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		if len(snapshot) > 0 {
			writeFrame(st, frameData, snapshot)
		}
		for chunk := range att.ch {
			if err := writeFrame(st, frameData, chunk); err != nil {
				break
			}
		}
		if ps.endedFor(att) {
			writeFrame(st, frameExit, encodeExit(0))
		}
		st.Close()
	}()

	// input: a writer's input goes to the terminal through the session's
	// feed (see feed), so a program that does not read its input holds up
	// only that: waiting on its queue, this loop still learns that the client
	// left or the session ended. A viewer's input is dropped.
	gone := connClosed(st)
	for {
		typ, payload, err := readFrame(st)
		if err != nil {
			break
		}
		if typ == frameData && att.write && !queueTyped(ps.typed, att, payload, outDone, gone) {
			break
		}
	}
	ps.detach(att)
}

// inputQueueLen is how many chunks of up to ioBufSize bytes of a command's
// input, or of a terminal's, wait for the goroutine that writes them there.
// When they are all taken the stream's reader waits, and the stream's flow
// control holds the client back, so input is never buffered without bound.
const inputQueueLen = 64

// queueInput hands p to the writer goroutine on q, in chunks of up to
// ioBufSize bytes, waiting while q is full. It gives up and returns false
// once stop or gone is closed: a reader waiting here is not reading its
// stream, and must still learn that its client or its program is gone.
func queueInput(q chan<- []byte, p []byte, stop, gone <-chan struct{}) bool {
	for len(p) > 0 {
		n := min(len(p), ioBufSize)
		select {
		case q <- p[:n]:
		case <-stop:
			return false
		case <-gone:
			return false
		}
		p = p[n:]
	}
	return true
}

// queueTyped is queueInput for a terminal's queue, whose chunks name the
// attachment that typed them.
func queueTyped(q chan<- typedInput, att *attachment, p []byte, stop, gone <-chan struct{}) bool {
	for len(p) > 0 {
		n := min(len(p), ioBufSize)
		select {
		case q <- typedInput{att, p[:n]}:
		case <-stop:
			return false
		case <-gone:
			return false
		}
		p = p[n:]
	}
	return true
}

// writeQueued writes the input queued on q to w until q is closed or stop
// is. Once stop is closed nothing more is written, a write already under way
// aside, even with input still queued. Once a write fails (the program
// closed its input, or ended) it drops the rest, so the reader that queues
// input never waits on a queue nobody drains.
func writeQueued(w io.Writer, q <-chan []byte, stop <-chan struct{}) {
	failed := false
	for {
		select {
		case p, ok := <-q:
			if !ok {
				return
			}
			select {
			case <-stop: // queued input was ready too: stop comes first
				return
			default:
			}
			if !failed {
				_, err := w.Write(p)
				failed = err != nil
			}
		case <-stop:
			return
		}
	}
}

// connClosed returns a channel closed when the connection carrying st ends,
// or nil (never closed) when st is not a stream of one, as in tests. A reader
// waiting on a full input queue learns that its client left only this way.
func connClosed(st net.Conn) <-chan struct{} {
	if s, ok := st.(*yamux.Stream); ok {
		return s.Session().CloseChan()
	}
	return nil
}

// --- exec (non-interactive command) ---

// dataFrames frames each Write as a data frame on w.
type dataFrames struct{ w io.Writer }

func (d dataFrames) Write(p []byte) (int, error) {
	if err := writeFrame(d.w, frameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func serveExec(st net.Conn, h streamHeader, label string, ctl *controls) {
	defer st.Close()
	if len(h.Cmd) == 0 {
		writeReply(st, streamReply{Err: "empty command"})
		return
	}
	cmd, err := newCommand(h.Cmd)
	if err != nil {
		writeReply(st, streamReply{Err: err.Error()})
		return
	}
	cmd.Env = childEnv() // don't leak the agent's own TERN_* secrets to the command
	// stdout and stderr go to a pipe read here rather than through os/exec,
	// whose Wait reaps the command before its output has ended: the command
	// must be reaped last (see process).
	outR, outW, err := os.Pipe()
	if err != nil {
		writeReply(st, streamReply{Err: err.Error()})
		return
	}
	cmd.Stdout, cmd.Stderr = outW, outW
	stdin, err := cmd.StdinPipe()
	if err != nil {
		outR.Close()
		outW.Close()
		writeReply(st, streamReply{Err: err.Error()})
		return
	}
	p, err := startCommand(cmd) // in a session (a job on Windows) of its own
	outW.Close()
	if err != nil {
		outR.Close()
		writeReply(st, streamReply{Err: err.Error()})
		return
	}

	// ended is closed once the exchange is over: the command ended or its
	// client left. When the client leaves, its stream or its connection
	// ending or its end request coming, kill the command and what it started
	// (see process.kill), so a cancelled REST job or MCP run or a dropped
	// client does not leave the command, its pipeline or its background jobs
	// running, and stop feeding it and serving its output, which may be held
	// open by a process that left the group.
	ended := make(chan struct{})
	var endOnce, leaveOnce sync.Once
	end := func() { endOnce.Do(func() { close(ended) }) }
	defer end()
	leave := func() {
		leaveOnce.Do(func() {
			p.kill()
			stdin.Close()
			outR.Close()
			st.Close()
			end()
		})
	}
	// The end request comes on the connection's control stream: the end of
	// this stream reaches the agent only after the input sent before it,
	// which a command that reads none never takes.
	defer ctl.add(st, func(typ byte, _ []byte) {
		if typ == frameEnd {
			go leave()
		}
	})()

	// The reply goes first; the output is read only after it.
	writeReply(st, streamReply{OK: true})
	// The program only, unless verbose: arguments can carry secrets, as in
	// mysql -pSECRET, and logs are kept and shared more widely than that.
	slog.Info("exec", "peer", label, "program", h.Cmd[0], "args", len(h.Cmd)-1)
	slog.Debug("exec arguments", "peer", label, "cmd", h.Cmd)

	if gone := connClosed(st); gone != nil {
		go func() {
			select {
			case <-gone:
				leave()
			case <-ended:
			}
		}()
	}

	// input: client frames -> stdin, through a queue, so a command that does
	// not read its input stalls only the goroutine writing it, never the
	// reader that must see the client leave.
	in := make(chan []byte, inputQueueLen)
	go func() {
		writeQueued(stdin, in, ended)
		stdin.Close()
	}()
	go func() {
		inputOpen := true
		for {
			typ, payload, err := readFrame(st)
			if err != nil {
				leave()
				return
			}
			switch typ {
			case frameData:
				if inputOpen && !queueInput(in, payload, ended, nil) {
					return
				}
			case frameEOF:
				if inputOpen {
					close(in)
					inputOpen = false
				}
			}
		}
	}()

	// output: the command's stdout and stderr, framed, until every process
	// holding them has closed them (or the client left).
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		if _, err := io.Copy(dataFrames{st}, outR); err != nil {
			leave()
		}
		outR.Close()
	}()
	<-outDone

	code := 0
	if err := p.wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	writeFrame(st, frameExit, encodeExit(code))
}

// --- forward -L: agent dials and bridges ---

func serveForward(st net.Conn, h streamHeader) {
	c, err := net.DialTimeout("tcp", h.Dial, forwardDialTimeout)
	if err != nil {
		writeReply(st, streamReply{Err: err.Error()})
		st.Close()
		return
	}
	writeReply(st, streamReply{OK: true})
	pipe(st, c)
}

// --- file copy ---

// maxPseudoFile and maxPseudoTime bound what is read of a file that reports
// size 0, such as those under /proc, to learn its real size, and for how
// long: one that keeps giving more, as a busy trace pipe can, is refused.
const (
	maxPseudoFile = 4 << 20
	maxPseudoTime = 5 * time.Second
)

// errNotRegular refuses a download of anything but a regular file.
var errNotRegular = errors.New("not a regular file")

func serveFile(st net.Conn, h streamHeader) {
	defer st.Close()
	switch h.Op {
	case fileSend: // client -> agent (write file on agent)
		// Write to a temp file in the same directory, then rename over the
		// target only on success, so a failed or interrupted upload never
		// truncates or destroys the pre-existing file.
		mode := os.FileMode(h.FileMode).Perm()
		if mode == 0 {
			mode = 0o644
		}
		// A path ending in a separator names a directory, not a file to write.
		rawDir, base := splitUploadPath(h.Path)
		if h.Path == "" || os.IsPathSeparator(h.Path[len(h.Path)-1]) || base == "" || base == "." || base == ".." {
			writeReply(st, streamReply{Err: fmt.Sprintf("%q is not a file path; name the file to write", h.Path)})
			return
		}
		// The directory is opened once and the file written where that open
		// directory is (see uploadTarget), so the path reported as Real is
		// where the upload lands. A path that cannot be resolved is reported
		// as "unresolved: ...", which a client checking paths refuses; plain
		// copies are unaffected.
		t, err := openUploadTarget(h.Path, rawDir, base, mode)
		if err != nil {
			writeReply(st, streamReply{Err: err.Error()})
			return
		}
		defer t.close()
		writeReply(st, streamReply{OK: true, Real: t.real})
		if h.Confirm {
			// The client checks Real first. Waiting for its go-ahead matters
			// most for an empty file, where no content would make us wait.
			var goAhead [1]byte
			if _, err := io.ReadFull(st, goAhead[:]); err != nil || goAhead[0] != 1 {
				t.abort()
				return
			}
		}
		n, cerr := io.CopyN(t.tmp, st, h.Size)
		if cerr != nil || n != h.Size {
			t.abort()
			slog.Warn("file upload failed", "path", h.Path, "written", n, "want", h.Size, "err", cerr)
			st.Write([]byte{0}) // nack: write incomplete/failed, original untouched
			return
		}
		if err := t.finish(); err != nil {
			slog.Warn("file upload failed", "path", h.Path, "err", err)
			st.Write([]byte{0})
			return
		}
		st.Write([]byte{1}) // ack: file fully on disk
	case fileRecv: // agent -> client (read file from agent)
		// Refuse anything but a regular file: opening a FIFO can block the
		// serving goroutine forever, and opening a device can act on it (a
		// terminal becomes ternd's controlling terminal). openRegular looks
		// at what the path names before it opens it and checks the file it
		// opened, so a name another user swaps meanwhile is refused too.
		f, info, err := openRegular(h.Path)
		if err != nil {
			writeReply(st, streamReply{Err: err.Error()})
			return
		}
		defer f.Close()
		// Real is the path of the file opened, from its descriptor: a name
		// swapped for a link after the open cannot make it name another.
		real, rerr := openedRealPath(f)
		dirsOpen := rerr == nil && dirsOpenToAll(real)
		if rerr != nil {
			real = "unresolved: " + rerr.Error()
		}
		writeReply(st, streamReply{OK: true, Size: info.Size(), FileMode: uint32(info.Mode().Perm()), Real: real, DirsOpen: dirsOpen})
		if h.Confirm {
			// Nothing of the file is read before the client, which checks
			// Real first, says go ahead: reading some files acts, as
			// /proc/kmsg hands each message to one reader only.
			var goAhead [1]byte
			if _, err := io.ReadFull(st, goAhead[:]); err != nil || goAhead[0] != 1 {
				return
			}
		}
		var pseudo []byte
		if info.Size() == 0 {
			// Kernel files such as /proc/cpuinfo report size 0 but have
			// content: it is read now, and a second reply carries the size
			// read.
			pseudo, err = readPseudo(f, maxPseudoFile+1, maxPseudoTime)
			if err == nil && len(pseudo) > maxPseudoFile {
				err = fmt.Errorf("file reports size 0 but holds more than %d bytes", maxPseudoFile)
			}
			if err != nil {
				writeReply(st, streamReply{Err: err.Error()})
				return
			}
			writeReply(st, streamReply{OK: true, Size: int64(len(pseudo))})
		}
		// The client sends nothing more, so its end of input means it stopped
		// reading (ReadFile takes a prefix): close, which ends a copy blocked
		// on a full window instead of holding the file until a timeout.
		go func() {
			io.Copy(io.Discard, st)
			st.Close()
		}()
		if info.Size() == 0 {
			st.Write(pseudo)
		} else {
			io.Copy(st, f)
		}
	default:
		writeReply(st, streamReply{Err: "bad file op"})
	}
}

// --- rpc: list sessions, set up remote forward (-R) ---

func (a *Agent) serveRPC(st net.Conn, h streamHeader, sess *yamux.Session, label string) {
	switch h.Op {
	case rpcList:
		writeReply(st, streamReply{OK: true, Sessions: a.mgr.list()})
		st.Close()
	case rpcRemoteForward:
		ln, err := ListenTCP(h.Bind)
		if err != nil {
			writeReply(st, streamReply{Err: err.Error()})
			st.Close()
			return
		}
		writeReply(st, streamReply{OK: true})
		slog.Info("remote-forward listening", "peer", label, "bind", h.Bind)
		// close the listener when the control stream goes away
		go func() {
			io.Copy(io.Discard, st)
			ln.Close()
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			go func(c net.Conn) {
				rs, err := sess.Open()
				if err != nil {
					c.Close()
					return
				}
				if err := writeHeader(rs, streamHeader{Kind: kindForwardR, Bind: h.Bind}); err != nil {
					rs.Close()
					c.Close()
					return
				}
				pipe(rs, c)
			}(c)
		}
		st.Close()
	default:
		writeReply(st, streamReply{Err: "bad rpc op"})
		st.Close()
	}
}
