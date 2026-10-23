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
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Client is an authenticated, multiplexed connection to an agent. One Client
// carries any number of shells, exec runs, forwards and file copies.
type Client struct {
	conn net.Conn
	sess *yamux.Session

	mu       sync.Mutex
	rforward map[string]string // -R bind -> local dial target

	ctlMu sync.Mutex
	ctl   net.Conn // the control stream, opened on first use (see control)
}

// Dial wraps transport in inner TLS (pinned via clientTLS), authenticates, and
// starts the mux. transport is a raw TCP conn (direct) or a relay-tunnelled
// stream (relay mode). On error, transport is closed. The handshake and auth
// are bounded by handshakeTimeout, so a peer that accepts but never answers
// cannot hang the dial.
// A nil clientTLS runs the session in plaintext (no TLS): it backs the client
// --insecure-skip-encryption flag and requires the agent to be in the matching
// plaintext mode. The token or key is still required, but the channel binding
// falls away (there is no TLS session), so auth is unprotected on the wire.
func Dial(transport net.Conn, clientTLS *tls.Config, keyFile, token string) (*Client, error) {
	transport.SetDeadline(time.Now().Add(handshakeTimeout))
	var conn net.Conn = transport
	// The proof binds to the TLS session made here with the agent, never to
	// the transport's: through a relay the transport is the relay's own TLS
	// connection, which the agent is not a party to.
	var bind []byte
	if clientTLS != nil {
		tc := tls.Client(transport, clientTLS)
		if err := tc.Handshake(); err != nil {
			transport.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		var err error
		if bind, err = sessionBind(tc, connCertFP(tc)); err != nil {
			tc.Close()
			return nil, err
		}
		conn = tc
	}
	if err := clientAuthenticate(conn, bind, keyFile, token); err != nil {
		conn.Close()
		return nil, err
	}
	sess, err := muxClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	transport.SetDeadline(time.Time{}) // authenticated: long-lived mux, no deadline
	c := &Client{conn: conn, sess: sess, rforward: make(map[string]string)}
	go c.acceptLoop()
	return c, nil
}

// Close tears down the mux session and the underlying connection.
func (c *Client) Close() error {
	c.sess.Close()
	return c.conn.Close()
}

// acceptLoop handles agent-initiated streams, which carry -R reverse
// connections only. An agent that opens one for no -R this client set up is
// broken or hostile, so the connection to it is closed; at most
// maxInboundHeaders streams may be waiting for their header at once, and any
// more are refused.
func (c *Client) acceptLoop() {
	headers := make(chan struct{}, maxInboundHeaders)
	for {
		st, err := c.sess.AcceptStream()
		if err != nil {
			return
		}
		c.mu.Lock()
		asked := len(c.rforward) > 0
		c.mu.Unlock()
		if !asked {
			c.dropAgent("opened a stream though no -R forward was set up")
			return
		}
		select {
		case headers <- struct{}{}:
			go c.handleInbound(st, func() { <-headers })
		default:
			st.Close()
		}
	}
}

// control sends a control request for st, a stream of this connection, on
// the connection's control stream, which it opens on first use: the request
// never waits behind input sent on st that the agent cannot take yet.
func (c *Client) control(st net.Conn, typ byte, payload []byte) error {
	s, ok := st.(*yamux.Stream)
	if !ok {
		return errors.New("not a stream of this connection")
	}
	msg := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(msg, s.StreamID())
	copy(msg[4:], payload)
	c.ctlMu.Lock()
	defer c.ctlMu.Unlock()
	if c.ctl == nil {
		cs, err := c.sess.Open()
		if err != nil {
			return err
		}
		if err := writeHeader(cs, streamHeader{Kind: kindControl}); err != nil {
			cs.Close()
			return err
		}
		c.ctl = cs
	}
	if err := writeFrame(c.ctl, typ, msg); err != nil {
		c.ctl.Close()
		c.ctl = nil // the next request opens another
		return err
	}
	return nil
}

// dropAgent closes the connection to an agent that broke the protocol.
func (c *Client) dropAgent(why string) {
	slog.Warn("closing the connection: the agent "+why, "agent", c.conn.RemoteAddr().String())
	c.Close()
}

func (c *Client) handleInbound(st net.Conn, headerRead func()) {
	// A malicious or buggy agent could open a reverse stream and never send a
	// header; bound the read so it cannot pin this goroutine indefinitely.
	st.SetReadDeadline(time.Now().Add(handshakeTimeout))
	h, err := readHeader(st)
	headerRead()
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	c.mu.Lock()
	to := c.rforward[h.Bind]
	c.mu.Unlock()
	if h.Kind != kindForwardR || to == "" {
		st.Close()
		c.dropAgent("opened a stream for no -R forward this client set up")
		return
	}
	d, err := net.DialTimeout("tcp", to, forwardDialTimeout)
	if err != nil {
		st.Close()
		return
	}
	pipe(st, d)
}

// Run executes a non-interactive command, streaming stdin to it (nil closes the
// command's stdin right away) and its merged stdout/stderr to stdout, and
// returns the exit code. Closing the Client while Run is in flight cancels it
// (the agent kills the process).
func (c *Client) Run(cmd []string, stdin io.Reader, stdout io.Writer) (int, error) {
	st, err := c.sess.Open()
	if err != nil {
		return -1, err
	}
	defer st.Close()
	if err := writeHeader(st, streamHeader{Kind: kindExec, Cmd: cmd}); err != nil {
		return -1, err
	}
	rep, err := readReply(st)
	if err != nil {
		return -1, err
	}
	if !rep.OK {
		return -1, fmt.Errorf("%s", CleanText(rep.Err))
	}
	exited := false
	defer func() {
		if !exited {
			// Leaving before the command ended: the agent kills it now, even
			// with input still queued for it, which closing the stream alone
			// would make it take first.
			c.control(st, frameEnd, nil)
		}
	}()
	fw := &frameWriter{w: st}
	if stdin == nil {
		// No input: send EOF now so a command that reads stdin does not wait
		// forever for data that will never come.
		if err := fw.write(frameEOF, nil); err != nil {
			return -1, err
		}
	} else {
		go func() {
			buf := make([]byte, ioBufSize)
			for {
				n, e := stdin.Read(buf)
				if n > 0 {
					fw.write(frameData, buf[:n])
				}
				if e != nil {
					fw.write(frameEOF, nil)
					return
				}
			}
		}()
	}
	for {
		typ, payload, err := readFrame(st)
		if err != nil {
			return -1, err
		}
		switch typ {
		case frameData:
			stdout.Write(payload)
		case frameExit:
			exited = true
			return decodeExit(payload), nil
		}
	}
}

// Exec runs a command with local stdin as its input; the remote stdout and
// stderr both arrive on local stdout.
func (c *Client) Exec(cmd []string) (int, error) { return c.Run(cmd, os.Stdin, os.Stdout) }

// ForwardLocal listens locally and tunnels each connection to dial (host:port)
// reached from the agent. It blocks until the listener fails or the connection
// to the agent closes, and returns why.
func (c *Client) ForwardLocal(listen, dial string) error {
	ln, err := ListenTCP(listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-c.sess.CloseChan()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if c.sess.IsClosed() {
				return errors.New("connection to the agent closed")
			}
			return err
		}
		go func(conn net.Conn) {
			st, err := c.sess.Open()
			if err != nil {
				conn.Close()
				return
			}
			if err := writeHeader(st, streamHeader{Kind: kindForward, Dial: dial}); err != nil {
				st.Close()
				conn.Close()
				return
			}
			rep, err := readReply(st)
			if err != nil || !rep.OK {
				st.Close()
				conn.Close()
				return
			}
			pipe(st, conn)
		}(conn)
	}
}

// ForwardRemote asks the agent to listen on bind (host:port) and tunnel each
// connection back to this client, which dials to (host:port) locally. It blocks
// while the forward is up and always returns a non-nil error saying why it
// ended.
func (c *Client) ForwardRemote(bind, to string) error {
	c.mu.Lock()
	c.rforward[bind] = to
	c.mu.Unlock()

	st, err := c.sess.Open()
	if err != nil {
		return err
	}
	if err := writeHeader(st, streamHeader{Kind: kindRPC, Op: rpcRemoteForward, Bind: bind}); err != nil {
		st.Close()
		return err
	}
	rep, err := readReply(st)
	if err != nil {
		st.Close()
		return err
	}
	if !rep.OK {
		st.Close()
		return fmt.Errorf("%s", CleanText(rep.Err))
	}
	io.Copy(io.Discard, st) // hold the listener open until the stream dies
	return errors.New("connection to the agent closed")
}

// ListSessions returns the names of live sessions on the agent.
func (c *Client) ListSessions() ([]string, error) {
	st, err := c.sess.Open()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := writeHeader(st, streamHeader{Kind: kindRPC, Op: rpcList}); err != nil {
		return nil, err
	}
	rep, err := readReply(st)
	if err != nil {
		return nil, err
	}
	if !rep.OK {
		return nil, fmt.Errorf("%s", CleanText(rep.Err))
	}
	return rep.Sessions, nil
}

// CopyTo uploads a local file to remotePath on the agent.
func (c *Client) CopyTo(localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	return c.WriteFile(remotePath, f, info.Size(), info.Mode(), nil)
}

// RealCheck vets the path the agent reports a file operation really reaches,
// with every symlink resolved, before any content moves. A reply that
// reports none gives the check "" to judge.
type RealCheck func(real string) error

// ReadCheck is RealCheck for a file the agent is about to send, which also
// sees the file's permission bits and whether every directory above it lets
// every user search it (see streamReply.DirsOpen).
type ReadCheck func(real string, perm os.FileMode, dirsOpen bool) error

// WriteFile uploads exactly size bytes from r to remotePath on the agent with
// mode's permission bits. The agent writes a temporary file beside the target
// and renames it into place, so a failed upload never truncates an existing
// file.
func (c *Client) WriteFile(remotePath string, r io.Reader, size int64, mode os.FileMode, check RealCheck) error {
	if size < 0 {
		return fmt.Errorf("negative size")
	}
	st, err := c.sess.Open()
	if err != nil {
		return err
	}
	defer st.Close()
	hdr := streamHeader{Kind: kindFile, Op: fileSend, Path: remotePath, Size: size, FileMode: uint32(mode.Perm()), Confirm: check != nil}
	if err := writeHeader(st, hdr); err != nil {
		return err
	}
	rep, err := readReply(st)
	if err != nil {
		return err
	}
	if !rep.OK {
		return fmt.Errorf("%s", CleanText(rep.Err))
	}
	if check != nil {
		if err := check(rep.Real); err != nil {
			return err // closing the stream makes the agent drop the upload
		}
		// An agent that sends Real honours Confirm and waits for this.
		if rep.Real != "" {
			if _, err := st.Write([]byte{1}); err != nil {
				return err
			}
		}
	}
	if _, err := io.CopyN(st, r, size); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(st, ack[:]); err != nil {
		return fmt.Errorf("upload not acknowledged: %w", err)
	}
	if ack[0] != 1 {
		return fmt.Errorf("agent failed to write %s", remotePath)
	}
	return nil
}

// openRecv opens a download stream for remotePath and returns it with the
// agent's reply, which carries the file's size and permission bits. With a
// check, the agent reads nothing of the file before check has passed the
// reply and the client has said go ahead. A file that reports size 0, as
// kernel files do, is read only then, and its real size comes in a second
// reply. A file over max bytes (none when max is negative) is refused as
// soon as its size is known. On error the stream is already closed.
func (c *Client) openRecv(remotePath string, check ReadCheck, max int64) (net.Conn, streamReply, error) {
	st, err := c.sess.Open()
	if err != nil {
		return nil, streamReply{}, err
	}
	fail := func(rep streamReply, err error) (net.Conn, streamReply, error) {
		st.Close()
		return nil, rep, err
	}
	if err := writeHeader(st, streamHeader{Kind: kindFile, Op: fileRecv, Path: remotePath, Confirm: check != nil}); err != nil {
		return fail(streamReply{}, err)
	}
	rep, err := readReply(st)
	if err != nil {
		return fail(streamReply{}, err)
	}
	if !rep.OK {
		return fail(rep, fmt.Errorf("%s", CleanText(rep.Err)))
	}
	sized := func() error {
		switch {
		case rep.Size < 0:
			return fmt.Errorf("agent reported a negative file size")
		case max >= 0 && rep.Size > max:
			return fmt.Errorf("%s is %d bytes, over the %d byte limit", remotePath, rep.Size, max)
		}
		return nil
	}
	if err := sized(); err != nil {
		return fail(rep, err)
	}
	if check != nil {
		if err := check(rep.Real, os.FileMode(rep.FileMode).Perm(), rep.DirsOpen); err != nil {
			return fail(rep, err)
		}
		if _, err := st.Write([]byte{1}); err != nil {
			return fail(rep, err)
		}
	}
	if rep.Size == 0 {
		read, err := readReply(st)
		if err != nil {
			return fail(rep, err)
		}
		if !read.OK {
			return fail(rep, fmt.Errorf("%s", CleanText(read.Err)))
		}
		rep.Size = read.Size
		if err := sized(); err != nil {
			return fail(rep, err)
		}
	}
	return st, rep, nil
}

// ReadTo streams remotePath into w and returns the file's size and its
// permission bits. It fails before the agent sends anything when the file
// is larger than max.
func (c *Client) ReadTo(remotePath string, w io.Writer, max int64, check ReadCheck) (int64, os.FileMode, error) {
	st, rep, err := c.openRecv(remotePath, check, max)
	if err != nil {
		return rep.Size, 0, err
	}
	defer st.Close()
	if n, err := io.CopyN(w, st, rep.Size); err != nil {
		return rep.Size, 0, fmt.Errorf("download incomplete (%d of %d bytes): %w", n, rep.Size, err)
	}
	return rep.Size, os.FileMode(rep.FileMode).Perm(), nil
}

// ReadFile reads up to max bytes of remotePath starting at offset, without
// touching the local disk, and returns them with the file's full size. The
// file protocol has no seek, so the skipped prefix is streamed and discarded;
// callers bound offset+max. The stream is closed early once enough is read.
func (c *Client) ReadFile(remotePath string, offset, max int64, check ReadCheck) ([]byte, int64, error) {
	if offset < 0 || max < 0 {
		return nil, 0, fmt.Errorf("negative offset or length")
	}
	st, rep, err := c.openRecv(remotePath, check, -1)
	if err != nil {
		return nil, 0, err
	}
	defer st.Close()
	if offset >= rep.Size {
		return nil, rep.Size, nil
	}
	if _, err := io.CopyN(io.Discard, st, offset); err != nil {
		return nil, rep.Size, fmt.Errorf("read %s: %w", remotePath, err)
	}
	want := min(max, rep.Size-offset)
	buf := make([]byte, want)
	if _, err := io.ReadFull(st, buf); err != nil {
		return nil, rep.Size, fmt.Errorf("read %s: %w", remotePath, err)
	}
	return buf, rep.Size, nil
}

// CopyFrom downloads remotePath from the agent to localPath.
func (c *Client) CopyFrom(remotePath, localPath string) error {
	st, rep, err := c.openRecv(remotePath, nil, -1)
	if err != nil {
		return err
	}
	defer st.Close()
	// Take only the permission bits the agent sent, never setuid/setgid/sticky:
	// a malicious or compromised agent must not get a client (especially one run
	// as root) to create a setuid file. OpenSSH's sftp client masks the same way.
	mode := os.FileMode(rep.FileMode).Perm()
	if mode == 0 {
		mode = 0o644
	}
	// Download to a new temp file beside the destination and rename it into
	// place on success, so an interrupted or short transfer never truncates
	// or replaces an existing destination. The destination's directory is
	// opened once and both happen in it (see uploadTarget, which uploads use
	// on the agent), so the file lands there however another local user
	// swaps a link or junction on the path meanwhile; the temp file is one of
	// its own, never one another user planted there or a link to one, and on
	// Windows it has the DACL the destination must keep.
	rawDir, base := splitUploadPath(localPath)
	if localPath == "" || os.IsPathSeparator(localPath[len(localPath)-1]) || base == "" || base == "." || base == ".." {
		return fmt.Errorf("%q is not a file path; name the file to write", localPath)
	}
	t, err := openUploadTarget(localPath, rawDir, base, mode)
	if err != nil {
		return err
	}
	defer t.close()
	n, cerr := io.CopyN(t.tmp, st, rep.Size)
	if cerr != nil || n != rep.Size {
		t.abort()
		if cerr != nil {
			return fmt.Errorf("download incomplete (%d of %d bytes): %w", n, rep.Size, cerr)
		}
		return fmt.Errorf("download truncated: got %d of %d bytes", n, rep.Size)
	}
	return t.finish()
}
