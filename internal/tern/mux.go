// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

// Protocol vocabulary shared by client and agent, so the wire strings live in
// one place instead of being retyped at every call site.
const (
	kindShell    = "shell"     // interactive PTY session (new/attach/share)
	kindExec     = "exec"      // non-interactive command
	kindForward  = "forward"   // -L: agent dials and bridges
	kindForwardR = "forward-r" // -R: agent-initiated back to the client
	kindFile     = "file"      // file copy
	kindRPC      = "rpc"       // list sessions / set up -R listener
	kindControl  = "control"   // control requests for the connection's shell and exec streams

	rpcList          = "list"
	rpcRemoteForward = "remote-forward"

	fileSend = "send" // client -> agent
	fileRecv = "recv" // agent -> client

	modeNew    = "new"
	modeAttach = "attach"
	modeAuto   = "auto"
)

// After the inner TLS handshake and auth, both ends run a yamux session over
// the connection. Each logical channel is a yamux stream that opens with a
// JSON header; channels that need confirmation get a JSON reply.
//
// kinds:
//   shell     interactive PTY session (attach/new/share). Framed both ways:
//             client->agent data; agent->client data (scrollback replay,
//             then live output) and an exit frame when the shell exits (none
//             for a client the agent drops for falling behind). The reply's
//             offset places the replay in the session's whole output, so a
//             client that reconnects can skip what it already has. Resize,
//             and end from a writer to close the session, go on the control
//             stream.
//   exec      non-interactive command. Framed: client->agent data/eof;
//             agent->client data/exit. A client that leaves before the exit
//             frame sends end on the control stream, and the agent kills the
//             command: the end of the stream itself reaches the agent only
//             after the input sent before it, which a command that reads
//             none never takes.
//   control   control requests for the connection's shell and exec streams,
//             on a stream of their own, opened once per connection, so a
//             request never waits behind input the agent cannot take yet.
//             Framed client->agent: each frame's payload starts with the
//             target stream's id. Requests for streams that are gone are
//             dropped.
//   forward   -L: agent dials Dial and bridges raw bytes.
//   forward-r -R: agent-initiated; client dials its local target and bridges.
//   file      copy a file to/from the agent. The reply names where the file
//             really is (Real); with Confirm, the client's go-ahead byte
//             follows before any content moves either way. An upload ends
//             with the agent's ack byte. A download's content follows the
//             reply, or, for a file that reports size 0, a second reply
//             with the size the agent read.
//   rpc       one JSON request/reply (list sessions; set up an -R listener,
//             whose stream then stays open for the listener's lifetime).

type streamHeader struct {
	Kind     string   `json:"k"`
	Session  string   `json:"s,omitempty"`
	Mode     string   `json:"m,omitempty"`   // auto | new | attach
	Write    bool     `json:"w,omitempty"`   // client wants to type
	Force    bool     `json:"fw,omitempty"`  // co-drive: write even if a writer is already attached
	Attach   string   `json:"aid,omitempty"` // per-process client id: a reconnect replaces that client's stale attachment
	Cols     int      `json:"c,omitempty"`
	Rows     int      `json:"r,omitempty"`
	Cmd      []string `json:"cmd,omitempty"`
	Dial     string   `json:"d,omitempty"`
	Bind     string   `json:"b,omitempty"`
	Op       string   `json:"op,omitempty"`
	Path     string   `json:"p,omitempty"`
	FileMode uint32   `json:"fm,omitempty"`
	Size     int64    `json:"sz,omitempty"`
	// Confirm asks, on a file upload or download, that the agent wait after
	// its reply for one byte from the client, 1 to go ahead, before it takes
	// any content or reads any of the file, so a client that checks the
	// reply's Real path can still refuse, and a refused download reads
	// nothing. On an upload the client sends that byte only when the reply
	// carries Real.
	Confirm bool `json:"cf,omitempty"`
}

type streamReply struct {
	OK       bool   `json:"ok"`
	Err      string `json:"err,omitempty"`
	Session  string `json:"s,omitempty"`
	Shared   bool   `json:"sh,omitempty"`
	ReadOnly bool   `json:"ro,omitempty"`
	// Size is, on a file download, the file's size. A file that reports
	// size 0, as kernel files such as /proc/cpuinfo do, may still have
	// content: the agent reads it only after this reply, and after the
	// go-ahead when one was asked for (see Confirm), and a second reply,
	// carrying Size or Err alone, gives what it read.
	Size     int64    `json:"sz,omitempty"`
	FileMode uint32   `json:"fm,omitempty"`
	Sessions []string `json:"ls,omitempty"`
	// Offset is, on a shell stream, the position in the session's whole
	// output of the first byte the stream sends. A reply without it leaves
	// the client's offset unknown (-1).
	Offset *int64 `json:"off,omitempty"`
	// Real is, on a file stream, the path with every symlink resolved, so a
	// client enforcing path rules can check where a link really leads.
	Real string `json:"real,omitempty"`
	// DirsOpen is, on a file download, whether every directory above Real
	// lets every user search it (its others-execute bit is set), so that a
	// client can tell, with the file's own others-read bit, whether every
	// user may read the file. A Windows agent, whose files are not judged by
	// mode bits, always sets it.
	DirsOpen bool `json:"dirs,omitempty"`
}

func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	return c
}

func muxServer(conn net.Conn) (*yamux.Session, error) { return yamux.Server(conn, muxConfig()) }
func muxClient(conn net.Conn) (*yamux.Session, error) { return yamux.Client(conn, muxConfig()) }

func writeHeader(w io.Writer, h streamHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return writeBlob(w, b)
}

func readHeader(r io.Reader) (streamHeader, error) {
	b, err := readBlob(r, 65535)
	if err != nil {
		return streamHeader{}, err
	}
	var h streamHeader
	return h, json.Unmarshal(b, &h)
}

func writeReply(w io.Writer, rep streamReply) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	return writeBlob(w, b)
}

func readReply(r io.Reader) (streamReply, error) {
	b, err := readBlob(r, 65535)
	if err != nil {
		return streamReply{}, err
	}
	var rep streamReply
	return rep, json.Unmarshal(b, &rep)
}

// exit code helpers for frameExit (exec and shell streams)
func encodeExit(code int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(int32(code)))
	return b
}

func decodeExit(b []byte) int {
	if len(b) != 4 {
		return -1
	}
	return int(int32(binary.BigEndian.Uint32(b)))
}

// pipe copies a<->b until either side ends, then closes both.
func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}
