// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// healthzWith is a GET /v1/healthz whose header holds lines lines, the Host
// line and, with auth, the token's among them.
func healthzWith(lines int, auth bool) string {
	var b strings.Builder
	b.WriteString("GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n")
	lines--
	if auth {
		b.WriteString("Authorization: Bearer " + restToken + "\r\n")
		lines--
	}
	for i := range lines {
		fmt.Fprintf(&b, "X%03d: a\r\n", i)
	}
	return b.String() + "\r\n"
}

// readStatus reads the next answer on a connection and returns its status,
// and whether it closes the connection.
func readStatus(t *testing.T, conn net.Conn, br *bufio.Reader) (int, bool) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Close
}

// Every request on a kept-alive connection is held to apiMaxHeaderLines
// header lines, as the first is: past them a later request is refused, with
// the token or without, before it is admitted or served. Its header, which
// only a connection whose first request carried the token gets to send, is
// parsed first, so what that costs is bounded by the byte limit: past it,
// net/http refuses the header as it arrives.
func TestRESTHeaderLinesCappedOnEveryRequest(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: noDial})
	for _, c := range []struct {
		lines int
		auth  bool
		want  int
	}{
		{apiMaxHeaderLines, true, 200}, {apiMaxHeaderLines + 1, true, 431},
		{apiMaxHeaderLines, false, 200}, {apiMaxHeaderLines + 1, false, 431},
	} {
		conn := dialRetry(t, addr)
		br := bufio.NewReader(conn)
		io.WriteString(conn, healthzWith(2, true))
		if code, closes := readStatus(t, conn, br); code != 200 || closes {
			t.Fatalf("the first request: %d, closes %v", code, closes)
		}
		// Sent once the first was answered, so net/http reads it through
		// the connection rather than from what it read ahead.
		io.WriteString(conn, healthzWith(c.lines, c.auth))
		if code, _ := readStatus(t, conn, br); code != c.want {
			t.Errorf("a second request of %d header lines, token %v: %d, want %d", c.lines, c.auth, code, c.want)
		}
		conn.Close()
	}

	// A header that never ends is refused once it passes the byte limit,
	// which on a kept-alive connection also lets in the 4 KiB net/http reads
	// ahead before it starts counting.
	conn := dialRetry(t, addr)
	defer conn.Close()
	br := bufio.NewReader(conn)
	io.WriteString(conn, healthzWith(2, true))
	readStatus(t, conn, br)
	head := healthzWith((apiMaxHeaderBytes+2*4096)/len("X000: a\r\n")+64, true)
	io.WriteString(conn, strings.TrimSuffix(head, "\r\n"))
	start := time.Now()
	if code, _ := readStatus(t, conn, br); code != 431 || time.Since(start) > 2*time.Second {
		t.Errorf("a header never ended, past the byte limit: %d after %s", code, time.Since(start).Round(time.Millisecond))
	}
}

// A request that net/http read ahead, while it served the one before it on
// the connection, as it does for a pipelining client, is held to the limit
// by what net/http parsed of it, before it is served, with the token or
// without.
func TestRESTPipelinedRequestHeaderLinesCapped(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: noDial})
	for _, c := range []struct {
		lines int
		auth  bool
		want  int
	}{{apiMaxHeaderLines, true, 200}, {100, true, 431}, {apiMaxHeaderLines, false, 200}, {100, false, 431}} {
		conn := dialRetry(t, addr)
		br := bufio.NewReader(conn)
		io.WriteString(conn, healthzWith(2, true)+healthzWith(c.lines, c.auth))
		if code, _ := readStatus(t, conn, br); code != 200 {
			t.Fatalf("the first request: %d", code)
		}
		if code, _ := readStatus(t, conn, br); code != c.want {
			t.Errorf("a pipelined request of %d header lines, token %v: %d, want %d", c.lines, c.auth, code, c.want)
		}
		conn.Close()
	}
}

// A pipelined request whose header net/http read ahead, while it served the
// one before, up to just before its blank line, is not cut short when that
// line arrives with a body of many lines: those are no header's lines.
func TestRESTPipelinedBodyLinesAreNoHeaderLines(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: func(string) (*Client, error) {
		return nil, errors.New("no agent here")
	}})
	body := `{"cmd":["true"],` + strings.Repeat(" \n", 100) + `"stdin":"x"}`
	head := "POST /v1/run HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + restToken +
		"\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	conn := dialRetry(t, addr)
	defer conn.Close()
	br := bufio.NewReader(conn)
	io.WriteString(conn, healthzWith(2, true)+head)
	if code, _ := readStatus(t, conn, br); code != 200 {
		t.Fatalf("the first request: %d", code)
	}
	io.WriteString(conn, "\r\n"+body)
	// The whole body parses; the agent it then asks for is not there.
	if code, _ := readStatus(t, conn, br); code != 502 {
		t.Errorf("a pipelined POST /v1/run with a body of 100 lines: %d, want 502", code)
	}
}

// Connections that carried the token count toward a cap of their own, so one
// token holder cannot take every file descriptor: past it a new one's request
// is refused, though it carries the token, never one already admitted closed
// to make room, and a connection that closes gives its place back, once.
func TestRESTAdmittedConnectionsCapped(t *testing.T) {
	l := &connCap{perSource: 100, total: 100, admittedMax: 2, grace: time.Hour}
	a, b, c := l.admit(from("192.0.2.1:1")), l.admit(from("192.0.2.1:2")), l.admit(from("192.0.2.1:3"))
	if !a.admitted() || !b.admitted() {
		t.Fatal("a connection within the cap was refused")
	}
	if c.admitted() || l.open() != 1 {
		t.Fatalf("past the cap: admitted %v, %d not admitted, want refused and still in the books", !c.booked, l.open())
	}
	if !a.admitted() {
		t.Error("an admitted connection was refused its next request")
	}
	a.Close()
	a.Close()
	if !c.admitted() || l.admit(from("192.0.2.1:4")).admitted() {
		t.Error("a closed admitted connection did not give its place back once")
	}

	addr := runGateway(t, &Gateway{Token: restToken, admittedCap: 2, Dial: noDial})
	var held []net.Conn
	var readers []*bufio.Reader
	for range 2 {
		conn := dialRetry(t, addr)
		br := bufio.NewReader(conn)
		io.WriteString(conn, healthzWith(2, true))
		if code, closes := readStatus(t, conn, br); code != 200 || closes {
			t.Fatalf("a connection within the cap: %d, closes %v", code, closes)
		}
		held = append(held, conn)
		readers = append(readers, br)
	}
	extra := dialRetry(t, addr)
	defer extra.Close()
	io.WriteString(extra, healthzWith(2, true))
	if code, closes := readStatus(t, extra, bufio.NewReader(extra)); code != 503 || !closes {
		t.Errorf("a connection past the cap: %d, closes %v, want 503 and closed", code, closes)
	}
	for i, conn := range held {
		io.WriteString(conn, healthzWith(2, true))
		if code, _ := readStatus(t, conn, readers[i]); code != 200 {
			t.Errorf("admitted connection %d lost its place: %d", i, code)
		}
	}
	held[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn := dialRetry(t, addr)
		io.WriteString(conn, healthzWith(2, true))
		code, _ := readStatus(t, conn, bufio.NewReader(conn))
		conn.Close()
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a connection after an admitted one closed: %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	held[1].Close()
}

// sayingConn is a connection from addr whose peer has sent said.
type sayingConn struct {
	*addrConn
	said *strings.Reader
}

func (c sayingConn) Read(p []byte) (int, error) { return c.said.Read(p) }

func saying(addr, said string) sayingConn {
	return sayingConn{from(addr), strings.NewReader(said)}
}

// Only a whole request line ends a connection's silence: one that sent no
// more than a byte goes first when room is needed, as one that sent nothing
// does, so a flood cannot spare its connections by sending a byte on each.
func TestRESTConnectionCapHearsWholeRequestLines(t *testing.T) {
	l := &connCap{perSource: 2, total: 100, grace: time.Nanosecond, clock: steppingClock()}
	buf := make([]byte, 64)
	client := saying("192.0.2.1:1", "GET /v1/healthz HTTP/1.1\r\n")
	l.admit(client).Read(buf)
	flood := saying("192.0.2.1:2", "G")
	l.admit(flood).Read(buf)
	l.admit(from("192.0.2.1:3")) // over the source's cap
	if !flood.closed.Load() || client.closed.Load() {
		t.Errorf("room made by closing the one that sent a byte %v, the one that sent a request line %v",
			flood.closed.Load(), client.closed.Load())
	}
}
