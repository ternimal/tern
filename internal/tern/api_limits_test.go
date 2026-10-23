// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const restToken = "rest-token-0123456789"

// runGateway serves g with Run, so with the server settings and connection
// caps it has in production, on a free loopback port, and returns the address.
func runGateway(t *testing.T, g *Gateway) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.Addr = ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	dialRetry(t, g.Addr).Close()
	return g.Addr
}

// noDial is the Dial of a gateway that must not reach an agent in the test.
func noDial(string) (*Client, error) {
	return nil, errors.New("dialed for a request the gateway should not admit")
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A request the gateway does not admit cannot hold its connection open: not
// by leaving a small or chunked body unsent after a 401 or 403, nor on
// healthz, which needs no token, or on a route that does not exist, where
// net/http would otherwise wait for the body to keep the connection.
func TestRESTUnadmittedRequestsLetGo(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: noDial})
	const ctJSON = "Content-Type: application/json\r\n"
	var wg sync.WaitGroup
	for _, c := range []struct {
		name string
		want int
		head string
	}{
		{"wrong token, small body", 401, "POST /v1/run HTTP/1.1\r\nHost: 127.0.0.1\r\n" + ctJSON + "Authorization: Bearer wrong\r\nContent-Length: 1000\r\n\r\n{"},
		{"no token, chunked body", 401, "POST /v1/exec HTTP/1.1\r\nHost: 127.0.0.1\r\n" + ctJSON + "Transfer-Encoding: chunked\r\n\r\n1\r\n{\r\n"},
		{"Origin", 403, "POST /v1/jobs HTTP/1.1\r\nHost: 127.0.0.1\r\n" + ctJSON + "Origin: http://evil.example\r\nContent-Length: 1000\r\n\r\n{"},
		{"text/plain", 403, "POST /v1/run HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\n\r\n{"},
		{"healthz, rebinding Host", 403, "GET /v1/healthz HTTP/1.1\r\nHost: rebind.example\r\nContent-Length: 1000\r\n\r\nx"},
		{"healthz", 200, "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1000\r\n\r\nx"},
		{"no such route", 404, "POST /v1/nothing HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1000\r\n\r\nx"},
		{"wrong method", 405, "PUT /v1/run HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1000\r\n\r\nx"},
	} {
		wg.Go(func() {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			io.WriteString(conn, c.head)
			start := time.Now()
			conn.SetReadDeadline(start.Add(5 * time.Second))
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Errorf("%s: no answer: %v", c.name, err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != c.want {
				t.Errorf("%s: status %d, want %d", c.name, resp.StatusCode, c.want)
			}
			if _, err := br.ReadByte(); isTimeout(err) {
				t.Errorf("%s: answered %d, then the connection was still open after %s", c.name, resp.StatusCode, time.Since(start).Round(time.Second))
			}
		})
	}
	wg.Wait()
}

// A peer without the token cannot make the gateway keep much of what it
// sends: the header it may send is small, and its connection, with the
// request parsed from it, is let go.
func TestRESTUnadmittedRequestsDoNotPinMemory(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: noDial})
	// Header lines up to net/http's default limit of 1 MiB, short ones, which
	// cost the most once parsed.
	var hdr strings.Builder
	for i := 0; hdr.Len() < 1<<20-2048; i++ {
		fmt.Fprintf(&hdr, "X%06d:a\r\n", i)
	}
	head := "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1000\r\n" + hdr.String() + "\r\nx"
	live := func() int64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	base := live()
	const conns = 8
	for range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		go func() {
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(c, head)
		}()
	}
	time.Sleep(3 * time.Second)
	if per := (live() - base) / conns; per > 1<<20 {
		t.Errorf("each connection without the token holds %d KiB of gateway memory", per>>10)
	}
}

// A request whose header is past apiMaxHeaderBytes is refused.
func TestRESTHeaderSizeCapped(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: noDial})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: "+strings.Repeat("a", 2*apiMaxHeaderBytes)+"\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a %d KiB header got status %d", 2*apiMaxHeaderBytes>>10, resp.StatusCode)
	}
}

// An admitted request is not held to the deadline a request without the token
// gets: its body may arrive slowly, and a command may stream for as long as
// it runs.
func TestRESTAdmittedRequestsTakeTheirTime(t *testing.T) {
	a, fp := newTestAgent(t)
	g := &Gateway{Token: restToken, preAuth: 300 * time.Millisecond, Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	addr := runGateway(t, g)

	resp := post(t, "http://"+addr+"/v1/exec", restToken, `{"cmd":["sh","-c","echo BEFORE; sleep 1; echo AFTER"]}`)
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !strings.Contains(string(b), "BEFORE") || !strings.Contains(string(b), "AFTER") || !strings.Contains(string(b), `{"exit":0}`) {
		t.Fatalf("a command streaming past the deadline was cut off: %v\n%s", err, b)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := `{"cmd":["cat"],"stdin":"SLOW-STDIN"}`
	fmt.Fprintf(c, "POST /v1/run HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n%s", restToken, len(body), body[:10])
	time.Sleep(time.Second)
	io.WriteString(c, body[10:])
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err = http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("a body sent slowly was not read: %v", err)
	}
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	if resp.StatusCode != 200 || m["output"] != "SLOW-STDIN" {
		t.Fatalf("a body sent slowly: status %d, %v", resp.StatusCode, m)
	}
}

// The gateway holds at most perSource connections not yet admitted from one
// source, an IPv4 address or IPv6 /64, and total in all. A newcomer is never
// refused: over its source's cap the source's oldest connection makes room,
// and on a full listener the oldest of the source holding the most within
// the address block holding the most, so a few sources cannot lock everyone
// else out. A closed connection gives its place back, once.
func TestRESTConnectionCap(t *testing.T) {
	admit := func(l *connCap, addr string) (*cappedConn, *addrConn) {
		c := from(addr)
		return l.admit(c), c
	}
	l := &connCap{perSource: 2, total: 100, grace: time.Hour}
	_, first := admit(l, "192.0.2.1:1")
	admit(l, "192.0.2.1:2")
	if _, c := admit(l, "192.0.2.1:3"); c.closed.Load() || !first.closed.Load() {
		t.Error("one IPv4 address is not held to its cap by giving up its oldest connection")
	}
	_, first6 := admit(l, "[2001:db8::1]:1")
	admit(l, "[2001:db8::2]:1")
	if _, c := admit(l, "[2001:db8::3]:1"); c.closed.Load() || !first6.closed.Load() {
		t.Error("one IPv6 /64 is not held to its cap by giving up its oldest connection")
	}
	_, other := admit(l, "192.0.2.2:1")
	_, other6 := admit(l, "[2001:db8:0:1::1]:1")
	if l.open() != 6 || other.closed.Load() || other6.closed.Load() {
		t.Errorf("open %d, want 6; another IPv4 source or IPv6 /64 lost a connection", l.open())
	}

	// A full listener: the flooding party (one /48, many /64s) gives way to
	// a newcomer, oldest first, and the newcomer's own place is kept.
	l = &connCap{perSource: 2, total: 6, grace: time.Hour}
	victim, _ := admit(l, "192.0.2.9:1")
	var flood []*addrConn
	for i := range 5 {
		_, c := admit(l, fmt.Sprintf("[2001:db8:0:%x::1]:1", i))
		flood = append(flood, c)
	}
	if _, user := admit(l, "192.0.2.10:1"); user.closed.Load() {
		t.Fatal("a newcomer to a full listener was closed")
	}
	if !flood[0].closed.Load() || flood[1].closed.Load() {
		t.Error("making room did not close the oldest connection of the party holding the most")
	}
	if !victim.booked || l.open() != 6 {
		t.Errorf("open %d, the lone first connection is out of the books: %v", l.open(), !victim.booked)
	}
	victim.Close()
	victim.Close() // giving a place back twice frees it once
	if l.open() != 5 {
		t.Errorf("open %d after one connection closed twice, want 5", l.open())
	}

	// Over a real listener, a connection past its source's cap is taken,
	// and the oldest of the source's closed for it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capped := &connCap{Listener: ln, perSource: 2, total: 8, grace: time.Hour}
	defer capped.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := capped.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	served := func() net.Conn {
		select {
		case c := <-accepted:
			t.Cleanup(func() { c.Close() })
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("a connection under the cap was not accepted")
			return nil
		}
	}
	oldest := dial()
	served()
	dial()
	served()
	dial()
	served()
	oldest.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := oldest.Read(make([]byte, 1)); isTimeout(err) {
		t.Fatal("the oldest connection of a source past its cap was kept open")
	}
}

// A connection that brought an admitted request leaves the books: it counts
// toward no cap, and nothing closes it to make room.
func TestRESTConnectionCapSparesAdmitted(t *testing.T) {
	l := &connCap{perSource: 2, total: 3, grace: time.Hour}
	admit := func(addr string) (*cappedConn, *addrConn) {
		c := from(addr)
		return l.admit(c), c
	}
	in, inRaw := admit("192.0.2.1:1")
	in.admitted()
	_, b := admit("192.0.2.1:2")
	admit("192.0.2.1:3")
	if n := l.open(); n != 2 || b.closed.Load() {
		t.Fatalf("open %d, want 2: the admitted connection still counts toward its source's cap", n)
	}
	admit("192.0.2.1:4") // over the source's cap
	admit("198.51.100.1:1")
	admit("203.0.113.1:1") // a full listener
	if !b.closed.Load() || inRaw.closed.Load() {
		t.Errorf("the oldest connection not admitted closed %v, the admitted one closed %v", b.closed.Load(), inRaw.closed.Load())
	}
	if n := l.open(); n != 3 {
		t.Errorf("open %d, want 3", n)
	}
}

// A connection that has sent nothing for the grace goes first when room is
// needed; one that has sent nothing for less is no likelier to go than any
// other, so a client the moment before its request is read loses nothing.
func TestRESTConnectionCapClosesLongSilentFirst(t *testing.T) {
	for _, c := range []struct {
		grace time.Duration
		want  int // which of the source's three goes for a newcomer: 0, the oldest, has spoken
	}{{time.Nanosecond, 1}, {time.Hour, 0}} {
		l := &connCap{perSource: 3, total: 100, grace: c.grace, clock: steppingClock()}
		var raw []*addrConn
		for i := range 3 {
			conn := from(fmt.Sprintf("192.0.2.1:%d", 1+i))
			cc := l.admit(conn)
			if i == 0 {
				l.spoke(cc)
			}
			raw = append(raw, conn)
		}
		l.admit(from("192.0.2.1:9")) // over the source's cap
		for i, conn := range raw {
			if conn.closed.Load() != (i == c.want) {
				t.Errorf("grace %s: connection %d closed %v", c.grace, i, conn.closed.Load())
			}
		}
		// On a full listener the oldest silent one goes when past the grace,
		// else the oldest of the block holding the most, which has spoken.
		l = &connCap{perSource: 100, total: 3, grace: c.grace, clock: steppingClock()}
		spokeRaw, quietRaw := from("192.0.2.1:1"), from("192.0.2.2:1")
		l.spoke(l.admit(spokeRaw))
		l.admit(quietRaw)
		l.admit(from("[2001:db8::1]:1"))
		l.admit(from("[2001:db8::2]:1"))
		long := c.grace == time.Nanosecond
		if quietRaw.closed.Load() != long || spokeRaw.closed.Load() == long {
			t.Errorf("grace %s: on a full listener the silent one closed %v, the one that spoke %v",
				c.grace, quietRaw.closed.Load(), spokeRaw.closed.Load())
		}
	}
}

// /v1/run and /v1/exec share maxRunningCommands slots; past them a request is
// refused with 429 instead of holding another agent connection.
func TestRESTCommandsCapped(t *testing.T) {
	var dialing atomic.Int32
	unblock := make(chan struct{})
	g := &Gateway{Token: restToken, Dial: func(string) (*Client, error) {
		dialing.Add(1)
		<-unblock
		return nil, errors.New("no agent in this test")
	}}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	send := func(client *http.Client, path string) (int, error) {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(`{"cmd":["true"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+restToken)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	var wg sync.WaitGroup
	for i := range maxRunningCommands {
		path := "/v1/run"
		if i%2 == 1 {
			path = "/v1/exec"
		}
		wg.Go(func() {
			if code, err := send(http.DefaultClient, path); err != nil || code != 502 {
				t.Errorf("%s within the cap: %d %v", path, code, err)
			}
		})
	}
	for deadline := time.Now().Add(10 * time.Second); dialing.Load() < maxRunningCommands; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			close(unblock)
			t.Fatalf("only %d of %d commands reached the agent", dialing.Load(), maxRunningCommands)
		}
	}
	impatient := &http.Client{Timeout: 5 * time.Second} // past the cap, the answer comes at once
	for _, path := range []string{"/v1/run", "/v1/exec"} {
		if code, err := send(impatient, path); err != nil || code != 429 {
			t.Errorf("%s past the cap: %d %v, want 429", path, code, err)
		}
	}
	close(unblock)
	wg.Wait()
	if code, err := send(http.DefaultClient, "/v1/run"); err != nil || code != 502 {
		t.Errorf("a command once the others ended: %d %v, want it to reach the agent", code, err)
	}
}

// A finished job can be read for a while and is then forgotten, so its output
// does not stay in memory for good; a running job is never forgotten.
func TestRESTFinishedJobsExpire(t *testing.T) {
	a, fp := newTestAgent(t)
	g := &Gateway{Token: restToken, keep: 200 * time.Millisecond, Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	resp := post(t, srv.URL+"/v1/jobs", restToken, `{"cmd":["sh","-c","sleep 1"]}`)
	var created map[string]string
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	status := func() (int, string) {
		r := get(t, srv.URL+"/v1/jobs/"+created["job"], restToken)
		defer r.Body.Close()
		var st map[string]any
		json.NewDecoder(r.Body).Decode(&st)
		s, _ := st["status"].(string)
		return r.StatusCode, s
	}
	time.Sleep(600 * time.Millisecond) // longer than the job is kept once finished
	if code, st := status(); code != 200 || st != "running" {
		t.Fatalf("a running job: %d %q", code, st)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if code, _ := status(); code == 404 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a finished job was never forgotten")
		}
	}
}

// A job lets go of its stdin once the command has been sent it, though the
// command runs on.
func TestRESTJobDropsSentStdin(t *testing.T) {
	a, fp := newTestAgent(t)
	g := &Gateway{Token: restToken, Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	live := func() int64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	const jobs, size = 2, 6 << 20
	body := `{"cmd":["sh","-c","cat >/dev/null; echo READ; sleep 30"],"stdin":"` + strings.Repeat("x", size) + `"}`
	base := live()
	var ids []string
	for range jobs {
		resp := post(t, srv.URL+"/v1/jobs", restToken, body)
		var created map[string]string
		json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()
		ids = append(ids, created["job"])
	}
	defer func() {
		for _, id := range ids {
			req, _ := http.NewRequest("DELETE", srv.URL+"/v1/jobs/"+id, nil)
			req.Header.Set("Authorization", "Bearer "+restToken)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}()
	for _, id := range ids {
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			r := get(t, srv.URL+"/v1/jobs/"+id+"/output", restToken)
			var out map[string]any
			json.NewDecoder(r.Body).Decode(&out)
			r.Body.Close()
			if data, _ := out["data"].(string); strings.Contains(data, "READ") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("job %s never read its stdin", id)
			}
		}
	}
	if held := live() - base; held > size {
		t.Errorf("%d running jobs that have been sent their %d MiB of stdin still hold %d MiB", jobs, size>>20, held>>20)
	}
	runtime.KeepAlive(body) // in base, so it must not be freed before the second count
}

// agentDial is a gateway Dial that reaches a real agent in the test.
func agentDial(t *testing.T) func(string) (*Client, error) {
	a, fp := newTestAgent(t)
	return func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "rest")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}
}

// dialFrom connects to addr from the loopback address src.
func dialFrom(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// dialsOK reports whether something accepts a connection at addr.
func dialsOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// startExec starts a command on the gateway at addr that streams for a few
// seconds and returns the rest of its stream once it is under way.
func startExec(t *testing.T, addr string) (rest func() string) {
	t.Helper()
	resp := post(t, "http://"+addr+"/v1/exec", restToken, `{"cmd":["sh","-c","echo START; sleep 3; echo END"]}`)
	t.Cleanup(func() { resp.Body.Close() })
	br := bufio.NewReader(resp.Body)
	if l, err := br.ReadString('\n'); err != nil || !strings.Contains(l, "START") {
		t.Fatalf("the command did not start: %q %v", l, err)
	}
	return func() string {
		b, _ := io.ReadAll(br)
		return string(b)
	}
}

// A peer without the token that holds its source's whole cap of connections
// that send nothing, as any local user can on the default loopback bind,
// does not lock a client with the token out of the same source: its
// newcomer takes the place of one of the silent ones.
func TestRESTSourceFloodLeavesTokenHoldersIn(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: agentDial(t)})
	for range apiMaxConnsPerSource {
		dialFrom(t, "127.0.0.1", addr)
	}
	time.Sleep(300 * time.Millisecond) // let the gateway take them all
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/run", strings.NewReader(`{"cmd":["echo","TOKEN-HOLDER-IN"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+restToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("a client with the token was turned away by %d silent connections from its source: %v", apiMaxConnsPerSource, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "TOKEN-HOLDER-IN") {
		t.Fatalf("a run with the token: %d %s", resp.StatusCode, b)
	}
}

// Every loopback address is one source to the gateway, IPv4 or IPv6, mapped
// or not: a loopback gateway listens on both, and a local peer must not
// double its share, or spread over 127.0.0.0/8, by using several.
func TestRESTLoopbackIsOneSource(t *testing.T) {
	for _, a := range []string{"127.0.0.1:1", "127.9.8.7:1", "[::1]:1", "[::ffff:127.0.0.1]:1"} {
		if got := connPath(testAddr(a)); !slices.Equal(got, []string{"loopback"}) {
			t.Errorf("%s: %q, want one loopback source", a, got)
		}
	}
	if got := connPath(testAddr("192.0.2.1:1")); !slices.Equal(got, addrPath(testAddr("192.0.2.1:1"))) {
		t.Errorf("another address: %q", got)
	}
	l := &connCap{perSource: 2, total: 100, grace: time.Hour}
	first := from("127.0.0.1:1")
	l.admit(first)
	l.admit(from("[::1]:1"))
	l.admit(from("127.0.0.2:1"))
	if !first.closed.Load() || l.open() != 2 {
		t.Errorf("loopback over its cap by using both families and another address: open %d, the oldest closed %v", l.open(), first.closed.Load())
	}
}

// A connection carrying an admitted command is never closed to make room
// for connections without the token, though they come from its own source,
// loopback, by either family and from many addresses, and have sent part of
// a request each. The agent would kill the command with it.
func TestRESTFloodSparesAdmittedCommands(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: agentDial(t)})
	rest := startExec(t, addr)
	type dialing struct{ src, to string }
	srcs := []dialing{{"127.0.0.1", addr}}
	_, port, _ := net.SplitHostPort(addr)
	if v6 := net.JoinHostPort("::1", port); dialsOK(v6) { // the gateway holds both loopbacks
		srcs = append(srcs, dialing{"::1", v6})
	}
	if runtime.GOOS == "linux" { // all of 127.0.0.0/8 is local there
		srcs = append(srcs, dialing{"127.1.0.1", addr}, dialing{"127.2.0.1", addr})
	}
	for _, s := range srcs {
		for range apiMaxConnsPerSource + 8 {
			// Part of a request, never its end; the gateway reads each
			// before the next comes.
			c := dialFrom(t, s.src, s.to)
			io.WriteString(c, "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n")
			time.Sleep(200 * time.Microsecond)
		}
	}
	if got := rest(); !strings.Contains(got, "END") || !strings.Contains(got, `{"exit":0}`) {
		t.Fatalf("an admitted command was cut off by connections without the token: it got only %q", got)
	}
}

// A request in asterisk form, "OPTIONS *", is held to the deadline of a
// request the gateway does not admit, like any other: net/http would answer
// it itself, with no deadline, and a peer without the token could keep the
// connection by never sending the body it announced.
func TestRESTOptionsStarIsBounded(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, preAuth: time.Second, Dial: noDial})
	var wg sync.WaitGroup
	for name, head := range map[string]string{
		"no body":             "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
		"a body never sent":   "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4096\r\n\r\n",
		"a chunk, then quiet": "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n",
	} {
		wg.Go(func() {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			io.WriteString(conn, head)
			start := time.Now()
			conn.SetReadDeadline(start.Add(6 * time.Second))
			if _, err := io.ReadAll(conn); isTimeout(err) {
				t.Errorf("%s: the connection was still open after %s", name, time.Since(start).Round(time.Second))
			}
		})
	}
	wg.Wait()
}

// The first request on a connection may carry apiMaxHeaderLines header lines
// and no more; past them it is refused as soon as they arrive. Each line a
// peer without the token sends costs a few hundred bytes once parsed, and
// net/http sets no limit on them: without this cap a header of short lines up
// to the byte limit would hold some 290 KiB a connection.
func TestRESTHeaderLinesCapped(t *testing.T) {
	addr := runGateway(t, &Gateway{Token: restToken, Dial: noDial})
	head := func(lines int) string {
		var b strings.Builder
		b.WriteString("GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n")
		for i := range lines - 1 {
			fmt.Fprintf(&b, "X%03d:a\r\n", i)
		}
		return b.String()
	}
	for _, c := range []struct {
		lines int
		want  int
	}{{apiMaxHeaderLines, 200}, {apiMaxHeaderLines + 1, 400}} {
		conn := dialRetry(t, addr)
		io.WriteString(conn, head(c.lines)+"\r\n")
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		conn.Close()
		if err != nil || resp.StatusCode != c.want {
			t.Errorf("%d header lines: %v %v, want status %d", c.lines, resp, err, c.want)
		}
	}

	// What a connection that sends a header of short lines, as many as are
	// allowed or as fit in the byte limit, and never its end, makes the
	// gateway hold.
	live := func() int64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	for _, lines := range []int{apiMaxHeaderLines, (apiMaxHeaderBytes+4096)/len("X0000:a\r\n") - 64} {
		base := live()
		const conns = 100
		var held []net.Conn
		for range conns {
			c := dialRetry(t, addr)
			held = append(held, c)
			io.WriteString(c, head(lines))
		}
		time.Sleep(time.Second)
		per := (live() - base) / conns
		t.Logf("%d connections sending %d header lines each: %d KiB of heap each", conns, lines, per>>10)
		if per > 32<<10 {
			t.Errorf("a connection without the token sending %d short header lines costs %d KiB of heap", lines, per>>10)
		}
		for _, c := range held {
			c.Close()
		}
	}
}

// The lines of a request header are counted however its bytes arrive, up to
// the blank line that ends it and no further, with CRLF or bare LF endings;
// of a header past the limit, only the bytes before the line break that
// ends the line past it are passed on.
func TestHeaderLinesCount(t *testing.T) {
	for _, c := range []struct {
		head      string
		lines     int
		ends      bool
		overLimit bool // past a limit of 2 lines
	}{
		{"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody\r\nmore\r\nlines\r\n", 2, true, false},
		{"GET / HTTP/1.1\nHost: x\n\nbody\n", 2, true, false},
		{"\r\nGET / HTTP/1.1\r\n\r\n", 1, true, false},
		{"GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\n\r\n", 3, true, true},
		{"GET / HTTP/1.1\r\nHost: x", 1, false, false},
	} {
		for _, chunk := range []int{1, 2, 3, 7, len(c.head)} {
			var h headerLines
			passed, within := 0, true
			for i := 0; i < len(c.head) && within && !h.end; i += chunk {
				part := c.head[i:min(i+chunk, len(c.head))]
				n := h.scan([]byte(part), 2)
				passed += n
				within = n == len(part)
			}
			if within == c.overLimit || !c.overLimit && (h.n != c.lines || h.end != c.ends) {
				t.Errorf("%q in chunks of %d: %d lines, ended %v, within the limit %v", c.head, chunk, h.n, h.end, within)
			}
			if !within && (strings.Count(c.head[:passed], "\n") != 2 || c.head[passed] != '\n') {
				t.Errorf("%q in chunks of %d: passed on %q", c.head, chunk, c.head[:passed])
			}
		}
	}
}

// silentAgentClient is a Client whose agent takes every stream and never
// answers on it.
func silentAgentClient(t *testing.T) *Client {
	sconn, cconn := loopbackPair(t)
	srv, err := muxServer(sconn)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, st)
		}
	}()
	sess, err := muxClient(cconn)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{conn: cconn, sess: sess, rforward: map[string]string{}}
}

// GET /v1/sessions lets go of an agent that never answers, once its client
// leaves and, at the latest, after its wait, rather than keep the request and
// the agent connection for good.
func TestRESTSessionsLetsGoOfSilentAgent(t *testing.T) {
	var running atomic.Int32
	var mu sync.Mutex
	var agents []*Client
	g := &Gateway{Token: restToken, sessions: 2 * time.Second, Dial: func(string) (*Client, error) {
		cl := silentAgentClient(t)
		mu.Lock()
		agents = append(agents, cl)
		mu.Unlock()
		return cl, nil
	}}
	h := g.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		running.Add(1)
		defer running.Add(-1)
		h.ServeHTTP(w, r)
	}))
	defer srv.Close() // which waits for every handler: let go of the agents first
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, cl := range agents {
			cl.Close()
		}
	}()
	ask := func(timeout time.Duration) (int, error) {
		client := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
		req, _ := http.NewRequest("GET", srv.URL+"/v1/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+restToken)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	ask(300 * time.Millisecond) // a client that leaves
	for deadline := time.Now().Add(time.Second); running.Load() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the request still held a silent agent after its client left")
		}
	}
	if code, err := ask(10 * time.Second); err != nil || code != 502 {
		t.Fatalf("a patient client: %d %v, want 502 once the wait ran out", code, err)
	}
}

// syncBuffer is a bytes.Buffer safe to write from the goroutines that log.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A gateway with a token warns when it listens off loopback, where its plain
// HTTP carries the token and the commands' input and output in cleartext.
func TestGatewayWarnsPlainHTTPOffLoopback(t *testing.T) {
	installLogger(slog.LevelInfo)
	logs := &syncBuffer{}
	logOut.set(logs)
	defer logOut.set(os.Stderr)
	for _, c := range []struct {
		addr string
		warn bool
	}{
		{"0.0.0.0:8080", true},
		{"192.0.2.1:8080", true},
		{"127.0.0.1:8080", false},
		{"[::1]:8080", false},
		{"localhost:8080", false},
	} {
		before := strings.Count(logs.String(), "plain HTTP")
		if err := (&Gateway{Addr: c.addr, Token: restToken}).checkAuthPolicy(); err != nil {
			t.Fatal(err)
		}
		if warned := strings.Count(logs.String(), "plain HTTP") > before; warned != c.warn {
			t.Errorf("listening on %s: warned %v, want %v", c.addr, warned, c.warn)
		}
	}
}
