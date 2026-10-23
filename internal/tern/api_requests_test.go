// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A request refused for its token gets its connection closed, so a peer
// without the token cannot hold one open by sending a long body slowly.
func TestRESTRefusedClosesConnection(t *testing.T) {
	g := &Gateway{Token: "secret", Dial: func(string) (*Client, error) { t.Fatal("dialed"); return nil, nil }}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /v1/run HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"+
		"Authorization: Bearer wrong\r\nContent-Length: 1000000\r\n\r\n{")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 || !resp.Close {
		t.Fatalf("status %d, close %v", resp.StatusCode, resp.Close)
	}
	io.Copy(io.Discard, resp.Body)
	if _, err := c.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("the connection stayed open: %v", err)
	}
}

func TestRESTRequestChecks(t *testing.T) {
	a, fp := newTestAgent(t)
	g := &Gateway{Token: "secret", Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "checks")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	status := func(path, auth, body string) int {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	long, _ := json.Marshal([]string{"echo", strings.Repeat("x", apiMaxCmd)})
	for _, c := range []struct {
		path, auth, body string
		want             int
	}{
		{"/v1/run", "Bearer secret", `{"cmd":["true"]}`, 200},
		{"/v1/run", "bearer secret", `{"cmd":["true"]}`, 200}, // the scheme ignores case
		{"/v1/run", "secret", `{"cmd":["true"]}`, 401},        // a bare token is not a scheme
		{"/v1/run", "Bearer secret", `{"cmd":` + string(long) + `}`, 400},
		{"/v1/jobs", "Bearer secret", `{"cmd":` + string(long) + `}`, 400},
		{"/v1/run", "Bearer secret", `{"cmd":["true"],"id":"box2"}`, 400}, // no relay to pick box2
		{"/v1/exec", "Bearer secret", `{"cmd":["true"],"id":"box2"}`, 400},
	} {
		if got := status(c.path, c.auth, c.body); got != c.want {
			t.Errorf("%s with %q, body %.40q: %d, want %d", c.path, c.auth, c.body, got, c.want)
		}
	}
	// Job ids say nothing about how many came before, or about a restart.
	resp := post(t, srv.URL+"/v1/jobs", "secret", `{"cmd":["true"]}`)
	var created map[string]string
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if id := created["job"]; len(id) != 17 || id == "j1" {
		t.Errorf("job id %q", id)
	}
	if !hostIsLoopback("[::1]") || !hostIsLoopback("[::1]:8080") || hostIsLoopback("[2001:db8::1]") {
		t.Error("hostIsLoopback with brackets")
	}
}

// Through a relay, the gateway reaches only the agent ids it has a fingerprint
// for; it refuses any other id rather than dial it under another agent's pin.
func TestRESTAgentIDs(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	g := &Gateway{Token: "secret", AgentIDs: []string{"box1", "box2"}, Dial: func(id string) (*Client, error) {
		mu.Lock()
		dialed = append(dialed, id)
		mu.Unlock()
		return nil, errors.New("no agent in this test")
	}}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/v1/run", `{"cmd":["true"]}`, 502}, // the connection's own agent: dialed (and no agent answers)
		{"/v1/run", `{"cmd":["true"],"id":"box2"}`, 502},
		{"/v1/exec", `{"cmd":["true"],"id":"box3"}`, 400}, // no fingerprint for box3
		{"/v1/jobs", `{"cmd":["true"],"id":"box3"}`, 400},
		{"/v1/run", `{"cmd":["true"],"id":"BOX2"}`, 400}, // ids are exact
	} {
		resp := post(t, srv.URL+c.path, "secret", c.body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: %d, want %d", c.path, c.body, resp.StatusCode, c.want)
		}
	}
	for id, want := range map[string]int{"box1": 502, "box3": 400} {
		resp := get(t, srv.URL+"/v1/sessions?id="+id, "secret")
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("sessions on %s: %d, want %d", id, resp.StatusCode, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(dialed, ",") != ",box2,box1" {
		t.Errorf("dialed %q", dialed)
	}
}

// A character split between two writes of a command's output reaches the
// client whole.
func TestRESTStreamKeepsCharacters(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &streamWriter{enc: json.NewEncoder(rec)}
	e := []byte("é") // two bytes
	sw.Write([]byte{'a', e[0]})
	sw.Write([]byte{e[1], 'b'})
	var got strings.Builder
	dec := json.NewDecoder(rec.Body)
	for {
		var m map[string]string
		if dec.Decode(&m) != nil {
			break
		}
		got.WriteString(m["stdout"])
	}
	if got.String() != "aéb" {
		t.Errorf("streamed %q", got.String())
	}
}
