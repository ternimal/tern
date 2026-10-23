// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newGuardServer serves a tokenless loopback gateway, so the tests exercise
// g.guard without the bearer check getting in the way first.
func newGuardServer(t *testing.T) *httptest.Server {
	t.Helper()
	a, fp := newTestAgent(t)
	g := &Gateway{Addr: "127.0.0.1:8080", RunTimeout: 5 * time.Second, Dial: func(string) (*Client, error) {
		sconn, cconn := loopbackPair(t)
		go a.Serve(sconn, "guard")
		return Dial(cconn, PinnedTLSConfig(fp), "", testToken)
	}}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, ctype, origin, host, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestGatewayBlocksBrowserCSRF: the exec gateway must reject the requests a web
// page can make to it, so a visited site cannot run commands on the agent.
func TestGatewayBlocksBrowserCSRF(t *testing.T) {
	srv := newGuardServer(t)
	run := `{"cmd":["echo","hi"]}`

	// A cross-site fetch carries an Origin header (even a no-cors POST): reject.
	if code := do(t, srv, "POST", "/v1/run", "text/plain;charset=UTF-8", "https://evil.example", "", run); code != 403 {
		t.Errorf("cross-origin text/plain POST = %d, want 403", code)
	}
	// Even without Origin, a simple-request Content-Type is not application/json.
	if code := do(t, srv, "POST", "/v1/run", "text/plain;charset=UTF-8", "", "", run); code != 403 {
		t.Errorf("text/plain POST = %d, want 403", code)
	}
	// A DNS-rebinding page reaches a loopback gateway with a non-loopback Host.
	if code := do(t, srv, "POST", "/v1/run", "application/json", "", "attacker.example", run); code != 403 {
		t.Errorf("non-loopback Host = %d, want 403", code)
	}
	// A GET is readable too: the Host guard must cover it (rebinding read access).
	if code := do(t, srv, "GET", "/v1/sessions", "", "", "attacker.example", ""); code != 403 {
		t.Errorf("non-loopback Host GET = %d, want 403", code)
	}
	// The legitimate local caller (no Origin, JSON, loopback Host) still works.
	if code := do(t, srv, "POST", "/v1/run", "application/json", "", "", run); code != 200 {
		t.Errorf("same-origin JSON POST = %d, want 200", code)
	}
	// healthz needs no token, but a page must not learn that a gateway is
	// there, while a plain liveness check (curl) still gets its answer.
	if code := do(t, srv, "GET", "/v1/healthz", "", "", "attacker.example", ""); code != 403 {
		t.Errorf("healthz with a non-loopback Host = %d, want 403", code)
	}
	if code := do(t, srv, "GET", "/v1/healthz", "", "https://evil.example", "", ""); code != 403 {
		t.Errorf("cross-origin healthz = %d, want 403", code)
	}
	if code := do(t, srv, "GET", "/v1/healthz", "", "", "", ""); code != 200 {
		t.Errorf("healthz = %d, want 200", code)
	}
}
