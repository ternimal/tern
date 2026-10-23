// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// guardHost runs g's guard on a GET whose Host is host.
func guardHost(g *Gateway, host string) string {
	r := httptest.NewRequest("GET", "/v1/sessions", nil)
	r.Host = host
	return g.guard(r)
}

// Every spelling of a loopback address that ListenTCP listens on loopback
// only for is loopback to the gateway too: its Host check stays on, so a
// DNS-rebinding page, whose requests name the attacker's host, is refused,
// it does not warn about plain HTTP off loopback, and it may run without a
// token, as on 127.0.0.1.
func TestGatewayLoopbackSpellingsKeepHostCheck(t *testing.T) {
	installLogger(slog.LevelInfo)
	logs := &syncBuffer{}
	logOut.set(logs)
	defer logOut.set(os.Stderr)
	for _, addr := range []string{"localhost:8080", "Localhost:8080", "LOCALHOST:8080", "localhost.:8080",
		"127.0.0.1:8080", "[::1]:8080", "[::1%lo]:8080", "[::ffff:127.0.0.1]:8080", "127.0.0.2:8080"} {
		g := &Gateway{Addr: addr, Token: restToken}
		if why := guardHost(g, "rebind.attacker.example:8080"); why == "" {
			t.Errorf("--api-addr %s: a request whose Host names another host passes the guard", addr)
		}
		for _, host := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "LocalHost:8080", "localhost.:8080"} {
			if why := guardHost(g, host); why != "" {
				t.Errorf("--api-addr %s: Host %s refused: %s", addr, host, why)
			}
		}
		before := strings.Count(logs.String(), "plain HTTP")
		if err := g.checkAuthPolicy(); err != nil {
			t.Fatal(err)
		}
		if strings.Count(logs.String(), "plain HTTP") != before {
			t.Errorf("--api-addr %s: warned of plain HTTP off loopback", addr)
		}
		if err := (&Gateway{Addr: addr}).checkAuthPolicy(); err != nil {
			t.Errorf("--api-addr %s with no token: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080"} {
		if (&Gateway{Addr: addr}).checkAuthPolicy() == nil {
			t.Errorf("--api-addr %s with no token was allowed", addr)
		}
	}
}

// A gateway told to listen on a host name that names loopback addresses
// only checks Host, and takes that very name in it, in any case and with or
// without the root's trailing dot: a client that dials the name sends it.
// Host is only ever compared, never looked up, so another name that would
// name loopback is refused.
func TestGatewayTakesItsOwnName(t *testing.T) {
	lookups := fakeHosts(t, map[string][]string{
		"loop.test":  {"::1", "127.0.0.1"},
		"loop.test.": {"::1", "127.0.0.1"},
		"other.test": {"127.0.0.1"},
	})
	for _, addr := range []string{"loop.test:8080", "loop.test.:8080"} {
		g := &Gateway{Addr: addr, Token: restToken}
		for host, ok := range map[string]bool{
			"loop.test:8080": true, "loop.test": true, "LOOP.Test:9": true, "127.0.0.1:8080": true,
			"loop.test.:8080": true, "LOOP.TEST.": true,
			"other.test:8080": false, "rebind.attacker.example:8080": false, "loop.test.evil.example": false,
			"[loop.test]:8080": false, "loop.test..:8080": false, ".": false, "": false,
		} {
			if why := guardHost(g, host); (why == "") != ok {
				t.Errorf("--api-addr %s: Host %s: %q, want ok=%v", addr, host, why, ok)
			}
		}
	}
	if n := lookups.Load(); n != 2 {
		t.Errorf("%d lookups, want one of each gateway's own name", n)
	}
}

// Trusted hosts given to a gateway off loopback are used there too: they
// turn its Host check on, so only they, loopback and the gateway's own
// address pass. With none, a gateway off loopback checks no Host, since it
// cannot know the names its clients use.
func TestGatewayTrustedHostsOffLoopback(t *testing.T) {
	open := &Gateway{Addr: "0.0.0.0:8080", Token: restToken}
	if why := guardHost(open, "anything.example"); why != "" {
		t.Errorf("a gateway off loopback with no trusted hosts checked Host: %s", why)
	}
	for _, addr := range []string{"0.0.0.0:8080", "192.0.2.1:8080"} {
		g := &Gateway{Addr: addr, Token: restToken, TrustedHosts: []string{"proxy.example"}}
		for host, ok := range map[string]bool{
			"proxy.example": true, "proxy.example:443": true, "localhost:8080": true, "127.0.0.1": true,
			"evil.example": false, "192.0.2.99:8080": false, "": false,
		} {
			if why := guardHost(g, host); (why == "") != ok {
				t.Errorf("%s: Host %q: %q, want ok=%v", addr, host, why, ok)
			}
		}
	}
	own := &Gateway{Addr: "192.0.2.1:8080", Token: restToken, TrustedHosts: []string{"proxy.example"}}
	if why := guardHost(own, "192.0.2.1:8080"); why != "" {
		t.Errorf("the gateway's own address was refused: %s", why)
	}
}

// Brackets in Host come off an IPv6 address only: "[name]" is no spelling
// of a name, so it matches no trusted host, and "[localhost]" is no
// loopback.
func TestHostBracketsOnlyAroundIPv6(t *testing.T) {
	g := &Gateway{Addr: "127.0.0.1:8080", TrustedHosts: []string{"tern.example.com", "[2001:db8::1]"}}
	for host, ok := range map[string]bool{
		"tern.example.com": true, "[tern.example.com]": false, "[tern.example.com]:80": false,
		"[2001:db8::1]": true, "[2001:db8::1]:8443": true, "2001:db8::1": true,
		"[localhost]": false, "[localhost]:8080": false, "[127.0.0.1]": false, "[::1]": true, "[::1]:8080": true,
	} {
		if why := guardHost(g, host); (why == "") != ok {
			t.Errorf("Host %q: %q, want ok=%v", host, why, ok)
		}
	}
}

// Run on a loopback name listens on both loopback addresses and serves a
// client that dials the name; a name for loopback and other addresses at
// once does not start.
func TestGatewayRunsOnLoopbackName(t *testing.T) {
	needIPv6Loopback(t)
	fakeHosts(t, map[string][]string{
		"loop.test":  {"::1", "127.0.0.1"},
		"mixed.test": {"127.0.0.1", "192.0.2.5"},
	})
	if err := (&Gateway{Addr: "mixed.test:0", Token: restToken, Dial: noDial}).Run(context.Background()); err == nil {
		t.Error("a gateway on a name for loopback and other addresses started")
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()
	g := &Gateway{Addr: "loop.test:" + port, Token: restToken, Dial: noDial}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	for _, host := range []string{"127.0.0.1", "::1"} {
		c := dialRetry(t, net.JoinHostPort(host, port))
		c.Close()
	}
	get := func(at, host string) int {
		req, _ := http.NewRequest("GET", "http://"+at+"/v1/healthz", nil)
		req.Host = host
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, at := range []string{net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port)} {
		if code := get(at, "loop.test:"+port); code != 200 {
			t.Errorf("%s with Host loop.test: %d", at, code)
		}
		if code := get(at, "rebind.attacker.example:"+port); code != 403 {
			t.Errorf("%s with the attacker's Host: %d", at, code)
		}
	}
}
