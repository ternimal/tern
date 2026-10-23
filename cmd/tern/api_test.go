// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tern "github.com/ternimal/tern/internal/tern"
)

// --api-agent pins each relay agent id to a fingerprint of its own, next to
// the connection's agent, and refuses what would not mean one pin per id.
func TestAPIAgentPins(t *testing.T) {
	fp1, fp2 := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	relay := &target{mode: "relay", id: "box1", fp: fp1}
	pins, err := apiAgentPins(relay, []string{"box2=" + strings.ToUpper(fp2[:2]) + ":" + fp2[2:], "box1=" + fp1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 || pins["box1"] != fp1 || pins["box2"] != fp2 {
		t.Fatalf("pins = %v", pins)
	}
	if pins, err := apiAgentPins(relay, nil); err != nil || len(pins) != 1 || pins["box1"] != fp1 {
		t.Fatalf("with no --api-agent: %v %v", pins, err)
	}
	for _, c := range []struct {
		name  string
		t     *target
		specs []string
	}{
		{"no fingerprint", relay, []string{"box2"}},
		{"empty fingerprint", relay, []string{"box2="}},
		{"short fingerprint", relay, []string{"box2=" + fp2[:62]}},
		{"not hex", relay, []string{"box2=" + strings.Repeat("zz", 32)}},
		{"no id", relay, []string{"=" + fp2}},
		{"id too long", relay, []string{strings.Repeat("b", 257) + "=" + fp2}},
		{"the connection's agent, another fingerprint", relay, []string{"box1=" + fp2}},
		{"one id, two fingerprints", relay, []string{"box2=" + fp2, "box2=" + fp1}},
		{"direct gateway", &target{mode: "direct", fp: fp1}, []string{"box2=" + fp2}},
		{"no fingerprint pinning", &target{mode: "relay", id: "box1", insecure: true}, []string{"box2=" + fp2}},
		{"no TLS", &target{mode: "relay", id: "box1", skipEnc: true}, []string{"box2=" + fp2}},
	} {
		if _, err := apiAgentPins(c.t, c.specs); err == nil {
			t.Errorf("%s: %q accepted", c.name, c.specs)
		}
	}
}

// A gateway reaching agents through a relay pins every agent id to that
// agent's own fingerprint, so agents keep their own keys, and an id it has
// no fingerprint for is refused, even when the agent registered under it
// presents a pinned agent's certificate (a copied key).
func TestAPIGatewayPinsEachAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	relayCert, err := tern.LoadOrCreateCert(filepath.Join(dir, "relay"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := ln.Addr().String()
	ln.Close()
	const relayToken, agentToken = "relay-token-0123456789", "agent-token-0123456789"
	go tern.RunRelay(ctx, relayAddr, filepath.Join(dir, "relay"), relayToken)
	relayFP := tern.CertFingerprint(relayCert)

	certs := map[string]string{"box1": "box1", "box2": "box2", "box3": "box1"} // box3 holds box1's key
	fps := map[string]string{}
	for id, certName := range certs {
		cert, err := tern.LoadOrCreateCert(filepath.Join(dir, certName))
		if err != nil {
			t.Fatal(err)
		}
		fps[id] = tern.CertFingerprint(cert)
		agent := tern.NewAgent(tern.ServerTLSConfig(cert), &tern.AuthConfig{Token: agentToken}, "/bin/sh", time.Minute, "")
		go func() {
			for ctx.Err() == nil {
				tr, err := tern.RelayDialAgent(ctx, relayAddr, relayFP, relayToken, id, false)
				if err != nil {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				go agent.Serve(tr, "relay:"+id)
			}
		}()
	}

	tg := &target{mode: "relay", relay: relayAddr, relayFP: relayFP, relayToken: relayToken, id: "box1", fp: fps["box1"], token: agentToken}
	ids, dial, err := tg.apiAgents([]string{"box2=" + fps["box2"]})
	if err != nil {
		t.Fatal(err)
	}
	g := &tern.Gateway{Token: "api-token-0123456789", AgentIDs: ids, Dial: dial}
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()
	for _, c := range []struct {
		id   string
		want int
	}{{"", 200}, {"box1", 200}, {"box2", 200}, {"box3", 400}} {
		var code int
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			req, _ := http.NewRequest("GET", srv.URL+"/v1/sessions?id="+c.id, nil)
			req.Header.Set("Authorization", "Bearer api-token-0123456789")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			// 502 until the agent has registered with the relay.
			if code = resp.StatusCode; code != 502 || time.Now().After(deadline) {
				break
			}
		}
		if code != c.want {
			t.Errorf("sessions on agent %q: %d, want %d", c.id, code, c.want)
		}
	}
	if _, err := dial("box3"); err == nil || !strings.Contains(err.Error(), "no pinned fingerprint") {
		t.Errorf("dialing an id with no pin: %v", err)
	}
}
