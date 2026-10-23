// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Tunables, gathered in one place so they are easy to find and adjust.
const (
	// transport / timeouts
	DialTimeout        = 15 * time.Second // TCP dial to an agent or relay
	forwardDialTimeout = 10 * time.Second
	resizePollInterval = 400 * time.Millisecond
	// ReconnectBackoffMax caps the retry backoff of the agent's relay re-dial
	// loop and of the client's auto-reconnect (1s, doubling up to this cap).
	ReconnectBackoffMax = 30 * time.Second
	shutdownGrace       = 5 * time.Second
	handshakeTimeout    = 15 * time.Second // deadline for the TLS handshake + auth exchange (and the relay hello)
	firstRecordTimeout  = 3 * time.Second  // deadline for a new connection's ClientHello (its first TLS records)
	acceptRetryMin      = 5 * time.Millisecond
	acceptRetryMax      = time.Second
	// Unauthenticated handshakes in flight on a listener per source (an IPv4
	// address or IPv6 /64) and per IPv6 /56 and /48 (the total is preAuthMax),
	// and the connections over a source's cap that may wait, for how long,
	// for one of its slots, per source and at most in all (the total is
	// preAuthWaitMax).
	maxPreAuthPerSource    = 64
	maxPreAuthPer56        = 2 * maxPreAuthPerSource
	maxPreAuthPer48        = 4 * maxPreAuthPerSource
	maxPreAuthWaiting      = 192
	maxPreAuthWaitingTotal = 1024
	preAuthWait            = 5 * time.Second
	// A connection that has sent nothing for silentGrace is closed first
	// when a full listener, a source past its cap, or a REST source past its
	// cap, needs room: a real client sends its first bytes as soon as it
	// connects.
	silentGrace = 20 * time.Millisecond
	// rtern's Catcher holds up to maxCatchHeld registered agents and checks for
	// shutdown this often while blocked in Accept.
	maxCatchHeld    = 4
	catchAcceptPoll = 250 * time.Millisecond
	// maxRelayToken is the longest relay token accepted; maxRelayID the
	// longest agent id.
	maxRelayToken = 1024
	maxRelayID    = 256
	// A relay (ternr) holds at most this many unpaired agent registrations,
	// and bridges, per party (an IPv4 address or IPv6 /48), and at most
	// maxRelayRegs and maxRelayPipes in all. A party at its cap gives up its
	// own oldest registration, or is refused a bridge; a full relay makes
	// room only from a party heavier than the newcomer's (partyTree.displace)
	// and refuses the newcomer otherwise.
	maxRelayRegsPerParty  = 256
	maxRelayPipesPerParty = 256
	// A relay asks an agent registration that waited relayRegIdle unpaired to
	// register again, which frees what a vanished agent held. An agent asked
	// sooner than relayRenewMin after registering waits that long first, so a
	// relay cannot make it register in a tight loop.
	relayRegIdle  = 10 * time.Minute
	relayRenewMin = time.Second
	// An agent in relay mode lets at most maxRelayPending paired connections
	// be in their unauthenticated handshake at once, each for at most
	// relayPairTimeout, and registers again only when one is free.
	maxRelayPending  = 64
	relayPairTimeout = 10 * time.Second
	// maxInboundHeaders caps the streams an agent opened to a client whose
	// header the client is still reading.
	maxInboundHeaders = 64
	// a shell connection that lived this long counts as stable: after it drops
	// the client redials at once instead of backing off
	stableConnection = 10 * time.Second
	// a client dial that finds no agent registered is retried this many times,
	// waiting 100ms, then doubling (1.5s in total), to ride out re-registration
	relayNoAgentRetries  = 4
	relayNoAgentRetryMin = 100 * time.Millisecond

	// REST gateway request limits. A request's header must arrive within
	// apiReadHeaderTimeout of a new connection, or of the first bytes of a
	// later request on a kept-alive one.
	apiReadHeaderTimeout = 5 * time.Second
	apiIdleTimeout       = 120 * time.Second
	apiMaxRequestBody    = 16 << 20 // cap on a single REST request body (incl. stdin)
	apiMaxCmd            = 60 << 10 // cap on a command's JSON, which must fit in a stream header

	// buffers
	ringMax       = 256 * 1024 // recent PTY output kept per session for replay/resume
	attachChanBuf = 1024       // queued output chunks per attached client
	pumpBufSize   = 32 * 1024  // PTY read buffer
	ioBufSize     = 4096       // generic stdin/stream copy buffer

	// REST job limits
	jobMaxOutput      = 8 << 20          // cap on buffered output per REST command (run + jobs)
	maxRetainedJobs   = 256              // finished jobs kept before the oldest are evicted
	maxRunningJobs    = 128              // concurrent running async jobs per gateway (DoS cap)
	defaultRunTimeout = 30 * time.Second // POST /v1/run timeout when none is configured/requested

	// resource caps
	maxSessions      = 256    // concurrent live shell sessions per agent (DoS cap)
	maxRunTimeoutSec = 86_400 // cap on a REST /v1/run "timeout" field (seconds), avoids Duration overflow
)

// maxRelayRegs and maxRelayPipes cap the registrations and bridges a relay
// holds in all.
var maxRelayRegs, maxRelayPipes = relayCaps(fdLimit())

// relayCaps sizes a relay's caps on registrations and bridges for a file
// descriptor limit: an eighth of it, and a sixteenth for bridges, which hold
// two each, but at most 1024 of each.
func relayCaps(limit uint64) (regs, pipes int) {
	return fdShare(limit, 8, 16, 1024), fdShare(limit, 16, 16, 1024)
}

// installLogger makes a text slog logger at level the process default. The
// standard log package keeps writing plain lines to stderr (slog.SetDefault
// would otherwise route it through the handler at INFO), so the commands' own
// messages and fatal errors read as "ternd: ..." rather than as INFO records.
func installLogger(level slog.Level) {
	slog.SetDefault(slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: level})))
	log.SetOutput(logOut)
}

// logOut is where all logging goes: stderr, switched to a CR-LF translating
// writer while an interactive shell has the terminal in raw mode, where a bare
// "\n" would not return the cursor to column 0.
var logOut = &switchWriter{w: os.Stderr}

type switchWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *switchWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *switchWriter) set(w io.Writer) {
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()
}

type crlfWriter struct{ w io.Writer }

func (c crlfWriter) Write(p []byte) (int, error) {
	if _, err := c.w.Write(bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// rawModeLogs switches log output to CR-LF line ends and returns the function
// that switches it back.
func rawModeLogs() func() {
	logOut.set(crlfWriter{os.Stderr})
	return func() { logOut.set(os.Stderr) }
}

// AcceptRetryDelay returns how long to pause after a failed Accept, given the
// previous pause (0 after a success): 5ms, doubling up to 1s as net/http does,
// so a persistent error such as running out of file descriptors cannot spin.
func AcceptRetryDelay(prev time.Duration) time.Duration {
	if prev == 0 {
		return acceptRetryMin
	}
	return min(prev*2, acceptRetryMax)
}

// SetupLogging installs a text slog logger as the process default. Level is
// Info unless the TERN_LOG environment variable is "debug".
func SetupLogging() {
	level := slog.LevelInfo
	if os.Getenv("TERN_LOG") == "debug" {
		level = slog.LevelDebug
	}
	installLogger(level)
}

// SetVerbose switches the default logger to debug level (what --verbose / -v
// does), equivalent to TERN_LOG=debug. Call it after flag parsing.
func SetVerbose(on bool) {
	if on {
		installLogger(slog.LevelDebug)
	}
}
