// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

package tern

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Limits on what a peer can make the REST gateway hold: a peer without the
// token, through its connections, and a client with it, through its commands.
const (
	// A request the gateway does not admit has apiPreAuthTimeout to arrive and
	// be answered; once it is answered, what is left of its body is read for
	// apiDrainTimeout at most.
	apiPreAuthTimeout = 10 * time.Second
	apiDrainTimeout   = time.Second
	// A request's line and header may take apiMaxHeaderBytes (net/http allows
	// 4 KiB more), and at most apiMaxHeaderLines header lines, which bounds
	// what parsing them costs to hold: net/http sets no limit on lines, and
	// each costs a few hundred bytes parsed.
	apiMaxHeaderBytes = 8 << 10
	apiMaxHeaderLines = 64
	// Connections not yet admitted held open per source (an IPv4 address or
	// IPv6 /64); the total is apiMaxConns. Admitted ones count toward a cap
	// of their own, apiMaxConns too.
	apiMaxConnsPerSource = 128
	maxRunningCommands   = 64               // concurrent /v1/run and /v1/exec requests, each holding an agent connection
	apiSessionsTimeout   = 30 * time.Second // a GET /v1/sessions waits this long for the agent at most
	jobKeep              = time.Hour        // how long a finished job stays readable
)

// apiMaxConns caps the connections not yet admitted the gateway holds, and,
// apart, the admitted ones.
var apiMaxConns = apiConnCap(fdLimit())

// apiConnCap sizes apiMaxConns for a file descriptor limit: a quarter of it,
// at most 1024.
func apiConnCap(limit uint64) int { return fdShare(limit, 4, 16, 1024) }

// apiConnKey is the request context key under which the gateway finds the
// connection a request came on.
type apiConnKey struct{}

// Gateway is a REST front end that runs commands on an agent, reaching it
// either directly or through a relay (whatever Dial builds). It supports
// long-running commands three ways:
//
//	POST /v1/run    runs with a timeout and returns one JSON result (simple)
//	POST /v1/exec   streams merged stdout+stderr as NDJSON until the command exits
//	POST /v1/jobs   starts the command and returns a job id immediately;
//	GET  /v1/jobs/{id}                 -> status + exit
//	GET  /v1/jobs/{id}/output?offset=N -> incremental output
//	DELETE /v1/jobs/{id}               -> cancel (agent kills the process)
//
//	GET  /v1/sessions  -> live shell sessions on the agent
//	GET  /v1/healthz    -> liveness (no token; guard still applies)
//
// Dial(id) opens a Client to the target; id may name another agent on the
// relay (one of AgentIDs), so one gateway can reach several agents.
type Gateway struct {
	Addr  string
	Token string                           // bearer token; "" disables auth, which Run allows only on a loopback Addr (or any Addr when Insecure)
	Dial  func(id string) (*Client, error) // id "" = default target

	// Insecure lets Run start a tokenless gateway on a NON-loopback address,
	// turning it into an unauthenticated remote command-exec endpoint reachable
	// from the network. It backs the --api-insecure-no-token flag and must never
	// be used in production; it has no effect when Token is set.
	Insecure bool

	RunTimeout time.Duration // default timeout for POST /v1/run (0 => 30s)
	MaxTimeout time.Duration // hard cap a request may ask for (0 => no cap)

	// AgentIDs are the agent ids a request may name, when the gateway reaches
	// agents through a relay. Dial passes the id on and pins each one to that
	// agent's own certificate fingerprint. Any other id is refused rather than
	// reached under another agent's pin, and a gateway that reaches one agent
	// directly (no AgentIDs) refuses every id rather than ignore it and run the
	// command on its one agent.
	AgentIDs []string

	// TrustedHosts are the host names a request's Host may name in addition
	// to loopback, for running behind a reverse proxy that preserves Host. A
	// name matches with any port or none; an entry with a port (host:port,
	// [v6]:port) matches that port only. Compared case-insensitively. Given
	// to a gateway off loopback, they turn guard's Host check on there too.
	TrustedHosts []string

	// Waits and caps that tests shorten; zero means the default.
	preAuth     time.Duration // apiPreAuthTimeout
	keep        time.Duration // jobKeep
	sessions    time.Duration // apiSessionsTimeout
	admittedCap int           // apiMaxConns

	bindOnce sync.Once
	bind     *bindAddrs // where the gateway listens, see listening
	bindErr  error

	mu       sync.Mutex
	jobs     map[string]*job
	running  int // async jobs currently executing (capped at maxRunningJobs)
	commands int // /v1/run and /v1/exec requests running (capped at maxRunningCommands)
}

type job struct {
	id      string
	cmd     []string
	client  *Client
	started time.Time
	expire  *time.Timer // forgets the job once it has been finished for jobKeep; guarded by Gateway.mu

	mu        sync.Mutex
	buf       []byte
	trunc     bool
	done      bool
	cancelled bool // DELETE stopped it; its stream ending is no error
	exit      int
	err       string
}

// appendCapped appends p to buf, keeping the total length at or below max, and
// reports whether any bytes were dropped.
func appendCapped(buf, p []byte, max int) ([]byte, bool) {
	room := max - len(buf)
	if room <= 0 {
		return buf, len(p) > 0
	}
	if len(p) > room {
		return append(buf, p[:room]...), true
	}
	return append(buf, p...), false
}

// Write appends captured output, capped at jobMaxOutput to bound memory.
func (j *job) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var dropped bool
	if j.buf, dropped = appendCapped(j.buf, p, jobMaxOutput); dropped {
		j.trunc = true
	}
	return len(p), nil
}

func (j *job) finish(code int, err error) {
	j.mu.Lock()
	j.done = true
	j.exit = code
	if err != nil && !j.cancelled {
		j.err = err.Error()
	}
	j.mu.Unlock()
}

// checkAuthPolicy enforces the rules for a tokenless gateway and logs the
// matching warning. A gateway with no bearer token is an unauthenticated
// remote-exec endpoint, allowed only on loopback (a deliberate local
// convenience) or when the operator opted in with --api-insecure (Insecure);
// otherwise it is refused. A gateway with a token is warned about only off
// loopback, where its plain HTTP carries the token across the network.
func (g *Gateway) checkAuthPolicy() error {
	if g.Token != "" {
		if !g.onLoopback() {
			slog.Warn("REST gateway serves plain HTTP on a non-loopback address; the bearer token and every command's input and output cross the network in cleartext, so reach it through a TLS reverse proxy or a tunnel", "addr", g.Addr)
		}
		return nil
	}
	switch {
	case g.onLoopback():
		slog.Warn("REST gateway has no token; any local process that can reach it can run commands", "addr", g.Addr)
	case g.Insecure:
		slog.Warn("INSECURE: REST gateway has NO token on a non-loopback address; this is an UNAUTHENTICATED remote command-exec endpoint reachable from the network", "addr", g.Addr)
	default:
		return fmt.Errorf("refusing to start the REST gateway on non-loopback %q without --api-token: that is an unauthenticated remote-exec endpoint. Set --api-token, bind 127.0.0.1, or pass --api-insecure-no-token to override", g.Addr)
	}
	return nil
}

// Run starts the HTTP server and blocks until ctx is cancelled (it then waits
// up to shutdownGrace for in-flight requests to finish) or the listener fails.
func (g *Gateway) Run(ctx context.Context) error {
	b, err := g.listening()
	if err != nil {
		return err
	}
	if err := g.checkAuthPolicy(); err != nil {
		return err
	}
	// ReadHeaderTimeout bounds slow-loris header attacks, MaxHeaderBytes (and
	// connCap, the lines of a connection's first request) the header a peer
	// can make the gateway parse and hold, and IdleTimeout reaps idle
	// keep-alives. Read/Write timeouts are intentionally unset so the
	// streaming /v1/exec and the blocking /v1/run (up to its timeout) are not
	// cut off mid-request; Handler bounds the requests it does not admit
	// instead, and the header lines of every request. Every request reaches
	// Handler, an "OPTIONS *" too, which net/http would otherwise answer
	// itself, with no deadline. ConnContext lets Handler find the connection
	// a request came on, which leaves connCap's books once a request on it is
	// admitted.
	srv := &http.Server{
		Handler:                      g.Handler(),
		ReadHeaderTimeout:            apiReadHeaderTimeout,
		IdleTimeout:                  apiIdleTimeout,
		MaxHeaderBytes:               apiMaxHeaderBytes,
		DisableGeneralOptionsHandler: true,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, apiConnKey{}, c)
		},
	}
	ln, err := b.listen()
	if err != nil {
		return err
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	slog.Info("REST gateway listening", "addr", g.Addr)
	capped := &connCap{Listener: ln, perSource: apiMaxConnsPerSource, total: apiMaxConns, admittedMax: cmp.Or(g.admittedCap, apiMaxConns)}
	if err := srv.Serve(capped); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained // Serve returns as soon as Shutdown starts; wait for it
	return nil
}

// Handler builds the HTTP routes (exposed so it can be served or tested).
// Serving it directly skips Run's refusal to run without a token on a
// non-loopback address, and Run's limits on connections and headers.
func (g *Gateway) Handler() http.Handler {
	if g.jobs == nil {
		g.jobs = make(map[string]*job)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		// No token is needed here, but the checks against web pages still
		// apply: a DNS-rebinding page must not learn that a gateway is there.
		if why := g.guard(r); why != "" {
			refuse(w, 403, why)
			return
		}
		respondJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/run", g.auth(g.handleRun))
	mux.HandleFunc("POST /v1/exec", g.auth(g.handleExec))
	mux.HandleFunc("POST /v1/jobs", g.auth(g.handleJobCreate))
	mux.HandleFunc("GET /v1/jobs/{id}", g.auth(g.handleJobStatus))
	mux.HandleFunc("GET /v1/jobs/{id}/output", g.auth(g.handleJobOutput))
	mux.HandleFunc("DELETE /v1/jobs/{id}", g.auth(g.handleJobDelete))
	mux.HandleFunc("GET /v1/sessions", g.auth(g.handleSessions))
	return g.bounded(mux)
}

// bounded serves a request the gateway does not admit (no token, or one that
// guard refuses), on any route, healthz and unknown ones included, under a
// deadline. After a handler returns, net/http reads up to 256 KiB of the body
// it left unread, to reuse the connection or, when the answer closes it,
// before closing; with no deadline a peer without the token could hold the
// connection, and the request it parsed, by sending that body a byte at a
// time, or by not reading the answer. An admitted request gets no deadline
// (net/http clears both before the next request on a connection): its stdin
// may take a while to arrive, and /v1/exec and /v1/run last as long as the
// command, which is why Run sets no ReadTimeout or WriteTimeout. A request
// not admitted also closes its connection once answered, so a peer without
// the token cannot keep idle connections open by asking for /v1/healthz now
// and then. A connection that brings an admitted request leaves the caps on
// those that have not (connCap): none of them can close it. It counts toward
// the admitted connections' own cap instead, past which a new one's request
// is refused, though it carries the token. A request with more header lines
// than any request may have is refused too, whoever sent it, before it is
// admitted or served: a connection's first request cannot get that far
// (see cappedConn.Read), but a later one on a kept-alive connection is held
// to the limit only here, by what net/http parsed of its header, which an
// admitted request could otherwise hold for as long as its command runs.
func (g *Gateway) bounded(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cc, _ := r.Context().Value(apiConnKey{}).(*cappedConn)
		if cc != nil {
			cc.headerRead()
		}
		serve := h
		switch {
		case headerLineCount(r) > apiMaxHeaderLines:
			serve = refusal(431, fmt.Sprintf("the request header has more than %d lines", apiMaxHeaderLines))
		case g.admits(r):
			if cc == nil || cc.admitted() {
				h.ServeHTTP(w, r)
				return
			}
			serve = refusal(503, fmt.Sprintf("the gateway already holds %d connections that carried the token; close idle ones and try again", cc.l.admittedMax))
		}
		w.Header().Set("Connection", "close")
		rc := http.NewResponseController(w)
		end := time.Now().Add(cmp.Or(g.preAuth, apiPreAuthTimeout))
		rc.SetReadDeadline(end)
		rc.SetWriteDeadline(end)
		serve.ServeHTTP(w, r)
		if r.ContentLength != 0 {
			// Answered: the rest of the body would only be read to keep the
			// connection, which is not worth waiting for. (A request with no
			// body has nothing left to read.)
			rc.SetReadDeadline(time.Now().Add(apiDrainTimeout))
		}
	})
}

// refusal answers every request with code and why, as refuse does.
func refusal(code int, why string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { refuse(w, code, why) })
}

// headerLineCount is how many lines r's header took, as net/http parsed it:
// a line per field value, a folded one once, and the Host line, which
// net/http takes out of the header.
func headerLineCount(r *http.Request) int {
	n := 0
	if r.Host != "" {
		n++
	}
	for _, vs := range r.Header {
		n += len(vs)
	}
	return n
}

// listening decides, once, where the gateway listens, by the rules
// ListenTCP follows (resolveBind): Run listens there, and guard, the
// warnings and the tokenless policy go by it, so all of them agree on
// whether that is loopback however Addr spells it, and a host name is
// looked up once.
func (g *Gateway) listening() (*bindAddrs, error) {
	g.bindOnce.Do(func() { g.bind, g.bindErr = resolveBind(g.Addr) })
	return g.bind, g.bindErr
}

// onLoopback reports whether the gateway listens on loopback addresses only.
// An empty or wildcard host (0.0.0.0, ::) is not loopback.
func (g *Gateway) onLoopback() bool {
	b, err := g.listening()
	return err == nil && b.loopback
}

func (g *Gateway) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, apiMaxRequestBody)
		if why := g.guard(r); why != "" {
			refuse(w, 403, why)
			return
		}
		if !g.tokenOK(r) {
			refuse(w, 401, "unauthorized")
			return
		}
		h(w, r)
	}
}

// admits reports whether auth lets r through: it passes guard and carries the
// bearer token, or the gateway has none.
func (g *Gateway) admits(r *http.Request) bool {
	return g.guard(r) == "" && g.tokenOK(r)
}

// tokenOK reports whether r carries the bearer token; a gateway with no token
// asks for none.
func (g *Gateway) tokenOK(r *http.Request) bool {
	if g.Token == "" {
		return true
	}
	scheme, cred, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.EqualFold(scheme, "Bearer") && subtle.ConstantTimeCompare([]byte(cred), []byte(g.Token)) == 1
}

// refuse answers a request turned away for its token or by guard and closes
// the connection, so the answer goes out at once rather than after the rest
// of the body, which net/http would read first to keep the connection for
// another request.
func refuse(w http.ResponseWriter, code int, why string) {
	w.Header().Set("Connection", "close")
	respondJSON(w, code, map[string]string{"error": why})
}

// guard blocks the requests a web page could make to this command-execution
// endpoint. It returns "" to allow, or a reason to reject with 403.
//
//   - Any request carrying an Origin header is cross-site: a browser attaches
//     Origin to every request script makes to another origin (including a
//     no-cors POST), while curl and the tern client send none. Rejecting it
//     stops CSRF regardless of Content-Type.
//   - A POST must be application/json. A page can only set text/plain,
//     form-urlencoded or multipart on a no-preflight ("simple") request, so
//     requiring JSON blocks that path even if an Origin ever slipped through.
//   - When the gateway listens on loopback only, the request's Host must name
//     the loopback interface too, or the host the gateway was told to listen
//     on, or a trusted host. A DNS-rebinding page is served from the
//     attacker's hostname, so its same-origin requests (which carry no Origin
//     header) still fail this check. Whether the gateway listens on loopback
//     is what ListenTCP made of its address (see listening); the Host itself
//     is only ever compared, never looked up. Trusted hosts given to a gateway
//     off loopback turn the check on there too.
func (g *Gateway) guard(r *http.Request) string {
	if r.Header.Get("Origin") != "" {
		return "cross-origin requests are not allowed on the REST gateway"
	}
	if r.Method == http.MethodPost {
		ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
		if strings.TrimSpace(strings.ToLower(ct)) != "application/json" {
			return "Content-Type must be application/json"
		}
	}
	if (g.onLoopback() || len(g.TrustedHosts) > 0) && !hostIsLoopback(r.Host) && !g.hostTrusted(r.Host) {
		return "request Host is not loopback or an --api-trusted-host"
	}
	return ""
}

// hostTrusted reports whether r.Host names a configured trusted host, so the
// gateway can sit behind a reverse proxy that preserves Host without turning the
// Host check off by binding a routable address. A proxy on another port than
// 80 or 443 sends that port in Host, so an entry without a port matches the
// name with any port; an entry with one matches that port only. The host the
// gateway was told to listen on is trusted too, with any port: a client
// that dials the name given to --api-addr, such as localhost.localdomain,
// sends it. Names match in any case and with or without the root's
// trailing dot, which name the same host, as "localhost." does.
func (g *Gateway) hostTrusted(host string) bool {
	name, port := splitHostHeader(host)
	if b, err := g.listening(); err == nil && len(b.hosts) > 0 {
		if own, _, err := net.SplitHostPort(b.addr); err == nil && sameHostName(name, own) {
			return true
		}
	}
	for _, h := range g.TrustedHosts {
		if tn, tp := splitHostHeader(h); sameHostName(name, tn) && (tp == "" || tp == port) {
			return true
		}
	}
	return false
}

// sameHostName reports whether two host names name the same host: equal in
// any case, a trailing dot aside. No name is the empty one.
func sameHostName(a, b string) bool {
	a, b = strings.TrimSuffix(a, "."), strings.TrimSuffix(b, ".")
	return a != "" && strings.EqualFold(a, b)
}

// splitHostHeader splits a Host header value, or a trusted-host entry, into
// the host and the port, "" when it has none. Brackets come off an IPv6
// address only; around anything else, such as a name, they make no spelling
// of it, so the value is kept whole and names no host.
func splitHostHeader(s string) (host, port string) {
	host = s
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		host = s[1 : len(s)-1]
	}
	if strings.HasPrefix(s, "[") {
		if a, err := netip.ParseAddr(host); err != nil || !a.Is6() {
			return s, ""
		}
	}
	return host, port
}

// hostIsLoopback reports whether an HTTP Host header (host or host:port)
// refers to the loopback interface: a loopback address, or "localhost" as
// ListenTCP takes it, in any case and with or without a trailing dot.
func hostIsLoopback(host string) bool {
	host, _ = splitHostHeader(host)
	if isLocalhost(host) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type execReq struct {
	Cmd   []string `json:"cmd"`
	ID    string   `json:"id"`
	Stdin string   `json:"stdin"` // optional input fed to the command's stdin
}

// check refuses a request the agent could not take or that would not mean
// what it says: a command too long for a stream header, or an agent id the
// gateway cannot pin.
func (g *Gateway) check(cmd []string, id string) string {
	if b, _ := json.Marshal(cmd); len(b) > apiMaxCmd {
		return fmt.Sprintf("the command is longer than %d bytes; pass large input as stdin", apiMaxCmd)
	}
	return g.checkID(id)
}

func (g *Gateway) checkID(id string) string {
	switch {
	case id == "" || slices.Contains(g.AgentIDs, id):
		return ""
	case len(g.AgentIDs) == 0:
		return "id names an agent on a relay, but this gateway reaches one agent directly"
	default:
		return "id names an agent this gateway has no fingerprint for; add it with --api-agent ID=FINGERPRINT"
	}
}

// stdinReader turns the optional request stdin field into an io.Reader (nil if
// empty; Client.Run then closes the command's stdin right away).
func stdinReader(s string) io.Reader {
	if s == "" {
		return nil
	}
	return &stdinText{s: s}
}

// stdinText reads out a request's stdin and then lets go of it: a command may
// run on long after its input was sent, and should not keep up to
// apiMaxRequestBody of it for that long.
type stdinText struct{ s string }

func (t *stdinText) Read(p []byte) (int, error) {
	if t.s == "" {
		return 0, io.EOF
	}
	n := copy(p, t.s)
	if n == len(t.s) {
		t.s = "" // t.s[n:] would be empty but could still point into the text
	} else {
		t.s = t.s[n:]
	}
	return n, nil
}

// lockedBuffer is a concurrency-safe, size-capped sink used by POST /v1/run.
type lockedBuffer struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var dropped bool
	if b.buf, dropped = appendCapped(b.buf, p, jobMaxOutput); dropped {
		b.truncated = true
	}
	return len(p), nil // always report a full write so Run keeps going
}

func (b *lockedBuffer) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf), b.truncated
}

// handleRun is the simple mode: run a command with a timeout and return the
// whole result in one JSON response (no streaming). If it exceeds the timeout
// the process is killed and whatever was produced is returned with
// timed_out:true.
func (g *Gateway) handleRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Cmd     []string `json:"cmd"`
		ID      string   `json:"id"`
		Stdin   string   `json:"stdin"`
		Timeout int      `json:"timeout"` // seconds; optional
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Cmd) == 0 {
		respondJSON(w, 400, map[string]string{"error": "body must be {\"cmd\":[...]}"})
		return
	}
	if why := g.check(req.Cmd, req.ID); why != "" {
		respondJSON(w, 400, map[string]string{"error": why})
		return
	}
	// Read the body to EOF: net/http only starts watching for a client that
	// goes away (cancelling r.Context()) once the body is fully consumed.
	io.Copy(io.Discard, r.Body)
	to := g.RunTimeout
	if to <= 0 {
		to = defaultRunTimeout
	}
	if req.Timeout > 0 {
		// Guard against overflow: req.Timeout * 1e9 can wrap time.Duration into a
		// negative (immediate-kill) value that also slips past MaxTimeout.
		if req.Timeout > maxRunTimeoutSec {
			to = time.Duration(maxRunTimeoutSec) * time.Second
		} else {
			to = time.Duration(req.Timeout) * time.Second
		}
	}
	if g.MaxTimeout > 0 && to > g.MaxTimeout {
		to = g.MaxTimeout
	}

	if !g.reserveCommand() {
		respondJSON(w, 429, map[string]string{"error": fmt.Sprintf("too many running commands (max %d)", maxRunningCommands)})
		return
	}
	defer g.releaseCommand()
	cl, err := g.Dial(req.ID)
	if err != nil {
		respondJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}

	lb := &lockedBuffer{}
	ch := make(chan int, 1)
	var runErr error
	cmd, stdin := req.Cmd, stdinReader(req.Stdin) // not req: only the reader holds the input, until it is sent
	go func() {
		code, e := cl.Run(cmd, stdin, lb)
		runErr = e
		ch <- code
	}()

	select {
	case <-r.Context().Done():
		cl.Close() // the HTTP client went away: the agent kills the process
		<-ch
		return
	case code := <-ch:
		cl.Close()
		out, trunc := lb.snapshot()
		resp := map[string]any{"exit": code, "output": out, "timed_out": false}
		if trunc {
			resp["truncated"] = true
		}
		if runErr != nil {
			resp["error"] = runErr.Error()
		}
		respondJSON(w, 200, resp)
	case <-time.After(to):
		cl.Close() // cancel: the agent kills the process
		<-ch       // let Run finish writing/returning
		out, trunc := lb.snapshot()
		resp := map[string]any{"exit": -1, "output": out, "timed_out": true, "timeout_sec": int(to.Seconds())}
		if trunc {
			resp["truncated"] = true
		}
		respondJSON(w, 200, resp)
	}
}

func (g *Gateway) handleExec(w http.ResponseWriter, r *http.Request) {
	var req execReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Cmd) == 0 {
		respondJSON(w, 400, map[string]string{"error": "body must be {\"cmd\":[...]}"})
		return
	}
	if why := g.check(req.Cmd, req.ID); why != "" {
		respondJSON(w, 400, map[string]string{"error": why})
		return
	}
	io.Copy(io.Discard, r.Body) // to EOF, so a client that leaves cancels r.Context()
	if !g.reserveCommand() {
		respondJSON(w, 429, map[string]string{"error": fmt.Sprintf("too many running commands (max %d)", maxRunningCommands)})
		return
	}
	defer g.releaseCommand()
	cl, err := g.Dial(req.ID)
	if err != nil {
		respondJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	// If the HTTP client goes away mid-stream, close the agent connection so
	// the agent kills the command instead of letting it run on unobserved.
	stop := context.AfterFunc(r.Context(), func() { cl.Close() })
	defer stop()

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	sw := &streamWriter{enc: enc, flusher: flusher}
	code, runErr := cl.Run(req.Cmd, stdinReader(req.Stdin), sw)
	final := map[string]any{"exit": code}
	if runErr != nil {
		final["error"] = runErr.Error()
	}
	sw.mu.Lock()
	if len(sw.carry) > 0 { // a character the command never finished
		enc.Encode(map[string]string{"stdout": string(sw.carry)})
	}
	enc.Encode(final)
	if flusher != nil {
		flusher.Flush()
	}
	sw.mu.Unlock()
}

type streamWriter struct {
	mu      sync.Mutex
	enc     *json.Encoder
	flusher http.Flusher
	carry   []byte // the start of a character split between writes
}

func (s *streamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// JSON strings hold whole characters: keep a split one for the next
	// write, which would otherwise turn both halves into U+FFFD.
	b := append(s.carry, p...)
	cut := len(b) - partialRune(b)
	s.carry = append([]byte(nil), b[cut:]...)
	if cut == 0 {
		return len(p), nil
	}
	if err := s.enc.Encode(map[string]string{"stdout": string(b[:cut])}); err != nil {
		return 0, err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return len(p), nil
}

func (g *Gateway) handleJobCreate(w http.ResponseWriter, r *http.Request) {
	var req execReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Cmd) == 0 {
		respondJSON(w, 400, map[string]string{"error": "body must be {\"cmd\":[...]}"})
		return
	}
	if why := g.check(req.Cmd, req.ID); why != "" {
		respondJSON(w, 400, map[string]string{"error": why})
		return
	}
	g.mu.Lock()
	if g.running >= maxRunningJobs {
		g.mu.Unlock()
		respondJSON(w, 429, map[string]string{"error": fmt.Sprintf("too many running jobs (max %d)", maxRunningJobs)})
		return
	}
	g.running++ // reserve the slot atomically with the check (no TOCTOU overshoot)
	g.mu.Unlock()

	cl, err := g.Dial(req.ID)
	if err != nil {
		g.mu.Lock()
		g.running-- // dial failed, release the reserved slot
		g.mu.Unlock()
		respondJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	// A random id: one a client polls after the gateway restarts names no
	// other client's job.
	id := "j" + randHex(8)
	g.mu.Lock()
	j := &job{id: id, cmd: req.Cmd, client: cl, started: time.Now()}
	g.jobs[id] = j
	g.evictLocked()
	g.mu.Unlock()

	stdin := stdinReader(req.Stdin)
	go func() {
		code, runErr := cl.Run(j.cmd, stdin, j) // not req: only the reader holds the input, until it is sent
		j.finish(code, runErr)
		cl.Close()
		g.mu.Lock()
		g.running--
		g.expireLocked(j)
		g.mu.Unlock()
	}()

	respondJSON(w, 202, map[string]string{"job": id, "status": "running"})
}

// expireLocked forgets finished job j once it has been kept for jobKeep, so
// its output does not stay in memory for good when no new jobs come to evict
// it. g.mu is held.
func (g *Gateway) expireLocked(j *job) {
	if g.jobs[j.id] != j {
		return // already evicted
	}
	j.expire = time.AfterFunc(cmp.Or(g.keep, jobKeep), func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.jobs[j.id] == j {
			delete(g.jobs, j.id)
		}
	})
}

// evictLocked drops the oldest finished jobs once the registry exceeds the cap,
// so the map does not grow without bound. Running jobs are never evicted.
func (g *Gateway) evictLocked() {
	if len(g.jobs) <= maxRetainedJobs {
		return
	}
	var finished []*job
	for _, j := range g.jobs {
		j.mu.Lock()
		done := j.done
		j.mu.Unlock()
		if done {
			finished = append(finished, j)
		}
	}
	sort.Slice(finished, func(i, k int) bool { return finished[i].started.Before(finished[k].started) })
	for _, j := range finished {
		if len(g.jobs) <= maxRetainedJobs {
			break
		}
		if j.expire != nil {
			j.expire.Stop() // its timer would hold on to it until it fired
		}
		delete(g.jobs, j.id)
	}
}

// reserveCommand takes one of the maxRunningCommands slots /v1/run and
// /v1/exec share, each request holding a connection to the agent and a
// running command for as long as its client waits, or reports that none is
// free. releaseCommand gives it back.
func (g *Gateway) reserveCommand() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.commands >= maxRunningCommands {
		return false
	}
	g.commands++
	return true
}

func (g *Gateway) releaseCommand() {
	g.mu.Lock()
	g.commands--
	g.mu.Unlock()
}

func (g *Gateway) lookup(r *http.Request) *job {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.jobs[r.PathValue("id")]
}

func (g *Gateway) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	j := g.lookup(r)
	if j == nil {
		respondJSON(w, 404, map[string]string{"error": "no such job"})
		return
	}
	// Build the reply under the lock and send it after: a client slow to
	// read must not hold the job, which its output and the job list wait on.
	j.mu.Lock()
	resp := map[string]any{
		"job":        j.id,
		"cmd":        j.cmd,
		"output_len": len(j.buf),
		"started":    j.started.UTC().Format(time.RFC3339),
	}
	if j.trunc {
		resp["truncated"] = true
	}
	switch {
	case j.done && j.cancelled:
		resp["status"] = "cancelled"
	case j.done:
		resp["status"] = "done"
		resp["exit"] = j.exit
		if j.err != "" {
			resp["error"] = j.err
		}
	default:
		resp["status"] = "running"
	}
	j.mu.Unlock()
	respondJSON(w, 200, resp)
}

func (g *Gateway) handleJobOutput(w http.ResponseWriter, r *http.Request) {
	j := g.lookup(r)
	if j == nil {
		respondJSON(w, 404, map[string]string{"error": "no such job"})
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	j.mu.Lock()
	next := len(j.buf)
	if !j.done {
		next -= partialRune(j.buf) // the rest of a character is still to come
	}
	if offset < 0 || offset > next {
		offset = next
	}
	data := make([]byte, next-offset)
	copy(data, j.buf[offset:next])
	done := j.done
	exit := j.exit
	j.mu.Unlock()

	resp := map[string]any{"next_offset": next, "data": string(data), "done": done}
	if done {
		resp["exit"] = exit
	}
	respondJSON(w, 200, resp)
}

func (g *Gateway) handleJobDelete(w http.ResponseWriter, r *http.Request) {
	j := g.lookup(r)
	if j == nil {
		respondJSON(w, 404, map[string]string{"error": "no such job"})
		return
	}
	j.mu.Lock()
	j.cancelled = !j.done
	j.mu.Unlock()
	j.client.Close() // tears down the stream; the agent kills the process
	respondJSON(w, 200, map[string]bool{"ok": true})
}

func (g *Gateway) handleSessions(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if why := g.checkID(id); why != "" {
		respondJSON(w, 400, map[string]string{"error": why})
		return
	}
	cl, err := g.Dial(id)
	if err != nil {
		respondJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	// An agent that does not answer, or a client that goes away, must not
	// keep the request and its agent connection.
	ctx, cancel := context.WithTimeout(r.Context(), cmp.Or(g.sessions, apiSessionsTimeout))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { cl.Close() })
	defer stop()
	names, err := cl.ListSessions()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = errors.New("the agent did not list its sessions in time")
		}
		respondJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if names == nil {
		names = []string{} // [] rather than null when there are none
	}
	respondJSON(w, 200, map[string]any{"sessions": names})
}

// connCap holds the gateway's connections that have not brought a request it
// admits to perSource per source (an IPv4 address or IPv6 /64, and all of
// loopback as one, see connPath) and total in all: whatever a peer without
// the token sends, the gateway would otherwise hold every connection it
// opens until it ran out of file descriptors or memory. A connection whose
// request the gateway admits leaves these books (cappedConn.admitted): it no
// longer counts, and nothing a peer without the token does can close it. A
// newcomer is never refused, since a few peers holding every place would
// then lock everyone out, the token's holders too: over its source's cap one
// of that source's connections makes room, else on a full listener one of
// anyone's, the oldest of the source holding the most within the address
// block holding the most at every level (see partyTree), unless one has not
// sent a whole request line for silentGrace, which goes first. Admitted
// connections count apart, up to admittedMax (0: no cap), so that one token
// holder cannot take every file descriptor either; past it a new one is
// refused, and none is ever closed to make room.
type connCap struct {
	net.Listener
	perSource, total int
	admittedMax      int
	grace            time.Duration    // 0 means silentGrace
	clock            func() time.Time // nil means time.Now (see PreAuthLimiter.clock)

	mu        sync.Mutex
	held      partyTree[*cappedConn] // the connections in the books
	seq       uint64                 // connections booked so far
	admittedN int                    // the admitted connections open
}

func (l *connCap) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.admit(c), nil
}

// connPath names the address blocks connCap books a connection from a under:
// those of addrPath, except that every loopback address, IPv4 or IPv6, is
// one source. A loopback gateway listens on both, so its local clients
// arrive from either, and a local peer must not double its share, or spread
// over 127.0.0.0/8, by using several, nor the operator's own client be split
// between two.
func connPath(a net.Addr) []string {
	if a != nil {
		if ap, err := netip.ParseAddrPort(a.String()); err == nil && ap.Addr().Unmap().IsLoopback() {
			return []string{"loopback"}
		}
	}
	return addrPath(a)
}

// admit books c, first closing another connection when c's source holds its
// cap or the listener is full.
func (l *connCap) admit(c net.Conn) *cappedConn {
	cc := &cappedConn{Conn: c, l: l, path: connPath(c.RemoteAddr())}
	cc.entry.val = cc
	now := time.Now()
	if l.clock != nil {
		now = l.clock()
	}
	grace := cmp.Or(l.grace, silentGrace)
	l.mu.Lock()
	var victim *partyEntry[*cappedConn]
	if src := l.held.nodes[cc.path[len(cc.path)-1]]; src != nil && src.n >= l.perSource {
		victim = l.held.victim(src, grace, now)
	} else if l.held.root.n >= l.total {
		victim = l.held.victim(&l.held.root, grace, now)
	}
	var evicted *cappedConn
	if victim != nil {
		evicted = victim.val
		l.dropLocked(evicted)
	}
	l.seq++
	l.held.add(&cc.entry, cc.path, l.seq, true, now)
	cc.booked = true
	l.mu.Unlock()
	if evicted != nil {
		evicted.Conn.Close()
	}
	return cc
}

// open is how many connections l holds in its books.
func (l *connCap) open() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held.root.n
}

// spoke records that cc has sent a whole request line. l.mu is not held.
func (l *connCap) spoke(cc *cappedConn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cc.booked {
		l.held.heard(&cc.entry)
	}
}

// dropLocked takes cc out of the books, once. l.mu is held.
func (l *connCap) dropLocked(cc *cappedConn) {
	if cc == nil || !cc.booked {
		return
	}
	cc.booked = false
	l.held.remove(&cc.entry)
}

// cappedConn is a connection under a connCap, which it leaves once a request
// on it is admitted or it is closed.
type cappedConn struct {
	net.Conn
	l       *connCap
	entry   partyEntry[*cappedConn]
	path    []string    // its address blocks
	booked  bool        // in l's books; guarded by l.mu
	counted bool        // among l's admitted connections; guarded by l.mu
	spoken  atomic.Bool // it sent a whole request line

	// head counts the lines of the header of the connection's first
	// request, whoever sent it. Read runs on net/http's goroutine for the
	// connection, or on its background reader while a handler runs, which
	// headerRead may do at that moment. Later requests come only on a
	// connection whose first was admitted (any other is closed once
	// answered), and where one starts among the bytes net/http reads ahead
	// cannot be told from here, so what parsing their header found holds
	// them to the limit instead (see Gateway.bounded); until then, what
	// that parse holds is bounded by net/http's byte limit, which on a
	// kept-alive connection also lets in the 4 KiB it read ahead, and by
	// ReadHeaderTimeout.
	mu   sync.Mutex
	head headerLines
	over bool // the header went past its lines: every read fails
}

// errHeaderLines fails the read of a request header with too many lines.
var errHeaderLines = errors.New("the request header has too many lines")

// Read passes on what arrives, up to the end of the line that takes the
// first request's header past its lines, and then fails: net/http never
// gets that line whole, and answers 400. It holds the bytes back, rather
// than failing at once, so that net/http has the 4 it peeks at before
// reading a request, where a failure would close the connection without an
// answer.
func (c *cappedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	over := c.over
	c.mu.Unlock()
	if over {
		return 0, errHeaderLines
	}
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	within := n
	if !c.head.end {
		within = c.head.scan(p[:n], 1+apiMaxHeaderLines)
	}
	c.over = within < n
	line := c.head.n > 0
	c.mu.Unlock()
	// Only a whole request line ends a connection's silence: a byte or two
	// costs a flood nothing, and would otherwise spare its connections
	// from going first (see connCap).
	if line && !c.spoken.Load() && c.spoken.CompareAndSwap(false, true) {
		c.l.spoke(c)
	}
	switch {
	case within == n:
		return n, err
	case within == 0:
		return 0, errHeaderLines
	}
	return within, nil
}

// headerRead records that net/http has read the header of the request it
// serves now: what arrives after it is that request's body, whose lines are
// no header's, and the requests after it, which Read does not count.
func (c *cappedConn) headerRead() {
	c.mu.Lock()
	c.head.end = true
	c.mu.Unlock()
}

// headerLines counts the lines of a request header as it arrives: net/http
// reads the request line and header of a connection's first request, which
// may be anyone's, through Read.
type headerLines struct {
	n   int  // lines ended, the request line first
	cur int  // bytes so far in the line under way, CR aside
	end bool // the header ended: its blank line arrived, or net/http read it
}

// scan counts the lines in p, the next bytes of the request, and returns how
// many of those bytes come before the line break that ends a line past max,
// before the header ended: len(p) while it stays within them.
func (h *headerLines) scan(p []byte, max int) int {
	for i, b := range p {
		switch b {
		case '\n':
			if h.cur == 0 {
				if h.n > 0 {
					h.end = true
					return len(p)
				}
				continue // a blank line ahead of the request, which net/http refuses
			}
			if h.n++; h.n > max {
				return i
			}
			h.cur = 0
		case '\r':
		default:
			h.cur++
		}
	}
	return len(p)
}

// admitted takes c, a request on which the gateway admits, out of its
// connCap's books and counts it among the admitted connections, unless they
// are at their cap: then it reports false and leaves c where it was, for
// the request to be refused. A connection once counted stays so until it
// closes.
func (c *cappedConn) admitted() bool {
	c.l.mu.Lock()
	defer c.l.mu.Unlock()
	if c.counted {
		return true
	}
	if c.l.admittedMax > 0 && c.l.admittedN >= c.l.admittedMax {
		return false
	}
	c.l.dropLocked(c)
	c.counted = true
	c.l.admittedN++
	return true
}

func (c *cappedConn) Close() error {
	c.l.mu.Lock()
	c.l.dropLocked(c)
	if c.counted {
		c.counted = false
		c.l.admittedN--
	}
	c.l.mu.Unlock()
	return c.Conn.Close()
}

// CloseWrite passes net/http's half-close through, which it uses to let a
// peer read a final answer before the connection is closed under it.
func (c *cappedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// partialRune is how many bytes at the end of b begin a UTF-8 character that
// is not complete yet.
func partialRune(b []byte) int {
	for i := 1; i <= utf8.UTFMax && i <= len(b); i++ {
		if utf8.RuneStart(b[len(b)-i]) {
			if utf8.FullRune(b[len(b)-i:]) {
				return 0
			}
			return i
		}
	}
	return 0
}

// randHex is n random bytes in hex.
func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
