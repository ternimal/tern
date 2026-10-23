// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Command tern is the Ternimal client: interactive shells, command exec, port
// forwarding, file copy, a session list, a REST gateway and an MCP server for
// AI clients, against an agent reached directly or through a relay.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tern "github.com/ternimal/tern/internal/tern"
	"golang.org/x/term"
)

const usage = `tern - Ternimal client: shells, exec, forwarding, file copy, REST and MCP

USAGE:
  tern connect [conn] [--session NAME] [--attach|--new] [--read-only]
               [--no-reconnect] [-L spec] [-R spec]   interactive shell
  tern run     [conn] -- CMD [ARGS...]      run a command, exit code propagated
  tern forward [conn] (-L spec | -R spec)   port forwarding only
  tern cp      [conn] SRC DST               copy (use agent:PATH for the remote)
  tern list    [conn]                       list live sessions on the agent
  tern api     [conn] [--api-addr ADDR]     REST gateway (exec over HTTP)
  tern mcp     [conn | --config F]          MCP server for AI clients, over stdio
  tern keygen  [--out F] [--comment C]      make an OpenSSH Ed25519 key pair
  tern genkey                               print a random 32-char token
  tern version                              print the version
  Every command but version takes -h for its flags.

CONNECTION (conn): a tern1: string (positional or --to), or explicit flags:
  tern1:...   (or --to tern1:...)          connection string (from ternd startup)
  direct: --addr HOST:PORT --fingerprint FP
  relay:  --relay HOST:PORT --relay-fingerprint FP --id ID --fingerprint FP,
          with the relay token in TERN_RELAY_TOKEN or --relay-token-file F
  auth:   --key ~/.ssh/id_ed25519, or a token in TERN_TOKEN or --token-file F

SECRETS: pass tokens in the environment or a file, as above; the REST
  gateway's goes in TERN_API_TOKEN or --api-token-file F. --token,
  --relay-token and --api-token also work, but put the secret on the command
  line, where other local users can read it.

PORT FORWARD specs (ssh-style):
  -L [lhost:]lport:rhost:rport    local  -> agent-reached rhost:rport
  -R [rbind:]rport:lhost:lport    agent  -> client-reached lhost:lport
`

// version is set at build time via -ldflags "-X main.version=..."; see
// tern.ResolveVersion for builds that do not set it.
var version = "dev"

func main() {
	version = tern.ResolveVersion(version)
	log.SetFlags(0)
	log.SetPrefix("tern: ")
	tern.SetupLogging()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "connect":
		cmdConnect(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "forward":
		cmdForward(os.Args[2:])
	case "cp":
		cmdCopy(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "api":
		cmdAPI(os.Args[2:])
	case "mcp":
		cmdMCP(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "genkey":
		cmdGenkey(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("tern %s\n", version)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

// --- shared connection flags ---

type connFlags struct {
	to, addr, fp                 *string
	relay, relayFP, relayTok, id *string
	key, token                   *string
	tokenFile, relayTokFile      *string
	toFile                       *string
	insecure, skipEnc, dangerous *bool
}

func addConnFlags(fs *flag.FlagSet) *connFlags {
	cf := &connFlags{
		to:           fs.String("to", "", "connection string (tern1:...)"),
		addr:         fs.String("addr", "", "direct: agent address host:port"),
		fp:           fs.String("fingerprint", "", "agent TLS SHA-256 fingerprint"),
		relay:        fs.String("relay", "", "relay: relay address host:port"),
		relayFP:      fs.String("relay-fingerprint", "", "relay: relay TLS SHA-256 fingerprint"),
		relayTok:     fs.String("relay-token", "", "relay: relay token (prefer TERN_RELAY_TOKEN or --relay-token-file)"),
		id:           fs.String("id", "", "relay: agent id"),
		key:          fs.String("key", "", "OpenSSH private key for public-key auth"),
		token:        fs.String("token", "", "token-auth secret (prefer TERN_TOKEN or --token-file)"),
		tokenFile:    fs.String("token-file", "", "read the token-auth secret from this file"),
		relayTokFile: fs.String("relay-token-file", "", "relay: read the relay token from this file"),
		toFile:       fs.String("to-file", "", "read the tern1: connection string from this file (or TERN_TO)"),
		insecure:     fs.Bool("insecure-skip-fingerprint", false, "DANGEROUS: skip TLS fingerprint verification, so the agent/relay is not authenticated and the connection can be intercepted; for testing only"),
		skipEnc:      fs.Bool("insecure-skip-encryption", false, "DANGEROUS: run the session in plaintext with no TLS (the agent must also run in plaintext: --insecure-skip-encryption or --insecure-dangerous); everything, including auth, is sent in cleartext; for testing only"),
		dangerous:    fs.Bool("insecure-dangerous", false, "DANGEROUS: shorthand for --insecure-skip-fingerprint plus --insecure-skip-encryption; turns off TLS and the check of the agent and relay certificates (the token or key is still required; its proof crosses in cleartext); for testing only"),
	}
	tern.Aliases(fs, map[string]string{
		"to": "c", "addr": "a", "fingerprint": "f", "relay": "r",
		"relay-fingerprint": "F", "relay-token": "T", "id": "i",
		"key": "k", "token": "t",
	})
	return cf
}

// addVerbose adds the --verbose/-v flag shared by every command.
func addVerbose(fs *flag.FlagSet) *bool {
	v := fs.Bool("verbose", false, "verbose (debug) logging")
	tern.Alias(fs, "verbose", "v")
	return v
}

// rejectArgs exits with a usage error if positional arguments are left over
// after flag parsing, instead of silently ignoring them.
func rejectArgs(fs *flag.FlagSet) {
	if fs.NArg() == 0 {
		return
	}
	// A tern1: string can carry a relay token, so it is not echoed.
	if tern.IsConnString(fs.Arg(0)) {
		fmt.Fprintf(os.Stderr, "tern %s: unexpected tern1: argument (it goes before the flags, or use --to)\n\n", fs.Name())
	} else {
		fmt.Fprintf(os.Stderr, "tern %s: unexpected argument %q\n\n", fs.Name(), fs.Arg(0))
	}
	fs.Usage()
	os.Exit(2)
}

// splitLeadingConn pulls an optional leading connection-string positional
// (tern1:...) off the front of args, so `tern <cmd> tern1:... [flags]` is
// shorthand for `--to tern1:...`. Only a tern1: string is recognized; a direct
// host:port stays behind --addr so it can't be confused with cp's agent:PATH,
// a Windows C:\path, or any other colon-bearing argument. The positional must
// come first (before flags); use --to if you want to put flags first.
func splitLeadingConn(args []string) (conn string, rest []string) {
	if len(args) > 0 && tern.IsConnString(args[0]) {
		return args[0], args[1:]
	}
	return "", args
}

// applyConn folds a positional connection string into the --to flag, erroring
// if the connection was also given with --to.
func (cf *connFlags) applyConn(conn string) {
	if conn == "" {
		return
	}
	if *cf.to != "" {
		log.Fatal("connection given twice: as a tern1: argument and with --to")
	}
	*cf.to = conn
}

type target struct {
	mode                           string
	addr, fp                       string
	relay, relayFP, relayToken, id string
	key, token                     string
	insecure, skipEnc              bool
}

func (cf *connFlags) target() (*target, error) {
	token, tokenFromFlag, err := tern.ResolveSecret("token", *cf.token, *cf.tokenFile, "TERN_TOKEN")
	if err != nil {
		return nil, err
	}
	tern.WarnSecretOnArgv(tokenFromFlag, "token", "TERN_TOKEN")
	t := &target{key: *cf.key, token: token, insecure: *cf.insecure || *cf.dangerous, skipEnc: *cf.skipEnc || *cf.dangerous}
	if t.insecure && (*cf.fp != "" || *cf.relayFP != "") {
		return nil, fmt.Errorf("--insecure-skip-fingerprint cannot be combined with --fingerprint or --relay-fingerprint; it turns fingerprint verification off entirely")
	}
	if t.skipEnc && *cf.fp != "" {
		return nil, fmt.Errorf("--insecure-skip-encryption cannot be combined with --fingerprint; a plaintext session has no agent certificate to pin")
	}
	relayToken := func() (string, error) {
		rt, rtFromFlag, err := tern.ResolveSecret("relay-token", *cf.relayTok, *cf.relayTokFile, "TERN_RELAY_TOKEN")
		tern.WarnSecretOnArgv(rtFromFlag, "relay-token", "TERN_RELAY_TOKEN")
		return rt, err
	}
	// A tern1: string may come from --to or the positional (argv), --to-file or
	// TERN_TO. A relay-mode string can embed the relay token, so prefer the
	// off-argv forms and warn when such a string is on argv.
	connStr := *cf.to
	connOnArgv := connStr != ""
	if connStr == "" && *cf.toFile != "" {
		s, rerr := tern.ReadConnStringFile(*cf.toFile)
		if rerr != nil {
			return nil, fmt.Errorf("--to-file: %w", rerr)
		}
		connStr = s
	}
	if connStr == "" {
		connStr = strings.TrimSpace(os.Getenv("TERN_TO"))
	}
	if connStr != "" {
		// A tern1: string carries the whole connection, so explicit dial flags
		// alongside it are silently ignored; reject the ambiguity.
		if t.insecure {
			return nil, fmt.Errorf("--insecure-skip-fingerprint cannot be combined with a tern1: connection string, which already carries the pinned fingerprints")
		}
		if t.skipEnc {
			return nil, fmt.Errorf("--insecure-skip-encryption cannot be combined with a tern1: connection string, which pins the agent certificate; use explicit --addr or --relay flags")
		}
		if *cf.addr != "" || *cf.relay != "" || *cf.fp != "" || *cf.id != "" {
			return nil, fmt.Errorf("a tern1: connection string cannot be combined with --addr/--relay/--fingerprint/--id")
		}
		cs, derr := tern.DecodeConnString(connStr)
		if derr != nil {
			return nil, derr
		}
		if connOnArgv && cs.Mode == "relay" && cs.RelayToken != "" {
			slog.Warn("the tern1: string on the command line carries the relay token, " +
				"visible to other local users; prefer TERN_TO or --to-file")
		}
		t.mode, t.addr, t.fp = cs.Mode, cs.Addr, cs.FP
		t.relay, t.relayFP, t.relayToken, t.id = cs.Relay, cs.RelayFP, cs.RelayToken, cs.ID
		if t.mode == "relay" && t.relayToken == "" { // as ternd prints it
			if t.relayToken, err = relayToken(); err != nil {
				return nil, err
			}
		}
	} else {
		t.fp = *cf.fp
		if *cf.relay != "" {
			rt, rerr := relayToken()
			if rerr != nil {
				return nil, rerr
			}
			t.mode, t.relay, t.relayFP, t.id = "relay", *cf.relay, *cf.relayFP, *cf.id
			t.relayToken = rt
		} else {
			t.mode, t.addr = "direct", *cf.addr
		}
	}
	if t.fp == "" && !t.insecure && !t.skipEnc {
		return nil, fmt.Errorf("agent fingerprint required (--fingerprint or --to); or pass --insecure-skip-fingerprint to skip verification, or --insecure-skip-encryption for a plaintext session")
	}
	if t.mode == "relay" {
		// --insecure-skip-fingerprint drops the fingerprint requirement; the relay token and id are
		// still needed to reach the right agent through the relay.
		if t.relay == "" || t.relayToken == "" || t.id == "" || (t.relayFP == "" && !t.insecure) {
			return nil, fmt.Errorf("relay mode needs --relay, --relay-fingerprint, --relay-token (or TERN_RELAY_TOKEN) and --id")
		}
	} else if t.addr == "" {
		return nil, fmt.Errorf("direct mode needs --addr (or use --to / --relay)")
	}
	return t, nil
}

func (t *target) dial(ctx context.Context, idOverride string) (*tern.Client, error) {
	id := t.id
	if idOverride != "" {
		id = idOverride
	}
	var transport net.Conn
	var err error
	if t.mode == "relay" {
		slog.Debug("dialing agent through relay", "relay", t.relay, "id", id)
		transport, err = tern.RelayDialClient(ctx, t.relay, t.relayFP, t.relayToken, id, t.insecure)
	} else {
		slog.Debug("dialing agent", "addr", t.addr)
		transport, err = (&net.Dialer{Timeout: tern.DialTimeout}).DialContext(ctx, "tcp", t.addr)
	}
	if err != nil {
		return nil, err
	}
	if t.skipEnc {
		return tern.Dial(transport, nil, t.key, t.token) // plaintext end-to-end
	}
	return tern.Dial(transport, tern.ClientTLSConfig(t.fp, t.insecure), t.key, t.token)
}

func mustTarget(cf *connFlags) *target {
	t, err := cf.target()
	if err != nil {
		log.Fatal(err)
	}
	switch {
	case t.skipEnc:
		log.Print("WARNING: --insecure-skip-encryption runs the session in PLAINTEXT with no TLS; everything, including the auth exchange, is sent in cleartext and can be read or altered in transit. Use only for testing.")
	case t.insecure:
		log.Print("WARNING: --insecure-skip-fingerprint skips TLS fingerprint verification; the agent and relay are NOT authenticated and the connection can be intercepted (man-in-the-middle). Use only for testing.")
	}
	// Load the key up front: an encrypted key asks for its passphrase once,
	// here on a normal terminal, and every later dial (shell reconnects, each
	// REST request) reuses it.
	if t.key != "" {
		if err := tern.PreloadKey(t.key); err != nil {
			log.Fatal(err)
		}
	}
	return t
}

func dialOrDie(cf *connFlags) *tern.Client {
	cl, err := mustTarget(cf).dial(context.Background(), "")
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	return cl
}

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// --- subcommands ---

func cmdConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	cf := addConnFlags(fs)
	session := fs.String("session", "", "session name (for resume/share)")
	attach := fs.Bool("attach", false, "attach to an existing session (fail if absent)")
	newSess := fs.Bool("new", false, "create a new session (fail if it exists)")
	readOnly := fs.Bool("read-only", false, "join an existing session without input (viewer)")
	noReconnect := fs.Bool("no-reconnect", false, "do not auto-reconnect if the connection drops")
	var locals, remotes stringSlice
	fs.Var(&locals, "L", "local forward [lhost:]lport:rhost:rport (repeatable)")
	fs.Var(&remotes, "R", "remote forward [rbind:]rport:lhost:lport (repeatable)")
	verbose := addVerbose(fs)
	tern.Aliases(fs, map[string]string{"session": "s", "attach": "A", "new": "n", "read-only": "V", "no-reconnect": "N"})
	tern.SetUsage(fs, "tern connect [conn] [flags] - interactive shell (-L/-R forwards)")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	rejectArgs(fs)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)

	t := mustTarget(cf)
	if *attach && *newSess {
		log.Fatal("--attach and --new are mutually exclusive")
	}
	mode := "auto"
	if *attach {
		mode = "attach"
	} else if *newSess {
		mode = "new"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Port forwards run on their own connection (they are not auto-reconnected).
	// A forward that ends while the shell runs is reported (with \r\n: the
	// terminal is raw); once the shell is over, closing them is not news.
	if len(locals)+len(remotes) > 0 {
		fcl, err := t.dial(context.Background(), "")
		if err != nil {
			log.Fatalf("connect: %v", err)
		}
		quitting := make(chan struct{})
		defer fcl.Close()
		defer close(quitting) // runs first, before fcl.Close ends the forwards
		report := func(spec string, err error) {
			select {
			case <-quitting:
			default:
				fmt.Fprintf(os.Stderr, "\r\n[tern] %s: %v\r\n", spec, err)
			}
		}
		for _, spec := range locals {
			listen, dial, err := parseLocalForward(spec)
			if err != nil {
				log.Fatalf("-L %s: %v", spec, err)
			}
			go func() { report("-L "+spec, fcl.ForwardLocal(listen, dial)) }()
		}
		for _, spec := range remotes {
			bind, to, err := parseRemoteForward(spec)
			if err != nil {
				log.Fatalf("-R %s: %v", spec, err)
			}
			go func() { report("-R "+spec, fcl.ForwardRemote(bind, to)) }()
		}
	}

	write, coDrive := tern.ResolveWriteMode(fs, *readOnly)

	dialFn := func(ctx context.Context) (*tern.Client, error) { return t.dial(ctx, "") }
	if err := tern.RunReconnectingShell(ctx, dialFn, *session, mode, write, coDrive, !*noReconnect); err != nil {
		log.Fatalf("shell: %v", err)
	}
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cf := addConnFlags(fs)
	verbose := addVerbose(fs)
	tern.SetUsage(fs, "tern run [conn] -- CMD [ARGS...] - run a command")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)
	cmd := fs.Args()
	if len(cmd) == 0 {
		log.Fatal("usage: tern run [conn] -- CMD [ARGS...]")
	}
	cl := dialOrDie(cf)
	defer cl.Close()
	code, err := cl.Exec(cmd)
	if err != nil {
		log.Fatalf("run: %v", err)
	}
	os.Exit(code)
}

func cmdForward(args []string) {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	cf := addConnFlags(fs)
	var locals, remotes stringSlice
	fs.Var(&locals, "L", "local forward [lhost:]lport:rhost:rport (repeatable)")
	fs.Var(&remotes, "R", "remote forward [rbind:]rport:lhost:lport (repeatable)")
	verbose := addVerbose(fs)
	tern.SetUsage(fs, "tern forward [conn] (-L spec | -R spec) - port forwarding only")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	rejectArgs(fs)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)
	if len(locals)+len(remotes) == 0 {
		log.Fatal("give at least one -L or -R")
	}
	cl := dialOrDie(cf)
	defer cl.Close()

	// Forwards run until one of them fails (a bind error, the agent refusing
	// an -R listener, or the connection dropping); that ends the command.
	errc := make(chan error, len(locals)+len(remotes))
	for _, spec := range locals {
		listen, dial, err := parseLocalForward(spec)
		if err != nil {
			log.Fatalf("-L %s: %v", spec, err)
		}
		log.Printf("-L %s -> agent %s", listen, dial)
		go func() { errc <- fmt.Errorf("-L %s: %w", spec, cl.ForwardLocal(listen, dial)) }()
	}
	for _, spec := range remotes {
		bind, to, err := parseRemoteForward(spec)
		if err != nil {
			log.Fatalf("-R %s: %v", spec, err)
		}
		log.Printf("-R agent %s -> %s", bind, to)
		go func() { errc <- fmt.Errorf("-R %s: %w", spec, cl.ForwardRemote(bind, to)) }()
	}
	log.Fatal(<-errc)
}

func cmdCopy(args []string) {
	fs := flag.NewFlagSet("cp", flag.ExitOnError)
	cf := addConnFlags(fs)
	verbose := addVerbose(fs)
	tern.SetUsage(fs, "tern cp [conn] SRC DST - copy files (prefix remote with agent:)")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)
	rest := fs.Args()
	if len(rest) != 2 {
		log.Fatal("usage: tern cp [conn] SRC DST  (prefix the remote side with agent:)")
	}
	src, dst := rest[0], rest[1]
	cl := dialOrDie(cf)
	defer cl.Close()

	switch {
	case strings.HasPrefix(src, "agent:"):
		remote := strings.TrimPrefix(src, "agent:")
		// Into a directory, as cp and scp do: dl/ or an existing dir keeps the name.
		if fi, err := os.Stat(dst); dst != "" && (os.IsPathSeparator(dst[len(dst)-1]) || err == nil && fi.IsDir()) {
			name := remoteBase(remote)
			if name == "" {
				log.Fatalf("cp: %q names no file to copy", remote)
			}
			dst = filepath.Join(dst, name)
		}
		if err := cl.CopyFrom(remote, dst); err != nil {
			log.Fatalf("cp: %v", err)
		}
	case strings.HasPrefix(dst, "agent:"):
		remote := strings.TrimPrefix(dst, "agent:")
		// agent:/dir/ (or C:\dir\ on Windows) keeps the local name. The agent
		// cannot tell this client's file name, so the client adds it.
		if remote != "" && (remote[len(remote)-1] == '/' || remote[len(remote)-1] == '\\') {
			remote += filepath.Base(src)
		}
		if err := cl.CopyTo(src, remote); err != nil {
			log.Fatalf("cp: %v", err)
		}
	default:
		log.Fatal("one of SRC or DST must be agent:PATH")
	}
}

// remoteBase is the last name in an agent path, which may use / or \\.
func remoteBase(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	if p == "." || p == ".." {
		return ""
	}
	return p
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	cf := addConnFlags(fs)
	verbose := addVerbose(fs)
	tern.SetUsage(fs, "tern list [conn] - list live sessions on the agent")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	rejectArgs(fs)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)
	cl := dialOrDie(cf)
	defer cl.Close()
	names, err := cl.ListSessions()
	if err != nil {
		log.Fatalf("list: %v", err)
	}
	if len(names) == 0 {
		fmt.Println("(no live sessions)")
		return
	}
	for _, n := range names {
		fmt.Println(tern.CleanText(n)) // names come from the agent: strip escape sequences
	}
}

func cmdAPI(args []string) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	cf := addConnFlags(fs)
	apiAddr := fs.String("api-addr", "127.0.0.1:8080", "REST gateway listen address")
	apiToken := fs.String("api-token", "", "REST gateway bearer token, >= 16 chars (prefer TERN_API_TOKEN or --api-token-file)")
	apiTokenFile := fs.String("api-token-file", "", "read the REST gateway bearer token from this file")
	apiTimeout := fs.Duration("api-timeout", 30*time.Second, "timeout for a POST /v1/run that sets none")
	apiMaxTimeout := fs.Duration("api-max-timeout", 10*time.Minute, "cap on the timeout a POST /v1/run may ask for, which is never more than 24h; 0 = no cap but that")
	apiTrustedHosts := fs.String("api-trusted-hosts", "", "comma-separated host names to accept in Host besides loopback and the --api-addr host (for a reverse proxy); a name matches with any port, name:port with that port only; off loopback they turn the Host check on")
	apiInsecure := fs.Bool("api-insecure-no-token", false, "DANGEROUS: run the gateway with NO bearer token, on any address; off loopback that is an unauthenticated remote-exec endpoint open to the network; for testing only")
	var apiAgents stringSlice
	fs.Var(&apiAgents, "api-agent", "relay: another agent a request may name with \"id\", as ID=FINGERPRINT (its id and TLS fingerprint, as ternd prints them; repeatable)")
	verbose := addVerbose(fs)
	tern.Aliases(fs, map[string]string{"api-addr": "A", "api-token": "b", "api-timeout": "d", "api-max-timeout": "m"})
	tern.SetUsage(fs, "tern api [conn] [flags] - REST gateway (exec over HTTP)")
	conn, args := splitLeadingConn(args)
	fs.Parse(args)
	rejectArgs(fs)
	cf.applyConn(conn)
	tern.SetVerbose(*verbose)
	t := mustTarget(cf)
	ids, dial, err := t.apiAgents(apiAgents)
	if err != nil {
		log.Fatal(err)
	}
	tok, apiTokFromFlag, err := tern.ResolveSecret("api-token", *apiToken, *apiTokenFile, "TERN_API_TOKEN")
	if err != nil {
		log.Fatal(err)
	}
	tern.WarnSecretOnArgv(apiTokFromFlag, "api-token", "TERN_API_TOKEN")
	switch {
	case *apiInsecure && tok != "":
		log.Fatal("--api-insecure-no-token runs the gateway with no token; do not also set --api-token")
	case *apiInsecure:
		// Explicit opt-in to a tokenless gateway: do not mint a token, and let
		// Run accept a non-loopback bind. Warn loudly.
		log.Print("WARNING: --api-insecure-no-token runs the REST gateway with NO authentication; any host that can reach it can run commands. Use only for testing.")
	case tok == "":
		// Never run the exec gateway unauthenticated by default: mint a bearer
		// token and print it so the operator can use it, the way ternd mints an
		// agent token. Only for a person at a terminal: run as a service, the
		// token would land in its log.
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			log.Fatal("no REST gateway token: set TERN_API_TOKEN or --api-token-file (tern api makes one up only on a terminal, where it is shown)")
		}
		tok = tern.GenToken()
		fmt.Fprintf(os.Stderr, "\nREST gateway bearer token (none set; generated one):\n  %s\n\n", tok)
	case len(tok) < 16:
		// A short bearer token on a remote-exec endpoint is brute-forceable with
		// no lockout; hold it to the same floor as the agent and relay tokens.
		log.Fatal("the REST gateway token is too short; use at least 16 characters (generate one with: tern genkey)")
	}
	var trusted []string
	for _, h := range strings.Split(*apiTrustedHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			trusted = append(trusted, h)
		}
	}
	g := &tern.Gateway{
		Addr:         *apiAddr,
		Token:        tok,
		Insecure:     *apiInsecure,
		RunTimeout:   *apiTimeout,
		MaxTimeout:   *apiMaxTimeout,
		TrustedHosts: trusted,
		AgentIDs:     ids,
		Dial:         dial,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := g.Run(ctx); err != nil {
		log.Fatalf("api: %v", err)
	}
}

// apiAgentPins maps each relay agent id a gateway request may name to the
// fingerprint it is pinned to: the connection's own agent, and every
// --api-agent ID=FINGERPRINT. Agents keep their own certificates, so one
// gateway pin cannot cover them all, and an id with no fingerprint of its own
// is not reached at all: under another agent's pin it would be reached as
// whoever holds that agent's key. A gateway that reaches its agent directly
// pins no ids.
func apiAgentPins(t *target, specs []string) (map[string]string, error) {
	if t.mode != "relay" {
		if len(specs) > 0 {
			return nil, fmt.Errorf("--api-agent names agents on a relay, but this gateway reaches one agent directly")
		}
		return nil, nil
	}
	if len(specs) > 0 && (t.insecure || t.skipEnc) {
		return nil, fmt.Errorf("--api-agent pins agent fingerprints; it cannot be combined with --insecure-skip-fingerprint or --insecure-skip-encryption, which turn pinning off")
	}
	pins := map[string]string{t.id: normFingerprint(t.fp)}
	for _, s := range specs {
		id, fp, _ := strings.Cut(s, "=")
		fp = normFingerprint(fp)
		if id == "" || len(id) > 256 || len(fp) != 64 || strings.Trim(fp, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("--api-agent %q: want ID=FINGERPRINT, an agent's relay id and the SHA-256 fingerprint ternd prints for it", s)
		}
		if old, ok := pins[id]; ok && old != fp {
			return nil, fmt.Errorf("--api-agent %s: that agent id is already pinned to a different fingerprint", id)
		}
		pins[id] = fp
	}
	return pins, nil
}

// normFingerprint spells a fingerprint the way the pin compares it.
func normFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(fp, ":", ""))
}

// apiAgents returns, for the connection and its --api-agent flags, the agent
// ids a gateway request may name and the gateway's Dial. A request with no id
// reaches the connection's agent, and one with an id reaches that agent pinned
// to its own fingerprint. The gateway refuses an id with no fingerprint before
// it dials; Dial refuses it again rather than fall back to another agent's pin.
func (t *target) apiAgents(specs []string) (ids []string, dial func(id string) (*tern.Client, error), err error) {
	pins, err := apiAgentPins(t, specs)
	if err != nil {
		return nil, nil, err
	}
	for id := range pins {
		ids = append(ids, id)
	}
	return ids, func(id string) (*tern.Client, error) {
		if id == "" {
			return t.dial(context.Background(), "")
		}
		fp, ok := pins[id]
		if !ok {
			return nil, fmt.Errorf("agent id %q has no pinned fingerprint", id)
		}
		pinned := *t
		pinned.fp = fp
		return pinned.dial(context.Background(), id)
	}, nil
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "tern_id_ed25519", "output path for the private key")
	comment := fs.String("comment", defaultKeyComment(), "comment stored in the key")
	verbose := addVerbose(fs)
	tern.Aliases(fs, map[string]string{"out": "o", "comment": "c"})
	tern.SetUsage(fs, "tern keygen [flags] - make an unencrypted OpenSSH Ed25519 key pair")
	fs.Parse(args)
	rejectArgs(fs)
	tern.SetVerbose(*verbose)
	if _, err := os.Stat(*out); err == nil {
		log.Fatalf("refusing to overwrite existing key %q", *out)
	}
	pubLine, err := tern.GenerateKeyFiles(*out, *comment)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	fmt.Printf("wrote private key: %s\nwrote public key:  %s.pub\n\n", *out, *out)
	fmt.Print("add this line to the agent's authorized_keys file:\n", pubLine)
}

func cmdGenkey(args []string) {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	tern.SetUsage(fs, "tern genkey - print a random 32-char token for TERN_TOKEN, TERN_RELAY_TOKEN or TERN_API_TOKEN")
	fs.Parse(args)
	rejectArgs(fs)
	fmt.Println(tern.GenToken())
}

// --- forward spec parsing ---

func parseLocalForward(spec string) (listen, dial string, err error) {
	p := strings.Split(spec, ":")
	switch len(p) {
	case 4:
		return bindHost(p[0]) + ":" + p[1], p[2] + ":" + p[3], nil
	case 3:
		return "127.0.0.1:" + p[0], p[1] + ":" + p[2], nil
	default:
		return "", "", fmt.Errorf("want [lhost:]lport:rhost:rport")
	}
}

func parseRemoteForward(spec string) (bind, to string, err error) {
	p := strings.Split(spec, ":")
	switch len(p) {
	case 4:
		return bindHost(p[0]) + ":" + p[1], p[2] + ":" + p[3], nil
	case 3:
		return "127.0.0.1:" + p[0], p[1] + ":" + p[2], nil
	default:
		return "", "", fmt.Errorf("want [rbind:]rport:lhost:lport")
	}
}

// bindHost defaults an empty forward bind host to loopback, so ":port:..." does
// not silently listen on every interface. An explicit host (including 0.0.0.0)
// is left as the caller's deliberate choice.
func bindHost(h string) string {
	if h == "" {
		return "127.0.0.1"
	}
	return h
}

func defaultKeyComment() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	host, _ := os.Hostname()
	if user != "" && host != "" {
		return user + "@" + host
	}
	return "tern"
}
