// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Command ternd is the Ternimal agent: it hosts interactive shells, commands,
// port forwards and file copy for authenticated clients that pin its TLS
// certificate, listening directly or registering with a relay (ternr or rtern)
// for reach through NAT.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	tern "github.com/ternimal/tern/internal/tern"
	"golang.org/x/term"
)

// version is set at build time via -ldflags "-X main.version=..."; see
// tern.ResolveVersion for builds that do not set it.
var version = "dev"

// killWait bounds how long ternd, shutting down, lets the kills of commands
// under way finish (see tern.WaitKills).
const killWait = 5 * time.Second

func main() {
	version = tern.ResolveVersion(version)
	log.SetFlags(0)
	log.SetPrefix("ternd: ")
	tern.SetupLogging()

	fs := flag.NewFlagSet("ternd", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:2222", "direct: listen address host:port")
	shell := fs.String("shell", defaultShell(), "shell to spawn for each session: $SHELL, else /bin/sh; %ComSpec% on Windows")
	certPath := fs.String("cert", "ternd-agent", "path prefix for the agent's TLS cert/key (.crt/.key), created if missing")
	tokenFlag := fs.String("token", "", "token-auth secret, >= 16 chars (prefer TERN_TOKEN or --token-file)")
	tokenFile := fs.String("token-file", "", "read the token-auth secret from this file")
	authKeys := fs.String("authorized-keys", "", "OpenSSH authorized_keys file (enables public-key auth; per-key options are not supported)")
	idle := fs.Duration("session-idle", 10*time.Minute, "keep a session alive this long after its last client leaves (0 = until the shell exits)")
	recordDir := fs.String("record-dir", "", "if set, record each session as an asciicast (.cast) file in this directory")
	skipEnc := fs.Bool("insecure-skip-encryption", false, "DANGEROUS: take only plaintext connections, with no TLS, from clients using --insecure-skip-encryption or --insecure-dangerous; the whole session, including auth, runs in cleartext; for testing only")
	dangerous := fs.Bool("insecure-dangerous", false, "DANGEROUS: shorthand that turns off all transport security on this side (implies --insecure-skip-encryption, and in relay mode without --relay-fingerprint also skips verifying the relay; a --relay-fingerprint given is still checked, and the hop to the relay keeps its TLS); for testing only")

	relayAddr := fs.String("relay", "", "relay: relay address host:port (ternr or rtern)")
	relayFP := fs.String("relay-fingerprint", "", "relay: relay TLS SHA-256 fingerprint")
	relayTok := fs.String("relay-token", "", "relay: relay token, >= 16 chars (prefer TERN_RELAY_TOKEN or --relay-token-file)")
	relayTokFile := fs.String("relay-token-file", "", "relay: read the relay token from this file")
	id := fs.String("id", "", "relay: this agent's id that clients connect to")
	verbose := fs.Bool("verbose", false, "verbose (debug) logging")
	showVersion := fs.Bool("version", false, "print version and exit")
	tern.Alias(fs, "verbose", "v")
	tern.Aliases(fs, map[string]string{
		"addr": "a", "shell": "s", "cert": "c", "token": "t",
		"authorized-keys": "A", "session-idle": "S", "record-dir": "R",
		"relay": "r", "relay-fingerprint": "F", "relay-token": "T", "id": "i",
	})
	tern.SetUsage(fs, "ternd - Ternimal agent: hosts sessions for authenticated clients")
	fs.Parse(os.Args[1:])
	if *showVersion || fs.Arg(0) == "version" {
		fmt.Printf("ternd %s\n", version)
		return
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ternd: unexpected argument %q\n\n", fs.Arg(0))
		fs.Usage()
		os.Exit(2)
	}
	tern.SetVerbose(*verbose)

	fmt.Fprintln(os.Stderr, tern.Banner(version))

	token, tokenFromFlag, err := tern.ResolveSecret("token", *tokenFlag, *tokenFile, "TERN_TOKEN")
	if err != nil {
		log.Fatal(err)
	}
	tern.WarnSecretOnArgv(tokenFromFlag, "token", "TERN_TOKEN")
	if token != "" && len(token) < 16 {
		log.Fatal("refusing to start: the token is too short; use at least 16 characters (generate one with: tern genkey)")
	}
	ac := &tern.AuthConfig{Token: token}
	if *authKeys != "" {
		keys, kerr := tern.LoadAuthorizedKeys(*authKeys)
		if kerr != nil {
			log.Fatalf("authorized keys: %v", kerr)
		}
		ac.Keys = keys
	}
	// The connect line is printed with the token in TERN_TOKEN=... env form so a
	// copy-paste keeps it out of the client's argv. The real token is shown only
	// when ternd generated it; a supplied one stays a placeholder.
	connectPrefix, connectSuffix := "TERN_TOKEN=<your-token> ", ""
	if ac.PubkeyEnabled() {
		connectPrefix, connectSuffix = "", " --key <your-key>"
	}
	if !ac.TokenEnabled() && !ac.PubkeyEnabled() {
		// zero-config: generate a strong ephemeral token so `ternd` just runs,
		// shown in the connect command below. Only for a person at a
		// terminal: run as a service, the line would put a live credential in
		// its log, and the token would change at every restart anyway.
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			log.Fatal("no auth configured: set TERN_TOKEN, --token-file or --authorized-keys (ternd makes up a token only on a terminal, where it is shown)")
		}
		ac.Token = tern.GenToken()
		connectPrefix = "TERN_TOKEN=" + ac.Token + " "
		log.Printf("no auth configured; using an ephemeral token (shown in the connect command below)")
	}

	cert, err := tern.LoadOrCreateCert(*certPath)
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}
	fp := tern.CertFingerprint(cert)
	agent := tern.NewAgent(tern.ServerTLSConfig(cert), ac, *shell, *idle, *recordDir)
	plaintext := *skipEnc || *dangerous
	agent.Plaintext = plaintext
	if plaintext {
		log.Print("WARNING: accepting PLAINTEXT connections with no TLS; the whole session, including the auth exchange, runs in cleartext and can be read or altered in transit. Use only for testing.")
	}

	log.Printf("shell: %s; auth: %s", *shell, strings.Join(ac.Methods(), ", "))
	if *recordDir != "" {
		log.Printf("recording sessions to %s", *recordDir)
	}
	log.Printf("agent fingerprint: %s", fp)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *relayAddr != "" {
		rt, rtFromFlag, rerr := tern.ResolveSecret("relay-token", *relayTok, *relayTokFile, "TERN_RELAY_TOKEN")
		if rerr != nil {
			log.Fatal(rerr)
		}
		tern.WarnSecretOnArgv(rtFromFlag, "relay-token", "TERN_RELAY_TOKEN")
		if rt == "" || *id == "" || (*relayFP == "" && !*dangerous) {
			log.Fatal("relay mode needs --relay-fingerprint, --relay-token (or TERN_RELAY_TOKEN) and --id")
		}
		if err := tern.CheckRelayToken(rt); err != nil {
			log.Fatal(err)
		}
		if err := tern.CheckRelayID(*id); err != nil {
			log.Fatalf("--id: %v", err)
		}
		cs := tern.ConnString{Mode: "relay", Relay: *relayAddr, RelayFP: *relayFP, RelayToken: rt, ID: *id, FP: fp}
		printConnect(os.Stderr, "connect through the relay (ternr) with", connectPrefix, cs, connectSuffix, plaintext)
		log.Printf("connecting to relay %s as id %q", *relayAddr, *id)
		agent.ServeRelay(ctx, *relayAddr, *relayFP, rt, *id, *dangerous)
		log.Print("shutting down")
		tern.WaitKills(killWait)
		return
	}

	ln, lerr := tern.ListenTCP(*addr)
	if lerr != nil {
		log.Fatalf("listen: %v", lerr)
	}
	log.Printf("listening (direct) on %s", *addr)
	printConnect(os.Stderr, "connect with", connectPrefix, tern.ConnString{Mode: "direct", Addr: dialableAddr(*addr), FP: fp}, connectSuffix, plaintext)
	agent.ServeListener(ctx, ln)
	log.Print("shutting down")
	tern.WaitKills(killWait)
}

// printConnect writes the copy-paste connection line as plain text (not slog),
// so it is easy to grab from the terminal. prefix carries any TERN_TOKEN=...
// env assignment (so a token stays off the client's argv) and suffix carries a
// --key placeholder; the token is real only when ternd generated it, which it
// does only on a terminal. The relay token is always the operator's, so it is
// never printed, only a placeholder: this line can end up in a service log.
// Values from the command line are quoted for a POSIX shell where they need
// it, so the line means the same when pasted.
func printConnect(w io.Writer, title, prefix string, cs tern.ConnString, suffix string, plaintext bool) {
	if cs.Mode == "relay" {
		prefix = "TERN_RELAY_TOKEN=<relay-token> " + prefix
		cs.RelayToken = ""
		if plaintext {
			// Plaintext cannot use the tern1: string (it pins the agent cert),
			// so print explicit flags.
			relayFP := "--insecure-skip-encryption --relay-fingerprint " + tern.ShellQuote(cs.RelayFP)
			if cs.RelayFP == "" { // --insecure-dangerous: the relay is not pinned either
				relayFP = "--insecure-dangerous"
			}
			fmt.Fprintf(w, "\n%s:\n  %stern connect %s --relay %s --id %s%s\n\n",
				title, prefix, relayFP, tern.ShellQuote(cs.Relay), tern.ShellQuote(cs.ID), suffix)
			return
		}
	}
	if plaintext {
		fmt.Fprintf(w, "\n%s:\n  %stern connect --insecure-skip-encryption --addr %s%s\n\n", title, prefix, tern.ShellQuote(cs.Addr), suffix)
		return
	}
	fmt.Fprintf(w, "\n%s:\n  %stern connect --to %s%s\n\n", title, prefix, cs.Encode(), suffix)
}

// dialableAddr turns a listen address into one a client can dial: a wildcard
// bind host (0.0.0.0, ::, empty) becomes 127.0.0.1 so the printed connect
// command works as-is on the same machine.
func dialableAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		if cs := os.Getenv("ComSpec"); cs != "" {
			return cs
		}
		return "cmd.exe"
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	return "/bin/sh"
}
