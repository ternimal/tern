// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Command rtern is the Ternimal combined relay + client: it listens for an
// agent (ternd) that dials out to it, then drops you straight into an
// interactive shell on that agent. It is the one-process form of
// "ternr + tern" for the reverse topology where the agent cannot be reached
// directly:
//
//	[ternd] ==> [rtern]
//
// Auth stays end-to-end: rtern pins the agent's TLS fingerprint and
// authenticates with a key or token, exactly like `tern connect`.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	tern "github.com/ternimal/tern/internal/tern"
)

// version is set at build time via -ldflags "-X main.version=..."; see
// tern.ResolveVersion for builds that do not set it.
var version = "dev"

func main() {
	version = tern.ResolveVersion(version)
	log.SetFlags(0)
	log.SetPrefix("rtern: ")
	tern.SetupLogging()

	fs := flag.NewFlagSet("rtern", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:7000", "listen address host:port for agents to dial")
	certPath := fs.String("cert", "rtern-relay", "path prefix for the relay's TLS cert/key (.crt/.key), created if missing")
	relayTok := fs.String("relay-token", "", "relay token, >= 16 chars (prefer TERN_RELAY_TOKEN or --relay-token-file); generated if empty")
	relayTokFile := fs.String("relay-token-file", "", "read the relay token from this file")
	id := fs.String("id", "", "agent id to catch (empty = the first agent that dials in)")
	fp := fs.String("fingerprint", "", "agent TLS SHA-256 fingerprint to pin (required)")
	keyFile := fs.String("key", "", "OpenSSH private key for public-key auth")
	tokenFlag := fs.String("token", "", "token-auth secret (prefer TERN_TOKEN or --token-file)")
	tokenFile := fs.String("token-file", "", "read the token-auth secret from this file")
	session := fs.String("session", "", "session name (for resume/share)")
	attach := fs.Bool("attach", false, "attach to an existing session (fail if absent)")
	newSess := fs.Bool("new", false, "create a new session (fail if it exists)")
	readOnly := fs.Bool("read-only", false, "join an existing session without input (viewer)")
	noReconnect := fs.Bool("no-reconnect", false, "do not auto-reconnect (wait for the agent to re-dial) if the connection drops")
	insecure := fs.Bool("insecure-skip-fingerprint", false, "DANGEROUS: skip the agent TLS fingerprint check, so the agent is not authenticated and the connection can be intercepted; for testing only")
	skipEnc := fs.Bool("insecure-skip-encryption", false, "DANGEROUS: run the session with no TLS of its own (the agent must also run in plaintext: --insecure-skip-encryption or --insecure-dangerous), so the agent is not authenticated: anyone with the relay token can pose as it, see what you type and decide what you see (the agent's connection to rtern keeps its TLS); for testing only")
	dangerous := fs.Bool("insecure-dangerous", false, "DANGEROUS: shorthand for --insecure-skip-fingerprint plus --insecure-skip-encryption; turns off the session's TLS and the check of the agent's certificate, so the agent is not authenticated (the token or key is still required, and its proof is bound to nothing); for testing only")
	verbose := fs.Bool("verbose", false, "verbose (debug) logging")
	showVersion := fs.Bool("version", false, "print version and exit")
	tern.Alias(fs, "verbose", "v")
	tern.Aliases(fs, map[string]string{
		"addr": "a", "cert": "c", "relay-token": "T", "id": "i",
		"fingerprint": "f", "key": "k", "token": "t", "session": "s",
		"attach": "A", "new": "n", "read-only": "V", "no-reconnect": "N",
	})
	tern.SetUsage(fs, "rtern - Ternimal combined relay + client: catches an agent that dials in")
	fs.Parse(os.Args[1:])
	if *showVersion || fs.Arg(0) == "version" {
		fmt.Printf("rtern %s\n", version)
		return
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "rtern: unexpected argument %q\n\n", fs.Arg(0))
		fs.Usage()
		os.Exit(2)
	}
	tern.SetVerbose(*verbose)

	if *dangerous { // the master switch turns on both of the specific flags
		*insecure, *skipEnc = true, true
	}
	if (*insecure || *skipEnc) && *fp != "" {
		log.Fatal("--insecure-skip-fingerprint, --insecure-skip-encryption and --insecure-dangerous cannot be combined with --fingerprint")
	}
	if *fp == "" && !*insecure && !*skipEnc {
		log.Fatal("--fingerprint (the agent's TLS fingerprint) is required (or pass --insecure-skip-fingerprint to skip verification, or --insecure-skip-encryption for a plaintext session)")
	}
	switch {
	case *skipEnc:
		log.Print("WARNING: --insecure-skip-encryption runs the session in PLAINTEXT with no TLS of its own; the agent must also run in plaintext (--insecure-skip-encryption or --insecure-dangerous), and it is NOT authenticated: anyone with the relay token can pose as it, see what you type and decide what you see. Use only for testing.")
	case *insecure:
		log.Print("WARNING: --insecure-skip-fingerprint skips the agent TLS fingerprint check; the agent is NOT authenticated and the connection can be intercepted. Use only for testing.")
	}
	if *attach && *newSess {
		log.Fatal("--attach and --new are mutually exclusive")
	}
	if *id != "" {
		if err := tern.CheckRelayID(*id); err != nil {
			log.Fatalf("--id: %v", err)
		}
	}
	token, tokenFromFlag, err := tern.ResolveSecret("token", *tokenFlag, *tokenFile, "TERN_TOKEN")
	if err != nil {
		log.Fatal(err)
	}
	tern.WarnSecretOnArgv(tokenFromFlag, "token", "TERN_TOKEN")
	if *keyFile == "" && token == "" {
		log.Fatal("provide --key or --token (or TERN_TOKEN) to authenticate to the agent")
	}
	// Load the key now, before the terminal goes raw, so an encrypted key can
	// ask for its passphrase; every later dial (reconnects too) reuses it.
	if *keyFile != "" {
		if err := tern.PreloadKey(*keyFile); err != nil {
			log.Fatal(err)
		}
	}
	// The printed agent command shows a real secret only when rtern made it
	// up; secrets you supplied stay placeholders.
	relayToken, rtFromFlag, err := tern.ResolveSecret("relay-token", *relayTok, *relayTokFile, "TERN_RELAY_TOKEN")
	if err != nil {
		log.Fatal(err)
	}
	tern.WarnSecretOnArgv(rtFromFlag, "relay-token", "TERN_RELAY_TOKEN")
	shownRelayToken := "<relay-token>" // a supplied token stays a placeholder in the printed command
	switch {
	case relayToken == "":
		relayToken = tern.GenToken()
		shownRelayToken = relayToken
		log.Printf("no relay token set; generated an ephemeral one (shown below)")
	default:
		if err := tern.CheckRelayToken(relayToken); err != nil {
			log.Fatal(err)
		}
	}
	// The printed command puts both tokens in env form so they stay off the
	// agent's argv. The relay token is real only when rtern generated it.
	envPrefix := "TERN_RELAY_TOKEN=" + shownRelayToken + " "
	authFlags := ""
	if *keyFile != "" {
		authFlags = " --authorized-keys <file-with-your-public-key>"
	} else {
		envPrefix += "TERN_TOKEN=<your-token> "
	}

	cert, err := tern.LoadOrCreateCert(*certPath)
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}
	serverTLS := tern.ServerTLSConfig(cert)
	relayFP := tern.CertFingerprint(cert)

	ln, err := tern.ListenTCP(*addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	log.Printf("version %s, listening on %s", version, *addr)
	log.Printf("relay fingerprint: %s", relayFP)
	catchID := *id
	if catchID == "" {
		catchID = "box1"
	}
	fmt.Fprintf(os.Stderr, "\nrun the agent so it dials here:\n  %sternd --relay %s --relay-fingerprint %s --id %s%s\n\nwaiting for the agent to connect...\n\n",
		envPrefix, advertiseAddr(*addr), relayFP, catchID, authFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	mode := "auto"
	if *attach {
		mode = "attach"
	} else if *newSess {
		mode = "new"
	}
	write, coDrive := tern.ResolveWriteMode(fs, *readOnly)
	// One Catcher for the whole run, so the spare registration the agent makes
	// after each pairing waits here and a reconnect pairs it at once.
	catcher := tern.NewCatcher(ctx, ln, serverTLS, relayToken, *id)
	dial := func(c context.Context) (*tern.Client, error) {
		return catcher.Catch(c, *fp, *keyFile, token, *insecure, *skipEnc)
	}
	if err := tern.RunReconnectingShell(ctx, dial, *session, mode, write, coDrive, !*noReconnect); err != nil {
		log.Fatalf("%v", err)
	}
}

// advertiseAddr turns a wildcard listen address into a placeholder host so the
// printed agent command is obviously meant to point at rtern's reachable IP.
// A real address is quoted for a POSIX shell where it needs it.
func advertiseAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return tern.ShellQuote(addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort("<rtern-host>", port)
	}
	return tern.ShellQuote(net.JoinHostPort(host, port))
}
