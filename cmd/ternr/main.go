// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Command ternr is the Ternimal relay: a public rendezvous that bridges clients
// to agents behind NAT/firewalls. It forwards opaque bytes only: the client and
// agent run their own end-to-end TLS + auth through it, so the relay never sees
// shell plaintext and cannot impersonate an agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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
	log.SetPrefix("ternr: ")
	tern.SetupLogging()

	fs := flag.NewFlagSet("ternr", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:7000", "listen address host:port")
	certPath := fs.String("cert", "ternr-relay", "path prefix for the relay's TLS cert/key (.crt/.key), created if missing")
	tokenFlag := fs.String("token", "", "relay token, >= 16 chars (prefer TERN_RELAY_TOKEN or --token-file)")
	tokenFile := fs.String("token-file", "", "read the relay token from this file")
	verbose := fs.Bool("verbose", false, "verbose (debug) logging")
	showVersion := fs.Bool("version", false, "print version and exit")
	tern.Alias(fs, "verbose", "v")
	tern.Aliases(fs, map[string]string{"addr": "a", "cert": "c", "token": "t"})
	tern.SetUsage(fs, "ternr - Ternimal relay: bridges clients to agents behind NAT")
	fs.Parse(os.Args[1:])
	if *showVersion || fs.Arg(0) == "version" {
		fmt.Printf("ternr %s\n", version)
		return
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ternr: unexpected argument %q\n\n", fs.Arg(0))
		fs.Usage()
		os.Exit(2)
	}
	tern.SetVerbose(*verbose)
	log.Printf("version %s", version)

	token, tokenFromFlag, err := tern.ResolveSecret("token", *tokenFlag, *tokenFile, "TERN_RELAY_TOKEN")
	if err != nil {
		log.Fatal(err)
	}
	tern.WarnSecretOnArgv(tokenFromFlag, "token", "TERN_RELAY_TOKEN")
	if token == "" {
		log.Fatal("a relay token of at least 16 characters is required " +
			"(set TERN_RELAY_TOKEN, --token-file or --token; generate one with: tern genkey)")
	}
	if err := tern.CheckRelayToken(token); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := tern.RunRelay(ctx, *addr, *certPath, token); err != nil {
		log.Fatalf("%v", err)
	}
	log.Print("shutting down")
}
