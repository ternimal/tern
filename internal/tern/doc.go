// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Package tern is the shared core of Ternimal, a minimal, portable, secure
// remote terminal. It implements the roles the cmd/ binaries wrap: the client
// (tern), the agent that hosts sessions (ternd), the relay that bridges clients
// to agents behind NAT (ternr), and the combined relay + client (rtern).
// Client-agent traffic is TLS with the agent's certificate pinned by SHA-256
// fingerprint, and every connection authenticates with an OpenSSH public key
// or a token.
//
// The protocol, auth and client compile for every released target (linux,
// macOS, windows, android) and for iOS. Hosting a shell (the agent side) needs
// a real PTY and process exec, which iOS forbids; that part lives behind
// spawnShell (see shell_pty.go / shell_stub.go).
package tern
