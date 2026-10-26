# Features

- **Direct or relay.** Reach an agent on your LAN directly, or through a relay
  so an agent behind NAT can be reached with no inbound ports.
- **End-to-end encryption through the relay.** The relay is an opaque
  byte-pipe; the inner TLS + auth run between client and agent, so the relay
  never sees shell plaintext and cannot impersonate an agent.
- **Two auth methods.** The agent enables at least one and the client picks
  one: OpenSSH **public keys** in `authorized_keys` format, or a shared
  **token**. `tern keygen` makes Ed25519 keys that OpenSSH tools accept, and
  Ed25519, ECDSA or RSA keys (1024 to 8192 bits) from `ssh-keygen` work as
  client keys; DSA and security keys (`sk-*`) do not. Prefer Ed25519: logins
  with P-384, P-521 or RSA keys over 3072 bits can be held up by a flood of
  unauthenticated attempts from many networks (see
  [SECURITY.md](../SECURITY.md)).
- **Session resume & multi-client share.** Sessions are named and outlive a
  connection: reconnect and resume with scrollback replay, or have several
  clients attach to one session (by default one writer + read-only viewers).
- **Auto-reconnect.** `tern connect` keeps the terminal in raw mode across
  drops and re-attaches to the same session automatically until the remote
  shell exits; a writer gets its seat back even before the agent notices that
  the old connection died. Press Ctrl-C while it is reconnecting to give up,
  or turn it off with `--no-reconnect`.
- **Multiplexed channels** (yamux): one authenticated connection can carry an
  interactive shell, `exec`, local (`-L`) and remote (`-R`) port forwards and
  file copy at once.
- **REST gateway** for running commands over HTTP, including stdin and
  long-running ones (simple, streaming and async-job modes).
- **AI agents over MCP**. `tern mcp` serves your agents to AI
  clients with a read-only default, per-host policy profiles, approval prompts
  for chosen actions, redaction of known secrets, an audit log, and terminals a
  person can watch live or take over.
- **Session recording.** The agent can record each session as an asciicast
  (`ternd --record-dir DIR`), playable with `asciinema play`.
- **Zero-config.** Run `ternd` with no flags on a terminal and it mints an
  ephemeral token and prints a ready-to-paste `tern connect` line (as a
  service it asks for `TERN_TOKEN`, `--token-file` or `--authorized-keys`
  instead).
- **Operable.** Logs go to stderr (`-v`/`--verbose` or `TERN_LOG=debug` for
  debug detail), and SIGINT/SIGTERM stop the servers cleanly.
- **Portable.** Linux, macOS, Windows and Android on amd64 and arm64; every
  target builds without cgo except android/amd64.
