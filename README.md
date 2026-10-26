# Ternimal

```
+------------------------------------------------------------------+
| \\\_\                                                            |
| \\\( ^>     t e r n                                              |
|  \\\=/      A minimal, portable, secure remote terminal with MCP |
|  ~~~~~                                                           |
+------------------------------------------------------------------+
```

[![release](https://img.shields.io/github/v/release/ternimal/tern)](https://github.com/ternimal/tern/releases/latest)
[![CI](https://github.com/ternimal/tern/actions/workflows/ci.yml/badge.svg)](https://github.com/ternimal/tern/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)

**Ternimal** (*terminal* + *minimal*) is a minimal, portable, secure remote
terminal: SSH-style shells, command exec, port forwarding and file copy over
end-to-end TLS, reached directly or through a relay for NAT traversal. One
project, four small binaries:

| binary | role |
|--------|------|
| `tern`  | **client**: shells, exec, port forwarding, file copy, REST gateway, MCP server for AI agents |
| `ternd` | **agent**: hosts sessions for authenticated clients; listens directly or dials a relay |
| `ternr` | **relay**: bridges clients to agents behind NAT; a public rendezvous that only forwards opaque bytes |
| `rtern` | **combined relay + client**: catches an agent that dials in and drops you into its shell; one process instead of `ternr` + `tern` |

Client-to-agent traffic is end-to-end TLS (clients pin the agent's certificate)
and authentication to the agent is mandatory. This is an administration tool,
not a stealth tool: connections are logged and the agent has no
unauthenticated mode. Only use it on systems you own or are authorized to
access.

## Installation

Download the zip for your OS and architecture from the
[latest release](https://github.com/ternimal/tern/releases/latest), check it
against `SHA256SUMS` and, with the [GitHub CLI](https://cli.github.com), its
build provenance attestation, and put the four binaries on your `PATH`:

```bash
curl -LO https://github.com/ternimal/tern/releases/latest/download/ternimal-linux-amd64.zip
curl -LO https://github.com/ternimal/tern/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify ternimal-linux-amd64.zip -R ternimal/tern
mkdir -p ~/.local/bin
unzip ternimal-linux-amd64.zip tern ternd ternr rtern -d ~/.local/bin
```

Or build them with Go 1.21 or later:

```bash
go install github.com/ternimal/tern/cmd/...@latest
```

Notes for macOS and Windows, building from source and the supported platforms
are in [docs/install.md](docs/install.md).

## Quick start

```bash
# agent: zero-config, listens on port 2222 on every IPv4 and IPv6 address,
# mints a token, prints its fingerprint
ternd

# client: connect by IP with the agent's fingerprint and token
TERN_TOKEN=<token> tern connect -a AGENT_IP:2222 -f <agent-fp>
```

![tern connecting directly to ternd](docs/demo/direct.gif)

[Getting started](docs/getting-started.md) also covers reaching an agent
behind NAT through a relay, catching one with `rtern` and logging in with
OpenSSH keys instead of a token.

## AI agents (`tern mcp`)

`tern mcp` lets an AI client such as Claude Code, Claude Desktop or Cursor work
on your agents through the
[Model Context Protocol](https://modelcontextprotocol.io), under a policy you
set and with an audit log of every call. It is read-only by default, and asks
you before the actions you choose.

In Claude Code, install tern first, then the Ternimal plugin:

```bash
claude plugin marketplace add ternimal/tern
claude plugin install ternimal@ternimal
```

The plugin starts `tern` from your `PATH` and reads your hosts from a config
file, `~/.config/tern/mcp.json` by default; its `ternimal:setup` skill walks
you through writing one. [plugin/README.md](plugin/README.md) says what it
runs and what it sends. Other clients, a one-line setup without a config
file, the tools and the safety model are in [docs/mcp.md](docs/mcp.md).

## Features

- **Direct or relay**: reach an agent on your LAN directly, or reach one behind
  NAT through a relay, so that agent needs no inbound port.
- **End-to-end encryption**: TLS and authentication run between client and
  agent, so a relay only forwards ciphertext.
- **Keys or tokens**: OpenSSH public keys in `authorized_keys` format, or a
  shared token.
- **Resumable sessions**: `tern connect` reconnects on its own after a drop and
  resumes the session with scrollback replay; others can join it as read-only
  viewers.
- **One connection, many channels**: one authenticated connection can carry a
  shell, `exec`, port forwards and file copy at once.
- **REST gateway and MCP server**: run commands over HTTP, or let AI agents
  work under a policy.
- **Recording**: with `ternd --record-dir`, the agent saves each session as an
  asciicast, playable with `asciinema play`.
- **Zero-config**: run `ternd` with no flags on a terminal and it mints a token
  and prints the line to connect with.
- **Portable**: Linux, macOS, Windows and Android on amd64 and arm64.

All of them in detail: [docs/features.md](docs/features.md).

## Documentation

- [Getting started](docs/getting-started.md): direct, through a relay, with
  `rtern`, with OpenSSH keys and the insecure flags for testing
- [Commands](docs/commands.md): every `tern` command, sharing and resuming
  sessions, copying files, port forwards
- [REST gateway](docs/rest-api.md): run commands on an agent over HTTP
- [AI agents over MCP](docs/mcp.md): the config file, profiles, tools,
  approvals and the audit log
- [Install and build](docs/install.md): checking a release, building from
  source, supported platforms
- [Keys, tokens and files](docs/files.md): the rules for the files tern reads
- [Operating notes](docs/notes.md): listeners, shutdown, recordings and other
  details
- [Security](SECURITY.md): the threat model, the dangerous flags and how to
  report a vulnerability
- [Contributing](CONTRIBUTING.md): license terms, the CLA, development and the
  code layout

## License

Ternimal is licensed under the **GNU Affero General Public License v3.0 only**
(AGPL-3.0-only); see [LICENSE](LICENSE). Running a modified version to provide
a network service requires offering that version's source to its users.

A separate **commercial license** is available for uses that cannot comply with
the AGPL, for example embedding Ternimal in a proprietary or hosted service;
see [NOTICE](NOTICE). Contributions are welcome; see
[CONTRIBUTING](CONTRIBUTING.md) for the license terms and the CLA.

"Ternimal", the binary names (`tern`, `ternd`, `ternr`, `rtern`) and the
project logo are project trademarks and are not licensed under the AGPL; see
[NOTICE](NOTICE).
