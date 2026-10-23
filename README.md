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
against `SHA256SUMS` and, with the [GitHub CLI](https://cli.github.com),
against the build provenance attestation every release asset carries, and put
the four binaries on your `PATH`:

```bash
curl -LO https://github.com/ternimal/tern/releases/latest/download/ternimal-linux-amd64.zip
curl -LO https://github.com/ternimal/tern/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify ternimal-linux-amd64.zip -R ternimal/tern
mkdir -p ~/.local/bin
unzip ternimal-linux-amd64.zip tern ternd ternr rtern -d ~/.local/bin
```

macOS zips are named `darwin`; on Windows, unzip and add the folder to `PATH`.
Each zip also holds LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt, the licenses
of the code in the binaries; the `unzip` line above takes only the binaries.

Or build them with Go 1.21 or later. When yours is older than Go 1.26.10, the
release toolchain, it fetches a Go 1.26 release at least that new on its own
(unless `GOTOOLCHAIN=local`):

```bash
go install github.com/ternimal/tern/cmd/...@latest
```

`go install` uses your toolchain's defaults; set `CGO_ENABLED=0` to build
without cgo like the release builds, which on Linux makes the binaries fully
static.

## Getting Started

Each recording below is a real session with the v1.0.0 binaries on one
machine over loopback, recorded with asciinema.

On startup `ternd` logs its fingerprint (`agent fingerprint: ...`) and prints a
`tern connect` line to paste. When ternd minted the token itself, the line
carries `TERN_TOKEN=<token>`; otherwise it has a placeholder for the credential
you configured, `TERN_TOKEN=<your-token>` or `--key <your-key>`: replace it, or
drop it when `TERN_TOKEN` is already set. In relay mode the line also starts
with a `TERN_RELAY_TOKEN=<relay-token>` placeholder: the relay token is yours,
so ternd never prints it.

### 1. Direct: `tern` -> `ternd`

```bash
# agent: zero-config, listens on port 2222 on every IPv4 and IPv6 address,
# mints a token, prints its fingerprint
ternd

# client: connect by IP with the agent's fingerprint and token
TERN_TOKEN=<token> tern connect -a AGENT_IP:2222 -f <agent-fp>
```

![tern connecting directly to ternd](docs/demo/direct.gif)

`ternd` also prints a ready-to-paste `TERN_TOKEN=... tern connect --to
tern1:...` line that bundles the address and fingerprint. Its address is the
listen address, with a wildcard bind such as `0.0.0.0` shown as `127.0.0.1`, so
as printed it only works on the agent host; from another machine, connect by IP
as above or start `ternd -a <agent-ip>:2222`.

### 2. Through a relay: `tern` -> `ternr` <- `ternd`

The agent dials out to a public relay, so it needs no inbound port.

```bash
# relay, on a public host: note the fingerprint=<relay-fp> it logs
export TERN_RELAY_TOKEN="$(tern genkey)"
ternr --addr 0.0.0.0:7000

# agent behind NAT: dials out with the same relay token
TERN_RELAY_TOKEN=<relay-token> ternd --relay RELAY:7000 --relay-fingerprint <relay-fp> --id box1

# client: paste the line ternd printed, with the relay token filled in
TERN_RELAY_TOKEN=<relay-token> TERN_TOKEN=... tern connect --to tern1:...
```

![tern reaching ternd through the ternr relay](docs/demo/relay.gif)

The `tern1:` string holds no secret: the relay token comes from
`TERN_RELAY_TOKEN` or `--relay-token-file`, as the agent token does from
`TERN_TOKEN`. Either way the relay token is only proved to the relay, never
sent.

### 3. Combined relay + client: `rtern` <- `ternd`

When one person needs to reach one agent, `rtern` replaces the separate relay
and client with a single process: it waits, the agent dials in, and you land in
its shell.

```
 separate — agent and client meet at a public relay (ternr)

    behind NAT                    public                     anywhere
   ┌──────────┐   dial out    ┌──────────┐    connect    ┌──────────┐
   │  ternd   │ ─────────────▶│  ternr   │◀───────────── │   tern   │
   │  agent   │               │  relay   │               │  client  │
   └──────────┘               └──────────┘               └──────────┘
        ╰─────── end-to-end TLS + auth · relay sees only ciphertext ───────╯

 combined — one process is relay + client (rtern)

    behind NAT                            you, anywhere
   ┌──────────┐      dial out       ┌────────────────────┐
   │  ternd   │ ───────────────────▶│       rtern        │
   │  agent   │                     │   relay + client   │
   └──────────┘                     └────────────────────┘
        ╰──── end-to-end TLS + auth · drops you straight in the shell ────╯
```

```bash
# agent, once: share a token, create the cert and note the agent fingerprint
export TERN_TOKEN="$(tern genkey)"
ternd -a 127.0.0.1:2222            # stop it once "agent fingerprint: <agent-fp>" shows

# you: same token, then listen and wait for the agent
export TERN_TOKEN=<same-token>
rtern --fingerprint <agent-fp>

# agent: paste the ternd line rtern printed, without its TERN_TOKEN=<your-token>
# placeholder since TERN_TOKEN is already set
TERN_RELAY_TOKEN=<token-rtern-printed> ternd --relay <rtern-host>:7000 --relay-fingerprint <rtern-fp> --id box1
```

![rtern catching an agent that dials in](docs/demo/rtern.gif)

If no relay token is given (`TERN_RELAY_TOKEN`, `--relay-token-file` or
`--relay-token`), `rtern` generates one and puts it in the `ternd` line it
prints; fill in `<rtern-host>` when it listens on a wildcard address. The
agent keeps its fingerprint as long as its `.crt/.key` files are kept. Auth
is end-to-end: `rtern` pins the agent's TLS fingerprint and authenticates
with a key or token, same as `tern connect`. `rtern` is the only client of
the agents it catches: ignore the `tern connect` line that `ternd` prints
for a `ternr` relay.

### Keys instead of tokens

Every mode above also works with OpenSSH keys:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
tern keygen --out ~/.ssh/id_tern   # or reuse an OpenSSH key such as ~/.ssh/id_ed25519
cp ~/.ssh/id_tern.pub agent_authorized_keys
ternd --authorized-keys agent_authorized_keys
tern connect --to tern1:... --key ~/.ssh/id_tern
```

`ternd` reads `authorized_keys` when it starts; restart it after changing
the file. As ssh's StrictModes does, `ternd` refuses a file someone else
could add a key to, or put in its place, and prints the fix: it must be
owned by the user `ternd` runs as, or by root (SYSTEM or Administrators on
Windows), and no one else may change it, which on Unix means no other-write
bit, and no group-write bit unless the group is that user's own private
group and the file has no ACL (tern reads ACLs only on Linux, and there a
file system that keeps none, as ZFS by default, counts as having none,
unless it is NFS, SMB or AFS, whose servers may keep their own; where tern
cannot tell, group write always counts), and on Windows no ACL entry letting
another account change or delete it. On Unix the directory it is in is held
to the same rule, but for a sticky one, as `/tmp` is, which others may write
to; a symlink at the path, and each link it leads to, must be owned by that
user or root (SYSTEM or Administrators on Windows), on Unix in a directory
held to that rule too. So a Kubernetes Secret or projected volume passes:
its directory, a tmpfs, is root's and sticky, and its `..data` and per-key
links are root's. A ConfigMap volume does not: its directory is root's but
writable by all and not sticky; mount the file from a Secret or a projected
volume instead, or with `subPath`. Directories further up are not looked at,
nor, on Windows, the directory's ACL, nor how the name came to be: in a
sticky directory another user may have made it first as a hard link to a
file of root's that lists their key, which macOS, the BSDs and Linux with
`fs.protected_hardlinks=0` let any user do. Others may read the file, and it
may hold at most 1 MiB. On Windows 10 and 11 keep the file in your profile:
a folder made under `C:\` there passes on an entry letting Authenticated
Users change what it holds, so a file copied into it is refused (the fix
printed is an `icacls` line). On Windows Server such a folder lets Users
read the file but not change it, and it is taken.

### Insecure flags (testing only)

For local testing you can relax the transport security. `--insecure-dangerous`
turns off TLS and the client's verification of the agent and relay at once: the
client reaches the agent in plaintext with no fingerprint, and the agent still
requires the token or key, whose proof crosses in cleartext. Both ends must run
in plaintext (`ternd` prints the client line with `--insecure-skip-encryption`,
or `--insecure-dangerous` when it does not pin the relay). Each flag prints a
loud warning, and none may be used outside testing. See
[SECURITY.md](SECURITY.md) for the full set of dangerous flags.

![a plaintext session with --insecure-dangerous](docs/demo/dangerous.gif)

## AI agents (`tern mcp`)

`tern mcp` lets an AI client such as Claude Code, Claude Desktop or Cursor work
on your agents through the
[Model Context Protocol](https://modelcontextprotocol.io), under a policy you
set and with an audit log of every call.

```bash
# read-only: a short allowlist of inspection commands and reads of config and logs
claude mcp add tern -e TERN_TO=tern1:... -e TERN_TOKEN=... -- tern mcp
```

Claude Code keeps what `-e` sets in plain text in `~/.claude.json`. To keep
the token in a file of its own, give `tern mcp` a `--token-file` (an
absolute or `~/` path) instead of `-e TERN_TOKEN=...`, or use the plugin.

Or install the Claude Code plugin, which runs `tern mcp` with a config file
(`~/.config/tern/mcp.json` by default) and adds skills that teach Claude the
tools and walk you through the setup. It starts `tern` from your `PATH`, so
install tern first:

```bash
claude plugin marketplace add ternimal/tern
claude plugin install ternimal@ternimal
```

The plugin's tools work in Claude Code and in Cowork sessions on your
computer; see [plugin/README.md](plugin/README.md).

A config file gives the AI more, per host: shell mode, file writes and
uploads, background jobs and interactive terminals, each within limits, and
with your approval before chosen actions run (`--workspace` alone lets it
download files into a local folder: give it one of its own, such as
`~/tern-work`, not a project or your home directory). Terminals keep their state
between calls, and the `tern connect --read-only` line that `pty_open` returns
lets you watch the AI's terminal live:

![an MCP client driving tern mcp while a person watches the same terminal](docs/demo/mcp.gif)

The client on the left is a scripted MCP client, not part of this repository,
that makes the calls an AI agent makes; `tern mcp`, `ternd` and `tern connect`
are the real binaries. See [docs/mcp.md](docs/mcp.md) for the config, the tools
and the safety model.

## Features

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
  unauthenticated attempts from many networks (see SECURITY.md).
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

## Build from source

Requires **Go 1.26.10+** (an older Go 1.21+ fetches it on its own).

```bash
make build            # native bin/tern, bin/ternd, bin/ternr, bin/rtern
make release          # dist/ternimal-<os>-<arch>.zip for every platform: the binaries,
                      # LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt (needs the Android NDK for android/amd64)
```

Every target builds as pure Go (`CGO_ENABLED=0`) except android/amd64, which
Go can only link with cgo and the Android NDK (point `NDK_CC_AMD64` at its
clang). The binaries need nothing beyond the OS, and the Linux builds are
fully static. A rebuild in a clean clone of the tag, with the same toolchain
and `VERSION` (`make release VERSION=<tag>`; for android/amd64 also the same
NDK), packs zips with the same bytes: every file in them carries the commit
time, or `SOURCE_DATE_EPOCH` when it is set. Go records the state of the
checkout in each binary (the tag as its version, and whether a file is
untracked or changed), so a tree with extra or changed files, or a source
archive, gives other bytes.

| OS | status |
|----|--------|
| Linux (amd64/arm64) | yes |
| macOS (amd64/arm64) | yes; release zips are named `darwin` |
| Windows (amd64/arm64) | yes: `.exe`, console, ConPTY host. Needs Windows 10 or later; hosting a shell needs Windows 10 1809 or Server 2019 or later |
| Android (arm64) | yes: pure Go, no cgo, no NDK; runs under Termux or `adb shell` |
| Android (amd64) | yes: x86-64 emulators and Android-x86; built with cgo + the NDK |
| iOS | no: the core compiles for `GOOS=ios`, but the sandbox forbids fork/exec, so an agent can't host a shell, and there is no public library API to embed it |

## Commands

```bash
tern connect [conn] [--session NAME] [--attach|--new] [--read-only] [--no-reconnect] [-L ..] [-R ..]
tern run     [conn] -- CMD [ARGS...]     # exec, exit code is propagated
tern forward [conn] -L 8080:localhost:80 # local forward (also -R for reverse)
tern cp      [conn] FILE agent:/path     # copy up (or agent:/path FILE to copy down)
tern list    [conn]                      # live sessions on the agent
tern api     [conn] [--api-addr ADDR]    # REST gateway on 127.0.0.1:8080, token in TERN_API_TOKEN
tern mcp     [conn | --config F]         # MCP server for AI clients, over stdio
tern keygen  [--out F]                   # unencrypted OpenSSH Ed25519 key pair (F, F.pub)
tern genkey                              # print a random 32-char token
tern version
```

Each command but `version` lists its flags with `-h`, and `-v`/`--verbose`
turns on debug logs (`genkey` has no `-v`). `tern run` delivers the remote
stdout and stderr on local stdout. Except on Windows, the command runs in a
session of its own with no controlling terminal, so one that prompts on a
terminal (sudo asking for a password, ssh confirming a host key) fails
instead of waiting; use `tern connect` for those.

- **Share / resume:** two people run `tern connect --session demo` to the same
  agent; the first is the writer, the next is `[read-only]` (or pass
  `--read-only=false` to co-drive) and leaves with Ctrl-C. `--read-only` only
  joins an existing session. Drop and reconnect with the same `--session` to
  resume, within `ternd --session-idle` (default 10m; 0 keeps a session until
  its shell exits).
- **Copy:** as with `cp`, a destination ending in `/`, or an existing local
  directory, keeps the file's name: `tern cp f agent:/tmp/` writes `/tmp/f`.
  An existing remote directory needs the trailing `/`. A copy writes into the
  directory it opened when it started, so a link or junction changed on the
  path meanwhile does not move the file. A file of yours that exists keeps
  its mode, unless it has a second name (a hard link) or another user may add
  names to its directory, and so could have moved a file of yours there: the
  directory is another user's (root aside), or its mode lets others write
  it, sticky or not, or its group, unless that is your own private group and
  the directory has no ACL (tern looks for one on Linux, taking a file system
  that keeps none as having none, but not NFS, SMB or AFS; elsewhere group
  write always counts). Such a file, or one another user owns, keeps no more
  than a new one would get; a new one gets the source's, less the umask. On
  Windows a file of yours with one name, whose ACL lets no other account
  change, delete, re-permission or take it over, keeps that ACL, protected or
  not (an explicit deny stays), unless another account (SYSTEM and
  Administrators aside) owns its folder or may add files to it, delete them,
  or re-permission or take over the folder, as other users may add files to
  a folder made under `C:\` (Users on Windows Server, Authenticated Users on
  Windows 10 and 11); a folder whose owner and ACL cannot be read counts too.
  Any other file, one another account owns included (planted or moved
  there), is replaced as a new file would be: owner-only for a private mode
  such as 0600, and when it replaces such a file of yours that no other
  account may read, or whose ACL is protected (inherits nothing from the
  folder) or holds an entry of its own other than an allow, such as a deny,
  which the folder's could widen; otherwise with the folder's inherited ACL.
  Windows will not replace a read-only file: the copy fails and leaves
  nothing behind. On Windows a name holding `:` names a data stream: a copy
  to it is refused.
- **Forward specs** are ssh-style, and an omitted bind host defaults to
  loopback rather than all interfaces: `-L [lhost:]lport:rhost:rport`,
  `-R [rbind:]rport:lhost:lport`; the local or bind host defaults to
  127.0.0.1. `tern forward` exits when a forward fails or the connection
  drops. `-L`/`-R` given to `tern connect` use their own connection and are
  not re-established after a drop. A bind host of 127.0.0.1 also holds the
  same port on ::1, localhost holds it on both, a host name that names
  loopback addresses only, such as ip6-localhost, holds it on every address
  it names (and on the other of 127.0.0.1 and ::1 beside either), and any
  other host name holds it on every address it names (see Notes), so no
  other local user can listen beside a forward; a port taken there makes the
  forward fail. A spec cannot hold an IPv6 address itself.

## REST gateway (`tern api`)

A gateway that runs commands on the agent (direct or via relay). It is a
remote-execution endpoint, so it requires a bearer token: pass one in
`TERN_API_TOKEN` or a file named by `--api-token-file`, or, started on a
terminal, `tern api` mints one and prints it. (`--api-token` also takes it,
but on the command line, where other local users can read it.)
Keep it on loopback (the default, `127.0.0.1:8080`): 127.0.0.1 and [::1]
each also hold the port on the other, localhost (any case, with or without
a trailing dot) holds both, and a host name that names loopback addresses
only, such as localhost.localdomain or ip6-localhost, holds every address it
names and, beside 127.0.0.1 or ::1, the other one too. The gateway refuses
to start if another program holds any of these, and refuses a name for
loopback and other addresses at once. Only the dangerous
`--api-insecure-no-token` flag runs it without a token, on any address (see
SECURITY.md).

```bash
tern api --to tern1:... --key ~/.ssh/id_tern --api-token-file api.token
```

It is not reachable from a web page: it rejects any request that carries an
`Origin` header, requires `Content-Type: application/json` on POSTs, and (when
it listens on loopback) requires a `Host` that is loopback, the host given to
`--api-addr`, or a trusted host (names in any case, with or without a
trailing dot), so a browser CSRF or DNS-rebinding attempt cannot run commands
on the agent. To front it with a reverse proxy that preserves `Host`, list
the proxied hostnames with `--api-trusted-hosts host1,host2` (a name matches
any port; `host:port` accepts only that port); given to a gateway off
loopback, they turn the `Host` check on there too. A request's header must
arrive within 5 seconds of connecting, and a request without the token then
gets 10 seconds to be answered. Headers are limited to 8 KiB (net/http
allows 4 KiB more, and on a kept-alive connection also the 4 KiB it read
ahead) and to 64 lines: a connection's first request is refused (400) as
soon as it passes them, and a later one, which only a connection that
carried the token can send, once net/http has parsed it (431). Connections
that have not yet carried a request with the token are capped at 128 per
client address (IPv6 /64; all of loopback counts as one) and a quarter of
the file-descriptor limit in all (16 to 1024). Past a cap one such
connection is closed to make room, never one that has carried an admitted
request: past the per-address cap one of that address's, past the total cap
one of the address block holding the most, and one that has not sent a
whole request line within 20 ms goes first unless another block holds more.
Connections that have carried the token have a cap of their own, as large
as the total one; past it a new one's request is refused with 503 and that
connection closed, and none already admitted is closed to make room.

Three execution modes, pick by use case:

| method & path | mode | purpose |
|---|---|---|
| `POST /v1/run` | **simple** | run with a timeout, return one JSON `{"exit":N,"output":"...","timed_out":bool}`. Body may set `"timeout"` in seconds (default 30s from `--api-timeout`, capped by `--api-max-timeout`, 10m); on timeout `exit` is -1. |
| `POST /v1/exec` | **streaming** | stream merged stdout+stderr as NDJSON until exit: lines `{"stdout":"..."}` then `{"exit":N}` (live output, long-running) |
| `POST /v1/jobs` | **async job** | start now, return HTTP 202 `{"job":"...","status":"running"}`; poll or cancel below (decoupled, long-running) |
| `GET /v1/jobs/{id}` | async job | status (`running`, `done` or `cancelled`) + exit code |
| `GET /v1/jobs/{id}/output?offset=N` | async job | incremental output: `{"data":"...","next_offset":N,"done":bool}`, plus `exit` once done |
| `DELETE /v1/jobs/{id}` | async job | cancel (the agent kills the command and its process group; on Linux also every process still in its session or descended from it, on Windows everything in its job object; a daemon that started a session of its own and was handed to init is not reached) |
| `GET /v1/sessions` | info | live sessions |
| `GET /v1/healthz` | info | liveness (no token; the Origin and Host checks still apply) |

`run`, `exec` and `jobs` accept an optional `"stdin"` string in the body that
is fed to the command; without it the command's stdin is closed. `run` and
`jobs` keep at most 8 MiB of output per command (`"truncated":true`); `exec`
streams it all. If the HTTP client disconnects, `run` and `exec` stop the
command, while a job keeps running until it ends or is cancelled. Every route
except `/v1/healthz` needs `Authorization: Bearer <api-token>`. At most 64
`run` and `exec` commands run at once (another gets HTTP 429; jobs have their
own limit of 128), and a finished job can be read for an hour, or until
newer jobs push it out: the gateway keeps 256 jobs, running ones included,
and drops the oldest finished one first. A command is at most 60 KiB of
JSON; pass large input as `stdin`. Through a relay, `run`, `exec` and `jobs`
can target another agent with `{"id":"box2"}` in the body,
and `GET /v1/sessions?id=box2`, once the gateway knows that agent's
fingerprint: add `--api-agent box2=<fingerprint>` (repeatable), with the
fingerprint `ternd` prints on box2. The gateway pins every agent id to its own
fingerprint and refuses an id it has none for; a gateway that reaches its agent
directly refuses any id. Each agent keeps its own `.crt/.key`: do not copy one
agent's key to another, since anyone who can read it there could pose as the
first agent.

```bash
# stream a long-running command
curl -N -H "Authorization: Bearer SECRET" -H "Content-Type: application/json" \
     -d '{"cmd":["sh","-c","for i in 1 2 3; do echo $i; sleep 1; done"]}' \
     http://127.0.0.1:8080/v1/exec

# or as a job
JID=$(curl -s -H "Authorization: Bearer SECRET" -H "Content-Type: application/json" \
      -d '{"cmd":["./backup.sh"]}' http://127.0.0.1:8080/v1/jobs | jq -r .job)
curl -s -H "Authorization: Bearer SECRET" http://127.0.0.1:8080/v1/jobs/$JID
```

## Layout

```
internal/tern/   portable core
  doc.go          package overview
  const.go        tunables + logging setup
  cli.go          shared CLI helpers: flag aliases + usage, env fallback, banner, write mode
  proto.go        wire frames, blobs, TLS cert + pinning
  auth.go         token / OpenSSH-pubkey auth, keygen
  mux.go          yamux channels + stream headers
  sessionmgr.go   named PTY sessions: resume + multi-client share
  recorder.go     asciicast session recording
  agent.go        agent: dispatch shell/exec/forward/file/rpc
  procgroup_*.go / killsession_linux.go / killwait.go / reap_linux.go   ending commands, PID-1 reaping
  upload_*.go / fileopen_*.go / filemode*.go   file copy
  client_ops.go   client: dial + auth, run/forward/copy/list
  relay.go        relay server (ternr), relay dialing, rtern's agent catch
  serve.go        agent accept loop and relay registration loop
  limit.go / party.go   caps on unauthenticated handshakes, and who gives way
  listen.go       listeners: loopback held on 127.0.0.1 and ::1 alike, a name on every address it gives
  secretfile*.go / keyfile_*.go   checks on the files tern reads: tokens, keys, certificates, tern1:, configs, authorized_keys
  connstr.go      tern1:... connection strings
  api.go          REST gateway (run/stream/jobs, stdin)
  session.go      client terminal + auto-reconnect
  shell_stream.go client side of a shell session: attach, type, resize, read
  shell_pty.go / shell_stub.go   PTY host (stub on iOS)
  *_test.go       unit tests
internal/mcpserver/  tern mcp: policy, confirmation, audit, redaction, jobs, terminals
internal/release/    make release packer: zips with LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt
cmd/tern   cmd/ternd   cmd/ternr   cmd/rtern
test/            end-to-end tests (e2e_test.go, mcp_*_test.go, e2e-windows.ps1)
docs/mcp.md      tern mcp reference
docs/demo/       the README demo recordings
plugin/          the Claude Code plugin: the tern mcp server it starts, and its skills
.claude-plugin/  marketplace.json, which lists the plugin for `claude plugin marketplace add`
```

## Notes

- Don't compress binaries with UPX; it sharply raises AV false positives.
- Keep private keys private: the key `tern keygen` writes (unencrypted) and
  the TLS `*.key` files that `ternd`, `ternr` and `rtern` make are written
  with mode `0600`. Windows ignores that mode, so the key files are created
  with a protected owner-only ACL instead, which no other local user can
  open, even while the file is being written. The `*.crt` file, which clients
  pin, is created owner-only too. The tools refuse a TLS key that is a
  symlink or owned by another account, or that others can open (on Unix any
  group or other permission bit; on Windows an ACL entry letting another
  account read, execute, change or delete it, with a PowerShell line to fix
  it), reading nothing from such a file or from anything but a regular file;
  the fix for a key others may have read is a new pair (delete the `.key`
  and its `.crt`; clients then need the new fingerprint). They refuse a
  certificate another account owns (root, SYSTEM and Administrators aside)
  or others could change; others may read it. A client key (`--key`, `key`
  in tern mcp's config) is held to ssh's rule: one the user owns is refused
  if others can open it (on Unix any group or other permission bit), and
  the fix is a new key from `tern keygen`, or restricting the file if nobody
  else could have read it; one another account owns, root included, is
  taken when the user can read it, as a deploy key root keeps for a group
  (`root:group 0640`) or a Kubernetes secret volume's (on Windows such an
  owner may only be SYSTEM or Administrators, as for Windows' OpenSSH, and
  no other account may open the key); and on Unix a pipe the user made,
  such as `--key <(op read ...)`, is read until its writer closes it,
  within 64 KiB and 30 seconds (one with a name, a FIFO, must not let
  others open it). `tern keygen`, `ternd`, `ternr` and `rtern` refuse, and
  remove, a key they just made where the file system cannot keep it private
  (FAT32, exFAT).
- On Windows the tools listen with `SO_EXCLUSIVEADDRUSE`, and on every OS a
  listener on 127.0.0.1 or ::1 also holds the same port on the other, one on
  localhost holds both, and one on a host name that names loopback addresses
  only (such as localhost.localdomain) holds every address it names and the
  other of 127.0.0.1 and ::1 beside either, so another local user cannot
  listen beside it; a name for loopback and other addresses at once is
  refused, and any other host name listens on every address it names (one
  that names more than 16, or none this system has, is refused). One of
  these addresses that the system does not have yet, as an IPv6 address
  until duplicate address detection is over, is held all the same on Linux,
  with `IP_FREEBIND`, which any local user could otherwise use to take the
  port there first; elsewhere it is passed over with a warning, and once the
  system has it another local user could listen there. With no IPv6 on the
  system at all, there is nothing to hold.
- `ternd` can be a container's entry point: as process 1 it reaps the
  processes its commands leave behind.
- An encrypted client key asks for its passphrase once, when a command starts,
  and is reused for every later connection (shell reconnects, REST requests),
  so `tern api` with an encrypted key needs a terminal at startup.
- `authorized_keys` options such as `from=`, `command=` or `restrict`, and
  certificate lines, are not supported. Such a line is skipped with a warning
  rather than granted access, so list the plain public key instead. A key of a
  kind tern does not take (DSA, security keys, RSA under 1024 or over 8192
  bits or with an exponent other than 65537, an Ed25519 key of small order)
  is skipped with a warning too.
- `ternd` prints placeholders for any credential it was given, such as
  `TERN_RELAY_TOKEN=<relay-token>`, and makes up and prints a token only on a
  terminal, so its connect line is safe in a service log; the relay token
  itself never crosses the wire. A `tern1:` string that carries a relay token
  also works; pass it through `TERN_TO` or `--to-file` rather than `--to` or
  the positional argument, which land on argv.
- Pass tokens through `TERN_TOKEN`/`TERN_RELAY_TOKEN`/`TERN_API_TOKEN` or the
  matching `--*-token-file`, not a plain `--token` flag: a command line is
  readable by other local users through `/proc`, and the tools warn when a
  secret is passed that way. The startup connect line is printed in
  `TERN_TOKEN=... tern connect ...` form for the same reason. A token file
  must be private to the user running the tool, as ssh requires of a private
  key: the tools refuse one other local users could read or change (on Unix
  any group or other permission bit, which `chmod 600 FILE` clears, or
  another owner; on Windows another owner, or an ACL entry letting another
  account read, execute, change or delete it) and print the fix: for a file
  another account owns, delete it and write a new token as this user; for
  one others could open, restrict it (with a PowerShell line on Windows) and
  put a new token in it, since others may know this one. Secret files that a
  platform mounts can fail this rule, such as a Kubernetes secret volume
  (0644 unless `defaultMode` is set, and owned by root), a docker secret
  (0444) or a systemd credential of a service that does not run as root,
  which can be owned by root: pass the token in the environment instead (in
  Kubernetes from a `secretKeyRef`), or, where the platform allows it, mount
  the file with mode 0400 or 0600, owned by the user the tool runs as.
- A `tern1:` file (`--to-file`, `to_file`) and tern mcp's config file say
  which agents to trust. The tools refuse one another account owns (root,
  SYSTEM and Administrators aside) or others could change: on Unix the
  other-write bit, or the group-write bit unless the group is the user's own
  private group and the file has no ACL (tern reads ACLs only on Linux);
  on Windows an ACL entry letting another account change or delete it. They
  refuse one another account could have put in its place too, through the
  directory it is in or a symlink, as `ternd` does for `authorized_keys`
  (see Keys instead of tokens). Others may read them, except a `tern1:`
  file that carries the relay token, which is held to the token-file rule.
- The user's own private group is told from `/etc/passwd` and `/etc/group`
  alone (tern reads them itself: a build without cgo cannot ask NSS), so a
  user whose account comes from a directory service (LDAP, sssd, FreeIPA,
  systemd-homed) has none: a group-writable file of theirs, such as the
  0664 a umask of 002 makes, or such a directory, is refused, and the
  `chmod go-w` printed fixes it. A file system that keeps no Unix modes
  shows every file as 0777, so every token, key, `tern1:`, config,
  certificate and `authorized_keys` file on it is refused: WSL's `/mnt/c`
  mounted without the `metadata` option, or a FAT volume mounted with
  `umask=000`. Keep them on a Linux file system, or mount with `metadata`,
  or with a umask that leaves group and others out.
- Token, key, certificate, `tern1:`, config and `authorized_keys` files must
  be regular files (a FIFO, a device or `<(...)` is refused unread; a
  client key may also be a pipe, see above) of at most 64 KiB (1 MiB for a
  certificate, config or `authorized_keys` file). A token, `tern1:` or
  config file saved as UTF-16 or with a byte order mark, as Windows
  PowerShell 5.1 writes one with `>`, is refused.
- No brute-force lockout: keep listeners behind a firewall/VPN and use
  high-entropy tokens (`tern genkey`). The REST gateway serves plain HTTP, so it
  especially should bind localhost or sit behind TLS + a proxy; `tern api`
  warns when it listens elsewhere. The caps on unauthenticated handshakes tell
  clients apart by address, so run `ternd`, `ternr` and `rtern` where they see
  each client's own address: behind a proxy or port forward that hides it, as
  on a loopback address, one unauthenticated peer can keep every other client
  waiting.
- Resume replays a scrollback buffer (the last 256 KiB of output), not a full
  screen redraw.
- Recordings (`--record-dir`) store what the terminal shows, output and
  resizes, not raw keystrokes: input at no-echo prompts such as passwords is
  not captured, but anything echoed, like a typed command line, is. Files are
  written `0600`. Play them with `asciinema play FILE.cast`.
- Sessions live in the agent's memory; restarting `ternd` ends them. On
  SIGINT/SIGTERM `ternd` and `ternr` stop accepting and exit, which ends live
  sessions and relay bridges. A command still running from `tern run`, the
  REST gateway or `tern mcp` is not killed (it ends with `ternd` on Windows,
  and where `ternd` is a container's process 1), but its output has nowhere
  to go: its next write to stdout or stderr ends it (SIGPIPE) unless it
  ignores that signal. `tern api` first lets in-flight requests finish (up
  to 5s).
- Hosted shells and commands do not inherit the agent's `TERN_*` environment
  variables (`TERN_TOKEN`, `TERN_RELAY_TOKEN`, `TERN_API_TOKEN`, `TERN_LOG`).

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
