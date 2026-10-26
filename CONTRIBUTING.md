# Contributing to Ternimal

Thanks for your interest in Ternimal. A few notes before you open a pull request.

## License of contributions

Ternimal is licensed under the GNU Affero General Public License v3.0 only
(AGPL-3.0-only); see [LICENSE](LICENSE). By contributing, you agree that your
contribution is provided under the same license.

New source files should carry the SPDX header used across the tree (in a
PowerShell script, with `#` instead of `//`):

```
// SPDX-FileCopyrightText: 2026 The Ternimal Authors
// SPDX-License-Identifier: AGPL-3.0-only
```

## Dual-licensing and the CLA

Ternimal is also offered under a separate commercial license alongside the
AGPL; see [NOTICE](NOTICE). To keep offering both, an outside contribution is
merged only under a **Contributor License Agreement (CLA)**.

The CLA is a *license grant* in the style of the Apache / Google ICLA: you keep
the copyright to your work and grant the project the right to use and
relicense it, including under a commercial license. No copyright assignment is
required.

Please open an issue to discuss a change before you send a pull request; the
reply says how to sign the CLA.

## Development

- Go 1.26.10 or later; CI and the release use exactly 1.26.10, and the
  staticcheck that `make lint` pins may not build with a newer Go. Every
  target builds as pure Go (`CGO_ENABLED=0`) except android/amd64; the
  binaries need nothing beyond the OS.
- `make build`: build the four binaries into `bin/`
- `make test`: unit tests plus the end-to-end suite in `test/`
  (`go test -count=1 ./...`; CI runs it with `-race` on Linux)
- `make lint`: gofmt, `go vet`, staticcheck
- End-to-end tests live in `test/` (`go test ./test/`). The interactive PTY
  tests, and the `tern mcp` terminal tests, run on Unix hosts; on Windows they
  are skipped unless `TERN_E2E_PTY=1` is set from a real console or SSH
  session.
- On Windows, CI runs the tests in `internal/mcpserver`, `cmd/...` and
  `test/`, where a test that needs a Unix shell or symlinks must skip, and
  the Windows tests of `internal/tern`.
- `internal/mcpserver` has fuzz targets for the terminal renderer, redaction,
  paging and other parsers: `go test -fuzz FuzzVTText ./internal/mcpserver/`,
  likewise `FuzzCleanWindow`, `FuzzRedactSplit`, `FuzzConfirmDisplay`,
  `FuzzKeyBytes`, `FuzzHiddenNotes`, `FuzzFilePagesEqualWhole`,
  `FuzzJobPagesEqualWhole`, `FuzzUTF16PagesEqualWhole` and
  `FuzzRedactionHints`; `internal/tern` has `FuzzReadClientHello`, for the
  reader of a peer's first TLS records.
- The Claude Code plugin lives in `plugin/`, and
  `.claude-plugin/marketplace.json` lists it. Check both with
  `claude plugin validate --strict ./plugin` and `claude plugin validate .`.
  The plugin's `version` is the release's: the release job refuses a tag it
  does not match, so raise it with each release.

Please run `make lint` and `make test` before opening a pull request.

## Code layout

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
docs/            user guides: getting started, commands, REST, tern mcp, install, files, notes, features
docs/demo/       the demo recordings
plugin/          the Claude Code plugin: the tern mcp server it starts, and its skills
.claude-plugin/  marketplace.json, which lists the plugin for `claude plugin marketplace add`
```
