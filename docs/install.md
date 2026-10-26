# Install and build

## Download a release

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
Releases after v1.0.1 publish every zip twice, the same file under two names:
`ternimal-<version>-<os>-<arch>.zip`, which says its version, and
`ternimal-<os>-<arch>.zip`, the name the `releases/latest/download` links above
use. `SHA256SUMS` lists both.
Each zip also holds LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt, the licenses
of the code in the binaries; the `unzip` line above takes only the binaries.

Run the same release of `tern`, `ternd`, `ternr` and `rtern` everywhere:
different releases are not promised to work with each other.

## With `go install`

Build them with Go 1.21 or later. When yours is older than Go 1.26.10, the
release toolchain, it fetches a Go 1.26 release at least that new on its own
(unless `GOTOOLCHAIN=local`):

```bash
go install github.com/ternimal/tern/cmd/...@latest
```

`go install` uses your toolchain's defaults; set `CGO_ENABLED=0` to build
without cgo like the release builds, which on Linux makes the binaries fully
static.

## Build from source

Requires **Go 1.26.10+** (an older Go 1.21+ fetches it on its own).

```bash
make build            # native bin/tern, bin/ternd, bin/ternr, bin/rtern
make release          # dist/ternimal-<os>-<arch>.zip for every platform: the binaries,
                      # LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt (needs the Android NDK for android/amd64);
                      # with VERSION set, also a copy named ternimal-<VERSION>-<os>-<arch>.zip
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

Don't compress binaries with UPX; it sharply raises AV false positives.

## Platforms

| OS | status |
|----|--------|
| Linux (amd64/arm64) | yes |
| macOS (amd64/arm64) | yes; release zips are named `darwin` |
| Windows (amd64/arm64) | yes: `.exe`, console, ConPTY host. Needs Windows 10 or later; hosting a shell needs Windows 10 1809 or Server 2019 or later |
| Android (arm64) | yes: pure Go, no cgo, no NDK; runs under Termux or `adb shell` |
| Android (amd64) | yes: x86-64 emulators and Android-x86; built with cgo + the NDK |
| iOS | no: the core compiles for `GOOS=ios`, but the sandbox forbids fork/exec, so an agent can't host a shell, and there is no public library API to embed it |
