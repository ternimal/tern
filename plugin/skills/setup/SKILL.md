---
description: Set up tern mcp for the Ternimal plugin, and fix a tern MCP server that does not start. Covers installing tern, starting ternd on a host, the key or token it needs, and writing the config file with hosts and policy profiles. Use when the user wants Claude to reach their own servers through tern, or when the plugin's tern server shows an error.
---

# Set up tern mcp

The plugin runs `tern mcp --config <file>` on this machine. The file defaults
to `~/.config/tern/mcp.json`; the user changes the path with
`/plugin configure ternimal@ternimal`. `tern mcp` reaches each host's `ternd`
agent over end-to-end TLS, pinned to the agent's certificate fingerprint.

Walk the user through these steps. Commands with credentials are theirs to run
in their own shell: never ask them to paste a key, token or password into the
chat.

## 1. Install tern on this machine

Check with `tern version`. If it is missing, install it from
https://github.com/ternimal/tern/releases/latest: download the zip for the OS
and architecture and `SHA256SUMS`, check the zip with
`sha256sum --ignore-missing -c SHA256SUMS`, and unzip only the binaries onto
the PATH Claude Code uses, for example
`unzip ternimal-linux-amd64.zip tern ternd ternr rtern -d ~/.local/bin`.
With Go installed, `go install github.com/ternimal/tern/cmd/...@latest` also
works.

## 2. Give the host an agent and a credential

A key pair is the simplest credential to keep private. Keep it in `~/.ssh`,
where the tern file tools never read or upload a file:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
tern keygen --out ~/.ssh/id_tern     # private key, written with mode 0600
# copy ~/.ssh/id_tern.pub to the host, into an authorized_keys file
```

On the host, start the agent with that file:

```bash
ternd --authorized-keys /path/to/authorized_keys
```

`ternd` logs `agent fingerprint: <64 hex digits>`; note it. Run `ternd` as a
user with no more privilege than the work needs: an authenticated client can
do anything that user can.

A token works too. `tern genkey` prints one; keep it in a file only the user
can read (`umask 077` before writing it, or `chmod 600` after) and start
`ternd --token-file` with the same token on the host. `tern mcp` refuses a
key or token file that other local users could read or change.

## 3. Write the config file

Start read-only. The file holds paths to credentials, never the secrets
themselves (`tern mcp` refuses an inline token):

```json
{
  "targets": {
    "web1": {
      "addr": "203.0.113.10:2222",
      "fingerprint": "<the 64 hex digits ternd logged>",
      "key": "~/.ssh/id_tern"
    }
  }
}
```

A target without `profile` uses `readonly`: a short list of inspection
commands and reads of config and logs. To allow more, add a profile and name
it in the target, for example `"profile": "ops"` with

```json
"profiles": {
  "ops": {
    "run": { "allow": [["systemctl", "restart", "nginx"]] },
    "confirm": ["run"]
  }
}
```

The full reference, including shell mode, file writes, terminals and limits,
is https://github.com/ternimal/tern/blob/main/docs/mcp.md. Grant the least
that does the job, and put actions that change the host in `confirm` so the
user approves each one.

## 4. Check, then reload

From a shell, check that the host answers:

```bash
tern run --addr 203.0.113.10:2222 --fingerprint <fp> --key ~/.ssh/id_tern -- uname -a
```

Then run `/reload-plugins` (or start a new session). `/mcp` lists the server
as `plugin:ternimal:tern`.

If the server does not start, run `tern mcp --config ~/.config/tern/mcp.json`
in a shell: it prints the reason and exits, for example a fingerprint that is
not 64 hex digits, a missing key, a token file others could read or change,
a key of yours others could read, or a config file others could change or
put in its place, with the fix.
