# Ternimal plugin

Lets Claude work on your own hosts through `tern mcp`, the MCP server in
[Ternimal](https://github.com/ternimal/tern): commands, file transfers,
background jobs and interactive terminals over end-to-end TLS, each host
under a policy profile you choose, with approval prompts for chosen actions,
redaction of known secrets and an audit log of every call.

## What you need

- `tern` on your `PATH`: from the
  [latest release](https://github.com/ternimal/tern/releases/latest) or
  `go install github.com/ternimal/tern/cmd/...@latest`
- `ternd` running on each host, with a key or token for it
- a config file that names your hosts and their profiles, by default
  `~/.config/tern/mcp.json`

The `ternimal:setup` skill walks through all three.

## Install

```bash
claude plugin marketplace add ternimal/tern
claude plugin install ternimal@ternimal
```

To use a config file elsewhere, run `/plugin configure ternimal@ternimal`.

If `/mcp` shows the `plugin:ternimal:tern` server as failed, run
`tern mcp --config <your file>` in a shell: it prints why it stopped and how
to fix it. The `ternimal:setup` skill covers the usual causes.

## Examples

Under the default read-only profile:

- "How is web1 doing? Check its disk space, memory and load." Claude can
  answer with `df -h`, `free -h` and `uptime`, which the profile allows.
- "nginx on web1 returns 502 errors. Read its error log and its last 100
  journal lines, and tell me why." Claude reads `/var/log/nginx/error.log`
  and runs `journalctl -u nginx -n 100`.

Under the `ops` profile from the `ternimal:setup` skill, which adds
`systemctl restart nginx` and asks you before every command:

- "Restart nginx on web1 and check that it came back up." Claude runs
  `systemctl restart nginx`, then `systemctl is-active nginx`, each once you
  approve it in a form.

## What the plugin contains and runs

- `.mcp.json` starts one local MCP server on your machine,
  `tern mcp --config <your file>`, with the `tern` on your `PATH`. On each
  host it runs only what Claude asks for within that host's profile, and a
  fixed `uname -srm`, or `cmd /c ver` where that fails, to learn the host's
  OS.
- Two skills: `ternimal:ops`, how Claude works with the tern tools, and
  `ternimal:setup`, how to install and configure them.
- No hooks, no binaries and no credentials. Keys and tokens stay in the files
  your config names, and `tern mcp` refuses a token file that other local
  users could read or change, a key of yours that they could read, and a
  config file they could change or could have put in its place.

The policy, redaction and audit details are in
[docs/mcp.md](https://github.com/ternimal/tern/blob/main/docs/mcp.md), and
the threat model in
[SECURITY.md](https://github.com/ternimal/tern/blob/main/SECURITY.md).

## Privacy

The plugin and `tern mcp` have no telemetry.

- `tern mcp` connects only to the agents, and the relays, that your config
  file names. TLS runs end to end to each agent and is pinned to its
  certificate; a relay passes on only encrypted bytes. Besides the login with
  your key or token, what travels there is what Claude asks for within the
  profile: commands and their input, the content of files it writes or
  uploads, and the text it types into a terminal.
- What comes back, such as command output, file contents and terminal text,
  goes to Claude as the tool's result, with known secrets redacted, and so
  becomes part of your conversation with Claude.
- What `tern mcp` keeps stays on your machine. The audit log has at least
  one JSON line per tool call: the tool, the target, the arguments, redacted,
  with input and typed text only by size and file contents by size and
  SHA-256, and the outcome, never the output. It is `mcp-audit.jsonl` in
  `~/.local/state/tern` (`$XDG_STATE_HOME/tern` when that is an absolute
  path, `%LocalAppData%\tern` on Windows) unless your config sets `audit_log`,
  readable only by you, and kept until you delete it. Only when your config
  asks for them does `tern mcp` also keep terminal recordings (`record_dir`),
  the list of terminals to reattach (`persist_ptys`) and the files Claude
  downloads (`workspace`).

## Support

Questions and bugs: [GitHub issues](https://github.com/ternimal/tern/issues).
Report a security issue privately, not in an issue, through the repository's
[private vulnerability reporting](https://github.com/ternimal/tern/security/advisories/new);
[SECURITY.md](https://github.com/ternimal/tern/blob/main/SECURITY.md) says
what to include.

## Where it works

The MCP server is a local command, so the plugin's tools work in Claude Code
and in Cowork sessions that run on your computer. claude.ai chat loads the
skills but not local servers.

## License

AGPL-3.0-only, the same as Ternimal. See [LICENSE](LICENSE).
