# Ternimal skills

Skills that teach Claude to work on your own hosts through `tern mcp`, the
MCP server in [Ternimal](https://github.com/ternimal/tern): commands, file
transfers, background jobs and interactive terminals over end-to-end TLS,
each host under a policy profile you choose, with approval prompts for chosen
actions, redaction of known secrets and an audit log of every call.

This plugin contains skills only. It does not start an MCP server, run a
command, or ship binaries, hooks or credentials. You add `tern mcp` to your
client yourself; the `ternimal:setup` skill walks you through it.

## What you need

- `tern` on your PATH: from the
  [latest release](https://github.com/ternimal/tern/releases/latest) or
  `go install github.com/ternimal/tern/cmd/...@latest`
- `ternd` running on each host, with a key or token for it
- a config file that names your hosts and their profiles, by default
  `~/.config/tern/mcp.json`
- `tern mcp` added as a local MCP server, for example in Claude Code:
  `claude mcp add tern -- tern mcp --config ~/.config/tern/mcp.json`

## What the plugin contains

Two skills:

- `ternimal:setup`: how to install tern, start `ternd`, create a key or
  token, write the config file and add `tern mcp` to your client.
- `ternimal:ops`: how Claude works with the tern tools: staying inside each
  host's profile, waiting for approvals, never asking for secrets in chat,
  and treating command output as untrusted.

The Claude Code plugin with the MCP server bundled is in
[`plugin/`](https://github.com/ternimal/tern/tree/main/plugin) and installs
with `claude plugin marketplace add ternimal/tern`.

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

## Privacy

The skills send nothing anywhere. `tern mcp` has no telemetry.

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
Anything else, or if you cannot use GitHub: contact@ternimal.org.
Report a security issue privately, not in an issue, through the repository's
[private vulnerability reporting](https://github.com/ternimal/tern/security/advisories/new);
[SECURITY.md](https://github.com/ternimal/tern/blob/main/SECURITY.md) says
what to include.

## Where it works

The skills load wherever the plugin is installed. The tern tools come from a
local MCP server, so they work in Claude Code, Claude Desktop and Cowork
sessions that run on your computer, not in claude.ai chat.

## License

AGPL-3.0-only, the same as Ternimal. See [LICENSE](LICENSE).
