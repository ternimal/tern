# Operating notes

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
- No brute-force lockout: keep listeners behind a firewall/VPN and use
  high-entropy tokens (`tern genkey`). The REST gateway serves plain HTTP, so it
  especially should bind localhost or sit behind TLS + a proxy; `tern api`
  warns when it listens elsewhere. The caps on unauthenticated handshakes tell
  clients apart by address, so run `ternd`, `ternr` and `rtern` where they see
  each client's own address: behind a proxy or port forward that hides it, as
  on a loopback address, one unauthenticated peer can keep every other client
  waiting.
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
