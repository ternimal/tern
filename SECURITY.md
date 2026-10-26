# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull
requests. Use the repository's private vulnerability reporting: the
**"Report a vulnerability"** button under its **Security** tab
(https://github.com/ternimal/tern/security/advisories/new) opens a private
advisory. Include a description, affected version/commit, and a reproduction
if possible. We aim to acknowledge within a few days and to coordinate a fix
and disclosure.

## Supported versions

Only the latest release and `main` receive security fixes.

Binary scanners report GO-2026-5932 (`golang.org/x/crypto/openpgp`, which has
no fix) against the release binaries because x/crypto is a dependency.
Ternimal does not import or link that package, so the binaries are not
affected; `govulncheck ./...` on the source finds no vulnerable code reached
(it lists GO-2026-5932 only as present in a required module).

## Threat model and scope

Ternimal is an authenticated remote terminal, so some behaviors are
intentional and are **not** vulnerabilities:

- **Authenticated clients are trusted on the agent.** A client that passes auth
  gets an interactive shell, command execution, port forwarding, and file copy.
  `tern cp` and `tern run` are therefore unsandboxed by design (full read/write
  and exec with the agent's privileges); this is not a privilege-boundary break.
  Run `ternd` as a least-privileged user if that matters.
- **Read-only viewing is not an access control.** `--read-only` and the
  single-writer default are choices the client makes; any authenticated client
  can co-drive a session (`--read-only=false`), run commands, or copy files.
- **The relay (`ternr`) is an opaque byte-pipe.** Inner TLS + auth are
  end-to-end between client and agent, so the relay cannot read shell plaintext
  or impersonate an agent (it lacks the agent's private key, so it cannot
  present the pinned certificate). The relay token is a shared secret: anyone
  holding it can register or displace an agent id (a denial of service), but
  still cannot read traffic or impersonate. The relay-mode `tern1:` string
  `ternd` prints holds no secret: the relay token comes from
  `TERN_RELAY_TOKEN` or a token file. A string you add the token to carries
  it, so share that only with people you would give the token. The token
  never crosses the wire: agents and clients prove it to the relay with an
  HMAC over the relay's challenge, bound to its certificate and to that TLS
  session, so a relay someone else's `tern1:` string names learns nothing
  usable on yours (a weak token can still be guessed offline; use
  `tern genkey`). A relay holds at most 256 unpaired registrations and 256
  bridges per address (an IPv4 address or IPv6 /48), and in all an eighth of
  its file-descriptor limit in registrations and a sixteenth in bridges, at
  most 1024 of each. A party at its cap gives up its oldest registration or
  is refused a bridge. A full relay makes room only from a heavier party: it
  weighs peers by the address blocks that hold them and takes a place only
  from a block holding at least two more than the newcomer's own, else
  refuses the newcomer, so an established bridge or an idle registration is
  never closed for an equal newcomer. A registration unpaired for 10 minutes
  is renewed.
- **No brute-force lockout.** Use high-entropy tokens or OpenSSH keys, and keep
  listeners behind a firewall/VPN. `tern genkey` prints 32 random characters;
  `ternd` refuses an agent token and, in relay mode, a relay token, `ternr` and
  `rtern` a relay token, and `tern api` a gateway token shorter than 16
  characters (counted in bytes). Handshakes not yet authenticated are capped at
  64 per source address (an IPv6 /64 counts as one; a /56 holds at most 128 and
  a /48 256) and, in all, a quarter of the file-descriptor limit (16 to 4096),
  with at most an eighth of it (8 to 1024) waiting. Over its source's cap a
  connection takes the place of the handshake of that source whose peer has
  sent nothing at all for longest since the agent began to read it, once that
  is 20 ms, never of one whose ClientHello has begun to come; if there is none
  it waits up to 5 s, at most 192 per source, and past that, or past the
  listener's waiting room, it is closed at once. A full listener admits a
  newcomer by closing one handshake: the one that has gone longest without a
  whole ClientHello, if that is over 20 ms and, going down the address blocks
  (IPv6 /32, /40, /48, /56, /64; IPv4 /16, /24, the address), its own block
  holds as many handshakes as the fullest one at the first level where the two
  differ; otherwise the oldest handshake of the source reached by going down
  into the fullest block at every level. A peer that sends no whole ClientHello
  within 3 s (in at most 32 records) is dropped. So a few sources, or many in
  one provider's block, cannot crowd out the rest. In relay mode an agent keeps
  at most 64 paired handshakes in flight (10 s each, a wait for a signature
  check included).
- **The pre-auth caps tell clients apart only by their address.** Run
  `ternd`, `ternr` and `rtern` where they see each client's own address.
  Behind an L4 proxy, load balancer or port forward that replaces it with its
  own (socat, an SSH `-L` forward, docker-proxy, a Kubernetes Service that
  rewrites the source), every client shares one source, and on a loopback
  address every local user does. There one unauthenticated peer can hold
  that source's 64 handshake slots and 192 waiting places: connections that
  send nothing give way to newcomers 20 ms after the agent begins to read
  them, but a peer that sends part of a ClientHello and stalls (each holds
  its slot up to 3 s), or a whole one (up to 15 s after it), or opens silent
  connections faster than they give way, keeps the other clients of that
  source waiting or refused for as long as it keeps going. Limit who can
  reach such a listener (firewall, VPN), or use a proxy that keeps client
  addresses.
- **Secrets belong in the environment or a file, not on the command line.**
  Prefer `TERN_TOKEN`/`TERN_RELAY_TOKEN`/`TERN_API_TOKEN` or the matching
  `--*-token-file`; a plain `--token` flag is readable by other local users
  through `/proc/<pid>/cmdline`, and the tools warn when one is used. A token
  file (`--token-file`, `--relay-token-file`, `--api-token-file`, `tern mcp`'s
  `token_file` and `relay_token_file`, and a `tern1:` file that carries the
  relay token) must be private: the tools refuse one other local users could
  read or change, and print the fix, which for a file another account owns or
  others could read starts with a new secret rather than taking the file over.
  Client private keys are held to ssh's rule instead: one of the user's that
  others could open is refused, while on Unix one another account owns, as a
  deploy key root keeps for a group or a Kubernetes secret volume's, is taken,
  its owner being free to use it anyway, and so is a pipe of the user's
  (`--key <(op read ...)`), read for at most 30 seconds; on Windows SYSTEM or
  Administrators may own the key too, and no other account may open it. A
  `tern1:` file and tern mcp's config name the agents to trust: one another
  account owns (root, SYSTEM and Administrators aside) or others could change,
  or could have put in its place (see the next point), is refused, though
  others may read the config and a `tern1:` file without the relay token.
  Startup connect lines are printed in `TERN_TOKEN=... tern connect ...` form,
  with the real token shown only when the tool generated it; the relay token a
  `ternd` was given appears only as a `<relay-token>` placeholder. `ternd` and
  `tern api` make up and print a token only on a terminal; with no credential
  configured (no token, and for `ternd` no `--authorized-keys`) and no
  terminal, as a service, they refuse to start, unless `tern api` is given
  `--api-insecure-no-token` (see below).
- **Key, certificate and authorized_keys files are checked before they are
  read.** `ternd`, `ternr` and `rtern` refuse a TLS key another account owns
  or others could open. They refuse a certificate, and `ternd` an
  `--authorized-keys` file, that another account owns (root, SYSTEM and
  Administrators aside) or others could change (on Unix, group write counts
  unless the group is the user's own private group and the file has no ACL,
  which tern reads only on Linux, where an NFS, SMB or AFS file without
  POSIX ACLs counts as having one), so another local user cannot add a login
  key or change the agent's certificate; others may read these two. An
  `--authorized-keys` file, a `tern1:` file and tern mcp's config are
  refused too when another account could have put them in their place, as
  ssh's StrictModes refuses such an authorized_keys: on Unix the directory
  that holds the file must be the user's or root's and, unless it is sticky
  as `/tmp` is, not writable by others; and a symlink at the path, and each
  link it leads to, must be the user's or root's (SYSTEM's or
  Administrators' on Windows), on Unix in such a directory, and lead to the
  file that was opened. The certificate need not be in such a place: it
  serves only with the key it matches, so one put in its place could only
  change the fingerprint clients pin, and they would refuse it. Directories
  further up are not looked at, nor, on Windows, a directory's ACL, nor a
  hard link another user made at the name in a sticky directory before the
  file was there, to a file of root's, which macOS, the BSDs and Linux with
  `fs.protected_hardlinks=0` let any user make; and on macOS an ACL entry
  (`chmod +a`) can let another user change a file whatever its mode, which
  tern, as ssh, does not read. These files, and token, `tern1:` and config
  files, are read only if they are regular files, and a client key only if
  it is one or a pipe, so a FIFO or device someone puts at the path cannot
  hang a tool or feed it without end, and only within 64 KiB (1 MiB for a
  certificate, config or authorized_keys file). The checks come before
  anything is read, except that a `tern1:` file others may read is read to
  learn whether it carries the relay token.
- **`authorized_keys` options, certificates and some key kinds are not
  supported.** A key line carrying per-key options (`from=`, `command=`,
  `restrict`, ...) or a certificate line is skipped with a warning rather than
  honoured, so a restriction the operator expected is never silently ignored.
  List the plain public key instead. Public-key auth takes Ed25519, ECDSA
  (nistp256, nistp384, nistp521) and RSA keys of 1024 to 8192 bits with the
  exponent 65537. Any other key (DSA, security keys such as sk-ssh-ed25519,
  RSA keys of another size or exponent, and an Ed25519 key that is a point
  of small order, for which a signature needs no private key) is skipped
  with a warning (a line tern cannot read at all, such as a key of a kind it
  does not know, is skipped without one), refused by the client that would
  use it, and refused unchecked when offered, so an unauthenticated peer
  cannot make the agent check a costly signature: an agent with no keys
  listed checks none, the costliest it checks (P-521, 8192-bit RSA) take a
  few milliseconds, at most as many run at once as the agent has CPUs, and
  those slow checks take at most half of its CPU time. A check waits only
  while its handshake holds its pre-auth slot: one closed to make room
  leaves the queue unchecked. Slow kinds are not flood-resistant: checks of
  P-384, P-521 and RSA keys over 3072 bits wait behind every such check in
  flight, so peers on many networks (64 IPv4 addresses, or 16 IPv6 /48s,
  fill even the largest listener) can delay such a login on a small agent
  up to the 15 s handshake deadline (measured: 14 to 15 s with one CPU, 7 s
  with two); Ed25519, P-256, RSA up to 3072 bits and tokens stay fast.
  Prefer Ed25519 (`tern keygen`).
- **Token auth never sends the raw token.** Both token and public-key auth are
  challenge-response bound to the agent's pinned certificate and to the TLS
  session itself (keying material exported from it): the client proves the
  token with an HMAC over a fresh challenge, so a malicious agent you reach
  cannot learn a token to reuse against another agent (a weak token can still
  be guessed offline from a proof; use `tern genkey`), and a proof cannot be
  replayed or passed on to another connection, not even to another agent that
  holds the same certificate and key. The relay token is proved to a relay the
  same way. Neither agents nor relays accept a raw token. With
  `--insecure-skip-encryption` there is no TLS session and the proof is bound
  to nothing (see below).
- **Ids and addresses carry no shell syntax.** Agent ids are letters, digits
  and `. _ - @ : +` (first a letter or digit). A `tern1:` string with any
  other id, a malformed address or a non-hex fingerprint is refused, and
  printed `tern connect` commands quote what they include, so pasting one runs
  nothing else.
- **An agent cannot flood its client.** A client closes its connection to an
  agent that opens a stream for no `-R` forward it set up, and reads at most
  64 stream headers at once.
- **Certificate pinning is mandatory and fail-closed by default.** Clients
  verify the agent's TLS certificate by SHA-256 fingerprint; an empty or
  mismatched fingerprint fails the handshake, with no trust-on-first-use.
  Obtain the fingerprint over a trusted channel (it is printed by `ternd` and
  embedded in the `tern1:` connection string). The `--insecure-skip-fingerprint`
  and `--insecure-skip-encryption` flags turn this off for testing only; see
  **Dangerous flags** below.
- **The REST gateway is a remote-exec endpoint.** By default it requires a
  bearer token (started on a terminal, `tern api` mints one if you set none)
  and rejects requests a web page could make (any `Origin` header, a non-JSON
  POST, or, when it listens on loopback, a `Host` that is not loopback, the
  host given to `--api-addr` or a trusted host, on every route including
  `/v1/healthz`), so a visited site cannot drive it. It still serves plain HTTP
  (and warns when bound off loopback), so bind it to 127.0.0.1, ::1 or
  localhost, which hold the port on both 127.0.0.1 and ::1, as does a host name
  that names one of them and nothing outside loopback (any other host name
  holds every address it names, on Linux even one the system does not have yet,
  as an IPv6 address during duplicate address detection, which elsewhere is
  passed over with a warning), or sit it behind TLS + a proxy. Connections that
  carried the token are capped too; past the cap a new one's request is
  refused, and none already admitted is closed to make room. A later request on
  a kept-alive connection is held to the 64 header lines by what net/http
  parsed, so a token holder can make the gateway parse up to about 16 KiB of
  header per connection for at most 5 s. Through a relay it pins each agent id
  to that agent's own fingerprint (`--api-agent ID=FINGERPRINT`) and refuses an
  id it has none for, so agents never need to share a key. Only
  `--api-insecure-no-token` runs it without a token; see **Dangerous flags**
  below.

In-scope issues include: authentication/authorization bypass, certificate-pinning
bypass, the relay gaining plaintext access or impersonating an agent,
unauthenticated remote code execution or crashes, and memory-safety problems.

## AI agents (`tern mcp`)

`tern mcp` serves agents to AI clients over the Model Context
Protocol. Its policy protects you from a model doing what you did not intend.
It does not change what an agent grants an authenticated client, so:

- **The policy runs on your machine.** `tern mcp` holds your credentials and
  checks each call the model makes against the target's profile before it
  reaches the agent (to learn a host's OS it also runs a fixed `uname -srm`
  and, where that fails, as on Windows, `cmd /c ver`). Whatever controls your
  machine or the MCP client process can use those credentials directly, and
  the agent still gives an authenticated client full access (see above).
  Give `tern mcp` credentials only for hosts the AI should reach, and run
  `ternd` with no more privilege than the work needs.
- **Command output is untrusted input to the model.** A file or a command's
  output can carry instructions meant for the model (prompt injection). The
  tool descriptions say so, but a model can still be talked into an action its
  profile allows. That is why the default profile is read-only, shell mode,
  interpreters and writes are opt-ins, secret paths such as private keys,
  tern's own keys and the logins MCP clients keep are never readable or
  writable through the file tools, places that run code later, such as
  `authorized_keys`, cron, shell startup files, a repository's `.git`, the
  project files build tools run code from and the settings of MCP clients and
  editors, are never writable (also not through symlinks, Windows short names,
  trailing dots or spaces, or the spellings a case-insensitive file system
  folds, and in the workspace also where a link in or into it that `tern mcp`
  saw at startup leads; when that look cannot finish within its time and
  bounds, downloads and uploads are refused; a hard link to a secret is not
  caught), a private key file never crosses with `upload` or `download`,
  whatever its name (a key in another form, such as DER, an archive or a cloud
  service-account JSON, is not caught), and chosen actions can require your
  approval. These lists are best effort, and what a project's tools run is
  open-ended: give `tern mcp` a workspace of its own, such as `~/tern-work`,
  not a project or your home directory. The path rules bind the file tools; a
  `run` pattern you add that lets a command take any path, such as
  `["cat", "*"]`, reads whatever the agent's user can. Invisible characters,
  which could carry instructions you would not see, are removed from what the
  model reads. Text a terminal escape sequence hides is removed too and marked
  as hidden: in file content wherever a string sequence (a title, a DCS or APC
  string) hides anything, in command and terminal output where one hides a line
  break or more than 256 bytes or shares its line with other text, and in both
  where a control sequence is malformed, implausibly long or holds an
  intermediate byte programs do not write, or a control sequence or escape has
  a control character carried out inside it. A short title in output that a
  line feed ends before any other text is not marked (a title a shell sets in
  its prompt shares the prompt's line and is), nor a control sequence of the
  usual shape, such as a color or a cursor move, nor an escape that hides at
  most three characters, yet what these hide (up to 64 bytes of a control
  sequence's parameters, such as `;` or `>`, two intermediates, such as `$` or
  `!`, and its final byte, such as `|`) can still change how a shell reads a
  line. Reads that go on from `next_offset` never start inside a sequence, but
  one asked to start inside a sequence that a C1 control began, with no ESC,
  CAN or SUB in the 64 KiB before it, can take another C1 control there for the
  start of a sequence that hides what follows. Terminal text is a rendering of
  the screen: a carriage return, a backspace or an erase can make a line a
  shell runs show as another or as nothing there, unmarked; review scripts with
  `read_file`.
- **Shell mode and terminals hand the model a shell.** The policy cannot look
  inside a command line or keystrokes, so with `run.shell` or `pty` the AI can
  do anything the agent's user can, limited only by the approvals you require.
- **Approval relies on the client.** The form shows the exact action, escaped
  and never cut short; standard input or file content it carries is previewed
  (the first 800 bytes or 20 lines, the form says when it shows only part,
  and content that is not UTF-8 is marked binary with its SHA-256). The
  approval is bound to the whole action, content included, used once and
  valid for five minutes. A client that approves without asking you defeats
  it; when a client cannot ask at all, actions that need approval are refused.
  A client that takes the form but never answers holds the call for at most
  five minutes, and then the action is refused: `tern mcp` cannot tell
  whether a client showed the form.
- **Redaction is a safety net.** Known secret formats are removed from results
  and from the audit log; secrets in other formats are not, nor a secret
  longer than the 8 KiB of text on each side that each paged read is
  redacted with, or one inside an escape sequence that began more than
  64 KiB before a page. A value of several unquoted words is taken whole only
  on a line its name starts, and to the end of that line or a comment on it,
  so there redaction also takes what follows on it (`DB_PASSWORD=x ./run.sh`
  shows as `DB_PASSWORD=[REDACTED]`), as a private key's BEGIN line with no
  END takes the rest of a read. Such a value that starts with `$` or `{`, as
  a reference or an expression does, is taken as its first word only, and
  each ends before a word that starts a comment (`#`, and after `=` also `;`,
  `//` or `/*`), so a passphrase that starts or goes on so shows its other
  words.
- **On Windows, a batch file's arguments are checked.** `.bat` and `.cmd` files
  run under `cmd.exe`, which would read `&` and similar characters in an
  argument as a second command; the agent refuses such characters in a batch
  file's arguments and in its program name, however its path is written
  (without the extension, relative, `C:name`, `\\?\` or UNC).
- **Commands end with their client.** When a command is cancelled or its
  client leaves, the agent kills it and what it started: its process group,
  and on Linux every process still in its session or descended from it (a
  daemon that started a session of its own and whose parent has ended is not
  reached; when ternd sees a /proc of another PID namespace, as under
  `unshare -p` without `--mount-proc` or in a sandbox that keeps the host's
  /proc, only the process group is killed); on Windows the job object each
  command runs in, where ternd exiting ends its commands too, as it does
  where ternd is a container's process 1 (the kernel then ends the rest of
  the container), while elsewhere ternd exiting kills no command still
  running (its next write to its output ends it, unless it ignores SIGPIPE).
  ternd shutting down lets a kill under way finish (up to 5 seconds), then
  kills what a kill still under way has stopped, and begins none after, so
  no command is left stopped (processes that kill had not reached yet are
  left running, as any command is when ternd exits). On Unix, commands run
  in a session of their own, with no controlling terminal. A background job
  that holds none of the command's output is killed when the command ends
  (on Linux, with anything else left in its session); on macOS it is not. On
  Windows a terminal's shell runs in a job object too, so what it starts
  (`start`, `Start-Process`) ends with the session or with ternd. A program
  can still leave its job through a broker such as WMI's
  Win32_Process.Create or the Task Scheduler, as setsid or systemd-run can on
  Unix.
- **Local files hold sensitive data.** The audit log is redacted, but terminal
  recordings (`--record-dir`) hold exactly what the terminal showed, and the
  persistence state file names live sessions (`tern mcp` reattaches only
  sessions it named itself). All are created owner-only (on Windows with an
  owner-only ACL from the start); protect them like shell history. The
  workspace tools never upload or create tern's own files (the state file,
  audit log, recordings and config file, the token, key and `tern1:` files
  the config or the flags name, and tern's state and configuration
  directories), and without a home or state directory for such a file
  `tern mcp` refuses to start rather than put it in the directory it was
  started in. `ternd` logs the program each command runs, and its arguments
  only at debug level (`--verbose` or `TERN_LOG=debug`).
- **Insecure transports are refused.** A man in the middle could put
  instructions into command output, so `tern mcp` refuses the `--insecure-*`
  connection flags unless `--allow-insecure-transport` is given.

In-scope issues for `tern mcp` include a model acting beyond its profile
(command, path or confirmation bypass, an approval replayed or applied to
another action, reaching a session it did not open), secrets surviving where
redaction claims to remove them, and calls that escape the audit log.

## Dangerous flags

A few flags deliberately weaken the defaults for testing and local convenience.
They are never needed in normal use, each prints a warning whenever it is
active, and they must not be used in production. Their behavior is by design and
not a vulnerability:

- **`--insecure-skip-fingerprint`** on the client commands (`tern connect`,
  `tern run`, `tern forward`, `tern cp`, `tern list`, `tern api`, and
  `tern mcp` with `--allow-insecure-transport`) and on `rtern` skips TLS
  fingerprint verification. The connection is still encrypted, but the agent
  and relay are not authenticated, so anyone able to intercept it can
  impersonate them (man-in-the-middle), see what the client sends and decide
  what it shows, and guess a weak token offline from the proof it receives;
  that proof is bound to the TLS session it has with the client, so it cannot
  be passed on to the real agent or relay. It cannot be combined with
  `--fingerprint`, `--relay-fingerprint` or a `tern1:` string, which already
  pin the peer; it does not weaken how the client authenticates itself to the
  agent.
- **`--insecure-skip-encryption`** on the same client commands, on `rtern` and
  on `ternd` runs the session in plaintext with no TLS at all; both ends must
  run in plaintext (this flag or `--insecure-dangerous`). There is neither
  encryption nor peer authentication (through a relay, or to `rtern`, anyone
  with the relay token can pose as the agent), so the whole session,
  including the token's proof or the key's signature exchanged at auth
  (never the token itself), travels in cleartext and can be read or altered
  by anything on the path (the relay too, in relay mode). A token or key is
  still required, but does not protect confidentiality, and a peer on the
  path can pass the exchange on to another agent that also runs in plaintext
  and trusts the same token or key: keep test credentials apart from real
  ones. A client accepts only a 32-byte challenge, so a proof made over
  plaintext cannot be made to pass on an agent that uses TLS. The relay hop
  keeps its own outer TLS.
- **`--insecure-dangerous`** on the client commands, on `rtern` and on `ternd`
  is a shorthand that turns on both `--insecure-skip-fingerprint` and
  `--insecure-skip-encryption` at once, so the session has no TLS and the
  client does not verify the agent or relay; the agent still requires the
  token or key, whose proof then crosses in cleartext. Both ends must run in
  plaintext (`--insecure-skip-encryption` or `--insecure-dangerous`). On
  `ternd` in relay mode without `--relay-fingerprint` it also skips verifying
  the relay; a fingerprint that is given is still checked.
- **`--allow-insecure-transport`** on `tern mcp` lets it use the `--insecure-*`
  flags above, which it otherwise refuses: an AI acts on what commands print,
  so a connection someone can alter lets them steer the model.
- **`--api-insecure-no-token`** on `tern api` runs the REST gateway with no
  bearer token, on any address: on a non-loopback one it is an
  unauthenticated remote command-exec endpoint reachable from the network.
  Without it, `tern api` always uses a token, minting one on a terminal if
  you set none and refusing to start otherwise.
