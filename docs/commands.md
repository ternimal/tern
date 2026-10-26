# Commands

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

## Sharing and resuming

Two people run `tern connect --session demo` to the same agent; the first is
the writer, the next is `[read-only]` (or pass `--read-only=false` to
co-drive) and leaves with Ctrl-C. `--read-only` only joins an existing
session. Drop and reconnect with the same `--session` to resume, within `ternd
--session-idle` (default 10m; 0 keeps a session until its shell exits).

Resume replays a scrollback buffer, the last 256 KiB of output, not a full
screen redraw.

## Copying files

As with `cp`, a destination ending in `/`, or an existing local directory,
keeps the file's name: `tern cp f agent:/tmp/` writes `/tmp/f`. An existing
remote directory needs the trailing `/`. A copy writes into the directory it
opened when it started, so a link or junction changed on the path meanwhile
does not move the file. A file of yours that exists keeps its mode, unless it
has a second name (a hard link) or another user may add names to its
directory, and so could have moved a file of yours there: the directory is
another user's (root aside), or its mode lets others write it, sticky or not,
or its group, unless that is your own private group and the directory has no
ACL (tern looks for one on Linux, taking a file system that keeps none as
having none, but not NFS, SMB or AFS; elsewhere group write always counts).
Such a file, or one another user owns, keeps no more than a new one would get;
a new one gets the source's, less the umask. On Windows a file of yours with
one name, whose ACL lets no other account change, delete, re-permission or
take it over, keeps that ACL, protected or not (an explicit deny stays),
unless another account (SYSTEM and Administrators aside) owns its folder or
may add files to it, delete them, or re-permission or take over the folder, as
other users may add files to a folder made under `C:\` (Users on Windows
Server, Authenticated Users on Windows 10 and 11); a folder whose owner and
ACL cannot be read counts too. Any other file, one another account owns
included (planted or moved there), is replaced as a new file would be:
owner-only for a private mode such as 0600, and when it replaces such a file
of yours that no other account may read, or whose ACL is protected (inherits
nothing from the folder) or holds an entry of its own other than an allow,
such as a deny, which the folder's could widen; otherwise with the folder's
inherited ACL. Windows will not replace a read-only file: the copy fails and
leaves nothing behind. On Windows a name holding `:` names a data stream: a
copy to it is refused.

## Port forwards

Forward specs are ssh-style, and an omitted bind host defaults to loopback
rather than all interfaces: `-L [lhost:]lport:rhost:rport`, `-R
[rbind:]rport:lhost:lport`; the local or bind host defaults to 127.0.0.1.
`tern forward` exits when a forward fails or the connection drops. `-L`/`-R`
given to `tern connect` use their own connection and are not re-established
after a drop. A bind host of 127.0.0.1 also holds the same port on ::1,
localhost holds it on both, a host name that names loopback addresses only,
such as ip6-localhost, holds it on every address it names (and on the other of
127.0.0.1 and ::1 beside either), and any other host name holds it on every
address it names (see [Operating notes](notes.md)), so no other local user can
listen beside a forward; a port taken there makes the forward fail. A spec
cannot hold an IPv6 address itself.
