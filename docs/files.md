# Keys, tokens and the files tern reads

tern, ternd, ternr and rtern check the files they read for tokens, keys,
certificates, `tern1:` strings, tern mcp's config and `authorized_keys`, and
refuse one that breaks the rules below, in most cases before reading anything
from it.

## Tokens

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

## Keys and certificates

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
- An encrypted client key asks for its passphrase once, when a command starts,
  and is reused for every later connection (shell reconnects, REST requests),
  so `tern api` with an encrypted key needs a terminal at startup.

## `authorized_keys`

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

`authorized_keys` options such as `from=`, `command=` or `restrict`, and
certificate lines, are not supported. Such a line is skipped with a warning
rather than granted access, so list the plain public key instead. A key of a
kind tern does not take (DSA, security keys, RSA under 1024 or over 8192 bits
or with an exponent other than 65537, an Ed25519 key of small order) is
skipped with a warning too.

## `tern1:` and config files

A `tern1:` file (`--to-file`, `to_file`) and tern mcp's config file say which
agents to trust. The tools refuse one another account owns (root, SYSTEM and
Administrators aside) or others could change: on Unix the other-write bit, or
the group-write bit unless the group is the user's own private group and the
file has no ACL (tern reads ACLs only on Linux); on Windows an ACL entry
letting another account change or delete it. They refuse one another account
could have put in its place too, through the directory it is in or a symlink,
as `ternd` does for [`authorized_keys`](#authorized_keys). Others may read
them, except a `tern1:` file that carries the relay token, which is held to
the token-file rule.

## Rules for every file

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
