# REST gateway (`tern api`)

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
[SECURITY.md](../SECURITY.md)).

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
loopback, they turn the `Host` check on there too.

## Endpoints

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

## Connection limits

A request's header must arrive within 5 seconds of connecting, and a request
without the token then gets 10 seconds to be answered. Headers are limited to
8 KiB (net/http allows 4 KiB more, and on a kept-alive connection also the 4
KiB it read ahead) and to 64 lines: a connection's first request is refused
(400) as soon as it passes them, and a later one, which only a connection that
carried the token can send, once net/http has parsed it (431). Connections
that have not yet carried a request with the token are capped at 128 per
client address (IPv6 /64; all of loopback counts as one) and a quarter of the
file-descriptor limit in all (16 to 1024). Past a cap one such connection is
closed to make room, never one that has carried an admitted request: past the
per-address cap one of that address's, past the total cap one of the address
block holding the most, and one that has not sent a whole request line within
20 ms goes first unless another block holds more. Connections that have
carried the token have a cap of their own, as large as the total one; past it
a new one's request is refused with 503 and that connection closed, and none
already admitted is closed to make room.

## Examples

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
