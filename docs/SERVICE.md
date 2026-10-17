# The service, the client, and the lock-down

```
  nsctl.exe  (any user)                          nano-sensor.exe  (NT SERVICE\nano-sensor)
  ─────────────────────                          ─────────────────────────────────────────
  CreateFile(\\.\pipe\nano-sensor,               pipe acceptor ── client thread per connection
     SECURITY_IDENTIFICATION)  ── kernel ACL ──►     │  impersonate caller → log DOMAIN\user, pid
  "status" / "scan 5000" /                           ▼
  "findings 7.0 20" / "affected CVE-…" / "dump"  Agent::handle ──► scan worker thread
                                       ◄── JSON ──    │            collect → CVE match → SQL Server
                                                      ▼
                                                  hang watchdog ── minidump + exit → SCM restarts
```

Two processes. The **service** (`nano-sensor.exe run`, started by the SCM)
owns the scanner, the database connection and crash handling. **`nsctl.exe`**
is a console client that owns nothing. It can crash, hang or be run by the
wrong user without affecting the service, and all it can do is send the
requests the pipe's ACL lets its caller send.

## Why each choice

| decision | reason |
|---|---|
| named pipe, not a localhost TCP port | A pipe has a security descriptor, so the **kernel** refuses unauthorised callers before the service reads a byte. A TCP port is open to every local process, and authentication would be the service's own, probably buggier, job. |
| message-mode pipe, one request → one JSON response | No framing protocol to get wrong. Responses larger than the 64 KB pipe buffer arrive as `ERROR_MORE_DATA` chunks that the client reassembles (tested with 300 KB). |
| client opens at `SECURITY_IDENTIFICATION` | The server can learn who the caller is, and logs it, but cannot *act as* the caller. If something squats the pipe name, it gets an identity, not an admin token. |
| client uses overlapped I/O with a timeout | A wedged service costs `nsctl` its timeout, not forever. This is what kept `nsctl status` usable against the deadlock and hang below. |
| thread per connection, max 8 instances | Simple, and a slow client cannot block others. Next-instance creation happens *before* handing off (see the race below). |

## Lock-down, layer by layer

| layer | setting | proof |
|---|---|---|
| **account** | `NT SERVICE\nano-sensor`, a per-service virtual account: no password, no group membership, its own SID | `sc qc` → `SERVICE_START_NAME: NT SERVICE\nano-sensor`; `nsctl status` → `"user":"NT SERVICE\\nano-sensor","elevated":false` |
| **privileges** | `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO` = `SeChangeNotifyPrivilege` only; the SCM strips everything else from the token | `sc qprivs` → `SeChangeNotifyPrivilege`; `status` → `"privileges_enabled":1` |
| **pipe DACL** | `D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)`: deny network logons; allow SYSTEM, *elevated* Administrators, and the owner (the service itself) | unelevated admin: `opening the pipe failed, error 5 (access denied)`; elevated: full `status` |
| **remote** | `PIPE_REJECT_REMOTE_CLIENTS` **and** the NU deny ACE: two independent locks | by construction |
| **pipe squatting** | first instance created with `FILE_FLAG_FIRST_PIPE_INSTANCE`; if another process already owns the name, the service refuses to start rather than share it | test `Ipc.refuses_to_share_a_squatted_name`; also happened for real when a stray dev agent held a pipe name |
| **binary** | `%ProgramFiles%\nano-sensor` (admin-writable only); `ImagePath` quoted | a service binary in a user-writable directory, or an unquoted path with spaces, is a privilege-escalation bug |
| **state dir** | `%ProgramData%\nano-sensor` (dumps, log): inheritance removed, only SYSTEM, Administrators and the service SID | unelevated `Get-ChildItem` → access denied |
| **SQL login** | SELECT/INSERT (+UPDATE `hosts`); no DELETE, no DDL | `tools\db\check_service_grants.ps1` (`EXECUTE AS LOGIN`): INSERT allowed; DELETE, DROP TABLE, CREATE TABLE denied |
| **recovery** | restart after 10 s, then 30 s, then stay down | a sensor that restart-loops forever is worse than one that is visibly down |

Evidence: [evidence/service-install.txt](evidence/service-install.txt),
[evidence/service-denials-and-sql-grants.txt](evidence/service-denials-and-sql-grants.txt).

The ACL is also tested without a live service.
`Ipc.stranger_is_denied_by_the_kernel` builds a restricted token (this user,
with the user SID and Administrators turned deny-only, i.e. "some other
standard user") and gets `ERROR_ACCESS_DENIED`. The control test gives the
same token a pipe with an `Everyone` ACE and gets in. So the denial comes from
this DACL, not from something incidental.

**What least privilege costs, measured.** On the same machine at the same
time, the service sees **37 packages and 10 findings**; the same scan as the
logged-in user sees **41 and 20**. The difference is per-user installs under
`HKCU`, which a service account doesn't see. Enumerating every user's hive
would need rights this account deliberately lacks. It's a trade-off, written
down rather than hidden.

## Bugs the real install found

None of these showed up in unit tests or console runs. All were found by
installing the service and debugging what it left behind.

**1. A diagnostics command that could hang the service.** About 2 minutes
after the first install, the SCM logged *"terminated unexpectedly… Restart
the service"*. The service's own hang watchdog had fired. The hang dump
([transcript](evidence/real-hang-status-count-windbg.txt)) showed the pipe
thread inside `Db::scalar` → `SQLExecDirectW` → `msodbcsql18!Np::ReadSync`,
called from `handle_status`: `status` was running `SELECT COUNT_BIG(*) FROM
dbo.findings`.

On the server side, `sys.dm_exec_requests` showed the query *running*, not
blocked (`MEMORY_ALLOCATION_EXT`). Timed by hand, the first count took **163 s**
and an immediate repeat **0.4 s**. The cause was the Express default
**`AUTO_CLOSE ON`**: idle, the database shuts down and its 1.16M-row table
leaves the buffer pool. Three fixes, each one sufficient on its own for this
case:
- `ALTER DATABASE … SET AUTO_CLOSE OFF` (in `schema.sql`)
- `status` never queries the database and never *waits* for the DB lock
  (`try_to_lock`); it reports `connected`/`disconnected`/`busy`. The command
  operators use when something is wrong must answer when the database is
  what's wrong.
- every ODBC statement gets `SQL_ATTR_QUERY_TIMEOUT` = 30 s, inside the
  watchdog's 120 s

The same hang hit the memory-soak agent independently. Its log reads
`"hang detected" … "stuck":"pipe:status","age_ms":"120078"`.

**2. The service would not start, but only as a service.** A change to make
the live log readable by admins (`_fsopen(_SH_DENYNO)` + `_dup2` onto stderr,
replacing `freopen_s`, whose `_SH_SECURE` sharing blocked even `Copy-Item`)
passed every console run. Under the SCM, the service failed with *"did not
respond to the start request in a timely fashion"*. A service has no stderr
at all, so the CRT sets `_fileno(stderr)` to −2, and `_dup2(fd, -2)` is an
invalid-parameter **fast-fail**. That happened before
`StartServiceCtrlDispatcher`, and before the crash handlers were installed,
so there was no dump and no log. Fix: give stderr a real descriptor (`NUL`)
first, then redirect it. Lesson: test the service as a service.

**3. A race that looked like "service not running".** Found by the
concurrent-client test, not the install. The acceptor handed a connected
instance to a worker *then* created the next listening instance. In that gap,
the only instances were busy ones about to close. A client got
`ERROR_PIPE_BUSY`, called `WaitNamedPipe`, the busy instances closed, the pipe
had zero instances, and `WaitNamedPipe` failed with `ERROR_FILE_NOT_FOUND`.
That's indistinguishable from "service not running". It failed in about 1 run
in 2; with the next instance created *before* the handoff, there were 0
failures in 200 repeats.

## Install / operate

```powershell
# elevated
powershell -File tools\install_service.ps1             # copies, registers, ACLs, grants, starts, collects evidence
powershell -File tools\install_service.ps1 -Uninstall
powershell -File tools\collect_service_state.ps1       # copy dumps + log out of the locked state dir

# any shell
nsctl status          # unelevated: access denied, by design
```
