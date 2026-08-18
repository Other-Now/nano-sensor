# nano-sensor — build plan

A weekend-scoped build. The constraint that sets the scope is not "what can be
generated in two days" but **"what can be written in two days and then defended
line by line in an interview"** — the second is much smaller than the first, and
it is the one that matters.

## 1. What this is

A lightweight cross-platform security sensor: it inventories the host it runs
on, matches the installed software against CVE data, and reports the result to a
cloud endpoint over mTLS without losing anything when the network goes away.

One binary, one codebase, two OS backends.

```
platform/  ──►  collectors  ──►  spool (WAL)  ──►  transport
┌────────┐      ┌──────────┐     ┌──────────┐      ┌────────┐
│ linux/ │      │ inventory│     │ bounded, │      │ mTLS   │
│  procfs│      │ vuln     │     │ crash-   │      │ POST   │
├────────┤      └──────────┘     │ safe,    │      │ +retry │
│  win/  │            ▲          │ replayed │      │ +spool │
│  Win32 │      ┌─────┴────┐     └──────────┘      │  drain │
└────────┘      │ CVE index│                       └────┬───┘
                │  (TSV)   │                            ▼
                └──────────┘                     mock-cloud/ (Python)
```

## 2. Scope decisions

Three of the nine capability areas in the target role are built properly. The
rest are designed and documented as explicit non-goals. That is the deliberate
trade: depth on three beats a thin smear across nine.

| Built | Not built (documented in README) |
|---|---|
| Asset inventory, Linux + Windows | Network scanning (subnet sweep, port scan, banners) |
| CVE/CPE matching + CVSS | Signed rule updates, remote config |
| mTLS reporting + disk spool + backoff/replay | Proxy `CONNECT`, `--selftrace`, diagnostics bundle |
| systemd unit + Windows service | Prometheus, Grafana |
| Dockerfile + K8s DaemonSet + CI | macOS backend |

## 3. The numbers this project has to produce

Every claim in the README must be a measurement, not an assertion.

1. **CVE matcher: precision / recall on ~40 hand-labelled packages, reported
   against a substring-match baseline.** Reporting the baseline you beat is what
   separates this from a toy. This is the headline result.
2. **Zero events lost** across a forced cloud outage plus a `kill -9` in the
   middle of a spool write, with the spool bounded at a configured size.

A third, cheap to collect once stage 1 lands: **collector cost** (wall-clock ms
and peak RSS per full inventory pass), because "lightweight" is otherwise a word
rather than a fact.

## 4. Stages

Each stage ends with a proof, not a checkbox.

| Stage | Build | Proof |
|---|---|---|
| **0** ✅ | CMake skeleton, platform abstraction, JSON writer, structured logging, `collect_host` on both OSes | Compiles clean at `/W4`; `nano-sensor inventory` emits JSON that `json.load` accepts |
| **1** ✅ | Inventory for real: interfaces, listening sockets → PID, processes, installed packages, both OSes | Output diffed against `ss -ltnp` / `netstat -ano` ground truth; collector cost measured |
| **2** ✅ | NVD subset → TSV index (Python, offline); C++ CPE matcher with version-range comparison; CVSS join | Precision/recall table vs substring baseline |
| **3** ✅ | Spool: append-only, bounded, ack watermark, crash-safe. mTLS POST over OpenSSL. Exponential backoff with jitter, replay on reconnect | Outage + `kill -9` chaos test showing zero loss and ordered replay |
| **4** ✅ | systemd unit + Windows SCM service wrapper | `systemctl status` / `sc query` green; clean shutdown on signal and on SCM stop |
| **5** ✅ | Dockerfile, K8s DaemonSet, CI, README with the numbers and the non-goals section | Image builds and runs the Linux backend |

**Ordering note.** Stage 4 was deliberately last and timeboxed. The agent runs
as a plain foreground process throughout, so if service registration had fought
back, the binary would still run and still demo — that would have cost one
bullet, not the project. It did not fight back, and the same binary now serves
as both the interactive tool and the service.

## 5. Design decisions worth defending

Written down now because these are what an interviewer will actually push on.

- **procfs, not netlink `INET_DIAG`, for socket enumeration.** Netlink is the
  better answer and a multi-hour detour; `ss` itself falls back to procfs. Know
  the difference out loud, ship the simpler one.
- **A platform TLS library terminates the mTLS, not a hand-rolled stack** --
  WinHTTP on Windows, OpenSSL on Linux. Writing your own TLS for a *security*
  product reads as risk, not strength. The credibility comes from having
  implemented RFC 8446's handshake and key schedule elsewhere (`nano-dtls`) and
  therefore being able to explain what the library is doing.
- **The server is verified by certificate pin rather than chain validation**, the
  same on both backends, and the request body is written only after the pin
  check passes. Pinning needs no trust-store mutation and states directly that
  the sensor talks to exactly one endpoint. The cost is that rotation means
  shipping a new pin.
- **The NVD feed is preprocessed offline in Python into a checked-in TSV
  index.** Real scanners preprocess feeds too; it removes JSON parsing in C++,
  removes a network dependency from the demo, and keeps the extraction policy
  (which CVSS version wins, which CPE nodes count) reviewable in a diff.
- **Collectors never throw and never abort the pass.** A sensor that dies on one
  permission-denied `/proc` entry goes silent on exactly the hosts that are
  interesting. Partial results plus explicit warnings beat all-or-nothing.
- **`world_reachable` is a first-class field on every socket.** It is what makes
  "vulnerable" and "actually exposed" separate columns in the final report.

## 6. Status

All five stages are built, tested, and measured. The number each stage had to
produce is in the README and is re-run by CI on every push.

## 7. Known risks

- **Windows internals is the real unknown.** `GetExtendedTcpTable` and
  Toolhelp32 are straightforward; the registry Uninstall keys need both the
  64- and 32-bit views or half the installed software goes missing. Budget the
  overrun in stage 1, not elsewhere.
- **CPE matching can eat the schedule.** The matcher stays general; the
  ground-truth set is capped at ~15 well-known products.
- **No Linux build environment on the development machine** (no WSL distro, no
  Docker). Mitigated rather than ignored: the full Linux build, unit tests,
  socket ground-truth diff against `ss`, CVE evaluation, chaos test, and a
  SIGTERM shutdown check all run in GitHub Actions on ubuntu-latest. CI is not
  a formality on this project — it is the only place the Linux backend is
  compiled at all.
