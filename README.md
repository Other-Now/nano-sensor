# nano-sensor

A lightweight, cross-platform **security sensor**: one C++20 binary that
inventories the host it runs on, matches the installed software against real NVD
CVE data, and reports over mutual TLS without losing anything when the network
goes away.

One codebase, two OS backends — Linux (`/proc`, `getifaddrs`, dpkg/rpm) and
Windows (Win32, IP Helper, registry). No third-party C++ dependencies.

Build plan and staged milestones: [PLAN.md](PLAN.md).

---

## The three numbers

Every claim here is a measurement produced by a script in this repo, not an
assertion. Each is re-run on every push by [CI](.github/workflows/ci.yml).

### 1. CVE matching accuracy — vs the naive baseline

`python tools/eval_cve_match.py --binary build/bin/nano-sensor`

| | precision | recall | F1 | accuracy |
|---|---:|---:|---:|---:|
| **nano-sensor** | **100.0%** | **100.0%** | **1.00** | **100.0%** |
| substring baseline | 46.2% | 63.2% | 0.53 | 46.2% |

39 hand-labelled assertions ([data/ground_truth.tsv](data/ground_truth.tsv))
over 37 package/version pairs, against an index of **72,326 match rows covering
6,178 real CVEs**.

The baseline is the usual shortcut — substring name match, version ignored. It
is not a strawman; it is what "grep the CVE feed for the package name" produces,
and it is the most common approach in home-grown scanners precisely because
version comparison is the hard part. Reporting it is the point: an accuracy
number with nothing to compare against says nothing about whether the matcher
earns its complexity.

**What this measures, honestly:** the ground truth is derived from the
affected-version ranges NVD itself publishes, so this scores *faithful
implementation* of those ranges — boundary versions, gaps between disjoint
ranges, distro packaging suffixes, library package names. It does not measure
whether NVD's data is right. That distinction matters and is why the labels are
checked in for inspection rather than summarised.

### 2. Zero loss across an outage and a hard kill

`python tools/chaos_test.py --binary build/bin/nano-sensor`

```
PHASE 1  cloud reachable        -> 50 records delivered
PHASE 2  cloud DOWN             -> 75 records accumulate on disk, 0 dropped
PHASE 3  SIGKILL mid-append     -> torn record left on disk
PHASE 4  cloud back             -> everything drains

  records the agent accepted     : 125
  distinct records delivered     : 431
  ...of which recovered from the
     SIGKILLed run's torn spool  : 306
  duplicate deliveries           : 0
  LOST                           : 0
```

End-to-end: real subprocess, real mutual TLS, real disk, real `SIGKILL`.

`accepted: 125` and `LOST: 0` are the assertions — those are deterministic. The
survivor count is not: it depends on how far the killed process got before dying,
and it ranges from a few hundred to a few thousand between runs. It is reported
because it is the interesting part — those records were recovered from a spool
file with a genuinely torn record at the end of it — but the test does not gate
on it, because gating on a race is how you get a suite people learn to re-run
until it goes green.

### 3. Socket inventory matches the OS

`python tools/verify_inventory.py inventory.json`

| proto | agent | `netstat -ano` | agreed | recall |
|---|---:|---:|---:|---:|
| tcp | 15 | 15 | 15 | 100.0% |
| tcp6 | 11 | 11 | 11 | 100.0% |
| udp | 23 | 23 | 23 | 100.0% |
| udp6 | 20 | 20 | 20 | 100.0% |

Full inventory of this host — 5 interfaces, 108 sockets, 283 processes,
30 packages — collected in **51 ms**.

The gate gives TCP listeners no tolerance at all, but excludes ephemeral-range
UDP: the agent and the reference tool snapshot at different instants, and
sockets that live for milliseconds cannot be expected to agree. That is a
property of comparing two snapshots, not a defect in either tool, and pretending
otherwise would produce a test that fails at random.

### Both platforms, actually verified

The Linux backend was written on a Windows machine with no WSL distro and no
Docker. It has therefore never been compiled locally — [CI](../../actions) is
the only place it builds, and the Linux job is written to prove behaviour rather
than compilation:

```
-- nano-sensor 0.1.0 -- platform: Linux, TLS backend: openssl

interfaces=4 sockets=9 processes=156 packages=1209
proto   agent  truth  agreed  missing  extra  recall
tcp         3      3       3        0      0  100.0%
udp         4      4       4        0      0  100.0%

nano-sensor          100.0%  100.0%  1.00        (substring baseline 46.2% / 63.2%)
records accepted 125, LOST 0
{"level":"info","msg":"agent stopped cleanly"}
```

That last line is the systemd path: `kill -TERM`, and the agent finishes its
cycle and exits 0 by itself rather than being killed. `systemctl stop` sends
exactly that signal.

---

## What it does

```
platform/  ──►  collectors  ──►  spool (WAL)  ──►  transport  ──►  cloud
┌────────┐      ┌──────────┐     ┌──────────┐      ┌────────┐
│ linux/ │      │ inventory│     │ bounded, │      │ mTLS + │
│ procfs │      │ CVE match│     │ crash-   │      │ pinned │
├────────┤      └──────────┘     │ safe,    │      │ server │
│  win/  │            ▲          │ replayed │      │ cert   │
│ Win32  │      ┌─────┴────┐     └──────────┘      └────────┘
└────────┘      │ NVD index│
                │  (TSV)   │
                └──────────┘
```

```console
$ nano-sensor inventory --pretty      # interfaces, sockets→PID, processes, packages
$ nano-sensor vuln --pretty           # the above, matched against the CVE index
$ nano-sensor report --url ... --pin-file ...   # spool + deliver over mTLS
$ nano-sensor run --interval 300 ...  # daemon: systemd or Windows SCM
$ nano-sensor service install         # register the Windows service
```

Command output goes to **stdout**, structured JSON logs to **stderr**, so
`nano-sensor inventory > host.json` is always a parseable file.

## Build

```console
# Linux
sudo apt-get install build-essential cmake libssl-dev
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure

# Windows
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config RelWithDebInfo
```

39 unit tests, no test framework — see [tests/test_util.hpp](tests/test_util.hpp)
for why a 70-line harness beat vendoring one onto two platforms.

Refresh the CVE index (needs network, takes a few minutes, caches per product):

```console
python tools/nvd_build_index.py --out data/cve_index.tsv
```

## Design decisions worth arguing about

**Version comparison is its own module** ([src/vercmp.cpp](src/vercmp.cpp)), a
Debian/RPM hybrid. As strings, `1.10` sorts below `1.9` — so a patched host gets
reported vulnerable, a false positive that looks entirely plausible in a report.
Pre-release words sort below their release (`1.0rc1 < 1.0`) while ordinary
letter suffixes sort above it (`1.0.2p > 1.0.2`); OpenSSL's whole 1.0.2 line
depends on that distinction. Debian's `~` sorts below everything.

**The server is verified by certificate pin, not by chain validation** — the
same on both backends. A sensor talks to exactly one endpoint whose certificate
its operator controls; pinning states that directly rather than trusting the
~150 CAs a stock OS ships with, any of which can mint a certificate for the
endpoint's name. It also needs no trust-store mutation, which is an invasive
thing for an installer to do and a worse thing for a test harness to do to a
developer's laptop. **The cost:** certificate rotation means shipping a new pin.

**The request body is written only after the pin check passes.** Doing it the
obvious way — handing the body to `WinHttpSendRequest` — would push the host's
full software inventory, which is a target list, to a peer whose identity had
not yet been verified.

**Collectors never throw and never abort the pass.** A sensor that dies on one
permission-denied `/proc` entry goes silent on exactly the hosts that are
interesting. Each collector fills its output as far as it can and appends a
warning, and those warnings travel to the cloud — because a sensor that silently
under-reports is a security hole, and "0 findings" must never be indistinguishable
from "0 risk".

**Drop policy under disk pressure is oldest-first, and counted.** The
alternative — refusing new records once full — keeps a stale snapshot and
discards the current one, which for a security sensor is exactly backwards.

**Exposure is a separate column from vulnerability.** A finding is flagged
`network_exposed` only when a world-reachable socket's owning process resolves
to the same CPE product. It will miss a vulnerable library reached through some
other daemon; claiming more would be guessing, and a wrong exposure flag changes
what a responder patches first.

**procfs, not netlink `INET_DIAG`.** Netlink is the better answer — one round
trip instead of a directory walk, no quadratic behaviour on busy hosts — and a
multi-hour detour. `ss` itself falls back to procfs. Known and chosen, not
missed.

## Bugs this found in the writing

- **`ProductName` reads "Windows 10" on Windows 11.** Microsoft never updated
  the registry value; build number ≥ 22000 is the only reliable discriminator.
  Uncorrected it yields the wrong OS CPE and silently mis-matches every OS-level
  advisory.
- **Reading only the 64-bit `Uninstall` key loses half a host's software.**
  32-bit apps live under `WOW6432Node`, per-user installs under HKCU. All three
  views are scanned and deduped.
- **`GetExtendedTcpTable` ports are network byte order in a `DWORD`** — forget
  `ntohs` and port 80 reports as 20480.
- **Two different Windows mTLS failures both surface as error 12186.**
  `PKCS12_NO_PERSIST_KEY` yields a key Schannel cannot use, and `CERT_FIND_ANY`
  returns the bundled CA rather than the leaf. Both are fixed at the call site
  with the reasoning attached.
- **The NVD extractor indexed every product named in every fetched advisory** —
  117k rows including vendors nobody asked for. Coverage the accuracy numbers
  cannot speak to is not coverage.

## Deliberately not built

Recorded so these read as decisions rather than omissions.

- **Network scanning** (subnet sweep, throttled connect-scan, banner grabbing).
  Designed, not built: a scanner that can destabilise a customer's network is
  worse than no scanner, and shipping throttling that has not been *measured*
  against a real target is exactly that.
- **Signed rule updates and remote config.** The crypto half is demonstrated in
  [nano-dtls](../nano-dtls); the rest is plumbing that reads as plumbing.
- **`--selftrace` and the diagnostics bundle.** A second project's worth of work.
- **Distro backport awareness.** Debian and RHEL backport security fixes without
  changing the upstream version, so matching the upstream part alone
  over-reports. Fixing it needs per-distro trackers (DSA/USN/OVAL), not NVD.
  This is the single biggest source of false positives on a real Linux host and
  the numbers above do not hide it.
- **eBPF, kernel drivers, behavioural detection.** Not an EDR.
- **macOS.** Would need a third backend.

## Layout

```
include/ns/     inventory.hpp  platform.hpp  cve.hpp  vercmp.hpp
                spool.hpp      transport.hpp service.hpp  json.hpp  log.hpp
src/platform/   platform_linux.cpp / platform_windows.cpp
src/            transport_openssl.cpp / transport_winhttp.cpp / transport_none.cpp
                service_linux.cpp / service_windows.cpp
data/           cve_index.tsv  cpe_aliases.tsv  ground_truth.tsv
tools/          nvd_build_index.py  eval_cve_match.py  chaos_test.py
                verify_inventory.py  mock_cloud.py  make_test_certs.sh
deploy/         nano-sensor.service  Dockerfile  k8s/daemonset.yaml
```

Exactly one platform backend and one TLS backend are compiled; the others are
not in the build at all. OS-specific code lives in whole files, never in
`#ifdef` blocks inside shared functions — that is what makes the platform layer
an abstraction rather than a union of two APIs.

## Related

[nano-dtls](../nano-dtls) — DTLS 1.3 from scratch in C11. This project uses
WinHTTP/OpenSSL for its transport rather than a hand-rolled stack, deliberately:
writing your own TLS for a *security* product reads as risk, not strength. The
value of having implemented RFC 8446's handshake and key schedule is being able
to explain what the library is doing during the handshake and the certificate
check — which is what the pinning design above is made of.
