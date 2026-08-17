# nano-sensor

A lightweight, cross-platform **security sensor**: one C++20 binary that
inventories the host it runs on, matches the installed software against CVE
data, and reports the result to a cloud endpoint over mTLS without losing
anything when the network goes away.

One codebase, two OS backends (Linux `/proc`, Windows Win32). Full build plan
and staged milestone list: [PLAN.md](PLAN.md).

## Status: stage 0 of 5 — scaffold, compiling and running

This is the honest state of the repo right now, not a description of the
finished thing.

| | |
|---|---|
| **Builds** | Windows / MSVC 19.44 (x64), clean at `/W4 /permissive-` |
| **Linux** | Backend is **written but not yet compiled or tested** — no WSL distro or Docker on the development machine yet. Treated as unverified until it is |
| **Works today** | `nano-sensor version`, `nano-sensor inventory` (host facts only) |
| **Stubbed** | interfaces, listening sockets, processes, installed packages — on both platforms |

The stubs are honest stubs: they report `implemented = false`, so the emitted
report says *"not collected on this platform"* rather than silently claiming the
host has zero listening sockets. Under-reporting is the one failure mode a
security sensor must never have.

```console
$ nano-sensor inventory --pretty
{
  "agent": { "name": "nano-sensor", "version": "0.1.0", "stage": "stage0-scaffold",
             "platform": "windows" },
  "collected_at_unix_ms": 1786971864208,
  "collect_duration_ms": 0,
  "host": {
    "hostname": "MANPRIT_01",
    "os_name": "Windows 11 Home Single Language",
    "os_version": "25H2",
    "kernel": "10.0.26200",
    "arch": "x86_64"
  },
  "interfaces": [], "listening_sockets": [], "processes": [], "packages": [],
  "warnings": [
    "interfaces: not implemented on windows yet",
    "sockets: not implemented on windows yet",
    "processes: not implemented on windows yet",
    "packages: not implemented on windows yet"
  ]
}
```

Command output goes to **stdout**, structured logs to **stderr**, so
`nano-sensor inventory > host.json` is always a parseable file even when the run
emitted warnings.

## Build

```console
cmake -S . -B build -G "Visual Studio 17 2022" -A x64     # Windows
cmake -S . -B build                                       # Linux
cmake --build build --config RelWithDebInfo
```

No third-party dependencies at stage 0. OpenSSL arrives with the transport in
stage 3; SQLite with the CVE index in stage 2.

## The first real bug this found

`ProductName` in the registry reads **"Windows 10 Home Single Language"** on a
Windows 11 machine. Microsoft never updated the value, and the build number
(11 starts at 22000) is the only reliable discriminator. Left uncorrected it
would hand the CVE matcher the wrong OS CPE and mis-match every OS-level
advisory — a silent, plausible-looking wrong answer, which is the worst kind for
a scanner to produce.

The correction lives in the collector rather than downstream, on the principle
that platform quirks get normalised at the platform boundary and nowhere else.
See [platform_windows.cpp](src/platform/platform_windows.cpp).

## Layout

```
include/ns/     inventory.hpp   the OS-neutral asset model
                platform.hpp    the collector interface both backends implement
                json.hpp        a small writer (the agent emits JSON, never parses it)
                log.hpp         structured logging, one JSON object per line
src/platform/   platform_linux.cpp / platform_windows.cpp
                exactly one is compiled — the other is not in the build at all
```

Keeping OS-specific code in **whole files** rather than `#ifdef` blocks inside
shared functions is the entire point of the platform layer. If a field can only
be produced on one of the two platforms, it does not belong in the shared model.

## Deliberately not built

Recorded so these read as decisions rather than omissions. Each one was scoped
and dropped for a stated reason:

- **Network scanning** (subnet sweep, throttled connect-scan, banner grabbing).
  Designed but not built: a scanner that can destabilise a customer's network is
  worse than no scanner, and shipping throttling that hasn't been *measured*
  against a real target is exactly that.
- **Raw-socket SYN scan.** Needs root/Npcap. Connect-scan is the polite choice
  and being polite is the product requirement here.
- **Signed rule updates and remote config.** Plumbing that reads as plumbing;
  the crypto half is already demonstrated in [nano-dtls](../nano-dtls).
- **Proxy `CONNECT` traversal, `--selftrace`, diagnostics bundle.** A second
  project's worth of work.
- **eBPF / kernel drivers / behavioural detection.** Not an EDR.
- **macOS.** Would need a third backend (`libproc`, `sysctl KERN_PROC`).
- **The full ~300k-CVE NVD feed.** A checked-in subset covering the
  ground-truth product set keeps the repo small and the demo offline.

## Related

- [nano-dtls](../nano-dtls) — DTLS 1.3 from scratch in C11. This project uses
  OpenSSL for its transport rather than a hand-rolled stack, deliberately; the
  value of having written one is being able to explain what OpenSSL is doing
  during the handshake and the chain validation, not shipping it in a security
  product.
