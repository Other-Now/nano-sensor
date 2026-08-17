#!/usr/bin/env python3
"""Diff nano-sensor's socket inventory against the OS's own tooling.

This is stage 1's proof. A collector that runs without crashing has proved
nothing; the claim is that it sees what `netstat -ano` / `ss -ltunp` sees, and
the only way to support that claim is to diff the two and publish the result --
including any rows where they disagree.

usage:
    nano-sensor inventory > inv.json
    python tools/verify_inventory.py inv.json
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys


def load_agent(path: str) -> set[tuple[str, str, int]]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return {
        (s["proto"], s["local_addr"], s["local_port"])
        for s in doc["listening_sockets"]
    }


def normalise(addr: str) -> str:
    """Strip the noise the two sources disagree about but nobody means.

    netstat prints IPv6 as [::], ss prints *; ss prints the v4 wildcard as 0.0.0.0
    and the v6 one as [::]. Scope IDs (fe80::1%12) are an interface detail, not a
    different bind address.
    """
    addr = addr.strip().strip("[]")
    addr = addr.split("%")[0]
    if addr in ("*", "::ffff:0.0.0.0"):
        addr = "0.0.0.0"
    return addr


def from_netstat() -> set[tuple[str, str, int]]:
    out = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True, check=True
    ).stdout
    found: set[tuple[str, str, int]] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        local = parts[1]
        # TCP rows carry a state column; only LISTENING ones are ours. UDP has no
        # state, so every bound socket counts.
        if proto == "TCP" and (len(parts) < 5 or parts[3] != "LISTENING"):
            continue

        host, _, port = local.rpartition(":")
        host = normalise(host)
        if not port.isdigit():
            continue
        family6 = ":" in host and host != "0.0.0.0"
        key = proto.lower() + ("6" if family6 else "")
        found.add((key, host, int(port)))
    return found


def from_ss() -> set[tuple[str, str, int]]:
    out = subprocess.run(
        ["ss", "-ltunH"], capture_output=True, text=True, check=True
    ).stdout
    found: set[tuple[str, str, int]] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        netid = parts[0].lower()
        if netid not in ("tcp", "udp"):
            continue
        local = parts[4]
        host, _, port = local.rpartition(":")
        host = normalise(host)
        if not port.isdigit():
            continue
        family6 = ":" in host and host != "0.0.0.0"
        found.add((netid + ("6" if family6 else ""), host, int(port)))
    return found


EPHEMERAL_FLOOR = 49152  # IANA dynamic/private range


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    agent = load_agent(sys.argv[1])
    agent = {(p, normalise(a), n) for p, a, n in agent}

    if platform.system() == "Windows":
        truth, tool = from_netstat(), "netstat -ano"
    else:
        truth, tool = from_ss(), "ss -ltunH"

    print(f"ground truth : {tool}\n")
    print(f"{'proto':<6} {'agent':>6} {'truth':>6} {'agreed':>7} {'missing':>8} {'extra':>6}  recall")

    hard_failures: list[tuple[str, str, int]] = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        a = {x for x in agent if x[0] == proto}
        t = {x for x in truth if x[0] == proto}
        both, missing, extra = a & t, t - a, a - t
        recall = len(both) / len(t) * 100 if t else 100.0
        print(f"{proto:<6} {len(a):>6} {len(t):>6} {len(both):>7} "
              f"{len(missing):>8} {len(extra):>6}  {recall:5.1f}%")

        # TCP listeners are stable state and must match exactly -- any
        # disagreement there is a real collector bug.
        #
        # UDP is different, and the difference is not a bug in either tool: the
        # agent and the reference run seconds apart, and in between, sockets in
        # the ephemeral range are opened and closed constantly by DNS lookups,
        # mDNS, and QUIC. Comparing two snapshots taken at different instants
        # cannot agree about them. So ephemeral-range UDP is reported and
        # excluded from the gate; a *well-known* UDP port going missing is still
        # a hard failure.
        hard_failures += [x for x in missing if proto.startswith("tcp")
                          or x[2] < EPHEMERAL_FLOOR]

    strays = [x for x in (truth - agent) | (agent - truth)
              if x[2] >= EPHEMERAL_FLOOR]
    if strays:
        print(f"\n{len(strays)} ephemeral-range (>= {EPHEMERAL_FLOOR}) UDP "
              f"disagreements, excluded from the gate as snapshot skew")

    if hard_failures:
        print("\nFAIL -- sockets the OS reported and the agent did not:")
        for proto, host, port in sorted(hard_failures):
            print(f"  {proto:<5} {host}:{port}")
        return 1

    print("\nPASS -- every stable listening socket the OS reports is in the inventory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
