#!/usr/bin/env python3
"""Assert that an inventory actually contains data.

Separate from verify_inventory.py, which compares sockets against the OS. This
one answers a blunter question: did the collectors return anything at all?

It exists because the Linux backend was written on a machine with no Linux on
it. "It compiles" and "it works" are very different claims, and a collector that
silently returns an empty vector on an unfamiliar platform would satisfy the
first while failing the second -- which is exactly the silent under-reporting
this project treats as the worst possible failure.

usage:
    nano-sensor inventory > inventory.json
    python3 tools/check_inventory_sane.py inventory.json
"""

from __future__ import annotations

import json
import sys

# Floors, not exact counts: CI runners differ, and a test that pins the process
# count to a number would fail on every image update for no reason.
MINIMUMS = {
    "interfaces": 1,
    "processes": 10,
    "packages": 20,
    "listening_sockets": 1,
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)

    failures: list[str] = []

    host = doc.get("host", {})
    for field in ("hostname", "os_name", "kernel", "arch"):
        if not host.get(field):
            failures.append(f"host.{field} is empty")

    for key, floor in MINIMUMS.items():
        got = len(doc.get(key, []))
        status = "ok" if got >= floor else "FAIL"
        print(f"  {status:<4} {key:<20} {got:>6}  (need >= {floor})")
        if got < floor:
            failures.append(f"{key}: {got} < {floor}")

    print(f"\n  host: {host.get('os_name')} {host.get('os_version')} "
          f"kernel={host.get('kernel')} arch={host.get('arch')}")
    print(f"  collected in {doc.get('collect_duration_ms')} ms")

    warnings = doc.get("warnings", [])
    if warnings:
        print("\n  collector warnings (reported, not hidden):")
        for w in warnings:
            print(f"    - {w}")

    if failures:
        print("\nFAIL -- " + "; ".join(failures))
        return 1
    print("\nPASS -- every collector returned data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
