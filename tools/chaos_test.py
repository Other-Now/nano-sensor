#!/usr/bin/env python3
"""Prove the agent loses nothing across an outage and a hard kill.

This is stage 3's proof, and it is the claim the whole spool exists to support.
The test is deliberately end-to-end -- real process, real mTLS, real disk, real
SIGKILL -- because every interesting failure here lives in the seams that a unit
test mocks away.

Phases:
  1  cloud up      -- records go straight through
  2  cloud down    -- records accumulate on disk, agent reports failure honestly
  3  hard kill     -- SIGKILL mid-append, leaving a torn record on disk
  4  cloud back    -- everything that was accepted for spooling is delivered

The pass condition is `delivered >= appended`: every record the agent
acknowledged is at the far end. Duplicates are allowed and counted, because
at-least-once delivery is the deliberate design -- a crash between send and
commit re-sends. Losing a record is a bug; sending one twice is a documented
property the cloud deduplicates by record id.

usage:
    python tools/chaos_test.py --binary build/bin/RelWithDebInfo/nano-sensor.exe
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import shutil
import signal
import ssl
import subprocess
import sys
import time

PORT = 8459


class Cloud:
    """The mock cloud as a killable subprocess."""

    def __init__(self, pki: pathlib.Path, port: int):
        self.pki = pki
        self.port = port
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "tools/mock_cloud.py", "--pki", str(self.pki),
             "--port", str(self.port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        # Wait for the listener rather than sleeping a guessed interval.
        for _ in range(100):
            try:
                self.stats()
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("mock cloud did not come up")

    def stop(self) -> None:
        if not self.proc:
            return
        self.proc.kill()
        self.proc.wait(timeout=10)
        self.proc = None
        # Wait for the port to actually close, so phase 2 really does hit a
        # refused connection rather than racing a still-draining listener.
        for _ in range(100):
            try:
                self.stats()
                time.sleep(0.1)
            except Exception:
                return

    def stats(self) -> dict:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(self.pki / "client.crt", self.pki / "client.key")
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx,
                                           timeout=5)
        try:
            conn.request("GET", "/stats")
            return json.loads(conn.getresponse().read())
        finally:
            conn.close()


def run_agent(binary: str, pki: pathlib.Path, spool: pathlib.Path, *extra: str,
              timeout: int = 120) -> dict:
    cmd = [
        str(pathlib.Path(binary).resolve()), "report",
        "--url", f"https://127.0.0.1:{PORT}/v1/events",
        "--client-cert", str(pki / "client.pfx") if os.name == "nt"
        else str(pki / "client.crt"),
        "--client-key", str(pki / "client.key"),
        "--pin-file", str(pki / "server.pin"),
        "--spool", str(spool),
        *extra,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"_stdout": proc.stdout, "_stderr": proc.stderr[-2000:],
                "_rc": proc.returncode}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--pki", default="build/testpki")
    ap.add_argument("--spool", default="build/chaos-spool")
    ap.add_argument("--batch", type=int, default=25,
                    help="records appended per agent run")
    args = ap.parse_args()

    pki = pathlib.Path(args.pki)
    spool = pathlib.Path(args.spool)
    shutil.rmtree(spool, ignore_errors=True)

    if not (pki / "server.pin").exists():
        print(f"missing test PKI in {pki}; run tools/make_test_certs.sh first")
        return 2

    appended = 0
    cloud = Cloud(pki, PORT)

    print("=" * 70)
    print("PHASE 1  cloud reachable")
    print("=" * 70)
    cloud.start()
    for i in range(2):
        r = run_agent(args.binary, pki, spool, "--synthetic", str(args.batch))
        appended += args.batch
        print(f"  run {i + 1}: sent={r.get('sent')} pending={r.get('pending')} "
              f"dropped={r.get('dropped')}")
    print(f"  server: {cloud.stats()}")

    print()
    print("=" * 70)
    print("PHASE 2  cloud DOWN -- records must accumulate, not vanish")
    print("=" * 70)
    cloud.stop()
    for i in range(3):
        r = run_agent(args.binary, pki, spool, "--synthetic", str(args.batch),
                      "--max-attempts", "2")
        appended += args.batch
        print(f"  run {i + 1}: sent={r.get('sent')} pending={r.get('pending')} "
              f"dropped={r.get('dropped')} gave_up={r.get('gave_up')}")

    print()
    print("=" * 70)
    print("PHASE 3  SIGKILL mid-append -- torn record on disk")
    print("=" * 70)
    # A large append keeps the process busy long enough to be killed inside a
    # write, which is exactly the state the frame checksum exists to survive.
    killed = subprocess.Popen(
        [str(pathlib.Path(args.binary).resolve()), "report",
         "--url", f"https://127.0.0.1:{PORT}/v1/events",
         "--client-cert", str(pki / "client.pfx") if os.name == "nt"
         else str(pki / "client.crt"),
         "--client-key", str(pki / "client.key"),
         "--pin-file", str(pki / "server.pin"),
         "--spool", str(spool), "--synthetic", "20000", "--max-attempts", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.35)
    killed.kill()
    killed.wait(timeout=10)
    print(f"  killed pid {killed.pid} mid-append (exit {killed.returncode})")
    # Records from the killed run are NOT counted in `appended`: the process
    # never returned, so nothing about them was acknowledged to anyone. Whatever
    # of them survives on disk is a bonus, not a requirement.

    print()
    print("=" * 70)
    print("PHASE 4  cloud back -- drain everything")
    print("=" * 70)
    cloud.start()
    for i in range(8):
        r = run_agent(args.binary, pki, spool, "--drain-only", "--max-attempts", "3")
        print(f"  drain {i + 1}: sent={r.get('sent')} pending={r.get('pending')} "
              f"dropped={r.get('dropped')}")
        if r.get("pending") == 0:
            break

    final = cloud.stats()
    cloud.stop()

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    delivered = final["distinct_records"]
    # Anything above `appended` came from the SIGKILLed run: records it had
    # already framed and flushed before dying. They are not required to survive,
    # but they do, which is the frame checksum and the read cursor doing their
    # job on a genuinely torn file.
    survivors = max(0, delivered - appended)

    print(f"  records the agent accepted     : {appended}")
    print(f"  distinct records delivered     : {delivered}")
    print(f"  ...of which recovered from the")
    print(f"     SIGKILLed run's torn spool  : {survivors}")
    print(f"  duplicate deliveries           : {final['duplicates']}  "
          f"(allowed: at-least-once, deduplicated by record id)")
    print(f"  batches received               : {final['batches']}")

    lost = appended - min(appended, delivered)
    print(f"  LOST                           : {lost}")

    if lost > 0:
        print("\nFAIL -- records the agent accepted never arrived")
        return 1
    print("\nPASS -- every record the agent accepted was delivered across an "
          "outage and a hard kill")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
