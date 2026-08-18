#!/usr/bin/env python3
"""A minimal mTLS ingest endpoint, standing in for the cloud.

Deliberately ~150 lines of Python rather than a second C++ service. The thing
under test is the AGENT's behaviour across an outage; the server just has to
terminate mutual TLS, count what arrives, and be killable on demand.

It refuses any client that does not present a certificate signed by the test CA,
so "the agent authenticated" is a property the harness actually verifies rather
than assumes.

Two knobs exist for the chaos test:
  --fail-rate N    reject a fraction of requests with 503, to exercise retry
  --outage-after N stop accepting after N successful batches, to simulate the
                   cloud going away mid-stream

usage:
    python tools/mock_cloud.py --pki build/testpki --port 8443
"""

from __future__ import annotations

import argparse
import json
import random
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATE = {
    "batches": 0,
    "records": 0,
    "rejected": 0,
    "record_ids": set(),
    "duplicates": 0,
    "outage_after": 0,
    "fail_rate": 0.0,
}
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A002 - signature fixed by the base class
        pass  # the harness prints its own timeline; the default log is noise

    def do_GET(self):  # noqa: N802 - name fixed by the base class
        if self.path != "/stats":
            self.send_error(404)
            return
        with LOCK:
            body = json.dumps({
                "batches": STATE["batches"],
                "records": STATE["records"],
                "rejected": STATE["rejected"],
                "distinct_records": len(STATE["record_ids"]),
                "duplicates": STATE["duplicates"],
            }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length) if length else b""

        with LOCK:
            if STATE["outage_after"] and STATE["batches"] >= STATE["outage_after"]:
                STATE["rejected"] += 1
                self._fail(503, "simulated outage")
                return
            if STATE["fail_rate"] and random.random() < STATE["fail_rate"]:
                STATE["rejected"] += 1
                self._fail(503, "simulated transient failure")
                return

        try:
            doc = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._fail(400, f"unparseable body: {exc}")
            return

        records = doc.get("records", [])
        with LOCK:
            STATE["batches"] += 1
            STATE["records"] += len(records)
            for rec in records:
                # The agent stamps every record with a stable id. At-least-once
                # delivery means duplicates are EXPECTED after a crash between
                # send and commit -- counting them here is how the harness proves
                # the retry path re-sends rather than loses.
                rid = rec.get("id")
                if rid is None:
                    continue
                if rid in STATE["record_ids"]:
                    STATE["duplicates"] += 1
                STATE["record_ids"].add(rid)
            accepted = len(records)

        body = json.dumps({"accepted": accepted}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, code: int, message: str):
        body = json.dumps({"error": message}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pki", default="build/testpki")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--fail-rate", type=float, default=0.0)
    ap.add_argument("--outage-after", type=int, default=0)
    args = ap.parse_args()

    pki = Path(args.pki)
    STATE["fail_rate"] = args.fail_rate
    STATE["outage_after"] = args.outage_after

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=pki / "server.crt", keyfile=pki / "server.key")
    # CERT_REQUIRED plus the CA is what makes this mutual TLS rather than
    # ordinary TLS. Without both lines the agent's client certificate would be
    # accepted-and-ignored, and the test would prove nothing about mTLS.
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=pki / "ca.crt")

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"mock cloud listening on https://127.0.0.1:{args.port} (mTLS required)",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
