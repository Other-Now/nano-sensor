#!/usr/bin/env python3
"""Build the checked-in CVE index from the NVD API 2.0.

Run offline, occasionally, by a human -- not by the agent. The agent loads the
resulting TSV and never talks to NVD itself.

Three reasons the split is this way round, all of which are how real scanners
work too:

  * The full NVD corpus is ~300k CVEs. Parsing that in C++ at every agent start
    would be minutes of work to answer questions about the ~30 products actually
    installed on a host.
  * A demo that depends on api.nist.gov being up and un-rate-limited is a demo
    that fails in front of an audience.
  * The extraction rules (which CVSS version to prefer, which CPE nodes count)
    are policy, and policy belongs somewhere reviewable and diffable rather than
    buried in a collector.

usage:
    python tools/nvd_build_index.py --out data/cve_index.tsv
    python tools/nvd_build_index.py --out data/cve_index.tsv --api-key $NVD_KEY
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# The product set the index covers. Kept small and explicit: this is a portfolio
# project with a hand-labelled ground truth, and an index covering products
# nobody labelled would inflate the row count without making the accuracy
# numbers mean any more.
#
# Chosen to span both target platforms -- the top group is what a Linux server
# actually runs, the bottom is what turns up in a Windows Uninstall key.
PRODUCTS = [
    ("openbsd", "openssh"),
    ("openssl", "openssl"),
    ("nginx", "nginx"),
    ("apache", "http_server"),
    ("python", "python"),
    ("postgresql", "postgresql"),
    ("redis", "redis"),
    ("haxx", "curl"),
    ("gnu", "glibc"),
    ("isc", "bind"),
    ("samba", "samba"),
    ("sudo_project", "sudo"),
    ("nodejs", "node.js"),
    ("docker", "docker"),
    ("git", "git"),
    ("7-zip", "7-zip"),
    ("videolan", "vlc_media_player"),
    ("wireshark", "wireshark"),
    ("mozilla", "firefox"),
    ("oracle", "virtualbox"),
]

COLUMNS = [
    "cve_id", "vendor", "product", "version", "update",
    "start_incl", "start_excl", "end_incl", "end_excl",
    "cvss_score", "cvss_severity", "cvss_version",
]


def fetch_page(vendor: str, product: str, start: int, api_key: str | None) -> dict:
    match = f"cpe:2.3:a:{vendor}:{product}"
    query = urllib.parse.urlencode(
        {"virtualMatchString": match, "resultsPerPage": 2000, "startIndex": start}
    )
    req = urllib.request.Request(
        f"{API}?{query}", headers={"User-Agent": "nano-sensor-index-builder/0.1"}
    )
    if api_key:
        req.add_header("apiKey", api_key)

    # NVD answers 403 and 503 under load rather than 429, and when it is really
    # unhappy it drops the connection without a response at all -- which surfaces
    # as http.client.RemoteDisconnected, NOT as urllib.error.URLError. Catching
    # only URLError therefore misses the most common failure. OSError is the
    # common base of all of them.
    delay = 10.0
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=120) as fh:
                return json.load(fh)
        except (OSError, urllib.error.HTTPError, TimeoutError) as exc:
            if attempt == 5:
                raise
            print(f"    retry {attempt + 1} after {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            time.sleep(delay)
            delay *= 2
    raise RuntimeError("unreachable")


def pick_cvss(metrics: dict) -> tuple[str, str, str]:
    """Prefer CVSS v3.1, then v3.0, then v2.

    Not "take the first metric present": a CVE carrying both a v2 and a v3.1
    score would otherwise be reported at whichever severity the dict happened to
    yield first, and v2 and v3 disagree often enough that the severity column
    would be untrustworthy.
    """
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return str(data["baseScore"]), data["baseSeverity"], version
    if metrics.get("cvssMetricV2"):
        entry = metrics["cvssMetricV2"][0]
        data = entry["cvssData"]
        severity = entry.get("baseSeverity", "")
        return str(data["baseScore"]), severity, "2.0"
    return "", "", ""


def rows_for_cve(cve: dict, wanted: set[tuple[str, str]]) -> list[list[str]]:
    score, severity, cvss_version = pick_cvss(cve.get("metrics", {}))
    out: list[list[str]] = []

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # `vulnerable: false` entries describe the platform a product has
                # to be running ON to be affected, not the affected product.
                # Treating them as vulnerable is a well-known way to generate
                # false positives against operating systems.
                if not match.get("vulnerable", False):
                    continue

                parts = match["criteria"].split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue  # application CPEs only; o/h are out of scope

                # A CVE record lists every product the advisory touches, not just
                # the one that matched the query. Without this filter the index
                # accumulates rows for products nobody asked about and nobody has
                # ground-truth labels for -- 117k rows and vendors like
                # "4d:webstar" on a first run. Coverage the accuracy numbers
                # cannot speak to is not coverage.
                if (parts[3], parts[4]) not in wanted:
                    continue

                out.append([
                    cve["id"],
                    parts[3],
                    parts[4],
                    parts[5],
                    parts[6] if len(parts) > 6 else "*",
                    match.get("versionStartIncluding", ""),
                    match.get("versionStartExcluding", ""),
                    match.get("versionEndIncluding", ""),
                    match.get("versionEndExcluding", ""),
                    score,
                    severity,
                    cvss_version,
                ])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default="tools/nvd/raw",
                    help="per-product JSON cache; makes re-runs free and lets an "
                         "interrupted build resume instead of restarting")
    ap.add_argument("--api-key", default=None,
                    help="an NVD API key raises the rate limit from 5 to 50 "
                         "requests per 30s; the build works without one")
    args = ap.parse_args()

    # Without a key NVD allows 5 requests per rolling 30 seconds. 10s between
    # requests stays well under that; the endpoint punishes optimism.
    pace = 0.7 if args.api_key else 10.0

    cache = pathlib.Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)

    wanted = set(PRODUCTS)
    seen: set[tuple[str, ...]] = set()
    rows: list[list[str]] = []

    for vendor, product in PRODUCTS:
        count_before = len(rows)
        blob = cache / f"{vendor}__{product}.json".replace("/", "_")

        if blob.exists():
            items = json.loads(blob.read_text(encoding="utf-8"))
            total = len(items)
            source = "cached"
        else:
            items, start, total, source = [], 0, None, "fetched"
            while total is None or start < total:
                page = fetch_page(vendor, product, start, args.api_key)
                total = page["totalResults"]
                got = page.get("vulnerabilities", [])
                items.extend(got)
                start += len(got)
                if not got:
                    break
                time.sleep(pace)
            # Written only after the product completes, so a crash mid-product
            # never leaves a half-cached file that a later run would trust.
            blob.write_text(json.dumps(items), encoding="utf-8")

        for item in items:
            for row in rows_for_cve(item["cve"], wanted):
                key = tuple(row)
                if key not in seen:
                    seen.add(key)
                    rows.append(row)

        print(f"  {vendor}:{product:<20} {len(items):>5} CVEs -> "
              f"{len(rows) - count_before:>6} match rows  ({source})", file=sys.stderr)

    rows.sort(key=lambda r: (r[1], r[2], r[0]))
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(COLUMNS) + "\n")
        for row in rows:
            fh.write("\t".join(row) + "\n")

    cves = len({r[0] for r in rows})
    print(f"\nwrote {args.out}: {len(rows)} match rows, {cves} distinct CVEs",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
