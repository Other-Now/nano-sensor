#!/usr/bin/env python3
"""Score the CVE matcher against the hand-labelled ground truth.

This is stage 2's proof, and the number it produces is the headline claim of the
whole project. Two rules make it worth anything:

  * It drives the REAL matcher (`nano-sensor vuln --packages`), not a Python
    reimplementation of it. Scoring a second implementation measures the wrong
    program.
  * It scores a baseline on the identical labels. "94% precision" means nothing
    without knowing what the naive approach scores on the same set -- if the
    naive approach also gets 94%, the whole matcher is decoration.

The baseline is the substring matcher: resolve a package to a CVE if the CPE
product name and the package name share a substring, and ignore the version
entirely. That is not a strawman -- it is what "grep the CVE feed for the
package name" produces, and it is the most common shortcut in home-grown
scanners precisely because version comparison is the hard part.

usage:
    python tools/eval_cve_match.py --binary build/bin/RelWithDebInfo/nano-sensor.exe
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import subprocess
import sys
import tempfile


def load_truth(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            rows.append({
                "package": parts[0],
                "version": parts[1],
                "cve": parts[2],
                "expected": parts[3].strip(),
                "note": parts[4] if len(parts) > 4 else "",
            })
    return rows


def run_matcher(binary: str, index: str, aliases: str,
                pairs: list[tuple[str, str]]) -> dict[tuple[str, str], set[str]]:
    """Ask the real agent what it finds for each (package, version)."""
    with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False,
                                     encoding="utf-8", newline="\n") as fh:
        for name, version in pairs:
            fh.write(f"{name}\t{version}\n")
        listing = fh.name

    try:
        # Resolved to an absolute path on purpose. Windows CreateProcess rejects
        # a RELATIVE path written with forward slashes -- "build/bin/x.exe" fails
        # with WinError 2 while "build\bin\x.exe" works -- so a script that runs
        # fine in CI on Linux dies on the developer's own machine.
        exe = str(pathlib.Path(binary).resolve())
        proc = subprocess.run(
            [exe, "vuln", "--packages", listing, "--index", index,
             "--aliases", aliases],
            capture_output=True, text=True, encoding="utf-8", check=True,
        )
    finally:
        pathlib.Path(listing).unlink(missing_ok=True)

    doc = json.loads(proc.stdout)
    found: dict[tuple[str, str], set[str]] = {p: set() for p in pairs}
    for f in doc["findings"]:
        key = (f["package"], f["installed_version"])
        found.setdefault(key, set()).add(f["cve"])
    return found


def run_baseline(index: str, pairs: list[tuple[str, str]]
                 ) -> dict[tuple[str, str], set[str]]:
    """Substring name match, version ignored."""
    products: dict[tuple[str, str], set[str]] = {}
    with open(index, encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            products.setdefault((row["vendor"], row["product"]), set()).add(row["cve_id"])

    found: dict[tuple[str, str], set[str]] = {}
    for name, version in pairs:
        lowered = name.lower()
        hits: set[str] = set()
        for (_vendor, product), cves in products.items():
            if product in lowered or lowered in product:
                hits |= cves
        found[(name, version)] = hits
    return found


def score(truth: list[dict], found: dict[tuple[str, str], set[str]]) -> dict:
    tp = fp = fn = tn = 0
    errors: list[str] = []
    for row in truth:
        key = (row["package"], row["version"])
        predicted = row["cve"] in found.get(key, set())
        expected = row["expected"] == "hit"

        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
            errors.append(f"FALSE POSITIVE  {row['package']} {row['version']} "
                          f"-> {row['cve']}  ({row['note']})")
        elif not predicted and expected:
            fn += 1
            errors.append(f"FALSE NEGATIVE  {row['package']} {row['version']} "
                          f"-> {row['cve']}  ({row['note']})")
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(truth) if truth else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": f1, "accuracy": accuracy, "errors": errors}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--index", default="data/cve_index.tsv")
    ap.add_argument("--aliases", default="data/cpe_aliases.tsv")
    ap.add_argument("--truth", default="data/ground_truth.tsv")
    args = ap.parse_args()

    truth = load_truth(args.truth)
    pairs = sorted({(r["package"], r["version"]) for r in truth})

    agent = score(truth, run_matcher(args.binary, args.index, args.aliases, pairs))
    base = score(truth, run_baseline(args.index, pairs))

    print(f"ground truth : {len(truth)} labelled assertions over {len(pairs)} "
          f"package/version pairs\n")
    header = f"{'':<22}{'precision':>10}{'recall':>9}{'F1':>8}{'acc':>8}" \
             f"{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}"
    print(header)
    print("-" * len(header))
    for label, s in (("nano-sensor", agent), ("substring baseline", base)):
        print(f"{label:<22}{s['precision']:>9.1%}{s['recall']:>9.1%}"
              f"{s['f1']:>8.2f}{s['accuracy']:>8.1%}"
              f"{s['tp']:>5}{s['fp']:>5}{s['fn']:>5}{s['tn']:>5}")

    if agent["errors"]:
        print("\nnano-sensor disagreements with the ground truth:")
        for e in agent["errors"]:
            print(f"  {e}")

    # The gate is on the agent, not the baseline: the baseline is expected to do
    # badly, that is the entire point of measuring it.
    return 0 if not agent["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
