#!/usr/bin/env python3
"""Record PRE-OPTIMIZATION timings. Run exactly once, before any optimization."""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
from butwhy import contract, jsonutil  # noqa: E402

OUT = os.path.join(ROOT, "reviews", "perf_before.json")


def bench_guard(n=60):
    t = time.perf_counter()
    for _ in range(n):
        contract.guard_offline()
    return time.perf_counter() - t


def bench_canonical(n=200):
    doc = {"k%04d" % i: "value-%d" % i for i in range(600)}
    t = time.perf_counter()
    for _ in range(n):
        jsonutil.canonical(doc)
    return time.perf_counter() - t


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    data = {
        "note": "Pre-optimization baseline, measured before any internal caching.",
        "guard_offline_60_calls_sec": bench_guard(),
        "canonical_600_keys_200_calls_sec": bench_canonical(),
    }
    with open(OUT, "w", encoding="utf-8") as h:
        json.dump(data, h, indent=2, sort_keys=True)
        h.write("\n")
    print("perf-baseline: guard=%.4fs canonical=%.4fs" % (
        data["guard_offline_60_calls_sec"], data["canonical_600_keys_200_calls_sec"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
