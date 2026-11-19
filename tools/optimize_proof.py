#!/usr/bin/env python3
"""Prove that internal optimizations preserved program FUNCTION.

Requires reviews/perf_before.json (measured before optimization) and
reviews/baseline/ (frozen before optimization). Writes
reviews/optimization_proof.json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
from butwhy import contract, jsonutil, runtime  # noqa: E402

BEFORE = os.path.join(ROOT, "reviews", "perf_before.json")
OUT = os.path.join(ROOT, "reviews", "optimization_proof.json")
ARTIFACTS = ("capsule.json", "diff.json", "ledger.json", "verdict.json", "golden.json")


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
    before = json.load(open(BEFORE, encoding="utf-8")) if os.path.isfile(BEFORE) else None
    if not before:
        print("optimize-proof: FAIL - run tools/perf_baseline.py first")
        return 1
    after = {"guard_offline_60_calls_sec": bench_guard(),
             "canonical_600_keys_200_calls_sec": bench_canonical()}

    # 1. Contract surface must be unchanged.
    surface = {
        "subcommands": list(contract.SUBCOMMANDS),
        "exit_codes": list(contract.EXIT_CODES),
        "verdicts": list(contract.VERDICTS),
        "replayable_families": list(contract.REPLAYABLE_FAMILIES),
        "non_replayable_families": list(contract.NON_REPLAYABLE_FAMILIES),
        "modules": sorted(contract.MODULES),
    }
    manifest = json.load(open(os.path.join(ROOT, "reviews", "golden_baseline.json"),
                              encoding="utf-8"))
    surface_ok = surface == manifest["surface"]

    # 2. Canonical artifacts must be BYTE-IDENTICAL to the frozen baseline.
    import shutil, tempfile  # noqa: E402
    ws = os.path.join(tempfile.gettempdir(), "butwhy-optimize-proof")
    shutil.rmtree(ws, ignore_errors=True)
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
           "PYTHONPATH": SRC, "SOURCE_DATE_EPOCH": "1700000000",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
           "HOME": tempfile.gettempdir()}
    p = subprocess.run([sys.executable, "-m", "butwhy", "demo", "--work", ws,
                        "--confirm=" + runtime.CONFIRM_TOKEN],
                       env=env, capture_output=True, text=True, timeout=180)
    byte_diffs = []
    if p.returncode == 0:
        for name in ARTIFACTS:
            if open(os.path.join(ws, name), "rb").read() != open(
                os.path.join(ROOT, "reviews", "baseline", name), "rb").read():
                byte_diffs.append(name)
    else:
        byte_diffs.append("demo-failed")

    # 3. Full test suite must still pass.
    t = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                       cwd=ROOT, env={**os.environ, "PYTHONPATH": SRC},
                       capture_output=True, text=True, timeout=300)
    suite_ok = t.returncode == 0

    proof = {
        "measured_before": before,
        "measured_after": after,
        "speedup_guard_offline": round(
            before["guard_offline_60_calls_sec"] / max(after["guard_offline_60_calls_sec"], 1e-9), 2),
        "canonical_bytes_stable": jsonutil.canonical({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}',
        "surface_unchanged": surface_ok,
        "byte_differences": byte_diffs,
        "full_suite_pass": suite_ok,
        "function_preserved": surface_ok and not byte_diffs and suite_ok,
        "rule": "A function change = any change to CLI surface, exit codes, "
                "verdict values, factor set, canonical artifact bytes, or "
                "ledger hash chain. Internal caching is allowed.",
    }
    with open(OUT, "w", encoding="utf-8") as h:
        json.dump(proof, h, indent=2, sort_keys=True)
        h.write("\n")
    print("optimize-proof: %s (guard speedup=%.2fx, byte diffs=%s, suite=%s)" % (
        "OK" if proof["function_preserved"] else "FAIL",
        proof["speedup_guard_offline"], byte_diffs, "PASS" if suite_ok else "FAIL"))
    return 0 if proof["function_preserved"] else 1


if __name__ == "__main__":
    sys.exit(main())
