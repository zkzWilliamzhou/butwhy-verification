#!/usr/bin/env python3
"""Byte-identical non-regression gate against the frozen pre-optimization baseline."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
from butwhy import contract, jsonutil, runtime  # noqa: E402

BASELINE_DIR = os.path.join(ROOT, "reviews", "baseline")
ARTIFACTS = ("capsule.json", "diff.json", "ledger.json", "verdict.json", "golden.json")
RESULT = {"valid": False, "byte_differences": [], "surface_differences": [],
          "suite": None, "artifacts": len(ARTIFACTS)}


def run_demo():
    ws = os.path.join(tempfile.gettempdir(), "butwhy-golden-check")
    shutil.rmtree(ws, ignore_errors=True)
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
           "PYTHONPATH": SRC, "SOURCE_DATE_EPOCH": "1700000000",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
           "HOME": tempfile.gettempdir()}
    p = subprocess.run(
        [sys.executable, "-m", "butwhy", "demo", "--work", ws,
         "--confirm=" + runtime.CONFIRM_TOKEN],
        env=env, capture_output=True, text=True, timeout=180,
    )
    return ws, p.returncode, p.stderr


def main():
    if not os.path.isdir(BASELINE_DIR) or not all(
        os.path.isfile(os.path.join(BASELINE_DIR, n)) for n in ARTIFACTS
    ):
        print("verify-golden: FAIL - baseline not frozen; run 'make review' first")
        return 1
    ws, rc, err = run_demo()
    if rc != 0:
        print("verify-golden: FAIL - demo failed: %s" % err[:200])
        return 1
    for name in ARTIFACTS:
        now = open(os.path.join(ws, name), "rb").read()
        ref = open(os.path.join(BASELINE_DIR, name), "rb").read()
        if now != ref:
            RESULT["byte_differences"].append(name)
    manifest_path = os.path.join(ROOT, "reviews", "golden_baseline.json")
    if os.path.isfile(manifest_path):
        frozen = json.load(open(manifest_path, encoding="utf-8"))
        now_surface = {
            "subcommands": list(contract.SUBCOMMANDS),
            "exit_codes": list(contract.EXIT_CODES),
            "verdicts": list(contract.VERDICTS),
            "replayable_families": list(contract.REPLAYABLE_FAMILIES),
            "non_replayable_families": list(contract.NON_REPLAYABLE_FAMILIES),
            "modules": sorted(contract.MODULES),
        }
        for key, value in now_surface.items():
            if frozen["surface"].get(key) != value:
                RESULT["surface_differences"].append(key)
    p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                       cwd=ROOT, env={**os.environ, "PYTHONPATH": SRC},
                       capture_output=True, text=True, timeout=300)
    RESULT["suite"] = "PASS" if p.returncode == 0 else "FAIL"
    RESULT["valid"] = (not RESULT["byte_differences"]
                       and not RESULT["surface_differences"]
                       and RESULT["suite"] == "PASS")
    with open(os.path.join(ROOT, "reviews", "verify_golden_result.json"),
              "w", encoding="utf-8") as h:
        json.dump(RESULT, h, indent=2, sort_keys=True)
        h.write("\n")
    print("verify-golden: %s (byte diffs=%s, surface diffs=%s, suite=%s)" % (
        "OK" if RESULT["valid"] else "FAIL", RESULT["byte_differences"],
        RESULT["surface_differences"], RESULT["suite"]))
    return 0 if RESULT["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
