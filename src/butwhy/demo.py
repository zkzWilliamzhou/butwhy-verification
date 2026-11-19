"""Self-contained offline demo: locale-dependent failure, full pipeline, tamper proof.

The fixture is an explicit locale guard. It models the real class of failures
where a program selects an encoding/behaviour from LANG/LC_ALL. It is a fixture,
not a claim about CPython's internal locale coercion. ASCII stderr is used so
the failure itself is never encoding-dependent.
"""
from __future__ import annotations

import copy
import os
import shutil

from . import capture, contract, diff, jsonutil, ledger, report, runtime

FIXTURE = '''import os
import sys

loc = os.environ.get("LC_ALL") or os.environ.get("LANG") or ""
if loc in ("C", "POSIX", ""):
    sys.stderr.write("boom: locale guard triggered (locale=%s)\\n" % loc)
    raise SystemExit(1)
sys.stdout.buffer.write("ok: café\\n".encode("utf-8"))
'''


def run_demo(workspace: str, confirmed: bool, keep: bool = True) -> int:
    if not confirmed:
        print(
            "butwhy: demo requires --confirm=%s ; no command was executed"
            % runtime.CONFIRM_TOKEN
        )
        return 1

    ws = os.path.abspath(workspace)
    os.makedirs(ws, mode=0o700, exist_ok=True)
    root = os.path.join(ws, "src")
    app = os.path.join(root, "app")
    os.makedirs(app, mode=0o700, exist_ok=True)
    with open(os.path.join(app, "check.py"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(FIXTURE)

    bounds = dict(runtime.DEFAULT_BOUNDS)
    print("butwhy: offline one-factor replay demo")
    print("butwhy: no network, no third-party packages, no root-cause claim")

    cap_a = capture.capture_environment([root], bounds)
    cap_a = capture.with_env_override(cap_a, "LANG", "C")
    cap_a = capture.with_env_override(cap_a, "LC_ALL", "C")
    cap_b = capture.capture_environment([root], bounds)
    cap_b = capture.with_env_override(cap_b, "LANG", "en_US.UTF-8")
    cap_b = capture.with_env_override(cap_b, "LC_ALL", "en_US.UTF-8")

    capsule_path = os.path.join(ws, "capsule.json")
    sha = capture.write_capsule(cap_a, capsule_path)
    print("butwhy: capture  -> capsule.json (%s...)" % sha[:12])

    factor_diff = diff.diff_capsules(cap_a, cap_b)
    diff_path = os.path.join(ws, "diff.json")
    jsonutil.write_document(diff_path, factor_diff)
    print("butwhy: diff     -> %d factor(s), %d replayable"
          % (len(factor_diff["diffs"]), factor_diff["summary"]["replayable"]))

    plan = runtime.build_plan(
        cap_a, factor_diff, os.path.basename(root), "python3 app/check.py", 3, bounds
    )
    print("butwhy: plan     -> command=%s n=%d factors=%d"
          % (" ".join(plan["command"]), plan["n"], len(plan["factors"])))

    ledger_path = os.path.join(ws, "ledger.json")
    verdict_path = os.path.join(ws, "verdict.json")
    result = runtime.execute_plan(
        plan, root, bounds, True,
        {
            "ledger": ledger_path,
            "verdict": verdict_path,
            "baseline_env": runtime.base_env(cap_a),
        },
    )
    led = result["ledger"]
    verdict = result["verdict"]
    print("butwhy: run      -> %d ledger events" % len(led["events"]))
    print("butwhy: verdict  -> %s (confidence %.2f)"
          % (verdict["overall"], verdict["confidence"]))

    rep = report.render_report(verdict, led)
    with open(os.path.join(ws, "report.txt"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(report.render_text(rep))
    jsonutil.write_document(os.path.join(ws, "report.json"), rep, pretty=True)

    check = ledger.verify_ledger(led)
    print("butwhy: verify   -> %s (%d entries)"
          % (check["status"], check["checked_entries"]))
    if not check["valid"]:
        print("butwhy: FAIL ledger verification")
        return 2

    tampered = copy.deepcopy(led)
    tampered["events"][0]["data"]["plan_id"] = "tampered-by-butwhy-demo"
    tamper_dir = os.path.join(ws, "tamper")
    os.makedirs(tamper_dir, mode=0o700, exist_ok=True)
    jsonutil.write_document(os.path.join(tamper_dir, "ledger.json"), tampered)
    bad = ledger.verify_ledger(tampered)
    print("butwhy: tamper   -> %s (detected=%s)"
          % (bad["status"], "yes" if not bad["valid"] else "no"))
    if bad["valid"]:
        print("butwhy: FAIL tamper was not detected")
        return 2

    golden = contract.snapshot(
        {
            "capsule": capsule_path,
            "diff": diff_path,
            "ledger": ledger_path,
            "verdict": verdict_path,
        }
    )
    jsonutil.write_document(os.path.join(ws, "golden.json"), golden)
    print("butwhy: golden   -> %s" % golden["golden_id"])
    print("butwhy: demo OK - artifacts retained in %s" % ws)
    if not keep:
        shutil.rmtree(ws, ignore_errors=True)
    return 0
