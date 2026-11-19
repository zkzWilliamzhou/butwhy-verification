"""Build immutable dry-run plans and execute one-factor experiments."""
from __future__ import annotations

import copy
import os
import shlex

from . import causal, contract, factors, isolation, jsonutil, ledger, secrets
from .errors import ReplayError, ResourceLimit, SafetyDenied, UsageError

CONFIRM_TOKEN = "yes-i-understand-butwhy-will-run-this"
MAX_FACTORS = 12

# Shared by cli.py and demo.py so the golden contract is reproducible.
DEFAULT_BOUNDS = {
    "max_input_bytes": 16 * 1024 * 1024,
    "max_depth": 32,
    "max_tree_bytes": 1024 * 1024 * 1024,
    "max_output_bytes": 64 * 1024 * 1024,
    "timeout_sec": 300,
    "n_repeats": 3,
}


def base_env(capsule: dict) -> dict:
    """Reconstruct the baseline child env from a capsule (no raw os.environ)."""
    snap = capsule["factor_snapshot"]
    env = {}
    for item in snap.get("env_var", []):
        if item.get("value") is not None and not secrets.never_transplant(item["name"]):
            env[item["name"]] = item["value"]
    for key, value in snap.get("locale", {}).items():
        if value:
            env[key] = value
    tz = snap.get("timezone", {}).get("tz")
    if tz:
        env["TZ"] = tz
    return env


def build_plan(capsule: dict, diff: dict, target: str, command: str,
               n: int, bounds: dict) -> dict:
    """`target` is a stable LABEL, never an absolute path (determinism)."""
    if jsonutil.check_envelope(capsule) != "capsule":
        raise UsageError("plan expects a capsule")
    if jsonutil.check_envelope(diff) != "factor_diff":
        raise UsageError("plan expects a factor_diff")
    if not isinstance(command, str) or not command.strip():
        raise UsageError("--command is required")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise UsageError("cannot parse --command: %s" % exc) from exc
    isolation.validate_argv(argv)
    if not (2 <= n <= 10):
        raise UsageError("--n must be between 2 and 10")
    if any(d.get("denied") for d in diff["diffs"]):
        raise SafetyDenied("diff contains denied factors; refusing to run")

    replayable = [
        d for d in diff["diffs"]
        if d["replayable"] and d["family"] in contract.REPLAYABLE_FAMILIES
    ]
    if len(replayable) > MAX_FACTORS:
        raise ResourceLimit("more than %d replayable factors" % MAX_FACTORS)
    notes = [d for d in diff["diffs"] if d not in replayable]
    payload = {
        "plan_id": jsonutil.deterministic_id(
            {"capsule": capsule["capsule_id"], "diff": diff["diff_id"],
             "argv": argv, "n": n, "factors": replayable}
        ),
        "capsule_id": capsule["capsule_id"],
        "diff_id": diff["diff_id"],
        "target_label": target,
        "command": argv,
        "n": n,
        "bounds": bounds,
        "factors": replayable,
        "notes": notes,
        "confirmation_required": CONFIRM_TOKEN,
    }
    return jsonutil.envelope("dry_run_plan", payload)


def _fresh_run(source_root: str, argv: list, env: dict, bounds: dict,
              factor: dict = None) -> dict:
    copy_root = isolation.make_copy(source_root, bounds)
    try:
        child_env = dict(env)
        record = None
        if factor is not None:
            ctx = {"env": child_env}
            record = factors.apply_factor(copy_root, factor, ctx)
            child_env = ctx["env"]
        result = isolation.spawn_isolated(copy_root, argv, child_env, bounds)
        if record is not None:
            try:
                factors.revert_factor(copy_root, record)
            except Exception:
                pass
        return result
    finally:
        isolation.destroy_copy(copy_root, bounds)


def execute_plan(plan: dict, source_root: str, bounds: dict,
                 confirmed: bool, out_paths: dict) -> dict:
    """Run baseline / flip / counter-flip groups in fresh disposable copies."""
    if jsonutil.check_envelope(plan) != "dry_run_plan":
        raise UsageError("execute expects a dry_run_plan")
    if not confirmed:
        return {"dry_run": True, "plan": plan}
    contract.guard_offline()
    argv = plan["command"]
    n = int(plan["n"])
    capsule_id = plan["capsule_id"]

    # Reconstruct baseline env from the plan's own factor snapshot is not
    # possible (a plan is intentionally minimal), so the caller supplies a
    # capsule-derived env via out_paths['baseline_env'].
    env = out_paths.get("baseline_env")
    if not isinstance(env, dict):
        raise ReplayError("baseline env was not supplied to execute_plan")

    led = ledger.new_ledger(
        {"capsule_id": capsule_id, "plan_id": plan["plan_id"], "created_at": 0}
    )
    led = ledger.append_event(led, {
        "kind": "plan",
        "data": {"plan_id": plan["plan_id"], "command": argv,
                 "factor_order": [f["family"] for f in plan["factors"]], "n": n},
    })

    results = []
    for spec in plan["factors"]:
        inverse = copy.deepcopy(spec)
        inverse["before"], inverse["after"] = spec["after"], spec["before"]
        inverse["action"] = "reverse"
        baseline = causal.run_repeats(
            plan, "baseline", bounds, source_root=source_root,
            base_env=env, factor=None, n=n, runner=_fresh_run,
        )
        flip = causal.run_repeats(
            plan, "flip", bounds, source_root=source_root,
            base_env=env, factor=spec, n=n, runner=_fresh_run,
        )
        if spec["family"] in causal.NON_INVERTIBLE:
            reverse = None
        else:
            reverse = causal.run_repeats(
                plan, "reverse", bounds, source_root=source_root,
                base_env=env, factor=inverse, n=n, runner=_fresh_run,
            )
        led = ledger.append_event(led, {
            "kind": "observe",
            "data": {"family": spec["family"], "baseline": baseline["outcomes"],
                     "flip": flip["outcomes"]},
        })
        verdict = causal.decide(
            {"replayable": True, "family": spec["family"],
             "baseline": baseline["outcomes"], "flip": flip["outcomes"],
             "reverse": reverse["outcomes"] if reverse else None}
        )
        verdict["family"] = spec["family"]
        verdict["path"] = spec.get("path")
        results.append(verdict)
        led = ledger.append_event(led, {"kind": "verdict", "data": {"factor": verdict}})

    for note in plan["notes"]:
        family = note["family"]
        classification = "no_effect" if family == "note" else "non_replayable"
        results.append({
            "family": family, "classification": classification,
            "confidence": 0.0, "baseline": None, "flip": None,
            "reverse": None, "rationale": note.get("reason", ""),
            "multi_factor": False,
        })
        led = ledger.append_event(led, {
            "kind": "note", "data": {"family": family, "classification": classification},
        })

    overall = causal.decide_overall(results)
    verdict_doc = jsonutil.envelope(
        "verdict_report",
        {
            "verdict_id": jsonutil.deterministic_id(
                {"ledger_id": led["ledger_id"], "results": results}
            ),
            "ledger_id": led["ledger_id"],
            "command": argv,
            "overall": overall["classification"],
            "confidence": overall["confidence"],
            "n": n,
            "factors": results,
            "multi_factor": overall["multi_factor"],
            "notes": ["evidence is counterfactual, not a causal claim"],
        },
    )
    led = ledger.append_event(led, {"kind": "verdict", "data": {"verdict": verdict_doc}})
    led = ledger.append_event(led, {"kind": "ledger_closed", "data": {"event_count": len(led["events"])}})
    led["closed"] = True

    if out_paths.get("ledger"):
        ledger.write_ledger(out_paths["ledger"], led)
    if out_paths.get("verdict"):
        jsonutil.write_document(out_paths["verdict"], verdict_doc)
    return {"dry_run": False, "ledger": led, "verdict": verdict_doc}
