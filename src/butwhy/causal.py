"""Repeat protocol and the causal truth table.

The tool never claims root cause. It reports only whether a single declared
factor is necessary, sufficient, both, has no effect, is non-replayable, or is
inconclusive under the observed counterfactual evidence.
"""
from __future__ import annotations

from typing import Optional

# A case-fold rename loses the original spelling, so we cannot honestly run a
# counter-flip. One-way verdicts remain reachable through this family.
NON_INVERTIBLE = frozenset({"filename_case"})

STABLE = ("pass", "fail")


def run_repeats(plan: dict, kind: str, bounds: dict, *, source_root: str,
                base_env: dict, factor: Optional[dict], n: int, runner) -> dict:
    """Run n independent repeats, each in a fresh disposable copy."""
    outcomes = []
    for index in range(n):
        env = dict(base_env)
        env["BUTWHY_REPEAT_INDEX"] = str(index)
        result = runner(source_root, plan["command"], env, bounds, factor)
        outcomes.append(
            {
                "index": index,
                "outcome": result["outcome"],
                "exit_code": result["exit_code"],
                "stdout_sha256": result["stdout_sha256"],
                "stderr_sha256": result["stderr_sha256"],
            }
        )
    return {"kind": kind, "outcomes": outcomes}


def _uniform(outcomes: Optional[list]) -> Optional[str]:
    """Return the single stable outcome, or None if mixed/unstable/unavailable."""
    if outcomes is None:
        return None
    values = [o["outcome"] for o in outcomes]
    if not values:
        return None
    first = values[0]
    if first not in STABLE:
        return "error"
    if any(v != first for v in values):
        return None
    return first


def decide(outcomes: dict) -> dict:
    """Pure truth table. No wall clock, no randomness, no hidden thresholds."""
    if not outcomes.get("replayable"):
        return {
            "classification": "non_replayable", "confidence": 0.0,
            "baseline": None, "flip": None, "reverse": None,
            "rationale": "factor cannot be replayed offline", "multi_factor": False,
        }
    baseline = _uniform(outcomes["baseline"])
    flip = _uniform(outcomes["flip"])
    reverse = _uniform(outcomes["reverse"]) if outcomes.get("reverse") is not None else None
    raw = {
        "baseline": outcomes["baseline"], "flip": outcomes["flip"],
        "reverse": outcomes.get("reverse"),
    }
    if baseline is None or flip is None or baseline == "error" or flip == "error":
        return {
            "classification": "inconclusive", "confidence": 0.0, **raw,
            "rationale": "a repeat group was mixed, timed out, errored or exceeded a limit",
            "multi_factor": False,
        }
    if baseline == flip:
        return {
            "classification": "no_effect", "confidence": 0.83, **raw,
            "rationale": "baseline and flipped outcomes were identical and stable",
            "multi_factor": False,
        }
    if reverse is None:
        classification = "necessary" if baseline == "fail" else "sufficient"
        return {
            "classification": classification, "confidence": 0.5, **raw,
            "rationale": "one-way evidence only; counter-flip was not available",
            "multi_factor": False,
        }
    if reverse != baseline:
        return {
            "classification": "inconclusive", "confidence": 0.0, **raw,
            "rationale": "counter-flip did not restore the baseline outcome",
            "multi_factor": False,
        }
    return {
        "classification": "necessary_and_sufficient", "confidence": 0.83, **raw,
        "rationale": "stable baseline, stable flipped outcome, and a verified counter-flip",
        "multi_factor": False,
    }


def decide_overall(results: list) -> dict:
    """Aggregate per-factor verdicts without ever inventing a single cause."""
    decisive = [
        r for r in results
        if r["classification"] in ("necessary_and_sufficient", "necessary", "sufficient")
    ]
    if len(decisive) > 1:
        return {
            "classification": "inconclusive", "confidence": 0.0,
            "multi_factor": True,
            "rationale": "multiple factors independently changed the outcome",
        }
    if len(decisive) == 1:
        return {
            "classification": decisive[0]["classification"],
            "confidence": decisive[0]["confidence"],
            "multi_factor": False,
            "rationale": "one factor changed the outcome under the declared conditions",
        }
    if any(r["classification"] == "inconclusive" for r in results):
        return {
            "classification": "inconclusive", "confidence": 0.0,
            "multi_factor": False, "rationale": "at least one factor was inconclusive",
        }
    if results and all(r["classification"] == "non_replayable" for r in results):
        return {
            "classification": "non_replayable", "confidence": 0.0,
            "multi_factor": False, "rationale": "no replayable factor was tested",
        }
    return {
        "classification": "no_effect", "confidence": 0.83,
        "multi_factor": False, "rationale": "no tested factor changed the observed outcome",
    }
