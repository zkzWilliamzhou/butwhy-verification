"""Render verdict reports. Machine output never asserts cause."""
from __future__ import annotations

from . import contract, jsonutil
from .errors import UsageError

FIX_RECIPES = {
    "env_var": "Set the variable on the other host, e.g. export {name}={value}",
    "locale": "Align locale variables, e.g. export LANG={lang} LC_ALL={lang}",
    "timezone": "Align TZ, e.g. export TZ={tz}",
    "line_endings": "Normalise {path} (e.g. dos2unix {path} or git config core.autocrlf)",
    "symlink_target": "Repoint {path} to the expected target",
    "filename_case": "Rename {path} to match the expected spelling",
    "file_mode": "Restore permissions on {path} (chmod <mode> {path})",
    "path_shadow": "Remove the shadowing shim from PATH or pin the tool version",
    "interpreter_version": "Use the same interpreter version; this cannot be replayed offline",
    "platform": "Use the same OS/architecture; this cannot be replayed offline",
    "note": "Inspect the content difference manually; no replayable factor is declared",
}


def render_report(verdict: dict, ledger: dict) -> dict:
    """Build a verdict_report document from a verdict + its ledger."""
    if jsonutil.check_envelope(verdict) != "verdict_report":
        raise UsageError("render_report expects a verdict_report")
    verification = ledger.get("head", "")
    factors = []
    for item in verdict["factors"]:
        recipe = FIX_RECIPES.get(item["family"], "Review the evidence for this factor")
        try:
            recipe = recipe.format(
                name=(item.get("path") or "VARIABLE"),
                value="the baseline value",
                lang="en_US.UTF-8",
                tz="UTC",
                path=item.get("path") or "the affected file",
            )
        except (KeyError, IndexError):
            pass
        factors.append(
            {
                "family": item["family"],
                "classification": item["classification"],
                "confidence": item["confidence"],
                "rationale": item["rationale"],
                "baseline": item.get("baseline"),
                "flip": item.get("flip"),
                "fix_recipe": recipe,
            }
        )
    return jsonutil.envelope(
        "verdict_report",
        {
            "report_id": jsonutil.deterministic_id(
                {"verdict": verdict["verdict_id"], "head": verification}
            ),
            "verdict_id": verdict["verdict_id"],
            "ledger_id": ledger["ledger_id"],
            "ledger_head_hash": verification,
            "event_count": len(ledger.get("events", [])),
            "verification_status": "valid" if ledger.get("closed") else "incomplete",
            "command": verdict["command"],
            "overall": verdict["overall"],
            "confidence": verdict["confidence"],
            "factors": factors,
            "multi_factor": verdict["multi_factor"],
            "limitations": [
                "butwhy reports counterfactual evidence, not a determination of cause",
                "only declared, reversible factors inside a disposable copy were tested",
                "the ledger proves record integrity, not capsule truth or command safety",
                "results are valid only for the recorded command and environment",
            ],
        },
    )


def render_text(report: dict) -> str:
    """Human text. Contains no forbidden claim phrases."""
    lines = [
        "butwhy - counterfactual one-factor replay",
        "------------------------------------------",
        "overall classification : %s" % report["overall"],
        "evidence confidence    : %.2f" % report["confidence"],
        "ledger events          : %d" % report["event_count"],
        "ledger head            : %s" % report["ledger_head_hash"][:16],
        "verification           : %s" % report["verification_status"],
        "",
        "factors tested:",
    ]
    if not report["factors"]:
        lines.append("  (none)")
    for item in report["factors"]:
        lines.append(
            "  - %-20s %-26s confidence=%.2f"
            % (item["family"], item["classification"], item["confidence"])
        )
        lines.append("      evidence: %s" % item["rationale"])
        lines.append("      fix: %s" % item["fix_recipe"])
    if report["multi_factor"]:
        lines.append("")
        lines.append("  NOTE: several factors independently changed the outcome.")
        lines.append("  No single-factor classification is claimed.")
    lines.append("")
    lines.append("limitations:")
    for note in report["limitations"]:
        lines.append("  - %s" % note)
    text = "\n".join(lines) + "\n"
    for phrase in contract.FORBIDDEN_PHRASES:
        if phrase in text.lower():
            raise UsageError("report contains a forbidden claim phrase")
    return text
