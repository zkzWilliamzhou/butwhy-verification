"""CLI: exactly six subcommands, one confirmation token, closed exit codes."""
from __future__ import annotations

import argparse
import os
import sys
import traceback
from typing import List, Optional, TextIO

from . import VERSION, capture, contract, demo, diff, jsonutil, ledger, report, runtime
from .errors import ButwhyError, UsageError

GOLDEN_LABELS = ("capsule", "diff", "ledger", "verdict")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="butwhy",
        description="Counterfactual one-factor replay for 'works on my machine' failures.",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    p = sub.add_parser("capture", help="record a secret-safe environment capsule")
    p.add_argument("--root", action="append", required=True, help="tree to capture (repeatable)")
    p.add_argument("--out", help="capsule path (default capsule.json)")

    p = sub.add_parser("diff", help="propose one-factor changes between two capsules")
    p.add_argument("--capsule", action="append", required=True, help="exactly two capsule paths")
    p.add_argument("--out", help="diff path (default diff.json)")

    p = sub.add_parser("run", help="execute baseline / flip / counter-flip experiments")
    p.add_argument("--capsule", required=True, help="baseline capsule")
    p.add_argument("--subject", help="subject capsule (computes a diff when --diff is absent)")
    p.add_argument("--diff", help="factor_diff document")
    p.add_argument("--work", required=True, help="source tree to copy")
    p.add_argument("--command", dest="cmd_string", required=True,
                   help="one command string (shlex-split, never a shell)")
    p.add_argument("--n", type=int, default=3, help="repeats per group (2..10)")
    p.add_argument("--timeout", type=float, help="per-command timeout seconds")
    p.add_argument("--stdout-cap", type=int, help="max captured bytes per stream")
    p.add_argument("--tree-cap", type=int, help="max copied tree bytes")
    p.add_argument("--confirm", help="exact confirmation token")
    p.add_argument("--out", help="verdict path (default verdict.json)")
    p.add_argument("--ledger", help="ledger path (default ledger.json)")

    p = sub.add_parser("report", help="render a verdict report")
    p.add_argument("--ledger", required=True, help="ledger path")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--out", help="write pretty JSON report here")

    p = sub.add_parser("verify", help="offline hash-chain verification")
    p.add_argument("--ledger", required=True, help="ledger path")
    p.add_argument("--golden", help="golden manifest to compare against local artifacts")
    p.add_argument("--strict", action="store_true", help="treat incomplete as invalid")
    p.add_argument("--out", help="verify result path (default verify.json)")

    p = sub.add_parser("demo", help="offline self-contained demonstration")
    p.add_argument("--work", help="demo workspace (default butwhy-demo)")
    p.add_argument("--confirm", help="exact confirmation token")
    p.add_argument("--keep", action="store_true", help="retain artifacts (default)")
    return parser


def parse(argv: List[str]) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def _bounds(ns: argparse.Namespace) -> dict:
    bounds = dict(runtime.DEFAULT_BOUNDS)
    if getattr(ns, "timeout", None) is not None:
        bounds["timeout_sec"] = float(ns.timeout)
    if getattr(ns, "stdout_cap", None) is not None:
        bounds["max_output_bytes"] = int(ns.stdout_cap)
    if getattr(ns, "tree_cap", None) is not None:
        bounds["max_tree_bytes"] = int(ns.tree_cap)
    return bounds


def _write_verify_result(vr: dict, out: TextIO, path: Optional[str]) -> int:
    if path:
        jsonutil.write_document(path, vr)
    out.write("OK\n" if vr["valid"] else "FAIL %s\n" % (vr["errors"][0] if vr["errors"] else "invalid"))
    return 0 if vr["valid"] else 2


def _golden_check(golden_path: str) -> dict:
    try:
        before = jsonutil.read_document(golden_path)
        if before.get("document") != "golden_manifest":
            raise ButwhyError("golden file is not a golden_manifest")
        base = os.path.dirname(os.path.abspath(golden_path))
        paths = {label: os.path.join(base, label + ".json") for label in GOLDEN_LABELS}
        for label, path in paths.items():
            if not os.path.isfile(path):
                raise ButwhyError("golden artifact missing: %s.json" % label)
        after = contract.snapshot(paths)
        return contract.compare_golden(before, after)
    except ButwhyError as exc:
        return {"identical": False, "differences": [{"label": "golden", "reason": str(exc)}]}


def dispatch(ns: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    try:
        if getattr(ns, "version", False):
            out.write("butwhy %s (schema 1, stdlib-only, offline)\n" % VERSION)
            return 0
        contract.assert_contract()

        if ns.command == "capture":
            bounds = _bounds(ns)
            capsule = capture.capture_environment(ns.root, bounds)
            path = ns.out or "capsule.json"
            sha = capture.write_capsule(capsule, path)
            out.write("butwhy: capsule %s sha256=%s\n" % (path, sha))
            return 0

        if ns.command == "diff":
            if len(ns.capsule) != 2:
                raise UsageError("diff requires exactly two --capsule arguments")
            a = jsonutil.read_document(ns.capsule[0])
            b = jsonutil.read_document(ns.capsule[1])
            document = diff.diff_capsules(a, b)
            path = ns.out or "diff.json"
            jsonutil.write_document(path, document)
            out.write("butwhy: diff %s factors=%d replayable=%d denied=%d\n"
                      % (path, len(document["diffs"]),
                         document["summary"]["replayable"],
                         document["summary"]["denied"]))
            return 0

        if ns.command == "run":
            if not os.path.isdir(ns.work):
                raise UsageError("--work must be an existing directory")
            capsule = jsonutil.read_document(ns.capsule)
            if ns.diff:
                factor_diff = jsonutil.read_document(ns.diff)
            elif ns.subject:
                subject = jsonutil.read_document(ns.subject)
                factor_diff = diff.diff_capsules(capsule, subject)
            else:
                raise UsageError("run requires --diff or --subject")
            bounds = _bounds(ns)
            plan = runtime.build_plan(
                capsule, factor_diff, os.path.basename(os.path.abspath(ns.work)),
                ns.cmd_string, ns.n, bounds,
            )
            if ns.confirm != runtime.CONFIRM_TOKEN:
                out.write(jsonutil.canonical(plan).decode("utf-8") + "\n")
                err.write("butwhy: dry-run only; no command was executed. "
                          "Pass --confirm=%s to run.\n" % runtime.CONFIRM_TOKEN)
                return 1
            ledger_path = ns.ledger or "ledger.json"
            verdict_path = ns.out or "verdict.json"
            result = runtime.execute_plan(
                plan, ns.work, bounds, True,
                {
                    "ledger": ledger_path,
                    "verdict": verdict_path,
                    "baseline_env": runtime.base_env(capsule),
                },
            )
            verdict = result["verdict"]
            out.write("butwhy: ledger %s (%d events)\n"
                      % (ledger_path, len(result["ledger"]["events"])))
            out.write("butwhy: verdict %s overall=%s confidence=%.2f\n"
                      % (verdict_path, verdict["overall"], verdict["confidence"]))
            return 0

        if ns.command == "report":
            led = jsonutil.read_document(ns.ledger)
            verdict = ledger.verdict_from_ledger(led)
            document = report.render_report(verdict, led)
            if ns.out:
                jsonutil.write_document(ns.out, document, pretty=True)
            if ns.format == "json":
                out.write(jsonutil.canonical(document).decode("utf-8") + "\n")
            else:
                out.write(report.render_text(document))
            return 0

        if ns.command == "verify":
            try:
                led = jsonutil.read_document(ns.ledger)
                vr = ledger.verify_ledger(led)
            except ButwhyError as exc:
                vr = jsonutil.envelope(
                    "verify_result",
                    {"status": "invalid", "valid": False, "checked_entries": 0,
                     "first_invalid_entry": type(exc).__name__, "errors": [str(exc)],
                     "head": None},
                )
            if ns.golden:
                comparison = _golden_check(ns.golden)
                if not comparison["identical"]:
                    vr["valid"] = False
                    vr["status"] = "invalid"
                    vr["errors"].append(
                        "golden mismatch: %s" % (comparison["differences"][0]["reason"],)
                    )
                    vr["first_invalid_entry"] = vr["first_invalid_entry"] or "golden"
            if ns.strict and vr["status"] == "incomplete":
                vr["valid"] = False
                vr["status"] = "invalid"
                vr["errors"].append("strict mode: incomplete ledger")
            return _write_verify_result(vr, out, ns.out or "verify.json")

        if ns.command == "demo":
            if ns.confirm != runtime.CONFIRM_TOKEN:
                err.write("butwhy: demo requires --confirm=%s ; nothing was executed\n"
                          % runtime.CONFIRM_TOKEN)
                return 1
            return demo.run_demo(ns.work or "butwhy-demo", True, keep=True)

        raise UsageError("unknown command: %s" % ns.command)

    except ButwhyError as exc:
        err.write("butwhy: %s\n" % exc)
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - defensive boundary
        if os.environ.get("BUTWHY_TRACE") == "1":
            traceback.print_exc(file=err)
        err.write("butwhy: internal error (%s)\n" % type(exc).__name__)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--version" in args:
        sys.stdout.write("butwhy %s (schema 1, stdlib-only, offline)\n" % VERSION)
        return 0
    try:
        ns = parse(args)
    except ButwhyError as exc:
        sys.stderr.write("butwhy: %s\n" % exc)
        return exc.exit_code
    return dispatch(ns, sys.stdout, sys.stderr)
