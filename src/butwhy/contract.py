"""Locked-contract assertions, offline import guard, golden snapshots.

This module is the boss's non-negotiable checklist encoded as executable code.
An optimization round that changes any of these constants is a FUNCTION CHANGE
and must be rejected.
"""
from __future__ import annotations

import ast
import os
import sys
from functools import lru_cache
from typing import Iterable

from . import jsonutil
from .errors import SafetyDenied, SchemaError

SUBCOMMANDS = ("capture", "diff", "run", "report", "verify", "demo")
EXIT_CODES = (0, 1, 2, 3, 4, 5, 6)
VERDICTS = (
    "necessary_and_sufficient", "necessary", "sufficient",
    "no_effect", "non_replayable", "inconclusive",
)
REPLAYABLE_FAMILIES = (
    "env_var", "locale", "timezone", "line_endings",
    "symlink_target", "filename_case", "file_mode", "path_shadow",
)
NON_REPLAYABLE_FAMILIES = ("interpreter_version", "platform")
ALL_FAMILIES = REPLAYABLE_FAMILIES + NON_REPLAYABLE_FAMILIES
MODULES = (
    "__init__.py", "__main__.py", "cli.py", "jsonutil.py", "secrets.py",
    "capture.py", "diff.py", "factors.py", "isolation.py", "runtime.py",
    "ledger.py", "causal.py", "report.py", "contract.py", "demo.py", "errors.py",
)
FORBIDDEN_IMPORTS = frozenset(
    {"socket", "urllib", "http", "ftplib", "smtplib", "webbrowser", "xmlrpc", "telnetlib"}
)
FORBIDDEN_PHRASES = ("root cause", "caused by", "the bug is")


def assert_contract() -> None:
    """Fail loudly if the implementation drifted from the locked contract."""
    from . import factors  # local import avoids a cycle at module load

    if tuple(factors.list_families()) != ALL_FAMILIES:
        raise SchemaError("factor family set drifted from the locked contract")
    if len(SUBCOMMANDS) != 6 or len(EXIT_CODES) != 7 or len(VERDICTS) != 6:
        raise SchemaError("CLI/verdict contract drifted")
    root = os.path.dirname(os.path.abspath(__file__))
    found = sorted(p.name for p in os.scandir(root) if p.name.endswith(".py"))
    if tuple(found) != tuple(sorted(MODULES)) or len(found) != len(MODULES):
        raise SchemaError("module set drifted from the locked 16: %s" % found)
    guard_offline()


@lru_cache(maxsize=1)
def _scan_production_modules() -> None:
    """AST-scan the 16 production modules. Source is immutable within a process.

    Optimization: this static scan is identical on every call in one process,
    so it is computed once. A new CLI invocation is a new process and re-scans.
    """
    root = os.path.dirname(os.path.abspath(__file__))
    for entry in sorted(os.scandir(root), key=lambda p: p.name):
        if not entry.name.endswith(".py"):
            continue
        with open(entry.path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=entry.path)
        for node in ast.walk(tree):
            names: Iterable[str] = ()
            if isinstance(node, ast.Import):
                names = (alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = (node.module.split(".")[0],)
            for name in names:
                if name in FORBIDDEN_IMPORTS:
                    raise SafetyDenied(
                        "offline contract violated: %s imports %s" % (entry.name, name)
                    )


def guard_offline() -> None:
    """Cached static scan + LIVE runtime check (never cached, so injection is caught)."""
    _scan_production_modules()
    # Runtime check: our own package must not have introduced a network module.
    for modname, module in list(sys.modules.items()):
        if modname.startswith("butwhy.") and module is not None:
            for bad in FORBIDDEN_IMPORTS:
                if hasattr(module, bad):
                    raise SafetyDenied("butwhy module exposes %s" % bad)


def snapshot(paths: dict) -> dict:
    """Build a golden manifest from labeled artifact paths.

    `paths` maps a stable label -> filesystem path. Only canonical bytes are
    hashed; wall-clock fields are excluded by construction.
    """
    entries = []
    for label in sorted(paths):
        with open(paths[label], "rb") as handle:
            blob = handle.read()
        obj = jsonutil.parse_canonical(blob)
        jsonutil.check_envelope(obj)
        entries.append(
            {
                "label": label,
                "canonical_sha256": jsonutil.sha256_hex(jsonutil.canonical(obj)),
                "byte_length": len(jsonutil.canonical(obj)),
            }
        )
    return jsonutil.envelope(
        "golden_manifest",
        {"golden_id": jsonutil.deterministic_id(entries), "entries": entries},
    )


def compare_golden(before: dict, after: dict) -> dict:
    """Byte-level golden comparison. Any difference is a forbidden function change."""
    jsonutil.check_envelope(before)
    jsonutil.check_envelope(after)
    b = {e["label"]: e for e in before["entries"]}
    a = {e["label"]: e for e in after["entries"]}
    diffs = []
    for label in sorted(set(b) | set(a)):
        if label not in b or label not in a:
            diffs.append({"label": label, "reason": "missing"})
        elif b[label] != a[label]:
            diffs.append({"label": label, "reason": "canonical_bytes_changed"})
    return {"identical": not diffs, "differences": diffs}
