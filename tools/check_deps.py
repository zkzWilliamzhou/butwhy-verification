#!/usr/bin/env python3
"""Verify butwhy is stdlib-only and offline. No network, no third-party imports."""
from __future__ import annotations

import ast
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "butwhy")
sys.path.insert(0, os.path.join(ROOT, "src"))

from butwhy import contract  # noqa: E402

FORBIDDEN = set(contract.FORBIDDEN_IMPORTS) | {"requests", "numpy", "yaml", "click", "pytest"}
STDLIB = set(getattr(sys, "stdlib_module_names", ()))
RESULT = {"third_party_imports": [], "forbidden_imports": [], "modules_scanned": 0,
          "dependencies_declared": [], "offline_guard": None, "valid": False}


def top_level(name):
    return name.split(".")[0]


for entry in sorted(os.scandir(SRC), key=lambda p: p.name):
    if not entry.name.endswith(".py"):
        continue
    RESULT["modules_scanned"] += 1
    tree = ast.parse(open(entry.path, encoding="utf-8").read(), filename=entry.path)
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            base = top_level(name)
            if base in FORBIDDEN:
                RESULT["forbidden_imports"].append("%s:%s" % (entry.name, name))
            if base not in STDLIB and base != "butwhy" and not name.startswith("."):
                RESULT["third_party_imports"].append("%s:%s" % (entry.name, name))

pyproject = os.path.join(ROOT, "pyproject.toml")
text = open(pyproject, encoding="utf-8").read()
import re  # noqa: E402
m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.M | re.S)
RESULT["dependencies_declared"] = (m.group(1).strip() if m else "MISSING")

try:
    contract.guard_offline()
    RESULT["offline_guard"] = "PASS"
except Exception as exc:  # pragma: no cover
    RESULT["offline_guard"] = "FAIL %s" % exc

RESULT["valid"] = (
    not RESULT["third_party_imports"]
    and not RESULT["forbidden_imports"]
    and RESULT["modules_scanned"] == 16
    and RESULT["dependencies_declared"] == ""
    and RESULT["offline_guard"] == "PASS"
)
os.makedirs(os.path.join(ROOT, "reviews"), exist_ok=True)
with open(os.path.join(ROOT, "reviews", "check_deps.json"), "w", encoding="utf-8") as h:
    json.dump(RESULT, h, indent=2, sort_keys=True)
    h.write("\n")
print("check-deps: %s (modules=%d, third-party=%d, forbidden=%d)" % (
    "OK" if RESULT["valid"] else "FAIL", RESULT["modules_scanned"],
    len(RESULT["third_party_imports"]), len(RESULT["forbidden_imports"])))
sys.exit(0 if RESULT["valid"] else 1)
