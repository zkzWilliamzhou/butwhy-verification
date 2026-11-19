"""Shared, offline test helpers. No pytest, no network, no third-party deps."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from typing import Dict

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
CONFIRM = "yes-i-understand-butwhy-will-run-this"

CHECK_SCRIPT = '''import os
import sys
loc = os.environ.get("LC_ALL") or os.environ.get("LANG") or ""
if loc in ("C", "POSIX", ""):
    sys.stderr.write("boom: locale guard triggered (locale=%s)\\n" % loc)
    raise SystemExit(1)
sys.stdout.buffer.write(b"ok\\n")
'''

FLAKY_SCRIPT = '''import os, sys
i = int(os.environ.get("BUTWHY_REPEAT_INDEX", "0"))
raise SystemExit(0 if i % 2 == 0 else 1)
'''

ALWAYS_FAIL = '''import sys
sys.stderr.write("always failing\\n")
raise SystemExit(1)
'''


def cli(*args, cwd=None, timeout=180):
    """Run `python -m butwhy` with a minimal, deterministic environment."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": SRC,
        "SOURCE_DATE_EPOCH": "1700000000",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": tempfile.gettempdir(),
        "TZ": "UTC",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "butwhy", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def tree(root: str, files: Dict[str, str]) -> str:
    os.makedirs(root, exist_ok=True)
    for rel, body in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)
    return root
