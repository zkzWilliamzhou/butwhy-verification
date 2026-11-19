"""Capture a deterministic, secret-safe environment capsule.

No wall clock is used by default: `captured_at` comes from SOURCE_DATE_EPOCH
(default 0) and is excluded from the capsule identity digest. Root paths are
normalized to a stable label so capsules are byte-stable across temp dirs.
"""
from __future__ import annotations

import hashlib
import os
import platform
import stat
import sys
from typing import Optional

from . import jsonutil, secrets
from .errors import ReplayError, ResourceLimit

EXCLUDED_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
)
LOCALE_NAMES = ("LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME", "LC_NUMERIC")
# Tool-control variables are provenance, not a machine difference. Excluding
# them keeps capsule identity byte-stable when SOURCE_DATE_EPOCH changes.
CONTROL_NAMES = frozenset(
    {"TZ", "SOURCE_DATE_EPOCH", "BUTWHY_SANDBOX", "BUTWHY_REPEAT_INDEX",
     "BUTWHY_SHIM_DIR", "BUTWHY_TRACE"}
)
MAX_FILES = 20000
MAX_PATH_DEPTH = 32


def _line_ending_kind(data: bytes) -> str:
    if b"\x00" in data:
        return "binary"
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n") - crlf
    cr = data.count(b"\r") - crlf
    if crlf and (lf or cr):
        return "mixed"
    if crlf:
        return "crlf"
    if cr and not lf:
        return "cr"
    if lf:
        return "lf"
    return "lf"


def _walk(root: str, label: str, bounds: dict) -> tuple:
    files, symlinks = [], []
    total = 0
    base_real = os.path.realpath(root)
    stack = [(root, "", 0)]
    while stack:
        current, rel, depth = stack.pop()
        if depth > MAX_PATH_DEPTH:
            raise ResourceLimit("path depth exceeds %d" % MAX_PATH_DEPTH)
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError as exc:
            raise ReplayError("cannot scan %s: %s" % (current, exc)) from exc
        for entry in entries:
            name = entry.name
            if name in EXCLUDED_DIRS or name.startswith(".butwhy-"):
                continue
            child_rel = (rel + "/" + name) if rel else name
            full = os.path.join(current, name)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(full)
                resolved = os.path.realpath(os.path.join(os.path.dirname(full), target))
                contained = resolved == base_real or resolved.startswith(base_real + os.sep)
                symlinks.append(
                    {"path": child_rel, "target": target, "in_tree": bool(contained),
                     "root_label": label}
                )
                files.append(
                    {"path": child_rel, "kind": "symlink", "mode": 0, "size": 0,
                     "sha256": None, "line_endings": None,
                     "filename_case_key": child_rel.casefold(), "root_label": label}
                )
                continue
            if stat.S_ISDIR(st.st_mode):
                files.append(
                    {"path": child_rel, "kind": "directory", "mode": stat.S_IMODE(st.st_mode) & 0o777,
                     "size": 0, "sha256": None, "line_endings": None,
                     "filename_case_key": child_rel.casefold(), "root_label": label}
                )
                stack.append((full, child_rel, depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                files.append(
                    {"path": child_rel, "kind": "special", "mode": 0, "size": 0,
                     "sha256": None, "line_endings": None,
                     "filename_case_key": child_rel.casefold(), "root_label": label}
                )
                continue
            if st.st_nlink > 1:
                files.append(
                    {"path": child_rel, "kind": "hardlink", "mode": stat.S_IMODE(st.st_mode) & 0o777,
                     "size": st.st_size, "sha256": None, "line_endings": None,
                     "filename_case_key": child_rel.casefold(), "root_label": label}
                )
                continue
            total += st.st_size
            if total > bounds["max_tree_bytes"]:
                raise ResourceLimit("tree exceeds %d bytes" % bounds["max_tree_bytes"])
            if len(files) >= MAX_FILES:
                raise ResourceLimit("tree exceeds %d entries" % MAX_FILES)
            digest = hashlib.sha256()
            head = b""
            with open(full, "rb") as handle:
                while True:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                    if len(head) < 65536:
                        head += chunk[: 65536 - len(head)]
            files.append(
                {"path": child_rel, "kind": "regular",
                 "mode": stat.S_IMODE(st.st_mode) & 0o777, "size": st.st_size,
                 "sha256": digest.hexdigest(), "line_endings": _line_ending_kind(head),
                 "filename_case_key": child_rel.casefold(), "root_label": label}
            )
    return files, symlinks


def _env_snapshot() -> list:
    out = []
    for name in sorted(os.environ):
        if name.upper() in LOCALE_NAMES or name.upper() in CONTROL_NAMES:
            continue
        rec = secrets.env_record(name, os.environ[name])
        out.append(rec)
    return out


def capture_environment(roots: list, bounds: dict) -> dict:
    """Read the live environment into a typed, deterministic capsule."""
    if not roots:
        raise ReplayError("capture requires at least one --root")
    labels, files, symlinks = [], [], []
    for index, root in enumerate(roots):
        root_abs = os.path.abspath(root)
        if not os.path.isdir(root_abs):
            raise ReplayError("root is not a directory: %s" % root)
        label = os.path.basename(root_abs) or "root"
        labels.append(label)
        part_files, part_links = _walk(root_abs, label, bounds)
        files.extend(part_files)
        symlinks.extend(part_links)
    files.sort(key=lambda f: (f["root_label"], f["path"]))
    symlinks.sort(key=lambda s: (s["root_label"], s["path"]))

    env_all = _env_snapshot()
    env_factor = [
        {"name": e["name"], "value": e["value"], "state": e["state"]}
        for e in env_all
        if e["transplantable"] and e["value"] is not None
    ]
    locale = {
        name: (os.environ.get(name) if os.environ.get(name) in secrets.SAFE_LOCALES else "")
        for name in LOCALE_NAMES
    }
    tz = os.environ.get("TZ", "")
    if not secrets.SAFE_TZ_RE.match(tz):
        tz = ""
    snapshot = {
        "env_var": env_factor,
        "locale": locale,
        "timezone": {"tz": tz},
        "line_endings": [
            {"path": f["path"], "kind": f["line_endings"]}
            for f in files if f["kind"] == "regular" and f["line_endings"]
        ],
        "symlink_target": [
            {"path": s["path"], "target": s["target"]} for s in symlinks
        ],
        "filename_case": [
            {"path": f["path"], "lower": f["filename_case_key"]}
            for f in files if f["kind"] in ("regular", "directory")
        ],
        "file_mode": [
            {"path": f["path"], "mode": f["mode"]}
            for f in files if f["kind"] in ("regular", "directory")
        ],
        "path_shadow": {"shim_dir": None, "prepend": False},
    }
    non_replayable = {
        "interpreter_version": sys.version.split()[0],
        "platform": platform.system() + "-" + platform.machine(),
    }
    captured_at = int(os.environ.get("SOURCE_DATE_EPOCH", "0") or "0")
    fingerprint = {
        "labels": labels, "env": env_all, "factor_snapshot": snapshot,
        "files": files, "symlinks": symlinks,
        "non_replayable": non_replayable, "bounds": bounds,
    }
    capsule_id = jsonutil.deterministic_id(fingerprint)
    return jsonutil.envelope(
        "capsule",
        {
            "capsule_id": capsule_id,
            "captured_at": captured_at,
            "roots": labels,
            "env": env_all,
            "factor_snapshot": snapshot,
            "files": files,
            "symlinks": symlinks,
            "non_replayable": non_replayable,
            "bounds": bounds,
        },
    )


def with_env_override(capsule: dict, name: str, value: Optional[str]) -> dict:
    """Fixture helper: derive a capsule with one env value replaced.

    Used by `demo` to model a second machine. It is a fixture construction
    primitive, NOT a claim about a real observed host.
    """
    import copy

    out = copy.deepcopy(capsule)
    upper = name.upper()
    rec = next((e for e in out["env"] if e["name"] == name), None)
    new_rec = secrets.env_record(name, value)
    if rec is None:
        out["env"].append(new_rec)
    else:
        out["env"][out["env"].index(rec)] = new_rec
    out["env"].sort(key=lambda e: e["name"])
    if upper in LOCALE_NAMES:
        out["factor_snapshot"]["locale"][name] = value if value in secrets.SAFE_LOCALES else ""
    elif upper == "TZ":
        out["factor_snapshot"]["timezone"]["tz"] = value or ""
    else:
        items = [x for x in out["factor_snapshot"]["env_var"] if x["name"] != name]
        if value is not None and not secrets.never_transplant(name):
            items.append({"name": name, "value": value, "state": "present"})
        items.sort(key=lambda x: x["name"])
        out["factor_snapshot"]["env_var"] = items
    fingerprint = {
        "labels": out["roots"], "env": out["env"],
        "factor_snapshot": out["factor_snapshot"], "files": out["files"],
        "symlinks": out["symlinks"], "non_replayable": out["non_replayable"],
        "bounds": out["bounds"],
    }
    out["capsule_id"] = jsonutil.deterministic_id(fingerprint)
    return out


def with_path_shadow(capsule: dict, shim_name: str, shim_exit: int) -> dict:
    """Fixture helper: declare a PATH-shadowing shim in a capsule.

    Used by tests and fixtures to model a machine where an earlier PATH entry
    shadows the expected tool. It is a declaration, not an observed host claim.
    """
    import copy

    out = copy.deepcopy(capsule)
    out["factor_snapshot"]["path_shadow"] = {
        "prepend": True, "shim_name": shim_name, "shim_exit": int(shim_exit)
    }
    fingerprint = {
        "labels": out["roots"], "env": out["env"],
        "factor_snapshot": out["factor_snapshot"], "files": out["files"],
        "symlinks": out["symlinks"], "non_replayable": out["non_replayable"],
        "bounds": out["bounds"],
    }
    out["capsule_id"] = jsonutil.deterministic_id(fingerprint)
    return out


def write_capsule(capsule: dict, path: str) -> str:
    jsonutil.check_envelope(capsule)
    if capsule.get("document") != "capsule":
        raise ReplayError("not a capsule document")
    return jsonutil.write_document(path, capsule)
