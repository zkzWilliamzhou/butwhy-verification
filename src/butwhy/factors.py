"""The 8 replayable + 2 non-replayable factor families.

Every apply() operates ONLY inside a disposable copy and returns a small,
deterministic revert record (never raw file bytes).
"""
from __future__ import annotations

import os
import stat
from typing import Optional

from . import secrets
from .contract import ALL_FAMILIES, REPLAYABLE_FAMILIES
from .errors import SafetyDenied, ReplayError, ResourceLimit

MAX_TEXT_BYTES = 4 * 1024 * 1024
SHIM_SCRIPT = """#!/bin/sh
# butwhy-owned shim. Offline, fixed behaviour, no network, no inherited env.
printf '%s\\n' 'BUTWHY_SHIM_MARKER'
exit {code}
"""


def list_families() -> list:
    return list(ALL_FAMILIES)


def is_replayable(family: str) -> bool:
    return family in REPLAYABLE_FAMILIES


def _safe_join(copy_root: str, rel: Optional[str]) -> str:
    if not rel or not isinstance(rel, str):
        raise SafetyDenied("factor requires a relative path")
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or "\x00" in rel:
        raise SafetyDenied("absolute path or NUL in factor path")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise SafetyDenied("unsafe path component in %r" % rel)
    base = os.path.realpath(copy_root)
    # Lexical join: the final component may itself be a symlink that a factor
    # is about to retarget, so resolving it here would silently operate on the
    # symlink's TARGET instead of the link itself. Containment is checked on
    # every ancestor directory instead.
    target = os.path.join(base, *parts)
    cur = base
    for part in parts[:-1]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            raise SafetyDenied("symlinked parent directory is not allowed")
        rp = os.path.realpath(cur)
        if not (rp == base or rp.startswith(base + os.sep)):
            raise SafetyDenied("factor path escapes the disposable copy")
    parent = os.path.dirname(target)
    if os.path.islink(parent):
        raise SafetyDenied("symlinked parent directory is not allowed")
    prp = os.path.realpath(parent)
    if not (prp == base or prp.startswith(base + os.sep)):
        raise SafetyDenied("factor path escapes the disposable copy")
    return target


def _validate_env(name: str, value: Optional[str]) -> None:
    if not isinstance(name, str) or not secrets.SAFE_NAME_RE.match(name):
        raise SafetyDenied("invalid env name for a factor")
    if secrets.never_transplant(name):
        raise SafetyDenied("env name is on the never-transplant list: %s" % name)
    if value is not None and not secrets.safe_value(name, value):
        raise SafetyDenied("unsafe value for env factor %s" % name)


def apply_factor(copy_root: str, spec: dict, ctx: dict) -> dict:
    """Apply exactly ONE factor. ctx is {'env': dict}."""
    family = spec.get("family")
    if family not in REPLAYABLE_FAMILIES:
        raise ReplayError("factor family is not replayable: %s" % family)
    if spec.get("denied"):
        raise SafetyDenied("factor was denied during diff")
    env = ctx.setdefault("env", {})
    before, after = spec.get("before", {}), spec.get("after", {})

    if family == "env_var":
        name = after.get("name") or before.get("name")
        value = after.get("value")
        _validate_env(name, value)
        had = name in env
        old = env.get(name)
        if spec.get("action") == "unset" or value is None:
            env.pop(name, None)
        else:
            env[name] = value
        return {"family": family, "kind": "env", "name": name, "had": had, "old": old}

    if family == "locale":
        changed = {}
        for key in sorted(set(before) | set(after)):
            value = after.get(key, "")
            if value:
                _validate_env(key, value)
            old = env.get(key)
            if value:
                env[key] = value
            else:
                env.pop(key, None)
            changed[key] = old
        return {"family": family, "kind": "env_map", "changed": changed}

    if family == "timezone":
        value = after.get("tz", "")
        if value:
            _validate_env("TZ", value)
        old = env.get("TZ")
        if value:
            env["TZ"] = value
        else:
            env.pop("TZ", None)
        return {"family": family, "kind": "env", "name": "TZ",
                "had": old is not None, "old": old}

    if family == "line_endings":
        path = spec.get("path")
        target = _safe_join(copy_root, path)
        if not os.path.isfile(target) or os.path.islink(target):
            raise ReplayError("line-ending target is not a regular file: %s" % path)
        size = os.path.getsize(target)
        if size > MAX_TEXT_BYTES:
            raise ResourceLimit("line-ending target exceeds %d bytes" % MAX_TEXT_BYTES)
        with open(target, "rb") as handle:
            data = handle.read()
        if b"\x00" in data:
            raise ReplayError("binary file cannot be line-ending flipped")
        kind = after.get("kind")
        if kind == "crlf":
            converted = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        elif kind in ("lf", "cr"):
            converted = data.replace(b"\r\n", b"\n")
            if kind == "cr":
                converted = converted.replace(b"\n", b"\r")
        else:
            raise ReplayError("unsupported target line-ending kind: %s" % kind)
        with open(target, "wb") as handle:
            handle.write(converted)
        return {"family": family, "kind": "bytes", "path": path,
                "restore": "normalized"}

    if family == "symlink_target":
        path = spec.get("path")
        target_path = _safe_join(copy_root, path)
        new_target = after.get("target")
        if not isinstance(new_target, str) or not new_target:
            raise ReplayError("symlink target is missing")
        if new_target.startswith("/") or ".." in new_target.split("/"):
            raise SafetyDenied("symlink target must stay inside the copy")
        old = os.readlink(target_path) if os.path.islink(target_path) else None
        if os.path.islink(target_path) or os.path.lexists(target_path):
            os.unlink(target_path)
        os.symlink(new_target, target_path)
        return {"family": family, "kind": "symlink", "path": path, "old": old}

    if family == "filename_case":
        path = spec.get("path")
        source = _safe_join(copy_root, path)
        new_rel = after.get("lower") or ""
        if not new_rel:
            raise ReplayError("filename-case target is missing")
        new_path = _safe_join(copy_root, new_rel)
        if not os.path.lexists(source):
            raise ReplayError("filename-case source does not exist")
        if os.path.lexists(new_path):
            # On a case-insensitive filesystem (e.g. macOS APFS) `DATA.txt`
            # already "exists" when `data.txt` does. If both names resolve to
            # the same inode this is a case-only rename of one file, which is
            # valid; any other existing destination is a genuine collision.
            try:
                same_file = os.path.samefile(source, new_path)
            except OSError:
                same_file = False
            if not same_file:
                raise ReplayError("filename-case destination already exists")
            # Rename via a scratch name so the case change is committed even on
            # filesystems that treat a direct case-only rename as a no-op.
            scratch = source + ".butwhy-case-tmp"
            counter = 0
            while os.path.lexists(scratch):
                counter += 1
                scratch = "%s.butwhy-case-tmp-%d" % (source, counter)
            os.rename(source, scratch)
            try:
                os.rename(scratch, new_path)
            except OSError:
                os.rename(scratch, source)
                raise
        else:
            os.rename(source, new_path)
        return {"family": family, "kind": "rename", "path": path,
                "moved_to": os.path.relpath(new_path, copy_root)}

    if family == "file_mode":
        path = spec.get("path")
        target = _safe_join(copy_root, path)
        mode = after.get("mode")
        if not isinstance(mode, int) or isinstance(mode, bool):
            raise ReplayError("file_mode requires an integer mode")
        mode &= 0o777
        if mode & 0o7000 or (mode & 0o002 and mode & 0o020 and mode & 0o200):
            raise SafetyDenied("refusing setuid/setgid/sticky or world-writable mode")
        old = stat.S_IMODE(os.stat(target).st_mode)
        os.chmod(target, mode)
        return {"family": family, "kind": "mode", "path": path, "old": old}

    if family == "path_shadow":
        # A counter-flip with prepend=False restores the baseline: no shim is
        # placed on PATH. This makes the two-way experiment honest.
        if after.get("prepend") is False:
            return {"family": family, "kind": "path_noop",
                    "name": after.get("shim_name") or "butwhy-shim"}
        shim_dir = os.path.join(os.path.realpath(copy_root), ".butwhy-shims")
        os.makedirs(shim_dir, mode=0o700, exist_ok=True)
        name = after.get("shim_name") or "butwhy-shim"
        if not secrets.SAFE_NAME_RE.match(name):
            raise SafetyDenied("invalid shim name")
        code = after.get("shim_exit", 0)
        if not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255:
            raise ReplayError("shim exit code must be 0..255")
        script_path = os.path.join(shim_dir, name)
        with open(script_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(SHIM_SCRIPT.format(code=code))
        os.chmod(script_path, 0o700)
        env["BUTWHY_SHIM_DIR"] = shim_dir
        return {"family": family, "kind": "path", "name": name,
                "shim_dir": ".butwhy-shims"}

    raise ReplayError("unhandled factor family: %s" % family)


def revert_factor(copy_root: str, record: dict) -> None:
    """Best-effort in-copy reversal. Fresh copies make this informational."""
    if not record:
        return
    kind = record.get("kind")
    if kind in ("env", "env_map", "path", "path_noop"):
        return
    if kind == "bytes":
        target = _safe_join(copy_root, record.get("path"))
        if os.path.isfile(target) and not os.path.islink(target):
            with open(target, "rb") as handle:
                data = handle.read()
            with open(target, "wb") as handle:
                handle.write(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
        return
    if kind == "symlink":
        target = _safe_join(copy_root, record.get("path"))
        if os.path.islink(target) or os.path.lexists(target):
            os.unlink(target)
        if record.get("old"):
            os.symlink(record["old"], target)
        return
    if kind == "rename":
        moved = _safe_join(copy_root, record.get("moved_to"))
        original = _safe_join(copy_root, record.get("path"))
        if os.path.lexists(moved) and not os.path.lexists(original):
            os.rename(moved, original)
        return
    if kind == "mode":
        target = _safe_join(copy_root, record.get("path"))
        if os.path.lexists(target):
            os.chmod(target, record["old"])
        return
