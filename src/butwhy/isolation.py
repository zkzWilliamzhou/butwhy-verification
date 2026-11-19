"""Disposable copies and a bounded, offline subprocess runner.

The temp directory is a containment boundary, NOT a kernel sandbox. This module
never claims otherwise. Every experiment gets a fresh copy; no state leaks.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from functools import lru_cache
from typing import Optional

from . import secrets
from .errors import ResourceLimit, ReplayError, SafetyDenied

EXCLUDED_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
)
ALLOWED_EXECUTABLES = frozenset(
    {"python", "python3", "sh", "bash", "make", "node", "ruby", "go", "cargo",
     "pytest", "butwhy-shim", "tool"}
)
DENIED_EXECUTABLES = frozenset(
    {"rm", "rmdir", "sudo", "su", "doas", "dd", "mkfs", "shutdown", "reboot",
     "curl", "wget", "ssh", "nc", "git", "pip", "pip3", "npm", "npx", "docker",
     "podman", "kubectl", "chmod", "chown", "mv", "kill", "pkill"}
)
SHELL_METACHARS = frozenset(";|&$`><\n\r")
INTERPRETER_EXPR_FLAGS = {
    "python": {"-c"}, "python3": {"-c"}, "node": {"-c", "-e"},
    "ruby": {"-e"}, "perl": {"-e"}, "sh": {"-c"}, "bash": {"-c"},
}
MAX_FILES = 20000
MAX_DEPTH = 32
# RLIMIT_FSIZE protects the disk from a child that writes unbounded files. It
# must NOT be the same value as the stdout/stderr capture cap: if stdout is a
# redirected file, setting RLIMIT_FSIZE to the capture cap delivers SIGXFSZ and
# turns an output-limit event into a misleading plain command failure.
MAX_CHILD_FILE_BYTES = 64 * 1024 * 1024


def validate_argv(argv: list) -> None:
    """Fail closed before a subprocess is ever reachable."""
    if not argv or not all(isinstance(a, str) and a for a in argv):
        raise SafetyDenied("command must be a non-empty argv list")
    for token in argv:
        if "\x00" in token or any(c in token for c in SHELL_METACHARS):
            raise SafetyDenied("shell metacharacter or NUL in command token")
    exe = argv[0]
    base = os.path.basename(exe)
    if base in DENIED_EXECUTABLES:
        raise SafetyDenied("executable is denied: %s" % base)
    if "/" in exe or "\\" in exe:
        rel = exe.replace("\\", "/")
        if rel.startswith("/") or any(p in ("", ".", "..") for p in rel.split("/")):
            raise SafetyDenied("executable path must be project-relative")
    elif base not in ALLOWED_EXECUTABLES:
        raise SafetyDenied("executable is not on the allowlist: %s" % base)
    flags = INTERPRETER_EXPR_FLAGS.get(base, set())
    for token in argv[1:]:
        if token in flags:
            raise SafetyDenied("interpreter expression flags are denied: %s" % token)
        norm = token.replace("\\", "/")
        if norm.startswith("/") or ".." in norm.split("/"):
            raise SafetyDenied("absolute or traversing argument is denied: %s" % token)


@lru_cache(maxsize=1)
def _safe_system_path() -> str:
    parts = []
    for chunk in (os.path.dirname(sys.executable), "/usr/local/bin", "/usr/bin", "/bin"):
        if chunk and chunk not in parts:
            parts.append(chunk)
    return ":".join(parts)


def build_child_env(copy_root: str, desired: dict) -> dict:
    """Construct a fresh env. Never inherit raw os.environ."""
    child = {}
    for name, value in sorted(desired.items()):
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if secrets.never_transplant(name):
            continue
        if not secrets.SAFE_NAME_RE.match(name):
            continue
        if name.upper() in ("LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME"):
            if value not in secrets.SAFE_LOCALES:
                continue
        elif name.upper() == "TZ":
            if not secrets.SAFE_TZ_RE.match(value) or ".." in value:
                continue
        elif not secrets.safe_value(name, value):
            continue
        child[name] = value
    # A path_shadow factor declares a tool-owned shim dir via this internal key.
    # It is only honoured when it resolves inside the disposable copy.
    shim = desired.get("BUTWHY_SHIM_DIR")
    base = os.path.realpath(copy_root)
    if isinstance(shim, str) and shim:
        real = os.path.realpath(shim)
        if real == base or real.startswith(base + os.sep):
            # Use the caller's spelling, not its realpath: on macOS the temp
            # root is reached through /var -> /private/var, so prepending the
            # realpath would not match the declared shim directory.
            child["PATH"] = shim + ":" + _safe_system_path()
        else:
            child["PATH"] = _safe_system_path()
    else:
        child["PATH"] = _safe_system_path()
    child["HOME"] = os.path.join(copy_root, ".butwhy-home")
    child["TMPDIR"] = os.path.join(copy_root, ".butwhy-tmp")
    child["PYTHONDONTWRITEBYTECODE"] = "1"
    child["BUTWHY_SANDBOX"] = "1"
    os.makedirs(child["HOME"], mode=0o700, exist_ok=True)
    os.makedirs(child["TMPDIR"], mode=0o700, exist_ok=True)
    return child


def make_copy(src_root: str, bounds: dict) -> str:
    """Create a 0o700 disposable root and return the inner work directory."""
    src = os.path.abspath(src_root)
    if not os.path.isdir(src):
        raise ReplayError("source is not a directory: %s" % src_root)
    outer = tempfile.mkdtemp(prefix="butwhy-")
    os.chmod(outer, 0o700)
    dst = os.path.join(outer, "work")
    os.makedirs(dst, mode=0o700)
    base_real = os.path.realpath(src)
    total = 0
    count = 0
    stack = [(src, dst, 0)]
    try:
        while stack:
            cur_src, cur_dst, depth = stack.pop()
            if depth > MAX_DEPTH:
                raise ResourceLimit("copy depth exceeds %d" % MAX_DEPTH)
            for entry in sorted(os.scandir(cur_src), key=lambda e: e.name):
                name = entry.name
                if name in EXCLUDED_DIRS or name.startswith(".butwhy-"):
                    continue
                s_path, d_path = entry.path, os.path.join(cur_dst, name)
                st = os.lstat(s_path)
                count += 1
                if count > MAX_FILES:
                    raise ResourceLimit("copy exceeds %d entries" % MAX_FILES)
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(s_path)
                    resolved = os.path.realpath(os.path.join(os.path.dirname(s_path), target))
                    if not (resolved == base_real or resolved.startswith(base_real + os.sep)):
                        raise SafetyDenied("symlink escapes the source tree: %s" % name)
                    os.symlink(target, d_path)
                elif stat.S_ISDIR(st.st_mode):
                    os.makedirs(d_path, mode=0o700, exist_ok=True)
                    stack.append((s_path, d_path, depth + 1))
                elif stat.S_ISREG(st.st_mode):
                    if st.st_nlink > 1:
                        raise SafetyDenied("hardlinks are not copied: %s" % name)
                    total += st.st_size
                    if total > bounds["max_tree_bytes"]:
                        raise ResourceLimit("copy exceeds %d bytes" % bounds["max_tree_bytes"])
                    shutil.copyfile(s_path, d_path)
                    os.chmod(d_path, stat.S_IMODE(st.st_mode) & 0o700)
                else:
                    raise SafetyDenied("special files are not copied: %s" % name)
        return dst
    except Exception:
        destroy_copy(dst, bounds)
        raise


def _set_limits(cap: int, timeout: int) -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
        cpu = max(1, int(timeout))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    except (ImportError, OSError, ValueError):
        pass
    try:
        os.umask(0o077)
    except OSError:
        pass


def _read_bounded(path: str, cap: int) -> tuple:
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        data = handle.read(cap + 1)
    truncated = size > cap
    return data[:cap], truncated, size


def spawn_isolated(copy_root: str, argv: list, desired_env: dict, bounds: dict) -> dict:
    """Run one command in copy_root. Returns a deterministic outcome record."""
    validate_argv(argv)
    env = build_child_env(copy_root, desired_env)
    cap = int(bounds["max_output_bytes"])
    timeout = float(bounds["timeout_sec"])
    out_path = os.path.join(copy_root, ".butwhy-stdout")
    err_path = os.path.join(copy_root, ".butwhy-stderr")
    out_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    err_fd = os.open(err_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    timed_out = False
    spawn_error = ""
    exit_code = -1
    try:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=copy_root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out_fd,
                stderr=err_fd,
                close_fds=True,
                start_new_session=(os.name == "posix"),
                preexec_fn=(lambda: _set_limits(MAX_CHILD_FILE_BYTES, timeout))
                if os.name == "posix" else None,
            )
        except (OSError, ValueError) as exc:
            spawn_error = type(exc).__name__
            proc = None
        if proc is not None:
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
    finally:
        os.close(out_fd)
        os.close(err_fd)

    out_data, out_trunc, out_size = _read_bounded(out_path, cap)
    err_data, err_trunc, err_size = _read_bounded(err_path, cap)
    truncated = out_trunc or err_trunc
    preview = lambda b: secrets.redact_text(b.decode("utf-8", "replace"))[:512]

    if spawn_error:
        outcome = "error"
    elif timed_out:
        outcome = "timeout"
    elif truncated:
        outcome = "output_limit"
    elif exit_code == 0:
        outcome = "pass"
    else:
        outcome = "fail"
    return {
        "outcome": outcome,
        "exit_code": int(exit_code),
        "stdout_sha256": hashlib.sha256(out_data).hexdigest(),
        "stderr_sha256": hashlib.sha256(err_data).hexdigest(),
        "stdout_len": out_size,
        "stderr_len": err_size,
        "stdout_preview": preview(out_data),
        "stderr_preview": preview(err_data),
        "timed_out": timed_out,
        "truncated": truncated,
        "spawn_error": spawn_error,
    }


def destroy_copy(path: str, bounds: dict) -> None:
    """Remove the whole temp root, never just the inner work dir."""
    outer = os.path.dirname(os.path.abspath(path))
    if not os.path.basename(outer).startswith("butwhy-"):
        return
    if not os.path.isdir(outer):
        return

    def _fixup(func, target, exc_info):
        try:
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            pass

    try:
        shutil.rmtree(outer, onerror=_fixup)
    except OSError:
        quarantine(path, "cleanup failed")


def quarantine(path: str, reason: str) -> str:
    """Move an undeletable temp tree into a 0o700 quarantine dir."""
    outer = os.path.dirname(os.path.abspath(path))
    dest = tempfile.mkdtemp(prefix="butwhy-quarantine-")
    try:
        os.chmod(dest, 0o700)
        target = os.path.join(dest, "work")
        shutil.move(outer, target)
    except OSError:
        pass
    return dest
