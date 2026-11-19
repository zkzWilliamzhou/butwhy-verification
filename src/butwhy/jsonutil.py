"""Canonical JSON, strict parsing, envelope validation, deterministic IDs.

Canonical form (used for ALL hashes and machine artifacts):
  UTF-8, sorted dict keys by UTF-8 byte order, compact separators,
  no insignificant whitespace, no NaN/Infinity, no duplicate keys,
  depth <= 32, size <= 16 MiB. No wall clock inside hashed payloads.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from functools import lru_cache
from typing import Any

from .errors import ResourceLimit, SchemaError

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
GENESIS_PREV = "0" * 64
VERSION = "0.1.0"

DOC_TYPES = frozenset(
    {
        "capsule",
        "factor_diff",
        "evidence_ledger",
        "verdict_report",
        "golden_manifest",
        "verify_result",
        "dry_run_plan",
    }
)
ENVELOPE_KEYS = frozenset({"schema_version", "document", "generator", "version"})


@lru_cache(maxsize=4096)
def _quoted(value: str) -> bytes:
    """Cache JSON string escaping. Pure function: identical input, identical bytes.

    Internal optimization only; the canonical byte stream is unchanged.
    """
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical(obj: Any, _depth: int = 0) -> bytes:
    """Return the canonical UTF-8 byte representation of a JSON value."""
    buf = bytearray()
    _write(buf, obj, _depth)
    return bytes(buf)


def _write(buf: bytearray, obj: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ResourceLimit("JSON depth exceeds %d" % MAX_DEPTH)
    if obj is None:
        buf += b"null"
    elif obj is True:
        buf += b"true"
    elif obj is False:
        buf += b"false"
    elif isinstance(obj, int) and not isinstance(obj, bool):
        buf += str(obj).encode("ascii")
    elif isinstance(obj, float):
        if not math.isfinite(obj):
            raise SchemaError("non-finite float is not allowed in canonical JSON")
        buf += json.dumps(obj, allow_nan=False).encode("ascii")
    elif isinstance(obj, str):
        buf += _quoted(obj)
    elif isinstance(obj, (list, tuple)):
        buf += b"["
        for i, item in enumerate(obj):
            if i:
                buf += b","
            _write(buf, item, depth + 1)
        buf += b"]"
    elif isinstance(obj, dict):
        for key in obj:
            if not isinstance(key, str):
                raise SchemaError("dict keys must be strings")
        keys = sorted(obj.keys(), key=lambda k: k.encode("utf-8"))
        buf += b"{"
        for i, key in enumerate(keys):
            if i:
                buf += b","
            _write(buf, key, depth + 1)
            buf += b":"
            _write(buf, obj[key], depth + 1)
        buf += b"}"
    else:
        raise SchemaError("unsupported type in canonical JSON: %s" % type(obj).__name__)
    if len(buf) > MAX_INPUT_BYTES:
        raise ResourceLimit("canonical JSON exceeds %d bytes" % MAX_INPUT_BYTES)


def _check_depth(obj: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ResourceLimit("JSON depth exceeds %d" % MAX_DEPTH)
    if isinstance(obj, dict):
        for key, value in obj.items():
            _check_depth(key, depth + 1)
            _check_depth(value, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            _check_depth(value, depth + 1)


def _reject_duplicates(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise SchemaError("duplicate JSON key: %s" % key)
        out[key] = value
    return out


def _reject_constant(value: str) -> Any:
    raise SchemaError("non-finite JSON constant rejected: %s" % value)


def parse_canonical(blob: bytes) -> Any:
    """Parse strict canonical JSON. Rejects duplicates, NaN/Inf, BOM, non-canonical text."""
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    if len(blob) > MAX_INPUT_BYTES + 1:
        raise ResourceLimit("input exceeds %d bytes" % MAX_INPUT_BYTES)
    data = blob.rstrip(b"\r\n")
    if data.startswith(b"\xef\xbb\xbf"):
        raise SchemaError("UTF-8 BOM is not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SchemaError("input is not valid UTF-8: %s" % exc) from exc
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise SchemaError("invalid JSON: %s" % exc) from exc
    _check_depth(obj)
    if canonical(obj) != data:
        raise SchemaError("input is not in canonical form")
    return obj


def envelope(doc_type: str, payload: dict) -> dict:
    """Wrap a payload in the locked envelope."""
    if doc_type not in DOC_TYPES:
        raise SchemaError("unknown document type: %s" % doc_type)
    overlap = ENVELOPE_KEYS & set(payload)
    if overlap:
        raise SchemaError("payload may not override envelope keys: %s" % sorted(overlap))
    doc = {
        "schema_version": 1,
        "document": doc_type,
        "generator": "butwhy",
        "version": VERSION,
    }
    doc.update(payload)
    return doc


def check_envelope(obj: dict) -> str:
    """Validate the envelope; return the document type."""
    if not isinstance(obj, dict):
        raise SchemaError("document must be a JSON object")
    version = obj.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise SchemaError("unsupported schema_version: %r" % (version,))
    if obj.get("generator") != "butwhy":
        raise SchemaError("unexpected generator")
    if obj.get("version") != VERSION:
        raise SchemaError("unexpected tool version: %r" % (obj.get("version"),))
    doc_type = obj.get("document")
    if doc_type not in DOC_TYPES:
        raise SchemaError("unknown document: %r" % (doc_type,))
    return doc_type


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deterministic_id(obj: Any) -> str:
    """20-hex-character stable ID. No clock, PID, hostname or randomness."""
    return sha256_hex(canonical(obj))[:20]


def write_document(path: str, obj: dict, pretty: bool = False) -> str:
    """Write a JSON artifact. Returns sha256 of the CANONICAL bytes.

    Machine artifacts (capsule/diff/ledger/verdict/golden) are compact canonical.
    Human-facing artifacts may be indent-2 presentation JSON.
    """
    check_envelope(obj)
    canonical_bytes = canonical(obj)
    if pretty:
        body = json.dumps(
            obj, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2
        ).encode("utf-8") + b"\n"
    else:
        body = canonical_bytes + b"\n"
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return sha256_hex(canonical_bytes)


def read_document(path: str) -> dict:
    with open(path, "rb") as handle:
        blob = handle.read()
    obj = parse_canonical(blob)
    check_envelope(obj)
    return obj
