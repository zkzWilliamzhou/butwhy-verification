"""Append-only, SHA-256 hash-chained evidence ledger.

A ledger proves that an accepted event sequence was not altered after genesis.
It does NOT prove the capsule was truthful, the command was safe, or a verdict
is correct. Those limits are disclosed in the README.
"""
from __future__ import annotations

from . import jsonutil
from .errors import SchemaError, VerifyInvalid

EVENT_KINDS = frozenset(
    {"plan", "capture", "apply", "revert", "execute", "observe", "verdict",
     "note", "error", "ledger_closed"}
)


def new_ledger(meta: dict) -> dict:
    payload = dict(meta)
    payload["ledger_id"] = jsonutil.deterministic_id({"meta": meta, "genesis": "butwhy-v1"})
    payload["head"] = jsonutil.GENESIS_PREV
    payload["events"] = []
    payload["closed"] = False
    return jsonutil.envelope("evidence_ledger", payload)


def event_hash(prev: str, event: dict) -> str:
    core = {
        "prev": prev,
        "seq": event["seq"],
        "kind": event["kind"],
        "data": event["data"],
    }
    return jsonutil.sha256_hex(jsonutil.canonical(core))


def append_event(ledger: dict, event: dict) -> dict:
    if jsonutil.check_envelope(ledger) != "evidence_ledger":
        raise SchemaError("not an evidence_ledger")
    if ledger.get("closed"):
        raise SchemaError("cannot append to a closed ledger")
    kind = event.get("kind")
    if kind not in EVENT_KINDS:
        raise SchemaError("unknown event kind: %r" % kind)
    seq = len(ledger["events"]) + 1
    prev = ledger["head"]
    full = {
        "event_id": jsonutil.deterministic_id(
            {"ledger": ledger["ledger_id"], "seq": seq, "kind": kind, "data": event["data"]}
        ),
        "seq": seq,
        "prev": prev,
        "kind": kind,
        "data": event["data"],
    }
    full["canonical_bytes_sha256"] = jsonutil.sha256_hex(
        jsonutil.canonical({"seq": seq, "kind": kind, "data": event["data"]})
    )
    full["hash"] = event_hash(prev, full)
    ledger["events"].append(full)
    ledger["head"] = full["hash"]
    return ledger


def verify_ledger(ledger: dict) -> dict:
    """Recompute every hash offline. Returns a verify_result payload."""
    errors = []
    checked = 0
    first_invalid = None
    status = "valid"
    try:
        if jsonutil.check_envelope(ledger) != "evidence_ledger":
            errors.append("not an evidence_ledger document")
            status = "invalid"
        events = ledger.get("events")
        if not isinstance(events, list) or not events:
            errors.append("ledger has no events")
            status = "invalid"
        if not ledger.get("closed"):
            errors.append("ledger is incomplete: not closed")
            if status == "valid":
                status = "incomplete"
        if status != "invalid":
            prev = jsonutil.GENESIS_PREV
            seen_ids = set()
            for index, event in enumerate(events, start=1):
                checked += 1
                if event.get("seq") != index:
                    errors.append("event %d has seq %r" % (index, event.get("seq")))
                eid = event.get("event_id")
                if eid in seen_ids:
                    errors.append("duplicate event_id at %d" % index)
                seen_ids.add(eid)
                if event.get("kind") not in EVENT_KINDS:
                    errors.append("unknown event kind at %d" % index)
                if event.get("prev") != prev:
                    errors.append("broken prev link at %d" % index)
                expected_payload = jsonutil.sha256_hex(
                    jsonutil.canonical(
                        {"seq": event.get("seq"), "kind": event.get("kind"),
                         "data": event.get("data")}
                    )
                )
                if event.get("canonical_bytes_sha256") != expected_payload:
                    errors.append("payload mismatch at %d" % index)
                if event.get("hash") != event_hash(prev, event):
                    errors.append("hash mismatch at %d" % index)
                prev = event.get("hash", "")
            if ledger.get("head") != prev:
                errors.append("ledger head does not match the final event hash")
            if events and events[-1].get("kind") != "ledger_closed":
                errors.append("ledger is incomplete: missing closing event")
                if status == "valid":
                    status = "incomplete"
            if errors and status == "valid":
                status = "invalid"
            if errors and first_invalid is None:
                first_invalid = errors[0]
    except (SchemaError, KeyError, TypeError, ValueError) as exc:
        errors.append("malformed ledger: %s" % exc)
        status = "invalid"
        first_invalid = first_invalid or errors[0]
    return jsonutil.envelope(
        "verify_result",
        {
            "status": status,
            "valid": status == "valid",
            "checked_entries": checked,
            "first_invalid_entry": first_invalid,
            "errors": errors,
            "head": ledger.get("head") if isinstance(ledger, dict) else None,
        },
    )


def write_ledger(path: str, ledger: dict) -> str:
    if jsonutil.check_envelope(ledger) != "evidence_ledger":
        raise SchemaError("not an evidence_ledger")
    return jsonutil.write_document(path, ledger)


def verdict_from_ledger(ledger: dict) -> dict:
    """Extract the final verdict event's verdict_report from a ledger."""
    for event in reversed(ledger.get("events", [])):
        if event.get("kind") == "verdict" and "verdict" in (event.get("data") or {}):
            return event["data"]["verdict"]
    raise VerifyInvalid("ledger contains no verdict event")
