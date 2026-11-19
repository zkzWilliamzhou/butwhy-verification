"""Compare two capsules and propose one-factor, individually addressable changes.

`note` entries describe observable differences for which no replayable factor
family exists. They are reported as `no_effect`; they never become a cause claim.
"""
from __future__ import annotations

from . import jsonutil, secrets
from .errors import SchemaError

REPLAYABLE = frozenset(
    {"env_var", "locale", "timezone", "line_endings", "symlink_target",
     "filename_case", "file_mode", "path_shadow"}
)


def _factor(family, before, after, action, path=None, name=None, denied=False,
            reason="") -> dict:
    return {
        "family": family,
        "replayable": (family in REPLAYABLE) and not denied,
        "path": path,
        "name": name,
        "before": before,
        "after": after,
        "action": action,
        "denied": bool(denied),
        "reason": reason,
    }


def _index(items, key):
    return {item[key]: item for item in items}


def diff_capsules(a: dict, b: dict) -> dict:
    """Return a factor_diff document. Deterministic, sorted, no secret values."""
    for doc in (a, b):
        if jsonutil.check_envelope(doc) != "capsule":
            raise SchemaError("diff expects two capsule documents")
    diffs = []
    sa, sb = a["factor_snapshot"], b["factor_snapshot"]

    # 1. env_var (locale and TZ are handled by their own families)
    ea = _index(sa.get("env_var", []), "name")
    eb = _index(sb.get("env_var", []), "name")
    for name in sorted(set(ea) | set(eb)):
        va = ea.get(name, {}).get("value")
        vb = eb.get(name, {}).get("value")
        if va == vb:
            continue
        action = "unset" if vb is None else "set"
        denied = secrets.never_transplant(name) or (
            vb is not None and not secrets.safe_value(name, vb)
        )
        diffs.append(
            _factor("env_var", {"name": name, "value": va},
                    {"name": name, "value": vb}, action, name=name,
                    denied=denied,
                    reason="denied env transplant" if denied else "")
        )

    # 2. locale
    la, lb = sa.get("locale", {}), sb.get("locale", {})
    if la != lb:
        bad = any(
            isinstance(v, str) and v and v not in secrets.SAFE_LOCALES
            for v in lb.values()
        )
        diffs.append(_factor("locale", dict(la), dict(lb), "change",
                             denied=bad, reason="unsafe locale value" if bad else ""))

    # 3. timezone
    ta, tb = sa.get("timezone", {}), sb.get("timezone", {})
    if ta != tb:
        tz = tb.get("tz", "")
        bad = bool(tz) and (not secrets.SAFE_TZ_RE.match(tz) or ".." in tz)
        diffs.append(_factor("timezone", dict(ta), dict(tb), "change",
                             denied=bad, reason="unsafe TZ value" if bad else ""))

    # 4. line endings
    xa = _index(sa.get("line_endings", []), "path")
    xb = _index(sb.get("line_endings", []), "path")
    for path in sorted(set(xa) | set(xb)):
        ka = xa.get(path, {}).get("kind")
        kb = xb.get(path, {}).get("kind")
        if ka != kb:
            diffs.append(_factor("line_endings", {"kind": ka}, {"kind": kb},
                                 "flip_line_endings", path=path))

    # 5. symlink targets
    ya = _index(sa.get("symlink_target", []), "path")
    yb = _index(sb.get("symlink_target", []), "path")
    for path in sorted(set(ya) | set(yb)):
        ta_ = ya.get(path, {}).get("target")
        tb_ = yb.get(path, {}).get("target")
        if ta_ != tb_:
            out = bool(tb_ and (tb_.startswith("/") or ".." in tb_.split("/")))
            diffs.append(_factor("symlink_target", {"target": ta_},
                                 {"target": tb_}, "retarget", path=path,
                                 denied=out, reason="out-of-tree symlink target" if out else ""))

    # 6. filename case
    ca = _index(sa.get("filename_case", []), "path")
    cb = _index(sb.get("filename_case", []), "path")
    for path in sorted(set(ca) | set(cb)):
        ka = ca.get(path, {}).get("lower")
        kb = cb.get(path, {}).get("lower")
        if ka != kb:
            diffs.append(_factor("filename_case", {"lower": ka}, {"lower": kb},
                                 "rename", path=path))

    # 7. file mode
    ma = _index(sa.get("file_mode", []), "path")
    mb = _index(sb.get("file_mode", []), "path")
    for path in sorted(set(ma) | set(mb)):
        va = ma.get(path, {}).get("mode")
        vb = mb.get(path, {}).get("mode")
        if va != vb:
            bad = bool(vb is not None and (vb & 0o222 and (vb & 0o002)))
            diffs.append(_factor("file_mode", {"mode": va}, {"mode": vb},
                                 "chmod", path=path, denied=bad,
                                 reason="world-writable mode" if bad else ""))

    # 8. path shadow
    pa, pb = sa.get("path_shadow", {}), sb.get("path_shadow", {})
    if pa != pb:
        declared = dict(pb)
        declared["shim_name"] = declared.get("shim_name") or "butwhy-shim"
        declared["shim_exit"] = declared.get("shim_exit", 0)
        declared["prepend"] = True
        diffs.append(_factor("path_shadow", dict(pa), declared, "prepend_shim"))

    # 9. non-replayable families
    for family in ("interpreter_version", "platform"):
        va = a.get("non_replayable", {}).get(family)
        vb = b.get("non_replayable", {}).get(family)
        if va != vb:
            diffs.append(_factor(family, {"value": va}, {"value": vb}, "change",
                                 reason="cannot change %s offline" % family))

    # 10. notes for differences with no replayable family
    fa = {f["path"]: f for f in a.get("files", []) if f.get("sha256")}
    fb = {f["path"]: f for f in b.get("files", []) if f.get("sha256")}
    for path in sorted(set(fa) | set(fb)):
        da = fa.get(path, {}).get("sha256")
        db = fb.get(path, {}).get("sha256")
        if da != db:
            diffs.append(_factor("note", {"sha256": da}, {"sha256": db}, "no_op",
                                 path=path, reason="content differs; no declared replayable factor"))

    def sort_key(d):
        return (d["family"], d.get("path") or "", d.get("name") or "", d["action"])

    diffs.sort(key=sort_key)
    summary = {
        "replayable": sum(1 for d in diffs if d["replayable"]),
        "non_replayable": sum(1 for d in diffs if d["family"] in ("interpreter_version", "platform")),
        "denied": sum(1 for d in diffs if d["denied"]),
        "notes": sum(1 for d in diffs if d["family"] == "note"),
    }
    payload = {
        "diff_id": jsonutil.deterministic_id(
            {"a": a["capsule_id"], "b": b["capsule_id"], "diffs": diffs}
        ),
        "capsule_a": a["capsule_id"], "capsule_b": b["capsule_id"],
        "diffs": diffs, "summary": summary,
    }
    return jsonutil.envelope("factor_diff", payload)
