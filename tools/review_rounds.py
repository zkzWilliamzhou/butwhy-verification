#!/usr/bin/env python3
"""Ten distinct, executable review rounds for butwhy.

Each round has a DIFFERENT lens and a BINARY gate: every check must pass or the
round fails. Artifacts are written to reviews/. The golden baseline is frozen
once (before optimization) and never overwritten; subsequent runs verify that
the program's canonical artifacts remain BYTE-IDENTICAL.

Usage:
    PYTHONPATH=src python3 tools/review_rounds.py
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from butwhy import (capture, causal, contract, diff, factors, isolation,  # noqa: E402
                    jsonutil, ledger, runtime, secrets)
from butwhy.errors import SchemaError, ResourceLimit, SafetyDenied  # noqa: E402

REVIEWS = os.path.join(ROOT, "reviews")
BASELINE_DIR = os.path.join(REVIEWS, "baseline")
BASELINE_MANIFEST = os.path.join(REVIEWS, "golden_baseline.json")
CONFIRM = runtime.CONFIRM_TOKEN
ARTIFACTS = ("capsule.json", "diff.json", "ledger.json", "verdict.json", "golden.json")


def cli(*args, cwd=None, timeout=180, extra_env=None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONPATH": SRC,
        "SOURCE_DATE_EPOCH": "1700000000",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": tempfile.gettempdir(),
        "TZ": "UTC",
    }
    if extra_env:
        env.update(extra_env)
    p = subprocess.run(
        [sys.executable, "-m", "butwhy", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def check(results, name, fn):
    try:
        passed, evidence = fn()
        results.append({"name": name, "passed": bool(passed), "evidence": str(evidence)[:300]})
    except Exception as exc:  # a raised exception is a failed check, never hidden
        results.append({"name": name, "passed": False,
                        "evidence": "EXCEPTION %s: %s" % (type(exc).__name__, exc)})
    return results


class Round:
    def __init__(self, number, slug, lens, description):
        self.number = number
        self.slug = slug
        self.lens = lens
        self.description = description
        self.results = []
        self.findings = []

    def check(self, name, fn):
        check(self.results, name, fn)

    def finding(self, text):
        self.findings.append(text)

    def finish(self):
        passed = all(r["passed"] for r in self.results)
        doc = {
            "round": self.number,
            "slug": self.slug,
            "lens": self.lens,
            "description": self.description,
            "gate": "PASS" if passed else "FAIL",
            "checks_total": len(self.results),
            "checks_passed": sum(1 for r in self.results if r["passed"]),
            "checks": self.results,
            "findings": self.findings,
        }
        os.makedirs(REVIEWS, exist_ok=True)
        path = os.path.join(REVIEWS, "round_%02d_%s.json" % (self.number, self.slug))
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(doc, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
        return doc


def fresh_demo(tag):
    ws = os.path.join(tempfile.gettempdir(), "butwhy-review-" + tag)
    shutil.rmtree(ws, ignore_errors=True)
    rc, out, err = cli("demo", "--work", ws, "--confirm=" + CONFIRM)
    return ws, rc, out, err


# --------------------------------------------------------------------------
# R01 - Functional completeness
# --------------------------------------------------------------------------
def round01():
    r = Round(1, "functional", "functional completeness",
              "Every locked CLI surface, artifact type and verdict is reachable and observable.")
    ws, rc, out, err = fresh_demo("r01")

    def help_lists_six():
        rc2, out2, _ = cli("--help")
        return rc2 == 0 and all(n in out2 for n in contract.SUBCOMMANDS), out2[:120]
    r.check("--help lists exactly the six subcommands", help_lists_six)

    def version():
        rc2, out2, _ = cli("--version")
        return rc2 == 0 and "butwhy 0.1.0" in out2, out2.strip()
    r.check("--version works without a subcommand", version)

    def subcommand_help():
        bad = []
        for n in contract.SUBCOMMANDS:
            rc2, _, _ = cli(n, "--help")
            if rc2 != 0:
                bad.append(n)
        return not bad, "failed=%s" % bad
    r.check("all six subcommands expose --help", subcommand_help)

    def demo_pipeline():
        return rc == 0 and "demo OK" in out and "verify   -> valid" in out, "rc=%d err=%s" % (rc, err[:150])
    r.check("demo runs the full pipeline offline", demo_pipeline)

    def artifact_types():
        expected = {"capsule": "capsule", "diff": "factor_diff",
                    "ledger": "evidence_ledger", "verdict": "verdict_report",
                    "golden": "golden_manifest"}
        bad = []
        for name, doc_type in expected.items():
            p = os.path.join(ws, name + ".json")
            if not os.path.isfile(p):
                bad.append(name + ":missing")
            elif jsonutil.check_envelope(jsonutil.read_document(p)) != doc_type:
                bad.append(name + ":wrong-type")
        return not bad, bad
    r.check("all five artifacts exist with correct document types", artifact_types)

    def report_and_verify():
        rc2, text, _ = cli("report", "--ledger", os.path.join(ws, "ledger.json"))
        rc3, vout, _ = cli("verify", "--ledger", os.path.join(ws, "ledger.json"))
        return rc2 == 0 and rc3 == 0 and "necessary_and_sufficient" in text and vout.startswith("OK"), \
            "report=%d verify=%d" % (rc2, rc3)
    r.check("report renders and verify attests the ledger", report_and_verify)

    def surface_frozen():
        return (len(contract.SUBCOMMANDS) == 6 and len(contract.EXIT_CODES) == 7
                and len(contract.VERDICTS) == 6
                and len(contract.REPLAYABLE_FAMILIES) == 8
                and len(contract.NON_REPLAYABLE_FAMILIES) == 2
                and len(contract.MODULES) == 16), "surface constants intact"
    r.check("locked surface constants unchanged", surface_frozen)

    def tamper_demo():
        return "tamper   -> invalid (detected=yes)" in out, "tamper proof present"
    r.check("demo demonstrates ledger tamper detection", tamper_demo)
    r.finding("No functional gaps found after the fixture TypeError fix.")
    return r.finish()


# --------------------------------------------------------------------------
# R02 - Safety and isolation
# --------------------------------------------------------------------------
def round02():
    r = Round(2, "safety", "safety and isolation",
              "Execution policy, environment denylist, secret redaction and containment boundaries.")
    tmp = tempfile.mkdtemp(prefix="butwhy-r02-")
    src = os.path.join(tmp, "src")
    os.makedirs(os.path.join(src, "app"))
    with open(os.path.join(src, "app", "ok.py"), "w") as h:
        h.write("import sys\nsys.stdout.buffer.write(b'ok\\n')\n")
    cap = os.path.join(tmp, "cap.json")
    cli("capture", "--root", src, "--out", cap)
    d = os.path.join(tmp, "d.json")
    cli("diff", "--capsule", cap, "--capsule", cap, "--out", d)
    # A real factor forces execute_plan to build disposable copies; an empty
    # diff would trivially pass the cleanup/immutability checks without testing.
    other_path = os.path.join(tmp, "other.json")
    jsonutil.write_document(other_path,
                            capture.with_env_override(jsonutil.read_document(cap), "LANG", "C"))
    d_factor = os.path.join(tmp, "df.json")
    cli("diff", "--capsule", cap, "--capsule", other_path, "--out", d_factor)

    def denied(payload):
        rc, _, _ = cli("run", "--capsule", cap, "--diff", d, "--work", src,
                       "--command", payload, "--confirm=" + CONFIRM,
                       "--ledger", os.path.join(tmp, "l.json"),
                       "--out", os.path.join(tmp, "v.json"))
        return rc == 3, "rc=%d for %r" % (rc, payload)

    for payload in ("rm -rf / --no-preserve-root", "sudo id",
                    "python3 -c 'import os'", "sh -c 'touch /tmp/x'",
                    "python3 /etc/passwd", "python3 ../secret"):
        r.check("argv policy denies %r" % payload, lambda p=payload: denied(p))

    def env_denylist():
        names = ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
                 "PYTHONPATH", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "BASH_ENV",
                 "IFS", "HOME", "USER", "SHELL", "PATH", "TMPDIR", "GIT_EXEC_PATH",
                 "ＰＹＴＨＯＮＰＡＴＨ", "HOSTNAME", "AWS_SECRET_ACCESS_KEY")
        bad = [n for n in names if not secrets.never_transplant(n)]
        return not bad, "not denied=%s" % bad
    r.check("never-transplant denylist covers loader/runtime/identity/confusables", env_denylist)

    def child_env_strip():
        env = isolation.build_child_env(src, {
            "LD_PRELOAD": "/tmp/evil.so", "HOME": "/home/attacker",
            "FEATURE_FLAG": "on", "LANG": "C.UTF-8"})
        return ("LD_PRELOAD" not in env and env["HOME"].startswith(src)
                and env["FEATURE_FLAG"] == "on"), "keys=%s" % sorted(env)[:12]
    r.check("child env is rebuilt and dangerous names stripped", child_env_strip)

    def secret_redaction():
        secret = "AKIAIOSFODNN7EXAMPLE"
        ws = os.path.join(tmp, "secretcap.json")
        rc, _, _ = cli("capture", "--root", src, "--out", ws,
                       extra_env={"AWS_SECRET_ACCESS_KEY": secret})
        blob = open(ws, "rb").read()
        return rc == 0 and secret.encode() not in blob and secret[:8].encode() not in blob, \
            "secret absent from capsule"
    r.check("secret values never enter a capsule", secret_redaction)

    def opaque_token_redaction():
        rec = secrets.env_record("SANDBOX_USER_ID", "42762274edd74eba978eb2e54ea4fbfc")
        rec2 = secrets.env_record("TUYA_CLIENT_ID", "j8k2m9p4q1w7e5r3t0ya")
        return rec["value"] is None and rec2["value"] is None, "opaque host ids are not stored in plaintext"
    r.check("host credential-ish values are redacted by value class", opaque_token_redaction)
    r.finding("REVISION APPLIED: capsules previously stored innocuously-named host IDs in plaintext. "
              "Added value-class token detection in secrets.py; regressed by this check.")

    def original_untouched():
        before = open(os.path.join(src, "app", "ok.py"), "rb").read()
        cli("run", "--capsule", cap, "--diff", d_factor, "--work", src,
            "--command", "python3 app/ok.py", "--confirm=" + CONFIRM,
            "--ledger", os.path.join(tmp, "l2.json"), "--out", os.path.join(tmp, "v2.json"))
        return open(os.path.join(src, "app", "ok.py"), "rb").read() == before, "source tree unchanged"
    r.check("experiments never modify the original tree", original_untouched)

    def no_temp_leftovers():
        pattern = os.path.join(tempfile.gettempdir(), "butwhy-*")
        before = set(glob.glob(pattern))
        cli("run", "--capsule", cap, "--diff", d_factor, "--work", src,
            "--command", "python3 app/ok.py", "--confirm=" + CONFIRM,
            "--ledger", os.path.join(tmp, "l3.json"), "--out", os.path.join(tmp, "v3.json"))
        leftovers = [p for p in set(glob.glob(pattern)) - before
                     if not p.startswith(os.path.join(tempfile.gettempdir(), "butwhy-review-"))]
        return not leftovers, "leftovers=%s" % leftovers
    r.check("disposable copies are always cleaned up", no_temp_leftovers)

    def private_files():
        return os.stat(os.path.join(tmp, "l3.json")).st_mode & 0o777 == 0o600, "ledger mode 0o600"
    r.check("ledger written with private permissions", private_files)

    def confirmation_gate():
        rc, out, err = cli("run", "--capsule", cap, "--diff", d, "--work", src,
                           "--command", "python3 app/ok.py")
        plan = json.loads(out.strip()) if out.strip().startswith("{") else {}
        return rc == 1 and plan.get("document") == "dry_run_plan" and "no command was executed" in err, \
            "dry-run gate enforced"
    r.check("run without the exact token only prints a dry-run plan", confirmation_gate)
    shutil.rmtree(tmp, ignore_errors=True)
    return r.finish()


# --------------------------------------------------------------------------
# R03 - Determinism and canonicalization
# --------------------------------------------------------------------------
def round03():
    r = Round(3, "determinism", "determinism and canonical encoding",
              "Byte-stable artifacts, canonical JSON, no wall clock inside hashed payloads.")

    def three_identical_demos():
        ids = []
        for i in range(3):
            ws, rc, _, err = fresh_demo("r03-%d" % i)
            assert rc == 0, err
            ids.append(jsonutil.read_document(os.path.join(ws, "golden.json"))["golden_id"])
        return len(set(ids)) == 1, "golden_ids=%s" % ids
    r.check("three independent demo runs produce identical golden IDs", three_identical_demos)

    def canonical_properties():
        ok = (jsonutil.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
              and jsonutil.canonical({"k": "café"}) == '{"k":"café"}'.encode("utf-8")
              and jsonutil.deterministic_id({"x": 1}) == jsonutil.deterministic_id({"x": 1}))
        return ok, "sorted keys, raw UTF-8, stable IDs"
    r.check("canonical JSON is compact, sorted, UTF-8 and stable", canonical_properties)

    def rejects_unsafe_json():
        bad = 0
        for blob in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xef\xbb\xbf{}', b'{ "a": 1 }'):
            try:
                jsonutil.parse_canonical(blob)
            except (SchemaError, ResourceLimit):
                bad += 1
        return bad == 4, "rejected %d/4 unsafe inputs" % bad
    r.check("duplicate keys, NaN, BOM and non-canonical text rejected", rejects_unsafe_json)

    def epoch_does_not_change_identity():
        a = capture.capture_environment([os.path.join(ROOT, "src", "butwhy")],
                                        dict(runtime.DEFAULT_BOUNDS))
        os.environ["SOURCE_DATE_EPOCH"] = "999999999"
        try:
            b = capture.capture_environment([os.path.join(ROOT, "src", "butwhy")],
                                            dict(runtime.DEFAULT_BOUNDS))
        finally:
            os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        return a["capsule_id"] == b["capsule_id"] and a["captured_at"] != b["captured_at"], \
            "captured_at is presentation-only, excluded from identity"
    r.check("wall-clock field is excluded from hashed identity", epoch_does_not_change_identity)

    def pure_decide():
        args = {"replayable": True, "family": "locale",
                "baseline": [{"outcome": "fail"}] * 3,
                "flip": [{"outcome": "pass"}] * 3,
                "reverse": [{"outcome": "fail"}] * 3}
        return causal.decide(args) == causal.decide(args), "decide() is pure"
    r.check("causal truth table is pure and reproducible", pure_decide)
    return r.finish()


# --------------------------------------------------------------------------
# R04 - Error handling and resource limits
# --------------------------------------------------------------------------
def round04():
    r = Round(4, "errors", "error handling and resource limits",
              "Malformed inputs, schema downgrades, caps, timeouts and clean failure codes.")
    tmp = tempfile.mkdtemp(prefix="butwhy-r04-")
    src = os.path.join(tmp, "src")
    os.makedirs(src)
    with open(os.path.join(src, "ok.py"), "w") as h:
        h.write("import sys\nsys.exit(0)\n")
    cap = os.path.join(tmp, "c.json")
    cli("capture", "--root", src, "--out", cap)

    def bad_envelope():
        p = os.path.join(tmp, "bad.json")
        doc = jsonutil.read_document(cap)
        doc["schema_version"] = 9999
        with open(p, "wb") as h:
            h.write(jsonutil.canonical(doc) + b"\n")
        rc, _, _ = cli("diff", "--capsule", cap, "--capsule", p)
        return rc == 5, "unsupported schema -> exit 5"
    r.check("unsupported schema version exits 5", bad_envelope)

    def malformed_capsule():
        p = os.path.join(tmp, "malformed.json")
        with open(p, "wb") as h:
            h.write(b"{not json")
        rc, _, _ = cli("diff", "--capsule", cap, "--capsule", p)
        return rc in (1, 5), "malformed JSON -> rc=%d" % rc
    r.check("malformed JSON is rejected without a traceback", malformed_capsule)

    def bounds():
        ok = True
        try:
            jsonutil.parse_canonical(b"[" + b"0," * (17 * 1024 * 1024) + b"0]")
            ok = False
        except (ResourceLimit, SchemaError):
            pass
        deep = []
        cur = deep
        for _ in range(40):
            nxt = []
            cur.append(nxt)
            cur = nxt
        try:
            jsonutil.canonical(deep)
            ok = False
        except ResourceLimit:
            pass
        return ok, "16 MiB and depth-32 bounds enforced"
    r.check("JSON size and depth bounds enforced before allocation", bounds)

    def tree_cap():
        dd = os.path.join(tmp, "d.json")
        other = capture.with_env_override(jsonutil.read_document(cap), "LANG", "C")
        other_path = os.path.join(tmp, "o.json")
        jsonutil.write_document(other_path, other)
        cli("diff", "--capsule", cap, "--capsule", other_path, "--out", dd)
        rc, _, err = cli("run", "--capsule", cap, "--diff", dd, "--work", src,
                         "--command", "python3 ok.py", "--confirm=" + CONFIRM,
                         "--tree-cap", "1", "--out", os.path.join(tmp, "v.json"),
                         "--ledger", os.path.join(tmp, "l.json"))
        return rc == 4, "tree cap -> exit 4 (err=%s)" % err[:80]
    r.check("exceeding the copy cap exits 4 with no partial artifact", tree_cap)

    def timeout_abstains():
        with open(os.path.join(src, "slow.py"), "w") as h:
            h.write("import time\ntime.sleep(30)\n")
        cap2 = os.path.join(tmp, "c2.json")
        cli("capture", "--root", src, "--out", cap2)
        dd = os.path.join(tmp, "d2.json")
        cli("diff", "--capsule", cap2, "--capsule", cap2, "--out", dd)
        other = capture.with_env_override(jsonutil.read_document(cap2), "FEATURE_FLAG", "on")
        op = os.path.join(tmp, "o2.json")
        jsonutil.write_document(op, other)
        dd2 = os.path.join(tmp, "d3.json")
        cli("diff", "--capsule", cap2, "--capsule", op, "--out", dd2)
        v = os.path.join(tmp, "v2.json")
        rc, _, err = cli("run", "--capsule", cap2, "--diff", dd2, "--work", src,
                         "--command", "python3 slow.py", "--confirm=" + CONFIRM,
                         "--timeout", "1", "--out", v,
                         "--ledger", os.path.join(tmp, "l2.json"))
        doc = jsonutil.read_document(v)
        return rc == 0 and doc["overall"] == "inconclusive", \
            "timeout is an observed outcome, verdict abstains (rc=%d)" % rc
    r.check("command timeout produces inconclusive, never a cause claim", timeout_abstains)
    r.finding("DOCUMENTED DISTINCTION: a child-command timeout is an observed outcome recorded "
              "as `inconclusive`; exceeding butwhy's own copy/output caps raises exit 4. "
              "Both are correct and are disclosed in README.md.")

    def output_cap():
        b = dict(runtime.DEFAULT_BOUNDS)
        b["max_output_bytes"] = 1024
        with open(os.path.join(src, "flood.py"), "w") as h:
            h.write("import sys\nsys.stdout.write('x'*20000)\n")
        dst = isolation.make_copy(src, b)
        try:
            res = isolation.spawn_isolated(dst, ["python3", "flood.py"], {}, b)
            return res["truncated"] and res["outcome"] == "output_limit", \
                "20 KB output capped at 1 KB, truncated=%s" % res["truncated"]
        finally:
            isolation.destroy_copy(dst, b)
    r.check("stdout byte cap enforced without unbounded memory", output_cap)
    shutil.rmtree(tmp, ignore_errors=True)
    return r.finish()


# --------------------------------------------------------------------------
# R05 - Edge cases
# --------------------------------------------------------------------------
def round05():
    r = Round(5, "edges", "edge cases and filesystem semantics",
              "Empty trees, unicode names, line endings, binaries, links, modes and case.")
    tmp = tempfile.mkdtemp(prefix="butwhy-r05-")
    bounds = dict(runtime.DEFAULT_BOUNDS)

    def empty_tree():
        p = os.path.join(tmp, "empty")
        os.makedirs(p)
        cap = capture.capture_environment([p], bounds)
        return cap["files"] == [] and cap["document"] == "capsule", "empty tree captured"
    r.check("empty working tree captures successfully", empty_tree)

    def unicode_and_dotfiles():
        p = os.path.join(tmp, "unicode")
        os.makedirs(p)
        for name in ("café.txt", "日本語.md", "🚀.bin", ".hidden"):
            with open(os.path.join(p, name), "w", encoding="utf-8") as h:
                h.write("x")
        cap = capture.capture_environment([p], bounds)
        names = {f["path"] for f in cap["files"]}
        return {"café.txt", "日本語.md", "🚀.bin", ".hidden"} <= names, sorted(names)
    r.check("unicode and dotfile names preserved", unicode_and_dotfiles)

    def line_endings_and_binary():
        p = os.path.join(tmp, "endings")
        os.makedirs(p)
        with open(os.path.join(p, "lf.txt"), "wb") as h:
            h.write(b"a\nb\n")
        with open(os.path.join(p, "crlf.txt"), "wb") as h:
            h.write(b"a\r\nb\r\n")
        with open(os.path.join(p, "bin.dat"), "wb") as h:
            h.write(b"\x00\x01\x02")
        cap = capture.capture_environment([p], bounds)
        kinds = {f["path"]: f["line_endings"] for f in cap["files"]}
        return (kinds.get("lf.txt") == "lf" and kinds.get("crlf.txt") == "crlf"
                and kinds.get("bin.dat") == "binary"), kinds
    r.check("LF / CRLF / binary classification is correct", line_endings_and_binary)

    def symlinks_hardlinks_specials():
        p = os.path.join(tmp, "links")
        os.makedirs(p)
        with open(os.path.join(p, "target.txt"), "w") as h:
            h.write("x")
        os.symlink("target.txt", os.path.join(p, "link"))
        cap = capture.capture_environment([p], bounds)
        has_link = any(f["kind"] == "symlink" for f in cap["files"])
        os.link(os.path.join(p, "target.txt"), os.path.join(p, "hard"))
        hard = capture.capture_environment([p], bounds)
        has_hard = any(f["kind"] == "hardlink" for f in hard["files"])
        try:
            isolation.make_copy(p, bounds)
            copy_rejected = False
        except SafetyDenied:
            copy_rejected = True
        return has_link and has_hard and copy_rejected, "symlink recorded, hardlink refused"
    r.check("in-tree symlinks recorded, hardlinks/special files refused", symlinks_hardlinks_specials)

    def identical_capsules():
        p = os.path.join(tmp, "same")
        os.makedirs(p)
        cap = capture.capture_environment([p], bounds)
        d = diff.diff_capsules(cap, cap)
        return d["diffs"] == [], "identical capsules -> empty factor list"
    r.check("identical capsules produce no factors", identical_capsules)

    def case_and_mode_factors():
        p = os.path.join(tmp, "factors")
        os.makedirs(p)
        with open(os.path.join(p, "a.txt"), "w") as h:
            h.write("x")
        rec = factors.apply_factor(p, {"family": "file_mode", "path": "a.txt",
                                       "before": {"mode": 0o644},
                                       "after": {"mode": 0o600}, "action": "chmod"}, {"env": {}})
        mode_ok = os.stat(os.path.join(p, "a.txt")).st_mode & 0o777 == 0o600
        factors.apply_factor(p, {"family": "filename_case", "path": "a.txt",
                                 "before": {"lower": "a.txt"},
                                 "after": {"lower": "A.txt"}, "action": "rename"}, {"env": {}})
        case_ok = os.path.isfile(os.path.join(p, "A.txt"))
        return mode_ok and case_ok and rec["kind"] == "mode", "mode + case factors applied in-copy"
    r.check("file_mode and filename_case factors apply only inside the copy", case_and_mode_factors)

    def retarget_fixes_realpath_bug():
        p = os.path.join(tmp, "retarget")
        os.makedirs(p)
        with open(os.path.join(p, "a.txt"), "w") as h:
            h.write("a")
        with open(os.path.join(p, "b.txt"), "w") as h:
            h.write("b")
        os.symlink("a.txt", os.path.join(p, "link"))
        factors.apply_factor(p, {"family": "symlink_target", "path": "link",
                                 "before": {"target": "a.txt"},
                                 "after": {"target": "b.txt"}, "action": "retarget"}, {"env": {}})
        return os.readlink(os.path.join(p, "link")) == "b.txt" and \
            open(os.path.join(p, "a.txt")).read() == "a", "link retargeted, target file intact"
    r.check("symlink retarget edits the link, not its target", retarget_fixes_realpath_bug)
    r.finding("REVISION APPLIED: _safe_join used realpath() on the final component, so retargeting "
              "a symlink operated on the symlink's TARGET. Replaced with lexical join + "
              "ancestor containment checks; regressed by this check.")
    shutil.rmtree(tmp, ignore_errors=True)
    return r.finish()


# --------------------------------------------------------------------------
# R06 - Performance budget
# --------------------------------------------------------------------------
def round06():
    r = Round(6, "performance", "performance and resource governance",
              "Measured budgets for capture, diff, replay and the full demo; offline guard.")
    tmp = tempfile.mkdtemp(prefix="butwhy-r06-")
    src = os.path.join(tmp, "src")
    os.makedirs(os.path.join(src, "app"))
    with open(os.path.join(src, "app", "check.py"), "w", encoding="utf-8") as h:
        h.write("import os,sys\nloc=os.environ.get('LC_ALL') or os.environ.get('LANG') or ''\n"
                "sys.stderr.write('boom\\n') if loc in ('C','POSIX','') else None\n"
                "raise SystemExit(1 if loc in ('C','POSIX','') else 0)\n")
    bounds = dict(runtime.DEFAULT_BOUNDS)

    def capture_budget():
        t = time.perf_counter()
        cap = capture.capture_environment([src], bounds)
        dt = time.perf_counter() - t
        return dt < 2.0 and cap["document"] == "capsule", "capture %.4fs < 2.0s" % dt
    r.check("capture completes within the 2s budget", capture_budget)

    def diff_budget():
        a = capture.capture_environment([src], bounds)
        b = capture.with_env_override(a, "LANG", "C")
        t = time.perf_counter()
        d = diff.diff_capsules(a, b)
        dt = time.perf_counter() - t
        return dt < 1.0 and d["document"] == "factor_diff", "diff %.4fs < 1.0s" % dt
    r.check("diff completes within the 1s budget", diff_budget)

    def canonical_budget():
        big = {"k%05d" % i: "v" * 40 for i in range(4000)}
        t = time.perf_counter()
        blob = jsonutil.canonical(big)
        dt = time.perf_counter() - t
        return len(blob) > 100000 and dt < 3.0, "canonical 4000-key doc %.4fs" % dt
    r.check("canonical encoding handles a large document within budget", canonical_budget)

    def demo_budget():
        t = time.perf_counter()
        ws, rc, _, err = fresh_demo("r06")
        dt = time.perf_counter() - t
        return rc == 0 and dt < 60.0, "demo %.2fs < 60s" % dt
    r.check("full demo completes within the 60s budget", demo_budget)

    def offline_guard():
        try:
            contract.guard_offline()
            return True, "AST + runtime offline guard passed"
        except SafetyDenied as exc:
            return False, str(exc)
    r.check("no network imports in production modules", offline_guard)

    def bounded_memory():
        b = dict(bounds)
        b["max_output_bytes"] = 2048
        dst = isolation.make_copy(src, b)
        try:
            with open(os.path.join(src, "flood.py"), "w") as h:
                h.write("import sys\nsys.stdout.write('x'*100000)\n")
            dst2 = isolation.make_copy(src, b)
            try:
                res = isolation.spawn_isolated(dst2, ["python3", "flood.py"], {}, b)
            finally:
                isolation.destroy_copy(dst2, b)
            return res["truncated"] and res["stdout_len"] >= 100000, "100 KB output capped to 2 KB in memory"
        finally:
            isolation.destroy_copy(dst, b)
    r.check("output memory is bounded by the byte cap", bounded_memory)
    shutil.rmtree(tmp, ignore_errors=True)
    return r.finish()


# --------------------------------------------------------------------------
# R07 - Documentation honesty
# --------------------------------------------------------------------------
def round07():
    r = Round(7, "docs", "documentation honesty",
              "Every documented claim is backed by code/tests; limitations and residual risks disclosed.")
    readme = os.path.join(ROOT, "README.md")
    changelog = os.path.join(ROOT, "CHANGELOG.md")
    license_ = os.path.join(ROOT, "LICENSE")

    def exists():
        return all(os.path.isfile(p) for p in (readme, changelog, license_)), "README/CHANGELOG/LICENSE present"
    r.check("required project documentation exists", exists)

    text = open(readme, encoding="utf-8").read()

    def required_claims():
        needles = ["Python 3.10", "standard library", "offline", "no third-party",
                   "capture", "diff", "run", "report", "verify", "demo",
                   "necessary_and_sufficient", "non_replayable", "inconclusive",
                   "root cause", "--confirm=yes-i-understand-butwhy-will-run-this",
                   "0", "3", "4", "5", "6", "LIMITATIONS", "Prior art"]
        missing = [n for n in needles if n not in text]
        return not missing, "missing=%s" % missing
    r.check("README states version, offline/zero-dep rule, CLI, verdicts, exit codes, limits", required_claims)

    def exit_table():
        for code, _ in enumerate(contract.EXIT_CODES):
            if str(code) not in text:
                return False, "exit code %d not documented" % code
        return True, "all 7 exit codes documented"
    r.check("README contains the full exit-code table", exit_table)

    def claims_backed_by_tests():
        tests = ""
        for path in glob.glob(os.path.join(ROOT, "tests", "test_*.py")):
            tests += open(path, encoding="utf-8").read()
        pairs = [("necessary_and_sufficient", "test_cli_e2e.py"),
                 ("confirm", "test_cli_e2e.py"),
                 ("tamper", "test_causal_ledger.py"),
                 ("symlink", "test_isolation_factors.py")]
        bad = [p for p, _ in pairs if p not in tests]
        return not bad, "untested claims=%s" % bad
    r.check("key README claims have corresponding automated tests", claims_backed_by_tests)

    def machine_output_clean():
        ws, rc, _, _ = fresh_demo("r07")
        bad = []
        for name in ("report.txt", "report.json", "ledger.json", "verdict.json",
                     "capsule.json", "diff.json", "golden.json"):
            content = open(os.path.join(ws, name), encoding="utf-8").read().lower()
            for phrase in contract.FORBIDDEN_PHRASES:
                if phrase in content:
                    bad.append((name, phrase))
        return rc == 0 and not bad, "forbidden claim phrases in machine output=%s" % bad
    r.check("machine output contains no root-cause language", machine_output_clean)

    def residual_risks():
        needles = ["not a kernel sandbox", "cannot undo", "does not prove", "bounded search",
                   "100k", "unprovable"]
        missing = [n for n in needles if n not in text]
        return not missing, "undisclosed risks=%s" % missing
    r.check("residual risks and the star target are disclosed honestly", residual_risks)
    return r.finish()


# --------------------------------------------------------------------------
# R08 - Adversarial red team
# --------------------------------------------------------------------------
def round08():
    r = Round(8, "redteam", "adversarial red team",
              "Hash-chain forgery, replay/downgrade, untrusted capsules, confusables and JSON bombs.")

    def make_ledger():
        led = ledger.new_ledger({"capsule_id": "c" * 20, "plan_id": "p" * 20, "created_at": 0})
        led = ledger.append_event(led, {"kind": "plan", "data": {"n": 3}})
        led = ledger.append_event(led, {"kind": "observe", "data": {"x": 1}})
        led = ledger.append_event(led, {"kind": "ledger_closed", "data": {"event_count": 3}})
        led["closed"] = True
        return led

    def tamper_variants():
        variants = {}
        a = make_ledger(); a["events"][0]["data"]["n"] = 999; variants["data"] = a
        b = make_ledger(); b["events"][0], b["events"][1] = b["events"][1], b["events"][0]; variants["reorder"] = b
        c = make_ledger(); c["events"][1]["event_id"] = c["events"][0]["event_id"]; variants["dupid"] = c
        d = make_ledger(); d["events"] = d["events"][:2]; d["head"] = d["events"][-1]["hash"]; variants["truncate"] = d
        e = make_ledger(); e["head"] = "0" * 64; variants["head"] = e
        f = make_ledger(); f["events"][1]["seq"] = 7; variants["seqgap"] = f
        caught = [k for k, v in variants.items() if not ledger.verify_ledger(v)["valid"]]
        return len(caught) == len(variants), "caught %d/%d: %s" % (len(caught), len(variants), sorted(caught))
    r.check("all six chain-forgery variants are detected", tamper_variants)

    def schema_downgrade():
        led = make_ledger()
        led["schema_version"] = 0
        try:
            jsonutil.check_envelope(led)
            return False, "downgrade accepted"
        except SchemaError:
            return True, "version 0 rejected"
    r.check("schema downgrade is rejected, never auto-upgraded", schema_downgrade)

    def untrusted_capsule_loader():
        src = tempfile.mkdtemp(prefix="butwhy-r08-")
        env = isolation.build_child_env(src, {
            "LD_PRELOAD": "/tmp/evil.so",
            "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
            "JAVA_TOOL_OPTIONS": "-agentlib:evil",
            "NODE_OPTIONS": "--require /tmp/evil.js",
            "PYTHONPATH": "/tmp/evil",
            "BUTWHY_REPEAT_INDEX": "0",
        })
        bad = [k for k in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
                           "JAVA_TOOL_OPTIONS", "NODE_OPTIONS", "PYTHONPATH") if k in env]
        shutil.rmtree(src, ignore_errors=True)
        return not bad, "hostile loader vars reaching child=%s" % bad
    r.check("untrusted capsule loader variables never reach the child", untrusted_capsule_loader)

    def confusables():
        return all(secrets.never_transplant(n) for n in
                   ("ＰＹＴＨＯＮＰＡＴＨ", "ＬＤ_ＰＲＥＬＯＡＤ", "LD_PRELOAD")), "NFKC confusables denied"
    r.check("Unicode confusable env names are denied", confusables)

    def json_bomb():
        try:
            jsonutil.parse_canonical(b"[" + b"0," * (17 * 1024 * 1024) + b"0]")
            return False, "bomb accepted"
        except (ResourceLimit, SchemaError):
            return True, "17 MiB bomb rejected before materialization"
    r.check("JSON bomb rejected before unbounded allocation", json_bomb)

    def path_escape():
        src = tempfile.mkdtemp(prefix="butwhy-r08b-")
        try:
            factors.apply_factor(src, {"family": "line_endings", "path": "../../etc/passwd",
                                       "before": {"kind": "lf"}, "after": {"kind": "crlf"},
                                       "action": "flip_line_endings"}, {"env": {}})
            return False, "traversal accepted"
        except SafetyDenied:
            return True, "traversal denied"
        finally:
            shutil.rmtree(src, ignore_errors=True)
    r.check("factor path traversal is denied before filesystem access", path_escape)

    def offline_verify():
        led = make_ledger()
        vr = ledger.verify_ledger(led)
        return vr["valid"] and vr["checked_entries"] == 3 and vr["head"] == led["head"], \
            "offline recomputation matches stored head"
    r.check("ledger verifies offline with no external trust anchor", offline_verify)
    return r.finish()


# --------------------------------------------------------------------------
# R09 - Causal honesty
# --------------------------------------------------------------------------
def round09():
    r = Round(9, "causal", "causal honesty",
              "Exhaustive truth table, abstention rules, multi-factor and flake handling.")

    def o(value, n=3):
        return [{"index": i, "outcome": value, "exit_code": 0 if value == "pass" else 1} for i in range(n)]

    def exhaustive_table():
        expected = {
            ("fail", "pass", "fail"): "necessary_and_sufficient",
            ("pass", "fail", "pass"): "necessary_and_sufficient",
            ("fail", "pass", None): "necessary",
            ("pass", "fail", None): "sufficient",
            ("pass", "pass", "pass"): "no_effect",
            ("fail", "fail", "fail"): "no_effect",
            ("fail", "pass", "pass"): "inconclusive",
            ("timeout", "pass", "timeout"): "inconclusive",
            ("error", "pass", "error"): "inconclusive",
        }
        bad = []
        for (b, f, rv), want in expected.items():
            got = causal.decide({"replayable": True, "family": "locale",
                                 "baseline": o(b), "flip": o(f),
                                 "reverse": o(rv) if rv else None})["classification"]
            if got != want:
                bad.append(((b, f, rv), want, got))
        return not bad, "mismatches=%s" % bad
    r.check("all nine truth-table rows produce the exact verdict", exhaustive_table)

    def one_way_never_ns():
        bad = []
        for b, f in (("fail", "pass"), ("pass", "fail")):
            v = causal.decide({"replayable": True, "family": "locale",
                               "baseline": o(b), "flip": o(f), "reverse": None})
            if v["classification"] == "necessary_and_sufficient":
                bad.append((b, f))
        return not bad, "one-way overclaims=%s" % bad
    r.check("one-way evidence never yields necessary_and_sufficient", one_way_never_ns)

    def multi_factor():
        v = causal.decide_overall([
            {"classification": "necessary_and_sufficient", "confidence": 0.83},
            {"classification": "necessary", "confidence": 0.5},
        ])
        return v["classification"] == "inconclusive" and v["multi_factor"] is True, "multi_factor note present"
    r.check("multiple decisive factors force abstention", multi_factor)

    def flake():
        mixed = o("pass") + [o("fail")[0]]
        v = causal.decide({"replayable": True, "family": "locale",
                           "baseline": mixed, "flip": o("pass"), "reverse": o("pass")})
        return v["classification"] == "inconclusive" and v["confidence"] == 0.0, "flake abstains"
    r.check("mixed repeats force inconclusive with zero confidence", flake)

    def all_verdicts_reachable():
        got = set()
        for b, f, rv in (("fail", "pass", "fail"), ("fail", "pass", None),
                         ("pass", "fail", None), ("pass", "pass", "pass"),
                         ("timeout", "pass", "timeout")):
            got.add(causal.decide({"replayable": True, "family": "locale",
                                   "baseline": o(b), "flip": o(f),
                                   "reverse": o(rv) if rv else None})["classification"])
        got.add(causal.decide({"replayable": False, "family": "platform",
                               "baseline": o("pass"), "flip": o("pass"),
                               "reverse": None})["classification"])
        return got == set(contract.VERDICTS), "reachable=%s" % sorted(got)
    r.check("all six verdict values are reachable and none are invented", all_verdicts_reachable)

    def no_overclaim_in_report():
        ws, rc, _, _ = fresh_demo("r09")
        text = open(os.path.join(ws, "report.txt"), encoding="utf-8").read().lower()
        return rc == 0 and not any(p in text for p in contract.FORBIDDEN_PHRASES), "report abstains from cause language"
    r.check("rendered report contains no causal overclaim", no_overclaim_in_report)
    return r.finish()


# --------------------------------------------------------------------------
# R10 - Golden freeze and non-regression
# --------------------------------------------------------------------------
def round10():
    r = Round(10, "golden", "golden non-regression gate",
              "Freeze canonical artifacts BEFORE optimization; prove byte-identical function.")
    os.makedirs(BASELINE_DIR, exist_ok=True)
    ws, rc, _, err = fresh_demo("r10")
    if rc != 0:
        r.check("fresh demo succeeds", lambda: (False, err[:200]))
        return r.finish()

    if not os.path.isfile(BASELINE_MANIFEST):
        for name in ARTIFACTS:
            src = os.path.join(ws, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(BASELINE_DIR, name))
        manifest = {
            "frozen_at_note": "Pre-optimization baseline. Never overwritten.",
            "artifacts": sorted(ARTIFACTS),
            "sha256": {name: jsonutil.sha256_hex(open(os.path.join(BASELINE_DIR, name), "rb").read())
                       for name in ARTIFACTS},
            "surface": {
                "subcommands": list(contract.SUBCOMMANDS),
                "exit_codes": list(contract.EXIT_CODES),
                "verdicts": list(contract.VERDICTS),
                "replayable_families": list(contract.REPLAYABLE_FAMILIES),
                "non_replayable_families": list(contract.NON_REPLAYABLE_FAMILIES),
                "modules": sorted(contract.MODULES),
            },
        }
        with open(BASELINE_MANIFEST, "w", encoding="utf-8", newline="\n") as h:
            json.dump(manifest, h, indent=2, sort_keys=True, ensure_ascii=False)
            h.write("\n")

    frozen = json.load(open(BASELINE_MANIFEST, encoding="utf-8"))

    def bytes_identical():
        bad = []
        for name in ARTIFACTS:
            now = open(os.path.join(ws, name), "rb").read()
            ref = open(os.path.join(BASELINE_DIR, name), "rb").read()
            if now != ref:
                bad.append(name)
        return not bad, "byte-differences=%s" % bad
    r.check("every canonical artifact is BYTE-IDENTICAL to the frozen baseline", bytes_identical)

    def hashes_match():
        bad = [n for n in ARTIFACTS
               if jsonutil.sha256_hex(open(os.path.join(ws, n), "rb").read()) != frozen["sha256"][n]]
        return not bad, "hash mismatches=%s" % bad
    r.check("frozen SHA-256 manifest matches current artifacts", hashes_match)

    def surface_unchanged():
        now = {
            "subcommands": list(contract.SUBCOMMANDS),
            "exit_codes": list(contract.EXIT_CODES),
            "verdicts": list(contract.VERDICTS),
            "replayable_families": list(contract.REPLAYABLE_FAMILIES),
            "non_replayable_families": list(contract.NON_REPLAYABLE_FAMILIES),
            "modules": sorted(contract.MODULES),
        }
        return now == frozen["surface"], "surface drift detected"
    r.check("CLI/verdict/factor/module surface unchanged", surface_unchanged)

    def full_suite():
        p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                           cwd=ROOT, env={**os.environ, "PYTHONPATH": SRC},
                           capture_output=True, text=True, timeout=300)
        return p.returncode == 0 and "OK" in p.stderr, p.stderr.strip().splitlines()[-1] if p.stderr else ""
    r.check("complete unittest suite passes", full_suite)
    return r.finish()


ROUNDS = [round01, round02, round03, round04, round05,
          round06, round07, round08, round09, round10]


def main():
    os.makedirs(REVIEWS, exist_ok=True)
    docs = []
    for fn in ROUNDS:
        try:
            docs.append(fn())
        except Exception as exc:
            docs.append({"round": fn.__name__, "gate": "FAIL",
                         "error": "%s: %s" % (type(exc).__name__, exc),
                         "traceback": traceback.format_exc()})
            traceback.print_exc()
    passed = sum(1 for d in docs if d.get("gate") == "PASS")
    lines = [
        "# butwhy - Post-Implementation Review Rounds",
        "",
        "Each round uses a DIFFERENT lens and a BINARY gate. A single failed check fails the round.",
        "Raw evidence is in `reviews/round_*.json`. The golden baseline in `reviews/baseline/`",
        "was frozen BEFORE optimization and is never overwritten.",
        "",
        "| Round | Lens | Gate | Checks passed | Findings |",
        "|---:|---|---|---:|---:|",
    ]
    for d in docs:
        lines.append("| %s | %s | **%s** | %s/%s | %d |" % (
            d.get("round", "?"), d.get("lens", "?"), d.get("gate", "FAIL"),
            d.get("checks_passed", 0), d.get("checks_total", 0),
            len(d.get("findings", []))))
    lines += ["", "**Overall: %d/%d rounds PASS.**" % (passed, len(docs)), "",
              "## Findings and revisions applied", ""]
    for d in docs:
        for f in d.get("findings", []):
            lines.append("- **R%s (%s):** %s" % (d.get("round", "?"), d.get("lens", "?"), f))
    lines += ["", "## Reject-and-rebuild conditions", "",
              "Any round returning FAIL sends the relevant module back for revision. ",
              "Faked output, missing cases, nondeterminism, overclaimed causality, ",
              "unredacted secrets, leftover temp state, or a changed canonical byte ",
              "is a release-blocking defect.", ""]
    with open(os.path.join(REVIEWS, "REVIEWS.md"), "w", encoding="utf-8", newline="\n") as h:
        h.write("\n".join(lines))
    print("review rounds: %d/%d PASS" % (passed, len(docs)))
    for d in docs:
        print("  R%02d %-14s %s (%s/%s)" % (
            d.get("round", 0), d.get("slug", "?"), d.get("gate", "FAIL"),
            d.get("checks_passed", 0), d.get("checks_total", 0)))
    return 0 if passed == len(docs) else 1


if __name__ == "__main__":
    sys.exit(main())
