import os
import tempfile
import unittest

from butwhy import capture, diff, jsonutil, secrets
from butwhy.errors import ResourceLimit, SchemaError
from butwhy.runtime import DEFAULT_BOUNDS
from tests.helpers import CHECK_SCRIPT, tree


class TestCanonicalJSON(unittest.TestCase):
    def test_sorted_keys_and_compact(self):
        self.assertEqual(jsonutil.canonical({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_unicode_is_raw_utf8(self):
        self.assertEqual(jsonutil.canonical({"k": "café"}), '{"k":"café"}'.encode("utf-8"))

    def test_deterministic_id_is_stable(self):
        a = jsonutil.deterministic_id({"x": [1, 2, 3]})
        b = jsonutil.deterministic_id({"x": [1, 2, 3]})
        self.assertEqual(a, b)
        self.assertEqual(len(a), 20)

    def test_rejects_nan_and_infinity(self):
        with self.assertRaises(SchemaError):
            jsonutil.canonical({"x": float("nan")})
        with self.assertRaises(SchemaError):
            jsonutil.canonical({"x": float("inf")})
        with self.assertRaises(SchemaError):
            jsonutil.parse_canonical(b'{"x":NaN}')

    def test_rejects_duplicate_keys(self):
        with self.assertRaises(SchemaError):
            jsonutil.parse_canonical(b'{"a":1,"a":2}')

    def test_rejects_non_canonical_text(self):
        with self.assertRaises(SchemaError):
            jsonutil.parse_canonical(b'{ "a": 1 }')

    def test_rejects_bom_and_bad_utf8(self):
        with self.assertRaises(SchemaError):
            jsonutil.parse_canonical(b"\xef\xbb\xbf{}")
        with self.assertRaises(SchemaError):
            jsonutil.parse_canonical(b'{"a":"\xff"}')

    def test_depth_bound(self):
        obj = []
        cur = obj
        for _ in range(40):
            nxt = []
            cur.append(nxt)
            cur = nxt
        with self.assertRaises(ResourceLimit):
            jsonutil.canonical(obj)

    def test_size_bound(self):
        with self.assertRaises(ResourceLimit):
            jsonutil.parse_canonical(b"[" + b"0," * (17 * 1024 * 1024) + b"0]")

    def test_envelope_validation(self):
        doc = jsonutil.envelope("capsule", {"x": 1})
        self.assertEqual(jsonutil.check_envelope(doc), "capsule")
        bad = dict(doc)
        bad["schema_version"] = 9999
        with self.assertRaises(SchemaError):
            jsonutil.check_envelope(bad)
        with self.assertRaises(SchemaError):
            jsonutil.envelope("capsule", {"schema_version": 2})

    def test_write_read_roundtrip_and_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = jsonutil.envelope("golden_manifest", {"items": [1, 2]})
            path = os.path.join(tmp, "a.json")
            sha = jsonutil.write_document(path, doc)
            self.assertEqual(sha, jsonutil.sha256_hex(jsonutil.canonical(doc)))
            self.assertEqual(jsonutil.read_document(path)["items"], [1, 2])
            pretty = os.path.join(tmp, "p.json")
            jsonutil.write_document(pretty, doc, pretty=True)
            with open(pretty, "r", encoding="utf-8") as handle:
                self.assertIn("\n  ", handle.read())


class TestSecrets(unittest.TestCase):
    def test_dynamic_loader_and_runtime_names_denied(self):
        for name in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH",
                     "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "BASH_ENV", "IFS",
                     "HOME", "USER", "SHELL", "PATH", "TMPDIR", "GIT_EXEC_PATH"):
            self.assertTrue(secrets.never_transplant(name), name)

    def test_host_bound_names_denied(self):
        for name in ("HOSTNAME", "PWD", "SHLVL", "DISPLAY"):
            self.assertTrue(secrets.never_transplant(name), name)

    def test_unicode_confusable_is_denied(self):
        self.assertTrue(secrets.never_transplant("ＰＹＴＨＯＮＰＡＴＨ"))
        self.assertTrue(secrets.never_transplant("ＬＤ_ＰＲＥＬＯＡＤ"))

    def test_secret_names_never_stored(self):
        rec = secrets.env_record("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        self.assertIsNone(rec["value"])
        self.assertTrue(rec["redacted"])
        self.assertNotIn("wJalrX", repr(rec))

    def test_opaque_host_ids_are_redacted_by_value_class(self):
        # Review round R02 finding: innocuously-named host credentials were
        # previously stored in plaintext capsules.
        for name, value in (
            ("SANDBOX_USER_ID", "42762274edd74eba978eb2e54ea4fbfc"),
            ("TUYA_CLIENT_ID", "j8k2m9p4q1w7e5r3t0ya"),
            ("AGS_GATEWAY_TARGET", "yuanbao-one-agent-yuanbao-open-api"),
        ):
            rec = secrets.env_record(name, value)
            self.assertIsNone(rec["value"], name)
            self.assertTrue(rec["redacted"], name)
            self.assertNotIn(value, repr(rec), name)

    def test_safe_short_factor_values_remain_plain(self):
        for name, value in (("FEATURE_FLAG", "on"), ("LANG", "C.UTF-8"), ("TZ", "UTC")):
            rec = secrets.env_record(name, value)
            self.assertEqual(rec["value"], value, name)
            self.assertTrue(rec["transplantable"], name)

    def test_mask_has_no_value_derived_digest(self):
        a = secrets.mask("hunter2")
        b = secrets.mask("hunter2")
        c = secrets.mask("hunter3")
        self.assertEqual(a, b)
        self.assertEqual(a, c)  # same length bucket, so identical marker
        self.assertNotIn("hunter", a)

    def test_safe_value_policy(self):
        self.assertTrue(secrets.safe_value("FEATURE_FLAG", "on"))
        self.assertTrue(secrets.safe_value("LANG", "C.UTF-8"))
        self.assertTrue(secrets.safe_value("TZ", "UTC"))
        self.assertFalse(secrets.safe_value("LANG", "../../etc"))
        self.assertFalse(secrets.safe_value("TZ", "../UTC"))
        self.assertFalse(secrets.safe_value("LD_PRELOAD", "x"))
        self.assertFalse(secrets.safe_value("X", "a\nb"))
        self.assertFalse(secrets.safe_value("X", "/etc/passwd"))

    def test_redact_text(self):
        text = "Authorization: Bearer ABCdef123456 and AKIAIOSFODNN7EXAMPLE"
        out = secrets.redact_text(text)
        self.assertNotIn("ABCdef123456", out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)


class TestCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = tree(os.path.join(self.tmp.name, "src"), {"app/check.py": CHECK_SCRIPT})

    def tearDown(self):
        self.tmp.cleanup()

    def test_capsule_is_deterministic(self):
        a = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))
        b = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))
        self.assertEqual(a["capsule_id"], b["capsule_id"])
        self.assertEqual(jsonutil.canonical(a), jsonutil.canonical(b))

    def test_no_secret_material_in_capsule(self):
        os.environ["BUTWHY_TEST_TOKEN"] = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        try:
            cap = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))
            self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789", repr(cap))
        finally:
            del os.environ["BUTWHY_TEST_TOKEN"]

    def test_excludes_vcs_and_cache_dirs(self):
        os.makedirs(os.path.join(self.root, ".git/hooks"), exist_ok=True)
        with open(os.path.join(self.root, ".git/hooks/post-checkout"), "w") as h:
            h.write("evil")
        cap = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))
        self.assertFalse(any(".git" in f["path"] for f in cap["files"]))

    def test_env_override_and_path_shadow_fixtures(self):
        cap = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))
        a = capture.with_env_override(cap, "LANG", "C")
        b = capture.with_env_override(cap, "LANG", "en_US.UTF-8")
        self.assertNotEqual(a["capsule_id"], b["capsule_id"])
        shadow = capture.with_path_shadow(cap, "tool", 7)
        self.assertTrue(shadow["factor_snapshot"]["path_shadow"]["prepend"])

    def test_write_capsule(self):
        cap = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))
        path = os.path.join(self.tmp.name, "cap.json")
        sha = capture.write_capsule(cap, path)
        self.assertEqual(len(sha), 64)
        self.assertEqual(jsonutil.read_document(path)["document"], "capsule")


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = tree(os.path.join(self.tmp.name, "src"), {"app/check.py": CHECK_SCRIPT})
        self.base = capture.capture_environment([self.root], dict(DEFAULT_BOUNDS))

    def tearDown(self):
        self.tmp.cleanup()

    def test_identical_capsules_produce_no_factors(self):
        d = diff.diff_capsules(self.base, self.base)
        self.assertEqual(d["diffs"], [])
        self.assertEqual(d["summary"]["replayable"], 0)

    def test_locale_difference_is_one_replayable_factor(self):
        b = capture.with_env_override(self.base, "LANG", "C")
        a = capture.with_env_override(self.base, "LANG", "en_US.UTF-8")
        d = diff.diff_capsules(a, b)
        self.assertEqual(len(d["diffs"]), 1)
        self.assertEqual(d["diffs"][0]["family"], "locale")
        self.assertTrue(d["diffs"][0]["replayable"])

    def test_env_var_presence_difference(self):
        a = capture.with_env_override(self.base, "FEATURE_FLAG", None)
        b = capture.with_env_override(self.base, "FEATURE_FLAG", "on")
        d = diff.diff_capsules(a, b)
        self.assertTrue(any(x["family"] == "env_var" for x in d["diffs"]))

    def test_denied_env_factor(self):
        a = capture.with_env_override(self.base, "LD_PRELOAD", None)
        b = capture.with_env_override(self.base, "LD_PRELOAD", "/tmp/evil.so")
        d = diff.diff_capsules(a, b)
        # LD_PRELOAD is never transplantable, so no cleartext factor is emitted
        self.assertNotIn("/tmp/evil.so", repr(d))

    def test_non_replayable_family(self):
        import copy
        b = copy.deepcopy(self.base)
        b["non_replayable"]["interpreter_version"] = "3.9.0"
        b["capsule_id"] = jsonutil.deterministic_id({"x": 1})
        d = diff.diff_capsules(self.base, b)
        self.assertTrue(any(x["family"] == "interpreter_version" and not x["replayable"]
                            for x in d["diffs"]))

    def test_content_difference_becomes_note(self):
        import copy
        b = copy.deepcopy(self.base)
        for f in b["files"]:
            if f["path"] == "app/check.py":
                f["sha256"] = "0" * 64
        b["capsule_id"] = jsonutil.deterministic_id({"y": 2})
        d = diff.diff_capsules(self.base, b)
        self.assertTrue(any(x["family"] == "note" for x in d["diffs"]))

    def test_diff_is_deterministic(self):
        b = capture.with_env_override(self.base, "LANG", "C")
        self.assertEqual(jsonutil.canonical(diff.diff_capsules(self.base, b)),
                         jsonutil.canonical(diff.diff_capsules(self.base, b)))


if __name__ == "__main__":
    unittest.main()
