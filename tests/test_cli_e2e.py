import copy
import json
import os
import tempfile
import unittest

from butwhy import capture, jsonutil
from tests.helpers import ALWAYS_FAIL, CHECK_SCRIPT, CONFIRM, FLAKY_SCRIPT, cli, tree


class TestCLISurface(unittest.TestCase):
    def test_six_subcommands(self):
        rc, out, err = cli("--help")
        self.assertEqual(rc, 0)
        for name in ("capture", "diff", "run", "report", "verify", "demo"):
            self.assertIn(name, out)

    def test_version(self):
        rc, out, _ = cli("--version")
        self.assertEqual(rc, 0)
        self.assertIn("butwhy 0.1.0", out)

    def test_unknown_command_is_usage_error(self):
        rc, _, err = cli("invented")
        self.assertEqual(rc, 1)


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = self.tmp.name
        self.src = tree(os.path.join(self.base, "src"), {"app/check.py": CHECK_SCRIPT})
        self.cap = os.path.join(self.base, "capsule.json")
        rc, _, err = cli("capture", "--root", self.src, "--out", self.cap)
        self.assertEqual(rc, 0, err)
        self.capsule = jsonutil.read_document(self.cap)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, doc):
        path = os.path.join(self.base, name)
        jsonutil.write_document(path, doc)
        return path

    def _diff(self, other):
        path = self._write("diff.json", __import__("butwhy.diff", fromlist=["diff_capsules"]).diff_capsules(
            self.capsule, other
        ))
        return path

    def test_dry_run_gate_does_not_execute(self):
        other = capture.with_env_override(self.capsule, "LANG", "C")
        other = capture.with_env_override(other, "LC_ALL", "C")
        dpath = self._diff(other)
        rc, out, err = cli(
            "run", "--capsule", self.cap, "--diff", dpath, "--work", self.src,
            "--command", "python3 app/check.py",
        )
        self.assertEqual(rc, 1)
        plan = json.loads(out.strip())
        self.assertEqual(plan["document"], "dry_run_plan")
        self.assertIn("no command was executed", err)

    def test_wrong_confirmation_is_rejected(self):
        other = capture.with_env_override(self.capsule, "LANG", "C")
        dpath = self._diff(other)
        rc, _, _ = cli(
            "run", "--capsule", self.cap, "--diff", dpath, "--work", self.src,
            "--command", "python3 app/check.py", "--confirm", "yes",
        )
        self.assertEqual(rc, 1)

    def test_locale_scenario_full_pipeline(self):
        other = capture.with_env_override(self.capsule, "LANG", "C")
        other = capture.with_env_override(other, "LC_ALL", "C")
        dpath = self._diff(other)
        ledger = os.path.join(self.base, "ledger.json")
        verdict = os.path.join(self.base, "verdict.json")
        rc, out, err = cli(
            "run", "--capsule", self.cap, "--diff", dpath, "--work", self.src,
            "--command", "python3 app/check.py", "--confirm", CONFIRM,
            "--ledger", ledger, "--out", verdict,
        )
        self.assertEqual(rc, 0, err)
        v = jsonutil.read_document(verdict)
        self.assertEqual(v["overall"], "necessary_and_sufficient")
        self.assertEqual(v["confidence"], 0.83)

        rc, text, _ = cli("report", "--ledger", ledger, "--format", "text")
        self.assertEqual(rc, 0)
        self.assertIn("necessary_and_sufficient", text)
        for phrase in ("root cause", "caused by", "the bug is"):
            self.assertNotIn(phrase, text.lower())

        rc, out, _ = cli("verify", "--ledger", ledger)
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("OK"))

    def test_tampered_ledger_exits_two(self):
        other = capture.with_env_override(self.capsule, "LANG", "C")
        dpath = self._diff(other)
        ledger = os.path.join(self.base, "ledger.json")
        cli("run", "--capsule", self.cap, "--diff", dpath, "--work", self.src,
            "--command", "python3 app/check.py", "--confirm", CONFIRM,
            "--ledger", ledger, "--out", os.path.join(self.base, "verdict.json"))
        led = jsonutil.read_document(ledger)
        led["events"][0]["data"]["plan_id"] = "tampered"
        jsonutil.write_document(ledger, led)
        rc, out, _ = cli("verify", "--ledger", ledger)
        self.assertEqual(rc, 2)
        self.assertTrue(out.startswith("FAIL"))

    def test_no_effect_scenario(self):
        tree_a = tree(os.path.join(self.base, "treeA"), {"fail.py": ALWAYS_FAIL + "#A\n"})
        tree_b = tree(os.path.join(self.base, "treeB"), {"fail.py": ALWAYS_FAIL + "#B\n"})
        cap_a = os.path.join(self.base, "a.json")
        cap_b = os.path.join(self.base, "b.json")
        self.assertEqual(cli("capture", "--root", tree_a, "--out", cap_a)[0], 0)
        self.assertEqual(cli("capture", "--root", tree_b, "--out", cap_b)[0], 0)
        dpath = os.path.join(self.base, "d.json")
        self.assertEqual(cli("diff", "--capsule", cap_a, "--capsule", cap_b,
                             "--out", dpath)[0], 0)
        verdict = os.path.join(self.base, "v.json")
        rc, _, err = cli("run", "--capsule", cap_a, "--diff", dpath, "--work", tree_a,
                         "--command", "python3 fail.py", "--confirm", CONFIRM,
                         "--out", verdict, "--ledger", os.path.join(self.base, "l.json"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(jsonutil.read_document(verdict)["overall"], "no_effect")

    def test_non_replayable_scenario(self):
        other = copy.deepcopy(self.capsule)
        other["non_replayable"]["interpreter_version"] = "3.9.0"
        other["capsule_id"] = jsonutil.deterministic_id({"z": 9})
        dpath = self._diff(other)
        verdict = os.path.join(self.base, "v.json")
        rc, _, err = cli("run", "--capsule", self.cap, "--diff", dpath, "--work", self.src,
                         "--command", "python3 app/check.py", "--confirm", CONFIRM,
                         "--out", verdict, "--ledger", os.path.join(self.base, "l.json"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(jsonutil.read_document(verdict)["overall"], "non_replayable")

    def test_flaky_command_is_inconclusive(self):
        work = tree(os.path.join(self.base, "flaky"), {"flaky.py": FLAKY_SCRIPT})
        cap = os.path.join(self.base, "fcap.json")
        cli("capture", "--root", work, "--out", cap)
        base = jsonutil.read_document(cap)
        a = capture.with_env_override(base, "FEATURE_FLAG", None)
        b = capture.with_env_override(base, "FEATURE_FLAG", "on")
        cap_a = self._write("fa.json", a)
        cap_b = self._write("fb.json", b)
        dpath = os.path.join(self.base, "fd.json")
        cli("diff", "--capsule", cap_a, "--capsule", cap_b, "--out", dpath)
        verdict = os.path.join(self.base, "fv.json")
        rc, _, err = cli("run", "--capsule", cap_a, "--diff", dpath, "--work", work,
                         "--command", "python3 flaky.py", "--confirm", CONFIRM,
                         "--out", verdict, "--ledger", os.path.join(self.base, "fl.json"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(jsonutil.read_document(verdict)["overall"], "inconclusive")

    def test_exit_codes(self):
        # 3: safety denied
        rc, _, _ = cli("run", "--capsule", self.cap, "--work", self.src,
                       "--command", "rm -rf /", "--diff",
                       self._diff(self.capsule))
        self.assertEqual(rc, 3)
        # 5: unsupported schema
        bad = dict(self.capsule)
        bad["schema_version"] = 9999
        # Deliberately malformed envelope: write raw bytes, bypassing validation.
        bad_path = os.path.join(self.base, "bad.json")
        with open(bad_path, "wb") as handle:
            handle.write(jsonutil.canonical(bad) + b"\n")
        rc, _, _ = cli("diff", "--capsule", self.cap, "--capsule", bad_path)
        self.assertEqual(rc, 5)
        # 4: resource limit (tree cap of 1 byte). A real factor is needed so
        # that execute_plan actually builds a disposable copy to enforce the cap.
        factor_diff = self._diff(
            capture.with_env_override(self.capsule, "LANG", "C")
        )
        rc, _, err = cli("run", "--capsule", self.cap, "--diff", factor_diff,
                         "--work", self.src, "--command", "python3 app/check.py",
                         "--confirm", CONFIRM, "--tree-cap", "1")
        self.assertEqual(rc, 4, err)


if __name__ == "__main__":
    unittest.main()
