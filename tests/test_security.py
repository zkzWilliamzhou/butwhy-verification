import glob
import json
import os
import tempfile
import unittest

from tests.helpers import CONFIRM, cli, tree


class TestSecurityRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_original_tree_is_never_modified(self):
        src = tree(os.path.join(self.base, "src"),
                   {"app/check.py": "import sys\nsys.exit(0)\n"})
        cap = os.path.join(self.base, "capsule.json")
        cli("capture", "--root", src, "--out", cap)
        dpath = os.path.join(self.base, "diff.json")
        cli("diff", "--capsule", cap, "--capsule", cap, "--out", dpath)
        before = {}
        for root, _, files in os.walk(src):
            for name in files:
                p = os.path.join(root, name)
                with open(p, "rb") as h:
                    before[os.path.relpath(p, src)] = h.read()
        rc, _, err = cli("run", "--capsule", cap, "--diff", dpath, "--work", src,
                         "--command", "python3 app/check.py", "--confirm", CONFIRM,
                         "--ledger", os.path.join(self.base, "l.json"),
                         "--out", os.path.join(self.base, "v.json"))
        self.assertEqual(rc, 0, err)
        after = {}
        for root, _, files in os.walk(src):
            for name in files:
                p = os.path.join(root, name)
                with open(p, "rb") as h:
                    after[os.path.relpath(p, src)] = h.read()
        self.assertEqual(before, after)

    def test_no_leftover_disposable_copies(self):
        src = tree(os.path.join(self.base, "src"), {"ok.py": "raise SystemExit(0)\n"})
        cap = os.path.join(self.base, "c.json")
        cli("capture", "--root", src, "--out", cap)
        d = os.path.join(self.base, "d.json")
        cli("diff", "--capsule", cap, "--capsule", cap, "--out", d)
        pattern = os.path.join(tempfile.gettempdir(), "butwhy-*")
        before = set(glob.glob(pattern))
        rc, _, err = cli("run", "--capsule", cap, "--diff", d, "--work", src,
                         "--command", "python3 ok.py", "--confirm", CONFIRM,
                         "--ledger", os.path.join(self.base, "l.json"),
                         "--out", os.path.join(self.base, "v.json"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(before, set(glob.glob(pattern)))

    def test_secret_never_appears_in_artifacts(self):
        src = tree(os.path.join(self.base, "src"), {"ok.py": "raise SystemExit(0)\n"})
        secret = "AKIAIOSFODNN7EXAMPLE"
        env = dict(os.environ)
        env.update({
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"),
            "AWS_SECRET_ACCESS_KEY": secret,
            "SOURCE_DATE_EPOCH": "1700000000",
        })
        import subprocess
        import sys
        cap = os.path.join(self.base, "c.json")
        proc = subprocess.run(
            [sys.executable, "-m", "butwhy", "capture", "--root", src, "--out", cap],
            env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(cap, "r", encoding="utf-8") as h:
            content = h.read()
        self.assertNotIn(secret, content)
        self.assertNotIn(secret[:8], content)

    def test_ledger_file_is_private(self):
        src = tree(os.path.join(self.base, "src"), {"ok.py": "raise SystemExit(0)\n"})
        cap = os.path.join(self.base, "c.json")
        cli("capture", "--root", src, "--out", cap)
        d = os.path.join(self.base, "d.json")
        cli("diff", "--capsule", cap, "--capsule", cap, "--out", d)
        ledger = os.path.join(self.base, "l.json")
        cli("run", "--capsule", cap, "--diff", d, "--work", src,
            "--command", "python3 ok.py", "--confirm", CONFIRM,
            "--ledger", ledger, "--out", os.path.join(self.base, "v.json"))
        self.assertEqual(os.stat(ledger).st_mode & 0o777, 0o600)

    def test_command_injection_payloads_do_not_execute(self):
        src = tree(os.path.join(self.base, "src"), {"ok.py": "raise SystemExit(0)\n"})
        marker = os.path.join(self.base, "PWNED")
        for payload in ("echo $(touch %s)" % marker,
                        "python3 -c 'open(\"%s\",\"w\").write(\"x\")'" % marker,
                        "sh -c 'touch %s'" % marker):
            rc, _, _ = cli("run", "--capsule", os.path.join(self.base, "c.json"),
                           "--work", src, "--command", payload)
            self.assertIn(rc, (1, 3))
            self.assertFalse(os.path.exists(marker), payload)

    def test_json_bomb_is_bounded(self):
        from butwhy import jsonutil
        from butwhy.errors import ResourceLimit, SchemaError
        huge = b"[" + b"0," * (17 * 1024 * 1024) + b"0]"
        with self.assertRaises((ResourceLimit, SchemaError)):
            jsonutil.parse_canonical(huge)

    def test_duplicate_json_keys_rejected(self):
        from butwhy import jsonutil
        from butwhy.errors import SchemaError
        with self.assertRaises(SchemaError):
            jsonutil.parse_canonical(b'{"schema_version":1,"schema_version":2}')

    def test_fullwidth_confusable_env_name_is_denied(self):
        from butwhy import secrets
        self.assertTrue(secrets.never_transplant("ＰＹＴＨＯＮＰＡＴＨ"))


if __name__ == "__main__":
    unittest.main()
