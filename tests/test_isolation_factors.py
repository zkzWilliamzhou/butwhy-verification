import os
import tempfile
import unittest

from butwhy import factors, isolation, secrets
from butwhy.errors import SafetyDenied
from butwhy.runtime import DEFAULT_BOUNDS
from tests.helpers import CHECK_SCRIPT, tree


class TestArgvPolicy(unittest.TestCase):
    def test_allows_project_relative_script(self):
        isolation.validate_argv(["python3", "app/check.py"])

    def test_denies_destructive_executables(self):
        for exe in ("rm", "sudo", "curl", "git", "dd", "chmod"):
            with self.assertRaises(SafetyDenied, msg=exe):
                isolation.validate_argv([exe, "-rf", "/"])

    def test_denies_interpreter_expressions(self):
        for argv in (["python3", "-c", "import os"],
                     ["sh", "-c", "echo hi"], ["node", "-e", "process.exit()"]):
            with self.assertRaises(SafetyDenied):
                isolation.validate_argv(argv)

    def test_denies_absolute_and_traversing_arguments(self):
        for arg in ("/etc/passwd", "../secret", "a/../../etc"):
            with self.assertRaises(SafetyDenied, msg=arg):
                isolation.validate_argv(["python3", arg])

    def test_denies_shell_metacharacters(self):
        for arg in ("echo $(id)", "a;rm", "a|b", "a`b`"):
            with self.assertRaises(SafetyDenied, msg=arg):
                isolation.validate_argv(["python3", arg])

    def test_denies_unknown_executable(self):
        with self.assertRaises(SafetyDenied):
            isolation.validate_argv(["totally-unknown-tool", "x"])


class TestChildEnv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "work")
        os.makedirs(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dangerous_vars_are_stripped(self):
        env = isolation.build_child_env(
            self.root,
            {"LD_PRELOAD": "/tmp/evil.so", "PYTHONPATH": "/tmp/evil",
             "HOME": "/home/attacker", "FEATURE_FLAG": "on", "LANG": "C.UTF-8"},
        )
        self.assertNotIn("LD_PRELOAD", env)
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotEqual(env["HOME"], "/home/attacker")
        self.assertTrue(env["HOME"].startswith(self.root))
        self.assertEqual(env["FEATURE_FLAG"], "on")
        self.assertEqual(env["LANG"], "C.UTF-8")

    def test_unsafe_locale_value_dropped(self):
        env = isolation.build_child_env(self.root, {"LANG": "../../etc"})
        self.assertNotIn("LANG", env)

    def test_shim_dir_only_inside_copy(self):
        env = isolation.build_child_env(self.root, {"BUTWHY_SHIM_DIR": "/etc"})
        self.assertNotIn("/etc:", env["PATH"])
        shim = os.path.join(self.root, ".butwhy-shims")
        os.makedirs(shim)
        env2 = isolation.build_child_env(self.root, {"BUTWHY_SHIM_DIR": shim})
        self.assertTrue(env2["PATH"].startswith(shim))


class TestCopyIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.src = tree(os.path.join(self.tmp.name, "src"), {"app/check.py": CHECK_SCRIPT})
        self.bounds = dict(DEFAULT_BOUNDS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_normal_tree_copied_and_excludes_git(self):
        os.makedirs(os.path.join(self.src, ".git/hooks"), exist_ok=True)
        dst = isolation.make_copy(self.src, self.bounds)
        try:
            self.assertTrue(os.path.isfile(os.path.join(dst, "app/check.py")))
            self.assertFalse(os.path.exists(os.path.join(dst, ".git")))
            self.assertEqual(os.stat(os.path.dirname(dst)).st_mode & 0o777, 0o700)
        finally:
            isolation.destroy_copy(dst, self.bounds)

    def test_symlink_escape_rejected(self):
        os.symlink("/etc", os.path.join(self.src, "escape"))
        with self.assertRaises(SafetyDenied):
            isolation.make_copy(self.src, self.bounds)

    def test_hardlink_rejected(self):
        a = os.path.join(self.src, "a.txt")
        b = os.path.join(self.src, "b.txt")
        with open(a, "w") as h:
            h.write("x")
        os.link(a, b)
        with self.assertRaises(SafetyDenied):
            isolation.make_copy(self.src, self.bounds)

    def test_fifo_rejected(self):
        os.mkfifo(os.path.join(self.src, "pipe"))
        with self.assertRaises(SafetyDenied):
            isolation.make_copy(self.src, self.bounds)

    def test_spawn_success_and_failure(self):
        dst = isolation.make_copy(self.src, self.bounds)
        try:
            good = isolation.spawn_isolated(
                dst, ["python3", "app/check.py"],
                {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}, self.bounds,
            )
            self.assertEqual(good["outcome"], "pass")
            bad = isolation.spawn_isolated(
                dst, ["python3", "app/check.py"],
                {"LANG": "C", "LC_ALL": "C"}, self.bounds,
            )
            self.assertEqual(bad["outcome"], "fail")
        finally:
            isolation.destroy_copy(dst, self.bounds)

    def test_output_cap_yields_output_limit_not_plain_failure(self):
        # Review rounds R04/R06 finding: RLIMIT_FSIZE was set to the capture
        # cap, so the child died from SIGXFSZ and the tool mislabeled the event.
        tree(self.src, {"flood.py": "import sys\nsys.stdout.write('x'*20000)\n"})
        bounds = dict(self.bounds)
        bounds["max_output_bytes"] = 1024
        dst = isolation.make_copy(self.src, bounds)
        try:
            res = isolation.spawn_isolated(dst, ["python3", "flood.py"], {}, bounds)
            self.assertTrue(res["truncated"])
            self.assertEqual(res["outcome"], "output_limit")
            self.assertGreater(res["stdout_len"], 1024)
        finally:
            isolation.destroy_copy(dst, bounds)

    def test_timeout_kills_process_group(self):
        tree(self.src, {"sleep.py": "import time\ntime.sleep(30)\n"})
        dst = isolation.make_copy(self.src, self.bounds)
        bounds = dict(self.bounds)
        bounds["timeout_sec"] = 1
        try:
            res = isolation.spawn_isolated(dst, ["python3", "sleep.py"], {}, bounds)
            self.assertTrue(res["timed_out"])
            self.assertEqual(res["outcome"], "timeout")
        finally:
            isolation.destroy_copy(dst, bounds)


class TestFactors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "work")
        tree(self.root, {"app/check.py": CHECK_SCRIPT, "data.txt": "a\nb\n"})

    def tearDown(self):
        self.tmp.cleanup()

    def ctx(self):
        return {"env": {"LANG": "C.UTF-8"}}

    def test_env_var_factor(self):
        ctx = self.ctx()
        rec = factors.apply_factor(self.root, {
            "family": "env_var", "before": {"name": "FEATURE_FLAG", "value": None},
            "after": {"name": "FEATURE_FLAG", "value": "on"}, "action": "set",
        }, ctx)
        self.assertEqual(ctx["env"]["FEATURE_FLAG"], "on")
        self.assertEqual(rec["kind"], "env")

    def test_env_var_denied_name(self):
        with self.assertRaises(SafetyDenied):
            factors.apply_factor(self.root, {
                "family": "env_var", "before": {}, "after": {"name": "LD_PRELOAD", "value": "x"},
                "action": "set",
            }, self.ctx())

    def test_locale_and_timezone(self):
        ctx = self.ctx()
        factors.apply_factor(self.root, {
            "family": "locale", "before": {"LANG": "C.UTF-8"},
            "after": {"LANG": "C", "LC_ALL": "C"}, "action": "change",
        }, ctx)
        self.assertEqual(ctx["env"]["LC_ALL"], "C")
        factors.apply_factor(self.root, {
            "family": "timezone", "before": {"tz": ""},
            "after": {"tz": "UTC"}, "action": "change",
        }, ctx)
        self.assertEqual(ctx["env"]["TZ"], "UTC")

    def test_line_endings(self):
        factors.apply_factor(self.root, {
            "family": "line_endings", "path": "data.txt",
            "before": {"kind": "lf"}, "after": {"kind": "crlf"},
            "action": "flip_line_endings",
        }, self.ctx())
        with open(os.path.join(self.root, "data.txt"), "rb") as h:
            self.assertIn(b"\r\n", h.read())

    def test_path_traversal_rejected(self):
        with self.assertRaises(SafetyDenied):
            factors.apply_factor(self.root, {
                "family": "line_endings", "path": "../escape.txt",
                "before": {"kind": "lf"}, "after": {"kind": "crlf"},
                "action": "flip_line_endings",
            }, self.ctx())

    def test_symlink_target(self):
        os.symlink("data.txt", os.path.join(self.root, "link"))
        factors.apply_factor(self.root, {
            "family": "symlink_target", "path": "link",
            "before": {"target": "data.txt"}, "after": {"target": "app/check.py"},
            "action": "retarget",
        }, self.ctx())
        self.assertEqual(os.readlink(os.path.join(self.root, "link")), "app/check.py")

    def test_out_of_tree_symlink_target_denied(self):
        os.symlink("data.txt", os.path.join(self.root, "link"))
        with self.assertRaises(SafetyDenied):
            factors.apply_factor(self.root, {
                "family": "symlink_target", "path": "link",
                "before": {"target": "data.txt"}, "after": {"target": "/etc/passwd"},
                "action": "retarget",
            }, self.ctx())

    def test_filename_case(self):
        factors.apply_factor(self.root, {
            "family": "filename_case", "path": "data.txt",
            "before": {"lower": "data.txt"}, "after": {"lower": "DATA.txt"},
            "action": "rename",
        }, self.ctx())
        self.assertTrue(os.path.isfile(os.path.join(self.root, "DATA.txt")))

    def test_file_mode_and_world_writable_refusal(self):
        path = os.path.join(self.root, "data.txt")
        factors.apply_factor(self.root, {
            "family": "file_mode", "path": "data.txt",
            "before": {"mode": 0o644}, "after": {"mode": 0o600}, "action": "chmod",
        }, self.ctx())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with self.assertRaises(SafetyDenied):
            factors.apply_factor(self.root, {
                "family": "file_mode", "path": "data.txt",
                "before": {"mode": 0o600}, "after": {"mode": 0o777}, "action": "chmod",
            }, self.ctx())

    def test_path_shadow(self):
        ctx = self.ctx()
        factors.apply_factor(self.root, {
            "family": "path_shadow", "before": {"prepend": False},
            "after": {"prepend": True, "shim_name": "tool", "shim_exit": 7},
            "action": "prepend_shim",
        }, ctx)
        self.assertTrue(os.path.isfile(os.path.join(self.root, ".butwhy-shims/tool")))
        self.assertEqual(ctx["env"]["BUTWHY_SHIM_DIR"],
                         os.path.join(os.path.realpath(self.root), ".butwhy-shims"))

    def test_all_families_declared(self):
        self.assertEqual(len(factors.list_families()), 10)
        self.assertEqual(sum(1 for f in factors.list_families() if factors.is_replayable(f)), 8)


if __name__ == "__main__":
    unittest.main()
