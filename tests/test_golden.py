"""GOLDEN CONTRACT: freeze program FUNCTION, not just its output shape.

Any optimization round must leave every canonical artifact byte-identical and
must not change the CLI surface, exit codes, verdict taxonomy, factor set,
module set, or offline guarantee.
"""
import json
import os
import tempfile
import unittest

from butwhy import contract, jsonutil
from tests.helpers import CONFIRM, cli


EXPECTED_DOCUMENTS = {
    "capsule": "capsule",
    "diff": "factor_diff",
    "ledger": "evidence_ledger",
    "verdict": "verdict_report",
    "golden": "golden_manifest",
}
EXPECTED_VERDICTS = (
    "necessary_and_sufficient", "necessary", "sufficient",
    "no_effect", "non_replayable", "inconclusive",
)
EXPECTED_EXIT_CODES = (0, 1, 2, 3, 4, 5, 6)
EXPECTED_SUBCOMMANDS = ("capture", "diff", "run", "report", "verify", "demo")


class TestGoldenContract(unittest.TestCase):
    def run_demo(self, workspace):
        rc, out, err = cli("demo", "--work", workspace, "--confirm", CONFIRM)
        self.assertEqual(rc, 0, err)
        return os.path.join(workspace, "golden.json")

    def test_locked_contract_asserts(self):
        contract.assert_contract()
        contract.guard_offline()

    def test_surface_is_frozen(self):
        self.assertEqual(tuple(contract.SUBCOMMANDS), EXPECTED_SUBCOMMANDS)
        self.assertEqual(tuple(contract.EXIT_CODES), EXPECTED_EXIT_CODES)
        self.assertEqual(tuple(contract.VERDICTS), EXPECTED_VERDICTS)
        self.assertEqual(len(contract.REPLAYABLE_FAMILIES), 8)
        self.assertEqual(len(contract.NON_REPLAYABLE_FAMILIES), 2)
        self.assertEqual(len(contract.MODULES), 16)

    def test_golden_artifacts_are_byte_identical_across_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.run_demo(os.path.join(tmp, "runA"))
            b = self.run_demo(os.path.join(tmp, "runB"))
            ma = jsonutil.read_document(a)
            mb = jsonutil.read_document(b)
            self.assertEqual(ma["golden_id"], mb["golden_id"])
            self.assertTrue(contract.compare_golden(ma, mb)["identical"])
            self.assertEqual(ma["entries"], mb["entries"])

    def test_demo_artifacts_are_canonical_and_typed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_demo(os.path.join(tmp, "demo"))
            for label, doc_type in EXPECTED_DOCUMENTS.items():
                path = os.path.join(tmp, "demo", label + ".json")
                self.assertTrue(os.path.isfile(path), label)
                self.assertEqual(jsonutil.check_envelope(jsonutil.read_document(path)),
                                 doc_type)

    def test_golden_comparison_detects_a_function_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = jsonutil.read_document(self.run_demo(os.path.join(tmp, "a")))
            b = json.loads(json.dumps(a))
            b["entries"][0]["canonical_sha256"] = "0" * 64
            result = contract.compare_golden(a, b)
            self.assertFalse(result["identical"])
            self.assertEqual(result["differences"][0]["reason"],
                             "canonical_bytes_changed")

    def test_no_forbidden_claim_phrases_in_any_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "demo")
            self.run_demo(base)
            for name in ("report.txt", "report.json", "ledger.json", "verdict.json",
                         "capsule.json", "diff.json", "golden.json"):
                with open(os.path.join(base, name), "r", encoding="utf-8") as h:
                    text = h.read().lower()
                for phrase in contract.FORBIDDEN_PHRASES:
                    self.assertNotIn(phrase, text, (name, phrase))

    def test_verify_golden_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "demo")
            self.run_demo(base)
            rc, out, _ = cli("verify", "--ledger", os.path.join(base, "ledger.json"),
                             "--golden", os.path.join(base, "golden.json"))
            self.assertEqual(rc, 0, out)
            self.assertTrue(out.startswith("OK"))
            # A modified artifact must make the golden gate fail with exit 2.
            path = os.path.join(base, "capsule.json")
            doc = jsonutil.read_document(path)
            doc["roots"] = ["changed"]
            jsonutil.write_document(path, doc)
            rc, out, _ = cli("verify", "--ledger", os.path.join(base, "ledger.json"),
                             "--golden", os.path.join(base, "golden.json"))
            self.assertEqual(rc, 2)
            self.assertTrue(out.startswith("FAIL"))


if __name__ == "__main__":
    unittest.main()
