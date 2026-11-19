import copy
import os
import tempfile
import unittest

from butwhy import causal, jsonutil, ledger
from butwhy.errors import SchemaError
from tests.helpers import cli


def outs(value, n=3):
    return [
        {"index": i, "outcome": value,
         "exit_code": 0 if value == "pass" else 1,
         "stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64}
        for i in range(n)
    ]


class TestCausal(unittest.TestCase):
    def decide(self, baseline, flip, reverse, replayable=True):
        return causal.decide(
            {"replayable": replayable, "family": "locale",
             "baseline": baseline, "flip": flip, "reverse": reverse}
        )

    def test_necessary_and_sufficient_requires_two_way(self):
        v = self.decide(outs("fail"), outs("pass"), outs("fail"))
        self.assertEqual(v["classification"], "necessary_and_sufficient")
        self.assertEqual(v["confidence"], 0.83)

    def test_one_way_necessary(self):
        v = self.decide(outs("fail"), outs("pass"), None)
        self.assertEqual(v["classification"], "necessary")
        self.assertEqual(v["confidence"], 0.5)

    def test_one_way_sufficient(self):
        v = self.decide(outs("pass"), outs("fail"), None)
        self.assertEqual(v["classification"], "sufficient")

    def test_no_effect(self):
        v = self.decide(outs("pass"), outs("pass"), outs("pass"))
        self.assertEqual(v["classification"], "no_effect")

    def test_non_replayable(self):
        v = self.decide(outs("pass"), outs("fail"), outs("pass"), replayable=False)
        self.assertEqual(v["classification"], "non_replayable")

    def test_flaky_group_is_inconclusive(self):
        mixed = outs("pass") + [outs("fail")[0]]
        v = self.decide(mixed, outs("pass"), outs("pass"))
        self.assertEqual(v["classification"], "inconclusive")
        self.assertEqual(v["confidence"], 0.0)

    def test_timeout_is_inconclusive(self):
        v = self.decide(outs("timeout"), outs("pass"), outs("timeout"))
        self.assertEqual(v["classification"], "inconclusive")

    def test_reverse_mismatch_is_inconclusive(self):
        v = self.decide(outs("fail"), outs("pass"), outs("pass"))
        self.assertEqual(v["classification"], "inconclusive")

    def test_multi_factor_never_claims_single_cause(self):
        results = [
            {"classification": "necessary_and_sufficient", "confidence": 0.83},
            {"classification": "necessary", "confidence": 0.5},
        ]
        overall = causal.decide_overall(results)
        self.assertEqual(overall["classification"], "inconclusive")
        self.assertTrue(overall["multi_factor"])

    def test_single_decisive_factor(self):
        overall = causal.decide_overall(
            [{"classification": "necessary_and_sufficient", "confidence": 0.83}]
        )
        self.assertEqual(overall["classification"], "necessary_and_sufficient")

    def test_all_non_replayable(self):
        overall = causal.decide_overall(
            [{"classification": "non_replayable", "confidence": 0.0}]
        )
        self.assertEqual(overall["classification"], "non_replayable")


class TestLedger(unittest.TestCase):
    def make(self):
        led = ledger.new_ledger({"capsule_id": "c" * 20, "plan_id": "p" * 20, "created_at": 0})
        led = ledger.append_event(led, {"kind": "plan", "data": {"n": 3}})
        led = ledger.append_event(led, {"kind": "observe", "data": {"x": 1}})
        led = ledger.append_event(led, {"kind": "ledger_closed", "data": {"event_count": 3}})
        led["closed"] = True
        return led

    def test_chain_is_valid(self):
        vr = ledger.verify_ledger(self.make())
        self.assertTrue(vr["valid"], vr["errors"])
        self.assertEqual(vr["checked_entries"], 3)

    def test_tampered_data_detected(self):
        led = self.make()
        led["events"][1]["data"]["x"] = 999
        vr = ledger.verify_ledger(led)
        self.assertFalse(vr["valid"])
        self.assertTrue(any("mismatch" in e for e in vr["errors"]))

    def test_reordered_events_detected(self):
        led = self.make()
        led["events"][0], led["events"][1] = led["events"][1], led["events"][0]
        vr = ledger.verify_ledger(led)
        self.assertFalse(vr["valid"])

    def test_duplicate_event_id_detected(self):
        led = self.make()
        led["events"][1]["event_id"] = led["events"][0]["event_id"]
        vr = ledger.verify_ledger(led)
        self.assertFalse(vr["valid"])

    def test_seq_gap_detected(self):
        led = self.make()
        led["events"][1]["seq"] = 7
        vr = ledger.verify_ledger(led)
        self.assertFalse(vr["valid"])

    def test_truncated_chain_is_incomplete(self):
        led = self.make()
        led["events"] = led["events"][:2]
        led["head"] = led["events"][-1]["hash"]
        vr = ledger.verify_ledger(led)
        self.assertFalse(vr["valid"])
        self.assertIn(vr["status"], ("invalid", "incomplete"))

    def test_head_mismatch_detected(self):
        led = self.make()
        led["head"] = "0" * 64
        vr = ledger.verify_ledger(led)
        self.assertFalse(vr["valid"])

    def test_unknown_event_kind_rejected(self):
        led = ledger.new_ledger({"capsule_id": "c" * 20, "created_at": 0})
        with self.assertRaises(SchemaError):
            ledger.append_event(led, {"kind": "invented", "data": {}})

    def test_write_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            led = self.make()
            ledger.write_ledger(path, led)
            loaded = jsonutil.read_document(path)
            self.assertTrue(ledger.verify_ledger(loaded)["valid"])

    def test_verify_result_envelope(self):
        vr = ledger.verify_ledger(self.make())
        self.assertEqual(jsonutil.check_envelope(vr), "verify_result")


if __name__ == "__main__":
    unittest.main()
