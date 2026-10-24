import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_temporal_risk_cards import (
    THO_NUMERIC_CONFIDENCE_SEMANTICS,
    attach_numeric_confidence_semantics,
)


class ConfidenceSemanticsTests(unittest.TestCase):
    def test_numeric_confidence_is_explicitly_nonprobabilistic(self) -> None:
        card = {}
        attach_numeric_confidence_semantics(card, {"confidence": 0.95})
        self.assertEqual(card["confidence"], 0.95)
        self.assertEqual(
            card["confidence_semantics"]["scale_type"],
            "ordinal_rule_strength",
        )
        self.assertIs(
            card["confidence_semantics"]["calibrated_probability"], False
        )
        self.assertIs(
            card["confidence_semantics"][
                "probability_interpretation_allowed"
            ],
            False,
        )
        self.assertIs(
            THO_NUMERIC_CONFIDENCE_SEMANTICS[
                "cross_method_comparison_allowed"
            ],
            False,
        )

    def test_missing_confidence_adds_no_synthetic_score(self) -> None:
        card = {}
        attach_numeric_confidence_semantics(card, {})
        self.assertEqual(card, {})

    def test_invalid_numeric_confidence_fails_closed(self) -> None:
        for value in (True, -0.1, 1.1, "0.95"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    attach_numeric_confidence_semantics(
                        {}, {"confidence": value}
                    )

    def test_historical_rule_values_are_unchanged(self) -> None:
        source = (ROOT / "src/build_temporal_risk_cards.py").read_text(
            encoding="utf-8"
        )
        values = {
            float(value)
            for value in re.findall(r'"confidence":\s*(0\.\d+)', source)
        }
        self.assertEqual(values, {0.50, 0.75, 0.80, 0.85, 0.90, 0.95})

    def test_machine_readable_policy_forbids_probability_claim(self) -> None:
        policy = json.loads(
            (
                ROOT / "config/core_risk_semantics_v2_1_repair_v1.json"
            ).read_text(encoding="utf-8")
        )["confidence_policy"]
        self.assertEqual(policy["semantic_type"], "ordinal_rule_strength")
        self.assertIs(policy["calibrated_probability"], False)
        self.assertIs(policy["probability_interpretation_allowed"], False)
        self.assertIs(policy["historical_numeric_values_changed"], False)


if __name__ == "__main__":
    unittest.main()
