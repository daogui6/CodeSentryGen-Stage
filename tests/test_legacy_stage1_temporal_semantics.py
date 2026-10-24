from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from benchmark_summary_writer import write_benchmark_summary
from benchmark_writer import (
    convert_to_benchmark_records,
    write_benchmark_jsonl,
)
from report_writer import write_summary_report
from risk_card import build_risk_card


GENERATION_TIME = "2026-09-28T00:00:00+00:00"
AUDIT_TIME = "2026-10-01T00:00:00+00:00"


def make_entity() -> SimpleNamespace:
    return SimpleNamespace(
        is_false_positive=False,
        is_local_module=False,
        source_type="manifest",
        mapped_name="controlled-package",
        raw_name="controlled-package",
        file="requirements.txt",
        line=1,
        original_text="controlled-package",
    )


def make_pypi(
    *,
    exists_now: bool,
    first_release_time: str | None,
) -> SimpleNamespace:
    return SimpleNamespace(
        exists_now=exists_now,
        first_release_time=first_release_time,
        audit_time=AUDIT_TIME,
        query_url=(
            "https://pypi.org/pypi/controlled-package/json"
        ),
        latest_version="1.0.0" if exists_now else None,
        error=None,
    )


def make_row(*, status: str, exists_now: bool) -> dict:
    return {
        "sample_id": "controlled-stage1",
        "prompt_id": "prompt-controlled-stage1",
        "package": "controlled-package",
        "raw_name": "controlled-package",
        "model": "controlled-test",
        "source_type": "manifest",
        "generation_time": GENERATION_TIME,
        "status": status,
        "install_reachability": "manifest_declared",
        "location": {"file": "requirements.txt", "line": 1},
        "pypi": {
            "exists_now": exists_now,
            "status_code": 200 if exists_now else 404,
            "query_url": (
                "https://pypi.org/pypi/controlled-package/json"
            ),
            "audit_time": AUDIT_TIME,
        },
    }


class LegacyStage1TemporalSemanticsTest(unittest.TestCase):
    def test_current_404_card_and_benchmark_are_auxiliary(self) -> None:
        card = build_risk_card(
            "controlled-stage1",
            make_entity(),
            make_pypi(exists_now=False, first_release_time=None),
            GENERATION_TIME,
        )
        self.assertIsNotNone(card)
        assert card is not None
        card_dict = card.to_dict()
        self.assertEqual(
            card_dict["type"],
            "temporal_package_hallucination",
        )
        self.assertEqual(card_dict["channel"], "auxiliary")
        self.assertFalse(card_dict["formal_eligible"])
        self.assertEqual(
            card_dict["claim_strength"],
            "audit_time_absence_only",
        )
        self.assertIsNone(card_dict["confidence"])
        self.assertEqual(
            card_dict["repair"]["action"],
            "review_temporal_and_identity_evidence",
        )

        benchmark = convert_to_benchmark_records(
            [make_row(status="nonexistent_now", exists_now=False)],
            [card_dict],
        )[0]
        self.assertEqual(benchmark["risk_channel"], "auxiliary")
        self.assertFalse(benchmark["formal_eligible"])
        self.assertEqual(benchmark["auto_label"], "auxiliary_review")

    def test_created_after_generation_remains_formal(self) -> None:
        card = build_risk_card(
            "controlled-stage1",
            make_entity(),
            make_pypi(
                exists_now=True,
                first_release_time="2026-09-29T00:00:00+00:00",
            ),
            GENERATION_TIME,
        )
        self.assertIsNotNone(card)
        assert card is not None
        card_dict = card.to_dict()
        self.assertEqual(card_dict["channel"], "formal")
        self.assertTrue(card_dict["formal_eligible"])

        benchmark = convert_to_benchmark_records(
            [make_row(status="created_after_tg", exists_now=True)],
            [card_dict],
        )[0]
        self.assertEqual(benchmark["risk_channel"], "formal")
        self.assertTrue(benchmark["formal_eligible"])
        self.assertEqual(benchmark["auto_label"], "risk")

    def test_missing_card_authority_fields_fail_closed(self) -> None:
        legacy_card = {
            "sample_id": "controlled-stage1",
            "package": "controlled-package",
            "type": "temporal_package_hallucination",
            "status": "nonexistent_now",
            "severity": "high",
            "confidence": 0.85,
            "evidence_level": "current_registry_evidence",
            "time_view": "as_of_audit_current_pypi",
            "repair": {"action": "remove_or_replace"},
        }
        benchmark = convert_to_benchmark_records(
            [make_row(status="nonexistent_now", exists_now=False)],
            [legacy_card],
        )[0]
        self.assertEqual(benchmark["risk_channel"], "auxiliary")
        self.assertFalse(benchmark["formal_eligible"])
        self.assertEqual(benchmark["auto_label"], "auxiliary_review")

    def test_reports_separate_formal_and_auxiliary_cards(self) -> None:
        auxiliary = build_risk_card(
            "controlled-stage1",
            make_entity(),
            make_pypi(exists_now=False, first_release_time=None),
            GENERATION_TIME,
        )
        self.assertIsNotNone(auxiliary)
        assert auxiliary is not None

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            benchmark_path = tmp_path / "benchmark.jsonl"
            benchmark_summary = tmp_path / "benchmark.md"
            stage1_summary = tmp_path / "stage1.md"
            row = make_row(status="nonexistent_now", exists_now=False)
            cards = [auxiliary.to_dict()]
            write_benchmark_jsonl(benchmark_path, [row], cards)
            write_benchmark_summary(benchmark_path, benchmark_summary)
            write_summary_report(stage1_summary, [row], cards)

            benchmark_text = benchmark_summary.read_text(encoding="utf-8")
            stage1_text = stage1_summary.read_text(encoding="utf-8")
            self.assertIn("自动标记为风险的记录数量：0", benchmark_text)
            self.assertIn("辅助复核记录数量：1", benchmark_text)
            self.assertIn("正式可计入风险卡片数量：0", stage1_text)
            self.assertIn("辅助复核卡片数量：1", stage1_text)


if __name__ == "__main__":
    unittest.main()
