"""Compatibility for predecessor manifests used by the completed R5 protocols."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import audit_step9_dataset_leakage as leakage  # noqa: E402


class ConsolidatedPredecessorCompatibilityTests(unittest.TestCase):
    def packet(self, revision: str) -> dict:
        records = [
            {
                "prompt_id": f"prior_{number}",
                "normalized_prompt_text_sha256": hashlib.sha256(
                    f"controlled prior prompt {number}".encode()
                ).hexdigest(),
            }
            for number in range(2)
        ]
        packet = {
            "schema_version": (
                f"step9_v4_r5_{revision}_predecessor_fingerprint_manifest_v1"
            ),
            "status": "FROZEN_PRE_SELECTION",
            "records": records,
        }
        if revision in {"r11", "r12", "r13"}:
            packet["record_contract"] = {
                "record_count": 2,
                "distinct_prompt_ids": 2,
                "distinct_prompt_text_hashes": 2,
            }
        else:
            packet["exclusion_policy"] = {
                "expected_total_records": 2,
                "expected_distinct_prompt_ids": 2,
                "expected_distinct_prompt_hashes": 2,
            }
        return packet

    def read_packet(self, packet: dict, expected_counts: dict | None = None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "predecessor.json").write_text(
                json.dumps(packet), encoding="utf-8"
            )
            protocol = {
                "freshness_rule": {
                    "predecessor_fingerprint_manifest": "predecessor.json"
                }
            }
            protocol["freshness_rule"].update(expected_counts or {})
            with patch.object(leakage, "ROOT", root):
                return leakage.explicit_exclusion_fingerprints(protocol)

    def test_r11_r12_r13_record_contracts_preserve_exclusion_identity(self):
        for revision in ("r11", "r12", "r13"):
            with self.subTest(revision=revision):
                packet = self.packet(revision)
                ids, hashes, metadata = self.read_packet(packet)
                self.assertEqual(ids, {"prior_0", "prior_1"})
                self.assertEqual(
                    hashes,
                    {
                        record["normalized_prompt_text_sha256"]
                        for record in packet["records"]
                    },
                )
                self.assertEqual(metadata["record_count"], 2)

    def test_legacy_r10_exclusion_policy_remains_supported(self):
        ids, hashes, metadata = self.read_packet(self.packet("r10"))
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(hashes), 2)
        self.assertEqual(metadata["record_count"], 2)

    def test_record_count_drift_is_rejected(self):
        packet = self.packet("r13")
        packet["record_contract"]["record_count"] = 3
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            self.read_packet(packet)

    def test_protocol_record_count_mismatch_is_rejected(self):
        for revision in ("r10", "r11", "r12", "r13"):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "count mismatch"):
                    self.read_packet(
                        self.packet(revision),
                        {"expected_predecessor_fingerprint_count": 3},
                    )

    def test_protocol_distinct_prompt_count_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            self.read_packet(
                self.packet("r13"),
                {"expected_predecessor_distinct_prompt_ids": 3},
            )

    def test_protocol_distinct_hash_count_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            self.read_packet(
                self.packet("r13"),
                {"expected_predecessor_distinct_prompt_text_hashes": 3},
            )

    def test_matching_protocol_counts_preserve_exclusion_identity(self):
        for revision in ("r10", "r11", "r12", "r13"):
            with self.subTest(revision=revision):
                ids, hashes, metadata = self.read_packet(
                    self.packet(revision),
                    {
                        "expected_predecessor_fingerprint_count": 2,
                        "expected_predecessor_distinct_prompt_ids": 2,
                        "expected_predecessor_distinct_prompt_text_hashes": 2,
                    },
                )
                self.assertEqual(len(ids), 2)
                self.assertEqual(len(hashes), 2)
                self.assertEqual(metadata["record_count"], 2)

    def test_unfrozen_predecessor_packet_is_rejected(self):
        packet = self.packet("r13")
        packet["status"] = "DRAFT"
        with self.assertRaisesRegex(ValueError, "not frozen"):
            self.read_packet(packet)


if __name__ == "__main__":
    unittest.main()
