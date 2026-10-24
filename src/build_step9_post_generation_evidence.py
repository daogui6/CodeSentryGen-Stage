from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_step9_method_freeze_v1 import verify_step9_formal_freeze_binding
from generation_outcome_accounting_v1 import validate_manifest_self_consistency
from generation_outcome_integration_v1 import (
    evaluate_split_statistical_eligibility,
    require_successor_method_revision_contract,
)
from step9_protocol_registry import require_active_frozen_protocol
from time_contract_v1 import require_aware_utc
from verify_core_freeze_closure_v1 import verify_core_freeze_closure


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def run(cmd: list[str]) -> None:
    print("[RUN]", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "After a frozen real Step9 generation stage, acquire the split-"
            "specific Registry snapshot and build the post-generation core "
            "evidence closure without changing the pre-generation method."
        )
    )
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--split", required=True, choices=["pilot", "test"])
    args = parser.parse_args()

    protocol_path, protocol, _ = require_active_frozen_protocol(
        args.protocol,
        operation=f"Step9 {args.split} post-generation evidence",
    )
    require_successor_method_revision_contract(protocol)

    split = args.split
    generation_key = (
        "pilot_generation_stage_manifest"
        if split == "pilot"
        else "test_generation_stage_manifest"
    )
    snapshot_key = (
        "pilot_release_snapshot_manifest"
        if split == "pilot"
        else "test_release_snapshot_manifest"
    )
    closure_key = (
        "pilot_core_freeze_closure"
        if split == "pilot"
        else "test_core_freeze_closure"
    )

    planned = protocol.get("planned_outputs")
    if not isinstance(planned, dict):
        raise ValueError("Frozen protocol planned_outputs missing")

    generation_path = ROOT / str(planned[generation_key])
    snapshot_path = ROOT / str(planned[snapshot_key])
    closure_path = ROOT / str(planned[closure_key])
    method_path = ROOT / str(planned["method_freeze"])

    if not generation_path.exists():
        raise FileNotFoundError(
            f"Frozen generation-stage manifest missing: {generation_path}"
        )
    generation = read_json(generation_path)
    if (
        generation.get("schema_version")
        != "step9_generation_stage_manifest_v1"
        or generation.get("status") != "PASS"
        or generation.get("split") != split
    ):
        raise ValueError("Generation-stage manifest is not a valid PASS")

    outcome_rel = str(
        generation.get("generation_outcome_manifest_file") or ""
    ).strip()
    if not outcome_rel:
        raise ValueError(
            "Generation stage does not bind generation outcome manifest"
        )
    outcome_path = ROOT / outcome_rel
    if not outcome_path.is_file():
        raise FileNotFoundError(outcome_path)
    outcome = read_json(outcome_path)
    validate_manifest_self_consistency(outcome)
    if outcome.get("split") != split:
        raise ValueError("Generation outcome manifest split mismatch")
    if generation.get("stage_evidence_status") != outcome.get(
        "stage_evidence_status"
    ):
        raise ValueError(
            "Generation stage/outcome finalization status mismatch"
        )
    if generation.get("generation_outcome_manifest_content_sha256") != (
        outcome.get("manifest_content_sha256")
    ):
        raise ValueError(
            "Generation stage/outcome content binding mismatch"
        )
    if outcome.get("stage_evidence_status") not in {
        "FINALIZED_ALL_ACCEPTED",
        "FINALIZED_WITH_TERMINALS",
    }:
        raise ValueError(
            "Post-generation evidence requires a durably finalized split"
        )
    if int(outcome.get("unresolved_count") or 0) != 0:
        raise ValueError(
            "Post-generation evidence refuses unresolved generation state"
        )
    eligibility = evaluate_split_statistical_eligibility(outcome)
    if eligibility.get("eligible") is not True:
        raise ValueError(
            "Post-generation formal analysis is statistically NO-GO: "
            f"{eligibility}"
        )

    method = verify_step9_formal_freeze_binding(
        method_path,
        protocol_path=protocol_path,
        require_git_identity=True,
        require_environment_versions=True,
    )
    if generation.get("method_closure_sha256") != method.get(
        "method_closure_sha256"
    ):
        raise ValueError(
            "Generation stage does not bind the active method freeze"
        )

    generation_max_raw = generation.get("generation_time_max")
    generation_max = (
        require_aware_utc(
            generation_max_raw,
            label=f"step9_{split}.generation_time_max",
        )
        if generation_max_raw is not None
        else None
    )
    finalized_at = require_aware_utc(
        generation.get("stage_finalized_at"),
        label=f"step9_{split}.stage_finalized_at",
    )
    now = datetime.now(timezone.utc)
    if now < finalized_at:
        raise ValueError(
            "Local acquisition clock is earlier than split finalization"
        )

    if snapshot_path.exists():
        raise FileExistsError(
            f"Refusing overwrite of split release snapshot: {snapshot_path}"
        )
    if closure_path.exists():
        raise FileExistsError(
            f"Refusing overwrite of split core closure: {closure_path}"
        )
    if snapshot_path.name != "manifest.json":
        raise ValueError(
            "Release snapshot planned output must end in manifest.json"
        )

    snapshot_time = now.isoformat()
    run(
        [
            sys.executable,
            "src/refresh_avcs_release_snapshots_v1.py",
            "--snapshot-time",
            snapshot_time,
            "--out-dir",
            str(snapshot_path.parent),
        ]
    )

    snapshot = read_json(snapshot_path)
    if snapshot.get("status") != "FROZEN":
        raise ValueError("Post-generation release snapshot is not FROZEN")
    actual_snapshot_time = require_aware_utc(
        snapshot.get("snapshot_time"),
        label=f"step9_{split}.snapshot_time",
    )
    if actual_snapshot_time < finalized_at:
        raise ValueError(
            "Acquired release snapshot predates durable split finalization"
        )
    if (
        generation_max is not None
        and actual_snapshot_time < generation_max
    ):
        raise ValueError(
            "Acquired release snapshot does not cover accepted generations"
        )

    run(
        [
            sys.executable,
            "src/build_core_freeze_closure_v1.py",
            "--release-snapshot-manifest",
            str(snapshot_path),
            "--method-freeze",
            str(method_path),
            "--out",
            str(closure_path),
        ]
    )
    closure = verify_core_freeze_closure(
        closure_path,
        require_git_identity=True,
        require_environment_versions=True,
    )
    if closure.get("method_closure_sha256") != method.get(
        "method_closure_sha256"
    ):
        raise ValueError(
            "Post-generation core closure changed the frozen method"
        )
    if Path(str(closure.get("release_snapshot_manifest"))).as_posix() != (
        snapshot_path.relative_to(ROOT).as_posix()
    ):
        raise ValueError(
            "Post-generation core closure binds a different release snapshot"
        )

    print("STEP9 POST-GENERATION EVIDENCE FREEZE PASS")
    print("split =", split)
    print("stage_evidence_status =", outcome.get("stage_evidence_status"))
    print(
        "accepted_complete_count =",
        outcome.get("accepted_complete_count"),
    )
    print("terminal_count =", outcome.get("terminal_count"))
    print("statistical_eligibility =", eligibility.get("status"))
    print("stage_finalized_at =", generation.get("stage_finalized_at"))
    print("generation_time_max =", generation.get("generation_time_max"))
    print("snapshot_time =", snapshot.get("snapshot_time"))
    print("snapshot_created_at =", snapshot.get("created_at"))
    print("method_closure_sha256 =", method.get("method_closure_sha256"))
    print("core_closure_sha256 =", closure.get("closure_sha256"))


if __name__ == "__main__":
    main()
