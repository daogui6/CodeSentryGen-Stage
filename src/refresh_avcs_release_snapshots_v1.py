from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from freeze_hash_v1 import canonical_sha256_file
from normalizer import pep503_normalize
from resolve_avcs_release_history import resolve_release_history
from time_contract_v1 import (
    TIMELINE_CONTRACT_VERSION,
    require_aware_utc,
    require_not_after,
    utc_iso,
    validate_release_snapshot_timeline,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB_DIR = ROOT / "data/avcs_package_kb"


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def sha256_file(path: Path) -> str:
    return canonical_sha256_file(path)


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_kb_distributions(kb_dir: Path) -> list[tuple[Path, str]]:
    rows: list[tuple[Path, str]] = []
    for path in sorted(kb_dir.glob("*_package_kb_v0.json")):
        kb = read_json(path)
        distribution = str(
            kb.get("distribution")
            or kb.get("normalized_distribution")
            or ""
        ).strip()
        if not distribution:
            raise ValueError(f"Package KB has no distribution: {path}")
        rows.append((path, distribution))
    if not rows:
        raise ValueError(f"No Package KBs found under {kb_dir}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Create an append-only, hash-verified AVCS PyPI release snapshot "
            "bundle for the core-audit repair line."
        )
    )
    parser.add_argument("--snapshot-time", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--package-kb-dir",
        type=Path,
        default=DEFAULT_KB_DIR,
    )
    args = parser.parse_args()

    requested_snapshot_time = require_aware_utc(
        args.snapshot_time,
        label="--snapshot-time",
    )
    acquisition_start = datetime.now(timezone.utc)
    require_not_after(
        requested_snapshot_time,
        acquisition_start,
        earlier_label="snapshot_time",
        later_label="acquisition_start",
    )
    snapshot_time_text = utc_iso(
        requested_snapshot_time
    )

    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    kb_dir = args.package_kb_dir
    if not kb_dir.is_absolute():
        kb_dir = ROOT / kb_dir

    if out_dir.exists():
        raise FileExistsError(
            f"Refusing overwrite of release snapshot bundle: {out_dir}"
        )

    artifact_dir = out_dir / "artifacts"
    raw_dir = out_dir / "raw_pypi"
    artifact_dir.mkdir(parents=True)
    raw_dir.mkdir(parents=True)

    packages: dict[str, dict[str, Any]] = {}
    timeline_artifacts: dict[str, dict[str, Any]] = {}
    try:
        for kb_path, distribution in load_kb_distributions(kb_dir):
            normalized = pep503_normalize(distribution)
            result = resolve_release_history(
                distribution=distribution,
                time_view_text=snapshot_time_text,
                cache_dir=raw_dir,
                refresh=True,
            )
            timeline_artifacts[normalized] = result
            artifact_path = artifact_dir / f"{normalized}.json"
            write_json(artifact_path, result)

            raw_path = raw_dir / f"{normalized}.json"
            if not raw_path.exists():
                raise FileNotFoundError(
                    f"Expected raw PyPI snapshot missing: {raw_path}"
                )

            packages[normalized] = {
                "distribution": distribution,
                "path": rel(artifact_path),
                "sha256": sha256_file(artifact_path),
                "raw_pypi_path": rel(raw_path),
                "raw_pypi_sha256": sha256_file(raw_path),
                "package_kb_path": rel(kb_path),
                "package_kb_sha256": sha256_file(kb_path),
                "time_view": result.get("time_view"),
                "audit_time": result.get("audit_time"),
                "release_history_status": result.get(
                    "release_history_status"
                ),
                "release_count_without_file_evidence": result.get(
                    "release_count_without_file_evidence"
                ),
                "registry_data_source": result.get("registry_data_source"),
                "source_url": (
                    f"https://pypi.org/pypi/{distribution}/json"
                ),
            }

        manifest = {
            "schema_version": "avcs_release_snapshot_manifest_v1",
            "status": "FROZEN",
            "created_at": utc_now(),
            "snapshot_time": snapshot_time_text,
            "registry_source": "PyPI JSON API",
            "refresh_required": True,
            "package_count": len(packages),
            "packages": packages,
            "scientific_boundary": {
                "snapshot_bytes_are_append_only": True,
                "raw_registry_payloads_are_preserved": True,
                "artifact_and_raw_payloads_are_sha256_bound": True,
                "hash_contract": "codesentry_gen_canonical_hash_v1",
                "cross_platform_text_hashing": True,
                "partial_release_history_remains_partial": True,
                "missing_file_evidence_is_not_coerced_to_negative": True,
                "timeline_contract_version": TIMELINE_CONTRACT_VERSION,
                "snapshot_time_not_after_acquisition": True,
                "future_dated_snapshot_forbidden": True,
            },
        }
        validate_release_snapshot_timeline(
            manifest,
            artifacts=timeline_artifacts,
            label="generated_release_snapshot",
        )
        manifest_path = out_dir / "manifest.json"
        write_json(manifest_path, manifest)

        print("F-02 RELEASE SNAPSHOT FREEZE PASS")
        print("packages =", len(packages))
        print("snapshot_time =", snapshot_time_text)
        print("manifest =", rel(manifest_path))
        print("manifest_sha256 =", sha256_file(manifest_path))
        partial = sorted(
            name
            for name, row in packages.items()
            if row.get("release_history_status") == "partial"
        )
        print("partial_packages =", partial)
    except Exception:
        # Never leave a half-built directory that could later be mistaken
        # for a frozen evidence bundle.
        shutil.rmtree(out_dir, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
