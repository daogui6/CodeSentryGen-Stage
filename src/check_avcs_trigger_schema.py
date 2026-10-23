from __future__ import annotations

import json
from pathlib import Path

try:
    from jsonschema import validate
except ImportError:
    raise SystemExit(
        "Missing dependency: jsonschema. "
        "Please install with: pip install jsonschema"
    )


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "avcs_trigger_schema_v0.json"
)


TRIGGER_EVIDENCE_FILES = [
    ROOT
    / "output"
    / "pyyaml_pysec_2021_142_trigger_evidence_v0.json",

    ROOT
    / "output"
    / "numpy_ghsa_9fq2_x9r6_wfmf_trigger_evidence_v0.json",

    ROOT
    / "output"
    / "pyjwt_ghsa_ffqj_6fqr_9h24_trigger_evidence_v0.json",

    ROOT
    / "output"
    / "aiohttp_pysec_2024_24_trigger_evidence_v0.json",

    ROOT
    / "output"
    / "requests_ghsa_9hjg_9r4m_mvj7_trigger_evidence_v0.json",

    ROOT
    / "output"
    / "urllib3_ghsa_pq67_6m6q_mj2v_trigger_evidence_v0.json",
]


def load_json(path: Path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def main():

    schema = load_json(
        SCHEMA_PATH
    )

    failed = 0

    print("=" * 60)
    print("AVCS Trigger Evidence Schema Validation")
    print("=" * 60)

    for path in TRIGGER_EVIDENCE_FILES:

        if not path.exists():
            print(
                f"[SKIP] missing: {path.name}"
            )
            continue

        try:
            data = load_json(path)

            validate(
                instance=data,
                schema=schema,
            )

            print(
                f"[PASS] {path.name}"
            )

        except Exception as exc:
            failed += 1

            print(
                f"[FAIL] {path.name}"
            )

            print(
                f"       {exc}"
            )


    print("")
    print(
        f"[OK] failed: {failed}"
    )

    if failed:
        raise SystemExit(1)

    print(
        "[OK] AVCS Trigger Evidence Schema ALL PASS"
    )


if __name__ == "__main__":
    main()