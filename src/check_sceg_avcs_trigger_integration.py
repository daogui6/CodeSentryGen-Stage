from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCEG_PATH = (
    ROOT
    / "output"
    / "sceg_avcs_control_full_load_v0.jsonl"
)


def read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(
            f"missing file: {path}"
        )

    rows: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        for line_no, line in enumerate(
            f,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{path} line {line_no} "
                    f"is invalid json: {e}"
                ) from e

    return rows


def check(
    name: str,
    expected: Any,
    actual: Any,
) -> bool:
    passed = expected == actual

    status = (
        "PASS"
        if passed
        else "FAIL"
    )

    print(
        f"[{status}] {name} | "
        f"expected={expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def main() -> None:
    rows = read_jsonl(
        SCEG_PATH
    )

    results: list[bool] = []

    results.append(
        check(
            "SCEG record count",
            1,
            len(rows),
        )
    )

    if len(rows) != 1:
        raise SystemExit(1)

    row = rows[0]

    nodes = row.get(
        "nodes",
        {},
    )

    evidence = row.get(
        "evidence",
        {},
    )

    analysis = row.get(
        "analysis",
        {},
    )

    edges = row.get(
        "edges",
        [],
    )

    risk_card_links = row.get(
        "risk_card_links",
        [],
    )

    sample = nodes.get(
        "sample",
        {},
    )

    package = nodes.get(
        "package",
        {},
    )

    dependency_entity = nodes.get(
        "dependency_entity",
        {},
    )

    trigger_evidence = evidence.get(
        "trigger"
    )

    results.extend(
        [
            check(
                "sample id",
                "avcs_control_full_load",
                sample.get(
                    "sample_id"
                ),
            ),

            check(
                "package",
                "PyYAML",
                package.get(
                    "name"
                ),
            ),

            check(
                "temporal status",
                "existed_at_tg",
                analysis.get(
                    "temporal_status_v2"
                ),
            ),

            check(
                "trigger evidence is object",
                True,
                isinstance(
                    trigger_evidence,
                    dict,
                ),
            ),
        ]
    )

    if not isinstance(
        trigger_evidence,
        dict,
    ):
        raise SystemExit(1)

    trigger = trigger_evidence.get(
        "trigger",
        {},
    )

    vulnerability = trigger_evidence.get(
        "vulnerability",
        {},
    )

    evidence_source = trigger_evidence.get(
        "evidence_source",
        {},
    )

    trigger_edges = [
        edge
        for edge in edges
        if (
            isinstance(edge, dict)
            and edge.get("type")
            == "has_trigger_evidence"
        )
    ]

    results.extend(
        [
            check(
                "trigger distribution",
                "PyYAML",
                trigger_evidence.get(
                    "distribution"
                ),
            ),

            check(
                "trigger vulnerability",
                "CVE-2020-14343",
                vulnerability.get(
                    "vulnerability_id"
                ),
            ),

            check(
                "trigger source sample",
                "avcs_control_full_load",
                evidence_source.get(
                    "sample_id"
                ),
            ),

            check(
                "trigger matched",
                True,
                trigger.get(
                    "matched"
                ),
            ),

            check(
                "trigger risk candidate",
                True,
                trigger.get(
                    "risk_candidate"
                ),
            ),

            check(
                "observed trigger APIs",
                ["yaml.full_load"],
                trigger.get(
                    "observed_trigger_apis"
                ),
            ),

            check(
                "trigger edge count",
                1,
                len(trigger_edges),
            ),

            check(
                "AVCS Risk Card link count",
                1,
                len(risk_card_links),
            ),

            # 这个检查非常关键：
            # 当前 temporal status 是 existed_at_tg，
            # 因此这里为 True 只能来自 AVCS trigger
            # （而不是 THO temporal risk）。
            check(
                "SCEG overall risk candidate",
                True,
                analysis.get(
                    "risk_candidate"
                ),
            ),

            check(
                "analysis Risk Card count",
                1,
                analysis.get(
                    "risk_card_count"
                ),
            ),
        ]
    )

    if trigger_edges:
        trigger_edge = (
            trigger_edges[0]
        )

        results.extend(
            [
                check(
                    "trigger edge source",
                    dependency_entity.get(
                        "entity_id"
                    ),
                    trigger_edge.get(
                        "source"
                    ),
                ),

                check(
                    "trigger edge target",
                    "trigger_evidence",
                    trigger_edge.get(
                        "target"
                    ),
                ),
            ]
        )

    if risk_card_links:
        risk_card = (
            risk_card_links[0]
        )

        results.extend(
            [
                check(
                    "Risk Card type",
                    (
                        "api_vulnerability_"
                        "compatibility"
                    ),
                    risk_card.get(
                        "type"
                    ),
                ),

                check(
                    "Risk Card status",
                    "candidate",
                    risk_card.get(
                        "status"
                    ),
                ),
            ]
        )

    passed = sum(results)
    total = len(results)

    print("")
    print("=" * 60)
    print(
        "SCEG AVCS Trigger Integration"
    )
    print("=" * 60)

    print(
        f"[OK] total checks: {total}"
    )
    print(
        f"[OK] passed: {passed}"
    )
    print(
        f"[OK] failed: {total - passed}"
    )

    if passed != total:
        raise SystemExit(1)

    print(
        "[OK] SCEG AVCS Trigger "
        "Integration ALL PASS"
    )


if __name__ == "__main__":
    main()