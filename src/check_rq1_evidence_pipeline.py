from __future__ import annotations

import json
import tempfile
from pathlib import Path

from run_rq1_evidence_pipeline import (
    CURRENT_ECOSYSTEM,
    PIPELINE_VERSION,
    ROOT,
    build_acquisition_overview,
    build_final_summary,
    build_paths,
    build_pipeline_plan,
    write_json,
)


def script_name(
    stage: dict,
) -> str:
    command = stage.get(
        "command",
        [],
    )

    if len(
        command
    ) < 2:
        return ""

    return Path(
        command[1]
    ).name


def main() -> None:
    output_root = (
        ROOT
        / "output"
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        dir=output_root
    ) as temporary:
        temporary_path = Path(
            temporary
        )

        inventory_path = (
            temporary_path
            / "inventory.json"
        )

        inventory = {
            "schema_version":
                "synthetic_rq1_pipeline_test",

            "cases": [
                {
                    "distribution":
                        "requests",

                    "vulnerability_ids": [
                        "GHSA-TEST-1"
                    ],

                    "sources":
                        [],
                },

                {
                    "distribution":
                        "urllib3",

                    "vulnerability_ids": [
                        "GHSA-TEST-2"
                    ],

                    "sources":
                        [],
                },

                # Same package again:
                # package-level OSV discovery must
                # still happen only once.
                {
                    "distribution":
                        "requests",

                    "vulnerability_ids": [
                        "GHSA-TEST-3"
                    ],

                    "sources":
                        [],
                },
            ],
        }

        inventory_path.write_text(
            json.dumps(
                inventory,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        run_dir = (
            temporary_path
            / "run"
        )

        plan = build_pipeline_plan(
            inventory_path=inventory_path,
            out_dir=run_dir,
            ecosystem=CURRENT_ECOSYSTEM,
            refresh=False,
            timeout=30,
        )

        assert (
            plan.get(
                "pipeline_version"
            )
            == PIPELINE_VERSION
        )

        assert (
            plan.get(
                "case_count"
            )
            == 3
        )

        assert (
            plan.get(
                "distributions"
            )
            == [
                "requests",
                "urllib3",
            ]
        )

        stages = plan.get(
            "stages",
            [],
        )

        # Two unique package OSV fetches
        # + 19 fixed downstream stages.
        assert len(
            stages
        ) == 21, len(
            stages
        )

        osv_fetches = [
            row
            for row in stages
            if script_name(
                row
            )
            == (
                "fetch_osv_package_"
                "vulnerabilities.py"
            )
        ]

        assert len(
            osv_fetches
        ) == 2

        assert [
            row.get(
                "name"
            )
            for row in osv_fetches
        ] == [
            "fetch_osv_requests",
            "fetch_osv_urllib3",
        ]

        assert (
            stages[
                2
            ].get(
                "name"
            )
            == "compile_seed_source_plan"
        )

        assert (
            stages[
                3
            ].get(
                "name"
            )
            == "acquire_seed_local_structured"
        )

        assert (
            stages[
                4
            ].get(
                "name"
            )
            == "discover_osv_references"
        )

        assert (
            stages[
                5
            ].get(
                "name"
            )
            == "compile_expanded_source_plan"
        )

        assert (
            script_name(
                stages[-5]
            )
            == "validate_trigger_candidate_facts.py"
        )

        assert (
            script_name(
                stages[-4]
            )
            == "compile_trigger_evidence_drafts.py"
        )

        assert (
            script_name(
                stages[-3]
            )
            == "compile_trigger_semantic_drafts.py"
        )

        assert (
            script_name(
                stages[-2]
            )
            == (
                "join_version_aware_"
                "trigger_evidence_drafts.py"
            )
        )

        assert (
            script_name(
                stages[-1]
            )
            == (
                "build_executable_"
                "trigger_admission.py"
            )
        )

        final_command = (
            stages[-1]
            .get(
                "command",
                [],
            )
        )

        assert (
            "--version-aware-drafts"
            in final_command
        )

        version_aware_index = (
            final_command.index(
                "--version-aware-drafts"
            )
            + 1
        )

        assert (
            final_command[
                version_aware_index
            ].endswith(
                "20_version_aware_drafts.json"
            )
        )

        # Planning must not execute anything.
        assert not (
            run_dir
            / "21_executable_admission.json"
        ).exists()

    # --------------------------------------------------
    # Final-summary acquisition metrics.
    #
    # This remains completely offline. Synthetic
    # acquisition summaries are used only to check
    # denominator and aggregation semantics.
    # --------------------------------------------------

    with tempfile.TemporaryDirectory(
        dir=output_root
    ) as temporary:

        temporary_path = Path(
            temporary
        )

        summary_run = (
            temporary_path
            / "summary_run"
        )

        paths = build_paths(
            summary_run
        )

        def write_summary(
            target: Path,
            *,
            selected: int,
            resolved: int,
            nested: bool,
        ) -> None:

            metrics = {
                "selected_source_count":
                    selected,

                "resolved_source_count":
                    resolved,

                "unresolved_source_count":
                    (
                        selected
                        - resolved
                    ),
            }

            if nested:
                payload = {
                    "summary":
                        metrics,
                }

            else:
                payload = {
                    "schema_version":
                        "synthetic_top_level_acquisition_v0",

                    "status":
                        (
                            "resolved"
                            if selected == resolved
                            else "partial"
                        ),

                    **metrics,

                    # Must not leak into compact summary.
                    "results": [
                        {
                            "synthetic":
                                True,
                        }
                    ],
                }

            write_json(
                target,
                payload,
            )

        write_summary(
            paths[
                "seed_local"
            ],
            selected=3,
            resolved=3,
            nested=False,
        )

        write_summary(
            paths[
                "github_files"
            ],
            selected=2,
            resolved=1,
            nested=False,
        )

        write_summary(
            paths[
                "github_commits"
            ],
            selected=3,
            resolved=3,
            nested=False,
        )

        write_summary(
            paths[
                "github_metadata"
            ],
            selected=1,
            resolved=1,
            nested=False,
        )

        write_summary(
            paths[
                "generic_http"
            ],
            selected=4,
            resolved=2,
            nested=True,
        )

        overview = build_acquisition_overview(
            paths
        )

        assert (
            overview[
                "seed_source_resolution_rate"
            ]
            == 1.0
        )

        assert (
            overview[
                "structured_followup_selected_count"
            ]
            == 6
        )

        assert (
            overview[
                "structured_followup_resolved_count"
            ]
            == 5
        )

        assert (
            overview[
                "structured_followup_acquisition_rate"
            ]
            == (
                5
                / 6
            )
        )

        assert (
            overview[
                "generic_http_selected_count"
            ]
            == 4
        )

        assert (
            overview[
                "generic_http_resolved_count"
            ]
            == 2
        )

        assert (
            overview[
                "generic_http_acquisition_rate"
            ]
            == 0.5
        )

        assert (
            overview[
                "network_acquirable_followup_count"
            ]
            == 10
        )

        assert (
            overview[
                "network_acquirable_followup_resolved_count"
            ]
            == 7
        )

        assert (
            overview[
                "network_acquirable_followup_acquisition_rate"
            ]
            == 0.7
        )

        synthetic_plan = {
            "case_count":
                3,

            "distributions": [
                "requests",
                "urllib3",
            ],
        }

        final_summary = build_final_summary(
            plan=synthetic_plan,
            paths=paths,
        )

        assert (
            final_summary.get(
                "acquisition_overview"
            )
            == overview
        )

        assert (
            final_summary.get(
                "generic_http_acquisition",
                {},
            ).get(
                "selected_source_count"
            )
            == 4
        )


        assert (
            final_summary.get(
                "seed_local_acquisition",
                {},
            ).get(
                "selected_source_count"
            )
            == 3
        )

        assert (
            "results"
            not in final_summary.get(
                "seed_local_acquisition",
                {},
            )
        )


    print(
        "[PASS] acquisition coverage metrics "
        "preserve explicit denominators."
    )

    print(
        "[PASS] network-acquirable coverage "
        "excludes deferred unsupported sources."
    )


    print(
        "[PASS] unique packages generate "
        "one OSV package fetch each."
    )

    print(
        "[PASS] RQ1 acquisition and evidence "
        "stages are ordered correctly."
    )

    print(
        "[PASS] version and semantic evidence "
        "remain separate before the join."
    )

    print(
        "[PASS] Executable Admission Gate is "
        "the final evidence stage."
    )

    print(
        "[PASS] pipeline planning performs "
        "no network or evidence execution."
    )

    print(
        "[PASS] RQ1 Evidence Automation "
        "Pipeline v0."
    )


if __name__ == "__main__":
    main()
