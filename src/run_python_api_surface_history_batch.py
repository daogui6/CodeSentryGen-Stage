from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from collect_python_api_release_history import (
    collect_api_release_history,
    safe_component,
)
from refine_python_api_symbol_release_history import (
    refine_symbol_release_history,
)
from compile_python_api_release_history_candidate import (
    compile_candidate,
)


SCHEMA_VERSION = (
    "avcs_python_api_surface_history_batch_v0.1"
)


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def load_symbols(
    spec_path: Path,
    only_symbols: list[str],
    symbol_limit: int | None,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:
    spec = read_json(
        spec_path
    )

    raw_symbols = spec.get(
        "symbols",
        [],
    )

    if not isinstance(
        raw_symbols,
        list,
    ):
        raise RuntimeError(
            "surface spec has no valid symbols list"
        )

    symbols = [
        dict(item)
        for item in raw_symbols
        if (
            isinstance(item, dict)
            and str(
                item.get(
                    "api_symbol",
                    "",
                )
            ).strip()
        )
    ]

    if only_symbols:
        wanted = {
            item.strip()
            for item in only_symbols
            if item.strip()
        }

        symbols = [
            item
            for item in symbols
            if str(
                item["api_symbol"]
            ).strip()
            in wanted
        ]

        missing = (
            wanted
            - {
                str(
                    item["api_symbol"]
                ).strip()
                for item in symbols
            }
        )

        if missing:
            raise RuntimeError(
                "requested symbols not found in spec: "
                + ", ".join(
                    sorted(missing)
                )
            )

    if symbol_limit is not None:
        if symbol_limit <= 0:
            raise ValueError(
                "--symbol-limit must be positive"
            )

        symbols = symbols[
            :symbol_limit
        ]

    if not symbols:
        raise RuntimeError(
            "no API symbols selected"
        )

    return (
        spec,
        symbols,
    )


def run_symbol(
    *,
    release_history_path: Path,
    distribution: str,
    symbol_spec: dict[str, Any],
    registry_cache_dir: Path,
    artifact_cache_dir: Path,
    history_batch_dir: Path,
    out_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    api_symbol = str(
        symbol_spec[
            "api_symbol"
        ]
    ).strip()

    symbol_dir = (
        out_dir
        / safe_component(
            api_symbol
        )
    )

    history_out = (
        symbol_dir
        / "release_history.json"
    )

    refined_out = (
        symbol_dir
        / "release_history_refined.json"
    )

    candidate_out = (
        symbol_dir
        / "api_history_candidate.json"
    )

    print("")
    print("=" * 72)
    print(
        f"[SYMBOL] {api_symbol}"
    )
    print("=" * 72)

    history = (
        collect_api_release_history(
            release_history_path=
                release_history_path,

            distribution=
                distribution,

            api_symbol=
                api_symbol,

            registry_cache_dir=
                registry_cache_dir,

            artifact_cache_dir=
                artifact_cache_dir,

            batch_dir=
                history_batch_dir,

            start_version_text=
                None,

            end_version_text=
                None,

            include_prereleases=
                False,

            limit=
                None,

            refresh=
                False,

            timeout=
                timeout,
        )
    )

    write_json(
        history_out,
        history,
    )

    refined = (
        refine_symbol_release_history(
            release_history_batch_path=
                history_out,
        )
    )

    write_json(
        refined_out,
        refined,
    )

    candidate = (
        compile_candidate(
            refined_history_path=
                refined_out,
        )
    )

    write_json(
        candidate_out,
        candidate,
    )

    lower_bound = (
        candidate.get(
            "lower_bound_candidate",
            {},
        )
    )

    if not isinstance(
        lower_bound,
        dict,
    ):
        lower_bound = {}

    result = {
        "api_symbol":
            api_symbol,

        "role":
            symbol_spec.get(
                "role"
            ),

        "latest_target":
            symbol_spec.get(
                "latest_target"
            ),

        "status":
            "completed",

        "selected_release_count":
            history.get(
                "selected_release_count"
            ),

        "public_symbol_resolved_count":
            history.get(
                "public_symbol_resolved_count"
            ),

        "public_symbol_unresolved_count":
            history.get(
                "public_symbol_unresolved_count"
            ),

        "supported_count":
            refined.get(
                "supported_count"
            ),

        "unsupported_count":
            refined.get(
                "unsupported_count"
            ),

        "unknown_count":
            refined.get(
                "unknown_count"
            ),

        "support_transition_count":
            candidate.get(
                "support_transition_count"
            ),

        "coverage_status":
            (
                candidate.get(
                    "coverage",
                    {},
                ).get(
                    "coverage_status"
                )
            ),

        "candidate_scope":
            candidate.get(
                "candidate_scope"
            ),

        "lower_bound_status":
            lower_bound.get(
                "status"
            ),

        "version_specifier":
            lower_bound.get(
                "version_specifier"
            ),

        "boundary_version":
            lower_bound.get(
                "boundary_version"
            ),

        "release_history_file":
            str(
                history_out
            ).replace(
                "\\",
                "/",
            ),

        "refined_history_file":
            str(
                refined_out
            ).replace(
                "\\",
                "/",
            ),

        "candidate_file":
            str(
                candidate_out
            ).replace(
                "\\",
                "/",
            ),
    }

    print("")
    print(
        "[DONE]",
        api_symbol,
        "| supported=",
        result["supported_count"],
        "| unsupported=",
        result["unsupported_count"],
        "| unknown=",
        result["unknown_count"],
        "| boundary=",
        result["version_specifier"],
    )

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run collect -> refine -> candidate "
            "for a minimal Python public API "
            "surface specification."
        )
    )

    parser.add_argument(
        "--release-history",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--surface-spec",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--summary-out",
        type=Path,
    )

    parser.add_argument(
        "--registry-cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_pypi_release_cache"
        ),
    )

    parser.add_argument(
        "--artifact-cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_api_artifact_cache"
        ),
    )

    parser.add_argument(
        "--history-batch-dir",
        type=Path,
    )

    parser.add_argument(
        "--only-symbol",
        action="append",
        default=[],
    )

    parser.add_argument(
        "--symbol-limit",
        type=int,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError(
            "--timeout must be positive"
        )

    (
        spec,
        symbols,
    ) = load_symbols(
        spec_path=
            args.surface_spec,

        only_symbols=
            args.only_symbol,

        symbol_limit=
            args.symbol_limit,
    )

    distribution = str(
        spec.get(
            "distribution",
            "",
        )
    ).strip()

    if not distribution:
        raise RuntimeError(
            "surface spec has no distribution"
        )

    history_batch_dir = (
        args.history_batch_dir
        if args.history_batch_dir
        is not None
        else (
            args.out_dir
            / "history_batch"
        )
    )

    summary_out = (
        args.summary_out
        if args.summary_out
        is not None
        else (
            args.out_dir
            / "batch_summary.json"
        )
    )

    results: list[
        dict[str, Any]
    ] = []

    for index, symbol_spec in enumerate(
        symbols,
        start=1,
    ):
        api_symbol = str(
            symbol_spec[
                "api_symbol"
            ]
        ).strip()

        print("")
        print(
            f"[BATCH] {index}/{len(symbols)} "
            f"{api_symbol}"
        )

        try:
            result = run_symbol(
                release_history_path=
                    args.release_history,

                distribution=
                    distribution,

                symbol_spec=
                    symbol_spec,

                registry_cache_dir=
                    args.registry_cache_dir,

                artifact_cache_dir=
                    args.artifact_cache_dir,

                history_batch_dir=
                    history_batch_dir,

                out_dir=
                    args.out_dir,

                timeout=
                    args.timeout,
            )

        except Exception as exc:
            result = {
                "api_symbol":
                    api_symbol,

                "role":
                    symbol_spec.get(
                        "role"
                    ),

                "status":
                    "error",

                "error_type":
                    type(exc).__name__,

                "error_message":
                    str(exc),
            }

            print(
                "[ERROR]",
                api_symbol,
                type(exc).__name__,
                str(exc),
            )

        results.append(
            result
        )

        partial_summary = {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                distribution,

            "surface_spec_file":
                str(
                    args.surface_spec
                ).replace(
                    "\\",
                    "/",
                ),

            "release_history_file":
                str(
                    args.release_history
                ).replace(
                    "\\",
                    "/",
                ),

            "selected_symbol_count":
                len(symbols),

            "completed_symbol_count":
                sum(
                    row.get(
                        "status"
                    )
                    == "completed"
                    for row in results
                ),

            "error_symbol_count":
                sum(
                    row.get(
                        "status"
                    )
                    == "error"
                    for row in results
                ),

            "results":
                results,
        }

        write_json(
            summary_out,
            partial_summary,
        )

    print("")
    print("=" * 72)
    print("API SURFACE HISTORY BATCH SUMMARY")
    print("=" * 72)

    for row in results:
        print(
            row.get(
                "api_symbol"
            ),
            "|",
            row.get(
                "status"
            ),
            "|",
            row.get(
                "version_specifier"
            ),
            "| unknown=",
            row.get(
                "unknown_count"
            ),
        )

    print(
        "[OK] summary:",
        summary_out,
    )


if __name__ == "__main__":
    main()
