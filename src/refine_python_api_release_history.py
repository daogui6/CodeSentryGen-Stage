from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from analyze_python_keyword_forwarding import (
    analyze_keyword_forwarding,
)
from collect_python_api_release_history import (
    safe_component,
)


SCHEMA_VERSION = (
    "avcs_python_api_release_history_refined_v0.1"
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


def find_parameter(
    signature: dict[str, Any],
    parameter_name: str,
) -> dict[str, Any] | None:
    parameters = signature.get(
        "parameters",
        [],
    )

    if not isinstance(
        parameters,
        list,
    ):
        return None

    for parameter in parameters:
        if (
            isinstance(
                parameter,
                dict,
            )
            and parameter.get(
                "name"
            )
            == parameter_name
        ):
            return parameter

    return None


def build_refinement_path(
    refinement_dir: Path,
    distribution: str,
    api_symbol: str,
    version: str,
    parameter_name: str,
) -> Path:
    return (
        refinement_dir
        / safe_component(
            distribution
        )
        / safe_component(
            api_symbol
        )
        / safe_component(
            version
        )
        / (
            safe_component(
                parameter_name
            )
            + "_keyword_forwarding.json"
        )
    )


def refine_release(
    batch: dict[str, Any],
    record: dict[str, Any],
    api_calls_path: Path,
    parameter_name: str,
    refinement_dir: Path,
) -> dict[str, Any]:
    distribution = str(
        batch.get(
            "distribution",
            "",
        )
    )

    api_symbol = str(
        batch.get(
            "api_symbol",
            "",
        )
    )

    version = str(
        record.get(
            "version",
            "",
        )
    )

    public_status = str(
        record.get(
            "public_symbol_status",
            "",
        )
    )

    signature = record.get(
        "public_signature"
    )

    result: dict[str, Any] = {
        "version":
            version,

        "api_symbol":
            api_symbol,

        "parameter":
            parameter_name,

        "public_symbol_status":
            public_status,

        "parameter_explicit":
            None,

        "accepts_var_keyword":
            None,

        "analysis_mode":
            None,

        "support_status":
            "unknown",

        "support_reason":
            None,

        "refinement_status":
            None,

        "refinement_reason":
            None,

        "refinement_assessment":
            None,

        "refinement_file":
            None,

        "error_type":
            None,

        "error_message":
            None,
    }

    if (
        public_status != "resolved"
        or not isinstance(
            signature,
            dict,
        )
    ):
        result[
            "analysis_mode"
        ] = "public_symbol"

        result[
            "support_reason"
        ] = (
            "public_signature_unresolved"
        )

        return result

    parameter = find_parameter(
        signature,
        parameter_name,
    )

    accepts_var_keyword = bool(
        signature.get(
            "accepts_var_keyword",
            False,
        )
    )

    result[
        "parameter_explicit"
    ] = parameter is not None

    result[
        "accepts_var_keyword"
    ] = accepts_var_keyword

    # --------------------------------------------------
    # Case 1:
    # 参数已经显式存在。
    #
    # 这是最强、最便宜的支持证据，
    # 不需要继续分析函数体。
    # --------------------------------------------------

    if parameter is not None:
        result[
            "analysis_mode"
        ] = "public_signature"

        result[
            "support_status"
        ] = "supported"

        result[
            "support_reason"
        ] = "explicit_parameter"

        return result

    # --------------------------------------------------
    # Case 2:
    # 参数不存在，且函数连 **kwargs 都没有。
    #
    # 可以直接判定该关键字不被接受，
    # 同样不需要更昂贵的 forwarding analysis。
    # --------------------------------------------------

    if not accepts_var_keyword:
        result[
            "analysis_mode"
        ] = "public_signature"

        result[
            "support_status"
        ] = "unsupported"

        result[
            "support_reason"
        ] = (
            "parameter_absent_and_"
            "no_var_keyword"
        )

        return result

    # --------------------------------------------------
    # Case 3:
    # 参数没有显式出现，但函数存在 **kwargs。
    #
    # 单看 signature 无法判断。
    # 只有这一类 release 才启动函数体 forwarding。
    # --------------------------------------------------

    result[
        "analysis_mode"
    ] = "keyword_forwarding"

    source_index_text = str(
        record.get(
            "source_index_file",
            "",
        )
    ).strip()

    public_symbol_text = str(
        record.get(
            "public_symbol_file",
            "",
        )
    ).strip()

    if (
        not source_index_text
        or not public_symbol_text
    ):
        result[
            "support_reason"
        ] = (
            "batch_evidence_path_missing"
        )

        return result

    source_index_path = Path(
        source_index_text
    )

    public_symbol_path = Path(
        public_symbol_text
    )

    if not source_index_path.exists():
        result[
            "support_reason"
        ] = (
            "source_index_file_missing"
        )

        return result

    if not public_symbol_path.exists():
        result[
            "support_reason"
        ] = (
            "public_symbol_file_missing"
        )

        return result

    refinement_path = (
        build_refinement_path(
            refinement_dir=
                refinement_dir,

            distribution=
                distribution,

            api_symbol=
                api_symbol,

            version=
                version,

            parameter_name=
                parameter_name,
        )
    )

    result[
        "refinement_file"
    ] = str(
        refinement_path
    ).replace(
        "\\",
        "/",
    )

    try:
        refinement = (
            analyze_keyword_forwarding(
                api_calls_path=
                    api_calls_path,

                public_symbol_path=
                    public_symbol_path,

                source_index_path=
                    source_index_path,

                api_symbol=
                    api_symbol,

                keyword_name=
                    parameter_name,
            )
        )

        write_json(
            refinement_path,
            refinement,
        )

    except Exception as exc:
        result[
            "support_reason"
        ] = (
            "keyword_forwarding_error"
        )

        result[
            "error_type"
        ] = type(
            exc
        ).__name__

        result[
            "error_message"
        ] = str(exc)

        return result

    refinement_status = str(
        refinement.get(
            "status",
            "",
        )
    )

    support_status = str(
        refinement.get(
            "support_status",
            "unknown",
        )
    )

    support_reason = str(
        refinement.get(
            "support_reason",
            "",
        )
    )

    result[
        "refinement_status"
    ] = refinement_status

    result[
        "refinement_reason"
    ] = support_reason

    result[
        "refinement_assessment"
    ] = refinement.get(
        "assessment"
    )

    if (
        refinement_status == "resolved"
        and support_status
        in {
            "supported",
            "unsupported",
        }
    ):
        result[
            "support_status"
        ] = support_status

        result[
            "support_reason"
        ] = (
            "refined_by_"
            "keyword_forwarding_evidence"
        )

        return result

    result[
        "support_status"
    ] = "unknown"

    result[
        "support_reason"
    ] = (
        "keyword_forwarding_unresolved"
    )

    return result


def summarize(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    supported = sum(
        record.get(
            "support_status"
        )
        == "supported"
        for record in records
    )

    unsupported = sum(
        record.get(
            "support_status"
        )
        == "unsupported"
        for record in records
    )

    unknown = sum(
        record.get(
            "support_status"
        )
        == "unknown"
        for record in records
    )

    signature_only = sum(
        record.get(
            "analysis_mode"
        )
        == "public_signature"
        for record in records
    )

    forwarding = sum(
        record.get(
            "analysis_mode"
        )
        == "keyword_forwarding"
        for record in records
    )

    forwarding_resolved = sum(
        (
            record.get(
                "analysis_mode"
            )
            == "keyword_forwarding"
        )
        and (
            record.get(
                "support_status"
            )
            in {
                "supported",
                "unsupported",
            }
        )
        for record in records
    )

    return {
        "release_count":
            len(records),

        "supported_count":
            supported,

        "unsupported_count":
            unsupported,

        "unknown_count":
            unknown,

        "signature_only_count":
            signature_only,

        "keyword_forwarding_attempt_count":
            forwarding,

        "keyword_forwarding_resolved_count":
            forwarding_resolved,
    }


def refine_api_release_history(
    release_history_batch_path: Path,
    api_calls_path: Path,
    parameter_name: str,
    refinement_dir: Path,
) -> dict[str, Any]:
    batch = read_json(
        release_history_batch_path
    )

    records = batch.get(
        "records",
        [],
    )

    if not isinstance(
        records,
        list,
    ):
        raise RuntimeError(
            "release-history batch has "
            "no valid records list"
        )

    api_symbol = str(
        batch.get(
            "api_symbol",
            "",
        )
    ).strip()

    if not api_symbol:
        raise RuntimeError(
            "release-history batch has "
            "no API symbol"
        )

    distribution = str(
        batch.get(
            "distribution",
            "",
        )
    ).strip()

    if not distribution:
        raise RuntimeError(
            "release-history batch has "
            "no distribution"
        )

    refined_records: list[
        dict[str, Any]
    ] = []

    for index, record in enumerate(
        records,
        start=1,
    ):
        if not isinstance(
            record,
            dict,
        ):
            continue

        version = str(
            record.get(
                "version",
                "",
            )
        )

        print(
            f"[RUN] "
            f"{index}/{len(records)} "
            f"{distribution} "
            f"{version} "
            f"{api_symbol} "
            f"parameter={parameter_name}"
        )

        refined = refine_release(
            batch=
                batch,

            record=
                record,

            api_calls_path=
                api_calls_path,

            parameter_name=
                parameter_name,

            refinement_dir=
                refinement_dir,
        )

        refined_records.append(
            refined
        )

        print(
            f"[{'OK' if refined.get('support_status') != 'unknown' else 'WARN'}] "
            f"{version} | "
            f"mode={refined.get('analysis_mode')} | "
            f"support={refined.get('support_status')} | "
            f"reason={refined.get('support_reason')}"
        )

        if refined.get(
            "error_message"
        ):
            print(
                f"       "
                f"{refined.get('error_type')}: "
                f"{refined.get('error_message')}"
            )

    summary = summarize(
        refined_records
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            batch.get(
                "ecosystem",
                "pypi",
            ),

        "distribution":
            distribution,

        "normalized_distribution":
            batch.get(
                "normalized_distribution",
                "",
            ),

        "api_symbol":
            api_symbol,

        "parameter":
            parameter_name,

        "release_history_batch_source":
            str(
                release_history_batch_path
            ).replace(
                "\\",
                "/",
            ),

        "api_calls_source":
            str(
                api_calls_path
            ).replace(
                "\\",
                "/",
            ),

        **summary,

        "records":
            refined_records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Refine release-level Python API "
            "parameter support. Cheap public "
            "signature evidence is used first; "
            "keyword forwarding analysis runs "
            "only for signature-level unknowns."
        )
    )

    parser.add_argument(
        "--release-history-batch",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--api-calls",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--parameter",
        required=True,
    )

    parser.add_argument(
        "--refinement-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_api_history_refinement"
        ),
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = refine_api_release_history(
        release_history_batch_path=
            args.release_history_batch,

        api_calls_path=
            args.api_calls,

        parameter_name=
            args.parameter.strip(),

        refinement_dir=
            args.refinement_dir,
    )

    write_json(
        args.out,
        result,
    )

    print("")
    print("=" * 60)
    print("API RELEASE HISTORY REFINEMENT SUMMARY")
    print("=" * 60)

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )

    print(
        f"[OK] API symbol: "
        f"{result['api_symbol']}"
    )

    print(
        f"[OK] parameter: "
        f"{result['parameter']}"
    )

    print(
        f"[OK] releases: "
        f"{result['release_count']}"
    )

    print(
        f"[OK] supported: "
        f"{result['supported_count']}"
    )

    print(
        f"[OK] unsupported: "
        f"{result['unsupported_count']}"
    )

    print(
        f"[OK] unknown: "
        f"{result['unknown_count']}"
    )

    print(
        f"[OK] signature only: "
        f"{result['signature_only_count']}"
    )

    print(
        f"[OK] forwarding attempts: "
        f"{result['keyword_forwarding_attempt_count']}"
    )

    print(
        f"[OK] forwarding resolved: "
        f"{result['keyword_forwarding_resolved_count']}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()