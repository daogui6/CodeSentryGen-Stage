from __future__ import annotations

import argparse
import ast
import io
import json
import tarfile
import tokenize
import zipfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "avcs_python_module_api_facts_v0.1"
MAX_SOURCE_BYTES = 5 * 1024 * 1024


def read_json(path: Path) -> dict[str, Any]:
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


def read_archive_member(
    artifact_path: Path,
    member_name: str,
) -> bytes:
    lower_name = (
        artifact_path.name.lower()
    )

    if lower_name.endswith(
        (
            ".whl",
            ".zip",
        )
    ):
        with zipfile.ZipFile(
            artifact_path
        ) as archive:
            info = archive.getinfo(
                member_name
            )

            if (
                info.file_size
                > MAX_SOURCE_BYTES
            ):
                raise RuntimeError(
                    f"source too large: "
                    f"{member_name}"
                )

            return archive.read(
                info
            )

    if lower_name.endswith(
        (
            ".tar.gz",
            ".tgz",
            ".tar.bz2",
            ".tar.xz",
        )
    ):
        with tarfile.open(
            artifact_path,
            "r:*",
        ) as archive:
            member = archive.getmember(
                member_name
            )

            if not member.isfile():
                raise RuntimeError(
                    "not a regular file: "
                    f"{member_name}"
                )

            if (
                member.size
                > MAX_SOURCE_BYTES
            ):
                raise RuntimeError(
                    f"source too large: "
                    f"{member_name}"
                )

            file_obj = (
                archive.extractfile(
                    member
                )
            )

            if file_obj is None:
                raise RuntimeError(
                    f"cannot read: "
                    f"{member_name}"
                )

            return file_obj.read()

    raise RuntimeError(
        "unsupported artifact: "
        f"{artifact_path.name}"
    )


def decode_python_source(
    data: bytes,
) -> str:
    encoding, _ = (
        tokenize.detect_encoding(
            io.BytesIO(
                data
            ).readline
        )
    )

    return data.decode(
        encoding
    )


def default_evidence(
    source: str,
    node: ast.AST | None,
) -> dict[str, Any]:
    if node is None:
        return {
            "has_default": False,
            "source_text": None,
        }

    result: dict[str, Any] = {
        "has_default": True,
        "source_text":
            ast.get_source_segment(
                source,
                node,
            ),
    }

    try:
        value = ast.literal_eval(
            node
        )
    except Exception:
        return result

    if (
        value is None
        or isinstance(
            value,
            (
                bool,
                int,
                float,
                str,
            ),
        )
    ):
        result[
            "literal_value"
        ] = value

    return result


def build_signature(
    node: (
        ast.FunctionDef
        | ast.AsyncFunctionDef
    ),
    source: str,
) -> dict[str, Any]:
    args = node.args

    positional = [
        *args.posonlyargs,
        *args.args,
    ]

    positional_kinds = (
        [
            "positional_only"
        ]
        * len(
            args.posonlyargs
        )
        + [
            "positional_or_keyword"
        ]
        * len(
            args.args
        )
    )

    positional_defaults: list[
        ast.AST | None
    ] = (
        [
            None
        ]
        * (
            len(
                positional
            )
            - len(
                args.defaults
            )
        )
        + list(
            args.defaults
        )
    )

    parameters: list[
        dict[str, Any]
    ] = []

    for (
        arg,
        kind,
        default_node,
    ) in zip(
        positional,
        positional_kinds,
        positional_defaults,
    ):
        parameters.append(
            {
                "name":
                    arg.arg,

                "kind":
                    kind,

                "required":
                    default_node
                    is None,

                "default":
                    default_evidence(
                        source,
                        default_node,
                    ),
            }
        )

    for (
        arg,
        default_node,
    ) in zip(
        args.kwonlyargs,
        args.kw_defaults,
    ):
        parameters.append(
            {
                "name":
                    arg.arg,

                "kind":
                    "keyword_only",

                "required":
                    default_node
                    is None,

                "default":
                    default_evidence(
                        source,
                        default_node,
                    ),
            }
        )

    return {
        "parameters":
            parameters,

        "explicit_parameter_names":
            [
                item["name"]
                for item
                in parameters
            ],

        "var_positional":
            (
                args.vararg.arg
                if args.vararg
                else None
            ),

        "var_keyword":
            (
                args.kwarg.arg
                if args.kwarg
                else None
            ),

        "accepts_var_positional":
            (
                args.vararg
                is not None
            ),

        "accepts_var_keyword":
            (
                args.kwarg
                is not None
            ),
    }


def find_module_record(
    source_index: dict[str, Any],
    module_name: str,
) -> dict[str, Any]:
    matches = [
        item
        for item
        in source_index.get(
            "python_sources",
            [],
        )
        if (
            isinstance(
                item,
                dict,
            )
            and item.get(
                "module"
            )
            == module_name
        )
    ]

    if len(matches) != 1:
        raise RuntimeError(
            f"module "
            f"{module_name!r} "
            f"matched "
            f"{len(matches)} "
            f"source records"
        )

    return matches[0]


def collect_module_api_facts(
    source_index_path: Path,
    module_name: str,
) -> dict[str, Any]:
    source_index = read_json(
        source_index_path
    )

    record = find_module_record(
        source_index,
        module_name,
    )

    artifact_file = str(
        source_index.get(
            "artifact",
            {},
        ).get(
            "cache_file",
            "",
        )
    ).strip()

    if not artifact_file:
        raise RuntimeError(
            "source index has no "
            "artifact.cache_file"
        )

    artifact_path = Path(
        artifact_file
    )

    if not artifact_path.exists():
        raise FileNotFoundError(
            artifact_path
        )

    archive_path = str(
        record.get(
            "archive_path",
            "",
        )
    ).strip()

    source = (
        decode_python_source(
            read_archive_member(
                artifact_path,
                archive_path,
            )
        )
    )

    tree = ast.parse(
        source,
        filename=str(
            record.get(
                "logical_path"
            )
            or archive_path
        ),
    )

    functions: list[
        dict[str, Any]
    ] = []

    classes: list[
        dict[str, Any]
    ] = []

    for node in tree.body:
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        ):
            functions.append(
                {
                    "name":
                        node.name,

                    "line":
                        node.lineno,

                    "signature":
                        build_signature(
                            node,
                            source,
                        ),
                }
            )

        elif isinstance(
            node,
            ast.ClassDef,
        ):
            methods = []

            for child in node.body:
                if isinstance(
                    child,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                    ),
                ):
                    methods.append(
                        {
                            "name":
                                child.name,

                            "line":
                                child.lineno,

                            "signature":
                                build_signature(
                                    child,
                                    source,
                                ),
                        }
                    )

            classes.append(
                {
                    "name":
                        node.name,

                    "line":
                        node.lineno,

                    "methods":
                        methods,
                }
            )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            source_index.get(
                "ecosystem",
                "pypi",
            ),

        "distribution":
            source_index.get(
                "distribution",
                "",
            ),

        "normalized_distribution":
            source_index.get(
                "normalized_distribution",
                "",
            ),

        "version":
            source_index.get(
                "version",
                "",
            ),

        "module":
            module_name,

        "logical_path":
            record.get(
                "logical_path"
            ),

        "archive_path":
            archive_path,

        "artifact_file":
            str(
                artifact_path
            ).replace(
                "\\",
                "/",
            ),

        "parse_status":
            "resolved",

        "top_level_functions":
            functions,

        "classes":
            classes,
    }


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Collect static "
                "top-level function "
                "and class-method "
                "signature facts "
                "from one historical "
                "Python module for "
                "AVCS API History."
            )
        )
    )

    parser.add_argument(
        "--source-index",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--module",
        required=True,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = (
        collect_module_api_facts(
            source_index_path=
                args.source_index,

            module_name=
                args.module.strip(),
        )
    )

    write_json(
        args.out,
        result,
    )

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )

    print(
        f"[OK] version: "
        f"{result['version']}"
    )

    print(
        f"[OK] module: "
        f"{result['module']}"
    )

    print(
        f"[OK] functions: "
        f"{len(result['top_level_functions'])}"
    )

    print(
        f"[OK] classes: "
        f"{len(result['classes'])}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()