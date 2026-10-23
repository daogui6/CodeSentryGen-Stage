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


SCHEMA_VERSION = "avcs_python_public_api_surface_v0.1"
MAX_SOURCE_BYTES = 5 * 1024 * 1024


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(encoding="utf-8")
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
    lower_name = artifact_path.name.lower()

    if lower_name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(artifact_path) as archive:
            info = archive.getinfo(member_name)

            if info.file_size > MAX_SOURCE_BYTES:
                raise RuntimeError(
                    f"source too large: {member_name}"
                )

            return archive.read(member_name)

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
                    f"not a regular file: {member_name}"
                )

            if member.size > MAX_SOURCE_BYTES:
                raise RuntimeError(
                    f"source too large: {member_name}"
                )

            file_obj = archive.extractfile(
                member
            )

            if file_obj is None:
                raise RuntimeError(
                    f"cannot read: {member_name}"
                )

            return file_obj.read()

    raise RuntimeError(
        f"unsupported artifact: {artifact_path.name}"
    )


def decode_python_source(
    data: bytes,
) -> str:
    encoding, _ = tokenize.detect_encoding(
        io.BytesIO(data).readline
    )

    return data.decode(encoding)


def find_package_init(
    source_index: dict[str, Any],
    package_module: str,
) -> dict[str, Any]:
    matches = [
        row
        for row in source_index.get(
            "python_sources",
            [],
        )
        if (
            isinstance(row, dict)
            and row.get("module")
            == package_module
            and row.get(
                "is_package_init"
            )
            is True
        )
    ]

    if len(matches) != 1:
        raise RuntimeError(
            f"package module {package_module!r} "
            f"matched {len(matches)} "
            "package __init__ records"
        )

    return matches[0]


def resolve_import_module(
    package_module: str,
    node: ast.ImportFrom,
) -> str:
    if node.level == 0:
        return node.module or ""

    package_parts = (
        package_module.split(".")
    )

    keep_count = (
        len(package_parts)
        - node.level
        + 1
    )

    if keep_count < 0:
        keep_count = 0

    parts = package_parts[
        :keep_count
    ]

    if node.module:
        parts.extend(
            node.module.split(".")
        )

    return ".".join(parts)


def collect_explicit_reexports(
    tree: ast.Module,
    package_module: str,
) -> list[dict[str, Any]]:
    exports: list[dict[str, Any]] = []

    for node in tree.body:
        if not isinstance(
            node,
            ast.ImportFrom,
        ):
            continue

        # from __future__ import annotations
        # is language configuration, not public API.
        if (
            node.level == 0
            and node.module == "__future__"
        ):
            continue

        source_module = (
            resolve_import_module(
                package_module,
                node,
            )
        )

        for alias in node.names:
            # Conservative v0 rule:
            #
            #   from .app import Flask as Flask
            #
            # Explicit same-name aliasing is treated as
            # deliberate package-root re-export evidence.
            if (
                alias.asname is None
                or alias.asname
                != alias.name
            ):
                continue

            public_name = alias.asname

            if public_name.startswith("_"):
                continue

            source_name = alias.name

            if source_module:
                source_symbol = (
                    f"{source_module}."
                    f"{source_name}"
                )
            else:
                source_symbol = (
                    source_name
                )

            exports.append(
                {
                    "public_name":
                        public_name,

                    "public_symbol":
                        (
                            f"{package_module}."
                            f"{public_name}"
                        ),

                    "source_module":
                        source_module,

                    "source_name":
                        source_name,

                    "source_symbol":
                        source_symbol,

                    "line":
                        node.lineno,

                    "discovery_method":
                        (
                            "package_init_"
                            "same_name_reexport"
                        ),
                }
            )

    exports.sort(
        key=lambda item: (
            item["public_name"],
            item["source_symbol"],
        )
    )

    return exports


def collect_public_api_surface(
    source_index_path: Path,
    package_module: str,
) -> dict[str, Any]:
    source_index = read_json(
        source_index_path
    )

    init_record = find_package_init(
        source_index,
        package_module,
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
        init_record.get(
            "archive_path",
            "",
        )
    ).strip()

    source = decode_python_source(
        read_archive_member(
            artifact_path,
            archive_path,
        )
    )

    tree = ast.parse(
        source,
        filename=str(
            init_record.get(
                "logical_path"
            )
            or archive_path
        ),
    )

    exports = (
        collect_explicit_reexports(
            tree=tree,
            package_module=
                package_module,
        )
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

        "package_module":
            package_module,

        "package_init_logical_path":
            init_record.get(
                "logical_path"
            ),

        "package_init_archive_path":
            archive_path,

        "source_index_file":
            str(
                source_index_path
            ).replace("\\", "/"),

        "artifact_file":
            str(
                artifact_path
            ).replace("\\", "/"),

        "status":
            "resolved",

        "discovery_scope":
            (
                "explicit_same_name_"
                "package_root_reexports"
            ),

        "explicit_reexport_count":
            len(exports),

        "exports":
            exports,

        "limitations": [
            (
                "Only explicit same-name "
                "ImportFrom re-exports are "
                "included in v0."
            ),
            (
                "__all__-based exports are "
                "not yet interpreted."
            ),
            (
                "Dynamic __getattr__ exports "
                "are not yet interpreted."
            ),
            (
                "Deprecation and removal "
                "metadata are not yet derived."
            ),
            (
                "Signature history is handled "
                "by later API History stages."
            )
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collect conservative package-root "
            "Python public API re-export surface "
            "from one historical release."
        )
    )

    parser.add_argument(
        "--source-index",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--package-module",
        required=True,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = collect_public_api_surface(
        source_index_path=
            args.source_index,
        package_module=
            args.package_module.strip(),
    )

    write_json(
        args.out,
        result,
    )

    print(
        "[OK] distribution:",
        result["distribution"],
    )
    print(
        "[OK] version:",
        result["version"],
    )
    print(
        "[OK] package module:",
        result["package_module"],
    )
    print(
        "[OK] explicit reexports:",
        result[
            "explicit_reexport_count"
        ],
    )
    print(
        "[OK] result saved to:",
        args.out,
    )


if __name__ == "__main__":
    main()
