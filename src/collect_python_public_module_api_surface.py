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


SCHEMA_VERSION = (
    "avcs_python_public_module_api_surface_v0.1"
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


def find_module_record(
    source_index: dict[str, Any],
    public_module: str,
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
            == public_module
        )
    ]

    if len(matches) != 1:
        raise RuntimeError(
            f"public module {public_module!r} "
            f"matched {len(matches)} "
            "source records"
        )

    return matches[0]


def read_archive_member(
    artifact_path: Path,
    archive_path: str,
) -> bytes:
    if tarfile.is_tarfile(
        artifact_path
    ):
        with tarfile.open(
            artifact_path,
            "r:*",
        ) as tf:
            member = tf.extractfile(
                archive_path
            )

            if member is None:
                raise RuntimeError(
                    "archive member has "
                    "no readable content: "
                    f"{archive_path}"
                )

            return member.read()

    if zipfile.is_zipfile(
        artifact_path
    ):
        with zipfile.ZipFile(
            artifact_path,
            "r",
        ) as zf:
            return zf.read(
                archive_path
            )

    raise RuntimeError(
        "unsupported artifact format: "
        f"{artifact_path}"
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


def resolve_import_module(
    current_module: str,
    is_package_init: bool,
    node: ast.ImportFrom,
) -> str:
    if node.level == 0:
        return node.module or ""

    if is_package_init:
        package_parts = (
            current_module.split(".")
        )
    else:
        package_parts = (
            current_module
            .split(".")[:-1]
        )

    keep_count = (
        len(package_parts)
        - (
            int(node.level)
            - 1
        )
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


def collect_direct_definitions(
    tree: ast.Module,
    public_module: str,
) -> list[dict[str, Any]]:
    exports: list[
        dict[str, Any]
    ] = []

    for node in tree.body:
        if not isinstance(
            node,
            (
                ast.ClassDef,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        ):
            continue

        name = node.name

        if name.startswith("_"):
            continue

        if isinstance(
            node,
            ast.ClassDef,
        ):
            kind = "class"
        elif isinstance(
            node,
            ast.AsyncFunctionDef,
        ):
            kind = "async_function"
        else:
            kind = "function"

        exports.append(
            {
                "public_name":
                    name,

                "public_symbol":
                    (
                        f"{public_module}."
                        f"{name}"
                    ),

                "source_module":
                    public_module,

                "source_name":
                    name,

                "source_symbol":
                    (
                        f"{public_module}."
                        f"{name}"
                    ),

                "kind":
                    kind,

                "line":
                    node.lineno,

                "discovery_method":
                    "module_direct_definition",
            }
        )

    return exports


def collect_explicit_reexports(
    tree: ast.Module,
    public_module: str,
    is_package_init: bool,
    known_modules: set[str],
) -> list[dict[str, Any]]:
    exports: list[
        dict[str, Any]
    ] = []

    for node in tree.body:
        if not isinstance(
            node,
            ast.ImportFrom,
        ):
            continue

        if (
            node.level == 0
            and node.module
            == "__future__"
        ):
            continue

        source_module = (
            resolve_import_module(
                current_module=
                    public_module,

                is_package_init=
                    is_package_init,

                node=
                    node,
            )
        )

        for alias in node.names:
            if alias.name == "*":
                continue

            # Explicit X as X remains valid.
            #
            # For package __init__.py only,
            # also accept:
            #
            #   from submodule import X
            #
            # as an implicit same-name
            # re-export candidate.
            #
            # Renaming imports are still
            # excluded conservatively.
            if (
                alias.asname is not None
                and alias.asname
                != alias.name
            ):
                continue

            if alias.asname is not None:
                public_name = (
                    alias.asname
                )

                discovery_method = (
                    "module_same_name_"
                    "reexport"
                )
            else:
                if not is_package_init:
                    continue

                public_name = (
                    alias.name
                )

                discovery_method = (
                    "package_init_implicit_"
                    "same_name_reexport"
                )

            if public_name.startswith(
                "_"
            ):
                continue

            source_name = (
                alias.name
            )

            if source_module:
                source_symbol = (
                    f"{source_module}."
                    f"{source_name}"
                )
            else:
                source_symbol = (
                    source_name
                )

            # A bare import in package
            # __init__.py may expose a
            # child module rather than a
            # class/function symbol.
            #
            # Keep module objects out of
            # this minimal callable/class
            # API surface.
            if (
                alias.asname is None
                and source_symbol
                in known_modules
            ):
                continue

            exports.append(
                {
                    "public_name":
                        public_name,

                    "public_symbol":
                        (
                            f"{public_module}."
                            f"{public_name}"
                        ),

                    "source_module":
                        source_module,

                    "source_name":
                        source_name,

                    "source_symbol":
                        source_symbol,

                    "kind":
                        "reexport",

                    "line":
                        node.lineno,

                    "discovery_method":
                        discovery_method,
                }
            )

    return exports


def collect_public_module_surface(
    source_index_path: Path,
    public_module: str,
) -> dict[str, Any]:
    source_index = read_json(
        source_index_path
    )

    module_record = (
        find_module_record(
            source_index,
            public_module,
        )
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
        module_record.get(
            "archive_path",
            "",
        )
    ).strip()

    if not archive_path:
        raise RuntimeError(
            "module record has no "
            "archive_path"
        )

    data = read_archive_member(
        artifact_path,
        archive_path,
    )

    source = decode_python_source(
        data
    )

    tree = ast.parse(
        source,
        filename=(
            module_record.get(
                "logical_path"
            )
            or archive_path
        ),
    )

    is_package_init = bool(
        module_record.get(
            "is_package_init"
        )
    )

    direct = (
        collect_direct_definitions(
            tree=
                tree,

            public_module=
                public_module,
        )
    )

    known_modules = {
        str(row.get("module"))
        for row in source_index.get(
            "python_sources",
            [],
        )
        if (
            isinstance(row, dict)
            and row.get("module")
        )
    }

    reexports = (
        collect_explicit_reexports(
            tree=
                tree,

            public_module=
                public_module,

            is_package_init=
                is_package_init,

            known_modules=
                known_modules,
        )
    )

    exports_by_key: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for item in [
        *direct,
        *reexports,
    ]:
        key = (
            item["public_name"],
            item["source_symbol"],
        )

        exports_by_key[
            key
        ] = item

    exports = sorted(
        exports_by_key.values(),
        key=lambda item: (
            item["public_name"],
            item["source_symbol"],
        ),
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

        "public_module":
            public_module,

        "logical_path":
            module_record.get(
                "logical_path"
            ),

        "archive_path":
            archive_path,

        "is_package_init":
            is_package_init,

        "source_index_file":
            str(
                source_index_path
            ).replace(
                "\\",
                "/",
            ),

        "artifact_file":
            str(
                artifact_path
            ).replace(
                "\\",
                "/",
            ),

        "status":
            "resolved",

        "discovery_scope":
            (
                "top_level_public_"
                "definitions_and_explicit_"
                "same_name_reexports"
            ),

        "direct_definition_count":
            len(direct),

        "explicit_reexport_count":
            len(reexports),

        "public_api_count":
            len(exports),

        "exports":
            exports,

        "limitations": [
            (
                "Only top-level public "
                "class/function definitions "
                "are treated as direct APIs."
            ),
            (
                "Explicit same-name ImportFrom "
                "aliases are treated as "
                "re-exports; package __init__.py "
                "also permits implicit same-name "
                "imports when the imported target "
                "is not itself an indexed module."
            ),
            (
                "__all__ is not yet "
                "interpreted."
            ),
            (
                "Dynamic __getattr__ exports "
                "are not yet interpreted."
            ),
            (
                "Public constants and other "
                "assignment-based APIs are "
                "not included in v0."
            ),
            (
                "Deprecation/removal metadata "
                "and historical signatures "
                "are handled by later stages."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collect a conservative public "
            "API surface for one explicitly "
            "selected Python public module."
        )
    )

    parser.add_argument(
        "--source-index",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--public-module",
        required=True,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = (
        collect_public_module_surface(
            source_index_path=
                args.source_index,

            public_module=
                args.public_module.strip(),
        )
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
        "[OK] public module:",
        result["public_module"],
    )

    print(
        "[OK] package init:",
        result["is_package_init"],
    )

    print(
        "[OK] direct definitions:",
        result[
            "direct_definition_count"
        ],
    )

    print(
        "[OK] explicit reexports:",
        result[
            "explicit_reexport_count"
        ],
    )

    print(
        "[OK] public APIs:",
        result[
            "public_api_count"
        ],
    )

    print(
        "[OK] result saved to:",
        args.out,
    )


if __name__ == "__main__":
    main()
