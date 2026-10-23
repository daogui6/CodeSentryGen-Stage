from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import requests

from normalizer import pep503_normalize
from resolve_avcs_release_history import load_pypi_json


SCHEMA_VERSION = "avcs_pypi_release_source_index_v0.1"
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024


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


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file_obj:
        for chunk in iter(
            lambda: file_obj.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def artifact_priority(
    file_info: dict[str, Any],
) -> tuple[int, int, str]:
    packagetype = str(
        file_info.get(
            "packagetype",
            "",
        )
    )

    filename = str(
        file_info.get(
            "filename",
            "",
        )
    )

    yanked = bool(
        file_info.get(
            "yanked",
            False,
        )
    )

    if packagetype == "sdist":
        type_priority = 0
    elif packagetype == "bdist_wheel":
        type_priority = 1
    else:
        type_priority = 2

    return (
        type_priority,
        1 if yanked else 0,
        filename.lower(),
    )


def choose_artifact(
    release_files: list[dict[str, Any]],
) -> dict[str, Any]:
    supported = []

    for file_info in release_files:
        if not isinstance(
            file_info,
            dict,
        ):
            continue

        filename = str(
            file_info.get(
                "filename",
                "",
            )
        ).lower()

        packagetype = str(
            file_info.get(
                "packagetype",
                "",
            )
        )

        if (
            packagetype == "sdist"
            and filename.endswith(
                (
                    ".tar.gz",
                    ".tgz",
                    ".tar.bz2",
                    ".tar.xz",
                    ".zip",
                )
            )
        ):
            supported.append(
                file_info
            )
            continue

        if (
            packagetype == "bdist_wheel"
            and filename.endswith(".whl")
        ):
            supported.append(
                file_info
            )

    if not supported:
        raise RuntimeError(
            "No supported sdist or wheel "
            "artifact found for release."
        )

    supported.sort(
        key=artifact_priority
    )

    # v0 优先选择 sdist。
    #
    # 原因：
    # API History 的目标是分析历史源码，
    # sdist 通常比平台相关 wheel 更适合作为
    # 静态源码证据。
    return supported[0]


def artifact_cache_path(
    artifact_cache_dir: Path,
    distribution: str,
    version: str,
    filename: str,
) -> Path:
    return (
        artifact_cache_dir
        / pep503_normalize(distribution)
        / version
        / filename
    )


def download_artifact(
    file_info: dict[str, Any],
    cache_path: Path,
    refresh: bool,
    timeout: int,
) -> tuple[str, Path]:
    digests = file_info.get(
        "digests",
        {},
    )

    if not isinstance(
        digests,
        dict,
    ):
        digests = {}

    expected_sha256 = str(
        digests.get(
            "sha256",
            "",
        )
    ).strip().lower()

    if (
        cache_path.exists()
        and not refresh
    ):
        actual_sha256 = sha256_file(
            cache_path
        )

        if (
            expected_sha256
            and actual_sha256
            != expected_sha256
        ):
            raise RuntimeError(
                "Cached artifact SHA256 "
                "does not match PyPI metadata."
            )

        return (
            "cache",
            cache_path,
        )

    url = str(
        file_info.get(
            "url",
            "",
        )
    ).strip()

    if not url:
        raise RuntimeError(
            "Selected PyPI artifact "
            "has no download URL."
        )

    response = requests.get(
        url,
        timeout=timeout,
        stream=True,
    )

    response.raise_for_status()

    content_length_text = (
        response.headers.get(
            "Content-Length"
        )
    )

    if content_length_text:
        try:
            content_length = int(
                content_length_text
            )
        except ValueError:
            content_length = None

        if (
            content_length is not None
            and content_length
            > MAX_ARTIFACT_BYTES
        ):
            raise RuntimeError(
                "Artifact is larger than "
                "the v0 safety limit."
            )

    cache_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = cache_path.with_suffix(
        cache_path.suffix + ".part"
    )

    downloaded_bytes = 0

    try:
        with temp_path.open(
            "wb"
        ) as file_obj:
            for chunk in response.iter_content(
                chunk_size=1024 * 1024
            ):
                if not chunk:
                    continue

                downloaded_bytes += len(
                    chunk
                )

                if (
                    downloaded_bytes
                    > MAX_ARTIFACT_BYTES
                ):
                    raise RuntimeError(
                        "Artifact download exceeded "
                        "the v0 safety limit."
                    )

                file_obj.write(chunk)

        actual_sha256 = sha256_file(
            temp_path
        )

        if (
            expected_sha256
            and actual_sha256
            != expected_sha256
        ):
            raise RuntimeError(
                "Downloaded artifact SHA256 "
                "does not match PyPI metadata."
            )

        temp_path.replace(
            cache_path
        )

    finally:
        if temp_path.exists():
            temp_path.unlink()

    return (
        "network",
        cache_path,
    )


def list_python_members(
    artifact_path: Path,
) -> list[str]:
    lower_name = (
        artifact_path.name.lower()
    )

    members: list[str] = []

    if (
        lower_name.endswith(".whl")
        or lower_name.endswith(".zip")
    ):
        with zipfile.ZipFile(
            artifact_path
        ) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue

                name = info.filename.replace(
                    "\\",
                    "/",
                )

                if name.endswith(".py"):
                    members.append(name)

    elif lower_name.endswith(
        (
            ".tar.gz",
            ".tgz",
            ".tar.bz2",
            ".tar.xz",
        )
    ):
        with tarfile.open(
            artifact_path,
            mode="r:*",
        ) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue

                name = member.name.replace(
                    "\\",
                    "/",
                )

                if name.endswith(".py"):
                    members.append(name)

    else:
        raise RuntimeError(
            "Unsupported artifact format: "
            f"{artifact_path.name}"
        )

    return sorted(
        set(members)
    )


def strip_archive_prefix(
    member_paths: list[str],
) -> list[tuple[str, str]]:
    if not member_paths:
        return []

    parts_rows = [
        PurePosixPath(path).parts
        for path in member_paths
    ]

    first_parts = {
        parts[0]
        for parts in parts_rows
        if parts
    }

    # Common sdist layout:
    #
    # PyJWT-0.4.3/jwt/api.py
    #
    # Strip the outer archive directory.
    strip_first = (
        len(first_parts) == 1
        and all(
            len(parts) >= 2
            for parts in parts_rows
        )
    )

    logical_parts_rows = [
        list(
            parts[1:]
            if strip_first
            else parts
        )
        for parts in parts_rows
    ]

    # Known source-container layouts.
    #
    # src/<package>/...
    # is already supported historically.
    #
    # For lib/<package>/..., be conservative:
    # strip "lib" only when lib itself is not a
    # Python package, while an immediate child is.
    #
    # This avoids corrupting a genuine package:
    #
    # lib/__init__.py
    source_container_roots = {
        "src",
    }

    lib_is_python_package = any(
        parts == [
            "lib",
            "__init__.py",
        ]
        for parts in logical_parts_rows
    )

    lib_contains_python_package = any(
        len(parts) == 3
        and parts[0] == "lib"
        and parts[1].isidentifier()
        and parts[2] == "__init__.py"
        for parts in logical_parts_rows
    )

    if (
        lib_contains_python_package
        and not lib_is_python_package
    ):
        source_container_roots.add(
            "lib"
        )

    results = []

    for (
        member_path,
        logical_parts,
    ) in zip(
        member_paths,
        logical_parts_rows,
    ):
        logical_parts = list(
            logical_parts
        )

        if (
            logical_parts
            and logical_parts[0]
            in source_container_roots
        ):
            logical_parts = (
                logical_parts[1:]
            )

        logical_path = (
            PurePosixPath(
                *logical_parts
            ).as_posix()
            if logical_parts
            else ""
        )

        results.append(
            (
                member_path,
                logical_path,
            )
        )

    return results

def module_name_from_path(
    logical_path: str,
) -> tuple[str | None, bool]:
    path = PurePosixPath(
        logical_path
    )

    if path.suffix != ".py":
        return None, False

    parts = list(
        path.parts
    )

    if not parts:
        return None, False

    filename = parts[-1]

    if filename == "__init__.py":
        module_parts = parts[:-1]
        is_package_init = True
    else:
        module_parts = (
            parts[:-1]
            + [path.stem]
        )
        is_package_init = False

    if not module_parts:
        return None, is_package_init

    # setup.py、tests 中带非法 Python module
    # 名称的路径不强行转换。
    if any(
        not part.isidentifier()
        for part in module_parts
    ):
        return None, is_package_init

    return (
        ".".join(module_parts),
        is_package_init,
    )


def build_source_index(
    artifact_path: Path,
) -> dict[str, Any]:
    member_paths = list_python_members(
        artifact_path
    )

    indexed_sources = []
    module_count = 0

    for (
        archive_path,
        logical_path,
    ) in strip_archive_prefix(
        member_paths
    ):
        (
            module_name,
            is_package_init,
        ) = module_name_from_path(
            logical_path
        )

        if module_name:
            module_count += 1

        indexed_sources.append(
            {
                "archive_path":
                    archive_path,
                "logical_path":
                    logical_path,
                "module":
                    module_name,
                "is_package_init":
                    is_package_init,
            }
        )

    return {
        "python_source_count":
            len(indexed_sources),
        "importable_module_count":
            module_count,
        "python_sources":
            indexed_sources,
    }


def collect_release_source_index(
    distribution: str,
    version: str,
    registry_cache_dir: Path,
    artifact_cache_dir: Path,
    refresh: bool,
    timeout: int,
) -> dict[str, Any]:
    (
        project_data,
        metadata_source,
        metadata_cache_path,
    ) = load_pypi_json(
        distribution=distribution,
        cache_dir=registry_cache_dir,
        refresh=refresh,
        timeout=timeout,
    )

    releases = project_data.get(
        "releases",
        {},
    )

    if not isinstance(
        releases,
        dict,
    ):
        raise RuntimeError(
            "PyPI project metadata has "
            "no releases object."
        )

    release_files = releases.get(
        version
    )

    if not isinstance(
        release_files,
        list,
    ):
        raise RuntimeError(
            "PyPI release version not found: "
            f"{distribution} {version}"
        )

    if not release_files:
        raise RuntimeError(
            "PyPI release has no files: "
            f"{distribution} {version}"
        )

    selected = choose_artifact(
        release_files
    )

    filename = str(
        selected.get(
            "filename",
            "",
        )
    )

    if not filename:
        raise RuntimeError(
            "Selected artifact "
            "has no filename."
        )

    cache_path = artifact_cache_path(
        artifact_cache_dir=
            artifact_cache_dir,
        distribution=
            distribution,
        version=
            version,
        filename=
            filename,
    )

    (
        artifact_source,
        artifact_path,
    ) = download_artifact(
        file_info=selected,
        cache_path=cache_path,
        refresh=refresh,
        timeout=timeout,
    )

    actual_sha256 = sha256_file(
        artifact_path
    )

    digests = selected.get(
        "digests",
        {},
    )

    if not isinstance(
        digests,
        dict,
    ):
        digests = {}

    expected_sha256 = str(
        digests.get(
            "sha256",
            "",
        )
    ).strip().lower()

    source_index = build_source_index(
        artifact_path
    )

    return {
        "schema_version":
            SCHEMA_VERSION,
        "ecosystem":
            "pypi",
        "distribution":
            distribution,
        "normalized_distribution":
            pep503_normalize(
                distribution
            ),
        "version":
            version,
        "registry_source":
            "PyPI JSON API",
        "registry_data_source":
            metadata_source,
        "registry_cache_file":
            str(
                metadata_cache_path
            ).replace(
                "\\",
                "/",
            ),
        "artifact": {
            "filename":
                filename,
            "packagetype":
                selected.get(
                    "packagetype"
                ),
            "url":
                selected.get(
                    "url"
                ),
            "yanked":
                bool(
                    selected.get(
                        "yanked",
                        False,
                    )
                ),
            "artifact_data_source":
                artifact_source,
            "cache_file":
                str(
                    artifact_path
                ).replace(
                    "\\",
                    "/",
                ),
            "sha256":
                actual_sha256,
            "pypi_expected_sha256":
                expected_sha256,
            "sha256_verified":
                (
                    not expected_sha256
                    or actual_sha256
                    == expected_sha256
                ),
        },
        **source_index,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch one historical PyPI release "
            "artifact and build a static Python "
            "source/module index for AVCS API "
            "History collection."
        )
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--version",
        required=True,
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
        "--refresh",
        action="store_true",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError(
            "--timeout must be positive."
        )

    result = collect_release_source_index(
        distribution=args.distribution,
        version=args.version,
        registry_cache_dir=
            args.registry_cache_dir,
        artifact_cache_dir=
            args.artifact_cache_dir,
        refresh=args.refresh,
        timeout=args.timeout,
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
        f"[OK] registry data: "
        f"{result['registry_data_source']}"
    )

    print(
        f"[OK] artifact: "
        f"{result['artifact']['filename']}"
    )

    print(
        f"[OK] artifact data: "
        f"{result['artifact']['artifact_data_source']}"
    )

    print(
        f"[OK] SHA256 verified: "
        f"{result['artifact']['sha256_verified']}"
    )

    print(
        f"[OK] Python sources: "
        f"{result['python_source_count']}"
    )

    print(
        f"[OK] importable modules: "
        f"{result['importable_module_count']}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()