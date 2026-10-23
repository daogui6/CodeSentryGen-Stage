from importlib import metadata
from dataclasses import dataclass


@dataclass
class PackageMetadata:
    name: str
    version: str
    author: str
    license: str


def read_package_metadata(package_name: str) -> PackageMetadata:
    try:
        meta = metadata.metadata(package_name)
        version = metadata.version(package_name)
    except metadata.PackageNotFoundError as exc:
        raise ValueError(f"Package not found: {package_name}") from exc

    return PackageMetadata(
        name=meta.get("Name", package_name),
        version=version,
        author=meta.get("Author", "UNKNOWN"),
        license=meta.get("License", "UNKNOWN"),
    )


def print_package_metadata(package_names: list[str]) -> None:
    for package_name in package_names:
        try:
            package_meta = read_package_metadata(package_name)
        except ValueError as exc:
            print(exc)
            continue

        print(f"Name: {package_meta.name}")
        print(f"Version: {package_meta.version}")
        print(f"Author: {package_meta.author}")
        print(f"License: {package_meta.license}")
        print("-" * 40)


if __name__ == "__main__":
    print_package_metadata(["pip", "setuptools", "wheel"])
