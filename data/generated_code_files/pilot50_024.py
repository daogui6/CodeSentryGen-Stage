from pathlib import Path

from jinja2 import Template


README_TEMPLATE = Template("""# {{ package_name }}

{{ description }}

## Installation

Run this command to install the package locally:

    pip install .

## License

{{ license_name }}
""")


SETUP_TEMPLATE = Template("""from setuptools import setup, find_packages

setup(
    name="{{ package_name }}",
    version="{{ version }}",
    author="{{ author }}",
    license="{{ license_name }}",
    description="{{ description }}",
    packages=find_packages(),
    include_package_data=True,
)
""")


def create_package_project(
    base_dir: Path,
    package_name: str,
    version: str,
    author: str,
    license_name: str,
    description: str,
) -> None:
    project_dir = base_dir / package_name
    module_dir = project_dir / package_name.replace("-", "_")

    module_dir.mkdir(parents=True, exist_ok=True)

    readme_content = README_TEMPLATE.render(
        package_name=package_name,
        description=description,
        license_name=license_name,
    )

    setup_content = SETUP_TEMPLATE.render(
        package_name=package_name,
        version=version,
        author=author,
        license_name=license_name,
        description=description,
    )

    (project_dir / "README.md").write_text(readme_content, encoding="utf-8")
    (project_dir / "setup.py").write_text(setup_content, encoding="utf-8")
    (project_dir / "MANIFEST.in").write_text(
        "include README.md\nrecursive-include * *.txt *.md\n",
        encoding="utf-8",
    )
    (module_dir / "__init__.py").write_text(
        f'"""Generated package {package_name}."""\n__version__ = "{version}"\n',
        encoding="utf-8",
    )


if __name__ == "__main__":
    create_package_project(
        base_dir=Path("generated_packages"),
        package_name="demo-package",
        version="0.1.0",
        author="Example Author",
        license_name="MIT",
        description="A simple package skeleton generated from templates.",
    )

    print("Package project created under ./generated_packages/demo-package")
