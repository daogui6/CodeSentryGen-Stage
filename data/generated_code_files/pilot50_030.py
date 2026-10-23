from pathlib import Path

from docutils.core import publish_string


def convert_rst_to_html(rst_text: str) -> str:
    return publish_string(
        source=rst_text,
        writer_name="html",
    ).decode("utf-8")


def convert_rst_to_latex(rst_text: str) -> str:
    return publish_string(
        source=rst_text,
        writer_name="latex",
    ).decode("utf-8")


def save_converted_documents(rst_text: str, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    html_output = convert_rst_to_html(rst_text)
    latex_output = convert_rst_to_latex(rst_text)

    (output_dir / "document.html").write_text(html_output, encoding="utf-8")
    (output_dir / "document.tex").write_text(latex_output, encoding="utf-8")


if __name__ == "__main__":
    sample_rst = """
Sample Title
============

This is a short reStructuredText document.

Features
--------

* Convert to HTML
* Convert to LaTeX
* Save generated files
"""

    save_converted_documents(sample_rst, Path("converted_docs"))
    print("Converted documents saved in ./converted_docs")
