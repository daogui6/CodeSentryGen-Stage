from __future__ import annotations

import argparse
from pathlib import Path


def merge_files(input_paths: list[Path], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total_lines = 0

    with output_path.open("w", encoding="utf-8") as out:
        for path in input_paths:
            if not path.exists():
                raise FileNotFoundError(f"Input file not found: {path}")

            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    out.write(line + "\n")
                    total_lines += 1

    print(f"[OK] merged files: {len(input_paths)}")
    print(f"[OK] total records: {total_lines}")
    print(f"[OK] output saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="Output merged jsonl file")
    parser.add_argument("inputs", nargs="+", help="Input jsonl files")
    args = parser.parse_args()

    input_paths = [Path(p) for p in args.inputs]
    output_path = Path(args.out)

    merge_files(input_paths, output_path)


if __name__ == "__main__":
    main()