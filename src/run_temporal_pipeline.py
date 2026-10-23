import argparse
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def run_cmd(cmd: list[str]):
    print("\n运行命令：")
    print(" ".join(cmd))

    result = subprocess.run(cmd, cwd=BASE_DIR)

    if result.returncode != 0:
        raise RuntimeError(f"命令执行失败，退出码：{result.returncode}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="一键运行 CodeSentryGen pilot temporal pipeline"
    )

    parser.add_argument(
        "--with-seed",
        action="store_true",
        help="是否运行包含 created_after_tg controlled seed 的流程"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.with_seed:
        reference_input = "output/pilot_reference_check_with_temporal_seed.jsonl"
        temporal_output = "output/pilot_temporal_enriched_with_seed.jsonl"
        temporal_summary = "output/pilot_temporal_summary_with_seed.md"
        risk_output = "output/temporal_risk_cards_v2_with_seed.jsonl"
        risk_summary = "output/temporal_risk_summary_with_seed.md"
    else:
        reference_input = "output/pilot_reference_check.jsonl"
        temporal_output = "output/pilot_temporal_enriched.jsonl"
        temporal_summary = "output/pilot_temporal_summary.md"
        risk_output = "output/temporal_risk_cards_v2.jsonl"
        risk_summary = "output/temporal_risk_summary.md"

    print("=" * 80)
    print("CodeSentryGen pilot temporal pipeline")
    print("模式：", "with created_after_tg seed" if args.with_seed else "default pilot_v0")
    print("=" * 80)

    run_cmd([
        PYTHON,
        "src/enrich_temporal_status.py",
        "--input", reference_input,
        "--output", temporal_output,
        "--summary", temporal_summary,
    ])

    run_cmd([
        PYTHON,
        "src/build_temporal_risk_cards.py",
        "--input", temporal_output,
        "--output", risk_output,
        "--summary", risk_summary,
    ])

    print("\n全部流程运行完成。")
    print("temporal summary：", temporal_summary)
    print("risk summary：", risk_summary)


if __name__ == "__main__":
    main()