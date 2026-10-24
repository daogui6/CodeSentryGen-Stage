"""Run the distributed core snapshot in an isolated, provider-free copy."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def verify_files(manifest: dict) -> None:
    for row in manifest["files"]:
        path = ROOT / row["path"]
        if not path.is_file():
            raise FileNotFoundError(f"Snapshot file missing: {row['path']}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != row["sha256"]:
            raise ValueError(f"Snapshot file changed: {row['path']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 10):
        raise SystemExit("Use Python 3.10; this snapshot was verified on CPython 3.10.20.")
    manifest_path = ROOT / "docs/STAGE_FILE_MANIFEST.json"
    manifest = read_json(manifest_path)
    verify_files(manifest)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = args.out_dir or Path("output/local_validation") / stamp
    out = out if out.is_absolute() else ROOT / out
    out.mkdir(parents=True, exist_ok=False)
    report = {
        "scope": "distributed_core_snapshot_offline_acceptance",
        "python": sys.version,
        "core_source_commit": manifest["core_source_commit"],
        "third_layer_source_commit": manifest["third_layer_source_commit"],
        "provider_calls": 0,
        "formal_experiment_started": False,
        "checks": [],
    }
    env = dict(os.environ)
    env.update({"PYTHONUTF8": "1", "PYTHONHASHSEED": "0", "DASHSCOPE_API_KEY": "", "PROVIDER_CALLS_AUTHORIZED": "0", "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": ""})
    try:
        with tempfile.TemporaryDirectory(prefix="codesentry-stage-") as raw:
            checkout = Path(raw) / "source"
            for row in manifest["files"]:
                target = checkout / row["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / row["path"], target)
            shutil.copyfile(manifest_path, checkout / "docs/STAGE_FILE_MANIFEST.json")

            def run(label: str, *arguments: str) -> str:
                result = subprocess.run([sys.executable, "-X", "utf8", *arguments], cwd=checkout, env=env, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                (out / f"{label}.log").write_text(result.stdout, encoding="utf-8")
                report["checks"].append({"name": label, "exit_code": result.returncode})
                print(f"[{'PASS' if result.returncode == 0 else 'FAIL'}] {label}", flush=True)
                if result.returncode:
                    print(result.stdout, flush=True)
                    raise RuntimeError(f"{label} failed; inspect {out / (label + '.log')}")
                return result.stdout

            tests = run("unit_tests", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v")
            match = re.search(r"Ran (\d+) tests", tests)
            report["unittest_count"] = int(match.group(1)) if match else None
            for package in sorted((checkout / "data/avcs_package_kb").glob("*.json")):
                run("kb_" + package.stem, "src/validate_avcs_package_kb.py", "--schema", "schemas/avcs_package_kb_schema_v0.json", "--kb", package.relative_to(checkout).as_posix(), "--repo-root", ".")
            if len(list((checkout / "data/avcs_package_kb").glob("*.json"))) != 6:
                raise ValueError("The snapshot must contain exactly the six reported package KBs")
            run("avcs_minimal", "src/check_avcs_minimal_pipeline.py")
            run("legacy_trigger", "src/check_avcs_trigger_rule_matching.py")
            fresh = "output/stage_acceptance/fresh_avcs"
            run("fresh_api_extraction", "src/extract_api_calls.py", "--code", "data/avcs_control_full_load.py", "--sample-id", "avcs_control_full_load", "--out", fresh + "/calls.json")
            run("fresh_api_constraints", "src/resolve_api_version_constraints.py", "--api-calls", fresh + "/calls.json", "--history", "config/avcs_api_history_seed.json", "--out", fresh + "/api.json")
            run("fresh_vulnerability_constraints", "src/resolve_vulnerability_constraints.py", "--distribution", "PyYAML", "--vulnerability", "config/avcs_vulnerability_seed.json", "--out", fresh + "/vulnerabilities.json")
            run("fresh_version_overlap", "src/evaluate_avcs_overlap.py", "--api-constraints", fresh + "/api.json", "--vulnerability-constraints", fresh + "/vulnerabilities.json", "--sample-records", "data/avcs_validation/avcs_validation_samples.jsonl", "--out", fresh + "/evaluation.json")
            run("fresh_avcs_cards", "src/build_avcs_risk_cards.py", "--evaluation", fresh + "/evaluation.json", "--out", fresh + "/cards.jsonl")
            run("fresh_legacy_trigger", "src/run_avcs_trigger_matcher.py", "--api-calls", fresh + "/calls.json", "--trigger-evidence", "output/pyyaml_pysec_2021_142_trigger_evidence_direct_rules_v0.json", "--distribution", "PyYAML", "--vulnerability-id", "PYSEC-2021-142", "--exposed-version", "5.3.1", "--out", fresh + "/trigger.json")
            api = read_json(checkout / fresh / "api.json")
            report["fresh_avcs"] = {"api_status": api["status"], "risk_card_count": len(read_jsonl(checkout / fresh / "cards.jsonl")), "legacy_seed_is_not_strict_exclusion_proof": True, "trigger_exposed_version_is_controlled_input": "5.3.1"}
            candidate = "output/step7_hitl_batch_v0/step7_pillow_ghsa_45hq_cxwh_f6vc/candidate.json"
            run("hitl_candidate", "src/validate_trigger_hitl_candidate.py", "--schema", "schemas/avcs_trigger_hitl_candidate_schema_v0.json", "--protocol", "schemas/avcs_trigger_eligibility_protocol_v0.json", "--candidate", candidate, "--repo-root", ".")
            gate = read_json(checkout / candidate)["review_gate"]
            if not (gate["review_required"] is True and gate["final_truth_created"] is False and gate["reviewer"] is None and gate["reviewed_at"] is None):
                raise ValueError("Candidate is no longer at the review-preparation boundary")
            proposal_path = "output/step7_batch_review_v0/batch_004_llm_proposals_v1/step7_pillow_ghsa_45hq_cxwh_f6vc/llm_proposal.json"
            run("proposal_schema", "-c", "import json;from pathlib import Path;from jsonschema import Draft202012Validator;s=json.loads(Path('schemas/avcs_trigger_llm_proposal_schema_v0.json').read_text(encoding='utf-8'));Draft202012Validator.check_schema(s);Draft202012Validator(s).validate(json.loads(Path(" + repr(proposal_path) + ").read_text(encoding='utf-8')));print('Proposal schema PASS; no model request or human conclusion created')")

            base = "output/stage_acceptance"
            run("sceg21_base", "src/build_sceg_ir_v21.py", "--samples", "data/samples/risk_seed_validation_dataset.jsonl", "--dependency-records", "output/risk_seed_validation_pilot_results.jsonl", "--code-dir", "data/risk_seed_validation_code_files", "--dataset-label", "stage_offline_control", "--out", base + "/base.json", "--dependency-projection-out", base + "/dependencies.jsonl")
            run("temporal", "src/enrich_temporal_status.py", "--input", base + "/dependencies.jsonl", "--output", base + "/temporal.jsonl", "--summary", base + "/temporal.md")
            run("reachability", "src/enrich_reachability_v2.py", "--input", base + "/temporal.jsonl", "--output", base + "/reachability.jsonl", "--summary", base + "/reachability.md", "--sceg-ir", base + "/base.json")
            run("risk_cards", "src/build_temporal_risk_cards.py", "--input", base + "/reachability.jsonl", "--output", base + "/risk_cards.jsonl", "--summary", base + "/risk_cards.md")
            normalize = "import json,sys;from pathlib import Path;sys.path.insert(0,'src');from risk_semantics_v21 import normalize_risk_card;p=Path('" + base + "');cards=[normalize_risk_card(json.loads(x),pipeline_origin='THO',generation_time_uncertainty_seconds=0) for x in (p/'risk_cards.jsonl').read_text(encoding='utf-8').splitlines() if x.strip()];(p/'risk_cards_v21.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\\n' for x in cards),encoding='utf-8');print('normalized Risk Cards:',len(cards))"
            run("risk_card_v21", "-c", normalize)
            run("sceg21_analyzed", "src/finalize_sceg_ir_v21.py", "--base-ir", base + "/base.json", "--tho-records", base + "/reachability.jsonl", "--avcs-dir", base + "/avcs", "--risk-cards", base + "/risk_cards_v21.jsonl", "--out", base + "/sceg.json")
            run("sceg_v0_compatibility", "src/build_sceg_v0.py", "--input", base + "/reachability.jsonl", "--risk-cards", base + "/risk_cards.jsonl", "--out", base + "/sceg_v0.jsonl", "--summary", base + "/sceg_v0.md", "--dataset-label", "stage_offline_control")
            rows = read_jsonl(checkout / base / "temporal.jsonl")
            cards = read_jsonl(checkout / base / "risk_cards_v21.jsonl")
            graph = read_json(checkout / base / "sceg.json")
            if len(rows) != 4 or len(cards) != 4:
                raise ValueError("Controlled THO/SCEG record count drift")
            run("sceg_schema", "-c", "import json,sys;from pathlib import Path;sys.path.insert(0,'src');from sceg_ir_v21 import verify_ir;from jsonschema import Draft202012Validator;g=json.loads(Path('" + base + "/sceg.json').read_text(encoding='utf-8'));verify_ir(g);schema=json.loads(Path('schemas/sceg_schema_v2_1.json').read_text(encoding='utf-8'));Draft202012Validator(schema).validate(g);print('SCEG 2.1 integrity and schema PASS')")
            report["controlled_tho_sceg"] = {"records": len(rows), "temporal_status_counts": dict(Counter(r["temporal_status_v2"] for r in rows)), "risk_cards": len(cards), "risk_channels": dict(Counter(c["channel"] for c in cards)), "risk_nodes": graph.get("analysis_summary", {}).get("risk_node_count")}
            replay = "import json,sys;from pathlib import Path;sys.path.insert(0,'src');from resolve_osv_package_catalog_constraints import resolve_catalog_constraints;files=sorted(Path('output/step7_osv_catalogs_v0').glob('*.json'));rows=[resolve_catalog_constraints(json.loads(p.read_text(encoding='utf-8')),p.stem) for p in files];counts=tuple(sum(r[k] for r in rows) for k in ('vulnerability_group_count','resolved_vulnerability_count','unresolved_vulnerability_count'));assert len(files)==11 and counts==(208,171,37),(len(files),counts);print(json.dumps({'packages':11,'groups':counts[0],'resolved':counts[1],'unresolved':counts[2]}))"
            report["osv_replay"] = json.loads(run("osv_replay", "-c", replay).strip())
            shutil.copytree(checkout / base, out / "controlled_outputs")
            verify_files(manifest)
            report["status"] = "PASS"
    except Exception as exc:
        report["status"] = "FAIL"
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        (out / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"STAGE OFFLINE VALIDATION PASS: {report['unittest_count']} tests; six KBs; AVCS; legacy Trigger; THO/SCEG 2.1; OSV 208/171/37")
    print(f"Report: {out / 'validation.json'}")


if __name__ == "__main__":
    main()
