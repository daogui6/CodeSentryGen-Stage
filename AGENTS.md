# Repository Guidelines

## Project Structure & Module Organization

- `src/` contains the Python pipeline: prompt generation, dependency extraction, import-to-distribution normalization, PyPI evidence, `temporal_status_v2`, `install_reachability_v2`, and Risk Card generation.
- `config/` stores mappings and reference lists. Never commit credentials; load API keys from environment variables.
- `data/` contains prompts, generated code, requirements sidecars, controlled seeds, hard negatives, and build evidence.
- `scripts/` provides PowerShell validation workflows. `output/` contains historical experiment artifacts; `archive/` contains retired implementations and results.
- `schemas/`, `reference/`, and `docs/` hold schemas, upstream datasets, and research notes.

## Build, Test, and Development Commands

Install dependencies with `pip install -r requirements.txt`. Run the base detector with `python src/run_pilot.py`. Run THO regression validation with `powershell -ExecutionPolicy Bypass -File .\scripts\run_all_tho_validation.ps1`; run THO plus SCEG validation with `powershell -ExecutionPolicy Bypass -File .\scripts\run_full_validation_with_sceg.ps1`. Use focused checks such as `python src/check_import_path_mapping.py` after mapping changes.

## Coding Style & Compatibility

Use four-space indentation, `snake_case` for functions and files, `PascalCase` for classes, type hints where practical, and `pathlib.Path` for paths. Keep existing JSON/JSONL fields and CLI interfaces compatible whenever possible. Avoid broad refactors without a concrete reason. Never overwrite historical files in `output/`; use dataset- or run-specific names.

## Testing & Evidence Integrity

Run the relevant focused test or regression workflow after every code change. Never fabricate command output, test results, or experiment data. If a test fails, preserve and report the failure and its cause. For import-to-distribution mapping, `temporal_status_v2`, `install_reachability`, manifest-only mismatch, or Risk Cards, document field meanings, evidence semantics, and likely false-positive/false-negative risks.

## Collaboration Workflow

Default to Chinese for communication and explanations. Before changing code, read the relevant files and present a plan. For complex tasks, analyze alternatives and wait for user confirmation before implementation. After each code change, explain what it implements, why it is needed, where it sits in the CodeSentry-Gen pipeline, its inputs, outputs, key logic, compatibility impact, and detection risks.

End every task with: modified files, major changes, commands executed, test results, and remaining issues.

## Commits & Pull Requests

This checkout has no accessible Git history, so no repository-specific convention can be verified. Use concise imperative commits, for example `fix: preserve reachability evidence`. PRs should describe scope, affected pipeline stages and fields, validation commands/results, compatibility risks, and any intentionally unchanged historical outputs.
