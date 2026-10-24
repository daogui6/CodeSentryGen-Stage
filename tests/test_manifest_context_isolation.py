from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from project_dependency_facts_v1 import (  # noqa: E402
    collect_project_dependency_facts,
)
from resolve_avcs_manifest_constraints import (  # noqa: E402
    resolve_manifest_constraints,
)
from run_step8_unified_avcs import build_package_coverage  # noqa: E402
from time_view_contract_v1 import build_time_view_contract  # noqa: E402


POLICY = ROOT / "config" / "package_identity_policy_v1.json"


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def resolve(root: Path) -> tuple[dict, dict]:
    facts = collect_project_dependency_facts(
        root,
        identity_policy_path=POLICY,
    )
    result = resolve_manifest_constraints(
        sample={"sample_id": "multi-project-controlled"},
        distribution="requests",
        project_facts_override=facts,
        identity_policy_path=POLICY,
    )
    return facts, result


def coverage_for(manifest: dict) -> dict:
    return build_package_coverage(
        kb={
            "kb_id": "controlled-kb",
            "vulnerability_catalog": [
                {
                    "vulnerability_id": "CVE-CONTROLLED",
                    "published_at": "2020-01-01T00:00:00Z",
                }
            ],
            "trigger_rules": [],
        },
        api_history_adapter={
            "status": "resolved",
            "scope_policy": "controlled_scope",
            "entries": [],
            "entry_count": 0,
            "scope_semantics": {
                "resolved_does_not_imply_package_wide_coverage": True,
            },
        },
        release_view={
            "knowledge_complete_to_requested_time": True,
            "release_evidence_complete": True,
            "snapshot_covers_requested_time": True,
        },
        filtered_calls={
            "api_call_count": 0,
            "syntax_parse_status": "parsed",
        },
        api_meta={
            "status": "resolved",
            "resolved_api_call_count": 0,
            "unresolved_api_call_count": 0,
        },
        manifest=manifest,
        constraint_satisfiability={
            "status": "not_applicable_unconstrained",
            "formal_negative_eligible": True,
        },
        findings=[],
        risk_cards=[],
        trigger_matches={},
        evaluation_time_view=build_time_view_contract(
            view_id="as_of_tg",
            generation_time="2020-01-01T00:00:00Z",
            evidence_cutoff="2020-01-01T00:00:00Z",
            evidence_snapshot_sha256="a" * 64,
            output_namespace="as_of_tg/manifest-context-test",
        ),
    )


class ManifestContextIsolationTests(unittest.TestCase):
    def assert_manifest_unknown_is_non_metric(self, manifest: dict) -> None:
        self.assertEqual(manifest["status"], "manifest_context_unresolved")
        coverage = coverage_for(manifest)
        self.assertEqual(coverage["main_metric_outcome"], "unknown_review")
        self.assertIs(coverage["main_metric_eligible"], False)
        self.assertIn(
            "manifest_status:manifest_context_unresolved",
            coverage["blocking_unknown_reasons"],
        )

    def test_nested_pyproject_local_install_binds_only_that_project(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "pyproject.toml",
                "[project]\nname='root'\ndependencies=['requests>=2.31']\n",
            )
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install ./plugin\n",
            )

            facts, result = resolve(project)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["specifier"], "<2")
        self.assertEqual(
            result["manifest"]["selected_manifest_files"],
            ["plugin/pyproject.toml"],
        )
        self.assertEqual(
            result["manifest"]["selected_install_target"],
            "plugin",
        )
        self.assertEqual(
            facts["installability_unresolved"],
            [],
        )

    def test_workflow_working_directory_resolves_project_dot(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/setup.cfg",
                "[metadata]\nname=plugin\n"
                "[options]\ninstall_requires=\n  requests<2\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - name: install plugin\n"
                "    working-directory: plugin\n"
                "    run: pip install .\n",
            )

            _, result = resolve(project)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["specifier"], "<2")
        self.assertEqual(
            result["manifest"]["selected_manifest_files"],
            ["plugin/setup.cfg"],
        )
        self.assertEqual(
            result["manifest"]["selected_install_target"],
            "plugin",
        )
        coverage = coverage_for(result)
        self.assertEqual(coverage["main_metric_outcome"], "formal_negative")
        self.assertIs(coverage["main_metric_eligible"], True)

    def test_two_local_project_install_targets_remain_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "app/pyproject.toml",
                "[project]\nname='app'\ndependencies=['requests>=2.31']\n",
            )
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - run: pip install ./app\n"
                "  - run: pip install ./plugin\n",
            )

            _, result = resolve(project)

        self.assertEqual(result["status"], "manifest_context_unresolved")
        self.assertEqual(result["constraint_kind"], "multiple_install_targets")
        self.assertEqual(
            result["manifest"]["available_install_targets"],
            ["app", "plugin"],
        )

    def test_shell_cd_local_project_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(project, "install.sh", "cd plugin && pip install .\n")

            facts = collect_project_dependency_facts(
                project,
                identity_policy_path=POLICY,
            )

        self.assertTrue(facts["installability_unresolved"])
        self.assertEqual(
            facts["installability_unresolved"][0]["reason"],
            "inline_shell_cd_not_resolved",
        )
        self.assertEqual(facts["installability"], {})

    def test_inline_workflow_cd_fails_closed_end_to_end(self) -> None:
        commands = (
            "cd plugin && pip install .",
            "cd plugin; pip install .",
        )
        for command in commands:
            with self.subTest(command=command):
                with tempfile.TemporaryDirectory() as raw_tmp:
                    project = Path(raw_tmp)
                    write(
                        project,
                        "pyproject.toml",
                        "[project]\nname='root'\ndependencies=['requests>=2.31']\n",
                    )
                    write(
                        project,
                        "plugin/pyproject.toml",
                        "[project]\nname='plugin'\ndependencies=['requests<2']\n",
                    )
                    write(
                        project,
                        ".github/workflows/ci.yml",
                        "steps:\n  - run: " + command + "\n",
                    )

                    facts, result = resolve(project)

                self.assertIn(
                    "inline_shell_cd_not_resolved",
                    {row.get("reason") for row in facts["installability_unresolved"]},
                )
                self.assertEqual(facts["installability"], {})
                self.assert_manifest_unknown_is_non_metric(result)

    def test_quoted_inline_workflow_cd_fails_closed(self) -> None:
        scalars = (
            '"cd plugin && pip install ."',
            "'cd plugin; pip install .'",
        )
        for scalar in scalars:
            with self.subTest(scalar=scalar):
                with tempfile.TemporaryDirectory() as raw_tmp:
                    project = Path(raw_tmp)
                    write(
                        project,
                        "pyproject.toml",
                        "[project]\nname='root'\ndependencies=['requests>=2.31']\n",
                    )
                    write(
                        project,
                        "plugin/pyproject.toml",
                        "[project]\nname='plugin'\ndependencies=['requests<2']\n",
                    )
                    write(
                        project,
                        ".github/workflows/ci.yml",
                        "steps:\n  - run: " + scalar + "\n",
                    )

                    facts, result = resolve(project)

                self.assertIn(
                    "inline_shell_cd_not_resolved",
                    {row.get("reason") for row in facts["installability_unresolved"]},
                )
                self.assertEqual(facts["installability"], {})
                self.assert_manifest_unknown_is_non_metric(result)

    def test_folded_workflow_cd_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "pyproject.toml",
                "[project]\nname='root'\ndependencies=['requests>=2.31']\n",
            )
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - name: install plugin\n"
                "    run: >-\n"
                "      cd plugin &&\n"
                "      pip install .\n",
            )

            facts, result = resolve(project)

        self.assertIn(
            "multiline_shell_cd_not_resolved",
            {row.get("reason") for row in facts["installability_unresolved"]},
        )
        self.assertEqual(facts["installability"], {})
        self.assert_manifest_unknown_is_non_metric(result)

    def test_inline_workflow_cd_with_dynamic_target_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "pyproject.toml",
                "[project]\nname='root'\ndependencies=['requests>=2.31']\n",
            )
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                'steps:\n  - run: cd "$SUBPROJECT" && pip install .\n',
            )

            facts, result = resolve(project)

        self.assertIn(
            "inline_shell_cd_not_resolved",
            {row.get("reason") for row in facts["installability_unresolved"]},
        )
        self.assertEqual(facts["installability"], {})
        self.assert_manifest_unknown_is_non_metric(result)

    def test_dynamic_setup_dependencies_fail_closed_for_local_install(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/setup.py",
                "from setuptools import setup\n"
                "deps = ['requests<2']\n"
                "setup(name='plugin', install_requires=deps)\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install ./plugin\n",
            )

            facts, result = resolve(project)

        self.assertIn(
            "unsupported_dynamic_install_requires",
            {
                row.get("reason")
                for row in facts["installability_unresolved"]
            },
        )
        self.assert_manifest_unknown_is_non_metric(result)

    def test_dynamic_pyproject_dependencies_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndynamic=['dependencies']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install ./plugin\n",
            )

            facts, result = resolve(project)

        self.assertIn(
            "unsupported_dynamic_dependencies",
            {
                row.get("reason")
                for row in facts["installability_unresolved"]
            },
        )
        self.assert_manifest_unknown_is_non_metric(result)

    def test_multiline_shell_cd_is_non_metric_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "pyproject.toml",
                "[project]\nname='root'\ndependencies=['requests>=2.31']\n",
            )
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - run: |\n"
                "      cd plugin\n"
                "      pip install .\n",
            )

            facts, result = resolve(project)

        self.assertIn(
            "multiline_shell_cd_not_resolved",
            {
                row.get("reason")
                for row in facts["installability_unresolved"]
            },
        )
        self.assert_manifest_unknown_is_non_metric(result)

    def test_variable_install_target_is_non_metric_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install $SUBPROJECT\n",
            )

            facts, result = resolve(project)

        self.assertIn(
            "dynamic_install_target_not_resolved",
            {
                row.get("reason")
                for row in facts["installability_unresolved"]
            },
        )
        self.assert_manifest_unknown_is_non_metric(result)

    def test_pipfile_alone_is_not_local_package_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/Pipfile",
                "[packages]\nrequests='<2'\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install ./plugin\n",
            )

            facts = collect_project_dependency_facts(
                project,
                identity_policy_path=POLICY,
            )

        self.assertIn(
            "local_project_packaging_metadata_missing",
            {
                row.get("reason")
                for row in facts["installability_unresolved"]
            },
        )
        self.assertEqual(facts["installability"], {})

    def test_local_project_extras_bind_to_project_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install './plugin[dev]'\n",
            )

            _, result = resolve(project)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["specifier"], "<2")
        self.assertEqual(
            result["manifest"]["selected_install_target"],
            "plugin",
        )

    def test_inherited_working_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(
                project,
                "plugin/pyproject.toml",
                "[project]\nname='plugin'\ndependencies=['requests<2']\n",
            )
            write(
                project,
                ".github/workflows/ci.yml",
                "defaults:\n"
                "  run:\n"
                "    working-directory: plugin\n"
                "steps:\n"
                "  - run: pip install .\n",
            )

            facts = collect_project_dependency_facts(
                project,
                identity_policy_path=POLICY,
            )

        self.assertIn(
            "workflow_inherited_working_directory_not_resolved",
            {
                row.get("reason")
                for row in facts["installability_unresolved"]
            },
        )
        self.assertEqual(facts["installability"], {})

    def test_nested_same_basename_manifests_do_not_intersect(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(project, "app/requirements.txt", "requests>=2.31\n")
            write(project, "plugin/requirements.txt", "requests<2\n")

            facts, result = resolve(project)

        contexts = {
            row["manifest_context_id"]
            for row in facts["manifests"]["requests"]
        }
        self.assertEqual(len(contexts), 2)
        self.assertEqual(result["status"], "manifest_context_unresolved")
        self.assertEqual(
            result["constraint_kind"],
            "multiple_default_manifest_contexts",
        )
        self.assertEqual(result["specifier"], "")
        self.assertEqual(
            result["manifest"]["context_selection"],
            "ambiguous_default_contexts",
        )

    def test_one_explicit_ci_target_selects_only_that_context(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(project, "app/requirements.txt", "requests>=2.31\n")
            write(project, "app/requirements.lock", "requests==2.31.0\n")
            write(project, "plugin/requirements.txt", "requests<2\n")
            write(project, "plugin/requirements.lock", "requests==1.26.0\n")
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n  - run: pip install -r app/requirements.txt\n",
            )

            _, result = resolve(project)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["constraint_kind"], "lockfile_exact_pin")
        self.assertEqual(result["specifier"], "==2.31.0")
        self.assertEqual(
            result["manifest"]["selected_install_target"],
            "app/requirements.txt",
        )
        self.assertEqual(
            result["manifest"]["selected_manifest_files"],
            ["app/requirements.txt"],
        )
        self.assertEqual(
            result["lockfile"]["source_path"],
            "app/requirements.lock",
        )

    def test_two_explicit_ci_targets_remain_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(project, "app/requirements.txt", "requests>=2.31\n")
            write(project, "plugin/requirements.txt", "requests<2\n")
            write(
                project,
                ".github/workflows/ci.yml",
                "steps:\n"
                "  - run: pip install -r app/requirements.txt\n"
                "  - run: pip install -r plugin/requirements.txt\n",
            )

            _, result = resolve(project)

        self.assertEqual(result["status"], "manifest_context_unresolved")
        self.assertEqual(
            result["constraint_kind"],
            "multiple_install_targets",
        )
        self.assertEqual(
            result["manifest"]["available_install_targets"],
            ["app/requirements.txt", "plugin/requirements.txt"],
        )

    def test_root_default_group_remains_distinct_from_dev_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(project, "requirements.txt", "requests>=2.31\n")
            write(project, "requirements-dev.txt", "requests<2\n")

            _, result = resolve(project)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["specifier"], ">=2.31")
        self.assertEqual(
            result["manifest"]["context_selection"],
            "single_default_context",
        )
        self.assertEqual(
            result["manifest"]["selected_manifest_files"],
            ["requirements.txt"],
        )

    def test_ambiguous_context_is_excluded_from_formal_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            project = Path(raw_tmp)
            write(project, "app/requirements.txt", "requests>=2.31\n")
            write(project, "plugin/requirements.txt", "requests<2\n")
            _, manifest = resolve(project)

        coverage = coverage_for(manifest)
        self.assertEqual(coverage["main_metric_outcome"], "unknown_review")
        self.assertIs(coverage["main_metric_eligible"], False)
        self.assertIn(
            "manifest_status:manifest_context_unresolved",
            coverage["blocking_unknown_reasons"],
        )


if __name__ == "__main__":
    unittest.main()
