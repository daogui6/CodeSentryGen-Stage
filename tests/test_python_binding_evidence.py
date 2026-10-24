from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from extract_api_calls import extract_api_calls  # noqa: E402
from extractor import extract_imports_from_code  # noqa: E402
from package_identity_v1 import PackageIdentityService  # noqa: E402
from run_avcs_trigger_matcher import match_trigger_entry  # noqa: E402
from run_step8_unified_avcs import build_package_coverage, filter_api_call_evidence  # noqa: E402
from run_codesentry_gen_e2e import summarize_avcs_coverage  # noqa: E402
from sceg_ir_v21 import (  # noqa: E402
    api_call_evidence_for_sample, build_base_ir, distributions_for_sample,
    project_dependency_records, read_json, verify_ir, write_json, write_jsonl,
)
from test_named_time_view_end_to_end import contract, write_coverage_sample  # noqa: E402


class PythonBindingEvidenceTests(unittest.TestCase):
    def evidence(self, code: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.py"
            path.write_text(code, encoding="utf-8")
            return extract_api_calls(path)

    def canonical(self, root: Path, code: str, *, omit_dependencies: bool = False) -> dict:
        code_dir = root / "code"
        code_dir.mkdir()
        (code_dir / "sample.py").write_text(code, encoding="utf-8")
        write_jsonl(root / "samples.jsonl", [{
            "sample_id": "sample", "model": "controlled", "ecosystem": "pypi",
            "language": "python", "prompt_id": "controlled", "generated_code": code,
            "generation_time": "2026-01-01T00:00:00Z", "requirements_text": "",
            "generation_error": "",
        }])
        identity_service = PackageIdentityService()
        records = []
        if not omit_dependencies:
            for entity in extract_imports_from_code(code, file_name="sample.py"):
                identity = identity_service.resolve(raw_name=entity.raw_name, source_type="import",
                                                    import_path=entity.import_path)
                records.append({"sample_id": "sample", "generation_time": "2026-01-01T00:00:00Z",
                    "raw_name": entity.raw_name, "import_path": entity.import_path,
                    "source_type": "import", "package": identity.normalized_distribution,
                    "package_identity": identity.to_dict(),
                    "location": {"file": entity.file, "line": entity.line}, "code_parse_status": "ok"})
        write_jsonl(root / "records.jsonl", records)
        ir = build_base_ir(samples_path=root / "samples.jsonl",
                           dependency_records_path=root / "records.jsonl",
                           code_dir=code_dir, mapping_path=ROOT / "config/import_mapping.json",
                           dataset_label="binding-controlled")
        verify_ir(ir)
        return ir

    def coverage(self, calls: dict, *, positive: bool = False) -> dict:
        time_view = contract("as_of_tg")
        return build_package_coverage(
            kb={"kb_id": "controlled", "vulnerability_catalog": [
                {"vulnerability_id": "CVE-CONTROLLED", "published_at": "2025-01-01T00:00:00Z"}],
                "trigger_rules": []},
            api_history_adapter={"status": "resolved", "scope_policy": "controlled",
                "entries": [], "entry_count": 0, "scope_semantics": {
                    "resolved_does_not_imply_package_wide_coverage": True}},
            release_view={"knowledge_complete_to_requested_time": True,
                          "release_evidence_complete": True, "snapshot_covers_requested_time": True},
            filtered_calls=calls, api_meta={"status": "resolved", "resolved_api_call_count": 0,
                                           "unresolved_api_call_count": 0},
            manifest={"status": "resolved", "constraint_kind": "version_specifier"},
            constraint_satisfiability={"status": "satisfiable", "formal_negative_eligible": True},
            findings=[], risk_cards=[{"type": "api_induced_vulnerable_dependency", "channel": "formal",
                "formal_eligible": True, "evaluation_time_view": copy.deepcopy(time_view)}] if positive else [],
            trigger_matches={}, evaluation_time_view=time_view,
        )

    def test_shadowing_and_source_order_are_unknown_instead_of_confirmed_api(self) -> None:
        cases = (
            "import yaml\ndef f(yaml): return yaml.load(data)\n",
            "import yaml\nyaml = custom\nyaml.load(data)\n",
            "import yaml\ndef f():\n yaml.load(data)\n yaml = custom\n",
            "yaml.load(data)\nimport yaml\n",
            "import yaml\nif cond: yaml = custom\nyaml.load(data)\n",
            "import yaml\n(lambda yaml: yaml.load(data))(custom)\n",
            "import yaml\n[yaml.load(data) for yaml in items]\n",
            "import yaml\ndef f(): return yaml.load(data)\nyaml = custom\n",
            "import yaml\nexec(text)\nyaml.load(data)\n",
            "import yaml\ndef f(): return yaml.load(data)\nexec(text)\n",
            "import yaml\ndef f():\n global yaml\n yaml = custom\ndef g(): return yaml.load(data)\n",
            "import yaml\nmatch data:\n case {'k': item, **yaml}: pass\nyaml.load(data)\n",
            "import yaml\ntry: work()\nexcept Exception as yaml: yaml.load(data)\n",
            "import yaml\n[(yaml := custom) for item in items]\nyaml.load(data)\n",
            "import yaml\nyaml.load = custom\nimport yaml\nyaml.load(data)\n",
        )
        for code in cases:
            with self.subTest(code=code):
                result = self.evidence(code)
                self.assertFalse(result["api_calls"])
                self.assertTrue(result["binding_unresolved"])
                self.assertEqual(result["binding_unresolved"][0]["candidate_distributions"], ["pyyaml"])

    def test_nested_imports_do_not_leak_and_binding_kind_replacement_is_ordered(self) -> None:
        result = self.evidence("import requests\ndef f():\n import yaml as requests\n requests.load(data)\nrequests.get(url)\n")
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["yaml.load", "requests.get"])
        result = self.evidence("import yaml as value\nfrom requests import get as value\nvalue(url)\n")
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["requests.get"])
        result = self.evidence("import requests as value, yaml as value\nvalue.load(data)\n")
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["yaml.load"])

    def test_relative_imports_are_local_at_both_dependency_and_api_extraction(self) -> None:
        for code in ("from .yaml import load\nload(data)\n", "from ..requests import get\nget(url)\n"):
            with self.subTest(code=code):
                self.assertFalse(extract_imports_from_code(code))
                self.assertFalse(self.evidence(code)["api_calls"])

    def test_simple_same_scope_receivers_and_stable_function_imports_remain_supported(self) -> None:
        for code in (
            "import urllib3\nhttp=urllib3.PoolManager(retries=0); http.request('GET', url)\n",
            "def f():\n import urllib3\n http=urllib3.PoolManager(retries=0)\n http.request('GET', url)\n",
        ):
            with self.subTest(code=code):
                result = self.evidence(code)
                self.assertEqual([row["api_symbol"] for row in result["api_calls"]],
                                 ["urllib3.PoolManager", "urllib3.PoolManager.request"])
                self.assertEqual(result["api_calls"][1]["receiver_provenance"]["producer_call_shape"]
                                 ["keyword_arg_values"]["retries"]["literal_value"], 0)
        result = self.evidence("import yaml\ndef f(data): return yaml.load(data, Loader=yaml.SafeLoader)\n")
        self.assertEqual(result["api_calls"][0]["call_shape"]["keyword_arg_values"]["Loader"]
                         ["resolved_symbol"], "yaml.SafeLoader")

    def test_class_methods_skip_class_namespace_and_argument_rebinding_loses_value_proof(self) -> None:
        result = self.evidence("import requests\nclass C:\n import yaml as requests\n def f(self): return requests.get(url)\n")
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["requests.get"])
        result = self.evidence("import yaml\nyaml.load((yaml := custom), Loader=yaml.SafeLoader)\n")
        self.assertIsNone(result["api_calls"][0]["call_shape"]["keyword_arg_values"]["Loader"]["resolved_symbol"])

    def test_unknown_binding_survives_shared_ir_and_cannot_enter_negative_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ir = self.canonical(root, "import yaml\ndef f(yaml): return yaml.load(data)\n")
            self.assertFalse(any(node["type"] == "APICall" for node in ir["nodes"]))
            projected = api_call_evidence_for_sample(ir, "sample")
            calls = filter_api_call_evidence(projected, "pyyaml")
            self.assertTrue(calls["binding_unresolved"])
            self.assertFalse(filter_api_call_evidence(projected, "requests")["binding_unresolved"])
            coverage = self.coverage(calls)
            self.assertEqual(coverage["main_metric_outcome"], "unknown_review")
            self.assertFalse(coverage["main_metric_eligible"])
            self.assertIn("api_binding_unresolved", coverage["blocking_unknown_reasons"])
            sample_dir = root / "avcs/samples/sample"
            write_coverage_sample(sample_dir, coverage)
            self.assertEqual(summarize_avcs_coverage([sample_dir])["formal_metric_eligible_count"], 0)
            # An independently confirmed high finding still dominates unknown.
            self.assertEqual(self.coverage(calls, positive=True)["main_metric_outcome"], "formal_positive")

    def test_python_comments_strings_and_prints_are_never_install_command_nodes(self) -> None:
        for code in ("# pip install ghost-package\n", "text='pip install ghost-package'\n",
                     "print('pip install ghost-package')\n", "print('uv add ghost-package')\n",
                     "print('poetry add ghost-package')\n"):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                ir = self.canonical(Path(tmp), code)
                self.assertFalse(any(node["type"] == "InstallCommand" for node in ir["nodes"]))
                self.assertNotIn("ghost-package", distributions_for_sample(ir, "sample",
                    node_types={"InstallCommand", "APICall", "ManifestDep", "Import"}, avcs_candidates_only=True))

    def test_runtime_function_and_variable_annotations_have_lexical_evidence(self) -> None:
        cases = (
            "import yaml\ndef f(value: yaml.safe_load(data)): pass\n",
            "import yaml\ndef f() -> yaml.safe_load(data): pass\n",
            "import yaml\ndef f(*args: yaml.safe_load(data)): pass\n",
            "import yaml\nasync def f(**kwargs: yaml.safe_load(data)): pass\n",
            "import yaml\nvalue: yaml.safe_load(data)\n",
            "import yaml\nclass C:\n value: yaml.safe_load(data)\n",
        )
        for code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                ir = self.canonical(Path(tmp), code)
                calls = api_call_evidence_for_sample(ir, "sample")
                self.assertEqual([row["api_symbol"] for row in calls["api_calls"]], ["yaml.safe_load"])
                self.assertFalse(calls["binding_unresolved"])

    def test_nonexecuting_annotations_never_create_api_evidence(self) -> None:
        cases = (
            "from __future__ import annotations\nimport yaml\ndef f(value: yaml.load(data)): pass\n",
            "from __future__ import annotations\nimport yaml\ndef f() -> yaml.load(data): pass\n",
            "from __future__ import annotations\nimport yaml\nvalue: yaml.load(data)\n",
            "import yaml\ndef f():\n value: yaml.load(data)\n",
        )
        for code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                ir = self.canonical(Path(tmp), code)
                calls = api_call_evidence_for_sample(ir, "sample")
                self.assertFalse(calls["api_calls"])
                self.assertFalse(calls["binding_unresolved"])
        result = self.evidence(
            "from __future__ import annotations\nimport yaml\n"
            "def f(value: yaml.load(data) = yaml.safe_load(data)): pass\n"
        )
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["yaml.safe_load"])

    def test_defaults_and_assignment_values_cannot_forge_annotation_binding(self) -> None:
        cases = (
            "import yaml\ndef f(value: yaml.load(data) = (yaml := custom)): pass\n",
            "import yaml\nvalue: yaml.load(data) = (yaml := custom)\n",
        )
        for code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                projected = api_call_evidence_for_sample(self.canonical(Path(tmp), code), "sample")
                self.assertFalse(projected["api_calls"])
                filtered = filter_api_call_evidence(projected, "pyyaml")
                self.assertTrue(filtered["binding_unresolved"])
                coverage = self.coverage(filtered)
                self.assertEqual(coverage["main_metric_outcome"], "unknown_review")
                self.assertFalse(coverage["main_metric_eligible"])

    def test_annotation_targets_keep_executed_calls_separate_from_annotation_text(self) -> None:
        cases = (
            ("import yaml\nobj[yaml.safe_load(data)]: yaml.load(data)\n",
             ["yaml.load", "yaml.safe_load"]),
            ("from __future__ import annotations\nimport yaml\n"
             "obj[yaml.safe_load(data)]: yaml.load(data)\n", ["yaml.safe_load"]),
            ("import yaml\ndef f(obj):\n obj[yaml.safe_load(data)]: yaml.load(data)\n",
             ["yaml.safe_load"]),
        )
        for code, expected in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                calls = api_call_evidence_for_sample(self.canonical(Path(tmp), code), "sample")
                self.assertEqual(sorted(row["api_symbol"] for row in calls["api_calls"]), expected)

    def assert_unknown_chain(self, root: Path, code: str, distribution: str,
                             rejected_symbol: str) -> dict:
        ir = self.canonical(root, code)
        write_json(root / "base_ir.json", ir)
        ir = read_json(root / "base_ir.json")
        verify_ir(ir)
        projected = api_call_evidence_for_sample(ir, "sample")
        calls = filter_api_call_evidence(projected, distribution)
        self.assertNotIn(rejected_symbol, [row["api_symbol"] for row in calls["api_calls"]])
        self.assertTrue(calls["binding_unresolved"])
        match = match_trigger_entry(api_call_evidence=calls, trigger_entry={
            "normalized_distribution": distribution,
            "trigger_conditions": {"api_symbols": [rejected_symbol]},
        }, confirmed_exposed_releases=[{"version": "1"}])
        self.assertEqual(match["summary"]["matched_trigger_evaluation_count"], 0)
        coverage = self.coverage(calls)
        self.assertEqual(coverage["main_metric_outcome"], "unknown_review")
        self.assertFalse(coverage["main_metric_eligible"])
        self.assertIn("api_binding_unresolved", coverage["blocking_unknown_reasons"])
        sample_dir = root / "avcs/samples/sample"
        write_coverage_sample(sample_dir, coverage)
        self.assertEqual(summarize_avcs_coverage([sample_dir])["formal_metric_eligible_count"], 0)
        self.assertEqual(self.coverage(calls, positive=True)["main_metric_outcome"], "formal_positive")
        return projected

    def test_bound_mutator_aliases_remain_unknown_through_trigger_and_final_summary(self) -> None:
        mutations = (
            "mutate=yaml.__dict__.update\nmutate({'load': custom})",
            "mutate=yaml.__dict__.clear\nmutate()",
            "mutate=yaml.__dict__.pop\nmutate('load')",
            "mutate=yaml.__dict__.popitem\nmutate()",
            "mutate=yaml.__dict__.setdefault\nmutate('load', custom)",
            "mutate=yaml.__dict__.__setitem__\nmutate('load', custom)",
            "mutate=yaml.__dict__.__delitem__\nmutate('load')",
            "mutate=yaml.__dict__.__ior__\nmutate({'load': custom})",
            "mutate=yaml.__setattr__\nmutate('load', custom)",
            "mutate=yaml.__delattr__\nmutate('load')",
            "namespace=yaml.__dict__\nmutate=namespace.update\nagain=mutate\nagain({'load': custom})",
            "if condition: mutate=yaml.__dict__.update\nmutate({'load': custom})",
            "mutate=yaml.__dict__.update\nif condition: mutate=custom\nmutate({'load': custom})",
            "mutate=yaml.__dict__.update\ndef change(): mutate({'load': custom})",
            "class Change:\n mutate=yaml.__dict__.update\n mutate({'load': custom})",
            "class Change:\n yaml.__dict__.update({'load': custom})",
            "def change():\n class Change:\n  mutate=yaml.__dict__.update\n  mutate({'load': custom})",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                projected = self.assert_unknown_chain(Path(tmp),
                    "import yaml\nimport requests\n" + mutation + "\nyaml.load(data)\nrequests.get(url)\n",
                    "pyyaml", "yaml.load")
                self.assertIn("requests.get", [row["api_symbol"] for row in projected["api_calls"]])
                self.assertFalse(filter_api_call_evidence(projected, "requests")["binding_unresolved"])

    def test_bound_mutators_capture_original_target_scope_and_source_position(self) -> None:
        for mutation in (
            "target=yaml\nmutate=target.__dict__.update\ntarget=requests\nmutate({'load': custom})",
            "target=yaml\nnamespace=target.__dict__\ntarget=requests\nnamespace.update({'load': custom})",
            "class Change:\n mutate=yaml.__dict__.update\n mutate({'load': custom})",
            "mutate=yaml.__dict__.update\ndef change():\n import requests as yaml\n mutate({'load': custom})\n yaml.get(url)",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                projected = self.assert_unknown_chain(Path(tmp),
                    "import yaml\nimport requests\nyaml.safe_load(data)\n" + mutation +
                    "\nyaml.load(data)\nrequests.get(url)\n", "pyyaml", "yaml.load")
                symbols = [row["api_symbol"] for row in projected["api_calls"]]
                self.assertIn("requests.get", symbols)
                if "def change" not in mutation:
                    self.assertIn("yaml.safe_load", symbols)
        code = ("import urllib3\nhttp=urllib3.PoolManager()\noriginal=http\n"
                "mutate=http.__dict__.update\nhttp=urllib3.PoolManager()\n"
                "mutate({'request': custom})\noriginal.request('GET', url)\nhttp.request('GET', url)\n")
        with tempfile.TemporaryDirectory() as tmp:
            projected = self.assert_unknown_chain(Path(tmp), code, "urllib3", "not-a-real-api")
            requests = [row for row in projected["api_calls"]
                        if row["api_symbol"] == "urllib3.PoolManager.request"]
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0]["location"]["line"], 8)

    def test_bound_mutator_shadowing_and_ordinary_dict_controls_keep_static_proof(self) -> None:
        controls = (
            "namespace={}\nmutate=namespace.update\nmutate({'load': custom})",
            "mutate=yaml.__dict__.update\nmutate=custom\nmutate({'load': custom})",
            "mutate=yaml.__dict__.update\ndef f(mutate): mutate({'load': custom})",
            "mutate=yaml.__dict__.update\ndef f():\n namespace={}\n mutate=namespace.update\n mutate({'load': custom})",
        )
        for index, mutation in enumerate(controls):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                ir = self.canonical(Path(tmp), "import yaml\n" + mutation + "\nyaml.load(data)\n")
                calls = filter_api_call_evidence(api_call_evidence_for_sample(ir, "sample"), "pyyaml")
                self.assertIn("yaml.load", [row["api_symbol"] for row in calls["api_calls"]])
                match = match_trigger_entry(api_call_evidence=calls, trigger_entry={
                    "trigger_conditions": {"api_symbols": ["yaml.load"]},
                }, confirmed_exposed_releases=[{"version": "1"}])
                self.assertEqual(match["summary"]["matched_trigger_evaluation_count"], 1)
                if index == 0:
                    self.assertFalse(calls["binding_unresolved"])
                    self.assertEqual(self.coverage(calls)["main_metric_outcome"], "formal_negative")
                else:
                    # Existing candidate diagnostics may retain a shadowed
                    # callable as unknown; its original module API stays proved.
                    self.assertEqual(self.coverage(calls)["main_metric_outcome"], "unknown_review")
                    self.assertEqual(self.coverage(calls, positive=True)["main_metric_outcome"], "formal_positive")

    def test_call_form_namespace_mutations_block_false_api_and_negative_end_to_end(self) -> None:
        mutations = (
            "setattr(yaml, 'load', custom)", "delattr(yaml, 'load')",
            "object.__setattr__(yaml, 'load', custom)", "type.__setattr__(yaml, 'load', custom)",
            "object.__delattr__(yaml, 'load')", "type.__delattr__(yaml, 'load')",
            "yaml.__dict__.update({'load': custom})", "yaml.__dict__.__setitem__('load', custom)",
            "yaml.__dict__.pop('load')", "yaml.__setattr__('load', custom)",
            "alias = yaml\nsetattr(alias, 'load', custom)",
            "namespace = yaml.__dict__\nnamespace.update({'load': custom})",
            "setter = setattr\nsetter(yaml, 'load', custom)",
            "import builtins as b\nb.setattr(yaml, 'load', custom)",
            "setattr = custom_setter\nsetattr(yaml, 'load', custom)",
            "if condition: setattr(yaml, 'load', custom)",
            "yaml.load = custom",  # Existing direct-write control.
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                projected = self.assert_unknown_chain(Path(tmp),
                    "import yaml\n" + mutation + "\nyaml.load(data)\n", "pyyaml", "yaml.load")
                self.assertFalse(filter_api_call_evidence(projected, "requests")["binding_unresolved"])

    def test_factory_receiver_mutations_keep_other_receivers_and_packages_proven(self) -> None:
        for mutation in ("setattr(http, 'request', custom)", "delattr(http, 'request')",
                         "http.__dict__.update({'request': custom})",
                         "alias=http\nobject.__setattr__(alias, 'request', custom)"):
            code = ("import urllib3\nimport requests\nhttp=urllib3.PoolManager(retries=0)\n"
                    "other=urllib3.PoolManager()\n" + mutation + "\n"
                    "http.request('GET', url)\nother.request('GET', url)\nrequests.get(url)\n")
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                projected = self.assert_unknown_chain(Path(tmp), code, "urllib3", "does-not-exist")
                symbols = [row["api_symbol"] for row in projected["api_calls"]]
                self.assertEqual(symbols.count("urllib3.PoolManager.request"), 1)
                self.assertIn("requests.get", symbols)
                self.assertFalse(filter_api_call_evidence(projected, "requests")["binding_unresolved"])

    def test_mutation_source_order_target_and_scope_controls(self) -> None:
        code = ("import yaml\nimport yaml as other\nyaml.safe_load(data)\n"
                "setattr(yaml, 'load', custom)\nother.load(data)\n")
        result = self.evidence(code)
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["yaml.safe_load"])
        self.assertTrue(result["binding_unresolved"])
        for code in (
            "import requests\nsetattr(local_object, 'get', custom)\nrequests.get(url)\n",
            "import requests\ndef f(requests): setattr(requests, 'get', custom)\nrequests.get(url)\n",
            "import requests\ndef f():\n setattr(choose_target(), 'get', custom)\nrequests.get(url)\n",
        ):
            with self.subTest(code=code):
                result = self.evidence(code)
                self.assertEqual([row["api_symbol"] for row in result["api_calls"]], ["requests.get"])
                self.assertFalse(result["binding_unresolved"])
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_unknown_chain(Path(tmp),
                "import yaml\ndef f(): setattr(yaml, 'load', custom)\nyaml.load(data)\n",
                "pyyaml", "yaml.load")
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_unknown_chain(Path(tmp),
                "import yaml\ndef f():\n setattr(choose_target(), 'load', custom)\n yaml.load(data)\n",
                "pyyaml", "yaml.load")

    def test_literal_dynamic_imports_share_dependency_api_identity_and_canonical_tho(self) -> None:
        cases = (
            ("import importlib\nrequests=importlib.import_module('requests')\nrequests.get(url)\n", "requests", "requests.get"),
            ("from importlib import import_module as load\nx=load('requests')\nx.get(url)\n", "requests", "requests.get"),
            ("import importlib as il\nload=il.import_module\nx=load('requests.sessions')\nx.Session()\n", "requests.sessions", "requests.sessions.Session"),
            ("x=__import__('requests')\nx.get(url)\n", "requests", "requests.get"),
            ("import builtins as b\nx=b.__import__('requests.sessions')\nx.get(url)\n", "requests.sessions", "requests.get"),
            ("x=__import__('requests.sessions', fromlist=['Session'])\nx.Session()\n", "requests.sessions", "requests.sessions.Session"),
            ("import importlib\ndef f():\n x=importlib.import_module('yaml')\n x.safe_load(data)\n", "yaml", "yaml.safe_load"),
            ("import importlib\nx=importlib.import_module('.sessions', package='requests')\nx.Session()\n", "requests.sessions", "requests.sessions.Session"),
            ("import importlib\nimportlib.import_module('requests').get(url)\n", "requests", "requests.get"),
            ("load=__import__\nx=load(name='yaml')\nx.safe_load(data)\n", "yaml", "yaml.safe_load"),
        )
        for code, module, symbol in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                ir = self.canonical(root, code)
                calls = api_call_evidence_for_sample(ir, "sample")
                self.assertEqual([row["api_symbol"] for row in calls["api_calls"]], [symbol])
                self.assertFalse(calls["binding_unresolved"])
                dynamic = calls["dynamic_imports"][0]
                self.assertEqual(dynamic["import_path"], module)
                records = project_dependency_records(ir)
                matching = [row for row in records if row.get("import_path") == module]
                self.assertEqual(len(matching), 1)
                self.assertEqual(matching[0]["package_identity"], dynamic["package_identity"])
                self.assertEqual(calls["api_calls"][0]["normalized_distribution"], matching[0]["package"])
                self.assertTrue(calls["analysis_support"]["THO"]["dependency_extraction_complete"])
                distribution = calls["api_calls"][0]["normalized_distribution"]
                self.assertIn(distribution, distributions_for_sample(ir, "sample", node_types={"Import"},
                                                                    avcs_candidates_only=True))

    def test_unknown_dynamic_imports_block_sample_coverage_and_remain_shared_unknown(self) -> None:
        cases = (
            "import importlib\nx=importlib.import_module(name)\nx.get(url)\n",
            "from importlib import import_module as load\nx=load(name)\nx.get(url)\n",
            "x=__import__(name)\nx.get(url)\n",
            "import importlib\nimportlib=custom\nx=importlib.import_module('requests')\nx.get(url)\n",
            "import importlib\nsetattr(importlib, 'import_module', custom)\nx=importlib.import_module('requests')\nx.get(url)\n",
            "import importlib\nx=importlib.import_module(*args)\nx.get(url)\n",
            "import importlib\nx=importlib.import_module('requests', name='yaml')\nx.get(url)\n",
            "import importlib\nx=importlib.import_module('.sessions', package=package_name)\nx.get(url)\n",
            "x=__import__('requests.sessions', fromlist=items)\nx.get(url)\n",
            "x=__import__('requests', level=1)\nx.get(url)\n",
            "def f(__import__):\n x=__import__('requests')\n x.get(url)\n",
            "il=__import__('importlib')\nsetattr(il, 'import_module', custom)\nx=il.import_module('requests')\nx.get(url)\n",
        )
        for code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                projected = self.assert_unknown_chain(Path(tmp), code, "requests", "requests.get")
                self.assertFalse(projected["api_calls"])
                self.assertTrue(any(row["status"] == "unresolved" for row in projected["dynamic_imports"]))
                tho = projected["analysis_support"]["THO"]
                self.assertEqual(tho["state"], "unknown_or_review")
                self.assertFalse(tho["dependency_extraction_complete"])
                self.assertTrue(tho["unresolved_dynamic_imports"])
                other = filter_api_call_evidence(projected, "pyyaml")
                self.assertTrue(any(row.get("unresolved_scope") == "sample" for row in other["binding_unresolved"]))
                self.assertFalse(self.coverage(other)["main_metric_eligible"])
                self.assertFalse(any(row.raw_name == "requests" for row in extract_imports_from_code(code)))

    def test_dynamic_import_factory_receiver_and_post_load_mutation(self) -> None:
        code = "import importlib\nhttp=importlib.import_module('requests').Session()\nhttp.get(url)\n"
        result = self.evidence(code)
        self.assertEqual([row["api_symbol"] for row in result["api_calls"]],
                         ["requests.Session", "requests.Session.get"])
        for code in (
            "import importlib\nx=importlib.import_module('yaml')\nsetattr(x, 'load', custom)\nx.load(data)\n",
            "import yaml\nsetattr(yaml, 'load', custom)\nx=__import__('yaml')\nx.load(data)\n",
            "import importlib\nhttp=importlib.import_module('requests').Session()\nsetattr(http, 'get', custom)\nhttp.get(url)\n",
        ):
            distribution, symbol = ("requests", "requests.Session.get") if "Session" in code else ("pyyaml", "yaml.load")
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                self.assert_unknown_chain(Path(tmp), code, distribution, symbol)

    def test_dynamic_loader_controls_nonexecuting_annotations_and_missing_dependency_guard(self) -> None:
        for code in (
            "from __future__ import annotations\nimport importlib\ndef f(x: importlib.import_module('requests')): pass\n",
            "import importlib\ndef f():\n x: importlib.import_module('requests')\n",
            "from importlib import util\nutil()\n",
        ):
            with self.subTest(code=code):
                result = self.evidence(code)
                self.assertFalse(result["dynamic_imports"])
                self.assertFalse(result["binding_unresolved"])
                self.assertFalse(any(row.raw_name == "requests" for row in extract_imports_from_code(code)))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "Literal dynamic import missing canonical dependency evidence"):
                self.canonical(Path(tmp), "import importlib\nx=importlib.import_module('requests')\n", omit_dependencies=True)
        code = "import requests\nrequests.get(url)\n"
        with tempfile.TemporaryDirectory() as tmp:
            projected = api_call_evidence_for_sample(self.canonical(Path(tmp), code), "sample")
            self.assertFalse(projected["dynamic_imports"])
            self.assertFalse(projected["binding_unresolved"])
            self.assertEqual(self.coverage(filter_api_call_evidence(projected, "requests"))
                             ["main_metric_outcome"], "formal_negative")

    def test_mutating_defaults_cannot_forge_runtime_annotation_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_unknown_chain(Path(tmp),
                "import yaml\ndef f(x: yaml.load(data) = setattr(yaml, 'load', custom)): pass\n",
                "pyyaml", "yaml.load")
        code = ("import importlib\ndef f(x: importlib.import_module('requests') = "
                "setattr(importlib, 'import_module', custom)): pass\n")
        result = self.evidence(code)
        self.assertEqual(result["dynamic_imports"][0]["status"], "unresolved")


if __name__ == "__main__":
    unittest.main()
