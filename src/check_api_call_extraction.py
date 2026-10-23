from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path
from typing import Any

from extract_api_calls import extract_api_calls


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = ROOT / "output" / "api_call_extraction_validation.csv"


TEST_CASES: list[dict[str, Any]] = [
    {
        "case_id": "module_import",
        "description": "普通模块导入",
        "code": """
import yaml

result = yaml.safe_load("name: test")
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["yaml.safe_load"],
        "expected_distributions": ["PyYAML"],
        "expected_binding_types": ["module_import"],
    },
    {
        "case_id": "module_alias",
        "description": "模块别名导入",
        "code": """
import yaml as y

result = y.safe_dump({"name": "test"})
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["yaml.safe_dump"],
        "expected_distributions": ["PyYAML"],
        "expected_binding_types": ["module_import"],
    },
    {
        "case_id": "from_import_alias",
        "description": "from import 及符号别名",
        "code": """
from yaml import safe_load as load

result = load("name: test")
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["yaml.safe_load"],
        "expected_distributions": ["PyYAML"],
        "expected_binding_types": ["from_import"],
    },
    {
        "case_id": "nested_module_import",
        "description": "无别名的多层模块导入",
        "code": """
import google.cloud.storage

client = google.cloud.storage.Client()
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["google.cloud.storage.Client"],
        "expected_distributions": ["google-cloud-storage"],
        "expected_binding_types": ["module_import"],
    },
    {
        "case_id": "nested_module_alias",
        "description": "带别名的多层模块导入",
        "code": """
import google.cloud.storage as storage

client = storage.Client()
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["google.cloud.storage.Client"],
        "expected_distributions": ["google-cloud-storage"],
        "expected_binding_types": ["module_import"],
    },
    {
        "case_id":
            "call_result_method_binding",

        "description":
            "直接调用结果变量的方法调用绑定",

        "code": """
import urllib3

http = urllib3.PoolManager(
    retries=0,
)

response = http.request(
    "GET",
    "https://example.com/start",
)
""",

        "expected_parse_status":
            "ok",

        "expected_symbols": [
            "urllib3.PoolManager",
            "urllib3.PoolManager.request",
        ],

        "expected_distributions": [
            "urllib3",
            "urllib3",
        ],

        "expected_binding_types": [
            "module_import",
            "call_result_method",
        ],

        "expected_receiver_provenance": [
            None,
            {
                "receiver_name":
                    "http",

                "producer_api_symbol":
                    "urllib3.PoolManager",

                "producer_binding_type":
                    "module_import",

                "producer_call_shape": {
                    "explicit_positional_arg_count":
                        0,

                    "positional_arg_values":
                        [],

                    "keyword_arg_names": [
                        "retries"
                    ],

                    "keyword_arg_values": {
                        "retries": {
                            "source_text":
                                "0",

                            "resolved_symbol":
                                None,

                            "literal_value":
                                0,
                        }
                    },

                    "has_star_args":
                        False,

                    "has_star_kwargs":
                        False,
                },
            },
        ],
    },
    {
        "case_id":
            "call_result_method_reassigned",

        "description":
            "调用结果变量重赋值后不得继续传播旧绑定",

        "code": """
import urllib3

http = urllib3.PoolManager(
    retries=0,
)

http = None

response = http.request(
    "GET",
    "https://example.com/start",
)
""",

        "expected_parse_status":
            "ok",

        "expected_symbols": [
            "urllib3.PoolManager",
        ],

        "expected_distributions": [
            "urllib3",
        ],

        "expected_binding_types": [
            "module_import",
        ],

        "expected_receiver_provenance": [
            None,
        ],
    },
    {
        "case_id": "unimported_local_call",
        "description": "未导入的本地函数不应被当作第三方 API",
        "code": """
def helper():
    return 1

value = helper()
""",
        "expected_parse_status": "ok",
        "expected_symbols": [],
        "expected_distributions": [],
        "expected_binding_types": [],
    },
    {
        "case_id": "positional_argument_shape",
        "description": "普通位置参数形态",
        "code": """
import yaml

result = yaml.safe_load("name: test")
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["yaml.safe_load"],
        "expected_distributions": ["PyYAML"],
        "expected_binding_types": ["module_import"],
        "expected_call_shapes": [
            {
                "explicit_positional_arg_count": 1,
                "keyword_arg_names": [],
                "keyword_arg_values": {},
                "has_star_args": False,
                "has_star_kwargs": False,
            }
        ],
    },
    {
        "case_id": "keyword_argument_shape",
        "description": "关键字参数形态",
        "code": """
import yaml

result = yaml.safe_dump(
    {"name": "test"},
    sort_keys=False,
)
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["yaml.safe_dump"],
        "expected_distributions": ["PyYAML"],
        "expected_binding_types": ["module_import"],
        "expected_call_shapes": [
            {
                "explicit_positional_arg_count": 1,
                "keyword_arg_names": ["sort_keys"],
                "keyword_arg_values": {
                    "sort_keys": {
                        "source_text": "False",
                        "resolved_symbol": None,
                        "literal_value": False,
                    }
                },
                "has_star_args": False,
                "has_star_kwargs": False,
            }
        ],
    },
    {
        "case_id":
            "aiohttp_static_follow_symlinks_true",

        "description":
            "aiohttp.web.static 布尔关键字参数",

        "code": """
from aiohttp import web

route = web.static(
    "/assets",
    "./assets",
    follow_symlinks=True,
)
""",

        "expected_parse_status":
            "ok",

        "expected_symbols": [
            "aiohttp.web.static"
        ],

        "expected_distributions": [
            "aiohttp"
        ],

        "expected_binding_types": [
            "from_import"
        ],

        "expected_call_shapes": [
            {
                "explicit_positional_arg_count":
                    2,

                "keyword_arg_names": [
                    "follow_symlinks"
                ],

                "keyword_arg_values": {
                    "follow_symlinks": {
                        "source_text":
                            "True",

                        "resolved_symbol":
                            None,

                        "literal_value":
                            True,
                    }
                },

                "has_star_args":
                    False,

                "has_star_kwargs":
                    False,
            }
        ],
    },
    {
        "case_id":
            "requests_positional_url_literal",

        "description":
            "Requests URL 位置参数 literal 提取",

        "code": """
import requests

response = requests.get(
    "http://github.com:@evil.example.net"
)
""",

        "expected_parse_status":
            "ok",

        "expected_symbols": [
            "requests.get"
        ],

        "expected_distributions": [
            "requests"
        ],

        "expected_binding_types": [
            "module_import"
        ],

        "expected_call_shapes": [
            {
                "explicit_positional_arg_count":
                    1,

                "keyword_arg_names":
                    [],

                "keyword_arg_values":
                    {},

                "has_star_args":
                    False,

                "has_star_kwargs":
                    False,
            }
        ],

        "expected_positional_arg_values": [
            [
                {
                    "position":
                        0,

                    "source_text":
                        "\"http://github.com:@evil.example.net\"",

                    "resolved_symbol":
                        None,

                    "literal_value":
                        "http://github.com:@evil.example.net",
                }
            ]
        ],
    },
    {
        "case_id": "star_argument_shape",
        "description": "星号参数形态",
        "code": """
import yaml

args = ["name: test"]
kwargs = {}
result = yaml.safe_load(*args, **kwargs)
""",
        "expected_parse_status": "ok",
        "expected_symbols": ["yaml.safe_load"],
        "expected_distributions": ["PyYAML"],
        "expected_binding_types": ["module_import"],
        "expected_call_shapes": [
            {
                "explicit_positional_arg_count": 0,
                "keyword_arg_names": [],
                "keyword_arg_values": {},
                "has_star_args": True,
                "has_star_kwargs": True,
            }
        ],
    },
    {
        "case_id": "yaml_load_full_loader",
        "description": (
            "yaml.load 显式使用 FullLoader"
        ),
        "code": """
import yaml

data = "name: test"

result = yaml.load(
    data,
    Loader=yaml.FullLoader,
)
""",
        "expected_parse_status": "ok",
        "expected_symbols": [
            "yaml.load"
        ],
        "expected_distributions": [
            "PyYAML"
        ],
        "expected_binding_types": [
            "module_import"
        ],
        "expected_call_shapes": [
            {
                "explicit_positional_arg_count": 1,
                "keyword_arg_names": [
                    "Loader"
                ],
                "keyword_arg_values": {
                    "Loader": {
                        "source_text":
                            "yaml.FullLoader",
                        "resolved_symbol":
                            "yaml.FullLoader",
                    }
                },
                "has_star_args": False,
                "has_star_kwargs": False,
            }
        ],
    },
    {
        "case_id": "yaml_load_safe_loader",
        "description": (
            "yaml.load 显式使用 SafeLoader"
        ),
        "code": """
import yaml

data = "name: test"

result = yaml.load(
    data,
    Loader=yaml.SafeLoader,
)
""",
        "expected_parse_status": "ok",
        "expected_symbols": [
            "yaml.load"
        ],
        "expected_distributions": [
            "PyYAML"
        ],
        "expected_binding_types": [
            "module_import"
        ],
        "expected_call_shapes": [
            {
                "explicit_positional_arg_count": 1,
                "keyword_arg_names": [
                    "Loader"
                ],
                "keyword_arg_values": {
                    "Loader": {
                        "source_text":
                            "yaml.SafeLoader",
                        "resolved_symbol":
                            "yaml.SafeLoader",
                    }
                },
                "has_star_args": False,
                "has_star_kwargs": False,
            }
        ],
    },
    {
        "case_id": "yaml_load_loader_omitted",
        "description": (
            "yaml.load 省略 Loader 参数"
        ),
        "code": """
import yaml

data = "name: test"

result = yaml.load(data)
""",
        "expected_parse_status": "ok",
        "expected_symbols": [
            "yaml.load"
        ],
        "expected_distributions": [
            "PyYAML"
        ],
        "expected_binding_types": [
            "module_import"
        ],
        "expected_call_shapes": [
            {
                "explicit_positional_arg_count": 1,
                "keyword_arg_names": [],
                "keyword_arg_values": {},
                "has_star_args": False,
                "has_star_kwargs": False,
            }
        ],
    },
    {
        "case_id": "syntax_error",
        "description": "语法错误时保留解析状态且不输出 API",
        "code": """
def broken(:
    pass
""",
        "expected_parse_status": "syntax_error",
        "expected_symbols": [],
        "expected_distributions": [],
        "expected_binding_types": [],
    },
]


def join_values(values: list[str]) -> str:
    return " | ".join(values)


def run_validation() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary_root = Path(temporary_directory)

        mapping_path = temporary_root / "import_mapping.json"
        mapping_path.write_text(
            json.dumps(
                {
                    "yaml": "PyYAML",
                    "google.cloud.storage": "google-cloud-storage",
                    "requests": "requests",
                    "urllib3": "urllib3",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        for test_case in TEST_CASES:
            code_path = temporary_root / f"{test_case['case_id']}.py"
            code_path.write_text(
                test_case["code"].strip() + "\n",
                encoding="utf-8",
            )

            result = extract_api_calls(
                code_path=code_path,
                mapping_path=mapping_path,
                sample_id=test_case["case_id"],
            )

            actual_symbols = [
                row["api_symbol"]
                for row in result["api_calls"]
            ]

            actual_distributions = [
                row["distribution"]
                for row in result["api_calls"]
            ]

            actual_binding_types = [
                row["binding_type"]
                for row in result["api_calls"]
            ]

            actual_receiver_provenance = []

            for row in result["api_calls"]:
                provenance = row.get(
                    "receiver_provenance"
                )

                if not isinstance(
                    provenance,
                    dict,
                ):
                    actual_receiver_provenance.append(
                        None
                    )
                    continue

                actual_receiver_provenance.append(
                    {
                        "receiver_name":
                            provenance.get(
                                "receiver_name"
                            ),

                        "producer_api_symbol":
                            provenance.get(
                                "producer_api_symbol"
                            ),

                        "producer_binding_type":
                            provenance.get(
                                "producer_binding_type"
                            ),

                        "producer_call_shape":
                            provenance.get(
                                "producer_call_shape"
                            ),
                    }
                )

            expected_receiver_provenance = (
                test_case.get(
                    "expected_receiver_provenance"
                )
            )

            receiver_provenance_passed = (
                expected_receiver_provenance
                is None
                or actual_receiver_provenance
                == expected_receiver_provenance
            )

            actual_call_shapes = [
                row["call_shape"]
                for row in result["api_calls"]
            ]

            # positional_arg_values 是本轮新增的
            # call-shape evidence。
            #
            # 旧的 expected_call_shapes 不包含这个字段，
            # 因此先移除新字段，再继续执行原来的
            # 严格回归比较。
            actual_legacy_call_shapes = [
                {
                    key: value
                    for key, value
                    in call_shape.items()
                    if key
                       != "positional_arg_values"
                }
                for call_shape
                in actual_call_shapes
            ]

            expected_call_shapes = (
                test_case.get(
                    "expected_call_shapes"
                )
            )

            call_shape_passed = (
                    expected_call_shapes is None
                    or actual_legacy_call_shapes
                    == expected_call_shapes
            )

            actual_positional_arg_values = [
                call_shape.get(
                    "positional_arg_values",
                    [],
                )
                for call_shape
                in actual_call_shapes
            ]

            expected_positional_arg_values = (
                test_case.get(
                    "expected_positional_arg_values"
                )
            )

            positional_arg_values_passed = (
                    expected_positional_arg_values
                    is None
                    or actual_positional_arg_values
                    == expected_positional_arg_values
            )

            passed = (
                    result["parse_status"]
                    == test_case["expected_parse_status"]
                    and actual_symbols
                    == test_case["expected_symbols"]
                    and actual_distributions
                    == test_case["expected_distributions"]
                    and actual_binding_types
                    == test_case["expected_binding_types"]
                    and receiver_provenance_passed
                    and call_shape_passed
                    and positional_arg_values_passed
            )

            rows.append(
                {
                    "case_id": test_case["case_id"],
                    "description": test_case["description"],
                    "expected_parse_status": test_case[
                        "expected_parse_status"
                    ],
                    "actual_parse_status": result["parse_status"],
                    "expected_api_symbols": join_values(
                        test_case["expected_symbols"]
                    ),
                    "actual_api_symbols": join_values(
                        actual_symbols
                    ),
                    "expected_distributions": join_values(
                        test_case["expected_distributions"]
                    ),
                    "actual_distributions": join_values(
                        actual_distributions
                    ),
                    "expected_binding_types": join_values(
                        test_case["expected_binding_types"]
                    ),
                    "actual_binding_types": join_values(
                        actual_binding_types
                    ),
                    "expected_call_shapes": json.dumps(
                        expected_call_shapes or [],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "actual_call_shapes": json.dumps(
                        actual_call_shapes,
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    "status": "PASS" if passed else "FAIL",
                }
            )

    return rows


def write_csv(rows: list[dict[str, str]]) -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "case_id",
        "description",
        "expected_parse_status",
        "actual_parse_status",
        "expected_api_symbols",
        "actual_api_symbols",
        "expected_distributions",
        "actual_distributions",
        "expected_binding_types",
        "actual_binding_types",
        "expected_call_shapes",
        "actual_call_shapes",
        "status",
    ]

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = run_validation()
    write_csv(rows)

    passed = sum(
        row["status"] == "PASS"
        for row in rows
    )
    failed = len(rows) - passed

    print(f"[OK] total tests: {len(rows)}")
    print(f"[OK] passed: {passed}")
    print(f"[OK] failed: {failed}")
    print(f"[OK] result saved to: {OUTPUT_PATH}")

    for row in rows:
        print(
            f"[{row['status']}] "
            f"{row['case_id']} | "
            f"{row['actual_api_symbols'] or '(no API calls)'}"
        )

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()