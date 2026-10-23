from pathlib import Path
from typing import Any

from extractor import extract_imports_from_code
from normalizer import (
    load_import_mapping,
    map_import_path_to_distribution,
    pep503_normalize,
)


ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "config" / "import_mapping.json"


TEST_CASES: list[dict[str, Any]] = [
    {
        "name": "future_and_backports",
        "code": """
from builtins import str, bytes, dict, int
from backports.functools_lru_cache import lru_cache
""",
        "expected": {
            "future",
            "backports-functools-lru-cache",
        },
    },
    {
        "name": "google_protobuf",
        "code": """
from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
""",
        "expected": {
            "protobuf",
        },
    },
    {
        "name": "google_auth",
        "code": """
import google.auth
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
""",
        "expected": {
            "google-auth",
        },
    },
    {
        "name": "google_cloud_storage",
        "code": """
from google.cloud import storage
""",
        "expected": {
            "google-cloud-storage",
        },
    },
    {
        "name": "google_cloud_bigquery",
        "code": """
from google.cloud import bigquery
""",
        "expected": {
            "google-cloud-bigquery",
        },
    },
    {
        "name": "websocket_client",
        "code": """
import websocket
""",
        "expected": {
            "websocket-client",
        },
    },
    {
        "name": "azure_namespace_packages",
        "code": """
from azure.core.credentials import TokenCredential
from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient
from azure.storage.blob import BlobServiceClient
from azure.eventhub import EventHubProducerClient
""",
        "expected": {
            "azure-core",
            "azure-identity",
            "azure-servicebus",
            "azure-storage-blob",
            "azure-eventhub",
        },
    },
]


def extract_mapped_distributions(
    code: str,
    mapping: dict[str, str],
) -> set[str]:
    """
    从代码中抽取 import，并映射为规范化的 PyPI distribution。
    """
    results: set[str] = set()

    entities = extract_imports_from_code(
        code,
        file_name="<mapping_test>",
    )

    for entity in entities:
        distribution = map_import_path_to_distribution(
            raw_name=entity.raw_name,
            import_path=entity.import_path,
            mapping=mapping,
        )

        results.add(
            pep503_normalize(distribution)
        )

    return results


def main() -> None:
    mapping = load_import_mapping(MAPPING_PATH)

    all_pass = True

    print("============================================================")
    print("Import path mapping regression check")
    print("============================================================")

    for case in TEST_CASES:
        name = str(case["name"])
        code = str(case["code"])

        expected = {
            pep503_normalize(item)
            for item in case["expected"]
        }

        actual = extract_mapped_distributions(
            code,
            mapping,
        )

        missing = expected - actual
        passed = not missing

        if not passed:
            all_pass = False

        print("")
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        print(f"expected: {sorted(expected)}")
        print(f"actual:   {sorted(actual)}")

        if missing:
            print(f"missing:  {sorted(missing)}")

    print("")
    print("============================================================")
    print(f"ALL_PASS = {all_pass}")
    print("============================================================")

    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()