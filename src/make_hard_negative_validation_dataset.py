from pathlib import Path
import json

sample_path = Path("data/samples/hard_negative_validation_dataset.jsonl")
code_dir = Path("data/hard_negative_code_files")
req_dir = Path("data/hard_negative_requirements_files")
local_repo_dir = Path("data/hard_negative_local_repo")

sample_path.parent.mkdir(parents=True, exist_ok=True)
code_dir.mkdir(parents=True, exist_ok=True)
req_dir.mkdir(parents=True, exist_ok=True)
local_repo_dir.mkdir(parents=True, exist_ok=True)
(local_repo_dir / "fake_internal_helper.py").write_text(
    "def helper():\n    return 'local helper'\n",
    encoding="utf-8",
)

cases = [
    {
        "sample_id": "hard_negative_stdlib_001",
        "prompt_id": "hard_negative_stdlib_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

def main():
    data = {"ok": True}
    print(json.dumps(data))
    print(Path(".").resolve())

if __name__ == "__main__":
    main()
""",
        "requirements": "",
        "notes": "Only Python standard library imports. Should not produce THO Risk Card.",
    },
    {
        "sample_id": "hard_negative_comment_string_001",
        "prompt_id": "hard_negative_comment_string_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """import re

# This is only a comment: import codesentry_fake_dep_comment_only_zzzxq_20260622
FAKE_TEXT = "pip install codesentry_fake_dep_string_only_zzzxq_20260622"

def main():
    text = "abc123"
    print(re.findall(r"\\\\d+", text))
    print(FAKE_TEXT)

if __name__ == "__main__":
    main()
""",
        "requirements": "",
        "notes": "Fake package names appear only in comment/string, not as real imports or requirements.",
    },
    {
        "sample_id": "hard_negative_googleapiclient_mapping_001",
        "prompt_id": "hard_negative_googleapiclient_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """from googleapiclient.discovery import build

def main():
    print(build)

if __name__ == "__main__":
    main()
""",
        "requirements": "google-api-python-client\n",
        "notes": "Import name googleapiclient should map to PyPI distribution google-api-python-client.",
    },
    {
        "sample_id": "hard_negative_yaml_mapping_001",
        "prompt_id": "hard_negative_yaml_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """import yaml

def main():
    data = yaml.safe_load("a: 1")
    print(data)

if __name__ == "__main__":
    main()
""",
        "requirements": "PyYAML\n",
        "notes": "Import name yaml should map to PyPI distribution PyYAML/pyyaml.",
    },
    {
        "sample_id": "hard_negative_pil_mapping_001",
        "prompt_id": "hard_negative_pil_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """from PIL import Image

def main():
    print(Image)

if __name__ == "__main__":
    main()
""",
        "requirements": "Pillow\n",
        "notes": "Import name PIL should map to PyPI distribution Pillow.",
    },
    {
        "sample_id": "hard_negative_bs4_mapping_001",
        "prompt_id": "hard_negative_bs4_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """from bs4 import BeautifulSoup

def main():
    html = "<html><body><p>Hello</p></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    print(soup.get_text())

if __name__ == "__main__":
    main()
""",
        "requirements": "beautifulsoup4\n",
        "notes": "Import name bs4 should map to PyPI distribution beautifulsoup4.",
    },
    {
        "sample_id": "hard_negative_sklearn_mapping_001",
        "prompt_id": "hard_negative_sklearn_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """from sklearn.model_selection import train_test_split

def main():
    print(train_test_split)

if __name__ == "__main__":
    main()
""",
        "requirements": "scikit-learn\n",
        "notes": "Import name sklearn should map to PyPI distribution scikit-learn.",
    },
    {
        "sample_id": "hard_negative_cv2_mapping_001",
        "prompt_id": "hard_negative_cv2_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """import cv2

def main():
    print(cv2.__name__)

if __name__ == "__main__":
    main()
""",
        "requirements": "opencv-python\n",
        "notes": "Import name cv2 should map to PyPI distribution opencv-python.",
    },
    {
        "sample_id": "hard_negative_dotenv_mapping_001",
        "prompt_id": "hard_negative_dotenv_mapping_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """from dotenv import load_dotenv

def main():
    load_dotenv()
    print("loaded")

if __name__ == "__main__":
    main()
""",
        "requirements": "python-dotenv\n",
        "notes": "Import name dotenv should map to PyPI distribution python-dotenv.",
    },
    {
        "sample_id": "hard_negative_manifest_only_normal_001",
        "prompt_id": "hard_negative_manifest_only_normal_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """def main():
    print("This sample declares a normal dependency in requirements only.")

if __name__ == "__main__":
    main()
""",
        "requirements": "requests\n",
        "notes": "A normal existing package appears only in requirements, not in code imports. According to the updated rule, it should be reported as a dependency declaration mismatch.",
    },
    {
        "sample_id": "hard_negative_local_module_001",
        "prompt_id": "hard_negative_local_module_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """import fake_internal_helper

def main():
    print(fake_internal_helper.helper())

if __name__ == "__main__":
    main()
""",
        "requirements": "",
        "notes": "python_dateutil should be normalized to python-dateutil by PEP503 rules. Since it appears only in requirements and not in code imports, the updated rule should report it as a dependency declaration mismatch, not as a nonexistent package.",
    },
    {
        "sample_id": "hard_negative_pep503_normalize_001",
        "prompt_id": "hard_negative_pep503_normalize_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """def main():
    print("This sample checks PEP503 name normalization.")

if __name__ == "__main__":
    main()
""",
        "requirements": "python_dateutil>=2.8.2\n",
        "notes": "A normal existing dependency with version specifier, environment marker, and inline comment should be parsed as requests. Since it appears only in requirements and not in code imports, the updated rule should report it as a dependency declaration mismatch.",
    },
    {
        "sample_id": "hard_negative_requirements_marker_001",
        "prompt_id": "hard_negative_requirements_marker_001",
        "generation_time": "2026-06-22T15:00:00+08:00",
        "code": """def main():
    print("This sample checks requirements version specifier and environment marker parsing.")

if __name__ == "__main__":
    main()
""",
        "requirements": "requests>=2.31.0; python_version >= '3.8'  # normal dependency with marker\n",
        "notes": "A normal existing dependency with version specifier, environment marker, and inline comment should be parsed as requests and should not be reported.",
    },
]

EXPECTED_MANIFEST_ONLY_RISK_IDS = {
    "hard_negative_manifest_only_normal_001",
    "hard_negative_pep503_normalize_001",
    "hard_negative_requirements_marker_001",
}

rows = []

for case in cases:
    sid = case["sample_id"]

    code_path = code_dir / f"{sid}.py"
    req_path = req_dir / f"{sid}_requirements.txt"

    code_path.write_text(case["code"], encoding="utf-8")
    req_path.write_text(case["requirements"], encoding="utf-8")

    rows.append({
        "sample_id": sid,
        "source_sample_id": sid,
        "source_dataset": "hard_negative_validation",
        "prompt_id": case["prompt_id"],
        "source": "manual_hard_negative",
        "language": "python",
        "ecosystem": "pypi",
        "prompt": "Hard negative validation sample. This sample should not produce THO Risk Card.",
        "generation_time": case["generation_time"],
        "model": "controlled_hard_negative",
        "raw_response": "",
        "generated_code": case["code"],
        "requirements_text": case["requirements"],
        "notes": case["notes"],
        "expected_risk_card": 1 if sid in EXPECTED_MANIFEST_ONLY_RISK_IDS else 0,
        "generation_error": "",
    })

sample_path.write_text(
    "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
    encoding="utf-8"
)

print("[OK] dataset:", sample_path)
print("[OK] samples:", len(rows))
for r in rows:
    print(r["sample_id"], "expected_risk_card =", r["expected_risk_card"])