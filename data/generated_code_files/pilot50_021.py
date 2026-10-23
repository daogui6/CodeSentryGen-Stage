import json
import re
from typing import Any


def extract_json_objects(text: str) -> list[dict[str, Any]]:
    pattern = re.compile(r"\{.*?\}", re.DOTALL)
    objects = []

    for match in pattern.finditer(text):
        raw_json = match.group(0)
        try:
            objects.append(json.loads(raw_json))
        except json.JSONDecodeError:
            continue

    return objects


def replace_json_value(json_text: str, key: str, new_value: Any) -> str:
    data = json.loads(json_text)
    data[key] = new_value
    return json.dumps(data, indent=2, ensure_ascii=False)


def normalize_json_spacing(json_text: str) -> str:
    json_text = re.sub(r"\s+", " ", json_text).strip()
    data = json.loads(json_text)
    return json.dumps(data, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    text = '''
    User data: {"name": "Alice", "age": 20}
    Config: {"debug": true, "timeout": 30}
    '''

    extracted = extract_json_objects(text)
    print("Extracted objects:")
    print(json.dumps(extracted, indent=2))

    sample = '{"name": "Bob", "age": 22}'
    updated = replace_json_value(sample, "age", 23)
    print("\nUpdated JSON:")
    print(updated)
