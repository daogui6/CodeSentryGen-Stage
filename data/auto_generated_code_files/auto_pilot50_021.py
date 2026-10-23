import json
import re

def process_json_data(json_str):
    data = json.loads(json_str)
    if 'age' in data:
        data['age'] += 1
    updated_json_str = json.dumps(data, indent=2)
    keys_pattern = r'"([^"]+)"\s*:'
    extracted_keys = re.findall(keys_pattern, json_str)
    modified_json_str = re.sub(r'example\.com', 'test.com', updated_json_str)
    return {
        "parsed_data": data,
        "extracted_keys": extracted_keys,
        "modified_json": modified_json_str
    }

if __name__ == "__main__":
    sample_json = '{"name": "Alice", "age": 30, "email": "alice@example.com"}'
    result = process_json_data(sample_json)
    print("Parsed Data:", result["parsed_data"])
    print("Extracted Keys:", result["extracted_keys"])
    print("Modified JSON:", result["modified_json"])
