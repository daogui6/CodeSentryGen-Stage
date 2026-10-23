import chardet

def detect_encoding(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    result = chardet.detect(data)
    print(f"Detected encoding: {result['encoding']}")

sample_bytes = "这是一个测试字符串。".encode('utf-8')
detect_encoding(sample_bytes)
