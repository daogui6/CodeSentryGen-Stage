import chardet

def detect_encoding(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    result = chardet.detect(data)
    if result['encoding'] is None:
        raise ValueError('Encoding cannot be detected.')
    return result['encoding']
