import chardet


class EncodingDetectionError(Exception):
    pass


def detect_encoding_or_raise(data: bytes, minimum_confidence: float = 0.5) -> str:
    result = chardet.detect(data)

    encoding = result.get("encoding")
    confidence = result.get("confidence") or 0.0

    if not encoding or confidence < minimum_confidence:
        raise EncodingDetectionError(
            f"Unable to detect encoding with enough confidence: {confidence}"
        )

    return encoding


def decode_bytes(data: bytes) -> str:
    encoding = detect_encoding_or_raise(data)
    return data.decode(encoding)


if __name__ == "__main__":
    raw = "Hello, 世界".encode("utf-8")

    try:
        encoding = detect_encoding_or_raise(raw)
        print("Detected encoding:", encoding)
        print("Decoded text:", decode_bytes(raw))
    except EncodingDetectionError as exc:
        print("Detection failed:", exc)
