import chardet


def detect_encoding(data: bytes) -> dict[str, object]:
    result = chardet.detect(data)
    return {
        "encoding": result.get("encoding"),
        "confidence": result.get("confidence"),
        "language": result.get("language"),
    }


def print_detected_encoding(text: str) -> None:
    raw_data = text.encode("utf-8")
    result = detect_encoding(raw_data)

    print("Detected encoding:", result["encoding"])
    print("Confidence:", result["confidence"])
    print("Language:", result["language"])


if __name__ == "__main__":
    sample_text = "Hello, 世界"
    print_detected_encoding(sample_text)
