from dataclasses import dataclass
from typing import Iterable


INTEGER_TAG = 0x02
OCTET_STRING_TAG = 0x04
NULL_TAG = 0x05
SEQUENCE_TAG = 0x30


@dataclass
class ASN1Value:
    tag: int
    value: bytes


def encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")

    if length < 128:
        return bytes([length])

    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    first = data[offset]
    offset += 1

    if first < 128:
        return first, offset

    length_size = first & 0x7F
    length = int.from_bytes(data[offset:offset + length_size], "big")
    return length, offset + length_size


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def decode_tlv(data: bytes, offset: int = 0) -> tuple[ASN1Value, int]:
    tag = data[offset]
    offset += 1

    length, offset = decode_length(data, offset)
    value = data[offset:offset + length]
    return ASN1Value(tag, value), offset + length


def encode_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative integers are not supported in this demo")

    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw

    return encode_tlv(INTEGER_TAG, raw)


def encode_octet_string(value: bytes) -> bytes:
    return encode_tlv(OCTET_STRING_TAG, value)


def encode_null() -> bytes:
    return encode_tlv(NULL_TAG, b"")


def encode_sequence(items: Iterable[bytes]) -> bytes:
    return encode_tlv(SEQUENCE_TAG, b"".join(items))


def decode_integer(value: bytes) -> int:
    return int.from_bytes(value, "big")


if __name__ == "__main__":
    der = encode_sequence([
        encode_integer(42),
        encode_octet_string(b"hello"),
        encode_null(),
    ])

    print("DER-like encoded data:", der.hex())

    top_level, _ = decode_tlv(der)
    print("Top-level tag:", hex(top_level.tag))
    print("Payload length:", len(top_level.value))

    offset = 0
    while offset < len(top_level.value):
        item, offset = decode_tlv(top_level.value, offset)
        if item.tag == INTEGER_TAG:
            print("INTEGER:", decode_integer(item.value))
        elif item.tag == OCTET_STRING_TAG:
            print("OCTET STRING:", item.value)
        elif item.tag == NULL_TAG:
            print("NULL")
