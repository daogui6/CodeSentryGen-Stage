class ASN1Error(Exception):
    pass

class ASN1Node:
    def __init__(self, tag_class, constructed, tag_number, value):
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag_number = tag_number
        self.value = value

def parse_tag(data, offset):
    if offset >= len(data):
        raise ASN1Error("Truncated tag")
    b = data[offset]
    tag_class = (b >> 6) & 0x03
    constructed = bool((b >> 5) & 0x01)
    tag_number = b & 0x1F
    offset += 1
    if tag_number == 0x1F:
        tag_number = 0
        while True:
            if offset >= len(data):
                raise ASN1Error("Truncated tag")
            b = data[offset]
            offset += 1
            tag_number = (tag_number << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    return tag_class, constructed, tag_number, offset

def parse_length(data, offset):
    if offset >= len(data):
        raise ASN1Error("Truncated length")
    b = data[offset]
    offset += 1
    if b == 0x80:
        return -1, offset
    if b & 0x80:
        num_bytes = b & 0x7F
        if num_bytes == 0 or num_bytes > 4:
            raise ASN1Error("Invalid length")
        if offset + num_bytes > len(data):
            raise ASN1Error("Truncated length")
        length = int.from_bytes(data[offset:offset+num_bytes], 'big')
        offset += num_bytes
        return length, offset
    return b, offset

def decode_ber(data, offset=0, end=None):
    if end is None:
        end = len(data)
    nodes = []
    while offset < end:
        if end - offset >= 2 and data[offset] == 0x00 and data[offset+1] == 0x00:
            offset += 2
            break
        tag_class, constructed, tag_number, offset = parse_tag(data, offset)
        length, offset = parse_length(data, offset)
        if length == -1:
            value, offset = decode_ber(data, offset, end)
            nodes.append(ASN1Node(tag_class, True, tag_number, value))
        else:
            if offset + length > end:
                raise ASN1Error("Truncated value")
            if constructed:
                value, _ = decode_ber(data, offset, offset + length)
            else:
                value = data[offset:offset+length]
            offset += length
            nodes.append(ASN1Node(tag_class, constructed, tag_number, value))
    return nodes, offset

def encode_tag(tag_class, constructed, tag_number):
    b = (tag_class << 6) | (int(constructed) << 5)
    if tag_number < 0x1F:
        return bytes([b | tag_number])
    else:
        res = [b | 0x1F]
        temp = []
        while tag_number > 0:
            temp.append(tag_number & 0x7F)
            tag_number >>= 7
        temp.reverse()
        for i in range(len(temp)-1):
            res.append(temp[i] | 0x80)
        res.append(temp[-1])
        return bytes(res)

def encode_length(length):
    if length < 0x80:
        return bytes([length])
    else:
        temp = []
        l = length
        while l > 0:
            temp.append(l & 0xFF)
            l >>= 8
        temp.reverse()
        return bytes([0x80 | len(temp)] + temp)

def encode_der(node):
    if isinstance(node, list):
        return b''.join(encode_der(n) for n in node)
    tag_bytes = encode_tag(node.tag_class, node.constructed, node.tag_number)
    if node.constructed:
        value_bytes = b''.join(encode_der(child) for child in node.value)
    else:
        value_bytes = node.value if isinstance(node.value, bytes) else b''
    length_bytes = encode_length(len(value_bytes))
    return tag_bytes + length_bytes + value_bytes

def make_integer(val):
    if val == 0:
        return ASN1Node(0, False, 2, bytes([0]))
    is_neg = val < 0
    if is_neg:
        byte_len = (val.bit_length() + 8) // 8
        val = (1 << (byte_len * 8)) + val
    else:
        byte_len = (val.bit_length() + 7) // 8
    b = val.to_bytes(byte_len, 'big')
    if not is_neg and b[0] & 0x80:
        b = bytes([0]) + b
    return ASN1Node(0, False, 2, b)

def make_sequence(nodes):
    return ASN1Node(0, True, 16, nodes)

def make_octet_string(data):
    return ASN1Node(0, False, 4, data)

if __name__ == "__main__":
    seq = make_sequence([
        make_integer(42),
        make_octet_string(b"hello")
    ])
    der_encoded = encode_der(seq)
    print("DER Encoded:", der_encoded.hex())
    decoded_nodes, _ = decode_ber(der_encoded)
    print("Decoded successfully:", len(decoded_nodes) == 1)
    re_encoded = encode_der(decoded_nodes[0])
    print("Re-encoded matches:", der_encoded == re_encoded)
