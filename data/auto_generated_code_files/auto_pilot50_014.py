import idna
from idna.core import IDNAError

def encode_domain(domain: str) -> str:
    """Converts a Unicode domain name to its ASCII equivalent (ACE)."""
    try:
        return idna.encode(domain).decode('ascii')
    except IDNAError as e:
        raise ValueError(f"Invalid domain name: {e}")

def decode_domain(domain: str) -> str:
    """Converts an ASCII domain name (ACE) back to Unicode."""
    try:
        return idna.decode(domain)
    except IDNAError as e:
        raise ValueError(f"Invalid ACE domain name: {e}")

def validate_domain(domain: str) -> bool:
    """Validates a domain name against IDNA rules."""
    try:
        idna.encode(domain)
        return True
    except IDNAError:
        return False

if __name__ == "__main__":
    test_domain = "münchen.de"
    print(f"Original: {test_domain}")
    print(f"Valid: {validate_domain(test_domain)}")
    encoded = encode_domain(test_domain)
    print(f"Encoded: {encoded}")
    decoded = decode_domain(encoded)
    print(f"Decoded: {decoded}")
