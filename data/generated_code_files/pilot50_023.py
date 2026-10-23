from math import gcd


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd_value, x, y


def modular_inverse(value: int, modulus: int) -> int:
    gcd_value, x, _ = extended_gcd(value, modulus)
    if gcd_value != 1:
        raise ValueError("modular inverse does not exist")
    return x % modulus


def generate_demo_keypair() -> tuple[tuple[int, int], tuple[int, int]]:
    p = 61
    q = 53

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 17
    if gcd(e, phi) != 1:
        raise ValueError("public exponent is not coprime with phi")

    d = modular_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


def encrypt(message: int, public_key: tuple[int, int]) -> int:
    e, n = public_key
    if message < 0 or message >= n:
        raise ValueError("message must be in range [0, n)")
    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: tuple[int, int]) -> int:
    d, n = private_key
    return pow(ciphertext, d, n)


if __name__ == "__main__":
    public_key, private_key = generate_demo_keypair()

    message = 123
    ciphertext = encrypt(message, public_key)
    recovered = decrypt(ciphertext, private_key)

    print("Public key:", public_key)
    print("Private key:", private_key)
    print("Message:", message)
    print("Ciphertext:", ciphertext)
    print("Recovered:", recovered)
