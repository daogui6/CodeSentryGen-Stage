import random

def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n

def modinv(e, phi):
    def egcd(a, b):
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            q, b, a = b // a, a, b % a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return b, x0, y0
    g, x, _ = egcd(e % phi, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

class RSA:
    def __init__(self, key_size=512):
        p = generate_prime(key_size // 2)
        q = generate_prime(key_size // 2)
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.e = 65537
        if self.e >= self.phi:
            self.e = 3
        self.d = modinv(self.e, self.phi)

    def encrypt(self, plaintext):
        m = int.from_bytes(plaintext.encode('utf-8'), 'big')
        if m >= self.n:
            raise ValueError('Message too long for this key size')
        return pow(m, self.e, self.n)

    def decrypt(self, ciphertext):
        m = pow(ciphertext, self.d, self.n)
        byte_length = (m.bit_length() + 7) // 8
        if byte_length == 0:
            byte_length = 1
        plaintext_bytes = m.to_bytes(byte_length, 'big')
        return plaintext_bytes.decode('utf-8').lstrip(chr(0))

if __name__ == '__main__':
    rsa = RSA(key_size=512)
    msg = 'Hello, RSA!'
    print(f'Original: {msg}')
    enc = rsa.encrypt(msg)
    print(f'Encrypted: {enc}')
    dec = rsa.decrypt(enc)
    print(f'Decrypted: {dec}')
