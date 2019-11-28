from math_utils import *
import asn1tools
import base64


class PublicKey:
    def export(self, output_file=''):
        with open(output_file, 'w+') as theFile:
            encoder = asn1tools._compile_files(
                './asn1-structures/RSAPublicKey.asn', 'der', 'der', '/tmp')
            a = encoder[0].encode('RSAPublicKey', {
                'modulus': self.n, 'publicExponent': self.e})
            b = base64.b64encode(a).decode('ascii')
            limit = 64
            offset = 0
            key = f'-----BEGIN PUBLIC KEY-----\r\n'
            while offset < len(b):
                key += b[offset:offset+limit] + '\r\n'
                offset += limit
            key += '-----END PUBLIC KEY-----'
            theFile.write(key)

    @classmethod
    def fromString(cls, input_file):
        with open(input_file, 'r') as theFile:
            data = theFile.readlines()
            encoded = ''
            for i in range(1, len(data)-1):
                encoded += data[i]
            encoder = asn1tools._compile_files(
                './asn1-structures/RSAPublicKey.asn', 'der', 'der', '/tmp')
            content = base64.b64decode(encoded)
            x = encoder[0].decode('RSAPublicKey', content)
            return cls(x['publicExponent'], x['modulus'])

    def __init__(self, e, n):
        self.n = n
        self.e = e


class PrivateKey:
    def export(self, output_file):
        with open(output_file, 'w+') as theFile:
            encoder = asn1tools._compile_files(
                './asn1-structures/RSAPrivateKey.asn', 'der', 'der', '/tmp')
            a = encoder[0].encode('RSAPrivateKey', {
                'modulus': self.n,
                'publicExponent': self.e,
                'privateExponent': self.d,
                'prime1': self.p,
                'prime2': self.q,
                'exponent1': self.dp,
                'exponent2': self.dq,
                'coefficient': self.qinv,
                'version': 0,
            })
            b = base64.b64encode(a).decode('ascii')
            limit = 64
            offset = 0
            key = f'-----BEGIN PRIVATE KEY-----\r\n'
            while offset < len(b):
                key += b[offset:offset+limit] + '\r\n'
                offset += limit
            key += '-----END PRIVATE KEY-----'
            theFile.write(key)

    @classmethod
    def fromString(cls, output_file):
        with open(output_file, 'r') as theFile:
            data = theFile.readlines()
            encoded = ''
            for i in range(1, len(data)-1):
                encoded += data[i]
            encoder = asn1tools._compile_files(
                './asn1-structures/RSAPrivateKey.asn', 'der', 'der', '/tmp')
            content = base64.b64decode(encoded)
            x = encoder[0].decode('RSAPrivateKey', content)
            return cls(x['publicExponent'], x['privateExponent'], x['prime1'], x['prime2'])

    def __init__(self, e, d, p, q):
        self.n = p*q
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = d % (p-1)
        self.dq = d % (q-1)
        _, self.qinv, _ = extended_euclid(q, p)


def generate_key_pair(bit_length):
    allowed_bit_lengths = [512, 1024, 2048, 3072, 4096]

    if bit_length not in allowed_bit_lengths:
        print(f'Key bit length {bit_length} not allowed')
        return

    e = 65537

    # Generate primes
    p = gen_prime(bit_length // 2)
    while (p % e) == 1:
        p = gen_prime(bit_length // 2)

    q = gen_prime(bit_length - bit_length // 2)
    while (q % e) == 1:
        q = gen_prime(bit_length - bit_length // 2)

    # Swap to use CRT when decrypting
    if p < q:
        temp = p
        p = q
        q = temp

    # Calculates N and its totient
    n = p * q
    phiN = (p-1) * (q-1)

    # Gets the equivalent d
    _, d, _ = extended_euclid(e, phiN)
    d = (d + 100 * phiN) % phiN

    # Creates the key objects and return them
    public_key = PublicKey(e, n)
    private_key = PrivateKey(e, d, p, q)
    return public_key, private_key


def encrypt(pub, message):
    """Encrypts an integer array with a provided public key"""
    cipher = [fexp(byte, pub.e, pub.n) for byte in message]
    return cipher


def decrypt(priv, message):
    """Decrypts an integer array with a provided private key"""
    plain = []
    for byte in message:
        m1 = fexp(byte, priv.dp, priv.p)
        m2 = fexp(byte, priv.dq, priv.q)
        h = (priv.qinv*(m1+priv.p - m2)) % priv.p
        m = m2 + h*priv.q
        plain.append(m)
    return plain
