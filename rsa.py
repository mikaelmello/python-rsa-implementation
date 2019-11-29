from math_utils import *
import asn1tools
import base64
import hashlib


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
    def importFile(cls, input_file):
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
    def importFile(cls, input_file):
        with open(input_file, 'r') as theFile:
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


def encrypt(key, message):
    """Encrypts an integer array with a provided key"""

    length = bits(key.n) // 8
    max_octets = length - 11
    plain = bytearray(message, "utf-8")
    padding_size = length - 3 - len(plain)

    if len(plain) >= max_octets:
        raise f'Message must have size of at most {max_octets} octets, it has {len(plain)}'

    encryption_block = bytearray()  # EB = 00 || BT || PS || 00 || D
    encryption_block.append(0x00)

    if type(key) is PrivateKey:
        encryption_block.append(0x01)
        for i in range(padding_size):
            encryption_block.append(0xFF)
    elif type(key) is PublicKey:
        encryption_block.append(0x02)
        for i in range(padding_size):
            random_octet = secrets.randbits(8)
            while random_octet == 0x00:
                random_octet = secrets.randbits(8)
            encryption_block.append(random_octet)
    else:
        raise 'Unknown key type'

    encryption_block.append(0x00)

    encryption_block.extend(plain)
    data = int.from_bytes(encryption_block, 'big')

    cipher = 0
    if type(key) is PrivateKey:
        m1 = fexp(data, key.dp, key.p)
        m2 = fexp(data, key.dq, key.q)
        h = (key.qinv*(m1+key.p - m2)) % key.p
        cipher = m2 + h*key.q
    else:
        cipher = fexp(data, key.e, key.n)

    hexrep = hex(cipher)[2:]
    if len(hexrep) % 2 == 1:
        hexrep = '0' + hexrep
    return hexrep


def sign(key, file, output):
    if type(key) is not PrivateKey:
        raise 'Must be private key to sign files'

    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(output, 'w+') as ofile:
        with open(file, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        hash = hasher.hexdigest()

        signature = encrypt(key, hash)
        ofile.write(signature)


def verify(key, file, signature_file):
    if type(key) is not PublicKey:
        raise 'Must be public key to sign files'

    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(signature_file, 'r') as ofile:
        signature = ofile.read()

        try:
            hash = decrypt(key, signature)

            with open(file, 'rb') as afile:
                buf = afile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile.read(BLOCKSIZE)
            file_hash = hasher.hexdigest()

            if file_hash == hash:
                print('Verified')
            else:
                print('Not verified')
        except:
            print('Not verified')


def decrypt(key, message):
    """Decrypts an integer array with a provided key key"""

    length = bits(key.n) // 8
    max_octets = length - 11
    data = int.from_bytes(bytes.fromhex(message), 'big')
    plain = data

    if type(key) is PrivateKey:
        m1 = fexp(data, key.dp, key.p)
        m2 = fexp(data, key.dq, key.q)
        h = (key.qinv*(m1+key.p - m2)) % key.p
        plain = m2 + h*key.q
    else:
        plain = fexp(data, key.e, key.n)

    plain_bytes = int.to_bytes(plain, length, 'big')
    if plain_bytes[0] != 0x00:
        raise 'Invalid decryption, wrong header byte'

    if plain_bytes[1] == 0x02 and type(key) is PublicKey:
        raise 'Trying to decrypt using public key when header says it should be a private key'
    elif plain_bytes[1] != 0x02 and type(key) is PrivateKey:
        raise 'Trying to decrypt using private key when header says it should be a public key'

    padding_index = 2
    while plain_bytes[padding_index] != 0x00:
        padding_index += 1
    padding_length = padding_index - 2 + 1

    if padding_length < 8:
        raise 'Invalid padding string'

    data = plain_bytes[padding_index + 1:]
    return str(data, 'utf-8')
