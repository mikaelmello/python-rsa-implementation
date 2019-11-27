from math_utils import *


class Key:
    def __init__(self, exp, n):
        self.n = n
        self.exp = exp


def generate_key_pair(bit_length):
    allowed_bit_lengths = [512, 1024, 2048, 3072, 4096]

    if bit_length not in allowed_bit_lengths:
        print(f'Key bit length {bit_length} not allowed')
        return

    e = 65537

    p = gen_prime(bit_length // 2)
    while (p % e) == 1:
        p = gen_prime(bit_length // 2)

    q = gen_prime(bit_length - bit_length // 2)
    while (q % e) == 1:
        q = gen_prime(bit_length - bit_length // 2)

    # Calculates N and its totient
    n = p * q
    phiN = (p-1) * (q-1)

    # Gets the equivalent d
    _, d, _ = extended_euclid(e, phiN)
    d = (d + 100 * phiN) % phiN

    # Creates the key objects and return them
    public_key = Key(e, n)
    private_key = Key(d, n)
    return public_key, private_key
