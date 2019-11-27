from math_utils import *


class Key:
    def __init__(self, exp, n):
        self.n = n
        self.exp = exp


def generate_key_pair():
    # Gets large primes
    p1, p2 = get_large_primes()

    # Calculates N and its totient
    n = p1 * p2
    phiN = (p1-1) * (p2-1)

    # Get a random e until it satisfies our condition
    # This does not take long for probabilistic reasons
    e = mrand(1, phiN-1)
    while(math.gcd(e, n) != 1 or math.gcd(e, phiN) != 1):
        e = mrand(1, phiN-1)

    # Gets the equivalent d
    _, d, _ = extended_euclid(e, phiN)
    d = (d + 100 * phiN) % phiN

    # Creates the key objects and return them
    public_key = Key(e, n)
    private_key = Key(d, n)
    return public_key, private_key
