import secrets
import math


def extended_euclid(a, b):
    """Extended euclidean algorithm"""
    s = 0
    t = 1
    r = b
    old_s = 1
    old_t = 0
    old_r = a

    while r != 0:
        quotient = old_r // r
        old_r, r = (r, old_r - quotient * r)
        old_s, s = (s, old_s - quotient * s)
        old_t, t = (t, old_t - quotient * t)

    return old_r, old_s, old_t


def mrand(l, r):
    """Generates a random number between l and r, inclusive"""
    sz = r - l + 1
    return l + secrets.randbelow(sz)


def bits(a):
    count = 0
    while a > 0:
        a = a // 2
        count += 1
    return count


def mulmod(a, b, c):
    """Returns (a*b)%c"""
    return (a*b) % c


def fexp(num, exponent, mod):
    """Fast exponentiation, returns (num^exponent)%mod."""
    res = 1
    while exponent > 0:
        if exponent % 2 == 1:
            res = (res * num) % mod

        exponent = exponent // 2
        num = (num * num) % mod
    return res


def is_prime(n):
    """Checks whether a number is prime"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    s = 0
    d = n - 1
    while(d % 2 == 0):
        d = d // 2
        s = s + 1
    for k in range(64):
        a = mrand(2, n)
        x = fexp(a, d, n)
        if x != 1 and x != n-1:
            for r in range(1, s):
                x = mulmod(x, x, n)
                if x == 1:
                    return False
                if x == n-1:
                    break
            if x != n-1:
                return False
    return True


def gen_prime(bit_length):
    prime = secrets.randbits(bit_length)
    prime = prime | 1
    prime = prime | (1 << (bit_length-1))
    prime = prime | (1 << (bit_length-2))

    while not is_prime(prime):
        prime += 2

    return prime


def get_large_primes():
    """Generates two large primes"""
    n = mrand(246, 256)
    base_num = 2**n
    x = base_num
    while(not is_prime(x)):
        x = x + 1
    while(not is_prime(base_num)):
        base_num = base_num - 1
    return (x, base_num)
