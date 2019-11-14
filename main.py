import secrets
import math

def extended_euclid(a,b) :
    if b == 0:
        return a, 1, 0
    q, w, e = extended_euclid(b,a % b)
    return q, e, w - e *(a//b)

def mrand(l, r):
    sz = r - l + 1
    return l + secrets.randbelow(sz)

def mulmod(a,b,c):
    return (a*b)%c

def fexp(num, exponent, mod):
    if exponent == 0 :
        return 1
    term = fexp(mulmod(num,num,mod), exponent//2, mod)
    if exponent % 2 == 0:
        return term
    else :
        return mulmod(term,num,mod)
        
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    s = 0
    d = n - 1
    while(d % 2 == 0) :
        d = d // 2
        s = s + 1
    for k in range(64) :
        a = mrand(2,n)
        x = fexp(a,d,n)
        if x != 1 and x != n-1 :
            for r in range(1,s):
                x = mulmod(x,x,n)
                if x == 1 :
                    return False
                if x == n-1 :
                    break
            if x != n-1 :
                return False
    return True

def get_primes():
    n = mrand(246,256)
    base_num = 2**n
    x = base_num
    while(not is_prime(x)):
        x = x + 1
    while(not is_prime(base_num)):
        base_num = base_num - 1
    return (x, base_num)

p1, p2 = get_primes()
N = p1 * p2
phiN = (p1-1) * (p2-1)
print(p1,p2)
print(phiN)
e = mrand(10,1000)
while(math.gcd(e, N) != 1 or math.gcd(e, phiN) != 1) :
    e = e + 1
_, d, _ = extended_euclid(e, phiN)
d = (d + 100 * phiN) % phiN
print(math.gcd(e, N), math.gcd(e,phiN))
print(e, d)
print(mulmod(e, d, phiN))
