
def extended_euclid(a,b) :
    if b == 0:
        return a, 1, 0
    q, w, e = extended_euclid(b,a % b)
    return q, e, w - e *(a//b)

print(extended_euclid(5,16))