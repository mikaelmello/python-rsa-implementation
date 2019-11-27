import rsa

public_key, private_key = rsa.generate_key_pair()

print(public_key.n)
print(public_key.exp)
print(private_key.n)
print(private_key.exp)
