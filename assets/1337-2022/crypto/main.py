from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from hashlib import sha256
from random import randint
from secrets import flag  # imports the challenge flag
import sys

sys.setrecursionlimit(10**8)

p = getPrime(1024)
G = [[1, 1337], [0, 1]]

# multiply two 2x2 matrices A and B:
def mult(A, B):
    result = [[0, 0], [0, 0]]
    for i in range(2):
        for j in range(2):
            result[i][j] = (A[i][0] * B[0][j] + A[i][1] * B[1][j]) % p
    return result


# compute A^n with exponentiation by squaring
def exp(A, n):
    if n == 0:
        return [[1, 0], [0, 1]]
    half = exp(A, n // 2)
    if n % 2 == 0:
        return mult(half, half)
    return mult(A, mult(half, half))


# generate Alice's private and public keys
alice_secret = randint(0, p)
alice_public = exp(G, alice_secret)

# generate Bob's private and public keys
bob_secret = randint(0, p)
bob_public = exp(G, bob_secret)

# generate their shared secrets & check that they're the same
shared_secret_A = exp(bob_public, alice_secret)
shared_secret_B = exp(alice_public, bob_secret)
assert shared_secret_A == shared_secret_B

# encrypt the flag with the shared secret
key = str(
    shared_secret_A[0][0]
    + shared_secret_A[0][1]
    + shared_secret_A[1][0]
    + shared_secret_A[1][1]
).encode()
key = sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(flag, 16))

print("p:", p)
print("Alice's public key:", alice_public)
print("Bob's public key:", bob_public)
print("Ciphertext:", ciphertext.hex())
