from math import floor, ceil
from secrets import randbits
from Crypto.Util.number import isPrime
from fractions import Fraction
from binascii import hexlify

class GaussianRational:
    def __init__(self, real: Fraction, imag: Fraction):
        assert(type(real) == Fraction)
        assert(type(imag) == Fraction)
        self.real = real
        self.imag = imag

    def conjugate(self):
        return GaussianRational(self.real, self.imag * -1)
    
    def __add__(self, other):
        return GaussianRational(self.real + other.real, self.imag + other.imag)
    
    def __sub__(self, other):
        return GaussianRational(self.real - other.real, self.imag - other.imag)
    
    def __mul__(self, other):
        return GaussianRational(self.real * other.real - self.imag * other.imag, self.real * other.imag + self.imag * other.real)

    def __truediv__(self, other):
        divisor = (other.conjugate() * other).real
        dividend = other.conjugate() * self
        return GaussianRational(dividend.real / divisor, dividend.imag / divisor)
    
    # credit to https://stackoverflow.com/questions/54553489/how-to-calculate-a-modulo-of-complex-numbers
    def __mod__(self, other):
        x = self/other
        y = GaussianRational(Fraction(round(x.real)), Fraction(round(x.imag)))
        z = y*other
        return self - z
    
    # note: does not work for negative exponents
    # exponent is (non-negative) integer, modulus is a Gaussian rational
    def __pow__(self, exponent, modulo):
        shifted_exponent = exponent
        powers = self
        result = GaussianRational(Fraction(1), Fraction(0))
        while (shifted_exponent > 0):
            if (shifted_exponent & 1 == 1):
                result = (result * powers) % modulo
            shifted_exponent >>= 1
            powers = (powers * powers) % modulo
        return result
    
    def __eq__(self, other):
        if type(other) != GaussianRational: return False
        return self.imag == other.imag and self.real == other.real
    
    def __repr__(self):
        return f"{self.real}\n+ {self.imag}i"

# gets a Gaussian prime with real/imaginary component being n bits each
def get_gaussian_prime(nbits):
    while True:
        candidate_real = randbits(nbits-1) + (1 << nbits)
        candidate_imag = randbits(nbits-1) + (1 << nbits)
        if isPrime(candidate_real*candidate_real + candidate_imag*candidate_imag):
            candidate = GaussianRational(Fraction(candidate_real), Fraction(candidate_imag))
            return candidate

def generate_keys(nbits, e=65537):
    p = get_gaussian_prime(nbits)
    q = get_gaussian_prime(nbits)
    N = p*q
    p_norm = int(p.real*p.real + p.imag*p.imag)
    q_norm = int(q.real*q.real + q.imag*q.imag)
    tot = (p_norm - 1) * (q_norm - 1)
    d = pow(e, -1, tot)
    return ((N, e), (N, d), (p, q)) # (N, e) is public key, (N, d) is private key

def encrypt(message, public_key):
    (N, e) = public_key
    return pow(message, e, N)

def decrypt(message, private_key):
    (N, d) = private_key
    return pow(message, d, N)

if __name__ == "__main__":
    flag = None
    with open("flag.txt", "r") as f:
        flag = f.read()
    (public_key, private_key, primes) = generate_keys(512)
    (p, q) = primes
    (N, e) = public_key
    print(f"N = {N}")
    print(f"e = {e}")
    flag1 = flag[:len(flag) // 2].encode()
    flag2 = flag[len(flag) // 2:].encode()
    real = int(hexlify(flag1).decode(), 16)
    imag = int(hexlify(flag2).decode(), 16)
    message = GaussianRational(Fraction(real), Fraction(imag))
    print(f"original: ",  message)
    ciphertext = encrypt(message, public_key)
    message = decrypt(ciphertext, private_key)
    print(f"decrypt", message)
    print(f"ciphertext = {ciphertext}")
    print(f"\n-- THE FOLLOWING IS YOUR SECRET KEY. DO NOT SHOW THIS TO ANYONE ELSE --")
    print(f"p = {p}")
    print(f"q = {q}")
