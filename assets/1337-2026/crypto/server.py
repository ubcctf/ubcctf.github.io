from hashlib import sha256
import os

def otp(flag, key):
    # wait, otp uses + instead of xor?
    return ''.join(chr(ord(flag[i]) + ord(key[i % len(key)])) for i in range(len(flag)))

flag = os.environ.get('FLAG', 'maple{fake_flag}')

while True:
    key = input('enter an OTP key: ')
    ciphertext = otp(flag, key)
    print('ciphertext:', '<<<REDACTED>>>')
    print('ciphertext(hash):', sha256(ciphertext.encode()).hexdigest())
