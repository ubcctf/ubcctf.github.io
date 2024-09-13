import hashlib
import os

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def pad(msg, block_size=16):
    return msg + b'\x00' * (block_size - len(msg))

def md5_cbc(msg, key):
    blocks = []
    prev = b'\x00' * 16
    for i in range(len(msg)):
        pt = pad(msg[i:i+1])
        ct = hashlib.md5(xor(pt, prev) + key).digest()
        blocks.append(ct)
        prev = ct
    return b''.join(blocks)

if __name__ == '__main__':
    with open('flag.txt', 'rb') as f:
        flag = f.read()

    # totally secure and not guessable key
    key = pad(os.urandom(1))

    print('Your encrypted flag (in hex):')
    print(md5_cbc(flag, key).hex())
