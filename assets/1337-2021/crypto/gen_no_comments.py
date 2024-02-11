from Crypto.Cipher import AES
import os 
import random 

def aes_enc(block, key):
    assert len(block) == 16 and len(key) == 16
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(block)

def aes_dec(block, key):
    assert len(block) == 16 and len(key) == 16
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(block)

def i2b(x):
    return x.to_bytes(8, byteorder="little")

def pad(in_bytes):
	num_bytes = (16 - len(in_bytes)) % 16
	append = bytes([num_bytes])
	for i in range(num_bytes):
		in_bytes+=append
	return in_bytes

def xor(a, b):
    pairs = zip(a,b)
    return bytes([x ^ y for (x,y) in pairs])

def aes_ctr_mode_enc(plaintext, nonce, key):
    nonce = i2b(nonce) 
    keystream = bytes()
    block_count = 0
    while len(keystream) < len(plaintext): 
        block = nonce + i2b(block_count)   
        block = pad(block)                 
        keystream += aes_enc(block, key)   
        block_count += 1                   
    return xor(plaintext, keystream)      


NONCE = 1337
KEY = os.urandom(16)

if __name__ == "__main__":
    output = []
    with open("secret_3.txt") as f:
        lines = f.readlines()
        for line in lines:
            plaintext = line.encode()
            ciphertext = aes_ctr_mode_enc(plaintext, NONCE, KEY)
            output.append(ciphertext.hex())

    with open("secret.enc", "w") as f:
        for line in output:
            f.write(line + "\n")

    print("Done!")