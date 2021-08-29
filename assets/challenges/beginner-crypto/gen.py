from Crypto.Cipher import AES # pip install pycryptodome
import os 

# Encrypt a single 16 byte block with AES
def aes_enc(block, key):
    assert len(block) == 16 and len(key) == 16
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(block)

# Decrypt a single 16 byte block with AES
def aes_dec(block, key):
    assert len(block) == 16 and len(key) == 16
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(block)

# Convert an int into 8 little endian bytes
def i2b(x):
    return x.to_bytes(8, byteorder="little")

# Pad some bytes to 16 bytes, you don't need to know the details about how this works. It's PKCS#7 if you're curious
def pad(in_bytes):
	num_bytes = (16 - len(in_bytes)) % 16
	append = bytes([num_bytes])
	for i in range(num_bytes):
		in_bytes+=append
	return in_bytes

# Remember ^ is integer xor in python
def xor(a, b):
    pairs = zip(a,b)
    return bytes([x ^ y for (x,y) in pairs])

def aes_ctr_mode_enc(plaintext, nonce, key):
    nonce = i2b(nonce) # nonces are typically numbers from random number generators
                       # but we want bytes so we can use it with our cipher

    keystream = bytes() # the random bytes we're going to xor our plaintext message with
    block_count = 0
    while len(keystream) < len(plaintext): # while we still need more keystream 
        block = nonce + i2b(block_count)   # make the next counter block
        block = pad(block)                 # pad the block to 16 bytes
        keystream += aes_enc(block, key)   # generate 16 random bytes for the keystream using AES
        block_count += 1                   # increment the counter
    return xor(plaintext, keystream)       # finally do the xor to encrypt the message


NONCE = 1337 # uh oh
KEY = os.urandom(16)

if __name__ == "__main__":
    output = []
    with open("secret_3.txt") as f:
        lines = f.readlines()
        for line in lines:
            plaintext = line.encode() # convert from string to bytes
            ciphertext = aes_ctr_mode_enc(plaintext, NONCE, KEY) # Nonce reuse! Each line will be using the same keystream!
            output.append(ciphertext.hex())

    with open("secret.enc", "w") as f:
        for line in output:
            f.write(line + "\n")

    print("Done!")