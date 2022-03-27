---
layout: post
title: "[LINE CTF 2022] Crypto"
author: vEvergarden
---

# ss-puzzle [100]

## Description
> I had stored this FLAG securely in five separate locations. However, three of the shares were lost and one was partially broken. Can you restore flag?

Attachments: `Share1`, `Share4`, `ss_puzzle.py`

We're given two raw files (Share1: `25243e2a3120271500000000000000002b0719073a0d2c2f0214251c09404813`) and (Share4: `1d08081b2d1d12310331361e3319061c0607001b3a0f311f3933342926756706`), along with the sharing scheme:

```python
S = [None]*4
R = [None]*4
Share = [None]*5

S[0] = FLAG[0:8]
S[1] = FLAG[8:16]
S[2] = FLAG[16:24]
S[3] = FLAG[24:32]

# Ideally, R should be random stream. (Not hint)
R[0] = FLAG[32:40]
R[1] = FLAG[40:48]
R[2] = FLAG[48:56]
R[3] = FLAG[56:64]

Share[0] = R[0]            + xor(R[1], S[3]) + xor(R[2], S[2]) + xor(R[3],S[1])
Share[1] = xor(R[0], S[0]) + R[1]            + xor(R[2], S[3]) + xor(R[3],S[2])
Share[2] = xor(R[0], S[1]) + xor(R[1], S[0]) + R[2]            + xor(R[3],S[3])
Share[3] = xor(R[0], S[2]) + xor(R[1], S[1]) + xor(R[2], S[0]) + R[3]
Share[4] = xor(R[0], S[3]) + xor(R[1], S[2]) + xor(R[2], S[1]) + xor(R[3],S[0])


# This share is partially broken.
Share[1] = Share[1][0:8]   + b'\x00'*8       + Share[1][16:24] + Share[1][24:32]
```

## Solve

Luckily, we know that the flag format is `LINECTF{`, which corresponds to `S[0]`.

From the first 8 bytes of `Share[1]`, we can find `R[0]` by performing `xor(Share[1][:8], S[0])`. Similarly, knowing `R[0]`, we can find `S[3]` from the first 8 bytes of `Share[4]`.

We can continue doing this until we find all 8-byte blocks:

```python
s0 = b'LINECTF{'
r0 = xor(share1[0:8], s0)
s3 = xor(share4[0:8], r0)
r2 = xor(share1[16:24], s3)
s1 = xor(share4[16:24], r2)
r3 = xor(share4[24:], s0)
s2 = xor(share1[24:], r3)
r1 = xor(share4[8:16], s2)
```

Stitching the blocks together: `LINECTF{Yeah_known_plaintext_is_important_in_xor_based_puzzle!!}`


# X Factor [100]

## Description

> Decrypt it!

Attachments: `x_factor.md`

```md
I have generated a RSA-1024 key pair:
* public key exponent: 0x10001
* public key modulus: 0xa9e7da28ebecf1f88efe012b8502122d70b167bdcfa11fd24429c23f27f55ee2cc3dcd7f337d0e630985152e114830423bfaf83f4f15d2d05826bf511c343c1b13bef744ff2232fb91416484be4e130a007a9b432225c5ead5a1faf02fa1b1b53d1adc6e62236c798f76695bb59f737d2701fe42f1fbf57385c29de12e79c5b3

Here are some known plain -> signature pairs I generated using my private key:
* 0x945d86b04b2e7c7 -> 0x17bb21949d5a0f590c6126e26dc830b51d52b8d0eb4f2b69494a9f9a637edb1061bec153f0c1d9dd55b1ad0fd4d58c46e2df51d293cdaaf1f74d5eb2f230568304eebb327e30879163790f3f860ca2da53ee0c60c5e1b2c3964dbcf194c27697a830a88d53b6e0ae29c616e4f9826ec91f7d390fb42409593e1815dbe48f7ed4
* 0x5de2 -> 0x3ea73715787028b52796061fb887a7d36fb1ba1f9734e9fd6cb6188e087da5bfc26c4bfe1b4f0cbfa0d693d4ac0494efa58888e8415964c124f7ef293a8ee2bc403cad6e9a201cdd442c102b30009a3b63fa61cdd7b31ce9da03507901b49a654e4bb2b03979aea0fab3731d4e564c3c30c75aa1d079594723b60248d9bdde50
* 0xa16b201cdd42ad70da249 -> 0x9444e3fc71056d25489e5ce78c6c986c029f12b61f4f4b5cbd4a0ce6b999919d12c8872b8f2a8a7e91bd0f263a4ead8f2aa4f7e9fdb9096c2ea11f693f6aa73d6b9d5e351617d6f95849f9c73edabd6a6fde6cc2e4559e67b0e4a2ea8d6897b32675be6fc72a6172fd42a8a8e96adfc2b899015b73ff80d09c35909be0a6e13a
* 0x6d993121ed46b -> 0x2b7a1c4a1a9e9f9179ab7b05dd9e0089695f895864b52c73bfbc37af3008e5c187518b56b9e819cc2f9dfdffdfb86b7cc44222b66d3ea49db72c72eb50377c8e6eb6f6cbf62efab760e4a697cbfdcdc47d1adc183cc790d2e86490da0705717e5908ad1af85c58c9429e15ea7c83ccf7d86048571d50bd721e5b3a0912bed7c
* 0x726fa7a7 -> 0xa7d5548d5e4339176a54ae1b3832d328e7c512be5252dabd05afa28cd92c7932b7d1c582dc26a0ce4f06b1e96814ee362ed475ddaf30dd37af0022441b36f08ec8c7c4135d6174167a43fa34f587abf806a4820e4f74708624518044f272e3e1215404e65b0219d42a706e5c295b9bf0ee8b7b7f9b6a75d76be64cf7c27dfaeb
* 0x31e828d97a0874cff -> 0x67832c41a913bcc79631780088784e46402a0a0820826e648d84f9cc14ac99f7d8c10cf48a6774388daabcc0546d4e1e8e345ee7fc60b249d95d953ad4d923ca3ac96492ba71c9085d40753cab256948d61aeee96e0fe6c9a0134b807734a32f26430b325df7b6c9f8ba445e7152c2bf86b4dfd4293a53a8d6f003bf8cf5dffd
* 0x904a515 -> 0x927a6ecd74bb7c7829741d290bc4a1fd844fa384ae3503b487ed51dbf9f79308bb11238f2ac389f8290e5bcebb0a4b9e09eda084f27add7b1995eeda57eb043deee72bfef97c3f90171b7b91785c2629ac9c31cbdcb25d081b8a1abc4d98c4a1fd9f074b583b5298b2b6cc38ca0832c2174c96f2c629afe74949d97918cbee4a

**What is the signature of 0x686178656c696f6e?**

Take the least significant 16 bytes of the signature, encode them in lowercase hexadecimal and format it as `LINECTF{sig_lowest_16_bytes_hex}` to obtain the flag.
E.g. the last signature from the list above would become `LINECTF{174c96f2c629afe74949d97918cbee4a}`.
```

## Solve

I first skipped over the plaintext-signature pairs and tried to factor the modulus/find the private key (Alpertron ECM, Wiener's attack), but unfortunately nothing came up.

Signing a message naively with RSA is raising the plaintext `m` to the private key `d`. In other words,

$$m ^ d \equiv c \mod N$$

Our goal is to find the value of

$$(0x686178656c696f6e) ^ d \equiv c \mod N$$

Usually this would require knowing the private key `d`, but notice that if:

$$m_1 ^ d \equiv c_2 \mod N$$

$$m_2 ^ d \equiv c_1 \mod N$$

Then,

$$(m_1 \cdot m_2) ^ d \equiv c_1 \cdot c_2 \mod N$$

So, we can try to express the value 0x686178656c696f6e as the product/division of the given plaintexts.

Looking closer at the values being signed:
- `0x945d86b04b2e7c7` factors as: `[811, 947, 947, 947, 970111]`
- `0x5de2` factors as: `[2, 61, 197]`
- `0xa16b201cdd42ad70da249` factors as: `[970111, 2098711, 2098711, 2854343]`
- `0x6d993121ed46b` factors as: `[947, 970111, 2098711]`
- `0x726fa7a7` factors as: `[61, 197, 197, 811]`
- `0x31e828d97a0874cff` factors as: `[2098711, 2854343, 9605087]`
- `0x904a515` factors as: `[197, 811, 947]`

And since `0x686178656c696f6e` factors as: `[2, 197, 947, 2098711, 9605087]`, our idea should likely work.

We can raise each value to a small negative or positive exponent, and see if the products match up to the target plaintext.

## Script
```python
from factordb.factordb import FactorDB

e = 0x10001
n = 0xa9e7da28ebecf1f88efe012b8502122d70b167bdcfa11fd24429c23f27f55ee2cc3dcd7f337d0e630985152e114830423bfaf83f4f15d2d05826bf511c343c1b13bef744ff2232fb91416484be4e130a007a9b432225c5ead5a1faf02fa1b1b53d1adc6e62236c798f76695bb59f737d2701fe42f1fbf57385c29de12e79c5b3

q = []
q.append((0x945d86b04b2e7c7, 0x17bb21949d5a0f590c6126e26dc830b51d52b8d0eb4f2b69494a9f9a637edb1061bec153f0c1d9dd55b1ad0fd4d58c46e2df51d293cdaaf1f74d5eb2f230568304eebb327e30879163790f3f860ca2da53ee0c60c5e1b2c3964dbcf194c27697a830a88d53b6e0ae29c616e4f9826ec91f7d390fb42409593e1815dbe48f7ed4))
q.append((0x5de2, 0x3ea73715787028b52796061fb887a7d36fb1ba1f9734e9fd6cb6188e087da5bfc26c4bfe1b4f0cbfa0d693d4ac0494efa58888e8415964c124f7ef293a8ee2bc403cad6e9a201cdd442c102b30009a3b63fa61cdd7b31ce9da03507901b49a654e4bb2b03979aea0fab3731d4e564c3c30c75aa1d079594723b60248d9bdde50))
...

'''
print out the factors of each plaintext
for i in range(len(q)):
	f = FactorDB(q[i][0])
	f.connect()
	print(f"- `{hex(q[i][0])}` factors as: `{f.get_factor_list()}`")
'''

target = 0x686178656c696f6e
def recur(index, cur, sigs):
	if index == len(q):
		if abs(target - cur) < 10 ** 5:
			print("Found: ", hex(sigs)[-32:])
		return
	
	for i in range(-3, 3):
		recur(index + 1, cur * pow(q[index][0], i), sigs * pow(q[index][1], i, n) % n)

recur(0, 1, 1)

```

Flag: `LINECTF{a049347a7db8226d496eb55c15b1d840}`


# Baby crypto revisited [138]

## Description

> Last time, our side-channel attack was quite easy. But our victim found out about our sneaky attack and increased the size of nonce. Fortunately, we could still capture the first half of the nonce, which is 64-bit this time. Now please help us to find out the encryption key again. The victim is using the secp160r1 curve. The following is the captured data: r, s, k, and hash respectively. Flag is LINECTF{<encryption key>}, e.g. LINECTF{0x1234}

The file contains 100 leaked signatures of the form:

```
0xe6b7c5a62d08e0216e1e7ed7948c96b74c0be9cd 0x49e1050393f885117de74e7a02d1091d67faa3d0 0xff07bbee67c3ab910000000000000000 0xe91f3200a87205d18a97bdf3bb3027c9f532c8a4
0x7e7b86c8624c9b597131bb883053b1856527a5ff 0x7787b9157fbbaf178ed091b23ce30b2e1ccf9abf 0x882f44f29c56aea60000000000000000 0x37c9f0d06570b0087430b9c66372e385839bb348
0x7951eb8b6ef6ebd080c0171252c53b40fd4ac3b5 0xe70efd784e8a5a35ebd875c4df23132324946e5f 0x842f1342234670730000000000000000 0x7635013447c4b0e7c637dde0b9f8f2eed2cda796
0xae1f8afabb6c971626e8616f30dc0781dee744ae 0xd836a959f2e963291c572a261081ada95ff8a3a 0x37261d496392b4140000000000000000 0x2e7684cae69cd153426acc333bace2c6a294ed4c
0x7b2ad17514e099820de955acf788a0820ce84d0b 0x8d55725ac8252cdc7b65ce9eb12fb87961ec0026 0xe1885611d2d677ba0000000000000000 0x4df56d8d7d972857e5d24d0b18eb0d5738cec1e0
0x4381ac639a53c05bbdd79e936edb1a9aad643a2e 0xb0a40dbd60ff868d233b4446a61592043eb3ea8a 0x780b62dd774107aa0000000000000000 0xf9a118138aa3916a469b0cf37a04f6b763ec978a
0xdac404ce56ca251e570de84c34bf53884c8b7f76 0xc99e802da4c9718c713ad53b616e25a6bb1a476b 0x6c5c4d7eacb9103a0000000000000000 0x926ca7ee88e96e6aed71e213e3aef1e3425583aa
```

## Introduction

An important aspect of [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) is that the random nonce should **always** be secret and cryptographically random. In fact, attacks such as [LadderLeak](https://eprint.iacr.org/2020/615.pdf) were able to recover the private key by repeatedly leaking *less than one bit of the nonce*. Trail of Bits has a nice [post](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/) that explains how nonce biases can be exploited.

If you know the nonce of a given signature, where $H(m)$ is the hash of the message:

$$s \equiv k^{-1}(H(m) + rd_a)$$

You can rearrange the equation to solve for $d_a$, the private key:

$$d_a \equiv r^{-1}(ks - H(m))$$

The attack described in [Biased Nonce Sense](https://eprint.iacr.org/2019/023.pdf) employs lattice to solve the hidden number problem, where you find a solution $x_1, x_2, ... x_n, y$ to the linear equations:

$$x_1 - t_1y + a_1 \equiv 0 \mod p$$

$$x_2 - t_2y + a_2 \equiv 0 \mod p$$

$$...$$

$$x_n - t_ny + a_n \equiv 0 \mod p$$

ECDSA signatures also follow this structure:

$$k_i - (s_i^{-1}r_i)d + (-s_i^{-1}h_i) \equiv 0 \mod n$$

Since we're given the first 64 bits of the nonce, we can write $k_i$ as $k_{ih} + k_{il}$, where $k_{il}$ represents the lower 64 bits and $k_{ih}$ the leaked nonce (i.e. `0x6c5c4d7eacb9103a0000000000000000`)

So,

$$k_l - (s_i^{-1}r_i)d + (k_h-s_i^{-1}h_i) \equiv 0 \mod n$$

To solve the hidden number problem, we construct a lattice like shown, except with $(h_i s_i^{-1} - k_{ih})$ in the bottom row:

![Lattice](https://i0.wp.com/blog.trailofbits.com/wp-content/uploads/2020/06/screen-shot-2020-04-25-at-2.32.39-pm.png?resize=428%2C322&ssl=1)

Image Source: [Trail of Bits](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)

After `LLL`, the rows of the matrix should contain the lower 64 bits of the nonces $k_{1l}, k_{2l}, ... k_{nl}$ that satisfy the above equations. Indeed, the second row produces: `(1446378667213923537, 14375776078636111506, ... 18446744073709551616)`.

We can take any of these nonces and the corresponding signature to solve for the private key.

## Script
```python
from Crypto.Util.number import *

with open('data.txt', 'r') as f:
	lines = f.readlines()

# https://neuromancer.sk/std/secg/secp160r1
n = 0x0100000000000000000001f4c8f927aed3ca752257

sz = 100
B = 2 ** 64
sigs = [list(map(lambda a: int(a, 16), l.split())) for l in lines]

matrix = [[0] * (sz + 2) for _ in range(sz + 2)]

for i in range(sz):
	matrix[i][i] = n

matrix[-2][-2] = B/n
matrix[-1][-1] = B

for i in range(sz):
	r = sigs[i][0]
	s = sigs[i][1]
	k = sigs[i][2]
	h = sigs[i][3]
	
	matrix[-2][i] = r * inverse(s, n)
	matrix[-1][i] = h * inverse(s, n) - k

m = Matrix(matrix)
m = m.LLL()

for r in m:
	print(r)

# ^^ gives this (64-bit) nonce
k_lower = 1446378667213923537
r = sigs[0][0]
s = sigs[0][1]
k = sigs[0][2] + k_lower
h = sigs[0][3]

key = inverse(r, n) * (k * s - h) % n
print(hex(key))
```

Flag: `LINECTF{0xd77d10fec685cbe16f64cba090db24d23b92f824}`

The attack works even with **only 2** signatures from the 100 provided!

# Forward-or [145]

## Description
> I doubled the length of the key to make this cipher even more secure. Can you decrypt it?

Attachments: `main.py`, `present.py`, and `output.txt`

`main.py`:
```python
class CTRMode():
    def __init__(self, key, nonce=None):
        self.key = key # 20bytes
        self.cipher = DoubleRoundReducedPresent(key)
        if None==nonce:
            nonce = os.urandom(self.cipher.block_size//2)
        self.nonce = nonce # 4bytes
    
    def XorStream(self, data):
        output = b""
        counter = 0
        for i in range(0, len(data), self.cipher.block_size):
            keystream = self.cipher.encrypt(self.nonce+counter.to_bytes(self.cipher.block_size//2, 'big'))
            if b""==keystream:
                exit(1)

            if len(data)<i+self.cipher.block_size:
                block = data[i:len(data)]
            block = data[i:i+self.cipher.block_size]
            block = strxor(keystream[:len(block)], block)
            
            output+=block
            counter+=1
        return output

    def encrypt(self, plaintext):
        return self.XorStream(plaintext)

    def decrypt(self, ciphertext):
        return self.XorStream(ciphertext)

class DoubleRoundReducedPresent():
    def __init__(self, key):
        self.block_size = 8
        self.key_length = 160
        self.round = 16
        self.cipher0 = Present(key[0:10], self.round)
        self.cipher1 = Present(key[10:20], self.round)
    
    def encrypt(self, plaintext):
        ...
        return self.cipher1.encrypt(self.cipher0.encrypt(plaintext))
    
    def decrypt(self, ciphertext):
        ...
        return self.cipher0.decrypt(self.cipher1.decrypt(ciphertext))

if __name__ == "__main__":
    ...

    # load key
    if not re.fullmatch(r'[0-3]+', key):
        exit(1)

    key = key.encode('ascii')

    # load flag
    flag = flag.encode('ascii')

    plain = flag
    cipher = CTRMode(key)
    ciphertext = cipher.encrypt(plain)
    nonce = cipher.nonce

    print(ciphertext.hex())
    print(nonce.hex())
```

`present.py` borrows the implementation from [pypresent.py](http://www.lightweightcrypto.org/downloads/implementations/pypresent.py).

`output.txt`: 
```
ciphertext_hex="3201339d0fcffbd152f169ddcb8349647d8bc36a73abc4d981d3206f4b1d98468995b9b1c15dc0f0"
nonce_hex="32e10325"
```

## Introduction

First, note that the key is matched against the regex: `[0-3]+`, which means that the key only contains the digits 0 through 3. Since the key is 20 bytes, a brute-force would take around $4^{20} = 2^{40}$ tries, too slow considering that the cipher also needs to decrypt a message each time.

However, the `DoubleRoundReducedPresent` round reduced class immediately draws suspicion: it divides the key into two 10-byte pieces, and encrypts/decrypts a message sequentially.

This makes the cipher vulnerable to a [meet-in-the-middle](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack) attack, the same principle that rendered Double DES insecure. Say that we know a single plaintext-ciphertext pair, encrypted by unknown keys $k_1$ and $k_2$:

Then,

$$C = ENC_{k2}(ENC_{k1}(P))$$

$$DEC_{k2}(C) = ENC_{k1}(P)$$

Instead of trying every combination of $(k_1, k_2)$, we can try all possible keys $k$, and calculate $DEC_{k}(C)$ and $ENC_{k}(P)$. If the decryption matches with a previous encryption, or vice versa, then we've found a potential pair of keys $(k_1, k_2)$. This attack would only take $4^{10} = 2^{20}$ operations since we're brute-forcing all possible 10-byte keys.

## Solve

There's one problem: we're only given the ciphertext and nonce, not the corresponding plaintext. The `CTRMODE` generates a psuedo-random keystream by encrypting the nonce and counter. Afterward, it XORs the keystream with the plaintext to produce the ciphertext. We don't know what $ENC(\text{nonce} + \text{counter})$ is, but we do know that the flag starts with `LINECTF{`!

So, we have a plaintext-ciphertext pair:

```python
P = nonce + counter.to_bytes(4, 'big')
C = xor('LINECTF', ciphertext[:8])
```

Now, we can brute force all possible 10-byte keys.

## Script
```python
from present import Present

...
ct = bytes.fromhex("3201339d0fcffbd152f169ddcb8349647d8bc36a73abc4d981d3206f4b1d98468995b9b1c15dc0f0")
nonce = bytes.fromhex("32e10325")

# take advantage of the known plaintext
counter = 0
plaintext = nonce + counter.to_bytes(4, 'big')

# data = block ^ keystream
# keystream = data ^ block
ciphertext = xor(b'LINECTF{', ct[:8])

pool_encrypted = {}
pool_decrypted = {}

# generate all 10-byte keys
possible = []
def recur(index, cur):
	if index == 10:
		possible.append(cur.encode('ascii'))
		return

	for i in range(4):
		recur(index + 1, cur + str(i))

recur(0, "")

# meet-in-the-middle
cnt = 0
for cur in possible:
	if cnt % 2 ** 16 == 0:
		print("[x] Status: {cnt}")

	cipher = Present(cur, 16)
	encrypted = cipher.encrypt(plaintext)
	decrypted = cipher.decrypt(ciphertext)

	pool_decrypted[decrypted] = cur
	pool_encrypted[encrypted] = cur

	if encrypted in pool_decrypted:
		print("Found!")
		print("Encrypted key: ", cur)
		print("Decrypted key: ", pool_decrypted[encrypted])

	cnt += 1
```

The script spits out a single keypair, `(3201323020, 2123003302)`. 

After decryption, we get our flag: `LINECTF{|->TH3Y_m3t_UP_1n_th3_m1ddl3<-|}`.