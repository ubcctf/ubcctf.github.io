---
layout: post
title: "[UTCTF 2022] Forky"
author: Robert Xiao
---

## Problem Description

### Forky

- Solves: 5
- Score: 1000
- Tags: cryptography

I like forks.

By Soham Roy (@Sohamster on discord)

`nc misc1.utctf.live 9992`

Attachments: `app.c`

## Introduction

We're provided a C program which implements a forking server that encrypts data using libsodium. The basic flow of the program is as follows:

1. Initialize a custom random number generator for libsodium which uses a set of global variables seeded with `getrandom` and a ChaCha20-based PRNG.
2. Initialize a random 32-byte encryption key
3. Create a listening socket on the given port
4. Accept a connection from the socket
5. Encrypt the flag and send it to the accepted connection
6. Fork, and handle the client in the child process. Parent process returns to `accept()`.
    1. In the child process, read 146 bytes from the client
    2. Encrypt the user's input and send it to the client

Encryption works as follows in `ee_buf`:

1. Generate a 24-byte nonce using the libsodium `randombytes_buf`, which forwards to the custom RNG implementation
2. Use `crypto_aead_xchacha20poly1305_ietf_encrypt_detached` to encrypt the input with the random key and generated nonce.
3. Encode the encrypted message + nonce + MAC tag with URL-safe base64

## Solution

ChaCha20 is a stream cipher, meaning that it generates a pseudorandom sequence of bytes, the *keystream*, using the provided key and nonce and XORs them with the plaintext to obtain the ciphertext. This type of cipher is vulnerable to nonce reuse: using the same key and nonce to encrypt two messages is very insecure as the same keystream will be used in both cases.

In our case, all messages are encrypted with the same key. Due to the use of fork(), the parent process and the child process will share the same RNG state (thanks to the custom RNG implementation). This makes it possible that the parent process and child process will both use the same nonce to encrypt a message. We can trigger this condition using the following sequence of events:

1. Open one connection C1 to the server. This encrypts the flag with a random nonce N1, forks a child, and waits for the user to input some text to encrypt.
2. Immediately open a second connection C2 to the server. This encrypts the flag with a random nonce N2.
3. Send text M to connection C1, which will *also* use random nonce N2, because both the parent process (for C2) and child process (for C1) have the same random state (right after generating nonce N1).

Now, we will have the flag encrypted with nonce N2 from connection C2, and a message M of our choosing encrypted with nonce N2 from connection C1. Because the message and keystream are just combined with XOR, we can recover the flag by simply XORing the two encrypted messages and the message M: XORing the messages cancels out the keystream and produces the XOR of the two plaintexts, and XORing out our known plaintext M reveals the other plaintext - the flag.

This is easy to do with a quick-and-dirty script:

```python
from pwn import *
from base64 import urlsafe_b64decode

def xor(a, b):
    return bytes([ca ^ cb for ca, cb in zip(a, b)])

r1 = remote('misc1.utctf.live', 9992)
r2 = remote('misc1.utctf.live', 9992)

msg = b'A' * 146

r1.readline()
r2.readuntil(b'flag: ')
flag = urlsafe_b64decode(r2.readline() + b'====')
r1.send(msg)
r1.readuntil(b'out:  ')
out = urlsafe_b64decode(r1.readline() + b'====')

fc, fnonce, fmac = flag[:-40], flag[-40:-16], flag[-16:]
oc, ononce, omac = out[:-40], out[-40:-16], out[-16:]
assert fnonce == ononce, "nonce mismatch - try again"

print(xor(xor(msg, oc), fc))
```

revealing the flag, `utflag{d3term1nistiC_rAnd0mn3Ss}`.
