---
layout: post
title: "[UTCTF 2022] SnECCanography"
author: Robert Xiao
---

## Problem Description

### SnECCanography

- Solves: 5
- Score: 1000
- Tags: forensics

I hid a secret message in this picture of my pet snECC, but I don't know what happened to it :(( Some of the pixels got corrupted... how do fix ?_? By oops (@oops on discord)

Attachments: `encode.py`, `snek2.png`

## Introduction

We're given an 896 x 396 PNG image of a cute snake with a lot of pixels replaced by coloured noise, and a Python script that generated it.

The Python script looks like this:

```python
from secret import secret
from PIL import Image
import galois

SZ = 128
GF = galois.GF(SZ)

def bin_rep(x):
    bits = []
    b = 1
    while(b < SZ):
        bits.append(1 if (x & b) else 0)
        b <<= 1
    return bits

def evaluate(c, x):
    y = GF(0)
    for k in range(len(c)):
        y += GF(c[k]) * (GF(x) ** k)
    return int(y)

def get_values(c):
    values = []
    for i in range(SZ):
        values.append(evaluate(c,i))
    return values

def get_bins(c):
    values = get_values(c)
    bins = []
    for v in values:
        bins += bin_rep(v)
    return bins

per_row = 64
secret = [ord(x) for x in secret]
secret += [0] * (per_row - len(secret) % per_row)

new_secret = []
for i in range(0, len(secret), per_row):
    new_secret += get_values(secret[i:i+per_row])
secret = new_secret

im = Image.open('snek.png')
w,h = im.size

mat = []

for i in range(len(secret) // per_row):
    mat.append(get_bins(secret[i*per_row:(i+1)*per_row]))

pixels = im.load()
for i in range(len(mat)):
    for j in range(w):
        r,g,b = pixels[j,i]
        r -= r & 1
        g -= g & 1
        b -= b & 1
        r += mat[i][j]
        g += mat[i][j]
        b += mat[i][j]
        pixels[j,i] = (r,g,b)


im.save('snek2.png')
```

In short, it's doing the following operations, where "byte" actually means 7-bit value in GF(128):

1. Pad the secret up to a multiple of 64 bytes
2. Encode each block of 64 secret bytes into 128 bytes using `get_values`
3. Encode each block of 64 encoded bytes into rows of 128 bytes again using `get_values`
4. Split each row of 128 bytes into 896 (= 128 x 7) bits
5. Overlay each row of bits onto the LSB of the pixels of a PNG (which must be 896 pixels wide)

Then, presumably, the resulting PNG was corrupted by changing random pixels, thus causing random bitflips in the LSBs.

The core of the encoding operation is the `get_values` function. `get_values` evaluates a polynomial over GF(128) whose coefficients are the 64 input bytes at the points `x = 0, 1, 2, 3, ..., 127`.

The term "ECC" in the title of the problem, as well as the idea of fixing corrupted data, suggests that this is an Error Correcting Code (ECC). Indeed, a quick survey of popular ECC techniques leads us to conclude that this is the Reed-Solomon scheme, specifically the ["simple encoding procedure"](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction#Simple_encoding_procedure:_The_message_as_a_sequence_of_coefficients) in which the message is treated as the coefficients of a polynomial that is then evaluated at several points.

## Solution

The solution is quite straightforward: find (or implement) a decoder for the Reed-Solomon scheme. Unfortunately, most common decoders operate with the "systematic encoding procedure" as that is much more commonly used in practice. Luckily, Wikipedia directs us to the [Berlekamp-Welch algorithm](https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Welch_algorithm) which is exactly what we need.

I didn't find a good implementation of Berlekamp-Welch online, so I figured I'd just roll my own. Here's a short description of the algorithm.

First, we let `n` be the number of outputs (here, n = 128) and `k` be the number of message inputs (here, k = 64). The message polynomial is denoted as `F(x)` and has degree `k - 1` (and `k` coefficients). The original encoded message is therefore `F(0), F(1), F(2), ... F(127)`.

Let the received message be `b_0, b_1, ..., b_127`. This received message might differ from the original message due to errors; let `e` be the number of errors (unknown). At non-error locations, `b_i == F(i)`, and at error locations, `b_i != F(i)`.

The basic idea is to define and solve for an extra "error" polynomial `E(x)` which will be zero at all errors and non-zero elsewhere. E will have degree `e`. We will try to solve the equations `b_i E(i) = E(i) F(i)` for E and F - note that when `i` is the index of an error, this equation resolves to zero on both sides, and when `i` is the index of a non-error, `E(i)` will cancel out. The trick is to replace `E(x) F(x)` with a polynomial `Q(x)`, of degree `n - k - 1`, which makes `b_i E(i) = Q(i)` a system of linear equations in the coefficients of `E` and `Q`. If the resulting `Q` polynomial divides `E` evenly, then `F(x) = Q(x) / E(x)` and the original message can be recovered from the coefficients. This process works so long as the number of errors stays below the error bound, `e <= (n-k)/2`.

The implementation is fairly straightforward as `galois` has full support for linear algebra operations:

```python
import sys
from PIL import Image
import numpy as np
import galois

SZ = 128
GF = galois.GF(SZ)
A = GF.Zeros((SZ, SZ))
for i in range(SZ):
    A[i] = [GF(i) ** k for k in range(SZ)]

def decode_row(row, maxerr):
    # Berlekamp-Welch algorithm
    assert len(row) == SZ
    row = GF(row)

    for e in reversed(range(maxerr+1)):
        M = GF.Zeros((SZ, SZ))
        y = GF.Zeros((SZ,))
        # Solve b_i * E(a_i) == Q(a_i) where Q(a_i) = E(a_i) * F(a_i)
        for i in range(SZ):
            M[i, :e] = row[i] * A[i, :e]    # E polynomial coefficients, deg(E) = e - 1
            M[i, e:] = -A[i, :SZ - e]       # Q polynomial coefficients, deg(Q) = e + k - 1 <= n - e - 1
            y[i] = -(row[i] * A[i, e])      # Implied leading coefficient of E, e_e = 1

        try:
            res = np.linalg.solve(M, y)
        except Exception as ex:
            continue

        # Assume leading coefficient of error polynomial is 1
        E = galois.Poly([1] + list(res[:e][::-1]), field=GF)
        Q = galois.Poly(res[e:][::-1])
        # Q(x) = E(x) * F(x) for the correct Q/E pair
        if (Q % E).degree == 0:
            return e, [int(c) for c in (Q / E).coeffs[::-1]]

def pad(row, sz):
    return row + [0] * (sz - len(row))

if __name__ == "__main__":
    arr = np.asarray(Image.open(sys.argv[1]))

    print("Decoding from image...")
    new_secret = []
    for rown, row in enumerate(arr):
        bits = row[:, 0] & 1
        assert len(bits) == 7 * 128
        out = np.zeros((128,), dtype=np.uint8)
        for i in range(7):
            out += bits[i::7] << i

        # n = 128, k = 64 ==> maxerr = 32
        nerr, res = decode_row(out, 32)
        if len(res) > 64:
            break
        print(rown, nerr, res)
        new_secret += pad(res, 64)

    print("Decoding secret...")
    secret = []
    for i in range(0, len(new_secret), 128):
        row = new_secret[i: i+128]
        row = pad(row, 128)
        nerr, res = decode_row(row, 32)
        print(i, nerr, res)
        secret += res

    print(bytearray(secret).decode())
```

This prints out a nice poem with the flag:

```
Here is a poem I wrote about snek, pls enjoy

snek is long, snek is cute

snek is strong and likes the flute

The flag is utflag{3rr0r_c0rr3ct10n_4nd_sn3k_affect10n}.

```
