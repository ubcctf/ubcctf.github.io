---
layout: post
title: "[UTCTF 2022] Failed Hash Function"
author: Robert Xiao
---

## Problem Description

### Failed Hash Function

- Solves: 35
- Score: 974
- Tags: cryptography

I made this keyed hash function for my final project, but I got a 0... Apparently, there's too many collisions and you can recover the key after one hash. I don't believe it. In fact, if you can break my hash function 100 times, I'll give you a flag! I'll even be nice -- you get two whole guesses to find the key. By oops (@oops on discord)

`nc misc1.utctf.live 5000`

Attachments: `main.py`

## Introduction

We're given a Python script that implements a keyed "hash" function. The hash function uses a random pair of bytes `k1` and `k2` as a key. The core of the hash function is as follows:

```python
def trailing(x):
    a = 0
    for _ in range(15):
        if x & 1:
            break
        x >>= 1
        a += 1
    return a

def print_hash(k1, k2, s):
    for x in s:
        for y in s:
            print(hex(trailing((k1 ^ x) * (k2 ^ y)))[2:], end='')
    print()
```

`trailing` computes the number of trailing 0 bits in the number, e.g. `trailing(0b10100) == 2`. Thus, an `n` byte produces `n*n` hex digits of "hash".

The problem itself is to pass 100 challenge rounds consecutively. In each round, a random 2-byte key is generated, and you're allowed to hash two 16-byte strings, after which you need to guess the key. The key has to be guessed correctly in all 100 rounds to get the flag.

## Solution

This is really more of a math problem than a cryptography problem. The first thing to observe is that `trailing(x * y) == trailing(x) + trailing(y)` (unless `x` or `y` is zero, in which case the output is 15), and so the hash function is really showing `trailing(k1 ^ x) + trailing(k2 ^ y)` for every combination of bytes `x` and `y` of the input.

We can get a lot of information if our first input consists of 16 bytes with the same upper 4 bits and all combinations of lower 4 bits, e.g. 0x40, 0x41, 0x42, ..., 0x4F (`@ABCDEFGHIJKLMNO`). Consider what happens with any byte `y` such that `k2 ^ y` is odd, meaning that `trailing(k2 ^ y) == 0` (exactly 8 bytes in the input have this property).

Over all possible combinations of bytes `x` in the input, exactly one will have `(x & 0xf) == (k1 & 0xf)`, meaning that `trailing(k1 ^ x)` will be at least 4 (for all other `x`, `trailing(k1 ^ x) < 4`). Furthermore, `trailing(k1 ^ x) == 4` if the 0x10 bit is set in `k1`, and `trailing(k1 ^ x) > 4` if the 0x10 bit is clear in `k1`. This therefore immediately reveals the low 5 bits of `k1`. A symmetric argument proves that we also get the low 5 bits of `k2`.

Thus, with a single input, we know for certain 10 of the 16 bits of the key. To get the remaining bits, we can submit an input like this:

`[(i << 5) + (k1 % 32) for i in range(8)] + [(i << 5) + (k2 % 32) for i in range(8)]`

That is, the input consists of the 8 bytes that share the same low 5 bits as k1, and the 8 bytes that have the same low 5 bits as k2. Note that exactly one input from the left half will actually be equal to k1, and one input on the right half will be equal to k2. Whenever `k1 ^ x == 0` or `k2 ^ y == 0`, the hash output from `trailing` will be 15 (`f`), making it very easy to work out the exact values of `k1` and `k2` by looking for the input bytes which result in all `f`s in the output.

Using this strategy is guaranteed to win in every case. My implementation uses a little bit less logic - it just bruteforces all `k1`, `k2` which could produce the target hash, but this is good enough for this challenge.

```python
import sys, os
from pwn import *
import itertools

def trailing(x):
    a = 0
    for _ in range(15):
        if x & 1:
            break
        x >>= 1
        a += 1
    return a

def print_hash(k1, k2, s):
    for x in s:
        for y in s:
            yield trailing((k1 ^ x) * (k2 ^ y))

def check(msg, result, poss=None):
    want = [int(c, 16) for c in result]
    if poss is None:
        poss = itertools.product(range(256), repeat=2)

    for k1, k2 in poss:
        for i, n in enumerate(print_hash(k1, k2, msg)):
            if n != want[i]:
                break
        else:
            yield (k1, k2)

s = remote('misc1.utctf.live', 5000)
for chid in range(1, 101):
    s.recvuntil(b'Challenge %d' % (chid))
    s.recvuntil(b'Enter 16 bytes to hash! You only get two tries ;)\n')
    msg = b'@ABCDEFGHIJKLMNO'
    s.send(msg)
    res = s.recvline().strip().decode()
    log.info("%s -> %s", msg, res)
    poss = list(check(msg, res))
    if not poss:
        raise ValueError("impossible!")

    k1, k2 = poss[0]
    s.recvuntil(b'Enter 16 bytes to hash! Last chance...\n')
    msg = bytearray([(i << 5) + (k1 % 32) for i in range(8)]) + bytearray([(i << 5) + (k2 % 32) for i in range(8)])
    s.send(msg)
    res = s.recvline().strip().decode()
    log.info("%s -> %s", msg, res)
    nposs = list(check(msg, res, poss))
    assert len(nposs) == 1, "bad nposs: %s" % nposs

    k1, k2 = nposs[0]
    s.recvuntil(b"k1:\n")
    s.sendline(str(k1).encode())
    s.recvuntil(b"k2:\n")
    s.sendline(str(k2).encode())

s.interactive()
```

This produces the flag after 100 rounds: `utflag{Ju5t_u53_SHA256_LoLc4t5_9a114be7f}`
