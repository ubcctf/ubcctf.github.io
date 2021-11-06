---
layout: post
title: "[hack.lu 2021] pycoin and whatthehecc"
author: vEvergarden
---


## tl;dr

Pycoin [146] was a Python bytecode reversing challenge that performed checks on different characters of a supplied input.

## Description
> A friend gave me this and he says he can not reverse this… but this is just python? 

We're a given a .pyc file, which asks for a valid key when run.

## Reversing the bytecode

After a bit of searching around, I found the [uncompyle6](https://pypi.org/project/uncompyle6/) library — according to its documentation, it translates Python bytecode back into equivalent Python source code.

Running this on our .pyc file gives us a cleaner looking file:

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.10 (default, Jun  2 2021, 10:49:15)
# [GCC 9.4.0]
# Embedded file name: challenge_generated.py
# Compiled at: 2021-10-27 14:40:15
# Size of source mod 2**32: 2836 bytes
import marshal
marshalled = b'\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00@\x00\x00\x00\xf3\xf0\x01\x00\x00n\x02tcd\x00d\x01l\x00m\x01Z\x01\x01\x00e\x02e\x03d\x02\x83\x01\x83\x01\xa0\x04\xa1\x00Z\x05e\x06e\x05\x83\x01d\x03k\x02\x90\x01o\xcee\x05d\x00\x19\x00d\x04k\x02\x90\x01o\xcee\x05d\x05\x19\x00e\x05d\x00\x19\x00d\x06\x17\x00k\x02\x90\x01o\xcee\x05d\x07\x19\x00e\x05d\x05\x19\x00e\x05d\x00\x19\x00\x18\x00d\x08n\n]\x02n\x02n\x02r\x04q\x04\x17\x00k\x02\x90\x01o\xcee\x05d\t\x19\x00d\nk\x02\x90\x01o\xcee\x05d\x0b\x19\x00e\x05d\x0c\x19\x00d\t\x14\x00d\r\x18\x00k\x02\x90\x01o\xcee\x05d\x0e\x19\x00e\x07e\x05\x83\x01d\x0f\x18\x00k\x02\x90\x01o\xcee\x05d\x06\x19\x00e\x05d\x10\x19\x00\x17\x00e\x05d\x11\x19\x00\x17\x00d\x12k\x02\x90\x01o\xcee\x08e\te\x05d\x10\x19\x00\x83\x01d\x07\x14\x00\x83\x01d\x05\x17\x00e\x05d\x13\x19\x00k\x02\x90\x01o\xcee\x05d\x14\x19\x00d\x15\x16\x00d\x03k\x02\x90\x01o\xcee\x05d\x13\x19\x00e\x05d\x14\x19\x00d\x07\x14\x00k\x02\x90\x01o\xcee\x01e\x05d\x11\x19\x00d\x16\x14\x00\x83\x01\xa0\n\xa1\x00d\x00\x19\x00d\x05\x18\x00e\x05d\t\x19\x00k\x02\x02\x00\x02\x00\x90\x01o\xcee\x05d\x0c\x19\x00d\x17k\x02\x90\x01o\xcee\x05d\x18\x19\x00e\x05d\x19\x19\x00d\x07\x1b\x00d\x07\x18\x00k\x02\x90\x01o\xcee\x05d\x1a\x19\x00e\x05d\x11\x19\x00e\x05d\x14\x19\x00\x14\x00d\x1b\x16\x00d\x07\x14\x00d\x05\x18\x00k\x02\x90\x01o\xcee\x05d\x19\x19\x00e\x05d\x18\x19\x00e\x05d\x13\x19\x00A\x00e\x05d\x1c\x19\x00A\x00d\t\x14\x00d\x1d\x18\x00k\x02\x90\x01o\xcee\x05d\x1c\x19\x00d\x1ek\x02Z\x0be\x0ce\x0b\x90\x01r\xe6d\x1fe\x05\xa0\r\xa1\x00\x9b\x00\x9d\x02n\x02d \x83\x01\x01\x00d!S\x00)"\xe9\x00\x00\x00\x00)\x01\xda\x03md5z\x1aplease supply a valid key:\xe9\x10\x00\x00\x00\xe9f\x00\x00\x00\xe9\x01\x00\x00\x00\xe9\x06\x00\x00\x00\xe9\x02\x00\x00\x00\xe9[\x00\x00\x00\xe9\x03\x00\x00\x00\xe9g\x00\x00\x00\xe9\x04\x00\x00\x00\xe9\x0b\x00\x00\x00\xe9*\x00\x00\x00\xe9\x05\x00\x00\x00i*\x05\x00\x00\xe9\x07\x00\x00\x00\xe9\n\x00\x00\x00i\x04\x01\x00\x00\xe9\t\x00\x00\x00\xe9\x08\x00\x00\x00\xe9\x11\x00\x00\x00\xf3\x01\x00\x00\x00a\xe97\x00\x00\x00\xe9\x0c\x00\x00\x00\xe9\x0e\x00\x00\x00\xe9\r\x00\x00\x00\xe9 \x00\x00\x00\xe9\x0f\x00\x00\x00\xe9\x17\x00\x00\x00\xe9}\x00\x00\x00z\x0bvalid key! z\x0einvalid key :(N)\x0eZ\x07hashlibr\x03\x00\x00\x00\xda\x03str\xda\x05input\xda\x06encode\xda\x01k\xda\x03len\xda\x03sum\xda\x03int\xda\x03chr\xda\x06digestZ\x07correct\xda\x05print\xda\x06decode\xa9\x00r)\x00\x00\x00r)\x00\x00\x00\xfa\r<disassembly>\xda\x08<module>\x01\x00\x00\x00sF\x00\x00\x00\x0c\x02\x10\x03\x0e\x01\n\xff\x04\x02\x12\xfe\x04\x03\x1a\xfd\x04\x04\n\xfc\x04\x05\x16\xfb\x04\x06\x12\xfa\x04\x07\x1a\xf9\x04\x08\x1e\xf8\x04\t\x0e\xf7\x04\n\x12\xf6\x04\x0b"\xf5\x04\x0c\n\xf4\x04\r\x16\xf3\x04\x0e"\xf2\x04\x0f&\xf1\x04\x10\n\xee\x02\x15'
exec(marshal.loads(marshalled))
# okay decompiling pycoin.pyc
```

The program loads in the [marshal](https://docs.python.org/3/library/marshal.html) library and executes the deserialized Python instructions. Luckily, we can inspect what this Python code object does by relying on uncompyle6's decompile function
```python
from uncompyle6.main import decompile

...

code = marshal.loads(marshalled)
print(decompile(3.8, code))
```

Though this gives a parse error, we can safely ignore it and look at the assembly instructions:

```
 L.   1         0  JUMP_FORWARD          4  'to 4'
                2  LOAD_GLOBAL          99  99
              4_0  COME_FROM           112  '112'
              4_1  COME_FROM             0  '0'
                4  LOAD_CONST               0
                6  LOAD_CONST               ('md5',)
                8  IMPORT_NAME              hashlib
               10  IMPORT_FROM              md5

 L.   3        12  STORE_NAME               md5
               14  POP_TOP          
               16  LOAD_NAME                str
               18  LOAD_NAME                input
               20  LOAD_STR                 'please supply a valid key:'
               22  CALL_FUNCTION_1       1  ''
               24  CALL_FUNCTION_1       1  ''
               26  LOAD_METHOD              encode

...

              346  LOAD_NAME                k

 L.   6       348  LOAD_CONST               12
              350  BINARY_SUBSCR    

 L.  20       352  LOAD_NAME                k
              354  LOAD_CONST               14
              356  BINARY_SUBSCR    
              358  LOAD_CONST               2
              360  BINARY_TRUE_DIVIDE
              362  LOAD_CONST               2
              364  BINARY_SUBTRACT  
              366  COMPARE_OP               ==
          368_370  JUMP_IF_FALSE_OR_POP   462  'to 462'

...

              462  STORE_NAME               correct
              464  LOAD_NAME                print
              466  LOAD_NAME                correct
          468_470  POP_JUMP_IF_FALSE   486  'to 486'
              472  LOAD_STR                 'valid key! '
              474  LOAD_NAME                k
              476  LOAD_METHOD              decode
              478  CALL_METHOD_0         0  ''
              480  FORMAT_VALUE          0  ''
              482  BUILD_STRING_2        2 
              484  JUMP_FORWARD        488  'to 488'
            486_0  COME_FROM           468  '468'
              486  LOAD_STR                 'invalid key :('
            488_0  COME_FROM           484  '484'
              488  CALL_FUNCTION_1       1  ''
              490  POP_TOP         

```

The bytecode instructions seem to check various characters of our input; all of them jump to 462 if the check fails (which would likely print out "invalid key"). Now, we can go through each of the checks with Python's [bytecode documentation](https://docs.python.org/3/library/dis.html).

In the end, we get a list of 15 checks for the flag's 16 characters (although we do know the flag format is `flag{...}`):
```python
k[0] = 102
k[0] + 6 = k[1]
k[2] = k[1] - k[0] + 91
k[3] = 103
k[4] = k[11] * 3 - 42
k[5] = sum_of_chars(k) - 1332
k[6] + k[7] + k[10] = 260
int(chr(k[7]) * 2) + 1 = k[9]
k[8] % 17 = 16
k[9] = 2 * k[8]
md5(k[10] * b'a')[0] - 1 = k[3]
k[11] = 55
k[12] = k[14]/2 - 2
k[13] = 2 * [(k[10] * k[8]) % 32] - 1
k[14] = (k[12] ^ k[9] ^ k[15]) * 3 - 23
```

Solving these equations is fairly straightforward: most of them are simple arithmetic, and the rest of them can be quickly brute forced. The flag is the valid key: `flag{5f92de703d}`

# Whatthehecc [198]

## tl;dr

Flawed elliptic curve signing and verifying algorithms, allowing attackers to forge arbitrary messages.

## Description

> Go hecc it!
nc flu.xxx 20085

We can connect to a server that signs/verifies messages using elliptic curves; if the verification is successful, the server then executes the given command. Since the server only signs the commands `'id', 'uname', 'ls', 'date'`, we'll need to forge a signature for `cat flag`.

## Forging signatures

Usually, elliptic curve signing/verifying involves [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm), so we can start by looking at their custom functions.

```python
...

def sign(r, key):
    r_prime = r * key.d.inverse(key._curve.order)

    date = int(time.time())
    nonce = Integer.random_range(min_inclusive=1,max_exclusive=key._curve.order)
    z = f'{nonce}||{date}'


    R = r_prime + (key._curve.G * hash(z))
    s = (key.d - hash(z)) % key._curve.order
    # return (R, s, z)
    # we can not give away z or this is unsafe: x = s+h(z)
    return R, s
...
```

In terms of the `cmd` we send, the sign algorithm will give us a signature of:
- (R, s) = (H(cmd) * G + G * H(z), d - H(z))

Where:
- H(x) is the SHA256 digest of x
- G is the generator point
- z is a random variable (`nonce||date`)
- d is the private key

Since H(z) is essentially random and out of our control, we can rewrite it as:
- s = d - H(z)
- H(z) = d - s

Substituting this value into our previous (R, s) expression gives:
- (R, s) = (H(cmd) * G + Q - G * s, s)

In other words, we can query for a value of `s` and rewrite R to forge any `cmd` we want. 

```python
def verify(msg, sig, pub):
    R, s = sig

    if s in [0,1,''] and s > 0:
        return False

    tmp1 = s * pub._curve.G
    tmp2 = - pub.pointQ 
    tmp3 = tmp2 + R

    return tmp1 + tmp3 == hash(msg) * pub._curve.G
```

Going through the verify process with the (R, s) pair:
- tmp1 + tmp3 = H(cmd) * G
- s * G + H(cmd) * G + Q - G * s - Q = H(cmd) * G
- H(cmd) * G = H(cmd) * G

Our forged signature passes the verification algorithm, and with it, `flag{d1d_you_f1nd_chakraborty_mehta}`.

A local proof of concept:
```python
...

Q = pubkey.pointQ
G = key._curve.G

r = blind('ls', pubkey)
R1, s1 = sign(r, key)

R = hash('cat flag') * G + Q + s1 * (-G)

sig = (ECC.EccPoint(R.x, R.y, curve='P-256'), int(s1))

assert(verify('cat flag', sig, pubkey))
```
