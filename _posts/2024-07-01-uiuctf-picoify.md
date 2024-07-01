---
layout: post
title: "[UIUCTF 2024] Picoify (500)"
author: Robert Xiao
---


## Problem Description

Picoify is a "king-of-the-hill" style challenge in which we're tasked with implementing a compression algorithm and corresponding decompressor under fairly severe restrictions. Better compression results in a better score.

Specifically, the task is to write a compression algorithm for the Microchip PIC16F628A, a small 8-bit microprocessor with 2048 *words* of program memory (i.e. space for 2048 instructions), and 224 *bytes* of RAM. The decompressor is written in Python, but is run in a strict seccomp sandbox with tight memory and CPU limits.

The input text is 2048 bytes long, drawn randomly from a list of 8192 uppercase words, with certain letters (ABEGIOSTZ) randomly replaced by 1337-speak equivalents (50% probability). Here's an example input:

> RE4LLY RUG C1TI35 633K R35P1RA7ORY GUARD COL0URS P4PER PRO7EC73D SQU4R3 C0M81NE P0RC3L41N L0 NI 7ASKS CER4MIC YO6A 7ERM1NA7I0N C0N50L3S 3F N0RT0N F1RM N3C HELP5 R1M UM 7R166ER MURPHY H3LP SENS0R EXTR4ORDINARY 5UPER M0R0CC0 B0T5WANA C0NN3C710N M3NT10N WO0D5 E4R AUTHEN71C 6OV3RNM3N74L CHRI5 S33KER LIN6ER1E PR0DUC71ON 3XPLORER F4C3 FLO0D DECAD3 AN4LYSES AV6 4GE5 4U5 P455AGE D 8R42IL14N 8RIN61N6 63OR614 TUR80 B3LG1UM CSS ARMED 0U7COM3 U5IN6 8UDDY AU7OM471ON R35ULT3D JACKET 6R CHR0NIC BESIDES L4ND M0V135 PREP4RE F15HIN6 N1CK SCH3ME ALPINE MUL7I 5UPPL3M[...]

The input is truncated to fit 2048 bytes, so the final word may be cut off.

The score of any submission is the number of bytes saved, and you need to compress by at least 25% to get a flag at all. Thus, the minimum score to get a flag is 512 (2048 * 1/4).

We're provided with a starter PIC assembly file that just echoes the input back to the output, as well as a Dockerfile for running the scoring system locally.

## Analysis

There are only 36 unique characters, so one very simple approach is to output 6 bits per byte; this would be sufficient to score **512** and get a flag (output is 2048*6/8 = 1536 bytes exactly). We can get more clever using entropy encoding, using a variable number of bits per character; the Huffman algorithm is a common approach. We can use a quick script to calculate the average entropy of the texts and estimate the score of such an approach:

```python
from collections import Counter
import math
c = Counter()
samples = []
for i in range(100):
    data = generate_data()
    samples.append(data)
    c.update(data)

total = len(samples) * 2048
entropy = sum((v / total) * -math.log2(v / total) for v in c.values())
```

This produces an entropy of 4.67 bits per character, meaning that we should be able to score around **852** with a Huffman-based approach (2048*4.67/8 ≈ 1196). From the challenge scoreboard provided by the organizers, it seems most successful teams took this approach.

While I considered these approaches, I figured it should be possible to score much higher given the constrained nature of the input text: there are only 8192 words (13 bits of entropy *per word*), and a few bits of extra entropy per word to account for the random 1337-speak letters (1 bit of entropy per 1337-speakable letter). Running a quick simulation, if we're able to actually encode each word using exactly 13 bits (plus 1337-speak bits), we could score an average of 1485 (average output size is 562.8 bytes):

```python
import re, statistics
comp_bits = [len(t.split()) * 13 + len(re.findall(b"[ABEGIOSTZ483610572]", t)) for t in samples]
print(statistics.mean(comp_bits) / 8)
```

This sets a rough upper bound on the performance of *any* compression algorithm - it measures the amount of entropy used to generate the output in the first place.

## The Compressor

For encoding words using a minimum number of bits, we can use *perfect hashing*. A perfect hash function is one which maps every input in a finite set to a unique numerical value with no collisions. If we can find a perfect hash function for our wordlist, we could compress by outputting the hash values for each word; as there are no collisions, the decompressor could uniquely map these back to the original words.

Luckily, the [GNU `gperf`](https://www.gnu.org/software/gperf/) command is designed specifically for this purpose. It is normally used to derive perfect hash functions for sets of keywords (e.g. for parsing a programming language). We can just feed `gperf` our entire wordlist: `head -n 8192 words.txt | tr a-z A-Z | gperf -n -m=10 -k '1-11,$' -7 > gperf.c`.

`gperf` outputs C code which implements the perfect hash function:

```c
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static unsigned int asso_values[] =
    {
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124,    145,  22134,  14665,   7025,     20,
       43498,   6070,   2551,     60,  13988,  38948,   1820,  30148,     15,     85,
        6351,   5350,     25,      5,     65,    555,  14565,   2027,    295,    735,
       45643,  29266,   7705,  42888,  10966,     21,   4875,    325,   4725,  53578,
       57958,  14261,   1220,  29394,  60128,  26679,  45243,    275,   2250,   1350,
       23954,    585,    430,     90,  35098,  11101,  49537,    401,  51258,      1,
       64213,  10636,   4410,   1945,  10338,   2786,  42248,  14110,   9063,  51277,
           5,   1385,    330, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124,
      206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124, 206124
    };
  register unsigned int hval = 0;

  switch (len)
    {
      default:
        hval += asso_values[(unsigned char)str[10]];
      /*FALLTHROUGH*/
      case 10:
        hval += asso_values[(unsigned char)str[9]];
      /*FALLTHROUGH*/
      case 9:
        hval += asso_values[(unsigned char)str[8]];
      /*FALLTHROUGH*/
      case 8:
        hval += asso_values[(unsigned char)str[7]];
      /*FALLTHROUGH*/
      case 7:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
        hval += asso_values[(unsigned char)str[5]+3];
      /*FALLTHROUGH*/
      case 5:
        hval += asso_values[(unsigned char)str[4]+19];
      /*FALLTHROUGH*/
      case 4:
        hval += asso_values[(unsigned char)str[3]+13];
      /*FALLTHROUGH*/
      case 3:
        hval += asso_values[(unsigned char)str[2]+29];
      /*FALLTHROUGH*/
      case 2:
        hval += asso_values[(unsigned char)str[1]];
      /*FALLTHROUGH*/
      case 1:
        hval += asso_values[(unsigned char)str[0]+42];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}
```

Over our wordlist, the maximum hash value is 206123, which can be comfortably encoded in 18 bits (2<sup>18</sup> = 262144). Simulating this, we find that this should compress to around 734 bytes per message on average, giving a score of **1314** - far better than the Huffman approach!

Instead of writing this in PIC assembly, I chose to use Microchip's XC8 C compiler. I converted the provided startup code to C in order to get the UART to work. Since we're working with a very small amount of memory, I chose the smallest possible data types to save space, making use of Microchip's special `uint24_t` 3-byte integer type to save even more space.

The implementation itself is relatively straightforward: we accumulate the hash and "1337 bits" as each plaintext character comes in, then flush the hash and any accumulated 1337 bits when we see a space character. When we reach 2028 total input characters, we switch to encoding the remaining characters directly to avoid problems with any final truncated word (as the longest word in the wordlist is 18 characters).

Here's what the PIC code looks like. This is compiled with `xc8-cc -mcpu=pic16f628a -O2`:

```c
#include <xc.h>
#include <stdint.h>

// disable the watchdog timer
#pragma config WDTE = OFF

static uint8_t txbuf[8];
static uint8_t txcnt = 0;

static void send_byte(uint8_t b) {
    txbuf[txcnt] = b;
    txcnt++;
}

static uint16_t total_rx_count = 0;
static uint8_t is_tail = 0;

static uint8_t word_len = 0;
static uint8_t last_char = 0;
static uint24_t cur_hash = 0;
static uint24_t leet_bits = 0;
static uint8_t leet_count = 0;

// compressed form of the gprof table, removing unreachable entries
static const uint16_t asso_values[] = {145, 22134, 14665, 7025, 20, 43498, 6070, 2551, 60, 13988, 38948, 1820, 30148, 15, 85, 6351, 5350, 25, 5, 65, 555, 14565, 2027, 295, 735, 45643, 29266, 7705, 42888, 10966, 21, 4875, 325, 4725, 53578, 57958, 14261, 1220, 29394, 60128, 26679, 45243, 275, 2250, 1350, 23954, 585, 430, 90, 35098, 11101, 49537, 401, 51258, 1, 64213, 10636, 4410, 1945, 10338, 2786, 42248, 14110, 9063, 51277, 5, 1385, 330};
// offsets applied to each character to get the asso_values index
static const int8_t asso_offs[] = {-23, -65, -36, -52, -46, -62, -65, -65, -65, -65, -65};
// offset applied to the final character
#define asso_final_off (-65)
static const uint8_t leet_map[] = { 'O', 'I', 'Z', 'E', 'A', 'S', 'G', 'T', 'B' };

static uint8_t cur_byte = 0;
static uint8_t cur_bit = 0;

static void push_bits(uint24_t x, uint8_t nbits) {
    while(nbits) {
        uint8_t cur = nbits;
        if(cur > (8 - cur_bit)) {
            cur = 8 - cur_bit;
        }
        cur_byte |= ((uint8_t)x) << cur_bit;
        cur_bit += cur;
        nbits -= cur;
        x >>= cur;
        if(cur_bit == 8) {
            send_byte(cur_byte);
            cur_byte = 0;
            cur_bit = 0;
        }
    }
}

static void process_char(uint8_t c) {
    total_rx_count++;
    if(is_tail) {
        // this could be more efficient (e.g. 6 bit or entropy encoding)
        // but we're only using it for at most 20 input characters
        push_bits(c, 8);
        if(total_rx_count == 2048) {
            push_bits(0, 8);
        }
        return;
    }

    if(c == ' ') {
        if(total_rx_count >= 2028) {
            is_tail = 1;
        }
        cur_hash += asso_values[last_char + asso_final_off];
        push_bits(cur_hash, 18);
        if(leet_count)
            push_bits(leet_bits, leet_count);

        word_len = 0;
        last_char = 0;
        cur_hash = 0;
        leet_bits = 0;
        leet_count = 0;
        return;
    }

    /* regular word character */
    if(c >= '0' && c <= '8') {
        c = leet_map[c - '0'];
        leet_bits |= (1 << leet_count);
        leet_count++;
    } else if(c == 'A' || c == 'B' || c == 'E' || c == 'G' || c == 'I' || c == 'O' || c == 'S' || c == 'T' || c == 'Z') {
        leet_count++;
    }

    if(word_len <= 10) {
        cur_hash += asso_values[c + asso_offs[word_len]];
    }
    word_len++;
    last_char = c;
}

void __interrupt() main_irq() {
    if(PIR1bits.RCIF) {
        /* rx interrupt */
        uint8_t c = RCREG;
        PIR1bits.RCIF = 0;
        process_char(c);
    }
}

int main() {
    // globally enable interrupts
    INTCONbits.GIE = 1;
    INTCONbits.PEIE = 1;

    // configure uart and transmitter
    TRISB = 0x06;
    SPBRG = 32;
    TXSTAbits.SYNC = 0;
    RCSTAbits.SPEN = 1;
    TXSTAbits.TXEN = 1;

    // configure uart receiver
    PIE1bits.RCIE = 1;
    RCSTAbits.CREN = 1;

    while(1) {
        while(!TXSTAbits.TRMT)
            ;
        while(!txcnt)
            ;
        TXREG = txbuf[0];
        txcnt--;
        for(uint8_t i=0; i<txcnt; i++)
            txbuf[i] = txbuf[i+1];
    }
}
```

One feature to note is that we buffer and send bytes asynchronously, because we only send bytes upon receiving a space character and may output several bytes at once (up to 36 bits).

This is a very space-efficient compressor, using only 583 words of program memory (28.5%) and 51 bytes of RAM (22.8%). Here's a sample compressed output corresponding to the sample input above (748 bytes); note that it's a bit larger than predicted because we encode up to 21 bytes of trailing characters rather inefficiently:

```
3877984a12693cb20b2b77c7e762860280bc84ef44aafde858752c9dce39bcf0e4c86cdac74d2bb1468988d1118c63d550165e8755454caa104b7b8e6adb991d4f351549d3ac77f4136f6c9b6740bf11081d258a21e8e1e9280125fd5e107a631df314e0b723b8d29e9ee609fb4330c066542f71b70742ee2a38610a6d0521291c8282269d7cc878028eece218c883bc987b1bad6e3dccbec98b3df8527f03e0aa0626385607af26b3b0230adde31e7bf90d180128a94a5d550035fa4cf5e4c99b910b1a7b76da874ca41a05fa132943a7d7df507b9e31f3330a736380750302a597a3f8dcd22dbeeb331b8c80e590ff202e374c51d960bb020b2d9895037c08704f8068216c472f50888de8d384064640847124da1fb78aa83c41384a1ab168e7e220e1dea20032b1c0ed148d4050d1563c6e618dcb8c1fe4ec9bebfb7e484b93a4b5aaa50b643e58e1e1989c0092117dface8aa2913720d31f2bc944bc4da22882cf2de3b3c5e0bd1a968da0447900dfc1a1e11ea9787c13506072a312abee9546b50927af86101c99f81b2f22d8012dacba093281ade5d0e18ea16f52cbaa87a7423e116986995222993c91c927cf50a542e2f2c01d45977e90bd3548e10156bcf4d2b9a8f69a346227c58bdc0e878c98e75066a6e221cd9f3118b8d3f7369c8857a4b5c9d1cc41de79962495c579092c101432cf81991cd2a1c36169172a701844c242c7f9fc6d6cb153e4221249026db5e09da72ecf0417c911292a94910cae855da54a0a14cab2353eb7b90a242f464551806b44be1723379c244f9a683e6e440823c73be876a83e7f2d13e506c06e4b870243081217c1c128b4cf3452fcf52131371a914301de7fa329bfaa22b77def64523e3ae0012e0e4a772697c785d9a4d2166dcc04d95bdc9800f2ccc1732e5a9d31c39e80a622882bc0de58690e38ac9b2600b49891e724688c749484aaa6ff67d8e9c81097bdf4fb1ceb132f979476d6480cdbc3b07edd2501291772370a1e4e3c731f8d571972c9448992ac629c66409c9ea890629c8e00
```

## The Decompressor

When I first devised this algorithm, I didn't really think about the decompressor much; I figured it would be easy to implement since we get to write Python code. Little did I know this would end up being the hardest part of the challenge.

The decompression code is run using a small stub called `decomp_runner.py`, which looks like this:

```python
#!/usr/bin/env python3

import sys
from base64 import b64decode
import resource
import pyseccomp


def run(prog, data, out):
    exec(prog, {'data': data, 'out': out})


def sandbox():
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 21, 1 << 21))
    resource.setrlimit(resource.RLIMIT_DATA, (1 << 21, 1 << 21))

    filter = pyseccomp.SyscallFilter(pyseccomp.ERRNO(pyseccomp.errno.EPERM))
    filter.add_rule(pyseccomp.ALLOW, 'write', pyseccomp.Arg(0, pyseccomp.EQ, sys.stdout.fileno()))
    filter.add_rule(pyseccomp.ALLOW, 'exit_group')
    filter.add_rule(pyseccomp.ALLOW, 'brk')
    filter.load()


def main():
    assert len(sys.argv) == 3

    prog = b64decode(sys.argv[1]).decode('ascii')
    data = b64decode(sys.argv[2])
    out = bytearray([0]*4096)

    sandbox()
    run(prog, data, out)


if __name__ == '__main__':
    main()
```

Our decompressor code is passed as a base64 blob on the command-line, together with the compressor's output. It installs tight CPU and memory limits (1 second CPU time, 2 MB memory size), then loads a very restrictive seccomp syscall filter which allows only `write(STDOUT_FILENO, ...)`, `exit_group` and `brk`. Finally, the provided code is launched with `exec`.

My first decoder attempt looked like this:

```python
wordmap = {
11: "MS",
31: "MN",
41: "ME",
51: "MR",
100: "GS",
121: "MI",
# [snip] #
194085: "OLYMPIC",
195863: "NIGHTLIFE",
203640: "HOMEWORK",
205457: "NETWORK",
206123: "BRUNSWICK",
}

leet_table = {
    'A': '4',
    'B': '8',
    'E': '3',
    'G': '6',
    'I': '1',
    'O': '0',
    'S': '5',
    'T': '7',
    'Z': '2'
}

cur_byte = 0
cur_bit = 0

def readbits(n):
    global cur_bit, cur_byte
    res = 0
    resbits = 0
    while resbits < n:
        chunk = n - resbits
        if chunk > 8 - cur_bit:
            chunk = 8 - cur_bit
        t = (data[cur_byte] >> cur_bit) & ((1 << chunk) - 1)
        res |= t << resbits
        resbits += chunk
        cur_bit += chunk
        if cur_bit == 8:
            cur_bit = 0
            cur_byte += 1
    return res

output = ""
while len(output) < 2028:
    word = wordmap[readbits(18)]
    for c in word:
        if c in leet_table:
            is_leet = readbits(1)
            if is_leet:
                output += leet_table[c]
            else:
                output += c
        else:
            output += c
    output += " "

while len(output) < 2048:
    output += chr(readbits(8))

sys.stdout.write(output)
sys.stdout.flush()
```

This worked great in preliminary testing, but failed entirely when run on the actual scoring system. The script was being passed as a base64 blob on the command line and was *exceeding the maximum length of a single command-line argument*. Some experimentation showed that the default maximum length was 128KB (131072 bytes) for a single argument, which translates into 96KB before base64 encoding. Thankfully, our raw wordlist is around 60KB, so my next attempt looked something like this:

```python
wordlist = """
THE
OF
AND
TO
A
[...]
CYLINDER
WITCH
BUCK
INDICATION
EH
""".split()

def perfect_hash(w):
  [...]
wordmap = {perfect_hash(w): w for w in wordlist}

[...]
```

This runs, but immediately crashes before executing any code. Some debugging with `strace` revealed that Python was attempting to use the `sbrk` system call to allocate memory to compile the program (in particular, allocating space for the `wordlist` constant). Unfortunately, only the `brk` system call has been permitted through the filter, so Python's attempt to allocate memory fails and it throws a `MemoryError` while compiling the code for `exec`.

This is much more serious than it initially appears. Without the ability to `sbrk` for additional memory, we're effectively limited to only the free memory that was available before the seccomp filter was installed - and that small amount of memory has to be enough for both the compiled program and all of the variables it creates as it runs. Some experimentation suggests that we have around 120KB of free memory. Keep in mind that Python objects are quite heavyweight: per `.__sizeof__()`, a simple integer is 28 bytes in size, while a single-character string is 50 bytes, and both sizes are likely underestimates due to padding and malloc metadata. I also did not immediately see a way to convince Python to use `brk` instead of `sbrk` using pure Python code.

To get around this problem, I chose to *smuggle* the wordlist in a comment, which would not be compiled and would therefore not incur a significant memory cost. We can access the source code of our program, and thus the embedded wordlist, by walking the stack:

```python
#THE,OF,AND,[...],BUCK,INDICATION,EH
try:
    1/0
except Exception as e:
    prog = e.__traceback__.tb_frame.f_back.f_locals["prog"]
```

However, we can't even do something like `wordlist = prog.split("\n")[0].split(",")` due to the severe memory restrictions - 8192 strings will occupy at least 400KB (per `__sizeof__()`), far more than the 100KB we have available.

Instead, I took the approach of dynamically searching the wordlist for each incoming word. To avoid an expensive linear search (which would blow our CPU limit - 1 second), I sorted the wordlist by hash value, then implemented a binary search:

```python
#,MS,MN,ME,MR,GS,MI,[...],OLYMPIC,NIGHTLIFE,HOMEWORK,NETWORK,BRUNSWICK,

try:
    1/0
except Exception as e:
    prog = e.__traceback__.tb_frame.f_back.f_locals["prog"]

table = (145,22134,14665,7025,20,43498,6070,2551,60,13988,38948,1820,30148,15,85,6351,5350,25,5,65,555,14565,2027,295,735,45643,29266,7705,42888,10966,21,4875,325,4725,53578,57958,14261,1220,29394,60128,26679,45243,275,2250,1350,23954,585,430,90,35098,11101,49537,401,51258,1,64213,10636,4410,1945,10338,2786,42248,14110,9063,51277,5,1385,330)
offs = (42,0,29,13,19,3,0,0,0,0,0)
def lookup(th):
    lo = 2
    hi = 61828
    while lo < hi:
        mid = (lo + hi) // 2
        a = prog.rfind(",", 0, mid)+1
        b = prog.find(",", mid)
        h = table[ord(prog[b-1]) - 65]
        for i in range(b-a):
            if i < len(offs):
                h += table[ord(prog[a+i]) + offs[i] - 65]
        if h < th:
            lo = mid + 1
        else:
            hi = mid
    return lo
```

One more final trick I used was to get a tiny bit more memory by clearing `sys.argv`, thereby freeing the large base64-encoded version of the program and buying around 100KB of extra memory to work with. I needed to do this because compiling the program itself still required more memory than was available:

```python
import sys
sys.argv[:] = []

exec(r"""
[rest of the program]
""")
```

Putting this all together produces the final decompressor:

```python
#,MS,MN,ME,MR,GS,MI,[...],OLYMPIC,NIGHTLIFE,HOMEWORK,NETWORK,BRUNSWICK,
import sys
# get ourselves just a little more memory to work with
sys.argv[:] = []

try:
    1/0
except Exception as e:
    prog = e.__traceback__.tb_frame.f_back.f_locals["prog"]

exec(r"""
table = (145,22134,14665,7025,20,43498,6070,2551,60,13988,38948,1820,30148,15,85,6351,5350,25,5,65,555,14565,2027,295,735,45643,29266,7705,42888,10966,21,4875,325,4725,53578,57958,14261,1220,29394,60128,26679,45243,275,2250,1350,23954,585,430,90,35098,11101,49537,401,51258,1,64213,10636,4410,1945,10338,2786,42248,14110,9063,51277,5,1385,330)
offs = (42,0,29,13,19,3,0,0,0,0,0)
def lookup(th):
    lo = 2
    hi = 61828
    while lo < hi:
        mid = (lo + hi) // 2
        a = prog.rfind(",", 0, mid)+1
        b = prog.find(",", mid)
        h = table[ord(prog[b-1]) - 65]
        for i in range(b-a):
            if i < len(offs):
                h += table[ord(prog[a+i]) + offs[i] - 65]
        if h < th:
            lo = mid + 1
        else:
            hi = mid
    return lo

leet_table = {
    'A': '4',
    'B': '8',
    'E': '3',
    'G': '6',
    'I': '1',
    'O': '0',
    'S': '5',
    'T': '7',
    'Z': '2'
}

cur_byte = 0
cur_bit = 0

def read_bits(n):
    global cur_bit, cur_byte
    res = 0
    resbits = 0
    while resbits < n:
        chunk = min(n - resbits, 8 - cur_bit)
        t = (data[cur_byte] >> cur_bit) & ((1 << chunk) - 1)
        res |= t << resbits
        resbits += chunk
        cur_bit += chunk
        if cur_bit == 8:
            cur_bit = 0
            cur_byte += 1
    return res

p = 0
while p < 2028:
    t = lookup(read_bits(18))
    while prog[t] != ",":
        c = prog[t]
        if c in leet_table and read_bits(1):
            sys.stdout.write(str(leet_table[c]))
        else:
            sys.stdout.write(c)
        t += 1
        p += 1
    sys.stdout.write(" ")
    sys.stdout.flush()
    p += 1

while p < 2048:
    print(chr(read_bits(8)), end="")
    p += 1

sys.stdout.flush()
exit(0)
""")
```

## Conclusion

This compressor is able to encode 2048 bytes of data in around 740 bytes on average (around 1308 points), more than sufficient to top the leaderboard. Running it several times produces different results, with the best result out of several runs being 1320 points (flag: `941379cb175c2e078e9d65606fc4ef3048468e0a4d45c717094dd268c0cafb60.1320`).

For "style" reasons, I decided to go a little further. Changing the constant 2028 to 2040 reduces the length of the (inefficiently-encoded) tail, at the risk of occasionally failing if the final word is too long. With this change, I was able to quickly obtain a score of **1337 points** (flag: `2fdd6a0e1801daa160f5475fb710879dd3f1bf6774da6c92e8f63867849b1cef.1337`). I also obtained slightly higher scores (up to 1340: `d5aedd5fcd9177849ba5d174c79a7074d66f60d911338616eb044290d9081088.1340`), but chose not to submit them. Here's how the leaderboard looked like by the end of the CTF:

```
           Team           |     Score       |           Time             
--------------------------+-----------------+----------------------------
 Maple Bacon              | {"score": 1337} | 2024-06-30 19:24:57.567+00
 thehackerscrew           | {"score": 980}  | 2024-06-30 19:49:18.4+00
 r3kapig                  | {"score": 859}  | 2024-06-30 13:29:04.553+00
 The Flat Network Society | {"score": 856}  | 2024-06-29 17:17:16.553+00
 Team Austria             | {"score": 850}  | 2024-06-29 19:03:02.087+00
 Perperikon               | {"score": 843}  | 2024-06-29 19:59:56.281+00
 Brunnerne                | {"score": 837}  | 2024-06-30 12:09:16.699+00
 Kalmarunionen            | {"score": 649}  | 2024-06-30 15:04:40.344+00
 pwnlentoni               | {"score": 603}  | 2024-06-30 10:46:12.362+00
 gsitcia                  | {"score": 512}  | 2024-06-30 01:46:13.402+00
 ```

This was a very fun challenge, with a rather unexpected twist in the form of some harsh restrictions on the Python side. Here's a summary of the solution:

- Use `gperf` to produce a perfect hash function for the wordlist, which can be efficiently implemented in C and compiled with the XC8 compiler.
- The compressor outputs 18 bits per word (regardless of word length), plus one bit per 1337-speakable character in the word.
- On the decompressor side, smuggle the entire wordlist in a comment to keep the overall size under the command-line argument size, and to avoid blowing the memory limit during `exec`.
- Obtain access to the embedded wordlist by extracting the `prog` variable from the parent stack frame via an exception object.
- Clear `sys.argv` to free up a bit more memory, and use a nested `exec` to avoid immediately blowing the memory limit in the outer `exec`.
- Use a binary search to search the wordlist each time, to avoid allocating more than O(1) extra memory, and avoid blowing the CPU time limit on an expensive (but simple) linear search.
- Use a slightly more aggressive implementation with a small probability of failure in order to score exactly 1337 points ("style").
