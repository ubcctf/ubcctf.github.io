---
layout: post
title: "[UTCTF 2022] Bloat"
author: alueft
---

## tl;dr

web person killsteals a pwn chall

## Intro

This is the problem entitled "Bloat" from
[UTCTF 2022](https://ctftime.org/event/1582).

The problem description is as follows:

```
I've created a new binary format. Unlike ELF, it has no bloat. It just consists
of a virtual address to store the data at, then 248 bytes of data. However, when
I tried to contribute it back to the mainline kernel they all called my
submission "idiotic", and "wildly unsafe". They just cant recognize the next
generation of Linux binaries.

Login with username bloat and no password

By Tristan (@trab on discord)

nc pwn.utctf.live 5003
```

Provided are a Linux kernel and initrd, and a script that uses both to run a
qemu instance.

## First steps

The script looks like this (where `bzImage` and `rootfs.cpio.gz` are the
aforementioned files, and `flag.txt` is manually provided):

```sh
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64 \
    -kernel bzImage \
    -initrd rootfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "rootwait root=/dev/vda console=ttyS0 kpti=1 quiet panic=1 nokaslr"
```

Of note here is `-hdb flag.txt`, which puts the flag in `/dev/sda` on the image,
and `nokaslr`, which means that [KASLR](https://lwn.net/Articles/569635/) isn't
in use and the kernel is guaranteed to be loaded into the same place in memory
every time.

We can either take the problem description at face value, or we (read as:
someone more knowledgeable about these matters in our Discord) can poke around
the image, find a custom `bloat.ko` module, extract it, and examine its
contents. In any case, we'll find that executing anything with a suffix of
`.bloat` will run the module, which writes 248 bytes to *any* place in memory.
Since the kernel's location in memory is static, we can probably find something
interesting to overwrite and allow us to do something as root.

## [insert search engine here] to the rescue

Someone else has already done a nicely detailed writeup on how to overwrite
`modprobe_path`
[here](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/), so
I won't bother with repeating what the attack vector is.

In fact, it's even easier than what the article describes: there's no KASLR so
we don't need to figure out how to make a ROP chain, and we can just write the
new `modprobe_path` directly to memory at the appropriate address.

## The plan

1. Figure out the address for `modprobe_path`.
    1. Unarchive the initrd, find `/etc/shadow`, and copy the hash of the
       `bloat` user over to `root`.
    1. Re-archive the initrd, start the container, and log in as `root` with a
       blank password.
    1. Run `grep modprobe_path /proc/kallsyms`.
    1. Or, use [this](https://github.com/marin-m/vmlinux-to-elf) to get an ELF
       file out of the kernel, and read the address from there.
1. Construct the payload of the address (`0xffffffff82038180`), in little
   endian, followed by `/tmp/x`, followed by zero-byte padding so the entire
   thing comes out to 248 + 8 = 256 bytes.
1. Construct the script that will be magically run as root as `/tmp/x`.
1. Encode the payload in base64, copy it over to the container, and decode and
   run it.
1. Construct and run a dummy file to trigger the `modprobe_path` call.
1. Get the flag.

## The execution

An important note here is that running the .bloat file results in a segfault,
which might give the impression that it didn't work. But you just have to have
faith that it did.

<video width="100%" controls>
  <source src="/assets/videos/utctf2022/bloat.webm" type="video/webm">
</video>

## Re: killstealing

Basically I didn't really do anything other than get the actual flag text -
[Robert](/authors/Nneonneo) figured out most of the problem's theory, and
[Kevin](/authors/Kevin) demonstrated the exploit almost working to me. We were
all submitting under one account anyway, so really this just meant I had to do
this writeup.

