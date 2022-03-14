---
layout: post
title: "[UTCTF 2022] Ebook DRM"
author: desp
---

## Challenge
>I know I have the flag somewhere in this book, but it's over a million lines long and the awful DRM won't let me read the file fast enough to find it remotely soon. Maybe you can help?

>I spent way too long writing this problem...

>[haystack.slowreader](https://utexas.box.com/s/23kqj1bd1u8av54m79l3memiwiogbtsi)

>By Daniel Parks (@danielp on discord)

>[slowreader](https://utctf.live/files/c7cecaa846d5e7641afcd8d62c91bb93/slowreader)
<br><br>

## TL;DR
Sometimes brute reversing things is not the way to go, especially when they are heavily guarded - there usually are smarter ways to trick the programs, such as proxying dynamically linked libraries.
<br><br><br>

## Investigation and Preliminary Patching

As with most rev challenges, it provided us a binary and no nc endpoints to connect to. So the first thing to do is of course to try running it and get a sense of how it works (~~who doesn't love running suspicious code on their machines, am I right?~~):
```
$ ./slowreader
./slowreader: /lib/libc.so.6: version `GLIBC_2.34' not found (required by ./slowreader)
```
Oh boy, glibc incompatibility - glibc this recent will require either backporting or upgrading the entire system, which would both take a lot of work and we don't have that much time in a CTF. Time to do some magic with the Linux dynamic linker! But first, we need to know what version of loader we should use:
```
$ file ./slowreader
./slowreader: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=d31e8e5b0e045dc57571fdf52fdd0d5829182eba, for GNU/Linux 4.4.0, stripped
```
With that, we can just go to [Ubuntu's download page for glibc](https://packages.ubuntu.com/impish/i386/libc6/download) (aka libc6) and grab the deb, unpack with `ar x libc6_2.34-0ubuntu3.2_amd64.deb`, then `zstd -d data.tar.zst` and `tar -xf data.tar` (run it in a separate directory or you will have files scattered around!). Now that we have the libraries, lets try the good ol' `LD_LIBRARY_PATH` trick:
```
$ LD_LIBRARY_PATH=./lib/i386-linux-gnu/ ./slowreader
Segmentation fault (core dumped)
```
Huh, that's really weird - seems like the system default linker which is of the older version is incompatible with the newer glibc libraries. Let's try again by directly calling the linker from the new glibc:
```
$ ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader
Usage: slowreader FILE
```
Eyy - now it works as expected. Lets pass the file provided by the challenge as a parameter:
```
$ ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader ./haystack.slowreader
Usage: slowreader FILE
```
Looks like it is not accepting the file for some reason. Guess it's time to start our reversing journey:

![argcheck.png](/assets/images/utctf2022/ebook-drm/argcheck.png)

Hmm, it's checking for the `slowreader` string, but we have to pass a valid path to the loader. Might as well just patch the check out entirely by bypassing the `jnz` - with the patch at `1CD7A` `0F 85 C2 00 00 00` -> `90 90 90 90 90 90`, we can try running it again now:
```
$ ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader ./haystack.slowreader
Welcome to SlowReader(c) 6.96.9
You are allowed to read 1 line every 2 seconds
Loading file...
Press ENTER to load a line.
```
Nice! It seems to want us to press enter over and over again to advance line by line, but we can do better:

![pressenter.png](/assets/images/utctf2022/ebook-drm/pressenter.png)

Just a simple `getline` call, nothing that can't be patched out. By patching the loop end `jmp` to skip the check with `1CE41` `C0` -> `DD`, we can press enter once and it will loop indefinitely:
```
$ ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader ./haystack.slowreader
Welcome to SlowReader(c) 6.96.9
You are allowed to read 1 line every 2 seconds
Loading file...
Press ENTER to load a line.

This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).
(...)
```
Great! But now the main problem comes - the lines are still only being read every 2 seconds. How are we gonna deal with it?
<br><br><br>


## ***Wait***, how'd it do that?

The 2 second delay has 2 possibilities - either they used a crude execution loop to time the delay, or they called one of the time related Linux functions to determine their elapsed time. The former seems very unlikely - the delay is very accurate, and the timer knows to delay if we press too fast but allows instantly if we press enter later than the delay, which would require that delay timer to be running in another thread if it was an execution loop. Looking at the imported functions in `extern`, we can prove that it is indeed the latter:
```
Function name	        Segment	Start	Length	Locals	Arguments	R	F	L	M	S	B	T	=
fileno			extern	0002F4B8	00000004	00000000	00000000	R	.	.	.	.	.	T	.
__errno_location		extern	0002F4BC	00000004	00000000	00000000	R	.	.	.	.	.	T	.
strerror			extern	0002F4C0	00000004	00000000	00000000	R	.	.	.	.	.	T	.
clock_gettime		extern	0002F4C4	00000004	00000000	00000000	R	.	.	.	.	.	T	.
ptrace			extern	0002F4C8	00000004	00000000	00000000	R	.	.	.	.	.	T	.
fgets			extern	0002F4CC	00000004	00000000	00000000	R	.	.	.	.	.	T	.
EVP_DecryptInit_ex	extern	0002F4D0	00000004			R	.	.	.	.	.	.	.
perror			extern	0002F4D4	00000004	00000000	00000000	R	.	.	.	.	.	T	.
free			extern	0002F4D8	00000004	00000000	00000000	R	.	.	.	.	.	T	.
getline			extern	0002F4DC	00000004			R	.	.	.	.	.	.	.
fclose			extern	0002F4E0	00000004	00000000	00000000	R	.	.	.	.	.	T	.
fopen			extern	0002F4E4	00000004	00000000	00000000	R	.	.	.	.	.	T	.
getppid			extern	0002F4E8	00000004	00000000	00000000	R	.	.	.	.	.	T	.
strcpy			extern	0002F4EC	00000004	00000000	00000000	R	.	.	.	.	.	T	.
printf			extern	0002F4F0	00000004	00000000	00000000	R	.	.	.	.	.	T	.
EVP_CIPHER_CTX_new	extern	0002F4F4	00000004			R	.	.	.	.	.	.	.
strstr			extern	0002F4F8	00000004	00000000	00000000	R	.	.	.	.	.	T	.
EVP_aes_256_cbc		extern	0002F4FC	00000004			R	.	.	.	.	.	.	.
malloc			extern	0002F500	00000004	00000000	00000000	R	.	.	.	.	.	T	.
__stack_chk_fail		extern	0002F504	00000004			.	.	.	.	.	.	.	.
memmove			extern	0002F508	00000004	00000000	00000000	R	.	.	.	.	.	T	.
puts			extern	0002F50C	00000004	00000000	00000000	R	.	.	.	.	.	T	.
rand			extern	0002F510	00000004	00000000	00000000	R	.	.	.	.	.	T	.
EVP_CIPHER_CTX_set_paddingextern	0002F514	00000004			R	.	.	.	.	.	.	.
index			extern	0002F518	00000004	00000000	00000000	R	.	.	.	.	.	T	.
fread			extern	0002F51C	00000004	00000000	00000000	R	.	.	.	.	.	T	.
snprintf			extern	0002F520	00000004	00000000	00000000	R	.	.	.	.	.	T	.
kill			extern	0002F524	00000004	00000000	00000000	R	.	.	.	.	.	T	.
__libc_start_main	extern	0002F528	00000004	00000000	00000000	R	.	.	.	.	.	T	.
EVP_DecryptUpdate	extern	0002F52C	00000004			R	.	.	.	.	.	.	.
strcmp			extern	0002F530	00000004	00000000	00000000	R	.	.	.	.	.	T	.
__cxa_finalize		extern	0002F534	00000004	00000000	00000000	R	.	.	.	.	.	T	.
exit			extern	0002F538	00000004	00000000	00000000	.	.	.	.	.	.	T	.
```
`clock_gettime` is referenced, whereas any threading calls are missing. But how are they referenced? Surely they didn't just make a simple comparison that is easily patched out:

![obfsfun.png](/assets/images/utctf2022/ebook-drm/obfsfun.png)

Yikes - reversing this directly will be a pain for sure. After poking around for quite a bit to see if there is any obvious places for time comparison (taking 2 `tp->tv_sec` at 2 different times and comparing, for example) and patching random bits and pieces, there still wasn't any good hint of how it's called. Tackling it in another direction seems to be time better spent than figuring out how this obfuscation works.

Since `clock_gettime` eventually enters kernel space through a syscall called, you guessed it, `clock_gettime`, `strace` should be able to pick it up, and we can figure out where and how the calls are made using the address information strace provides. Time to fire it up:
```
$ strace ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader ./haystack.slowreader

(...)

ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
getppid()                               = 19426
kill(19426, SIGTERM)                    = 0
strace: Process 19429 detached
Terminated
```
Seems like they actually implemented a typical anti-debug measure using `ptrace(PTRACE_TRACEME)` calls - this call fails with EPERM if there is a ptrace parent attached, so the code flow can be redirected, which for this case is into termination. No worries - we can just patch it out if it's simple. Tracing xrefs from the ptrace function, we can see where it's utilized:

![ptraceshennanigans.png](/assets/images/utctf2022/ebook-drm/ptraceshennanigans.png)

Yep, straightforward enough - skipping the `jz` check with `1CF26` `74 12` -> `90 90` should do the job.

```
$ strace ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader ./haystack.slowreader

(...)

read(4, "Name:\tstrace\nUmask:\t0077\nState:\t"..., 1024) = 1024
close(4)                                = 0
kill(20063, SIGBUSBus error (core dumped)
$ Press ENTER to load a line.
```

What? strace got terminated by `SIGBUS` while the child process is still going (it detaches from the terminal and goes into background), which really shouldn't be something that the patch can introduce. After a lot of poking around with ptrace returns and such, it ended up being a problem completely unrelated to the patch, but once again glibc itself - it seems like both the parent and the child have to be using the same glibc version. However, we have a slight problem - strace is 64bit, which means we have to fetch the 64bit version of glibc *again* using the same method, and then use **2** loaders to load each one in respectively. 
```
$ ./lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path ./lib/x86_64-linux-gnu/ /usr/bin/strace -fi ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ ./slowreader ./haystack.slowreader
[f7f32149] getppid()                    = 24763
[f7f32149] openat(AT_FDCWD, "/proc/24763/cmdline", O_RDONLY) = 4
[f7f32149] statx(4, "", AT_STATX_SYNC_AS_STAT|AT_NO_AUTOMOUNT|AT_EMPTY_PATH, STATX_BASIC_STATS, {stx_mask=STATX_BASIC_STATS, stx_attributes=0, stx_mode=S_IFREG|0444, stx_size=0, ...}) = 0
[f7f32149] read(4, "./lib/x86_64-linux-gnu/"..., 1024) = 247
[f7f32149] close(4)                     = 0
[f7f32149] write(1, "This is not the needle you are l"..., 57This is not the needle you are looking for (move along).
) = 57
```
With an overly long command, we can finally strace reliably - but where did the `clock_gettime` calls go? `-f` should've handled threading, and the program ain't calling any threading functions to begin with. Guess we are at a dead end again - time to find another path in.
<br><br><br>


## Speeding up
Just as I was stuck figuring out what to do next, [@Kevin](../../../authors/Kevin/) gave a great idea: Instead of reversing and patching the `clock_gettime` calls, is there any way to emulate time to speed it up? I know RDTSC emulation and syscall emulation is possible, but writing it ourselves would take quite a bit of time, especially when my only experience emulating RDTSC is for windows and it requires a lot of OS specific internals knowledge.

Apparently though, [@Kevin](../../../authors/Kevin/) noticed one such library that does exactly what we want exists, and it's called [libfaketime](https://github.com/wolfcw/libfaketime) - which can be loaded using `LD_PRELOAD`, but since we are manually invoking loaders, we can just use the `--preload` option instead. After going through the syntax and wondering why it doesnt work even with known working commands like `watch` and `date`, we eventually figured out `FAKETIME` requires a date modifier then a speed modifier. Time to test it out:
```
$ FAKETIME='@2000-01-01 11:12:13 x20000' ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ --pre
load "./usr/lib/i386-linux-gnu/faketime/libfaketime.so.1" ./slowreader ./haystack.slowreader
Welcome to SlowReader(c) 6.96.9
You are allowed to read 1 line every 2 seconds
Loading file...
Press ENTER to load a line.

This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).
(...)
```
Woah now that's speed - it is practically running at real time, as if the 2 second restriction was never placed in the first place. All that's left is to wait for it to print all the lines, and then fish out the flag, right?
```
(...)
This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).

[4]+  Stopped                 FAKETIME='@2000-01-01 11:12:13 x20000' ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ --preload "./usr/lib/i386-linux-gnu/faketime/libfaketime.so.1" ./slowreader ./haystack.slowreader
```
Oh no - this is a really bad sign that something broke. Under strace, we can get some more info on it:
```
$ FAKETIME='@2000-01-01 11:12:13 x20000' .lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 --library-path ./lib/x86_64-linux-gnu/ /usr/bin/strace -fi ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ --preload "./usr/lib/i386-linux-gnu/faketime/libfaketime.so.1" ./slowreader ./haystack.slowreader

(...)

[f7f1d149] read(6, "Name:\tld-linux-x86-64\nUmask:\t007"..., 1024) = 1024
[f7f1d149] close(6)                     = 0
[f7ef6058] --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=NULL} ---
[????????] +++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)
```
Oh boy - something is not right here. Digging into the core dump generated by `apport-unpack` on the file in `/var/crash/` (on a Ubuntu system) using `gdb`, we get this:
```
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0xf7eaa058 in ?? ()
(gdb) bt
#0  0xf7eaa058 in ?? ()
#1  0xf7eb8e28 in ?? ()
#2  0xf79ae4ca in ?? ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
(gdb) x/10i 0xf7eaa058
=> 0xf7eaa058:  mov    %eax,(%esi)
   0xf7eaa05a:  mov    0xf7ecb2c8,%edi
   0xf7eaa060:  mov    0xf7ecb330,%esi
   0xf7eaa066:  call   0xf7eb5ab0
   0xf7eaa06b:  imul   $0x3587719a,-0x81442e8(,%eax,4),%ebx
   0xf7eaa076:  call   0xf7eb5ad0
   0xf7eaa07b:  mov    -0x81442dc(,%eax,4),%eax
   0xf7eaa082:  add    %ebx,%eax
   0xf7eaa084:  add    $0x8773f3a0,%eax
   0xf7eaa089:  cmp    %eax,%esi
(gdb) x/100bx 0xf7eaa058
0xf7eaa058:     0x89    0x06    0x8b    0x3d    0xc8    0xb2    0xec    0xf7
0xf7eaa060:     0x8b    0x35    0x30    0xb3    0xec    0xf7    0xe8    0x45
0xf7eaa068:     0xba    0x00    0x00    0x69    0x1c    0x85    0x18    0xbd
0xf7eaa070:     0xeb    0xf7    0x9a    0x71    0x87    0x35    0xe8    0x55
0xf7eaa078:     0xba    0x00    0x00    0x8b    0x04    0x85    0x24    0xbd
0xf7eaa080:     0xeb    0xf7    0x01    0xd8    0x05    0xa0    0xf3    0x73
0xf7eaa088:     0x87    0x39    0xc6    0x0f    0x9c    0xc3    0xe8    0x5d
0xf7eaa090:     0xba    0x00    0x00    0x8b    0x04    0x85    0x30    0xbd
0xf7eaa098:     0xeb    0xf7    0xb9    0x7e    0x0f    0xdd    0xde    0x31
0xf7eaa0a0:     0xc8    0x8d    0x34    0x07    0x83    0xc6    0x01    0x0f
0xf7eaa0a8:     0xaf    0xf7    0xe8    0x61    0xba    0x00    0x00    0x0f
0xf7eaa0b0:     0xb6    0x0c    0x85    0x3c    0xbd    0xeb    0xf7    0xbf
0xf7eaa0b8:     0x78    0x9b    0x05    0x05
(gdb)
```
Which after searching for bytes in IDA, maps to address `E058` before ASLR.

![morepain.png](/assets/images/utctf2022/ebook-drm/morepain.png)

Seems like `fileno` is returning a null pointer for `stdin` for some reason, with which the next segment of code dereferenced - did stdin get prematurely closed?

Understanding how this happens is probably as difficult as reversing how `clock_gettime` works itself, not to mention how sporadic this failure is even with slow time multipliers - which means it is time to move onto yet another method to try.
<br><br><br>


## Proxying
Thinking back to the days where I used to bypass kernel protection using dll proxying on windows, I suddenly wondered if it is possible on Linux too, in order to grab information directly from the `openssl` `EVP_Decrypt*` functions. This way, we can at least know if the key and iv dynamically changes, and how the program decrypts the haystack file. Turns out, `LD_PRELOAD` allows exactly this with much more ease than windows - it overrides any function of any library with the `.so`s provided to it. Since we mainly want to get the key and iv, we can choose `EVP_DecryptInit_ex` to proxy first, of which the function signature is freely available on [man page](https://linux.die.net/man/3/evp_decryptinit_ex). With that knowledge, we can write something similar to this:
```c
#include <stdio.h>
#include <string.h>

int EVP_DecryptInit_ex(void *ctx, const void *type, void *impl, const unsigned char *key, const unsigned char *iv) {
    int i;

    printf("key 0x");
    for (i=0; i < 32; i++)
        printf("%02x",key[i] & 0xff);

    printf("\niv 0x");

    for (i=0; i < 16; i++)
        printf("%02x",iv[i] & 0xff);
    printf("\n");

    return 0;
}
```
Note that the specific struct pointers are all changed to `void*` to avoid needing to link openssl libraries, since we don't need them anyways. The key and iv sizes are fixed - AES-256-CBC requires 32 bytes for key and 16 bytes for iv respectively. Compiling with `gcc -fPIC -shared -m32 evpintercept.c -o evpintercept.so` and preloading it gets us:
```
$ ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ --preload ./evpintercept.so ./slowreader ./h
aystack.slowreader
Welcome to SlowReader(c) 6.96.9
You are allowed to read 1 line every 2 seconds
Loading file...
key 0x4498a9650fa72cf38d0777a611b33c140172cfef7bda174fba255c4a59551678
iv 0x3d07501c1386909a3eee28e8e97a5e29

[2]+  Stopped                 ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ --preload ./evpintercept.so ./slowreader ./haystack.slowreader
```
Nice, we got the first key! However, since we are writing a stub that prints and returns without doing the actual decrypt init routines, it segfaults right afterwards as expected. We would like to see whether there are more keys and ivs that are being used after this initial load - the file might be segmented into chunks of data with different keys that the program computes and cycles through. This is where dynamic linking comes into play - we can utilize the `dlopen` and `dlsym` functions, which are analogous to `LoadLibraryEx` and `GetProcAddress` for Windows, to get a function pointer to call on.
```c
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

int EVP_DecryptInit_ex(void *ctx, const void *type, void *impl, const unsigned char *key, const unsigned char *iv) {
    int i;

    printf("key 0x");
    for (i=0; i < 32; i++)
        printf("%02x",key[i] & 0xff);

    printf("\niv 0x");

    for (i=0; i < 16; i++)
        printf("%02x",iv[i] & 0xff);
    printf("\n");

    void *handle = dlopen("/usr/lib/libssl.so.1.1", RTLD_NOW);

    int (*orig_func)() = dlsym(handle, "EVP_DecryptInit_ex");
    return orig_func(ctx, type, impl, key, iv);
}
```
Compiling and preloading again gives us the following output:
```
$ ./lib/ld-linux.so.2 --library-path ./lib/i386-linux-gnu/ --preload ./evpintercept.so ./slowreader ./haystack.slowreader
Welcome to SlowReader(c) 6.96.9
You are allowed to read 1 line every 2 seconds
Loading file...
key 0x4498a9650fa72cf38d0777a611b33c140172cfef7bda174fba255c4a59551678
iv 0x3d07501c1386909a3eee28e8e97a5e29
Press ENTER to load a line.

This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).
(...)
```
Nice! It's not segfaulting anymore, and it doesn't seem like the key and iv is ever changed. Just to be sure that the keys are for decrypting the haystack file, we can proxy `EVP_DecryptUpdate` to check what the keys are being used for:
```c
int EVP_DecryptUpdate(void *ctx, unsigned char *out,int *outl, unsigned char *in, int inl) {

     int i;

     printf("ciphertext of length 0x%d: 0x", inl);
     for (i=0; i < inl; i++)
       printf("%02x",in[i] & 0xff);
     printf("\n");

     void *handle = dlopen("/usr/lib/libssl.so.1.1", RTLD_NOW);


     int (*orig_func)() = dlsym(handle, "EVP_DecryptUpdate");
     int ret = orig_func(ctx, out, outl, in, inl);

     printf("plaintext of length 0x%d: %s\n\n", *outl, out);

     return ret;
}
```
Time to check what prints after we press enter:
```
Press ENTER to load a line.

ciphertext of length 0x16: 0xf97f2a875aa1034513dc2ebbfb3d2539
plaintext of length 0x16: This is not the

ciphertext of length 0x16: 0x318d88be24200e1dac9facf80e13e67c
plaintext of length 0x16: needle you are l

ciphertext of length 0x16: 0x4b8bebb6bb4c5cd04e7ae499c610c05f
plaintext of length 0x16: ooking for (move

ciphertext of length 0x16: 0xc66a76feb2852f003ea35346fc62ca9c
plaintext of length 0x16:  along).
This is

This is not the needle you are looking for (move along).
```
Exactly what we are looking for! Time to try the keys out and hope for the best.
<br><br><br>

## Finding the needle in the haystack
I've always had a tendency to screw up code for encryption and decryption for some reason, but [@Kevin](../../../authors/Kevin/) is once again back to save my *bacon*, and he quickly whipped up a decrypter:
```py
from Crypto.Cipher import AES

key = bytes.fromhex("4498a9650fa72cf38d0777a611b33c140172cfef7bda174fba255c4a59551678")
iv = bytes.fromhex("3d07501c1386909a3eee28e8e97a5e29")
cipher = AES.new(key, AES.MODE_CBC)
f = open("haystack.slowreader", "rb")
ct = f.read()
pt = cipher.decrypt(ct)
g = open("flag.txt", "wb")
g.write(pt)
```
Looking at the file, we see some junk in the header and footer, but:
```
slowreader book
This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).
This is not the needle you are looking for (move along).
```
It worked! All that's left is to actually find the *flag* in the *textstacks* - something we can easily do with a simple ctrl-f for `utflag`. Thus finally we have the flag:

`utflag{ghidra_isnt_always_the_answer}`

at line `1789678`!