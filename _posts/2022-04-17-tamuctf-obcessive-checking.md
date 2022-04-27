---
layout: post
title: "[TAMUCTF 2022] Obcessive Checking"
author: desp
---

## Challenge
>Author: `Addison`

>Decrypt flag_book.txt.bin using the binary obcessive-checking.
>I wouldn't try to wait for it though...

>Heavily inspired by UTCTF 2022's "eBook DRM". Use that information as you will... :)

>[obcessive-checking.zip]()
<br><br>

 - Solves: 4 (first blood)
 - Points: 499/500
 - Category: Reversing
<br><br><br>

Time for a sequel to the [ebook DRM writeup](../../03/utctf-ebook-drm/)!

## So familiar, yet so foreign
Since ebook DRM was from just a month ago, I still remember most of the details about its implementation, from time manipulation detection to how the "book" is decrypted. Learning from the things that went wrong last time, I went in trying to see just how similar they are:
```
$ file ./obsessive-checking
./obsessive-checking: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0005a874509ba56e24577efa7c840eee2f74e8e2, for GNU/Linux 3.2.0, with debug_info, not stripped

$ ./obsessive-checking ./flag_book.txt.bin
why yes, this is a string of output; unfortunately, it won't do you much good...
why yes, this is a string of output; unfortunately, it won't do you much good...
why yes, this is a string of output; unfortunately, it won't do you much good...
(...)
```
Yay, no glibc issues! It looks like the press enter requirement is also not present this time, which saves us a bit of time. Aside from the fact that this is a 64 bit program now, everything looks pretty much the same on the surface - you provide a "book" file, and the reader takes its time reading it line by line. Since we couldn't get `libfaketime` to work in ebook DRM, why not try it again this time? Using `LD_PRELOAD` instead of the long command for changing glibc, we can run `libfaketime` in it's intended way:
```
$ LD_PRELOAD='./usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1' FAKETIME='@2000-01-01 11:12:13 x20000' ./obsessive-checking ./flag_book.txt.bin
thread 'main' panicked at 'suspicious jitter detected', src/main.rs:89:21
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```
Oh, here we go - the first major difference from ebook DRM. This program is written in rust instead, and the abstractions in rust makes reversing natively much harder. Luckily, it also means there is some higher level tools to help debugging, and the `RUST_BACKTRACE` mentioned in the panic message is one of them. Let's try it with the option `full` to get the backtrace:
```
$ RUST_BACKTRACE=full LD_PRELOAD='./usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1' FAKETIME='@2000-01-01 11:12:13 x20000' ./obsessive-checking ./flag_book.txt.bin
thread 'main' panicked at 'suspicious jitter detected', src/main.rs:89:21
stack backtrace:
   0:     0x55b2477d2611 - std::backtrace_rs::backtrace::libunwind::trace::h8c46421c648dbca9
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/../../backtrace/src/backtrace/libunwind.rs:93:5
   1:     0x55b2477d2611 - std::backtrace_rs::backtrace::trace_unsynchronized::hd50105c9d2b7da0a
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/../../backtrace/src/backtrace/mod.rs:66:5
   2:     0x55b2477d2611 - std::sys_common::backtrace::_print_fmt::hc699a2576ed455f0
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/sys_common/backtrace.rs:66:5
   3:     0x55b2477d2611 - <std::sys_common::backtrace::_print::DisplayBacktrace as core::fmt::Display>::fmt::hab6293987879eaf3
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/sys_common/backtrace.rs:45:22
   4:     0x55b24779b29c - core::fmt::write::h905fba7b43355745
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/core/src/fmt/mod.rs:1190:17
   5:     0x55b2477b2364 - std::io::Write::write_fmt::hd9b8771b7d0491ea
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/io/mod.rs:1655:15
   6:     0x55b2477d351a - std::sys_common::backtrace::_print::h993426b661a82299
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/sys_common/backtrace.rs:48:5
   7:     0x55b2477d351a - std::sys_common::backtrace::print::h31544447d64d529b
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/sys_common/backtrace.rs:35:9
   8:     0x55b2477d351a - std::panicking::default_hook::{{closure}}::h0f7b64811cfee79b
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/panicking.rs:295:22
   9:     0x55b2477d4506 - std::panicking::default_hook::h7f152c7e049791f6
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/panicking.rs:314:9
  10:     0x55b2477d4506 - std::panicking::rust_panic_with_hook::h277d612d2aaee173
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/panicking.rs:698:17
  11:     0x55b2477d3fd2 - std::panicking::begin_panic_handler::{{closure}}::ha6482b98e6c37965
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/panicking.rs:588:13
  12:     0x55b2477d3f46 - std::sys_common::backtrace::__rust_end_short_backtrace::h6f3ea54196387ec9
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/sys_common/backtrace.rs:138:18
  13:     0x55b2477d3f02 - rust_begin_unwind
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/std/src/panicking.rs:584:5
  14:     0x55b24777d4a2 - core::panicking::panic_fmt::he32ed279ce75bfff
                               at /rustc/335ffbfa547df94ac236f5c56130cecf99c8d82b/library/core/src/panicking.rs:143:14
  15:     0x55b247787580 - core::panicking::panic_display::h86f5ce82e2f50064
  16:     0x55b24779179a - <core::future::from_generator::GenFuture<T> as core::future::future::Future>::poll::hfef14762bdc823d3
  17:     0x55b2477931fb - obsessive_checking::main::hc5a58fdfe2bc1617
  18:     0x55b247783043 - std::sys_common::backtrace::__rust_begin_short_backtrace::h148379274e80f0d6
  19:     0x55b247795bc7 - main
  20:     0x7f0c5105b2bd - __libc_start_main
  21:     0x55b247782e8e - _start
  22:                0x0 - <unknown>
```
Looks like debug symbols are also present as it is usually with most rust challenges - that is gonna help in figuring out what "suspicious jitter detected" actually means. Time to bust out our reversing tools!
<br><br><br>

## *Rust*-y reversing skills
Weirdly enough, searching for anything resembling the panic reason string "suspicious jitter detected" in the ELF yielded no results, so we will have to find another way in. Since the backtrace will most likely prove very useful, let's start with getting the ASLR base address to figure out where each function is at. Looking at where `_start` is, we can get the ASLR offset quite easily:

![getaslr.png](/assets/images/tamuctf2022/obcessive-checking/getaslr.png)

Since there is only 1 `call` in `_start`, the return address is definitely at the `hlt` instruction right after the call; It also lines up with line 21 in the backtrace. With that info, we can easily obtain the offset by calculating `0x55b247782e8e - 0xee8e = 0x55b247774000`.

Now that we have the offset, we can move on to analysing what results in the panic - by looking into the function that calls `core::panicking::panic_display::h86f5ce82e2f50064`. At `1D79A`, which is line 16 from the backtrace with ASLR removed, we see something really interesting:

![suscheck.png](/assets/images/tamuctf2022/obcessive-checking/suscheck.png)

Just as the backtrace suggested, this function indeed triggers a panic, but only when `v479` is set - and it seems to be operating on the result from a call to a function named `sub_timespec`. Hmm, this is starting to feel more and more like the time comparison codes in ebook DRM that detects if there is time manipulation. Upon further inspection, the function indeed subtracts one timespec with another, as the name suggests.

Wait a second, ain't this one of the "obvious places for time comparison" that we struggled to find in ebook DRM? Might as well test our theory out - if that check is purely for panicking, there should be no issues with bypassing that entire code block. With `1D608` `0F 84 EE 00 00 00` -> `90 90 90 90 90 90`, we patch out the `jz` to the panicking block:

![dontpanic.png](/assets/images/tamuctf2022/obcessive-checking/dontpanic.png)

Moment of truth - if this doesn't crash even though we cranked the speed multiplier much higher, we should be golden:
```
$ LD_PRELOAD='./usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1' FAKETIME='@2000-01-01 11:12:13 x20000000' ./obsessive-checking ./flag_book.txt.bin > flag.txt
$
```
Nice! Even though it still took a while, it finished without problems. Let's run a grep on the file for the flag header, just like we did in ebook DRM:
```
$ grep -n 'gigem' flag2.txt
200000:gigem{round_and_round_and_round_it_goes_when_it_stops_checking_nobody_knows}
```
There it is:

`gigem{round_and_round_and_round_it_goes_when_it_stops_checking_nobody_knows}`

at line `200000`! Once again, it is near the end of the file to deter waiting, just like how it was in ebook DRM.
<br><br>

## Thoughts

With how similar the entire challenge was to ebook DRM mechanics wise, it did feel slightly unfair for those who didn't compete and solve it in UTCTF. With the techniques we attempted and documented in the writeup that challenge, I was able to analyse and solve this in a fraction of the amount I spent on ebook DRM, even though the code was entirely reimplemented in rust along with tweaks made for it.

This is not to say that this challenge was not good though - the rust elements were fun to figure out and adapt to, and one certainly can't just implement the techniques for ebook DRM directly here without knowing how this version works first. Along with the public availability of the ebook DRM source code and writeups for it, it seems fair enough with the direct hint in the challenge description, and this certainly did not feel like a work of plagiarism.

Overall, I really enjoyed solving this - props to Addison for reimagining the already fun ebook DRM challenge!