---
layout: post
title: "[LINE CTF 2022] Rolling"
author: desp
---

## Challenge
>what you know about rolling?

>[rolling.apk]()
<br><br>

 - Solves: 19
 - Points: 210
 - Category: Reversing
<br><br><br>

## Investigation

It's quite nice to see something other than ELFs for reversing every now and then. *But is this really not one of them?*

This time we are provided with an Android application package, which we can unpack and investigate. But first, getting it up and running with an emulator or an actual phone will provide us with a better feel of what it does. Since I have a rooted phone already geared up for testing things on, it's time to do some `adb` magic and get it installed after connecting with USB debugging on:
```
D:\Downloads\linectf2022>adb install rolling.apk
Performing Streamed Install
adb: failed to install rolling.apk: Failure [INSTALL_FAILED_OLDER_SDK: Failed parse during installPackageLI: /data/app/vmdl1884702458.tmp/base.apk (at Binary XML file line #7): Requires newer sdk version #29 (current version is #28)]
```
Ah, what's a good challenge without hiccups? It seems like the organizers compiled this with a newer Android version than my phone. Fret not, we can most likely just repack it. Time to unpack with [apktool](https://ibotpeaches.github.io/Apktool/):
```
D:\Downloads\linectf2022>java -jar ..\apktool_2.6.1.jar d rolling.apk
I: Using Apktool 2.6.1 on rolling.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: 1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Baksmaling classes2.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```
And now we can edit the `apktool.yml` in the resultant folder and change the `minSdkVersion` to `28` instead of `29`. Repacking and installing should give us:
```
D:\Downloads\linectf2022>java -jar ..\apktool_2.6.1.jar b rolling
I: Using Apktool 2.6.1
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether sources has changed...
I: Smaling smali_classes2 folder into classes2.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Copying libs... (/lib)
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...

D:\Downloads\linectf2022>adb install rolling\dist\rolling.apk
Performing Streamed Install
adb: failed to install rolling\dist\rolling.apk: Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: Failed to collect certificates from /data/app/vmdl2102788743.tmp/base.apk: Attempt to get length of null array]
```
Oops, forgot to sign the apk as required [by Android](https://developer.android.com/studio/publish/app-signing). Luckily, [dex2jar](https://github.com/pxb1988/dex2jar) provide us with a really simple way to insert a dummy certificate into the apk:
```
D:\Downloads\linectf2022>..\dex-tools-2.1\d2j-apk-sign.bat rolling\dist\rolling.apk
sign rolling\dist\rolling.apk -> rolling-signed.apk

D:\Downloads\linectf2022>adb install rolling-signed.apk
Performing Streamed Install
adb: failed to install rolling-signed.apk: Failure [INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2]
```
Aha, native libraries are present - when an app uses native libraries, which are basically Linux ELF files, we need to page align the libs using `zipalign -p` for the apk to install successfully. This means we are very likely gonna have to reverse ELF files again, and the java code will just act as a wrapper. Either way, we shall march on for now:
```
D:\Downloads\linectf2022>zipalign -p 4 rolling-signed.apk rolling-signed-aligned.apk

D:\Downloads\linectf2022>adb install rolling-signed-aligned.apk
Performing Streamed Install
Success
```
And there we finally have it. Let's check out the UI:

<img src="/assets/images/linectf2022/rolling/ui.png" alt="ui.png" style="display:block;margin:auto;max-width:50%"/>

Looks like a flag checker, which is common for reversing challenges. The question now, though, is how does it actually check the flag?
<br><br><br>

## It was me, ELF!

To start our reversing, lets first take a look in the dex files of the apk. `dex2jar` also provides us a nice way to convert them to java class files for decompilation:
```
D:\Downloads\linectf2022>..\dex-tools-2.1\d2j-dex2jar.bat rolling.apk -o rolling.jar
dex2jar rolling.apk -> rolling.jar
```
And now we can open it in [Enigma](https://github.com/FabricMC/Enigma). After poking around, there seems to only be one useful class to look at:

![enigma.png](/assets/images/linectf2022/rolling/enigma.png)

And just as guessed, there is nothing useful here aside from a placeholder flag (~~nice rickroll you got there~~). The verification codes are probably all hidden in `deep()`, which means we have to finally take a look at the native ELF file bundled. Open `libnative-lib.so` unpacked from `apktools` in IDA, and we can see that we are indeed correct:

![deep.png](/assets/images/linectf2022/rolling/deep.png)

The code seems to be hooking the java functions and basically redirecting `checkFlag()` to itself, and checking the flag by iterating through the flag and checking each character with 3 different obfuscation methods to compare with the data in `asc_47E8`. All 3 functions looks to be quite convoluted, but they seem to be working independently, with no relation to position or previous input.

This means we got 2 easier choices than to perform static analysis - either map the output of each character and each obfuscation "box"es, or do a character by character brute force using `v41` as an indicator of failure. The former seems to be more efficient, so lets go with that.
<br><br><br>

## Androids are still Linuxes, y'know
Since the native lib is just an ELF file, and the `*box` functions don't seem to be calling any JNI methods, it is likely possible to directly call the obfuscation functions on an ARM machine to obtain the results. Just to be safe though, we can directly debug on the phone itself since it is rooted, just like how we would normally debug on Linux, by using the `gdb` provided in Android NDK. Lets get `gdbserver` up and running on the phone:
```
D:\Downloads\linectf2022>adb push ..\android-ndk\prebuilt\android-arm64\gdbserver\gdbserver /data/local/tmp/
..\android-ndk\prebuilt\android-arm64\gdbserver\gdbserver: 1 file pushed, 0 skipped. 285.0 MB/s (1429848 bytes in 0.005s)

D:\Downloads\linectf2022>adb forward tcp:1337 tcp:1337
1337

D:\Downloads\linectf2022>adb shell
/ $ su
/ # cd /data/local/tmp
/data/local/tmp # chmod 700 ./gdbserver
/data/local/tmp # ps -A | grep 'linectf'
u0_a161      25832  2253 3814304  83956 SyS_epoll_wait 73bf38d94c S me.linectf.app
/data/local/tmp # ./gdbserver --attach :1337 25832
warning: Found custom handler for signal 39 (Unknown signal 39) preinstalled.
Some signal dispositions inherited from the environment (SIG_DFL/SIG_IGN)
won't be propagated to spawned programs.
Attached; pid = 25832
Listening on port 1337
```
Time to write a script to automate gdb! Since gdb is entirely text based, it is easily automatable using `pwntools`, but it is not available on windows where NDK has prebuilt binaries for. Luckily [pwintools](https://github.com/masthoon/pwintools) is available as a basic reimplementation in windows, which is just enough for our use case. After a few keysmashes, we can get something like this:
```py
from pwintools import *
import logging

logging.basicConfig(level=logging.DEBUG)

#start gdb client
io = Process(r'..\android-ndk\prebuilt\windows-x86_64\bin\gdb.exe')
io.set_timeout(300000)  #avoid connection dropping due to slow USB connections

#connect to phone via port forwarded
io.sendline('target remote :1337')
io.recvuntil(b'\n(gdb) ')

#get native lib's base address
io.recvuntil(b'\n(gdb) ')
io.sendline('info proc mapping')
print("getting proc info...")
lines = io.recvuntil(b'base.apk').decode('utf-8').split('\n')  #first occurence should be the native lib
addr = int(lines[len(lines) - 1].split('0x')[1].strip(), 16)
print('base addr:', hex(addr))

#set breakpoint
io.recvuntil(b'\n(gdb) ')
io.sendline('b *' + hex(addr + 0x39E0))  #breakpoint right after *box for obtaining the values
print('breakpoint set - enter characters as flag now')  #manually entering all the printable characters in the input box on the phone then clicking check to trigger the stepping is easier to handle
io.recvuntil(b'\n(gdb) ')

map = {}

#step through all the printable characters
for i in range(0x7f - 0x20):
    io.sendline('continue')

    #get current char
    io.recvuntil(b'\n(gdb) ')
    io.sendline('x/s $sp+0x94')

    chr = io.recvuntil(b'\n(gdb) ').decode('utf-8').split('"')[1]
    print("current char:", chr)

    #get registers that corresponds to the returned value pointers of each *box
    io.sendline('i r')
    regs = io.recvuntil(b'\n(gdb) ').decode('utf-8').split('\n')
    x0 = regs[0].split('0x')[1].split(' ')[0].strip()
    x24 = regs[24].split('0x')[1].split(' ')[0].strip()
    x25 = regs[25].split('0x')[1].split(' ')[0].strip()
    print('value addrs:', x0, x24, x25)

    io.sendline('x/x 0x' + x0)
    godbox = int(io.recvuntil(b'\n(gdb) ').decode('utf-8').split('0x')[2].split('\r')[0].strip(), 16)

    io.sendline('x/x 0x' + x24)
    soulbox = int(io.recvuntil(b'\n(gdb) ').decode('utf-8').split('0x')[2].split('\r')[0].strip(), 16)

    io.sendline('x/x 0x' + x25)
    meatbox = int(io.recvuntil(b'\n(gdb) ').decode('utf-8').split('0x')[2].split('\r')[0].strip(), 16)

    map[(godbox, soulbox, meatbox)] = chr

print(map)

io.close()
```
Eventually after running it we will obtain the mapped values, which we can paste into another script and decode `asc_47E8` into the actual flag:
```py
map = {(10, 28, 1): ' ', (18, 26, 14): '!', (11, 1, 19): '\\', (19, 21, 1): '#', (16, 17, 9): '$', (10, 21, 15): '%', (18, 2, 3): '&', (14, 11, 16): "'", (0, 29, 8): '(', (17, 11, 5): ')', (6, 6, 14): 'V', (9, 27, 3): '+', (18, 27, 1): ',', (0, 11, 0): '-', (12, 9, 1): '.', (9, 13, 7): '/', (18, 11, 8): '0', (15, 28, 14): '1', (12, 22, 4): '2', (16, 13, 4): '3', (9, 4, 7): '4', (17, 25, 9): '5', (4, 3, 1): '6', (0, 0, 11): '7', (18, 24, 6): '8', (13, 18, 3): '9', (4, 3, 15): ':', (8, 3, 11): ';', (7, 5, 15): '<', (5, 24, 15): '=', (2, 11, 2): '>', (18, 15, 17): '?', (16, 2, 12): '@', (13, 7, 16): 'A', (4, 27, 4): 'B', (8, 6, 18): 'C', (19, 15, 6): 'D', (15, 2, 11): 'E', (11, 9, 5): 'F', (2, 0, 5): 'G', (9, 13, 5): 'H', (18, 28, 15): 'I', (2, 10, 14): 'J', (4, 9, 11): 'K', (16, 24, 7): 'L', (11, 26, 16): 'M', (7, 10, 5): 'N', (1, 24, 8): 'O', (17, 0, 1): 'P', (10, 24, 19): 'Q', (18, 26, 0): 'R', (5, 12, 10): 'S', (7, 10, 19): 'T', (14, 7, 13): 'U', (8, 29, 8): 'W', (11, 15, 3): 'X', (14, 2, 0): 'Y', (12, 24, 19): 'Z', (1, 24, 2): '[', (0, 19, 7): '\\\\', (13, 18, 1): ']', (13, 4, 6): '^', (12, 1, 1): '_', (19, 29, 11): '`', (14, 1, 19): 'a', (14, 0, 18): 'b', (9, 1, 1): 'c', (10, 22, 6): 'd', (17, 16, 19): 'e', (5, 11, 7): 'f', (17, 21, 16): 'g', (8, 2, 9): 'h', (4, 20, 16): 'i', (2, 24, 6): 'j', (16, 5, 9): 'k', (15, 24, 8): 'l', (14, 14, 9): 'm', (10, 18, 1): 'n', (3, 23, 0): 'o', (5, 15, 17): 'p', (2, 19, 13): 'q', (4, 5, 7): 'r', (14, 27, 13): 's', (0, 11, 3): 't', (11, 15, 1): 'u', (8, 4, 12): 'v', (19, 4, 17): 'w', (10, 0, 6): 'x', (11, 23, 18): 'y', (0, 2, 6): 'z', (15, 15, 6): '{', (18, 28, 0): '|', (2, 23, 7): '}', (4, 23, 12): '~'}

#from asc_47E8; length 0x33 * 3 = 153 - from strlen check at 0x3A28
flag = [0x07, 0x18, 0x10, 0x0F, 0x1C, 0x12, 0x05, 0x0A, 0x07,
0x0B, 0x02, 0x0F, 0x12, 0x06, 0x08, 0x13, 0x0A, 0x07,
0x05, 0x09, 0x0B, 0x06, 0x0F, 0x0F, 0x11, 0x04, 0x13,
0x13, 0x01, 0x0E, 0x03, 0x0B, 0x00, 0x01, 0x01, 0x09,
0x09, 0x02, 0x08, 0x13, 0x01, 0x0E, 0x01, 0x01, 0x0C,
0x09, 0x05, 0x10, 0x01, 0x12, 0x0A, 0x08, 0x0B, 0x12,
0x11, 0x04, 0x13, 0x01, 0x01, 0x0C, 0x13, 0x01, 0x0E,
0x12, 0x00, 0x0E, 0x08, 0x0B, 0x12, 0x01, 0x0F, 0x0B,
0x03, 0x0B, 0x00, 0x01, 0x01, 0x0C, 0x07, 0x05, 0x04,
0x08, 0x0B, 0x12, 0x08, 0x18, 0x0F, 0x08, 0x18, 0x0F,
0x0E, 0x1C, 0x0F, 0x01, 0x12, 0x0A, 0x10, 0x15, 0x11,
0x01, 0x01, 0x0C, 0x06, 0x16, 0x0A, 0x08, 0x0B, 0x12,
0x11, 0x04, 0x13, 0x01, 0x12, 0x0A, 0x01, 0x01, 0x0C,
0x0E, 0x1C, 0x0F, 0x01, 0x12, 0x0A, 0x01, 0x01, 0x0C,
0x03, 0x0B, 0x00, 0x09, 0x02, 0x08, 0x04, 0x0D, 0x10,
0x01, 0x01, 0x0C, 0x06, 0x16, 0x0A, 0x04, 0x0D, 0x10,
0x04, 0x0D, 0x10, 0x11, 0x0F, 0x05, 0x07, 0x17, 0x02]

for i in range(0, len(flag), 3):
    print(map[(flag[i+2], flag[i+1], flag[i])], end='')
```
Run it and we can get the flag! `LINECTF{watcha_kn0w_ab0ut_r0ll1ng_d0wn_1n_th3_d33p}`
<br><br>

## Thoughts

This is not a particularly hard reversing challenge, but it sheds light on the interesting relationship between Android and Linux, and shows how Linux techniques can be translated into reversing Android apps. Even though I've been jesting on how it is still an ELF challenge after all, it is still a nice breath of fresh air, and I very much enjoyed going through the Android specific niches.

I ended up solving it right when the competition ended due to USB connection issues, and unfortunately it seems to not have counted on the official scoreboard even though the logger on discord congratulated us:

<img src="/assets/images/linectf2022/rolling/sadge.png" alt="sadge.png" style="display:block;margin:auto"/>

Lesson learnt: leave more time than you think you might need to solve challenges!

