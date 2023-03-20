---
layout: post
title: "[vikeCTF 2023] Dig Deep"
author: "Kevin"
---

# Challenge Description
During our travels, we encouter a cute viking gopher! She keeps the flag safe and sound in her burrow. She won't let you see it, but she'll tell you if your guesses are right or wrong. It may seem like she hasn't given you much to work with, but you'll have to dig deep if you want to recover what has been lost.

# Introduction

This challenge is a flag checker written in Go. This was my first time reverse engineering Go so my Googling skills were working overtime.

# Solution
## Overview
The first step is to recover all the function names. This can be done by running the following Ghidra [script](https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/go_func.py)

Once the function names are recovered we can poke around the binary in Ghidra. We see that `main.main()` looks something like this now:

![main](/assets/images/vikeCTF2023/main.PNG)

We can see that the binary will print something but we can't see what it is printing because the Go calling convention is non-standard. However, if we dig a little deeper (haha) we can see in the disassembly that something is loaded into a register right before the call to `runtime.printstring()`

![disassembly](/assets/images/vikeCTF2023/dissassembly.PNG)

Following these references shows that when `cVar1 == 0` it will print `Nope, that's not the flag. Try again!` or else it will print `Hmm, yep, that's the flag! Good job!`. Furthermore, we see that `cVar1` is set from the result of `runtime.memequal()` and some other check (we'll get to that later) The premise of the challenge is now clear. The program will take in your input, encrypt it and then check if the result of the encryption is equal to some precomputed buffer using `runtime.memequal()`.

## Encryption Function
Now lets take a look at how the encryption function works. Here's what it looks like in Ghidra (yikes that is ugly):

![encrypt](/assets/images/vikeCTF2023/encrypt.PNG)

But we can see that its using chacha20 as the encryption scheme. Trying to recover the key and nonce statically is too hard so its time to go to GDB.

If we set a breakpoint right at the call to the creation of the cipher object we should be able to see what the nonce and key are. However, as mentioned before Go uses a custom calling convention so I found [this](https://dr-knz.net/go-calling-convention-x86-64.html) page that describes how the Go calling convention works. Unfortunately, its a bit outdated as it mentions how Go passes arguments purely through the stack which is not the case as we will see in a bit.

If we go back to the disassembly we can see that the following registers are loaded right before the call: 
- RBX
- RCX
- RDI
- RSI
- R8
- R9

![args](/assets/images/vikeCTF2023/args.PNG)

Then if we go to GDB we can see the registers are in the following state right before the call to create the cipher object:

![gdb_args](/assets/images/vikeCTF2023/args_gdb.PNG)

From here two pieces of information is helpful: 
1. Go stores byte slices as a tuple of length, capacity and pointer to first element
2. Chacha20 uses a 32 byte key and a 12/24 byte nonce

By looking at the registers we can deduce the following:
- RCX is the length of the key slice since its 32
- RDI is likely the capacity of the key slice
- R8 is the length of the nonce slice since its 12
- R9 is likely the capacity of the nonce size
- RSI and RBX are likely the pointers to the key slice and nonce slice

At this point I wasn't sure which of RSI and RBX was the key so lets take a peek at what they're pointing at:

![key_nonce](/assets/images/vikeCTF2023/key_nonce.PNG)

From here we can see that RSI is pointing at something this probably only around 24 bytes long so this is most likely the key slice. Which means that RBX is most likely the nonce slice. Dump the memory of the locations using GDB and we have now recovered the key and nonce.

## Comparison Function
Now that we have recovered the nonce and key lets try to find the ciphertext that our encrypted input is being compared against. We can do that by inserting a breakpoint at `runtime.memequal()` and seeing what is in the register. So lets do that, run the program and we get the following:

![check](/assets/images/vikeCTF2023/check.PNG)

Huh why did the program just end and not break? It is most likely the if check that happens right before the call to `runtime.memequal()` so lets see what that if check is comparing by inserting a breakpoint at the `cmp RBX, RCX` instruction before the call and we get the following:

![length](/assets/images/vikeCTF2023/length.PNG)

The value of RBX is 4 which is exactly the length of our input. So the if check just checking that our input is 0x15 characters long. Therefore, as long as we give an input that is 0x15 characters long we can reach the `runtime.memequal()` breakpoint properly. Doing that we now get the state of the register to be the following right before `runtime.memequal()` is called:

![ciphertext](/assets/images/vikeCTF2023/ciphertext.PNG)

RAX and RBX were the only registers assigned right before the call to `runtime.memequal()` so it's most likely those are the pointers to what is being compared. The issue is which one is the expected ciphertext and which one is our encrypted input? This can be easily determined by just running the program again with a different input and seeing what changes. 

After doing that we see that RBX changed and RAX stayed the same.

![changed_ct](/assets/images/vikeCTF2023/changed_ct.PNG)

Now we just do the same thing we did with the nonce and key and just dump the expected ciphertext using GDB. Then we just run the following Python script:

```python
from Crypto.Cipher import ChaCha20

key = open("key.bin", "rb").read()
nonce = open("nonce.bin", "rb").read()

cipher = ChaCha20.new(key=key, nonce=nonce)
pt = cipher.encrypt(open("ciphertext.bin", "rb").read())
print(pt)
```

`vikeCTF{ilovegolang!}`

