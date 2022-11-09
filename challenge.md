--- 
layout: default
title: 1337 Challenges | CTF @ UBC 
---

# Maple Bacon 1337 Challenges
---

All flags will begin with the prefix `maple{`. You can find last year's challenges [here](challenge-2021.md).

**Note**: Some challenges will require you to connect to a remote server. Netcat (abbreviated as `nc`) is a simple tool installable on Mac/Linux that makes this easy: connect to a server with `nc <ip> <port>`. If you're using Windows, we highly recommend installing [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) - feel free to ask for help if you're having trouble setting anything up.

These 1337 challenges are designed to be **approachable by beginners** - our goal is to make them slightly challenging, exposing you to new CTF concepts without requiring advanced technical knowledge. Challenges with some harder concepts have additional resources or guides associated with them that explain prerequisite knowledge you may need. **Remember**: if you get stuck, join us in the #1337-challenges channel on our [Discord](https://discord.gg/keeTZsmfVA) to receive hints and share ideas with others!

Good luck!

# Miscellaneous - The Return of 110

Author: [Arctic](/authors/rctcwyvrn/)

Hey you. You're finally awake. You were trying to cross into second year, right? Walked right into that ambush, same as us, and that cpen student over there. Damn you Gregor. CPSC 110 was imperative until you came along. Programming was nice and easy.

Part 1 will put you in a jail with no restrictions to let you get used to the basics. Connect with `nc 1337.maplebacon.org 4000`.

Part 2 will put you in a jail with quite a few restrictions that you'll have to work around. Connect with `nc 1337.maplebacon.org 4001`.

**Submit the part 1 and part 2 flags together!** For example - if you get `maple{ab` for Part 1 and `cdef}` for Part 2, submit `maple{abcdef}` as one flag.

### Files:
- Part 1: [jail1.rkt](/assets/1337-2022/misc/jail1.rkt)
- Part 2: [jail2.rkt](/assets/1337-2022/misc/jail2.rkt)


See [our guide](/2022/11/jail-challenges-guide/) on what "jail challenges" are in CTFs!



# Reversing - Rando

Author: [Desp](/authors/desp/)

This guy keeps taunting me for not being able to guess his flag :( Surely there's a better way to this, right?

### Files:
- [rando](/assets/1337-2022/rev/rando)

### Resources
- You likely would want to use a disassembler like [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for your journey.
- What is a disassembler you might ask? Check out a high level overview of what it does [here](/2022/11/reversing-guide/)!
- To understand how a program works, it would be beneficial to understand how our machines themselves work - for a quick primer, here's a great [blog post](https://0x41.cf/reversing/2021/07/21/reversing-x86-and-c-code-for-beginners.html) by `0x41.cf` that touches on most of the low-level concepts involved!


# Web - Cat Clickr

Author: [JJ](/authors/apropos/)

hey everybody!! imade my first website and its AWESOME!!!

if u dig  closely u might even find some secrets...

check it out here: `1337.maplebacon.org`

### Files:
- [app.py](/assets/1337-2022/web/app.py)


# Pwn - X86 Playground

Author: [Desp](/authors/desp/)

Let's see how creative you can be in coming up with shellcodes!

Connect with `nc 1337.maplebacon.org 1337` and provide the payload you designed.

### Files:
- [playground](/assets/1337-2022/pwn/playground)


### Resources
- Binary exploitation (or pwn) has quite a bit of similarity with reversing - you might find the resources in the reversing challenge useful too.
- Here are also some quick tools for prototyping shellcodes:
  - https://godbolt.org/ for exploring how a function translates into assembly
  - https://defuse.ca/online-x86-assembler.htm for handwriting assembly into machine code
- Don't be intimidated! The intended solution is very short and utilizes one specific aspect of low-level computing. You can ignore everything in the `handlefaults` function - they are only here to help the challenge run more smoothly.


# Cryptography - The Matrix Exchange

Author: [vEvergarden](/authors/vEvergarden/)

Alice and Bob are having a great time exchanging their little secret messages... until they realize they're living in a simulation.

Check out [our guide](/2022/11/diffie-hellman-guide/) for an introduction to Diffie-Hellman Key Exchange and a story of Alice and Bob's adventures!

### Files:
- [main.py](/assets/1337-2022/crypto/main.py)
- [output.txt](/assets/1337-2022/crypto/output.txt)

### Resources
- A [great video](https://www.youtube.com/watch?v=NmM9HA2MQGI) from Computerphile that illustrates the Diffie-Hellman key exchange
- A more [mathematical approach](https://www.youtube.com/watch?v=Yjrfm_oRO0w), the second part of the series by Computerphile


