---
layout: default
title: 2026 1337 Challenges | CTF @ UBC
---

# Maple Bacon 1337 Challenges
---

All flags will begin with the prefix `maple{`. You can find last year's challenges [here](challenge-2024.md).

**Note**: Some challenges will require you to connect to a remote server. Netcat (abbreviated as `nc`) is a simple tool installable on Mac/Linux that makes this easy: connect to a server with `nc <ip> <port>`. Netcat is used mainly for remote, text-based connections. For example, entering the command `nc 1337.maplebacon.org 1337` in your terminal will let you interact with the first part of the Pwn challenge.

If you're using Windows, we highly recommend installing [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) - feel free to ask for help if you're having trouble setting anything up.

These 1337 challenges are designed to be **approachable by beginners** - our goal is to make them slightly challenging, exposing you to new CTF concepts without requiring advanced technical knowledge. Challenges with some harder concepts have additional resources or guides associated with them that explain prerequisite knowledge you may need. **Remember**: if you get stuck, join us in the `#1337-challenges` channel on our [Discord](https://discord.gg/keeTZsmfVA) to receive hints and share ideas with others!

Good luck!

---

# Misc - backrooms

**Author:** [Aden](/authors/adenc/)

I got lost in the UBC backrooms... can you help me find my way out?

You must find 3 pieces of information:
1. What building was this image taken in? Format as the name of the building (not including the word "building") in PascalCase.
2. What room is to the left of the camera? Write only the room number, exactly as printed on the sign.
3. What room is to the right of the camera? Write only the room number, exactly as printed on the sign.

The flag is in the following format: `maple{answer1_answer2_answer3}`

### Files

- [`backrooms.jpg`](/assets/1337-2026/misc/backrooms.jpg)

---

# Rev - SQL Heavy

**Author:** [Aditya](/authors/hiswui/)

Who said SQL cannot be a programming language?

You can chosoe to run the file with:
```sh
$ sqlite3 < chall.sql
```

This is flag checker challenge. The challenge does not contain the flag, but rather takes a flag as an "input" and tells you whether you have the right flag or not. This challenge does not have a remote server. 

### Files

- [`chall.sql`](/assets/1337-2026/rev/chall.sql)

---

# Pwn - syrup

**Author:** [Lyndon](/authors/lydxn/)

mmm... buffer overflows are tasty

Note: there are 4 parts to this challenge. solving each one will give you 1/4 of the flag.

Remotes:
- syrup0: `nc 1337.maplebacon.org 1337`
- syrup1: `nc 1337.maplebacon.org 1338`
- syrup2: `nc 1337.maplebacon.org 1339`
- syrup3: `nc 1337.maplebacon.org 1340`
- syrup4: `nc 1337.maplebacon.org 1341`


### Files

- [`syrup.zip`](/assets/1337-2026/pwn/syrup.zip)
- [`syrup4.zip`](/assets/1337-2026/pwn/syrup4.zip) (bonus challenge, same libc)

### Resources

- [Buffer overflow](https://ctf101.org/binary-exploitation/buffer-overflow/)
- [Return-Oriented Programming (ROP)](https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop)

---

# Forensics - maple signals

**Author:** [Yana](/authors/yana/)

Hey, I am sending you my new sample. I know you have been waiting for a long time.
It is not meant to be listened to like a normal track, but you’ll recognize what to do once you open it.
Everything you need is already inside the sound - nothing extra.
Handle it the same way we always do.

Let me know when you get the message ;)

**Details:**
- Genre: experimental
- Tempo: ~100 BPM
- Key: doesn’t really matter, u will see it

### Files

- [`maple-signals.wav`](/assets/1337-2026/forensics/maple-signals.wav)


# Web - pickle-adventure

**Author:** [Aden](/authors/adenc/)

Can you defeat King Pickle and save the world? Or will you take the throne for yourself?

Remote is hosted at [http://leet.maplebacon.org:3000/](http://leet.maplebacon.org:3000/). 

Download the code and run `docker compose up` to test locally first.

### Files

- [`pickle-adventure.zip`](/assets/1337-2026/web/pickle-adventure.zip)

### Resources

- [Webhook.site](https://webhook.site)


# Crypto - leaky-otp

**Author:** [Lyndon](/authors/lydxn/)

XOR encryption is all the craze these days, wonder why no one just uses addition...

Connect to remote using: `nc 1337.maplebacon.org 31337`.

### Files

- [`server.py`](/assets/1337-2026/crypto/server.py)