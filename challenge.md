---
layout: default
title: 2024 1337 Challenges | CTF @ UBC
---

# Maple Bacon 1337 Challenges
---

All flags will begin with the prefix `maple{`. You can find last year's challenges [here](challenge-2021.md).

**Note**: Some challenges will require you to connect to a remote server. Netcat (abbreviated as `nc`) is a simple tool installable on Mac/Linux that makes this easy: connect to a server with `nc <ip> <port>`. Netcat is used mainly for remote, text-based connections. For example, entering the command `nc 1337.maplebacon.org 1337` in your terminal will let you interact with the first part of the Pwn challenge.

If you're using Windows, we highly recommend installing [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) - feel free to ask for help if you're having trouble setting anything up.

These 1337 challenges are designed to be **approachable by beginners** - our goal is to make them slightly challenging, exposing you to new CTF concepts without requiring advanced technical knowledge. Challenges with some harder concepts have additional resources or guides associated with them that explain prerequisite knowledge you may need. **Remember**: if you get stuck, join us in the `#1337-challenges` channel on our [Discord](https://discord.gg/keeTZsmfVA) to receive hints and share ideas with others!

Good luck!

---

# Misc - counterfeit

**Author:** [Lyndon](/authors/lydxn/)

I found someone trying to counterfeit the maple bacon logo! something looks off, though...

### Files

- [bacon.lol](/assets/1337-2024/misc/bacon.lol)

### Resources

- See [Stego Tricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks) for ways to hide information in data!

---

# Rev - What...?

**Author:** [Aditya Adiraju](/authors/hiswui/)

This is screwing with my head.

```
+[--------->++<]>+.++.--------.+++[++>---<]>.[------>+<]>-.+[->++++++<]>.[--->++<]>-.+++.--------------.-[->+++<]>-.+[--->+<]>+++.-----------.-[->++++<]>+.------------.-[->++++++<]>+.++++.--[----->+<]>.+++.--------------.-[->+++<]>-.-.+++++++++.---------.++..+.--.--[-->+++<]>--.+.[---->+++<]>..[-->+++++<]>.[----->++<]>-.---------.++[->+++<]>.+++++++++.+++.[-->+++++<]>+++.-[--->++<]>-.[--->+<]>---.-[--->++<]>-.+++++.-[->+++++<]>-.---[----->++<]>.+++[->+++<]>++.+++++++++++++.-------.--.--[->+++<]>-.----[->+++<]>.-------.+++++++++.++[++>---<]>.+[--->+<]>+++.---[->+++<]>..-[------>+<]>+.-[->++++++<]>+.-[-->+++<]>+..[->+++++<]>.++++++++...-----.++.-.++..++.-------.++.++++.+.-----..+.+.------.++.++.---..++++++++.---.+++.-----.+++++.--------.++++++.---.+++++..-.-.---.++.--.---.++++++.-------.+++++++.---.+++.------.-.>++++++++++.
```

(Note: wrap the reversed output in `maple{reversed_text_here}`)

---

# Pwn - STOP COPYING ME!

**Author:** [Aditya Adiraju](/authors/hiswui/)

My program is hiding a secret from me. However, whenever I ask it a question, it just repeats it back to me :(

Connect to remote using: `nc 1337.maplebacon.org 1337`.

### Files

[chal.c](/assets/1337-2024/pwn/chal.c)

### Resources

- [Format specifiers](https://alonza.com.br/format-specifiers-in-c/) are great but I wonder what happens when you misuse them?

---

# Web - baple macon

**Author:** [Ming C. Jiang](/authors/ming/)

my flag got chopped into three pieces and i forgot the password to my web server pls help me retrieve them thx [http://1337.maplebacon.org](http://1337.maplebacon.org)

### Files

[leet-web-dist.zip](/assets/1337-2024/web/leet-web-dist.zip)

### Resources

- [What is a JWT?](https://jwt.io/introduction)

# Crypto - MD5-CBC

**Author:** [Lyndon](/authors/lydxn/)

I just learned about MD5 and CBC today! I wonder what happens when you try and combine
them. Someone told me my padding method is a little suspicious...

### Files

- [encrypt.py](/assets/1337-2024/crypto/encrypt.py)
- [output.txt](/assets/1337-2024/crypto/output.txt)

### Resources

- MD5 is a common hash algorithm used in cryptography, see [here](https://www.youtube.com/watch?v=b4b8ktEV4Bg) and [here](https://en.wikipedia.org/wiki/MD5) for more information
- [Wikipedia article](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)) on CBC (cipher block chaining)
