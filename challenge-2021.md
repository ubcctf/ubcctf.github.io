---
layout: default
title: 2021 1337 Challenges | CTF @ UBC
---

# Maple Bacon 1337 Challenges
---

**Thanks for trying out this year's 1337 challenges! Although the 1337 role is no longer obtainable, you can find all challenge files and resources below.**

**NOTE**: All flags will begin with either the prefix `maple{` or `flag{`.

**NOTE**: These are **practice** challenges and are **not part of MapleCTF**!
However, they are good practice for challenges you might see during the competition.

## Reversing

x86 binary

```
8b64240844464c614731db4331fd6681ff676c751d31fe81fd541840
1a7513c1ef106681ff6167750981fe1c1f165475014b31c040cd8090
```

## Pwn

- [baby_pwn (executable)](/assets/1337-2021/pwn/baby_pwn)
- [baby_pwn.c (source)](/assets/1337-2021/pwn/baby_pwn.c)

## Crypto

Stack Exchange says everyone uses AES-GCM, but I don't need the tag so I'll just use CTR.

- [gen.py](/assets/1337-2021/crypto/gen_no_comments.py)
- [secret.enc](/assets/1337-2021/crypto/secret.enc)

For complete newcomers, I would recommend giving this [companion guide](/2021/08/beginner-crypto/) a read.
It covers some background and gives you the gist of how this challenge is solved.

## Forensics

There's nothing here... or is there?
<!-- Hey, you're close! But there's nothing in the HTML comments either... maybe there are other comments you can find? -->

[//]: <> (Nice! flag{M@pl3Syrup} )
