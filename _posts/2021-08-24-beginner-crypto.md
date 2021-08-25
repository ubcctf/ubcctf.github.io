---
layout: post
title: "Maple Bacon Beginner crypto"
author: rctcwyvrn
hide: "true"
---

Modern cryptography has a few main categories,
1. Securing messages via encryption
2. Acquiring keys via key exchange
3. Ensuring the integrity of messages via signing and hashing

Normally beginner cryptography challenges involve simple alphabetic substituion ciphers, which are fine but also completely irrelevant in the modern day. I think that's a shame because there exist easy beginner challenges that are also _breaking real world cryptography_.

Why is that?

Modern cryptography is excellent and extremely secure, however it it has a major flaw.

**Cryptography is extremely brittle and easy to misuse.**

Algorithms can go from "it will take you til the heat death of the universe to crack" to "I can break this in 30 seconds with a 100 line python script" if you don't know what you're doing. This makes writing cryptography code extremely perilous, but it also makes for extremely fun CTF challenges!

Let's begin!

AES-CTR, modern encryption
---
What is AES-CTR? The name has two parts, the cipher (AES) and the mode (CTR).

AES is the [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) and it's the standard (haha) modern encryption primitive. You don't need to know how it works, just that it does one simple job. Given a 16 byte key and a 16 byte message it will secure that message and give you a 16 byte ciphertext. It has many strong security properties and it's passed the test of time (unlike many other ciphers).

CTR refers to the mode of operation. Most messages are not exactly 16 bytes long, and you want to be able to encrypt variable length messages. Different modes of operation give you ways to deal with variable length messages.

To explain CTR it's best to start with the one time pad. Did you know there exists a cipher that is **impossible** to crack? Not like it will take you a million years but that even given infinite time it is _impossible_ to break. It's called the [one time pad](https://en.wikipedia.org/wiki/One-time_pad) and it's incredibly simple. Just XOR your message with a stream of perfectly random bytes. 

Why it's perfectly secure is actually pretty simple is left as an exercise to the reader but it brings this powerful idea that XOR is actually a very secure way to encrypt your messages, and it's this idea that is crucial for how CTR mode works. There's also a big hint in it's name, one time pad, you can only use this stream of bytes _once_ if you want it to be secure. 

So now lets talk CTR.

What CTR mode does is it uses AES to create a stream of random bytes that you can then use to XOR against your message to encrypt it. How it does this is by asking AES to encrypt a series of numbers (ie 21, 22, 23, 24...) and this generates a bunch of random bytes which you can use for XOR. What number it starts from (21 in the example above) is determined by something called a nonce, and it's used because you can only use that stream of bytes _once_, after that you must choose a new nonce and get a new keystream.

AES-CTR isn't used on it's own very often, but it's older sibling [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode), which uses CTR mode for encryption, is used very often. It's a part of ethernet, wifi, TLS/HTTPS, SSH just to name a few.

I said that CTR is only secure if you use a new nonce every time, but why exactly does CTR fail if you don't pick a new nonce? What happens if you're a naive web developer and you just choose AES-GCM because that's what stackoverflow told you to use?

Let's find out!

The challenge: Repeated nonce CTR
---
Ok so what happens if you use the same nonce and key for multiple messages?

Well AES-CTR will encrypt the same counter with the same key, meaning each message will be encrypted with identical keystreams.

So if we have messages `m1`, `m2`, `m3`, and keystream `K`, the three ciphertexts will be 
- `c1 = m1 XOR K`
- `c2 = m2 XOR K`
- `c3 = m3 XOR K`

Well what's the problem? Well consider the first byte of the three ciphertexts.

The first byte of `c1` will be the first byte of `m1` xor'd with the first byte of `K`, and same for `c2` and `c3`. 

But we know two important pieces of information here
1. All the messages contain english text
2. There are only 256 possible values of the first byte of `K`

So what we can do is:
1. Guess the value of the first byte of `K`, call it `g`
2. XOR the first bytes of `c1` `c2` `c3` with `g` and see what we get
3. If we get english characters for all three, we can be pretty sure that `g` is right, otherwise we try another guess for `g`

You may have noticed that this isn't very consistent, there could be many possible `g` where all three are english characters, but imagine instead of only 3 ciphertexts we have 10, or 20, or 1000. The more we have the higher confidence we have that `g` is correct.

How do we score english characters? You have two options
1. Of the 256 possible byte values, the vast majority of them will ascii decode to garbage, so as long as it's a letter, number, punctuation, or whitespace you can give it a +1, and a -1 otherwise. Maybe with some extra tuning to say letter > whitespace > number > punctuation or something like that.
2. We know from analysis of writing that certain letters are more common in english writing than other letters, so we can score letters based on their frequency in the sentences. This is generally more accurate than method 1 but of course is more complicated.

(Note: I tested both, they should both work)

Now you try!
- [gen.py](/assets/challenges/beginner-crypto/gen.py) was used to encrypt `secret.txt` to generate [secret.enc](/assets/challenges/beginner-crypto/secret.enc)
- `secret.txt` contains the flag along with enough english text to make this attack feasible 

Hint: Beware of uppercase/lowercase!