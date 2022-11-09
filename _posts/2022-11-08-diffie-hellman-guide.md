---
layout: post
title: "1337 Crypto Guide - Diffie Hellman"
author: vEvergarden
hide: "true"
---

Let's begin by introducing our two favourite people - Alice and Bob.

![](https://i.imgur.com/46b0dOe.png)


Alice and Bob have a mutual enemy - Eve. 
![](https://i.imgur.com/HPTmmsh.png)


Eve is notorious for *eaves*dropping on other people's conversations and listening to all of their gossip. One day, Alice and Bob decide that they've had enough of Eve's eavesdropping. They want to communicate in public, but in a way such that only they themselves can understand each other.

One way they can accomplish this is by speaking a different language that Eve doesn't understand. Now, they can freely talk to each other in the open without worrying about Eve listening in on their conversations.

Similarly, **cryptographic ciphers** are another way Alice and Bob can securely communicate with each other. If they decide on a secret key on a slip of paper beforehand (similar to a password), they can **encrypt** all of their messages with that secret key. To Eve who doesn't know the secret key, all of Alice's and Bob's messages are just random garbage that she can't understand.

![](https://i.imgur.com/t5DAg1l.png)


Now, all is well - Alice and Bob have found a way to talk without Eve understanding what they're saying. 


### Details
[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) is the most widely used block cipher - it's used to encrypt/decrypt messages with a given secret key. The length of the key and message must be multiples of 16 bytes; for the message, we can simply add a few extra bytes at the end; for the key, we can apply the [SHA-256](https://www.n-able.com/blog/sha-256-encryption) hash function to produce a 32-byte hash.

The Python `pycryptodome` library offers a wide range of cryptography tools - try playing around with the code below!
```python
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256

# we use SHA256 to ensure that the key is the right length
key = sha256(b'my secret key').digest()
cipher = AES.new(key, AES.MODE_ECB)

# the length of your message has to be a multiple of 16, so we pad it with some extra bytes
message = pad(b'This is a secret message!', 16)
ciphertext = cipher.encrypt(message)
print("Encrypted message:", ciphertext)

# Decryption is very similar!
plaintext = cipher.decrypt(ciphertext)
print("Decrypted message:", plaintext)
```

## Part 2

Five years later, Alice and Bob have moved to different parts of the world. They can't talk to each other in-person anymore, but they would like to communicate digitally. Unfortunately, Bob has forgotten the original secret key that they decided on, and (even after 5 years) they're still worried about Eve spying on their conversations.

What's different is that this time there's **no easy way to decide on a secret key**. For example:
- If they mail a slip of paper with the key written on it, someone could intercept it midway
- If they send it through e-mail, someone hosting the mail server may see the secret key
- If they say what the key is over a call, someone could tap in on their conversation

![](https://i.imgur.com/pffi11V.png)

Think about this problem for a bit and see if you can come up with your own ideas. Is it possible to decide on something secret over a network where anyone can see what you send?

Yes! In fact, the **Diffie-Hellman Key Exchange** is one method for securely exchanging a secret key. Alice and Bob will each generate a "public" and "private" key - using those, they can then generate a shared secret that only they know. Even if Eve sees all of the communication between Alice and Bob, she can't figure out what their shared secret is.

### Details

The Diffie-Hellman Key Exchange revolves around some mathematical concepts - but don't be intimidated! 

The process begins with:
- Alice randomly picks an integer $a$
- Bob randomly picks an integer $b$

$a$ and $b$ are Alice's and Bob's personal "private keys". If anyone is able to guess or brute-force either of these private keys, they can recover the shared secret. Usually, $a$ and $b$ are on the order of $2^{1024}$, making it computationally infeasible to try out all possibilities.

Beforehand, Alice and Bob have publicly decided on the integers $g$ and $p$ - Eve will know these values.

Now:
- Alice calculates $g^a \mod p$ and sends it publicly to Bob 
- Bob calculates $g^b \mod p$ and sends it publicly to Alice 
- (Here, $g^x \mod p$ is the remainder when $g^x$ is divided by p)

![](https://i.imgur.com/jGHumNZ.png)



**The key idea is that: even if Eve knows $g$, $p$, and $g^a \mod p$, she won't be able to find the value of $a$**. Not even Bob will know the value of $a$ - only Alice knows $a$ because she was the one who chose it.

Similarly, neither Alice nor Eve know the value of $b$, even though they know $g$, $p$, and $g^b \mod p$

The problem of finding either $a$ or $b$ in these cases is known as the [**Discrete Logarithm Problem**](https://en.wikipedia.org/wiki/Discrete_logarithm). There are faster solutions than simply trying out all values of $a$, but they are still far too slow to find $a$ or $b$ in reasonable time.

Alice, now knowing the value of $g^b$, can compute $(g^b) ^a \equiv g^{ba} \mod p$

Bob, now knowing the value of $g^a$, can compute $(g^a) ^ b \equiv g ^ {ab} \mod p$.

![](https://i.imgur.com/OnAbfVE.png)


Since $g^{ab} \equiv g^{ba} \mod p$, **Alice and Bob have successfully decided on a secret value: $g^{ab} \mod p$!** Even though Eve knows the values:
- $g$
- $p$
- $g^a \mod p$
- $g^b \mod p$

there is no way for her to find $g^{ab} \mod p$ because the **Discrete Logarithm Problem** is computationally hard and will take a *very, very* long time to solve.

```python
from Crypto.Util.number import getPrime
from random import randint

p = getPrime(1024)        # generate a large modulus 
g = 2

alice_secret = randint(0, p)
alice_public = pow(g, alice_secret, p)        # g^a mod p

bob_secret = randint(0, p)
bob_public = pow(g, bob_secret, p)            # g^b mod p

# Alice calculates the shared secret: (g^b)^a == g^(ba) mod p
shared_secret_A = pow(bob_public, alice_secret, p)   

# Bob calculates the shared secret: (g^a)^b == g^(ab) mod p
shared_secret_B = pow(alice_public, bob_secret, p)

# They've successfully shared a secret that only they know!
assert shared_secret_A == shared_secret_B
```

Now, Alice and Bob can continue along their merry ways and use AES, with the shared secret as the AES key, to securely encrypt their messages (see Part 1 for details).

# Summary

We started off with Alice and Bob - they wanted to communicate securely because Eve was eavesdropping on their conversations. We accomplished this by making Alice and Bob decide on a secret, then using a cryptographic cipher like [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) to encrypt/decrypt their messages.

Then, we pondered how we could decide a shared secret if Eve could also eavesdrop on that process. Ultimately, the **Diffie-Hellman Key Exchange** came to the rescue - it relies on the Discrete Logarithm Problem being hard to solve. Even if Eve can see everything that Alice sends to Bob and everything that Bob sends to Alice, she still won't be able to calculate Alice and Bob's shared secret. From there, Alice and Bob can use a cipher like AES, as in the first part.

![](https://i.imgur.com/ZY1jz82.png)
