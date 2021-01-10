---
layout: post
title: "A companion to the Monsanto Cryptopals challenges"
author: rctcwyvrn
---

Preparations before we start
* This companion in general will not provide any direct solutions, I instead mostly give leading questions. If you need solutions, plenty of solutions and writeups are just a google away, though remember that looking at the answers at the back of the book leads to understanding less. Feel free to DM me on discord or in the `crypto` channel if you're stuck
* Almost all ctfers use python for solving challenges across basically all categories, so that’s what I would recommend
   * For python, all you’ll need is
      * A working python installation
      * [pycryptodome](https://pypi.org/project/pycryptodome/)
      * Something to write code with, `vscode` is nice
   * I’ll be assuming you’ll be writing in python for this guide
* Make sure you read the homepage, everything it says is true
   * You don’t need (and aren’t expected to) know any cryptography beforehand
      * They do unfortunately skip out on defining some terms, but that’s what this companion is for
   * You only need simple math 
      * The hard math is left to the professionals and we just copy their equations :)
      * No math shows up until set 5 anyway 
   * These challenges are attacks, not puzzles with tricks. The challenge authors make an effort to make the challenges clear and "doable", instead of obfuscated like you'd see in competitions. This companion guide also helps clear up the occasional ambiguity and confusing wording
   * I like to put an extra little disclaimer whenever I recommend someone take a look at cryptopals, which is that after solving these challenges most people feel a strong feeling of dread. Dread when they realize how fragile cryptography can be and how most people writing code that uses cryptography are **completely unaware** that these fragile points exist
* The general structure of the sets is
   * Set 1 is preparation and “the qualifier set” 
   * Sets 2-4 are various attacks on symmetric ciphers and a few hashes in set 4
   * Sets 5-6 are attacks on various asymmetric primitives, all using primes and numbers
* In case you’re wondering how well cryptopals will prepare you for CTFs, take a look at CSAW CTF 2020. Three challenges are basically directly taken from cryptopals and can be solved by copying over the code
   * Authy is a length extension sha attack, covered in challenge 29
   * modus operandi is a ciphertext detection challenge, covered in challenge 11
   * adversarial is a fixed nonce CTR, covered in challenges 6 and 20

Some quick definitions
---
**Encryption**
   * Encryption is turning a message (like “cryptography is cool”) and changing into a message that appears to be a garbled mess (like “falkjdior30vjs”) based on some “key”
   * The method of encrypting the message and what the key is vastly depends on the algorithm, for example in rsa the key is a number, in caesar ciphers the key is a table, and in aes the key is 16 bytes
   * **Plaintext** is used to refer to the message before encryption and **ciphertext** is used for the garbled message after encryption

Set 1
---
Intro
   * A lot of this set comes down to how comfortable you are writing code in python
   * There is a little hitch in that byte representations in python changed a lot between python2 and python3, meaning stackoverflow answers and such will be outdated and might not work, feel free to bug me on discord if you’re having trouble

Challenge 1: Some useful functions and notes about python bytes
   * `int(x, 16)` will parse the string x as a hex string, and return a number
   * The `Crypto.Util.number.long_to_bytes` and `Crypto.Util.number.bytes_to_long` functions from pycryptodome convert between numbers and bytes
   * Bytes in python are really just an array of ints between 0 and 255
      * `b”hi”` is really just `[104, 105]`
      * the `bytes()` constructor takes an int array and returns a bytes object
      * using a for loop or a list comprehension like `[x for x in my_bytes]` will return the int array
      * you can also index into bytes objects to get the integers, `b”hi”[0] == 104`
      * Remember that bytes are just numbers with base 255
   * `ord()` takes a single character and returns its integer value
   * `chr()` does the opposite, integer to char
   * the `base64` package has functions to go from bytes <-> base64 strings, namely `b64decode` and `b64encode`

Challenge 2: XOR in python
   * The xor operator in python is `^` and it takes two integers and returns the result of xor
   * A note about XOR in case you aren’t familiar: The operation cancels out with itself if you do it twice
      * Ie: `A xor B xor B == A`
      * If you aren’t sure why this is the case, try writing out the table for XOR
      * This is why “encryption” and “decryption” are actually the same action when using XOR, you end up doing the exact same thing
   * How do we use `^` with bytes objects? Remember that we can index into bytes objects to get the underlying integers, so try a for loop and then combining the results afterwards with `bytes()` back into a bytes object

Challenge 3
   * This general idea comes up sometimes in cryptography attacks, but the idea is that we know the original must have been some english sentence, so we can bruteforce and see which one is most like an english sentence
      * This idea also can be generalized to cases where we know some "structure" that the original message must be in and use that information to inform our bruteforce
   * Note: Do not be lazy and do it by eye, the “scoring” function will be needed in the next challenge
   * The `sorted()` function will probably come in handy
   * [https://en.wikipedia.org/wiki/Letter_frequency](https://en.wikipedia.org/wiki/Letter_frequency)

Challenge 4
   * Basically the same as challenge 3 but at a larger scale, same principle applies
   * We can assume that anything that isn’t encrypted with a single character XOR will result in a garbled mess when we perform an XOR on it

Challenge 5
   * Just coding, good luck!
   * The modulo operator `%` will probably come in handy here

Challenge 6
   * Hamming distance function tips
      * To format an integer as a binary string, use `“{0:b}”.format(x)`
      * Use in combination with `bytes_to_long` to convert the bytes to the bit string
      * If the lengths differ, the difference in length should be added to the distance
   * Solve tips
      * Try to reuse as much code from earlier challenges as possible
      * Transposing means taking `[[a,b,c], [1,2,3]]` and making it into `[[a,1], [b,2], [c,3]]`
   * An aside
      * I’ve actually used my code for this challenge quite a few times. You might be wondering what real world algorithm uses a repeating key xor and the answer is none, but many ciphers do actually use XORs. This challenge may seem like a toy challenge, but when we get to challenge 20 in set 3, you’ll see how this attack actually works **very well** on a popular block cipher mode.

Some definitions
* **AES** (Advanced Encryption Standard) is a **block cipher**, it takes a block of 16 bytes and garbles it based on a 16 byte key
   * However this presents a problem, what do you do if your message is longer than 16 bytes, for example a 32 byte message?
   * If you’re curious about what AES does under the hood (not needed for these challenges, but fun to learn about) https://www.youtube.com/watch?v=O4xNJsjtN6E
* **ECB** stands for Electronic Code Book, and is a **block cipher mode of operation**. Block cipher modes are ways of making block ciphers (which can only encrypt a single block) usable for larger messages
   * ECB is the most straightforward, cut the message into blocks and encrypt each of them separately.
   * This turns out to be a terrible way of doing things, and you’ll see why in the next few challenges
   * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
  
Challenge 7

   * pycryptodome provides an AES implementation in Crypto.Cipher.AES
      * https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
   * You should make both encryption and decryption functions, you’ll need it in a bit
  
Challenge 8
   * There is a hidden assumption in this challenge that I think really should have been mentioned. **The challenge assumes that the plaintext must have a repeated block**. 
   * The important point here is that ECB is the only cipher mode that has this property, that the same plaintext blocks will result in the same ciphertext blocks
      * This weakness of ECB turns out to cause many many problems, which you’ll see in set 2
      * The worst part is ECB is seen as the “default” setting for block ciphers, despite it being almost always a terrible idea


Set 2
---
Challenge 9
   * Fairly straightforward, just some more programming


Challenge 10: A new block cipher mode, CBC
   * **CBC** or Cipher block chaining is another block cipher mode
      * The goal of CBC is to not be deterministic like ECB, ie two identical plaintext blocks should encrypt to _different_ ciphertext blocks
      * How does it accomplish this?
         * CBC requires an extra **initialization vector** or IV for short, which is just random bytes the size of a block
         * For each plaintext block we want to xor our plaintext with something first, and then encrypt it with our cipher
            * For the first block we xor it with the IV before encrypting
            * For every other block we xor it with the _last ciphertext block_
         * Essentially “chaining” the different blocks together, so the resulting ciphertext of a block depends on the “sum” of all the previous blocks and the IV
      * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC) has some very useful diagrams
   * Implementing it is fairly straightforward once you understand whats going on
   * Decryption is just running this in reverse, block cipher decryption first and then xor
   * Note: ECB mode with one block is the same as just running the cipher, so you can reuse that as long as you’re encrypting/decrypting only one block
  
![CBCEncryption](/assets/images/cryptopals/cbc_encryption.png)
  
Challenge 11
   * This is a bit of a weird challenge, I’m not really sure what it’s accomplishing?
   * I don’t think there’s a good way to detect CBC mode, so I just detected ECB mode and then guessed CBC otherwise
   * Again, it only works if you send a plaintext with repeated blocks
   * Idk, maybe skip this one, it kinda comes back in challenge 12 but as an “optional” thing

Challenge 12
   * Now don’t skip this one though, because it’s really cool (and also shows up in real CTFs!)
   * The explanation is pretty good for how to get the first byte of the unknown-string, but the next step and automating it can be a bit tricky
      * For the next byte you would first send 14 A’s + the first byte of the unknown string
         * The first block would then be aes(“A”s + first byte + second byte)
      * Then you want to start sending 13 A’s + first byte + guesses for the second byte
      * And then like last time stop when you find a match
   * The congratulations at the bottom is pretty accurate for CTFs too, every once in awhile I see another one of these pop up
      * [Here’s the last one I remember](https://ctftime.org/writeup/18675)

Challenge 13: Cut and paste
   * This one is fun to figure out, it’s the first time the authors really let you out and try to figure out how to do what it wants
   * The title is a big hint, if we could copy paste things, what _would_ we want to cut and replace?
   * Given that this is ECB mode, what exactly can we cut and replace? (bits? bytes? characters? blocks? messages?)

Challenge 14
   * Some clarification on this challenge, I originally thought the random prefix would be generated each time, a new random prefix of random length each time you touch the oracle
   * I honestly don’t really know how one would go about solving that, so I and everyone else who has write ups for cryptopals instead assumed that the random prefix would be generated once and be reused for all later oracle calls
   * So now the trouble is really just one thing, how long is that random prefix? How can you figure that out?

Challenge 15
   * More programming stuff, this is just setup for challenge 17, which is gonna be a big one

Challenge 16
   * Another fun one to figure out
   * Try to think about what happens in CBC decryption with the user data block and the block after it
   * How can we completely replace the second ciphertext block in a way to make the third block decrypt to what we want, namely “;admin=true;”? What happens to the second plaintext block in that case?


Set 3
---
Intro
   * For me, this is the set where things really started to get fun
   * This note at the start made me really hyped and I hope it makes you excited too
      * “We've also reached a point in the crypto challenges where all the challenges, with one possible exception, are valuable in breaking real-world crypto.”

Challenge 17
   * This is a great challenge
      * CBC is (unfortunately) still a relatively popular block cipher mode, and is seen as "the good alternative" to ECB
      * This directly builds off of what you learned about CBC decryption in challenge 16, how bit flips in one ciphertext block affect the resulting decryption in the next block
      * This shows off how useful these side channel leaks are. A **side channel leak** is when a system unintentionally reveals information about it's inner workings
         * For this challenge, the "decryption server" is leaking the fact that the padding is invalid
         * For later challenges you'll see that even leaking how long the code takes to run can be enough to cryptography
         * Some other side channels you won't see in cryptopals: 
            * The amount of power the CPU is using can be used to retrieve AES keys from smart cards
            * Using information about the CPU cache to break OpenSSL's carefully implemented RSA algorithm https://web.eecs.umich.edu/~genkin/cachebleed/index.html
      * CBC padding oracles also show up from time to time in CTFs, though more rarely due to how famous this attack is
   * Here is a good explanation of the attack: https://robertheaton.com/2013/07/29/padding-oracle-attack/ 
   * From my experience this challenge is not necessarily conceptually difficult, but can be a bit tricky to get right
      * Start with just finding one byte, then work towards automating it for the rest of the bytes in the block, and then finally for multiple blocks
      * Made sure the padding functions from set 2 are fully correct
         * A plaintext that is all padding should be accepted
         * A plaintext with no padding should be rejected
   * Aside: Anyone else feeling that dread after realizing that all it takes to break a perfectly secure algorithm like AES and a reasonably sensible mode like CBC is something as small as having two different error messages for wrong password vs bad padding? Because I definitely was