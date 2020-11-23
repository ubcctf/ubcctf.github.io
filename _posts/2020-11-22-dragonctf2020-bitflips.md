---
layout: post
title: "[DragonCTF 2020] Bit flip 1/2/3"
author: rctcwyvrn
---

# Bit Flip

Bit flip was a cryptography challenge with 3 parts, where each part slowly removed information or made the challenge more difficult.

Solution scripts can be found [here](https://github.com/rctcwyvrn/ctf_stuff/tree/master/dragonctf2020)
## Bit flip 1
```
Cryptography, 155
Difficulty: easy (84 solvers)

Flip bits and decrypt communication between Bob and Alice.
```

Here's what the challenge script does
1. Set `alice_seed` to be a random 16 bytes
2. Then in a while loop do the following
- Ask for a base64 string
- Use it to perform bitflips on `alice_seed`
- Use `alice_seed` to seed the Rng object in the diffie-hellman object
- Use the Rng to generate a 512 bit prime by tapping the Rng in a loop until a prime drops out, then print out the # of iterations it took
- Use the Rng to generate a 8 byte secret for Alice
- Use a random 16 bytes to seed a second diffie-hellman object for Bob, using the prime from the last part and again generating an 8 byte secret
- Perform the DH exchange, but only printing out `pow(5, bob.secret, alice.prime)`
- Slightly unusual, but let the shared key be `1336 ^ pow(5, bob.secret * alice.secret, alice.prime)`
- Use the shared key as an AES key and encrypt the flag, printing out the IV and encrypted flag

The RNG object
1. Takes a 16 byte seed
2. Generates 16 bytes (256 bits) of random data at a time by doing sha256(self.seed) and then incrementing the seed by 1

We see that we need to generate the shared value out of what we get, `bob_number = pow(5, bob.secret, alice.prime)`. So we need to compute `pow(bob_number, alice.secret, alice.prime)`. To do so we need to figure out what `alice_seed` was and calculate `alice.secret` and `alice.prime` ourselves

There's two key points to note:
1. The challenge leaks some important information, the number of iterations it takes for that seed to hit a prime. 
2. The challenge loop happens after alice_seed is decided, so we get as many tries as we need to figure out alice_seed

_(Note: because this is a ctf challenge and not a real hack, the authors were nice enough to actually print out the number of iterations. In the real world the attackers would have to measure the time it took for requests to return and make an educated guess at the number of iterations from the time taken)_

### Attempt #1
What numbers exactly are generated from Rng.getbits(512)?
- The first number is `sha(alice_seed) + sha(alice_seed + 1)`
- The next is `sha(alice_seed + 2) + sha(alice_seed + 3)`
- and so on until
- `sha(alice_seed + iter) + sha(alice_seed + iter + 1)` is prime, and then it prints out `iter`

What happens if we turn `alice_seed` into `alice_seed - 2`? 

Then when generating the prime the Rng will compute 
- `sha(alice_seed - 2) + sha(alice_seed - 1)`, then 
- `sha(alice_seed) + sha(alice_seed + 1)`
- and so on until it reaches `sha(alice_seed + iter) + sha(alice_seed + iter + 1)` like before

But this time it will print out that it took `iter + 1` iterations

What about if we make `alice_seed` into `alice_seed + 2`? Then the same idea, we see that it takes `iter - 1` iterations.

So from the # of iterations it takes, we can see if `alice_seed` went up or went down! The problem is that we can't exactly just shift `alice_seed` up or down, the only thing we can do is flip bits in `alice_seed`.

But what happens if we flip the 2nd bit? If `alice_seed` had a 1 in that position, then `flipped = alice_seed - 2` because we flip the 1 to a 0, otherwise `flipped = alice_seed + 2` because we flip the 0 to a 1. 

So we can
1. Flip the kth bit
2. See if the number of iterations taken went up or down by `2^(k-1)`
3. If it went down then the kth bit of the seed is 0, if it went up then the kth bit of the seed is 1!

(Note: You need to guess the 0th bit though, because flipping it will increment/decrement `alice_seed` by 1, and since prime gen increments the seed by even numbers, this throws everything off)

Perfect! Let's just run that and...
```
lily@DESKTOP-0475EF8:~/code/ctf/dragonctf2020/bit_flip_1$ python solve_2.py 
base iter: 939
Failed at i = 9
```

Aww... why does this method fail?

What happens when we flip the 9th bit? Well we flip `alice_seed` into `alice_seed +/- 512` and we expect the iterations taken to be `base_iter +/- 256`. Do you see the problem? As we shift `alice_seed` more and more, it becomes almost certain that it'll just hit a completely different prime than what we expected or that it'll jump over the base prime completely

For example if it took 100 iterations to find a prime for `alice_seed` without any flips, then `sha(alice_seed + 200) + sha(alice_seed + 200 + 1)` is prime. But what happens if we flip the 9th bit and make `flipped = alice_seed + 512`? Then we jump right over the original prime and we'll get something completely different.

So this method won't work for the entire seed, but it does work for the first 10 ish bits so we can hold onto that.

### Attempt #2

```
> Robert: @rctcwyvrn (crypto) idea: if you know the low k bits of the seed, can you distinguish 0111111...111 from 1000000...000
> that is, you flip the low k bits s.t. you get all ones and ignore the k+1'th bit. If it's a zero, then when the flipped number is incremented it should behave the same as flipping the low k+1 bits to 100000...000
> but if it's a one, you should get totally random behaviour (as 1111111...111 flips up to 0000000...000 and affects the next bit up from there)
> so that way you're only ever dealing with looking for +1 or being totally off
```

ooo, thanks Robert. So what exactly is he describing?

Let's say we know the low k bits of the seed. We can easily flip all but the last bit to 1, so then we get
```
flipped = ... ? 1 1 1 1 ... 1 1 0
```
where ? is the k+1th bit that we're trying to figure out

This flipped seed then eventually gets to a prime in `i1` iterations

The first iteration, is almost never a prime so we can ignore that case. In the next iteration it gets incremented by 2, giving two cases based on the true value of ?
```
if ? is 0
        = ... 1 0 0 0 0 ... 0 0 0
then we end up with the k+1th bit being flipped to 1 and everything below it being zero

if ? is 1
        = ..x 0 0 0 0 0 ... 0 0 0
then we flip the k+2th bit and everything below it being zero.
```

Now to determine which of the two cases occured, we need to send one of
```
        = ... 1 0 0 0 0 ... 0 0 0
or
        = ..x 0 0 0 0 0 ... 0 0 0
```

I chose the first case because it was simpler, simply flip the low k bits to 0 and flip the k+1th bit, and send this to get `i2`. 

So if ? is 0 then we know `i2 = i1 - 1`. Since it's very unlikely that the first seed we send will immediately yield a prime, we circumvent the problem from attempt #1, even for large k!

With that we can easily recover the entirety of `alice_seed`, then from there we just need to instantiate our own alice DH object, generate the prime and secret, compute the shared value, and we're golden!

`DrgnS{T1min9_4ttack_f0r_k3y_generation}`

(I was confused by the mention of timing attack in the flag, but really the leak of the # of iterations taken which allows for this attack is really just a simplified timing leak as mentioned earlier)

## Bit flip 2
```
Cryptography, 324
Difficulty: medium (19 solvers)

Flip bits and decrypt communication between Bob and Alice, 
but this time Bob is not so talkative.
```

Looking at the `task.py` file we see that only one thing has changed, the challenge no longer gives us `bob_number`

This is a problem, because now we have no way of computing the shared secret. To compute it like before we would need `bob.secret`, and to get that we would need to guess Bob's 16 byte seed. The good news is that our code for recovering `alice_seed` still works exactly the same

Guessing a 16 byte random value isn't the way to go, what else can we try?

We need to control what we can (`alice_seed, alice.prime, alice.secret`) to make Bob's secret completely irrelevant or easily guessable. I fell down the rabbit hole of trying to modify the prime Alice generates to be one that has small subgroups generated by 5, making `bob_number` easy to brute force, but once again, Robert had the right idea.

How can we make Bob's secret completely irrelevant? Well the shared value is `pow(5, bob.secret * alice.secret, alice.prime)` right? What happens if we set `alice.secret = 0`?

To do that we would need to manipulate `alice_seed` to something where `sha(alice_seed) + sha(alice_seed + 1)` is prime, and the upper 64 bits of `sha(alice_seed + 2)` is zero.

Now where can we find a bunch of values that sha256 into a number with a lot of leading zeroes?

```
> Robert: https://www.blockchain.com/btc/block/0000000000000000000f78eed8be49db9fec38fa846675ddd9ff404a4258ef68
> there's a lot of people calculating sha-256 hashes with lots of leading zeros
> and they're using double SHA-256 so the intermediate hash is exactly 32 bytes long
> we have, in fact, tens of thousands of SHA-256 hashes - with preimages - which have many leading zeros. statistically one of these leads to a prime
> (maybe even a safe prime)
```

Blockchain! For blockchain blocks, they're made difficult by requiring the blocks to have many leading zeroes, so the hundreds of thousands of hashes on the bitcoin blockchain all satisfy the last property, that the upper 64 bits are zero. So what we need to do is to just take all these bitcoin hashes, and see if `sha(hash - 2) + sha(hash - 1)` is a prime.

Once we find one that works, which took maybe 10 seconds
1. Recover `alice_seed` like in bit flip 1
2. Flip `alice_seed` to `hash - 2`
3. We now know that `pow(5, bob.secret * alice.secret, alice.prime) = 1`, so the shared key is `1337 ^ 1 = 1336`, so we know the AES key must be `1336`

`DrgnS{B1tc0in_p0w3r_crypt0_brut3}`

Note: This was such a clever challenge, combining the vulnerability of DH with bad secrets with a sha256 based RNG and the leading zeroes on bitcoin blocks. Hats off the challenge author(s) at Dragon Sector.

## Bit flip 3
```
Cryptography, 343
Difficulty: medium (16 solvers)

Flip bits and decrypt communication between Bob and Alice, 
but this time Bob is not so talkative and primes are stronger.
```

Now instead of just checking if we hit a prime, we check if it's a strong prime, namely
```
prime = self.rng.getbits(512)
strong_prime = 2*prime+1
check if (prime % 5 == 4) and is_prime(prime) and is_prime(strong_prime):
```

Does this break our solution from part 2? Actually not at all at first glance. All we need to do is to look in the blockchain again for hashes, this time for one where `sha(hash - 2) + sha(hash - 1)` is a strong prime.

This turned out to take forever, and we managed to exhaust the entire bitcoin blockchain before finding any. But eventually we found one on the bitcoin cash blockchain.

Now all we need to do is just plug in the new hash and run the exact same script as bit flip 2 right?

```
> Robert: it looks like bitflip 3 has a 30 minute timeout, and we hit it
> so we need to make that solver faster...
```

Crap...

The problem is that the requirements for the strong prime make the number of iterations required to hit one from the rng much much higher, from a few hundred to a few hundred thousand iterations. And this computation is done twice each time we request a bitflip, so we need to cut down that number somehow.

Our solution script runs two parts, the two attempts from bit flip 1.

Part 1 obtains 1 bit of the seed from 1 request to the server, but only works for the first 15 bits or so. It works better in bit flip 3 than in bit flip 1 because the strong prime requirement makes it less likely to hit something else, but it's still far from the 128 bits of the entire seed

Part 2 gets 1 bit per 2 requests. For the kth bit it sends flips to flip the seed into 
```
f11 = ... ? 1 1 1 1 ... 1 1 0

and

f12 = ... 1 0 0 0 0 ... 0 0 0
```

Now consider what we would send for the k+1th bit

In the case where the kth bit was 1, then we send

```
f21 = ..? 1 1 1 1 1 ... 1 1 0

and

f22 = ..1 0 0 0 0 0 ... 0 0 0
```

But look at f11 and f21, they're actually the same thing in the case where the kth bit is 1. So using that information we can save 25% of requests (half of the time we can save half of the requests), and that brings us just below the timeout! 

I'm pretty sure there's more cases like that to reduce the number of sends, but I let it run while I ate lunch and it got the flag so whatever, good enough!

`DrgnS{C0nst_A3S_K3y_1111111111111!}`