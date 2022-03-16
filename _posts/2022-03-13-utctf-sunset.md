---
layout: post
title: "[UTCTF 2022] Sunset"
author: zhed
---

# [UTCTF 2021] Sunset

## tl;dr

Break a [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) like scheme for generating a shared secret with a cryptosystem relating to some sort of
[discrete fourier transform (DFT)](https://en.wikipedia.org/wiki/Discrete_Fourier_transform).
The solution described here involves 
exploiting the **group properties of a cyclic array under convolution modulo a prime**.

## Description

cryptography/Sunset; 15 solves, 996 points

Challenge author: `oops`

```
subset sumset what did i do Wrap the value of key with utflag{} for the flag.
```

Files: `main.py` and `output.txt`

## Encryption scheme and goal of the problem

First let's look what's going on by looking at the code in `main.py`:

```python
N = 111
MOD = 10**9+7

...

A_sk = get_secret_key()
B_sk = get_secret_key()

A_pk = compute_public_key(A_sk)
B_pk = compute_public_key(B_sk)

print("Alice's public key:", A_pk)
print("Bob's public key:", B_pk)

remove_elements = random.sample(range(1,N), 20)

print("Remove: ", remove_elements)

for x in remove_elements:
    A_sk.remove(x)
    B_sk.remove(x)

A_shared = compute_arr(B_pk, A_sk)
B_shared = compute_arr(A_pk, B_sk)

assert(A_shared == B_shared)

key = hashlib.sha256(str(A_shared).encode('utf-8')).hexdigest()
print(key)
```

In summary the code does the following:

1. Generate secret key for Alice and Bob
2. Compute a public key from Alice and Bob's secret keys
3. Compute a public list `removed_elements` and remove from secret key
4. Compute a shared secret derived from one's secret key and the other's private key

Through some magic math voodoo, somehow calling the function 
`compute_arr` on the other person's public key and their own 
modified secret key, they end up with the same shared secret.
You can see the parallels of this with [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) 
which also compute a shared secret in the same way.

The provided code above prints the shared secret key between Alice and Bob. 
Inspecting the `output.txt` file we see:
```
Alice's public key: [337229599, 325950080, 542718415, 860180877, 323040995, 735779310, 864361739, 339968680, 3785502, 533120016, 467897389, 215111289, 669987332, 343447968, 613364155, 51939983, 765449638, 551522273, 206741830, 696620161, 429342149, 124186177, 279591669, 271013814, 267312863, 288321995, 348764133, 49562754, 432321364, 733407888, 336309352, 680320244, 258955444, 50477576, 936414592, 540997130, 244887424, 802248001, 190201074, 608424912, 230214096, 106258442, 396015541, 632533267, 826926560, 765609879, 938836920, 938836920, 765609879, 826926560, 632533267, 396015541, 106258442, 230214096, 608424912, 190201074, 802248001, 244887424, 540997130, 936414592, 50477576, 258955444, 680320244, 336309352, 733407888, 432321364, 49562754, 348764133, 288321995, 267312863, 271013814, 279591669, 124186177, 429342149, 696620161, 206741830, 551522273, 765449638, 51939983, 613364155, 343447968, 669987332, 215111289, 467897389, 533120016, 3785502, 339968680, 864361739, 735779310, 323040995, 860180877, 542718415, 325950080, 337229599, 243380866, 59055212, 837326354, 161482058, 581310056, 136700435, 58971689, 605319217, 379539507, 605319217, 58971689, 136700435, 581310056, 161482058, 837326354, 59055212, 243380866]
Bob's public key: [299803618, 455114136, 158280000, 635585934, 770371709, 383640342, 296136746, 167814744, 69244076, 541537643, 915075673, 662114959, 715449225, 683799468, 84778891, 896156816, 900734048, 198579752, 761121766, 717769786, 696556462, 127571411, 667366203, 170409968, 339590760, 825653373, 824582729, 15723318, 429669228, 984644620, 731130374, 784679266, 21817661, 158555711, 566121948, 42699221, 705127489, 434494456, 798843545, 597222370, 728101364, 552436778, 728101364, 597222370, 798843545, 434494456, 705127489, 42699221, 566121948, 158555711, 21817661, 784679266, 731130374, 984644620, 429669228, 15723318, 824582729, 825653373, 339590760, 170409968, 667366203, 127571411, 696556462, 717769786, 761121766, 198579752, 900734048, 896156816, 84778891, 683799468, 715449225, 662114959, 915075673, 541537643, 69244076, 167814744, 296136746, 383640342, 770371709, 635585934, 158280000, 455114136, 299803618, 22273348, 709433923, 414958344, 318725017, 13092806, 621372737, 546139744, 640412379, 142648001, 843445006, 404605625, 548571564, 663856325, 565838629, 565838629, 663856325, 548571564, 404605625, 843445006, 142648001, 640412379, 546139744, 621372737, 13092806, 318725017, 414958344, 709433923, 22273348]
Remove:  [88, 2, 49, 14, 20, 91, 56, 79, 44, 81, 57, 73, 65, 67, 46, 84, 66, 17, 31, 53]
```

Notably we have Alice and Bob's public key and the remove array,
but the key is not.
As suggested in the description of the challenge,
the goal of the challenge is to recover the key.

## The implementation of the cryptosystem 

Let's take a closer look at the functions used.
The first is the secret key which is generates a list of random numbers
between 1 and $N$ where each number has a random multiplicity between 1 and 10.
The list is then shuffled.
```python
def get_secret_key():
    key = []
    for i in range(1, N):
        x = random.randrange(1,10)
        key += [i] * x
    random.shuffle(key)
    return key
```

  The next function applies an **array** of size $N$ 
  and an arbitrary length **list** of numbers that take on values between $1$ and $N$.
  These **arrays** of size $N$ seem to be the objects of this cryptosystem.
  and these **lists** seem to be the keys. I will use these two terms to distinguish between
  the two.
For each number $a_i$ in the list of numbers,
it takes the array, and adds it modulo $MOD$ to a rotated version
of itself, where the rotation is by $a_i$ and modulo $N$.
This strongly smells of something involving a 
[discrete fourier transform (DFT)](https://en.wikipedia.org/wiki/Discrete_Fourier_transform),
as it involving rotations of an array.

```python
def compute_arr(arr, sk):
    for x in sk:
        new_arr = arr.copy()
        for y in range(N):
            new_arr[(x+y)%N] += arr[y]
            new_arr[(x+y)%N] %= MOD
        arr = new_arr
    return arr
```

The last function explains how the public key is generated.
The secret key is applied to what is essentially an identity element of sorts,
an array $[1,0, ...,0]$

```python
def compute_public_key(sk):
    arr = [0] * N
    arr[0] = 1
    return compute_arr(arr, sk)
```

## Investigating the cryptosystem

  The first thing to do is to play around with the cryptosystem to see what's going on.
  The most mysterious code is the `compute_arr` function, but its hard to understand
  what it does, so it serves to investigate how it is used. 
  The cyclic nature of things really smelled like something involving DFTS.
  I'm only familiar with DFTS from the
  [Fast Fourier Transform (FFT)](https://en.wikipedia.org/wiki/Fast_Fourier_transform), 
  which has numerous applications in computer science. That inspired this approach.

  The most suspicious thing is how the two generate a shared secret when they know nothing
  about each other's secret keys, except they know each other's public keys and removed
  the same elements from their own secret keys.
  In particular, the order is randomized, and the removed elements are the first ones.

  The easiest explanation is that the **order doesn't matter**, and whatever operation
  `compute_arr` does to an array is independent of whatever list that's passed in.

  We easily verify that this is indeed the case with some code:

```python
>>> A_pk = compute_public_key(A_sk)
>>> random.shuffle(A_sk)
>>> A2_pk = compute_public_key(A_sk)
>>> A_pk == A2_pk
True
```

This means that to compute their shared secret, they are essentially **concatenating their 
secret keys and removing the same number of elements.** 
So if we could recover their secret keys, we'd be done (I believe it should be possible to 
do so because of the connection to DFTS, but I haven't spent the time to think about
it yet)
Because I know this has something to do with DFTS, concatenation of the lists 
(or more precisely pointwise addition of the multiplicities of the elements) 
is something done in the *Fourier transform* space,
while the arrays live in the *primal* space.

I reasoned that there must be some sort of group operation on the arrays that 
would correspond to the concatenation of lists in the *Fourier transform* space.
Guessing from what I know about FFT, I figured it might be **convolution**, so 
I coded it and tried it out.

```python
def conv_arr(a1, a2):
    a3 = [0] * N
    for i in range(N):
        for j in range(N):
            a3[i] += a1[j] * a2[(i-j+N)%N]
            a3[i] %= MOD
    return a3

assert(compute_arr(compute_public_key(A_sk), B_sk) == conv_arr(compute_public_key(A_sk), compute_public_key(B_sk)))
```

   Lo and behold, it actually worked!
   Furthermore it seems that the array $I = [1,0,...,0]$
   is the **identity** element, as `conv_arr(I, arr) == arr`.
   This means that we have a **commutative group structure** in the *Fourier transform* space
   with the group operator being **convolution**.
   With this group structure, all we need to do is apply the group operator to `A_pk` and
   `B_pk` and apply the group operator to the **inverse** of `compute_public_key(remove_elements)`!

   Technically I haven't shown that this is a group yet, since its not clear that these inverses 
   exists.
   But things are working modulo a prime $MOD = 10^9+7$, so there's strong reason
   to believe that applying the group operation to a single element 
   enough times it will be cyclic.

   Now I have no idea how to compute the inverse,
   so I made it a goal to compute the inverse of `compute_public_key([3])` which I will denote by
   $\mathcal{T}([3])$.
   If we knew the **order** of the elements in the group,
   we could compute inverses. 
   To see why, let's denote the order by $m$ so 

$$\mathcal{T}([3])^m = \mathcal{T}([3]).$$

   Then $\mathcal{T}([3])^{m-2}$ would be an inverse.
   Since operations are done modulo $MOD$, it stands to reason that $MOD$ would be a good guess of 
   an order of an element. 
   To verify this guess I would need to take a lot of convolutions (which would be too slow), but 
   we can use a 
   [fast exponentiation technique](https://en.wikipedia.org/wiki/Exponentiation_by_squaring)
   to do so with only $O(\log MOD)$ convolutions.
```python
def compute_pow(sk, t):
    arr = [0] * N
    arr[0] = 1
    ans = arr.copy()
    arr = compute_arr(arr, sk)
    while t:
        if t&1:
            ans = conv_arr(ans, arr)
        arr = conv_arr(arr, arr)
        t >>= 1 
    return ans
```

  Unfortunately it turned out that $MOD$ was not the order. 

```python
>>> compute_public_key([3])
[1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
>>> compute_pow([3], MOD)
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
>>> compute_public_key([3]) == compute_pow([3], MOD)
False
```
However, $\mathcal{T}([3])$ looked a lot like $\mathcal{T}([24])$.
```python
>>> compute_public_key([24]) == compute_pow([3], MOD)
True
```
This leads me to conjecture that

$$\mathcal{T}([k])^{MOD} = \mathcal{T}([8k]).$$ 

I do some testing and this statement seems to be true.
Next I observe that as the array is cyclic mod $N = 111$ so for some value $h$,

$$\mathcal{T}([k])^{MOD^h} = \mathcal{T}([(8hk\;\text{mod}\;111)]).$$ 

Choosing $h = \phi(N) = 72$ we should get what we want!

$$\mathcal{T}([k])^{MOD^{72}} = \mathcal{T}([k]).$$ 

It takes a few seconds to run and verify this, but it works!
```python
>>>  compute_pow([3], MOD**72) == compute_public_key([3])
True
```
This means we can find inverses now!

```python
def inverse_arr(arr, sk):
    ans = conv_arr(arr, compute_pow(sk, MOD**72-2))
    return ans
```
Now , we've computed the order of elements of the group, we finish it off in one 
beautiful line of computation:

```python
shared = inverse_arr(conv_arr(A_pk, B_pk), removed_elements)
```

It takes 6 seconds on my beefy machine, 
but that's to be expected when we have to do $O(\phi(N)\cdot \log MOD)$ convolutions
of a length $N$ array in python.

## The mathematics behind it

Why does this work? Well mostly because of the 
[shift theorem and circular convolution theorem](https://en.wikipedia.org/wiki/Discrete_Fourier_transform#Shift_theorem), `compute_arr` adds to the array 
a phase shifted copy of itself. 
On top of this convolution naturally forms a group operation, 
   so it magically lends itself to this group structure.
I didn't really think too hard about why these things work, and mostly just made good guesses.
I'll work out the math some other day (including as to whether directly recovering the private keys is possible)

## Solve script

This is was the final script:
```python
import hashlib

N = 111
MOD = 10**9+7

A_pk =  [337229599, 325950080, 542718415, 860180877, 323040995, 735779310, 864361739, 339968680, 3785502, 533120016, 467897389, 215111289, 669987332, 343447968, 613364155, 51939983, 765449638, 551522273, 206741830, 696620161, 429342149, 124186177, 279591669, 271013814, 267312863, 288321995, 348764133, 49562754, 432321364, 733407888, 336309352, 680320244, 258955444, 50477576, 936414592, 540997130, 244887424, 802248001, 190201074, 608424912, 230214096, 106258442, 396015541, 632533267, 826926560, 765609879, 938836920, 938836920, 765609879, 826926560, 632533267, 396015541, 106258442, 230214096, 608424912, 190201074, 802248001, 244887424, 540997130, 936414592, 50477576, 258955444, 680320244, 336309352, 733407888, 432321364, 49562754, 348764133, 288321995, 267312863, 271013814, 279591669, 124186177, 429342149, 696620161, 206741830, 551522273, 765449638, 51939983, 613364155, 343447968, 669987332, 215111289, 467897389, 533120016, 3785502, 339968680, 864361739, 735779310, 323040995, 860180877, 542718415, 325950080, 337229599, 243380866, 59055212, 837326354, 161482058, 581310056, 136700435, 58971689, 605319217, 379539507, 605319217, 58971689, 136700435, 581310056, 161482058, 837326354, 59055212, 243380866]
B_pk =  [299803618, 455114136, 158280000, 635585934, 770371709, 383640342, 296136746, 167814744, 69244076, 541537643, 915075673, 662114959, 715449225, 683799468, 84778891, 896156816, 900734048, 198579752, 761121766, 717769786, 696556462, 127571411, 667366203, 170409968, 339590760, 825653373, 824582729, 15723318, 429669228, 984644620, 731130374, 784679266, 21817661, 158555711, 566121948, 42699221, 705127489, 434494456, 798843545, 597222370, 728101364, 552436778, 728101364, 597222370, 798843545, 434494456, 705127489, 42699221, 566121948, 158555711, 21817661, 784679266, 731130374, 984644620, 429669228, 15723318, 824582729, 825653373, 339590760, 170409968, 667366203, 127571411, 696556462, 717769786, 761121766, 198579752, 900734048, 896156816, 84778891, 683799468, 715449225, 662114959, 915075673, 541537643, 69244076, 167814744, 296136746, 383640342, 770371709, 635585934, 158280000, 455114136, 299803618, 22273348, 709433923, 414958344, 318725017, 13092806, 621372737, 546139744, 640412379, 142648001, 843445006, 404605625, 548571564, 663856325, 565838629, 565838629, 663856325, 548571564, 404605625, 843445006, 142648001, 640412379, 546139744, 621372737, 13092806, 318725017, 414958344, 709433923, 22273348]
rem =  [88, 2, 49, 14, 20, 91, 56, 79, 44, 81, 57, 73, 65, 67, 46, 84, 66, 17, 31, 53]

# apply transform to convolution world 
def compute_arr(arr, sk):
    for x in sk:
        new_arr = arr.copy()
        for y in range(N):
            # take values in sk, and circularly add values of arr.
            new_arr[(x+y)%N] += arr[y]
            new_arr[(x+y)%N] %= MOD

        arr = new_arr
    return arr

# fast exponentiation
def compute_pow(sk, t):
    arr = [0] * N
    arr[0] = 1
    ans = arr.copy()
    arr = compute_arr(arr, sk)
    while t:
        if t&1:
            ans = conv_arr(ans, arr)
        arr = conv_arr(arr, arr)
        t >>= 1 
    return ans

# compute inverse of array
def inverse_arr(arr, sk):
    ans = conv_arr(arr, compute_pow(sk, MOD**72-2))
    return ans


# convolution is group operation 
def conv_arr(a1, a2):
    a3 = [0] * N
    for i in range(N):
        for j in range(N):
            a3[i] += a1[j] * a2[(i-j+N)%N]
            a3[i] %= MOD
    return a3

# the transform operation
def compute_public_key(sk):
    arr = [0] * N
    arr[0] = 1
    return compute_arr(arr, sk)

A_shared = inverse_arr(conv_arr(A_pk, B_pk), rem)
key = hashlib.sha256(str(A_shared).encode('utf-8')).hexdigest()
print(key)
```

Flag:
```
utflag{3f3ae3284970df318be8404747bb003fe47cd9bdbb57fc1da52a01b3c028180f}
```

