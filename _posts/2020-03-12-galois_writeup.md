---
layout: post
title: "[UTCTF 2020] Galois (1072)"
author: rctcwyvrn
---
The full challenge writeup can be found [here](https://rctcwyvrn.github.io/posts/2020-03-12-galois_writeup.html).

## TL;DR 

- taking advantage of nonce repetition 
1. Collect pairs of ciphertexts and their tags encrypted under the same nonce
2. Generate h(x) for each pair and find the root(s)
3. Decide that the root that appeared the most times must be the correct value of H
4. Profit!