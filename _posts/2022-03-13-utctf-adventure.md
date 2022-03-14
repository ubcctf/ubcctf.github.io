---
layout: post
title: "[UTCTF 2022] UTCTF Adventure ROM 4"
author: alueft
---

## Intro

This is the problem entitled "UTCTF Adventure ROM 4" from
[UTCTF 2022](https://ctftime.org/event/1582).

The problem description is as follows:

```
We went back in time to the late 80s and discovered this mysterious ROM. It
seems to be intended to run on a certain Nintendo portable console. I wonder
what lies beyond the goal?

Flag is in all caps.

By ggu (@ggu on discord)
```

A `game.gb` file is provided.

## Is this game on Steam

We can quickly verify that the provided file is a Gameboy ROM, so we need to...
obtain an extremely legal way of playing the game. For me on my Ubuntu machine,
this meant:

1. Running `sudo apt install visualboyadvance`.
1. Verifying my mailbox didn't have a Nintendo cease and desist notice in it.

Both steps had the desired result, so we can begin playing (after a bit of
Googling to find the controls). The game is a simple platformer, and eventually
we find ourselves here:

![wall](/assets/images/utctf2022/adventure/wall.png)

Touching the flag has no effect, and we can't get past this wall, which given
the problem description probably has something interesting on the other side.

## Still no cease and desist in the mail

Thankfully, someone else has done the work of writing a Gameboy ROM disassembler
for us:
[https://github.com/mattcurrie/mgbdis](https://github.com/mattcurrie/mgbdis)

Running this on our ROM outputs a few files, most of which aren't very useful
because they have nothing other than `rst $38` repeated a few thousand times.
There are functions that look interesting, and some of them presumably do things
we might be able to modify like implement gravity and collision detection.
However:

1. They're still assembly functions, which are inscrutable especially to someone
   who usually doesn't do binary challenges (me).
1. At the time, a few teams had solved this problem, which suggested that it
   couldn't be *that* difficult.

There was a section that stuck out, though:

```asm
    ld [hl], $00
    ld hl, $c32c
    ld [hl], $04
    ld hl, $c32d
    ld [hl], $01
    ld hl, $c32e
    ld [hl], $40
    ld hl, $c32f
    ld [hl], $05
    ld hl, $c330
    ld [hl], $00
    ld hl, $c331

    ; [...continues for a couple thousand lines...]
```

which loads a ton of bytes into a contiguous block of memory. This suspiciously
sounds like a mapping of the play area. Most of the written bytes were 0, so if
we make an educated guess that 0 = free space and 1 = wall, maybe we can delete
the wall next to the flag? Or read the flag from the map alone?

## Insert montage of trial-and-error Python scripting here

I ended up with this extremely legible and understandable script:

```py
# "code.txt" was generated from a Ghidra disassembly, which is similar to the
# above assembly snippet but with assignments to data variables
x = [bin(int(i.strip().split(" ")[-1][:-1],16))[2:] for i in open("code.txt").readlines()]

# convert each byte into 8-character strings and denote wall vs. empty space
y="".join(["0"*(8-len(i))+i for i in x]).replace("1","X").replace("0"," ")

# print in blocks of 40 (since the play area has a width of 20 blocks)
print("\n".join([y[24:][40*i:40*(i+1)][::-1][::1] for i in range(int(len(y)/40))]))
```

which ends up generating this (with the uninteresting bit snipped):

[something that looks like a map](/assets/images/utctf2022/adventure/map.png)

From top to bottom, we can figure out these are different levels in the game:

1. This looks a lot like "UTCTF 2022", which is good!
1. This looks like the win screen, but slightly obfuscated.
1. This looks like "UTFLAG{"...something...
1. This isn't very legible at all.
1. This also doesn't look like English characters.

(Also, it looks like there are *two* bits assigned to each cell, not just one -
probably because the flag cell is a third type that could be rendered.)

So we can't immediately read the flag out (and all screens are weirdly flipped),
meaning there's probably some additional deobfuscation in the game. But instead
of going through the effort of figuring all that out, what if we just cleared
the walls that block us from our destination?

## Skipping more mundane Python scripting...

There's probably a smarter way of doing this, but I ended up just writing `0xff`
at random places and regenerating the map until I figured out which map byte to
clear. The modified assembly is as follows:

```diff
6641c6641
<     ld [hl], $50
---
>     ld [hl], $00
6643c6643
<     ld [hl], $01
---
>     ld [hl], $00
6815c6815
<     ld [hl], $10
---
>     ld [hl], $00
6817c6817
<     ld [hl], $04
---
>     ld [hl], $00
6819c6819
<     ld [hl], $41
---
>     ld [hl], $00
6821c6821
<     ld [hl], $10
---
>     ld [hl], $00
6823c6823
<     ld [hl], $04
---
>     ld [hl], $00
```

Now we simply have to recreate the ROM, which required another GitHub repo
[here](https://github.com/gbdev/rgbds). While building the new ROM, I got a
warning saying `Overwrote a non-zero byte in the global checksum`, which a) made
sense since the assembly was directly modified, and b) thankfully was just a
warning, so no additional work to find and modify the checksum was required.

## UTCTF ROM 4 Any% Speedrun in 0:34

This took more tries than I'd care to admit.

<iframe
    width="100%"
    style="aspect-ratio: 5/4"
    src="/assets/videos/utctf2022/adventureflag.webm"
    frameborder="0"
    allowfullscreen>
</iframe>

