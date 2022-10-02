---
layout: post
title: "[SekaiCTF 2022] Console Port Pro"
author: Robert Xiao
---

## Overview

Console Port is a two-part challenge based around solving an ASCII console port of [Keep Talking and Nobody Explodes](https://keeptalkinggame.com/).
In the game, your goal is to disarm a bomb in a set amount of time. The bomb has several modules which must be solved to win, such as cutting wires, pressing buttons
and entering codes, and an accompanying manual which describes exactly how to solve each module.

![ktane on a terminal, easy mode](/assets/images/sekaictf2022/ktane-easy.png)

In the first part, called Console Port (100 points, 291 solves), you get 3108 ticks running at approximately 10 ticks per second (so, around 5 minutes) to solve a bomb with five modules. With some experience,
it's possible to just solve this manually.

![ktane on a terminal, hard mode](/assets/images/sekaictf2022/ktane-pro.png)

In the second part, called Console Port Pro (498 points, 7 solves), you get 120 ticks, so around 12 seconds. This is not sufficient for human play, so we'll have to automate it. Or do we?

## Problem Description

### Console Port

- Solves: 291
- Score: 100
- Category: misc
- Difficulty: 1/5

> - Hey Miku, here’s [the manual](https://www.bombmanual.com/). Can you help me port the game to consoles?
> - Sure, no problem.
> 
> [ 1 week later... ]
> 
> - Hey Miku, how’s the porting going?
> - I just finished it today, wanna take a look?
> - Sure, which console did you port it to?
> - Huh...? What do you mean “which console”?
> 
> Author: pamLELcu

### Console Port Pro

- Solves: 7
- Score: 498
- Category: professional programming & coding
- Difficulty: 5/5

> - Hey Miku, since you’ve already done the porting, can you write an AI solving the game for me?
> - Well, it shouldn’t be hard. I’ll give it a try.
> - Cool. Here’s the game you need to solve. I made some changes so that you won’t cheat manually.
> - Hmm...
> 
> Author: pamLELcu

## Solution

We don't get source code. The game is written using some kind of text console framework (probably curses) which sends partial screen updates,
meaning we have to maintain a virtual console and do some janky parsing to learn what all the modules are and how to interact with them.
Plus, we have to implement all the horrible logic to solve the modules - which is hardcoding a ton of convoluted rules from the manual.

Or, we could cheat! Playing with the game a bit, I found that just clicking outside of the bomb area (e.g. in the top-left corner) caused
the game timer to pause - probably because it was coded to skip a game tick if an input was detected. So if we just *click the screen repeatedly*
we can freeze time and spend as long as we want defusing the bomb 😂

Since that's hard to do while also trying to solve the puzzle, I wrote a little wrapper script that clicks the screen for me whenever I'm
not interacting with the game:

```python
import socket
import sys
import time
import threading

def setup_tty(fd):
    import termios
    import atexit

    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
    termios.tcsetattr(fd, termios.TCSANOW, new)
    atexit.register(lambda: termios.tcsetattr(fd, termios.TCSANOW, old))

setup_tty(1)

s = socket.socket()
s.connect(("challs.ctf.sekai.team", 6001))

def recvuntil(suffix):
    buf = bytearray()
    while 1:
        ch = s.recv(1)
        sys.stdout.buffer.write(ch)
        sys.stdout.buffer.flush()
        buf += ch
        if buf.endswith(suffix):
            break

recvuntil(b"Press any key to start")
s.send(b"x")
recvuntil(b"Defuse the bomb with your mouse.")

has_update = False
def recv_thread():
    global has_update
    while 1:
        sys.stdout.buffer.write(s.recv(1))
        has_update = True
        sys.stdout.flush()

do_idle = True
def idle_clicker():
    while 1:
        if do_idle:
            s.send(b"\x1b[<0;11;4M\x1b[<0;11;4m")
        time.sleep(0.1)

threading.Thread(target=recv_thread, daemon=True).start()
threading.Thread(target=idle_clicker, daemon=True).start()

def read_input():
    ch = sys.stdin.buffer.read(1)
    if ch != b"\x1b":
        return ch

    buf = bytearray(ch)
    while 1:
        ch = sys.stdin.buffer.read(1)
        buf += ch
        if 0x40 <= ch[0] <= 0x7e and ch[0] != ord(b"["):
            break
    return buf

while 1:
    inp = read_input()
    if inp.startswith(b"\x1b[<"):
        if inp.endswith(b"M"):
            do_idle = False
            s.send(inp)
        elif inp.endswith(b"m"):
            has_update = False
            s.send(inp)
            while not has_update:
                time.sleep(0.01)
            do_idle = True
            s.send(b"\x1b[<0;11;4M\x1b[<0;11;4m")
        else:
            s.send(inp)
    else:
        s.send(inp)
```

This clicks somewhere in the top-left corner 10 times per second (matching the game's tick rate). With this wrapper,
we can take as long as we want in solving the bomb. I specifically restarted the game until there was no Button module,
as the Button module usually requires holding down the button until the time reaches a certain point, which might take
too long. It only takes a few tries to find a suitable game.

After solving the bomb by hand, we get a flag and first blood too!
Note that the displayed flag was slightly wrong (a space should be a `_`).

![ktane on a terminal, solved](/assets/images/sekaictf2022/ktane-solved.png)

```
SEKAI{ANSI?xterm?VT100?idk`\_(''/)_/`}
```
