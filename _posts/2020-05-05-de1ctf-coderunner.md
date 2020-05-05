---
layout: post
title: "[De1CTF 2020] Coderunner (11 solves)"
author: Filip Kilibarda
---

CODE RUNNER
===========

Hilarious team effort to solve this in the last 6 minutes of the competition that involved Robert
grabbing random mips shellcode off the internet and this dialouge

>
    Robert: JUST RUN THIS
    Robert: NO PAD IT WITH LOTS OF ZEROS
    Me:     How many zeros?
    Robert: LOTS
    Me:     Like more than 256?
    Robert: NO NOT THAT MANY, *pastes padded shell code into slack*, RUN THIS
    Me:     Ok
    ...
    Me:     Holy crap it worked *crying*
    Robert: WHAT?

<image> of the final shot

This was an awesome problem in my opinion. For several reasons. Because it required:
    - serious considerations of network latency
    - serious considerations for how quickly your exploit program must run

When I first opened the problem, I was a bit confused by the proof of work, for some reason I
thought it would be way too slow to try and do it in python, so I wasted some time and thought I'd
try and get more familiar with `hashcat`. If hashcat had a setting for this kind of proof of work,
it would do it extremely fast (with the GPU acceleration), but as it turns out trying to do this
with `hashcat` is just overkill.

In the worst case Python 3.8 can do the proof work in about 12 seconds.

<%timeit image>

Once I finished messing around with the proof of work, it was time to look at the actual problem!

After submitting the proof of work (for each new connection), the server says "Binary dump" and
hands you a large base64 encoded blob of text.

<image>

And prints this title apparently showing a scoreboard, then prompts you with `Faster >`

# TODO use image instead here
```
===============
Rank(Refresh Every Min)
===============
1st. n132(1000)
2ed. (2549796)
3th. (2602650)
________         ____        __    _____
\______ \   ____/_   | _____/  |__/ ____\
 |    |  \_/ __ \|   |/ ___\   __\   __\
 |    `   \  ___/|   \  \___|  |  |  |
/_______  /\___  >___|\___  >__|  |__|
        \/     \/         \/
---------------Code Runner---------------

Faster >
```

And that's it, the server just waits for you to enter something. If you enter some random text, say
`AAAA`, the server just closes the connection.

It was pretty unclear just from that what I was supposed to do.

So next step was to take a look at that base64 blob they gave us and see what it was. 

`b64d(blob)` returns a Gzip file, `gzip.decompress(gzip_blob)`, and that returns an ELF 32-bit MIPS
program!

I put it in Ghidra

<image>

The `main` function in Ghidra is pretty straight foward,
    - call `gettimeofday`, save the result
    - disable libc IO buffering
    - call `unknown` function - get back to this later
    - if `unknown` function returns truthy value continue execution
    - else exit
    - if execution continued, call `gettimeofday` again and save the result
    - compare the old time to the new time
    - write your time to a scoreboard
    - if your time was fast enough, call `read` on stdin
    - finally call the buffer that the `read` was done on

So basically we know that we're being timed for how long it takes to execute `unknown` function and
we also need `unknown` function to return truthy value.

So the questions are
    - what does it take for `unknown` func to return truthy
    - how fast does it need to be, so that we get to execute arbitrary shellcode?

Next I dug into `unknown` function.

<image>

- allocated 256 bytes onto the stack
- call `read` stdin on the buffer
- call another function with the buffer

Following the function call, lead me to this

<image>

- do a bunch of checks on the first 4 bytes of the buffer
- if the checks pass, call another function with buffer + 4
- otherwise return 0

Now we can't have this function return 0, because parent function will then also return 0, which
will mean that the part that executes arbitrary shellcode from the user will never execute.  So we
need this to return non-zero.

If the check passes another function is called with the `param+4`, where param is the stack buffer.

<image>

And the pattern repeats, check 4 bytes and call another function, although the structure of the
checks is a bit different.

I followed these function calls about 16 levels deep until I finally got to this

<image>

which returns `0xc001babe`, a non-zero value!

So what we needed to do was send `16*4` bytes, such that they satisfy the tests in the 16 functions.

Ok so that's super easy, especially since the chunks of 4 bytes are independent of one another. We
could easily run this through Angr or construct our own z3 forumla to solve this.

But here's the catch, on each new connection to the server, you get a **different** binary, one
where the checks in the 16 functions are slightly different.

But still, that isn't necessarily that bad, because we have Angr in our toolbelt. With angr, we can
very easily programatically solve for the satisfying input for every new binary the server gives us.

So to recap what I knew at this point:
    - the binary calls `gettimeofday`
    - reads 64 bytes from the user
    - calls the function chain
    - if your 64 bytes satisfied the 16 functions
        - call `gettimeofday` to measure how long it took (including time to send/recv the packets)
        - if it was fast enough
            - read shellcode and call it
        - else crash

So really all that was left to fully understand what was required here was to determine how quickly
our program needs to run.

Reading Ghidra's decompiled output for the time calculations was pretty confusing to me and I didn't
feel like trying to understand it. I figured since I'd probably need to run the program at some
point anyway, I'd just run it and determine the time constraint emperically.

At this point I had saved a few of the binaries the server had given me, and was reusing the same
ones for testing (rather than connecting to the server each time and getting a new binary).

In order to get to the part of the program where the time calculations happen, I needed to have
a satisfying set of 64 bytes to feed it. Here I thought of a couple options:
    - run the program under Angr and have Angr tell me the solution
    - patch the binary to call `sleep` instead of executing the 16 functions
        - then I could mess with how long it sleeps for

Because I don't know much about mips, in particular syscall numbers, compilers, etc. and didn't feel
like spending any time figuring it out, I just used Angr, which I was already quite familiar with.

I deleted the original code so here this untested replica.

```python
p = angr.Project("./code.0")
myinput = BVS("myinput", 8*64)
state = p.factory.blank_state(addr=START_OF_16_FUNCS)
state.memory.store(addr=MYINPUT_ADDR, myinput)
state.regs.a0 = MYINPUT_ADDR
sm = p.factory.simulation_manager(state)
sm.use_technique(angr.exploration_techniques.DFS())
sm.explore(find=LAST_OF_16_FUNC, avoid=RETURN_0)
print(sm.found[0].solver.eval(myinput, cast_to=bytes))
```

That gave me the 64 bytes I needed to get to the second part of the program!

This is where I learned how much time I actually had and I was pretty shocked. I had started this
CTF a bit late, and started working on this question about 20 hours into the competition and at this
point the problem only had 4 solves, so I knew this was going to be really hard, but nevertheless, I
was shocked that it was even possible.

*Note, in order to run it I needed to get a functional qemu-mips setup for dynamically linked
binaries, [notes on that here](link)*

It turns out that you had roughly under 1.1 seconds.

To understand how crazy that is, we need look at it a bit deeper.

After the server receives your proof of work and verifies that it's correct, it `base64(gzip())`s
the binary, then writes the data to its TCP socket connected to you. Since `write` or `send` to a
socket is non-blocking (in the sense that it doesn't wait for a message recevied confirmation from
the receiver), the server immediately continues execution before you've even received the base64
binary. The server then presumably calls `execve` with the binary it sent you, hooking up its
stdin/stdout to the socket. Now the binary is executing --- it calls `gettimeofday`, then prompts you
for the 64 bytes. At this point you **haven't even received** the binary yet and the clock is
already ticking.

So how much of your precious 1.1 seconds are you losing just to network latency?

`ping` from my place in Vancouver, BC, Canada is about 390ms average and 250ms minimum.

So in **best case** it take 250ms to receive the binary, then takes another 250ms for the server
to receive my 64 bytes. So the best scenario is 500ms just for network communication. That leaves me
with 600ms for everything else.

Now that Angr script I mentioned above, that took somewhere between 10-20 seconds to compute the 64
byte solution. So the prospect of running in under 600ms is quite low.

I should mention... one of the thoughts that came to mind here was, well, where is the server?

I googled "ping test location" or something and it lead to some website that pings a target IP from
several locations around the world and gives you the time for each ping. Turned out that the server
was in Tokyo, so I spun up a AWS instance in the Tokyo region and found that I could get ping
replies in 60ms average with low variance. So that brings down the network latency issue to around
120ms, much better.

That means I had about 1 second to compute a 64 byte solution. # MINUS THE TIME IT TAKES FOR THE
BINARY ACTUALLY EXECUTE

Here's where I sat and thought for a while....

Angr clearly isn't going to work for us in the *usual* way that it's used. But maybe I could dig
down into some of the lower level components and figure out how to use only the bits that are
important for our problem? Maybe by stripping out extra bulk I could make it faster?

Angr is an amazing tool that does **alot**. It tracks memory, registers, executes code, builds
symbolic constraints, solves them, etc. Setting up the data structures for all these things and
executing the code take a while, and we really don't need most of it.

I decided that personally, I wasn't interested in digging deep into the inner workings of Angr to
figure this out, and in hindsight, I think it wouldn't have worked anyway and I would've wasted a
bunch of time. Maybe Shellpish has some different thoughts on that? They are the authors of Angr and
they were one of the teams that solved this challenge... so I'd be curious to hear what they did.

So I had to come up with some other way. This lead me back to analyzing the binaries I got from the
server.

I took a close look at the 16 functions, and noticed that some of them had exactly the same
structure, just some of the constants and comparison directions were changed. In fact, there were
only 5 different types of functions.

For example:

# TODO DISCUSS A COUPLE IMAGES

This is where it was helpful to speculate about how the server might have been generating these
binaries. I figured it was probably using some template C source code, substituting in random
constants (*random while still being satisfiable*), compiling it, then sending it over.

And this is where I realized that I could potentially write a super specialized little tiny version
of Angr just for this problem.

All I needed to do was extract the important constants, identify the function templates (of the 5
templates), then substitute the constants into a z3 expression for the corresponding function
template. Then get Z3 to solve the constraints.

So that was the plan. I got in touch with Robert to get some affirmation that this plan actually
made sense. He helped me break down some of the differences between the functions even further.  He
mentioned that he has solved some challenges like this with regex, although not under such time
constraints.

That brings up an interesting point, maybe we can disassemble the code, the simply just regex the
disassembly to extract all the useful bits. I ended up using regex for matching against individual
disassembled instruction, but maybe I could've regexed across entire functions? Maybe that would've
been simpler.

There's a common pattern in problems like this, where we're trying to implement as fast as possible,
with as few bugs along the way as possible, we don't really care about maintainability/readability
of the code, but can be helpful as it grows. We can always come up with a nice clean solution that's
well engineered and tested, but that takes time and in a competition we really just want it done as
fast as possible. The trick to implementing quickly in problems like this, I believe, really comes
down to how well you identify the common patterns and simplicities in the problem.

For example, we could spend a bunch of time writing code that can parse out all the functions from
the program and create nice `Function` objects, which some attributes, like number of instructions,
offset in the file, number of basic blocks, etc. This metadata would all be very useful, especially
if we were doing real software engineering and needed our components to be reusable elsewhere. But
this is not software engineering, this is racing (something that I'm not very good at). I actually
have to try really hard to deviate away from the over engineering.

To continue the example and relate back to the point of finding the simplicities in the problem: if
we really look at the binary and decompiled code, you'll notice that the 16 functions are always
adjacent in the file. 

You'll also notice that each function has a deterministic structure. It starts with a simple
function prelude that saves the return address, and ends with a `jr` return instruction. The return
instruction is always exactly right before the start of the next function's prelude in the binary
file. This may seem obvious, but compilers don't always put the return instructions at the latest
offset in the file. Sometimes the return is placed near the function prelude, then there's jump
statement away from it, then other sections of the funciton will jump back to an earlier offset in
the function.

Another note is that the functions are ordered in the binary file by the reverse order in which they
are called. This is also a hilariously helpful property that will make our binary parser so much
simpler.

So all we need to do is find the offset where the deepest function in the call chain is stored in
the binary, then consume instructions forward, stopping whenever we hit a `jr` return instruction to
record the end of a function, and so on. We just need to consume 16 functions worth of instrucitons,
and we've got every function, in order.

Now to identify the function templates. Once again, you can design some really nice solution that
identifies templates based on number of basic blocks, number of instructions, length of the basic
blocks, etc. or you can look for some super simple metric that will **work most** of the time.

I noticed that the function types had disjoint numbers of instructions. So that's it. All I had to
do was define a size range for each type of function, and match on that. Sometimes functions in the
same type would vary in size because of slight differences in how they were compiled. Even then the
sizes were still disjoint.

Once I had the function types, I then needed to parse out the constants. Each function type had the
same number of constants that needed to be extracted. So basically for each type I needed to specify
how many constants there were, then pass that to a general purpose function for extracting them.

For example, in this function, the indices into the buffer, and the constant values in the
comparisons, are what need to be extracted.

<image>

Robert pointed out that the compiler was really kind to us here and used completely predictable
instrucitons for loading bytes from the stack buffer and for loading constants into registers. The
order in which these operations happened was also always exactly the same for each binary. Basically
the compiler was being really kind to us; the problem authors most likely turned off all
optimizations.

So basically what I needed to do was: for each function, identify the type, for each instruction in
function, if instruction matched one of the patterns, extract the value, continue until end of
function.

Now I just needed to use the extracted values to solve for a satisfying solution. This is where z3
came in. There were only 5 types of functions, so I wrote 5 z3 reimplementations of each type of
function, that took on the values that we extracted from the binary as arguments.

Here's the z3 reimplementation of this type

<image>

```python
def or_func(params, *args):
    conds = []
    s = Solver()
    p = [BitVec(f"p{i}", 8) for i in range(4)]

    for _ in range(3):
        idxs, consts = next(params)
        conds.append( p[next(idxs)] + p[next(idxs)] == next(consts) )

    s.add(Not(Or(*conds)))
    s.check()
    m = s.model()
    return bytes([m.eval(pp).as_long() for pp in p])
```

I create 4 symbolic bytes, then just copy what the code does. I.e., add two bytes and compare to a
constant.

In the end I had about 600 lines of python to solve this part of the challenge and was huge pain to
debug. I definitely over-engineered some parts of it as usual, the code could've been a lot DRYer,
but writing DRY code often takes much longer and restricts the program's flexibility, so I'm not too
hard on myself for that.

One of the mistakes I made was not casting my z3 `BitVec`s up to 32 bits prior to doing
multiplication between them (as you can see in the decompiled output). 

<image>

So I was overflowing unknowingly and z3 was giving solutions that didn't work against the binary.

Here's where I fixed it:

<image>

I tested my solver locally using these two wonderful qemu commands

```
qemu-mipsel -strace ./code   # strace
qemu-mipsel -g 5000 ./code   # gdb
```

My solution ran in about 400ms (just to compute the solution, nothing else). This was much faster
than it needed to be, but with the network latency between Japan and Canada, it actually didn't work
*most* of the time when connecting to the server from my machine.

At this point there was only 1 hour left, I wanted to get a setup running on an AWS instance in
Japan so it could run more consistently, and I also needed some mips shellcode. I hit up Daniel and
Robert to help me get some shellcode running while I got the server set up.

A funny trick they put in the binary is that the faster your code runs, the more shellcode you get
to write.

1.3s you get 4 bytes of code, 1 mips instruction
1.0s : 16 bytes
0.8s : 24 bytes
0.6s : 32 bytes

I was rushing and wasn't really sure how fast it was going to run on the AWS instance in Japan while
Robert was developing the shellcode, so we didn't make any drastic assumptions about how much
shellcode we were going to get. Robert assumed at the very least, we would have 12 bytes, which was
definitely true given the run time I observered. So he designed some code that calls `read` to read
in even more shellcode :), then we would send many more bytes to complete it.

The trick here was that the binary calls `read` immediately before calling the buffer, 

<image>

this meant that the argument registers from the `read` call were left unchanged when calling your
shellcode, i.e., `a0` was still be zero (stdin) and `a1` was still the stack buffer. All we wanted
to change, was the number of bytes to read.

So basically the 12 byte shellcode just needed to set `a2 = 0xff` and set `v0` (the syscall
register) to `SYS_READ` and execute `syscall` :)

```
addi    a2, zero, 256
li      v0, 4003
syscall
```

Robert confirmed that the 12 byte `read` code definitely worked, and all we needed was some mips
code that called `execve("/bin/sh", NULL, NULL)`. He tried using pwntools `asm(shellcraft.sh())` and
it didn't work for some reason.

At this point there were 6 minutes left.

I had the AWS instance all set up, I had connected to the server, solved the constraints, sent the
64 bytes, sent the 12 byte read shellcode, and had called `IPython.embed()`, so I just had a Python
prompt infront of me and didn't actually know if the 12 byte `read` code worked and whether the
connection was still open.

<image> of just an ipython prompt

My next step was to give `asm(shellcraft.sh())` a shot myself, in case Robert forgot to set the
architecture `context.arch = "mips"`.

Meanwhile Robert was literally pulling random mips shellcode off the internet and sending it to me.

He pasted some space separated hex shellcode into Slack and said "RUN THIS".

I pasted it into my Python prompt and hoped that `bytes.fromhex` could handle space separated hex.

Here's what the final moments of this problem looked like on my screen.

<image>

And it worked, I don't think either Robert or I ever disassembled this code to see what it was,
anyway, it got us flag, so thanks random internet shellcode.

# Setting up qemu-mips

This meant I needed a working qemu-mips setup, something I had once
set up on another machine, but didn't have on my current VM.

To get a functional mips set up I had to install a few things, make some symlinks and the magic of
qemu and binfmt covered everything else.

I usually use [Zach Riggle's Stackexchange answer](link) (author of pwntools) for reference when
doing anything QEMU related.

Short summary:
    - install libc compiled for mips little endian `apt install libc6-mipsel-cross`
    - install qemu-mips
    - set up symlink for `binfmt` to find libc from mips programs `ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel`

And now we can run the program with just `./code`, we don't even need `qemu-mipsel` infront.


