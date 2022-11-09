---
layout: post
title: "1337 Reversing Guide - "
author: Kevin
hide: "true"
---


## What is reverse engineering?
In the context of software engineering, reverse engineering is the process of taking a program and finding out what it does. This is a difficult process because source code is not usually provided which means that the only thing you can work with is the machine code that the program is comprised of. Luckily, there are tools out there that can make your life a lot easier.

## How do I reverse engineer a program?
A program is comprised of machine code that in not legible by a human. This is why when you open an `.exe` file in a text editor it just looks like garbage. So the first step in reverse engineering is to turn this machine code into something a person can read. Usually, a disassembler is used to convert machine code into human readable assembly.

![disassembly.PNG](/assets/images/rev-guide/disassembly.PNG)
<center> <em>The result of disassembling a program using a disassembler.</em> </center></br>

However, it is still difficult to understand what is going on. Fortunately, we can do better than the disassembly. There are programs called decompilers that will try to decompile the program into C like source code.

![decompile.PNG](/assets/images/rev-guide/decompile.PNG)
<center> <em>The result of decompiling a program using a decompiler.</em> </center></br>

## Disassemblers vs. Decompilers

One may be asking why would they ever use a disassembler over a decompiler. The answer is that while decompilers generate output that is easier to understand the way it does this is through a heuristic. This means that sometimes that decompilers will output something that does not make any sense at all. On the other hand, disassemblers generate their output by directly translating machine code to assembly using documentation from the instruction set that the CPU must follow.  This is why its still important to be able to understand assembly.

## Static Analysis vs. Dynamic Analysis
There are two approaches to reverse engineering; static analysis and dynamic analysis.</br>
Static analysis is the practice of reverse engineering the program without ever running it. This involves figuring out what the machine code is trying to do using some of the tools that we have mentioned before.

Dynamic analysis is all about running the program to figure out what its doing. It involves attaching a debugger to the program when it is running and then examining the state of the during the execution of the program. The state of the program includes things such as register values and what is in memory at the time of execution.

There is no single best approach and one may be better than the other depending on the program that you are trying to analyze.

## Tools
Okay, now for the important part. What are these tools that I have been talking about all this time?

For static analysis, `Ghidra` is an open source disassembler/decompiler that is developed by the NSA. It is both a disassembler and decompiler. The best part is its open source and free!

For dynamic analysis, personally I use `gdb` plus an extension like `gef` that provides a couple more features.

