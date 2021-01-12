---
layout: default
title: Getting Started | CTF @ UBC
---

# Getting Started

This page is meant as a first steps introduction to get you into your CTF journey. There are many online resources related to CTFs and so this page aims to present an effective approach to improving your CTF skills, while also linking to good resources along the way.

The best way to learn is to solve challenges, get stuck, google things, make progress, get stuck again, ask questions, get flag, repeat. You will pick up knowledge, skills and tools along the way.

## What are CTFs?

Capture The Flag competitions or "CTFs" for short are competitions in which players attempt to solve computer security related problems in the form of challenges with present vulnerabilities in order to obtain a secret piece of text known as the "flag" and turn it in for points. Problems range widely in focus, from the theoretical aspects of computer science all the way to the applied aspects of system administration and software engineering. It's a great way to gain a wide breadth of knowledge in all things related to computer systems, while also achieving a sense of accomplishment and competition along the way.

## Prerequisites

Before you get started working on CTF problems, there's a minimum subset of tools you'll need. You'll need access to a UNIX system, such as Linux or MacOS. If you're using Windows and don't want to install a separate partition, you can use a virtual machine or the Windows Subsystem for Linux (WSL). Many of the most common tools you'll need to know how to use can be found in the [picoCTF learning guides](https://picoctf.org/resources). This will give you a base understanding for the largest topics in CTFs and some of the tools you need to have available.


## Binary Exploitation / Reverse Engineering

Most problems in CTFs involve developing a good understanding for the functionality of a target and then finding ways to break the target in unintended ways to get access to the flag. The best way to learn any category in a CTF is to complete more CTF problems, learning about more technologies and principles in the process. A good starting point for binary exploitation (also known as "pwn") and reverse engineering is to complete the starting problems in [picoGym](https://picoctf.org/index#picogym). Once you've developed some confidence working on these problems, check out [pwn.college](pwn.college) and [ionetgarage](http://io.netgarage.org/) for more intermediate-level content.

The above practice resources are mostly focused on Linux-based systems and x86 assembly. There are other resources that focus on other systems such as Windows or Android, but aside from the listed practice resources the next best way to get good is to participate in actual CTFs so you can experience the wide variety of problems CTFs have to offer. You can find some problems and writeups to learn from by also going to [CTFtime](https://ctftime.org/), which is the most popular site for keeping up with all things CTF.

There are several tools that get used a lot for Linux-based pwn/reversing challenges. You'll need to learn to use more tools as you encounter new CTF problems, so providing an exhaustive list wouldn't be of much aid. Some of the ones you'll definitely need are as follows:
- a debugger ([GDB](https://www.gnu.org/software/gdb/) + an extension like [gef](https://gef.readthedocs.io/en/master/)
- a disassembler/decompiler ([Ghidra](https://ghidra-sre.org/)
- [pwntools](http://docs.pwntools.com/en/stable/) for quickly writing exploit scripts

## Cryptography

1. Work through the Monsanto Cryptopals crypto challenges https://cryptopals.com/
   - I also have a work-in-progress companion guide, it currently covers up to set 3 [link](https://ubcctf.github.io/2021/01/cryptopals-companion/)
2. Dive straight into CTFs

Important note: Unlike the other CTF categories, I --do not-- recommend starting with picoCTF for learning cryptography
   - I find that the sort of “guided challenges with hints” that are in cryptopals are much better for beginners who lack confidence and might not be used to the “thrown into the deep end” style that most CTFs follow (pico does provide hints and such, but in the end it still is a competition)
   - picoCTF also lacks the “building up” aspect of cryptopals, which steadily works up to the major challenges like the CBC padding oracle
   - picoCTF also starts you off with a bunch of, to be blunt, boring toy challenges that have nothing to do with the cryptography you’ll see in CTFs
   - Working through pico after some cryptopals is a great idea (pico is very biased towards rsa challenges though)

Some other learning options, extra additions if they fit your learning style better:
- If you like watching lectures, [RPISEC’s lectures seem good](https://www.youtube.com/c/RPISEC_talks/videos)
- Reading a mathematics or cryptography textbook to learn more about the fundamentals
- Reading write-ups for past challenges on CTFtime or elsewhere helps get exposed to more types of problems

## Web Application Security

The web problems available on [picoCTF](https://picoctf.org/index#picogym) are a great way to get started on learning the basics of web security from the ground-up. However, you may notice two things after doing a number of picoCTF web problems: the pico challenges are pretty stacked towards classic/popular web exploits, and they will give a steady stream of hints to help you along. After going through them, it'll be helpful to try out web exploitation in an environment where hints are not as readily available, to intentionally train your recon skills without requiring a guiding hand. If you do get stuck, by all means ask for help or google the writeups, but going in totally blind is the most effective way to develop your auditing skills, granting you the acumen for identifying other exploits that you will see in other CTFs.

A big portion of web application security is auditing and recon - many web-based exploits are similar but different and the scope of web exploits is vast. Being able to correctly identify the key symptoms of a specific vulnerability helps in narrowing down what sorts of exploits you should be crafting, and so researching what kind of bug you're up against is half the battle. [Project Juice Shop](https://owasp.org/www-project-juice-shop/) is a recommended resource for sandboxing web exploits, and is a good way to strengthen your recon skills to find and identify vulnerabilities.
