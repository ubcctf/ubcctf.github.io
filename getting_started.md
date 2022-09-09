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

Before you get started working on CTF problems, there's a minimum subset of tools you'll need. You'll need access to a UNIX system, such as Linux or MacOS. If you're using Windows and don't want to install a separate partition, you can use a virtual machine or the Windows Subsystem for Linux (WSL). Many of the most common tools you'll need to know how to use can be found in the [picoCTF learning guides](https://picoctf.org/resources.html). This will give you a base understanding for the largest topics in CTFs and some of the tools you need to have available.


## Binary Exploitation / Reverse Engineering

Most problems in CTFs involve developing a good understanding for the functionality of a target and then finding ways to break the target in unintended ways to get access to the flag. The best way to learn any category in a CTF is to complete more CTF problems, learning about more technologies and principles in the process. A good starting point for binary exploitation (also known as "pwn") and reverse engineering is to complete the starting problems in [picoGym](https://picoctf.org/index.html#picogym). Once you've developed some confidence working on these problems, check out [pwn.college](https://pwn.college) and [ionetgarage](http://io.netgarage.org/) for more intermediate-level content.

The above practice resources are mostly focused on Linux-based systems and x86 assembly. There are other resources that focus on other systems such as Windows or Android, but aside from the listed practice resources the next best way to get good is to participate in actual CTFs so you can experience the wide variety of problems CTFs have to offer. You can find some problems and writeups to learn from by also going to [CTFtime](https://ctftime.org/), which is the most popular site for keeping up with all things CTF.

There are several tools that get used a lot for Linux-based pwn/reversing challenges. You'll need to learn to use more tools as you encounter new CTF problems, so providing an exhaustive list wouldn't be of much aid. Some of the ones you'll definitely need are as follows:
- a debugger ([GDB](https://www.gnu.org/software/gdb/) + an extension like [gef](https://hugsy.github.io/gef/))
- a disassembler/decompiler ([Ghidra](https://ghidra-sre.org/) or [IDA](https://hex-rays.com/ida-free/))
- [pwntools](http://docs.pwntools.com/en/stable/) for quickly writing exploit scripts

## Cryptography

Check out the Cryptographer's Codex over at [crypto.maplebacon.org](https://crypto.maplebacon.org/), which has a compiled set of challenges, guides, and resources for learning cryptography

TLDR
- Try out the beginner chals on the site to get a feel for what cryptography is like
- Do the [cryptopals](https://cryptopals.com/) challenges to get a solid foundation 
- Alternatively try out [cryptohack](https://cryptohack.org/) or [picoCTF](https://picoctf.org/) more challenges 
- Dive into CTFs for real!

## Web Application Security

Web exploits can be easy to get into, since many straightforward exploits don't require heavy tooling to work out. Consider these as a rough guideline of what to get into to get started into web.

- Knowledge in scripting languages (Python is our favourite)
- Foundational knowledge in Javascript, PHP and common web frameworks (nodeJS, Flask for Python, etc)
- Understanding of common web protocols, such as HTTP, IP and DNS.
- Having an understanding of RESTful APIs, and server-client interactions.

These are good lessons to develop if you're unsure of where to start for web exploits. Since 90% of the internet runs on Javascript, having an understanding of the syntax and conventions in that language will resolve much of the confusion when first starting out. It also goes without saying that knowing the key concepts of the internet from a developer's perspective also helps with web exploits.

It can be argued that web exploits are easy to get into but hard to overcome the learning curves as you gp. Like the other categories, web can build on itself so having a foundation for the basics is crucial - but you need to continue building up. When you move past relatively straightforward bugs like XSS, LFI and SQLi you can gradually move on to complex exploits which may branch out wildly from what you first started out with in this category, such as pop chains or XS-leaks. The best way to learn, realistically, is to try out any CTF and see for yourself what the web challenges may look like.

To get started into web hacking, consider the following resources:

1. [picoCTF](https://picoctf.org/index.html#picogym): The web problems available on picoCTF are a great way to get started on learning the basics of web security from the ground-up. However, you may notice two things after doing a number of picoCTF web problems: the pico challenges are pretty stacked towards classic/popular web exploits, and they will give a steady stream of hints to help you along. After going through them, it'll be helpful to try out web exploitation in an environment where hints are not as readily available, to intentionally train your recon skills without requiring a guiding hand.  If you do get stuck, by all means ask for help or google the writeups, but going in totally blind is the most effective way to develop your auditing skills, granting you the acumen for identifying other exploits that you will see in other CTFs.

2. [Project Juice Shop](https://owasp.org/www-project-juice-shop/): A big portion of web application security is auditing and recon - many web-based exploits are similar but different and the scope of web exploits is vast. Being able to correctly identify the key symptoms of a specific vulnerability helps in narrowing down what sorts of exploits you should be crafting, and so researching what kind of bug you're up against is half the battle. OWASP Juice Shop is a recommended resource for sandboxing web exploits, and is a good way to strengthen your recon skills to find and identify vulnerabilities.

Other learning options:
- [PortSwigger Web Academy](https://portswigger.net/web-security): Provides wiki-like knowledge and labs for all sorts of commonly seen web exploits. Although some labs require the use of Burpsuite Pro, the learning materials are still a good resource to learn new exploits.

- [HackTricks](https://book.hacktricks.xyz/): Consider this a "cheat sheet" that consolidates all manner of vulnerabilities and different edge cases to consider when looking at specific exploits. It's good to check in on this when you have an idea of a certain exploit in play, and would like to know more about it and how to properly take advantage of it.

