---
layout: post
title: "1337 Misc Guide - Jail Challenges"
author: rctcwyvrn
hide: "true"
---

### Jail challenges in CTFs

Jail challenges are a kind of `misc` category challenge in CTFs where the server lets you run arbitrary code, but subject to certain restrictions. For example python jails might not let you import anything or limit you to a very limited character set.

Typically in jail challenges the goal is to spawn a shell, ie to convince the jail to let you execute something like `bash` or `sh`.

For example a python jail might call `exec` on your input, but doing `exec("import os; os.system('bash')")` would let you escape into the shell.
- https://docs.python.org/3/library/functions.html#exec 
- https://docs.python.org/3/library/os.html#os.system 

Now these examples are for python jails, in this challenge you'll be in a racket jail. Convincing the jail to allow you execute the racket equivalent like `os.system("bash")` will usually require some manipulation of your input in order to work around the blocklist or restrictions put in place by the jail, and it'll be a similar story in this challenge.


