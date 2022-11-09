---
layout: post
title: "1337 Misc Guide - Jail Challenges"
author: rctcwyvrn
hide: "true"
---

### Jail challenges in CTFs

Jail challenges are a kind of `misc` category challenge in CTFs where the server lets you run arbitrary code, but subject to certain restrictions. For example python jails might not let you import anything or limit you to a very limited character set.

Typically in jail challenges the goal is to spawn a shell, ie to convince the jail to let you execute something like `bash` or `sh`.

For example a python jail might call `exec` on your input, which would normally restrict you to just running python code. But by running `exec("import os; os.system('bash')")` you could escape into the shell and be completely free to do whatever you want, like find and read the flag file.

- [https://docs.python.org/3/library/functions.html#exec](https://docs.python.org/3/library/functions.html#exec )
- [https://docs.python.org/3/library/os.html#os.system](https://docs.python.org/3/library/os.html#os.system)

In this challenge you'll be in a racket jail and you'll have to convince the jail to allow you execute the racket equivalent of `os.system("bash")`. In the first part there will be no restrictions so you can run whatever you'd like, however for the second part the jail will strictly restrict what code you're allowed to execute so you'll have to be more clever to spawn a shell.

Good luck!