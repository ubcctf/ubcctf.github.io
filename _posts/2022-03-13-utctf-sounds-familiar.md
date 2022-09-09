---
layout: post
title: "[UTCTF 2022] Sounds Familiar"
author: alueft
---

## Problem description

This is the problem entitled "Sounds Familiar" from
[UTCTF 2022](https://ctftime.org/event/1582).

```
You have one new message. Main menu. To listen to your messages press 1.

By Aly (Prince_Ali#9152 on discord)
```

A .wav sound file is provided.

## Solution (amateur radio edition)

Note that Direwolf expects `#` as an end of string marker, so we need to
manually insert that tone ourselves.

<video width="100%" controls>
  <source src="/assets/videos/utctf2022/soundsfamiliar.webm" type="video/webm">
</video>

