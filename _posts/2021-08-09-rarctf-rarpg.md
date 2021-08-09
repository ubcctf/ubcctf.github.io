---
layout: post
title: "[RaRCTF] RaRPG"
author: Kevin Zhang
---

# TL:DR
Patch the binary to change horizontal position by two in order to get past the wall.

# Description

I've been building a brand new Massively(?) Multiplayer(?) Online Role-Playing(?) Game(?) - try it out! Just don't try and visit the secret dev room...

# Setup

We are given a terminal based video game client that connects to a game server. Once we connect to the game server we are presented with this.

![main_screen](/assets/images/rarctf2021/rarpg/level1_edit.jpg)

The `*` is the player and each `X` is a level transition. For example, when a player reaches an `X` the screen transitions to another level that might look like this.

![uwu_level](/assets/images/rarctf2021/rarpg/level2.PNG)

The objective here is to reach the `X` circled in red in the previous picture. However, this is not possible because it is walled off by the `W`'s.

The player can be controlled by the arrow keys. 

# Approach

In my initial apparoach I captured the traffic being sent to the server and tried to see if I could spoof the packets so it looked like I was inside the wall. However, the binary uses Protobuf which makes trying to analyze the packet structure a bit difficult.

When we decompile the client we see something quite interesting.

![decompile](/assets/images/rarctf2021/rarpg/decompile.PNG)

If we Google the function we can see that the if statements are checking for the arrow keys. This means that this block controls the player's position. At this point I was stuck for a while before realizing that if the client is the one that is updating the player position then that probably implies that the server trusts whatever position the client reports.

After this realization I patched the client so that everytime I pressed the right arrow key it would shift the player's position by two instead of one. This would allow me to jump past the wall and get the flag.

![flag](/assets/images/rarctf2021/rarpg/flag.PNG)

