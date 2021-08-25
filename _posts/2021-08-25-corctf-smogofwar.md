---
layout: post
title: "[corCTF 2021] smogofwar"
author: David Zheng
---

# [corCTF 2021] smogofwar

## tl;dr

Beat a chess bot in "Smog of War" a variant of chess (almost?) identical to the
Fog of War variation of chess by sending two different moves to the server.

## Description

misc/smogofwar; strellic ; 7 solves / 497 points

Hey, I made a chess website to play my favorite variant, smog of war!
Why don't you check it out and play against my AI. He has some nasty surprises,
but if you beat him I'll give you a flag.. good luck :)

<https://smogofwar.be.ax>

You're also given a zip file named `smogofwar.zip` that presumably has the
contents of the website and the backend server that handles the chess game.

## Solving the Challenge

The website contains a variation of chess against a bot where you can only see
squares where either you have pieces, can move to, or capture.
Beating the bot would give you the flag.
As an added bonus, every time the bot captures your piece, it spits out a
random piece of trash talk in the chat.

![example](/assets/images/corctf2021/smogofwar/example.jpg)

Playing around with the bot, the bot seems really strong, but seemed to move
deterministically. I'm not good enough at chess for this, so I
enlisting the help of an amateur chess friend Henry I had on hand.
He tried to play the bot and realized it was not deterministic and seemed quite strong.

Looking at the source code for the bot, it turned out it was running one of the
best and newest chess bots: Stockfish 14.
```python
class Enemy:
    def __init__(self, fen, emit):
        self.internal_board = chess.Board(fen)
        self.emit = emit
        self.stockfish = Stockfish("./stockfish_14_linux_x64_avx2/stockfish_14_x64_avx2", parameters={"Threads": 4})
        self.quit = False
```

Furthermore, it was given 10 seconds to think about each move.
```python
        best_move = self.stockfish.get_best_move_time(10000)
```

On top of that our worst fears were confirmed when we realized that our move
`m1` was being sent to the bot (lemonthink), so the bot knew the entire state of the board
while we were restricted by the 'smog of war'!
```python
        self.enemy.lemonthink(m1)

        enemy_move = self.enemy.normalthink(self.get_moves())
        self.play_move(enemy_move)
```

Henry informed me that even a professional chess player would struggle to beat
stockfish, even without fog of war. We considered writing
another bot running stockfish with more thinking time, but with fog of war and non-deterministic
moves, it would have been difficult to beat the bot with another bot.

By looking closer at the code for the game, we found the following suspicious lines:
```python
    def player_move(self, data):
        if self.get_turn() != chess.WHITE or self.is_game_over():
            return

        m0 = data
        m1 = data

        if isinstance(data, dict) and "_debug" in data:
            m0 = data["move"]
            m1 = data["move2"]

        if not self.play_move(m0):
            self.emit("chat", {"name": "System", "msg": "Invalid move"})
            return
```
It looked like that if we send a move to the server with the `_debug` field,
the move `m0` would get played on the board but the move `m1` would get sent
to the bot. With this, we had enough to trick the bot by giving it a fake
move, when we in fact performed another move!

However, it wasn't that easy because the chess bot had various checks to make
sure the game was progressing normally and would set `self.quit=True` if it
detected anything out of the usual. If it quit, it wouldn't output the flag:
```python
    def resign(self):
        if self.quit:
            return

        self.chat("damn, how did you do that???")
        self.chat(FLAG)
```

Thus we had to beat the bot by only making moves that kept the bot's internal
board state consistent. The easiest way to do so would be to trick the bot one
move before taking the king. I left the job up to Henry to find the best line,
which he used a mix of playing the bot and <https://lichess.org> analysis tool
to figure what the bot would likely do. In the end he came up with this sequence
of moves where the bot behaved predictably.

![winning](/assets/images/corctf2021/smogofwar/winning.jpg)

Then we would run this command:
```
socket.emit('move', {'_debug': true, 'move': 'd4e4', 'move2': 'd4f4'})
```
The command meant that we moved our queen to E4, which puts the king in check.
This would normally prompt a block from the dark square bishop but the chess
bot thought we moved the queen to F4. The bot didn't know it was in check
so this allowed us us to take the king and win!

![wonned](/assets/images/corctf2021/smogofwar/wonned.jpg)

```
corctf{"The opportunity of defeating the enemy is provided by the enemy himself." - Sun Tzu}
```

This was a pretty fun and interesting challenge that we solved the way the
authors intended. The challenge authors speculated whether there were unintended
solutions involving beating the bot legitimately, but we concluded that even if
you had a professional chess player handy, it would be difficult.
