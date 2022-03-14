---
layout: post
title: "[UTCTF 2022] Cheating Battleship"
author: Kevin Zhang
---



# TL:DR
The client sends a packet to the server right as you place your last ship. This packet contains the coordinates of your ships which the AI uses to cheat. You can intercept and replace this packet to provide bogus positions and make the AI miss. Then proceed to play Battleships normally and when you win you'll get the flag.

# Premise
The objective of this challenge is to beat the AI in the children's game Battleship. However, if you play the game normally you will soon discover that the AI is a dirty cheater with an aimbot. It will be impossible to win given these circumstances.
| ![battleship.png](/assets/images/utctf2022/Battleship/battleship.png) |
|:--:|
| <b>The AI is cheating and has 100% accuracy.</b>|

# Approach #1: Reverse the JS
The biggest hint here from the organizers is that this challenge was categorized as networking so the first thing I did was capture some of the traffic. From there, we can see that the client is using a WebScocket to communicate with the server. Now that we have the packets that are being sent,  we tried to reverse the source code on the client side to see if we could get a better understanding of the packet structure.

The issue is, the JS code is over 100KB and is heavily obfuscated. Furthermore, there are multiple debugger checks built into the code. Jason actually has some experience reversing obfuscated JS so he volunteered to try to reverse this mess. I on the other hand do not want to even look at this thing for another second so I moved on. 

Here is a snippet of the JS code:
```Javascript
(function (saralee, pamilla) {
  const lakhi = saralee();
  while (!![]) {
    try {
      const deontee = parseInt(tinashe(959, "zzP[")) / 1 * (-parseInt(tinashe(1587, "03Wo")) / 2) + parseInt(tinashe(1830, "OvRH")) / 3 + -parseInt(tinashe(1393, "Hsix")) / 4 * (parseInt(tinashe(1129, "Hsix")) / 5) + parseInt(tinashe(327, "(HuH")) / 6 + -parseInt(tinashe(583, "8Q]R")) / 7 * (-parseInt(tinashe(1574, "$Xi%")) / 8) + -parseInt(tinashe(307, "uXdQ")) / 9 + -parseInt(tinashe(960, "bsQF")) / 10 * (-parseInt(tinashe(572, "2MM%")) / 11);
      if (deontee === pamilla) break; else lakhi.push(lakhi.shift());
    } catch (samrawit) {
      lakhi.push(lakhi.shift());
    }
  }
}(jerrye, 120320));
...
```

# Approach #2: Packet Analysis
Like I said before, the biggest hint from the organizers was that this challenge was categorized under networking. Therefore, I decided to analyze the packets a bit more in depth. I captured the traffic a couple of times while playing the game and determined the following timings:
![wireshark.png](/assets/images/utctf2022/Battleship/wireshark.png)

The blue packet is sent right as the user clicks the Captcha. The red packet is sent right as the player places their last ship. The black packets are sets of 3 packets that are sent/received every time the player takes a shot.

## Deeper look
Now lets take a deeper look at what the packets might mean. The red packet is sent right as the captcha is clicked and is the first WebSocket packet that is sent to the traffic. I assumed that this was some initialization mechanism and decided to come back to this later.

Next, the black packets are sent/received right after the player takes a shot. The first packet is sent by the client so it probably contains information about where the player wants to shoot. The second packet is sent by the server and it is always `82 02 08 01` when the player misses and is always `82 02 08 00 ` when the player lands a hit. So the second packet probably indicates to the client whether or not the shot was a hit. For the third packet, it is sent by the server and it was initially `82 06 0a 04 08 01 10 09` for the first shot but changed to `82 06 0a 04 08 00 10 09` on the second shot. They only differ by one byte and the difference in value is only one. Based on how I placed my ships right next to each other this packet is probably the server sending the coordinate that it is shooting at.

Finally, the red packet is sent by the client right as the player places their last ship. It is a relatively big packet as well compared to the other packets that the client sends.
```
00000000: 0814 1014 1a0a 0a04 0800 1000 1000 1805  ................
00000010: 1a0a 0a04 0800 1001 1000 1804 1a0a 0a04  ................
00000020: 0800 1002 1000 1803 1a0a 0a04 0800 1003  ................
00000030: 1000 1803 1a0a 0a04 0800 1004 1000 1802  ................
00000040: 1a0a 0a04 0800 1005 1000 1805 1a0a 0a04  ................
00000050: 0800 1006 1000 1804 1a0a 0a04 0800 1007  ................
00000060: 1000 1803 1a0a 0a04 0800 1008 1000 1803  ................
00000070: 1a0a 0a04 0800 1009 1000 1802            ............
```

My hypothesis was that this is the positions of the player's ships which the AI will use to cheat and get 100% accuracy. To test this hypothesis I placed my ships in the same positions twice and compared the red packets. They were identical! Now, all we need to do is change the placement and see if the red packet changed. And it changes! 

Now that we have confirmed that the red packet is the positions of the player's ships the solution becomes clear. We can send the server fake positions to make the AI miss and just beat it normally.

# Solution
However, we are still missing fake positions to send to the server. Luckily, we don't actually need to know how the positions are structured; all we need to do is place the ships in other positions, copy the positions packet that was sent by the client and use that instead.

Now, we just need a way to intercept and replace WebSocket traffic. To Google we go! It looks like Burp Suite is able to do this. 

Finally, intercept and replace the positions packet, and we see that the AI starts missing! Then proceed to play the game normally and you are basically guaranteed to win since the AI will miss all of their shots initially. Win the game and see that the flag appears.

`utflag{if_u_want_it_done_right_dont_rely_on_client}`