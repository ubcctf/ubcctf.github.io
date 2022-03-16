---
layout: post
title: "[UTCTF 2022] Baby Shark"
author: frehlid
---

# Baby Shark

## Problem Description
> I think someone downloaded something from an http site. Luckily I caught the traffic. I'm super curious about what it was. Let's go hunt! (doo, doo, doo, doo, doo, doo) By Robert Hill (@Rob H on discord)


## Solution
Baby shark is a beginner challenge introducing some key web concepts. The challenge provides us with a pcap file and a short description.

For many beginners, the pcap file might be unfamiliar. However with a quick google search, and some context from the description, they can realize that the pcap file stores packet data from a network scan. Or, in other words, stores the traffic over a network. Clearly, we’re going to want to examine this traffic.

To do so, we can utilize a program called Wireshark, as the challenge name alludes to. Opening the file in Wireshark presents us with what seems like gibberish:

![wireshark-output.png](/assets/images/utctf2022/Baby-Shark/wireshark-output.png)

The pcap file stores lots of information, much of which is outside the scope of the challenge. A keen eyed viewer might notice that line number 7 contains a GET request for “flag.png”. This is what we’re after. To view the image, simply go to file → export objects → HTTP. This will allow you to export the captured HTTP data. Wireshark will automatically read detect that the file is a PNG, and export it as such. 

Opening the PNG, we get our flag!

![flag.png](/assets/images/utctf2022/Baby-Shark/flag.png)