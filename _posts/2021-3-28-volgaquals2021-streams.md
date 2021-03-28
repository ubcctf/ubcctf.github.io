---
layout: post
title: "[Volga Qualifiers 2021] Streams"
author: Kevin Zhang
---

## TLDR:

1. Extract RAR password from USB keyboard capture
2. Fix RAR file and extract
3. Grep for flag

## Premise

We are given two Wireshark files. One contains a TCP stream that is a file transfer a file called `root.RAR`. The other is a USB capture of all USB activity happening at the time,


## RAR

Using Wireshark to extract the `.RAR` file we see that the archive is password protected. Throwing it into a hex dump only showed that the structure of the archive was a tree with a lot of branches and we'll probably have to use grep or something to look for the flag.  

## Password

At this point I was lost but then I realized that the USB capture might have captured keyboard activity that might include the password to the archive. Looking at the capture we see that there are four USB devices present at the time.  
[Devices](/assets/images/volgaquals2021/Stremas/devices.PNG)  

1.1.0: A hub. Not interesting  
1.2.0: Device  
1.3.0: Device  
1.4.0: TP-LINK WiFi adapter.  


Looking at 1.2.0 we see that it is made by A4Tech. After doing some research I found out that they made HID devices. This is probably our keyboard. We also know that USB keyboards use interrupts and if its a keyboard then the keyboard will be sending the keystrokes to the host. So we'll just filter interrupt traffic that originates from 1.2.x. Which looks something like this.  
[Packets](/assets/images/volgaquals2021/Stremas/packets.PNG)  
The HID Data section is the keystrokes being sent over. Essentially, the first 2 bytes are control keys like SHIFT and CTRL and then each byte after that is one key on the keyboard being pressed at time of the interrupt. [Chapter 10](https://usb.org/sites/default/files/hut1_21_0.pdf) of this document shows how to translate each byte to a character. Doing this for each packet yields `wpwhqsdhlp7hx69`.

## Extraction

Once we try to extract `root.RAR` we are prompted for a password and it happens that the password we extracted was correct. However, I got a prompt that said that the archive ended unexpectedly which is a sign of a corrupted archive. Fortunately, WinRAR has a tool for fixing RAR files built into it. Once the RAR is fixed we can extract again and the hint in the challenge says the file begins with `VolgaCTF` so we just do a grep on the extracted archive and we see that the flag can be found at `/folder#5/folder#5/folder#3/folder#7/FLAG IS HERE.txt` and the flag itself is `VolgaCTF{1T_w42_e45y_t0_cR4cK_8R0keN_r4R}`.