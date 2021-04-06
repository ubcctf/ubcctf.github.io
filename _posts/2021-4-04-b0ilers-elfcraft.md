---
layout: post
title: "[bo1lersCTF 2021] Elfcraft"
author: Kevin Zhang
---

## TLDR:
1. Extract x,y positions of each block
2. Map it into a hex digit.
3. Brute force extracted ELF


## Setup:

We are given a ZIP file that is a Minecraft datapack. You can actually load it into Minecraft but nothing interesting happens so its time to dig into the code. Opening the datapack shows that it is 228 files called `check*.mcfunction`. Opening one of these files shows that it is checking for the existence of a type of block at certain xyz coordinates.

## Setting Blocks:

Problem is that the blocks are all at y=-1 which is not possible in Minecraft. I thought about it before realizing maybe that the y coordinates don't matter and we should just plot out the xz coordinates. So I wrote a script that would extract all the xz coordinates in each file and place blocks at those locations. I got something that looks liked this.

![minecraft](/assets/images/bo1lers2021/elfcraft/minecraft.png)  

Okay those look like ASCII characters so that might be the flag. So plug this into a hex to ASCII translator and we get: `ELF`...... Wait a second. Thats not a flag. Its a bloody ELF file.

## Extract ELF:
That explained the title of the challenge. Also now it made sense why there were so many `check*.mcfunction` files. Each file is one byte so that means there are a total 228 bytes in the file. There is no way I am doing this by flying around in Minecraft and extracting it by hand so I wrote a script with the help of Jason.

```
import os

final = [-1] * 228

lookup = {
0 : [
1,1,1, 
1,0,1,
1,0,1,
1,0,1,
1,1,1,
],
1 : [
0,0,1, 
0,0,1,
0,0,1,
0,0,1,
0,0,1,   
],
2 : [
1,1,1, 
0,0,1,
1,1,1,
1,0,0,
1,1,1,   
],
3 : [
1,1,1, 
0,0,1,
1,1,1,
0,0,1,
1,1,1,   
],
4 : [
1,0,1, 
1,0,1,
1,1,1,
0,0,1,
0,0,1,   
],
5 : [
1,1,1, 
1,0,0,
1,1,1,
0,0,1,
1,1,1,   
],
6 : [
1,1,1, 
1,0,0,
1,1,1,
1,0,1,
1,1,1,    
],
7 : [
1,1,1, 
0,0,1,
0,0,1,
0,0,1,
0,0,1,   
],
8 : [
1,1,1, 
1,0,1,
1,1,1,
1,0,1,
1,1,1,
],
9 : [
1,1,1, 
1,0,1,
1,1,1,
0,0,1,
1,1,1,
],
10 : [
1,1,1, 
1,0,1,
1,1,1,
1,0,1,
1,0,1,
],
11 : [
1,1,0, 
1,1,0,
1,1,1,
1,0,1,
1,1,1,    
],
12 : [
1,1,1, 
1,0,0,
1,0,0,
1,0,0,
1,1,1,
],
13 : [
1,1,0, 
1,0,1,
1,0,1,
1,0,1,
1,1,0,
],
14 : [
1,1,1, 
1,0,0,
1,1,1,
1,0,0,
1,1,1,
],
15 : [
1,1,1, 
1,0,0,
1,1,1,
1,0,0,
1,0,0,
]
}

def look(array):
    # print(array)
    for n in lookup:
        if array == lookup[n]:
            # print(n)
            return n
    return -1

index = 0


directory = os.fsencode("/mnt/i/ctf/b0iler/minecraft/elfcraft/data/elfcraft/functions/checks")
for file in os.listdir(directory):
     filename = os.fsdecode(file)
     if filename.endswith(".mcfunction"):
        a = [0] * 15
        b = [0] * 15
        c = 0
        x = open(filename, "r")
        lines = x.readlines()
        for l in lines:
            if "block" in l:
                f = False
                arr = l.split("block")
                if len(arr) < 2:
                    continue

                coord = arr[1]
                i = coord.find("minecraft")
                coord = coord[:i]
                coord.replace(" ","")
                coord = coord.split("~")
                # print(coord)
                x = coord[1]
                x = int(x)
                if x >= 8:
                    x = x - 8
                    if x > 2:
                        f = True
                        x = (x-1) % 3

                    z = coord[3]
                    z = int(z)
                    # print("Index:{0}, z:{1}".format(index,z))
                    c = z // 6
                    z = z % 6
                    if not f:
                        a[z*3+x] = 1
                    else:
                        b[z*3+x] = 1
        ha = look(a)
        hb = look(b)
        if hb == -1:
            byte = ha
        else:
            byte = ha*16+hb
        final[c] = byte
        index = index + 1

f = open("b.txt", "wb")
for hi in final:
    f.write(hi.to_bytes(1,'little'))
```

Basically, we map the bytes to a 3x5 square and see which blocks are set and compare it to entries in a table to see what the byte actually is.

## PWN the ELF:  
Time to beat this elf up. Turns out that its taking one byte as an input and doing operations on it and printing the result. It doesn't matter what these operations are since there are only 256 possibilities which make it simple to brute force. So brute force it and we get: `bctf{m1n3cra4ft_ELFcr4ft}`. Overall, really fun problem and all the challenges in the CTF were interesting.