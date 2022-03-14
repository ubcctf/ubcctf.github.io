---
layout: post
title: "[UTCTF 2022] Scrambled"
author: Dontmindme
---

# Scrambled - A Sonnet by DontMindMe

There was a keyboard which had caps mixed up    
A flag hidden among the scrambled text    
Such we turn to frequency to cleanup     
words to find the real flag, to not be vexed    


We start by claiming that backspace is R    
And write some code to see the text unfurled    
Say "a" is Shift and "g" the whitespace char    
Two once-used chars must be the brackets curled    


The flag must be then final string observed    
"utflag" follows, then small tweaks are made    
To see the final script we used preserved    
Look to the end, see how we made the grade    


And while we reach the challenge terminus    
We witness true love lost to nervousness    

## Solve Script

```
FREQ = "B Xetaoinsrhdlucmfywgpbv\nkxqjz  { }"

s = "a[qjj7ahga2gc2jjg=qf/g.7xgm[qgpjo,g2fgog=q87f/tga=7vqm[2f,gpxff.g[o11qfq/gm[7x,[ahga2g1286q/gx1gv.g6q.n7ou/bgnxmgm[qg6q.=gcquqg2fgcq2u/g1jo8q=t3a2g/7f4mg6f7cgc[omg[o11qfq/bgnxmg2m4=g76o.g=2f8qga2g=mouqgomgm[qg6q.n7ou/gof.co.=galay33aoj=7ga24-qg[o/gog8ux=[g7fg.7xgp7ug.qou=bg/7g.7xgcofmgm7g,7g7xmgc2m[gvqa0rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr3aof.co.=bg[quqg2=gm[qgpjo,gai[71qpxjj.ayalgxmpjo,aza=xna=m2amxama27afa58a2a1[aqua5a2a5[aoua/aj.a56af7aca5[aqua]3"

S = {}

for c in s:
    S[c] = S.get(c,0)+1
print(len(S), len(FREQ))

tups = []

for c in S:
    tups.append((S[c], c))
tups.sort()
tups.reverse()
print(tups)
mapping = {}

print(len(FREQ))
cc = 0
for _, c in tups:
    if cc < len(FREQ):
        mapping[c] = FREQ[cc]
        cc+=1
    else:
        mapping[c] = c


news = ""
for c in s:
    news+=mapping[c]

for c in mapping:
    print(c, mapping[c])
print(news)

remap = {}
r1 = "dowutpinamysrxhcgflq-"
r2 = "utflaghiowunsmydcpr'v"
for i in range(len(r1)):
    remap[r1[i]] = r2[i]

newnews = ""
for c in news:
    if remap.get(c, -1)!=-1:
        newnews += remap[c]
    else:
        newnews += c

print(newnews)
```

## PlainText
```
Hello, I will send you the flag in a second. Something funny happened though, I picked up my keyboard but the keys were in weird places.
I don't know what happened but it's okay since I stare at the keyboard anyways.

Also I've had a crush on you for years, do you want to go out with me?BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Anyways, here is the flag hopefully.  utflag{SubStiTuTIoN_cIPhEr_I_hArDLy_kNoW_hEr}
```
