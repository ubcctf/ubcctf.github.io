---
layout: post
title: "[R3CTF/YUANHENGCTF-2024] Transit"
author: frankuu
co-authors: [lf-]
---







## R3CTF/YUANHENGCTF 2024 Transit Challenge [MISC]

Authors: [Jade Lovelace](https://jade.fyi), [Frank Yan](https://github.com/frankuyan)






## TL;DR
Utilize the overhead signage to identify the city and metro system. Scan through local Chinese media for any images of local metro rolling stock.  Use the rolling stock number to identify the line and stations. Use the street view images and line schematic to identify the station.


## Challenge Description 

```
This is an OSINT chal! The city's rail transit is like the veins of time, glides effortlessly through the concrete jungle, transforming every journey into a flowing tapestry. So which station is this?

The flag format is R3CTF{city_lowercase_name_endswith_station}. For example the Huixin Xijie Nankou station of the Beijing Subway would be R3CTF{beijing_huixin_xijie_nankou_station}.
```


## The Image
![image](/assets/images/r3ctf2024/e6007e3f-e141-470a-8294-6828ffe8bc43.jpg)









## Solution
We took the image and stared at it to try to figure out if it was a metro or mainline railway. Our main hint that it was a metro is the grade in the background but we kinda just guessed.

We looked at the overhead signage identifying the supports for the catenary, and noticed that it was in two parts, the first one seemingly being track ID or segment ID or so, and the second one being sequential as you go along the line, as seen in the picture.

We decided to do this by just [dorking wikipedia](https://en.wikipedia.org/wiki/Urban_rail_transit_in_China#Urban_rapid_transit_lines) and googling around for Chinese metros looking for ones that use the same style of trackside signage for their overhead lines.

Google results usually yield schematic subway maps of the system. Thankfully Frank does read Chinese, and Baidu is more helpful in giving out images of rolling stock on tracks.

We started out with "[`Name of tier one/two Chinese cities`] + 地铁轨道交通 + 铁轨 (subway transportation system + railtracks)" and have found some images.

Shanghai does not have visible hanging signs on overhead powerlines.

![Shanghai](/assets/images/r3ctf2024/1a29e466-761d-4266-9532-d3bc3ba22e70.png)

Beijing does use a few hanging signs, but they are usually three digit numbers on a blue background.

![Beijing](/assets/images/r3ctf2024/5162f04c-1a34-4d29-ba82-d18e39217c95.png)

Chengdu on the other hand, uses a three character system with the first letter being an alphabet. Although the colorscheme does resemble to the image (black letters on white), it uses a different font with wider characters.

![Chengdu](/assets/images/r3ctf2024/d1075b76-ab75-41c4-82ed-3213dfbb8721.png)

After going through an exhaustive list of tier one and two Chinese cities, we stumbled upon a picture from Hangzhou's metro system.

It has an overhead signage that actually match the same track segment, M368.

![Hangzhou](/assets/images/r3ctf2024/c7405574-8c7a-46f0-8418-3e8bc8d0e3d9.png)

We now have the rolling stock number `190181` and the line color turquoise blue. Given that the majority of Chinese systems use a numbered system to name metro lines and associate a unique color to each line, we are getting closer to the flag.

We then went on Wikipedia looking at Hangzhou metro, to figure out which line it was by looking at the rolling stock and found it was line 19:

![Line 19](/assets/images/r3ctf2024/35c99cb7-1d8b-4bdd-9cc7-85e464993e63.png)

Line 19 is an airport express line that only partially opened in 2022. Baidu Baike tells us that there are four elevated stations on line 19.

![Baidu Baike](/assets/images/r3ctf2024/7711c0fa-bfd8-445a-9d40-2aaef9e75b65.png)

高架 means elevated while 地下 means underground. This helps us to narrow down to
- 御道站(Yudao Station)
- 平澜路站 (Pinglan Road Station)
- 耕文路站 (Gengwen Road Station)
- 知行路站 (Zhixing Road Station)

While these stations all share the common features of being elevated and running in parallel along the Hangyong Expressway (the viaduct in the picture).

We decided to further examine the street view at each of the four sites.

平澜路站 (Pinglan Road Station) provides a view of a four-lane highway with rows of trees densely lined to its sides. We decided to move on to the other three stations, but the same highway is repeated throughout.

Until we realized...

![Street View](/assets/images/r3ctf2024/34d246c8-ba1d-4f09-b539-8e74070ac546.png)

These images are from August 2017.

Clearly, given China's otherworldly pace of construction, most information from 2017 can be considered to be outdated.

Hence, we just tried to input the names of the four stations.


## Flag

`R3CTF{hangzhou_zhixing_road_station}`