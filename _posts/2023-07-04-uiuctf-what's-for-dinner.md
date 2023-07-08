---
layout: post
title: "[UIUCTF 2023] What's for Dinner"
author: HydroHomie
---
# What's for Dinner 

## Challenge Description

Jonah Explorer, world renowned, recently landed in the city of Chicago, so you fly there to try and catch him. He was spotted at a joyful Italian restaurant in West Loop. You miss him narrowly but find out that he uses a well known social network and and loves documenting his travels and reviewing his food. Find his online profile.

## Hint 

what does joy translate to?

## Solution
And so Jonah's series starts! As a brief overview to anyone who may be a beginner to OSINT (**O**pen **S**ource **INT**elligence) challenges, the name of the game here is to collect data sources that are publicly available to everyone on the internet. This includes (but is not limited to) social media websites, news articles, company websties, etc. Now that we know what the gist of OSINT challenges are, let's dive in!

To start this challenge, I noticed the description was talking about an Italian restaurant in West Loop, Chicago, so I did a quick google search. Lo and behold, the amount of Italian restaurants that showed up was overwhelming. I had no idea where to start! I came back to the challenge description to see if there was something I was missing, and I decided to click the hint. It was asking what the word 'joy' translates to. At this point I figured since it was along the theme of Italian restaurants, it must be referring to the Italian translation, which is Gioia (those Italian classes really payed off!). 

I got the feeling that since this Jonah Explorer character loves documenting their food, I may as well give the google reviews a try as a first step seeing how accessible it is. This however, proved to be a step in the wrong direction as the google reviews weren't exactly the most active. Feeling a bit stumped, I decided to check a few more review sites deemed as generally popular before I hit this absolute goldmine on Yelp. 

![What's-for-dinner](/assets/images/uiuctf2023/What's-for-dinner.png)

This review led me to their twitter page which was in line with the description as it was "... a well-known social network..." and my eyes were blessed with a beautiful flag :,)

## Flag
  ```uiuctf{i_like_spaghetti}```
