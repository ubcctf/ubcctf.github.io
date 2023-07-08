---
layout: post
title: "[UIUCTF 2023] Finding Jonah"
author: HydroHomie
---


# Finding Jonah

## Challenge
Jonah offered a reward to whoever can find out what hotel he is staying in. Based on the past information (chals), can you find out what the hotel he stayed at was? Flag should be uiuctf{hotel_name_inn}

## Hint
what does joy translate to?

## Solution
For this challenge in the Jonah series, we were actually given a jpeg file! Here is the picture
![Finding-Jonah](/assets/images/uiuc2023-osint/finding-jonah.png)

To start this challenge, I did what many would probably do in this situation. I chucked the picture into an online exif tool! 

Now for anyone unfamiliar with what exif tools are, they're tools used to extract the exif data of a picture. Exif data refers to the data found in EXIF (**Ex**changeable **I**mage **F**ile Format). This data, also commonly known as 'metadata' is typically embedded within the image. It offers information such as (but not limited to) the type of camera used to take the photo, the photo's exposure values, the date and time the photo was taken, and even the gps coordinates in some cases. 

In the case of this photo, I threw it in a website called "aperisolve" which is an online steganography tool. The main focus was to see if there was a special message hidden within the metadata of the photo, however I didn't find any such message. From here, I started to treat it like a 'geoguesser' challenge. A 'geoguesser' challenge is one where an author gives you a photo, and it's the reader's job to find where in the world it was taken! For any beginners reading this, keep in mind that the only reason I was able to make this connection is because of experience. Given enough experience you too can identify certain challenges as well! 

### Step 1
So yeah, now that I made the decision to treat it as a geoguesser challenge, the first step was figuring out what city we were in. Because the challenge description said "Based on past information (chals)..." I attributed this to mean that we can refer to the "What's for Dinner" challenge. The hint also pushed me in this direction as it was the exact same hint as the "What's for Dinner" challenge! So that's one step down. We know we are in Chicago. 

### Step 2
The next step is to look for any significant landmark in the picture. Seeing as how Chicago is a rather large city, what we need is some sort of identifier that we can use to narrow down the location to some area. In the picture, while kind of blurry I saw a building towards the right with what seems to be a logo. Maybe that's something we can use! 

![Finding-Jonah-Boeing-Logo](/assets/images/uiuc2023-osint/finding-jonah-boeing-logo.png)

It looks like a Boeing logo! That's a pretty notable company... right?
Now the next step is to actually narrow down the area and to confirm through the use of a lovely developer's tool that I like to call "Google."

### Step 3
After a quick search I figured out that there exists a Boeing office in Chicago. The address is `100 N Riverside Plaza, Chicago, IL 60606, United States`. This led me to search a list of hotels near the Boeing building in Chicago as the picture seemed to depict, and Hampton Inn was the first result. Puttin this into a flag format yielded the correct answer!

## Flag
```uiuctf{hampton_inn}```
