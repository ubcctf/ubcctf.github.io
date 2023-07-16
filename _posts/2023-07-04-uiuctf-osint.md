---
layout: post
title: "[UIUCTF 2023] OSINT"
author: HydroHomie
---
# What's for Dinner [50]

## Challenge Description

Jonah Explorer, world renowned, recently landed in the city of Chicago, so you fly there to try and catch him. He was spotted at a joyful Italian restaurant in West Loop. You miss him narrowly but find out that he uses a well known social network and and loves documenting his travels and reviewing his food. Find his online profile.

## Hint 

what does joy translate to?

## Solution
And so Jonah's series starts! As a brief overview to anyone who may be a beginner to OSINT (**O**pen **S**ource **INT**elligence) challenges, the name of the game here is to collect data sources that are publicly available to everyone on the internet. This includes (but is not limited to) social media websites, news articles, company websties, etc. Now that we know what the gist of OSINT challenges are, let's dive in!

To start this challenge, I noticed the description was talking about an Italian restaurant in West Loop, Chicago, so I did a quick google search. Lo and behold, the amount of Italian restaurants that showed up was overwhelming. I had no idea where to start! I came back to the challenge description to see if there was something I was missing, and I decided to click the hint. It was asking what the word 'joy' translates to. At this point I figured since it was along the theme of Italian restaurants, it must be referring to the Italian translation, which is Gioia (those Italian classes really payed off!). 

I got the feeling that since this Jonah Explorer character loves documenting their food, I may as well give the google reviews a try as a first step seeing how accessible it is. This however, proved to be a step in the wrong direction as the google reviews weren't exactly the most active. Feeling a bit stumped, I decided to check a few more review sites deemed as generally popular before I hit this absolute goldmine on Yelp. 

![What's-for-dinner](/assets/images/uiuc2023-osint/whats-for-dinner.png)

This review led me to their twitter page which was in line with the description as it was "... a well-known social network..." and my eyes were blessed with a beautiful flag :,)

## Flag
  ```uiuctf{i_like_spaghetti}```




# Finding Jonah [50]

## Challenge Description
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





# Jonah's Journal [50]

## Challenge Description
After dinner, Jonah took notes into an online notebook and pushed his changes there. His usernames have been relatively consistent but what country is he going to next? Flag should be in format uiuctf{country_name}

## Hint
forks, trees, pushing, and pulling

## Solution 
Within the context of the series, this challenge seems to be one where we're given the least information! Just a description and a hint where this Jonah person could have gone anywhere in the world. Given the lack of routes to take here, I opened the hint and decided to go from there. The hint actually proved to be very helpful, and if you're thinking what I'm thinking, there's only one place to go. An online place where we can fork, push, and pull from trees. You guessed it! It's Github.

Okay so what do we do now? The description says he took to the online notebook and *his usernames have been relatively consistent*. That phrase is very important because now we just need to try to find an account similarly named to the twitter account we found in the "What's for Dinner" challenge.

After a bit of trial and error, I found an account by the username of ```JonahExplorer``` where there exists a public repository called ```adventurecodes```.

Not only that but the date it was created also seemed to line up as well (considering it was made for UIUCTF 2023!)

Looking throught the repo, they says the next place they would like to visit is the "...great wall of china...". You'd think this means they want to go to China right? WRONG. At least that's what the challenge flag submitter said :(

If that wasn't right then what could we do? 

Jonah also mentioned "...not until I get off flight UA5040." Maybe we jumped the gun a bit, got a little trigger-happy with the flag there. Let's see if we can track where this flight is going. Maybe *this* will give us the flag!

Wrong again ;-;

It turns out UA5040 is just a regional flight going from Chicago and Johnstown, Pennsylvania. I even tried to try to find a sort of database of flights because I was so sure this was the way to obtain the flag. That is... until I noticed something else.

The hint said "forks, trees, pushing, and pulling." This prompted me to dive deeper not into the repoistory itself, but githubs features. More so forks and branches (because trees have branches! :o ). After I decided to shift my focus to the features of github itself, I found something very interesting. 
![jonah-github-branch-discovery](/assets/images/uiuc2023-osint/jonah-github-branch-discovery.png)

Do you see it too? 

There's a second branch!

Hallelujah! We've found a new lead!

We were just in the main branch, so let's see what's in the active branch. Upon clicking, we see the following screen.

![jonah-github-second-branch](/assets/images/uiuc2023-osint/jonah-github-second-branch.png)

There's 4 commits in this branch! Let's open it up a bit more and see what's inside. 

The initial commit isn't very exiciting.
![jonah-github-second-branch-initial](/assets/images/uiuc2023-osint/jonah-github-second-branch-initial.png)

The second one is just what we saw in the main branch
![jonah-github-second-branch-second](/assets/images/uiuc2023-osint/jonah-github-second-branch-second.png)


The third one is especially exciting. We find out Jonah is going to Italy before China!
![jonah-github-second-branch-third](/assets/images/uiuc2023-osint/jonah-github-second-branch-third.png)

## Flag
Adhering to the flag format specified in the description, we get ```uiuctf{italy}```

