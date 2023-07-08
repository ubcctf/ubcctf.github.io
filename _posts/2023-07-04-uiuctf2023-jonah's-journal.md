---
layout: post
title: "[UIUCTF 2023] Jonah's Journal"
author: HydroHomie
---

# Challenge
After dinner, Jonah took notes into an online notebook and pushed his changes there. His usernames have been relatively consistent but what country is he going to next? Flag should be in format uiuctf{country_name}

# Hint
forks, trees, pushing, and pulling

# Solution
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
