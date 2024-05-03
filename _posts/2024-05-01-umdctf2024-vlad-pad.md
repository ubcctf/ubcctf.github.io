---
layout: post
title: "[UMDCTF 2024] Vlad Pad"
author: frankuu
---





# Vlad Pad (500 OSINT)





## Challenge Description


Paul Atreides gets a message delivered by ornithopter late at night from Chani asking him to meet her at an undisclosed location so that she can help him practice summoning the Shai-Hulud. The message only provided a Google Street View location. Paul believes there is an IT company nearby that will be able to help him find Chani. Help Paul Atreides find the name of the company.





## Solution




![image](/assets/images/umdctf2024/vlad-pad.jpg)



We are given a Google Street View of a location. This time, we are looking for an IT company near by. 

We can determine that on location is located in a English speaking developing country, based on the tropical architecture and the rental signs.  Broadly speaking, this narrows to India, Philippines, Malaysia. 

As the people in the images look Southeast Asian, we can rule out India. Although the Northeastern Indian states (Assam, Manipur, etc) have a similar demographic, the architecture is not similar to the one in the image. 


Now the image name ```vlad-pad.jpg``` is a clue. Vladmir Harkonnen is the head of the House of Harkonnen. This might be useful in our search. 


A simple search of "philippines Vladmir tech" doesn't yield any results. 

![iamge](/assets/images/umdctf2024/image11.png)

However, a search of "philippines Harkonnen tech" directs us to a company called Harkonnen Industries Corporation. Which is located in the outerskirs of Metro Manilla. Lets take a close look at the streetview. 


![image](/assets/images/umdctf2024/image-1.png)

![image](/assets/images/umdctf2024/image13.png)

This highly resembles the alley indicated in the image. Upon a closer look, we can see that this is the location of the streetview. 





![image](/assets/images/umdctf2024/image14.png)




## Flag

```UMDCTF{Harkonnen_Industries_Corporation}```

