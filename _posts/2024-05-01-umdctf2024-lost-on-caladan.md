---
layout: post
title: "[UMDCTF 2024] Lost on Caladan"
author: frankuu
---




# Lost on Caladan [500] OSINT




## Challenge Description


you seek to find the finest doctor on caladan. it's rumored he works at this location. find his name for me.





## Solution


As a Dune enthuaist, who has seen both films half a dozen times, I know that the finest doctor on Caladan is Dr. Yueh. However, the ctf server did not accept the flag ```UMDCTF{Wellington_Yueh}```. Nonetheless, we were provided with a .jpg file of a certain google street view (360 degress full panoramic view)


![image](/assets/images/umdctf2024/lost-on-caladan.jpg)







From here, we are given an image of a Google StreetView of a supposedly medical center. 

Lets try to find cues to identify macro details of the location i.e. country, administrative division such as provinces, states, cities, etc.







With the glarring white on red stop octogon being the 'Stop Sign' , we can tell that is based in North America, specifcally in an English speaking territory. Québec, being the uniquely French speaking province in Canada, have French signages of 'arrêt'. We can rule out the possibility of it being in Québec.













Additoinally, we can see the detailed high-visibility direction signs near the entrance/exit of the parking lot. In North America, as medical centers often span multiple buildings, clear and concise directions are necessary. They are also presented in high contrast colors (blue and white or red and white) for high visibility. Additionally, there are arrows to point the way at intersections. 


![image](/assets/images/umdctf2024//image-copy-3.png)





or 



![image](/assets/images/umdctf2024//image-copy-4.png)





We can conclude that this is located at a fairly largel medical center in the region. Possibly with more than 300+ beds and attached with out-patient, emergency, rehabilitation, and surgical facilities.





Now lets look for some other identifiers. 

The newstand by the entrance of the building may provide some insight. Only the **"amp"** is visble in this newspaper or megazine dispenser.




![image](/assets/images/umdctf2024//image-copy.png)







![image](/assets/images/umdctf2024//image2.png)


We can initially conclude that **"amp"** matches the megazine "Arkansas Money & Politics" which is a local Arkansas publication. This should help us narrow down the search to Arkansas, USA. However, given the scope of the state 





1. Baptist Health Medical Center - Little Rock (834 Beds)
2. CHI St. Vincent Infirmary (615 Beds)
3. UAMS Medical Center (535 Beds)

[Source](https://www.hospitalmanagement.net/features/largest-hospitals-arkansas-2021/?cf-view) .



The satellite view of Baptist Health Medical Center - Little Rock shows a similar parking lot layout and the same high-visibility direction signs.



![image](/assets/images/umdctf2024//image-copy-5.png)




The parking lot layout and the high-visibility direction signs (white on dark blue) are similar to the ones in image. 

![image](/assets/images/umdctf2024//image6.png)



Zooming in on Google Street View, we can select an intersection that fit in our criteria of being near a large parking lot and a medical tower.


![image](/assets/images/umdctf2024//image7.png)



The beige building on the right is rather interesting, as it is accros from a parking lot and matches the color of the building in the image.

![image](/assets/images/umdctf2024//image8.png)


Aha we've reached our destination, where a minibus is parked at the front and where the latest issues of Arkansas Money & Politics are available.

"Baptist Eye Center", is a surgical opthamology center affiliated with Baptist Health Medical Center - Little Rock. Doctors at this center should be the people we are looking for.



Heading over on [WebMD](https://doctor.webmd.com/practice/baptist-health-eye-and-surgery-center-9d3dc05a-da81-4601-a0eb-e564ea77205d/physicians/) we can see a list of ophanmologists working at the center.





![image](/assets/images/umdctf2024//image-copy-9.png)




We took the name 'best' doctor literally, as we initially tried to submit the flags containing the names of the highest rated doctors, such as as ```UMDCTF{Christian_Cardell_Hester}```. It was not until after nearly 15 minutes of bruting through all of the doctors names that we realized the zero star rated "Dr. Sean Adonis Atreides."

```UMDCTF{Sean_Adonis_Atreides}``` unfortunately was not his full name. We scrambled to find the full name of the doctor, and going on Oklahoman Board of Medical Licensure and Supervision, we found that his full name is "Sean Paul Adonis Atreides".


![image](/assets/images/umdctf2024//image10.png)



## Flag 


```UMDCTF{Sean_Paul_Adonis_Atreides}``` 