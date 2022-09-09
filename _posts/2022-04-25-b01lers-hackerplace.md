---
layout: post
title: "[b01lers 2022] hacker/place"
author: Vie
---


This writeup is a collaborative effort between Vie, [Alueft](https://ubcctf.github.io/authors/alueft/) and [Ming](https://ubcctf.github.io/authors/ming/).


## TL;DR
Starved webgang swarms first web challenge within an hour of release.

![webgang.png](/assets/images/b01lersctf2022/hackerplace/webgang_assemble.png)

## Challenge Description

After the smash success of r/place, hackers have opened hacker/place for their own groups to duke it out on. However, some script kiddies managed to steal the secret key and place pixels much faster than all of us. It's your job to hack the hackers and even the playing field.

Author: DJ

Difficulty: Medium

## Solution

The challenge is inspired by reddit’s r/place, which gives us a canvas and the ability to place a pixel at a position every 10 seconds. The premise of the challenge has us looking at a bot that is busy occupying the middle of the canvas with a giant b01lers logo. 

The source of the challenge is provided. In the `app.js` file, we can observe a `/flag` endpoint which requires the correct admin-valued JWT token in the cookie of the visitor to access, which gives us the flag. The secret which is used to sign the JWT is given as a header to the b01lers bot on the application. 

The bot connects to the canvas server through a websocket, then colours the appropriate x,y coordinates on the canvas with “red” and “darkred” values to create the b01lers logo. If anyone tries to colour those x,y positions with another colour, the bot will swiftly change it back (this is important for later). When the bot receives a message signaling a colour change anywhere on the canvas (including when it adds a colour too), it will take note of the colour and make an axios POST request to that colour with the given x,y coordinates. The bot code will attempt to block any bad colour inputs through a trivial replace function:

```js
let color = JSON.parse(str.slice(7));
try {
    color = color.replace('://', '')
} catch (err) {
    //
}
console.log(`Logging opposing pixel placed at ${x}, ${y} with color ${color}`);
axios(color, {
    method: 'post',
    data: { x, y }
})
```

This can be easily bypassed by simply adding another `://` into your input, since only the first one in the string gets removed. This allows us to make the bot make a POST request to anywhere we want - which is nice, since any HTTP request will also include the custom header that has the JWT signing secret we need to make our own JWTs. 

Going back to `app.js`, the canvas is updated using a 2d array of “clients” (read: people on the canvas adding pixels, including the bot). In the `set_pixel()` function, the 2nd try-catch block performs the logic needed to update the canvas to all clients on it with the newly-coloured pixel. In this try-catch, there is also logic which will validate the provided colour amongst the enumeration of colours available, so even if we did bypass the trivial `://` replacer, we wouldn’t pass the if statement and our payload would not have been accessed by the bot… in theory. The application also keeps tabs on the client who last changed the updated pixel separately, and updates them with the change first before updating everyone else - and this occurs in the first try-catch block, before the if statement validates the provided colour. 

Therefore, we can choose a pixel that's watched by the bot, change it (using a valid colour), and let the bot change it back. Then, we can change the pixel back, but this time change the colour to a link to our server. The logic will thus send our payload to the bot first without verifying the colour. Of course, afterwards the colour check in the 2nd try-catch will fail us, and our payload will not be broadcast to the rest of the people on the canvas. 

Once we've managed to make the app send our payload to the bot, we will get a request to our server with the header containing the secret needed to sign our own JWT tokens. Simply make your JWT “admin” token, access `/flag`, and receive your hard-earned goddamned-web-challenge flag. 
