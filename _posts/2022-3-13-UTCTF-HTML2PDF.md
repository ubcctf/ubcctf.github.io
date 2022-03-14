---
layout: post
title: "[UTCTF 2022] HTML2PDF & Sigma!"
author: Vie
---

# HTML2PDF

## Problem Description
> My friend bet me I couldn't pwn this site. Can you help me break in?

## All is XSS in the web
Before we do anything, notice the `/admin` endpoint which looks for a username and password. Would be nice to try and access that, hey? 

Back to the PDF maker: You can specify a `src` attribute in an img tag (or any tag with a `src` attribute) and the server will happily visit the URL you provided, looking for a picture. I sent it to my site just to see what specific html pdf converter was being used - [wkhtmltopdf](https://wkhtmltopdf.org/).

Search online for any vulnerabilities or potential flaws with wkhtmltopdf and you'll see 2 avenues: SSRF to access the AWS meta-data service (rabbit hole), and server-side XSS for LFI. 

I'm going to skip over the time spent on attempting to gain control of the AWS EC2 which was a red herring. The TL;DR of the vulnerabilities associated with wkhtmltopdf is its ability to execute arbitrary code, likely stemming from a legacy version of [webkit](https://blogs.gnome.org/mcatanzaro/2016/02/01/on-webkit-security-updates/). Remembering the `/admin` endpoint, it would be nice to see if there were any usernames or passwords to look out for that was in a file, and steal it through the execution of said JS code. Since we have JS execution, why not have wkhtmltopdf visit local files for us? 

So, execute a server-side XSS which will grab the `etc/shadow` file - good to know we have some nice permissions to be able to access it. The output will be presented in the PDF.

```html
<script>
    x = new XMLHttpRequest();
    //x.open("GET","file:///etc/passwd");
    x.open("GET","file:///etc/shadow");
    x.send();
    x.onload = function(){document.write(this.responseText);}
</script>
```

![html2pdf etc/shadow](/assets/images/utctf2022/html2pdf/HTML2PDF_etcshadow.png) 

The username is now known: WeakPasswordAdmin. Now, we simply need to bruteforce the hash of WeakPasswordAdmin's password using something like John. Let the hash cracker do its thing and it should return "sunshine" as the password. Log in with those credentials and get yourself the flag:

![html2pdf flag](/assets/images/utctf2022/html2pdf/HTML2PDF_flag.png) 

# Sigma

## Challenge description

> Our new image processing tool runs completely in your browser! Right now we only support one image effect and image format though. Note: this challenge is also a reversing challenge.

## Why is there pwn in my web

We're given source - poke around and notice the `report.js` file which is a simple puppeteer bot that has the flag stored in their cookie. Okay, XSS, got it. 

```js
    await page.setCookie({
      "name": "flag",
      "value": process.env.FLAG,
      "url": "http://localhost:" + port
    });
```

But what does the bot even visit? 

```js
    await page.setRequestInterception(true);
    page.once('request', request => {
      var data = {
        "method": "POST",
        "postData": "image=" + encodeURIComponent(img),
        'headers': {
          ...request.headers(),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
      };
```

The POST request to the admin is looking for a base64'd stream of bytes representing a png file. Let's zoom out for a bit and try to understand specifically what this application is doing. The high-level summary is as so: 

- User provides a .PNG file which, ostensibly, has to be under 10kb because of the bodyParser limit in `app.js`:

``` js
app.use(bodyParser.urlencoded({limit: '10kb', extended: true}));
```
- If user wants to invert the colors on their image, a JS file called `index.js` passes to a wasm file called `a.out.wasm` the PNG, which goes through that process (if the file is too big we get a 413 when trying to do this)
- We can make a request to report a given image to the admin - it's sent as a POST request to `/report` with the Base64'd bytes of the image file in it
- Admin looks at our picture 

So if we want to steal the cookie when the bot looks at our picture, we have to hide our request in the bytes of the image. But wait - the hidden JS probably won't be interpreted as code, so even if we do stego JS into our picture, how will we know it'll execute? 

## Oh boy, I hope you like wasm

The wasm file is the logic behind the pixel color inversion. After 10 mins of reinstalling Ghidra, we can observe the output of decompiling the wasm.

We can also observe and debug the behaviour of the wasm file using the dev console in the browser.


A 3M byte stack buffer is set, with size checks expecting a max of 1000x1000 RGB triples. However, the logic supports RGBA (RGB Alpha) - meaning that the max buffer size is an additional 1M to accomodate the opacity bytes, totaling to 4M. If we give the program an image that is over 3M RGBA bytes but less than 4M, we trigger an overflow whilst never triggering the size checks.

When an overflow occurs, the extra bytes end up overwriting the string `draw_buf(%u, %u, %u)` which is the name of an actual function defined in `index.js`. The original logic would have eval'ed that string as JavaScript code, effectively calling that function in a JS context, in the wasm. However, overflowing into it will change the string of what gets interpreted as JS code. Sounds like just what we need then!

The attack flow is now clear: we just need need to create an image which, when decoded, is a little over 3M bytes and overflow the allocated buffer. The remaining bytes that spill into the string `draw_buf` will be a string that represents JS code. Therefore, when the logic evals it, it doesn't eval `draw_buf()`, it evals our XSS payload instead. 

But, wouldn't our image fail the `10kb` limit on the bodyparser? Well, since the wasm was decoding the png, it would compress down all bytes that were just 0xFF. So the overflow would trigger but the finished png would be under 10kb. 