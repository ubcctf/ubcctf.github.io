---
layout: post
title: "[Trendmicro 2021] OSINTⅡ 400"
author: aynakeya
---

# [Trendmicro 2021] OSINT Ⅱ - 400

## main concept: code review, image stego, web, zero-width Steganography

# tl;dr

missing

The challenge came along with a `README.txt`, `advisories.png`, and `pwnconfig-1.0.jar`.

The challenge url is `http://pwnieconfig.tmctf.trendmicro.com` 

# information

The `README.txt` file is clearly encode in the hex, read the file and convert hex to bytes, we got the following information.

```python
with open("README.txt","r") as f:
    print(bytes.fromhex(f.read()).decode())
```

the message tell us the bug only found in v1.0. However the website that challenge provide with us is v2.0. So, need to find a way to access v1.0.

```
Advisory Date: Sept. 18th 2021

Dear Pwnieconfig Users,

A security update v2.0 has been published for Pwnieconfig. Please find attached the corresponding Pwnieconfig Security Advisory document.
Pwnieconfig v1.0 will reach end of life in 36hrs but until then, it has been archived so that you may still access your configuration files.
As part of our transparency policy, we have provided a lightweight model of the vulnerable version.

Cheers,
Pwnieconfig Team
```

After using dirmap to find possible entry of v1.0, I give up and decide to start code review.

# code review

open `pwnieconfig-1.0.jar`

There are some easily spotted exploits.

**Admin backend -  login with out password**

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled.png)

**filename is used directly in the combination of file path**

- download file from upper directory using `../`

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled%201.png)

**configBase also combine directly with the directory**

- list upper level directory using `../`

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled%202.png)

# stego

@Filip do the stego on the `advisories.png` and found two important information, the v1.0 are deployed in the `archive` subdomain. And the flag is encrypted using zero-width steganography.

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled%203.png)

# web

use `archive.pwnieconfig.tmctf.trendmicro.com` to access v1.0 web with security issues.

using admin backend, we got the username and password (jeoqj/hisgqjqlcg)

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled%204.png)

then login the system, find the flag file location using `list?configBase=../` and download the java class file `http://archive.pwnieconfig.tmctf.trendmicro.com/download?id=-1&filename=../RetrieveFlag.class`

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled%205.png)

after decompile the java class file. we get the flag content whiich is locate at `/view/3ec4e19a-2a70-4aac-9893-ac3712473928/b64content`

```
// 
// Decompiled by Procyon v0.5.36
// 

package com.tmctf.pwnieconfig.flag;

import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.GetMapping;
import java.io.IOException;
import java.util.Base64;
import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.springframework.stereotype.Controller;

@Controller
public class RetrieveFlag
{
    @GetMapping({ "/view/3ec4e19a-2a70-4aac-9893-ac3712473928/b64content" })
    @ResponseBody
    public String content() throws IOException {
        final String note_fyi = "TrendCTF requires flag format";
        note_fyi.concat("to be formatted as TMCTF{flag}.");
        note_fyi.concat("Keep this in mind!");
        String b64_flag = "";
        final String salt = "ac3712473928";
        final ProcessBuilder pb = new ProcessBuilder(new String[] { "python", System.getProperty("user.dir") + "/4aac-9893/decoder.py", salt });
        final Process process = pb.start();
        final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        final StringBuilder builder = new StringBuilder();
        builder.append(reader.read());
        b64_flag = Base64.getEncoder().encodeToString(builder.toString().getBytes());
        return b64_flag;
    }
}
```

after open the link. the webpage return a very long base64 string.

decode base64 string will get a string which encrypted with zero-width stego.

```python
data = "SGVsbG8sIOKAjOKAi+KAjOKAi+KAjOKAi+KAjOKAjOKAjeKAjOKAi+KAjOKAjOKAi+KAi+KAjOKAi1RyZW5kTWljcm8g4oCN4oCM4oCL4oCM4oCM4oCM4oCM4oCL4oCL4oCN4oCM4oCL4oCM4oCL4oCM4oCL4oCMQ1RGIOKAjOKAjeKAjOKAi+KAjOKAjOKAjOKAi+KAi+KAjOKAjeKAjOKAi+KAi+KAi+KAi+KAjHJlcXVpcmVzIOKAi+KAi+KAjeKAjOKAi+KAjOKAjOKAi+KAjOKAi+KAjOKAjeKAjOKAi+KAi+KAjOKAjHRoZSDigIzigIzigIvigI3igIzigIvigIvigIvigIzigIvigIvigIzigI3igIzigIvigIzigIxmbGFnIOKAjOKAjOKAjOKAjOKAjeKAjOKAi+KAjOKAi+KAjOKAi+KAi+KAi+KAjeKAjOKAi+KAi3RvIOKAjOKAjOKAi+KAjOKAi+KAjeKAjOKAi+KAi+KAjOKAjOKAjOKAi+KAjOKAjeKAjOKAi2JlIOKAjOKAjOKAjOKAjOKAjOKAi+KAjeKAjOKAi+KAi+KAi+KAjOKAjOKAjOKAjOKAjeKAjGluIOKAi+KAi+KAi+KAjOKAjOKAjOKAjOKAjeKAjOKAi+KAjOKAi+KAjOKAjOKAi+KAi+KAjXRoZSDigIzigIvigIvigIvigIzigIzigIzigIzigI3igIzigIvigIvigIzigIvigIvigIzigIxmb3JtYXQg4oCN4oCM4oCM4oCL4oCL4oCM4oCM4oCM4oCM4oCN4oCM4oCL4oCL4oCM4oCL4oCM4oCMVE1DVEZ7ZmxhZ30uIOKAi+KAjeKAjOKAi+KAi+KAi+KAjOKAi+KAjOKAjOKAjeKAjOKAi+KAi+KAi+KAi+KAjERvIOKAi+KAjOKAjeKAjOKAi+KAjOKAjOKAjOKAjOKAi+KAi+KAjeKAjOKAi+KAi+KAjOKAi3lvdSDigIzigIzigIzigI3igIzigIzigIvigIvigIzigIvigIzigIzigI3igIzigIvigIvigIxzZWUg4oCL4oCM4oCM4oCL4oCN4oCM4oCL4oCL4oCM4oCL4oCL4oCL4oCM4oCN4oCM4oCL4oCM4oCL4oCL4oCM4oCL4oCM4oCN4oCM4oCL4oCL4oCL4oCL4oCL4oCM4oCLaXQ/IA=="
```

note that every 8 unicode character is separate by `"\u200d"` 

so separate characters by `"\u200d"` and replace `"\u200c"` with 0 and `"\u200b"` with 1. we get the flag

![Untitled](/assets/images/trendmicro2021/basicwebvul/Untitled%206.png)

```python
data = "SGVsbG8sIOKAjOKAi+KAjOKAi+KAjOKAi+KAjOKAjOKAjeKAjOKAi+KAjOKAjOKAi+KAi+KAjOKAi1RyZW5kTWljcm8g4oCN4oCM4oCL4oCM4oCM4oCM4oCM4oCL4oCL4oCN4oCM4oCL4oCM4oCL4oCM4oCL4oCMQ1RGIOKAjOKAjeKAjOKAi+KAjOKAjOKAjOKAi+KAi+KAjOKAjeKAjOKAi+KAi+KAi+KAi+KAjHJlcXVpcmVzIOKAi+KAi+KAjeKAjOKAi+KAjOKAjOKAi+KAjOKAi+KAjOKAjeKAjOKAi+KAi+KAjOKAjHRoZSDigIzigIzigIvigI3igIzigIvigIvigIvigIzigIvigIvigIzigI3igIzigIvigIzigIxmbGFnIOKAjOKAjOKAjOKAjOKAjeKAjOKAi+KAjOKAi+KAjOKAi+KAi+KAi+KAjeKAjOKAi+KAi3RvIOKAjOKAjOKAi+KAjOKAi+KAjeKAjOKAi+KAi+KAjOKAjOKAjOKAi+KAjOKAjeKAjOKAi2JlIOKAjOKAjOKAjOKAjOKAjOKAi+KAjeKAjOKAi+KAi+KAi+KAjOKAjOKAjOKAjOKAjeKAjGluIOKAi+KAi+KAi+KAjOKAjOKAjOKAjOKAjeKAjOKAi+KAjOKAi+KAjOKAjOKAi+KAi+KAjXRoZSDigIzigIvigIvigIvigIzigIzigIzigIzigI3igIzigIvigIvigIzigIvigIvigIzigIxmb3JtYXQg4oCN4oCM4oCM4oCL4oCL4oCM4oCM4oCM4oCM4oCN4oCM4oCL4oCL4oCM4oCL4oCM4oCMVE1DVEZ7ZmxhZ30uIOKAi+KAjeKAjOKAi+KAi+KAi+KAjOKAi+KAjOKAjOKAjeKAjOKAi+KAi+KAi+KAi+KAjERvIOKAi+KAjOKAjeKAjOKAi+KAjOKAjOKAjOKAjOKAi+KAi+KAjeKAjOKAi+KAi+KAjOKAi3lvdSDigIzigIzigIzigI3igIzigIzigIvigIvigIzigIvigIzigIzigI3igIzigIvigIvigIxzZWUg4oCL4oCM4oCM4oCL4oCN4oCM4oCL4oCL4oCM4oCL4oCL4oCL4oCM4oCN4oCM4oCL4oCM4oCL4oCL4oCM4oCL4oCM4oCN4oCM4oCL4oCL4oCL4oCL4oCL4oCM4oCLaXQ/IA=="
data1 = base64.b64decode(data)
a = data1.decode()
# remove standard unicode character
for s in a:
    if ord(s) > 128:
        uns.append(s)
unss = "".join(uns)
uns1 = unss.split("\u200d")
print(len(uns1),uns1,unss.count("\u200d"))
def replacer(s:str):
    return s.replace("\u200c","0").replace("\u200b", "1")
for s in uns1:
    sss = replacer(s)
    print(chr(int(sss,2)),end="")

# TMCTF{Jav@WebAppSpl0itzCh4inZ}
```