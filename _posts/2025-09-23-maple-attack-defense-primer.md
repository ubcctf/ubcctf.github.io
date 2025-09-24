---
layout: post
title: "A primer on Attack Defense CTFs"
author: hiswui 
---

## Introduction and Target Audience

Hi! If you're reading this, it means you're atleast a _little_ curious about Attack/Defense CTFs. 

This guide assumes that you are familiar with:
 - the concept of Capture The Flag competitions (atleast Jeopardy CTFs)
 - what a flag looks like and how to find them.

If you're still here, strap in tight while we explore what the heck an Attack Defense CTF is.


## Flavours of CTFs

CTFs come in many flavors. The most common are Jeopardy, followed by Attack-Defense, and on rare occassions HackQuests (shout to hackceler8!). Each of these competition types require different skill sets revolving around cybersecurity.

- **Jeopardy**: This is the most common type of CTF. Players solve from a list of challenges from different Categories (Web, Crypto, Pwn, Rev,misc). These challenges are hosted on a central server. Teams get points by attacking this challenge on the server and retrieving a flag. The competitions generally range from 24 to 48 hours and don't require active involvement throughout the competition. Famouse Jeopardy CTFs include CSAW CTF, Plaid CTF, and Maple CTF :)

- **Attack-Defense**: The original CTF type. Each Team is assigned a server in a shared network. Each server starts by hosting the same set of vulnerable services. Each round or tick (1-5 minutes long), Teams can gain points by attacking the services hosted on other teams' servers to retrieve flags, and defending your services against attacks from other teams by patching out vulnerabilities _without_ breaking its core functionality. The team with the highest points after X ticks win! These compeitions last around 6 - 10 hours and often require active player involvement. Popular A/D CTFs include DEF CON CTF, ENOWARS, and FAUST CTF.

- **HackQuests**: This is just an example to demonstrate that CTFs don't always fit in the above categories. A popular HackQuest is Hackceler8 (Google CTF Finals). In this competition, players are incentivized to find glitches in custom (retro) video games in order to achieve the fastest speedruns.


## Attack-Defense CTFs

This is a more in-depth section that covers the specific details about Attack Defense (A/D) CTFs.

### Game Duration & Ticks

An attack defense CTF typically runs for about 8 hours. It is played in rounds of 1 to 5 minutes called a **tick**.

A game that starts at `14:00` with `5` minute ticks will look as follows
```
+--------+----------------+
|  TICK  |     TIME       |
|--------+----------------|
|TICK 1  | 14:00 to 14:04 |
|--------+----------------|
|TICK 2  | 14:05 to 14:09 |
|--------+----------------|
|TICK 3  | 14:15 to 14:19 |
|--------+----------------|
|  ...   |      ...       |
+--------+----------------+

```

### The Game Network & Your Vulnbox


When you register for an Attack-Defense competition, each team is assigned a server. This server is referred to as a **Vulnbox**. This ["box"](http://box.urbanup.com/151562)  hosts a set of vulnerable *services* that your team attempts to defend.

The core of an A/D CTF is the **Game Network**. It refers to the computer network that connects all the Team boxes to each other. That is, allow you to access the services on other teams' boxes and allow other teams to access the services on your box. Aside from vulnboxes, it also hosts a central *gameserver*.

The method used to host services vary from CTF to CTF. It can range from using docker compose for each service to having a VM for each service.

(TODO: add photo of game network and examples of CTFs with docker compose)


### VPNs, vulnbox setup and whatnot

To connect your vulnbox to the game network and also generally access game resources like the flag submitter or an internal scoreboard, competitions provide you a **VPN configuration**, maybe in the form of a [wireguard](https://www.wireguard.com/quickstart/) configuration. Teams can use this VPN configuration to submit flags from their local machine or even attack other teams from their local machine to save compute resources on your vulnbox.

Vulnbox setups differs between competitions. Some competitions like ENOWARS has historically provided teams with a virtual machine as their vulnbox with minimal setup required, others like FAUST CTF expect you to provide your own machine to connect to the game network and need you to apply a VM image to set your vulnbox up.

### Services
A **service** in an A/D CTF refers to a computer program/application that contain one or more vulnerabilities. A service can be considered as the A/D analogue for a challenge in Jeopardy CTF.

Similar to challenges in a Jeopardy CTF, services can fall into one or more categories such as Web, Crypto, Pwn, rev, etc. They can also provide you with the source code or only provide you with a binary executable for your team to reverse and exploit.


Here are a few examples of services:
- [piratesay](https://github.com/enowars/enowars8-service-piratesay): From ENOWARS 8, this service mimics a pirate-themed dark web forum where users can chat and brag about exploits. The service falls into the pwn category and only provides a binary executable.
- [nautro](https://github.com/Nautilus-Institute/finals-2025/tree/main/nautro): From DEF CON 33 CTF , A Balatro-like resource management card game where players attempt to maximize their resources by playing cards. This service falls into the miscellaneous category, and only provides a binary executable.
- [quickr-maps](https://github.com/fausecteam/faustctf-2024-quickr-maps/tree/master/checker): From FAUST CTF 2024, a location sharing application with an API. This falls into the Web category, and it contains the Go/Python source code.


Note: The above services are of the Attack Defense Category of Services. Services can also use the "King of The Hill" format for scoring.


### King of The Hill (KotH)

TODO at a later date.

No attack or defense involved. Services revolve around scoring the highest number of points among the other teams. It's typically only seen in smaller A/D Competitions like DEF CON CTF (12 teams).



### Scoring Points

There are 3 ways to score points in an A/D CTF. Each compeition places a different weightage on these components.

For each tick, you can win points from:
- **Attack Points**: Points you gain from exploiting another team's service and submitting their flag. The more teams you exploit, the more points you gain.
- **Defense Points**: Points you gain if no other team (fully) exploits your service. One service might have multiple flags.
- **SLA Points**: Points you gain by having an active and reachable service which passes a set of tests from the gameserver.


At any given tick, each of your services might be in the following states (varies between CTFs):

- `OK`: Everything working fine
- `DOWN`: Service not running or another error in the network connection, e.g. a timeout or connection abort
- `FAULTY`: Service is available, but not behaving as expected (fails SLA)
- `FLAG_NOT_FOUND`: Service is behaving as expected, but a flag could not be retrieved
- `RECOVERING`: Service is behaving as expected, at least one flag could be retrieved, but one or more from previous ticks could not.

(adapted from https://ctf-gameserver.org/checkers/#check-results)

### The Gameserver
The **gameserver** is a machine/set of machines in the _game network_ that plays a variety of roles. 

It is responsible for:
- Placing flags in your services every tick
- Running tests against each service every tick. (SLA)
- Flag submission
- Providing additional information about services if required.
- Anonymizing web traffic (sometimes)

### Attacking Services, Attack Info and Flag stores
Attacking a service is similar to exploiting a challenge in a Jeopardy CTF. The general workflow is to find a vulnerability, exploit it to retrieve the flag. 

Services typically can contain multiple flags, the location of each flag is often referred to as a **flag store**. An example of a flag store in `piratesay` from earlier would be the secrets file associated with each user account on the web forum. The same service also has another flag store in the from `.treasure` files which are password-protected.

Finding the flag stores can be unclear. However, examining the source code or reverse engineering the service is helpful. More on this in the later sections.

**Attack Info** is a special and very important API endpoint on the gameserver that provides useful information about the flag stores for each Team's service for the last few ticks. This can be in the form of user IDs, file paths, and more.


**Attack Info** is typically presented as a large JSON with the following schema. (varies from CTF to CTF)

```JSON
{
    "team1": {
        "tick n":
            {
                "flagstore 1": ["data"],
                "flagstore 2": ["more", "data"]
            }, 
        "tick n-1":
            {
                "flagstore 1": ["otherdata"],
                "flagstore 2": ["dead", "beef"]
            }, 
        "tick n-3":
            {
                "flagstore 1": ["data"],
                "flagstore 2": ["deadbeef", "face"]
            }, 
            
    },
    "team2":,
    "team3":,
    ...
}
```

Here is a real example of the attack info from [ENOWARS 9 - timetype] which displayed the Attack Info for the last 10 ticks.
```JSON
{
...
 "10.1.26.1": {
        "205": {
          "1": [
            "hlU9y0DChKvoaWz"
          ],
          "2": [
            "PBPXITUPPU"
          ]
        },
        "206": {
          "1": [
            "4PZafbjfHLguKBX"
          ],
          "2": [
            "A460UZVSHR"
          ]
        },
        "207": {
          "1": [
            "VbaVyFL82Gi"
          ],
          "2": [
            "6KTHS66AUK"
          ]
        },
        "208": {
          "1": [
            "CsYkxqsbmu0"
          ],
          "2": [
            "PKFTDKIFPR"
          ]
        },
        "209": {
          "1": [
            "jOE2Vs2H"
          ],
          "2": [
            "59ZZEVTEK6"
          ]
        },
        "210": {
          "1": [
            "mPC5pP9JOEmb5W"
          ],
          "2": [
            "XUVI2O4HQO"
          ]
        },
        "211": {
          "1": [
            "umbqwFv4VkOw"
          ]
        },
        "212": {
          "1": [
            "6fHMlCfIbmZ1HG"
          ],
          "2": [
            "M9LGS3ZSEB"
          ]
        },
        "213": {
          "1": [
            "GBtSMPAv"
          ],
          "2": [
            "8U57UI01UA"
          ]
        },
        "214": {
          "1": [
            "H8Tu4MelKHHU9"
          ],
          "2": [
            "5JXUWCCXW7"
          ]
        }
      },
...
}

```
**Note:** some A/D CTFs do not have Attack Info endpoints.

If a CTF _does_ have this endpoint, it's **ALWAYS** a good idea to check it for useful information that helps you understand and exploit a challenge.

Finally, it's important to make sure that your exploits can run fast enough to retrieve the flag before it expires. Flags expire after X ticks. (X is set by the A/D CTF). 


### Defending Services and Patching
So, you found a vulnerability in your service. Now what? Well, you get to **patch** it. 

Depending on the service and the game setup which varies from CTF to CTF, patching ranges from being a trivial task to annoyingly tedious.

**If patching source code:** If your patch involves modifying the source code written in Python/Go/Java/etc, it's a simply a matter of changing the code, recompiling the program if neccessary and restarting the service (via docker compose or VMs).

**If patching a binary (binpatching):** If your patch needs to be applied on a binary executable, you would need to use a utility like [pwntools patching](https://docs.pwntools.com/en/stable/elf/elf.html) or [patchelf](https://github.com/NixOS/patchelf) to patch the bytes/assembly code.

Note that when you "push" your patch to your service, you might have to take it down for a tick losing out on sweet sweet SLA points. Even if your service "recovers", you might end up failing the SLA.


### the Service Level Agreement (SLA)

At this point, you might wonder why you cannot patch your service by disabling access to all features. The issue is that you might fail the SLA.

As mentioned earlier, a **Service Level Agreement (SLA)** is set of tests that the gameserver runs against your services every tick. These tests are intended to ensure that your service still maintains its core features. A messaging app should be able to send/recieve messages, a game about cards should allow you to play the cards, and so on.

If your services pass these tests, your team recieves points for having a functional service.
If your services fail these tests, your team does not recieve SLA points or defense points.

### The Secret Other Thing: Network Traffic Analysis

A team's biggest asset for Attack/Defense CTFs is the network traffic it recieves from other teams. 

Each tick, your team is able to capture the packets sent to it in the form of **[PCAPs](https://en.wikipedia.org/wiki/Pcap)**.

Analyzing the payloads that other teams send to your service is extremely insightful. This data can help you find vulnerabilities in your services by showing you where to look in the service's code. This information can also help you learn more about the service as well as help you write exploits to attack other teams. PCAPs can also be useful to identify how other teams might be stepping around your patches to services. 

Traffic Analysis is an essential tool to succeed at Attack Defense CTFs. Teams often have extensive Infrastructure dedicating to capturing and analyzing packets.

### Flag submission

Once you captured the flag (haha), you need to submit them to recieve points for the tick. It's generally as simple as sending newline separated flags to a port at the submission URL.

More details can be found [here](https://ctf-gameserver.org/submission/). It does a much better job at explaining the internals of flag submitters if you're interested.

## AD Infrastructure

To succeed in an Attack-Defense CTF, you must have infrastructure/tooling to automate/avoid repetitive tasks. The **infrastructure** can be as simple as a bash script that helps you submit flags to a bespoke application built from the ground up to efficiently analyze PCAPs.

Having access to tooling during the competition, enables your team to focus more of their precious resources on looking at services rather than remembering to run your exploit script every tick.

Infrastructure can define difference between winning and losing a game. Naturally, many teams are secretive about the tools/infrastructure that they use.

Let's go through a few common tools many teams would use:

### Throwers
A **thrower** is a tool that runs your exploit script against all the other boxes on the network and submits recieved flags for you. It's a great abstraction that takes care of:

- Running exploits each team
- Using the team-specifc and tick-specifc information about a service (attack info)
- Submitting flags

A thrower might take the form of an _exploit template_ that members can write and throw exploits with.

A popular "off-the-shelf" thrower is [ataka](https://github.com/OpenAttackDefenseTools/ataka)

### PCAP Analyzers

A **PCAP Analyzer** is an application that is used to tag, view, filter, and analyze Packet Capture data uploaded to it. These tools often have UIs where you are able to filter for and tag certain patterns in a packet such as `path_traversal` when you see a pattern of `../../../`.
By filtering through and monitoring data sent to services, you can gain a clearer understanding of how services work and how to approach exploiting/patching them.

There are plenty of popular "off-the-shelf" PCAP analyzers. The most commonly used tool is [Tulip](https://github.com/OpenAttackDefenseTools/tulip).

### Patcher
A **Patcher** is a nice-to-have tool to reliably patch services in the competitions and avoiding the need to SSH into the vulnbox each time.

There are many solutions to patching. One such solution is to use git. You can read more about this in our previous writeup [Patching infrastructure for attack-defense CTFs](https://maplebacon.org/2024/09/faustctf-patcher/).

### Anything you find useful :D
Yeah. What the title says. Tooling is an iterative process. As you compete in more CTFs, you find more use cases and functionalities in existing tools that are missing. 

It's a very exciting experience to build your own tooling from scratch that's custom built for a CTF. Maybe you feel that you're basically copy-pasting machine between your code editor and chatGPT, try to write a tool to automate triage with LLMs! There is an infinite potential for new tools you never knew you needed :D

## An Important Conclusion

Overwhelmed? It's a lot of information to process in a single page. The best way to learn is to partcipate in competitions and learn as you go. The most exciting part is failing, iterating and improving for the years moving forward. 

Each step towards improving your team's processes, communication, and team allocation strategy to services, tooling is step for growth. Remember that the most important rule in CTFing is to have fun <3

## Resources
- [https://glitchrange.com/attack-defense](https://glitchrange.com/attack-defense): A quick overview of A/D CTFs.
- [https://2025.faustctf.net/information/attackdefense-for-beginners/](https://2025.faustctf.net/information/attackdefense-for-beginners/): Rules and the setup of a real Attack Defense CTF 
- [https://ctf-gameserver.org/](https://ctf-gameserver.org/): An excellent resource going over organizing Attack Defense CTFs
- [https://github.com/OpenAttackDefenseTools]: Nice Off the shelf tooling for A/D CTFs

