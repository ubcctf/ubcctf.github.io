---
layout: post
title: "[TrendMicroCTF Quals 2020] Keybox"
author: Vie
---

# TL;DR 

1. Literally just decrypt everything. RC4 and key = "TrendMicro"
2. Have an android app command you to do things for hours
3. Flag


# Keybox

Keybox is an android application that sort of operates like spyware, but advising you to do certain actions on your android phone (emulator) to unlock 5 portions of a string that acts as the decryption key to decode the flag. These 5 bits were encoded themselves in RC4, and there were hints in the application that would try to steer you in the direction of the specific key for that bit, and those hints were _also_ encrypted in RC4. I collaborated with crypto hacker [Arctic](https://ubcctf.github.io/authors/rctcwyvrn/) during this challenge.

## "Key" portion 0, idk really

Arctic and I didn't know what the key was to decrypt the hints found in the app, so she made a scoring function to decode bits and pieces of the hints until we found that the key was "TrendMicro" much later. 

Anyway, to decode the actual flag key 0, I didn't know how to start. By chance I saw in the `AndroidManifest.xml` of the app that it had a unique "hint" intent implementation, so I used it with the password given to us to unzip the contents of this application... and somehow that _worked_. 

```
KEY0-7135446200
```

## “Key” portion 1, call me maybe

The hint for the next portion was `To unlock Key 1, you must call Trend Micro`.

Mentor Robert quickly spun up a python script called ``decrypt.py`` to automate much of the decrypting process, now that we figured out the password. 
But the full hint for key 1 didn't reveal anything else. That was the whole hint. 

So now I had to look at and see how the app listens in for incoming and outgoing calls.

I spent a good portion of my time calling up all possible Trend Micro office numbers through my emulator, and simulating incoming calls from them, to no avail. And so I thought about it a bit more: 

In the observer class in the APK file, they instantiated a listener to look for incoming calls (the CALL_STATE android intent). The hint suggested to call the office, but the code itself seemed to only be paying attention to incoming callers, not calls you make. Whether or not the intention was to do both, I thought about how this would work. 

Since the app was listening in on call history, how would it then know when to decrypt KEY1? What is the encryption key it's looking for? Well, since the hint and the code all pointed to the act of making and recieving calls, then the encryption key to decode KEY1 must be a phone number. And wether or not I was having luck with dialing all possible offices to see if the app's listener would take notice, the components were all there. The encryption key had to be a phone number. We knew that KEY1 bit was encoded in rc4. So, couldn't we just take the .enc file and give it a couple Trend Micro phone numbers as a key, and run it through the rc4 decryption process? 

It turned out that the phone number for Trend Micro's Japan HQ was the key to decrypt KEY1. 

```
KEY1-1047645455
```

## “Key” portion 2, whats the secret code?

`To unlock KEY2, send the secret code.`

Secret codes are specific sequences of numbers that could perform special actions. For example, the code 232338 would reveal your android phone’s MAC address. Applications can also use them to perform secret tasks or unlock hidden features. If you wanted to test this out on your android device, open up your dialer and input a secret code as so: *#*#123456#*#*.

In the AndroidManifest.xml file, the SECRET_CODE intent is defined:

```xml
            <intent-filter>
                <action android:name="android.provider.Telephony.SECRET_CODE"/>
                <data android:host="\ 8736364276" android:scheme="android_secret_code"/>
                <data android:host="\ 8736364275" android:scheme="android_secret_code"/>
            </intent-filter>
```

So the secret code in the app is the encryption key for KEY2!

You can either use abd to send the android.provider.Telephony.SECRET_CODE intent or just use the dialer in the emulator, as the app has a listener on the call function. Either way, you get KEY2.

```
KEY2-9517232028
```

## “Key” portion 3, spamming messages

`Unlock KEY3 by sending the right text message`. In androids, SMS messages are kept in a relational database - specifically, sqlite. In the APK’s observer class, we see some interesting checking going on:

```java
    invoke-interface {v5, v2}, Landroid/database/Cursor;->getColumnName(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_a8

    iget-object v4, p0, Lcom/trendmicro/keybox/Observer;->cursor:Landroid/database/Cursor;

    iget-object v5, p0, Lcom/trendmicro/keybox/Observer;->cursor:Landroid/database/Cursor;

    const-string v6, "type"

    invoke-interface {v5, v6}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v5

    invoke-interface {v4, v5}, Landroid/database/Cursor;->getInt(I)I
```

What’s happening here? Well, long story short, when we send an SMS message, the app will access the SMS sqlite database and iterate through the columns of that database, and match the content of the text message to the column name. If there’s a match, then the app will unlock the 3rd key for us. This must mean that the string needed to decrypt the third key bit must be one of the column names!

```
KEY3-2510789910
```

## “Key” portion 4, meet me in Tokyo

```js
// why actually calculate distance when you can just fake it ;)
        if(Math.abs(location_latitude - singleton_latitude) < 0.001 && Math.abs(location_longitude - singleton_longitude) < 0.001 ) {
            Log("Matched Location " + location.location);
            var SHA1 = new Hashes.SHA1;
            hash = SHA1.hex(location.location)
            if( hash == location.hash) {
                location_match = "Welcome to " + location.location;
            } else {
                location_match = "Welcome to " + location.location;
                singleton.push(location.hash);
            }
            break;
        } else {
            location_match = ""
        }
    }


    titleView.setText("Key Four Hints");
    textView.setText(
    "Visit " + /* all three of */ "the headquarters to unlock Key 4" + "\n\n" +
    location_match
    );

    return(true)`
```
The hint specified to visit only the 3 headquarters, which were in the USA, Canada and Japan (Irving, Ontario and Tokyo respectively). While you can simulate your location in the emulator to pretend as if you visited all 3 locations, what it was looking for was the hash of the lat-lon location. It would check if that hash was among the list of accepted ones (which are only the hashes of the 3 HQs), and then append those hashes and use it as the key to decrypt KEY4.

So, we needed to just append the hashes of the 3 headquarters, and input that as our decryption key to key4.enc.

```
KEY4-4721296569
```

# Flag

With all 5 keys decrypted, all that was left was to combine them all and decrypt the flag.

``TMCTF{pzDbkfWGcE}``

Android app security, everyone.