---
layout: post
title: "[ImaginaryCTF 2025] passwordless"
author: george
---

> Description
> Didn't have time to implement the email sending feature but that's ok, the site is 100% secure if nobody knows their password to sign in!
>
> http://passwordless.chal.imaginaryctf.org
>
> Attachments: [passwordless.zip](https://2025.imaginaryctf.org/files/passwordless/passwordless.zip)

I solved this challenge in collaboration with Leo at the Maple Bacon CTF club meetup. Clicking the link presented us with the following webpage:
![passwordless landing page](/assets/images/imaginaryctf2025/passwordless.png)

We attempted registering for an account, but unfortunately the application generates it's own password containing 16 random bytes for the user and does not return it for the user to see. The password generation function is shown below:

```javascript
const initialPassword = req.body.email + crypto.randomBytes(16).toString("hex");
```

Due to this, it seemed we had to find a bypass to log in without the password being returned to us. Seeing that we were given the source code for the application, we started reading it for an hour until we noticed something odd with the user registration route:

```javascript
app.post("/user", limiter, (req, res, next) => {
  if (!req.body) return res.redirect("/login");

  const nEmail = normalizeEmail(req.body.email);

  if (nEmail.length > 64) {
    req.session.error = "Your email address is too long";
    return res.redirect("/login");
  }

  const initialPassword = req.body.email + crypto.randomBytes(16).toString("hex");
  bcrypt.hash(initialPassword, 10, function (err, hash) {
  ...
  });
});

```

The route compares the length of the user's email after running a
`normalizeEmail` function on it, but uses the original email to generate a password off of. Seeing this, we started testing out how the normalizeEmail function worked.

```javascript
normalizeEmail("foo@gmail.com");
// 'foo@gmail.com'
normalizeEmail("f.o.o@gmail.com");
// 'foo@gmail.com'
normalizeEmail(".................@gmail.com");
// '@gmail.com'
```

Upon realizing we could bypass the length check, we assumed that if there was a bypass for the length of the email, there must be some maximum length that the
`bcrypt` password hashing algorithm was able to handle. Surely enough, after a quick google search, we found a [stackoverflow link](https://stackoverflow.com/questions/76177745/does-bcrypt-have-a-length-limit) which states:

> BCrypt hashed passwords and secrets have a 72 character limit.

Upon seeing this, we registered a user with the following email:

```
......................................................................................................................................................@gmail.com
```

(in case you were wondering, thats 150 `.` characters)

By registering this email, we were able to bypass the email length check and input a string into the bcrypt hash function longer than 72 characters, removing the 16 random bytes added to the end of the password. Once registered, we logged into the application with the username and password being the email above, presenting us with the flag.

![passwordless flag](/assets/images/imaginaryctf2025/passwordless-flag.png)

flag: `ictf{8ee2ebc4085927c0dc85f07303354a05}`
