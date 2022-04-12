---
layout: post
title: "[PlaidCTF 2022] but I plaidiversed that already"
author: alueft
---

## tl;dr

Area Man Decides that Playing 256 Consecutive Games of Terraforming Mars was a
Good Idea

## Intro

This is the challenge entitled "but I plaidiversed that already" from
[PlaidCTF 2022](https://ctftime.org/event/1542).

We're given a web instance of a
[Terraforming Mars](https://github.com/terraforming-mars/terraforming-mars)
clone that's been patched to add a "challenge" of winning 256 solo games in a
row (with at most one loss allowed). Once this is complete, you get a flag.

It went unsolved during the contest, so the organizers offered a $100 USD bounty
on the challenge to the first team to get the flag within a week.

## Hold on, what is Terraforming Mars?

[Here](https://www.youtube.com/watch?v=n3yVpsiVwL8) is a 29-minute video
explaining how to play Terraforming Mars.

If that last sentence sounded unappealing to you, I respectfully suggest you
save your time and stop reading this post. Otherwise, I'll assume a general
familiarity with the rules of the game.

A game in this challenge uses solo game rules, Corporate Era cards, and the
Prelude expansion, which reduces the solo game length to 12 generations. You
have that long to fully terraform Mars in order to win.

## Initial thoughts

I played a few games to get a feel for the solo rules during the contest (mostly
because all the other challenges were too hard), and figured that I could win
maybe 50% of the time. Obviously, this made winning 256 of 257 games extremely
unlikely, not to mention it took me 10 minutes on average to play through a
game. I like board games, but probably not enough to play 40+ hours of the same
game within a week.

The fact that there were no solves during the contest, and no other challenge
was worth more points with static scoring, suggested that there wasn't an easy
exploit. That is, there wouldn't be anything like pwning the server instance, or
attacking a vulnerable SQL query to modify the challenge state - we'd have to
get our hands dirty and actually play through 256 games in a row.

This did seem a little sadistic (even for PlaidCTF), and I'm not an ML engineer,
so I didn't think it was likely that I would be able to put together an AI for
the game. Thus, I started poking around the game code to see if there'd be a
vulnerability in the implementation itself.

## Oops! All Preludes

I eventually found
[this issue](https://github.com/terraforming-mars/terraforming-mars/issues/4221)
on Github, which references a different expansion but presents the intriguing
idea that preludes could be duplicated. Sure enough, in the initial card
selection phase of the game, we can send a prelude array of two of the same card
to the server without getting an error, and both can be played normally.
Similarly, project cards weren't deduped, so any strong card could be duplicated
up to 10 times.

This was useful, but not *that* useful - certainly there existed some
potentially game-breaking cards, like Standard Technology which could generate
infinite money if four of them were played. But hoping for very specific cards
wasn't exactly a viable strategy, since there were checks to prevent selecting
cards that hadn't been dealt to the player.

However, this did get me looking at the part of the code that populated the
player's initial game state (comments added by me):

```js
this.options.push(
  new SelectCard<ICorporationCard>(
    'Select corporation', undefined, player.dealtCorporationCards,
    // callback after selected corp is parsed
    (foundCards: Array<ICorporationCard>) => {
      corporation = foundCards[0];
      return undefined;
    }, // default values omitted here: must select exactly one corp
  ),
);

if (player.game.gameOptions.preludeExtension) {
  this.options.push(
    new SelectCard(
      'Select 2 Prelude cards', undefined, player.dealtPreludeCards,
      // callback after selected preludes are parsed
      (preludeCards: Array<IProjectCard>) => {
        // preludes are *appended*, not assigned???
        player.preludeCardsInHand.push(...preludeCards);
        return undefined;
      }, 2, 2, // must select exactly two preludes
    ),
  );
}

this.options.push(
  new SelectCard(
    'Select initial cards to buy', undefined, player.dealtProjectCards,
    // callback after selected project cards are parsed
    (foundCards: Array<IProjectCard>) => {
      player.cardsInHand.push(...foundCards);
      return undefined;
    }, 10, 0, // must select between 0 and 10 projects
  ),
);
```

The comment of note here is the one in the prelude callback. Because the
selected cards are *appended*, and there exists an additional parsing block
after preludes for project cards, we can construct a query containing a valid
corp, two valid preludes, and a bogus project card:

![exploitrequest](/assets/images/plaidctf2022/bipta/exploitrequest.png)

The query will fail, so the server will refuse to progress the game and expect
us to try again, but there are now two additional preludes in the player's hand
which will show up when we ultimately send a valid request. This allows us to
replicate and play an arbitrary number of the four preludes dealt to us.

We end up with something like this:

![exploitresult](/assets/images/plaidctf2022/bipta/exploitresult.png)

Note that the same bug exists for project cards, but we can't exploit it because
there's no way to make the request fail and prevent the game from progressing if
we supply an array of valid project cards.

Also, this is technically a zero-day vulnerability because it's in the live
codebase
[here](https://github.com/terraforming-mars/terraforming-mars/blob/8cec38f8e7f6e660c3bcb3fa123e1a60664ce4f9/src/inputs/SelectInitialCards.ts#L36).
This isn't exactly the Linux kernel, though, and I mean...sure, you can take
this bug and cheat at this board game playing against other people, but what
exactly does that accomplish?

## The actual game plan

Using this exploit, we can hopefully generate enough money to make the game
trivial. If we only generate money, we need roughly 750 M€ to do all the
necessary standard projects. We can also replicate preludes that do terraforming
actions, which makes the game much easier. The worst case scenario is a
selection of four preludes that aren't very useful, but we still should be able
to do something like draw a bunch of cards to play or sell for more money.

OK, so we've finally gotten to the point where we can write code. The procedure
is as follows:

1. Select a corp and preludes to replicate.
1. Send bogus requests to replicate the preludes, and a valid request to
   progress the game.
1. Play all the preludes that were replicated.
1. Pass a few times if necessary (e.g. if the prelude was Dome Farming, which
   increases income).
1. Do aquifer standard projects until oceans are done.
1. Do asteroid standard projects until temperature is done.
1. Do greenery standard projects until oxygen is done.
1. Pass until generation 12 is done.
1. Repeat until 256 games are complete?

This may sound simple, but of course there are myriad edge cases to consider.
Some examples are:

* Solo rules add a pseudo-second player that places two cities and greeneries
  randomly on the map, so greenery placement can't be a static array of tiles.
* If a card is drawn at any point, the array of available actions given to the
  player may or may not change depending on whether the card is playable.
* Playing enough oceans will eventually result in getting 8 plants, which adds
  a greenery option that may change the array of available actions.
* The Helion corp adds an additional prompt to use heat (if available) as money
  for all actions.
* The Tharsis Republic and Valley Trust corps add additional first-turn actions
  which require additional input.
* If Great Aquifer was replicated, we'll be able to place 9 oceans, but we still
  have to play any redundant copies afterward for no effect.
* Business Empire and Loan aren't great on their own, but together they can
  generate infinite money.

And so on. To deal with all this, we could either do what the challenge author
did, which is write a really good script to handle the vast majority of cases
and manually play the worst-case scenarios, which takes a total of ~20 minutes.
Or...

## Semi Automated Luxury Mars Communism

...we could write functions to handle the easy parts, and manually evaluate the
harder decisions. I figured that if I needed to babysit a script that paused on
unhandled edge cases, it'd be simpler for me to just run the actions myself.

For example, here's the Python code I used to place all greeneries:

```python
input_url = "http://bipta.chal.pwni.ng/player/input?id=" + game_id

# start_tile: where to place the first greenery (usually "03", top left)
# num: the index of "standard project" in the array of available player actions
# midway_start: if I messed up and need to restart the function
def api_greeneries(start_tile, num, midway_start=0):
    # place the first greenery
    r = requests.post(input_url, json=[[str(num)],["Greenery"]])
    r = requests.post(input_url, json=[[start_tile]])

    # place the remaining greeneries
    for i in range(midway_start+1,14):
        r = requests.post(input_url, json=[[str(num)],["Greenery"]])
        x = json.loads(r.text)

        # avoid the tiles that make us draw a card
        no_card_please = None
        for tile in x["waitingFor"]["availableSpaces"]:
            if (tile == "14" or tile == "55" or tile == "56"):
                continue
            no_card_please = tile
            break
        if not no_card_please:
            print("something is wrong, bailing")
            return
        r = requests.post(input_url, json=[[no_card_please]])

    print("greeneries done")
```

But I ended up using the following snippet in a Python REPL just as much, which
places a single greenery in the first available space:

```python
r=requests.post(input_url, json=[["0"],["Greenery"]])
requests.post(input_url, json=[[json.loads(r.text)['waitingFor']['availableSpaces'][0]]])
```

The important part of replicating preludes worked, though, so I got through all
256 games with losing once. At some point the sunk-cost fallacy kicked in, and I
stoppped thinking about improving my methodology.

After the 256th win, the "continue" button becomes a "get flag" button:

![flag](/assets/images/plaidctf2022/bipta/flag.png)

## Wait, so *how* long did this take?

Like 12 hours. Not all at once, mind you - I did sleep and take breaks, and
around game 175 switched hands for moving the mouse to save my wrists.

Easy games (e.g. where Donation was available) took under 30 seconds. Harder
games with bad prelude choices took up to 5 minutes. I ended up averaging
slightly more than 2 minutes per game.

## Lessons learned, and conclusion

Science cards are bad if you don't care about victory points.

I probably should've used the provided script to run a local instance of the
game, which would've negated server latency and allowed me to figure out a way
to transition to new games without copying a new URL every time. If the
challenge had been to play 1024 games, I hopefully would've realized that fully
automating a script was the way to go...

Overall, this was still fun (and props to the challenge author for putting it
together), because I wouldn't have grinded it out otherwise. (I do have over 500
hours in Factorio, so this wasn't an entirely new thing to me.)
