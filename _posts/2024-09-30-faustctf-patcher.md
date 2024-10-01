---
layout: post
title: "[FAUST 2024] Patching infrastructure for attack-defense CTFs"
author: apropos
---

This is a writeup of the patching setup Maple Bacon used in FAUST 2024.

This last weekend, we played in [FAUST CTF 2024](https://2024.faustctf.net/). While we were limited on manpower & had to scramble about with challenges, it was still quite a lot of fun.

FAUST provided eight challenges:
- `floppcraft`: xxe + ssrf + fixed jwt signing
- `quickr-maps`: url injection + ssrf, flags plotted as QR codes
- `secretchannel`: bit flipping token id
- `todo-list`: user id collision
- `lvm`: type confusion pwn
- `asm-chat`: insecure session handling
- `missions`: cache shenanigans
- `vault`: hardcoded rsa n

Out of those, no one was able to exploit one (`lvm`), and only a handful of teams had an exploit for another (`missions`). We had working exploits for three: `floppcraft`, `todo-list`, and `asm_chat`, and had a nearly-working exploit for `quickr-maps`. We were able to patch `floppcraft` and `asm_chat` entirely, and partially patch `quickr-maps`, `todo-list-service`, and `vault`. We placed 27th, but peaked at 20th (when our exploits were all mostly working). Overall pretty alright! Not our best performance, but it was the first time we had played in an A/D CTF in a while.

I handled defense + patching + network analysis infrastructure. We used an entirely new system for patching that worked quite well (despite putting it together a week before the competition) - so I figured I'd write up a little something on it.

## Design

In previous years, we've managed patching by SSHing into the box and manually editing the appropriate files + rebuilding. This sucks, for everyone involved - and if patches are more than a couple of lines long, it *really* sucks. We've used Git for ease of rollback / version history, but only to *track* services on the box itself. This got me thinking: could we just... set up a Git server on the box and push patches directly to it? We would need some way to treat a normal repo as an origin, though. And the Git server expects its origin repositories to be "bare". So that wouldn't work directly.

Or would it? As it turns out, the "bare" requirement is [*just a configuration option*](https://stackoverflow.com/a/28381311/11087133) and can be disabled. Treating an ordinary Git repository as an origin repo has several issues to watch out for, however: every file must be owned by the `git` user and you *cannot* have working/staged changes in the origin repository. But that's it. Otherwise, it works fine. Ownership issues can be circumvented by treating the `git` user as `root`: not the best security practice, for sure, but fine for a team-internal server. This will let authorized users clone services with `git clone git@<box-ip>:/srv/<service>`, develop patches locally, and push their changes with `git push`.

Typically, services will need to be rebuilt for changes to be applied. While this is a nicer design for pushing *patches*, deploying those patches still means SSHing into the box, navigating to the challenge, and running `docker-compose up -d --build` or similar. Can this process be made any more streamlined?

As it turns out - Git supports has [a rich *hooks* system](https://git-scm.com/docs/githooks) that we can adapt for our purposes. These hooks can run at arbitrary points in the Git workflow process - but the two we're interested in are `pre-receive` and `post-receive`, as they are the only hooks that can take *user-specified parameters* (with the `--push-option` flag). The `pre-receive` hook runs immediately upon receiving a `git push`. The `post-receive` hook runs immediately after all new references are processed, and *only* if a reference was updated as a result. This isn't perfect - it would be convenient if we could run the hook regardless of push success, so that in case a deploy fails at first we can run another commit - but it will suffice.

Creating a custom `post-receive` hook is straightforward. The Git documentation provides an example service, which we can modify to serve our purposes:

```bash
#!/bin/sh
#
# A hook script to execute arbitrary code from push options.
# This script will run when a new push is successful and the
# --push-option flag has been used at least once.
# It will execute the commands in the push-option in sequence.

if test -n "$GIT_PUSH_OPTION_COUNT"
then
    i=0
    while test "$i" -lt "$GIT_PUSH_OPTION_COUNT"
    do # this is exceptionally ugly but needed for indirect variables
        eval "action=\$GIT_PUSH_OPTION_$i"
        echo "$action"
        eval "$action"
        i=$((i + 1))
    done
fi
```

This hook must be placed in `.git/hooks/post-receive`, and be made executable. If desired, hooks can be installed *globally* by setting the global `core.hooksPath` configuration option. This is convenient for our purposes. Now, arbitrary build commands can be executed after a (successful) push with ex. `git push --push-option="docker-compose up -d --build"`

## Configuration

With fairly minimal configuration, we can get this all set up:

1. Create a new user `git` w/ the same UID/GID as `root` and w/ `git-shell` as their login shell:
```bash
useradd -ou 0 -g 0 --system --disabled-password --create-home --shell /usr/bin/git-shell git
```

2. Generate SSH keys for the `git` user:
```bash
git ssh-keygen -t ed25519 -N '' -f /home/git/.ssh/id_ed25519
```

3. Install `authorized_keys`, disable password authentication, install `post-receive` hooks, etc:
```bash
mv authorized_keys /home/git/.ssh/authorized_keys && chmod 640 /home/git/.ssh/authorized_keys
echo "PasswordAuthentication no" >> /etc/ssh/ssh_config
mv post-receive /home/git/hooks/post-receive && chmod 777 /home/git/hooks/post-receive
```

Be sure to run `systemctl restart sshd` after making these changes.

The following settings must be made for the `git` user:
```bash
git config --global receive.denyCurrentBranch updateInstead
git config --global receive.advertisePushOptions true
git config --global core.hooksPath /home/git/hooks/
```

These settings allow pushing to non-bare repos, allow the use of `--push-option`, and allow the installation of global commit hooks.
The following settings are also recommended:
```bash
git config --global user.name "vulnbox"
git config --global user.email "vulnbox@example.com"
git config --global init.defaultBranch main
```

Now, upon the release of services, check them into Git.
If there is any mutable data, remove it from Git tracking to avoid unstaged data issues.
```bash
git init && git stage . && git commit -m "initial commit"
git rm -r --cached data/ && git commit -m "do not track mutable data"
```

And that's all you need. The SSH server will handle anyone connecting to the box via Git, and plumb them into `git-shell` so that cloning/pulling/pushing works.

If you encounter errors of the form `! [remote rejected]`, ensure that there are no uncommitted changes in any service. Be sure to remove mutable state from Git tracking to prevent this.

Hopefully this writeup is helpful to any teams new to the attack-defense format. If you find it useful, or have come up with any improvements that have worked for your team - let us know! We're contactable over [Mastodon](https://mastodon.social/@maplebaconctf), [Twitter](https://twitter.com/maplebaconctf), and [email](mailto:maple.bacon.ctf@gmail.com).
