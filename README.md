# ubcctf.github.io

Source code for Maple Bacon's team website.

## Build Instructions (Nix)

Install [Nix](https://nixos.org/download) on any Linux (WSL2 on Windows) or
macOS computer, and enable the `flakes` and `nix-command` experimental features
(`experimental-features = nix-command flakes` in `/etc/nix/nix.conf`).

Then:

```
git clone https://github.com/ubcctf/ubcctf.github.io
cd ubcctf.github.io
nix develop
```

and within the `nix develop` shell,

```
jekyll <build|serve>
```

## Build Instructions (system Ruby)

Ensure you have Ruby and Bundler installed:

```bash
ruby -v
gem install bundler
```

Clone this repository, set up bundle to install to this directory, and install
project dependencies locally.

```bash
git clone https://github.com/ubcctf/ubcctf.github.io
cd ubcctf.github.io
bundle config path 'vendor/bundle' --local
bundle install
bundle exec jekyll <build|serve>
```

## Care and feeding of the gemset

When updating gems, if you are not in a `nix develop` shell, please make sure
that you have `BUNDLE_FORCE_RUBY_PLATFORM=true` set in your environment, or in
`.bundle/config`. This works around [a bug in
bundix](https://github.com/nix-community/bundix/issues/88) by forcing the gem
infrastructure to build native extensions from source.

After changing the gems, run `lock-gems` from the `nix develop` shell (or,
`bundix -l`). This will update `gemset.nix`, used by the Nix infrastructure
to automatically grab the proper Jekyll.

## Creating a new author

Create a new file with the following contents at the path `_authors/{short_name}.md`:

* `short_name`: Your alias, must match your author file name. No spaces. This will displayed on blog posts and the article list.
* `name`: Your name or nickname for the about page.
* `position`: Categories you play in. Can be any or multiple of the following, comma separated:
    * Web
    * Crypto
    * Misc
    * Rev
    * Pwn
* `website`: Link to your website or a social media account.
* `website_title`: Pretty name of your website - the content within the \<a> tag.
* `layout`: must be `author`

Template:

```md
---
short_name: hackerman
name: John Doe
position: Web,Crypto,Misc,Rev,Pwn
website: https://www.web.site
website_title: web.site
layout: author
---
Some description.
```

Finally, open a PR.

## Creating blog posts

Create a new file with the following contents at the path `_posts/{yyyy}-{mm}-{dd}-{ctf_name}-{challenge_name}.md`:

* `layout`: must be `author`
* `title`: Name of your blog post, format is `"[{ctf_name}] {challenge_name}"`
* `author`: Authors `short_name`. Author must already exist in `_authors/`, see [creating a new author](#creating-a-new-author).

Template:

```md
---
layout: post
title: "[FakeCTF 2024] Challenge Name"
author: hackerman
---

Post contents support *markdown*!
```

If your post has any assets place them in `assets/` and link the path appropriately in the post contents.

> [!TIP]
> We should probably standardize the `assets/` format. It's currently a bit of a mess.

Finally, test the post locally and open a PR.
