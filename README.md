# ubcctf.github.io

Source code for Maple Bacon's team website.

## Build Instructions

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

## Build Instructions (with system Ruby)

Check that you have Ruby installed and install `bundler`.

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
