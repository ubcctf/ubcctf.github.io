# ubcctf.github.io

Source code for Maple Bacon's team website.

## Build Instructions

Check that you have Ruby installed and install `bundler`.

```bash
ruby -v
gem install bundler
```

Add `gem` binaries to PATH and set GEM_HOME to a writable location.

```bash
# Linux (in `.bash_profile`):
export PATH="$PATH:$HOME/.local/share/gem/ruby/3.0.0/bin"
export GEM_HOME="$HOME/.gems"
```

Clone this repository and install project dependencies locally.

```bash
git clone https://github.com/ubcctf/ubcctf.github.io
cd ubcctf.github.io
bundle install
bundle exec jekyll <build|serve>
```
