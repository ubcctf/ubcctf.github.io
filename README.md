# ubcctf.github.io

Source code for the UBC CTF team website.


## Build Instructions

Check that you have ruby

```
ruby -v
```

Install `bundler`. *We depend on version < 2.0 currently because of our Gemfile.lock. If we switch to > 2.0 then everyone contributing will have to upgrade as well.*

```
sudo gem install bundler -v '< 2.0'
```

Install project dependencies locally

```bash
cd project_root
bundle install
bundle exec jekyll <build|serve>
```