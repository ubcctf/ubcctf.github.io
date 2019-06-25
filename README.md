# ubcctf.github.io

Source code for the UBC CTF team website.


## Build Instructions

Check that you have ruby

```
ruby -v
```

Install `bundler`

```
sudo gem install bundler -v '< 2.0'
```

```
cd project_root
bundle install --path ./vendor    # Local install for just this project
bundle exec jekyll <build|serve>
```

Or if you'd like to install the dependencies globally on your system (not
recommened)

```
bundle install
```
