---
layout: post
title: "[RedPwnCTF 2020] Viper"
author: Vie
---

# TL;DR

1. Steal admin CSRF token from `/analytics`
2. Poison redis cache with a viper page that fires a request to `admin/create` to modify viper page
3. Report viper page to admin
4. Revisit viper page after admin to get flag

The full challenge writeup can be found [here](https://jamvie.net/posts/2020/07/redpwnctf-2020-part-3/).

