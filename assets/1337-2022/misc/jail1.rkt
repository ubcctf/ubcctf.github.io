#lang racket

(define (jail)
  ; Prepare the jail namespace
  (parameterize ([current-namespace (make-base-namespace)])
    ; Inside your jail you have racket/system and racket/base
    ; https://docs.racket-lang.org/reference/subprocess.html#%28mod-path._racket%2Fsystem%29
    (namespace-require 'racket/system)
    (printf "> ")
    (let ([stx (syntax->datum (read-syntax))])
      (printf "Your input: ~a\n" stx)
      (printf "Result: ~a \n" (eval stx)))))

(module+ main
  (displayln "Welcome to Racket jail, where people who complain about the usage of Racket in 110 are sentenced to, forced to live in a Racket REPL for all eternity")
  (displayln "'Racket has no practical uses' you say? Well you better learn about some practical uses if you wanna escape!\n")
  (displayln "Hint: Successfully run the `get-flag` command in a shell to obtain the flag. You'll need to escape from Racket into the system shell in order to do it")
  (jail)
  (displayln "Exiting"))