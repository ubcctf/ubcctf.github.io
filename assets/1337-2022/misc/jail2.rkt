#lang racket

; Just a conversion function
(define (datum->string d)
  (cond
    [(string? d) d]
    [(number? d) (number->string d)]
    [(symbol? d) (symbol->string d)]
    [else (error "datum->string: not a terminal")]))

; None of these functions are allowed this time! No easy escape tools!
(define (strictly-forbidden? x)
  (ormap (curry string-contains? x) 
         (list "system" "process" "read-eval-print-loop" "shell-execute")))

; Have you used your one exception?
(define has-seen-allowed-exception #f)

; A string is allowed if it it is one of:
; - A single character in length 
; - A string containing "string" (https://docs.racket-lang.org/reference/strings.html)
; - A string containing "quote" (https://docs.racket-lang.org/guide/quote.html https://docs.racket-lang.org/guide/qq.html)
; Hint: https://cadence.moe/blog/2022-10-17-explaining-lisp-quoting-without-getting-tangled 
(define (allowed? term)
  (or (string-contains? term "string") 
      (string-contains? term "quote")
      (eq? (string-length term) 1)))

; Check that each term follows the requirements
(define (check term)
  (printf "check: ~a (has-seen-allowed-exception ~a) \n" term has-seen-allowed-exception)
  (cond
    ; Never allow any strictly forbidden terms
    [(strictly-forbidden? term) #f]
    ; Check if the term is allowed
    [(allowed? term) #t]
    ; You're allowed to have ONE term that is not normally allowed! Use it wisely
    [has-seen-allowed-exception #f]
    [else
     (begin
       (set! has-seen-allowed-exception #t)
       #t)]))

; Walk down the syntax tree to check that everything follows the requirements
(define (valid stx)
  (match stx
    [`(,xs ...) (andmap valid xs)]
    [x (check (datum->string x))]))

(define (jail)
  ; Prepare the jail namespace
  (parameterize ([current-namespace (make-base-namespace)])
    ; Inside your jail you have racket/system and racket/base
    ; https://docs.racket-lang.org/reference/subprocess.html#%28mod-path._racket%2Fsystem%29
    (namespace-require 'racket/system)
    (printf "> ")
    (let ([stx (syntax->datum (read-syntax))])
      (printf "Your input: ~a\n" stx)
      ; Check the given racket expression
      (if (valid stx) 
          ; if it's valid, eval it https://docs.racket-lang.org/guide/eval.html
          (begin
            (flush-output) ; this is just to make sure the previous print statements are flushd to stdout before the eval command runs
            (printf "Result: ~a \n" (eval stx)))
          (printf "Invalid input: ~a \n" stx)))))

(module+ main
  (displayln "Well done escaping out of that last jail, but there's no way you'll get out of this one!")
  (displayln "We've taken away all of your escape tools so there should be no way of escaping")
  (displayln "PS: Warden Gregor felt bad for you so he said to give you one exception to our rules, it's not like you can escape with just one exception anyway")
  (displayln "Hint: Successfully run the `get-flag` command to obtain the flag")
  (jail)
  (displayln "Exiting"))