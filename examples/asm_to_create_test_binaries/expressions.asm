; Test data for expressions.py (the bracketing of expressions, October 2026).
; Assemble with: acme -o ../orig/expressions.orig expressions.asm
; Each byte (or word) is the value of an expression given to expr() in the
; control file, which says what each one tests.

    * = $2000

    !byte $35       ; <(table + 1)
    !byte $13       ; (>table) + 1
    !byte $00       ; (255 - k) EOR 128
    !byte $06       ; a + b + c                (built as (a + b) + c)
    !byte $06       ; a + b + c                (built as a + (b + c))
    !byte $0b       ; ten - (b - c)
    !byte $0b       ; x * 2 + 1
    !byte $0f       ; x * (2 + 1)
    !byte $f0       ; NOT(m) AND $ff
    !byte $3c       ; (p OR q) AND r
    !byte $3f       ; p OR (q AND r)
    !byte $34       ; (<table) AND $7f
    !byte $20       ; (p+1) * 2                (a user's expression string)
    !byte $13       ; >(table + $100)
    !byte $03       ; p EOR q EOR r            (built as p EOR (q EOR r))
    !byte $0f       ; p OR (q EOR r)
    !byte $12       ; (table >> 8) AND $ff
    !byte $09       ; (1 << 3) + 1
    !byte $02       ; x DIV 2
    !word $1233     ; table - 1
