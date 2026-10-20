; Regression tests for the z88dk-8080 expression operators (October 2026).
; Assemble with: z88dk-z80asm -m8080 -b -o../orig/regression_tests_8080.orig regression_tests_8080.asm
; The control file (python/regression_tests_8080.py) replaces each immediate
; operand with an expression that evaluates to the same value.

    ORG $1000

    mvi a, $80      ; (~low_seven_bits) & $ff
    ani $30         ; x_val & y_val
    ori $fc         ; x_val | y_val
    xri $cc         ; x_val ^ y_val
    mvi b, $0f      ; x_val / 16
    mvi c, $02      ; x_val % 7
    ret
