; A Plus/4 program, for python/plus4_basic.py: its BASIC program uses BASIC
; 3.5's keywords ($ce is RLUM, not a C128 prefix). Assemble with:
;
;   acme -f cbm -o ../orig/plus4_basic.orig plus4_basic.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6502

    * = $1001

; The BASIC program: 10 GRAPHIC1:PRINT RLUM(1):SYS4119
line_10
    !word basic_end
    !word 10
    !byte $de               ; GRAPHIC
    !pet "1:"
    !byte $99               ; PRINT
    !pet " "
    !byte $ce               ; RLUM
    !pet "(1):"
    !byte $9e               ; SYS
    !pet "4119", 0
basic_end
    !word 0

start
    rts
