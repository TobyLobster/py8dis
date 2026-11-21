; A C128 program, for python/c128_fixes.py: its BASIC program uses BASIC
; 7.0's keywords, including two-byte ones ($fe $02 BANK, $fe $25 FAST, $ce
; $08 XOR), and it sets the MMU to a configuration with bit 0 set and the
; internal function ROM at $c000-$ffff, so that $d000-$dfff is that ROM
; rather than the character ROM. Assemble with:
;
;   acme -f cbm -o ../orig/c128_fixes.orig c128_fixes.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6502

    * = $1c01

; The BASIC program: 10 BANK15:FAST:SYS7205, 20 PRINT XOR(1,2):GRAPHIC1
line_10
    !word line_20
    !word 10
    !byte $fe, $02          ; BANK
    !pet "15:"
    !byte $fe, $25          ; FAST
    !pet ":"
    !byte $9e               ; SYS
    !pet "7205", 0
line_20
    !word basic_end
    !word 20
    !byte $99               ; PRINT
    !byte $ce, $08          ; XOR
    !pet "(1,2):"
    !byte $de               ; GRAPHIC
    !pet "1", 0
basic_end
    !word 0

start
    ; RAM 0, the internal function ROM at $8000-$ffff, and bit 0 set: the
    ; internal function ROM at $d000-$dfff too
    lda #$17
    sta $ff00
    lda $d000
    sta $fb
    lda #0                  ; bank 15
    sta $ff00
    rts
