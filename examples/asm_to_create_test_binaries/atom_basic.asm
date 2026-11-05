; An Acorn Atom BASIC program in an ATM file (November 2026), for
; python/atom_basic.py, which loads it with load_atm() and marks the
; program with acorn.atom_basic_program(). Atom BASIC isn't tokenised: the
; program is a CR, then each line's number (high byte first), its text and
; a CR, ending with #FF. Its line 300 calls the machine code after it with
; LINK. (The execution address, #C2B2, is BASIC's, which runs the program.)
; Assemble with:
;
;   acme -o ../orig/atom_basic.orig atom_basic.asm

!cpu 6502

    * = $2900 - 22

; The ATM file's header
    !text "BASIC TEST"
    !fill 6, 0
    !word program, $c2b2, end - program

program
    !byte 13
    !byte 0, 10
    !text "REM AN ATOM BASIC PROGRAM"
    !byte 13
    !byte 0, 20
    !text "P.", 34, "HELLO, WORLD", 34
    !byte 13
    !byte 1, 44                         ; line 300
    !text "LINK #2950"
    !byte 13
    !byte 1, 54                         ; line 310
    !text "E."
    !byte 13
    !byte $ff

    !fill $2950 - *, 0
machine_code
    lda #'A'
    jsr $fff4
    rts
end
