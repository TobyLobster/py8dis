; Two banks of code that both run at $8000, and the main program that calls
; them, for python/banks_z80.py (as banks_test.asm is for the 6502). The
; three parts are at $1000, $2000 and $3000 in the file (which starts at
; $1000), and the control file loads each part separately, so that there are
; gaps between them. Assemble with:
;
;   z88dk-z80asm -mz80 -b -o../orig/banks_z80.orig banks_z80.asm

bank_select = $5b00

    ORG $1000

main:
    ld a,0
    ld (bank_select),a
    call $8000          ; (bank A's entry point)
    ld a,1
    ld (bank_select),a
    call $8000          ; (bank B's entry point)
    ret
main_end:
    DEFS $1000 - (main_end - main)

bank_a_start:
    PHASE $8000
bank_a:
    call a_print
    ret
a_print:
    ld hl,a_text
a_loop:
    ld a,(hl)
    or a
    ret z
    rst $10
    inc hl
    jr a_loop
a_text:
    DEFM "Bank A", 13, 0
    DEPHASE
bank_a_end:
    DEFS $1000 - (bank_a_end - bank_a_start)

    PHASE $8000
bank_b:
    jp b_start
b_text:
    DEFM "Bank B", 13, 0
b_start:
    ld hl,b_text
b_loop:
    ld a,(hl)
    or a
    ret z
    rst $10
    inc hl
    jr b_loop
    DEPHASE
