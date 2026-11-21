; A Z80 program for python/crash_fixes_z80.py, with things that used to
; stop py8dis with an error of its own (a Python exception): an expr() on
; the address in an instruction with a prefix (four bytes long), and an
; instruction cut off by the end of the loaded data. Assemble with:
;
;   z88dk-z80asm -mz80 -b -o../orig/crash_fixes_z80.orig crash_fixes_z80.asm
;
; (It isn't meant to do anything useful when run.)

    ORG $8000

start:
    ld hl,(table)           ; three bytes: the address is bytes 1-2
    ld ix,(table+2)         ; DD 2A: four bytes, the address is bytes 2-3
    ld (table+2),bc         ; ED 43: four bytes too
    ld iy,(table)           ; FD 2A
    ret

table:
    defw $1234, $5678

; An instruction cut off by the end of the data: 'ld ix,$xx34' needs four
; bytes, but only three are loaded (the control file traces it)
cut_off:
    defb $dd, $21, $34
