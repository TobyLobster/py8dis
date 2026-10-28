; An 8080 program that copies a routine to $8000 and calls it there, for
; python/move_8080.py, which uses move() and include_binary_file() with
; z88dk-z80asm (as PHASE/DEPHASE and BINARY). Assemble with:
;
;   z88dk-z80asm -m8080 -b -o../orig/move_8080.orig move_8080.asm
;
; and the table at the end on its own (for include_binary_file()) with:
;
;   dd if=../orig/move_8080.orig of=../orig/move_8080_table.bin bs=1 skip=32

    ORG $0100

start:
    lxi h, copy_source
    lxi d, $8000
    mvi b, copy_end - copy_source
copy_loop:
    mov a, m
    stax d
    inx h
    inx d
    dcr b
    jnz copy_loop
    call routine
    hlt

copy_source:
    PHASE $8000
routine:
    lxi h, table
    mvi b, 4
loop:
    mov a, m
    inx h
    dcr b
    jnz loop
    ret
    DEPHASE
copy_end:

table:
    defb 1, 2, 4, 8
