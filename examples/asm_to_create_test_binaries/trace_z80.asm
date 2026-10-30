; Tracing Z80 code (October 2026), for trace_z80 (see its control file):
; - RST, with a subroutine hook for RST $08, which is followed by a data byte
;   (as on the ZX Spectrum, where it's an error code);
; - JP (IX), JR and DJNZ, including relative jumps that wrap round the top
;   and bottom of memory;
; - code copied elsewhere to run (PHASE and DEPHASE: py8dis's move()),
;   including to the top of memory;
; - expressions for an index register's displacement, an immediate value and
;   a port.
; Assemble with:
;
;   z88dk-z80asm -mz80 -b -o../orig/trace_z80.orig trace_z80.asm

    ORG $0000

count       EQU 3
ula_port    EQU $fe
copy_to     EQU $8000

start:
    di
    jp main

    DEFS $08 - ASMPC

error:                          ; RST $08: an error, whose number follows
    ex (sp),hl
    ld a,(hl)
    inc hl
    ex (sp),hl
    jr report

    DEFS $10 - ASMPC

print:                          ; RST $10
    out (ula_port),a
    ret

    DEFS $18 - ASMPC

report:
    ld (last_error),a
    jr top - $10000             ; (to the top of memory)

main:
    ld sp,$ff00
    ld a,'*'
    rst $10
    ld b,(count+1)*2
loop:
    djnz loop
    in a,(ula_port)
    ld ix,variables
    ld a,(ix+count)
    ld (ix-1),a
    ld hl,routine_source
    ld de,copy_to
    ld bc,routine_end - routine_source
    ldir
    call routine
    ld hl,done
    push hl
    ld ix,finish
    jp (ix)

done:
    rst $08
    db 5                        ; (the error number)

finish:
    halt
    jr finish

routine_source:
    PHASE copy_to
routine:
    ld a,(ix+0)
    inc a
    ret nz
    jr routine
    DEPHASE
routine_end:

last_error:
    db 0
    db 0
variables:
    db 1, 2, 3, 4

; Copied to the top of memory, $fff8-$ffff, to run there
top_source:
    PHASE $fff8
top:
    nop
    jr nz,$+$24                 ; (to the bottom of memory: main, at $001d)
    ld a,1
    or a
last:
    ret nz
    ret
    DEPHASE
