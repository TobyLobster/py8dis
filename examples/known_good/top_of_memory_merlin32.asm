; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l0020   equ $20

; Other
l412c   equ $412c

    org $ffe0

pydis_start
start
    ldx #$80                                                          ; ffe0: a2 80       ..
    dfb $30, {l0020-*-2} & $ff ; bmi l0020 (a branch that wraps round memory) ; ffe2: 30 3c       0< ; ALWAYS branch

    jmp cfffd                                                         ; ffe4: 4c fd ff    L..

    asc 'THE TOP OF MEMORY'                                           ; ffe7: 54 48 45... THE
    dfb 0, 0, 0, 0, 0                                                 ; fff8: 00 00 00... ...

; $fffd referenced 1 time by $ffe4
cfffd
    bit l412c                                                         ; fffd: 2c 2c 41    ,,A
pydis_end


; Label references by decreasing frequency:
;     cfffd:   1
;     l0020:   1
;     l412c:   1

; Automatically generated labels:
;     cfffd
;     l0020
;     l412c

; Stats:
;
;     Total size (Code + Data) = 32 bytes
;     Code                     = 10 bytes (31%)
;     Data                     = 22 bytes (69%)
;
;     Number of instructions   = 4
;     Number of data bytes     = 5 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 17 bytes
;     Number of strings        = 1
