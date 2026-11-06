; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations
lfff2   equ $fff2

    org $0000

pydis_start
start
    nop                                                               ; 0000: ea          .
    nop                                                               ; 0001: ea          .
    dfb $30, {lfff2-*-2} & $ff ; bmi lfff2 (a branch that wraps round memory) ; 0002: 30 ee       0.
    rts                                                               ; 0004: 60          `

pydis_end


; Label references by decreasing frequency:
;     lfff2:   1

; Automatically generated labels:
;     lfff2

; Stats:
;
;     Total size (Code + Data) = 5 bytes
;     Code                     = 5 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 4
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
