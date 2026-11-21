; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; The character map for PETSCII (for strings and character literals)
    .charmap $41, $c1 ; 'A'
    .charmap $42, $c2 ; 'B'
    .charmap $43, $c3 ; 'C'
    .charmap $44, $c4 ; 'D'
    .charmap $45, $c5 ; 'E'
    .charmap $46, $c6 ; 'F'
    .charmap $47, $c7 ; 'G'
    .charmap $48, $c8 ; 'H'
    .charmap $49, $c9 ; 'I'
    .charmap $4a, $ca ; 'J'
    .charmap $4b, $cb ; 'K'
    .charmap $4c, $cc ; 'L'
    .charmap $4d, $cd ; 'M'
    .charmap $4e, $ce ; 'N'
    .charmap $4f, $cf ; 'O'
    .charmap $50, $d0 ; 'P'
    .charmap $51, $d1 ; 'Q'
    .charmap $52, $d2 ; 'R'
    .charmap $53, $d3 ; 'S'
    .charmap $54, $d4 ; 'T'
    .charmap $55, $d5 ; 'U'
    .charmap $56, $d6 ; 'V'
    .charmap $57, $d7 ; 'W'
    .charmap $58, $d8 ; 'X'
    .charmap $59, $d9 ; 'Y'
    .charmap $5a, $da ; 'Z'
    .charmap $61, $41 ; 'a'
    .charmap $62, $42 ; 'b'
    .charmap $63, $43 ; 'c'
    .charmap $64, $44 ; 'd'
    .charmap $65, $45 ; 'e'
    .charmap $66, $46 ; 'f'
    .charmap $67, $47 ; 'g'
    .charmap $68, $48 ; 'h'
    .charmap $69, $49 ; 'i'
    .charmap $6a, $4a ; 'j'
    .charmap $6b, $4b ; 'k'
    .charmap $6c, $4c ; 'l'
    .charmap $6d, $4d ; 'm'
    .charmap $6e, $4e ; 'n'
    .charmap $6f, $4f ; 'o'
    .charmap $70, $50 ; 'p'
    .charmap $71, $51 ; 'q'
    .charmap $72, $52 ; 'r'
    .charmap $73, $53 ; 's'
    .charmap $74, $54 ; 't'
    .charmap $75, $55 ; 'u'
    .charmap $76, $56 ; 'v'
    .charmap $77, $57 ; 'w'
    .charmap $78, $58 ; 'x'
    .charmap $79, $59 ; 'y'
    .charmap $7a, $5a ; 'z'

; The PRG file's header: the address to load it at
    .org $0fff
    .word $1001

    .org $1001

; 10 GRAPHIC1:PRINT RLUM(1):SYS4119
pydis_start:
basic_line_10:
    .word basic_end                                                   ; 1001: 15 10       ..
    .word 10                                                          ; 1003: 0a 00       ..
    .byte $de                                                         ; 1005: de          .
    .byte "1:"                                                        ; 1006: 31 3a       1:
    .byte $99                                                         ; 1008: 99          .
    .byte " "                                                         ; 1009: 20
    .byte $ce                                                         ; 100a: ce          N
    .byte "(1):"                                                      ; 100b: 28 31 29... (1)
    .byte $9e                                                         ; 100f: 9e          .
    .byte "4119"                                                      ; 1010: 34 31 31... 411
    .byte 0                                                           ; 1014: 00          .
basic_end:
    .word 0                                                           ; 1015: 00 00       ..

sys_entry:
    rts                                                               ; 1017: 60          .

pydis_end:

.assert (basic_end) = $1015, error, "Assertion failed: basic_end = $1015"

; Stats:
;
;     Total size (Code + Data) = 23 bytes
;     Code                     = 1 bytes (4%)
;     Data                     = 22 bytes (96%)
;
;     Number of instructions   = 1
;     Number of data bytes     = 5 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 11 bytes
;     Number of strings        = 4

