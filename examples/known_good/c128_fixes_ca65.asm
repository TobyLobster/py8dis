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

; Memory locations

; Zero page ($0000-$00ff)
l00fb   = $00fb

; MMU ($ff00-$ff04)
mmu_configuration   = $ff00

; Other banks
ld000   = $d000

; The PRG file's header: the address to load it at
    .org $1bff
    .word $1c01

    .org $1c01

; 10 BANK15:FAST:SYS7205
pydis_start:
basic_line_10:
    .word basic_line_20                                               ; 1c01: 13 1c       ..
    .word 10                                                          ; 1c03: 0a 00       ..
    .byte $fe                                                         ; 1c05: fe          .
    .byte 2                                                           ; 1c06: 02          .
    .byte "15:"                                                       ; 1c07: 31 35 3a    15:
    .byte $fe                                                         ; 1c0a: fe          .
    .byte "%:"                                                        ; 1c0b: 25 3a       %:
    .byte $9e                                                         ; 1c0d: 9e          .
    .byte "7205"                                                      ; 1c0e: 37 32 30... 720
    .byte 0                                                           ; 1c12: 00          .
; 20 PRINTXOR(1,2):GRAPHIC1
basic_line_20:
    .word basic_end                                                   ; 1c13: 23 1c       #.
    .word 20                                                          ; 1c15: 14 00       ..
    .byte $99                                                         ; 1c17: 99          .
    .byte $ce                                                         ; 1c18: ce          N
    .byte 8                                                           ; 1c19: 08          .
    .byte "(1,2):"                                                    ; 1c1a: 28 31 2c... (1,
    .byte $de                                                         ; 1c20: de          .
    .byte "1"                                                         ; 1c21: 31          1
    .byte 0                                                           ; 1c22: 00          .
basic_end:
    .word 0                                                           ; 1c23: 00 00       ..

sys_entry:
    lda #$17                                                          ; 1c25: a9 17       ..
    sta mmu_configuration                                             ; 1c27: 8d 00 ff    ... ; Set the MMU to RAM 0, internal function ROM at $8000-$ffff
    lda ld000                                                         ; 1c2a: ad 00 d0    ..P
    sta l00fb                                                         ; 1c2d: 85 fb       ..
    lda #0                                                            ; 1c2f: a9 00       ..
    sta mmu_configuration                                             ; 1c31: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    rts                                                               ; 1c34: 60          .

pydis_end:

.assert (basic_end) = $1c23, error, "Assertion failed: basic_end = $1c23"
.assert (basic_line_20) = $1c13, error, "Assertion failed: basic_line_20 = $1c13"

; Label references by decreasing frequency:
;     mmu_configuration:   2
;     l00fb:               1
;     ld000:               1

; Automatically generated labels:
;     l00fb

; Stats:
;
;     Total size (Code + Data) = 52 bytes
;     Code                     = 16 bytes (31%)
;     Data                     = 36 bytes (69%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 10 bytes
;     Number of data words     = 10 bytes
;     Number of string bytes   = 16 bytes
;     Number of strings        = 5

