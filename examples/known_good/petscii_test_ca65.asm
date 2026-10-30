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
l0400   = $0400
chrout  = $ffd2

    .org $c000

pydis_start:
start:
    lda #$93                                                          ; c000: a9 93       ..
    jsr chrout                                                        ; c002: 20 d2 ff     R.
    ldx #0                                                            ; c005: a2 00       ..
; $c007 referenced 1 time by $c010
loop_cc007:
    lda lc023,x                                                       ; c007: bd 23 c0    .#.
    beq cc012                                                         ; c00a: f0 06       ..
    jsr chrout                                                        ; c00c: 20 d2 ff     R.
    inx                                                               ; c00f: e8          .
    bne loop_cc007                                                    ; c010: d0 f5       P.
; $c012 referenced 1 time by $c00a
cc012:
    ; Copy 21 bytes of memory from lc04e to l0400
    ldx #$14                                                          ; c012: a2 14       ..
; $c014 referenced 1 time by $c01b
loop_cc014:
    lda lc04e,x                                                       ; c014: bd 4e c0    .n.
    sta l0400,x                                                       ; c017: 9d 00 04    ...
    dex                                                               ; c01a: ca          J
    bpl loop_cc014                                                    ; c01b: 10 f7       ..
    lda #'a'                                                          ; c01d: a9 41       .a
    jsr chrout                                                        ; c01f: 20 d2 ff     R.
    rts                                                               ; c022: 60          .

; $c023 referenced 1 time by $c007
lc023:
    .byte $93, "Hello, World! Say ", '"', "hi", '"', $0d, 0           ; c023: 93 c8 45... .He
    .byte "cost: ", $5c, "5 ", $5e, $5f, $60, $7b, $a0, $b0, $db, $ff ; c03c: 43 4f 53... cos
    .byte 0                                                           ; c04d: 00          .
; $c04e referenced 1 time by $c014
lc04e:
    .byte 0, $20, $53, 3, $0f, $12, 5, $20, $1b ; screen "@ Score ["  ; c04e: 00 20 53... @ S
    .byte $30, $30, $30, $1d, $20, $4c, 9, $16 ; screen "000] Liv"    ; c057: 30 30 30... 000
    .byte 5, $13, $20, $33 ; screen "es 3"                            ; c05f: 05 13 20... es
    .byte $41, $53, $43, $49, $49, $20, $74, $65 ; ascii "ASCII te"   ; c063: 41 53 43... ASC
    .byte $78, $74, 0 ; ascii "xt", $00                               ; c06b: 78 74 00    xt.
    .byte "end", $80 + $78                                            ; c06e: 45 4e 44... end
    .byte "found by autostring"                                       ; c072: 46 4f 55... fou
    .byte 0                                                           ; c085: 00          .
    .byte $6f, $80 + $6b ; ascii "o", $eb                             ; c086: 6f eb       o.
pydis_end:

.assert ($80 + $6b) = $eb, error, "Assertion failed: $80 + $6b = $eb"
.assert ($80 + $78) = $f8, error, "Assertion failed: $80 + $78 = $f8"

; Label references by decreasing frequency:
;     chrout:       3
;     cc012:        1
;     l0400:        1
;     lc023:        1
;     lc04e:        1
;     loop_cc007:   1
;     loop_cc014:   1

; Automatically generated labels:
;     cc012
;     l0400
;     lc023
;     lc04e
;     loop_cc007
;     loop_cc014

; Stats:
;
;     Total size (Code + Data) = 136 bytes
;     Code                     = 35 bytes (26%)
;     Data                     = 101 bytes (74%)
;
;     Number of instructions   = 16
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 100 bytes
;     Number of strings        = 7

