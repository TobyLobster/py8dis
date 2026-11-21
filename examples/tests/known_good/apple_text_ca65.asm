; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; The character map for high ASCII (for strings and character literals)
    .charmap $20, $a0 ; ' '
    .charmap $21, $a1 ; '!'
    .charmap $22, $a2 ; '"'
    .charmap $23, $a3 ; '#'
    .charmap $24, $a4 ; '$'
    .charmap $25, $a5 ; '%'
    .charmap $26, $a6 ; '&'
    .charmap $27, $a7 ; '''
    .charmap $28, $a8 ; '('
    .charmap $29, $a9 ; ')'
    .charmap $2a, $aa ; '*'
    .charmap $2b, $ab ; '+'
    .charmap $2c, $ac ; ','
    .charmap $2d, $ad ; '-'
    .charmap $2e, $ae ; '.'
    .charmap $2f, $af ; '/'
    .charmap $30, $b0 ; '0'
    .charmap $31, $b1 ; '1'
    .charmap $32, $b2 ; '2'
    .charmap $33, $b3 ; '3'
    .charmap $34, $b4 ; '4'
    .charmap $35, $b5 ; '5'
    .charmap $36, $b6 ; '6'
    .charmap $37, $b7 ; '7'
    .charmap $38, $b8 ; '8'
    .charmap $39, $b9 ; '9'
    .charmap $3a, $ba ; ':'
    .charmap $3b, $bb ; ';'
    .charmap $3c, $bc ; '<'
    .charmap $3d, $bd ; '='
    .charmap $3e, $be ; '>'
    .charmap $3f, $bf ; '?'
    .charmap $40, $c0 ; '@'
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
    .charmap $5b, $db ; '['
    .charmap $5c, $dc ; '\'
    .charmap $5d, $dd ; ']'
    .charmap $5e, $de ; '^'
    .charmap $5f, $df ; '_'
    .charmap $60, $e0 ; '`'
    .charmap $61, $e1 ; 'a'
    .charmap $62, $e2 ; 'b'
    .charmap $63, $e3 ; 'c'
    .charmap $64, $e4 ; 'd'
    .charmap $65, $e5 ; 'e'
    .charmap $66, $e6 ; 'f'
    .charmap $67, $e7 ; 'g'
    .charmap $68, $e8 ; 'h'
    .charmap $69, $e9 ; 'i'
    .charmap $6a, $ea ; 'j'
    .charmap $6b, $eb ; 'k'
    .charmap $6c, $ec ; 'l'
    .charmap $6d, $ed ; 'm'
    .charmap $6e, $ee ; 'n'
    .charmap $6f, $ef ; 'o'
    .charmap $70, $f0 ; 'p'
    .charmap $71, $f1 ; 'q'
    .charmap $72, $f2 ; 'r'
    .charmap $73, $f3 ; 's'
    .charmap $74, $f4 ; 't'
    .charmap $75, $f5 ; 'u'
    .charmap $76, $f6 ; 'v'
    .charmap $77, $f7 ; 'w'
    .charmap $78, $f8 ; 'x'
    .charmap $79, $f9 ; 'y'
    .charmap $7a, $fa ; 'z'
    .charmap $7b, $fb ; '{'
    .charmap $7c, $fc ; '|'
    .charmap $7d, $fd ; '}'
    .charmap $7e, $fe ; '~'

; Constants
cr  = 141

; Memory locations
cout = $fded

    .org $0800

pydis_start:
start:
    ldx #0                                                            ; 0800: a2 00       ".
; $0802 referenced 1 time by $080b
loop_c0802:
    lda message,x                                                     ; 0802: bd 35 08    =..
    beq c080d                                                         ; 0805: f0 06       p.
    jsr cout                                                          ; 0807: 20 ed fd    .m}
    inx                                                               ; 080a: e8          h
    bne loop_c0802                                                    ; 080b: d0 f5       Pu
; $080d referenced 1 time by $0805
c080d:
    lda #'A'                                                          ; 080d: a9 c1       )A
    jsr cout                                                          ; 080f: 20 ed fd    .m}
    lda #'"'                                                          ; 0812: a9 a2       )"
    jsr cout                                                          ; 0814: 20 ed fd    .m}
    lda #cr                                                           ; 0817: a9 8d       ).
    jsr cout                                                          ; 0819: 20 ed fd    .m}
    ldx #0                                                            ; 081c: a2 00       ".
; $081e referenced 1 time by $0829
loop_c081e:
    lda dci_message,x                                                 ; 081e: bd 4d 08    =..
    php                                                               ; 0821: 08          .
    ora #$80                                                          ; 0822: 09 80       ..
    jsr cout                                                          ; 0824: 20 ed fd    .m}
    inx                                                               ; 0827: e8          h
    plp                                                               ; 0828: 28          .
    bmi loop_c081e                                                    ; 0829: 30 f3       .s
    lda line                                                          ; 082b: ad 51 08    -..
    ldx ascii_message                                                 ; 082e: ae 56 08    ...
    ldy found_by_itself                                               ; 0831: ac 60 08    ,..
    rts                                                               ; 0834: 60          .

; $0835 referenced 1 time by $0802
message:
    .byte "SAY ", '"', "HI", '"', " TO \APPLE II!", $8d, 0            ; 0835: d3 c1 d9... SAY
; $084d referenced 1 time by $081e
dci_message:
    .byte "DON", $45                                                  ; 084d: c4 cf ce... DON
; $0851 referenced 1 time by $082b
line:
    .byte "LINE", cr                                                  ; 0851: cc c9 ce... LIN
; $0856 referenced 1 time by $082e
ascii_message:
    .byte $6c, $6f, $77, $20, $41, $53, $43, $49 ; ascii "low ASCI"   ; 0856: 6c 6f 77... low
    .byte $49, 0 ; ascii "I", $00                                     ; 085e: 49 00       I.
; $0860 referenced 1 time by $0831
found_by_itself:
    .byte "FOUND BY ITSELF"                                           ; 0860: c6 cf d5... FOU
    .byte 0                                                           ; 086f: 00          .
pydis_end:


; Label references by decreasing frequency:
;     cout:              5
;     ascii_message:     1
;     c080d:             1
;     dci_message:       1
;     found_by_itself:   1
;     line:              1
;     loop_c0802:        1
;     loop_c081e:        1
;     message:           1

; Automatically generated labels:
;     c080d
;     loop_c0802
;     loop_c081e

; Stats:
;
;     Total size (Code + Data) = 112 bytes
;     Code                     = 53 bytes (47%)
;     Data                     = 59 bytes (53%)
;
;     Number of instructions   = 24
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 58 bytes
;     Number of strings        = 5

