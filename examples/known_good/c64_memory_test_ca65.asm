; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

    .setcpu "6502X"

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

; Constants
colour_black    = 0
colour_white    = 1

; Memory locations

; 6510 I/O port ($0000-$0001)
cpu_port = $0001

; BASIC program area ($0800-$9fff)
l4000   = $4000

; VIC-II ($d000-$d3ff)
vic_border_colour       = $d020
vic_background_colour_0 = $d021

; Kernal ROM ($e000-$ff80)
le010   = $e010

; Kernal entry points ($ff81-$fff9)
CHROUT  = $ffd2

; 6502 vectors ($fffa-$ffff)
hardware_irq_vector = $fffe

; Other memory configurations
la000   = $a000
ld000   = $d000
ld020   = $d020
le000   = $e000
lffd2   = $ffd2

; The PRG file's header: the address to load it at
    .org $07ff
    .word $0801

    .org $0801

; 10 SYS2061
pydis_start:
basic_line_10:
    .word basic_end                                                   ; 0801: 0b 08       ..
    .word 10                                                          ; 0803: 0a 00       ..
    .byte $9e                                                         ; 0805: 9e          .
    .byte "2061"                                                      ; 0806: 32 30 36... 206
    .byte 0                                                           ; 080a: 00          .
basic_end:
    .word 0                                                           ; 080b: 00 00       ..

sys_entry:
    sei                                                               ; 080d: 78          .
    lda #$35 ; '5'                                                    ; 080e: a9 35       .5
    sta cpu_port                                                      ; 0810: 85 01       .. ; Set the memory configuration to RAM, I/O ($35)
    lda #colour_black                                                 ; 0812: a9 00       ..
    sta vic_border_colour                                             ; 0814: 8d 20 d0    . P
    lda le000                                                         ; 0817: ad 00 e0    ...
    sta la000                                                         ; 081a: 8d 00 a0    ...
    jsr lffd2                                                         ; 081d: 20 d2 ff     R.
    dec cpu_port                                                      ; 0820: c6 01       F. ; Set the memory configuration to RAM only ($34)
    ldx #0                                                            ; 0822: a2 00       ..
; $0824 referenced 1 time by $082b
loop_c0824:
    lda ld000,x                                                       ; 0824: bd 00 d0    ..P
    sta l4000,x                                                       ; 0827: 9d 00 40    ..@
    inx                                                               ; 082a: e8          .
    bne loop_c0824                                                    ; 082b: d0 f7       P.
    jsr sub_c0853                                                     ; 082d: 20 53 08     s.
    inc cpu_port                                                      ; 0830: e6 01       .. ; Set the memory configuration to RAM, I/O ($35)
    lda #colour_white                                                 ; 0832: a9 01       ..
    sta vic_background_colour_0                                       ; 0834: 8d 21 d0    .!P
    lda cpu_port                                                      ; 0837: a5 01       ..
    and #$f8                                                          ; 0839: 29 f8       ).
    ora #7                                                            ; 083b: 09 07       ..
    sta cpu_port                                                      ; 083d: 85 01       .. ; Set the memory configuration to the usual one (RAM, BASIC ROM, Kernal ROM, I/O) ($37)
    lda #$61                                                          ; 083f: a9 61       .. ; A=character to output
    jsr CHROUT                                                        ; 0841: 20 d2 ff     R. ; Output $61
    jsr sub_c085a                                                     ; 0844: 20 5a 08     z.
    lda le000                                                         ; 0847: ad 00 e0    ... ; Redundant instruction?
    lda #$37 ; '7'                                                    ; 084a: a9 37       .7
    sta cpu_port                                                      ; 084c: 85 01       .. ; Set the memory configuration to the usual one (RAM, BASIC ROM, Kernal ROM, I/O) ($37)
    jsr sub_c0863                                                     ; 084e: 20 63 08     ..
    cli                                                               ; 0851: 58          x
    rts                                                               ; 0852: 60          .

; $0853 referenced 1 time by $082d
sub_c0853:
    lda ld020                                                         ; 0853: ad 20 d0    . P
    sta le000                                                         ; 0856: 8d 00 e0    ...
    rts                                                               ; 0859: 60          .

; $085a referenced 1 time by $0844
sub_c085a:
    lda #$35 ; '5'                                                    ; 085a: a9 35       .5
    sta cpu_port                                                      ; 085c: 85 01       .. ; Set the memory configuration to RAM, I/O ($35)
    rts                                                               ; 085e: 60          .

kernal_out_routine_entry:
    lda le010                                                         ; 085f: ad 10 e0    ...
    rts                                                               ; 0862: 60          .

; $0863 referenced 1 time by $084e
sub_c0863:
    lda hardware_irq_vector                                           ; 0863: ad fe ff    ...
    rts                                                               ; 0866: 60          .

pydis_end:

.assert (basic_end) = $080b, error, "Assertion failed: basic_end = $080b"

; Label references by decreasing frequency:
;     cpu_port:                  7
;     le000:                     3
;     CHROUT:                    2
;     ld020:                     2
;     lffd2:                     2
;     vic_border_colour:         2
;     hardware_irq_vector:       1
;     l4000:                     1
;     la000:                     1
;     ld000:                     1
;     le010:                     1
;     loop_c0824:                1
;     sub_c0853:                 1
;     sub_c085a:                 1
;     sub_c0863:                 1
;     vic_background_colour_0:   1

; Automatically generated labels:
;     l4000
;     le010
;     loop_c0824
;     sub_c0853
;     sub_c085a
;     sub_c0863

; Stats:
;
;     Total size (Code + Data) = 102 bytes
;     Code                     = 90 bytes (88%)
;     Data                     = 12 bytes (12%)
;
;     Number of instructions   = 41
;     Number of data bytes     = 2 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1

