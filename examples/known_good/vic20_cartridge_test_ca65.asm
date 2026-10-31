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

; Vectors ($0300-$0333)
nmi_vector  = $0318

; BASIC ROM ($c000-$dfff)
basic_warm_start_vector = $c002

; Kernal ROM ($e000-$ff89)
CINT        = $e518
RESTOR_ROM  = $fd52
RAMTAS      = $fd8d
IOINIT      = $fdf9

; Kernal entry points ($ff8a-$fff9)
GETIN   = $ffe4

    .org $a000

; Cartridge header
pydis_start:
cartridge_cold_start_vector:
    .word cartridge_cold_start                                        ; a000: 09 a0       ..
cartridge_warm_start_vector:
    .word cartridge_warm_start                                        ; a002: 24 a0       $.
cartridge_signature:
    .byte "a0CBM"                                                     ; a004: 41 30 c3... a0C

cartridge_cold_start:
    jsr RAMTAS                                                        ; a009: 20 8d fd     ..
    jsr RESTOR_ROM                                                    ; a00c: 20 52 fd     r.
    jsr IOINIT                                                        ; a00f: 20 f9 fd     ..
    jsr CINT                                                          ; a012: 20 18 e5     ..

    ; Set the NMI vector to nmi_handler
    ldx #<nmi_handler                                                 ; a015: a2 27       .'
    ldy #>nmi_handler                                                 ; a017: a0 a0       ..
    stx nmi_vector                                                    ; a019: 8e 18 03    ...
    sty nmi_vector+1                                                  ; a01c: 8c 19 03    ...

; $a01f referenced 1 time by $a022
loop_ca01f:
    jsr GETIN                                                         ; a01f: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    beq loop_ca01f                                                    ; a022: f0 fb       ..
cartridge_warm_start:
    jmp (basic_warm_start_vector)                                     ; a024: 6c 02 c0    ...

nmi_handler:
    rti                                                               ; a027: 40          @

pydis_end:

.assert (<nmi_handler) = $27, error, "Assertion failed: <nmi_handler = $27"
.assert (>nmi_handler) = $a0, error, "Assertion failed: >nmi_handler = $a0"
.assert (cartridge_cold_start) = $a009, error, "Assertion failed: cartridge_cold_start = $a009"
.assert (cartridge_warm_start) = $a024, error, "Assertion failed: cartridge_warm_start = $a024"

; Label references by decreasing frequency:
;     CINT:                      1
;     GETIN:                     1
;     IOINIT:                    1
;     RAMTAS:                    1
;     RESTOR_ROM:                1
;     basic_warm_start_vector:   1
;     loop_ca01f:                1
;     nmi_vector:                1

; Automatically generated labels:
;     loop_ca01f

; Stats:
;
;     Total size (Code + Data) = 40 bytes
;     Code                     = 31 bytes (78%)
;     Data                     = 9 bytes (22%)
;
;     Number of instructions   = 12
;     Number of data bytes     = 0 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1

