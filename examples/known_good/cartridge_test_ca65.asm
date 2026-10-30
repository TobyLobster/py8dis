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
irq_vector      = $0314
brk_vector      = $0316
nmi_vector      = $0318
chrout_vector   = $0326

; BASIC ROM ($a000-$bfff)
basic_warm_start_vector = $a002

; VIC-II ($d000-$d3ff)
vic_border_colour   = $d020

; Kernal ROM ($e000-$ff80)
kernal_irq_handler  = $ea31
nbsout              = $f1ca
restor_rom          = $fd15
ramtas_rom          = $fd50
ioinit_rom          = $fda3
pcint               = $ff5b

; Kernal entry points ($ff81-$fff9)
getin   = $ffe4

    .org $8000

; Cartridge header
pydis_start:
cartridge_cold_start_vector:
    .word cartridge_cold_start                                        ; 8000: 09 80       ..
cartridge_warm_start_vector:
    .word cartridge_warm_start                                        ; 8002: 48 80       h.
cartridge_signature:
    .byte "CBM80"                                                     ; 8004: c3 c2 cd... CBM

cartridge_cold_start:
    sei                                                               ; 8009: 78          .
    jsr ioinit_rom                                                    ; 800a: 20 a3 fd     ..
    jsr ramtas_rom                                                    ; 800d: 20 50 fd     p.
    jsr restor_rom                                                    ; 8010: 20 15 fd     ..
    jsr pcint                                                         ; 8013: 20 5b ff     [.

    ; Set the NMI vector to nmi_handler
    ldx #<nmi_handler                                                 ; 8016: a2 4b       .k
    ldy #>nmi_handler                                                 ; 8018: a0 80       ..
    stx nmi_vector                                                    ; 801a: 8e 18 03    ...
    sty nmi_vector+1                                                  ; 801d: 8c 19 03    ...

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 8020: a9 50       .p
    ldx #>irq_handler                                                 ; 8022: a2 80       ..
    sta irq_vector                                                    ; 8024: 8d 14 03    ...
    stx irq_vector+1                                                  ; 8027: 8e 15 03    ...

    ; Set the BRK vector to brk_handler
    ldy #<brk_handler                                                 ; 802a: a0 4c       .l
    sty brk_vector                                                    ; 802c: 8c 16 03    ...
    ldy #>brk_handler                                                 ; 802f: a0 80       ..
    sty brk_vector+1                                                  ; 8031: 8c 17 03    ...

    ; Set the CHROUT vector to chrout_handler
    ldx #<chrout_handler                                              ; 8034: a2 4d       .m
    lda #>chrout_handler                                              ; 8036: a9 80       ..
    sta chrout_vector+1                                               ; 8038: 8d 27 03    .'.
    stx chrout_vector                                                 ; 803b: 8e 26 03    .&.

    cli                                                               ; 803e: 58          x
; $803f referenced 2 times by $8042, $8046
c803f:
    jsr getin                                                         ; 803f: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    beq c803f                                                         ; 8042: f0 fb       ..
    cmp #$51 ; 'q'                                                    ; 8044: c9 51       Iq ; A=character read
    bne c803f                                                         ; 8046: d0 f7       P.
cartridge_warm_start:
    jmp (basic_warm_start_vector)                                     ; 8048: 6c 02 a0    ...

nmi_handler:
    rti                                                               ; 804b: 40          @

brk_handler:
    rti                                                               ; 804c: 40          @

chrout_handler:
    jmp nbsout                                                        ; 804d: 4c ca f1    lJ.

irq_handler:
    inc vic_border_colour                                             ; 8050: ee 20 d0    . P
    jmp kernal_irq_handler                                            ; 8053: 4c 31 ea    l1. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

pydis_end:

.assert (<brk_handler) = $4c, error, "Assertion failed: <brk_handler = $4c"
.assert (<chrout_handler) = $4d, error, "Assertion failed: <chrout_handler = $4d"
.assert (<irq_handler) = $50, error, "Assertion failed: <irq_handler = $50"
.assert (<nmi_handler) = $4b, error, "Assertion failed: <nmi_handler = $4b"
.assert (>brk_handler) = $80, error, "Assertion failed: >brk_handler = $80"
.assert (>chrout_handler) = $80, error, "Assertion failed: >chrout_handler = $80"
.assert (>irq_handler) = $80, error, "Assertion failed: >irq_handler = $80"
.assert (>nmi_handler) = $80, error, "Assertion failed: >nmi_handler = $80"
.assert (cartridge_cold_start) = $8009, error, "Assertion failed: cartridge_cold_start = $8009"
.assert (cartridge_warm_start) = $8048, error, "Assertion failed: cartridge_warm_start = $8048"

; Label references by decreasing frequency:
;     c803f:                     2
;     basic_warm_start_vector:   1
;     brk_vector:                1
;     chrout_vector:             1
;     getin:                     1
;     ioinit_rom:                1
;     irq_vector:                1
;     kernal_irq_handler:        1
;     nbsout:                    1
;     nmi_vector:                1
;     pcint:                     1
;     ramtas_rom:                1
;     restor_rom:                1
;     vic_border_colour:         1

; Automatically generated labels:
;     c803f

; Stats:
;
;     Total size (Code + Data) = 86 bytes
;     Code                     = 77 bytes (90%)
;     Data                     = 9 bytes (10%)
;
;     Number of instructions   = 32
;     Number of data bytes     = 0 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1

