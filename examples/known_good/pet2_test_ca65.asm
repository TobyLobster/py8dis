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
irq_vector              = $0090
keyboard_buffer_length  = $009e
reverse_flag            = $009f

; Screen memory ($8000-$83e7)
screen_memory   = $8000

; BASIC ROM ($c000-$dfff)
basic_print_string  = $ca1c
basic_print_number  = $dcd9

; Screen editor ROM ($e000-$e7ff)
kernal_irq_handler  = $e62e

; PIA 1 ($e810-$e813)
pia1_port_a = $e810
pia1_port_b = $e812

; VIA ($e840-$e84f)
via_peripheral_control  = $e84c

; Kernal entry points ($ffc0-$fff9)
CLRCHN  = $ffcc
CHROUT  = $ffd2
STOP    = $ffe1
GETIN   = $ffe4

; The PRG file's header: the address to load it at
    .org $03ff
    .word $0401

    .org $0401

; 10 SYS1056
pydis_start:
basic_line_10:
    .word basic_end                                                   ; 0401: 0b 04       ..
    .word 10                                                          ; 0403: 0a 00       ..
    .byte $9e                                                         ; 0405: 9e          .
    .byte "1056"                                                      ; 0406: 31 30 35... 105
    .byte 0                                                           ; 040a: 00          .
basic_end:
    .word 0                                                           ; 040b: 00 00       ..
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0     ; 040d: 00 00 00... ...

sys_entry:
    lda #$93                                                          ; 0420: a9 93       .. ; A=character to output
    jsr CHROUT                                                        ; 0422: 20 d2 ff     R. ; Output $93 (clear screen)
    lda #<l046e                                                       ; 0425: a9 6e       .. ; A=string address (low byte)
    ldy #>l046e                                                       ; 0427: a0 04       .. ; Y=string address (high byte)
    jsr basic_print_string                                            ; 0429: 20 1c ca     .J ; Print the zero-terminated string at A/Y
    lda #4                                                            ; 042c: a9 04       .. ; A=number to print (high byte)
    ldx #$d2 ; 'R'                                                    ; 042e: a2 d2       .R ; X=number to print (low byte)
    jsr basic_print_number                                            ; 0430: 20 d9 dc     Y. ; Print the 16-bit number in A/X
    sei                                                               ; 0433: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 0434: a9 68       ..
    sta irq_vector                                                    ; 0436: 85 90       ..
    lda #>irq_handler                                                 ; 0438: a9 04       ..
    sta irq_vector+1                                                  ; 043a: 85 91       ..

    cli                                                               ; 043c: 58          x
    lda #$0e                                                          ; 043d: a9 0e       ..
    sta via_peripheral_control                                        ; 043f: 8d 4c e8    .l.
    lda #1                                                            ; 0442: a9 01       ..
    sta reverse_flag                                                  ; 0444: 85 9f       ..
    lda #$61                                                          ; 0446: a9 61       ..
    sta screen_memory                                                 ; 0448: 8d 00 80    ...
    lda #0                                                            ; 044b: a9 00       ..
    sta keyboard_buffer_length                                        ; 044d: 85 9e       ..
; $044f referenced 1 time by $0457
loop_c044f:
    jsr STOP                                                          ; 044f: 20 e1 ff     .. ; Check the STOP key (Z set if it's pressed)
    beq c045c                                                         ; 0452: f0 08       ..
    jsr GETIN                                                         ; 0454: 20 e4 ff     .. ; Get a character from the keyboard buffer (0 if there's none)
    beq loop_c044f                                                    ; 0457: f0 f6       ..
    jsr CHROUT                                                        ; 0459: 20 d2 ff     R. ; Output a character
; $045c referenced 1 time by $0452
c045c:
    jsr CLRCHN                                                        ; 045c: 20 cc ff     L. ; Restore the default input and output (keyboard and screen)
    lda #9                                                            ; 045f: a9 09       ..
    sta pia1_port_a                                                   ; 0461: 8d 10 e8    ...
    lda pia1_port_b                                                   ; 0464: ad 12 e8    ...
    rts                                                               ; 0467: 60          .

irq_handler:
    inc screen_memory+39                                              ; 0468: ee 27 80    .'.
    jmp kernal_irq_handler                                            ; 046b: 4c 2e e6    l.. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

l046e:
    .byte "hello, pet", $0d, 0                                        ; 046e: 48 45 4c... hel
pydis_end:

.assert (<irq_handler) = $68, error, "Assertion failed: <irq_handler = $68"
.assert (<l046e) = $6e, error, "Assertion failed: <l046e = $6e"
.assert (>irq_handler) = $04, error, "Assertion failed: >irq_handler = $04"
.assert (>l046e) = $04, error, "Assertion failed: >l046e = $04"
.assert (basic_end) = $040b, error, "Assertion failed: basic_end = $040b"

; Label references by decreasing frequency:
;     CHROUT:                   2
;     CLRCHN:                   1
;     GETIN:                    1
;     STOP:                     1
;     basic_print_number:       1
;     basic_print_string:       1
;     c045c:                    1
;     irq_vector:               1
;     kernal_irq_handler:       1
;     keyboard_buffer_length:   1
;     loop_c044f:               1
;     pia1_port_a:              1
;     pia1_port_b:              1
;     reverse_flag:             1
;     screen_memory:            1
;     via_peripheral_control:   1

; Automatically generated labels:
;     c045c
;     l046e
;     loop_c044f

; Stats:
;
;     Total size (Code + Data) = 121 bytes
;     Code                     = 78 bytes (64%)
;     Data                     = 43 bytes (36%)
;
;     Number of instructions   = 34
;     Number of data bytes     = 21 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 16 bytes
;     Number of strings        = 2

