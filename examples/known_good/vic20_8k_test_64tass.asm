; Text encodings (for '.text' and character literals)
    .enc "petscii"
    .cdef " @", $20
    .cdef "AZ", $c1
    .cdef "[[", $5b
    .cdef "]]", $5d
    .cdef "az", $41

; Constants
colour_red  = 2

; Memory locations

; OS workspace ($0200-$02ff)
text_colour = $0286

; Vectors ($0300-$0333)
irq_vector  = $0314

; Screen memory ($1000-$11ff)
screen_memory   = $1000

; VIC ($9000-$900f)
vic_voice3_frequency        = $900c
vic_volume_aux_colour       = $900e
vic_background_border_colour = $900f

; VIA 1 ($9110-$911f)
via1_port_a             = $9111
via1_data_direction_a   = $9113

; VIA 2 ($9120-$912f)
via2_port_b = $9120
via2_port_a = $9121

; Colour RAM ($9400-$95ff)
colour_ram  = $9400

; BASIC ROM ($c000-$dfff)
basic_print_string  = $cb1e
basic_print_number  = $ddcd

; Kernal ROM ($e000-$ff89)
kernal_irq_handler  = $eabf

; Kernal entry points ($ff8a-$fff9)
chrout  = $ffd2
getin   = $ffe4
plot    = $fff0

; The PRG file's header: the address to load it at
    * = $11ff
    .word $1201

    * = $1201

; 10 SYS4621
pydis_start
basic_line_10
    .word basic_end                                                   ; 1201: 0b 12       ..
    .word 10                                                          ; 1203: 0a 00       ..
    .byte $9e                                                         ; 1205: 9e          .
    .text "4621"                                                      ; 1206: 34 36 32... 462
    .byte 0                                                           ; 120a: 00          .
basic_end
    .word 0                                                           ; 120b: 00 00       ..

sys_entry
    sei                                                               ; 120d: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 120e: a9 81       ..
    sta irq_vector                                                    ; 1210: 8d 14 03    ...
    lda #>irq_handler                                                 ; 1213: a9 12       ..
    sta irq_vector+1                                                  ; 1215: 8d 15 03    ...

    cli                                                               ; 1218: 58          x
    lda #8                                                            ; 1219: a9 08       ..
    sta vic_background_border_colour                                  ; 121b: 8d 0f 90    ...
    lda #$0f                                                          ; 121e: a9 0f       ..
    sta vic_volume_aux_colour                                         ; 1220: 8d 0e 90    ...
    lda #$c8 ; 'H'                                                    ; 1223: a9 c8       .H
    sta vic_voice3_frequency                                          ; 1225: 8d 0c 90    ...
    lda #colour_red                                                   ; 1228: a9 02       ..
    sta text_colour                                                   ; 122a: 8d 86 02    ...
    lda #$93                                                          ; 122d: a9 93       .. ; A=character to output
    jsr chrout                                                        ; 122f: 20 d2 ff     R. ; Output $93 (clear screen)
    ldx #0                                                            ; 1232: a2 00       ..
; $1234 referenced 1 time by $123d
loop_c1234
    lda l1287,x                                                       ; 1234: bd 87 12    ... ; A=character to output
    beq c123f                                                         ; 1237: f0 06       ..
    jsr chrout                                                        ; 1239: 20 d2 ff     R. ; Output a character
    inx                                                               ; 123c: e8          .
    bne loop_c1234                                                    ; 123d: d0 f5       P.
; $123f referenced 1 time by $1237
c123f
    clc                                                               ; 123f: 18          .
    ldx #$0a                                                          ; 1240: a2 0a       .. ; X=cursor row
    ldy #5                                                            ; 1242: a0 05       .. ; Y=cursor column
    jsr plot                                                          ; 1244: 20 f0 ff     .. ; Move the cursor to row 10, column 5
    ldx #$15                                                          ; 1247: a2 15       ..
; $1249 referenced 1 time by $1254
loop_c1249
    lda #$51 ; 'q'                                                    ; 1249: a9 51       .q
    sta screen_memory,x                                               ; 124b: 9d 00 10    ...
    lda #6                                                            ; 124e: a9 06       ..
    sta colour_ram,x                                                  ; 1250: 9d 00 94    ...
    dex                                                               ; 1253: ca          J
    bpl loop_c1249                                                    ; 1254: 10 f3       ..
    lda #0                                                            ; 1256: a9 00       ..
    sta via1_data_direction_a                                         ; 1258: 8d 13 91    ...
    lda via1_port_a                                                   ; 125b: ad 11 91    ...
    sta l129e                                                         ; 125e: 8d 9e 12    ...
    lda #$7f                                                          ; 1261: a9 7f       ..
    sta via2_port_b                                                   ; 1263: 8d 20 91    . .
    lda via2_port_a                                                   ; 1266: ad 21 91    .!.
    sta l129f                                                         ; 1269: 8d 9f 12    ...
    jsr getin                                                         ; 126c: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    sta l12a0                                                         ; 126f: 8d a0 12    ... ; A=character read
    lda #<l128f                                                       ; 1272: a9 8f       .. ; A=string address (low byte)
    ldy #>l128f                                                       ; 1274: a0 12       .. ; Y=string address (high byte)
    jsr basic_print_string                                            ; 1276: 20 1e cb     .K ; Print the zero-terminated string at A/Y
    lda #0                                                            ; 1279: a9 00       .. ; A=number to print (high byte)
    ldx #$14                                                          ; 127b: a2 14       .. ; X=number to print (low byte)
    jsr basic_print_number                                            ; 127d: 20 cd dd     M. ; Print the 16-bit number in A/X
    rts                                                               ; 1280: 60          .

irq_handler
    inc vic_background_border_colour                                  ; 1281: ee 0f 90    ...
    jmp kernal_irq_handler                                            ; 1284: 4c bf ea    l.. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

; $1287 referenced 1 time by $1234
l1287
    .text "vic-20"                                                    ; 1287: 56 49 43... vic
    .byte $0d, 0                                                      ; 128d: 0d 00       ..
l128f
    .text "the answer is ", 0                                         ; 128f: 54 48 45... the
; $129e referenced 1 time by $125e
l129e
    .byte 0                                                           ; 129e: 00          .
; $129f referenced 1 time by $1269
l129f
    .byte 0                                                           ; 129f: 00          .
; $12a0 referenced 1 time by $126f
l12a0
    .byte 0                                                           ; 12a0: 00          .
pydis_end

.cerror (<irq_handler) != $81, "Assertion failed: <irq_handler == $81"
.cerror (<l128f) != $8f, "Assertion failed: <l128f == $8f"
.cerror (>irq_handler) != $12, "Assertion failed: >irq_handler == $12"
.cerror (>l128f) != $12, "Assertion failed: >l128f == $12"
.cerror (basic_end) != $120b, "Assertion failed: basic_end == $120b"

; Label references by decreasing frequency:
;     chrout:                         2
;     vic_background_border_colour:   2
;     basic_print_number:             1
;     basic_print_string:             1
;     c123f:                          1
;     colour_ram:                     1
;     getin:                          1
;     irq_vector:                     1
;     kernal_irq_handler:             1
;     l1287:                          1
;     l129e:                          1
;     l129f:                          1
;     l12a0:                          1
;     loop_c1234:                     1
;     loop_c1249:                     1
;     plot:                           1
;     screen_memory:                  1
;     text_colour:                    1
;     via1_data_direction_a:          1
;     via1_port_a:                    1
;     via2_port_a:                    1
;     via2_port_b:                    1
;     vic_voice3_frequency:           1
;     vic_volume_aux_colour:          1

; Automatically generated labels:
;     c123f
;     l1287
;     l128f
;     l129e
;     l129f
;     l12a0
;     loop_c1234
;     loop_c1249

; Stats:
;
;     Total size (Code + Data) = 160 bytes
;     Code                     = 122 bytes (76%)
;     Data                     = 38 bytes (24%)
;
;     Number of instructions   = 52
;     Number of data bytes     = 7 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 25 bytes
;     Number of strings        = 3

