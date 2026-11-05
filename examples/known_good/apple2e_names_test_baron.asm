; Assemble with Baron, which writes the program to the file named in its
; section (apple2e_names_test_baron), in the folder given with -p:
;     baron -p . apple2e_names_test_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0006           = &0006
l0007           = &0007
cursor_column   = &0024
cursor_row      = &0025
text_mask       = &0032
output_hook     = &0036
monitor_a1      = &003c
monitor_a2      = &003e
monitor_a4      = &0042

; Stack (&0100-&01ff)
l0100   = &0100

; Input buffer (&0200-&02ff)
input_buffer = &0200

; Vectors (&03f0-&03ff)
reset_vector = &03f2
irq_vector  = &03fe

; Soft switches (&c000-&c07f)
keyboard                = &c000
keyboard_strobe         = &c010
is_not_vertical_blank   = &c019
speaker                 = &c030
show_graphics           = &c050
show_hires              = &c057
button_0                = &c061

; Slot ROMs (&c100-&c7ff)
aux_move = &c311

; Monitor ROM (&f800-&ffff)
plot_lores_block    = &f800
set_lores_colour    = &f864
print_spaces        = &f94a
read_paddle         = &fb1e
set_lores_mode      = &fb40
move_cursor_to_row  = &fb5b
set_power_up_byte   = &fb6f
clear_screen        = &fc58
wait                = &fca8
read_key            = &fd0c
input_line          = &fd6a
print_cr            = &fd8e
print_hex_byte      = &fdda
print_char          = &fded
print_char_to_screen = &fdf0
set_normal          = &fe84
output_to_screen    = &fe93
output_to_slot      = &fe95
bell                = &ff3a
known_rts           = &ff58
monitor_no_beep     = &ff69

section pydis, org = &0803, filename = "apple2e_names_test_baron"

.pydis_start
.start
    jsr clear_screen                                                  ; 0803: 20 58 fc    ..| ; Clear the window and put the cursor at its top left
    ; print message
    ldx #0                                                            ; 0806: a2 00       ".
; &0808 referenced 1 time by &0811
.loop_c0808
    lda l08fb,x                                                       ; 0808: bd fb 08    ={. ; A=character
    beq c0813                                                         ; 080b: f0 06       p.
    jsr print_char                                                    ; 080d: 20 ed fd    .m} ; Print a character (through CSW)
    inx                                                               ; 0810: e8          h
    bne loop_c0808                                                    ; 0811: d0 f5       Pu
; &0813 referenced 1 time by &080b
.c0813
    ; Print "HI"
    lda #'H' or &80                                                   ; 0813: a9 c8       )H
    jsr print_char                                                    ; 0815: 20 ed fd    .m} ; Print 'H'
    lda #'I' or &80                                                   ; 0818: a9 c9       )I
    jsr print_char                                                    ; 081a: 20 ed fd    .m} ; Print 'I'
    lda #&8d                                                          ; 081d: a9 8d       ).
    jsr print_char                                                    ; 081f: 20 ed fd    .m} ; Print a carriage return
    jsr print_cr                                                      ; 0822: 20 8e fd    ..} ; Start a new line
    ; DOS command: PR#0
    lda #&84                                                          ; 0825: a9 84       ).
    jsr print_char                                                    ; 0827: 20 ed fd    .m} ; Print Ctrl-D (to start a DOS command)
    lda #'P' or &80                                                   ; 082a: a9 d0       )P
    jsr print_char                                                    ; 082c: 20 ed fd    .m} ; Print 'P'
    lda #'R' or &80                                                   ; 082f: a9 d2       )R
    jsr print_char                                                    ; 0831: 20 ed fd    .m} ; Print 'R'
    lda #'#' or &80                                                   ; 0834: a9 a3       )#
    jsr print_char                                                    ; 0836: 20 ed fd    .m} ; Print '#'
    lda #'0' or &80                                                   ; 0839: a9 b0       )0
    jsr print_char                                                    ; 083b: 20 ed fd    .m} ; Print '0'
    lda #&8d                                                          ; 083e: a9 8d       ).
    jsr print_char                                                    ; 0840: 20 ed fd    .m} ; Print a carriage return
    lda #&12                                                          ; 0843: a9 12       ).
    jsr print_hex_byte                                                ; 0845: 20 da fd    .Z} ; Print A in hex
    ldx #5                                                            ; 0848: a2 05       ".
    jsr print_spaces                                                  ; 084a: 20 4a f9    ..y ; Print 5 spaces
    lda #&0a                                                          ; 084d: a9 0a       ).
    jsr move_cursor_to_row                                            ; 084f: 20 5b fb    ..{ ; Move the cursor to row 10
    lda #&40                                                          ; 0852: a9 40       ).
    jsr wait                                                          ; 0854: 20 a8 fc    .(| ; Wait 11,117 cycles (about 10.9 ms)
    lda #1                                                            ; 0857: a9 01       ).
    jsr output_to_slot                                                ; 0859: 20 95 fe    ..~ ; Send output to slot 1 (PR#1)
    jsr output_to_screen                                              ; 085c: 20 93 fe    ..~ ; Send output to the screen (PR#0)
    jsr bell                                                          ; 085f: 20 3a ff    ... ; Beep (by printing Ctrl-G)
    jsr set_lores_mode                                                ; 0862: 20 40 fb    ..{ ; Set lo-res mixed mode, and clear the graphics
    lda #9                                                            ; 0865: a9 09       ).
    jsr set_lores_colour                                              ; 0867: 20 64 f8    ..x ; Set the lo-res colour to 9 (orange)
    lda #&0a                                                          ; 086a: a9 0a       ). ; A=row (0-47)
    ldy #5                                                            ; 086c: a0 05        . ; Y=column (0-39)
    jsr plot_lores_block                                              ; 086e: 20 00 f8    ..x ; Plot a lo-res block (in COLOR)
    ldx #0                                                            ; 0871: a2 00       ".
    jsr read_paddle                                                   ; 0873: 20 1e fb    ..{ ; Read paddle 0
    sty l0006                                                         ; 0876: 84 06       .. ; Y=paddle's value (0-255)
    jsr read_key                                                      ; 0878: 20 0c fd    ..} ; Read a key (through KSW)
    cmp #&d9 ; 'Y'                                                    ; 087b: c9 d9       IY ; A=key (with bit 7 set)
    beq c0887                                                         ; 087d: f0 08       p.
    jsr input_line                                                    ; 087f: 20 6a fd    ..} ; Input a line into IN, after PROMPT
    stx l0007                                                         ; 0882: 86 07       .. ; X=line's length
    lda input_buffer                                                  ; 0884: ad 00 02    -..
; &0887 referenced 1 time by &087d
.c0887
    lda #5                                                            ; 0887: a9 05       ).
    sta cursor_column                                                 ; 0889: 85 24       ..
    sta cursor_row                                                    ; 088b: 85 25       ..
    lda #&3f                                                          ; 088d: a9 3f       ).
    sta text_mask                                                     ; 088f: 85 32       ..
    jsr set_normal                                                    ; 0891: 20 84 fe    ..~ ; Print in normal text

    ; Set the reset vector to 'reset_handler'
    lda #<reset_handler                                               ; 0894: a9 f4       )t
    sta reset_vector                                                  ; 0896: 8d f2 03    .r.
    lda #>reset_handler                                               ; 0899: a9 08       ).
    sta reset_vector+1                                                ; 089b: 8d f3 03    .s.

    jsr set_power_up_byte                                             ; 089e: 20 6f fb    ..{ ; Set PWREDUP to match SOFTEV, so that reset uses it

    ; Set the output hook (CSW) to 'output_handler'
    lda #<output_handler                                              ; 08a1: a9 f7       )w
    sta output_hook                                                   ; 08a3: 85 36       ..
    lda #>output_handler                                              ; 08a5: a9 08       ).
    sta output_hook+1                                                 ; 08a7: 85 37       ..

    ; Set the IRQ vector to 'irq_handler'
    lda #<irq_handler                                                 ; 08a9: a9 fa       )z
    sta irq_vector                                                    ; 08ab: 8d fe 03    .~.
    lda #>irq_handler                                                 ; 08ae: a9 08       ).
    sta irq_vector+1                                                  ; 08b0: 8d ff 03    ...

    bit show_graphics                                                 ; 08b3: 2c 50 c0    ..@
    bit show_hires                                                    ; 08b6: 2c 57 c0    ..@
    lda speaker                                                       ; 08b9: ad 30 c0    -.@
; &08bc referenced 1 time by &08bf
.loop_c08bc
    lda keyboard                                                      ; 08bc: ad 00 c0    -.@
    bpl loop_c08bc                                                    ; 08bf: 10 fb       .{
    sta keyboard_strobe                                               ; 08c1: 8d 10 c0    ..@
    lda button_0                                                      ; 08c4: ad 61 c0    -.@
    bmi c08c9                                                         ; 08c7: 30 00       ..
; &08c9 referenced 2 times by &08c7, &08cc
.c08c9
    lda is_not_vertical_blank                                         ; 08c9: ad 19 c0    -.@
    bpl c08c9                                                         ; 08cc: 10 fb       .{
    lda #0                                                            ; 08ce: a9 00       ).
    sta monitor_a1                                                    ; 08d0: 85 3c       ..
    lda #&20                                                          ; 08d2: a9 20       ).
    sta monitor_a1+1                                                  ; 08d4: 85 3d       ..
    lda #&ff                                                          ; 08d6: a9 ff       ).
    sta monitor_a2                                                    ; 08d8: 85 3e       ..
    lda #&3f                                                          ; 08da: a9 3f       ).
    sta monitor_a2+1                                                  ; 08dc: 85 3f       ..
    lda #0                                                            ; 08de: a9 00       ).
    sta monitor_a4                                                    ; 08e0: 85 42       ..
    lda #&20                                                          ; 08e2: a9 20       ).
    sta monitor_a4+1                                                  ; 08e4: 85 43       ..
    sec                                                               ; 08e6: 38          .
    jsr aux_move                                                      ; 08e7: 20 11 c3    ..C ; Copy A1 to A2 to A4 in the other memory (C set: main to auxiliary)
    jsr known_rts                                                     ; 08ea: 20 58 ff    ... ; Return (an RTS: code calls it to find its own address on the stack)
    tsx                                                               ; 08ed: ba          :
    lda l0100,x                                                       ; 08ee: bd 00 01    =..
    jmp monitor_no_beep                                               ; 08f1: 4c 69 ff    ... ; Enter the Monitor

.reset_handler
    jmp monitor_no_beep                                               ; 08f4: 4c 69 ff    ... ; Enter the Monitor

.output_handler
    jmp print_char_to_screen                                          ; 08f7: 4c f0 fd    .p} ; Print a character on the screen

.irq_handler
    rti                                                               ; 08fa: 40          .

; &08fb referenced 1 time by &0808
.l08fb
    equb &c8, &c5, &cc, &cc, &cf, &ac, &a0, &d7 ; apple "HELLO, W"    ; 08fb: c8 c5 cc... HEL
    equb &cf, &d2, &cc, &c4 ; apple "ORLD"                            ; 0903: cf d2 cc... ORL
    equb &8d, 0                                                       ; 0907: 8d 00       ..
.pydis_end

    assert (<irq_handler) = &fa
    assert (<output_handler) = &f7
    assert (<reset_handler) = &f4
    assert (>irq_handler) = &08
    assert (>output_handler) = &08
    assert (>reset_handler) = &08

endsection

; Label references by decreasing frequency:
;     print_char:             10
;     c08c9:                   2
;     monitor_no_beep:         2
;     aux_move:                1
;     bell:                    1
;     button_0:                1
;     c0813:                   1
;     c0887:                   1
;     clear_screen:            1
;     cursor_column:           1
;     cursor_row:              1
;     input_buffer:            1
;     input_line:              1
;     irq_vector:              1
;     is_not_vertical_blank:   1
;     keyboard:                1
;     keyboard_strobe:         1
;     known_rts:               1
;     l0006:                   1
;     l0007:                   1
;     l0100:                   1
;     l08fb:                   1
;     loop_c0808:              1
;     loop_c08bc:              1
;     monitor_a1:              1
;     monitor_a2:              1
;     monitor_a4:              1
;     move_cursor_to_row:      1
;     output_hook:             1
;     output_to_screen:        1
;     output_to_slot:          1
;     plot_lores_block:        1
;     print_char_to_screen:    1
;     print_cr:                1
;     print_hex_byte:          1
;     print_spaces:            1
;     read_key:                1
;     read_paddle:             1
;     reset_vector:            1
;     set_lores_colour:        1
;     set_lores_mode:          1
;     set_normal:              1
;     set_power_up_byte:       1
;     show_graphics:           1
;     show_hires:              1
;     speaker:                 1
;     text_mask:               1
;     wait:                    1

; Automatically generated labels:
;     c0813
;     c0887
;     c08c9
;     l0006
;     l0007
;     l0100
;     l08fb
;     loop_c0808
;     loop_c08bc

; Stats:
;
;     Total size (Code + Data) = 262 bytes
;     Code                     = 248 bytes (95%)
;     Data                     = 14 bytes (5%)
;
;     Number of instructions   = 103
;     Number of data bytes     = 2 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 12 bytes
;     Number of strings        = 1
