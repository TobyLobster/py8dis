; Memory locations

; Vectors ($0300-$0332)
irq_vector  = $0314

; Colour RAM ($0800-$0bff)
colour_ram  = $0800

; Screen memory ($0c00-$0fff)
screen_memory   = $0c00

; Kernal ROM ($c000-$fcff)
lc000               = $c000
kernal_irq_return   = $fcc3

; I/O ($fd00-$feff)
acia_status     = $fd01
keyboard_latch  = $fd30

; TED ($ff00-$ff3f)
ted_keyboard_latch      = $ff08
ted_voice1_frequency_low = $ff0e
ted_sound_control       = $ff11
ted_background_colour_0 = $ff15
ted_border_colour       = $ff19
ted_rom_select          = $ff3e
ted_ram_select          = $ff3f

; Kernal entry points ($ff40-$fff9)
primm   = $ff4f
chrout  = $ffd2
getin   = $ffe4

; The PRG file's header: the address to load it at
    * = $0fff
    !word $1001

    * = $1001

; 10 SYS4109
pydis_start
basic_line_10
    !word basic_end                                                   ; 1001: 0b 10       ..
    !word 10                                                          ; 1003: 0a 00       ..
    !byte $9e                                                         ; 1005: 9e          .
    !pet "4109"                                                       ; 1006: 34 31 30... 410
    !byte 0                                                           ; 100a: 00          .
basic_end
    !word 0                                                           ; 100b: 00 00       ..

sys_entry
    jsr primm                                                         ; 100d: 20 4f ff     o. ; Print the zero-terminated string that follows the JSR
    !pet "hello, plus/4", $0d, 0                                      ; 1010: 48 45 4c... hel

    lda #$93                                                          ; 101f: a9 93       .. ; A=character to output
    jsr chrout                                                        ; 1021: 20 d2 ff     R. ; Output $93 (clear screen)
    lda #$71                                                          ; 1024: a9 71       ..
    sta ted_border_colour                                             ; 1026: 8d 19 ff    ...
    lda #0                                                            ; 1029: a9 00       ..
    sta ted_background_colour_0                                       ; 102b: 8d 15 ff    ...
    lda #$80                                                          ; 102e: a9 80       ..
    sta ted_voice1_frequency_low                                      ; 1030: 8d 0e ff    ...
    lda #$1f                                                          ; 1033: a9 1f       ..
    sta ted_sound_control                                             ; 1035: 8d 11 ff    ...
    lda #$7f                                                          ; 1038: a9 7f       ..
    sta keyboard_latch                                                ; 103a: 8d 30 fd    .0.
    sta ted_keyboard_latch                                            ; 103d: 8d 08 ff    ...
    lda ted_keyboard_latch                                            ; 1040: ad 08 ff    ...
    sta l107a                                                         ; 1043: 8d 7a 10    ...
    ldx #$27 ; '''                                                    ; 1046: a2 27       .'
; $1048 referenced 1 time by $1053
loop_c1048
    lda #$51 ; 'q'                                                    ; 1048: a9 51       .q
    sta screen_memory,x                                               ; 104a: 9d 00 0c    ...
    lda #$71                                                          ; 104d: a9 71       ..
    sta colour_ram,x                                                  ; 104f: 9d 00 08    ...
    dex                                                               ; 1052: ca          J
    bpl loop_c1048                                                    ; 1053: 10 f3       ..
    lda acia_status                                                   ; 1055: ad 01 fd    ...
    sta l107b                                                         ; 1058: 8d 7b 10    ...
    sei                                                               ; 105b: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 105c: a9 74       ..
    sta irq_vector                                                    ; 105e: 8d 14 03    ...
    lda #>irq_handler                                                 ; 1061: a9 10       ..
    sta irq_vector+1                                                  ; 1063: 8d 15 03    ...

    cli                                                               ; 1066: 58          x
    sta ted_ram_select                                                ; 1067: 8d 3f ff    .?.
    lda lc000                                                         ; 106a: ad 00 c0    ...
    sta ted_rom_select                                                ; 106d: 8d 3e ff    .>.
    jsr getin                                                         ; 1070: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    rts                                                               ; 1073: 60          .

irq_handler
    inc ted_border_colour                                             ; 1074: ee 19 ff    ...
    jmp kernal_irq_return                                             ; 1077: 4c c3 fc    lC. ; Restore the registers and return from the interrupt

; $107a referenced 1 time by $1043
l107a
    !byte 0                                                           ; 107a: 00          .
; $107b referenced 1 time by $1058
l107b
    !byte 0                                                           ; 107b: 00          .
pydis_end

!if (<irq_handler) != $74 {
    !error "Assertion failed: <irq_handler == $74"
}
!if (>irq_handler) != $10 {
    !error "Assertion failed: >irq_handler == $10"
}
!if (basic_end) != $100b {
    !error "Assertion failed: basic_end == $100b"
}

; Label references by decreasing frequency:
;     ted_border_colour:          2
;     ted_keyboard_latch:         2
;     acia_status:                1
;     chrout:                     1
;     colour_ram:                 1
;     getin:                      1
;     irq_vector:                 1
;     kernal_irq_return:          1
;     keyboard_latch:             1
;     l107a:                      1
;     l107b:                      1
;     lc000:                      1
;     loop_c1048:                 1
;     primm:                      1
;     screen_memory:              1
;     ted_background_colour_0:    1
;     ted_ram_select:             1
;     ted_rom_select:             1
;     ted_sound_control:          1
;     ted_voice1_frequency_low:   1

; Automatically generated labels:
;     l107a
;     l107b
;     lc000
;     loop_c1048

; Stats:
;
;     Total size (Code + Data) = 123 bytes
;     Code                     = 94 bytes (76%)
;     Data                     = 29 bytes (24%)
;
;     Number of instructions   = 38
;     Number of data bytes     = 4 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 19 bytes
;     Number of strings        = 2

