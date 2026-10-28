; Constants
colour_blue     = 6
device_disk_8   = 8

; Memory locations

; Zero page ($0000-$00ff)
far_call_bank       = $02
far_call_pc_high    = $03
far_call_pc_low     = $04
screen_mode_40_80   = $d7

; OS workspace ($0200-$03ff)
irq_vector  = $0314

; VIC-II ($d000-$d3ff)
vic_border_colour   = $d020
vic_clock_speed     = $d030

; VDC ($d600-$d6ff)
vdc_address = $d600
vdc_data    = $d601

; Kernal ROM ($e000-$feff)
kernal_irq_handler  = $fa65

; MMU ($ff00-$ff04)
mmu_configuration   = $ff00

; Kernal entry points ($ff47-$fff9)
setbnk  = $ff68
jsrfar  = $ff6e
primm   = $ff7d
setlfs  = $ffba
setnam  = $ffbd
chrout  = $ffd2
load    = $ffd5

; The PRG file's header: the address to load it at
    * = $1bff
    !word $1c01

    * = $1c01

; 10 SYS7181
pydis_start
basic_line_10
    !word basic_end                                                   ; 1c01: 0b 1c       ..
    !word 10                                                          ; 1c03: 0a 00       ..
    !byte $9e                                                         ; 1c05: 9e          .
    !pet "7181"                                                       ; 1c06: 37 31 38... 718
    !byte 0                                                           ; 1c0a: 00          .
basic_end
    !word 0                                                           ; 1c0b: 00 00       ..

sys_entry
    lda #0                                                            ; 1c0d: a9 00       ..
    sta mmu_configuration                                             ; 1c0f: 8d 00 ff    ...
    lda #1                                                            ; 1c12: a9 01       ..
    sta vic_clock_speed                                               ; 1c14: 8d 30 d0    .0P
    jsr primm                                                         ; 1c17: 20 7d ff     .. ; Print the zero-terminated string that follows the JSR
    !pet "hello, c128", $0d, 0                                        ; 1c1a: 48 45 4c... hel

    lda #$21 ; '!'                                                    ; 1c27: a9 21       .! ; A=character to output
    jsr chrout                                                        ; 1c29: 20 d2 ff     R. ; Output '!'
    lda #colour_blue                                                  ; 1c2c: a9 06       ..
    sta vic_border_colour                                             ; 1c2e: 8d 20 d0    . P
    ldx #$1a                                                          ; 1c31: a2 1a       ..
    stx vdc_address                                                   ; 1c33: 8e 00 d6    ..V
; $1c36 referenced 1 time by $1c39
loop_c1c36
    bit vdc_address                                                   ; 1c36: 2c 00 d6    ,.V
    bpl loop_c1c36                                                    ; 1c39: 10 fb       ..
    lda #$f0                                                          ; 1c3b: a9 f0       ..
    sta vdc_data                                                      ; 1c3d: 8d 01 d6    ..V
    lda screen_mode_40_80                                             ; 1c40: a5 d7       .W
    sta l1c8d                                                         ; 1c42: 8d 8d 1c    ...
    sei                                                               ; 1c45: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 1c46: a9 83       ..
    sta irq_vector                                                    ; 1c48: 8d 14 03    ...
    lda #>irq_handler                                                 ; 1c4b: a9 1c       ..
    sta irq_vector+1                                                  ; 1c4d: 8d 15 03    ...

    cli                                                               ; 1c50: 58          x
    lda #0                                                            ; 1c51: a9 00       ..
    sta far_call_bank                                                 ; 1c53: 85 02       ..
    lda #$1c                                                          ; 1c55: a9 1c       ..
    sta far_call_pc_high                                              ; 1c57: 85 03       ..
    lda #$7f                                                          ; 1c59: a9 7f       ..
    sta far_call_pc_low                                               ; 1c5b: 85 04       ..
    jsr jsrfar                                                        ; 1c5d: 20 6e ff     .. ; Call a routine in another bank (set up at $02-$08)
    lda #1                                                            ; 1c60: a9 01       .. ; A=bank for the data
    ldx #0                                                            ; 1c62: a2 00       .. ; X=bank for the filename
    jsr setbnk                                                        ; 1c64: 20 68 ff     .. ; Set the banks for LOAD, SAVE and VERIFY, and for the filename
    lda #1                                                            ; 1c67: a9 01       .. ; A=logical file number
    ldx #device_disk_8                                                ; 1c69: a2 08       .. ; X=device number
    ldy #1                                                            ; 1c6b: a0 01       .. ; Y=secondary address
    jsr setlfs                                                        ; 1c6d: 20 ba ff     .. ; Set logical file 1 to device 8 (disk drive), secondary address 1
    lda #4                                                            ; 1c70: a9 04       .. ; A=filename length
    ldx #<filename                                                    ; 1c72: a2 89       .. ; X=filename address (low byte)
    ldy #>filename                                                    ; 1c74: a0 1c       .. ; Y=filename address (high byte)
    jsr setnam                                                        ; 1c76: 20 bd ff     .. ; Set the filename to "data"
    lda #0                                                            ; 1c79: a9 00       .. ; A=0 to load, 1 to verify
    jsr load                                                          ; 1c7b: 20 d5 ff     U. ; Load a file
    rts                                                               ; 1c7e: 60          .

    !byte $ee, $20, $d0, $60                                          ; 1c7f: ee 20 d0... . P

irq_handler
    inc vic_border_colour                                             ; 1c83: ee 20 d0    . P
    jmp kernal_irq_handler                                            ; 1c86: 4c 65 fa    l.. ; The Kernal's IRQ handler (blinks the cursor, scans the keyboard etc., then returns from the interrupt)

filename
    !pet "data"                                                       ; 1c89: 44 41 54... dat
; $1c8d referenced 1 time by $1c42
l1c8d
    !byte 0                                                           ; 1c8d: 00          .
pydis_end

!if (<filename) != $89 {
    !error "Assertion failed: <filename == $89"
}
!if (<irq_handler) != $83 {
    !error "Assertion failed: <irq_handler == $83"
}
!if (>filename) != $1c {
    !error "Assertion failed: >filename == $1c"
}
!if (>irq_handler) != $1c {
    !error "Assertion failed: >irq_handler == $1c"
}
!if (basic_end) != $1c0b {
    !error "Assertion failed: basic_end == $1c0b"
}

; Label references by decreasing frequency:
;     vdc_address:          2
;     vic_border_colour:    2
;     chrout:               1
;     far_call_bank:        1
;     far_call_pc_high:     1
;     far_call_pc_low:      1
;     irq_vector:           1
;     jsrfar:               1
;     kernal_irq_handler:   1
;     l1c8d:                1
;     load:                 1
;     loop_c1c36:           1
;     mmu_configuration:    1
;     primm:                1
;     screen_mode_40_80:    1
;     setbnk:               1
;     setlfs:               1
;     setnam:               1
;     vdc_data:             1
;     vic_clock_speed:      1

; Automatically generated labels:
;     l1c8d
;     loop_c1c36

; Stats:
;
;     Total size (Code + Data) = 141 bytes
;     Code                     = 107 bytes (76%)
;     Data                     = 34 bytes (24%)
;
;     Number of instructions   = 46
;     Number of data bytes     = 7 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 21 bytes
;     Number of strings        = 3

