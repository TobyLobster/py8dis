.cpu "6502i"

; Text encodings (for '.text' and character literals)
    .enc "petscii"
    .cdef " @", $20
    .cdef "AZ", $c1
    .cdef "[[", $5b
    .cdef "]]", $5d
    .cdef "az", $41

; Constants
colour_black    = 0
colour_blue     = 6
colour_white    = 1
device_disk_8   = 8

; Memory locations

; Zero page ($0000-$00ff)
jiffy_clock             = $00a0
keyboard_buffer_length  = $00c6
free_zero_page          = $00fb

; OS workspace ($0200-$02ff)
text_colour = $0286

; Vectors ($0300-$0333)
irq_vector  = $0314

; Screen memory ($0400-$07ff)
screen_memory   = $0400
sprite_pointers = $07f8

; BASIC ROM ($a000-$bfff)
basic_print_string  = $ab1e
basic_print_number  = $bdcd

; VIC-II ($d000-$d3ff)
vic_sprite0_x           = $d000
vic_control_1           = $d011
vic_raster_line         = $d012
vic_interrupt_status    = $d019
vic_interrupt_enable    = $d01a
vic_border_colour       = $d020
vic_background_colour_0 = $d021

; Colour RAM ($d800-$dbff)
colour_ram  = $d800

; CIA 1 ($dc00-$dcff)
cia1_port_a             = $dc00
cia1_interrupt_control  = $dc0d

; Kernal ROM ($e000-$ff80)
kernal_irq_handler  = $ea31

; Kernal entry points ($ff81-$fff9)
SETMSG  = $ff90
READST  = $ffb7
SETLFS  = $ffba
SETNAM  = $ffbd
OPEN    = $ffc0
CLOSE   = $ffc3
CHKIN   = $ffc6
CLRCHN  = $ffcc
CHRIN   = $ffcf
CHROUT  = $ffd2
LOAD    = $ffd5
SAVE    = $ffd8
RDTIM   = $ffde
GETIN   = $ffe4
SCREEN  = $ffed
PLOT    = $fff0

; The PRG file's header: the address to load it at
    * = $07ff
    .word $0801

    * = $0801

; 10 REM C64 TEST
pydis_start
basic_line_10
    .word basic_line_15                                               ; 0801: 10 08       ..
    .word 10                                                          ; 0803: 0a 00       ..
    .byte $8f                                                         ; 0805: 8f          .
    .text " c64 test"                                                 ; 0806: 20 43 36...  c6
    .byte 0                                                           ; 080f: 00          .
; 15 PRINT"{$93}HI"
basic_line_15
    .word basic_line_20                                               ; 0810: 1b 08       ..
    .word 15                                                          ; 0812: 0f 00       ..
    .byte $99                                                         ; 0814: 99          .
    .text """"                                                        ; 0815: 22          "
    .byte $93                                                         ; 0816: 93          .
    .text "hi"""                                                      ; 0817: 48 49 22    hi"
    .byte 0                                                           ; 081a: 00          .
; 20 SYS2087
basic_line_20
    .word basic_end                                                   ; 081b: 25 08       %.
    .word 20                                                          ; 081d: 14 00       ..
    .byte $9e                                                         ; 081f: 9e          .
    .text "2087"                                                      ; 0820: 32 30 38... 208
    .byte 0                                                           ; 0824: 00          .
basic_end
    .word 0                                                           ; 0825: 00 00       ..

sys_entry
    sei                                                               ; 0827: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 0828: a9 30       .0
    sta irq_vector                                                    ; 082a: 8d 14 03    ...
    lda #>irq_handler                                                 ; 082d: a9 09       ..
    sta irq_vector+1                                                  ; 082f: 8d 15 03    ...

    lda #$7f                                                          ; 0832: a9 7f       ..
    sta cia1_interrupt_control                                        ; 0834: 8d 0d dc    ...
    lda #1                                                            ; 0837: a9 01       ..
    sta vic_interrupt_enable                                          ; 0839: 8d 1a d0    ..P ; Enable only the VIC-II's raster interrupt
    lda #$64                                                          ; 083c: a9 64       ..
    sta vic_raster_line                                               ; 083e: 8d 12 d0    ..P ; Raster interrupt at line 100
    lda vic_control_1                                                 ; 0841: ad 11 d0    ..P
    and #$7f                                                          ; 0844: 29 7f       ).
    sta vic_control_1                                                 ; 0846: 8d 11 d0    ..P
    cli                                                               ; 0849: 58          x
    lda #colour_black                                                 ; 084a: a9 00       ..
    sta vic_border_colour                                             ; 084c: 8d 20 d0    . P
    lda #colour_blue                                                  ; 084f: a9 06       ..
    sta vic_background_colour_0                                       ; 0851: 8d 21 d0    .!P
    ldx #colour_white                                                 ; 0854: a2 01       ..
    stx text_colour                                                   ; 0856: 8e 86 02    ...
    lda #$93                                                          ; 0859: a9 93       .. ; A=character to output
    jsr CHROUT                                                        ; 085b: 20 d2 ff     R. ; Output $93 (clear screen)
    ldx #0                                                            ; 085e: a2 00       ..
; $0860 referenced 1 time by $0869
loop_c0860
    lda l0939,x                                                       ; 0860: bd 39 09    .9. ; A=character to output
    beq c086b                                                         ; 0863: f0 06       ..
    jsr CHROUT                                                        ; 0865: 20 d2 ff     R. ; Output a character
    inx                                                               ; 0868: e8          .
    bne loop_c0860                                                    ; 0869: d0 f5       P.
; $086b referenced 1 time by $0863
c086b
    lda #'!'                                                          ; 086b: a9 21       .! ; A=character to output
    jsr CHROUT                                                        ; 086d: 20 d2 ff     R. ; Output '!'
    clc                                                               ; 0870: 18          .
    ldx #5                                                            ; 0871: a2 05       .. ; X=cursor row
    ldy #$0a                                                          ; 0873: a0 0a       .. ; Y=cursor column
    jsr PLOT                                                          ; 0875: 20 f0 ff     .. ; Move the cursor to row 5, column 10
    sec                                                               ; 0878: 38          8
    jsr PLOT                                                          ; 0879: 20 f0 ff     .. ; Read the cursor position into X (row) and Y (column)
    stx l095c                                                         ; 087c: 8e 5c 09    ... ; X=cursor row
    sty l095d                                                         ; 087f: 8c 5d 09    .]. ; Y=cursor column
    lda #$0f                                                          ; 0882: a9 0f       .. ; A=logical file number
    ldx #device_disk_8                                                ; 0884: a2 08       .. ; X=device number
    ldy #$0f                                                          ; 0886: a0 0f       .. ; Y=secondary address
    jsr SETLFS                                                        ; 0888: 20 ba ff     .. ; Set logical file 15 to device 8 (disk drive), secondary address 15
    lda #2                                                            ; 088b: a9 02       .. ; A=filename length
    ldx #<filename                                                    ; 088d: a2 47       .g ; X=filename address (low byte)
    ldy #>filename                                                    ; 088f: a0 09       .. ; Y=filename address (high byte)
    jsr SETNAM                                                        ; 0891: 20 bd ff     .. ; Set the filename to "i0"
    jsr OPEN                                                          ; 0894: 20 c0 ff     .. ; Open a logical file (set up with SETLFS and SETNAM)
    ldx #$0f                                                          ; 0897: a2 0f       .. ; X=logical file number
    jsr CHKIN                                                         ; 0899: 20 c6 ff     F. ; Open a channel for input
    jsr CHRIN                                                         ; 089c: 20 cf ff     O. ; Read a character from the input channel
    sta l095e                                                         ; 089f: 8d 5e 09    ... ; A=character read
    jsr CLRCHN                                                        ; 08a2: 20 cc ff     L. ; Restore the default input and output channels
    lda #$0f                                                          ; 08a5: a9 0f       .. ; A=logical file number
    jsr CLOSE                                                         ; 08a7: 20 c3 ff     C. ; Close a logical file
    lda #1                                                            ; 08aa: a9 01       .. ; A=logical file number
    ldx #device_disk_8                                                ; 08ac: a2 08       .. ; X=device number
    ldy #1                                                            ; 08ae: a0 01       .. ; Y=secondary address
    jsr SETLFS                                                        ; 08b0: 20 ba ff     .. ; Set logical file 1 to device 8 (disk drive), secondary address 1
    lda #4                                                            ; 08b3: a9 04       .. ; A=filename length
    ldx #<filename_2                                                  ; 08b5: a2 49       .i ; X=filename address (low byte)
    ldy #>filename_2                                                  ; 08b7: a0 09       .. ; Y=filename address (high byte)
    jsr SETNAM                                                        ; 08b9: 20 bd ff     .. ; Set the filename to "data"
    lda #0                                                            ; 08bc: a9 00       .. ; A=0 to load, 1 to verify
    jsr LOAD                                                          ; 08be: 20 d5 ff     U. ; Load a file
    stx l095f                                                         ; 08c1: 8e 5f 09    ... ; X=end address of the data loaded (low byte)
    sty l0960                                                         ; 08c4: 8c 60 09    ... ; Y=end address of the data loaded (high byte)
    lda #$27 ; '''                                                    ; 08c7: a9 27       .'
    sta free_zero_page                                                ; 08c9: 85 fb       ..
    lda #8                                                            ; 08cb: a9 08       ..
    sta free_zero_page+1                                              ; 08cd: 85 fc       ..
    lda #free_zero_page                                               ; 08cf: a9 fb       .. ; A=zero page address of the start address
    ldx #<pydis_end                                                   ; 08d1: a2 68       .. ; X=end address + 1 (low byte)
    ldy #>pydis_end                                                   ; 08d3: a0 09       .. ; Y=end address + 1 (high byte)
    jsr SAVE                                                          ; 08d5: 20 d8 ff     X. ; Save memory to a file (set up with SETLFS and SETNAM)
    lda #$c0                                                          ; 08d8: a9 c0       .. ; A=message flags
    jsr SETMSG                                                        ; 08da: 20 90 ff     .. ; Show Kernal control and error messages
    jsr RDTIM                                                         ; 08dd: 20 de ff     .. ; Read the jiffy clock
    sty l0961                                                         ; 08e0: 8c 61 09    ... ; Y=jiffy clock (low byte)
    stx l0962                                                         ; 08e3: 8e 62 09    ... ; X=jiffy clock (middle byte)
    sta l0963                                                         ; 08e6: 8d 63 09    ... ; A=jiffy clock (high byte)
    jsr GETIN                                                         ; 08e9: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    sta l0964                                                         ; 08ec: 8d 64 09    ... ; A=character read
    jsr READST                                                        ; 08ef: 20 b7 ff     .. ; Read the I/O status
    sta l0965                                                         ; 08f2: 8d 65 09    ... ; A=I/O status
    jsr SCREEN                                                        ; 08f5: 20 ed ff     .. ; Read the screen size
    stx l0966                                                         ; 08f8: 8e 66 09    ... ; X=number of columns
    sty l0967                                                         ; 08fb: 8c 67 09    ... ; Y=number of rows
    lda #<l094d                                                       ; 08fe: a9 4d       .m ; A=string address (low byte)
    ldy #>l094d                                                       ; 0900: a0 09       .. ; Y=string address (high byte)
    jsr basic_print_string                                            ; 0902: 20 1e ab     .. ; Print the zero-terminated string at A/Y
    lda #0                                                            ; 0905: a9 00       .. ; A=number to print (high byte)
    ldx #$2a ; '*'                                                    ; 0907: a2 2a       .* ; X=number to print (low byte)
    jsr basic_print_number                                            ; 0909: 20 cd bd     M. ; Print the 16-bit number in A/X
    lda keyboard_buffer_length                                        ; 090c: a5 c6       .F
    sta l0964                                                         ; 090e: 8d 64 09    ...
    ldx #$27 ; '''                                                    ; 0911: a2 27       .'
; $0913 referenced 1 time by $091e
loop_c0913
    lda #$51 ; 'q'                                                    ; 0913: a9 51       .q
    sta screen_memory,x                                               ; 0915: 9d 00 04    ...
    lda #1                                                            ; 0918: a9 01       ..
    sta colour_ram,x                                                  ; 091a: 9d 00 d8    ..X
    dex                                                               ; 091d: ca          J
    bpl loop_c0913                                                    ; 091e: 10 f3       ..
    lda cia1_port_a                                                   ; 0920: ad 00 dc    ...
    sta vic_sprite0_x                                                 ; 0923: 8d 00 d0    ..P
    lda jiffy_clock+2                                                 ; 0926: a5 a2       ..
    sta sprite_pointers                                               ; 0928: 8d f8 07    ...
    lax free_zero_page                                                ; 092b: a7 fb       ..
    sbx #1                                                            ; 092d: cb 01       K.
    rts                                                               ; 092f: 60          .

irq_handler
    asl vic_interrupt_status                                          ; 0930: 0e 19 d0    ..P ; Acknowledge the VIC-II's interrupts
    inc vic_border_colour                                             ; 0933: ee 20 d0    . P
    jmp kernal_irq_handler                                            ; 0936: 4c 31 ea    l1. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

; $0939 referenced 1 time by $0860
l0939
    .text "hello, world"                                              ; 0939: 48 45 4c... hel
    .byte $0d, 0                                                      ; 0945: 0d 00       ..
filename
    .text "i0"                                                        ; 0947: 49 30       i0
filename_2
    .text "data"                                                      ; 0949: 44 41 54... dat
l094d
    .text "the answer is ", 0                                         ; 094d: 54 48 45... the
; $095c referenced 1 time by $087c
l095c
    .byte 0                                                           ; 095c: 00          .
; $095d referenced 1 time by $087f
l095d
    .byte 0                                                           ; 095d: 00          .
; $095e referenced 1 time by $089f
l095e
    .byte 0                                                           ; 095e: 00          .
; $095f referenced 1 time by $08c1
l095f
    .byte 0                                                           ; 095f: 00          .
; $0960 referenced 1 time by $08c4
l0960
    .byte 0                                                           ; 0960: 00          .
; $0961 referenced 1 time by $08e0
l0961
    .byte 0                                                           ; 0961: 00          .
; $0962 referenced 1 time by $08e3
l0962
    .byte 0                                                           ; 0962: 00          .
; $0963 referenced 1 time by $08e6
l0963
    .byte 0                                                           ; 0963: 00          .
; $0964 referenced 2 times by $08ec, $090e
l0964
    .byte 0                                                           ; 0964: 00          .
; $0965 referenced 1 time by $08f2
l0965
    .byte 0                                                           ; 0965: 00          .
; $0966 referenced 1 time by $08f8
l0966
    .byte 0                                                           ; 0966: 00          .
; $0967 referenced 1 time by $08fb
l0967
    .byte 0                                                           ; 0967: 00          .
pydis_end

.cerror (<filename) != $47, "Assertion failed: <filename == $47"
.cerror (<filename_2) != $49, "Assertion failed: <filename_2 == $49"
.cerror (<irq_handler) != $30, "Assertion failed: <irq_handler == $30"
.cerror (<l094d) != $4d, "Assertion failed: <l094d == $4d"
.cerror (<pydis_end) != $68, "Assertion failed: <pydis_end == $68"
.cerror (>filename) != $09, "Assertion failed: >filename == $09"
.cerror (>filename_2) != $09, "Assertion failed: >filename_2 == $09"
.cerror (>irq_handler) != $09, "Assertion failed: >irq_handler == $09"
.cerror (>l094d) != $09, "Assertion failed: >l094d == $09"
.cerror (>pydis_end) != $09, "Assertion failed: >pydis_end == $09"
.cerror (basic_end) != $0825, "Assertion failed: basic_end == $0825"
.cerror (basic_line_15) != $0810, "Assertion failed: basic_line_15 == $0810"
.cerror (basic_line_20) != $081b, "Assertion failed: basic_line_20 == $081b"
.cerror (free_zero_page) != $fb, "Assertion failed: free_zero_page == $fb"

; Label references by decreasing frequency:
;     CHROUT:                    3
;     PLOT:                      2
;     SETLFS:                    2
;     SETNAM:                    2
;     free_zero_page:            2
;     l0964:                     2
;     vic_border_colour:         2
;     vic_control_1:             2
;     CHKIN:                     1
;     CHRIN:                     1
;     CLOSE:                     1
;     CLRCHN:                    1
;     GETIN:                     1
;     LOAD:                      1
;     OPEN:                      1
;     RDTIM:                     1
;     READST:                    1
;     SAVE:                      1
;     SCREEN:                    1
;     SETMSG:                    1
;     basic_print_number:        1
;     basic_print_string:        1
;     c086b:                     1
;     cia1_interrupt_control:    1
;     cia1_port_a:               1
;     colour_ram:                1
;     irq_vector:                1
;     kernal_irq_handler:        1
;     keyboard_buffer_length:    1
;     l0939:                     1
;     l095c:                     1
;     l095d:                     1
;     l095e:                     1
;     l095f:                     1
;     l0960:                     1
;     l0961:                     1
;     l0962:                     1
;     l0963:                     1
;     l0965:                     1
;     l0966:                     1
;     l0967:                     1
;     loop_c0860:                1
;     loop_c0913:                1
;     screen_memory:             1
;     sprite_pointers:           1
;     text_colour:               1
;     vic_background_colour_0:   1
;     vic_interrupt_enable:      1
;     vic_interrupt_status:      1
;     vic_raster_line:           1
;     vic_sprite0_x:             1

; Automatically generated labels:
;     c086b
;     l0939
;     l094d
;     l095c
;     l095d
;     l095e
;     l095f
;     l0960
;     l0961
;     l0962
;     l0963
;     l0964
;     l0965
;     l0966
;     l0967
;     loop_c0860
;     loop_c0913

; Stats:
;
;     Total size (Code + Data) = 359 bytes
;     Code                     = 274 bytes (76%)
;     Data                     = 85 bytes (24%)
;
;     Number of instructions   = 113
;     Number of data bytes     = 21 bytes
;     Number of data words     = 14 bytes
;     Number of string bytes   = 50 bytes
;     Number of strings        = 8

