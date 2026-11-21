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
l0002                   = $0002
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
    lda #<irq_handler                                                 ; 0828: a9 4b       .k
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
    lda #$93                                                          ; 0859: a9 93       ..  ; A=character to output
    jsr CHROUT                                                        ; 085b: 20 d2 ff     R. ; Output $93 (clear screen)
    ldx #0                                                            ; 085e: a2 00       ..
; $0860 referenced 1 time by $0869
loop_c0860
    lda l0954,x                                                       ; 0860: bd 54 09    .t. ; A=character to output
    beq c086b                                                         ; 0863: f0 06       ..
    jsr CHROUT                                                        ; 0865: 20 d2 ff     R. ; Output a character
    inx                                                               ; 0868: e8          .
    bne loop_c0860                                                    ; 0869: d0 f5       P.
; $086b referenced 1 time by $0863
c086b
    lda #'!'                                                          ; 086b: a9 21       .!  ; A=character to output
    jsr CHROUT                                                        ; 086d: 20 d2 ff     R. ; Output '!'
    ldx #0                                                            ; 0870: a2 00       ..
; $0872 referenced 1 time by $087b
loop_c0872
    lda l0977,x                                                       ; 0872: bd 77 09    ... ; A=character to output
    jsr CHROUT                                                        ; 0875: 20 d2 ff     R. ; Output a character
    inx                                                               ; 0878: e8          .
    cpx #3                                                            ; 0879: e0 03       ..
    bne loop_c0872                                                    ; 087b: d0 f5       P.
    lda #0                                                            ; 087d: a9 00       ..
    sta l0002                                                         ; 087f: 85 02       ..
    lda #'.'                                                          ; 0881: a9 2e       ..  ; A=character to output
    jsr CHROUT                                                        ; 0883: 20 d2 ff     R. ; Output '.'
    lda l0002                                                         ; 0886: a5 02       ..
    beq c088b                                                         ; 0888: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 088a: ea          .
; $088b referenced 1 time by $0888
c088b
    clc                                                               ; 088b: 18          .
    ldx #5                                                            ; 088c: a2 05       ..  ; X=cursor row
    ldy #$0a                                                          ; 088e: a0 0a       ..  ; Y=cursor column
    jsr PLOT                                                          ; 0890: 20 f0 ff     .. ; Move the cursor to row 5, column 10
    sec                                                               ; 0893: 38          8
    jsr PLOT                                                          ; 0894: 20 f0 ff     .. ; Read the cursor position into X (row) and Y (column)
    stx l097a                                                         ; 0897: 8e 7a 09    ... ; X=cursor row
    sty l097b                                                         ; 089a: 8c 7b 09    ... ; Y=cursor column
    lda #$0f                                                          ; 089d: a9 0f       ..  ; A=logical file number
    ldx #device_disk_8                                                ; 089f: a2 08       ..  ; X=device number
    ldy #$0f                                                          ; 08a1: a0 0f       ..  ; Y=secondary address
    jsr SETLFS                                                        ; 08a3: 20 ba ff     .. ; Set logical file 15 to device 8 (disk drive), secondary address 15
    lda #2                                                            ; 08a6: a9 02       ..  ; A=filename length
    ldx #<filename                                                    ; 08a8: a2 62       ..  ; X=filename address (low byte)
    ldy #>filename                                                    ; 08aa: a0 09       ..  ; Y=filename address (high byte)
    jsr SETNAM                                                        ; 08ac: 20 bd ff     .. ; Set the filename to "i0"
    jsr OPEN                                                          ; 08af: 20 c0 ff     .. ; Open a logical file (set up with SETLFS and SETNAM)
    ldx #$0f                                                          ; 08b2: a2 0f       ..  ; X=logical file number
    jsr CHKIN                                                         ; 08b4: 20 c6 ff     F. ; Open a channel for input
    jsr CHRIN                                                         ; 08b7: 20 cf ff     O. ; Read a character from the input channel
    sta l097c                                                         ; 08ba: 8d 7c 09    ... ; A=character read
    jsr CLRCHN                                                        ; 08bd: 20 cc ff     L. ; Restore the default input and output channels
    lda #$0f                                                          ; 08c0: a9 0f       ..  ; A=logical file number
    jsr CLOSE                                                         ; 08c2: 20 c3 ff     C. ; Close a logical file
    lda #1                                                            ; 08c5: a9 01       ..  ; A=logical file number
    ldx #device_disk_8                                                ; 08c7: a2 08       ..  ; X=device number
    ldy #1                                                            ; 08c9: a0 01       ..  ; Y=secondary address
    jsr SETLFS                                                        ; 08cb: 20 ba ff     .. ; Set logical file 1 to device 8 (disk drive), secondary address 1
    lda #4                                                            ; 08ce: a9 04       ..  ; A=filename length
    ldx #<filename_2                                                  ; 08d0: a2 64       ..  ; X=filename address (low byte)
    ldy #>filename_2                                                  ; 08d2: a0 09       ..  ; Y=filename address (high byte)
    jsr SETNAM                                                        ; 08d4: 20 bd ff     .. ; Set the filename to "data"
    lda #0                                                            ; 08d7: a9 00       ..  ; A=0 to load, 1 to verify
    jsr LOAD                                                          ; 08d9: 20 d5 ff     U. ; Load a file
    stx l097d                                                         ; 08dc: 8e 7d 09    ... ; X=end address of the data loaded (low byte)
    sty l097e                                                         ; 08df: 8c 7e 09    ... ; Y=end address of the data loaded (high byte)
    lda #$27 ; '''                                                    ; 08e2: a9 27       .'
    sta free_zero_page                                                ; 08e4: 85 fb       ..
    lda #8                                                            ; 08e6: a9 08       ..
    sta free_zero_page+1                                              ; 08e8: 85 fc       ..
    lda #free_zero_page                                               ; 08ea: a9 fb       ..  ; A=zero page address of the start address
    ldx #<pydis_end                                                   ; 08ec: a2 86       ..  ; X=end address + 1 (low byte)
    ldy #>pydis_end                                                   ; 08ee: a0 09       ..  ; Y=end address + 1 (high byte)
    jsr SAVE                                                          ; 08f0: 20 d8 ff     X. ; Save memory to a file (set up with SETLFS and SETNAM)
    lda #$c0                                                          ; 08f3: a9 c0       ..  ; A=message flags
    jsr SETMSG                                                        ; 08f5: 20 90 ff     .. ; Show Kernal control and error messages
    jsr RDTIM                                                         ; 08f8: 20 de ff     .. ; Read the jiffy clock
    sty l097f                                                         ; 08fb: 8c 7f 09    ... ; Y=jiffy clock (low byte)
    stx l0980                                                         ; 08fe: 8e 80 09    ... ; X=jiffy clock (middle byte)
    sta l0981                                                         ; 0901: 8d 81 09    ... ; A=jiffy clock (high byte)
    jsr GETIN                                                         ; 0904: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    sta l0982                                                         ; 0907: 8d 82 09    ... ; A=character read
    jsr READST                                                        ; 090a: 20 b7 ff     .. ; Read the I/O status
    sta l0983                                                         ; 090d: 8d 83 09    ... ; A=I/O status
    jsr SCREEN                                                        ; 0910: 20 ed ff     .. ; Read the screen size
    stx l0984                                                         ; 0913: 8e 84 09    ... ; X=number of columns
    sty l0985                                                         ; 0916: 8c 85 09    ... ; Y=number of rows
    lda #<l0968                                                       ; 0919: a9 68       ..  ; A=string address (low byte)
    ldy #>l0968                                                       ; 091b: a0 09       ..  ; Y=string address (high byte)
    jsr basic_print_string                                            ; 091d: 20 1e ab     .. ; Print the zero-terminated string at A/Y
    lda #0                                                            ; 0920: a9 00       ..  ; A=number to print (high byte)
    ldx #$2a ; '*'                                                    ; 0922: a2 2a       .*  ; X=number to print (low byte)
    jsr basic_print_number                                            ; 0924: 20 cd bd     M. ; Print the 16-bit number in A/X
    lda keyboard_buffer_length                                        ; 0927: a5 c6       .F
    sta l0982                                                         ; 0929: 8d 82 09    ...
    ldx #$27 ; '''                                                    ; 092c: a2 27       .'
; $092e referenced 1 time by $0939
loop_c092e
    lda #$51 ; 'q'                                                    ; 092e: a9 51       .q
    sta screen_memory,x                                               ; 0930: 9d 00 04    ...
    lda #1                                                            ; 0933: a9 01       ..
    sta colour_ram,x                                                  ; 0935: 9d 00 d8    ..X
    dex                                                               ; 0938: ca          J
    bpl loop_c092e                                                    ; 0939: 10 f3       ..
    lda cia1_port_a                                                   ; 093b: ad 00 dc    ...
    sta vic_sprite0_x                                                 ; 093e: 8d 00 d0    ..P
    lda jiffy_clock+2                                                 ; 0941: a5 a2       ..
    sta sprite_pointers                                               ; 0943: 8d f8 07    ...
    lax free_zero_page                                                ; 0946: a7 fb       ..
    sbx #1                                                            ; 0948: cb 01       K.
    rts                                                               ; 094a: 60          .

irq_handler
    asl vic_interrupt_status                                          ; 094b: 0e 19 d0    ..P ; Acknowledge the VIC-II's interrupts
    inc vic_border_colour                                             ; 094e: ee 20 d0    . P
    jmp kernal_irq_handler                                            ; 0951: 4c 31 ea    l1. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

; $0954 referenced 1 time by $0860
l0954
    .text "hello, world"                                              ; 0954: 48 45 4c... hel
    .byte $0d, 0                                                      ; 0960: 0d 00       ..
filename
    .text "i0"                                                        ; 0962: 49 30       i0
filename_2
    .text "data"                                                      ; 0964: 44 41 54... dat
l0968
    .text "the answer is ", 0                                         ; 0968: 54 48 45... the
; A table of 3 bytes, indexed by X (0 to 2), read at $0872
; $0977 referenced 1 time by $0872
l0977
    .byte $31, $32, $33                                               ; 0977: 31 32 33    123
; $097a referenced 1 time by $0897
l097a
    .byte 0                                                           ; 097a: 00          .
; $097b referenced 1 time by $089a
l097b
    .byte 0                                                           ; 097b: 00          .
; $097c referenced 1 time by $08ba
l097c
    .byte 0                                                           ; 097c: 00          .
; $097d referenced 1 time by $08dc
l097d
    .byte 0                                                           ; 097d: 00          .
; $097e referenced 1 time by $08df
l097e
    .byte 0                                                           ; 097e: 00          .
; $097f referenced 1 time by $08fb
l097f
    .byte 0                                                           ; 097f: 00          .
; $0980 referenced 1 time by $08fe
l0980
    .byte 0                                                           ; 0980: 00          .
; $0981 referenced 1 time by $0901
l0981
    .byte 0                                                           ; 0981: 00          .
; $0982 referenced 2 times by $0907, $0929
l0982
    .byte 0                                                           ; 0982: 00          .
; $0983 referenced 1 time by $090d
l0983
    .byte 0                                                           ; 0983: 00          .
; $0984 referenced 1 time by $0913
l0984
    .byte 0                                                           ; 0984: 00          .
; $0985 referenced 1 time by $0916
l0985
    .byte 0                                                           ; 0985: 00          .
pydis_end

.cerror (<filename) != $62, "Assertion failed: <filename == $62"
.cerror (<filename_2) != $64, "Assertion failed: <filename_2 == $64"
.cerror (<irq_handler) != $4b, "Assertion failed: <irq_handler == $4b"
.cerror (<l0968) != $68, "Assertion failed: <l0968 == $68"
.cerror (<pydis_end) != $86, "Assertion failed: <pydis_end == $86"
.cerror (>filename) != $09, "Assertion failed: >filename == $09"
.cerror (>filename_2) != $09, "Assertion failed: >filename_2 == $09"
.cerror (>irq_handler) != $09, "Assertion failed: >irq_handler == $09"
.cerror (>l0968) != $09, "Assertion failed: >l0968 == $09"
.cerror (>pydis_end) != $09, "Assertion failed: >pydis_end == $09"
.cerror (basic_end) != $0825, "Assertion failed: basic_end == $0825"
.cerror (basic_line_15) != $0810, "Assertion failed: basic_line_15 == $0810"
.cerror (basic_line_20) != $081b, "Assertion failed: basic_line_20 == $081b"
.cerror (free_zero_page) != $fb, "Assertion failed: free_zero_page == $fb"

; Label references by decreasing frequency:
;     CHROUT:                    5
;     PLOT:                      2
;     SETLFS:                    2
;     SETNAM:                    2
;     free_zero_page:            2
;     l0002:                     2
;     l0982:                     2
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
;     c088b:                     1
;     cia1_interrupt_control:    1
;     cia1_port_a:               1
;     colour_ram:                1
;     irq_vector:                1
;     kernal_irq_handler:        1
;     keyboard_buffer_length:    1
;     l0954:                     1
;     l0977:                     1
;     l097a:                     1
;     l097b:                     1
;     l097c:                     1
;     l097d:                     1
;     l097e:                     1
;     l097f:                     1
;     l0980:                     1
;     l0981:                     1
;     l0983:                     1
;     l0984:                     1
;     l0985:                     1
;     loop_c0860:                1
;     loop_c0872:                1
;     loop_c092e:                1
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
;     c088b
;     l0002
;     l0954
;     l0968
;     l0977
;     l097a
;     l097b
;     l097c
;     l097d
;     l097e
;     l097f
;     l0980
;     l0981
;     l0982
;     l0983
;     l0984
;     l0985
;     loop_c0860
;     loop_c0872
;     loop_c092e

; Stats:
;
;     Total size (Code + Data) = 389 bytes
;     Code                     = 301 bytes (77%)
;     Data                     = 88 bytes (23%)
;
;     Number of instructions   = 126
;     Number of data bytes     = 24 bytes
;     Number of data words     = 14 bytes
;     Number of string bytes   = 50 bytes
;     Number of strings        = 8

