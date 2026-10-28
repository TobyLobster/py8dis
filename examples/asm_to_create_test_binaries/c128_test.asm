; A C128 program for commodore.c128() (see python/c128_test.py): a BASIC
; program that SYSes to the machine code, which prints with PRIMM, uses the
; MMU, the VDC, the VIC-II and the C128's workspace, sets the IRQ vector,
; calls routines in other banks with JSRFAR and JMPFAR (set up in different
; orders), and loads a file into bank 1.
; Assemble with:
;
;   acme -f cbm -o ../orig/c128_test.orig c128_test.asm
;
; (It isn't meant to do anything useful when run.)

primm   = $ff7d
jsrfar  = $ff6e
jmpfar  = $ff71
setbnk  = $ff68
setlfs  = $ffba
setnam  = $ffbd
load    = $ffd5
chrout  = $ffd2

    * = $1c01

; The BASIC program: 10 SYS7181
line10
    !word basic_end
    !word 10
    !byte $9e               ; SYS
    !pet "7181", 0
basic_end
    !word 0

start
!if start != 7181 { !error "start isn't at 7181, as the SYS says" }
    ; Bank 15 (the ROMs and I/O), and 2MHz
    lda #0
    sta $ff00
    lda #1
    sta $d030

    ; Print with PRIMM, and CHROUT
    jsr primm
    !pet "hello, c128", 13, 0
    lda #'!'
    jsr chrout

    ; The VIC-II's border, and the VDC's register 26 (its colours)
    lda #6
    sta $d020
    ldx #26
    stx $d600
vdc_wait
    bit $d600
    bpl vdc_wait
    lda #$f0
    sta $d601

    ; Which screen is in use (40 or 80 columns)?
    lda $d7
    sta screen_mode

    ; The IRQ vector
    sei
    lda #<irq
    sta $0314
    lda #>irq
    sta $0315
    cli

    ; Call a routine in bank 0 with JSRFAR
    lda #0
    sta $02
    lda #>far_routine
    sta $03
    lda #<far_routine
    sta $04
    jsr jsrfar

    ; The same in another order, with the status and A to call it with, and
    ; the C128's usual bank 15
    lda #<far_routine_2
    sta $04
    lda #15
    sta $02
    lda #0
    sta $05
    lda #>far_routine_2
    sta $03
    lda #1
    sta $06
    jsr jsrfar

    ; A routine in RAM 1, which isn't this program's
    lda #1
    sta $02
    lda #$20
    sta $03
    lda #$00
    sta $04
    jsr jsrfar

    ; JMPFAR, from a subroutine
    jsr far_jump

    ; Load a file into bank 1
    lda #1
    ldx #0
    jsr setbnk
    lda #1
    ldx #8
    ldy #1
    jsr setlfs
    lda #filename_end - filename
    ldx #<filename
    ldy #>filename
    jsr setnam
    lda #0
    jsr load
    rts

far_routine
    inc $d020
    rts

far_routine_2
    dec $d020
    rts

far_jump
    lda #0
    sta $02
    lda #>far_routine_3
    sta $03
    lda #<far_routine_3
    sta $04
    jmp jmpfar

far_routine_3
    inc $d021
    rts

irq
    inc $d020
    jmp $fa65

filename
    !pet "data"
filename_end
screen_mode
    !byte 0
