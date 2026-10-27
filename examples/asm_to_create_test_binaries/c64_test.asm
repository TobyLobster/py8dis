; A C64 program for commodore.c64() (see python/c64_test.py): a BASIC
; program that SYSes to the machine code, which sets up a raster interrupt,
; calls the Kernal (CHROUT, PLOT, files, LOAD, SAVE etc.) and BASIC's ROM
; routines, uses the hardware and the OS workspace, and has PETSCII strings
; and undocumented opcodes. Assemble with:
;
;   acme -f cbm -o ../orig/c64_test.orig c64_test.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6510

chrout  = $ffd2
plot    = $fff0
setlfs  = $ffba
setnam  = $ffbd
open    = $ffc0
close   = $ffc3
chkin   = $ffc6
chrin   = $ffcf
clrchn  = $ffcc
load    = $ffd5
save    = $ffd8
setmsg  = $ff90
rdtim   = $ffde
getin   = $ffe4
readst  = $ffb7
screen  = $ffed
strout  = $ab1e
linprt  = $bdcd

    * = $0801

; The BASIC program: 10 REM C64 TEST, 15 PRINT"{clear}HI", 20 SYS2087
line10
    !word line15
    !word 10
    !byte $8f               ; REM
    !pet " c64 test", 0
line15
    !word line20
    !word 15
    !byte $99, $22, $93     ; PRINT " {clear}
    !pet "hi"
    !byte $22, 0            ; "
line20
    !word basic_end
    !word 20
    !byte $9e               ; SYS
    !pet "2087", 0
basic_end
    !word 0

start
!if start != 2087 {
    !error "start isn't at 2087, as the SYS says"
}
    ; A raster interrupt
    sei
    lda #<irq
    sta $0314
    lda #>irq
    sta $0315
    lda #$7f
    sta $dc0d
    lda #1
    sta $d01a
    lda #100
    sta $d012
    lda $d011
    and #$7f
    sta $d011
    cli

    ; Colours
    lda #0
    sta $d020
    lda #6
    sta $d021
    ldx #1
    stx $0286

    ; Print a message
    lda #$93
    jsr chrout
    ldx #0
print_loop
    lda message,x
    beq printed
    jsr chrout
    inx
    bne print_loop
printed
    lda #'!'
    jsr chrout

    ; Move the cursor, then read where it is
    clc
    ldx #5
    ldy #10
    jsr plot
    sec
    jsr plot
    stx cursor_row
    sty cursor_column

    ; Read a byte from the disk drive's command channel
    lda #15
    ldx #8
    ldy #15
    jsr setlfs
    lda #command_end - command
    ldx #<command
    ldy #>command
    jsr setnam
    jsr open
    ldx #15
    jsr chkin
    jsr chrin
    sta byte_read
    jsr clrchn
    lda #15
    jsr close

    ; Load a file to the address it was saved from, then save some memory
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
    stx load_end
    sty load_end + 1
    lda #<start
    sta $fb
    lda #>start
    sta $fc
    lda #$fb
    ldx #<end
    ldy #>end
    jsr save

    ; Kernal messages, the clock, the keyboard, the status and the screen
    lda #$c0
    jsr setmsg
    jsr rdtim
    sty jiffies
    stx jiffies + 1
    sta jiffies + 2
    jsr getin
    sta key
    jsr readst
    sta io_status
    jsr screen
    stx screen_columns
    sty screen_rows

    ; BASIC's ROM: print a string and a number
    lda #<basic_message
    ldy #>basic_message
    jsr strout
    lda #0
    ldx #42
    jsr linprt

    ; The OS workspace, the screen, the colour RAM, a CIA and a sprite
    lda $c6
    sta key
    ldx #39
fill_loop
    lda #$51
    sta $0400,x
    lda #1
    sta $d800,x
    dex
    bpl fill_loop
    lda $dc00
    sta $d000
    lda $a2
    sta $07f8

    ; Undocumented opcodes
    lax $fb
    sbx #1
    rts

irq
    asl $d019
    inc $d020
    jmp $ea31

message
    !pet "hello, world", 13, 0
command
    !pet "i0"
command_end
filename
    !pet "data"
filename_end
basic_message
    !pet "the answer is ", 0

cursor_row
    !byte 0
cursor_column
    !byte 0
byte_read
    !byte 0
load_end
    !word 0
jiffies
    !byte 0, 0, 0
key
    !byte 0
io_status
    !byte 0
screen_columns
    !byte 0
screen_rows
    !byte 0
end
