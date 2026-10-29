; A C64 program with code for the 1541 disk drive in it, for
; python/fastload_test.py: it sends the drive code to the drive with M-W,
; 32 bytes at a time, then runs it with M-E. The drive code (at drive_code
; here) runs at &0500 in the drive, with an EXECUTE job's code at &0600.
;
;   acme -f cbm -o ../orig/fastload_test.orig fastload_test.asm

chrout  = $ffd2
setlfs  = $ffba
setnam  = $ffbd
open    = $ffc0
chkout  = $ffc9
clrchn  = $ffcc
listen  = $ffb1
ptr     = $fb

    * = $0801
    !word basic_end
    !word 10
    !byte $9e           ; SYS
    !pet "2061", 0
basic_end
    !word 0

start
    lda #$37            ; the 6510's port: the usual memory configuration
    sta $01
    lda #0
    sta $d020           ; (not the drive's VIA)
    lda #15             ; open 15,8,15
    ldx #8
    ldy #15
    jsr setlfs
    lda #0
    jsr setnam
    jsr open
    ldx #15
    jsr chkout
    ldy #0
send_byte
    lda drive_code,y    ; (just the bytes, after "M-W", address, 32)
    jsr chrout
    iny
    bne send_byte
    jsr clrchn
    rts

drive_code
!pseudopc $0500 {
    sei
    lda $1c00           ; turn on the LED
    ora #$08
    sta $1c00
    lda #18             ; read track 18, sector 1 into buffer 0
    sta $06
    lda #1
    sta $07
    lda #$80
    sta $00
wait_read
    lda $00
    bmi wait_read
    ldx #69
move_up
    lda $0300,x
    sta $0345,x
    dex
    bne move_up
    lda #18             ; run the code in buffer 3 on track 18
    sta $0c
    lda #$e0
    sta $03
wait_execute
    lda $03
    bmi wait_execute
    lda $1800           ; the serial bus
    and #$04
    cli
    jmp $ebe7           ; the DOS's main loop
    !fill $0600 - *, 0
    ; The EXECUTE job's code
    jsr $f556           ; wait for a sync mark
wait_byte
    bvc wait_byte
    clv
    lda $1c01
    sta $0400
    lda #1
    jmp $f969           ; end the job
}
