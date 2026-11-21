; A C64 program with code for the 1541 disk drive in it, for
; python/drive_code_fixes.py: the drive code runs at $0310, in the middle
; of buffer 0 (so buffer 0 isn't named), and stores to the job queue's $05,
; which isn't a job (the 1541 has no buffer 5), and to $01, which is job 1.
; Assemble with:
;
;   acme -f cbm -o ../orig/drive_code_fixes.orig drive_code_fixes.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6502

    * = $0801

; The BASIC program: 10 SYS2061
    !word basic_end
    !word 10
    !byte $9e               ; SYS
    !pet "2061", 0
basic_end
    !word 0

start
    rts

; The drive code, which runs at $0310 in the drive (in buffer 0)
drive_code
!pseudopc $0310 {
    lda #$80                ; not a job: $05 is unused
    sta $05
    lda #$80                ; job 1: read
    sta $01
    lda $0300               ; buffer 0, which the drive code is in
    sta $0301
    rts
}
drive_code_end
