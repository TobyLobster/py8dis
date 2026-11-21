; A C64 program with code for the 1541 disk drive in it, for
; python/drive_code_names.py: the C64 code and the drive code both use $0300
; (the C64's IERROR vector, and the 1541's buffer 0), the C64 code first, so
; each must get its own machine's name for it. Assemble with:
;
;   acme -f cbm -o ../orig/drive_code_names.orig drive_code_names.asm
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
    lda $0300               ; the C64's IERROR vector
    sta $fb
    rts

; The drive code, which runs at $0500 in the drive (in buffer 2)
drive_code
!pseudopc $0500 {
    lda $0300               ; the drive's buffer 0
    sta $0301
    rts
}
drive_code_end
