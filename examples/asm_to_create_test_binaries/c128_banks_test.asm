; A C128 program that changes the MMU's configuration, for commodore.c128()
; (see python/c128_banks_test.py). The same addresses mean different things
; in different configurations: e.g. $d020 is the VIC-II's border colour with
; I/O at $d000, and RAM in bank 0. Assemble with:
;
;   acme -f cbm -o ../orig/c128_banks_test.orig c128_banks_test.asm
;
; (It isn't meant to do anything useful when run.)

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
    ; Bank 15: the ROMs and I/O
    lda #0
    sta $ff00
    sta $d020               ; the border colour

    ; All RAM (RAM 0), but with I/O
    lda #$3e
    sta $ff00
    sta $d021               ; the background colour
    lda $e000               ; RAM, not the Kernal ROM
    sta $fb

    ; Bank 0: RAM 0 only
    lda #$3f
    sta $ff00
    lda $d020               ; RAM, not the VIC-II
    sta $fc
    lda #$41
    jsr $ffd2               ; RAM, not the Kernal's CHROUT

    ; Bank 1, through the MMU's register in I/O, from bank 15
    lda #0
    sta $ff00
    ldx #$7f
    stx $d500
    lda $1000               ; RAM 1, not the function key lengths
    sta $0300               ; (common RAM: RAM 0 in every bank)

    ; Preconfiguration A (whatever was set at $d501)
    sta $ff01
    lda $d020

    ; Back to bank 15, then call a routine that runs in bank 0 (see the
    ; control file)
    lda #0
    sta $ff00
    jsr in_bank_0
    lda $d020               ; the border colour again
    lda #$41
    jsr $ffd2               ; the Kernal's CHROUT
    rts

; Called with the MMU set to bank 0 (by the caller, in a real program)
in_bank_0
    ldx #0
-
    lda $d000,x             ; RAM, not the VIC-II
    sta $4000,x             ; RAM, not BASIC
    inx
    bne -
    lda #1
    sta $d020               ; RAM, so not a colour
    jsr $ff7d               ; RAM, not the Kernal's PRIMM, so no string after it
    rts
in_bank_0_end
