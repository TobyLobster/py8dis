; A C64 program for commodore.c64() (see python/c64_memory_test.py) that
; changes the memory configuration with the 6510's port at $01, to switch the
; ROMs and the I/O out and in: with known values, INC and DEC, and a
; read-modify-write (LDA, AND, ORA, STA), in straight code, a loop, a
; subroutine and a subroutine that sets its own configuration, and a routine
; whose configuration the control file gives. Assemble with:
;
;   acme -f cbm -o ../orig/c64_memory_test.orig c64_memory_test.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6510

chrout  = $ffd2

    * = $0801

; The BASIC program: 10 SYS2061
    !word basic_end
    !word 10
    !byte $9e               ; SYS
    !pet "2061", 0
basic_end
    !word 0

start
    sei
    lda #$35                ; RAM, I/O (the BASIC and Kernal ROMs out)
    sta $01
    lda #0
    sta $d020               ; (I/O)
    lda $e000               ; (RAM under the Kernal)
    sta $a000               ; (RAM under BASIC)
    jsr $ffd2               ; (RAM: not CHROUT)
    dec $01                 ; $34: RAM only
    ldx #0
copy_loop
    lda $d000,x             ; (RAM under the I/O, in a loop)
    sta $4000,x
    inx
    bne copy_loop
    jsr all_ram_routine     ; (called with RAM only)
    inc $01                 ; $35 again
    lda #1
    sta $d021               ; (I/O)
    lda $01
    and #$f8
    ora #$07                ; $37: the usual configuration
    sta $01
    lda #'a'
    jsr chrout              ; (CHROUT)
    jsr ram_and_io          ; (sets $35 itself, and returns with it)
    lda $e000               ; (RAM under the Kernal)
    lda #$37
    sta $01
    jsr kernal_out_routine
    cli
    rts

all_ram_routine
    lda $d020               ; (RAM)
    sta $e000
    rts

ram_and_io
    lda #$35
    sta $01
    rts

; Called with the Kernal switched out (by the code that calls it, which isn't
; in this program: the control file says so)
kernal_out_routine_entry
    lda $e010               ; (RAM)
    rts

kernal_out_routine
    lda $fffe               ; (the usual configuration: the Kernal's IRQ vector)
    rts
