; A DOS 3.3 binary file for python/dos33_test.py (with apple.apple2()): its
; 4-byte header (load address and length), then a program at $6000 that
; uses DOS 3.3 from machine code: a DOS command printed with COUT, the
; length and address of the file loaded, RWTS with two IOBs of its own
; (one with its own device characteristics table) and with DOS's (found
; with $03E3, and by its address), the file manager, reconnecting DOS's
; hooks after setting the output hook, DOS's memory, and DOS's warm and
; cold starts. Assemble with:
;
;   acme -o ../orig/dos33_test.orig dos33_test.asm
;
; (It isn't meant to do anything useful when run.)

cout            = $fded
dos_warm        = $03d0
dos_cold        = $03d3
dos_fm          = $03d6
dos_rwts        = $03d9
dos_get_fm      = $03dc
dos_get_iob     = $03e3
dos_connect     = $03ea
dos_buffers     = $9d00
saved_csw       = $aa53
maxfiles        = $aa57
load_length     = $aa60
load_address    = $aa72
basic_flag      = $aab6
fm_params       = $b5bb
rwts_entry      = $b7b5
dos_iob         = $b7e8
ibslot          = $b7e9
ibstat          = $b7f5
dos_dct         = $b7fb
rwts            = $bd00
cswl            = $36
ptr             = $06
length          = $08
status          = $0a
old_csw         = $0b

    * = $6000 - 4
    !word start
    !word end - start

start
    ; Is DOS there? ($03D0 holds a JMP)
    lda dos_warm
    cmp #$4c
    beq dos_found
    rts
dos_found

    ; BLOAD a picture, with a DOS command, then find its address and length
    lda #$8d
    jsr cout
    lda #$84
    jsr cout
    ldx #0
print_loop
    lda bload_command,x
    beq printed
    jsr cout
    inx
    bne print_loop
printed
    lda load_address
    sta ptr
    lda load_address+1
    sta ptr+1
    lda load_length
    sta length
    lda load_length+1
    sta length+1

    ; Read track 17, sector 0 with an IOB of our own
    lda #17
    sta iob+4
    lda #0
    sta iob+5
    lda #1
    sta iob+12
    lda #>iob
    ldy #<iob
    jsr dos_rwts
    bcs disk_error
    lda iob+13

    ; Write it with DOS's IOB, found with $03E3
    jsr dos_get_iob
    sty ptr
    sta ptr+1
    ldy #12
    lda #2
    sta (ptr),y
    ldy ptr
    lda ptr+1
    jsr dos_rwts

    ; DOS's IOB by its address, with RWTS's entry
    lda ibslot
    sta iob2+1
    lda #>dos_iob
    ldy #<dos_iob
    jsr rwts_entry
    lda ibstat
    sta status

    ; Another IOB of our own, with RWTS itself (interrupts disabled)
    sei
    lda #>iob2
    ldy #<iob2
    jsr rwts
    cli

    ; The file manager: delete a file, then open one (creating it)
    jsr dos_get_fm
    sty ptr
    sta ptr+1
    ldy #0
    lda #5
    sta (ptr),y
    ldx #1
    jsr dos_fm
    lda fm_params+10
    ldx #0
    jsr dos_fm
    ldx create_flag
    jsr dos_fm

    ; Set the output hook, then reconnect DOS
    lda #<my_output
    sta cswl
    lda #>my_output
    sta cswl+1
    jsr dos_connect
    lda saved_csw
    sta old_csw
    lda saved_csw+1
    sta old_csw+1

    ; DOS's memory
    lda basic_flag
    sta status
    lda maxfiles
    sta status
    lda dos_buffers
    sta ptr
    lda dos_buffers+1
    sta ptr+1
    jmp dos_warm

disk_error
    jsr dos_cold

bload_command
    !xor $80 {
    !text "BLOAD PICTURE,A$2000", $0d
    }
    !byte 0

create_flag
    !byte 1

my_output
    jmp cout

iob
    !byte 1                 ; Table type
    !byte $60               ; Slot 6
    !byte 1                 ; Drive 1
    !byte 0                 ; Any volume
    !byte 0                 ; Track
    !byte 0                 ; Sector
    !word dct
    !word $1000             ; Sector buffer
    !byte 0                 ; Not used
    !byte 0                 ; Byte count
    !byte 1                 ; Command: read
    !byte 0, 0, $60, 1
dct
    !byte 0, 1
    !word $efd8

iob2
    !byte 1, $60, 2, 0, 3, 5
    !word dos_dct
    !word $4000
    !byte 0, 0, 2, 0, 0, $60, 1
end
