; A ProDOS 8 SYS program for python/prodos_test.py (with apple.apple2()):
; MLI calls with their parameter lists (pathnames, buffers, a position, an
; interrupt handler), two calls sharing a list, ProDOS's global page, and
; QUIT. The go script copies it to prodos_test#ff2000, so that
; load_apple_file() loads it as a SYS file. Assemble with:
;
;   acme -o ../orig/prodos_test.orig prodos_test.asm
;
; (It isn't meant to do anything useful when run.)

mli      = $bf00
date     = $bf90
machid   = $bf98
cout     = $fded

* = $2000

start
    ; Which machine is this?
    lda machid
    and #$30
    sta $06

    ; The prefix, the time and the date
    jsr mli
    !byte $c7               ; GET_PREFIX
    !word get_prefix_params
    jsr mli
    !byte $82               ; GET_TIME
    !word 0
    lda date

    ; Create, open, write and close a file
    jsr mli
    !byte $c0               ; CREATE
    !word create_params
    jsr mli
    !byte $c8               ; OPEN
    !word open_params
    bcs error
    lda open_ref
    sta write_ref
    sta mark_ref
    sta close_ref
    jsr mli
    !byte $ce               ; SET_MARK
    !word mark_params
    jsr mli
    !byte $cb               ; WRITE
    !word write_params
    jsr mli
    !byte $cc               ; CLOSE
    !word close_params

    ; An interrupt handler
    jsr mli
    !byte $40               ; ALLOC_INTERRUPT
    !word interrupt_params

    ; Quit
    jsr mli
    !byte $65               ; QUIT
    !word quit_params
error
    jsr cout
    rts

my_interrupt
    clc
    rts

get_prefix_params
    !byte 1
    !word prefix_buffer
create_params
    !byte 7
    !word filename
    !byte $c3               ; Access
    !byte $06               ; File type (BIN)
    !word $2000             ; Aux type
    !byte $01               ; Storage type
    !word 0, 0              ; Date and time
open_params
    !byte 3
    !word filename
    !word $9600             ; I/O buffer
open_ref
    !byte 0
mark_params
    !byte 2
mark_ref
    !byte 0
    !byte 0, 2, 0           ; Position ($200)
write_params
    !byte 4
write_ref
    !byte 0
    !word $4000             ; Data buffer (hi-res page 2)
    !word $2000             ; Request count
    !word 0                 ; Transfer count
close_params
    !byte 1
close_ref
    !byte 0
interrupt_params
    !byte 2
    !byte 0
    !word my_interrupt
quit_params
    !byte 4
    !byte 0
    !word 0
    !byte 0
    !word 0
filename
    !byte filename_end - filename - 1
    !text "PICTURE"
filename_end
prefix_buffer
    !fill 64, 0
