; A ZX Spectrum program (October 2026), for spectrum_test (see its control
; file), which disassembles it with spectrum.spectrum48(): it prints with
; RST $10, uses the calculator (RST $28), the system variables (directly and
; with IY), ROM routines, the border, the keyboard and the screen, sets the
; current channel's output routine, pushes a value and a return address, and
; stops with an error (RST $08).
; Assemble with: z88dk-z80asm -mz80 -b -o../orig/spectrum_test.orig spectrum_test.asm

    ORG $8000

start:
    call $0d6b                      ; CLS
    ld a,2
    call $1601                      ; CHAN-OPEN: the upper screen
    ld a,$16                        ; AT 10,5
    rst $10
    ld a,10
    rst $10
    ld a,5
    rst $10
    ld de,message
    ld bc,message_end - message
    call $203c                      ; PR-STRING

    ; Print 2 * PI with the calculator
    rst $28
    db $a3                          ; stk-pi/2
    db $34                          ; stk-data 4
    db $40, $b0, $00, $04
    db $04                          ; multiply
    db $38                          ; end-calc
    call $2de3                      ; PRINT-FP

    ; The border, and wait for a key in the bottom half row
    ld a,1
    out ($fe),a
wait:
    ld a,$7f
    in a,($fe)
    rra
    jr c,wait
    xor a
    ld ($5c08),a                    ; LAST-K
    res 5,(iy+$01)                  ; FLAGS: no key yet

    ; Colour the top left of the screen, and plot a pixel
    ld a,$38
    ld ($5800),a
    ld a,$ff
    ld ($4000),a
    ld bc,$1020
    call $22e5                      ; PLOT-SUB

    ; Wait for 50 frames
    ld hl,$5c78                     ; FRAMES
    ld a,(hl)
    add a,50
frame:
    cp (hl)
    jr nz,frame

    ; Set the current channel's output routine to my_print (found from
    ; what the code does, and traced)
    ld hl,($5c51)                   ; CURCHL
    ld de,my_print
    ld (hl),e
    inc hl
    ld (hl),d

    ; A value pushed and popped again: table is data, not code
    ld hl,table
    push hl
    call $0d6b                      ; CLS
    pop hl

    ; A return address pushed: clear_screen returns to resume (found from
    ; what the code does, and traced)
    ld hl,resume
    push hl
    jp clear_screen
resume:
    ; Stop with report 9, STOP statement
    rst $08
    db $08

clear_screen:
    call $0d6b                      ; CLS
    ret

my_print:
    jp $09f4                        ; PRINT-OUT

table:
    db $3e, $01, $c9                ; (as code, 'ld a,1 : ret')

message:
    db "Hello", $0d
message_end:
