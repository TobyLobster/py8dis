; An Acorn Atom program (November 2026), for python/atom_hardware.py, which
; disassembles it with acorn.atom(): it writes to the 8255's ports (the
; graphics mode and keyboard row at #B000, the speaker and colour set at
; #B002, and the control register at #B003), with known values and with
; read-modify-writes, and tests their input bits. Assemble with:
;
;   acme -o ../orig/atom_hardware.orig atom_hardware.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6502

PORT_A = $b000
PORT_B = $b001
PORT_C = $b002
CONTROL = $b003

    * = $2900

start
    lda #$8a                ; the 8255's modes, as the kernel sets them
    sta CONTROL
    lda #$f0                ; CLEAR 4
    sta PORT_A
    lda #$10                ; 64x64, 4 colours
    sta PORT_A
    lda #0                  ; text mode
    sta PORT_A
    ldx #5                  ; keyboard row 5
    stx PORT_A
    lda PORT_A              ; keyboard row 3, keeping the mode
    and #$f0
    ora #3
    sta PORT_A
    inc PORT_A              ; the next row

    lda PORT_C              ; toggle the speaker
    eor #4
    sta PORT_C
    lda PORT_C              ; the other colour set
    ora #8
    sta PORT_C
    lda PORT_C              ; colour set 0
    and #$f7
    sta PORT_C
    lda #5                  ; set port C bit 2
    sta CONTROL
    lda #4                  ; clear it
    sta CONTROL

wait_sync
    bit PORT_C              ; wait for the field sync
    bpl wait_sync
wait_keys
    bit PORT_B              ; wait for SHIFT and CTRL to be let go
    bpl wait_keys
    bvc wait_keys
    bit PORT_C              ; REPT, then the field sync
    bvs wait_keys
    bmi wait_keys
    bit PORT_B              ; SHIFT and CTRL
    bit PORT_B              ; CTRL
    bvc ctrl_pressed
    lda #$10                ; the 2.4 kHz tone input
    bit PORT_C
    beq ctrl_pressed
ctrl_pressed
    lda PORT_B              ; CTRL
    and #$40
    sta $70
    lda PORT_C              ; REPT
    and #$40
    sta $71
    rts
