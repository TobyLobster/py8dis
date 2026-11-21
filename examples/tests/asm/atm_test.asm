; An Acorn Atom ATM file (November 2026), for python/atm_test.py, which
; loads it with load_atm(): a 22-byte header (the name, padded with zeroes
; to 16 bytes, then the load address, execution address and length), then
; a short program whose code starts after its message, at the execution
; address. Assemble with:
;
;   acme -o ../orig/atm_test.orig atm_test.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6502

OSWRCH = $fff4

    * = $2900 - 22

; The header
    !text "ATM TEST"
    !fill 8, 0
    !word load, exec, end - load

load
message
    !text "HELLO"
    !byte 13
message_end

exec
    ldx #0
loop
    lda message,x
    jsr OSWRCH
    inx
    cpx #message_end - message
    bne loop
    rts
end
