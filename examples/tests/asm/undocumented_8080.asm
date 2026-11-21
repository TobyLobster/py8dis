; The 8080's undocumented opcodes (October 2026), written as bytes since
; assemblers don't accept them.
; Assemble with: z88dk-z80asm -m8080 -b -o../orig/undocumented_8080.orig undocumented_8080.asm
;
; &08, &10, &18, &20, &28, &30 and &38 run as NOP, &CB as JMP, &D9 as RET, and
; &DD, &ED and &FD as CALL. py8dis traces them as what they run as, and writes
; them as data bytes.

    ORG $0100

start:
    mvi a, $41
    db $08, $10, $18, $20, $28, $30, $38    ; NOP (seven times)
    db $dd                                  ; CALL subroutine
    dw subroutine
    db $ed                                  ; CALL subroutine
    dw subroutine
    db $fd                                  ; CALL subroutine
    dw subroutine
    db $cb                                  ; JMP finish
    dw finish

subroutine:
    inr a
    db $d9                                  ; RET

finish:
    ret
