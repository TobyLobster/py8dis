; 8080 code (November 2026) for python/fixes_8080.py: RST traced as a call
; (on after it, and at the code it calls), CALL and RST naming the code
; they call sub_..., LXI's character comment only for a value under $100,
; and a conditional jump with an expression.
; Assemble with: z88dk-z80asm -m8080 -b -o../orig/fixes_8080.orig fixes_8080.asm

    ORG $0000

start:
    jmp main
    db 0, 0, 0, 0, 0

; RST 1's code, at $0008
    mvi a, 1
    ret

main:
    rst $08                 ; RST 1, which returns here
    lxi h, $0120            ; not ' ' (its low byte)
    lxi b, $0041            ; 'A'
    cpi 0
    jz start + finish_offset ; with expr()
    call subroutine
finish:
    hlt

subroutine:
    inr a
    ret

finish_offset = finish - start
