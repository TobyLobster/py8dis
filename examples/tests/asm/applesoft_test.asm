; An Applesoft program with machine code after it, for
; python/applesoft_test.py (with apple.apple2() and
; apple.applesoft_program()): its lines (with quotes, a REM, CALLs to the
; machine code and to the Monitor's HOME), then the machine code at $0900,
; which calls Applesoft's routines (STROUT, LINPRT, the hi-res routines,
; CHRGET and GETBYT) and sets the USR and & vectors. Assemble with:
;
;   acme -o ../orig/applesoft_test.orig applesoft_test.asm
;
; (It isn't meant to do anything useful when run.)

; Applesoft's tokens
TOKEN_HOME  = $97
TOKEN_PRINT = $ba
TOKEN_REM   = $b2
TOKEN_POKE  = $b9
TOKEN_CALL  = $8c
TOKEN_END   = $80
TOKEN_EQUAL = $d0
TOKEN_FOR   = $81
TOKEN_TO    = $c1
TOKEN_NEXT  = $82

; Applesoft's zero page and routines
usrvec  = $0a
txttab  = $67
errnum  = $de
chrget  = $b1
chrgot  = $b7
strout  = $db3a
getbyt  = $e6f8
linprt  = $ed24
hgr     = $f3e2
hplot0  = $f457
hglin   = $f53a
sethcol = $f6f0
amperv  = $03f5

* = $0801

line_10
    !word line_20
    !word 10
    !byte TOKEN_HOME, ':', TOKEN_PRINT
    !text "\"HELLO, WORLD\""
    !byte 0
line_20
    !word line_30
    !word 20
    !byte TOKEN_REM
    !text " A \"REMARK\": NOT A PRINT"
    !byte 0
line_30
    !word line_40
    !word 30
    !byte TOKEN_FOR
    !text "I", TOKEN_EQUAL, "1", TOKEN_TO, "3", ':', TOKEN_CALL, "2304", ':', TOKEN_NEXT
    !byte 0
line_40
    !word line_50
    !word 40
    !byte TOKEN_CALL
    !text "-936"
    !byte 0
line_50
    !word program_end
    !word 50
    !byte TOKEN_END
    !byte 0
program_end
    !word 0

    !fill $0900 - *, 0

; The machine code, which line 30 calls
    lda #<message
    ldy #>message
    jsr strout
    lda #$12
    ldx #$34
    jsr linprt
    jsr hgr
    ldx #3
    jsr sethcol
    ldx #<140
    ldy #>140
    lda #96
    jsr hplot0
    lda #<279
    ldx #>279
    ldy #191
    jsr hglin
    jsr chrget
    jsr getbyt
    stx $06
    lda errnum
    sta $07
    lda txttab
    sta $08

    ; The USR() function's vector, and the & command's
    lda #<usr_function
    sta usrvec+1
    lda #>usr_function
    sta usrvec+2
    lda #$4c
    sta amperv
    lda #<ampersand
    sta amperv+1
    lda #>ampersand
    sta amperv+2
    rts

usr_function
    rts

ampersand
    jsr chrgot
    rts

message
    !text "IN MACHINE CODE", 0
