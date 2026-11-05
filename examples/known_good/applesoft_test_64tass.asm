; Text encodings (for '.text' and character literals)
    .enc "apple"
    .cdef " ~", $a0

; Memory locations

; Zero page ($0000-$00ff)
l0006   = $0006
l0007   = $0007
l0008   = $0008
usr_jump = $000a
TXTTAB  = $0067
CHRGET  = $00b1
CHRGOT  = $00b7
ERRNUM  = $00de

; Vectors ($03f0-$03ff)
AMPERV  = $03f5

; Applesoft ROM ($d000-$f7ff)
STROUT  = $db3a
GETBYT  = $e6f8
LINPRT  = $ed24
HGR     = $f3e2
HPLOT0  = $f457
HGLIN   = $f53a
SETHCOL = $f6f0

    * = $0801

; 10 HOME : PRINT "HELLO, WORLD"
pydis_start
basic_line_10
    .word basic_line_20                                               ; 0801: 17 08       ..
    .word 10                                                          ; 0803: 0a 00       ..
    .byte $97                                                         ; 0805: 97          .
    .enc "none"
    .text ":"                                                         ; 0806: 3a          :
    .enc "apple"
    .byte $ba                                                         ; 0807: ba          :
    .enc "none"
    .text """HELLO, WORLD"""                                          ; 0808: 22 48 45... "HE
    .enc "apple"
    .byte 0                                                           ; 0816: 00          .
; 20 REM A "REMARK": NOT A PRINT
basic_line_20
    .word basic_line_30                                               ; 0817: 35 08       ..
    .word 20                                                          ; 0819: 14 00       ..
    .byte $b2                                                         ; 081b: b2          2
    .enc "none"
    .text " A ""REMARK"": NOT A PRINT"                                ; 081c: 20 41 20...  A
    .enc "apple"
    .byte 0                                                           ; 0834: 00          .
; 30 FOR I = 1 TO 3: CALL 2304: NEXT
basic_line_30
    .word basic_line_40                                               ; 0835: 48 08       ..
    .word 30                                                          ; 0837: 1e 00       ..
    .byte $81                                                         ; 0839: 81          .
    .enc "none"
    .text "I"                                                         ; 083a: 49          I
    .enc "apple"
    .byte $d0                                                         ; 083b: d0          P
    .enc "none"
    .text "1"                                                         ; 083c: 31          1
    .enc "apple"
    .byte $c1                                                         ; 083d: c1          A
    .enc "none"
    .text "3:"                                                        ; 083e: 33 3a       3:
    .enc "apple"
    .byte $8c                                                         ; 0840: 8c          .
    .enc "none"
    .text "2304:"                                                     ; 0841: 32 33 30... 230
    .enc "apple"
    .byte $82                                                         ; 0846: 82          .
    .byte 0                                                           ; 0847: 00          .
; 40 CALL -936
basic_line_40
    .word basic_line_50                                               ; 0848: 52 08       ..
    .word 40                                                          ; 084a: 28 00       ..
    .byte $8c                                                         ; 084c: 8c          .
    .enc "none"
    .text "-936"                                                      ; 084d: 2d 39 33... -93
    .enc "apple"
    .byte 0                                                           ; 0851: 00          .
; 50 END
basic_line_50
    .word basic_end                                                   ; 0852: 58 08       ..
    .word 50                                                          ; 0854: 32 00       ..
    .byte $80                                                         ; 0856: 80          .
    .byte 0                                                           ; 0857: 00          .
basic_end
    .word 0                                                           ; 0858: 00 00       ..
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 085a: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 086e: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0882: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0896: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08aa: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08be: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08d2: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08e6: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0                                            ; 08fa: 00 00 00... ...

call_entry
    lda #<l0955                                                       ; 0900: a9 55       ).
    ldy #>l0955                                                       ; 0902: a0 09        .
    jsr STROUT                                                        ; 0904: 20 3a db    ..[ ; Print the zero-terminated string at A (low) and Y (high)
    lda #$12                                                          ; 0907: a9 12       ).
    ldx #$34                                                          ; 0909: a2 34       ".
    jsr LINPRT                                                        ; 090b: 20 24 ed    ..m ; Print 4660
    jsr HGR                                                           ; 090e: 20 e2 f3    .bs ; Show hi-res page 1 (mixed), and clear it
    ldx #3                                                            ; 0911: a2 03       ".
    jsr SETHCOL                                                       ; 0913: 20 f0 f6    .pv ; Set the hi-res colour to 3 (white)
    ldx #$8c                                                          ; 0916: a2 8c       ".
    ldy #0                                                            ; 0918: a0 00        .
    lda #$60                                                          ; 091a: a9 60       ).
    jsr HPLOT0                                                        ; 091c: 20 57 f4    ..t ; Plot a hi-res point at (140, 96)
    lda #$17                                                          ; 091f: a9 17       ).
    ldx #1                                                            ; 0921: a2 01       ".
    ldy #$bf ; '?'                                                    ; 0923: a0 bf        ?
    jsr HGLIN                                                         ; 0925: 20 3a f5    ..u ; Draw a hi-res line to (279, 191)
    jsr CHRGET                                                        ; 0928: 20 b1 00    .1. ; Get the program's next character (C clear for a digit)
    jsr GETBYT                                                        ; 092b: 20 f8 e6    .xf ; Evaluate a byte (0-255) into X
    stx l0006                                                         ; 092e: 86 06       .. ; X=byte
    lda ERRNUM                                                        ; 0930: a5 de       %^
    sta l0007                                                         ; 0932: 85 07       ..
    lda TXTTAB                                                        ; 0934: a5 67       %.
    sta l0008                                                         ; 0936: 85 08       ..

    ; Set the USR() function's JMP to 'usr_handler'
    lda #<usr_handler                                                 ; 0938: a9 50       ).
    sta usr_jump+1                                                    ; 093a: 85 0b       ..
    lda #>usr_handler                                                 ; 093c: a9 09       ).
    sta usr_jump+2                                                    ; 093e: 85 0c       ..

    lda #$4c                                                          ; 0940: a9 4c       ).
    sta AMPERV                                                        ; 0942: 8d f5 03    .u.

    ; Set the & command's JMP to 'ampersand_handler'
    lda #<ampersand_handler                                           ; 0945: a9 51       ).
    sta AMPERV+1                                                      ; 0947: 8d f6 03    .v.
    lda #>ampersand_handler                                           ; 094a: a9 09       ).
    sta AMPERV+2                                                      ; 094c: 8d f7 03    .w.

    rts                                                               ; 094f: 60          .

usr_handler
    rts                                                               ; 0950: 60          .

ampersand_handler
    jsr CHRGOT                                                        ; 0951: 20 b7 00    .7. ; Get the program's character again (C clear for a digit)
    rts                                                               ; 0954: 60          .

l0955
    .enc "none"
    .text "IN MACHINE CODE", 0                                        ; 0955: 49 4e 20... IN
    .enc "apple"
pydis_end

.cerror (<ampersand_handler) != $51, "Assertion failed: <ampersand_handler == $51"
.cerror (<l0955) != $55, "Assertion failed: <l0955 == $55"
.cerror (<usr_handler) != $50, "Assertion failed: <usr_handler == $50"
.cerror (>ampersand_handler) != $09, "Assertion failed: >ampersand_handler == $09"
.cerror (>l0955) != $09, "Assertion failed: >l0955 == $09"
.cerror (>usr_handler) != $09, "Assertion failed: >usr_handler == $09"
.cerror (basic_end) != $0858, "Assertion failed: basic_end == $0858"
.cerror (basic_line_20) != $0817, "Assertion failed: basic_line_20 == $0817"
.cerror (basic_line_30) != $0835, "Assertion failed: basic_line_30 == $0835"
.cerror (basic_line_40) != $0848, "Assertion failed: basic_line_40 == $0848"
.cerror (basic_line_50) != $0852, "Assertion failed: basic_line_50 == $0852"

; Label references by decreasing frequency:
;     AMPERV:    1
;     CHRGET:    1
;     CHRGOT:    1
;     ERRNUM:    1
;     GETBYT:    1
;     HGLIN:     1
;     HGR:       1
;     HPLOT0:    1
;     LINPRT:    1
;     SETHCOL:   1
;     STROUT:    1
;     TXTTAB:    1
;     l0006:     1
;     l0007:     1
;     l0008:     1

; Automatically generated labels:
;     l0006
;     l0007
;     l0008
;     l0955

; Stats:
;
;     Total size (Code + Data) = 356 bytes
;     Code                     = 85 bytes (24%)
;     Data                     = 271 bytes (76%)
;
;     Number of instructions   = 38
;     Number of data bytes     = 181 bytes
;     Number of data words     = 22 bytes
;     Number of string bytes   = 68 bytes
;     Number of strings        = 9

