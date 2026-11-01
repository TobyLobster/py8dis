; Memory locations

; Zero page ($0000-$00ff)
l0007   = $07
l0070   = $70

    * = $2000

pydis_start
start
    lda #$ff                                                          ; 2000: a9 ff       .. ; Snippet 1 matched
    sta l0007                                                         ; 2002: 85 07       ..
    asl                                                               ; 2004: 0a          .
    ldx #5                                                            ; 2005: a2 05       ..
    bne c200a                                                         ; 2007: d0 01       .. ; ALWAYS branch

    brk                                                               ; 2009: 00          .

; $200a referenced 1 time by $2007
c200a
    lda l2010                                                         ; 200a: ad 10 20    .. ; Snippet 2 matched
    sta l0070,x                                                       ; 200d: 95 70       .p
    rts                                                               ; 200f: 60          `

; $2010 referenced 1 time by $200a
l2010
    !byte 1                                                           ; 2010: 01          .
pydis_end


; Label references by decreasing frequency:
;     c200a:   1
;     l0007:   1
;     l0070:   1
;     l2010:   1

; Automatically generated labels:
;     c200a
;     l0007
;     l0070
;     l2010

; Stats:
;
;     Total size (Code + Data) = 17 bytes
;     Code                     = 16 bytes (94%)
;     Data                     = 1 bytes (6%)
;
;     Number of instructions   = 9
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

