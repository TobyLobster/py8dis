!ct pet ; (so a character literal, e.g. 'a', is PETSCII)

; Memory locations
l0400   = $0400
chrout  = $ffd2

    * = $c000

pydis_start
start
    lda #$93                                                          ; c000: a9 93       ..
    jsr chrout                                                        ; c002: 20 d2 ff     R.
    ldx #0                                                            ; c005: a2 00       ..
; $c007 referenced 1 time by $c010
loop_cc007
    lda lc023,x                                                       ; c007: bd 23 c0    .#.
    beq cc012                                                         ; c00a: f0 06       ..
    jsr chrout                                                        ; c00c: 20 d2 ff     R.
    inx                                                               ; c00f: e8          .
    bne loop_cc007                                                    ; c010: d0 f5       P.
; $c012 referenced 1 time by $c00a
cc012
    ; Copy 21 bytes of memory from lc04e to l0400
    ldx #$14                                                          ; c012: a2 14       ..
; $c014 referenced 1 time by $c01b
loop_cc014
    lda lc04e,x                                                       ; c014: bd 4e c0    .n.
    sta l0400,x                                                       ; c017: 9d 00 04    ...
    dex                                                               ; c01a: ca          J
    bpl loop_cc014                                                    ; c01b: 10 f7       ..
    lda #'a'                                                          ; c01d: a9 41       .a
    jsr chrout                                                        ; c01f: 20 d2 ff     R.
    rts                                                               ; c022: 60          .

; $c023 referenced 1 time by $c007
lc023
    !pet $93, "Hello, World! Say ", '"', "hi", '"', $0d, 0            ; c023: 93 c8 45... .He
    !pet "cost: ", $5c, "5 ", $5e, $5f, $60, $7b, $a0, $b0, $db, $ff  ; c03c: 43 4f 53... cos
    !pet 0                                                            ; c04d: 00          .
; $c04e referenced 1 time by $c014
lc04e
    !scr "@ Score [000] Lives 3"                                      ; c04e: 00 20 53... @ S
    !raw "ASCII text", 0                                              ; c063: 41 53 43... ASC
    !pet "end", $80 + $78                                             ; c06e: 45 4e 44... end
    !pet "found by autostring"                                        ; c072: 46 4f 55... fou
    !byte 0                                                           ; c085: 00          .
    !raw "o", $80 + $6b                                               ; c086: 6f eb       o.
pydis_end

!if ($80 + $6b) != $eb {
    !error "Assertion failed: $80 + $6b == $eb"
}
!if ($80 + $78) != $f8 {
    !error "Assertion failed: $80 + $78 == $f8"
}

; Label references by decreasing frequency:
;     chrout:       3
;     cc012:        1
;     l0400:        1
;     lc023:        1
;     lc04e:        1
;     loop_cc007:   1
;     loop_cc014:   1

; Automatically generated labels:
;     cc012
;     l0400
;     lc023
;     lc04e
;     loop_cc007
;     loop_cc014

; Stats:
;
;     Total size (Code + Data) = 136 bytes
;     Code                     = 35 bytes (26%)
;     Data                     = 101 bytes (74%)
;
;     Number of instructions   = 16
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 100 bytes
;     Number of strings        = 7

