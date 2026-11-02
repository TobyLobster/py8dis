; Memory locations
lffee   = $ffee

    * = $4000

pydis_start
start
    ; Copy 16 bytes of memory from ca000 to c4010
    ldx #$0f                                                          ; 4000: a2 0f       ..
; $4002 referenced 1 time by $4009
loop_c4002
    lda ca000,x                                                       ; 4002: bd 00 a0    ...
    sta c4010,x                                                       ; 4005: 9d 10 40    ..@
    dex                                                               ; 4008: ca          .
    bpl loop_c4002                                                    ; 4009: 10 f7       ..
    jmp c4010                                                         ; 400b: 4c 10 40    L.@

    .byte $ea, $ea                                                    ; 400e: ea ea       ..
; $4010 referenced 2 times by $4005, $400b
    .byte $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea  ; 4010: ea ea ea... ...
    .byte $ea, $ea, $ea, $ea                                          ; 401c: ea ea ea... ...

    * = $a000

ca000

; Move 1: $a000 to $4010 for length 16
.logical $4010
c4010
    lda #$41 ; 'A'                                                    ; a000: a9 41       .A  :4010[1]
    jsr lffee                                                         ; a002: 20 ee ff     .. :4012[1]
    lda #$42 ; 'B'                                                    ; a005: a9 42       .B  :4015[1]
    jsr lffee                                                         ; a007: 20 ee ff     .. :4017[1]
    lda #$43 ; 'C'                                                    ; a00a: a9 43       .C  :401a[1]
    jsr lffee                                                         ; a00c: 20 ee ff     .. :401c[1]
    rts                                                               ; a00f: 60          `   :401f[1]

.here

pydis_end


; Label references by decreasing frequency:
;     lffee:        3
;     c4010:        2
;     ca000:        1
;     loop_c4002:   1

; Automatically generated labels:
;     c4010
;     ca000
;     lffee
;     loop_c4002

; Stats:
;
;     Total size (Code + Data) = 48 bytes
;     Code                     = 30 bytes (62%)
;     Data                     = 18 bytes (38%)
;
;     Number of instructions   = 13
;     Number of data bytes     = 18 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

