; Memory locations
l5b00   equ $5b00

    org $1000

pydis_start:
main:
    ld a,0                                                            ; 1000: 3e 00       >.
    ld (l5b00),a                                                      ; 1002: 32 00 5b    2.[
    call bank_a                                                       ; 1005: cd 00 80    ...
    ld a,1                                                            ; 1008: 3e 01       >.
    ld (l5b00),a                                                      ; 100a: 32 00 5b    2.[
    call bank_b                                                       ; 100d: cd 00 80    ...
    ret                                                               ; 1010: c9          .


    defs 4079 ; (to $2000)


; Move 1: $2000 to $8000 for length 22
    phase $8000
; $2000 referenced 2 times by $1005, $100d
bank_a:
    call sub_c8004                                                    ; 2000: cd 04 80    ... :8000[1]
    ret                                                               ; 2003: c9          .   :8003[1]

; $2004 referenced 1 time by $8000[1]
sub_c8004:
    ld hl,$800e                                                       ; 2004: 21 0e 80    !.. :8004[1]
; $2007 referenced 1 time by $800c[1]
loop_c8007:
    ld a,(hl)                                                         ; 2007: 7e          ~   :8007[1]
    or a                                                              ; 2008: b7          .   :8008[1]
    ret z                                                             ; 2009: c8          .   :8009[1]
    rst $10                                                           ; 200a: d7          .   :800a[1]
    inc hl                                                            ; 200b: 23          #   :800b[1]
    jr loop_c8007                                                     ; 200c: 18 f9       ..  :800c[1]

    db "Bank A"                                                       ; 200e: 42 61 6e... Ban :800e[1]
    db $0d, 0                                                         ; 2014: 0d 00       ..  :8014[1]
    dephase


    defs 4074 ; (to $3000)


; Move 2: $3000 to $8000 for length 21
    phase $8000
bank_b:
    jp c800b                                                          ; 3000: c3 0b 80    ... :8000[2]

    db $42                                                            ; 3003: 42          B   :8003[2]
    db "ank"                                                          ; 3004: 61 6e 6b    ank :8004[2]
    db $20, $42, $0d, 0                                               ; 3007: 20 42 0d...  B. :8007[2]

; $300b referenced 1 time by $8000[2]
c800b:
    ld hl,$8003                                                       ; 300b: 21 03 80    !.. :800b[2]
; $300e referenced 1 time by $8013[2]
loop_c800e:
    ld a,(hl)                                                         ; 300e: 7e          ~   :800e[2]
    or a                                                              ; 300f: b7          .   :800f[2]
    ret z                                                             ; 3010: c8          .   :8010[2]
    rst $10                                                           ; 3011: d7          .   :8011[2]
    inc hl                                                            ; 3012: 23          #   :8012[2]
    jr loop_c800e                                                     ; 3013: 18 f9       ..  :8013[2]

    dephase

pydis_end:

; ASSERT ((bank_b) == $8000)

; Label references by decreasing frequency:
;     bank_a:       2
;     bank_b:       2
;     l5b00:        2
;     c800b:        1
;     loop_c8007:   1
;     loop_c800e:   1
;     sub_c8004:    1

; Automatically generated labels:
;     c800b
;     l5b00
;     loop_c8007
;     loop_c800e
;     sub_c8004

; Stats:
;
;     Total size (Code + Data) = 60 bytes
;     Code                     = 44 bytes (73%)
;     Data                     = 16 bytes (27%)
;
;     Number of instructions   = 24
;     Number of data bytes     = 7 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 9 bytes
;     Number of strings        = 2

