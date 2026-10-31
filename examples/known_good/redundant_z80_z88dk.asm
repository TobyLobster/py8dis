    org $8000

pydis_start:
start:
    ld a,(hl)                                                         ; 8000: 7e          ~  ; Redundant instruction?
    pop af                                                            ; 8001: f1          .
    ld b,1                                                            ; 8002: 06 01       .. ; Redundant instruction?
    inc b                                                             ; 8004: 04          .  ; Redundant instruction?
    ld bc,$1234                                                       ; 8005: 01 34 12    .4.
    scf                                                               ; 8008: 37          7  ; Redundant instruction?
    scf                                                               ; 8009: 37          7  ; Redundant instruction?
    cp (ix+3)                                                         ; 800a: dd be 03    ... ; Redundant instruction?
    cp (ix+3)                                                         ; 800d: dd be 03    ...
    jr nz,return_1                                                    ; 8010: 20 26        &
    ld a,1                                                            ; 8012: 3e 01       >.
    ld (hl),a                                                         ; 8014: 77          w
    ld e,2                                                            ; 8015: 1e 02       ..
    out (c),e                                                         ; 8017: ed 59       .Y
    ld a,$7f                                                          ; 8019: 3e 7f       >.
    in a,($fe)                                                        ; 801b: db fe       ..
    ld d,3                                                            ; 801d: 16 03       ..
    call return_1                                                     ; 801f: cd 38 80    .8.
    ld d,4                                                            ; 8022: 16 04       ..
    xor a                                                             ; 8024: af          .  ; Redundant instruction?
    ld a,5                                                            ; 8025: 3e 05       >.
    sub b                                                             ; 8027: 90          .
    ld h,6                                                            ; 8028: 26 06       &.
    push hl                                                           ; 802a: e5          .
    ret z                                                             ; 802b: c8          .
    ld l,7                                                            ; 802c: 2e 07       .. ; Redundant instruction?
    res 0,l                                                           ; 802e: cb 85       .. ; Redundant instruction?
    ld hl,$4000                                                       ; 8030: 21 00 40    !.@
    set 3,(hl)                                                        ; 8033: cb de       ..
    ld (ix+0),e                                                       ; 8035: dd 73 00    .s.
; $8038 referenced 2 times by $8010, $801f
return_1:
    ret                                                               ; 8038: c9          .

pydis_end:


; Label references by decreasing frequency:
;     return_1:   2

; Automatically generated labels:
;     return_1

; Stats:
;
;     Total size (Code + Data) = 57 bytes
;     Code                     = 57 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 31
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

