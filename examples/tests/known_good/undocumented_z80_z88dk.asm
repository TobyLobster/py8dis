    org $8000

pydis_start:
start:
    ld ixh,a                                                          ; 8000: dd 67       .g  8 cycles     ; Redundant instruction?
    ld ixl,$12                                                        ; 8002: dd 2e 12    ... 11 cycles
    ld a,iyh                                                          ; 8005: fd 7c       .|  8 cycles
    ld b,iyl                                                          ; 8007: fd 45       .E  8 cycles
    ld ixh,ixl                                                        ; 8009: dd 65       .e  8 cycles
    ld iyl,iyh                                                        ; 800b: fd 6c       .l  8 cycles
    inc ixh                                                           ; 800d: dd 24       .$  8 cycles
    dec iyl                                                           ; 800f: fd 2d       .-  8 cycles
    add a,ixl                                                         ; 8011: dd 85       ..  8 cycles
    adc a,iyh                                                         ; 8013: fd 8c       ..  8 cycles
    sub ixh                                                           ; 8015: dd 94       ..  8 cycles
    sbc a,iyl                                                         ; 8017: fd 9d       ..  8 cycles
    and ixl                                                           ; 8019: dd a5       ..  8 cycles
    xor iyh                                                           ; 801b: fd ac       ..  8 cycles
    or ixh                                                            ; 801d: dd b4       ..  8 cycles
    cp iyl                                                            ; 801f: fd bd       ..  8 cycles
    sll b                                                             ; 8021: cb 30       .0  8 cycles
    sll a                                                             ; 8023: cb 37       .7  8 cycles
    sll (hl)                                                          ; 8025: cb 36       .6  15 cycles
    sll (ix+3)                                                        ; 8027: dd cb 03... ... 23 cycles
    sll (iy-3)                                                        ; 802b: fd cb fd... ... 23 cycles
    rlc (ix+2),b                                                      ; 802f: dd cb 02... ... 23 cycles
    rr (iy-2),c                                                       ; 8033: fd cb fe... ... 23 cycles
    sll (ix+1),d                                                      ; 8037: dd cb 01... ... 23 cycles
    srl (iy+0),a                                                      ; 803b: fd cb 00... ... 23 cycles
    set 3,(iy+1),a                                                    ; 803f: fd cb 01... ... 23 cycles
    res 0,(ix-1),l                                                    ; 8043: dd cb ff... ... 23 cycles
    in f,(c)                                                          ; 8047: ed 70       .p  12 cycles
    out (c),0                                                         ; 8049: ed 71       .q  12 cycles
    db $ed, $4c ; neg (undocumented)                                  ; 804b: ed 4c       .L  8 cycles     ; Redundant instruction?
    db $ed, $4e ; im 0 (undocumented)                                 ; 804d: ed 4e       .N  8 cycles
    db $ed, $76 ; im 1 (undocumented)                                 ; 804f: ed 76       .v  8 cycles
    db $ed, $7e ; im 2 (undocumented)                                 ; 8051: ed 7e       .~  8 cycles
    db $ed, $63, word & $ff, word >> 8 ; ld (word),hl (undocumented)  ; 8053: ed 63 7c... .c| 20 cycles
    db $ed, $6b, word & $ff, word >> 8 ; ld hl,(word) (undocumented)  ; 8057: ed 6b 7c... .k| 20 cycles
    db $dd, $cb, 5, $41 ; bit 0,(ix+5) (undocumented)                 ; 805b: dd cb 05... ... 20 cycles    ; Redundant instruction?
    db $fd, $cb, -2, $7f ; bit 7,(iy-2) (undocumented)                ; 805f: fd cb fe... ... 20 cycles    ; Redundant instruction?
    db $ed, $00 ; nop (undocumented)                                  ; 8063: ed 00       ..  8 cycles
    db $ed, $77 ; nop (undocumented)                                  ; 8065: ed 77       .w  8 cycles
    db $ed, $ff ; nop (undocumented)                                  ; 8067: ed ff       ..  8 cycles
    db $dd ; prefix with no effect (undocumented)                     ; 8069: dd          .   4 cycles
    ld a,5                                                            ; 806a: 3e 05       >.  7 cycles
    db $fd ; prefix with no effect (undocumented)                     ; 806c: fd          .   4 cycles
    ld ix,$1234                                                       ; 806d: dd 21 34... .!4 14 cycles
    db $dd ; prefix with no effect (undocumented)                     ; 8071: dd          .   4 cycles
    neg                                                               ; 8072: ed 44       .D  8 cycles
    db $fd ; prefix with no effect (undocumented)                     ; 8074: fd          .   4 cycles
    jp finish                                                         ; 8075: c3 7a 80    .z. 10 cycles

    db 0, 0                                                           ; 8078: 00 00       ..

; $807a referenced 1 time by $8075
finish:
    db $ed, $55 ; retn (undocumented)                                 ; 807a: ed 55       .U  14 cycles

; $807c referenced 2 times by $8053, $8057
word:
    dw $1234                                                          ; 807c: 34 12       4.
pydis_end:


; Label references by decreasing frequency:
;     word:     2
;     finish:   1

; Stats:
;
;     Total size (Code + Data) = 126 bytes
;     Code                     = 122 bytes (97%)
;     Data                     = 4 bytes (3%)
;
;     Number of instructions   = 49
;     Number of data bytes     = 2 bytes
;     Number of data words     = 2 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

