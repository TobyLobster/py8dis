    org $0100

pydis_start:
    mvi a, $41 ; 'A'                                                  ; 0100: 3e 41       >A  7 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $08 ; nop (undocumented)                                       ; 0102: 08          .   4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $10 ; nop (undocumented)                                       ; 0103: 10          .   4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $18 ; nop (undocumented)                                       ; 0104: 18          .   4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $20 ; nop (undocumented)                                       ; 0105: 20              4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $28 ; nop (undocumented)                                       ; 0106: 28          (   4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $30 ; nop (undocumented)                                       ; 0107: 30          0   4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $38 ; nop (undocumented)                                       ; 0108: 38          8   4 cycles      A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $dd, subroutine & $ff, subroutine >> 8 ; call subroutine (undocumented); 0109: dd 15 01    ... 17 cycles     A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $ed, subroutine & $ff, subroutine >> 8 ; call subroutine (undocumented); 010c: ed 15 01    ... 17 cycles     A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $fd, subroutine & $ff, subroutine >> 8 ; call subroutine (undocumented); 010f: fd 15 01    ... 17 cycles     A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $cb, finish & $ff, finish >> 8 ; jmp finish (undocumented)     ; 0112: cb 17 01    ... 10 cycles     A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----

; $0115 referenced 3 times by $0109, $010c, $010f
subroutine:
    inr a                                                             ; 0115: 3c          <   5 cycles      A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----
    db $d9 ; ret (undocumented)                                       ; 0116: d9          .   10 cycles     A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----

; $0117 referenced 1 time by $0112
finish:
    ret                                                               ; 0117: c9          .   10 cycles     A:-- B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----

pydis_end:


; Label references by decreasing frequency:
;     subroutine:   3
;     finish:       1

; Stats:
;
;     Total size (Code + Data) = 24 bytes
;     Code                     = 24 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 15
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

