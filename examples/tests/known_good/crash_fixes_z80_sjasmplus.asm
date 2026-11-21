; Assemble with sjasmplus, to a plain binary:
;     sjasmplus --nologo --raw=program.bin this_file.asm

    org $8000

pydis_start:
start:
    ld hl,(table)                                                     ; 8000: 2a 10 80    *..
    ld ix,(table+2)                                                   ; 8003: dd 2a 12... .*.
    ld (table+2),bc                                                   ; 8007: ed 43 12... .C.
    ld iy,(table)                                                     ; 800b: fd 2a 10... .*.
    ret                                                               ; 800f: c9          .

; $8010 referenced 2 times by $8000, $800b
table:
    db $34, $12                                                       ; 8010: 34 12       4.
; $8012 referenced 2 times by $8003, $8007
    db $78, $56                                                       ; 8012: 78 56       xV
cut_off:
    db $dd                                                            ; 8014: dd          .
    db $21, $34                                                       ; 8015: 21 34       !4
pydis_end:

    assert (table) == $8010
    assert (table+2) == $8012

; Label references by decreasing frequency:
;     table:   2

; Stats:
;
;     Total size (Code + Data) = 23 bytes
;     Code                     = 16 bytes (70%)
;     Data                     = 7 bytes (30%)
;
;     Number of instructions   = 5
;     Number of data bytes     = 7 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

