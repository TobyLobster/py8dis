; Constants
a       = 1
b       = 2
c       = 3
k       = 127
m       = 15
p       = 15
q       = 48
r       = 60
table   = 4660
ten     = 10
x       = 5

    * = $2000

pydis_start
    .byte <(table + 1)                                                ; 2000: 35          5
    .byte (>table) + 1                                                ; 2001: 13          .
    .byte (255 - k) ^ 128                                             ; 2002: 00          .
    .byte a + b + c                                                   ; 2003: 06          .
    .byte a + b + c                                                   ; 2004: 06          .
    .byte ten - (b - c)                                               ; 2005: 0b          .
    .byte x * 2 + 1                                                   ; 2006: 0b          .
    .byte x * (2 + 1)                                                 ; 2007: 0f          .
    .byte ~m & $ff                                                    ; 2008: f0          .
    .byte (p | q) & r                                                 ; 2009: 3c          <
    .byte p | (q & r)                                                 ; 200a: 3f          ?
    .byte (<table) & $7f                                              ; 200b: 34          4
    .byte (p+1) * 2                                                   ; 200c: 20
    .byte >(table + $0100)                                            ; 200d: 13          .
    .byte p ^ q ^ r                                                   ; 200e: 03          .
    .byte p | (q ^ r)                                                 ; 200f: 0f          .
    .byte (table >> 8) & $ff                                          ; 2010: 12          .
    .byte (1 << 3) + 1                                                ; 2011: 09          .
    .byte x / 2                                                       ; 2012: 02          .
    .word table - 1                                                   ; 2013: 33 12       3.
    .byte ~m & $ff                                                    ; 2015: f0          .
    .byte (0 - k) & $ff                                               ; 2016: 81          .
    .word ~table & $ffff                                              ; 2017: cb ed       ..
pydis_end

.cerror ((0 - k) & $ff) != $81, "Assertion failed: (0 - k) & $ff == $81"
.cerror ((1 << 3) + 1) != $09, "Assertion failed: (1 << 3) + 1 == $09"
.cerror ((255 - k) ^ 128) != $00, "Assertion failed: (255 - k) ^ 128 == $00"
.cerror ((<table) & $7f) != $34, "Assertion failed: (<table) & $7f == $34"
.cerror ((>table) + 1) != $13, "Assertion failed: (>table) + 1 == $13"
.cerror ((p | q) & r) != $3c, "Assertion failed: (p | q) & r == $3c"
.cerror ((p+1) * 2) != $20, "Assertion failed: (p+1) * 2 == $20"
.cerror ((table >> 8) & $ff) != $12, "Assertion failed: (table >> 8) & $ff == $12"
.cerror (<(table + 1)) != $35, "Assertion failed: <(table + 1) == $35"
.cerror (>(table + $0100)) != $13, "Assertion failed: >(table + $0100) == $13"
.cerror (a + b + c) != $06, "Assertion failed: a + b + c == $06"
.cerror (p ^ q ^ r) != $03, "Assertion failed: p ^ q ^ r == $03"
.cerror (p | (q & r)) != $3f, "Assertion failed: p | (q & r) == $3f"
.cerror (p | (q ^ r)) != $0f, "Assertion failed: p | (q ^ r) == $0f"
.cerror (table - 1) != $1233, "Assertion failed: table - 1 == $1233"
.cerror (ten - (b - c)) != $0b, "Assertion failed: ten - (b - c) == $0b"
.cerror (x * (2 + 1)) != $0f, "Assertion failed: x * (2 + 1) == $0f"
.cerror (x * 2 + 1) != $0b, "Assertion failed: x * 2 + 1 == $0b"
.cerror (x / 2) != $02, "Assertion failed: x / 2 == $02"
.cerror (~m & $ff) != $f0, "Assertion failed: ~m & $ff == $f0"
.cerror (~table & $ffff) != $edcb, "Assertion failed: ~table & $ffff == $edcb"

; Stats:
;
;     Total size (Code + Data) = 25 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 25 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 21 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

