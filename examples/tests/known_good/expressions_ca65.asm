; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Constants
a_      = 1
b       = 2
c       = 3
k       = 127
m       = 15
p       = 15
q       = 48
r       = 60
table   = 4660
ten     = 10
x_      = 5

    .org $2000

pydis_start:
    .byte <(table + 1)                                                ; 2000: 35          5
    .byte (>table) + 1                                                ; 2001: 13          .
    .byte (255 - k) ^ 128                                             ; 2002: 00          .
    .byte a_ + b + c                                                  ; 2003: 06          .
    .byte a_ + b + c                                                  ; 2004: 06          .
    .byte ten - (b - c)                                               ; 2005: 0b          .
    .byte x_ * 2 + 1                                                  ; 2006: 0b          .
    .byte x_ * (2 + 1)                                                ; 2007: 0f          .
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
    .byte x_ / 2                                                      ; 2012: 02          .
    .word table - 1                                                   ; 2013: 33 12       3.
    .byte ~m & $ff                                                    ; 2015: f0          .
    .byte (0 - k) & $ff                                               ; 2016: 81          .
    .word ~table & $ffff                                              ; 2017: cb ed       ..
pydis_end:

.assert ((0 - k) & $ff) = $81, error, "Assertion failed: (0 - k) & $ff = $81"
.assert ((1 << 3) + 1) = $09, error, "Assertion failed: (1 << 3) + 1 = $09"
.assert ((255 - k) ^ 128) = $00, error, "Assertion failed: (255 - k) ^ 128 = $00"
.assert ((<table) & $7f) = $34, error, "Assertion failed: (<table) & $7f = $34"
.assert ((>table) + 1) = $13, error, "Assertion failed: (>table) + 1 = $13"
.assert ((p | q) & r) = $3c, error, "Assertion failed: (p | q) & r = $3c"
.assert ((p+1) * 2) = $20, error, "Assertion failed: (p+1) * 2 = $20"
.assert ((table >> 8) & $ff) = $12, error, "Assertion failed: (table >> 8) & $ff = $12"
.assert (<(table + 1)) = $35, error, "Assertion failed: <(table + 1) = $35"
.assert (>(table + $0100)) = $13, error, "Assertion failed: >(table + $0100) = $13"
.assert (a_ + b + c) = $06, error, "Assertion failed: a_ + b + c = $06"
.assert (p ^ q ^ r) = $03, error, "Assertion failed: p ^ q ^ r = $03"
.assert (p | (q & r)) = $3f, error, "Assertion failed: p | (q & r) = $3f"
.assert (p | (q ^ r)) = $0f, error, "Assertion failed: p | (q ^ r) = $0f"
.assert (table - 1) = $1233, error, "Assertion failed: table - 1 = $1233"
.assert (ten - (b - c)) = $0b, error, "Assertion failed: ten - (b - c) = $0b"
.assert (x_ * (2 + 1)) = $0f, error, "Assertion failed: x_ * (2 + 1) = $0f"
.assert (x_ * 2 + 1) = $0b, error, "Assertion failed: x_ * 2 + 1 = $0b"
.assert (x_ / 2) = $02, error, "Assertion failed: x_ / 2 = $02"
.assert (~m & $ff) = $f0, error, "Assertion failed: ~m & $ff = $f0"
.assert (~table & $ffff) = $edcb, error, "Assertion failed: ~table & $ffff = $edcb"

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

