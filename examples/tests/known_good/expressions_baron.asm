; Assemble with Baron, which writes the program to the file named in its
; section (expressions_baron), in the folder given with -p:
;     baron -p . expressions_baron.asm

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

section pydis, org = &2000, filename = "expressions_baron"

.pydis_start
    equb <(table + 1)                                                 ; 2000: 35          5
    equb (>table) + 1                                                 ; 2001: 13          .
    equb (255 - k) EOR 128                                            ; 2002: 00          .
    equb a + b + c                                                    ; 2003: 06          .
    equb a + b + c                                                    ; 2004: 06          .
    equb ten - (b - c)                                                ; 2005: 0b          .
    equb x * 2 + 1                                                    ; 2006: 0b          .
    equb x * (2 + 1)                                                  ; 2007: 0f          .
    equb NOT(m) AND &ff                                               ; 2008: f0          .
    equb (p OR q) AND r                                               ; 2009: 3c          <
    equb p OR (q AND r)                                               ; 200a: 3f          ?
    equb (<table) AND &7f                                             ; 200b: 34          4
    equb (p+1) * 2                                                    ; 200c: 20
    equb >(table + &0100)                                             ; 200d: 13          .
    equb p EOR q EOR r                                                ; 200e: 03          .
    equb p OR (q EOR r)                                               ; 200f: 0f          .
    equb (table >> 8) AND &ff                                         ; 2010: 12          .
    equb (1 << 3) + 1                                                 ; 2011: 09          .
    equb x DIV 2                                                      ; 2012: 02          .
    equw table - 1                                                    ; 2013: 33 12       3.
    equb NOT(m) AND &ff                                               ; 2015: f0          .
    equb (0 - k) AND &ff                                              ; 2016: 81          .
    equw NOT(table) AND &ffff                                         ; 2017: cb ed       ..
.pydis_end

    assert ((0 - k) AND &ff) = &81
    assert ((1 << 3) + 1) = &09
    assert ((255 - k) EOR 128) = &00
    assert ((<table) AND &7f) = &34
    assert ((>table) + 1) = &13
    assert ((p OR q) AND r) = &3c
    assert ((p+1) * 2) = &20
    assert ((table >> 8) AND &ff) = &12
    assert (<(table + 1)) = &35
    assert (>(table + &0100)) = &13
    assert (NOT(m) AND &ff) = &f0
    assert (NOT(table) AND &ffff) = &edcb
    assert (a + b + c) = &06
    assert (p EOR q EOR r) = &03
    assert (p OR (q AND r)) = &3f
    assert (p OR (q EOR r)) = &0f
    assert (table - 1) = &1233
    assert (ten - (b - c)) = &0b
    assert (x * (2 + 1)) = &0f
    assert (x * 2 + 1) = &0b
    assert (x DIV 2) = &02

endsection

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
