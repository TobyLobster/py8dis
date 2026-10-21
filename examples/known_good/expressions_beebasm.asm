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

; Memory locations

    org &2000

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
.pydis_end

    assert &09 == (1 << 3) + 1
    assert &00 == ((255 - k) EOR 128)
    assert &34 == ((<table) AND &7f)
    assert &13 == (>table) + 1
    assert &3c == ((p OR q) AND r)
    assert &20 == (p+1) * 2
    assert &12 == ((table >> 8) AND &ff)
    assert &35 == <(table + 1)
    assert &13 == >(table + &0100)
    assert &f0 == (NOT(m) AND &ff)
    assert &06 == a + b + c
    assert &03 == (p EOR q EOR r)
    assert &3f == (p OR (q AND r))
    assert &0f == (p OR (q EOR r))
    assert &1233 == table - 1
    assert &0b == ten - (b - c)
    assert &0f == x * (2 + 1)
    assert &0b == x * 2 + 1
    assert &02 == x DIV 2

save pydis_start, pydis_end

; Stats:
;
;     Total size (Code + Data) = 21 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 21 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 19 bytes
;     Number of data words     = 2 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

