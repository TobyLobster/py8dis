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

    * = $2000

pydis_start
    !byte <(table + 1)                                                ; 2000: 35          5
    !byte (>table) + 1                                                ; 2001: 13          .
    !byte (255 - k) XOR 128                                           ; 2002: 00          .
    !byte a + b + c                                                   ; 2003: 06          .
    !byte a + b + c                                                   ; 2004: 06          .
    !byte ten - (b - c)                                               ; 2005: 0b          .
    !byte x * 2 + 1                                                   ; 2006: 0b          .
    !byte x * (2 + 1)                                                 ; 2007: 0f          .
    !byte !m & $ff                                                    ; 2008: f0          .
    !byte (p | q) & r                                                 ; 2009: 3c          <
    !byte p | (q & r)                                                 ; 200a: 3f          ?
    !byte (<table) & $7f                                              ; 200b: 34          4
    !byte (p+1) * 2                                                   ; 200c: 20
    !byte >(table + $0100)                                            ; 200d: 13          .
    !byte p XOR q XOR r                                               ; 200e: 03          .
    !byte p | (q XOR r)                                               ; 200f: 0f          .
    !byte (table >> 8) & $ff                                          ; 2010: 12          .
    !byte (1 << 3) + 1                                                ; 2011: 09          .
    !byte x DIV 2                                                     ; 2012: 02          .
    !word table - 1                                                   ; 2013: 33 12       3.
pydis_end

!if (!m & $ff) != $f0 {
    !error "Assertion failed: !m & $ff == $f0"
}
!if ((1 << 3) + 1) != $09 {
    !error "Assertion failed: (1 << 3) + 1 == $09"
}
!if ((255 - k) XOR 128) != $00 {
    !error "Assertion failed: (255 - k) XOR 128 == $00"
}
!if ((<table) & $7f) != $34 {
    !error "Assertion failed: (<table) & $7f == $34"
}
!if ((>table) + 1) != $13 {
    !error "Assertion failed: (>table) + 1 == $13"
}
!if ((p | q) & r) != $3c {
    !error "Assertion failed: (p | q) & r == $3c"
}
!if ((p+1) * 2) != $20 {
    !error "Assertion failed: (p+1) * 2 == $20"
}
!if ((table >> 8) & $ff) != $12 {
    !error "Assertion failed: (table >> 8) & $ff == $12"
}
!if (<(table + 1)) != $35 {
    !error "Assertion failed: <(table + 1) == $35"
}
!if (>(table + $0100)) != $13 {
    !error "Assertion failed: >(table + $0100) == $13"
}
!if (a + b + c) != $06 {
    !error "Assertion failed: a + b + c == $06"
}
!if (p XOR q XOR r) != $03 {
    !error "Assertion failed: p XOR q XOR r == $03"
}
!if (p | (q & r)) != $3f {
    !error "Assertion failed: p | (q & r) == $3f"
}
!if (p | (q XOR r)) != $0f {
    !error "Assertion failed: p | (q XOR r) == $0f"
}
!if (table - 1) != $1233 {
    !error "Assertion failed: table - 1 == $1233"
}
!if (ten - (b - c)) != $0b {
    !error "Assertion failed: ten - (b - c) == $0b"
}
!if (x * (2 + 1)) != $0f {
    !error "Assertion failed: x * (2 + 1) == $0f"
}
!if (x * 2 + 1) != $0b {
    !error "Assertion failed: x * 2 + 1 == $0b"
}
!if (x DIV 2) != $02 {
    !error "Assertion failed: x DIV 2 == $02"
}

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

