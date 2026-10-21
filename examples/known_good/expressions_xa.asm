// Constants
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

// Memory locations

    * = $2000

pydis_start
    .byt <(table + 1)                                                 // 2000: 35          5
    .byt (table >> 8) + 1                                             // 2001: 13          .
    .byt (255 - k) ^ 128                                              // 2002: 00          .
    .byt a + b + c                                                    // 2003: 06          .
    .byt a + b + c                                                    // 2004: 06          .
    .byt ten - (b - c)                                                // 2005: 0b          .
    .byt x * 2 + 1                                                    // 2006: 0b          .
    .byt x * (2 + 1)                                                  // 2007: 0f          .
    .byt (-1 - m) & $ff                                               // 2008: f0          .
    .byt (p | q) & r                                                  // 2009: 3c          <
    .byt p | (q & r)                                                  // 200a: 3f          ?
    .byt table & $ff & $7f                                            // 200b: 34          4
    .byt (p+1) * 2                                                    // 200c: 20
    .byt >(table + $0100)                                             // 200d: 13          .
    .byt p ^ q ^ r                                                    // 200e: 03          .
    .byt p | (q ^ r)                                                  // 200f: 0f          .
    .byt (table >> 8) & $ff                                           // 2010: 12          .
    .byt (1 << 3) + 1                                                 // 2011: 09          .
    .byt x / 2                                                        // 2012: 02          .
    .word table - 1                                                   // 2013: 33 12       3.
pydis_end

#if ((-1 - m) & $ff) <> $f0
#error Assertion failed: (-1 - m) & $ff == $f0
#endif
#if ((1 << 3) + 1) <> $09
#error Assertion failed: (1 << 3) + 1 == $09
#endif
#if ((255 - k) ^ 128) <> $00
#error Assertion failed: (255 - k) ^ 128 == $00
#endif
#if ((p | q) & r) <> $3c
#error Assertion failed: (p | q) & r == $3c
#endif
#if ((p+1) * 2) <> $20
#error Assertion failed: (p+1) * 2 == $20
#endif
#if ((table >> 8) & $ff) <> $12
#error Assertion failed: (table >> 8) & $ff == $12
#endif
#if ((table >> 8) + 1) <> $13
#error Assertion failed: (table >> 8) + 1 == $13
#endif
#if ((table + 1) & $ff) <> $35
#error Assertion failed: <(table + 1) == $35
#endif
#if (((table + $0100) >> 8) & $ff) <> $13
#error Assertion failed: >(table + $0100) == $13
#endif
#if (a + b + c) <> $06
#error Assertion failed: a + b + c == $06
#endif
#if (p ^ q ^ r) <> $03
#error Assertion failed: p ^ q ^ r == $03
#endif
#if (p | (q & r)) <> $3f
#error Assertion failed: p | (q & r) == $3f
#endif
#if (p | (q ^ r)) <> $0f
#error Assertion failed: p | (q ^ r) == $0f
#endif
#if (table & $ff & $7f) <> $34
#error Assertion failed: table & $ff & $7f == $34
#endif
#if (table - 1) <> $1233
#error Assertion failed: table - 1 == $1233
#endif
#if (ten - (b - c)) <> $0b
#error Assertion failed: ten - (b - c) == $0b
#endif
#if (x * (2 + 1)) <> $0f
#error Assertion failed: x * (2 + 1) == $0f
#endif
#if (x * 2 + 1) <> $0b
#error Assertion failed: x * 2 + 1 == $0b
#endif
#if (x / 2) <> $02
#error Assertion failed: x / 2 == $02
#endif

// Stats:
//
//     Total size (Code + Data) = 21 bytes
//     Code                     = 0 bytes (0%)
//     Data                     = 21 bytes (100%)
//
//     Number of instructions   = 0
//     Number of data bytes     = 19 bytes
//     Number of data words     = 2 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

