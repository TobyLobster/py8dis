// Memory locations

// Zero page ($0000-$00ff)
l0070   = $0070
l0072   = $0072

// Other
l3000   = $3000
l3456   = $3456

    * = $2000

pydis_start
start
    .byt $03, l0070 // slo (l0070,x) (undocumented)                   // 2000: 03 70       .p  8 cycles      A:-- X:-- Y:-- ------
    .byt $07, l0070 // slo l0070 (undocumented)                       // 2002: 07 70       .p  5 cycles      A:-- X:-- Y:-- ------
    .byt $0f, <l3000, >l3000 // slo l3000 (undocumented)              // 2004: 0f 00 30    ..0 6 cycles      A:-- X:-- Y:-- ------
    .byt $13, l0070 // slo (l0070),y (undocumented)                   // 2007: 13 70       .p  8 cycles      A:-- X:-- Y:-- ------
    .byt $17, l0070 // slo l0070,x (undocumented)                     // 2009: 17 70       .p  6 cycles      A:-- X:-- Y:-- ------
    .byt $1b, <l3000, >l3000 // slo l3000,y (undocumented)            // 200b: 1b 00 30    ..0 7 cycles      A:-- X:-- Y:-- ------
    .byt $1f, <l3000, >l3000 // slo l3000,x (undocumented)            // 200e: 1f 00 30    ..0 7 cycles      A:-- X:-- Y:-- ------
    .byt $23, l0070 // rla (l0070,x) (undocumented)                   // 2011: 23 70       #p  8 cycles      A:-- X:-- Y:-- ------
    .byt $27, l0070 // rla l0070 (undocumented)                       // 2013: 27 70       'p  5 cycles      A:-- X:-- Y:-- ------
    .byt $2f, <l3000, >l3000 // rla l3000 (undocumented)              // 2015: 2f 00 30    /.0 6 cycles      A:-- X:-- Y:-- ------
    .byt $33, l0070 // rla (l0070),y (undocumented)                   // 2018: 33 70       3p  8 cycles      A:-- X:-- Y:-- ------
    .byt $37, l0070 // rla l0070,x (undocumented)                     // 201a: 37 70       7p  6 cycles      A:-- X:-- Y:-- ------
    .byt $3b, <l3000, >l3000 // rla l3000,y (undocumented)            // 201c: 3b 00 30    ;.0 7 cycles      A:-- X:-- Y:-- ------
    .byt $3f, <l3000, >l3000 // rla l3000,x (undocumented)            // 201f: 3f 00 30    ?.0 7 cycles      A:-- X:-- Y:-- ------
    .byt $43, l0070 // sre (l0070,x) (undocumented)                   // 2022: 43 70       Cp  8 cycles      A:-- X:-- Y:-- ------
    .byt $47, l0070 // sre l0070 (undocumented)                       // 2024: 47 70       Gp  5 cycles      A:-- X:-- Y:-- ------
    .byt $4f, <l3000, >l3000 // sre l3000 (undocumented)              // 2026: 4f 00 30    O.0 6 cycles      A:-- X:-- Y:-- ------
    .byt $53, l0070 // sre (l0070),y (undocumented)                   // 2029: 53 70       Sp  8 cycles      A:-- X:-- Y:-- ------
    .byt $57, l0070 // sre l0070,x (undocumented)                     // 202b: 57 70       Wp  6 cycles      A:-- X:-- Y:-- ------
    .byt $5b, <l3000, >l3000 // sre l3000,y (undocumented)            // 202d: 5b 00 30    [.0 7 cycles      A:-- X:-- Y:-- ------
    .byt $5f, <l3000, >l3000 // sre l3000,x (undocumented)            // 2030: 5f 00 30    _.0 7 cycles      A:-- X:-- Y:-- ------
    .byt $63, l0070 // rra (l0070,x) (undocumented)                   // 2033: 63 70       cp  8 cycles      A:-- X:-- Y:-- ------
    .byt $67, l0070 // rra l0070 (undocumented)                       // 2035: 67 70       gp  5 cycles      A:-- X:-- Y:-- ------
    .byt $6f, <l3000, >l3000 // rra l3000 (undocumented)              // 2037: 6f 00 30    o.0 6 cycles      A:-- X:-- Y:-- ------
    .byt $73, l0070 // rra (l0070),y (undocumented)                   // 203a: 73 70       sp  8 cycles      A:-- X:-- Y:-- ------
    .byt $77, l0070 // rra l0070,x (undocumented)                     // 203c: 77 70       wp  6 cycles      A:-- X:-- Y:-- ------
    .byt $7b, <l3000, >l3000 // rra l3000,y (undocumented)            // 203e: 7b 00 30    {.0 7 cycles      A:-- X:-- Y:-- ------
    .byt $7f, <l3000, >l3000 // rra l3000,x (undocumented)            // 2041: 7f 00 30    ..0 7 cycles      A:-- X:-- Y:-- ------
    .byt $c3, l0072 // dcp (l0072,x) (undocumented)                   // 2044: c3 72       .r  8 cycles      A:-- X:-- Y:-- ----??
    .byt $c7, l0072 // dcp l0072 (undocumented)                       // 2046: c7 72       .r  5 cycles      A:-- X:-- Y:-- ----??
    .byt $cf, <l3456, >l3456 // dcp l3456 (undocumented)              // 2048: cf 56 34    .V4 6 cycles      A:-- X:-- Y:-- ----??
    .byt $d3, l0072 // dcp (l0072),y (undocumented)                   // 204b: d3 72       .r  8 cycles      A:-- X:-- Y:-- ----??
    .byt $d7, l0072 // dcp l0072,x (undocumented)                     // 204d: d7 72       .r  6 cycles      A:-- X:-- Y:-- ----??
    .byt $db, <l3456, >l3456 // dcp l3456,y (undocumented)            // 204f: db 56 34    .V4 7 cycles      A:-- X:-- Y:-- ----??
    .byt $df, <l3456, >l3456 // dcp l3456,x (undocumented)            // 2052: df 56 34    .V4 7 cycles      A:-- X:-- Y:-- ----??
    .byt $e3, l0072 // isc (l0072,x) (undocumented)                   // 2055: e3 72       .r  8 cycles      A:-- X:-- Y:-- ------
    .byt $e7, l0072 // isc l0072 (undocumented)                       // 2057: e7 72       .r  5 cycles      A:-- X:-- Y:-- ------
    .byt $ef, <l3456, >l3456 // isc l3456 (undocumented)              // 2059: ef 56 34    .V4 6 cycles      A:-- X:-- Y:-- ------
    .byt $f3, l0072 // isc (l0072),y (undocumented)                   // 205c: f3 72       .r  8 cycles      A:-- X:-- Y:-- ------
    .byt $f7, l0072 // isc l0072,x (undocumented)                     // 205e: f7 72       .r  6 cycles      A:-- X:-- Y:-- ------
    .byt $fb, <l3456, >l3456 // isc l3456,y (undocumented)            // 2060: fb 56 34    .V4 7 cycles      A:-- X:-- Y:-- ------
    .byt $ff, <l3456, >l3456 // isc l3456,x (undocumented)            // 2063: ff 56 34    .V4 7 cycles      A:-- X:-- Y:-- ------
    .byt $83, l0070 // sax (l0070,x) (undocumented)                   // 2066: 83 70       .p  6 cycles      A:-- X:-- Y:-- ------
    .byt $87, l0070 // sax l0070 (undocumented)                       // 2068: 87 70       .p  3 cycles      A:-- X:-- Y:-- ------
    .byt $8f, <l3000, >l3000 // sax l3000 (undocumented)              // 206a: 8f 00 30    ..0 4 cycles      A:-- X:-- Y:-- ------
    .byt $97, l0070 // sax l0070,y (undocumented)                     // 206d: 97 70       .p  4 cycles      A:-- X:-- Y:-- ------
    .byt $a3, l0072 // lax (l0072,x) (undocumented)                   // 206f: a3 72       .r  6 cycles      A:-- X:-- Y:-- ------
    .byt $a7, l0072 // lax l0072 (undocumented)                       // 2071: a7 72       .r  3 cycles      A:-- X:-- Y:-- ------
    .byt $af, <l3456, >l3456 // lax l3456 (undocumented)              // 2073: af 56 34    .V4 4 cycles      A:-- X:-- Y:-- ------
    .byt $b3, l0072 // lax (l0072),y (undocumented)                   // 2076: b3 72       .r  5/6 cycles    A:-- X:-- Y:-- ------
    .byt $b7, l0072 // lax l0072,y (undocumented)                     // 2078: b7 72       .r  4 cycles      A:-- X:-- Y:-- ------
    .byt $bf, <l3456, >l3456 // lax l3456,y (undocumented)            // 207a: bf 56 34    .V4 4/5 cycles    A:-- X:-- Y:-- ------
    .byt $0f, <l0070, >l0070 // slo l0070 (undocumented)              // 207d: 0f 70 00    .p. 6 cycles      A:-- X:-- Y:-- ------
    .byt $bf, <l0072, >l0072 // lax l0072,y (undocumented)            // 2080: bf 72 00    .r. 4/5 cycles    A:-- X:-- Y:-- ------
    .byt $1c, <l0070, >l0070 // nop l0070,x (undocumented)            // 2083: 1c 70 00    .p. 4/5 cycles    A:-- X:-- Y:-- ------
    lda #$ff                                                          // 2086: a9 ff       ..  2 cycles      A:ff X:-- Y:-- N---z-
    .byt $0b, $81 // anc #$81 (undocumented)                          // 2088: 0b 81       ..  2 cycles      A:81 X:-- Y:-- N---zC // A=$81
    .byt $2b, $7f // anc #$7f (undocumented)                          // 208a: 2b 7f       +.  2 cycles      A:01 X:-- Y:-- n---zc // A=1
    lda #$f3                                                          // 208c: a9 f3       ..  2 cycles      A:f3 X:-- Y:-- N---zc
    .byt $4b, $0f // alr #$0f (undocumented)                          // 208e: 4b 0f       K.  2 cycles      A:01 X:-- Y:-- n---zC // A=1
    lda #$3c // '<'                                                   // 2090: a9 3c       .<  2 cycles      A:3c X:-- Y:-- n---zC
    ldx #$0f                                                          // 2092: a2 0f       ..  2 cycles      A:3c X:0f Y:-- n---zC
    .byt $cb, 5 // sbx #5 (undocumented)                              // 2094: cb 05       ..  2 cycles      A:3c X:07 Y:-- n---zC // X=7
    .byt $6b, $12 // arr #$12 (undocumented)                          // 2096: 6b 12       k.  2 cycles      A:-- X:07 Y:-- ------
    .byt $eb, 1 // sbc #1 (undocumented)                              // 2098: eb 01       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $1a // nop (undocumented)                                    // 209a: 1a          .   2 cycles      A:-- X:07 Y:-- ------
    .byt $3a // nop (undocumented)                                    // 209b: 3a          :   2 cycles      A:-- X:07 Y:-- ------
    .byt $5a // nop (undocumented)                                    // 209c: 5a          Z   2 cycles      A:-- X:07 Y:-- ------
    .byt $7a // nop (undocumented)                                    // 209d: 7a          z   2 cycles      A:-- X:07 Y:-- ------
    .byt $da // nop (undocumented)                                    // 209e: da          .   2 cycles      A:-- X:07 Y:-- ------
    .byt $fa // nop (undocumented)                                    // 209f: fa          .   2 cycles      A:-- X:07 Y:-- ------
    .byt $80, $12 // nop #$12 (undocumented)                          // 20a0: 80 12       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $82, $12 // nop #$12 (undocumented)                          // 20a2: 82 12       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $89, $12 // nop #$12 (undocumented)                          // 20a4: 89 12       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $c2, $12 // nop #$12 (undocumented)                          // 20a6: c2 12       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $e2, $12 // nop #$12 (undocumented)                          // 20a8: e2 12       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $04, l0070 // nop l0070 (undocumented)                       // 20aa: 04 70       .p  3 cycles      A:-- X:07 Y:-- ------
    .byt $44, l0070 // nop l0070 (undocumented)                       // 20ac: 44 70       Dp  3 cycles      A:-- X:07 Y:-- ------
    .byt $64, l0070 // nop l0070 (undocumented)                       // 20ae: 64 70       dp  3 cycles      A:-- X:07 Y:-- ------
    .byt $14, l0070 // nop l0070,x (undocumented)                     // 20b0: 14 70       .p  4 cycles      A:-- X:07 Y:-- ------
    .byt $34, l0070 // nop l0070,x (undocumented)                     // 20b2: 34 70       4p  4 cycles      A:-- X:07 Y:-- ------
    .byt $54, l0070 // nop l0070,x (undocumented)                     // 20b4: 54 70       Tp  4 cycles      A:-- X:07 Y:-- ------
    .byt $74, l0070 // nop l0070,x (undocumented)                     // 20b6: 74 70       tp  4 cycles      A:-- X:07 Y:-- ------
    .byt $d4, l0070 // nop l0070,x (undocumented)                     // 20b8: d4 70       .p  4 cycles      A:-- X:07 Y:-- ------
    .byt $f4, l0070 // nop l0070,x (undocumented)                     // 20ba: f4 70       .p  4 cycles      A:-- X:07 Y:-- ------
    .byt $0c, <l3000, >l3000 // nop l3000 (undocumented)              // 20bc: 0c 00 30    ..0 4 cycles      A:-- X:07 Y:-- ------
    .byt $1c, <l3000, >l3000 // nop l3000,x (undocumented)            // 20bf: 1c 00 30    ..0 4 cycles      A:-- X:07 Y:-- ------
    .byt $3c, <l3000, >l3000 // nop l3000,x (undocumented)            // 20c2: 3c 00 30    <.0 4 cycles      A:-- X:07 Y:-- ------
    .byt $5c, <l3000, >l3000 // nop l3000,x (undocumented)            // 20c5: 5c 00 30    \.0 4 cycles      A:-- X:07 Y:-- ------
    .byt $7c, <l3000, >l3000 // nop l3000,x (undocumented)            // 20c8: 7c 00 30    |.0 4 cycles      A:-- X:07 Y:-- ------
    .byt $dc, <l3000, >l3000 // nop l3000,x (undocumented)            // 20cb: dc 00 30    ..0 4 cycles      A:-- X:07 Y:-- ------
    .byt $fc, <l3000, >l3000 // nop l3000,x (undocumented)            // 20ce: fc 00 30    ..0 4 cycles      A:-- X:07 Y:-- ------
    .byt $8b, $12 // ane #$12 (undocumented)                          // 20d1: 8b 12       ..  2 cycles      A:-- X:07 Y:-- ------
    .byt $ab, $12 // lxa #$12 (undocumented)                          // 20d3: ab 12       ..  2 cycles      A:-- X:-- Y:-- ------
    .byt $bb, <l3000, >l3000 // las l3000,y (undocumented)            // 20d5: bb 00 30    ..0 4 cycles      A:-- X:-- Y:-- ------
    .byt $9b, <l3000, >l3000 // tas l3000,y (undocumented)            // 20d8: 9b 00 30    ..0 5 cycles      A:-- X:-- Y:-- ------
    .byt $93, l0070 // sha (l0070),y (undocumented)                   // 20db: 93 70       .p  6 cycles      A:-- X:-- Y:-- ------
    .byt $9f, <l3000, >l3000 // sha l3000,y (undocumented)            // 20dd: 9f 00 30    ..0 5 cycles      A:-- X:-- Y:-- ------
    .byt $9e, <l3000, >l3000 // shx l3000,y (undocumented)            // 20e0: 9e 00 30    ..0 5 cycles      A:-- X:-- Y:-- ------
    .byt $9c, <l3000, >l3000 // shy l3000,x (undocumented)            // 20e3: 9c 00 30    ..0 5 cycles      A:-- X:-- Y:-- ------
    beq c20e9                                                         // 20e6: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $02 // jam (undocumented)                                    // 20e8: 02          .   halts         A:-- X:-- Y:-- ------

// $20e9 referenced 1 time by $20e6
c20e9
    beq c20ec                                                         // 20e9: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $12 // jam (undocumented)                                    // 20eb: 12          .   halts         A:-- X:-- Y:-- ------

// $20ec referenced 1 time by $20e9
c20ec
    beq c20ef                                                         // 20ec: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $22 // jam (undocumented)                                    // 20ee: 22          "   halts         A:-- X:-- Y:-- ------

// $20ef referenced 1 time by $20ec
c20ef
    beq c20f2                                                         // 20ef: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $32 // jam (undocumented)                                    // 20f1: 32          2   halts         A:-- X:-- Y:-- ------

// $20f2 referenced 1 time by $20ef
c20f2
    beq c20f5                                                         // 20f2: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $42 // jam (undocumented)                                    // 20f4: 42          B   halts         A:-- X:-- Y:-- ------

// $20f5 referenced 1 time by $20f2
c20f5
    beq c20f8                                                         // 20f5: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $52 // jam (undocumented)                                    // 20f7: 52          R   halts         A:-- X:-- Y:-- ------

// $20f8 referenced 1 time by $20f5
c20f8
    beq c20fb                                                         // 20f8: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $62 // jam (undocumented)                                    // 20fa: 62          b   halts         A:-- X:-- Y:-- ------

// $20fb referenced 1 time by $20f8
c20fb
    beq c20fe                                                         // 20fb: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $72 // jam (undocumented)                                    // 20fd: 72          r   halts         A:-- X:-- Y:-- ------

// $20fe referenced 1 time by $20fb
c20fe
    beq c2101                                                         // 20fe: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $92 // jam (undocumented)                                    // 2100: 92          .   halts         A:-- X:-- Y:-- ------

// $2101 referenced 1 time by $20fe
c2101
    beq c2104                                                         // 2101: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $b2 // jam (undocumented)                                    // 2103: b2          .   halts         A:-- X:-- Y:-- ------

// $2104 referenced 1 time by $2101
c2104
    beq c2107                                                         // 2104: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $d2 // jam (undocumented)                                    // 2106: d2          .   halts         A:-- X:-- Y:-- ------

// $2107 referenced 1 time by $2104
c2107
    beq return_1                                                      // 2107: f0 01       ..  2/3 cycles    A:-- X:-- Y:-- ----z-
    .byt $f2 // jam (undocumented)                                    // 2109: f2          .   halts         A:-- X:-- Y:-- ------

// $210a referenced 1 time by $2107
return_1
    rts                                                               // 210a: 60          `   6 cycles      A:-- X:-- Y:-- ------

pydis_end


// Label references by decreasing frequency:
//     l0070:     31
//     l3000:     25
//     l0072:     13
//     l3456:      8
//     c20e9:      1
//     c20ec:      1
//     c20ef:      1
//     c20f2:      1
//     c20f5:      1
//     c20f8:      1
//     c20fb:      1
//     c20fe:      1
//     c2101:      1
//     c2104:      1
//     c2107:      1
//     return_1:   1

// Automatically generated labels:
//     c20e9
//     c20ec
//     c20ef
//     c20f2
//     c20f5
//     c20f8
//     c20fb
//     c20fe
//     c2101
//     c2104
//     c2107
//     l0070
//     l0072
//     l3000
//     l3456
//     return_1

// Stats:
//
//     Total size (Code + Data) = 267 bytes
//     Code                     = 267 bytes (100%)
//     Data                     = 0 bytes (0%)
//
//     Number of instructions   = 125
//     Number of data bytes     = 0 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

