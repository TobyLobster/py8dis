; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l0070   equ $70

    org $1000

pydis_start

; Move 1: $1000 to $1a00 for length 64
    org $1a00
; $1000 referenced 1 time by $1100
a_entry
    jsr d_entry                                                       ; 1000: 20 00 0c     .. :1a00[1]
    jsr c_entry                                                       ; 1003: 20 00 19     .. :1a03[1]
    rts                                                               ; 1006: 60          `   :1a06[1]

    dfb $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa    ; 1007: aa aa aa... ... :1a07[1]
    dfb $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa    ; 1013: aa aa aa... ... :1a13[1]
    dfb $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa    ; 101f: aa aa aa... ... :1a1f[1]
    dfb $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa    ; 102b: aa aa aa... ... :1a2b[1]
    dfb $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa, $aa                   ; 1037: aa aa aa... ... :1a37[1]
    org $1040


; Move 2: $1040 to $0c00 for length 64
    org $0c00
; $1040 referenced 1 time by $1a00[1]
d_entry
    lda #1                                                            ; 1040: a9 01       ..  :0c00[2]
    sta l0070                                                         ; 1042: 85 70       .p  :0c02[2]
    rts                                                               ; 1044: 60          `   :0c04[2]

    dfb $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd    ; 1045: dd dd dd... ... :0c05[2]
    dfb $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd    ; 1051: dd dd dd... ... :0c11[2]
    dfb $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd    ; 105d: dd dd dd... ... :0c1d[2]
    dfb $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd    ; 1069: dd dd dd... ... :0c29[2]
    dfb $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd, $dd         ; 1075: dd dd dd... ... :0c35[2]
    org $1080


; Move 3: $1080 to $1900 for length 48
    org $1900
; $1080 referenced 1 time by $1a03[1]
c_entry
    lda b_data                                                        ; 1080: ad 80 18    ... :1900[3]
    rts                                                               ; 1083: 60          `   :1903[3]

    dfb $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc    ; 1084: cc cc cc... ... :1904[3]
    dfb $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc    ; 1090: cc cc cc... ... :1910[3]
    dfb $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc    ; 109c: cc cc cc... ... :191c[3]
    dfb $cc, $cc, $cc, $cc, $cc, $cc, $cc, $cc                        ; 10a8: cc cc cc... ... :1928[3]
    org $10b0

    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 10b0: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 10c5: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 10da: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0             ; 10ef: 00 00 00... ...

start
    jsr a_entry                                                       ; 1100: 20 00 1a     ..
    jsr e_entry                                                       ; 1103: 20 e0 0f     ..
    jsr f_entry                                                       ; 1106: 20 c0 14     ..
    rts                                                               ; 1109: 60          `

    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 110a: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 111f: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1134: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1149: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 115e: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1173: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1188: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 119d: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 11b2: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 11c7: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 11dc: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 11f1: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1206: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 121b: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1230: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1245: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 125a: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 126f: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1284: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1299: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 12ae: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 12c3: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 12d8: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0       ; 12ed: 00 00 00... ...

; Move 4: $1300 to $1880 for length 64
    org $1880
; $1300 referenced 1 time by $1900[3]
b_data
    dfb 1, 2, 3, 4, 5, 6, 7, 8                                        ; 1300: 01 02 03... ... :1880[4]
    dfb $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb    ; 1308: bb bb bb... ... :1888[4]
    dfb $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb    ; 1314: bb bb bb... ... :1894[4]
    dfb $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb    ; 1320: bb bb bb... ... :18a0[4]
    dfb $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb    ; 132c: bb bb bb... ... :18ac[4]
    dfb $bb, $bb, $bb, $bb, $bb, $bb, $bb, $bb                        ; 1338: bb bb bb... ... :18b8[4]
    org $1340

    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1340: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1355: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 136a: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 137f: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1394: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 13a9: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 13be: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 13d3: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 13e8: 00 00 00... ...
    dfb 0, 0, 0                                                       ; 13fd: 00 00 00    ...

; Move 5: $1400 to $0fe0 for length 256
    org $0fe0
; $1400 referenced 1 time by $1103
e_entry
    ldx #3                                                            ; 1400: a2 03       ..  :0fe0[5]
    lda f_table,x                                                     ; 1402: bd c1 14    ... :0fe2[5]
    rts                                                               ; 1405: 60          `   :0fe5[5]

    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1406: ee ee ee... ... :0fe6[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1412: ee ee ee... ... :0ff2[5]
    dfb $ee, $ee                                                      ; 141e: ee ee       ..  :0ffe[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1420: ee ee ee... ... :1000[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 142c: ee ee ee... ... :100c[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1438: ee ee ee... ... :1018[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1444: ee ee ee... ... :1024[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1450: ee ee ee... ... :1030[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 145c: ee ee ee... ... :103c[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1468: ee ee ee... ... :1048[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1474: ee ee ee... ... :1054[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1480: ee ee ee... ... :1060[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 148c: ee ee ee... ... :106c[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 1498: ee ee ee... ... :1078[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14a4: ee ee ee... ... :1084[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14b0: ee ee ee... ... :1090[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14bc: ee ee ee... ... :109c[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14c8: ee ee ee... ... :10a8[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14d4: ee ee ee... ... :10b4[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14e0: ee ee ee... ... :10c0[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee    ; 14ec: ee ee ee... ... :10cc[5]
    dfb $ee, $ee, $ee, $ee, $ee, $ee, $ee, $ee                        ; 14f8: ee ee ee... ... :10d8[5]
    org $1500

    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1500: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 1515: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 152a: 00 00 00... ...
    dfb 0                                                             ; 153f: 00          .

; Move 6: $1540 to $14c0 for length 192
    org $14c0
; $1540 referenced 1 time by $1106
f_entry
    rts                                                               ; 1540: 60          `   :14c0[6]

; $1541 referenced 1 time by $0fe2[5]
f_table
    dfb $10, $20, $30, $40                                            ; 1541: 10 20 30... . 0 :14c1[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 1545: ff ff ff... ... :14c5[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 1551: ff ff ff... ... :14d1[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 155d: ff ff ff... ... :14dd[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 1569: ff ff ff... ... :14e9[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 1575: ff ff ff... ... :14f5[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 1581: ff ff ff... ... :1501[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 158d: ff ff ff... ... :150d[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 1599: ff ff ff... ... :1519[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15a5: ff ff ff... ... :1525[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15b1: ff ff ff... ... :1531[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15bd: ff ff ff... ... :153d[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15c9: ff ff ff... ... :1549[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15d5: ff ff ff... ... :1555[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15e1: ff ff ff... ... :1561[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff    ; 15ed: ff ff ff... ... :156d[6]
    dfb $ff, $ff, $ff, $ff, $ff, $ff, $ff                             ; 15f9: ff ff ff... ... :1579[6]
    org $1600

pydis_end


; Label references by decreasing frequency:
;     a_entry:   1
;     b_data:    1
;     c_entry:   1
;     d_entry:   1
;     e_entry:   1
;     f_entry:   1
;     f_table:   1
;     l0070:     1

; Automatically generated labels:
;     l0070

; Stats:
;
;     Total size (Code + Data) = 1536 bytes
;     Code                     = 33 bytes (2%)
;     Data                     = 1503 bytes (98%)
;
;     Number of instructions   = 16
;     Number of data bytes     = 1503 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
