    org $8000

pydis_start:
start:
    ld b,b                                                            ; 8000: 40          @   4 cycles
    ld b,c                                                            ; 8001: 41          A   4 cycles
    ld b,d                                                            ; 8002: 42          B   4 cycles
    ld b,e                                                            ; 8003: 43          C   4 cycles
    ld b,h                                                            ; 8004: 44          D   4 cycles
    ld b,l                                                            ; 8005: 45          E   4 cycles
    ld b,a                                                            ; 8006: 47          G   4 cycles
    ld c,b                                                            ; 8007: 48          H   4 cycles
    ld c,c                                                            ; 8008: 49          I   4 cycles
    ld c,d                                                            ; 8009: 4a          J   4 cycles
    ld c,e                                                            ; 800a: 4b          K   4 cycles
    ld c,h                                                            ; 800b: 4c          L   4 cycles
    ld c,l                                                            ; 800c: 4d          M   4 cycles
    ld c,a                                                            ; 800d: 4f          O   4 cycles
    ld d,b                                                            ; 800e: 50          P   4 cycles
    ld d,c                                                            ; 800f: 51          Q   4 cycles
    ld d,d                                                            ; 8010: 52          R   4 cycles
    ld d,e                                                            ; 8011: 53          S   4 cycles
    ld d,h                                                            ; 8012: 54          T   4 cycles
    ld d,l                                                            ; 8013: 55          U   4 cycles
    ld d,a                                                            ; 8014: 57          W   4 cycles
    ld e,b                                                            ; 8015: 58          X   4 cycles
    ld e,c                                                            ; 8016: 59          Y   4 cycles
    ld e,d                                                            ; 8017: 5a          Z   4 cycles
    ld e,e                                                            ; 8018: 5b          [   4 cycles
    ld e,h                                                            ; 8019: 5c          \   4 cycles
    ld e,l                                                            ; 801a: 5d          ]   4 cycles
    ld e,a                                                            ; 801b: 5f          _   4 cycles
    ld h,b                                                            ; 801c: 60          `   4 cycles
    ld h,c                                                            ; 801d: 61          a   4 cycles
    ld h,d                                                            ; 801e: 62          b   4 cycles
    ld h,e                                                            ; 801f: 63          c   4 cycles
    ld h,h                                                            ; 8020: 64          d   4 cycles
    ld h,l                                                            ; 8021: 65          e   4 cycles
    ld h,a                                                            ; 8022: 67          g   4 cycles
    ld l,b                                                            ; 8023: 68          h   4 cycles
    ld l,c                                                            ; 8024: 69          i   4 cycles
    ld l,d                                                            ; 8025: 6a          j   4 cycles
    ld l,e                                                            ; 8026: 6b          k   4 cycles
    ld l,h                                                            ; 8027: 6c          l   4 cycles
    ld l,l                                                            ; 8028: 6d          m   4 cycles
    ld l,a                                                            ; 8029: 6f          o   4 cycles
    ld a,b                                                            ; 802a: 78          x   4 cycles
    ld a,c                                                            ; 802b: 79          y   4 cycles
    ld a,d                                                            ; 802c: 7a          z   4 cycles
    ld a,e                                                            ; 802d: 7b          {   4 cycles
    ld a,h                                                            ; 802e: 7c          |   4 cycles
    ld a,l                                                            ; 802f: 7d          }   4 cycles
    ld a,a                                                            ; 8030: 7f          .   4 cycles
    ld b,$11                                                          ; 8031: 06 11       ..  7 cycles
    ld c,$22                                                          ; 8033: 0e 22       ."  7 cycles
    ld d,$33                                                          ; 8035: 16 33       .3  7 cycles
    ld e,$44                                                          ; 8037: 1e 44       .D  7 cycles
    ld h,$55                                                          ; 8039: 26 55       &U  7 cycles
    ld l,$66                                                          ; 803b: 2e 66       .f  7 cycles
    ld a,$77                                                          ; 803d: 3e 77       >w  7 cycles
    ld b,(hl)                                                         ; 803f: 46          F   7 cycles
    ld c,(hl)                                                         ; 8040: 4e          N   7 cycles
    ld d,(hl)                                                         ; 8041: 56          V   7 cycles
    ld e,(hl)                                                         ; 8042: 5e          ^   7 cycles
    ld h,(hl)                                                         ; 8043: 66          f   7 cycles
    ld l,(hl)                                                         ; 8044: 6e          n   7 cycles
    ld a,(hl)                                                         ; 8045: 7e          ~   7 cycles
    ld (hl),b                                                         ; 8046: 70          p   7 cycles
    ld (hl),c                                                         ; 8047: 71          q   7 cycles
    ld (hl),d                                                         ; 8048: 72          r   7 cycles
    ld (hl),e                                                         ; 8049: 73          s   7 cycles
    ld (hl),h                                                         ; 804a: 74          t   7 cycles
    ld (hl),l                                                         ; 804b: 75          u   7 cycles
    ld (hl),a                                                         ; 804c: 77          w   7 cycles
    ld (hl),$5a                                                       ; 804d: 36 5a       6Z  10 cycles
    ld b,(ix+0)                                                       ; 804f: dd 46 00    .F. 19 cycles
    ld c,(ix+5)                                                       ; 8052: dd 4e 05    .N. 19 cycles
    ld d,(ix-1)                                                       ; 8055: dd 56 ff    .V. 19 cycles
    ld e,(ix+127)                                                     ; 8058: dd 5e 7f    .^. 19 cycles
    ld h,(ix-128)                                                     ; 805b: dd 66 80    .f. 19 cycles
    ld l,(ix+0)                                                       ; 805e: dd 6e 00    .n. 19 cycles
    ld a,(ix+5)                                                       ; 8061: dd 7e 05    .~. 19 cycles
    ld (ix+5),b                                                       ; 8064: dd 70 05    .p. 19 cycles
    ld (ix-1),c                                                       ; 8067: dd 71 ff    .q. 19 cycles
    ld (ix+127),d                                                     ; 806a: dd 72 7f    .r. 19 cycles
    ld (ix-128),e                                                     ; 806d: dd 73 80    .s. 19 cycles
    ld (ix+0),h                                                       ; 8070: dd 74 00    .t. 19 cycles
    ld (ix+5),l                                                       ; 8073: dd 75 05    .u. 19 cycles
    ld (ix-1),a                                                       ; 8076: dd 77 ff    .w. 19 cycles
    ld (ix+2),$a5                                                     ; 8079: dd 36 02... .6. 19 cycles
    ld b,(iy+3)                                                       ; 807d: fd 46 03    .F. 19 cycles
    ld c,(iy-3)                                                       ; 8080: fd 4e fd    .N. 19 cycles
    ld d,(iy+64)                                                      ; 8083: fd 56 40    .V@ 19 cycles
    ld e,(iy+3)                                                       ; 8086: fd 5e 03    .^. 19 cycles
    ld h,(iy-3)                                                       ; 8089: fd 66 fd    .f. 19 cycles
    ld l,(iy+64)                                                      ; 808c: fd 6e 40    .n@ 19 cycles
    ld a,(iy+3)                                                       ; 808f: fd 7e 03    .~. 19 cycles
    ld (iy-3),b                                                       ; 8092: fd 70 fd    .p. 19 cycles
    ld (iy+64),c                                                      ; 8095: fd 71 40    .q@ 19 cycles
    ld (iy+3),d                                                       ; 8098: fd 72 03    .r. 19 cycles
    ld (iy-3),e                                                       ; 809b: fd 73 fd    .s. 19 cycles
    ld (iy+64),h                                                      ; 809e: fd 74 40    .t@ 19 cycles
    ld (iy+3),l                                                       ; 80a1: fd 75 03    .u. 19 cycles
    ld (iy-3),a                                                       ; 80a4: fd 77 fd    .w. 19 cycles
    ld (iy+2),$a5                                                     ; 80a7: fd 36 02... .6. 19 cycles
    ld a,(bc)                                                         ; 80ab: 0a          .   7 cycles
    ld a,(de)                                                         ; 80ac: 1a          .   7 cycles
    ld a,(value)                                                      ; 80ad: 3a 89 85    :.. 13 cycles
    ld (bc),a                                                         ; 80b0: 02          .   7 cycles
    ld (de),a                                                         ; 80b1: 12          .   7 cycles
    ld (value),a                                                      ; 80b2: 32 89 85    2.. 13 cycles
    ld a,i                                                            ; 80b5: ed 57       .W  9 cycles
    ld a,r                                                            ; 80b7: ed 5f       ._  9 cycles
    ld i,a                                                            ; 80b9: ed 47       .G  9 cycles
    ld r,a                                                            ; 80bb: ed 4f       .O  9 cycles
    ld bc,$1234                                                       ; 80bd: 01 34 12    .4. 10 cycles
    ld de,$8589                                                       ; 80c0: 11 89 85    ... 10 cycles
    ld hl,$858c                                                       ; 80c3: 21 8c 85    !.. 10 cycles
    ld sp,$ff00                                                       ; 80c6: 31 00 ff    1.. 10 cycles
    ld ix,$858c                                                       ; 80c9: dd 21 8c... .!. 14 cycles
    ld iy,$4000                                                       ; 80cd: fd 21 00... .!. 14 cycles
    ld hl,(word)                                                      ; 80d1: 2a 8a 85    *.. 16 cycles
    ld bc,(word)                                                      ; 80d4: ed 4b 8a... .K. 20 cycles
    ld de,(word)                                                      ; 80d8: ed 5b 8a... .[. 20 cycles
    ld sp,(word)                                                      ; 80dc: ed 7b 8a... .{. 20 cycles
    ld ix,(word)                                                      ; 80e0: dd 2a 8a... .*. 20 cycles
    ld iy,(word)                                                      ; 80e4: fd 2a 8a... .*. 20 cycles
    ld (word),hl                                                      ; 80e8: 22 8a 85    ".. 16 cycles
    ld (word),bc                                                      ; 80eb: ed 43 8a... .C. 20 cycles
    ld (word),de                                                      ; 80ef: ed 53 8a... .S. 20 cycles
    ld (word),sp                                                      ; 80f3: ed 73 8a... .s. 20 cycles
    ld (word),ix                                                      ; 80f7: dd 22 8a... .". 20 cycles
    ld (word),iy                                                      ; 80fb: fd 22 8a... .". 20 cycles
    ld sp,hl                                                          ; 80ff: f9          .   6 cycles
    ld sp,ix                                                          ; 8100: dd f9       ..  10 cycles
    ld sp,iy                                                          ; 8102: fd f9       ..  10 cycles
    push bc                                                           ; 8104: c5          .   11 cycles
    push de                                                           ; 8105: d5          .   11 cycles
    push hl                                                           ; 8106: e5          .   11 cycles
    push af                                                           ; 8107: f5          .   11 cycles
    push ix                                                           ; 8108: dd e5       ..  15 cycles
    push iy                                                           ; 810a: fd e5       ..  15 cycles
    pop bc                                                            ; 810c: c1          .   10 cycles
    pop de                                                            ; 810d: d1          .   10 cycles
    pop hl                                                            ; 810e: e1          .   10 cycles
    pop af                                                            ; 810f: f1          .   10 cycles
    pop ix                                                            ; 8110: dd e1       ..  14 cycles
    pop iy                                                            ; 8112: fd e1       ..  14 cycles
    ex de,hl                                                          ; 8114: eb          .   4 cycles
    ex af,af'                                                         ; 8115: 08          .   4 cycles
    exx                                                               ; 8116: d9          .   4 cycles
    ex (sp),hl                                                        ; 8117: e3          .   19 cycles
    ex (sp),ix                                                        ; 8118: dd e3       ..  23 cycles
    ex (sp),iy                                                        ; 811a: fd e3       ..  23 cycles
    ldi                                                               ; 811c: ed a0       ..  16 cycles
    ldir                                                              ; 811e: ed b0       ..  16/21 cycles
    ldd                                                               ; 8120: ed a8       ..  16 cycles
    lddr                                                              ; 8122: ed b8       ..  16/21 cycles
    cpi                                                               ; 8124: ed a1       ..  16 cycles
    cpir                                                              ; 8126: ed b1       ..  16/21 cycles
    cpd                                                               ; 8128: ed a9       ..  16 cycles
    cpdr                                                              ; 812a: ed b9       ..  16/21 cycles
    add a,b                                                           ; 812c: 80          .   4 cycles
    add a,c                                                           ; 812d: 81          .   4 cycles
    add a,d                                                           ; 812e: 82          .   4 cycles
    add a,e                                                           ; 812f: 83          .   4 cycles
    add a,h                                                           ; 8130: 84          .   4 cycles
    add a,l                                                           ; 8131: 85          .   4 cycles
    add a,a                                                           ; 8132: 87          .   4 cycles
    add a,(hl)                                                        ; 8133: 86          .   7 cycles
    add a,$0f                                                         ; 8134: c6 0f       ..  7 cycles
    add a,(ix+4)                                                      ; 8136: dd 86 04    ... 19 cycles
    add a,(iy-4)                                                      ; 8139: fd 86 fc    ... 19 cycles
    adc a,b                                                           ; 813c: 88          .   4 cycles
    adc a,c                                                           ; 813d: 89          .   4 cycles
    adc a,d                                                           ; 813e: 8a          .   4 cycles
    adc a,e                                                           ; 813f: 8b          .   4 cycles
    adc a,h                                                           ; 8140: 8c          .   4 cycles
    adc a,l                                                           ; 8141: 8d          .   4 cycles
    adc a,a                                                           ; 8142: 8f          .   4 cycles
    adc a,(hl)                                                        ; 8143: 8e          .   7 cycles
    adc a,$0f                                                         ; 8144: ce 0f       ..  7 cycles
    adc a,(ix+4)                                                      ; 8146: dd 8e 04    ... 19 cycles
    adc a,(iy-4)                                                      ; 8149: fd 8e fc    ... 19 cycles
    sub b                                                             ; 814c: 90          .   4 cycles
    sub c                                                             ; 814d: 91          .   4 cycles
    sub d                                                             ; 814e: 92          .   4 cycles
    sub e                                                             ; 814f: 93          .   4 cycles
    sub h                                                             ; 8150: 94          .   4 cycles
    sub l                                                             ; 8151: 95          .   4 cycles
    sub a                                                             ; 8152: 97          .   4 cycles
    sub (hl)                                                          ; 8153: 96          .   7 cycles
    sub $0f                                                           ; 8154: d6 0f       ..  7 cycles
    sub (ix+4)                                                        ; 8156: dd 96 04    ... 19 cycles
    sub (iy-4)                                                        ; 8159: fd 96 fc    ... 19 cycles
    sbc a,b                                                           ; 815c: 98          .   4 cycles
    sbc a,c                                                           ; 815d: 99          .   4 cycles
    sbc a,d                                                           ; 815e: 9a          .   4 cycles
    sbc a,e                                                           ; 815f: 9b          .   4 cycles
    sbc a,h                                                           ; 8160: 9c          .   4 cycles
    sbc a,l                                                           ; 8161: 9d          .   4 cycles
    sbc a,a                                                           ; 8162: 9f          .   4 cycles
    sbc a,(hl)                                                        ; 8163: 9e          .   7 cycles
    sbc a,$0f                                                         ; 8164: de 0f       ..  7 cycles
    sbc a,(ix+4)                                                      ; 8166: dd 9e 04    ... 19 cycles
    sbc a,(iy-4)                                                      ; 8169: fd 9e fc    ... 19 cycles
    and b                                                             ; 816c: a0          .   4 cycles
    and c                                                             ; 816d: a1          .   4 cycles
    and d                                                             ; 816e: a2          .   4 cycles
    and e                                                             ; 816f: a3          .   4 cycles
    and h                                                             ; 8170: a4          .   4 cycles
    and l                                                             ; 8171: a5          .   4 cycles
    and a                                                             ; 8172: a7          .   4 cycles
    and (hl)                                                          ; 8173: a6          .   7 cycles
    and $0f                                                           ; 8174: e6 0f       ..  7 cycles
    and (ix+4)                                                        ; 8176: dd a6 04    ... 19 cycles
    and (iy-4)                                                        ; 8179: fd a6 fc    ... 19 cycles
    xor b                                                             ; 817c: a8          .   4 cycles
    xor c                                                             ; 817d: a9          .   4 cycles
    xor d                                                             ; 817e: aa          .   4 cycles
    xor e                                                             ; 817f: ab          .   4 cycles
    xor h                                                             ; 8180: ac          .   4 cycles
    xor l                                                             ; 8181: ad          .   4 cycles
    xor a                                                             ; 8182: af          .   4 cycles
    xor (hl)                                                          ; 8183: ae          .   7 cycles
    xor $0f                                                           ; 8184: ee 0f       ..  7 cycles
    xor (ix+4)                                                        ; 8186: dd ae 04    ... 19 cycles
    xor (iy-4)                                                        ; 8189: fd ae fc    ... 19 cycles
    or b                                                              ; 818c: b0          .   4 cycles
    or c                                                              ; 818d: b1          .   4 cycles
    or d                                                              ; 818e: b2          .   4 cycles
    or e                                                              ; 818f: b3          .   4 cycles
    or h                                                              ; 8190: b4          .   4 cycles
    or l                                                              ; 8191: b5          .   4 cycles
    or a                                                              ; 8192: b7          .   4 cycles
    or (hl)                                                           ; 8193: b6          .   7 cycles
    or $0f                                                            ; 8194: f6 0f       ..  7 cycles
    or (ix+4)                                                         ; 8196: dd b6 04    ... 19 cycles
    or (iy-4)                                                         ; 8199: fd b6 fc    ... 19 cycles
    cp b                                                              ; 819c: b8          .   4 cycles
    cp c                                                              ; 819d: b9          .   4 cycles
    cp d                                                              ; 819e: ba          .   4 cycles
    cp e                                                              ; 819f: bb          .   4 cycles
    cp h                                                              ; 81a0: bc          .   4 cycles
    cp l                                                              ; 81a1: bd          .   4 cycles
    cp a                                                              ; 81a2: bf          .   4 cycles
    cp (hl)                                                           ; 81a3: be          .   7 cycles
    cp $0f                                                            ; 81a4: fe 0f       ..  7 cycles
    cp (ix+4)                                                         ; 81a6: dd be 04    ... 19 cycles
    cp (iy-4)                                                         ; 81a9: fd be fc    ... 19 cycles
    inc b                                                             ; 81ac: 04          .   4 cycles
    inc c                                                             ; 81ad: 0c          .   4 cycles
    inc d                                                             ; 81ae: 14          .   4 cycles
    inc e                                                             ; 81af: 1c          .   4 cycles
    inc h                                                             ; 81b0: 24          $   4 cycles
    inc l                                                             ; 81b1: 2c          ,   4 cycles
    inc a                                                             ; 81b2: 3c          <   4 cycles
    inc (hl)                                                          ; 81b3: 34          4   11 cycles
    inc (ix+1)                                                        ; 81b4: dd 34 01    .4. 23 cycles
    inc (iy-1)                                                        ; 81b7: fd 34 ff    .4. 23 cycles
    dec b                                                             ; 81ba: 05          .   4 cycles
    dec c                                                             ; 81bb: 0d          .   4 cycles
    dec d                                                             ; 81bc: 15          .   4 cycles
    dec e                                                             ; 81bd: 1d          .   4 cycles
    dec h                                                             ; 81be: 25          %   4 cycles
    dec l                                                             ; 81bf: 2d          -   4 cycles
    dec a                                                             ; 81c0: 3d          =   4 cycles
    dec (hl)                                                          ; 81c1: 35          5   11 cycles
    dec (ix+1)                                                        ; 81c2: dd 35 01    .5. 23 cycles
    dec (iy-1)                                                        ; 81c5: fd 35 ff    .5. 23 cycles
    daa                                                               ; 81c8: 27          '   4 cycles
    cpl                                                               ; 81c9: 2f          /   4 cycles
    neg                                                               ; 81ca: ed 44       .D  8 cycles
    ccf                                                               ; 81cc: 3f          ?   4 cycles
    scf                                                               ; 81cd: 37          7   4 cycles
    nop                                                               ; 81ce: 00          .   4 cycles
    halt                                                              ; 81cf: 76          v   4 cycles
    di                                                                ; 81d0: f3          .   4 cycles
    ei                                                                ; 81d1: fb          .   4 cycles
    im 0                                                              ; 81d2: ed 46       .F  8 cycles
    im 1                                                              ; 81d4: ed 56       .V  8 cycles
    im 2                                                              ; 81d6: ed 5e       .^  8 cycles
    add hl,bc                                                         ; 81d8: 09          .   11 cycles
    add hl,de                                                         ; 81d9: 19          .   11 cycles
    add hl,hl                                                         ; 81da: 29          )   11 cycles
    add hl,sp                                                         ; 81db: 39          9   11 cycles
    add ix,bc                                                         ; 81dc: dd 09       ..  15 cycles
    add ix,de                                                         ; 81de: dd 19       ..  15 cycles
    add ix,ix                                                         ; 81e0: dd 29       .)  15 cycles
    add ix,sp                                                         ; 81e2: dd 39       .9  15 cycles
    add iy,bc                                                         ; 81e4: fd 09       ..  15 cycles
    add iy,de                                                         ; 81e6: fd 19       ..  15 cycles
    add iy,iy                                                         ; 81e8: fd 29       .)  15 cycles
    add iy,sp                                                         ; 81ea: fd 39       .9  15 cycles
    adc hl,bc                                                         ; 81ec: ed 4a       .J  15 cycles
    adc hl,de                                                         ; 81ee: ed 5a       .Z  15 cycles
    adc hl,hl                                                         ; 81f0: ed 6a       .j  15 cycles
    adc hl,sp                                                         ; 81f2: ed 7a       .z  15 cycles
    sbc hl,bc                                                         ; 81f4: ed 42       .B  15 cycles
    sbc hl,de                                                         ; 81f6: ed 52       .R  15 cycles
    sbc hl,hl                                                         ; 81f8: ed 62       .b  15 cycles
    sbc hl,sp                                                         ; 81fa: ed 72       .r  15 cycles
    inc bc                                                            ; 81fc: 03          .   6 cycles
    inc de                                                            ; 81fd: 13          .   6 cycles
    inc hl                                                            ; 81fe: 23          #   6 cycles
    inc sp                                                            ; 81ff: 33          3   6 cycles
    inc ix                                                            ; 8200: dd 23       .#  10 cycles
    inc iy                                                            ; 8202: fd 23       .#  10 cycles
    dec bc                                                            ; 8204: 0b          .   6 cycles
    dec de                                                            ; 8205: 1b          .   6 cycles
    dec hl                                                            ; 8206: 2b          +   6 cycles
    dec sp                                                            ; 8207: 3b          ;   6 cycles
    dec ix                                                            ; 8208: dd 2b       .+  10 cycles
    dec iy                                                            ; 820a: fd 2b       .+  10 cycles
    rlca                                                              ; 820c: 07          .   4 cycles
    rla                                                               ; 820d: 17          .   4 cycles
    rrca                                                              ; 820e: 0f          .   4 cycles
    rra                                                               ; 820f: 1f          .   4 cycles
    rld                                                               ; 8210: ed 6f       .o  18 cycles
    rrd                                                               ; 8212: ed 67       .g  18 cycles
    rlc b                                                             ; 8214: cb 00       ..  8 cycles
    rlc c                                                             ; 8216: cb 01       ..  8 cycles
    rlc d                                                             ; 8218: cb 02       ..  8 cycles
    rlc e                                                             ; 821a: cb 03       ..  8 cycles
    rlc h                                                             ; 821c: cb 04       ..  8 cycles
    rlc l                                                             ; 821e: cb 05       ..  8 cycles
    rlc a                                                             ; 8220: cb 07       ..  8 cycles
    rlc (hl)                                                          ; 8222: cb 06       ..  15 cycles
    rlc (ix+7)                                                        ; 8224: dd cb 07... ... 23 cycles
    rlc (iy-7)                                                        ; 8228: fd cb f9... ... 23 cycles
    rl b                                                              ; 822c: cb 10       ..  8 cycles
    rl c                                                              ; 822e: cb 11       ..  8 cycles
    rl d                                                              ; 8230: cb 12       ..  8 cycles
    rl e                                                              ; 8232: cb 13       ..  8 cycles
    rl h                                                              ; 8234: cb 14       ..  8 cycles
    rl l                                                              ; 8236: cb 15       ..  8 cycles
    rl a                                                              ; 8238: cb 17       ..  8 cycles
    rl (hl)                                                           ; 823a: cb 16       ..  15 cycles
    rl (ix+7)                                                         ; 823c: dd cb 07... ... 23 cycles
    rl (iy-7)                                                         ; 8240: fd cb f9... ... 23 cycles
    rrc b                                                             ; 8244: cb 08       ..  8 cycles
    rrc c                                                             ; 8246: cb 09       ..  8 cycles
    rrc d                                                             ; 8248: cb 0a       ..  8 cycles
    rrc e                                                             ; 824a: cb 0b       ..  8 cycles
    rrc h                                                             ; 824c: cb 0c       ..  8 cycles
    rrc l                                                             ; 824e: cb 0d       ..  8 cycles
    rrc a                                                             ; 8250: cb 0f       ..  8 cycles
    rrc (hl)                                                          ; 8252: cb 0e       ..  15 cycles
    rrc (ix+7)                                                        ; 8254: dd cb 07... ... 23 cycles
    rrc (iy-7)                                                        ; 8258: fd cb f9... ... 23 cycles
    rr b                                                              ; 825c: cb 18       ..  8 cycles
    rr c                                                              ; 825e: cb 19       ..  8 cycles
    rr d                                                              ; 8260: cb 1a       ..  8 cycles
    rr e                                                              ; 8262: cb 1b       ..  8 cycles
    rr h                                                              ; 8264: cb 1c       ..  8 cycles
    rr l                                                              ; 8266: cb 1d       ..  8 cycles
    rr a                                                              ; 8268: cb 1f       ..  8 cycles
    rr (hl)                                                           ; 826a: cb 1e       ..  15 cycles
    rr (ix+7)                                                         ; 826c: dd cb 07... ... 23 cycles
    rr (iy-7)                                                         ; 8270: fd cb f9... ... 23 cycles
    sla b                                                             ; 8274: cb 20       .   8 cycles
    sla c                                                             ; 8276: cb 21       .!  8 cycles
    sla d                                                             ; 8278: cb 22       ."  8 cycles
    sla e                                                             ; 827a: cb 23       .#  8 cycles
    sla h                                                             ; 827c: cb 24       .$  8 cycles
    sla l                                                             ; 827e: cb 25       .%  8 cycles
    sla a                                                             ; 8280: cb 27       .'  8 cycles
    sla (hl)                                                          ; 8282: cb 26       .&  15 cycles
    sla (ix+7)                                                        ; 8284: dd cb 07... ... 23 cycles
    sla (iy-7)                                                        ; 8288: fd cb f9... ... 23 cycles
    sra b                                                             ; 828c: cb 28       .(  8 cycles
    sra c                                                             ; 828e: cb 29       .)  8 cycles
    sra d                                                             ; 8290: cb 2a       .*  8 cycles
    sra e                                                             ; 8292: cb 2b       .+  8 cycles
    sra h                                                             ; 8294: cb 2c       .,  8 cycles
    sra l                                                             ; 8296: cb 2d       .-  8 cycles
    sra a                                                             ; 8298: cb 2f       ./  8 cycles
    sra (hl)                                                          ; 829a: cb 2e       ..  15 cycles
    sra (ix+7)                                                        ; 829c: dd cb 07... ... 23 cycles
    sra (iy-7)                                                        ; 82a0: fd cb f9... ... 23 cycles
    srl b                                                             ; 82a4: cb 38       .8  8 cycles
    srl c                                                             ; 82a6: cb 39       .9  8 cycles
    srl d                                                             ; 82a8: cb 3a       .:  8 cycles
    srl e                                                             ; 82aa: cb 3b       .;  8 cycles
    srl h                                                             ; 82ac: cb 3c       .<  8 cycles
    srl l                                                             ; 82ae: cb 3d       .=  8 cycles
    srl a                                                             ; 82b0: cb 3f       .?  8 cycles
    srl (hl)                                                          ; 82b2: cb 3e       .>  15 cycles
    srl (ix+7)                                                        ; 82b4: dd cb 07... ... 23 cycles
    srl (iy-7)                                                        ; 82b8: fd cb f9... ... 23 cycles
    bit 0,b                                                           ; 82bc: cb 40       .@  8 cycles
    bit 0,c                                                           ; 82be: cb 41       .A  8 cycles
    bit 0,d                                                           ; 82c0: cb 42       .B  8 cycles
    bit 0,e                                                           ; 82c2: cb 43       .C  8 cycles
    bit 0,h                                                           ; 82c4: cb 44       .D  8 cycles
    bit 0,l                                                           ; 82c6: cb 45       .E  8 cycles
    bit 0,a                                                           ; 82c8: cb 47       .G  8 cycles
    bit 0,(hl)                                                        ; 82ca: cb 46       .F  12 cycles
    bit 0,(ix+0)                                                      ; 82cc: dd cb 00... ... 20 cycles
    bit 0,(iy-1)                                                      ; 82d0: fd cb ff... ... 20 cycles
    bit 1,b                                                           ; 82d4: cb 48       .H  8 cycles
    bit 1,c                                                           ; 82d6: cb 49       .I  8 cycles
    bit 1,d                                                           ; 82d8: cb 4a       .J  8 cycles
    bit 1,e                                                           ; 82da: cb 4b       .K  8 cycles
    bit 1,h                                                           ; 82dc: cb 4c       .L  8 cycles
    bit 1,l                                                           ; 82de: cb 4d       .M  8 cycles
    bit 1,a                                                           ; 82e0: cb 4f       .O  8 cycles
    bit 1,(hl)                                                        ; 82e2: cb 4e       .N  12 cycles
    bit 1,(ix+1)                                                      ; 82e4: dd cb 01... ... 20 cycles
    bit 1,(iy-2)                                                      ; 82e8: fd cb fe... ... 20 cycles
    bit 2,b                                                           ; 82ec: cb 50       .P  8 cycles
    bit 2,c                                                           ; 82ee: cb 51       .Q  8 cycles
    bit 2,d                                                           ; 82f0: cb 52       .R  8 cycles
    bit 2,e                                                           ; 82f2: cb 53       .S  8 cycles
    bit 2,h                                                           ; 82f4: cb 54       .T  8 cycles
    bit 2,l                                                           ; 82f6: cb 55       .U  8 cycles
    bit 2,a                                                           ; 82f8: cb 57       .W  8 cycles
    bit 2,(hl)                                                        ; 82fa: cb 56       .V  12 cycles
    bit 2,(ix+2)                                                      ; 82fc: dd cb 02... ... 20 cycles
    bit 2,(iy-3)                                                      ; 8300: fd cb fd... ... 20 cycles
    bit 3,b                                                           ; 8304: cb 58       .X  8 cycles
    bit 3,c                                                           ; 8306: cb 59       .Y  8 cycles
    bit 3,d                                                           ; 8308: cb 5a       .Z  8 cycles
    bit 3,e                                                           ; 830a: cb 5b       .[  8 cycles
    bit 3,h                                                           ; 830c: cb 5c       .\  8 cycles
    bit 3,l                                                           ; 830e: cb 5d       .]  8 cycles
    bit 3,a                                                           ; 8310: cb 5f       ._  8 cycles
    bit 3,(hl)                                                        ; 8312: cb 5e       .^  12 cycles
    bit 3,(ix+3)                                                      ; 8314: dd cb 03... ... 20 cycles
    bit 3,(iy-4)                                                      ; 8318: fd cb fc... ... 20 cycles
    bit 4,b                                                           ; 831c: cb 60       .`  8 cycles
    bit 4,c                                                           ; 831e: cb 61       .a  8 cycles
    bit 4,d                                                           ; 8320: cb 62       .b  8 cycles
    bit 4,e                                                           ; 8322: cb 63       .c  8 cycles
    bit 4,h                                                           ; 8324: cb 64       .d  8 cycles
    bit 4,l                                                           ; 8326: cb 65       .e  8 cycles
    bit 4,a                                                           ; 8328: cb 67       .g  8 cycles
    bit 4,(hl)                                                        ; 832a: cb 66       .f  12 cycles
    bit 4,(ix+4)                                                      ; 832c: dd cb 04... ... 20 cycles
    bit 4,(iy-5)                                                      ; 8330: fd cb fb... ... 20 cycles
    bit 5,b                                                           ; 8334: cb 68       .h  8 cycles
    bit 5,c                                                           ; 8336: cb 69       .i  8 cycles
    bit 5,d                                                           ; 8338: cb 6a       .j  8 cycles
    bit 5,e                                                           ; 833a: cb 6b       .k  8 cycles
    bit 5,h                                                           ; 833c: cb 6c       .l  8 cycles
    bit 5,l                                                           ; 833e: cb 6d       .m  8 cycles
    bit 5,a                                                           ; 8340: cb 6f       .o  8 cycles
    bit 5,(hl)                                                        ; 8342: cb 6e       .n  12 cycles
    bit 5,(ix+5)                                                      ; 8344: dd cb 05... ... 20 cycles
    bit 5,(iy-6)                                                      ; 8348: fd cb fa... ... 20 cycles
    bit 6,b                                                           ; 834c: cb 70       .p  8 cycles
    bit 6,c                                                           ; 834e: cb 71       .q  8 cycles
    bit 6,d                                                           ; 8350: cb 72       .r  8 cycles
    bit 6,e                                                           ; 8352: cb 73       .s  8 cycles
    bit 6,h                                                           ; 8354: cb 74       .t  8 cycles
    bit 6,l                                                           ; 8356: cb 75       .u  8 cycles
    bit 6,a                                                           ; 8358: cb 77       .w  8 cycles
    bit 6,(hl)                                                        ; 835a: cb 76       .v  12 cycles
    bit 6,(ix+6)                                                      ; 835c: dd cb 06... ... 20 cycles
    bit 6,(iy-7)                                                      ; 8360: fd cb f9... ... 20 cycles
    bit 7,b                                                           ; 8364: cb 78       .x  8 cycles
    bit 7,c                                                           ; 8366: cb 79       .y  8 cycles
    bit 7,d                                                           ; 8368: cb 7a       .z  8 cycles
    bit 7,e                                                           ; 836a: cb 7b       .{  8 cycles
    bit 7,h                                                           ; 836c: cb 7c       .|  8 cycles
    bit 7,l                                                           ; 836e: cb 7d       .}  8 cycles
    bit 7,a                                                           ; 8370: cb 7f       ..  8 cycles
    bit 7,(hl)                                                        ; 8372: cb 7e       .~  12 cycles
    bit 7,(ix+7)                                                      ; 8374: dd cb 07... ... 20 cycles
    bit 7,(iy-8)                                                      ; 8378: fd cb f8... ... 20 cycles
    set 0,b                                                           ; 837c: cb c0       ..  8 cycles
    set 0,c                                                           ; 837e: cb c1       ..  8 cycles
    set 0,d                                                           ; 8380: cb c2       ..  8 cycles
    set 0,e                                                           ; 8382: cb c3       ..  8 cycles
    set 0,h                                                           ; 8384: cb c4       ..  8 cycles
    set 0,l                                                           ; 8386: cb c5       ..  8 cycles
    set 0,a                                                           ; 8388: cb c7       ..  8 cycles
    set 0,(hl)                                                        ; 838a: cb c6       ..  15 cycles
    set 0,(ix+0)                                                      ; 838c: dd cb 00... ... 23 cycles
    set 0,(iy-1)                                                      ; 8390: fd cb ff... ... 23 cycles
    set 1,b                                                           ; 8394: cb c8       ..  8 cycles
    set 1,c                                                           ; 8396: cb c9       ..  8 cycles
    set 1,d                                                           ; 8398: cb ca       ..  8 cycles
    set 1,e                                                           ; 839a: cb cb       ..  8 cycles
    set 1,h                                                           ; 839c: cb cc       ..  8 cycles
    set 1,l                                                           ; 839e: cb cd       ..  8 cycles
    set 1,a                                                           ; 83a0: cb cf       ..  8 cycles
    set 1,(hl)                                                        ; 83a2: cb ce       ..  15 cycles
    set 1,(ix+1)                                                      ; 83a4: dd cb 01... ... 23 cycles
    set 1,(iy-2)                                                      ; 83a8: fd cb fe... ... 23 cycles
    set 2,b                                                           ; 83ac: cb d0       ..  8 cycles
    set 2,c                                                           ; 83ae: cb d1       ..  8 cycles
    set 2,d                                                           ; 83b0: cb d2       ..  8 cycles
    set 2,e                                                           ; 83b2: cb d3       ..  8 cycles
    set 2,h                                                           ; 83b4: cb d4       ..  8 cycles
    set 2,l                                                           ; 83b6: cb d5       ..  8 cycles
    set 2,a                                                           ; 83b8: cb d7       ..  8 cycles
    set 2,(hl)                                                        ; 83ba: cb d6       ..  15 cycles
    set 2,(ix+2)                                                      ; 83bc: dd cb 02... ... 23 cycles
    set 2,(iy-3)                                                      ; 83c0: fd cb fd... ... 23 cycles
    set 3,b                                                           ; 83c4: cb d8       ..  8 cycles
    set 3,c                                                           ; 83c6: cb d9       ..  8 cycles
    set 3,d                                                           ; 83c8: cb da       ..  8 cycles
    set 3,e                                                           ; 83ca: cb db       ..  8 cycles
    set 3,h                                                           ; 83cc: cb dc       ..  8 cycles
    set 3,l                                                           ; 83ce: cb dd       ..  8 cycles
    set 3,a                                                           ; 83d0: cb df       ..  8 cycles
    set 3,(hl)                                                        ; 83d2: cb de       ..  15 cycles
    set 3,(ix+3)                                                      ; 83d4: dd cb 03... ... 23 cycles
    set 3,(iy-4)                                                      ; 83d8: fd cb fc... ... 23 cycles
    set 4,b                                                           ; 83dc: cb e0       ..  8 cycles
    set 4,c                                                           ; 83de: cb e1       ..  8 cycles
    set 4,d                                                           ; 83e0: cb e2       ..  8 cycles
    set 4,e                                                           ; 83e2: cb e3       ..  8 cycles
    set 4,h                                                           ; 83e4: cb e4       ..  8 cycles
    set 4,l                                                           ; 83e6: cb e5       ..  8 cycles
    set 4,a                                                           ; 83e8: cb e7       ..  8 cycles
    set 4,(hl)                                                        ; 83ea: cb e6       ..  15 cycles
    set 4,(ix+4)                                                      ; 83ec: dd cb 04... ... 23 cycles
    set 4,(iy-5)                                                      ; 83f0: fd cb fb... ... 23 cycles
    set 5,b                                                           ; 83f4: cb e8       ..  8 cycles
    set 5,c                                                           ; 83f6: cb e9       ..  8 cycles
    set 5,d                                                           ; 83f8: cb ea       ..  8 cycles
    set 5,e                                                           ; 83fa: cb eb       ..  8 cycles
    set 5,h                                                           ; 83fc: cb ec       ..  8 cycles
    set 5,l                                                           ; 83fe: cb ed       ..  8 cycles
    set 5,a                                                           ; 8400: cb ef       ..  8 cycles
    set 5,(hl)                                                        ; 8402: cb ee       ..  15 cycles
    set 5,(ix+5)                                                      ; 8404: dd cb 05... ... 23 cycles
    set 5,(iy-6)                                                      ; 8408: fd cb fa... ... 23 cycles
    set 6,b                                                           ; 840c: cb f0       ..  8 cycles
    set 6,c                                                           ; 840e: cb f1       ..  8 cycles
    set 6,d                                                           ; 8410: cb f2       ..  8 cycles
    set 6,e                                                           ; 8412: cb f3       ..  8 cycles
    set 6,h                                                           ; 8414: cb f4       ..  8 cycles
    set 6,l                                                           ; 8416: cb f5       ..  8 cycles
    set 6,a                                                           ; 8418: cb f7       ..  8 cycles
    set 6,(hl)                                                        ; 841a: cb f6       ..  15 cycles
    set 6,(ix+6)                                                      ; 841c: dd cb 06... ... 23 cycles
    set 6,(iy-7)                                                      ; 8420: fd cb f9... ... 23 cycles
    set 7,b                                                           ; 8424: cb f8       ..  8 cycles
    set 7,c                                                           ; 8426: cb f9       ..  8 cycles
    set 7,d                                                           ; 8428: cb fa       ..  8 cycles
    set 7,e                                                           ; 842a: cb fb       ..  8 cycles
    set 7,h                                                           ; 842c: cb fc       ..  8 cycles
    set 7,l                                                           ; 842e: cb fd       ..  8 cycles
    set 7,a                                                           ; 8430: cb ff       ..  8 cycles
    set 7,(hl)                                                        ; 8432: cb fe       ..  15 cycles
    set 7,(ix+7)                                                      ; 8434: dd cb 07... ... 23 cycles
    set 7,(iy-8)                                                      ; 8438: fd cb f8... ... 23 cycles
    res 0,b                                                           ; 843c: cb 80       ..  8 cycles
    res 0,c                                                           ; 843e: cb 81       ..  8 cycles
    res 0,d                                                           ; 8440: cb 82       ..  8 cycles
    res 0,e                                                           ; 8442: cb 83       ..  8 cycles
    res 0,h                                                           ; 8444: cb 84       ..  8 cycles
    res 0,l                                                           ; 8446: cb 85       ..  8 cycles
    res 0,a                                                           ; 8448: cb 87       ..  8 cycles
    res 0,(hl)                                                        ; 844a: cb 86       ..  15 cycles
    res 0,(ix+0)                                                      ; 844c: dd cb 00... ... 23 cycles
    res 0,(iy-1)                                                      ; 8450: fd cb ff... ... 23 cycles
    res 1,b                                                           ; 8454: cb 88       ..  8 cycles
    res 1,c                                                           ; 8456: cb 89       ..  8 cycles
    res 1,d                                                           ; 8458: cb 8a       ..  8 cycles
    res 1,e                                                           ; 845a: cb 8b       ..  8 cycles
    res 1,h                                                           ; 845c: cb 8c       ..  8 cycles
    res 1,l                                                           ; 845e: cb 8d       ..  8 cycles
    res 1,a                                                           ; 8460: cb 8f       ..  8 cycles
    res 1,(hl)                                                        ; 8462: cb 8e       ..  15 cycles
    res 1,(ix+1)                                                      ; 8464: dd cb 01... ... 23 cycles
    res 1,(iy-2)                                                      ; 8468: fd cb fe... ... 23 cycles
    res 2,b                                                           ; 846c: cb 90       ..  8 cycles
    res 2,c                                                           ; 846e: cb 91       ..  8 cycles
    res 2,d                                                           ; 8470: cb 92       ..  8 cycles
    res 2,e                                                           ; 8472: cb 93       ..  8 cycles
    res 2,h                                                           ; 8474: cb 94       ..  8 cycles
    res 2,l                                                           ; 8476: cb 95       ..  8 cycles
    res 2,a                                                           ; 8478: cb 97       ..  8 cycles
    res 2,(hl)                                                        ; 847a: cb 96       ..  15 cycles
    res 2,(ix+2)                                                      ; 847c: dd cb 02... ... 23 cycles
    res 2,(iy-3)                                                      ; 8480: fd cb fd... ... 23 cycles
    res 3,b                                                           ; 8484: cb 98       ..  8 cycles
    res 3,c                                                           ; 8486: cb 99       ..  8 cycles
    res 3,d                                                           ; 8488: cb 9a       ..  8 cycles
    res 3,e                                                           ; 848a: cb 9b       ..  8 cycles
    res 3,h                                                           ; 848c: cb 9c       ..  8 cycles
    res 3,l                                                           ; 848e: cb 9d       ..  8 cycles
    res 3,a                                                           ; 8490: cb 9f       ..  8 cycles
    res 3,(hl)                                                        ; 8492: cb 9e       ..  15 cycles
    res 3,(ix+3)                                                      ; 8494: dd cb 03... ... 23 cycles
    res 3,(iy-4)                                                      ; 8498: fd cb fc... ... 23 cycles
    res 4,b                                                           ; 849c: cb a0       ..  8 cycles
    res 4,c                                                           ; 849e: cb a1       ..  8 cycles
    res 4,d                                                           ; 84a0: cb a2       ..  8 cycles
    res 4,e                                                           ; 84a2: cb a3       ..  8 cycles
    res 4,h                                                           ; 84a4: cb a4       ..  8 cycles
    res 4,l                                                           ; 84a6: cb a5       ..  8 cycles
    res 4,a                                                           ; 84a8: cb a7       ..  8 cycles
    res 4,(hl)                                                        ; 84aa: cb a6       ..  15 cycles
    res 4,(ix+4)                                                      ; 84ac: dd cb 04... ... 23 cycles
    res 4,(iy-5)                                                      ; 84b0: fd cb fb... ... 23 cycles
    res 5,b                                                           ; 84b4: cb a8       ..  8 cycles
    res 5,c                                                           ; 84b6: cb a9       ..  8 cycles
    res 5,d                                                           ; 84b8: cb aa       ..  8 cycles
    res 5,e                                                           ; 84ba: cb ab       ..  8 cycles
    res 5,h                                                           ; 84bc: cb ac       ..  8 cycles
    res 5,l                                                           ; 84be: cb ad       ..  8 cycles
    res 5,a                                                           ; 84c0: cb af       ..  8 cycles
    res 5,(hl)                                                        ; 84c2: cb ae       ..  15 cycles
    res 5,(ix+5)                                                      ; 84c4: dd cb 05... ... 23 cycles
    res 5,(iy-6)                                                      ; 84c8: fd cb fa... ... 23 cycles
    res 6,b                                                           ; 84cc: cb b0       ..  8 cycles
    res 6,c                                                           ; 84ce: cb b1       ..  8 cycles
    res 6,d                                                           ; 84d0: cb b2       ..  8 cycles
    res 6,e                                                           ; 84d2: cb b3       ..  8 cycles
    res 6,h                                                           ; 84d4: cb b4       ..  8 cycles
    res 6,l                                                           ; 84d6: cb b5       ..  8 cycles
    res 6,a                                                           ; 84d8: cb b7       ..  8 cycles
    res 6,(hl)                                                        ; 84da: cb b6       ..  15 cycles
    res 6,(ix+6)                                                      ; 84dc: dd cb 06... ... 23 cycles
    res 6,(iy-7)                                                      ; 84e0: fd cb f9... ... 23 cycles
    res 7,b                                                           ; 84e4: cb b8       ..  8 cycles
    res 7,c                                                           ; 84e6: cb b9       ..  8 cycles
    res 7,d                                                           ; 84e8: cb ba       ..  8 cycles
    res 7,e                                                           ; 84ea: cb bb       ..  8 cycles
    res 7,h                                                           ; 84ec: cb bc       ..  8 cycles
    res 7,l                                                           ; 84ee: cb bd       ..  8 cycles
    res 7,a                                                           ; 84f0: cb bf       ..  8 cycles
    res 7,(hl)                                                        ; 84f2: cb be       ..  15 cycles
    res 7,(ix+7)                                                      ; 84f4: dd cb 07... ... 23 cycles
    res 7,(iy-8)                                                      ; 84f8: fd cb f8... ... 23 cycles
    in a,($fe)                                                        ; 84fc: db fe       ..  11 cycles
    out ($fe),a                                                       ; 84fe: d3 fe       ..  11 cycles
    in b,(c)                                                          ; 8500: ed 40       .@  12 cycles
    in c,(c)                                                          ; 8502: ed 48       .H  12 cycles
    in d,(c)                                                          ; 8504: ed 50       .P  12 cycles
    in e,(c)                                                          ; 8506: ed 58       .X  12 cycles
    in h,(c)                                                          ; 8508: ed 60       .`  12 cycles
    in l,(c)                                                          ; 850a: ed 68       .h  12 cycles
    in a,(c)                                                          ; 850c: ed 78       .x  12 cycles
    out (c),b                                                         ; 850e: ed 41       .A  12 cycles
    out (c),c                                                         ; 8510: ed 49       .I  12 cycles
    out (c),d                                                         ; 8512: ed 51       .Q  12 cycles
    out (c),e                                                         ; 8514: ed 59       .Y  12 cycles
    out (c),h                                                         ; 8516: ed 61       .a  12 cycles
    out (c),l                                                         ; 8518: ed 69       .i  12 cycles
    out (c),a                                                         ; 851a: ed 79       .y  12 cycles
    ini                                                               ; 851c: ed a2       ..  16 cycles
    inir                                                              ; 851e: ed b2       ..  16/21 cycles
    ind                                                               ; 8520: ed aa       ..  16 cycles
    indr                                                              ; 8522: ed ba       ..  16/21 cycles
    outi                                                              ; 8524: ed a3       ..  16 cycles
    otir                                                              ; 8526: ed b3       ..  16/21 cycles
    outd                                                              ; 8528: ed ab       ..  16 cycles
    otdr                                                              ; 852a: ed bb       ..  16/21 cycles
; $852c referenced 13 times by $852c, $852f, $8532, $8535, $8538, $853b, $853e, $8541, $8544, $8546, $8548, $854a, $854c
loop:
    jp nz,loop                                                        ; 852c: c2 2c 85    .,. 10 cycles
    jp z,loop                                                         ; 852f: ca 2c 85    .,. 10 cycles
    jp nc,loop                                                        ; 8532: d2 2c 85    .,. 10 cycles
    jp c,loop                                                         ; 8535: da 2c 85    .,. 10 cycles
    jp po,loop                                                        ; 8538: e2 2c 85    .,. 10 cycles
    jp pe,loop                                                        ; 853b: ea 2c 85    .,. 10 cycles
    jp p,loop                                                         ; 853e: f2 2c 85    .,. 10 cycles
    jp m,loop                                                         ; 8541: fa 2c 85    .,. 10 cycles
    jr nz,loop                                                        ; 8544: 20 e6        .  7/12 cycles
    jr z,loop                                                         ; 8546: 28 e4       (.  7/12 cycles
    jr nc,loop                                                        ; 8548: 30 e2       0.  7/12 cycles
    jr c,loop                                                         ; 854a: 38 e0       8.  7/12 cycles
    djnz loop                                                         ; 854c: 10 de       ..  8/13 cycles
    call nz,subroutine                                                ; 854e: c4 77 85    .w. 10/17 cycles
    call z,subroutine                                                 ; 8551: cc 77 85    .w. 10/17 cycles
    call nc,subroutine                                                ; 8554: d4 77 85    .w. 10/17 cycles
    call c,subroutine                                                 ; 8557: dc 77 85    .w. 10/17 cycles
    call po,subroutine                                                ; 855a: e4 77 85    .w. 10/17 cycles
    call pe,subroutine                                                ; 855d: ec 77 85    .w. 10/17 cycles
    call p,subroutine                                                 ; 8560: f4 77 85    .w. 10/17 cycles
    call m,subroutine                                                 ; 8563: fc 77 85    .w. 10/17 cycles
    call subroutine                                                   ; 8566: cd 77 85    .w. 17 cycles
    rst $00                                                           ; 8569: c7          .   11 cycles
    rst $08                                                           ; 856a: cf          .   11 cycles
    rst $10                                                           ; 856b: d7          .   11 cycles
    rst $18                                                           ; 856c: df          .   11 cycles
    rst $20                                                           ; 856d: e7          .   11 cycles
    rst $28                                                           ; 856e: ef          .   11 cycles
    rst $30                                                           ; 856f: f7          .   11 cycles
    rst $38                                                           ; 8570: ff          .   11 cycles
    jr c8574                                                          ; 8571: 18 01       ..  12 cycles

    db $ff                                                            ; 8573: ff          .

; $8574 referenced 1 time by $8571
c8574:
    jp finish                                                         ; 8574: c3 84 85    ... 10 cycles

; $8577 referenced 9 times by $854e, $8551, $8554, $8557, $855a, $855d, $8560, $8563, $8566
subroutine:
    ret nz                                                            ; 8577: c0          .   5/11 cycles
    ret z                                                             ; 8578: c8          .   5/11 cycles
    ret nc                                                            ; 8579: d0          .   5/11 cycles
    ret c                                                             ; 857a: d8          .   5/11 cycles
    ret po                                                            ; 857b: e0          .   5/11 cycles
    ret pe                                                            ; 857c: e8          .   5/11 cycles
    ret p                                                             ; 857d: f0          .   5/11 cycles
    ret m                                                             ; 857e: f8          .   5/11 cycles
    ret                                                               ; 857f: c9          .   10 cycles

interrupt:
    reti                                                              ; 8580: ed 4d       .M  14 cycles

nmi:
    retn                                                              ; 8582: ed 45       .E  14 cycles

; $8584 referenced 1 time by $8574
finish:
    jp (hl)                                                           ; 8584: e9          .   4 cycles

jump_ix:
    jp (ix)                                                           ; 8585: dd e9       ..  8 cycles

jump_iy:
    jp (iy)                                                           ; 8587: fd e9       ..  8 cycles

; $8589 referenced 2 times by $80ad, $80b2
value:
    db $42                                                            ; 8589: 42          B
; $858a referenced 12 times by $80d1, $80d4, $80d8, $80dc, $80e0, $80e4, $80e8, $80eb, $80ef, $80f3, $80f7, $80fb
word:
    dw $1234                                                          ; 858a: 34 12       4.
table:
    db 1, 2, 3, 4                                                     ; 858c: 01 02 03... ...
pydis_end:


; Label references by decreasing frequency:
;     loop:        13
;     word:        12
;     subroutine:   9
;     value:        2
;     c8574:        1
;     finish:       1

; Automatically generated labels:
;     c8574

; Stats:
;
;     Total size (Code + Data) = 1424 bytes
;     Code                     = 1416 bytes (99%)
;     Data                     = 8 bytes (1%)
;
;     Number of instructions   = 696
;     Number of data bytes     = 6 bytes
;     Number of data words     = 2 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

