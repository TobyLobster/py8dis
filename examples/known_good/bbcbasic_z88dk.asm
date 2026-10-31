; Memory locations
warm_boot   equ $00
bdos        equ $05
l0006       equ $06
l005c       equ $5c

    org $0100

pydis_start:
start:
    jp cold                                                           ; 0100: c3 2a 01    .*.

    jp warm                                                           ; 0103: c3 98 01    ...

    jp escape                                                         ; 0106: c3 ec 0e    ...

    jp exterr                                                         ; 0109: c3 1a 08    ...

    jp tell                                                           ; 010c: c3 55 0d    .U.

    jp text                                                           ; 010f: c3 4c 0d    .L.

    jp settop                                                         ; 0112: c3 d2 08    ...

    jp clear                                                          ; 0115: c3 f6 08    ...

    jp run0                                                           ; 0118: c3 e1 0d    ...

    jp oscli                                                          ; 011b: c3 71 37    .q7

    jp osbget                                                         ; 011e: c3 34 35    .45

    jp osbput                                                         ; 0121: c3 17 35    ..5

    jp osstat                                                         ; 0124: c3 4e 35    .N5

    jp osshut                                                         ; 0127: c3 26 34    .&4

; $012a referenced 1 time by $0100
cold:
    ld hl,$3f00                                                       ; 012a: 21 00 3f    !.?
    ld sp,hl                                                          ; 012d: f9          .
    ld (hl),$0a                                                       ; 012e: 36 0a       6.
    inc l                                                             ; 0130: 2c          ,
    ld (hl),9                                                         ; 0131: 36 09       6.
    inc l                                                             ; 0133: 2c          ,
    xor a                                                             ; 0134: af          .
; $0135 referenced 1 time by $0137
purge:
    ld (hl),a                                                         ; 0135: 77          w
    inc l                                                             ; 0136: 2c          ,
    jr nz,purge                                                       ; 0137: 20 fc        .
    ld a,$37                                                          ; 0139: 3e 37       >7
    ld (liston),a                                                     ; 013b: 32 fe 3f    2.?
    ld hl,$0177                                                       ; 013e: 21 77 01    !w.
    ld (errtxt),hl                                                    ; 0141: 22 ee 3f    ".?
    call osinit                                                       ; 0144: cd 9c 39    ..9
    ld (himem),de                                                     ; 0147: ed 53 e4... .S.
    ld (page),hl                                                      ; 014b: 22 dc 3f    ".?
    call newit                                                        ; 014e: cd ee 08    ...
    jp nz,chain0                                                      ; 0151: c2 da 0d    ...
    call tell                                                         ; 0154: cd 55 0d    .U.
l0157:
notice equ l0157+32
    db "BBC BASIC (Z80) Version 3.00  ", $0d, $0a, "(C) Copyright R." ; 0157: 42 42 43... BBC
    db "T.Russell 1987", $0d, $0a, 0                                  ; 0187: 54 2e 52... T.R

; $0198 referenced 5 times by $0103, $06b6, $073b, $0802, $0e47
warm:
cloop equ warm+1
    or $37                                                            ; 0198: f6 37       .7
; overlapping: scf                                                    ; 0199: 37          7
; $0199 referenced 9 times by $0217, $0254, $0667, $06bd, $0700, $07d6, $0856, $0e3f, $14e9
    ld sp,(himem)                                                     ; 019a: ed 7b e4... .{.
    call prompt                                                       ; 019e: cd 7f 3a    ..:
    ld hl,$3ffe                                                       ; 01a1: 21 fe 3f    !.?
    ld a,(hl)                                                         ; 01a4: 7e          ~
    and $0f                                                           ; 01a5: e6 0f       ..
    or $30                                                            ; 01a7: f6 30       .0
    ld (hl),a                                                         ; 01a9: 77          w
    sbc hl,hl                                                         ; 01aa: ed 62       .b
    ld (errtrp),hl                                                    ; 01ac: 22 ec 3f    ".?
    ld (errlin),hl                                                    ; 01af: 22 f4 3f    ".?
    ld hl,(autono)                                                    ; 01b2: 2a ea 3f    *.?
    ld (lineno),hl                                                    ; 01b5: 22 e6 3f    ".?
    ld a,h                                                            ; 01b8: 7c          |
    or l                                                              ; 01b9: b5          .
    jr z,noauto                                                       ; 01ba: 28 17       (.
    push hl                                                           ; 01bc: e5          .
    call pbcd                                                         ; 01bd: cd 2f 0a    ./.
    pop hl                                                            ; 01c0: e1          .
    ld bc,(increm)                                                    ; 01c1: ed 4b ff... .K.
    ld b,0                                                            ; 01c5: 06 00       ..
    add hl,bc                                                         ; 01c7: 09          .
    jp c,toobig                                                       ; 01c8: da 10 0c    ...
    ld (autono),hl                                                    ; 01cb: 22 ea 3f    ".?
    ld a,$20                                                          ; 01ce: 3e 20       >
    call outchr                                                       ; 01d0: cd 9e 09    ...
; $01d3 referenced 1 time by $01ba
noauto:
    ld hl,$3d00                                                       ; 01d3: 21 00 3d    !.=
    call osline                                                       ; 01d6: cd b7 3a    ..:
    xor a                                                             ; 01d9: af          .
    ld (count),a                                                      ; 01da: 32 fb 3f    2.?
    ld iy,$3d00                                                       ; 01dd: fd 21 00... .!.
    call linnum                                                       ; 01e1: cd eb 0b    ...
    call nxt                                                          ; 01e4: cd a2 25    ..%
    ld a,h                                                            ; 01e7: 7c          |
    or l                                                              ; 01e8: b5          .
    jr z,lnzero                                                       ; 01e9: 28 03       (.
    ld (lineno),hl                                                    ; 01eb: 22 e6 3f    ".?
; $01ee referenced 1 time by $01e9
lnzero:
    ld de,$3e00                                                       ; 01ee: 11 00 3e    ..>
    ld c,1                                                            ; 01f1: 0e 01       ..
    call lexan2                                                       ; 01f3: cd 7f 0c    ...
    ld (de),a                                                         ; 01f6: 12          .
    xor a                                                             ; 01f7: af          .
    ld b,a                                                            ; 01f8: 47          G
    ld c,e                                                            ; 01f9: 4b          K
    inc de                                                            ; 01fa: 13          .
    ld (de),a                                                         ; 01fb: 12          .
    ld hl,(lineno)                                                    ; 01fc: 2a e6 3f    *.?
    ld a,h                                                            ; 01ff: 7c          |
    or l                                                              ; 0200: b5          .
    ld iy,$3e00                                                       ; 0201: fd 21 00... .!.
    jp z,xeq_exec                                                     ; 0205: ca 12 0e    ...
    push bc                                                           ; 0208: c5          .
    push hl                                                           ; 0209: e5          .
    call settop                                                       ; 020a: cd d2 08    ...
    pop hl                                                            ; 020d: e1          .
    call findl                                                        ; 020e: cd d5 09    ...
    call z,del                                                        ; 0211: cc 92 08    ...
    pop bc                                                            ; 0214: c1          .
    ld a,c                                                            ; 0215: 79          y
    or a                                                              ; 0216: b7          .
    jp z,cloop                                                        ; 0217: ca 99 01    ...
    add a,4                                                           ; 021a: c6 04       ..
    ld c,a                                                            ; 021c: 4f          O
    push de                                                           ; 021d: d5          .
    push bc                                                           ; 021e: c5          .
    ex de,hl                                                          ; 021f: eb          .
    ld hl,(top)                                                       ; 0220: 2a de 3f    *.?
    push hl                                                           ; 0223: e5          .
    add hl,bc                                                         ; 0224: 09          .
    push hl                                                           ; 0225: e5          .
    inc h                                                             ; 0226: 24          $
    xor a                                                             ; 0227: af          .
    sbc hl,sp                                                         ; 0228: ed 72       .r
    pop hl                                                            ; 022a: e1          .
    jp nc,error_main                                                  ; 022b: d2 05 08    ...
    ld (top),hl                                                       ; 022e: 22 de 3f    ".?
    ex (sp),hl                                                        ; 0231: e3          .
    push hl                                                           ; 0232: e5          .
    inc hl                                                            ; 0233: 23          #
    or a                                                              ; 0234: b7          .
    sbc hl,de                                                         ; 0235: ed 52       .R
    ld b,h                                                            ; 0237: 44          D
    ld c,l                                                            ; 0238: 4d          M
    pop hl                                                            ; 0239: e1          .
    pop de                                                            ; 023a: d1          .
    jr z,atend                                                        ; 023b: 28 02       (.
    lddr                                                              ; 023d: ed b8       ..
; $023f referenced 1 time by $023b
atend:
    pop bc                                                            ; 023f: c1          .
    pop de                                                            ; 0240: d1          .
    inc hl                                                            ; 0241: 23          #
    ld (hl),c                                                         ; 0242: 71          q
    inc hl                                                            ; 0243: 23          #
    ld (hl),e                                                         ; 0244: 73          s
    inc hl                                                            ; 0245: 23          #
    ld (hl),d                                                         ; 0246: 72          r
    inc hl                                                            ; 0247: 23          #
    ld de,$3e00                                                       ; 0248: 11 00 3e    ..>
    ex de,hl                                                          ; 024b: eb          .
    dec c                                                             ; 024c: 0d          .
    dec c                                                             ; 024d: 0d          .
    dec c                                                             ; 024e: 0d          .
    ldir                                                              ; 024f: ed b0       ..
    call clean                                                        ; 0251: cd c7 08    ...
    jp cloop                                                          ; 0254: c3 99 01    ...

keywds:
    db $80                                                            ; 0257: 80          .
    db "AND"                                                          ; 0258: 41 4e 44    AND
    db $94                                                            ; 025b: 94          .
    db "ABS"                                                          ; 025c: 41 42 53    ABS
    db $95                                                            ; 025f: 95          .
    db "ACS"                                                          ; 0260: 41 43 53    ACS
    db $96                                                            ; 0263: 96          .
    db "ADVAL"                                                        ; 0264: 41 44 56... ADV
    db $97                                                            ; 0269: 97          .
    db "ASC"                                                          ; 026a: 41 53 43    ASC
    db $98                                                            ; 026d: 98          .
    db "ASN"                                                          ; 026e: 41 53 4e    ASN
    db $99                                                            ; 0271: 99          .
    db "ATN"                                                          ; 0272: 41 54 4e    ATN
    db $c6                                                            ; 0275: c6          .
    db "AUTO"                                                         ; 0276: 41 55 54... AUT
    db $9a                                                            ; 027a: 9a          .
    db "BGET"                                                         ; 027b: 42 47 45... BGE
    db 0, $d5                                                         ; 027f: 00 d5       ..
    db "BPUT"                                                         ; 0281: 42 50 55... BPU
    db 0, $fb                                                         ; 0285: 00 fb       ..
    db "COLOUR"                                                       ; 0287: 43 4f 4c... COL
    db $fb                                                            ; 028d: fb          .
    db "COLOR"                                                        ; 028e: 43 4f 4c... COL
    db $d6                                                            ; 0293: d6          .
    db "CALL"                                                         ; 0294: 43 41 4c... CAL
    db $d7                                                            ; 0298: d7          .
    db "CHAIN"                                                        ; 0299: 43 48 41... CHA
    db $bd                                                            ; 029e: bd          .
    db "CHR$"                                                         ; 029f: 43 48 52... CHR
    db $d8                                                            ; 02a3: d8          .
    db "CLEAR"                                                        ; 02a4: 43 4c 45... CLE
    db 0, $d9                                                         ; 02a9: 00 d9       ..
    db "CLOSE"                                                        ; 02ab: 43 4c 4f... CLO
    db 0, $da                                                         ; 02b0: 00 da       ..
    db "CLG"                                                          ; 02b2: 43 4c 47    CLG
    db 0, $db                                                         ; 02b5: 00 db       ..
    db "CLS"                                                          ; 02b7: 43 4c 53    CLS
    db 0, $9b                                                         ; 02ba: 00 9b       ..
    db "COS"                                                          ; 02bc: 43 4f 53    COS
    db $9c                                                            ; 02bf: 9c          .
    db "COUNT"                                                        ; 02c0: 43 4f 55... COU
    db 0, $dc                                                         ; 02c5: 00 dc       ..
    db "DATA"                                                         ; 02c7: 44 41 54... DAT
    db $9d                                                            ; 02cb: 9d          .
    db "DEG"                                                          ; 02cc: 44 45 47    DEG
    db $dd                                                            ; 02cf: dd          .
    db "DEF"                                                          ; 02d0: 44 45 46    DEF
    db $c7                                                            ; 02d3: c7          .
    db "DELETE"                                                       ; 02d4: 44 45 4c... DEL
    db $81                                                            ; 02da: 81          .
    db "DIV"                                                          ; 02db: 44 49 56    DIV
    db $de                                                            ; 02de: de          .
    db "DIM"                                                          ; 02df: 44 49 4d    DIM
    db $df                                                            ; 02e2: df          .
    db "DRAW"                                                         ; 02e3: 44 52 41... DRA
    db $e1                                                            ; 02e7: e1          .
    db "ENDPROC"                                                      ; 02e8: 45 4e 44... END
    db 0, $e0                                                         ; 02ef: 00 e0       ..
    db "END"                                                          ; 02f1: 45 4e 44    END
    db 0, $e2                                                         ; 02f4: 00 e2       ..
    db "ENVELOPE"                                                     ; 02f6: 45 4e 56... ENV
    db $8b                                                            ; 02fe: 8b          .
    db "ELSE"                                                         ; 02ff: 45 4c 53... ELS
    db $a0                                                            ; 0303: a0          .
    db "EVAL"                                                         ; 0304: 45 56 41... EVA
    db $9e                                                            ; 0308: 9e          .
    db "ERL"                                                          ; 0309: 45 52 4c    ERL
    db 0, $85                                                         ; 030c: 00 85       ..
    db "ERROR"                                                        ; 030e: 45 52 52... ERR
    db $c5                                                            ; 0313: c5          .
    db "EOF"                                                          ; 0314: 45 4f 46    EOF
    db 0, $82                                                         ; 0317: 00 82       ..
    db "EOR"                                                          ; 0319: 45 4f 52    EOR
    db $9f                                                            ; 031c: 9f          .
    db "ERR"                                                          ; 031d: 45 52 52    ERR
    db 0, $a1                                                         ; 0320: 00 a1       ..
    db "EXP"                                                          ; 0322: 45 58 50    EXP
    db $a2                                                            ; 0325: a2          .
    db "EXT"                                                          ; 0326: 45 58 54    EXT
    db 0, $e3                                                         ; 0329: 00 e3       ..
    db "FOR"                                                          ; 032b: 46 4f 52    FOR
    db $a3                                                            ; 032e: a3          .
    db "FALSE"                                                        ; 032f: 46 41 4c... FAL
    db 0, $a4, $46, $4e, $e5                                          ; 0334: 00 a4 46... ..F
    db "GOTO"                                                         ; 0339: 47 4f 54... GOT
    db $be                                                            ; 033d: be          .
    db "GET$"                                                         ; 033e: 47 45 54... GET
    db $a5                                                            ; 0342: a5          .
    db "GET"                                                          ; 0343: 47 45 54    GET
    db $e4                                                            ; 0346: e4          .
    db "GOSUB"                                                        ; 0347: 47 4f 53... GOS
    db $e6                                                            ; 034c: e6          .
    db "GCOL"                                                         ; 034d: 47 43 4f... GCO
    db $93                                                            ; 0351: 93          .
    db "HIMEM"                                                        ; 0352: 48 49 4d... HIM
    db 0, $e8                                                         ; 0357: 00 e8       ..
    db "INPUT"                                                        ; 0359: 49 4e 50... INP
    db $e7, $49, $46, $bf                                             ; 035e: e7 49 46... .IF
    db "INKEY$"                                                       ; 0362: 49 4e 4b... INK
    db $a6                                                            ; 0368: a6          .
    db "INKEY"                                                        ; 0369: 49 4e 4b... INK
    db $a8                                                            ; 036e: a8          .
    db "INT"                                                          ; 036f: 49 4e 54    INT
    db $a7                                                            ; 0372: a7          .
    db "INSTR("                                                       ; 0373: 49 4e 53... INS
    db $c9                                                            ; 0379: c9          .
    db "LIST"                                                         ; 037a: 4c 49 53... LIS
    db $86                                                            ; 037e: 86          .
    db "LINE"                                                         ; 037f: 4c 49 4e... LIN
    db $c8                                                            ; 0383: c8          .
    db "LOAD"                                                         ; 0384: 4c 4f 41... LOA
    db $92                                                            ; 0388: 92          .
    db "LOMEM"                                                        ; 0389: 4c 4f 4d... LOM
    db 0, $ea                                                         ; 038e: 00 ea       ..
    db "LOCAL"                                                        ; 0390: 4c 4f 43... LOC
    db $c0                                                            ; 0395: c0          .
    db "LEFT$("                                                       ; 0396: 4c 45 46... LEF
    db $a9                                                            ; 039c: a9          .
    db "LEN"                                                          ; 039d: 4c 45 4e    LEN
    db $e9                                                            ; 03a0: e9          .
    db "LET"                                                          ; 03a1: 4c 45 54    LET
    db $ab                                                            ; 03a4: ab          .
    db "LOG"                                                          ; 03a5: 4c 4f 47    LOG
    db $aa, $4c, $4e, $c1                                             ; 03a8: aa 4c 4e... .LN
    db "MID$("                                                        ; 03ac: 4d 49 44... MID
    db $eb                                                            ; 03b1: eb          .
    db "MODE"                                                         ; 03b2: 4d 4f 44... MOD
    db $83                                                            ; 03b6: 83          .
    db "MOD"                                                          ; 03b7: 4d 4f 44    MOD
    db $ec                                                            ; 03ba: ec          .
    db "MOVE"                                                         ; 03bb: 4d 4f 56... MOV
    db $ed                                                            ; 03bf: ed          .
    db "NEXT"                                                         ; 03c0: 4e 45 58... NEX
    db $ca                                                            ; 03c4: ca          .
    db "NEW"                                                          ; 03c5: 4e 45 57    NEW
    db 0, $ac                                                         ; 03c8: 00 ac       ..
    db "NOT"                                                          ; 03ca: 4e 4f 54    NOT
    db $cb                                                            ; 03cd: cb          .
    db "OLD"                                                          ; 03ce: 4f 4c 44    OLD
    db 0, $ee, $4f, $4e, $87                                          ; 03d1: 00 ee 4f... ..O
    db "OFF"                                                          ; 03d6: 4f 46 46    OFF
    db $84, $4f, $52, $8e                                             ; 03d9: 84 4f 52... .OR
    db "OPENIN"                                                       ; 03dd: 4f 50 45... OPE
    db $ae                                                            ; 03e3: ae          .
    db "OPENOUT"                                                      ; 03e4: 4f 50 45... OPE
    db $ad                                                            ; 03eb: ad          .
    db "OPENUP"                                                       ; 03ec: 4f 50 45... OPE
    db $ff                                                            ; 03f2: ff          .
    db "OSCLI"                                                        ; 03f3: 4f 53 43... OSC
    db $f1                                                            ; 03f8: f1          .
    db "PRINT"                                                        ; 03f9: 50 52 49... PRI
    db $90                                                            ; 03fe: 90          .
    db "PAGE"                                                         ; 03ff: 50 41 47... PAG
    db 0, $8f                                                         ; 0403: 00 8f       ..
    db "PTR"                                                          ; 0405: 50 54 52    PTR
    db 0, $af, $50, $49, 0, $f0                                       ; 0408: 00 af 50... ..P
    db "PLOT"                                                         ; 040e: 50 4c 4f... PLO
    db $b0                                                            ; 0412: b0          .
    db "POINT("                                                       ; 0413: 50 4f 49... POI
    db $f2                                                            ; 0419: f2          .
    db "PROC"                                                         ; 041a: 50 52 4f... PRO
    db $b1                                                            ; 041e: b1          .
    db "POS"                                                          ; 041f: 50 4f 53    POS
    db 0, $ce                                                         ; 0422: 00 ce       ..
    db "PUT"                                                          ; 0424: 50 55 54    PUT
    db $f8                                                            ; 0427: f8          .
    db "RETURN"                                                       ; 0428: 52 45 54... RET
    db 0, $f5                                                         ; 042e: 00 f5       ..
    db "REPEAT"                                                       ; 0430: 52 45 50... REP
    db $f6                                                            ; 0436: f6          .
    db "REPORT"                                                       ; 0437: 52 45 50... REP
    db 0, $f3                                                         ; 043d: 00 f3       ..
    db "READ"                                                         ; 043f: 52 45 41... REA
    db $f4                                                            ; 0443: f4          .
    db "REM"                                                          ; 0444: 52 45 4d    REM
    db $f9                                                            ; 0447: f9          .
    db "RUN"                                                          ; 0448: 52 55 4e    RUN
    db 0, $b2                                                         ; 044b: 00 b2       ..
    db "RAD"                                                          ; 044d: 52 41 44    RAD
    db $f7                                                            ; 0450: f7          .
    db "RESTORE"                                                      ; 0451: 52 45 53... RES
    db $c2                                                            ; 0458: c2          .
    db "RIGHT$("                                                      ; 0459: 52 49 47... RIG
    db $b3                                                            ; 0460: b3          .
    db "RND"                                                          ; 0461: 52 4e 44    RND
    db 0, $cc                                                         ; 0464: 00 cc       ..
    db "RENUMBER"                                                     ; 0466: 52 45 4e... REN
    db $88                                                            ; 046e: 88          .
    db "STEP"                                                         ; 046f: 53 54 45... STE
    db $cd                                                            ; 0473: cd          .
    db "SAVE"                                                         ; 0474: 53 41 56... SAV
    db $b4                                                            ; 0478: b4          .
    db "SGN"                                                          ; 0479: 53 47 4e    SGN
    db $b5                                                            ; 047c: b5          .
    db "SIN"                                                          ; 047d: 53 49 4e    SIN
    db $b6                                                            ; 0480: b6          .
    db "SQR"                                                          ; 0481: 53 51 52    SQR
    db $89                                                            ; 0484: 89          .
    db "SPC"                                                          ; 0485: 53 50 43    SPC
    db $c3                                                            ; 0488: c3          .
    db "STR$"                                                         ; 0489: 53 54 52... STR
    db $c4                                                            ; 048d: c4          .
    db "STRING$("                                                     ; 048e: 53 54 52... STR
    db $d4                                                            ; 0496: d4          .
    db "SOUND"                                                        ; 0497: 53 4f 55... SOU
    db $fa                                                            ; 049c: fa          .
    db "STOP"                                                         ; 049d: 53 54 4f... STO
    db 0, $b7                                                         ; 04a1: 00 b7       ..
    db "TAN"                                                          ; 04a3: 54 41 4e    TAN
    db $8c                                                            ; 04a6: 8c          .
    db "THEN"                                                         ; 04a7: 54 48 45... THE
    db $b8, $54, $4f, $8a                                             ; 04ab: b8 54 4f... .TO
    db "TAB("                                                         ; 04af: 54 41 42... TAB
    db $fc                                                            ; 04b3: fc          .
    db "TRACE"                                                        ; 04b4: 54 52 41... TRA
    db $91                                                            ; 04b9: 91          .
    db "TIME"                                                         ; 04ba: 54 49 4d... TIM
    db 0, $b9                                                         ; 04be: 00 b9       ..
    db "TRUE"                                                         ; 04c0: 54 52 55... TRU
    db 0, $fd                                                         ; 04c4: 00 fd       ..
    db "UNTIL"                                                        ; 04c6: 55 4e 54... UNT
    db $ba                                                            ; 04cb: ba          .
    db "USR"                                                          ; 04cc: 55 53 52    USR
    db $ef                                                            ; 04cf: ef          .
    db "VDU"                                                          ; 04d0: 56 44 55    VDU
    db $bb                                                            ; 04d3: bb          .
    db "VAL"                                                          ; 04d4: 56 41 4c    VAL
    db $bc                                                            ; 04d7: bc          .
    db "VPOS"                                                         ; 04d8: 56 50 4f... VPO
    db 0, $fe                                                         ; 04dc: 00 fe       ..
    db "WIDTH"                                                        ; 04de: 57 49 44... WID
    db $d3                                                            ; 04e3: d3          .
    db "HIMEM"                                                        ; 04e4: 48 49 4d... HIM
    db $d2                                                            ; 04e9: d2          .
    db "LOMEM"                                                        ; 04ea: 4c 4f 4d... LOM
    db $d0                                                            ; 04ef: d0          .
    db "PAGE"                                                         ; 04f0: 50 41 47... PAG
    db $cf                                                            ; 04f4: cf          .
    db "PTR"                                                          ; 04f5: 50 54 52    PTR
    db $d1                                                            ; 04f8: d1          .
    db "TIME"                                                         ; 04f9: 54 49 4d... TIM
    db 1                                                              ; 04fd: 01          .
    db "Missing "                                                     ; 04fe: 4d 69 73... Mis
    db 2                                                              ; 0506: 02          .
    db "No such "                                                     ; 0507: 4e 6f 20... No
    db 3                                                              ; 050f: 03          .
    db "Bad "                                                         ; 0510: 42 61 64... Bad
    db 4                                                              ; 0514: 04          .
    db " range"                                                       ; 0515: 20 72 61...  ra
    db 5                                                              ; 051b: 05          .
    db "variable"                                                     ; 051c: 76 61 72... var
    db 6                                                              ; 0524: 06          .
    db "Out of"                                                       ; 0525: 4f 75 74... Out
    db 7                                                              ; 052b: 07          .
    db "No "                                                          ; 052c: 4e 6f 20    No
    db 8                                                              ; 052f: 08          .
    db " space"                                                       ; 0530: 20 73 70...  sp
    db $ff, $ff                                                       ; 0536: ff ff       ..
errwds:
    db 7                                                              ; 0538: 07          .
    db "room"                                                         ; 0539: 72 6f 6f... roo
    db 0, 6, 4, 0, 0, 0                                               ; 053d: 00 06 04... ...
    db "Mistake"                                                      ; 0543: 4d 69 73... Mis
    db 0, 1, $2c, 0                                                   ; 054a: 00 01 2c... ..,
    db "Type mismatch"                                                ; 054e: 54 79 70... Typ
    db 0, 7, $a4, 0, 0, 1, $22, 0, 3, $de, 0, $de, 8, 0               ; 055b: 00 07 a4... ...
    db "Not "                                                         ; 0569: 4e 6f 74... Not
    db $ea, 0, 7, $f2, 0                                              ; 056d: ea 00 07... ...
    db "Array"                                                        ; 0572: 41 72 72... Arr
    db 0                                                              ; 0577: 00          .
    db "Subscript"                                                    ; 0578: 53 75 62... Sub
    db 0                                                              ; 0581: 00          .
    db "Syntax error"                                                 ; 0582: 53 79 6e... Syn
    db 0                                                              ; 058e: 00          .
    db "Escape"                                                       ; 058f: 45 73 63... Esc
    db 0                                                              ; 0595: 00          .
    db "Division by zero"                                             ; 0596: 44 69 76... Div
    db 0                                                              ; 05a6: 00          .
    db "String too long"                                              ; 05a7: 53 74 72... Str
    db 0                                                              ; 05b6: 00          .
    db "Too big"                                                      ; 05b7: 54 6f 6f... Too
    db 0                                                              ; 05be: 00          .
    db "-ve root"                                                     ; 05bf: 2d 76 65... -ve
    db 0                                                              ; 05c7: 00          .
    db "Log"                                                          ; 05c8: 4c 6f 67    Log
    db 4, 0                                                           ; 05cb: 04 00       ..
    db "Accuracy lost"                                                ; 05cd: 41 63 63... Acc
    db 0                                                              ; 05da: 00          .
    db "Exp"                                                          ; 05db: 45 78 70    Exp
    db 4, 0, 0, 2, 5, 0, 1, $29, 0, 3                                 ; 05de: 04 00 00... ...
    db "HEX"                                                          ; 05e8: 48 45 58    HEX
    db 0, 2, $a4, $2f, $f2, 0, 3                                      ; 05eb: 00 02 a4... ...
    db "call"                                                         ; 05f2: 63 61 6c... cal
    db 0                                                              ; 05f6: 00          .
    db "Arguments"                                                    ; 05f7: 41 72 67... Arg
    db 0, 7, $e3, 0                                                   ; 0600: 00 07 e3... ...
    db "Can't match "                                                 ; 0604: 43 61 6e... Can
    db $e3, 0, $e3, $20, 5, 0, 0, 7, $b8, 0, 0, 7, $e4, 0, $ee        ; 0610: e3 00 e3... ...
    db " syntax"                                                      ; 061f: 20 73 79...  sy
    db 0, $ee, 4, 0, 2                                                ; 0626: 00 ee 04... ...
    db "line"                                                         ; 062b: 6c 69 6e... lin
    db 0, 6, $20, $dc, 0, 7, $f5, 0, 0, 1, $23, 0                     ; 062f: 00 06 20... ..

delete_main:
    call settop                                                       ; 063b: cd d2 08    ...
    call dlpair                                                       ; 063e: cd 38 0c    .8.
; $0641 referenced 1 time by $065b
delet1:
    ld a,(hl)                                                         ; 0641: 7e          ~
    or a                                                              ; 0642: b7          .
    jr z,warmnc                                                       ; 0643: 28 71       (q
    inc hl                                                            ; 0645: 23          #
    ld e,(hl)                                                         ; 0646: 5e          ^
    inc hl                                                            ; 0647: 23          #
    ld d,(hl)                                                         ; 0648: 56          V
    ld a,d                                                            ; 0649: 7a          z
    or e                                                              ; 064a: b3          .
    jr z,cloop1                                                       ; 064b: 28 1a       (.
    dec hl                                                            ; 064d: 2b          +
    dec hl                                                            ; 064e: 2b          +
    ex de,hl                                                          ; 064f: eb          .
    scf                                                               ; 0650: 37          7
    sbc hl,bc                                                         ; 0651: ed 42       .B
    ex de,hl                                                          ; 0653: eb          .
    jr nc,warmnc                                                      ; 0654: 30 60       0`
    push bc                                                           ; 0656: c5          .
    call del                                                          ; 0657: cd 92 08    ...
    pop bc                                                            ; 065a: c1          .
    jr delet1                                                         ; 065b: 18 e4       ..

; $065d referenced 1 time by $066c
listo:
    inc iy                                                            ; 065d: fd 23       .#
    call expri                                                        ; 065f: cd be 1f    ...
    exx                                                               ; 0662: d9          .
    ld a,l                                                            ; 0663: 7d          }
    ld (liston),a                                                     ; 0664: 32 fe 3f    2.?
; $0667 referenced 1 time by $064b
cloop1:
    jp cloop                                                          ; 0667: c3 99 01    ...

list:
    cp $4f                                                            ; 066a: fe 4f       .O
    jr z,listo                                                        ; 066c: 28 ef       (.
    call dlpair                                                       ; 066e: cd 38 0c    .8.
    call nxt                                                          ; 0671: cd a2 25    ..%
    cp $e7                                                            ; 0674: fe e7       ..
    ld a,0                                                            ; 0676: 3e 00       >.
    jr nz,listb                                                       ; 0678: 20 15        .
    inc iy                                                            ; 067a: fd 23       .#
    call nxt                                                          ; 067c: cd a2 25    ..%
    ex de,hl                                                          ; 067f: eb          .
    push iy                                                           ; 0680: fd e5       ..
    pop hl                                                            ; 0682: e1          .
    ld a,$0d                                                          ; 0683: 3e 0d       >.
    push bc                                                           ; 0685: c5          .
    ld bc,$0100                                                       ; 0686: 01 00 01    ...
    cpir                                                              ; 0689: ed b1       ..
    ld a,c                                                            ; 068b: 79          y
    cpl                                                               ; 068c: 2f          /
    pop bc                                                            ; 068d: c1          .
    ex de,hl                                                          ; 068e: eb          .
; $068f referenced 1 time by $0678
listb:
    ld e,a                                                            ; 068f: 5f          _
    ld a,b                                                            ; 0690: 78          x
    or c                                                              ; 0691: b1          .
    jr nz,lista                                                       ; 0692: 20 01        .
    dec bc                                                            ; 0694: 0b          .
; $0695 referenced 1 time by $0692
lista:
    exx                                                               ; 0695: d9          .
    ld ix,$3ffe                                                       ; 0696: dd 21 fe... .!.
    ld bc,0                                                           ; 069a: 01 00 00    ...
    exx                                                               ; 069d: d9          .
    ld a,$14                                                          ; 069e: 3e 14       >.
; $06a0 referenced 1 time by $06e6
listc:
    push bc                                                           ; 06a0: c5          .
    push de                                                           ; 06a1: d5          .
    push hl                                                           ; 06a2: e5          .
    ex af,af'                                                         ; 06a3: 08          .
    ld a,(hl)                                                         ; 06a4: 7e          ~
    or a                                                              ; 06a5: b7          .
    jr z,warmnc                                                       ; 06a6: 28 0e       (.
    ld a,e                                                            ; 06a8: 7b          {
    inc hl                                                            ; 06a9: 23          #
    ld e,(hl)                                                         ; 06aa: 5e          ^
    inc hl                                                            ; 06ab: 23          #
    ld d,(hl)                                                         ; 06ac: 56          V
    dec hl                                                            ; 06ad: 2b          +
    dec hl                                                            ; 06ae: 2b          +
    push de                                                           ; 06af: d5          .
    ex de,hl                                                          ; 06b0: eb          .
    scf                                                               ; 06b1: 37          7
    sbc hl,bc                                                         ; 06b2: ed 42       .B
    ex de,hl                                                          ; 06b4: eb          .
    pop de                                                            ; 06b5: d1          .
; $06b6 referenced 3 times by $0643, $0654, $06a6
warmnc:
    jp nc,warm                                                        ; 06b6: d2 98 01    ...
    ld c,(hl)                                                         ; 06b9: 4e          N
    ld b,a                                                            ; 06ba: 47          G
    ld a,d                                                            ; 06bb: 7a          z
    or e                                                              ; 06bc: b3          .
    jp z,cloop                                                        ; 06bd: ca 99 01    ...
    inc hl                                                            ; 06c0: 23          #
    inc hl                                                            ; 06c1: 23          #
    inc hl                                                            ; 06c2: 23          #
    dec c                                                             ; 06c3: 0d          .
    dec c                                                             ; 06c4: 0d          .
    dec c                                                             ; 06c5: 0d          .
    dec c                                                             ; 06c6: 0d          .
    push de                                                           ; 06c7: d5          .
    push hl                                                           ; 06c8: e5          .
    xor a                                                             ; 06c9: af          .
    cp b                                                              ; 06ca: b8          .
    push iy                                                           ; 06cb: fd e5       ..
    pop de                                                            ; 06cd: d1          .
    call nz,search_eval                                               ; 06ce: c4 5d 23    .]#
    pop hl                                                            ; 06d1: e1          .
    pop de                                                            ; 06d2: d1          .
    push iy                                                           ; 06d3: fd e5       ..
    call z,listit                                                     ; 06d5: cc 0e 09    ...
    pop iy                                                            ; 06d8: fd e1       ..
    ex af,af'                                                         ; 06da: 08          .
    dec a                                                             ; 06db: 3d          =
    call ltrap                                                        ; 06dc: cd cd 39    ..9
    pop hl                                                            ; 06df: e1          .
    ld e,(hl)                                                         ; 06e0: 5e          ^
    ld d,0                                                            ; 06e1: 16 00       ..
    add hl,de                                                         ; 06e3: 19          .
    pop de                                                            ; 06e4: d1          .
    pop bc                                                            ; 06e5: c1          .
    jr listc                                                          ; 06e6: 18 b8       ..

renum:
    call clear                                                        ; 06e8: cd f6 08    ...
    call pair_main                                                    ; 06eb: cd 15 0c    ...
    exx                                                               ; 06ee: d9          .
    ld hl,(page)                                                      ; 06ef: 2a dc 3f    *.?
    ld de,(lomem)                                                     ; 06f2: ed 5b e0... .[.
; $06f6 referenced 1 time by $0722
renum1:
    ld a,(hl)                                                         ; 06f6: 7e          ~
    or a                                                              ; 06f7: b7          .
    jr z,renum2                                                       ; 06f8: 28 30       (0
    inc hl                                                            ; 06fa: 23          #
    ld c,(hl)                                                         ; 06fb: 4e          N
    inc hl                                                            ; 06fc: 23          #
    ld b,(hl)                                                         ; 06fd: 46          F
    ld a,b                                                            ; 06fe: 78          x
    or c                                                              ; 06ff: b1          .
    jp z,cloop                                                        ; 0700: ca 99 01    ...
    ex de,hl                                                          ; 0703: eb          .
    ld (hl),c                                                         ; 0704: 71          q
    inc hl                                                            ; 0705: 23          #
    ld (hl),b                                                         ; 0706: 70          p
    inc hl                                                            ; 0707: 23          #
    exx                                                               ; 0708: d9          .
    push hl                                                           ; 0709: e5          .
    add hl,bc                                                         ; 070a: 09          .
    jp c,toobig                                                       ; 070b: da 10 0c    ...
    exx                                                               ; 070e: d9          .
    pop bc                                                            ; 070f: c1          .
    ld (hl),c                                                         ; 0710: 71          q
    inc hl                                                            ; 0711: 23          #
    ld (hl),b                                                         ; 0712: 70          p
    inc hl                                                            ; 0713: 23          #
    ex de,hl                                                          ; 0714: eb          .
    dec hl                                                            ; 0715: 2b          +
    dec hl                                                            ; 0716: 2b          +
    xor a                                                             ; 0717: af          .
    ld b,a                                                            ; 0718: 47          G
    ld c,(hl)                                                         ; 0719: 4e          N
    add hl,bc                                                         ; 071a: 09          .
    ex de,hl                                                          ; 071b: eb          .
    push hl                                                           ; 071c: e5          .
    inc h                                                             ; 071d: 24          $
    sbc hl,sp                                                         ; 071e: ed 72       .r
    pop hl                                                            ; 0720: e1          .
    ex de,hl                                                          ; 0721: eb          .
    jr c,renum1                                                       ; 0722: 38 d2       8.
    call exterr                                                       ; 0724: cd 1a 08    ...
    db $cc, 8, 0                                                      ; 0727: cc 08 00    ...

; $072a referenced 1 time by $06f8
renum2:
    ex de,hl                                                          ; 072a: eb          .
    ld (hl),$ff                                                       ; 072b: 36 ff       6.
    inc hl                                                            ; 072d: 23          #
    ld (hl),$ff                                                       ; 072e: 36 ff       6.
    ld de,(lomem)                                                     ; 0730: ed 5b e0... .[.
    exx                                                               ; 0734: d9          .
    ld hl,(page)                                                      ; 0735: 2a dc 3f    *.?
; $0738 referenced 1 time by $075b
renum3:
    ld c,(hl)                                                         ; 0738: 4e          N
    ld a,c                                                            ; 0739: 79          y
    or a                                                              ; 073a: b7          .
    jp z,warm                                                         ; 073b: ca 98 01    ...
    exx                                                               ; 073e: d9          .
    ex de,hl                                                          ; 073f: eb          .
    inc hl                                                            ; 0740: 23          #
    inc hl                                                            ; 0741: 23          #
    ld e,(hl)                                                         ; 0742: 5e          ^
    inc hl                                                            ; 0743: 23          #
    ld d,(hl)                                                         ; 0744: 56          V
    inc hl                                                            ; 0745: 23          #
    push de                                                           ; 0746: d5          .
    ex de,hl                                                          ; 0747: eb          .
    ld (lineno),hl                                                    ; 0748: 22 e6 3f    ".?
    exx                                                               ; 074b: d9          .
    pop de                                                            ; 074c: d1          .
    inc hl                                                            ; 074d: 23          #
    ld (hl),e                                                         ; 074e: 73          s
    inc hl                                                            ; 074f: 23          #
    ld (hl),d                                                         ; 0750: 72          r
    inc hl                                                            ; 0751: 23          #
    dec c                                                             ; 0752: 0d          .
    dec c                                                             ; 0753: 0d          .
    dec c                                                             ; 0754: 0d          .
    ld b,0                                                            ; 0755: 06 00       ..
; $0757 referenced 1 time by $079f
renum7:
    ld a,$8d                                                          ; 0757: 3e 8d       >.
    cpir                                                              ; 0759: ed b1       ..
    jr nz,renum3                                                      ; 075b: 20 db        .
    push bc                                                           ; 075d: c5          .
    push hl                                                           ; 075e: e5          .
    push hl                                                           ; 075f: e5          .
    pop iy                                                            ; 0760: fd e1       ..
    exx                                                               ; 0762: d9          .
    call decode                                                       ; 0763: cd 50 24    .P$
    exx                                                               ; 0766: d9          .
    ld b,h                                                            ; 0767: 44          D
    ld c,l                                                            ; 0768: 4d          M
    ld hl,(lomem)                                                     ; 0769: 2a e0 3f    *.?
; $076c referenced 1 time by $0779
renum4:
    ld e,(hl)                                                         ; 076c: 5e          ^
    inc hl                                                            ; 076d: 23          #
    ld d,(hl)                                                         ; 076e: 56          V
    inc hl                                                            ; 076f: 23          #
    ex de,hl                                                          ; 0770: eb          .
    or a                                                              ; 0771: b7          .
    sbc hl,bc                                                         ; 0772: ed 42       .B
    ex de,hl                                                          ; 0774: eb          .
    ld e,(hl)                                                         ; 0775: 5e          ^
    inc hl                                                            ; 0776: 23          #
    ld d,(hl)                                                         ; 0777: 56          V
    inc hl                                                            ; 0778: 23          #
    jr c,renum4                                                       ; 0779: 38 f1       8.
    ex de,hl                                                          ; 077b: eb          .
    jr z,renum5                                                       ; 077c: 28 19       (.
    call tell                                                         ; 077e: cd 55 0d    .U.
    db "Failed at ", 0                                                ; 0781: 46 61 69... Fai

    ld hl,(lineno)                                                    ; 078c: 2a e6 3f    *.?
    call pbcdl                                                        ; 078f: cd 2b 0a    .+.
    call crlf                                                         ; 0792: cd 97 09    ...
    jr renum6                                                         ; 0795: 18 06       ..

; $0797 referenced 1 time by $077c
renum5:
    pop de                                                            ; 0797: d1          .
    push de                                                           ; 0798: d5          .
    dec de                                                            ; 0799: 1b          .
    call encode                                                       ; 079a: cd 23 0d    .#.
; $079d referenced 1 time by $0795
renum6:
    pop hl                                                            ; 079d: e1          .
    pop bc                                                            ; 079e: c1          .
    jr renum7                                                         ; 079f: 18 b6       ..

auto:
    call pair_main                                                    ; 07a1: cd 15 0c    ...
    ld (autono),hl                                                    ; 07a4: 22 ea 3f    ".?
    ld a,c                                                            ; 07a7: 79          y
    ld (increm),a                                                     ; 07a8: 32 ff 3f    2.?
    jr cloop0                                                         ; 07ab: 18 29       .)

; $07ad referenced 2 times by $07ce, $08e4
bad_main:
    call tell                                                         ; 07ad: cd 55 0d    .U.
    db 3, "program", $0d, $0a, 0                                      ; 07b0: 03 70 72... .pr

new:
    call newit                                                        ; 07bb: cd ee 08    ...
    jr cloop0                                                         ; 07be: 18 16       ..

old:
    ld hl,(page)                                                      ; 07c0: 2a dc 3f    *.?
    push hl                                                           ; 07c3: e5          .
    inc hl                                                            ; 07c4: 23          #
    inc hl                                                            ; 07c5: 23          #
    inc hl                                                            ; 07c6: 23          #
    ld bc,$fc                                                         ; 07c7: 01 fc 00    ...
    ld a,$0d                                                          ; 07ca: 3e 0d       >.
    cpir                                                              ; 07cc: ed b1       ..
    jr nz,bad_main                                                    ; 07ce: 20 dd        .
    ld a,l                                                            ; 07d0: 7d          }
    pop hl                                                            ; 07d1: e1          .
    ld (hl),a                                                         ; 07d2: 77          w
    call clean                                                        ; 07d3: cd c7 08    ...
; $07d6 referenced 2 times by $07ab, $07be
cloop0:
    jp cloop                                                          ; 07d6: c3 99 01    ...

load_main:
    call exprs                                                        ; 07d9: cd c7 1f    ...
    ld a,$0d                                                          ; 07dc: 3e 0d       >.
    ld (de),a                                                         ; 07de: 12          .
    call load0_main                                                   ; 07df: cd ad 08    ...
    call clear                                                        ; 07e2: cd f6 08    ...
    jr warm0                                                          ; 07e5: 18 1b       ..

save_main:
    call settop                                                       ; 07e7: cd d2 08    ...
    call exprs                                                        ; 07ea: cd c7 1f    ...
    ld a,$0d                                                          ; 07ed: 3e 0d       >.
    ld (de),a                                                         ; 07ef: 12          .
    ld de,(page)                                                      ; 07f0: ed 5b dc... .[.
    ld hl,(top)                                                       ; 07f4: 2a de 3f    *.?
    or a                                                              ; 07f7: b7          .
    sbc hl,de                                                         ; 07f8: ed 52       .R
    ld b,h                                                            ; 07fa: 44          D
    ld c,l                                                            ; 07fb: 4d          M
    ld hl,$3d00                                                       ; 07fc: 21 00 3d    !.=
    call ossave                                                       ; 07ff: cd e3 33    ..3
; $0802 referenced 1 time by $07e5
warm0:
    jp warm                                                           ; 0802: c3 98 01    ...

; $0805 referenced 26 times by $022b, $08c4, $0a66, $0c12, $0eee, $0fbd, $1118, $1243, $12f3, $133d, $149f, $1580, $16f3, $174e, $180a, $18e8, $1a97, $1f6b, $1fe5, $2012, $20cd, $2260, $230a, $2435, $24cc, $2570
error_main:
    ld sp,(himem)                                                     ; 0805: ed 7b e4... .{.
    ld hl,$0538                                                       ; 0809: 21 38 05    !8.
    or a                                                              ; 080c: b7          .
    jr z,error1_main                                                  ; 080d: 28 0a       (.
    ld b,a                                                            ; 080f: 47          G
    ex af,af'                                                         ; 0810: 08          .
    xor a                                                             ; 0811: af          .
; $0812 referenced 2 times by $0814, $0816
error0_main:
    cp (hl)                                                           ; 0812: be          .
    inc hl                                                            ; 0813: 23          #
    jr nz,error0_main                                                 ; 0814: 20 fc        .
    djnz error0_main                                                  ; 0816: 10 fa       ..
    ex af,af'                                                         ; 0818: 08          .
; $0819 referenced 1 time by $080d
error1_main:
    push hl                                                           ; 0819: e5          .
; $081a referenced 16 times by $0109, $0724, $0c2f, $0c75, $32ab, $33ef, $3417, $3493, $34db, $35eb, $361a, $3660, $367e, $36cc, $3803, $3824
exterr:
    pop hl                                                            ; 081a: e1          .
    ld (errtxt),hl                                                    ; 081b: 22 ee 3f    ".?
    ld sp,(himem)                                                     ; 081e: ed 7b e4... .{.
    ld (err),a                                                        ; 0822: 32 fd 3f    2.?
    call setlin                                                       ; 0825: cd ee 09    ...
    ld (erl),hl                                                       ; 0828: 22 f2 3f    ".?
    or a                                                              ; 082b: b7          .
    jr z,error2_main                                                  ; 082c: 28 0b       (.
    ld hl,(errtrp)                                                    ; 082e: 2a ec 3f    *.?
    ld a,h                                                            ; 0831: 7c          |
    or l                                                              ; 0832: b5          .
    push hl                                                           ; 0833: e5          .
    pop iy                                                            ; 0834: fd e1       ..
    jp nz,xeq_exec                                                    ; 0836: c2 12 0e    ...
; $0839 referenced 1 time by $082c
error2_main:
    ld hl,0                                                           ; 0839: 21 00 00    !..
    ld (autono),hl                                                    ; 083c: 22 ea 3f    ".?
    ld (tracen),hl                                                    ; 083f: 22 e8 3f    ".?
    call reset                                                        ; 0842: cd ce 38    ..8
    call crlf                                                         ; 0845: cd 97 09    ...
    call report                                                       ; 0848: cd 49 0d    .I.
    call sayln                                                        ; 084b: cd 18 0a    ...
    ld e,0                                                            ; 084e: 1e 00       ..
    call c,osshut                                                     ; 0850: dc 26 34    .&4
    call crlf                                                         ; 0853: cd 97 09    ...
    jp cloop                                                          ; 0856: c3 99 01    ...

; $0859 referenced 2 times by $0cc5, $0ccf
lex:
    ld hl,$0257                                                       ; 0859: 21 57 02    !W.
; $085c referenced 1 time by $086a
lex0:
    ld a,(iy+0)                                                       ; 085c: fd 7e 00    .~.
    ld b,(hl)                                                         ; 085f: 46          F
    inc hl                                                            ; 0860: 23          #
    cp (hl)                                                           ; 0861: be          .
    jr z,lex2                                                         ; 0862: 28 08       (.
    ret c                                                             ; 0864: d8          .
; $0865 referenced 2 times by $0868, $0886
lex1:
    inc hl                                                            ; 0865: 23          #
    bit 7,(hl)                                                        ; 0866: cb 7e       .~
    jr z,lex1                                                         ; 0868: 28 fb       (.
    jr lex0                                                           ; 086a: 18 f0       ..

; $086c referenced 1 time by $0862
lex2:
    push iy                                                           ; 086c: fd e5       ..
; $086e referenced 1 time by $087d
lex3:
    inc hl                                                            ; 086e: 23          #
    bit 7,(hl)                                                        ; 086f: cb 7e       .~
    jr nz,lex6                                                        ; 0871: 20 1b        .
    inc iy                                                            ; 0873: fd 23       .#
    ld a,(iy+0)                                                       ; 0875: fd 7e 00    .~.
    cp $2e                                                            ; 0878: fe 2e       ..
    jr z,lex6                                                         ; 087a: 28 12       (.
    cp (hl)                                                           ; 087c: be          .
    jr z,lex3                                                         ; 087d: 28 ef       (.
    call range1                                                       ; 087f: cd 5c 0c    .\.
    jr c,lex5                                                         ; 0882: 38 04       8.
; $0884 referenced 1 time by $088a
lex4:
    pop iy                                                            ; 0884: fd e1       ..
    jr lex1                                                           ; 0886: 18 dd       ..

; $0888 referenced 1 time by $0882
lex5:
    ld a,(hl)                                                         ; 0888: 7e          ~
    or a                                                              ; 0889: b7          .
    jr nz,lex4                                                        ; 088a: 20 f8        .
    dec iy                                                            ; 088c: fd 2b       .+
; $088e referenced 2 times by $0871, $087a
lex6:
    pop af                                                            ; 088e: f1          .
    xor a                                                             ; 088f: af          .
    ld a,b                                                            ; 0890: 78          x
    ret                                                               ; 0891: c9          .

; $0892 referenced 2 times by $0211, $0657
del:
    push de                                                           ; 0892: d5          .
    push hl                                                           ; 0893: e5          .
    push hl                                                           ; 0894: e5          .
    ld b,0                                                            ; 0895: 06 00       ..
    ld c,(hl)                                                         ; 0897: 4e          N
    add hl,bc                                                         ; 0898: 09          .
    push hl                                                           ; 0899: e5          .
    ex de,hl                                                          ; 089a: eb          .
    ld hl,(top)                                                       ; 089b: 2a de 3f    *.?
    sbc hl,de                                                         ; 089e: ed 52       .R
    ld b,h                                                            ; 08a0: 44          D
    ld c,l                                                            ; 08a1: 4d          M
    pop hl                                                            ; 08a2: e1          .
    pop de                                                            ; 08a3: d1          .
    ldir                                                              ; 08a4: ed b0       ..
    ld (top),de                                                       ; 08a6: ed 53 de... .S.
    pop hl                                                            ; 08aa: e1          .
    pop de                                                            ; 08ab: d1          .
    ret                                                               ; 08ac: c9          .

; $08ad referenced 2 times by $07df, $0dde
load0_main:
    ld de,(page)                                                      ; 08ad: ed 5b dc... .[.
    ld hl,$ff00                                                       ; 08b1: 21 00 ff    !..
    add hl,sp                                                         ; 08b4: 39          9
    sbc hl,de                                                         ; 08b5: ed 52       .R
    ld b,h                                                            ; 08b7: 44          D
    ld c,l                                                            ; 08b8: 4d          M
    ld hl,$3d00                                                       ; 08b9: 21 00 3d    !.=
    call osload                                                       ; 08bc: cd 87 34    ..4
    call nc,newit                                                     ; 08bf: d4 ee 08    ...
    ld a,0                                                            ; 08c2: 3e 00       >.
    jp nc,error_main                                                  ; 08c4: d2 05 08    ...
; $08c7 referenced 2 times by $0251, $07d3
clean:
    call settop                                                       ; 08c7: cd d2 08    ...
    dec hl                                                            ; 08ca: 2b          +
    ld (hl),$ff                                                       ; 08cb: 36 ff       6.
    dec hl                                                            ; 08cd: 2b          +
    ld (hl),$ff                                                       ; 08ce: 36 ff       6.
    jr clear                                                          ; 08d0: 18 24       .$

; $08d2 referenced 5 times by $0112, $020a, $063b, $07e7, $08c7
settop:
    ld hl,(page)                                                      ; 08d2: 2a dc 3f    *.?
    ld b,0                                                            ; 08d5: 06 00       ..
    ld a,$0d                                                          ; 08d7: 3e 0d       >.
; $08d9 referenced 1 time by $08e2
setop1:
    ld c,(hl)                                                         ; 08d9: 4e          N
    inc c                                                             ; 08da: 0c          .
    dec c                                                             ; 08db: 0d          .
    jr z,setop2                                                       ; 08dc: 28 09       (.
    add hl,bc                                                         ; 08de: 09          .
    dec hl                                                            ; 08df: 2b          +
    cp (hl)                                                           ; 08e0: be          .
    inc hl                                                            ; 08e1: 23          #
    jr z,setop1                                                       ; 08e2: 28 f5       (.
    jp bad_main                                                       ; 08e4: c3 ad 07    ...

; $08e7 referenced 2 times by $08dc, $08f3
setop2:
    inc hl                                                            ; 08e7: 23          #
    inc hl                                                            ; 08e8: 23          #
    inc hl                                                            ; 08e9: 23          #
    ld (top),hl                                                       ; 08ea: 22 de 3f    ".?
    ret                                                               ; 08ed: c9          .

; $08ee referenced 3 times by $014e, $07bb, $08bf
newit:
    ld hl,(page)                                                      ; 08ee: 2a dc 3f    *.?
    ld (hl),0                                                         ; 08f1: 36 00       6.
    call setop2                                                       ; 08f3: cd e7 08    ...
; $08f6 referenced 7 times by $0115, $06e8, $07e2, $08d0, $0df7, $14f2, $1563
clear:
    push hl                                                           ; 08f6: e5          .
    ld hl,(top)                                                       ; 08f7: 2a de 3f    *.?
    ld (lomem),hl                                                     ; 08fa: 22 e0 3f    ".?
    ld (free),hl                                                      ; 08fd: 22 e2 3f    ".?
    ld hl,$3f6c                                                       ; 0900: 21 6c 3f    !l?
    push bc                                                           ; 0903: c5          .
    ld b,$70                                                          ; 0904: 06 70       .p
; $0906 referenced 1 time by $0909
clear1:
    ld (hl),0                                                         ; 0906: 36 00       6.
    inc hl                                                            ; 0908: 23          #
    djnz clear1                                                       ; 0909: 10 fb       ..
    pop bc                                                            ; 090b: c1          .
    pop hl                                                            ; 090c: e1          .
    ret                                                               ; 090d: c9          .

; $090e referenced 1 time by $06d5
listit:
    push hl                                                           ; 090e: e5          .
    ex de,hl                                                          ; 090f: eb          .
    push bc                                                           ; 0910: c5          .
    call pbcd                                                         ; 0911: cd 2f 0a    ./.
    pop bc                                                            ; 0914: c1          .
    pop hl                                                            ; 0915: e1          .
    ld a,(hl)                                                         ; 0916: 7e          ~
    cp $ed                                                            ; 0917: fe ed       ..
    call z,indent                                                     ; 0919: cc 7a 09    .z.
    cp $fd                                                            ; 091c: fe fd       ..
    call z,indent                                                     ; 091e: cc 7a 09    .z.
    exx                                                               ; 0921: d9          .
    ld a,$20                                                          ; 0922: 3e 20       >
    bit 0,(ix+0)                                                      ; 0924: dd cb 00... ...
    call nz,outchr                                                    ; 0928: c4 9e 09    ...
    ld a,b                                                            ; 092b: 78          x
    add a,a                                                           ; 092c: 87          .
    bit 1,(ix+0)                                                      ; 092d: dd cb 00... ...
    call nz,fill_exec                                                 ; 0931: c4 54 18    .T.
    ld a,c                                                            ; 0934: 79          y
    add a,a                                                           ; 0935: 87          .
    bit 2,(ix+0)                                                      ; 0936: dd cb 00... ...
    call nz,fill_exec                                                 ; 093a: c4 54 18    .T.
    exx                                                               ; 093d: d9          .
    ld a,(hl)                                                         ; 093e: 7e          ~
    cp $e3                                                            ; 093f: fe e3       ..
    call z,indent                                                     ; 0941: cc 7a 09    .z.
    cp $f5                                                            ; 0944: fe f5       ..
    call z,indent                                                     ; 0946: cc 7a 09    .z.
    ld e,0                                                            ; 0949: 1e 00       ..
; $094b referenced 1 time by $0959
list8:
    ld a,(hl)                                                         ; 094b: 7e          ~
    inc hl                                                            ; 094c: 23          #
    cp $0d                                                            ; 094d: fe 0d       ..
    jr z,crlf                                                         ; 094f: 28 46       (F
    cp $22                                                            ; 0951: fe 22       ."
    jr nz,list7                                                       ; 0953: 20 01        .
    inc e                                                             ; 0955: 1c          .
; $0956 referenced 1 time by $0953
list7:
    call lout                                                         ; 0956: cd 6e 09    .n.
    jr list8                                                          ; 0959: 18 f0       ..

; $095b referenced 1 time by $0974
prlino:
    push hl                                                           ; 095b: e5          .
    pop iy                                                            ; 095c: fd e1       ..
    push bc                                                           ; 095e: c5          .
    call decode                                                       ; 095f: cd 50 24    .P$
    pop bc                                                            ; 0962: c1          .
    exx                                                               ; 0963: d9          .
    push bc                                                           ; 0964: c5          .
    call pbcdl                                                        ; 0965: cd 2b 0a    .+.
    pop bc                                                            ; 0968: c1          .
    exx                                                               ; 0969: d9          .
    push iy                                                           ; 096a: fd e5       ..
    pop hl                                                            ; 096c: e1          .
    ret                                                               ; 096d: c9          .

; $096e referenced 1 time by $0956
lout:
    bit 0,e                                                           ; 096e: cb 43       .C
    jr nz,outchr                                                      ; 0970: 20 2c        ,
    cp $8d                                                            ; 0972: fe 8d       ..
    jr z,prlino                                                       ; 0974: 28 e5       (.
    call out                                                          ; 0976: cd b7 09    ...
    ld a,(hl)                                                         ; 0979: 7e          ~
; $097a referenced 4 times by $0919, $091e, $0941, $0946
indent:
    exx                                                               ; 097a: d9          .
    cp $e3                                                            ; 097b: fe e3       ..
    jr z,ind1                                                         ; 097d: 28 08       (.
    cp $ed                                                            ; 097f: fe ed       ..
    jr nz,ind2                                                        ; 0981: 20 05        .
    dec b                                                             ; 0983: 05          .
    jp p,ind2                                                         ; 0984: f2 88 09    ...
; $0987 referenced 1 time by $097d
ind1:
    inc b                                                             ; 0987: 04          .
; $0988 referenced 2 times by $0981, $0984
ind2:
    cp $f5                                                            ; 0988: fe f5       ..
    jr z,ind3                                                         ; 098a: 28 08       (.
    cp $fd                                                            ; 098c: fe fd       ..
    jr nz,ind4                                                        ; 098e: 20 05        .
    dec c                                                             ; 0990: 0d          .
    jp p,ind4                                                         ; 0991: f2 95 09    ...
; $0994 referenced 1 time by $098a
ind3:
    inc c                                                             ; 0994: 0c          .
; $0995 referenced 2 times by $098e, $0991
ind4:
    exx                                                               ; 0995: d9          .
    ret                                                               ; 0996: c9          .

; $0997 referenced 12 times by $0792, $0845, $0853, $094f, $09b5, $1099, $14e6, $1818, $1834, $1986, $386f, $38b2
crlf:
    ld a,$0d                                                          ; 0997: 3e 0d       >.
    call outchr                                                       ; 0999: cd 9e 09    ...
    ld a,$0a                                                          ; 099c: 3e 0a       >.
; $099e referenced 21 times by $01d0, $0928, $0970, $0999, $09b9, $09cb, $0a45, $0e67, $0e6f, $0e74, $142c, $1431, $185a, $186a, $31e3, $31e8, $31f4, $31ff, $322d, $3232, $323a
outchr:
    call oswrch                                                       ; 099e: cd 5c 3a    .\:
    sub $0d                                                           ; 09a1: d6 0d       ..
    jr z,carret                                                       ; 09a3: 28 05       (.
    ret c                                                             ; 09a5: d8          .
    ld a,(count)                                                      ; 09a6: 3a fb 3f    :.?
    inc a                                                             ; 09a9: 3c          <
; $09aa referenced 1 time by $09a3
carret:
    ld (count),a                                                      ; 09aa: 32 fb 3f    2.?
    ret z                                                             ; 09ad: c8          .
    push hl                                                           ; 09ae: e5          .
    ld hl,(width)                                                     ; 09af: 2a fc 3f    *.?
    cp l                                                              ; 09b2: bd          .
    pop hl                                                            ; 09b3: e1          .
    ret nz                                                            ; 09b4: c0          .
    jr crlf                                                           ; 09b5: 18 e0       ..

; $09b7 referenced 4 times by $0976, $0d50, $197f, $19a4
out:
    cp $8a                                                            ; 09b7: fe 8a       ..
    jp pe,outchr                                                      ; 09b9: ea 9e 09    ...
    push bc                                                           ; 09bc: c5          .
    push hl                                                           ; 09bd: e5          .
    ld hl,$0257                                                       ; 09be: 21 57 02    !W.
    ld bc,$02df                                                       ; 09c1: 01 df 02    ...
    cpir                                                              ; 09c4: ed b1       ..
; $09c6 referenced 1 time by $09cf
token1:
    ld a,(hl)                                                         ; 09c6: 7e          ~
    inc hl                                                            ; 09c7: 23          #
    cp $8a                                                            ; 09c8: fe 8a       ..
    push af                                                           ; 09ca: f5          .
    call pe,outchr                                                    ; 09cb: ec 9e 09    ...
    pop af                                                            ; 09ce: f1          .
    jp pe,token1                                                      ; 09cf: ea c6 09    ...
    pop hl                                                            ; 09d2: e1          .
    pop bc                                                            ; 09d3: c1          .
    ret                                                               ; 09d4: c9          .

; $09d5 referenced 4 times by $020e, $0c4b, $112a, $1506
findl:
    ex de,hl                                                          ; 09d5: eb          .
    ld hl,(page)                                                      ; 09d6: 2a dc 3f    *.?
    xor a                                                             ; 09d9: af          .
    cp (hl)                                                           ; 09da: be          .
    inc a                                                             ; 09db: 3c          <
    ret nc                                                            ; 09dc: d0          .
    xor a                                                             ; 09dd: af          .
    ld b,a                                                            ; 09de: 47          G
; $09df referenced 1 time by $09eb
findl1:
    ld c,(hl)                                                         ; 09df: 4e          N
    push hl                                                           ; 09e0: e5          .
    inc hl                                                            ; 09e1: 23          #
    ld a,(hl)                                                         ; 09e2: 7e          ~
    inc hl                                                            ; 09e3: 23          #
    ld h,(hl)                                                         ; 09e4: 66          f
    ld l,a                                                            ; 09e5: 6f          o
    sbc hl,de                                                         ; 09e6: ed 52       .R
    pop hl                                                            ; 09e8: e1          .
    ret nc                                                            ; 09e9: d0          .
    add hl,bc                                                         ; 09ea: 09          .
    jp findl1                                                         ; 09eb: c3 df 09    ...

; $09ee referenced 3 times by $0825, $0e3a, $14e0
setlin:
    ld b,0                                                            ; 09ee: 06 00       ..
    ld de,(errlin)                                                    ; 09f0: ed 5b f4... .[.
    ld hl,(page)                                                      ; 09f4: 2a dc 3f    *.?
    or a                                                              ; 09f7: b7          .
    sbc hl,de                                                         ; 09f8: ed 52       .R
    add hl,de                                                         ; 09fa: 19          .
    jr nc,set3                                                        ; 09fb: 30 16       0.
; $09fd referenced 1 time by $0a06
set1:
    ld c,(hl)                                                         ; 09fd: 4e          N
    inc c                                                             ; 09fe: 0c          .
    dec c                                                             ; 09ff: 0d          .
    jr z,set3                                                         ; 0a00: 28 11       (.
    add hl,bc                                                         ; 0a02: 09          .
    sbc hl,de                                                         ; 0a03: ed 52       .R
    add hl,de                                                         ; 0a05: 19          .
    jr c,set1                                                         ; 0a06: 38 f5       8.
    sbc hl,bc                                                         ; 0a08: ed 42       .B
    inc hl                                                            ; 0a0a: 23          #
    ld e,(hl)                                                         ; 0a0b: 5e          ^
    inc hl                                                            ; 0a0c: 23          #
    ld d,(hl)                                                         ; 0a0d: 56          V
    ex de,hl                                                          ; 0a0e: eb          .
; $0a0f referenced 1 time by $0a16
set2:
    ld (lineno),hl                                                    ; 0a0f: 22 e6 3f    ".?
    ret                                                               ; 0a12: c9          .

; $0a13 referenced 2 times by $09fb, $0a00
set3:
    ld hl,0                                                           ; 0a13: 21 00 00    !..
    jr set2                                                           ; 0a16: 18 f7       ..

; $0a18 referenced 2 times by $084b, $14e3
sayln:
    ld hl,(lineno)                                                    ; 0a18: 2a e6 3f    *.?
    ld a,h                                                            ; 0a1b: 7c          |
    or l                                                              ; 0a1c: b5          .
    ret z                                                             ; 0a1d: c8          .
    call tell                                                         ; 0a1e: cd 55 0d    .U.
    db " at line ", 0                                                 ; 0a21: 20 61 74...  at

; $0a2b referenced 6 times by $078f, $0965, $0e6a, $31ef, $31fa, $3235
pbcdl:
    ld c,0                                                            ; 0a2b: 0e 00       ..
    jr pbcd0                                                          ; 0a2d: 18 02       ..

; $0a2f referenced 2 times by $01bd, $0911
pbcd:
    ld c,$20                                                          ; 0a2f: 0e 20       .
; $0a31 referenced 1 time by $0a2d
pbcd0:
    ld b,5                                                            ; 0a31: 06 05       ..
    ld de,$2710                                                       ; 0a33: 11 10 27    ..'
; $0a36 referenced 1 time by $0a56
pbcd1:
    xor a                                                             ; 0a36: af          .
; $0a37 referenced 1 time by $0a3a
pbcd2:
    sbc hl,de                                                         ; 0a37: ed 52       .R
    inc a                                                             ; 0a39: 3c          <
    jr nc,pbcd2                                                       ; 0a3a: 30 fb       0.
    add hl,de                                                         ; 0a3c: 19          .
    dec a                                                             ; 0a3d: 3d          =
    jr z,pbcd3                                                        ; 0a3e: 28 04       (.
    set 4,c                                                           ; 0a40: cb e1       ..
    set 5,c                                                           ; 0a42: cb e9       ..
; $0a44 referenced 1 time by $0a3e
pbcd3:
    or c                                                              ; 0a44: b1          .
    call nz,outchr                                                    ; 0a45: c4 9e 09    ...
    ld a,b                                                            ; 0a48: 78          x
    cp 5                                                              ; 0a49: fe 05       ..
    jr z,pbcd4                                                        ; 0a4b: 28 06       (.
    add hl,hl                                                         ; 0a4d: 29          )
    ld d,h                                                            ; 0a4e: 54          T
    ld e,l                                                            ; 0a4f: 5d          ]
    add hl,hl                                                         ; 0a50: 29          )
    add hl,hl                                                         ; 0a51: 29          )
    add hl,de                                                         ; 0a52: 19          .
; $0a53 referenced 1 time by $0a4b
pbcd4:
    ld de,$03e8                                                       ; 0a53: 11 e8 03    ...
    djnz pbcd1                                                        ; 0a56: 10 de       ..
    scf                                                               ; 0a58: 37          7
    ret                                                               ; 0a59: c9          .

; $0a5a referenced 3 times by $0ee6, $1678, $1714
putvar:
    call create_main                                                  ; 0a5a: cd a7 0b    ...
    ld a,(iy+0)                                                       ; 0a5d: fd 7e 00    .~.
    cp $28                                                            ; 0a60: fe 28       .(
    jr nz,getvz                                                       ; 0a62: 20 68        h
; $0a64 referenced 1 time by $0a86
array:
    ld a,$0e                                                          ; 0a64: 3e 0e       >.
; $0a66 referenced 1 time by $0aaf
error3_main:
    jp error_main                                                     ; 0a66: c3 05 08    ...

; $0a69 referenced 7 times by $0ee2, $0f38, $11d3, $1303, $1674, $170f, $206e
getvar:
    ld a,(iy+0)                                                       ; 0a69: fd 7e 00    .~.
    cp $24                                                            ; 0a6c: fe 24       .$
    jr z,getv4                                                        ; 0a6e: 28 62       (b
    cp $21                                                            ; 0a70: fe 21       .!
    jr z,getv5                                                        ; 0a72: 28 62       (b
    cp $3f                                                            ; 0a74: fe 3f       .?
    jr z,getv6                                                        ; 0a76: 28 62       (b
    call locate                                                       ; 0a78: cd 1f 0b    ...
    ret nz                                                            ; 0a7b: c0          .
    ld a,(iy+0)                                                       ; 0a7c: fd 7e 00    .~.
    cp $28                                                            ; 0a7f: fe 28       .(
    jr nz,getvx                                                       ; 0a81: 20 41        A
    push de                                                           ; 0a83: d5          .
    ld a,(hl)                                                         ; 0a84: 7e          ~
    or a                                                              ; 0a85: b7          .
    jr z,array                                                        ; 0a86: 28 dc       (.
    inc hl                                                            ; 0a88: 23          #
    ld de,0                                                           ; 0a89: 11 00 00    ...
    push af                                                           ; 0a8c: f5          .
    inc iy                                                            ; 0a8d: fd 23       .#
    jr getv3                                                          ; 0a8f: 18 04       ..

; $0a91 referenced 1 time by $0ab4
getv2:
    push af                                                           ; 0a91: f5          .
    call comma                                                        ; 0a92: cd 5a 25    .Z%
; $0a95 referenced 1 time by $0a8f
getv3:
    push hl                                                           ; 0a95: e5          .
    push de                                                           ; 0a96: d5          .
    call expri                                                        ; 0a97: cd be 1f    ...
    exx                                                               ; 0a9a: d9          .
    pop de                                                            ; 0a9b: d1          .
    ex (sp),hl                                                        ; 0a9c: e3          .
    ld c,(hl)                                                         ; 0a9d: 4e          N
    inc hl                                                            ; 0a9e: 23          #
    ld b,(hl)                                                         ; 0a9f: 46          F
    inc hl                                                            ; 0aa0: 23          #
    ex (sp),hl                                                        ; 0aa1: e3          .
    ex de,hl                                                          ; 0aa2: eb          .
    push de                                                           ; 0aa3: d5          .
    call mul16                                                        ; 0aa4: cd cd 18    ...
    pop de                                                            ; 0aa7: d1          .
    add hl,de                                                         ; 0aa8: 19          .
    ex de,hl                                                          ; 0aa9: eb          .
    or a                                                              ; 0aaa: b7          .
    sbc hl,bc                                                         ; 0aab: ed 42       .B
    ld a,$0f                                                          ; 0aad: 3e 0f       >.
    jr nc,error3_main                                                 ; 0aaf: 30 b5       0.
    pop hl                                                            ; 0ab1: e1          .
    pop af                                                            ; 0ab2: f1          .
    dec a                                                             ; 0ab3: 3d          =
    jr nz,getv2                                                       ; 0ab4: 20 db        .
    call braket                                                       ; 0ab6: cd 66 25    .f%
    pop af                                                            ; 0ab9: f1          .
    push hl                                                           ; 0aba: e5          .
    call x4or5                                                        ; 0abb: cd c0 18    ...
    pop hl                                                            ; 0abe: e1          .
    add hl,de                                                         ; 0abf: 19          .
    ld d,a                                                            ; 0ac0: 57          W
    ld a,(iy+0)                                                       ; 0ac1: fd 7e 00    .~.
; $0ac4 referenced 1 time by $0a81
getvx:
    cp $3f                                                            ; 0ac4: fe 3f       .?
    jr z,getv9                                                        ; 0ac6: 28 1d       (.
    cp $21                                                            ; 0ac8: fe 21       .!
    jr z,getv8                                                        ; 0aca: 28 15       (.
; $0acc referenced 1 time by $0a62
getvz:
    push hl                                                           ; 0acc: e5          .
    pop ix                                                            ; 0acd: dd e1       ..
    ld a,d                                                            ; 0acf: 7a          z
    cp a                                                              ; 0ad0: bf          .
    ret                                                               ; 0ad1: c9          .

; $0ad2 referenced 1 time by $0a6e
getv4:
    ld a,$80                                                          ; 0ad2: 3e 80       >.
    jr getv7                                                          ; 0ad4: 18 05       ..

; $0ad6 referenced 1 time by $0a72
getv5:
    ld a,4                                                            ; 0ad6: 3e 04       >.
    jr getv7                                                          ; 0ad8: 18 01       ..

; $0ada referenced 1 time by $0a76
getv6:
    xor a                                                             ; 0ada: af          .
; $0adb referenced 2 times by $0ad4, $0ad8
getv7:
    ld hl,0                                                           ; 0adb: 21 00 00    !..
    push af                                                           ; 0ade: f5          .
    jr getv0                                                          ; 0adf: 18 15       ..

; $0ae1 referenced 1 time by $0aca
getv8:
    ld b,4                                                            ; 0ae1: 06 04       ..
    jr getva                                                          ; 0ae3: 18 02       ..

; $0ae5 referenced 1 time by $0ac6
getv9:
    ld b,0                                                            ; 0ae5: 06 00       ..
; $0ae7 referenced 1 time by $0ae3
getva:
    push hl                                                           ; 0ae7: e5          .
    pop ix                                                            ; 0ae8: dd e1       ..
    ld a,d                                                            ; 0aea: 7a          z
    cp $81                                                            ; 0aeb: fe 81       ..
    ret z                                                             ; 0aed: c8          .
    push bc                                                           ; 0aee: c5          .
    call loadn                                                        ; 0aef: cd 77 20    .w
    call sfix_eval                                                    ; 0af2: cd 65 22    .e"
    exx                                                               ; 0af5: d9          .
; $0af6 referenced 1 time by $0adf
getv0:
    push hl                                                           ; 0af6: e5          .
    inc iy                                                            ; 0af7: fd 23       .#
    call itemi                                                        ; 0af9: cd d5 1f    ...
    exx                                                               ; 0afc: d9          .
    pop de                                                            ; 0afd: d1          .
    pop af                                                            ; 0afe: f1          .
    add hl,de                                                         ; 0aff: 19          .
    push hl                                                           ; 0b00: e5          .
    pop ix                                                            ; 0b01: dd e1       ..
    cp a                                                              ; 0b03: bf          .
    ret                                                               ; 0b04: c9          .

; $0b05 referenced 3 times by $1255, $1272, $128d
getdef:
    ld a,(iy+1)                                                       ; 0b05: fd 7e 01    .~.
    call range1                                                       ; 0b08: cd 5c 0c    .\.
    ret c                                                             ; 0b0b: d8          .
    ld a,(iy+0)                                                       ; 0b0c: fd 7e 00    .~.
    ld hl,$3fd8                                                       ; 0b0f: 21 d8 3f    !.?
    cp $a4                                                            ; 0b12: fe a4       ..
    jr z,loc2                                                         ; 0b14: 28 43       (C
    ld hl,$3fda                                                       ; 0b16: 21 da 3f    !.?
    cp $f2                                                            ; 0b19: fe f2       ..
    jr z,loc2                                                         ; 0b1b: 28 3c       (<
    scf                                                               ; 0b1d: 37          7
    ret                                                               ; 0b1e: c9          .

; $0b1f referenced 1 time by $0a78
locate:
    sub $40                                                           ; 0b1f: d6 40       .@
    ret c                                                             ; 0b21: d8          .
    ld h,0                                                            ; 0b22: 26 00       &.
    cp $1b                                                            ; 0b24: fe 1b       ..
    jr nc,loc0                                                        ; 0b26: 30 1d       0.
    add a,a                                                           ; 0b28: 87          .
    ld l,a                                                            ; 0b29: 6f          o
    ld a,(iy+1)                                                       ; 0b2a: fd 7e 01    .~.
    cp $25                                                            ; 0b2d: fe 25       .%
    jr nz,loc1                                                        ; 0b2f: 20 20
    ld a,(iy+2)                                                       ; 0b31: fd 7e 02    .~.
    cp $28                                                            ; 0b34: fe 28       .(
    jr z,loc1                                                         ; 0b36: 28 19       (.
    add hl,hl                                                         ; 0b38: 29          )
    ld de,$3f00                                                       ; 0b39: 11 00 3f    ..?
    add hl,de                                                         ; 0b3c: 19          .
    inc iy                                                            ; 0b3d: fd 23       .#
    inc iy                                                            ; 0b3f: fd 23       .#
    ld d,4                                                            ; 0b41: 16 04       ..
    xor a                                                             ; 0b43: af          .
    ret                                                               ; 0b44: c9          .

; $0b45 referenced 1 time by $0b26
loc0:
    cp $1f                                                            ; 0b45: fe 1f       ..
    ret c                                                             ; 0b47: d8          .
    cp $3b                                                            ; 0b48: fe 3b       .;
    ccf                                                               ; 0b4a: 3f          ?
    dec a                                                             ; 0b4b: 3d          =
    ret c                                                             ; 0b4c: d8          .
    sub 3                                                             ; 0b4d: d6 03       ..
    add a,a                                                           ; 0b4f: 87          .
    ld l,a                                                            ; 0b50: 6f          o
; $0b51 referenced 2 times by $0b2f, $0b36
loc1:
    ld de,$3f6c                                                       ; 0b51: 11 6c 3f    .l?
    dec l                                                             ; 0b54: 2d          -
    dec l                                                             ; 0b55: 2d          -
    scf                                                               ; 0b56: 37          7
    ret m                                                             ; 0b57: f8          .
    add hl,de                                                         ; 0b58: 19          .
; $0b59 referenced 3 times by $0b14, $0b1b, $0b75
loc2:
    ld e,(hl)                                                         ; 0b59: 5e          ^
    inc hl                                                            ; 0b5a: 23          #
    ld d,(hl)                                                         ; 0b5b: 56          V
    ld a,d                                                            ; 0b5c: 7a          z
    or e                                                              ; 0b5d: b3          .
    jr z,loc6                                                         ; 0b5e: 28 45       (E
    ld h,d                                                            ; 0b60: 62          b
    ld l,e                                                            ; 0b61: 6b          k
    inc hl                                                            ; 0b62: 23          #
    inc hl                                                            ; 0b63: 23          #
    push iy                                                           ; 0b64: fd e5       ..
; $0b66 referenced 1 time by $0b6d
loc3:
    ld a,(hl)                                                         ; 0b66: 7e          ~
    inc hl                                                            ; 0b67: 23          #
    inc iy                                                            ; 0b68: fd 23       .#
    cp (iy+0)                                                         ; 0b6a: fd be 00    ...
    jr z,loc3                                                         ; 0b6d: 28 f7       (.
    or a                                                              ; 0b6f: b7          .
    jr z,loc5                                                         ; 0b70: 28 06       (.
; $0b72 referenced 2 times by $0b8a, $0b92
loc4:
    pop iy                                                            ; 0b72: fd e1       ..
    ex de,hl                                                          ; 0b74: eb          .
    jp loc2                                                           ; 0b75: c3 59 0b    .Y.

; $0b78 referenced 1 time by $0b70
loc5:
    dec iy                                                            ; 0b78: fd 2b       .+
    ld a,(iy+0)                                                       ; 0b7a: fd 7e 00    .~.
    cp $28                                                            ; 0b7d: fe 28       .(
    jr z,loc5a                                                        ; 0b7f: 28 13       (.
    inc iy                                                            ; 0b81: fd 23       .#
    call range                                                        ; 0b83: cd 50 0c    .P.
    jr c,loc5a                                                        ; 0b86: 38 0c       8.
    cp $28                                                            ; 0b88: fe 28       .(
    jr z,loc4                                                         ; 0b8a: 28 e6       (.
    ld a,(iy-1)                                                       ; 0b8c: fd 7e ff    .~.
    call range1                                                       ; 0b8f: cd 5c 0c    .\.
    jr nc,loc4                                                        ; 0b92: 30 de       0.
; $0b94 referenced 2 times by $0b7f, $0b86
loc5a:
    pop de                                                            ; 0b94: d1          .
; $0b95 referenced 1 time by $0bd3
type_main:
    ld a,(iy-1)                                                       ; 0b95: fd 7e ff    .~.
    cp $24                                                            ; 0b98: fe 24       .$
    ld d,$81                                                          ; 0b9a: 16 81       ..
    ret z                                                             ; 0b9c: c8          .
    cp $25                                                            ; 0b9d: fe 25       .%
    ld d,4                                                            ; 0b9f: 16 04       ..
    ret z                                                             ; 0ba1: c8          .
    inc d                                                             ; 0ba2: 14          .
    cp a                                                              ; 0ba3: bf          .
    ret                                                               ; 0ba4: c9          .

; $0ba5 referenced 1 time by $0b5e
loc6:
    inc a                                                             ; 0ba5: 3c          <
    ret                                                               ; 0ba6: c9          .

; $0ba7 referenced 3 times by $0a5a, $0f40, $127a
create_main:
    xor a                                                             ; 0ba7: af          .
    ld de,(free)                                                      ; 0ba8: ed 5b e2... .[.
    ld (hl),d                                                         ; 0bac: 72          r
    dec hl                                                            ; 0bad: 2b          +
    ld (hl),e                                                         ; 0bae: 73          s
    ex de,hl                                                          ; 0baf: eb          .
    ld (hl),a                                                         ; 0bb0: 77          w
    inc hl                                                            ; 0bb1: 23          #
    ld (hl),a                                                         ; 0bb2: 77          w
    inc hl                                                            ; 0bb3: 23          #
; $0bb4 referenced 2 times by $0bc0, $0bcb
loc7:
    inc iy                                                            ; 0bb4: fd 23       .#
    call range                                                        ; 0bb6: cd 50 0c    .P.
    jr c,loc8                                                         ; 0bb9: 38 14       8.
    ld (hl),a                                                         ; 0bbb: 77          w
    inc hl                                                            ; 0bbc: 23          #
    call range1                                                       ; 0bbd: cd 5c 0c    .\.
    jr nc,loc7                                                        ; 0bc0: 30 f2       0.
    cp $28                                                            ; 0bc2: fe 28       .(
    jr z,loc8                                                         ; 0bc4: 28 09       (.
    ld a,(iy+1)                                                       ; 0bc6: fd 7e 01    .~.
    cp $28                                                            ; 0bc9: fe 28       .(
    jr z,loc7                                                         ; 0bcb: 28 e7       (.
    inc iy                                                            ; 0bcd: fd 23       .#
; $0bcf referenced 2 times by $0bb9, $0bc4
loc8:
    ld (hl),0                                                         ; 0bcf: 36 00       6.
    inc hl                                                            ; 0bd1: 23          #
    push hl                                                           ; 0bd2: e5          .
    call type_main                                                    ; 0bd3: cd 95 0b    ...
    ld a,5                                                            ; 0bd6: 3e 05       >.
    cp d                                                              ; 0bd8: ba          .
    jr z,loc9                                                         ; 0bd9: 28 01       (.
    dec a                                                             ; 0bdb: 3d          =
; $0bdc referenced 2 times by $0bd9, $0be0
loc9:
    ld (hl),0                                                         ; 0bdc: 36 00       6.
    inc hl                                                            ; 0bde: 23          #
    dec a                                                             ; 0bdf: 3d          =
    jr nz,loc9                                                        ; 0be0: 20 fa        .
    ld (free),hl                                                      ; 0be2: 22 e2 3f    ".?
    call check                                                        ; 0be5: cd e9 16    ...
    pop hl                                                            ; 0be8: e1          .
    xor a                                                             ; 0be9: af          .
    ret                                                               ; 0bea: c9          .

; $0beb referenced 6 times by $01e1, $0c15, $0c27, $0c38, $0c47, $0cb2
linnum:
    call nxt                                                          ; 0beb: cd a2 25    ..%
    ld hl,0                                                           ; 0bee: 21 00 00    !..
; $0bf1 referenced 1 time by $0c0e
linnm1:
    ld a,(iy+0)                                                       ; 0bf1: fd 7e 00    .~.
    sub $30                                                           ; 0bf4: d6 30       .0
    ret c                                                             ; 0bf6: d8          .
    cp $0a                                                            ; 0bf7: fe 0a       ..
    ret nc                                                            ; 0bf9: d0          .
    inc iy                                                            ; 0bfa: fd 23       .#
    ld d,h                                                            ; 0bfc: 54          T
    ld e,l                                                            ; 0bfd: 5d          ]
    add hl,hl                                                         ; 0bfe: 29          )
    jr c,toobig                                                       ; 0bff: 38 0f       8.
    add hl,hl                                                         ; 0c01: 29          )
    jr c,toobig                                                       ; 0c02: 38 0c       8.
    add hl,de                                                         ; 0c04: 19          .
    jr c,toobig                                                       ; 0c05: 38 09       8.
    add hl,hl                                                         ; 0c07: 29          )
    jr c,toobig                                                       ; 0c08: 38 06       8.
    ld e,a                                                            ; 0c0a: 5f          _
    ld d,0                                                            ; 0c0b: 16 00       ..
    add hl,de                                                         ; 0c0d: 19          .
    jr nc,linnm1                                                      ; 0c0e: 30 e1       0.
; $0c10 referenced 6 times by $01c8, $070b, $0bff, $0c02, $0c05, $0c08
toobig:
    ld a,$14                                                          ; 0c10: 3e 14       >.
    jp error_main                                                     ; 0c12: c3 05 08    ...

; $0c15 referenced 2 times by $06eb, $07a1
pair_main:
    call linnum                                                       ; 0c15: cd eb 0b    ...
    ld a,h                                                            ; 0c18: 7c          |
    or l                                                              ; 0c19: b5          .
    jr nz,pair1_main                                                  ; 0c1a: 20 02        .
    ld l,$0a                                                          ; 0c1c: 2e 0a       ..
; $0c1e referenced 1 time by $0c1a
pair1_main:
    call termq                                                        ; 0c1e: cd ec 17    ...
    inc iy                                                            ; 0c21: fd 23       .#
    push hl                                                           ; 0c23: e5          .
    ld hl,$0a                                                         ; 0c24: 21 0a 00    !..
    call nz,linnum                                                    ; 0c27: c4 eb 0b    ...
    ex (sp),hl                                                        ; 0c2a: e3          .
    pop bc                                                            ; 0c2b: c1          .
    ld a,b                                                            ; 0c2c: 78          x
    or c                                                              ; 0c2d: b1          .
    ret nz                                                            ; 0c2e: c0          .
    call exterr                                                       ; 0c2f: cd 1a 08    ...
    db "Silly", 0                                                     ; 0c32: 53 69 6c... Sil

; $0c38 referenced 2 times by $063e, $066e
dlpair:
    call linnum                                                       ; 0c38: cd eb 0b    ...
    push hl                                                           ; 0c3b: e5          .
    call termq                                                        ; 0c3c: cd ec 17    ...
    jr z,dlp1                                                         ; 0c3f: 28 09       (.
    cp $e7                                                            ; 0c41: fe e7       ..
    jr z,dlp1                                                         ; 0c43: 28 05       (.
    inc iy                                                            ; 0c45: fd 23       .#
    call linnum                                                       ; 0c47: cd eb 0b    ...
; $0c4a referenced 2 times by $0c3f, $0c43
dlp1:
    ex (sp),hl                                                        ; 0c4a: e3          .
    call findl                                                        ; 0c4b: cd d5 09    ...
    pop bc                                                            ; 0c4e: c1          .
    ret                                                               ; 0c4f: c9          .

; $0c50 referenced 3 times by $0b83, $0bb6, $20ac
range:
    ld a,(iy+0)                                                       ; 0c50: fd 7e 00    .~.
    cp $24                                                            ; 0c53: fe 24       .$
    ret z                                                             ; 0c55: c8          .
    cp $25                                                            ; 0c56: fe 25       .%
    ret z                                                             ; 0c58: c8          .
    cp $28                                                            ; 0c59: fe 28       .(
    ret z                                                             ; 0c5b: c8          .
; $0c5c referenced 5 times by $087f, $0b08, $0b8f, $0bbd, $0c8a
range1:
    cp $30                                                            ; 0c5c: fe 30       .0
    ret c                                                             ; 0c5e: d8          .
    cp $3a                                                            ; 0c5f: fe 3a       .:
    ccf                                                               ; 0c61: 3f          ?
    ret nc                                                            ; 0c62: d0          .
    cp $40                                                            ; 0c63: fe 40       .@
    ret z                                                             ; 0c65: c8          .
; $0c66 referenced 1 time by $0cee
range2:
    cp $41                                                            ; 0c66: fe 41       .A
    ret c                                                             ; 0c68: d8          .
    cp $5b                                                            ; 0c69: fe 5b       .[
    ccf                                                               ; 0c6b: 3f          ?
    ret nc                                                            ; 0c6c: d0          .
    cp $5f                                                            ; 0c6d: fe 5f       ._
    ret c                                                             ; 0c6f: d8          .
    cp $7b                                                            ; 0c70: fe 7b       .{
    ccf                                                               ; 0c72: 3f          ?
    ret                                                               ; 0c73: c9          .

; $0c74 referenced 1 time by $0c82
space:
    xor a                                                             ; 0c74: af          .
    call exterr                                                       ; 0c75: cd 1a 08    ...
    db $86, 8, 0                                                      ; 0c78: 86 08 00    ...

; $0c7b referenced 4 times by $0c95, $0c99, $0cc2, $0d17
lexan1:
    ld (de),a                                                         ; 0c7b: 12          .
    inc de                                                            ; 0c7c: 13          .
    inc iy                                                            ; 0c7d: fd 23       .#
; $0c7f referenced 3 times by $01f3, $0cbc, $228b
lexan2:
    ld a,e                                                            ; 0c7f: 7b          {
    cp $fc                                                            ; 0c80: fe fc       ..
    jr nc,space                                                       ; 0c82: 30 f0       0.
    ld a,(iy+0)                                                       ; 0c84: fd 7e 00    .~.
    cp $0d                                                            ; 0c87: fe 0d       ..
    ret z                                                             ; 0c89: c8          .
    call range1                                                       ; 0c8a: cd 5c 0c    .\.
    jr nc,lexan3                                                      ; 0c8d: 30 04       0.
    res 5,c                                                           ; 0c8f: cb a9       ..
    res 3,c                                                           ; 0c91: cb 99       ..
; $0c93 referenced 1 time by $0c8d
lexan3:
    cp $20                                                            ; 0c93: fe 20       .
    jr z,lexan1                                                       ; 0c95: 28 e4       (.
    cp $2c                                                            ; 0c97: fe 2c       .,
    jr z,lexan1                                                       ; 0c99: 28 e0       (.
    cp $47                                                            ; 0c9b: fe 47       .G
    jr c,lexan4                                                       ; 0c9d: 38 02       8.
    res 3,c                                                           ; 0c9f: cb 99       ..
; $0ca1 referenced 1 time by $0c9d
lexan4:
    cp $22                                                            ; 0ca1: fe 22       ."
    jr nz,lexan5                                                      ; 0ca3: 20 05        .
    rl c                                                              ; 0ca5: cb 11       ..
    ccf                                                               ; 0ca7: 3f          ?
    rr c                                                              ; 0ca8: cb 19       ..
; $0caa referenced 1 time by $0ca3
lexan5:
    bit 4,c                                                           ; 0caa: cb 61       .a
    jr z,lexan6                                                       ; 0cac: 28 10       (.
    res 4,c                                                           ; 0cae: cb a1       ..
    push bc                                                           ; 0cb0: c5          .
    push de                                                           ; 0cb1: d5          .
    call linnum                                                       ; 0cb2: cd eb 0b    ...
    pop de                                                            ; 0cb5: d1          .
    pop bc                                                            ; 0cb6: c1          .
    ld a,h                                                            ; 0cb7: 7c          |
    or l                                                              ; 0cb8: b5          .
    call nz,encode                                                    ; 0cb9: c4 23 0d    .#.
    jr lexan2                                                         ; 0cbc: 18 c1       ..

; $0cbe referenced 1 time by $0cac
lexan6:
    dec c                                                             ; 0cbe: 0d          .
    jr z,lexan7                                                       ; 0cbf: 28 09       (.
    inc c                                                             ; 0cc1: 0c          .
    jr nz,lexan1                                                      ; 0cc2: 20 b7        .
    or a                                                              ; 0cc4: b7          .
    call p,lex                                                        ; 0cc5: f4 59 08    .Y.
    jr lexan8                                                         ; 0cc8: 18 12       ..

; $0cca referenced 1 time by $0cbf
lexan7:
    cp $2a                                                            ; 0cca: fe 2a       .*
    jr z,lexan9                                                       ; 0ccc: 28 16       (.
    or a                                                              ; 0cce: b7          .
    call p,lex                                                        ; 0ccf: f4 59 08    .Y.
    cp $8f                                                            ; 0cd2: fe 8f       ..
    jr c,lexan8                                                       ; 0cd4: 38 06       8.
    cp $94                                                            ; 0cd6: fe 94       ..
    jr nc,lexan8                                                      ; 0cd8: 30 02       0.
    add a,$40                                                         ; 0cda: c6 40       .@
; $0cdc referenced 3 times by $0cc8, $0cd4, $0cd8
lexan8:
    cp $f4                                                            ; 0cdc: fe f4       ..
    jr z,lexan9                                                       ; 0cde: 28 04       (.
    cp $dc                                                            ; 0ce0: fe dc       ..
    jr nz,lexana                                                      ; 0ce2: 20 02        .
; $0ce4 referenced 2 times by $0ccc, $0cde
lexan9:
    set 6,c                                                           ; 0ce4: cb f1       ..
; $0ce6 referenced 1 time by $0ce2
lexana:
    cp $a4                                                            ; 0ce6: fe a4       ..
    jr z,lexanb                                                       ; 0ce8: 28 09       (.
    cp $f2                                                            ; 0cea: fe f2       ..
    jr z,lexanb                                                       ; 0cec: 28 05       (.
    call range2                                                       ; 0cee: cd 66 0c    .f.
    jr c,lexanc                                                       ; 0cf1: 38 02       8.
; $0cf3 referenced 2 times by $0ce8, $0cec
lexanb:
    set 5,c                                                           ; 0cf3: cb e9       ..
; $0cf5 referenced 1 time by $0cf1
lexanc:
    cp $26                                                            ; 0cf5: fe 26       .&
    jr nz,lexand                                                      ; 0cf7: 20 02        .
    set 3,c                                                           ; 0cf9: cb d9       ..
; $0cfb referenced 1 time by $0cf7
lexand:
    ld hl,$0d1a                                                       ; 0cfb: 21 1a 0d    !..
    push bc                                                           ; 0cfe: c5          .
    ld bc,6                                                           ; 0cff: 01 06 00    ...
    cpir                                                              ; 0d02: ed b1       ..
    pop bc                                                            ; 0d04: c1          .
    jr nz,lexane                                                      ; 0d05: 20 02        .
    set 4,c                                                           ; 0d07: cb e1       ..
; $0d09 referenced 1 time by $0d05
lexane:
    ld hl,$0d1e                                                       ; 0d09: 21 1e 0d    !..
    push bc                                                           ; 0d0c: c5          .
    ld bc,5                                                           ; 0d0d: 01 05 00    ...
    cpir                                                              ; 0d10: ed b1       ..
    pop bc                                                            ; 0d12: c1          .
    jr nz,lexanf                                                      ; 0d13: 20 02        .
    set 0,c                                                           ; 0d15: cb c1       ..
; $0d17 referenced 1 time by $0d13
lexanf:
    jp lexan1                                                         ; 0d17: c3 7b 0c    .{.

list1:
    db $e5, $e4, $f7, $fc                                             ; 0d1a: e5 e4 f7... ...
list2:
    db $8c, $8b, $f5, $85, $3a                                        ; 0d1e: 8c 8b f5... ...

; $0d23 referenced 2 times by $079a, $0cb9
encode:
    set 4,c                                                           ; 0d23: cb e1       ..
    ex de,hl                                                          ; 0d25: eb          .
    ld (hl),$8d                                                       ; 0d26: 36 8d       6.
    inc hl                                                            ; 0d28: 23          #
    ld a,d                                                            ; 0d29: 7a          z
    and $c0                                                           ; 0d2a: e6 c0       ..
    rrca                                                              ; 0d2c: 0f          .
    rrca                                                              ; 0d2d: 0f          .
    ld b,a                                                            ; 0d2e: 47          G
    ld a,e                                                            ; 0d2f: 7b          {
    and $c0                                                           ; 0d30: e6 c0       ..
    or b                                                              ; 0d32: b0          .
    rrca                                                              ; 0d33: 0f          .
    rrca                                                              ; 0d34: 0f          .
    xor $54                                                           ; 0d35: ee 54       .T
    ld (hl),a                                                         ; 0d37: 77          w
    inc hl                                                            ; 0d38: 23          #
    ld a,e                                                            ; 0d39: 7b          {
    and $3f                                                           ; 0d3a: e6 3f       .?
    or $40                                                            ; 0d3c: f6 40       .@
    ld (hl),a                                                         ; 0d3e: 77          w
    inc hl                                                            ; 0d3f: 23          #
    ld a,d                                                            ; 0d40: 7a          z
    and $3f                                                           ; 0d41: e6 3f       .?
    or $40                                                            ; 0d43: f6 40       .@
    ld (hl),a                                                         ; 0d45: 77          w
    inc hl                                                            ; 0d46: 23          #
    ex de,hl                                                          ; 0d47: eb          .
    ret                                                               ; 0d48: c9          .

; $0d49 referenced 2 times by $0848, $14ec
report:
    ld hl,(errtxt)                                                    ; 0d49: 2a ee 3f    *.?
; $0d4c referenced 3 times by $010f, $0d53, $0d56
text:
    ld a,(hl)                                                         ; 0d4c: 7e          ~
    inc hl                                                            ; 0d4d: 23          #
    or a                                                              ; 0d4e: b7          .
    ret z                                                             ; 0d4f: c8          .
    call out                                                          ; 0d50: cd b7 09    ...
    jr text                                                           ; 0d53: 18 f7       ..

; $0d55 referenced 7 times by $010c, $0154, $077e, $07ad, $0a1e, $14d9, $31c1
tell:
    ex (sp),hl                                                        ; 0d55: e3          .
    call text                                                         ; 0d56: cd 4c 0d    .L.
    ex (sp),hl                                                        ; 0d59: e3          .
    ret                                                               ; 0d5a: c9          .

cmdtab:
    dw auto                                                           ; 0d5b: a1 07       ..
    dw delete_main                                                    ; 0d5d: 3b 06       ;.
    dw load_main                                                      ; 0d5f: d9 07       ..
    dw list                                                           ; 0d61: 6a 06       j.
    dw new                                                            ; 0d63: bb 07       ..
    dw old                                                            ; 0d65: c0 07       ..
    dw renum                                                          ; 0d67: e8 06       ..
    dw save_main                                                      ; 0d69: e7 07       ..
    dw put                                                            ; 0d6b: 62 16       b.
    dw ptr_exec                                                       ; 0d6d: 18 15       ..
    dw pagev_exec                                                     ; 0d6f: 2d 15       -.
    dw timev_exec                                                     ; 0d71: 3c 15       <.
    dw lomemv_exec                                                    ; 0d73: 5d 15       ].
    dw himemv_exec                                                    ; 0d75: 70 15       p.
    dw adval                                                          ; 0d77: aa 32       .2
    dw bput                                                           ; 0d79: e4 15       ..
    dw call                                                           ; 0d7b: f7 15       ..
    dw chain                                                          ; 0d7d: d4 0d       ..
    dw clr                                                            ; 0d7f: f2 14       ..
    dw close_exec                                                     ; 0d81: db 15       ..
    dw adval                                                          ; 0d83: aa 32       .2
    dw cls                                                            ; 0d85: cf 14       ..
    dw rem                                                            ; 0d87: 8b 0e       ..
    dw rem                                                            ; 0d89: 8b 0e       ..
    dw dim                                                            ; 0d8b: 38 0f       8.
    dw adval                                                          ; 0d8d: aa 32       .2
    dw end                                                            ; 0d8f: 3a 0e       :.
    dw endpro                                                         ; 0d91: 27 13       '.
    dw adval                                                          ; 0d93: aa 32       .2
    dw for_exec                                                       ; 0d95: 7c 11       |.
    dw gosub                                                          ; 0d97: 37 11       7.
    dw goto                                                           ; 0d99: 20 11        .
    dw gcol                                                           ; 0d9b: 40 32       @2
    dw if                                                             ; 0d9d: a2 14       ..
    dw input                                                          ; 0d9f: b2 13       ..
    dw let                                                            ; 0da1: ab 0e       ..
    dw local                                                          ; 0da3: d9 12       ..
    dw mode                                                           ; 0da5: 86 32       .2
    dw adval                                                          ; 0da7: aa 32       .2
    dw forchk                                                         ; 0da9: c1 11       ..
    dw on                                                             ; 0dab: ba 10       ..
    dw vdu                                                            ; 0dad: ba 15       ..
    dw plot                                                           ; 0daf: 91 32       .2
    dw print                                                          ; 0db1: e5 0f       ..
    dw fnchk                                                          ; 0db3: 4a 12       J.
    dw read_exec                                                      ; 0db5: 51 14       Q.
    dw rem                                                            ; 0db7: 8b 0e       ..
    dw repeat                                                         ; 0db9: 52 11       R.
    dw repor                                                          ; 0dbb: ec 14       ..
    dw restor                                                         ; 0dbd: fa 14       ..
    dw goschk                                                         ; 0dbf: 42 11       B.
    dw run                                                            ; 0dc1: cf 0d       ..
    dw stop_exec                                                      ; 0dc3: d9 14       ..
    dw colour                                                         ; 0dc5: 13 32       .2
    dw trace                                                          ; 0dc7: a0 15       ..
    dw repchk                                                         ; 0dc9: 5a 11       Z.
    dw widthv                                                         ; 0dcb: 95 15       ..
    dw cli                                                            ; 0dcd: 77 0e       w.

run:
    call termq                                                        ; 0dcf: cd ec 17    ...
    jr z,run0                                                         ; 0dd2: 28 0d       (.
chain:
    call exprs                                                        ; 0dd4: cd c7 1f    ...
    ld a,$0d                                                          ; 0dd7: 3e 0d       >.
    ld (de),a                                                         ; 0dd9: 12          .
; $0dda referenced 1 time by $0151
chain0:
    ld sp,(himem)                                                     ; 0dda: ed 7b e4... .{.
    call load0_main                                                   ; 0dde: cd ad 08    ...
; $0de1 referenced 2 times by $0118, $0dd2
run0:
    ld sp,(himem)                                                     ; 0de1: ed 7b e4... .{.
    ld ix,$3ff6                                                       ; 0de5: dd 21 f6... .!.
    ld a,r                                                            ; 0de9: ed 5f       ._
    jr nz,rand                                                        ; 0deb: 20 01        .
    inc a                                                             ; 0ded: 3c          <
; $0dee referenced 1 time by $0deb
rand:
    rlca                                                              ; 0dee: 07          .
    rlca                                                              ; 0def: 07          .
    ld (ix+3),a                                                       ; 0df0: dd 77 03    .w.
    sbc a,a                                                           ; 0df3: 9f          .
    ld (ix+4),a                                                       ; 0df4: dd 77 04    .w.
    call clear                                                        ; 0df7: cd f6 08    ...
    ld hl,0                                                           ; 0dfa: 21 00 00    !..
    ld (errtrp),hl                                                    ; 0dfd: 22 ec 3f    ".?
    ld hl,(page)                                                      ; 0e00: 2a dc 3f    *.?
    ld a,$dc                                                          ; 0e03: 3e dc       >.
    call search_exec                                                  ; 0e05: cd aa 18    ...
    ld (datptr),hl                                                    ; 0e08: 22 f0 3f    ".?
    ld iy,(page)                                                      ; 0e0b: fd 2a dc... .*.
; $0e0f referenced 4 times by $0e24, $0e96, $1130, $14c6
xeq0_exec:
    call newlin                                                       ; 0e0f: cd 4a 0e    .J.
; $0e12 referenced 47 times by $0205, $0836, $0e83, $0eae, $0ec1, $0fae, $0ff1, $109c, $10ae, $114b, $1157, $1175, $11be, $121f, $122e, $12c7, $12d6, $131d, $1338, $1364, $13c8, $148c, $14af, $14b9, $14d6, $14ef, $1515, $152a, $1539, $154c, $155a, $156d, $158d, $1592, $159d, $15b7, $15d8, $15e1, $15f4, $1627, $1671, $323d, $3260, $326c, $3283, $328e, $3299
xeq_exec:
    ld (errlin),iy                                                    ; 0e12: fd 22 f4... .".
    call trap                                                         ; 0e16: cd c6 39    ..9
; $0e19 referenced 1 time by $0e20
xeq1_exec:
    call nxt                                                          ; 0e19: cd a2 25    ..%
    inc iy                                                            ; 0e1c: fd 23       .#
    cp $3a                                                            ; 0e1e: fe 3a       .:
    jr z,xeq1_exec                                                    ; 0e20: 28 f7       (.
    cp $0d                                                            ; 0e22: fe 0d       ..
    jr z,xeq0_exec                                                    ; 0e24: 28 e9       (.
    sub $c6                                                           ; 0e26: d6 c6       ..
    jr c,let0                                                         ; 0e28: 38 6f       8o
    add a,a                                                           ; 0e2a: 87          .
    ld c,a                                                            ; 0e2b: 4f          O
    ld b,0                                                            ; 0e2c: 06 00       ..
    ld hl,$0d5b                                                       ; 0e2e: 21 5b 0d    ![.
    add hl,bc                                                         ; 0e31: 09          .
    ld a,(hl)                                                         ; 0e32: 7e          ~
    inc hl                                                            ; 0e33: 23          #
    ld h,(hl)                                                         ; 0e34: 66          f
    ld l,a                                                            ; 0e35: 6f          o
    call nxt                                                          ; 0e36: cd a2 25    ..%
    jp (hl)                                                           ; 0e39: e9          .

; $0e3a referenced 1 time by $0e53
end:
    call setlin                                                       ; 0e3a: cd ee 09    ...
    ld a,h                                                            ; 0e3d: 7c          |
    or l                                                              ; 0e3e: b5          .
    jp z,cloop                                                        ; 0e3f: ca 99 01    ...
    ld e,0                                                            ; 0e42: 1e 00       ..
    call osshut                                                       ; 0e44: cd 26 34    .&4
    jp warm                                                           ; 0e47: c3 98 01    ...

; $0e4a referenced 2 times by $0e0f, $0ec4
newlin:
    ld a,(iy+0)                                                       ; 0e4a: fd 7e 00    .~.
    ld bc,3                                                           ; 0e4d: 01 03 00    ...
    add iy,bc                                                         ; 0e50: fd 09       ..
    or a                                                              ; 0e52: b7          .
    jr z,end                                                          ; 0e53: 28 e5       (.
    ld hl,(tracen)                                                    ; 0e55: 2a e8 3f    *.?
    ld a,h                                                            ; 0e58: 7c          |
    or l                                                              ; 0e59: b5          .
    ret z                                                             ; 0e5a: c8          .
    ld d,(iy-1)                                                       ; 0e5b: fd 56 ff    .V.
    ld e,(iy-2)                                                       ; 0e5e: fd 5e fe    .^.
    sbc hl,de                                                         ; 0e61: ed 52       .R
    ret c                                                             ; 0e63: d8          .
    ex de,hl                                                          ; 0e64: eb          .
    ld a,$5b                                                          ; 0e65: 3e 5b       >[
    call outchr                                                       ; 0e67: cd 9e 09    ...
    call pbcdl                                                        ; 0e6a: cd 2b 0a    .+.
    ld a,$5d                                                          ; 0e6d: 3e 5d       >]
    call outchr                                                       ; 0e6f: cd 9e 09    ...
    ld a,$20                                                          ; 0e72: 3e 20       >
    jp outchr                                                         ; 0e74: c3 9e 09    ...

cli:
    call exprs                                                        ; 0e77: cd c7 1f    ...
    ld a,$0d                                                          ; 0e7a: 3e 0d       >.
    ld (de),a                                                         ; 0e7c: 12          .
    ld hl,$3d00                                                       ; 0e7d: 21 00 3d    !.=
    call oscli                                                        ; 0e80: cd 71 37    .q7
    jr xeq_exec                                                       ; 0e83: 18 8d       ..

; $0e85 referenced 1 time by $0e9f
ext_exec:
    push iy                                                           ; 0e85: fd e5       ..
    pop hl                                                            ; 0e87: e1          .
    call oscli                                                        ; 0e88: cd 71 37    .q7
; $0e8b referenced 2 times by $0e9b, $10b7
rem:
    push iy                                                           ; 0e8b: fd e5       ..
    pop hl                                                            ; 0e8d: e1          .
    ld a,$0d                                                          ; 0e8e: 3e 0d       >.
    ld b,a                                                            ; 0e90: 47          G
    cpir                                                              ; 0e91: ed b1       ..
    push hl                                                           ; 0e93: e5          .
    pop iy                                                            ; 0e94: fd e1       ..
    jp xeq0_exec                                                      ; 0e96: c3 0f 0e    ...

; $0e99 referenced 1 time by $0e28
let0:
    cp $c5                                                            ; 0e99: fe c5       ..
    jr z,rem                                                          ; 0e9b: 28 ee       (.
    cp $64                                                            ; 0e9d: fe 64       .d
    jr z,ext_exec                                                     ; 0e9f: 28 e4       (.
    cp $77                                                            ; 0ea1: fe 77       .w
    jr z,fnend                                                        ; 0ea3: 28 4c       (L
    cp $95                                                            ; 0ea5: fe 95       ..
    jr z,asm                                                          ; 0ea7: 28 1e       (.
    dec iy                                                            ; 0ea9: fd 2b       .+
let:
    call assign                                                       ; 0eab: cd 74 16    .t.
    jp z,xeq_exec                                                     ; 0eae: ca 12 0e    ...
    jr c,syntax                                                       ; 0eb1: 38 36       86
    push af                                                           ; 0eb3: f5          .
    call equals                                                       ; 0eb4: cd 00 18    ...
    push hl                                                           ; 0eb7: e5          .
    call exprs                                                        ; 0eb8: cd c7 1f    ...
    pop ix                                                            ; 0ebb: dd e1       ..
    pop af                                                            ; 0ebd: f1          .
    call staccs                                                       ; 0ebe: cd b1 16    ...
; $0ec1 referenced 1 time by $0ee0
xeqr:
    jp xeq_exec                                                       ; 0ec1: c3 12 0e    ...

; $0ec4 referenced 1 time by $0ed5
asm0:
    call newlin                                                       ; 0ec4: cd 4a 0e    .J.
; $0ec7 referenced 1 time by $0ea7
asm:
    ld (errlin),iy                                                    ; 0ec7: fd 22 f4... .".
    call trap                                                         ; 0ecb: cd c6 39    ..9
    call assem                                                        ; 0ece: cd f3 18    ...
    jr c,syntax                                                       ; 0ed1: 38 16       8.
    cp $0d                                                            ; 0ed3: fe 0d       ..
    jr z,asm0                                                         ; 0ed5: 28 ed       (.
    ld hl,$3ffe                                                       ; 0ed7: 21 fe 3f    !.?
    ld a,(hl)                                                         ; 0eda: 7e          ~
    and $0f                                                           ; 0edb: e6 0f       ..
    or $30                                                            ; 0edd: f6 30       .0
    ld (hl),a                                                         ; 0edf: 77          w
    jr xeqr                                                           ; 0ee0: 18 df       ..

; $0ee2 referenced 6 times by $136d, $13f1, $1461, $1610, $1786, $19af
var:
    call getvar                                                       ; 0ee2: cd 69 0a    .i.
    ret z                                                             ; 0ee5: c8          .
    jp nc,putvar                                                      ; 0ee6: d2 5a 0a    .Z.
; $0ee9 referenced 9 times by $0eb1, $0ed1, $1126, $12ab, $1306, $1ee9, $2058, $209e, $2187
syntax:
    ld a,$10                                                          ; 0ee9: 3e 10       >.
; overlapping: ld hl,$113e                                            ; 0eeb: 21 3e 11    !>.
    db $21                                                            ; 0eeb: 21          !

; $0eec referenced 2 times by $0106, $39d7
escape:
    ld a,$11                                                          ; 0eec: 3e 11       >.
; $0eee referenced 1 time by $0f09
error0_exec:
    jp error_main                                                     ; 0eee: c3 05 08    ...

; $0ef1 referenced 1 time by $0ea3
fnend:
    call expr                                                         ; 0ef1: cd ae 1e    ...
    ld b,e                                                            ; 0ef4: 43          C
    ex de,hl                                                          ; 0ef5: eb          .
    exx                                                               ; 0ef6: d9          .
    ex de,hl                                                          ; 0ef7: eb          .
; $0ef8 referenced 2 times by $0f29, $0f36
fnend5:
    pop bc                                                            ; 0ef8: c1          .
    ld hl,$17cc                                                       ; 0ef9: 21 cc 17    !..
    or a                                                              ; 0efc: b7          .
    sbc hl,bc                                                         ; 0efd: ed 42       .B
    jr z,fnend0                                                       ; 0eff: 28 19       (.
    ld hl,$124a                                                       ; 0f01: 21 4a 12    !J.
    or a                                                              ; 0f04: b7          .
    sbc hl,bc                                                         ; 0f05: ed 42       .B
    ld a,7                                                            ; 0f07: 3e 07       >.
    jr nz,error0_exec                                                 ; 0f09: 20 e3        .
    pop iy                                                            ; 0f0b: fd e1       ..
    ld (errlin),iy                                                    ; 0f0d: fd 22 f4... .".
    ex de,hl                                                          ; 0f11: eb          .
    exx                                                               ; 0f12: d9          .
    ex de,hl                                                          ; 0f13: eb          .
    ld de,$3d00                                                       ; 0f14: 11 00 3d    ..=
    ld e,b                                                            ; 0f17: 58          X
    ex af,af'                                                         ; 0f18: 08          .
    ret                                                               ; 0f19: c9          .

; $0f1a referenced 1 time by $0eff
fnend0:
    pop ix                                                            ; 0f1a: dd e1       ..
    pop bc                                                            ; 0f1c: c1          .
    ld a,b                                                            ; 0f1d: 78          x
    or a                                                              ; 0f1e: b7          .
    jp m,fnend1                                                       ; 0f1f: fa 2b 0f    .+.
    pop hl                                                            ; 0f22: e1          .
    exx                                                               ; 0f23: d9          .
    pop hl                                                            ; 0f24: e1          .
    exx                                                               ; 0f25: d9          .
    call store                                                        ; 0f26: cd 88 16    ...
    jr fnend5                                                         ; 0f29: 18 cd       ..

; $0f2b referenced 1 time by $0f1f
fnend1:
    ld hl,0                                                           ; 0f2b: 21 00 00    !..
    add hl,sp                                                         ; 0f2e: 39          9
    push de                                                           ; 0f2f: d5          .
    ld e,c                                                            ; 0f30: 59          Y
    call stores                                                       ; 0f31: cd b4 16    ...
    pop de                                                            ; 0f34: d1          .
    ld sp,hl                                                          ; 0f35: f9          .
    jr fnend5                                                         ; 0f36: 18 c0       ..

; $0f38 referenced 1 time by $0fb6
dim:
    call getvar                                                       ; 0f38: cd 69 0a    .i.
    jr c,baddim                                                       ; 0f3b: 38 7b       8{
    jp z,dim4                                                         ; 0f3d: ca c0 0f    ...
    call create_main                                                  ; 0f40: cd a7 0b    ...
    push hl                                                           ; 0f43: e5          .
    pop ix                                                            ; 0f44: dd e1       ..
    ld a,(iy+0)                                                       ; 0f46: fd 7e 00    .~.
    cp $28                                                            ; 0f49: fe 28       .(
    ld a,d                                                            ; 0f4b: 7a          z
    jr nz,dim4                                                        ; 0f4c: 20 72        r
    push hl                                                           ; 0f4e: e5          .
    push af                                                           ; 0f4f: f5          .
    ld de,1                                                           ; 0f50: 11 01 00    ...
    ld b,d                                                            ; 0f53: 42          B
; $0f54 referenced 1 time by $0f7d
dim1:
    inc iy                                                            ; 0f54: fd 23       .#
    push bc                                                           ; 0f56: c5          .
    push de                                                           ; 0f57: d5          .
    push ix                                                           ; 0f58: dd e5       ..
    call expri                                                        ; 0f5a: cd be 1f    ...
    bit 7,h                                                           ; 0f5d: cb 7c       .|
    jr nz,baddim                                                      ; 0f5f: 20 57        W
    exx                                                               ; 0f61: d9          .
    inc hl                                                            ; 0f62: 23          #
    pop ix                                                            ; 0f63: dd e1       ..
    inc ix                                                            ; 0f65: dd 23       .#
    ld (ix+0),l                                                       ; 0f67: dd 75 00    .u.
    inc ix                                                            ; 0f6a: dd 23       .#
    ld (ix+0),h                                                       ; 0f6c: dd 74 00    .t.
    pop bc                                                            ; 0f6f: c1          .
    call mul16                                                        ; 0f70: cd cd 18    ...
    jr c,noroom                                                       ; 0f73: 38 46       8F
    ex de,hl                                                          ; 0f75: eb          .
    pop bc                                                            ; 0f76: c1          .
    inc b                                                             ; 0f77: 04          .
    ld a,(iy+0)                                                       ; 0f78: fd 7e 00    .~.
    cp $2c                                                            ; 0f7b: fe 2c       .,
    jr z,dim1                                                         ; 0f7d: 28 d5       (.
    call braket                                                       ; 0f7f: cd 66 25    .f%
    pop af                                                            ; 0f82: f1          .
    inc ix                                                            ; 0f83: dd 23       .#
    ex (sp),ix                                                        ; 0f85: dd e3       ..
    ld (ix+0),b                                                       ; 0f87: dd 70 00    .p.
    call x4or5                                                        ; 0f8a: cd c0 18    ...
    pop hl                                                            ; 0f8d: e1          .
    jr c,noroom                                                       ; 0f8e: 38 2b       8+
; $0f90 referenced 1 time by $0fe3
dim3:
    add hl,de                                                         ; 0f90: 19          .
    jr c,noroom                                                       ; 0f91: 38 28       8(
    push hl                                                           ; 0f93: e5          .
    inc h                                                             ; 0f94: 24          $
    jr z,noroom                                                       ; 0f95: 28 24       ($
    sbc hl,sp                                                         ; 0f97: ed 72       .r
    jr nc,noroom                                                      ; 0f99: 30 20       0
    pop hl                                                            ; 0f9b: e1          .
    ld (free),hl                                                      ; 0f9c: 22 e2 3f    ".?
; $0f9f referenced 1 time by $0fa7
dim2:
    ld a,d                                                            ; 0f9f: 7a          z
    or e                                                              ; 0fa0: b3          .
    jr z,dim5                                                         ; 0fa1: 28 06       (.
    dec hl                                                            ; 0fa3: 2b          +
    ld (hl),0                                                         ; 0fa4: 36 00       6.
    dec de                                                            ; 0fa6: 1b          .
    jr dim2                                                           ; 0fa7: 18 f6       ..

; $0fa9 referenced 1 time by $0fa1
dim5:
    call nxt                                                          ; 0fa9: cd a2 25    ..%
    cp $2c                                                            ; 0fac: fe 2c       .,
    jp nz,xeq_exec                                                    ; 0fae: c2 12 0e    ...
    inc iy                                                            ; 0fb1: fd 23       .#
    call nxt                                                          ; 0fb3: cd a2 25    ..%
    jr dim                                                            ; 0fb6: 18 80       ..

; $0fb8 referenced 5 times by $0f3b, $0f5f, $0fc1, $0fc3, $0fcd
baddim:
    ld a,$0a                                                          ; 0fb8: 3e 0a       >.
c0fba:
noroom equ c0fba+1
    ld hl,$0b3e                                                       ; 0fba: 21 3e 0b    !>.
; overlapping: ld a,$0b                                               ; 0fbb: 3e 0b       >.
; $0fbb referenced 5 times by $0f73, $0f8e, $0f91, $0f95, $0f99
error1_exec:
    jp error_main                                                     ; 0fbd: c3 05 08    ...

; $0fc0 referenced 2 times by $0f3d, $0f4c
dim4:
    or a                                                              ; 0fc0: b7          .
    jr z,baddim                                                       ; 0fc1: 28 f5       (.
    jp m,baddim                                                       ; 0fc3: fa b8 0f    ...
    ld b,a                                                            ; 0fc6: 47          G
    ld a,(iy-1)                                                       ; 0fc7: fd 7e ff    .~.
    cp $29                                                            ; 0fca: fe 29       .)
    ld a,b                                                            ; 0fcc: 78          x
    jr z,baddim                                                       ; 0fcd: 28 e9       (.
    ld hl,(free)                                                      ; 0fcf: 2a e2 3f    *.?
    exx                                                               ; 0fd2: d9          .
    ld hl,0                                                           ; 0fd3: 21 00 00    !..
    ld c,h                                                            ; 0fd6: 4c          L
    call store                                                        ; 0fd7: cd 88 16    ...
    call expri                                                        ; 0fda: cd be 1f    ...
    exx                                                               ; 0fdd: d9          .
    inc hl                                                            ; 0fde: 23          #
    ex de,hl                                                          ; 0fdf: eb          .
    ld hl,(free)                                                      ; 0fe0: 2a e2 3f    *.?
    jr dim3                                                           ; 0fe3: 18 ab       ..

print:
    cp $23                                                            ; 0fe5: fe 23       .#
    jr nz,print0                                                      ; 0fe7: 20 6b        k
    call chnl                                                         ; 0fe9: cd eb 18    ...
; $0fec referenced 2 times by $1019, $1032
prntn1:
    call nxt                                                          ; 0fec: cd a2 25    ..%
    cp $2c                                                            ; 0fef: fe 2c       .,
    jp nz,xeq_exec                                                    ; 0ff1: c2 12 0e    ...
    inc iy                                                            ; 0ff4: fd 23       .#
    push de                                                           ; 0ff6: d5          .
    call expr                                                         ; 0ff7: cd ae 1e    ...
    ex af,af'                                                         ; 0ffa: 08          .
    jp m,prntn2                                                       ; 0ffb: fa 1b 10    ...
    pop de                                                            ; 0ffe: d1          .
    push bc                                                           ; 0fff: c5          .
    exx                                                               ; 1000: d9          .
    ld a,l                                                            ; 1001: 7d          }
    exx                                                               ; 1002: d9          .
    call osbput                                                       ; 1003: cd 17 35    ..5
    exx                                                               ; 1006: d9          .
    ld a,h                                                            ; 1007: 7c          |
    exx                                                               ; 1008: d9          .
    call osbput                                                       ; 1009: cd 17 35    ..5
    ld a,l                                                            ; 100c: 7d          }
    call osbput                                                       ; 100d: cd 17 35    ..5
    ld a,h                                                            ; 1010: 7c          |
    call osbput                                                       ; 1011: cd 17 35    ..5
    pop bc                                                            ; 1014: c1          .
    ld a,c                                                            ; 1015: 79          y
    call osbput                                                       ; 1016: cd 17 35    ..5
    jr prntn1                                                         ; 1019: 18 d1       ..

; $101b referenced 1 time by $0ffb
prntn2:
    ld c,e                                                            ; 101b: 4b          K
    pop de                                                            ; 101c: d1          .
    ld hl,$3d00                                                       ; 101d: 21 00 3d    !.=
    inc c                                                             ; 1020: 0c          .
; $1021 referenced 1 time by $102b
prntn3:
    dec c                                                             ; 1021: 0d          .
    jr z,prntn4                                                       ; 1022: 28 09       (.
    ld a,(hl)                                                         ; 1024: 7e          ~
    inc hl                                                            ; 1025: 23          #
    push bc                                                           ; 1026: c5          .
    call osbput                                                       ; 1027: cd 17 35    ..5
    pop bc                                                            ; 102a: c1          .
    jr prntn3                                                         ; 102b: 18 f4       ..

; $102d referenced 1 time by $1022
prntn4:
    ld a,$0d                                                          ; 102d: 3e 0d       >.
    call osbput                                                       ; 102f: cd 17 35    ..5
    jr prntn1                                                         ; 1032: 18 b8       ..

; $1034 referenced 1 time by $1065
print6:
    ld b,2                                                            ; 1034: 06 02       ..
    jr printc                                                         ; 1036: 18 22       ."

; $1038 referenced 1 time by $1069
print8:
    ld bc,$0100                                                       ; 1038: 01 00 01    ...
    jr printc                                                         ; 103b: 18 1d       ..

; $103d referenced 1 time by $106d
print9:
    ld hl,$3f00                                                       ; 103d: 21 00 3f    !.?
    xor a                                                             ; 1040: af          .
    cp (hl)                                                           ; 1041: be          .
    jr z,print0                                                       ; 1042: 28 10       (.
    ld a,(count)                                                      ; 1044: 3a fb 3f    :.?
    or a                                                              ; 1047: b7          .
    jr z,print0                                                       ; 1048: 28 0a       (.
; $104a referenced 1 time by $104d
printa:
    sub (hl)                                                          ; 104a: 96          .
    jr z,print0                                                       ; 104b: 28 07       (.
    jr nc,printa                                                      ; 104d: 30 fb       0.
    neg                                                               ; 104f: ed 44       .D
    call fill_exec                                                    ; 1051: cd 54 18    .T.
; $1054 referenced 4 times by $0fe7, $1042, $1048, $104b
print0:
    ld a,(stavar)                                                     ; 1054: 3a 00 3f    :.?
    ld c,a                                                            ; 1057: 4f          O
    ld b,0                                                            ; 1058: 06 00       ..
; $105a referenced 4 times by $1036, $103b, $1072, $1095
printc:
    call termq                                                        ; 105a: cd ec 17    ...
    jr z,print4                                                       ; 105d: 28 38       (8
    res 0,b                                                           ; 105f: cb 80       ..
    inc iy                                                            ; 1061: fd 23       .#
    cp $7e                                                            ; 1063: fe 7e       .~
    jr z,print6                                                       ; 1065: 28 cd       (.
    cp $3b                                                            ; 1067: fe 3b       .;
    jr z,print8                                                       ; 1069: 28 cd       (.
    cp $2c                                                            ; 106b: fe 2c       .,
    jr z,print9                                                       ; 106d: 28 ce       (.
    call format                                                       ; 106f: cd 0d 18    ...
    jr z,printc                                                       ; 1072: 28 e6       (.
    dec iy                                                            ; 1074: fd 2b       .+
    push bc                                                           ; 1076: c5          .
    call expr                                                         ; 1077: cd ae 1e    ...
    ex af,af'                                                         ; 107a: 08          .
    jp m,print3                                                       ; 107b: fa 91 10    ...
    pop de                                                            ; 107e: d1          .
    push de                                                           ; 107f: d5          .
    bit 1,d                                                           ; 1080: cb 4a       .J
    push af                                                           ; 1082: f5          .
    call z,str_eval                                                   ; 1083: cc c0 24    ..$
    pop af                                                            ; 1086: f1          .
    call nz,hexstr                                                    ; 1087: c4 7d 24    .}$
    pop bc                                                            ; 108a: c1          .
    push bc                                                           ; 108b: c5          .
    ld a,c                                                            ; 108c: 79          y
    sub e                                                             ; 108d: 93          .
    call nc,fill_exec                                                 ; 108e: d4 54 18    .T.
; $1091 referenced 1 time by $107b
print3:
    pop bc                                                            ; 1091: c1          .
    call ptext_exec                                                   ; 1092: cd 62 18    .b.
    jr printc                                                         ; 1095: 18 c3       ..

; $1097 referenced 1 time by $105d
print4:
    bit 0,b                                                           ; 1097: cb 40       .@
    call z,crlf                                                       ; 1099: cc 97 09    ...
    jp xeq_exec                                                       ; 109c: c3 12 0e    ...

; $109f referenced 1 time by $10bc
onerr:
    inc iy                                                            ; 109f: fd 23       .#
    ld hl,0                                                           ; 10a1: 21 00 00    !..
    ld (errtrp),hl                                                    ; 10a4: 22 ec 3f    ".?
    call nxt                                                          ; 10a7: cd a2 25    ..%
    cp $87                                                            ; 10aa: fe 87       ..
    inc iy                                                            ; 10ac: fd 23       .#
    jp z,xeq_exec                                                     ; 10ae: ca 12 0e    ...
    dec iy                                                            ; 10b1: fd 2b       .+
    ld (errtrp),iy                                                    ; 10b3: fd 22 ec... .".
    jp rem                                                            ; 10b7: c3 8b 0e    ...

on:
    cp $85                                                            ; 10ba: fe 85       ..
    jr z,onerr                                                        ; 10bc: 28 e1       (.
    call expri                                                        ; 10be: cd be 1f    ...
    ld a,(iy+0)                                                       ; 10c1: fd 7e 00    .~.
    inc iy                                                            ; 10c4: fd 23       .#
    ld e,$2c                                                          ; 10c6: 1e 2c       .,
    cp $e5                                                            ; 10c8: fe e5       ..
    jr z,on1                                                          ; 10ca: 28 0b       (.
    cp $e4                                                            ; 10cc: fe e4       ..
    jr z,on1                                                          ; 10ce: 28 07       (.
    ld e,$f2                                                          ; 10d0: 1e f2       ..
    cp e                                                              ; 10d2: bb          .
    ld a,$27                                                          ; 10d3: 3e 27       >'
    jr nz,error2_exec                                                 ; 10d5: 20 41        A
; $10d7 referenced 2 times by $10ca, $10ce
on1:
    ld d,a                                                            ; 10d7: 57          W
    exx                                                               ; 10d8: d9          .
    push hl                                                           ; 10d9: e5          .
    exx                                                               ; 10da: d9          .
    pop bc                                                            ; 10db: c1          .
    ld a,b                                                            ; 10dc: 78          x
    or h                                                              ; 10dd: b4          .
    or l                                                              ; 10de: b5          .
    jr nz,on4                                                         ; 10df: 20 27        '
    or c                                                              ; 10e1: b1          .
    jr z,on4                                                          ; 10e2: 28 24       ($
    dec c                                                             ; 10e4: 0d          .
    jr z,on3                                                          ; 10e5: 28 0d       (.
; $10e7 referenced 2 times by $10ef, $10f2
on2:
    call termq                                                        ; 10e7: cd ec 17    ...
    jr z,on4                                                          ; 10ea: 28 1c       (.
    inc iy                                                            ; 10ec: fd 23       .#
    cp e                                                              ; 10ee: bb          .
    jr nz,on2                                                         ; 10ef: 20 f6        .
    dec c                                                             ; 10f1: 0d          .
    jr nz,on2                                                         ; 10f2: 20 f3        .
; $10f4 referenced 1 time by $10e5
on3:
    ld a,e                                                            ; 10f4: 7b          {
    cp $f2                                                            ; 10f5: fe f2       ..
    jr z,onproc                                                       ; 10f7: 28 22       ("
    push de                                                           ; 10f9: d5          .
    call itemi                                                        ; 10fa: cd d5 1f    ...
    pop de                                                            ; 10fd: d1          .
    ld a,d                                                            ; 10fe: 7a          z
    cp $e5                                                            ; 10ff: fe e5       ..
    jr z,goto2                                                        ; 1101: 28 26       (&
    call span                                                         ; 1103: cd f8 17    ...
    jr gosub1                                                         ; 1106: 18 32       .2

; $1108 referenced 4 times by $10df, $10e2, $10ea, $1114
on4:
    ld a,(iy+0)                                                       ; 1108: fd 7e 00    .~.
    inc iy                                                            ; 110b: fd 23       .#
    cp $8b                                                            ; 110d: fe 8b       ..
    jp z,if1                                                          ; 110f: ca b4 14    ...
    cp $0d                                                            ; 1112: fe 0d       ..
    jr nz,on4                                                         ; 1114: 20 f2        .
    ld a,$28                                                          ; 1116: 3e 28       >(
; $1118 referenced 6 times by $10d5, $1135, $1150, $1164, $117a, $1189
error2_exec:
    jp error_main                                                     ; 1118: c3 05 08    ...

; $111b referenced 1 time by $10f7
onproc:
    ld a,$ee                                                          ; 111b: 3e ee       >.
    jp fnchk                                                          ; 111d: c3 4a 12    .J.

; $1120 referenced 1 time by $14bc
goto:
    call itemi                                                        ; 1120: cd d5 1f    ...
; $1123 referenced 1 time by $113f
goto1:
    call termq                                                        ; 1123: cd ec 17    ...
    jp nz,syntax                                                      ; 1126: c2 e9 0e    ...
; $1129 referenced 1 time by $1101
goto2:
    exx                                                               ; 1129: d9          .
    call findl                                                        ; 112a: cd d5 09    ...
    push hl                                                           ; 112d: e5          .
    pop iy                                                            ; 112e: fd e1       ..
    jp z,xeq0_exec                                                    ; 1130: ca 0f 0e    ...
    ld a,$29                                                          ; 1133: 3e 29       >)
    jr error2_exec                                                    ; 1135: 18 e1       ..

gosub:
    call itemi                                                        ; 1137: cd d5 1f    ...
; $113a referenced 1 time by $1106
gosub1:
    push iy                                                           ; 113a: fd e5       ..
    call check                                                        ; 113c: cd e9 16    ...
    call goto1                                                        ; 113f: cd 23 11    .#.
goschk:
return:
    pop de                                                            ; 1142: d1          .
    ld hl,$1142                                                       ; 1143: 21 42 11    !B.
    or a                                                              ; 1146: b7          .
    sbc hl,de                                                         ; 1147: ed 52       .R
    pop iy                                                            ; 1149: fd e1       ..
    jp z,xeq_exec                                                     ; 114b: ca 12 0e    ...
    ld a,$26                                                          ; 114e: 3e 26       >&
    jr error2_exec                                                    ; 1150: 18 c6       ..

repeat:
    push iy                                                           ; 1152: fd e5       ..
    call check                                                        ; 1154: cd e9 16    ...
    call xeq_exec                                                     ; 1157: cd 12 0e    ...
repchk:
until:
    pop bc                                                            ; 115a: c1          .
    push bc                                                           ; 115b: c5          .
    ld hl,$115a                                                       ; 115c: 21 5a 11    !Z.
    or a                                                              ; 115f: b7          .
    sbc hl,bc                                                         ; 1160: ed 42       .B
    ld a,$2b                                                          ; 1162: 3e 2b       >+
    jr nz,error2_exec                                                 ; 1164: 20 b2        .
    call expri                                                        ; 1166: cd be 1f    ...
    call test_eval                                                    ; 1169: cd 49 24    .I$
    pop bc                                                            ; 116c: c1          .
    pop de                                                            ; 116d: d1          .
    jr nz,xeq2                                                        ; 116e: 20 05        .
    push de                                                           ; 1170: d5          .
    push bc                                                           ; 1171: c5          .
    push de                                                           ; 1172: d5          .
    pop iy                                                            ; 1173: fd e1       ..
; $1175 referenced 1 time by $116e
xeq2:
    jp xeq_exec                                                       ; 1175: c3 12 0e    ...

; $1178 referenced 1 time by $117f
forvar:
    ld a,$22                                                          ; 1178: 3e 22       >"
    jr error2_exec                                                    ; 117a: 18 9c       ..

for_exec:
    call assign                                                       ; 117c: cd 74 16    .t.
    jr nz,forvar                                                      ; 117f: 20 f7        .
    push af                                                           ; 1181: f5          .
    ld a,(iy+0)                                                       ; 1182: fd 7e 00    .~.
    cp $b8                                                            ; 1185: fe b8       ..
    ld a,$24                                                          ; 1187: 3e 24       >$
    jr nz,error2_exec                                                 ; 1189: 20 8d        .
    inc iy                                                            ; 118b: fd 23       .#
    push ix                                                           ; 118d: dd e5       ..
    call exprn                                                        ; 118f: cd b7 1f    ...
    pop ix                                                            ; 1192: dd e1       ..
    pop af                                                            ; 1194: f1          .
    ld b,a                                                            ; 1195: 47          G
    push bc                                                           ; 1196: c5          .
    push hl                                                           ; 1197: e5          .
    ld hl,0                                                           ; 1198: 21 00 00    !..
    ld c,h                                                            ; 119b: 4c          L
    exx                                                               ; 119c: d9          .
    push hl                                                           ; 119d: e5          .
    ld hl,1                                                           ; 119e: 21 01 00    !..
    exx                                                               ; 11a1: d9          .
    ld a,(iy+0)                                                       ; 11a2: fd 7e 00    .~.
    cp $88                                                            ; 11a5: fe 88       ..
    jr nz,for1                                                        ; 11a7: 20 09        .
    inc iy                                                            ; 11a9: fd 23       .#
    push ix                                                           ; 11ab: dd e5       ..
    call exprn                                                        ; 11ad: cd b7 1f    ...
    pop ix                                                            ; 11b0: dd e1       ..
; $11b2 referenced 1 time by $11a7
for1:
    push bc                                                           ; 11b2: c5          .
    push hl                                                           ; 11b3: e5          .
    exx                                                               ; 11b4: d9          .
    push hl                                                           ; 11b5: e5          .
    exx                                                               ; 11b6: d9          .
    push iy                                                           ; 11b7: fd e5       ..
    push ix                                                           ; 11b9: dd e5       ..
    call check                                                        ; 11bb: cd e9 16    ...
    call xeq_exec                                                     ; 11be: cd 12 0e    ...
; $11c1 referenced 1 time by $1224
forchk:
next:
    pop bc                                                            ; 11c1: c1          .
    ld hl,$11c1                                                       ; 11c2: 21 c1 11    !..
    or a                                                              ; 11c5: b7          .
    sbc hl,bc                                                         ; 11c6: ed 42       .B
    ld a,$20                                                          ; 11c8: 3e 20       >
    jr nz,error3_exec                                                 ; 11ca: 20 77        w
    call termq                                                        ; 11cc: cd ec 17    ...
    pop hl                                                            ; 11cf: e1          .
    push hl                                                           ; 11d0: e5          .
    push bc                                                           ; 11d1: c5          .
    push hl                                                           ; 11d2: e5          .
    call nz,getvar                                                    ; 11d3: c4 69 0a    .i.
    pop de                                                            ; 11d6: d1          .
    ex de,hl                                                          ; 11d7: eb          .
    or a                                                              ; 11d8: b7          .
; $11d9 referenced 1 time by $123f
next0:
    sbc hl,de                                                         ; 11d9: ed 52       .R
    jr nz,next1                                                       ; 11db: 20 54        T
    push de                                                           ; 11dd: d5          .
    ld ix,8                                                           ; 11de: dd 21 08... .!.
    add ix,sp                                                         ; 11e2: dd 39       .9
    call dload5_eval                                                  ; 11e4: cd ef 20    ..
    ld a,(ix+11)                                                      ; 11e7: dd 7e 0b    .~.
    pop ix                                                            ; 11ea: dd e1       ..
    call loadn                                                        ; 11ec: cd 77 20    .w
    bit 7,d                                                           ; 11ef: cb 7a       .z
    push af                                                           ; 11f1: f5          .
    ld a,$0b                                                          ; 11f2: 3e 0b       >.
    call fpp                                                          ; 11f4: cd c6 25    ..%
    jr c,error3_exec                                                  ; 11f7: 38 4a       8J
    pop af                                                            ; 11f9: f1          .
    push af                                                           ; 11fa: f5          .
    call store                                                        ; 11fb: cd 88 16    ...
    ld ix,$0e                                                         ; 11fe: dd 21 0e... .!.
    add ix,sp                                                         ; 1202: dd 39       .9
    call dload5_eval                                                  ; 1204: cd ef 20    ..
    pop af                                                            ; 1207: f1          .
    call z,swap_eval                                                  ; 1208: cc 41 24    .A$
    ld a,8                                                            ; 120b: 3e 08       >.
    call fpp                                                          ; 120d: cd c6 25    ..%
    jr c,error3_exec                                                  ; 1210: 38 31       81
    inc h                                                             ; 1212: 24          $
    jr nz,loop                                                        ; 1213: 20 11        .
    ld hl,$12                                                         ; 1215: 21 12 00    !..
    add hl,sp                                                         ; 1218: 39          9
    ld sp,hl                                                          ; 1219: f9          .
    call nxt                                                          ; 121a: cd a2 25    ..%
    cp $2c                                                            ; 121d: fe 2c       .,
    jp nz,xeq_exec                                                    ; 121f: c2 12 0e    ...
    inc iy                                                            ; 1222: fd 23       .#
    jr forchk                                                         ; 1224: 18 9b       ..

; $1226 referenced 1 time by $1213
loop:
    pop bc                                                            ; 1226: c1          .
    pop de                                                            ; 1227: d1          .
    pop iy                                                            ; 1228: fd e1       ..
    push iy                                                           ; 122a: fd e5       ..
    push de                                                           ; 122c: d5          .
    push bc                                                           ; 122d: c5          .
    jp xeq_exec                                                       ; 122e: c3 12 0e    ...

; $1231 referenced 1 time by $11db
next1:
    ld hl,$12                                                         ; 1231: 21 12 00    !..
    add hl,sp                                                         ; 1234: 39          9
    ld sp,hl                                                          ; 1235: f9          .
    pop bc                                                            ; 1236: c1          .
    ld hl,$11c1                                                       ; 1237: 21 c1 11    !..
    sbc hl,bc                                                         ; 123a: ed 42       .B
    pop hl                                                            ; 123c: e1          .
    push hl                                                           ; 123d: e5          .
    push bc                                                           ; 123e: c5          .
    jr z,next0                                                        ; 123f: 28 98       (.
    ld a,$21                                                          ; 1241: 3e 21       >!
; $1243 referenced 5 times by $11ca, $11f7, $1210, $125d, $1292
error3_exec:
    jp error_main                                                     ; 1243: c3 05 08    ...

fn:
    push af                                                           ; 1246: f5          .
    call proc1                                                        ; 1247: cd 4e 12    .N.
; $124a referenced 1 time by $111d
fnchk:
proc:
    push af                                                           ; 124a: f5          .
    call proc1                                                        ; 124b: cd 4e 12    .N.
; $124e referenced 2 times by $1247, $124b
proc1:
prochk:
    call check                                                        ; 124e: cd e9 16    ...
    dec iy                                                            ; 1251: fd 2b       .+
    push iy                                                           ; 1253: fd e5       ..
    call getdef                                                       ; 1255: cd 05 0b    ...
    pop bc                                                            ; 1258: c1          .
    jr z,proc4                                                        ; 1259: 28 39       (9
    ld a,$1e                                                          ; 125b: 3e 1e       >.
    jr c,error3_exec                                                  ; 125d: 38 e4       8.
    push bc                                                           ; 125f: c5          .
    ld hl,(page)                                                      ; 1260: 2a dc 3f    *.?
; $1263 referenced 1 time by $1289
proc2:
    ld a,$dd                                                          ; 1263: 3e dd       >.
    call search_exec                                                  ; 1265: cd aa 18    ...
    jr c,proc3                                                        ; 1268: 38 21       8!
    push hl                                                           ; 126a: e5          .
    pop iy                                                            ; 126b: fd e1       ..
    inc iy                                                            ; 126d: fd 23       .#
    call nxt                                                          ; 126f: cd a2 25    ..%
    call getdef                                                       ; 1272: cd 05 0b    ...
    push iy                                                           ; 1275: fd e5       ..
    pop de                                                            ; 1277: d1          .
    jr c,proc6                                                        ; 1278: 38 09       8.
    call nz,create_main                                               ; 127a: c4 a7 0b    ...
    push iy                                                           ; 127d: fd e5       ..
    pop de                                                            ; 127f: d1          .
    ld (hl),e                                                         ; 1280: 73          s
    inc hl                                                            ; 1281: 23          #
    ld (hl),d                                                         ; 1282: 72          r
; $1283 referenced 1 time by $1278
proc6:
    ex de,hl                                                          ; 1283: eb          .
    ld a,$0d                                                          ; 1284: 3e 0d       >.
    ld b,a                                                            ; 1286: 47          G
    cpir                                                              ; 1287: ed b1       ..
    jr proc2                                                          ; 1289: 18 d8       ..

; $128b referenced 1 time by $1268
proc3:
    pop iy                                                            ; 128b: fd e1       ..
    call getdef                                                       ; 128d: cd 05 0b    ...
    ld a,$1d                                                          ; 1290: 3e 1d       >.
    jr nz,error3_exec                                                 ; 1292: 20 af        .
; $1294 referenced 1 time by $1259
proc4:
    ld e,(hl)                                                         ; 1294: 5e          ^
    inc hl                                                            ; 1295: 23          #
    ld d,(hl)                                                         ; 1296: 56          V
    ld hl,2                                                           ; 1297: 21 02 00    !..
    add hl,sp                                                         ; 129a: 39          9
    call nxt                                                          ; 129b: cd a2 25    ..%
    push de                                                           ; 129e: d5          .
    ex (sp),iy                                                        ; 129f: fd e3       ..
    pop de                                                            ; 12a1: d1          .
    cp $28                                                            ; 12a2: fe 28       .(
    jr nz,proc5                                                       ; 12a4: 20 1b        .
    call nxt                                                          ; 12a6: cd a2 25    ..%
    cp $28                                                            ; 12a9: fe 28       .(
    jp nz,syntax                                                      ; 12ab: c2 e9 0e    ...
    push iy                                                           ; 12ae: fd e5       ..
    pop bc                                                            ; 12b0: c1          .
    exx                                                               ; 12b1: d9          .
    call savloc                                                       ; 12b2: cd 7a 17    .z.
    call braket                                                       ; 12b5: cd 66 25    .f%
    exx                                                               ; 12b8: d9          .
    push bc                                                           ; 12b9: c5          .
    pop iy                                                            ; 12ba: fd e1       ..
    push hl                                                           ; 12bc: e5          .
    call argue                                                        ; 12bd: cd 05 17    ...
    pop hl                                                            ; 12c0: e1          .
; $12c1 referenced 1 time by $12a4
proc5:
    ld (hl),e                                                         ; 12c1: 73          s
    inc hl                                                            ; 12c2: 23          #
    ld a,(hl)                                                         ; 12c3: 7e          ~
    ld (hl),d                                                         ; 12c4: 72          r
    cp $ee                                                            ; 12c5: fe ee       ..
    jp nz,xeq_exec                                                    ; 12c7: c2 12 0e    ...
    push de                                                           ; 12ca: d5          .
    ex (sp),iy                                                        ; 12cb: fd e3       ..
    call span                                                         ; 12cd: cd f8 17    ...
    ex (sp),iy                                                        ; 12d0: fd e3       ..
    pop de                                                            ; 12d2: d1          .
    ld (hl),d                                                         ; 12d3: 72          r
    dec hl                                                            ; 12d4: 2b          +
    ld (hl),e                                                         ; 12d5: 73          s
    jp xeq_exec                                                       ; 12d6: c3 12 0e    ...

local:
    pop bc                                                            ; 12d9: c1          .
    push bc                                                           ; 12da: c5          .
    ld hl,$124a                                                       ; 12db: 21 4a 12    !J.
    or a                                                              ; 12de: b7          .
    sbc hl,bc                                                         ; 12df: ed 42       .B
    jr z,local1                                                       ; 12e1: 28 13       (.
    ld hl,$124e                                                       ; 12e3: 21 4e 12    !N.
    or a                                                              ; 12e6: b7          .
    sbc hl,bc                                                         ; 12e7: ed 42       .B
    jr z,local1                                                       ; 12e9: 28 0b       (.
    ld hl,$17cc                                                       ; 12eb: 21 cc 17    !..
    or a                                                              ; 12ee: b7          .
    sbc hl,bc                                                         ; 12ef: ed 42       .B
    ld a,$0c                                                          ; 12f1: 3e 0c       >.
    jp nz,error_main                                                  ; 12f3: c2 05 08    ...
; $12f6 referenced 2 times by $12e1, $12e9
local1:
    push iy                                                           ; 12f6: fd e5       ..
    pop bc                                                            ; 12f8: c1          .
    exx                                                               ; 12f9: d9          .
    dec iy                                                            ; 12fa: fd 2b       .+
    call savloc                                                       ; 12fc: cd 7a 17    .z.
    exx                                                               ; 12ff: d9          .
    push bc                                                           ; 1300: c5          .
    pop iy                                                            ; 1301: fd e1       ..
; $1303 referenced 1 time by $1325
local2:
    call getvar                                                       ; 1303: cd 69 0a    .i.
    jp nz,syntax                                                      ; 1306: c2 e9 0e    ...
    or a                                                              ; 1309: b7          .
    ex af,af'                                                         ; 130a: 08          .
    call zero_eval                                                    ; 130b: cd e8 24    ..$
    ex af,af'                                                         ; 130e: 08          .
    push af                                                           ; 130f: f5          .
    call p,store                                                      ; 1310: f4 88 16    ...
    pop af                                                            ; 1313: f1          .
    ld e,c                                                            ; 1314: 59          Y
    call m,stores                                                     ; 1315: fc b4 16    ...
    call nxt                                                          ; 1318: cd a2 25    ..%
    cp $2c                                                            ; 131b: fe 2c       .,
    jp nz,xeq_exec                                                    ; 131d: c2 12 0e    ...
    inc iy                                                            ; 1320: fd 23       .#
    call nxt                                                          ; 1322: cd a2 25    ..%
    jr local2                                                         ; 1325: 18 dc       ..

; $1327 referenced 2 times by $134f, $135a
endpro:
    pop bc                                                            ; 1327: c1          .
    ld hl,$17cc                                                       ; 1328: 21 cc 17    !..
    or a                                                              ; 132b: b7          .
    sbc hl,bc                                                         ; 132c: ed 42       .B
    jr z,unstk                                                        ; 132e: 28 10       (.
    ld hl,$124e                                                       ; 1330: 21 4e 12    !N.
    or a                                                              ; 1333: b7          .
    sbc hl,bc                                                         ; 1334: ed 42       .B
    pop iy                                                            ; 1336: fd e1       ..
    jp z,xeq_exec                                                     ; 1338: ca 12 0e    ...
    ld a,$0d                                                          ; 133b: 3e 0d       >.
    jp error_main                                                     ; 133d: c3 05 08    ...

; $1340 referenced 1 time by $132e
unstk:
    pop ix                                                            ; 1340: dd e1       ..
    pop bc                                                            ; 1342: c1          .
    ld a,b                                                            ; 1343: 78          x
    or a                                                              ; 1344: b7          .
    jp m,unstk1                                                       ; 1345: fa 51 13    .Q.
    pop hl                                                            ; 1348: e1          .
    exx                                                               ; 1349: d9          .
    pop hl                                                            ; 134a: e1          .
    exx                                                               ; 134b: d9          .
    call store                                                        ; 134c: cd 88 16    ...
    jr endpro                                                         ; 134f: 18 d6       ..

; $1351 referenced 1 time by $1345
unstk1:
    ld hl,0                                                           ; 1351: 21 00 00    !..
    add hl,sp                                                         ; 1354: 39          9
    ld e,c                                                            ; 1355: 59          Y
    call stores                                                       ; 1356: cd b4 16    ...
    ld sp,hl                                                          ; 1359: f9          .
    jr endpro                                                         ; 135a: 18 cb       ..

; $135c referenced 2 times by $13b4, $1453
inputn:
    call chnl                                                         ; 135c: cd eb 18    ...
; $135f referenced 2 times by $1397, $13b0
inpn1:
    call nxt                                                          ; 135f: cd a2 25    ..%
    cp $2c                                                            ; 1362: fe 2c       .,
    jp nz,xeq_exec                                                    ; 1364: c2 12 0e    ...
    inc iy                                                            ; 1367: fd 23       .#
    call nxt                                                          ; 1369: cd a2 25    ..%
    push de                                                           ; 136c: d5          .
    call var                                                          ; 136d: cd e2 0e    ...
    pop de                                                            ; 1370: d1          .
    push af                                                           ; 1371: f5          .
    push hl                                                           ; 1372: e5          .
    or a                                                              ; 1373: b7          .
    jp m,inpn2                                                        ; 1374: fa 99 13    ...
    call osbget                                                       ; 1377: cd 34 35    .45
    exx                                                               ; 137a: d9          .
    ld l,a                                                            ; 137b: 6f          o
    exx                                                               ; 137c: d9          .
    call osbget                                                       ; 137d: cd 34 35    .45
    exx                                                               ; 1380: d9          .
    ld h,a                                                            ; 1381: 67          g
    exx                                                               ; 1382: d9          .
    call osbget                                                       ; 1383: cd 34 35    .45
    ld l,a                                                            ; 1386: 6f          o
    call osbget                                                       ; 1387: cd 34 35    .45
    ld h,a                                                            ; 138a: 67          g
    call osbget                                                       ; 138b: cd 34 35    .45
    ld c,a                                                            ; 138e: 4f          O
    pop ix                                                            ; 138f: dd e1       ..
    pop af                                                            ; 1391: f1          .
    push de                                                           ; 1392: d5          .
    call store                                                        ; 1393: cd 88 16    ...
    pop de                                                            ; 1396: d1          .
    jr inpn1                                                          ; 1397: 18 c6       ..

; $1399 referenced 1 time by $1374
inpn2:
    ld hl,$3d00                                                       ; 1399: 21 00 3d    !.=
; $139c referenced 1 time by $13a5
inpn3:
    call osbget                                                       ; 139c: cd 34 35    .45
    cp $0d                                                            ; 139f: fe 0d       ..
    jr z,inpn4                                                        ; 13a1: 28 04       (.
    ld (hl),a                                                         ; 13a3: 77          w
    inc l                                                             ; 13a4: 2c          ,
    jr nz,inpn3                                                       ; 13a5: 20 f5        .
; $13a7 referenced 1 time by $13a1
inpn4:
    pop ix                                                            ; 13a7: dd e1       ..
    pop af                                                            ; 13a9: f1          .
    push de                                                           ; 13aa: d5          .
    ex de,hl                                                          ; 13ab: eb          .
    call staccs                                                       ; 13ac: cd b1 16    ...
    pop de                                                            ; 13af: d1          .
    jr inpn1                                                          ; 13b0: 18 ad       ..

input:
    cp $23                                                            ; 13b2: fe 23       .#
    jr z,inputn                                                       ; 13b4: 28 a6       (.
    ld c,0                                                            ; 13b6: 0e 00       ..
    cp $86                                                            ; 13b8: fe 86       ..
    jr nz,input0                                                      ; 13ba: 20 04        .
    inc iy                                                            ; 13bc: fd 23       .#
    ld c,$80                                                          ; 13be: 0e 80       ..
; $13c0 referenced 2 times by $13ba, $13ec
input0:
    ld hl,$3e00                                                       ; 13c0: 21 00 3e    !.>
    ld (hl),$0d                                                       ; 13c3: 36 0d       6.
; $13c5 referenced 1 time by $1424
input1:
    call termq                                                        ; 13c5: cd ec 17    ...
    jp z,xeq_exec                                                     ; 13c8: ca 12 0e    ...
    inc iy                                                            ; 13cb: fd 23       .#
    cp $2c                                                            ; 13cd: fe 2c       .,
    jr z,input3                                                       ; 13cf: 28 51       (Q
    cp $3b                                                            ; 13d1: fe 3b       .;
    jr z,input3                                                       ; 13d3: 28 4d       (M
    push hl                                                           ; 13d5: e5          .
    cp $22                                                            ; 13d6: fe 22       ."
    jr nz,input6                                                      ; 13d8: 20 0a        .
    push bc                                                           ; 13da: c5          .
    call cons                                                         ; 13db: cd b9 20    ..
    pop bc                                                            ; 13de: c1          .
    call ptext_exec                                                   ; 13df: cd 62 18    .b.
    jr input9                                                         ; 13e2: 18 05       ..

; $13e4 referenced 1 time by $13d8
input6:
    call format                                                       ; 13e4: cd 0d 18    ...
    jr nz,input2                                                      ; 13e7: 20 05        .
; $13e9 referenced 1 time by $13e2
input9:
    pop hl                                                            ; 13e9: e1          .
    set 0,c                                                           ; 13ea: cb c1       ..
    jr input0                                                         ; 13ec: 18 d2       ..

; $13ee referenced 1 time by $13e7
input2:
    dec iy                                                            ; 13ee: fd 2b       .+
    push bc                                                           ; 13f0: c5          .
    call var                                                          ; 13f1: cd e2 0e    ...
    pop bc                                                            ; 13f4: c1          .
    pop hl                                                            ; 13f5: e1          .
    push af                                                           ; 13f6: f5          .
    ld a,(hl)                                                         ; 13f7: 7e          ~
    inc hl                                                            ; 13f8: 23          #
    cp $0d                                                            ; 13f9: fe 0d       ..
    call z,refill                                                     ; 13fb: cc 26 14    .&.
    bit 7,c                                                           ; 13fe: cb 79       .y
    push af                                                           ; 1400: f5          .
    call nz,lines                                                     ; 1401: c4 80 18    ...
    pop af                                                            ; 1404: f1          .
    call z,fetchs                                                     ; 1405: cc 6f 18    .o.
    pop af                                                            ; 1408: f1          .
    push bc                                                           ; 1409: c5          .
    push hl                                                           ; 140a: e5          .
    or a                                                              ; 140b: b7          .
    jp m,input4                                                       ; 140c: fa 1d 14    ...
    push af                                                           ; 140f: f5          .
    push ix                                                           ; 1410: dd e5       ..
    call val0                                                         ; 1412: cd 70 22    .p"
    pop ix                                                            ; 1415: dd e1       ..
    pop af                                                            ; 1417: f1          .
    call store                                                        ; 1418: cd 88 16    ...
    jr input5                                                         ; 141b: 18 03       ..

; $141d referenced 1 time by $140c
input4:
    call staccs                                                       ; 141d: cd b1 16    ...
; $1420 referenced 1 time by $141b
input5:
    pop hl                                                            ; 1420: e1          .
    pop bc                                                            ; 1421: c1          .
; $1422 referenced 2 times by $13cf, $13d3
input3:
    res 0,c                                                           ; 1422: cb 81       ..
    jr input1                                                         ; 1424: 18 9f       ..

; $1426 referenced 1 time by $13fb
refill:
    bit 0,c                                                           ; 1426: cb 41       .A
    jr nz,refil0                                                      ; 1428: 20 0a        .
    ld a,$3f                                                          ; 142a: 3e 3f       >?
    call outchr                                                       ; 142c: cd 9e 09    ...
    ld a,$20                                                          ; 142f: 3e 20       >
    call outchr                                                       ; 1431: cd 9e 09    ...
; $1434 referenced 1 time by $1428
refil0:
    ld hl,$3e00                                                       ; 1434: 21 00 3e    !.>
    push bc                                                           ; 1437: c5          .
    push hl                                                           ; 1438: e5          .
    push ix                                                           ; 1439: dd e5       ..
    call osline                                                       ; 143b: cd b7 3a    ..:
    pop ix                                                            ; 143e: dd e1       ..
    pop hl                                                            ; 1440: e1          .
    pop bc                                                            ; 1441: c1          .
    ld b,a                                                            ; 1442: 47          G
    xor a                                                             ; 1443: af          .
    ld (count),a                                                      ; 1444: 32 fb 3f    2.?
    cp b                                                              ; 1447: b8          .
    ret z                                                             ; 1448: c8          .
; $1449 referenced 1 time by $144e
refil1:
    ld a,(hl)                                                         ; 1449: 7e          ~
    cp $0d                                                            ; 144a: fe 0d       ..
    ret z                                                             ; 144c: c8          .
    inc hl                                                            ; 144d: 23          #
    djnz refil1                                                       ; 144e: 10 f9       ..
    ret                                                               ; 1450: c9          .

read_exec:
    cp $23                                                            ; 1451: fe 23       .#
    jp z,inputn                                                       ; 1453: ca 5c 13    .\.
    ld hl,(datptr)                                                    ; 1456: 2a f0 3f    *.?
; $1459 referenced 1 time by $1494
read0:
    ld a,(hl)                                                         ; 1459: 7e          ~
    inc hl                                                            ; 145a: 23          #
    cp $0d                                                            ; 145b: fe 0d       ..
    call z,getdat                                                     ; 145d: cc 96 14    ...
    push hl                                                           ; 1460: e5          .
    call var                                                          ; 1461: cd e2 0e    ...
    pop hl                                                            ; 1464: e1          .
    or a                                                              ; 1465: b7          .
    jp m,read1                                                        ; 1466: fa 7c 14    .|.
    push hl                                                           ; 1469: e5          .
    ex (sp),iy                                                        ; 146a: fd e3       ..
    push af                                                           ; 146c: f5          .
    push ix                                                           ; 146d: dd e5       ..
    call exprn                                                        ; 146f: cd b7 1f    ...
    pop ix                                                            ; 1472: dd e1       ..
    pop af                                                            ; 1474: f1          .
    call store                                                        ; 1475: cd 88 16    ...
    ex (sp),iy                                                        ; 1478: fd e3       ..
    jr read2                                                          ; 147a: 18 07       ..

; $147c referenced 1 time by $1466
read1:
    call fetchs                                                       ; 147c: cd 6f 18    .o.
    push hl                                                           ; 147f: e5          .
    call staccs                                                       ; 1480: cd b1 16    ...
; $1483 referenced 1 time by $147a
read2:
    pop hl                                                            ; 1483: e1          .
    ld (datptr),hl                                                    ; 1484: 22 f0 3f    ".?
    call nxt                                                          ; 1487: cd a2 25    ..%
    cp $2c                                                            ; 148a: fe 2c       .,
    jp nz,xeq_exec                                                    ; 148c: c2 12 0e    ...
    inc iy                                                            ; 148f: fd 23       .#
    call nxt                                                          ; 1491: cd a2 25    ..%
    jr read0                                                          ; 1494: 18 c3       ..

; $1496 referenced 1 time by $145d
getdat:
    ld a,$dc                                                          ; 1496: 3e dc       >.
    call search_exec                                                  ; 1498: cd aa 18    ...
    inc hl                                                            ; 149b: 23          #
    ret nc                                                            ; 149c: d0          .
    ld a,$2a                                                          ; 149d: 3e 2a       >*
; $149f referenced 1 time by $150b
error4:
    jp error_main                                                     ; 149f: c3 05 08    ...

if:
    call expri                                                        ; 14a2: cd be 1f    ...
    call test_eval                                                    ; 14a5: cd 49 24    .I$
    jr z,ifnot                                                        ; 14a8: 28 15       (.
    ld a,(iy+0)                                                       ; 14aa: fd 7e 00    .~.
    cp $8c                                                            ; 14ad: fe 8c       ..
    jp nz,xeq_exec                                                    ; 14af: c2 12 0e    ...
    inc iy                                                            ; 14b2: fd 23       .#
; $14b4 referenced 2 times by $110f, $14cd
if1:
    call nxt                                                          ; 14b4: cd a2 25    ..%
    cp $8d                                                            ; 14b7: fe 8d       ..
    jp nz,xeq_exec                                                    ; 14b9: c2 12 0e    ...
    jp goto                                                           ; 14bc: c3 20 11    . .

; $14bf referenced 2 times by $14a8, $14cb
ifnot:
    ld a,(iy+0)                                                       ; 14bf: fd 7e 00    .~.
    cp $0d                                                            ; 14c2: fe 0d       ..
    inc iy                                                            ; 14c4: fd 23       .#
    jp z,xeq0_exec                                                    ; 14c6: ca 0f 0e    ...
    cp $8b                                                            ; 14c9: fe 8b       ..
    jr nz,ifnot                                                       ; 14cb: 20 f2        .
    jr if1                                                            ; 14cd: 18 e5       ..

cls:
    call clrscn                                                       ; 14cf: cd c0 31    ..1
    xor a                                                             ; 14d2: af          .
    ld (count),a                                                      ; 14d3: 32 fb 3f    2.?
    jp xeq_exec                                                       ; 14d6: c3 12 0e    ...

stop_exec:
    call tell                                                         ; 14d9: cd 55 0d    .U.
    db $0d, $0a, $fa, 0                                               ; 14dc: 0d 0a fa... ...

    call setlin                                                       ; 14e0: cd ee 09    ...
    call sayln                                                        ; 14e3: cd 18 0a    ...
    call crlf                                                         ; 14e6: cd 97 09    ...
    jp cloop                                                          ; 14e9: c3 99 01    ...

repor:
    call report                                                       ; 14ec: cd 49 0d    .I.
    jp xeq_exec                                                       ; 14ef: c3 12 0e    ...

clr:
    call clear                                                        ; 14f2: cd f6 08    ...
    ld hl,(page)                                                      ; 14f5: 2a dc 3f    *.?
    jr restr1                                                         ; 14f8: 18 13       ..

restor:
    ld hl,(page)                                                      ; 14fa: 2a dc 3f    *.?
    call termq                                                        ; 14fd: cd ec 17    ...
    jr z,restr1                                                       ; 1500: 28 0b       (.
    call itemi                                                        ; 1502: cd d5 1f    ...
    exx                                                               ; 1505: d9          .
    call findl                                                        ; 1506: cd d5 09    ...
    ld a,$29                                                          ; 1509: 3e 29       >)
    jr nz,error4                                                      ; 150b: 20 92        .
; $150d referenced 2 times by $14f8, $1500
restr1:
    ld a,$dc                                                          ; 150d: 3e dc       >.
    call search_exec                                                  ; 150f: cd aa 18    ...
    ld (datptr),hl                                                    ; 1512: 22 f0 3f    ".?
    jp xeq_exec                                                       ; 1515: c3 12 0e    ...

ptr_exec:
    call chanel                                                       ; 1518: cd e1 18    ...
    call equals                                                       ; 151b: cd 00 18    ...
    ld a,e                                                            ; 151e: 7b          {
    push af                                                           ; 151f: f5          .
    call expri                                                        ; 1520: cd be 1f    ...
    push hl                                                           ; 1523: e5          .
    exx                                                               ; 1524: d9          .
    pop de                                                            ; 1525: d1          .
    pop af                                                            ; 1526: f1          .
    call putptr                                                       ; 1527: cd 84 35    ..5
    jp xeq_exec                                                       ; 152a: c3 12 0e    ...

pagev_exec:
    call equals                                                       ; 152d: cd 00 18    ...
    call expri                                                        ; 1530: cd be 1f    ...
    exx                                                               ; 1533: d9          .
    ld l,0                                                            ; 1534: 2e 00       ..
    ld (page),hl                                                      ; 1536: 22 dc 3f    ".?
    jp xeq_exec                                                       ; 1539: c3 12 0e    ...

timev_exec:
    cp $24                                                            ; 153c: fe 24       .$
    jr z,timevs_exec                                                  ; 153e: 28 0f       (.
    call equals                                                       ; 1540: cd 00 18    ...
    call expri                                                        ; 1543: cd be 1f    ...
    push hl                                                           ; 1546: e5          .
    exx                                                               ; 1547: d9          .
    pop de                                                            ; 1548: d1          .
    call putime                                                       ; 1549: cd 12 32    ..2
    jp xeq_exec                                                       ; 154c: c3 12 0e    ...

; $154f referenced 1 time by $153e
timevs_exec:
    inc iy                                                            ; 154f: fd 23       .#
    call equals                                                       ; 1551: cd 00 18    ...
    call exprs                                                        ; 1554: cd c7 1f    ...
    call adval                                                        ; 1557: cd aa 32    ..2
    jp xeq_exec                                                       ; 155a: c3 12 0e    ...

lomemv_exec:
    call equals                                                       ; 155d: cd 00 18    ...
    call expri                                                        ; 1560: cd be 1f    ...
    call clear                                                        ; 1563: cd f6 08    ...
    exx                                                               ; 1566: d9          .
    ld (lomem),hl                                                     ; 1567: 22 e0 3f    ".?
    ld (free),hl                                                      ; 156a: 22 e2 3f    ".?
    jp xeq_exec                                                       ; 156d: c3 12 0e    ...

himemv_exec:
    call equals                                                       ; 1570: cd 00 18    ...
    call expri                                                        ; 1573: cd be 1f    ...
    exx                                                               ; 1576: d9          .
    ld de,(free)                                                      ; 1577: ed 5b e2... .[.
    inc d                                                             ; 157b: 14          .
    xor a                                                             ; 157c: af          .
    sbc hl,de                                                         ; 157d: ed 52       .R
    add hl,de                                                         ; 157f: 19          .
    jp c,error_main                                                   ; 1580: da 05 08    ...
    ld de,(himem)                                                     ; 1583: ed 5b e4... .[.
    ld (himem),hl                                                     ; 1587: 22 e4 3f    ".?
    ex de,hl                                                          ; 158a: eb          .
    sbc hl,sp                                                         ; 158b: ed 72       .r
    jp nz,xeq_exec                                                    ; 158d: c2 12 0e    ...
    ex de,hl                                                          ; 1590: eb          .
    ld sp,hl                                                          ; 1591: f9          .
    jp xeq_exec                                                       ; 1592: c3 12 0e    ...

widthv:
    call expri                                                        ; 1595: cd be 1f    ...
    exx                                                               ; 1598: d9          .
    ld a,l                                                            ; 1599: 7d          }
    ld (width),a                                                      ; 159a: 32 fc 3f    2.?
    jp xeq_exec                                                       ; 159d: c3 12 0e    ...

trace:
    inc iy                                                            ; 15a0: fd 23       .#
    ld hl,0                                                           ; 15a2: 21 00 00    !..
    cp $ee                                                            ; 15a5: fe ee       ..
    jr z,trace0                                                       ; 15a7: 28 0a       (.
    cp $87                                                            ; 15a9: fe 87       ..
    jr z,trace1                                                       ; 15ab: 28 07       (.
    dec iy                                                            ; 15ad: fd 2b       .+
    call expri                                                        ; 15af: cd be 1f    ...
    exx                                                               ; 15b2: d9          .
; $15b3 referenced 1 time by $15a7
trace0:
    dec hl                                                            ; 15b3: 2b          +
; $15b4 referenced 1 time by $15ab
trace1:
    ld (tracen),hl                                                    ; 15b4: 22 e8 3f    ".?
    jp xeq_exec                                                       ; 15b7: c3 12 0e    ...

; $15ba referenced 1 time by $15d6
vdu:
    call expri                                                        ; 15ba: cd be 1f    ...
    exx                                                               ; 15bd: d9          .
    ld a,l                                                            ; 15be: 7d          }
    call oswrch                                                       ; 15bf: cd 5c 3a    .\:
    ld a,(iy+0)                                                       ; 15c2: fd 7e 00    .~.
    cp $2c                                                            ; 15c5: fe 2c       .,
    jr z,vdu2                                                         ; 15c7: 28 08       (.
    cp $3b                                                            ; 15c9: fe 3b       .;
    jr nz,vdu3                                                        ; 15cb: 20 06        .
    ld a,h                                                            ; 15cd: 7c          |
    call oswrch                                                       ; 15ce: cd 5c 3a    .\:
; $15d1 referenced 1 time by $15c7
vdu2:
    inc iy                                                            ; 15d1: fd 23       .#
; $15d3 referenced 1 time by $15cb
vdu3:
    call termq                                                        ; 15d3: cd ec 17    ...
    jr nz,vdu                                                         ; 15d6: 20 e2        .
    jp xeq_exec                                                       ; 15d8: c3 12 0e    ...

close_exec:
    call chanel                                                       ; 15db: cd e1 18    ...
    call osshut                                                       ; 15de: cd 26 34    .&4
    jp xeq_exec                                                       ; 15e1: c3 12 0e    ...

bput:
    call chanel                                                       ; 15e4: cd e1 18    ...
    push de                                                           ; 15e7: d5          .
    call comma                                                        ; 15e8: cd 5a 25    .Z%
    call expri                                                        ; 15eb: cd be 1f    ...
    exx                                                               ; 15ee: d9          .
    ld a,l                                                            ; 15ef: 7d          }
    pop de                                                            ; 15f0: d1          .
    call osbput                                                       ; 15f1: cd 17 35    ..5
    jp xeq_exec                                                       ; 15f4: c3 12 0e    ...

call:
    call expri                                                        ; 15f7: cd be 1f    ...
    exx                                                               ; 15fa: d9          .
    push hl                                                           ; 15fb: e5          .
    ld b,0                                                            ; 15fc: 06 00       ..
    ld de,$3e00                                                       ; 15fe: 11 00 3e    ..>
; $1601 referenced 1 time by $161d
call1:
    call nxt                                                          ; 1601: cd a2 25    ..%
    cp $2c                                                            ; 1604: fe 2c       .,
    jr nz,call2                                                       ; 1606: 20 17        .
    inc iy                                                            ; 1608: fd 23       .#
    inc b                                                             ; 160a: 04          .
    call nxt                                                          ; 160b: cd a2 25    ..%
    push bc                                                           ; 160e: c5          .
    push de                                                           ; 160f: d5          .
    call var                                                          ; 1610: cd e2 0e    ...
    pop de                                                            ; 1613: d1          .
    pop bc                                                            ; 1614: c1          .
    inc de                                                            ; 1615: 13          .
    ld (de),a                                                         ; 1616: 12          .
    inc de                                                            ; 1617: 13          .
    ex de,hl                                                          ; 1618: eb          .
    ld (hl),e                                                         ; 1619: 73          s
    inc hl                                                            ; 161a: 23          #
    ld (hl),d                                                         ; 161b: 72          r
    ex de,hl                                                          ; 161c: eb          .
    jr call1                                                          ; 161d: 18 e2       ..

; $161f referenced 1 time by $1606
call2:
    ld a,b                                                            ; 161f: 78          x
    ld (buffer),a                                                     ; 1620: 32 00 3e    2.>
    pop hl                                                            ; 1623: e1          .
    call usr1                                                         ; 1624: cd 2e 16    ...
    jp xeq_exec                                                       ; 1627: c3 12 0e    ...

usr:
    call itemi                                                        ; 162a: cd d5 1f    ...
    exx                                                               ; 162d: d9          .
; $162e referenced 1 time by $1624
usr1:
    push hl                                                           ; 162e: e5          .
    ex (sp),iy                                                        ; 162f: fd e3       ..
    inc h                                                             ; 1631: 24          $
    ld hl,usr2                                                        ; 1632: 21 5d 16    !].
    push hl                                                           ; 1635: e5          .
    ld ix,$3f00                                                       ; 1636: dd 21 00... .!.
    call z,oscall                                                     ; 163a: cc bb 34    ..4
    ld c,(ix+24)                                                      ; 163d: dd 4e 18    .N.
    push bc                                                           ; 1640: c5          .
    pop af                                                            ; 1641: f1          .
    ld a,(ix+4)                                                       ; 1642: dd 7e 04    .~.
    ld b,(ix+8)                                                       ; 1645: dd 46 08    .F.
    ld c,(ix+12)                                                      ; 1648: dd 4e 0c    .N.
    ld d,(ix+16)                                                      ; 164b: dd 56 10    .V.
    ld e,(ix+20)                                                      ; 164e: dd 5e 14    .^.
    ld h,(ix+32)                                                      ; 1651: dd 66 20    .f
    ld l,(ix+48)                                                      ; 1654: dd 6e 30    .n0
    ld ix,$3e00                                                       ; 1657: dd 21 00... .!.
    jp (iy)                                                           ; 165b: fd e9       ..

usr2:
    pop iy                                                            ; 165d: fd e1       ..
    xor a                                                             ; 165f: af          .
    ld c,a                                                            ; 1660: 4f          O
    ret                                                               ; 1661: c9          .

put:
    call expri                                                        ; 1662: cd be 1f    ...
    exx                                                               ; 1665: d9          .
    push hl                                                           ; 1666: e5          .
    call comma                                                        ; 1667: cd 5a 25    .Z%
    call expri                                                        ; 166a: cd be 1f    ...
    exx                                                               ; 166d: d9          .
    pop bc                                                            ; 166e: c1          .
    out (c),l                                                         ; 166f: ed 69       .i
    jp xeq_exec                                                       ; 1671: c3 12 0e    ...

; $1674 referenced 2 times by $0eab, $117c
assign:
    call getvar                                                       ; 1674: cd 69 0a    .i.
    ret c                                                             ; 1677: d8          .
    call nz,putvar                                                    ; 1678: c4 5a 0a    .Z.
    or a                                                              ; 167b: b7          .
    ret m                                                             ; 167c: f8          .
    push af                                                           ; 167d: f5          .
    call equals                                                       ; 167e: cd 00 18    ...
    push hl                                                           ; 1681: e5          .
    call exprn                                                        ; 1682: cd b7 1f    ...
    pop ix                                                            ; 1685: dd e1       ..
    pop af                                                            ; 1687: f1          .
; $1688 referenced 10 times by $0f26, $0fd7, $11fb, $1310, $134c, $1393, $1418, $1475, $176b, $19bc
store:
    bit 0,a                                                           ; 1688: cb 47       .G
    jr z,storei                                                       ; 168a: 28 13       (.
    cp a                                                              ; 168c: bf          .
; $168d referenced 1 time by $22c8
store5:
    ld (ix+4),c                                                       ; 168d: dd 71 04    .q.
; $1690 referenced 2 times by $16a8, $16d7
store4:
    exx                                                               ; 1690: d9          .
    ld (ix+0),l                                                       ; 1691: dd 75 00    .u.
    ld (ix+1),h                                                       ; 1694: dd 74 01    .t.
    exx                                                               ; 1697: d9          .
    ld (ix+2),l                                                       ; 1698: dd 75 02    .u.
    ld (ix+3),h                                                       ; 169b: dd 74 03    .t.
    ret                                                               ; 169e: c9          .

; $169f referenced 1 time by $168a
storei:
    push af                                                           ; 169f: f5          .
    inc c                                                             ; 16a0: 0c          .
    dec c                                                             ; 16a1: 0d          .
    call nz,sfix_eval                                                 ; 16a2: c4 65 22    .e"
    pop af                                                            ; 16a5: f1          .
    cp 4                                                              ; 16a6: fe 04       ..
    jr z,store4                                                       ; 16a8: 28 e6       (.
    cp a                                                              ; 16aa: bf          .
store1:
    exx                                                               ; 16ab: d9          .
    ld (ix+0),l                                                       ; 16ac: dd 75 00    .u.
    exx                                                               ; 16af: d9          .
    ret                                                               ; 16b0: c9          .

; $16b1 referenced 5 times by $0ebe, $13ac, $141d, $1480, $1775
staccs:
    ld hl,$3d00                                                       ; 16b1: 21 00 3d    !.=
; $16b4 referenced 3 times by $0f31, $1315, $1356
stores:
    rra                                                               ; 16b4: 1f          .
    jr nc,stors3                                                      ; 16b5: 30 3f       0?
    push hl                                                           ; 16b7: e5          .
    call load4                                                        ; 16b8: cd 83 20    ..
    ld a,e                                                            ; 16bb: 7b          {
    exx                                                               ; 16bc: d9          .
    ld l,a                                                            ; 16bd: 6f          o
    ld a,h                                                            ; 16be: 7c          |
    exx                                                               ; 16bf: d9          .
    cp e                                                              ; 16c0: bb          .
    jr nc,stors1                                                      ; 16c1: 30 14       0.
    exx                                                               ; 16c3: d9          .
    ld h,l                                                            ; 16c4: 65          e
    exx                                                               ; 16c5: d9          .
    push hl                                                           ; 16c6: e5          .
    ld b,0                                                            ; 16c7: 06 00       ..
    ld c,a                                                            ; 16c9: 4f          O
    add hl,bc                                                         ; 16ca: 09          .
    ld bc,(free)                                                      ; 16cb: ed 4b e2... .K.
    sbc hl,bc                                                         ; 16cf: ed 42       .B
    pop hl                                                            ; 16d1: e1          .
    scf                                                               ; 16d2: 37          7
    jr z,stors1                                                       ; 16d3: 28 02       (.
    ld h,b                                                            ; 16d5: 60          `
    ld l,c                                                            ; 16d6: 69          i
; $16d7 referenced 2 times by $16c1, $16d3
stors1:
    call store4                                                       ; 16d7: cd 90 16    ...
    ld b,0                                                            ; 16da: 06 00       ..
    ld c,e                                                            ; 16dc: 4b          K
    ex de,hl                                                          ; 16dd: eb          .
    pop hl                                                            ; 16de: e1          .
    dec c                                                             ; 16df: 0d          .
    inc c                                                             ; 16e0: 0c          .
    ret z                                                             ; 16e1: c8          .
    ldir                                                              ; 16e2: ed b0       ..
    ret nc                                                            ; 16e4: d0          .
    ld (free),de                                                      ; 16e5: ed 53 e2... .S.
; $16e9 referenced 12 times by $0be5, $113c, $1154, $11bb, $124e, $172e, $17ae, $17cc, $203a, $2509, $2523, $3514
check:
    push hl                                                           ; 16e9: e5          .
    ld hl,(free)                                                      ; 16ea: 2a e2 3f    *.?
    inc h                                                             ; 16ed: 24          $
    sbc hl,sp                                                         ; 16ee: ed 72       .r
    pop hl                                                            ; 16f0: e1          .
    ret c                                                             ; 16f1: d8          .
    xor a                                                             ; 16f2: af          .
    jp error_main                                                     ; 16f3: c3 05 08    ...

; $16f6 referenced 1 time by $16b5
stors3:
    ld c,e                                                            ; 16f6: 4b          K
    push ix                                                           ; 16f7: dd e5       ..
    pop de                                                            ; 16f9: d1          .
    xor a                                                             ; 16fa: af          .
    ld b,a                                                            ; 16fb: 47          G
    cp c                                                              ; 16fc: b9          .
    jr z,stors5                                                       ; 16fd: 28 02       (.
    ldir                                                              ; 16ff: ed b0       ..
; $1701 referenced 1 time by $16fd
stors5:
    ld a,$0d                                                          ; 1701: 3e 0d       >.
    ld (de),a                                                         ; 1703: 12          .
    ret                                                               ; 1704: c9          .

; $1705 referenced 1 time by $12bd
argue:
    ld a,$ff                                                          ; 1705: 3e ff       >.
    push af                                                           ; 1707: f5          .
; $1708 referenced 1 time by $174a
argue1:
    inc iy                                                            ; 1708: fd 23       .#
    inc de                                                            ; 170a: 13          .
    push de                                                           ; 170b: d5          .
    call nxt                                                          ; 170c: cd a2 25    ..%
    call getvar                                                       ; 170f: cd 69 0a    .i.
    jr c,argerr                                                       ; 1712: 38 38       88
    call nz,putvar                                                    ; 1714: c4 5a 0a    .Z.
    pop de                                                            ; 1717: d1          .
    push hl                                                           ; 1718: e5          .
    or a                                                              ; 1719: b7          .
    push af                                                           ; 171a: f5          .
    push de                                                           ; 171b: d5          .
    ex (sp),iy                                                        ; 171c: fd e3       ..
    jp m,argue2                                                       ; 171e: fa 33 17    .3.
    call exprn                                                        ; 1721: cd b7 1f    ...
    ex (sp),iy                                                        ; 1724: fd e3       ..
    pop de                                                            ; 1726: d1          .
    pop af                                                            ; 1727: f1          .
    exx                                                               ; 1728: d9          .
    push hl                                                           ; 1729: e5          .
    exx                                                               ; 172a: d9          .
    push hl                                                           ; 172b: e5          .
    ld b,a                                                            ; 172c: 47          G
    push bc                                                           ; 172d: c5          .
    call check                                                        ; 172e: cd e9 16    ...
    jr argue4                                                         ; 1731: 18 0d       ..

; $1733 referenced 1 time by $171e
argue2:
    call exprs                                                        ; 1733: cd c7 1f    ...
    ex (sp),iy                                                        ; 1736: fd e3       ..
    exx                                                               ; 1738: d9          .
    pop de                                                            ; 1739: d1          .
    exx                                                               ; 173a: d9          .
    pop af                                                            ; 173b: f1          .
    call pushs                                                        ; 173c: cd 09 25    ..%
    exx                                                               ; 173f: d9          .
; $1740 referenced 1 time by $1731
argue4:
    call nxt                                                          ; 1740: cd a2 25    ..%
    cp $2c                                                            ; 1743: fe 2c       .,
    jr nz,argue5                                                      ; 1745: 20 0a        .
    ld a,(de)                                                         ; 1747: 1a          .
    cp $2c                                                            ; 1748: fe 2c       .,
    jr z,argue1                                                       ; 174a: 28 bc       (.
; $174c referenced 2 times by $1712, $1757
argerr:
    ld a,$1f                                                          ; 174c: 3e 1f       >.
    jp error_main                                                     ; 174e: c3 05 08    ...

; $1751 referenced 1 time by $1745
argue5:
    call braket                                                       ; 1751: cd 66 25    .f%
    ld a,(de)                                                         ; 1754: 1a          .
    cp $29                                                            ; 1755: fe 29       .)
    jr nz,argerr                                                      ; 1757: 20 f3        .
    inc de                                                            ; 1759: 13          .
    exx                                                               ; 175a: d9          .
; $175b referenced 2 times by $176e, $1778
argue6:
    pop bc                                                            ; 175b: c1          .
    ld a,b                                                            ; 175c: 78          x
    inc a                                                             ; 175d: 3c          <
    exx                                                               ; 175e: d9          .
    ret z                                                             ; 175f: c8          .
    exx                                                               ; 1760: d9          .
    dec a                                                             ; 1761: 3d          =
    jp m,argue7                                                       ; 1762: fa 70 17    .p.
    pop hl                                                            ; 1765: e1          .
    exx                                                               ; 1766: d9          .
    pop hl                                                            ; 1767: e1          .
    exx                                                               ; 1768: d9          .
    pop ix                                                            ; 1769: dd e1       ..
    call store                                                        ; 176b: cd 88 16    ...
    jr argue6                                                         ; 176e: 18 eb       ..

; $1770 referenced 1 time by $1762
argue7:
    call pops                                                         ; 1770: cd 28 25    .(%
    pop ix                                                            ; 1773: dd e1       ..
    call staccs                                                       ; 1775: cd b1 16    ...
    jr argue6                                                         ; 1778: 18 e1       ..

; $177a referenced 2 times by $12b2, $12fc
savloc:
    pop de                                                            ; 177a: d1          .
; $177b referenced 1 time by $17d4
savlo1_exec:
    inc iy                                                            ; 177b: fd 23       .#
    call nxt                                                          ; 177d: cd a2 25    ..%
    push de                                                           ; 1780: d5          .
    exx                                                               ; 1781: d9          .
    push bc                                                           ; 1782: c5          .
    push de                                                           ; 1783: d5          .
    push hl                                                           ; 1784: e5          .
    exx                                                               ; 1785: d9          .
    call var                                                          ; 1786: cd e2 0e    ...
    exx                                                               ; 1789: d9          .
    pop hl                                                            ; 178a: e1          .
    pop de                                                            ; 178b: d1          .
    pop bc                                                            ; 178c: c1          .
    exx                                                               ; 178d: d9          .
    pop de                                                            ; 178e: d1          .
    or a                                                              ; 178f: b7          .
    jp m,savlo2                                                       ; 1790: fa a1 17    ...
    exx                                                               ; 1793: d9          .
    push hl                                                           ; 1794: e5          .
    exx                                                               ; 1795: d9          .
    ld b,a                                                            ; 1796: 47          G
    call loadn                                                        ; 1797: cd 77 20    .w
    exx                                                               ; 179a: d9          .
    ex (sp),hl                                                        ; 179b: e3          .
    exx                                                               ; 179c: d9          .
    push hl                                                           ; 179d: e5          .
    push bc                                                           ; 179e: c5          .
    jr savlo4                                                         ; 179f: 18 26       .&

; $17a1 referenced 1 time by $1790
savlo2:
    push af                                                           ; 17a1: f5          .
    push de                                                           ; 17a2: d5          .
    exx                                                               ; 17a3: d9          .
    push hl                                                           ; 17a4: e5          .
    exx                                                               ; 17a5: d9          .
    call loads                                                        ; 17a6: cd 01 21    ..!
    exx                                                               ; 17a9: d9          .
    pop hl                                                            ; 17aa: e1          .
    exx                                                               ; 17ab: d9          .
    ld c,e                                                            ; 17ac: 4b          K
    pop de                                                            ; 17ad: d1          .
    call check                                                        ; 17ae: cd e9 16    ...
    pop af                                                            ; 17b1: f1          .
    ld hl,0                                                           ; 17b2: 21 00 00    !..
    ld b,l                                                            ; 17b5: 45          E
    sbc hl,bc                                                         ; 17b6: ed 42       .B
    add hl,sp                                                         ; 17b8: 39          9
    ld sp,hl                                                          ; 17b9: f9          .
    ld b,a                                                            ; 17ba: 47          G
    push bc                                                           ; 17bb: c5          .
    jr z,savlo4                                                       ; 17bc: 28 09       (.
    push de                                                           ; 17be: d5          .
    ld de,$3d00                                                       ; 17bf: 11 00 3d    ..=
    ex de,hl                                                          ; 17c2: eb          .
    ld b,l                                                            ; 17c3: 45          E
    ldir                                                              ; 17c4: ed b0       ..
    pop de                                                            ; 17c6: d1          .
; $17c7 referenced 2 times by $179f, $17bc
savlo4:
    push ix                                                           ; 17c7: dd e5       ..
    call locchk                                                       ; 17c9: cd cc 17    ...
; $17cc referenced 1 time by $17c9
locchk:
savlo5:
    call check                                                        ; 17cc: cd e9 16    ...
    call nxt                                                          ; 17cf: cd a2 25    ..%
    cp $2c                                                            ; 17d2: fe 2c       .,
    jr z,savlo1_exec                                                  ; 17d4: 28 a5       (.
    ex de,hl                                                          ; 17d6: eb          .
    jp (hl)                                                           ; 17d7: e9          .

; $17d8 referenced 2 times by $1c5c, $1c69
delim:
    ld a,(iy+0)                                                       ; 17d8: fd 7e 00    .~.
    cp $20                                                            ; 17db: fe 20       .
    ret z                                                             ; 17dd: c8          .
    cp $2c                                                            ; 17de: fe 2c       .,
    ret z                                                             ; 17e0: c8          .
    cp $29                                                            ; 17e1: fe 29       .)
    ret z                                                             ; 17e3: c8          .
; $17e4 referenced 1 time by $1c6d
term:
    cp $3b                                                            ; 17e4: fe 3b       .;
    ret z                                                             ; 17e6: c8          .
    cp $5c                                                            ; 17e7: fe 5c       .\
    ret z                                                             ; 17e9: c8          .
    jr term0                                                          ; 17ea: 18 06       ..

; $17ec referenced 11 times by $0c1e, $0c3c, $0dcf, $105a, $10e7, $1123, $11cc, $13c5, $14fd, $15d3, $17f8
termq:
    call nxt                                                          ; 17ec: cd a2 25    ..%
    cp $8b                                                            ; 17ef: fe 8b       ..
    ret nc                                                            ; 17f1: d0          .
; $17f2 referenced 2 times by $17ea, $1929
term0:
    cp $3a                                                            ; 17f2: fe 3a       .:
    ret nc                                                            ; 17f4: d0          .
    cp $0d                                                            ; 17f5: fe 0d       ..
    ret                                                               ; 17f7: c9          .

; $17f8 referenced 3 times by $1103, $12cd, $17fe
span:
    call termq                                                        ; 17f8: cd ec 17    ...
    ret z                                                             ; 17fb: c8          .
    inc iy                                                            ; 17fc: fd 23       .#
    jr span                                                           ; 17fe: 18 f8       ..

; $1800 referenced 8 times by $0eb4, $151b, $152d, $1540, $1551, $155d, $1570, $167e
equals:
    call nxt                                                          ; 1800: cd a2 25    ..%
    inc iy                                                            ; 1803: fd 23       .#
    cp $3d                                                            ; 1805: fe 3d       .=
    ret z                                                             ; 1807: c8          .
    ld a,4                                                            ; 1808: 3e 04       >.
    jp error_main                                                     ; 180a: c3 05 08    ...

; $180d referenced 2 times by $106f, $13e4
format:
    cp $8a                                                            ; 180d: fe 8a       ..
    jr z,dotab                                                        ; 180f: 28 0c       (.
    cp $89                                                            ; 1811: fe 89       ..
    jr z,dospc                                                        ; 1813: 28 38       (8
    cp $27                                                            ; 1815: fe 27       .'
    ret nz                                                            ; 1817: c0          .
    call crlf                                                         ; 1818: cd 97 09    ...
    xor a                                                             ; 181b: af          .
    ret                                                               ; 181c: c9          .

; $181d referenced 1 time by $180f
dotab:
    push bc                                                           ; 181d: c5          .
    call expri                                                        ; 181e: cd be 1f    ...
    exx                                                               ; 1821: d9          .
    pop bc                                                            ; 1822: c1          .
    ld a,(iy+0)                                                       ; 1823: fd 7e 00    .~.
    cp $2c                                                            ; 1826: fe 2c       .,
    jr z,dotab1                                                       ; 1828: 28 11       (.
    call braket                                                       ; 182a: cd 66 25    .f%
    ld a,l                                                            ; 182d: 7d          }
; $182e referenced 2 times by $1966, $1976
tabit:
    ld hl,$3ffb                                                       ; 182e: 21 fb 3f    !.?
    cp (hl)                                                           ; 1831: be          .
    ret z                                                             ; 1832: c8          .
    push af                                                           ; 1833: f5          .
    call c,crlf                                                       ; 1834: dc 97 09    ...
    pop af                                                            ; 1837: f1          .
    sub (hl)                                                          ; 1838: 96          .
    jr fill_exec                                                      ; 1839: 18 19       ..

; $183b referenced 1 time by $1828
dotab1:
    inc iy                                                            ; 183b: fd 23       .#
    push bc                                                           ; 183d: c5          .
    push hl                                                           ; 183e: e5          .
    call expri                                                        ; 183f: cd be 1f    ...
    exx                                                               ; 1842: d9          .
    pop de                                                            ; 1843: d1          .
    pop bc                                                            ; 1844: c1          .
    call braket                                                       ; 1845: cd 66 25    .f%
    call putcsr                                                       ; 1848: cd da 31    ..1
    xor a                                                             ; 184b: af          .
    ret                                                               ; 184c: c9          .

; $184d referenced 1 time by $1813
dospc:
    push bc                                                           ; 184d: c5          .
    call itemi                                                        ; 184e: cd d5 1f    ...
    exx                                                               ; 1851: d9          .
    ld a,l                                                            ; 1852: 7d          }
    pop bc                                                            ; 1853: c1          .
; $1854 referenced 5 times by $0931, $093a, $1051, $108e, $1839
fill_exec:
    or a                                                              ; 1854: b7          .
    ret z                                                             ; 1855: c8          .
    push bc                                                           ; 1856: c5          .
    ld b,a                                                            ; 1857: 47          G
; $1858 referenced 1 time by $185d
fill1:
    ld a,$20                                                          ; 1858: 3e 20       >
    call outchr                                                       ; 185a: cd 9e 09    ...
    djnz fill1                                                        ; 185d: 10 f9       ..
    pop bc                                                            ; 185f: c1          .
    xor a                                                             ; 1860: af          .
    ret                                                               ; 1861: c9          .

; $1862 referenced 2 times by $1092, $13df
ptext_exec:
    ld hl,$3d00                                                       ; 1862: 21 00 3d    !.=
    inc e                                                             ; 1865: 1c          .
; $1866 referenced 1 time by $186d
ptext1:
    dec e                                                             ; 1866: 1d          .
    ret z                                                             ; 1867: c8          .
    ld a,(hl)                                                         ; 1868: 7e          ~
    inc hl                                                            ; 1869: 23          #
    call outchr                                                       ; 186a: cd 9e 09    ...
    jr ptext1                                                         ; 186d: 18 f7       ..

; $186f referenced 2 times by $1405, $147c
fetchs:
    push af                                                           ; 186f: f5          .
    push bc                                                           ; 1870: c5          .
    push hl                                                           ; 1871: e5          .
    ex (sp),iy                                                        ; 1872: fd e3       ..
    call xtract                                                       ; 1874: cd 8c 18    ...
    call nxt                                                          ; 1877: cd a2 25    ..%
    ex (sp),iy                                                        ; 187a: fd e3       ..
    pop hl                                                            ; 187c: e1          .
    pop bc                                                            ; 187d: c1          .
    pop af                                                            ; 187e: f1          .
    ret                                                               ; 187f: c9          .

; $1880 referenced 1 time by $1401
lines:
    ld de,$3d00                                                       ; 1880: 11 00 3d    ..=
; $1883 referenced 1 time by $188a
line1s:
    ld a,(hl)                                                         ; 1883: 7e          ~
    ld (de),a                                                         ; 1884: 12          .
    cp $0d                                                            ; 1885: fe 0d       ..
    ret z                                                             ; 1887: c8          .
    inc hl                                                            ; 1888: 23          #
    inc e                                                             ; 1889: 1c          .
    jr line1s                                                         ; 188a: 18 f7       ..

; $188c referenced 1 time by $1874
xtract:
    call nxt                                                          ; 188c: cd a2 25    ..%
    cp $22                                                            ; 188f: fe 22       ."
    inc iy                                                            ; 1891: fd 23       .#
    jp z,cons                                                         ; 1893: ca b9 20    ..
    dec iy                                                            ; 1896: fd 2b       .+
    ld de,$3d00                                                       ; 1898: 11 00 3d    ..=
; $189b referenced 1 time by $18a8
xtrac1:
    ld a,(iy+0)                                                       ; 189b: fd 7e 00    .~.
    ld (de),a                                                         ; 189e: 12          .
    cp $2c                                                            ; 189f: fe 2c       .,
    ret z                                                             ; 18a1: c8          .
    cp $0d                                                            ; 18a2: fe 0d       ..
    ret z                                                             ; 18a4: c8          .
    inc iy                                                            ; 18a5: fd 23       .#
    inc e                                                             ; 18a7: 1c          .
    jr xtrac1                                                         ; 18a8: 18 f1       ..

; $18aa referenced 4 times by $0e05, $1265, $1498, $150f
search_exec:
    ld b,0                                                            ; 18aa: 06 00       ..
; $18ac referenced 1 time by $18ba
srch1_exec:
    ld c,(hl)                                                         ; 18ac: 4e          N
    inc c                                                             ; 18ad: 0c          .
    dec c                                                             ; 18ae: 0d          .
    jr z,srch2_exec                                                   ; 18af: 28 0c       (.
    inc hl                                                            ; 18b1: 23          #
    inc hl                                                            ; 18b2: 23          #
    inc hl                                                            ; 18b3: 23          #
    cp (hl)                                                           ; 18b4: be          .
    ret z                                                             ; 18b5: c8          .
    dec c                                                             ; 18b6: 0d          .
    dec c                                                             ; 18b7: 0d          .
    dec c                                                             ; 18b8: 0d          .
    add hl,bc                                                         ; 18b9: 09          .
    jp srch1_exec                                                     ; 18ba: c3 ac 18    ...

; $18bd referenced 1 time by $18af
srch2_exec:
    dec hl                                                            ; 18bd: 2b          +
    scf                                                               ; 18be: 37          7
    ret                                                               ; 18bf: c9          .

; $18c0 referenced 2 times by $0abb, $0f8a
x4or5:
    cp 5                                                              ; 18c0: fe 05       ..
    ld h,d                                                            ; 18c2: 62          b
    ld l,e                                                            ; 18c3: 6b          k
    add hl,hl                                                         ; 18c4: 29          )
    ret c                                                             ; 18c5: d8          .
    add hl,hl                                                         ; 18c6: 29          )
    ret c                                                             ; 18c7: d8          .
    ex de,hl                                                          ; 18c8: eb          .
    ret nz                                                            ; 18c9: c0          .
    add hl,de                                                         ; 18ca: 19          .
    ex de,hl                                                          ; 18cb: eb          .
    ret                                                               ; 18cc: c9          .

; $18cd referenced 2 times by $0aa4, $0f70
mul16:
    ex de,hl                                                          ; 18cd: eb          .
    ld hl,0                                                           ; 18ce: 21 00 00    !..
    ld a,$10                                                          ; 18d1: 3e 10       >.
; $18d3 referenced 1 time by $18de
mul161:
    add hl,hl                                                         ; 18d3: 29          )
    ret c                                                             ; 18d4: d8          .
    sla e                                                             ; 18d5: cb 23       .#
    rl d                                                              ; 18d7: cb 12       ..
    jr nc,mul162                                                      ; 18d9: 30 02       0.
    add hl,bc                                                         ; 18db: 09          .
    ret c                                                             ; 18dc: d8          .
; $18dd referenced 1 time by $18d9
mul162:
    dec a                                                             ; 18dd: 3d          =
    jr nz,mul161                                                      ; 18de: 20 f3        .
    ret                                                               ; 18e0: c9          .

; $18e1 referenced 7 times by $1518, $15db, $15e4, $212e, $213a, $21be, $21c6
chanel:
    call nxt                                                          ; 18e1: cd a2 25    ..%
    cp $23                                                            ; 18e4: fe 23       .#
    ld a,$2d                                                          ; 18e6: 3e 2d       >-
    jp nz,error_main                                                  ; 18e8: c2 05 08    ...
; $18eb referenced 2 times by $0fe9, $135c
chnl:
    inc iy                                                            ; 18eb: fd 23       .#
    call itemi                                                        ; 18ed: cd d5 1f    ...
    exx                                                               ; 18f0: d9          .
    ex de,hl                                                          ; 18f1: eb          .
    ret                                                               ; 18f2: c9          .

; $18f3 referenced 4 times by $0ece, $18fa, $1951, $1989
assem:
    call skip                                                         ; 18f3: cd 69 1c    .i.
    inc iy                                                            ; 18f6: fd 23       .#
    cp $3a                                                            ; 18f8: fe 3a       .:
    jr z,assem                                                        ; 18fa: 28 f7       (.
    cp $5d                                                            ; 18fc: fe 5d       .]
    ret z                                                             ; 18fe: c8          .
    cp $0d                                                            ; 18ff: fe 0d       ..
    ret z                                                             ; 1901: c8          .
    dec iy                                                            ; 1902: fd 2b       .+
    ld ix,(pc)                                                        ; 1904: dd 2a 40... .*@
    ld hl,$3ffe                                                       ; 1908: 21 fe 3f    !.?
    bit 6,(hl)                                                        ; 190b: cb 76       .v
    jr z,assem0                                                       ; 190d: 28 04       (.
    ld ix,(oc)                                                        ; 190f: dd 2a 3c... .*<
; $1913 referenced 1 time by $190d
assem0:
    push ix                                                           ; 1913: dd e5       ..
    push iy                                                           ; 1915: fd e5       ..
    call asmb                                                         ; 1917: cd a7 19    ...
    pop bc                                                            ; 191a: c1          .
    pop de                                                            ; 191b: d1          .
    ret c                                                             ; 191c: d8          .
    call skip                                                         ; 191d: cd 69 1c    .i.
    scf                                                               ; 1920: 37          7
    ret nz                                                            ; 1921: c0          .
    dec iy                                                            ; 1922: fd 2b       .+
; $1924 referenced 1 time by $192c
assem3:
    inc iy                                                            ; 1924: fd 23       .#
    ld a,(iy+0)                                                       ; 1926: fd 7e 00    .~.
    call term0                                                        ; 1929: cd f2 17    ...
    jr nz,assem3                                                      ; 192c: 20 f6        .
    ld a,(liston)                                                     ; 192e: 3a fe 3f    :.?
    push ix                                                           ; 1931: dd e5       ..
    pop hl                                                            ; 1933: e1          .
    or a                                                              ; 1934: b7          .
    sbc hl,de                                                         ; 1935: ed 52       .R
    ex de,hl                                                          ; 1937: eb          .
    push hl                                                           ; 1938: e5          .
    ld hl,(pc)                                                        ; 1939: 2a 40 3f    *@?
    push hl                                                           ; 193c: e5          .
    add hl,de                                                         ; 193d: 19          .
    ld (pc),hl                                                        ; 193e: 22 40 3f    "@?
    bit 6,a                                                           ; 1941: cb 77       .w
    jr z,assem5                                                       ; 1943: 28 07       (.
    ld hl,(oc)                                                        ; 1945: 2a 3c 3f    *<?
    add hl,de                                                         ; 1948: 19          .
    ld (oc),hl                                                        ; 1949: 22 3c 3f    "<?
; $194c referenced 1 time by $1943
assem5:
    pop hl                                                            ; 194c: e1          .
    pop ix                                                            ; 194d: dd e1       ..
    bit 4,a                                                           ; 194f: cb 67       .g
    jr z,assem                                                        ; 1951: 28 a0       (.
    ld a,h                                                            ; 1953: 7c          |
    call hex_exec                                                     ; 1954: cd 93 19    ...
    ld a,l                                                            ; 1957: 7d          }
    call hexsp                                                        ; 1958: cd 8c 19    ...
    xor a                                                             ; 195b: af          .
    cp e                                                              ; 195c: bb          .
    jr z,assem2                                                       ; 195d: 28 15       (.
; $195f referenced 1 time by $1972
assem1:
    ld a,(count)                                                      ; 195f: 3a fb 3f    :.?
    cp $11                                                            ; 1962: fe 11       ..
    ld a,5                                                            ; 1964: 3e 05       >.
    call nc,tabit                                                     ; 1966: d4 2e 18    ...
    ld a,(ix+0)                                                       ; 1969: dd 7e 00    .~.
    call hexsp                                                        ; 196c: cd 8c 19    ...
    inc ix                                                            ; 196f: dd 23       .#
    dec e                                                             ; 1971: 1d          .
    jr nz,assem1                                                      ; 1972: 20 eb        .
; $1974 referenced 1 time by $195d
assem2:
    ld a,$12                                                          ; 1974: 3e 12       >.
    call tabit                                                        ; 1976: cd 2e 18    ...
    push iy                                                           ; 1979: fd e5       ..
    pop hl                                                            ; 197b: e1          .
    sbc hl,bc                                                         ; 197c: ed 42       .B
; $197e referenced 1 time by $1984
assem4:
    ld a,(bc)                                                         ; 197e: 0a          .
    call out                                                          ; 197f: cd b7 09    ...
    inc bc                                                            ; 1982: 03          .
    dec l                                                             ; 1983: 2d          -
    jr nz,assem4                                                      ; 1984: 20 f8        .
    call crlf                                                         ; 1986: cd 97 09    ...
    jp assem                                                          ; 1989: c3 f3 18    ...

; $198c referenced 2 times by $1958, $196c
hexsp:
    call hex_exec                                                     ; 198c: cd 93 19    ...
    ld a,$20                                                          ; 198f: 3e 20       >
    jr outch1                                                         ; 1991: 18 11       ..

; $1993 referenced 2 times by $1954, $198c
hex_exec:
    push af                                                           ; 1993: f5          .
    rrca                                                              ; 1994: 0f          .
    rrca                                                              ; 1995: 0f          .
    rrca                                                              ; 1996: 0f          .
    rrca                                                              ; 1997: 0f          .
    call hexout                                                       ; 1998: cd 9c 19    ...
    pop af                                                            ; 199b: f1          .
; $199c referenced 1 time by $1998
hexout:
    and $0f                                                           ; 199c: e6 0f       ..
    add a,$90                                                         ; 199e: c6 90       ..
    daa                                                               ; 19a0: 27          '
    adc a,$40                                                         ; 19a1: ce 40       .@
    daa                                                               ; 19a3: 27          '
; $19a4 referenced 1 time by $1991
outch1:
    jp out                                                            ; 19a4: c3 b7 09    ...

; $19a7 referenced 1 time by $1917
asmb:
    cp $2e                                                            ; 19a7: fe 2e       ..
    jr nz,asmb1                                                       ; 19a9: 20 16        .
    inc iy                                                            ; 19ab: fd 23       .#
    push ix                                                           ; 19ad: dd e5       ..
    call var                                                          ; 19af: cd e2 0e    ...
    push af                                                           ; 19b2: f5          .
    call zero_eval                                                    ; 19b3: cd e8 24    ..$
    exx                                                               ; 19b6: d9          .
    ld hl,(pc)                                                        ; 19b7: 2a 40 3f    *@?
    exx                                                               ; 19ba: d9          .
    pop af                                                            ; 19bb: f1          .
    call store                                                        ; 19bc: cd 88 16    ...
    pop ix                                                            ; 19bf: dd e1       ..
; $19c1 referenced 1 time by $19a9
asmb1:
    call skip                                                         ; 19c1: cd 69 1c    .i.
    ret z                                                             ; 19c4: c8          .
    cp $d6                                                            ; 19c5: fe d6       ..
    ld c,$c4                                                          ; 19c7: 0e c4       ..
    inc iy                                                            ; 19c9: fd 23       .#
    jp z,grpc                                                         ; 19cb: ca b8 1a    ...
    dec iy                                                            ; 19ce: fd 2b       .+
    ld hl,$1c7b                                                       ; 19d0: 21 7b 1c    !{.
    call find_exec                                                    ; 19d3: cd 20 1c    . .
    ret c                                                             ; 19d6: d8          .
    ld c,b                                                            ; 19d7: 48          H
    ld d,0                                                            ; 19d8: 16 00       ..
    sub $27                                                           ; 19da: d6 27       .'
    jr nc,group2                                                      ; 19dc: 30 07       0.
    cp $e8                                                            ; 19de: fe e8       ..
    call nc,ed                                                        ; 19e0: d4 86 1b    ...
    jr byte0                                                          ; 19e3: 18 68       .h

; $19e5 referenced 1 time by $19dc
group2:
    sub $0a                                                           ; 19e5: d6 0a       ..
    jr nc,group4                                                      ; 19e7: 30 0f       0.
    cp $f9                                                            ; 19e9: fe f9       ..
    call c,bit                                                        ; 19eb: dc 10 1c    ...
    ret c                                                             ; 19ee: d8          .
    call reglo                                                        ; 19ef: cd e5 1b    ...
    ret c                                                             ; 19f2: d8          .
    call cb                                                           ; 19f3: cd 8a 1b    ...
    jr byte0                                                          ; 19f6: 18 55       .U

; $19f8 referenced 1 time by $19e7
group4:
    sub 3                                                             ; 19f8: d6 03       ..
    jr nc,group5                                                      ; 19fa: 30 06       0.
; $19fc referenced 2 times by $1a2d, $1a36
g4:
    call pair_exec                                                    ; 19fc: cd 04 1c    ...
    ret c                                                             ; 19ff: d8          .
    jr byte0                                                          ; 1a00: 18 4b       .K

; $1a02 referenced 1 time by $19fa
group5:
    sub $0a                                                           ; 1a02: d6 0a       ..
    jr nc,group7                                                      ; 1a04: 30 32       02
    cp $fd                                                            ; 1a06: fe fd       ..
    ld b,7                                                            ; 1a08: 06 07       ..
    call nc,opnd                                                      ; 1a0a: d4 98 1b    ...
    ld a,b                                                            ; 1a0d: 78          x
    cp 7                                                              ; 1a0e: fe 07       ..
    jr nz,g6hl                                                        ; 1a10: 20 10        .
; $1a12 referenced 1 time by $1af0
g6:
    call reglo                                                        ; 1a12: cd e5 1b    ...
    ld a,c                                                            ; 1a15: 79          y
    jr nc,bind1                                                       ; 1a16: 30 28       0(
    xor $46                                                           ; 1a18: ee 46       .F
    call bind                                                         ; 1a1a: cd 8c 1b    ...
; $1a1d referenced 1 time by $1b31
db:
    call number_exec                                                  ; 1a1d: cd c8 1b    ...
    jr val8                                                           ; 1a20: 18 78       .x

; $1a22 referenced 1 time by $1a10
g6hl:
    and $3f                                                           ; 1a22: e6 3f       .?
    cp $0c                                                            ; 1a24: fe 0c       ..
    scf                                                               ; 1a26: 37          7
    ret nz                                                            ; 1a27: c0          .
    ld a,c                                                            ; 1a28: 79          y
    cp $80                                                            ; 1a29: fe 80       ..
    ld c,9                                                            ; 1a2b: 0e 09       ..
    jr z,g4                                                           ; 1a2d: 28 cd       (.
    xor $1c                                                           ; 1a2f: ee 1c       ..
    rrca                                                              ; 1a31: 0f          .
    ld c,a                                                            ; 1a32: 4f          O
    call ed                                                           ; 1a33: cd 86 1b    ...
    jr g4                                                             ; 1a36: 18 c4       ..

; $1a38 referenced 1 time by $1a04
group7:
    sub 2                                                             ; 1a38: d6 02       ..
    jr nc,group8                                                      ; 1a3a: 30 14       0.
    call reghi                                                        ; 1a3c: cd eb 1b    ...
    ld a,c                                                            ; 1a3f: 79          y
; $1a40 referenced 1 time by $1a16
bind1:
    jp nc,bind                                                        ; 1a40: d2 8c 1b    ...
    xor $64                                                           ; 1a43: ee 64       .d
    rlca                                                              ; 1a45: 07          .
    rlca                                                              ; 1a46: 07          .
    rlca                                                              ; 1a47: 07          .
    ld c,a                                                            ; 1a48: 4f          O
    call pair1_exec                                                   ; 1a49: cd 08 1c    ...
    ret c                                                             ; 1a4c: d8          .
; $1a4d referenced 4 times by $19e3, $19f6, $1a00, $1a63
byte0:
    ld a,c                                                            ; 1a4d: 79          y
    jr byte2                                                          ; 1a4e: 18 7f       ..

; $1a50 referenced 1 time by $1a3a
group8:
    sub 2                                                             ; 1a50: d6 02       ..
    jr nc,groupa                                                      ; 1a52: 30 21       0!
    cp $ff                                                            ; 1a54: fe ff       ..
    call z,corn                                                       ; 1a56: cc 7b 1b    .{.
    ex af,af'                                                         ; 1a59: 08          .
    call reghi                                                        ; 1a5a: cd eb 1b    ...
    ret c                                                             ; 1a5d: d8          .
    ex af,af'                                                         ; 1a5e: 08          .
    call c,corn                                                       ; 1a5f: dc 7b 1b    .{.
    inc h                                                             ; 1a62: 24          $
    jr z,byte0                                                        ; 1a63: 28 e8       (.
    ld a,b                                                            ; 1a65: 78          x
    cp 7                                                              ; 1a66: fe 07       ..
    scf                                                               ; 1a68: 37          7
    ret nz                                                            ; 1a69: c0          .
    ld a,c                                                            ; 1a6a: 79          y
    xor 3                                                             ; 1a6b: ee 03       ..
    rlca                                                              ; 1a6d: 07          .
    rlca                                                              ; 1a6e: 07          .
    rlca                                                              ; 1a6f: 07          .
    call byte                                                         ; 1a70: cd b8 1b    ...
    jr val8                                                           ; 1a73: 18 25       .%

; $1a75 referenced 1 time by $1a52
groupa:
    sub 2                                                             ; 1a75: d6 02       ..
    jr nc,groupb                                                      ; 1a77: 30 24       0$
    cp $ff                                                            ; 1a79: fe ff       ..
    call nz,cond                                                      ; 1a7b: c4 f1 1b    ...
    ld a,c                                                            ; 1a7e: 79          y
    jr nc,grpa                                                        ; 1a7f: 30 02       0.
    ld a,$18                                                          ; 1a81: 3e 18       >.
; $1a83 referenced 1 time by $1a7f
grpa:
    call byte                                                         ; 1a83: cd b8 1b    ...
    call number_exec                                                  ; 1a86: cd c8 1b    ...
    ld de,(pc)                                                        ; 1a89: ed 5b 40... .[@
    inc de                                                            ; 1a8d: 13          .
    scf                                                               ; 1a8e: 37          7
    sbc hl,de                                                         ; 1a8f: ed 52       .R
    ld a,l                                                            ; 1a91: 7d          }
    rla                                                               ; 1a92: 17          .
    sbc a,a                                                           ; 1a93: 9f          .
    cp h                                                              ; 1a94: bc          .
; $1a95 referenced 1 time by $1acb
toofar:
    ld a,1                                                            ; 1a95: 3e 01       >.
    jp nz,error_main                                                  ; 1a97: c2 05 08    ...
; $1a9a referenced 3 times by $1a20, $1a73, $1abe
val8:
    ld a,l                                                            ; 1a9a: 7d          }
    jr byte2                                                          ; 1a9b: 18 32       .2

; $1a9d referenced 1 time by $1a77
groupb:
    ld b,a                                                            ; 1a9d: 47          G
    jr nz,groupc                                                      ; 1a9e: 20 16        .
    call cond                                                         ; 1aa0: cd f1 1b    ...
    ld a,c                                                            ; 1aa3: 79          y
    jr nc,grpb                                                        ; 1aa4: 30 0b       0.
    ld a,b                                                            ; 1aa6: 78          x
    and $3f                                                           ; 1aa7: e6 3f       .?
    cp 6                                                              ; 1aa9: fe 06       ..
    ld a,$e9                                                          ; 1aab: 3e e9       >.
    jr z,byte2                                                        ; 1aad: 28 20       (
    ld a,$c3                                                          ; 1aaf: 3e c3       >.
; $1ab1 referenced 3 times by $1aa4, $1b06, $1b1d
grpb:
    call byte                                                         ; 1ab1: cd b8 1b    ...
    jr addr                                                           ; 1ab4: 18 05       ..

; $1ab6 referenced 1 time by $1a9e
groupc:
    djnz groupd                                                       ; 1ab6: 10 0c       ..
; $1ab8 referenced 1 time by $19cb
grpc:
    call grpe                                                         ; 1ab8: cd d3 1a    ...
; $1abb referenced 2 times by $1ab4, $1b34
addr:
    call number_exec                                                  ; 1abb: cd c8 1b    ...
; $1abe referenced 1 time by $1b2e
val16:
    call val8                                                         ; 1abe: cd 9a 1a    ...
    ld a,h                                                            ; 1ac1: 7c          |
    jr byte2                                                          ; 1ac2: 18 0b       ..

; $1ac4 referenced 1 time by $1ab6
groupd:
    djnz groupe                                                       ; 1ac4: 10 0b       ..
    call number_exec                                                  ; 1ac6: cd c8 1b    ...
    and c                                                             ; 1ac9: a1          .
    or h                                                              ; 1aca: b4          .
    jr nz,toofar                                                      ; 1acb: 20 c8        .
    ld a,l                                                            ; 1acd: 7d          }
    or c                                                              ; 1ace: b1          .
; $1acf referenced 4 times by $1a4e, $1a9b, $1aad, $1ac2
byte2:
    jr byte1                                                          ; 1acf: 18 78       .x

; $1ad1 referenced 1 time by $1ac4
groupe:
    djnz groupf                                                       ; 1ad1: 10 0a       ..
; $1ad3 referenced 1 time by $1ab8
grpe:
    call cond                                                         ; 1ad3: cd f1 1b    ...
    ld a,c                                                            ; 1ad6: 79          y
    jr nc,byte1                                                       ; 1ad7: 30 70       0p
    or 9                                                              ; 1ad9: f6 09       ..
    jr byte1                                                          ; 1adb: 18 6c       .l

; $1add referenced 1 time by $1ad1
groupf:
    djnz misc                                                         ; 1add: 10 6c       .l
    call ldop                                                         ; 1adf: cd 1d 1c    ...
    jr nc,lda                                                         ; 1ae2: 30 5f       0_
    call reghi                                                        ; 1ae4: cd eb 1b    ...
    ex af,af'                                                         ; 1ae7: 08          .
    call skip                                                         ; 1ae8: cd 69 1c    .i.
    cp $28                                                            ; 1aeb: fe 28       .(
    jr z,ldin                                                         ; 1aed: 28 1d       (.
    ex af,af'                                                         ; 1aef: 08          .
    jp nc,g6                                                          ; 1af0: d2 12 1a    ...
    ld c,1                                                            ; 1af3: 0e 01       ..
    call pair1_exec                                                   ; 1af5: cd 08 1c    ...
    ret c                                                             ; 1af8: d8          .
    ld a,$0e                                                          ; 1af9: 3e 0e       >.
    cp b                                                              ; 1afb: b8          .
    ld b,a                                                            ; 1afc: 47          G
    call z,pair_exec                                                  ; 1afd: cc 04 1c    ...
    ld a,b                                                            ; 1b00: 78          x
    and $3f                                                           ; 1b01: e6 3f       .?
    cp $0c                                                            ; 1b03: fe 0c       ..
    ld a,c                                                            ; 1b05: 79          y
    jr nz,grpb                                                        ; 1b06: 20 a9        .
    ld a,$f9                                                          ; 1b08: 3e f9       >.
    jr byte1                                                          ; 1b0a: 18 3d       .=

; $1b0c referenced 1 time by $1aed
ldin:
    ex af,af'                                                         ; 1b0c: 08          .
    push bc                                                           ; 1b0d: c5          .
    call nc,reglo                                                     ; 1b0e: d4 e5 1b    ...
    ld a,c                                                            ; 1b11: 79          y
    pop bc                                                            ; 1b12: c1          .
    jr nc,bind                                                        ; 1b13: 30 77       0w
    ld c,$0a                                                          ; 1b15: 0e 0a       ..
    call pair1_exec                                                   ; 1b17: cd 08 1c    ...
    call ld16                                                         ; 1b1a: cd 62 1b    .b.
    jr nc,grpb                                                        ; 1b1d: 30 92       0.
    call number_exec                                                  ; 1b1f: cd c8 1b    ...
    ld c,2                                                            ; 1b22: 0e 02       ..
    call pair_exec                                                    ; 1b24: cd 04 1c    ...
    call ld16                                                         ; 1b27: cd 62 1b    .b.
    ret c                                                             ; 1b2a: d8          .
    call byte                                                         ; 1b2b: cd b8 1b    ...
    jr val16                                                          ; 1b2e: 18 8e       ..

; $1b30 referenced 1 time by $1b4b
opt_exec:
    dec b                                                             ; 1b30: 05          .
    jp z,db                                                           ; 1b31: ca 1d 1a    ...
    djnz addr                                                         ; 1b34: 10 85       ..
    call number_exec                                                  ; 1b36: cd c8 1b    ...
    ld hl,$3ffe                                                       ; 1b39: 21 fe 3f    !.?
    ld c,a                                                            ; 1b3c: 4f          O
    rld                                                               ; 1b3d: ed 6f       .o
    ld a,c                                                            ; 1b3f: 79          y
    rrd                                                               ; 1b40: ed 67       .g
    ret                                                               ; 1b42: c9          .

; $1b43 referenced 1 time by $1ae2
lda:
    cp 4                                                              ; 1b43: fe 04       ..
    call c,ed                                                         ; 1b45: dc 86 1b    ...
    ld a,b                                                            ; 1b48: 78          x
; $1b49 referenced 4 times by $1acf, $1ad7, $1adb, $1b0a
byte1:
    jr byte                                                           ; 1b49: 18 6d       .m

; $1b4b referenced 1 time by $1add
misc:
    djnz opt_exec                                                     ; 1b4b: 10 e3       ..
    push ix                                                           ; 1b4d: dd e5       ..
    call exprs                                                        ; 1b4f: cd c7 1f    ...
    pop ix                                                            ; 1b52: dd e1       ..
    ld hl,$3d00                                                       ; 1b54: 21 00 3d    !.=
; $1b57 referenced 1 time by $1b60
defm1:
    xor a                                                             ; 1b57: af          .
    cp e                                                              ; 1b58: bb          .
    ret z                                                             ; 1b59: c8          .
    ld a,(hl)                                                         ; 1b5a: 7e          ~
    inc hl                                                            ; 1b5b: 23          #
    call byte                                                         ; 1b5c: cd b8 1b    ...
    dec e                                                             ; 1b5f: 1d          .
    jr defm1                                                          ; 1b60: 18 f5       ..

; $1b62 referenced 2 times by $1b1a, $1b27
ld16:
    ld a,b                                                            ; 1b62: 78          x
    jr c,ld8                                                          ; 1b63: 38 0e       8.
    ld a,b                                                            ; 1b65: 78          x
    and $3f                                                           ; 1b66: e6 3f       .?
    cp $0c                                                            ; 1b68: fe 0c       ..
    ld a,c                                                            ; 1b6a: 79          y
    ret z                                                             ; 1b6b: c8          .
    call ed                                                           ; 1b6c: cd 86 1b    ...
    ld a,c                                                            ; 1b6f: 79          y
    or $43                                                            ; 1b70: f6 43       .C
    ret                                                               ; 1b72: c9          .

; $1b73 referenced 1 time by $1b63
ld8:
    cp 7                                                              ; 1b73: fe 07       ..
    scf                                                               ; 1b75: 37          7
    ret nz                                                            ; 1b76: c0          .
    ld a,c                                                            ; 1b77: 79          y
    or $30                                                            ; 1b78: f6 30       .0
    ret                                                               ; 1b7a: c9          .

; $1b7b referenced 2 times by $1a56, $1a5f
corn:
    push bc                                                           ; 1b7b: c5          .
    call opnd                                                         ; 1b7c: cd 98 1b    ...
    bit 5,b                                                           ; 1b7f: cb 68       .h
    pop bc                                                            ; 1b81: c1          .
    jr z,number_exec                                                  ; 1b82: 28 44       (D
    ld h,$ff                                                          ; 1b84: 26 ff       &.
; $1b86 referenced 4 times by $19e0, $1a33, $1b45, $1b6c
ed:
    ld a,$ed                                                          ; 1b86: 3e ed       >.
    jr byte                                                           ; 1b88: 18 2e       ..

; $1b8a referenced 1 time by $19f3
cb:
    ld a,$cb                                                          ; 1b8a: 3e cb       >.
; $1b8c referenced 3 times by $1a1a, $1a40, $1b13
bind:
    cp $76                                                            ; 1b8c: fe 76       .v
    scf                                                               ; 1b8e: 37          7
    ret z                                                             ; 1b8f: c8          .
    call byte                                                         ; 1b90: cd b8 1b    ...
    inc d                                                             ; 1b93: 14          .
    ret p                                                             ; 1b94: f0          .
    ld a,e                                                            ; 1b95: 7b          {
    jr byte                                                           ; 1b96: 18 20       .

; $1b98 referenced 5 times by $1a0a, $1b7c, $1bda, $1bf1, $1c04
opnd:
    push hl                                                           ; 1b98: e5          .
    ld hl,$1dc2                                                       ; 1b99: 21 c2 1d    !..
    call find_exec                                                    ; 1b9c: cd 20 1c    . .
    pop hl                                                            ; 1b9f: e1          .
    ret c                                                             ; 1ba0: d8          .
    bit 7,b                                                           ; 1ba1: cb 78       .x
    ret z                                                             ; 1ba3: c8          .
    bit 3,b                                                           ; 1ba4: cb 58       .X
    push hl                                                           ; 1ba6: e5          .
    call z,offset                                                     ; 1ba7: cc bf 1b    ...
    ld e,l                                                            ; 1baa: 5d          ]
    pop hl                                                            ; 1bab: e1          .
    ld a,$dd                                                          ; 1bac: 3e dd       >.
    bit 6,b                                                           ; 1bae: cb 70       .p
    jr z,op1                                                          ; 1bb0: 28 02       (.
    ld a,$fd                                                          ; 1bb2: 3e fd       >.
; $1bb4 referenced 1 time by $1bb0
op1:
    or a                                                              ; 1bb4: b7          .
    inc d                                                             ; 1bb5: 14          .
    ld d,a                                                            ; 1bb6: 57          W
    ret m                                                             ; 1bb7: f8          .
; $1bb8 referenced 9 times by $1a70, $1a83, $1ab1, $1b2b, $1b49, $1b5c, $1b88, $1b90, $1b96
byte:
    ld (ix+0),a                                                       ; 1bb8: dd 77 00    .w.
    inc ix                                                            ; 1bbb: dd 23       .#
    or a                                                              ; 1bbd: b7          .
    ret                                                               ; 1bbe: c9          .

; $1bbf referenced 1 time by $1ba7
offset:
    ld a,(iy+0)                                                       ; 1bbf: fd 7e 00    .~.
    cp $29                                                            ; 1bc2: fe 29       .)
    ld hl,0                                                           ; 1bc4: 21 00 00    !..
    ret z                                                             ; 1bc7: c8          .
; $1bc8 referenced 8 times by $1a1d, $1a86, $1abb, $1ac6, $1b1f, $1b36, $1b82, $1c10
number_exec:
    call skip                                                         ; 1bc8: cd 69 1c    .i.
    push bc                                                           ; 1bcb: c5          .
    push de                                                           ; 1bcc: d5          .
    push ix                                                           ; 1bcd: dd e5       ..
    call expri                                                        ; 1bcf: cd be 1f    ...
    pop ix                                                            ; 1bd2: dd e1       ..
    exx                                                               ; 1bd4: d9          .
    pop de                                                            ; 1bd5: d1          .
    pop bc                                                            ; 1bd6: c1          .
    ld a,l                                                            ; 1bd7: 7d          }
    or a                                                              ; 1bd8: b7          .
    ret                                                               ; 1bd9: c9          .

; $1bda referenced 2 times by $1be5, $1beb
reg:
    call opnd                                                         ; 1bda: cd 98 1b    ...
    ret c                                                             ; 1bdd: d8          .
    ld a,b                                                            ; 1bde: 78          x
    and $3f                                                           ; 1bdf: e6 3f       .?
    cp 8                                                              ; 1be1: fe 08       ..
    ccf                                                               ; 1be3: 3f          ?
    ret                                                               ; 1be4: c9          .

; $1be5 referenced 3 times by $19ef, $1a12, $1b0e
reglo:
    call reg                                                          ; 1be5: cd da 1b    ...
    ret c                                                             ; 1be8: d8          .
    jr orc                                                            ; 1be9: 18 2f       ./

; $1beb referenced 3 times by $1a3c, $1a5a, $1ae4
reghi:
    call reg                                                          ; 1beb: cd da 1b    ...
    ret c                                                             ; 1bee: d8          .
    jr shl3                                                           ; 1bef: 18 26       .&

; $1bf1 referenced 3 times by $1a7b, $1aa0, $1ad3
cond:
    call opnd                                                         ; 1bf1: cd 98 1b    ...
    ret c                                                             ; 1bf4: d8          .
    ld a,b                                                            ; 1bf5: 78          x
    and $1f                                                           ; 1bf6: e6 1f       ..
    sub $10                                                           ; 1bf8: d6 10       ..
    jr nc,shl3                                                        ; 1bfa: 30 1b       0.
    cp $f1                                                            ; 1bfc: fe f1       ..
    scf                                                               ; 1bfe: 37          7
    ret nz                                                            ; 1bff: c0          .
    ld a,3                                                            ; 1c00: 3e 03       >.
    jr shl3                                                           ; 1c02: 18 13       ..

; $1c04 referenced 3 times by $19fc, $1afd, $1b24
pair_exec:
    call opnd                                                         ; 1c04: cd 98 1b    ...
    ret c                                                             ; 1c07: d8          .
; $1c08 referenced 3 times by $1a49, $1af5, $1b17
pair1_exec:
    ld a,b                                                            ; 1c08: 78          x
    and $0f                                                           ; 1c09: e6 0f       ..
    sub 8                                                             ; 1c0b: d6 08       ..
    ret c                                                             ; 1c0d: d8          .
    jr shl3                                                           ; 1c0e: 18 07       ..

; $1c10 referenced 1 time by $19eb
bit:
    call number_exec                                                  ; 1c10: cd c8 1b    ...
    cp 8                                                              ; 1c13: fe 08       ..
    ccf                                                               ; 1c15: 3f          ?
    ret c                                                             ; 1c16: d8          .
; $1c17 referenced 4 times by $1bef, $1bfa, $1c02, $1c0e
shl3:
    rlca                                                              ; 1c17: 07          .
    rlca                                                              ; 1c18: 07          .
    rlca                                                              ; 1c19: 07          .
; $1c1a referenced 1 time by $1be9
orc:
    or c                                                              ; 1c1a: b1          .
    ld c,a                                                            ; 1c1b: 4f          O
    ret                                                               ; 1c1c: c9          .

; $1c1d referenced 1 time by $1adf
ldop:
    ld hl,$1e07                                                       ; 1c1d: 21 07 1e    !..
; $1c20 referenced 2 times by $19d3, $1b9c
find_exec:
    call skip                                                         ; 1c20: cd 69 1c    .i.
; $1c23 referenced 1 time by $1c31
exit_exec:
    ld b,0                                                            ; 1c23: 06 00       ..
    scf                                                               ; 1c25: 37          7
    ret z                                                             ; 1c26: c8          .
    cp $dd                                                            ; 1c27: fe dd       ..
    jr z,find0                                                        ; 1c29: 28 04       (.
    cp $85                                                            ; 1c2b: fe 85       ..
    ccf                                                               ; 1c2d: 3f          ?
    ret c                                                             ; 1c2e: d8          .
; $1c2f referenced 2 times by $1c29, $1c41
find0:
    ld a,(hl)                                                         ; 1c2f: 7e          ~
    or a                                                              ; 1c30: b7          .
    jr z,exit_exec                                                    ; 1c31: 28 f0       (.
    xor (iy+0)                                                        ; 1c33: fd ae 00    ...
    and $5f                                                           ; 1c36: e6 5f       ._
    jr z,find2                                                        ; 1c38: 28 09       (.
; $1c3a referenced 2 times by $1c3d, $1c5a
find1_exec:
    bit 7,(hl)                                                        ; 1c3a: cb 7e       .~
    inc hl                                                            ; 1c3c: 23          #
    jr z,find1_exec                                                   ; 1c3d: 28 fb       (.
    inc hl                                                            ; 1c3f: 23          #
    inc b                                                             ; 1c40: 04          .
    jr find0                                                          ; 1c41: 18 ec       ..

; $1c43 referenced 1 time by $1c38
find2:
    push iy                                                           ; 1c43: fd e5       ..
; $1c45 referenced 1 time by $1c56
find3:
    bit 7,(hl)                                                        ; 1c45: cb 7e       .~
    inc iy                                                            ; 1c47: fd 23       .#
    inc hl                                                            ; 1c49: 23          #
    jr nz,find5                                                       ; 1c4a: 20 10        .
    cp (hl)                                                           ; 1c4c: be          .
    call z,skip0                                                      ; 1c4d: cc 68 1c    .h.
    ld a,(hl)                                                         ; 1c50: 7e          ~
    xor (iy+0)                                                        ; 1c51: fd ae 00    ...
    and $5f                                                           ; 1c54: e6 5f       ._
    jr z,find3                                                        ; 1c56: 28 ed       (.
; $1c58 referenced 1 time by $1c62
find4:
    pop iy                                                            ; 1c58: fd e1       ..
    jr find1_exec                                                     ; 1c5a: 18 de       ..

; $1c5c referenced 1 time by $1c4a
find5:
    call delim                                                        ; 1c5c: cd d8 17    ...
    call nz,sign                                                      ; 1c5f: c4 75 1c    .u.
    jr nz,find4                                                       ; 1c62: 20 f4        .
find6:
    ld a,b                                                            ; 1c64: 78          x
    ld b,(hl)                                                         ; 1c65: 46          F
    pop hl                                                            ; 1c66: e1          .
    ret                                                               ; 1c67: c9          .

; $1c68 referenced 1 time by $1c4d
skip0:
    inc hl                                                            ; 1c68: 23          #
; $1c69 referenced 7 times by $18f3, $191d, $19c1, $1ae8, $1bc8, $1c20, $1c73
skip:
    call delim                                                        ; 1c69: cd d8 17    ...
    ret nz                                                            ; 1c6c: c0          .
    call term                                                         ; 1c6d: cd e4 17    ...
    ret z                                                             ; 1c70: c8          .
    inc iy                                                            ; 1c71: fd 23       .#
    jr skip                                                           ; 1c73: 18 f4       ..

; $1c75 referenced 1 time by $1c5f
sign:
    cp $2b                                                            ; 1c75: fe 2b       .+
    ret z                                                             ; 1c77: c8          .
    cp $2d                                                            ; 1c78: fe 2d       .-
    ret                                                               ; 1c7a: c9          .

opcods:
xlist:
    db $4e, $4f, $d0, 0                                               ; 1c7b: 4e 4f d0... NO.
    db "RLC"                                                          ; 1c7f: 52 4c 43    RLC
    db $c1, 7, $45, $58, 0, $41, $46, 0, $41, $46, $a7, 8             ; 1c82: c1 07 45... ..E
    db "RRC"                                                          ; 1c8e: 52 52 43    RRC
    db $c1, $0f, $52, $4c, $c1, $17, $52, $52, $c1, $1f, $44, $41     ; 1c91: c1 0f 52... ..R
    db $c1                                                            ; 1c9d: c1          .
    db "'CP"                                                          ; 1c9e: 27 43 50    'CP
    db $cc                                                            ; 1ca1: cc          .
    db "/SC"                                                          ; 1ca2: 2f 53 43    /SC
    db $c6                                                            ; 1ca5: c6          .
    db "7CC"                                                          ; 1ca6: 37 43 43    7CC
    db $c6                                                            ; 1ca9: c6          .
    db "?HAL"                                                         ; 1caa: 3f 48 41... ?HA
    db $d4                                                            ; 1cae: d4          .
    db "vEX"                                                          ; 1caf: 76 45 58    vEX
    db $d8, $d9, $45, $58,   0, $44, $45, 0, $48, $cc, $eb, $44, $c9  ; 1cb2: d8 d9 45... ..E
    db $f3, $45, $c9, $fb, $4e, $45, $c7                              ; 1cbf: f3 45 c9... .E.
    db "DIM"                                                          ; 1cc6: 44 49 4d    DIM
    db 0, $b0                                                         ; 1cc9: 00 b0       ..
    db "FRET"                                                         ; 1ccb: 46 52 45... FRE
    db $ce                                                            ; 1ccf: ce          .
    db "ERET"                                                         ; 1cd0: 45 52 45... ERE
    db $c9                                                            ; 1cd4: c9          .
    db "MIM"                                                          ; 1cd5: 4d 49 4d    MIM
    db 0, $b1                                                         ; 1cd8: 00 b1       ..
    db "VIM"                                                          ; 1cda: 56 49 4d    VIM
    db 0, $b2                                                         ; 1cdd: 00 b2       ..
    db "^RR"                                                          ; 1cdf: 5e 52 52    ^RR
    db $c4                                                            ; 1ce2: c4          .
    db "gRL"                                                          ; 1ce3: 67 52 4c    gRL
    db $c4                                                            ; 1ce6: c4          .
    db "oLD"                                                          ; 1ce7: 6f 4c 44    oLD
    db $c9, $a0, $43, $50, $c9, $a1, $49, $4e, $c9, $a2               ; 1cea: c9 a0 43... ..C
    db "OUT"                                                          ; 1cf4: 4f 55 54    OUT
    db $c9, $a3, $4c, $44, $c4, $a8, $43, $50, $c4, $a9, $49, $4e     ; 1cf7: c9 a3 4c... ..L
    db $c4, $aa                                                       ; 1d03: c4 aa       ..
    db "OUT"                                                          ; 1d05: 4f 55 54    OUT
    db $c4, $ab                                                       ; 1d08: c4 ab       ..
    db "LDI"                                                          ; 1d0a: 4c 44 49    LDI
    db $d2, $b0                                                       ; 1d0d: d2 b0       ..
    db "CPI"                                                          ; 1d0f: 43 50 49    CPI
    db $d2, $b1                                                       ; 1d12: d2 b1       ..
    db "INI"                                                          ; 1d14: 49 4e 49    INI
    db $d2, $b2                                                       ; 1d17: d2 b2       ..
    db "OTI"                                                          ; 1d19: 4f 54 49    OTI
    db $d2, $b3                                                       ; 1d1c: d2 b3       ..
    db "LDD"                                                          ; 1d1e: 4c 44 44    LDD
    db $d2, $b8                                                       ; 1d21: d2 b8       ..
    db "CPD"                                                          ; 1d23: 43 50 44    CPD
    db $d2, $b9                                                       ; 1d26: d2 b9       ..
    db "IND"                                                          ; 1d28: 49 4e 44    IND
    db $d2, $ba                                                       ; 1d2b: d2 ba       ..
    db "OTD"                                                          ; 1d2d: 4f 54 44    OTD
    db $d2, $bb, $42, $49, $d4                                        ; 1d30: d2 bb 42... ..B
    db "@RE"                                                          ; 1d35: 40 52 45    @RE
    db $d3, $80, $53, $45, $d4, $c0, $52, $4c, $c3,   0, $52, $52     ; 1d38: d3 80 53... ..S
    db $c3,   8, $52, $cc, $10, $52, $d2, $18, $53, $4c, $c1          ; 1d44: c3 08 52... ..R
    db " SR"                                                          ; 1d4f: 20 53 52     SR
    db $c1                                                            ; 1d52: c1          .
    db "(SR"                                                          ; 1d53: 28 53 52    (SR
    db $cc                                                            ; 1d56: cc          .
    db "8PO"                                                          ; 1d57: 38 50 4f    8PO
    db $d0, $c1                                                       ; 1d5a: d0 c1       ..
    db "PUS"                                                          ; 1d5c: 50 55 53    PUS
    db $c8, $c5, $45, $58,   0, $28, $53, $d0, $e3, $53, $55, $c2     ; 1d5f: c8 c5 45... ..E
    db $90, $41, $4e, $c4, $a0, $58, $4f, $d2, $a8, $4f, $d2, $b0     ; 1d6b: 90 41 4e... .AN
    db $43, $d0, $b8, $80, $a0, $84, $b0, $41, $44, $c4, $80, $41     ; 1d77: 43 d0 b8... C..
    db $44, $c3, $88, $53, $42, $c3, $98, $49, $4e, $c3,   4, $44     ; 1d83: 44 c3 88... D..
    db $45, $c3,   5, $49, $ce                                        ; 1d8f: 45 c3 05... E..
    db "@OU"                                                          ; 1d94: 40 4f 55    @OU
    db $d4, $41, $4a, $d2                                             ; 1d97: d4 41 4a... .AJ
    db " DJN"                                                         ; 1d9b: 20 44 4a...  DJ
    db $da, $10, $4a, $d0, $c2                                        ; 1d9f: da 10 4a... ..J
    db "CAL"                                                          ; 1da4: 43 41 4c    CAL
    db $cc, $c4, $52, $53, $d4, $c7, $52, $45, $d4, $c0, $4c, $c4     ; 1da7: cc c4 52... ..R
    db $40, $5d, $cd,   0, $5d, $c2,   0, $4f, $50, $d4,   0, $5d     ; 1db3: 40 5d cd... @].
    db $d7,   0,   0                                                  ; 1dbf: d7 00 00    ...
oprnds:
    db $c2,   0, $c3,   1, $c4,   2, $c5,   3, $c8,   4, $cc,   5     ; 1dc2: c2 00 c3... ...
    db $28, $48, $cc,   6, $c1,   7, $28, $49, $d8, $86, $28, $49     ; 1dce: 28 48 cc... (H.
    db $d9, $c6, $42, $c3,   8, $44, $c5, $0a, $48, $cc, $0c, $49     ; 1dda: d9 c6 42... ..B
    db $d8, $8c, $49, $d9, $cc, $41, $c6, $0e, $53, $d0, $0e, $4e     ; 1de6: d8 8c 49... ..I
    db $da, $10, $da, $11, $4e, $c3, $12, $50, $cf, $14, $50, $c5     ; 1df2: da 10 da... ...
    db $15, $d0, $16, $cd, $17, $28, $c3, $20,   0                    ; 1dfe: 15 d0 16... ...
ldops:
    db $49, 0, $c1, $47, $52, 0, $c1, $4f, $41, 0, $c9, $57, $41, 0   ; 1e07: 49 00 c1... I..
    db $d2                                                            ; 1e15: d2          .
    db "_(BC"                                                         ; 1e16: 5f 28 42... _(B
    db 0, $c1, 2                                                      ; 1e1a: 00 c1 02    ...
    db "(DE"                                                          ; 1e1d: 28 44 45    (DE
    db   0, $c1, $12, $41, 0, $28, $42, $c3, $0a, $41, 0, $28, $44    ; 1e20: 00 c1 12... ...
    db $c5, $1a,   0                                                  ; 1e2d: c5 1a 00    ...
funtbl:
    dw decode                                                         ; 1e30: 50 24       P$
    dw openin                                                         ; 1e32: a9 21       .!
    dw ptr_eval                                                       ; 1e34: c6 21       .!
    dw pagev_eval                                                     ; 1e36: 7b 21       {!
    dw timev_eval                                                     ; 1e38: ce 21       .!
    dw lomemv_eval                                                    ; 1e3a: 71 21       q!
    dw himemv_eval                                                    ; 1e3c: 76 21       v!
    dw abs_eval                                                       ; 1e3e: 1a 22       ."
    dw acs_eval                                                       ; 1e40: 56 22       V"
    dw adval                                                          ; 1e42: aa 32       .2
    dw asc                                                            ; 1e44: 5e 21       ^!
    dw asn_eval                                                       ; 1e46: 4e 22       N"
    dw atn_eval                                                       ; 1e48: 52 22       R"
    dw bget                                                           ; 1e4a: 3a 21       :!
    dw cos_eval                                                       ; 1e4c: 3a 22       :"
    dw countv                                                         ; 1e4e: 99 21       .!
    dw deg_eval                                                       ; 1e50: 22 22       ""
    dw erlv                                                           ; 1e52: 8f 21       .!
    dw errv                                                           ; 1e54: 94 21       .!
    dw eval                                                           ; 1e56: 7a 22       z"
    dw exp_eval                                                       ; 1e58: 42 22       B"
    dw ext_eval                                                       ; 1e5a: be 21       .!
    dw zero_eval                                                      ; 1e5c: e8 24       .$
    dw fn                                                             ; 1e5e: 46 12       F.
    dw get                                                            ; 1e60: 48 21       H!
    dw inkey_eval                                                     ; 1e62: 43 21       C!
    dw instr                                                          ; 1e64: 13 23       .#
    dw int_eval                                                       ; 1e66: 2e 22       ."
    dw len                                                            ; 1e68: 6b 21       k!
    dw ln_eval                                                        ; 1e6a: 46 22       F"
    dw log_eval                                                       ; 1e6c: 4a 22       J"
    dw not_eval                                                       ; 1e6e: 1e 22       ."
    dw openup                                                         ; 1e70: a6 21       .!
    dw openot                                                         ; 1e72: a4 21       .!
    dw pi_eval                                                        ; 1e74: 16 22       ."
    dw adval                                                          ; 1e76: aa 32       .2
    dw pos                                                            ; 1e78: 23 21       #!
    dw rad_eval                                                       ; 1e7a: 26 22       &"
    dw rnd                                                            ; 1e7c: a7 22       ."
    dw sgn_eval                                                       ; 1e7e: 2a 22       *"
    dw sin_eval                                                       ; 1e80: 3e 22       >"
    dw sqr_eval                                                       ; 1e82: 32 22       2"
    dw tan_eval                                                       ; 1e84: 36 22       6"
    dw topv                                                           ; 1e86: 80 21       .!
    dw true_eval                                                      ; 1e88: 0b 22       ."
    dw usr                                                            ; 1e8a: 2a 16       *.
    dw val_eval                                                       ; 1e8c: 6d 22       m"
    dw vpos                                                           ; 1e8e: 29 21       )!
    dw chrs                                                           ; 1e90: 91 23       .#
    dw gets                                                           ; 1e92: 98 23       .#
    dw inkeys                                                         ; 1e94: 9e 23       .#
    dw lefts                                                          ; 1e96: df 23       .#
    dw mids                                                           ; 1e98: ae 23       .#
    dw rights                                                         ; 1e9a: fa 23       .#
    dw strs                                                           ; 1e9c: a8 24       .$
    dw string                                                         ; 1e9e: 0e 24       .$
    dw eof                                                            ; 1ea0: 2e 21       .!
soptbl:
    dw sle                                                            ; 1ea2: f9 21       .!
    dw sne                                                            ; 1ea4: 01 22       ."
    dw sge                                                            ; 1ea6: f3 21       .!
    dw slt                                                            ; 1ea8: e6 21       .!
    dw seq                                                            ; 1eaa: 07 22       ."
    dw sgt                                                            ; 1eac: ec 21       .!

; $1eae referenced 8 times by $0ef1, $0ff7, $1077, $1fb7, $1fbe, $1fc7, $1fe8, $229a
expr:
    call expr1                                                        ; 1eae: cd c3 1e    ...
; $1eb1 referenced 1 time by $1ec1
expr0a:
    cp $82                                                            ; 1eb1: fe 82       ..
    jr z,expr0b                                                       ; 1eb3: 28 03       (.
    cp $84                                                            ; 1eb5: fe 84       ..
    ret nz                                                            ; 1eb7: c0          .
; $1eb8 referenced 1 time by $1eb3
expr0b:
    call save_eval                                                    ; 1eb8: cd 73 25    .s%
    call expr1                                                        ; 1ebb: cd c3 1e    ...
    call doit                                                         ; 1ebe: cd 81 25    ..%
    jr expr0a                                                         ; 1ec1: 18 ee       ..

; $1ec3 referenced 2 times by $1eae, $1ebb
expr1:
    call expr2                                                        ; 1ec3: cd d4 1e    ...
; $1ec6 referenced 1 time by $1ed2
expr1a:
    cp $80                                                            ; 1ec6: fe 80       ..
    ret nz                                                            ; 1ec8: c0          .
    call save_eval                                                    ; 1ec9: cd 73 25    .s%
    call expr2                                                        ; 1ecc: cd d4 1e    ...
    call doit                                                         ; 1ecf: cd 81 25    ..%
    jr expr1a                                                         ; 1ed2: 18 f2       ..

; $1ed4 referenced 2 times by $1ec3, $1ecc
expr2:
    call expr3                                                        ; 1ed4: cd 33 1f    .3.
    call relopq                                                       ; 1ed7: cd 4e 25    .N%
    ret nz                                                            ; 1eda: c0          .
    ld b,a                                                            ; 1edb: 47          G
    inc iy                                                            ; 1edc: fd 23       .#
    call nxt                                                          ; 1ede: cd a2 25    ..%
    call relopq                                                       ; 1ee1: cd 4e 25    .N%
    jr nz,expr2b                                                      ; 1ee4: 20 08        .
    inc iy                                                            ; 1ee6: fd 23       .#
    cp b                                                              ; 1ee8: b8          .
    jp z,syntax                                                       ; 1ee9: ca e9 0e    ...
    add a,b                                                           ; 1eec: 80          .
    ld b,a                                                            ; 1eed: 47          G
; $1eee referenced 1 time by $1ee4
expr2b:
    ld a,b                                                            ; 1eee: 78          x
    ex af,af'                                                         ; 1eef: 08          .
    jp m,expr2s                                                       ; 1ef0: fa 06 1f    ...
    ex af,af'                                                         ; 1ef3: 08          .
    sub 4                                                             ; 1ef4: d6 04       ..
    cp $3a                                                            ; 1ef6: fe 3a       .:
    jr nz,expr2c                                                      ; 1ef8: 20 02        .
    add a,2                                                           ; 1efa: c6 02       ..
; $1efc referenced 1 time by $1ef8
expr2c:
    call save1_eval                                                   ; 1efc: cd 75 25    .u%
    call expr3                                                        ; 1eff: cd 33 1f    .3.
    call doit                                                         ; 1f02: cd 81 25    ..%
    ret                                                               ; 1f05: c9          .

; $1f06 referenced 1 time by $1ef0
expr2s:
    ex af,af'                                                         ; 1f06: 08          .
    dec a                                                             ; 1f07: 3d          =
    and 7                                                             ; 1f08: e6 07       ..
    call pushs                                                        ; 1f0a: cd 09 25    ..%
    push af                                                           ; 1f0d: f5          .
    call expr3                                                        ; 1f0e: cd 33 1f    .3.
    ex af,af'                                                         ; 1f11: 08          .
    jp p,type_eval                                                    ; 1f12: f2 e3 1f    ...
    pop af                                                            ; 1f15: f1          .
    ld c,e                                                            ; 1f16: 4b          K
    pop de                                                            ; 1f17: d1          .
    ld hl,0                                                           ; 1f18: 21 00 00    !..
    add hl,sp                                                         ; 1f1b: 39          9
    ld b,e                                                            ; 1f1c: 43          C
    push de                                                           ; 1f1d: d5          .
    ld de,$3d00                                                       ; 1f1e: 11 00 3d    ..=
    ex de,hl                                                          ; 1f21: eb          .
    call dispt2                                                       ; 1f22: cd ad 25    ..%
    pop de                                                            ; 1f25: d1          .
    ex de,hl                                                          ; 1f26: eb          .
    ld h,0                                                            ; 1f27: 26 00       &.
    add hl,sp                                                         ; 1f29: 39          9
    ld sp,hl                                                          ; 1f2a: f9          .
    ex de,hl                                                          ; 1f2b: eb          .
    xor a                                                             ; 1f2c: af          .
    ld c,a                                                            ; 1f2d: 4f          O
    ex af,af'                                                         ; 1f2e: 08          .
    ld a,(iy+0)                                                       ; 1f2f: fd 7e 00    .~.
    ret                                                               ; 1f32: c9          .

; $1f33 referenced 3 times by $1ed4, $1eff, $1f0e
expr3:
    call expr4                                                        ; 1f33: cd 82 1f    ...
; $1f36 referenced 2 times by $1f4b, $1f80
expr3a:
    cp $2d                                                            ; 1f36: fe 2d       .-
    jr z,expr3b                                                       ; 1f38: 28 08       (.
    cp $2b                                                            ; 1f3a: fe 2b       .+
    ret nz                                                            ; 1f3c: c0          .
    ex af,af'                                                         ; 1f3d: 08          .
    jp m,expr3s                                                       ; 1f3e: fa 4d 1f    .M.
    ex af,af'                                                         ; 1f41: 08          .
; $1f42 referenced 1 time by $1f38
expr3b:
    call save_eval                                                    ; 1f42: cd 73 25    .s%
    call expr4                                                        ; 1f45: cd 82 1f    ...
    call doit                                                         ; 1f48: cd 81 25    ..%
    jr expr3a                                                         ; 1f4b: 18 e9       ..

; $1f4d referenced 1 time by $1f3e
expr3s:
    ex af,af'                                                         ; 1f4d: 08          .
    inc iy                                                            ; 1f4e: fd 23       .#
    call pushs                                                        ; 1f50: cd 09 25    ..%
    call expr4                                                        ; 1f53: cd 82 1f    ...
    ex af,af'                                                         ; 1f56: 08          .
    jp p,type_eval                                                    ; 1f57: f2 e3 1f    ...
    ld c,e                                                            ; 1f5a: 4b          K
    pop de                                                            ; 1f5b: d1          .
    push de                                                           ; 1f5c: d5          .
    ld hl,$3d00                                                       ; 1f5d: 21 00 3d    !.=
    ld d,h                                                            ; 1f60: 54          T
    ld a,c                                                            ; 1f61: 79          y
    or a                                                              ; 1f62: b7          .
    jr z,exp3s3                                                       ; 1f63: 28 0f       (.
    ld b,l                                                            ; 1f65: 45          E
    ld l,a                                                            ; 1f66: 6f          o
    add a,e                                                           ; 1f67: 83          .
    ld e,a                                                            ; 1f68: 5f          _
    ld a,$13                                                          ; 1f69: 3e 13       >.
    jp c,error_main                                                   ; 1f6b: da 05 08    ...
    push de                                                           ; 1f6e: d5          .
    dec e                                                             ; 1f6f: 1d          .
    dec l                                                             ; 1f70: 2d          -
    lddr                                                              ; 1f71: ed b8       ..
    pop de                                                            ; 1f73: d1          .
; $1f74 referenced 1 time by $1f63
exp3s3:
    exx                                                               ; 1f74: d9          .
    pop bc                                                            ; 1f75: c1          .
    call pops                                                         ; 1f76: cd 28 25    .(%
    exx                                                               ; 1f79: d9          .
    or $80                                                            ; 1f7a: f6 80       ..
    ex af,af'                                                         ; 1f7c: 08          .
    ld a,(iy+0)                                                       ; 1f7d: fd 7e 00    .~.
    jr expr3a                                                         ; 1f80: 18 b4       ..

; $1f82 referenced 3 times by $1f33, $1f45, $1f53
expr4:
    call expr5                                                        ; 1f82: cd 9f 1f    ...
; $1f85 referenced 1 time by $1f9d
expr4a:
    cp $2a                                                            ; 1f85: fe 2a       .*
    jr z,expr4b                                                       ; 1f87: 28 0b       (.
    cp $2f                                                            ; 1f89: fe 2f       ./
    jr z,expr4b                                                       ; 1f8b: 28 07       (.
    cp $83                                                            ; 1f8d: fe 83       ..
    jr z,expr4b                                                       ; 1f8f: 28 03       (.
    cp $81                                                            ; 1f91: fe 81       ..
    ret nz                                                            ; 1f93: c0          .
; $1f94 referenced 3 times by $1f87, $1f8b, $1f8f
expr4b:
    call save_eval                                                    ; 1f94: cd 73 25    .s%
    call expr5                                                        ; 1f97: cd 9f 1f    ...
    call doit                                                         ; 1f9a: cd 81 25    ..%
    jr expr4a                                                         ; 1f9d: 18 e6       ..

; $1f9f referenced 2 times by $1f82, $1f97
expr5:
    call item                                                         ; 1f9f: cd 3a 20    .:
    or a                                                              ; 1fa2: b7          .
    ex af,af'                                                         ; 1fa3: 08          .
; $1fa4 referenced 1 time by $1fb5
expr5a:
    call nxt                                                          ; 1fa4: cd a2 25    ..%
    cp $5e                                                            ; 1fa7: fe 5e       .^
    ret nz                                                            ; 1fa9: c0          .
    call save_eval                                                    ; 1faa: cd 73 25    .s%
    call item                                                         ; 1fad: cd 3a 20    .:
    or a                                                              ; 1fb0: b7          .
    ex af,af'                                                         ; 1fb1: 08          .
    call doit                                                         ; 1fb2: cd 81 25    ..%
    jr expr5a                                                         ; 1fb5: 18 ed       ..

; $1fb7 referenced 5 times by $118f, $11ad, $146f, $1682, $1721
exprn:
    call expr                                                         ; 1fb7: cd ae 1e    ...
    ex af,af'                                                         ; 1fba: 08          .
    ret p                                                             ; 1fbb: f0          .
    jr type_eval                                                      ; 1fbc: 18 25       .%

; $1fbe referenced 31 times by $065f, $0a97, $0f5a, $0fda, $10be, $1166, $14a2, $1520, $1530, $1543, $1560, $1573, $1595, $15af, $15ba, $15eb, $15f7, $1662, $166a, $181e, $183f, $1bcf, $2333, $23b4, $23e5, $240e, $3213, $3240, $3286, $329c, $32a4
expri:
    call expr                                                         ; 1fbe: cd ae 1e    ...
    ex af,af'                                                         ; 1fc1: 08          .
    jp p,sfix_eval                                                    ; 1fc2: f2 65 22    .e"
    jr type_eval                                                      ; 1fc5: 18 1c       ..

; $1fc7 referenced 11 times by $07d9, $07ea, $0dd4, $0e77, $0eb8, $1554, $1733, $1b4f, $2319, $2418, $2557
exprs:
    call expr                                                         ; 1fc7: cd ae 1e    ...
    ex af,af'                                                         ; 1fca: 08          .
    ret m                                                             ; 1fcb: f8          .
    jr type_eval                                                      ; 1fcc: 18 15       ..

; $1fce referenced 5 times by $2015, $204c, $2259, $2474, $24af
itemn:
    call item                                                         ; 1fce: cd 3a 20    .:
    or a                                                              ; 1fd1: b7          .
    ret p                                                             ; 1fd2: f0          .
    jr type_eval                                                      ; 1fd3: 18 0e       ..

; $1fd5 referenced 12 times by $0af9, $10fa, $1120, $1137, $1502, $162a, $184e, $18ed, $214f, $22ce, $2391, $239e
itemi:
    call item                                                         ; 1fd5: cd 3a 20    .:
    or a                                                              ; 1fd8: b7          .
    jp p,sfix_eval                                                    ; 1fd9: f2 65 22    .e"
    jr type_eval                                                      ; 1fdc: 18 05       ..

; $1fde referenced 5 times by $215e, $216b, $21ac, $226d, $227a
items:
    call item                                                         ; 1fde: cd 3a 20    .:
    or a                                                              ; 1fe1: b7          .
    ret m                                                             ; 1fe2: f8          .
; $1fe3 referenced 9 times by $1f12, $1f57, $1fbc, $1fc5, $1fcc, $1fd3, $1fdc, $2576, $2582
type_eval:
    ld a,6                                                            ; 1fe3: 3e 06       >.
    jp error_main                                                     ; 1fe5: c3 05 08    ...

; $1fe8 referenced 1 time by $2050
item1:
    call expr                                                         ; 1fe8: cd ae 1e    ...
    call braket                                                       ; 1feb: cd 66 25    .f%
    ex af,af'                                                         ; 1fee: 08          .
    ret                                                               ; 1fef: c9          .

; $1ff0 referenced 1 time by $2044
hex_eval:
    call zero_eval                                                    ; 1ff0: cd e8 24    ..$
    call hexdig                                                       ; 1ff3: cd 3b 25    .;%
    jr c,badhex                                                       ; 1ff6: 38 18       8.
; $1ff8 referenced 1 time by $200c
hex1_eval:
    inc iy                                                            ; 1ff8: fd 23       .#
    and $0f                                                           ; 1ffa: e6 0f       ..
    ld b,4                                                            ; 1ffc: 06 04       ..
; $1ffe referenced 1 time by $2003
hex2_eval:
    exx                                                               ; 1ffe: d9          .
    add hl,hl                                                         ; 1fff: 29          )
    exx                                                               ; 2000: d9          .
    adc hl,hl                                                         ; 2001: ed 6a       .j
    djnz hex2_eval                                                    ; 2003: 10 f9       ..
    exx                                                               ; 2005: d9          .
    or l                                                              ; 2006: b5          .
    ld l,a                                                            ; 2007: 6f          o
    exx                                                               ; 2008: d9          .
    call hexdig                                                       ; 2009: cd 3b 25    .;%
    jr nc,hex1_eval                                                   ; 200c: 30 ea       0.
    xor a                                                             ; 200e: af          .
    ret                                                               ; 200f: c9          .

; $2010 referenced 1 time by $1ff6
badhex:
    ld a,$1c                                                          ; 2010: 3e 1c       >.
    jp error_main                                                     ; 2012: c3 05 08    ...

; $2015 referenced 1 time by $2048
minus:
    call itemn                                                        ; 2015: cd ce 1f    ...
minus0:
    dec c                                                             ; 2018: 0d          .
    inc c                                                             ; 2019: 0c          .
    jr z,negate_eval                                                  ; 201a: 28 06       (.
    ld a,h                                                            ; 201c: 7c          |
    xor $80                                                           ; 201d: ee 80       ..
    ld h,a                                                            ; 201f: 67          g
    xor a                                                             ; 2020: af          .
    ret                                                               ; 2021: c9          .

; $2022 referenced 1 time by $201a
negate_eval:
    exx                                                               ; 2022: d9          .
    ld a,h                                                            ; 2023: 7c          |
    cpl                                                               ; 2024: 2f          /
    ld h,a                                                            ; 2025: 67          g
    ld a,l                                                            ; 2026: 7d          }
    cpl                                                               ; 2027: 2f          /
    ld l,a                                                            ; 2028: 6f          o
    exx                                                               ; 2029: d9          .
    ld a,h                                                            ; 202a: 7c          |
    cpl                                                               ; 202b: 2f          /
    ld h,a                                                            ; 202c: 67          g
    ld a,l                                                            ; 202d: 7d          }
    cpl                                                               ; 202e: 2f          /
    ld l,a                                                            ; 202f: 6f          o
; $2030 referenced 1 time by $2310
add1_eval:
    exx                                                               ; 2030: d9          .
    inc hl                                                            ; 2031: 23          #
    ld a,h                                                            ; 2032: 7c          |
    or l                                                              ; 2033: b5          .
    exx                                                               ; 2034: d9          .
    ld a,0                                                            ; 2035: 3e 00       >.
    ret nz                                                            ; 2037: c0          .
    inc hl                                                            ; 2038: 23          #
    ret                                                               ; 2039: c9          .

; $203a referenced 5 times by $1f9f, $1fad, $1fce, $1fd5, $1fde
item:
    call check                                                        ; 203a: cd e9 16    ...
    call nxt                                                          ; 203d: cd a2 25    ..%
    inc iy                                                            ; 2040: fd 23       .#
    cp $26                                                            ; 2042: fe 26       .&
    jr z,hex_eval                                                     ; 2044: 28 aa       (.
    cp $2d                                                            ; 2046: fe 2d       .-
    jr z,minus                                                        ; 2048: 28 cb       (.
    cp $2b                                                            ; 204a: fe 2b       .+
    jr z,itemn                                                        ; 204c: 28 80       (.
    cp $28                                                            ; 204e: fe 28       .(
    jr z,item1                                                        ; 2050: 28 96       (.
    cp $22                                                            ; 2052: fe 22       ."
    jr z,cons                                                         ; 2054: 28 63       (c
    cp $c6                                                            ; 2056: fe c6       ..
    jp nc,syntax                                                      ; 2058: d2 e9 0e    ...
    cp $8d                                                            ; 205b: fe 8d       ..
    jp nc,dispat_eval                                                 ; 205d: d2 b3 25    ..%
    dec iy                                                            ; 2060: fd 2b       .+
    cp $3a                                                            ; 2062: fe 3a       .:
    jr nc,item2                                                       ; 2064: 30 08       0.
    cp $30                                                            ; 2066: fe 30       .0
    jr nc,con_eval                                                    ; 2068: 30 74       0t
    cp $2e                                                            ; 206a: fe 2e       ..
    jr z,con_eval                                                     ; 206c: 28 70       (p
; $206e referenced 1 time by $2064
item2:
    call getvar                                                       ; 206e: cd 69 0a    .i.
    jr nz,nosuch                                                      ; 2071: 20 2b        +
    or a                                                              ; 2073: b7          .
    jp m,loads                                                        ; 2074: fa 01 21    ..!
; $2077 referenced 3 times by $0aef, $11ec, $1797
loadn:
    or a                                                              ; 2077: b7          .
    jr z,load1_eval                                                   ; 2078: 28 18       (.
    ld c,0                                                            ; 207a: 0e 00       ..
    bit 0,a                                                           ; 207c: cb 47       .G
    jr z,load4                                                        ; 207e: 28 03       (.
; $2080 referenced 2 times by $22b2, $22e2
load5:
    ld c,(ix+4)                                                       ; 2080: dd 4e 04    .N.
; $2083 referenced 4 times by $16b8, $207e, $20b7, $2107
load4:
    exx                                                               ; 2083: d9          .
    ld l,(ix+0)                                                       ; 2084: dd 6e 00    .n.
    ld h,(ix+1)                                                       ; 2087: dd 66 01    .f.
    exx                                                               ; 208a: d9          .
    ld l,(ix+2)                                                       ; 208b: dd 6e 02    .n.
    ld h,(ix+3)                                                       ; 208e: dd 66 03    .f.
    ret                                                               ; 2091: c9          .

; $2092 referenced 1 time by $2078
load1_eval:
    ld hl,0                                                           ; 2092: 21 00 00    !..
    exx                                                               ; 2095: d9          .
    ld h,0                                                            ; 2096: 26 00       &.
    ld l,(ix+0)                                                       ; 2098: dd 6e 00    .n.
    exx                                                               ; 209b: d9          .
    ld c,h                                                            ; 209c: 4c          L
    ret                                                               ; 209d: c9          .

; $209e referenced 1 time by $2071
nosuch:
    jp c,syntax                                                       ; 209e: da e9 0e    ...
    ld a,(liston)                                                     ; 20a1: 3a fe 3f    :.?
    bit 5,a                                                           ; 20a4: cb 6f       .o
    ld a,$1a                                                          ; 20a6: 3e 1a       >.
    jr nz,error0_eval                                                 ; 20a8: 20 23        #
; $20aa referenced 1 time by $20af
nos1:
    inc iy                                                            ; 20aa: fd 23       .#
    call range                                                        ; 20ac: cd 50 0c    .P.
    jr nc,nos1                                                        ; 20af: 30 f9       0.
    ld ix,$3f40                                                       ; 20b1: dd 21 40... .!@
    xor a                                                             ; 20b5: af          .
    ld c,a                                                            ; 20b6: 4f          O
    jr load4                                                          ; 20b7: 18 ca       ..

; $20b9 referenced 3 times by $13db, $1893, $2054
cons:
    ld de,$3d00                                                       ; 20b9: 11 00 3d    ..=
; $20bc referenced 1 time by $20c9
cons3:
    ld a,(iy+0)                                                       ; 20bc: fd 7e 00    .~.
    inc iy                                                            ; 20bf: fd 23       .#
    cp $22                                                            ; 20c1: fe 22       ."
    jr z,cons2                                                        ; 20c3: 28 0b       (.
; $20c5 referenced 1 time by $20d7
cons1:
    ld (de),a                                                         ; 20c5: 12          .
    inc e                                                             ; 20c6: 1c          .
    cp $0d                                                            ; 20c7: fe 0d       ..
    jr nz,cons3                                                       ; 20c9: 20 f1        .
    ld a,9                                                            ; 20cb: 3e 09       >.
; $20cd referenced 2 times by $20a8, $20e7
error0_eval:
    jp error_main                                                     ; 20cd: c3 05 08    ...

; $20d0 referenced 1 time by $20c3
cons2:
    ld a,(iy+0)                                                       ; 20d0: fd 7e 00    .~.
    cp $22                                                            ; 20d3: fe 22       ."
    inc iy                                                            ; 20d5: fd 23       .#
    jr z,cons1                                                        ; 20d7: 28 ec       (.
    dec iy                                                            ; 20d9: fd 2b       .+
    ld a,$80                                                          ; 20db: 3e 80       >.
    ret                                                               ; 20dd: c9          .

; $20de referenced 2 times by $2068, $206c
con_eval:
    push iy                                                           ; 20de: fd e5       ..
    pop ix                                                            ; 20e0: dd e1       ..
    ld a,$24                                                          ; 20e2: 3e 24       >$
    call fpp                                                          ; 20e4: cd c6 25    ..%
    jr c,error0_eval                                                  ; 20e7: 38 e4       8.
    push ix                                                           ; 20e9: dd e5       ..
    pop iy                                                            ; 20eb: fd e1       ..
    xor a                                                             ; 20ed: af          .
    ret                                                               ; 20ee: c9          .

; $20ef referenced 2 times by $11e4, $1204
dload5_eval:
    ld b,(ix+4)                                                       ; 20ef: dd 46 04    .F.
    exx                                                               ; 20f2: d9          .
    ld e,(ix+0)                                                       ; 20f3: dd 5e 00    .^.
    ld d,(ix+1)                                                       ; 20f6: dd 56 01    .V.
    exx                                                               ; 20f9: d9          .
    ld e,(ix+2)                                                       ; 20fa: dd 5e 02    .^.
    ld d,(ix+3)                                                       ; 20fd: dd 56 03    .V.
    ret                                                               ; 2100: c9          .

; $2101 referenced 2 times by $17a6, $2074
loads:
    ld de,$3d00                                                       ; 2101: 11 00 3d    ..=
    rra                                                               ; 2104: 1f          .
    jr nc,loads2                                                      ; 2105: 30 10       0.
    call load4                                                        ; 2107: cd 83 20    ..
    exx                                                               ; 210a: d9          .
    ld a,l                                                            ; 210b: 7d          }
    exx                                                               ; 210c: d9          .
    or a                                                              ; 210d: b7          .
    ld c,a                                                            ; 210e: 4f          O
    ld a,$80                                                          ; 210f: 3e 80       >.
    ret z                                                             ; 2111: c8          .
    ld b,0                                                            ; 2112: 06 00       ..
    ldir                                                              ; 2114: ed b0       ..
    ret                                                               ; 2116: c9          .

; $2117 referenced 2 times by $2105, $2120
loads2:
    ld a,(hl)                                                         ; 2117: 7e          ~
    ld (de),a                                                         ; 2118: 12          .
    inc hl                                                            ; 2119: 23          #
    cp $0d                                                            ; 211a: fe 0d       ..
    ld a,$80                                                          ; 211c: 3e 80       >.
    ret z                                                             ; 211e: c8          .
    inc e                                                             ; 211f: 1c          .
    jr nz,loads2                                                      ; 2120: 20 f5        .
    ret                                                               ; 2122: c9          .

pos:
    call getcsr                                                       ; 2123: cd 03 32    ..2
    ex de,hl                                                          ; 2126: eb          .
    jr count1                                                         ; 2127: 18 75       .u

vpos:
    call getcsr                                                       ; 2129: cd 03 32    ..2
    jr count1                                                         ; 212c: 18 70       .p

eof:
    call chanel                                                       ; 212e: cd e1 18    ...
    call osstat                                                       ; 2131: cd 4e 35    .N5
    jp z,true_eval                                                    ; 2134: ca 0b 22    .."
    jp zero_eval                                                      ; 2137: c3 e8 24    ..$

bget:
    call chanel                                                       ; 213a: cd e1 18    ...
    call osbget                                                       ; 213d: cd 34 35    .45
    ld l,a                                                            ; 2140: 6f          o
    jr count0                                                         ; 2141: 18 59       .Y

inkey_eval:
    call inkeys                                                       ; 2143: cd 9e 23    ..#
    jr asc0                                                           ; 2146: 18 19       ..

get:
    call nxt                                                          ; 2148: cd a2 25    ..%
    cp $28                                                            ; 214b: fe 28       .(
    jr nz,get0                                                        ; 214d: 20 0a        .
    call itemi                                                        ; 214f: cd d5 1f    ...
    exx                                                               ; 2152: d9          .
    ld b,h                                                            ; 2153: 44          D
    ld c,l                                                            ; 2154: 4d          M
    in l,(c)                                                          ; 2155: ed 68       .h
    jr count0                                                         ; 2157: 18 43       .C

; $2159 referenced 1 time by $214d
get0:
    call gets                                                         ; 2159: cd 98 23    ..#
    jr asc1                                                           ; 215c: 18 08       ..

asc:
    call items                                                        ; 215e: cd de 1f    ...
; $2161 referenced 1 time by $2146
asc0:
    xor a                                                             ; 2161: af          .
    cp e                                                              ; 2162: bb          .
    jp z,true_eval                                                    ; 2163: ca 0b 22    .."
; $2166 referenced 1 time by $215c
asc1:
    ld hl,(accs)                                                      ; 2166: 2a 00 3d    *.=
    jr count0                                                         ; 2169: 18 31       .1

len:
    call items                                                        ; 216b: cd de 1f    ...
    ex de,hl                                                          ; 216e: eb          .
    jr count0                                                         ; 216f: 18 2b       .+

lomemv_eval:
    ld hl,(lomem)                                                     ; 2171: 2a e0 3f    *.?
    jr count1                                                         ; 2174: 18 28       .(

himemv_eval:
    ld hl,(himem)                                                     ; 2176: 2a e4 3f    *.?
    jr count1                                                         ; 2179: 18 23       .#

pagev_eval:
    ld hl,(page)                                                      ; 217b: 2a dc 3f    *.?
    jr count1                                                         ; 217e: 18 1e       ..

topv:
    ld a,(iy+0)                                                       ; 2180: fd 7e 00    .~.
    inc iy                                                            ; 2183: fd 23       .#
    cp $50                                                            ; 2185: fe 50       .P
    jp nz,syntax                                                      ; 2187: c2 e9 0e    ...
    ld hl,(top)                                                       ; 218a: 2a de 3f    *.?
    jr count1                                                         ; 218d: 18 0f       ..

erlv:
    ld hl,(erl)                                                       ; 218f: 2a f2 3f    *.?
    jr count1                                                         ; 2192: 18 0a       ..

errv:
    ld hl,(err)                                                       ; 2194: 2a fd 3f    *.?
    jr count0                                                         ; 2197: 18 03       ..

countv:
    ld hl,(count)                                                     ; 2199: 2a fb 3f    *.?
; $219c referenced 6 times by $2141, $2157, $2169, $216f, $2197, $21bc
count0:
    ld h,0                                                            ; 219c: 26 00       &.
; $219e referenced 8 times by $2127, $212c, $2174, $2179, $217e, $218d, $2192, $235a
count1:
    exx                                                               ; 219e: d9          .
    xor a                                                             ; 219f: af          .
    ld c,a                                                            ; 21a0: 4f          O
    ld h,a                                                            ; 21a1: 67          g
    ld l,a                                                            ; 21a2: 6f          o
    ret                                                               ; 21a3: c9          .

openot:
    xor a                                                             ; 21a4: af          .
; overlapping: ld hl,$023e                                            ; 21a5: 21 3e 02    !>.
    db $21                                                            ; 21a5: 21          !

openup:
    ld a,2                                                            ; 21a6: 3e 02       >.
; overlapping: ld hl,$013e                                            ; 21a8: 21 3e 01    !>.
    db $21                                                            ; 21a8: 21          !

openin:
    ld a,1                                                            ; 21a9: 3e 01       >.
    push af                                                           ; 21ab: f5          .
    call items                                                        ; 21ac: cd de 1f    ...
    ld a,$0d                                                          ; 21af: 3e 0d       >.
    ld (de),a                                                         ; 21b1: 12          .
    pop af                                                            ; 21b2: f1          .
    add a,$ff                                                         ; 21b3: c6 ff       ..
    ld hl,$3d00                                                       ; 21b5: 21 00 3d    !.=
    call osopen                                                       ; 21b8: cd c8 34    ..4
    ld l,a                                                            ; 21bb: 6f          o
    jr count0                                                         ; 21bc: 18 de       ..

ext_eval:
    call chanel                                                       ; 21be: cd e1 18    ...
    call getext                                                       ; 21c1: cd 55 35    .U5
    jr time0                                                          ; 21c4: 18 12       ..

ptr_eval:
    call chanel                                                       ; 21c6: cd e1 18    ...
    call getptr                                                       ; 21c9: cd 6e 35    .n5
    jr time0                                                          ; 21cc: 18 0a       ..

timev_eval:
    ld a,(iy+0)                                                       ; 21ce: fd 7e 00    .~.
    cp $24                                                            ; 21d1: fe 24       .$
    jr z,timevs_eval                                                  ; 21d3: 28 09       (.
    call getime                                                       ; 21d5: cd 0b 32    ..2
; $21d8 referenced 2 times by $21c4, $21cc
time0:
    push de                                                           ; 21d8: d5          .
    exx                                                               ; 21d9: d9          .
    pop hl                                                            ; 21da: e1          .
    xor a                                                             ; 21db: af          .
    ld c,a                                                            ; 21dc: 4f          O
    ret                                                               ; 21dd: c9          .

; $21de referenced 1 time by $21d3
timevs_eval:
    inc iy                                                            ; 21de: fd 23       .#
    call adval                                                        ; 21e0: cd aa 32    ..2
    ld a,$80                                                          ; 21e3: 3e 80       >.
    ret                                                               ; 21e5: c9          .

slt:
    call scp                                                          ; 21e6: cd e5 24    ..$
    ret nc                                                            ; 21e9: d0          .
    jr true_eval                                                      ; 21ea: 18 1f       ..

sgt:
    call scp                                                          ; 21ec: cd e5 24    ..$
    ret z                                                             ; 21ef: c8          .
    ret c                                                             ; 21f0: d8          .
    jr true_eval                                                      ; 21f1: 18 18       ..

sge:
    call scp                                                          ; 21f3: cd e5 24    ..$
    ret c                                                             ; 21f6: d8          .
    jr true_eval                                                      ; 21f7: 18 12       ..

sle:
    call scp                                                          ; 21f9: cd e5 24    ..$
    jr z,true_eval                                                    ; 21fc: 28 0d       (.
    ret nc                                                            ; 21fe: d0          .
    jr true_eval                                                      ; 21ff: 18 0a       ..

sne:
    call scp                                                          ; 2201: cd e5 24    ..$
    ret z                                                             ; 2204: c8          .
    jr true_eval                                                      ; 2205: 18 04       ..

seq:
    call scp                                                          ; 2207: cd e5 24    ..$
    ret nz                                                            ; 220a: c0          .
; $220b referenced 8 times by $2134, $2163, $21ea, $21f1, $21f7, $21fc, $21ff, $2205
true_eval:
    ld a,$ff                                                          ; 220b: 3e ff       >.
    exx                                                               ; 220d: d9          .
    ld h,a                                                            ; 220e: 67          g
    ld l,a                                                            ; 220f: 6f          o
    exx                                                               ; 2210: d9          .
    ld h,a                                                            ; 2211: 67          g
    ld l,a                                                            ; 2212: 6f          o
    inc a                                                             ; 2213: 3c          <
    ld c,a                                                            ; 2214: 4f          O
    ret                                                               ; 2215: c9          .

pi_eval:
    ld a,$23                                                          ; 2216: 3e 23       >#
    jr fpp1                                                           ; 2218: 18 43       .C

abs_eval:
    ld a,$10                                                          ; 221a: 3e 10       >.
    jr fppn                                                           ; 221c: 18 3a       .:

not_eval:
    ld a,$1a                                                          ; 221e: 3e 1a       >.
    jr fppn                                                           ; 2220: 18 36       .6

deg_eval:
    ld a,$15                                                          ; 2222: 3e 15       >.
    jr fppn                                                           ; 2224: 18 32       .2

rad_eval:
    ld a,$1b                                                          ; 2226: 3e 1b       >.
    jr fppn                                                           ; 2228: 18 2e       ..

sgn_eval:
    ld a,$1c                                                          ; 222a: 3e 1c       >.
    jr fppn                                                           ; 222c: 18 2a       .*

int_eval:
    ld a,$17                                                          ; 222e: 3e 17       >.
    jr fppn                                                           ; 2230: 18 26       .&

sqr_eval:
    ld a,$1e                                                          ; 2232: 3e 1e       >.
    jr fppn                                                           ; 2234: 18 22       ."

tan_eval:
    ld a,$1f                                                          ; 2236: 3e 1f       >.
    jr fppn                                                           ; 2238: 18 1e       ..

cos_eval:
    ld a,$14                                                          ; 223a: 3e 14       >.
    jr fppn                                                           ; 223c: 18 1a       ..

sin_eval:
    ld a,$1d                                                          ; 223e: 3e 1d       >.
    jr fppn                                                           ; 2240: 18 16       ..

exp_eval:
    ld a,$16                                                          ; 2242: 3e 16       >.
    jr fppn                                                           ; 2244: 18 12       ..

ln_eval:
    ld a,$18                                                          ; 2246: 3e 18       >.
    jr fppn                                                           ; 2248: 18 0e       ..

log_eval:
    ld a,$19                                                          ; 224a: 3e 19       >.
    jr fppn                                                           ; 224c: 18 0a       ..

asn_eval:
    ld a,$12                                                          ; 224e: 3e 12       >.
    jr fppn                                                           ; 2250: 18 06       ..

atn_eval:
    ld a,$13                                                          ; 2252: 3e 13       >.
    jr fppn                                                           ; 2254: 18 02       ..

acs_eval:
    ld a,$11                                                          ; 2256: 3e 11       >.
; $2258 referenced 15 times by $221c, $2220, $2224, $2228, $222c, $2230, $2234, $2238, $223c, $2240, $2244, $2248, $224c, $2250, $2254
fppn:
    push af                                                           ; 2258: f5          .
    call itemn                                                        ; 2259: cd ce 1f    ...
    pop af                                                            ; 225c: f1          .
; $225d referenced 4 times by $2218, $2267, $226b, $2278
fpp1:
    call fpp                                                          ; 225d: cd c6 25    ..%
    jp c,error_main                                                   ; 2260: da 05 08    ...
    xor a                                                             ; 2263: af          .
    ret                                                               ; 2264: c9          .

; $2265 referenced 6 times by $0af2, $16a2, $1fc2, $1fd9, $230d, $247d
sfix_eval:
    ld a,$26                                                          ; 2265: 3e 26       >&
    jr fpp1                                                           ; 2267: 18 f4       ..

sfloat_eval:
    ld a,$27                                                          ; 2269: 3e 27       >'
    jr fpp1                                                           ; 226b: 18 f0       ..

val_eval:
    call items                                                        ; 226d: cd de 1f    ...
; $2270 referenced 1 time by $1412
val0:
    xor a                                                             ; 2270: af          .
    ld (de),a                                                         ; 2271: 12          .
    ld ix,$3d00                                                       ; 2272: dd 21 00... .!.
    ld a,$24                                                          ; 2276: 3e 24       >$
    jr fpp1                                                           ; 2278: 18 e3       ..

eval:
    call items                                                        ; 227a: cd de 1f    ...
    ld a,$0d                                                          ; 227d: 3e 0d       >.
    ld (de),a                                                         ; 227f: 12          .
    push iy                                                           ; 2280: fd e5       ..
    ld de,$3d00                                                       ; 2282: 11 00 3d    ..=
    ld iy,$3d00                                                       ; 2285: fd 21 00... .!.
    ld c,0                                                            ; 2289: 0e 00       ..
    call lexan2                                                       ; 228b: cd 7f 0c    ...
    ld (de),a                                                         ; 228e: 12          .
    inc de                                                            ; 228f: 13          .
    xor a                                                             ; 2290: af          .
    call pushs                                                        ; 2291: cd 09 25    ..%
    ld iy,2                                                           ; 2294: fd 21 02... .!.
    add iy,sp                                                         ; 2298: fd 39       .9
    call expr                                                         ; 229a: cd ae 1e    ...
    pop iy                                                            ; 229d: fd e1       ..
    add iy,sp                                                         ; 229f: fd 39       .9
    ld sp,iy                                                          ; 22a1: fd f9       ..
    pop iy                                                            ; 22a3: fd e1       ..
    ex af,af'                                                         ; 22a5: 08          .
    ret                                                               ; 22a6: c9          .

rnd:
    ld ix,$3ff6                                                       ; 22a7: dd 21 f6... .!.
    call nxt                                                          ; 22ab: cd a2 25    ..%
    cp $28                                                            ; 22ae: fe 28       .(
    jr z,rnd5                                                         ; 22b0: 28 1c       (.
    call load5                                                        ; 22b2: cd 80 20    ..
; $22b5 referenced 1 time by $22e5
rnd1:
    rr c                                                              ; 22b5: cb 19       ..
    ld b,$20                                                          ; 22b7: 06 20       .
; $22b9 referenced 1 time by $22c4
rnd2:
    exx                                                               ; 22b9: d9          .
    adc hl,hl                                                         ; 22ba: ed 6a       .j
    exx                                                               ; 22bc: d9          .
    adc hl,hl                                                         ; 22bd: ed 6a       .j
    bit 3,l                                                           ; 22bf: cb 5d       .]
    jr z,rnd3                                                         ; 22c1: 28 01       (.
    ccf                                                               ; 22c3: 3f          ?
; $22c4 referenced 1 time by $22c1
rnd3:
    djnz rnd2                                                         ; 22c4: 10 f3       ..
; $22c6 referenced 1 time by $22d8
rnd4:
    rl c                                                              ; 22c6: cb 11       ..
    call store5                                                       ; 22c8: cd 8d 16    ...
    xor a                                                             ; 22cb: af          .
    ld c,a                                                            ; 22cc: 4f          O
    ret                                                               ; 22cd: c9          .

; $22ce referenced 1 time by $22b0
rnd5:
    call itemi                                                        ; 22ce: cd d5 1f    ...
    ld ix,$3ff6                                                       ; 22d1: dd 21 f6... .!.
    bit 7,h                                                           ; 22d5: cb 7c       .|
    scf                                                               ; 22d7: 37          7
    jr nz,rnd4                                                        ; 22d8: 20 ec        .
    call test_eval                                                    ; 22da: cd 49 24    .I$
    push af                                                           ; 22dd: f5          .
    call swap_eval                                                    ; 22de: cd 41 24    .A$
    exx                                                               ; 22e1: d9          .
    call load5                                                        ; 22e2: cd 80 20    ..
    call nz,rnd1                                                      ; 22e5: c4 b5 22    .."
    exx                                                               ; 22e8: d9          .
    ld c,$7f                                                          ; 22e9: 0e 7f       ..
; $22eb referenced 1 time by $22f5
rnd6:
    bit 7,h                                                           ; 22eb: cb 7c       .|
    jr nz,rnd7                                                        ; 22ed: 20 08        .
    exx                                                               ; 22ef: d9          .
    add hl,hl                                                         ; 22f0: 29          )
    exx                                                               ; 22f1: d9          .
    adc hl,hl                                                         ; 22f2: ed 6a       .j
    dec c                                                             ; 22f4: 0d          .
    jr nz,rnd6                                                        ; 22f5: 20 f4        .
; $22f7 referenced 1 time by $22ed
rnd7:
    res 7,h                                                           ; 22f7: cb bc       ..
    pop af                                                            ; 22f9: f1          .
    ret z                                                             ; 22fa: c8          .
    exx                                                               ; 22fb: d9          .
    ld a,e                                                            ; 22fc: 7b          {
    dec a                                                             ; 22fd: 3d          =
    or d                                                              ; 22fe: b2          .
    exx                                                               ; 22ff: d9          .
    or e                                                              ; 2300: b3          .
    or d                                                              ; 2301: b2          .
    ret z                                                             ; 2302: c8          .
    ld b,0                                                            ; 2303: 06 00       ..
    ld a,$0a                                                          ; 2305: 3e 0a       >.
    call fpp                                                          ; 2307: cd c6 25    ..%
    jp c,error_main                                                   ; 230a: da 05 08    ...
    call sfix_eval                                                    ; 230d: cd 65 22    .e"
    jp add1_eval                                                      ; 2310: c3 30 20    .0

instr:
    call exprsc                                                       ; 2313: cd 57 25    .W%
    call pushs                                                        ; 2316: cd 09 25    ..%
    call exprs                                                        ; 2319: cd c7 1f    ...
    pop bc                                                            ; 231c: c1          .
    ld hl,0                                                           ; 231d: 21 00 00    !..
    add hl,sp                                                         ; 2320: 39          9
    push bc                                                           ; 2321: c5          .
    ld b,e                                                            ; 2322: 43          C
    call nxt                                                          ; 2323: cd a2 25    ..%
    cp $2c                                                            ; 2326: fe 2c       .,
    ld a,0                                                            ; 2328: 3e 00       >.
    jr nz,instr1                                                      ; 232a: 20 17        .
    inc iy                                                            ; 232c: fd 23       .#
    push bc                                                           ; 232e: c5          .
    push hl                                                           ; 232f: e5          .
    call pushs                                                        ; 2330: cd 09 25    ..%
    call expri                                                        ; 2333: cd be 1f    ...
    pop bc                                                            ; 2336: c1          .
    call pops                                                         ; 2337: cd 28 25    .(%
    pop hl                                                            ; 233a: e1          .
    pop bc                                                            ; 233b: c1          .
    exx                                                               ; 233c: d9          .
    ld a,l                                                            ; 233d: 7d          }
    exx                                                               ; 233e: d9          .
    or a                                                              ; 233f: b7          .
    jr z,instr1                                                       ; 2340: 28 01       (.
    dec a                                                             ; 2342: 3d          =
; $2343 referenced 2 times by $232a, $2340
instr1:
    ld de,$3d00                                                       ; 2343: 11 00 3d    ..=
    call search_eval                                                  ; 2346: cd 5d 23    .]#
    pop de                                                            ; 2349: d1          .
    jr z,instr2                                                       ; 234a: 28 03       (.
    sbc hl,hl                                                         ; 234c: ed 62       .b
    add hl,sp                                                         ; 234e: 39          9
; $234f referenced 1 time by $234a
instr2:
    sbc hl,sp                                                         ; 234f: ed 72       .r
    ex de,hl                                                          ; 2351: eb          .
    ld h,0                                                            ; 2352: 26 00       &.
    add hl,sp                                                         ; 2354: 39          9
    ld sp,hl                                                          ; 2355: f9          .
    ex de,hl                                                          ; 2356: eb          .
    call braket                                                       ; 2357: cd 66 25    .f%
    jp count1                                                         ; 235a: c3 9e 21    ..!

; $235d referenced 2 times by $06ce, $2346
search_eval:
    push bc                                                           ; 235d: c5          .
    ld b,0                                                            ; 235e: 06 00       ..
    ld c,a                                                            ; 2360: 4f          O
    add hl,bc                                                         ; 2361: 09          .
    pop bc                                                            ; 2362: c1          .
    sub c                                                             ; 2363: 91          .
    jr nc,srch4                                                       ; 2364: 30 28       0(
    neg                                                               ; 2366: ed 44       .D
    ld c,a                                                            ; 2368: 4f          O
; $2369 referenced 1 time by $238a
srch1_eval:
    ld a,(de)                                                         ; 2369: 1a          .
    push bc                                                           ; 236a: c5          .
    ld b,0                                                            ; 236b: 06 00       ..
    cpir                                                              ; 236d: ed b1       ..
    ld a,c                                                            ; 236f: 79          y
    pop bc                                                            ; 2370: c1          .
    jr nz,srch4                                                       ; 2371: 20 1b        .
    ld c,a                                                            ; 2373: 4f          O
    dec b                                                             ; 2374: 05          .
    cp b                                                              ; 2375: b8          .
    inc b                                                             ; 2376: 04          .
    jr c,srch4                                                        ; 2377: 38 15       8.
    push bc                                                           ; 2379: c5          .
    push de                                                           ; 237a: d5          .
    push hl                                                           ; 237b: e5          .
    dec b                                                             ; 237c: 05          .
    jr z,srch3                                                        ; 237d: 28 08       (.
; $237f referenced 1 time by $2385
srch2_eval:
    inc de                                                            ; 237f: 13          .
    ld a,(de)                                                         ; 2380: 1a          .
    cp (hl)                                                           ; 2381: be          .
    jr nz,srch3                                                       ; 2382: 20 03        .
    inc hl                                                            ; 2384: 23          #
    djnz srch2_eval                                                   ; 2385: 10 f8       ..
; $2387 referenced 2 times by $237d, $2382
srch3:
    pop hl                                                            ; 2387: e1          .
    pop de                                                            ; 2388: d1          .
    pop bc                                                            ; 2389: c1          .
    jr nz,srch1_eval                                                  ; 238a: 20 dd        .
    xor a                                                             ; 238c: af          .
    ret                                                               ; 238d: c9          .

; $238e referenced 3 times by $2364, $2371, $2377
srch4:
    or $ff                                                            ; 238e: f6 ff       ..
    ret                                                               ; 2390: c9          .

chrs:
    call itemi                                                        ; 2391: cd d5 1f    ...
    exx                                                               ; 2394: d9          .
    ld a,l                                                            ; 2395: 7d          }
    jr get1                                                           ; 2396: 18 03       ..

; $2398 referenced 1 time by $2159
gets:
    call osrdch                                                       ; 2398: cd f6 39    ..9
; $239b referenced 1 time by $2396
get1:
    scf                                                               ; 239b: 37          7
    jr inkey1                                                         ; 239c: 18 07       ..

; $239e referenced 1 time by $2143
inkeys:
    call itemi                                                        ; 239e: cd d5 1f    ...
    exx                                                               ; 23a1: d9          .
    call oskey                                                        ; 23a2: cd 1e 3a    ..:
; $23a5 referenced 1 time by $239c
inkey1:
    ld de,$3d00                                                       ; 23a5: 11 00 3d    ..=
    ld (de),a                                                         ; 23a8: 12          .
    ld a,$80                                                          ; 23a9: 3e 80       >.
    ret nc                                                            ; 23ab: d0          .
    inc e                                                             ; 23ac: 1c          .
    ret                                                               ; 23ad: c9          .

mids:
    call exprsc                                                       ; 23ae: cd 57 25    .W%
    call pushs                                                        ; 23b1: cd 09 25    ..%
    call expri                                                        ; 23b4: cd be 1f    ...
    pop bc                                                            ; 23b7: c1          .
    call pops                                                         ; 23b8: cd 28 25    .(%
    exx                                                               ; 23bb: d9          .
    ld a,l                                                            ; 23bc: 7d          }
    exx                                                               ; 23bd: d9          .
    or a                                                              ; 23be: b7          .
    jr z,mids1                                                        ; 23bf: 28 0d       (.
    dec a                                                             ; 23c1: 3d          =
    ld l,a                                                            ; 23c2: 6f          o
    sub e                                                             ; 23c3: 93          .
    ld e,0                                                            ; 23c4: 1e 00       ..
    jr nc,mids1                                                       ; 23c6: 30 06       0.
    neg                                                               ; 23c8: ed 44       .D
    ld c,a                                                            ; 23ca: 4f          O
    call right1                                                       ; 23cb: cd 05 24    ..$
; $23ce referenced 2 times by $23bf, $23c6
mids1:
    call nxt                                                          ; 23ce: cd a2 25    ..%
    cp $2c                                                            ; 23d1: fe 2c       .,
    inc iy                                                            ; 23d3: fd 23       .#
    jr z,left1                                                        ; 23d5: 28 0b       (.
    dec iy                                                            ; 23d7: fd 2b       .+
    call braket                                                       ; 23d9: cd 66 25    .f%
    ld a,$80                                                          ; 23dc: 3e 80       >.
    ret                                                               ; 23de: c9          .

; $23df referenced 1 time by $23fa
lefts:
    call exprsc                                                       ; 23df: cd 57 25    .W%
; $23e2 referenced 1 time by $23d5
left1:
    call pushs                                                        ; 23e2: cd 09 25    ..%
    call expri                                                        ; 23e5: cd be 1f    ...
    pop bc                                                            ; 23e8: c1          .
    call pops                                                         ; 23e9: cd 28 25    .(%
    call braket                                                       ; 23ec: cd 66 25    .f%
    exx                                                               ; 23ef: d9          .
    ld a,l                                                            ; 23f0: 7d          }
    exx                                                               ; 23f1: d9          .
    cp e                                                              ; 23f2: bb          .
    jr nc,left3                                                       ; 23f3: 30 02       0.
    ld l,e                                                            ; 23f5: 6b          k
; $23f6 referenced 1 time by $2420
left2:
    ld e,a                                                            ; 23f6: 5f          _
; $23f7 referenced 1 time by $23f3
left3:
    ld a,$80                                                          ; 23f7: 3e 80       >.
    ret                                                               ; 23f9: c9          .

rights:
    call lefts                                                        ; 23fa: cd df 23    ..#
    ret nc                                                            ; 23fd: d0          .
    inc e                                                             ; 23fe: 1c          .
    dec e                                                             ; 23ff: 1d          .
    ret z                                                             ; 2400: c8          .
    ld c,e                                                            ; 2401: 4b          K
    ld a,l                                                            ; 2402: 7d          }
    sub e                                                             ; 2403: 93          .
    ld l,a                                                            ; 2404: 6f          o
; $2405 referenced 1 time by $23cb
right1:
    ld b,0                                                            ; 2405: 06 00       ..
    ld h,d                                                            ; 2407: 62          b
    ld e,b                                                            ; 2408: 58          X
    ldir                                                              ; 2409: ed b0       ..
    ld a,$80                                                          ; 240b: 3e 80       >.
    ret                                                               ; 240d: c9          .

string:
    call expri                                                        ; 240e: cd be 1f    ...
    call comma                                                        ; 2411: cd 5a 25    .Z%
    exx                                                               ; 2414: d9          .
    ld a,l                                                            ; 2415: 7d          }
    exx                                                               ; 2416: d9          .
    push af                                                           ; 2417: f5          .
    call exprs                                                        ; 2418: cd c7 1f    ...
    call braket                                                       ; 241b: cd 66 25    .f%
    pop af                                                            ; 241e: f1          .
    or a                                                              ; 241f: b7          .
    jr z,left2                                                        ; 2420: 28 d4       (.
    dec a                                                             ; 2422: 3d          =
    ld c,a                                                            ; 2423: 4f          O
    ld a,$80                                                          ; 2424: 3e 80       >.
    ret z                                                             ; 2426: c8          .
    inc e                                                             ; 2427: 1c          .
    dec e                                                             ; 2428: 1d          .
    ret z                                                             ; 2429: c8          .
    ld b,e                                                            ; 242a: 43          C
    ld h,d                                                            ; 242b: 62          b
    ld l,0                                                            ; 242c: 2e 00       ..
; $242e referenced 1 time by $243c
strin1:
    push bc                                                           ; 242e: c5          .
; $242f referenced 1 time by $2438
strin2:
    ld a,(hl)                                                         ; 242f: 7e          ~
    inc hl                                                            ; 2430: 23          #
    ld (de),a                                                         ; 2431: 12          .
    inc e                                                             ; 2432: 1c          .
    ld a,$13                                                          ; 2433: 3e 13       >.
    jp z,error_main                                                   ; 2435: ca 05 08    ...
    djnz strin2                                                       ; 2438: 10 f5       ..
    pop bc                                                            ; 243a: c1          .
    dec c                                                             ; 243b: 0d          .
    jr nz,strin1                                                      ; 243c: 20 f0        .
    ld a,$80                                                          ; 243e: 3e 80       >.
    ret                                                               ; 2440: c9          .

; $2441 referenced 2 times by $1208, $22de
swap_eval:
    ld a,c                                                            ; 2441: 79          y
    ld c,b                                                            ; 2442: 48          H
    ld b,a                                                            ; 2443: 47          G
    ex de,hl                                                          ; 2444: eb          .
    exx                                                               ; 2445: d9          .
    ex de,hl                                                          ; 2446: eb          .
    exx                                                               ; 2447: d9          .
    ret                                                               ; 2448: c9          .

; $2449 referenced 3 times by $1169, $14a5, $22da
test_eval:
    ld a,h                                                            ; 2449: 7c          |
    or l                                                              ; 244a: b5          .
    exx                                                               ; 244b: d9          .
    or h                                                              ; 244c: b4          .
    or l                                                              ; 244d: b5          .
    exx                                                               ; 244e: d9          .
    ret                                                               ; 244f: c9          .

; $2450 referenced 2 times by $0763, $095f
decode:
    exx                                                               ; 2450: d9          .
    ld a,(iy+0)                                                       ; 2451: fd 7e 00    .~.
    inc iy                                                            ; 2454: fd 23       .#
    rla                                                               ; 2456: 17          .
    rla                                                               ; 2457: 17          .
    ld h,a                                                            ; 2458: 67          g
    and $c0                                                           ; 2459: e6 c0       ..
    xor (iy+0)                                                        ; 245b: fd ae 00    ...
    inc iy                                                            ; 245e: fd 23       .#
    ld l,a                                                            ; 2460: 6f          o
    ld a,h                                                            ; 2461: 7c          |
    rla                                                               ; 2462: 17          .
    rla                                                               ; 2463: 17          .
    and $c0                                                           ; 2464: e6 c0       ..
    xor (iy+0)                                                        ; 2466: fd ae 00    ...
    inc iy                                                            ; 2469: fd 23       .#
    ld h,a                                                            ; 246b: 67          g
    exx                                                               ; 246c: d9          .
    xor a                                                             ; 246d: af          .
    ld c,a                                                            ; 246e: 4f          O
    ld h,a                                                            ; 246f: 67          g
    ld l,a                                                            ; 2470: 6f          o
    ret                                                               ; 2471: c9          .

; $2472 referenced 1 time by $24ad
hexsts:
    inc iy                                                            ; 2472: fd 23       .#
    call itemn                                                        ; 2474: cd ce 1f    ...
    call hexstr                                                       ; 2477: cd 7d 24    .}$
    ld a,$80                                                          ; 247a: 3e 80       >.
    ret                                                               ; 247c: c9          .

; $247d referenced 2 times by $1087, $2477
hexstr:
    call sfix_eval                                                    ; 247d: cd 65 22    .e"
    ld bc,8                                                           ; 2480: 01 08 00    ...
    ld de,$3d00                                                       ; 2483: 11 00 3d    ..=
; $2486 referenced 2 times by $249b, $24a6
hexst1:
    push bc                                                           ; 2486: c5          .
    ld b,4                                                            ; 2487: 06 04       ..
    xor a                                                             ; 2489: af          .
; $248a referenced 1 time by $2490
hexst2:
    exx                                                               ; 248a: d9          .
    add hl,hl                                                         ; 248b: 29          )
    exx                                                               ; 248c: d9          .
    adc hl,hl                                                         ; 248d: ed 6a       .j
    rla                                                               ; 248f: 17          .
    djnz hexst2                                                       ; 2490: 10 f8       ..
    pop bc                                                            ; 2492: c1          .
    dec c                                                             ; 2493: 0d          .
    ret m                                                             ; 2494: f8          .
    jr z,hexst3                                                       ; 2495: 28 06       (.
    or a                                                              ; 2497: b7          .
    jr nz,hexst3                                                      ; 2498: 20 03        .
    cp b                                                              ; 249a: b8          .
    jr z,hexst1                                                       ; 249b: 28 e9       (.
; $249d referenced 2 times by $2495, $2498
hexst3:
    add a,$90                                                         ; 249d: c6 90       ..
    daa                                                               ; 249f: 27          '
    adc a,$40                                                         ; 24a0: ce 40       .@
    daa                                                               ; 24a2: 27          '
    ld (de),a                                                         ; 24a3: 12          .
    inc de                                                            ; 24a4: 13          .
    ld b,a                                                            ; 24a5: 47          G
    jr hexst1                                                         ; 24a6: 18 de       ..

strs:
    call nxt                                                          ; 24a8: cd a2 25    ..%
    cp $7e                                                            ; 24ab: fe 7e       .~
    jr z,hexsts                                                       ; 24ad: 28 c3       (.
    call itemn                                                        ; 24af: cd ce 1f    ...
    ld ix,$3f00                                                       ; 24b2: dd 21 00... .!.
    ld a,(ix+3)                                                       ; 24b6: dd 7e 03    .~.
    or a                                                              ; 24b9: b7          .
    ld ix,$24e2                                                       ; 24ba: dd 21 e2... .!.
    jr z,str0                                                         ; 24be: 28 04       (.
; $24c0 referenced 1 time by $1083
str_eval:
    ld ix,$3f00                                                       ; 24c0: dd 21 00... .!.
; $24c4 referenced 1 time by $24be
str0:
    ld de,$3d00                                                       ; 24c4: 11 00 3d    ..=
    ld a,$25                                                          ; 24c7: 3e 25       >%
    call fpp                                                          ; 24c9: cd c6 25    ..%
    jp c,error_main                                                   ; 24cc: da 05 08    ...
    bit 0,(ix+2)                                                      ; 24cf: dd cb 02... ...
; $24d3 referenced 1 time by $24da
str1:
    ld a,$80                                                          ; 24d3: 3e 80       >.
    ret z                                                             ; 24d5: c8          .
    ld a,c                                                            ; 24d6: 79          y
    add a,4                                                           ; 24d7: c6 04       ..
; $24d9 referenced 1 time by $24e1
str2_eval:
    cp e                                                              ; 24d9: bb          .
    jr z,str1                                                         ; 24da: 28 f7       (.
    ex de,hl                                                          ; 24dc: eb          .
    ld (hl),$20                                                       ; 24dd: 36 20       6
    inc hl                                                            ; 24df: 23          #
    ex de,hl                                                          ; 24e0: eb          .
    jr str2_eval                                                      ; 24e1: 18 f6       ..

g9:
    db 9, 0                                                           ; 24e3: 09 00       ..

; $24e5 referenced 6 times by $21e6, $21ec, $21f3, $21f9, $2201, $2207
scp:
    call scp0                                                         ; 24e5: cd f2 24    ..$
; $24e8 referenced 4 times by $130b, $19b3, $1ff0, $2137
zero_eval:
    ld a,0                                                            ; 24e8: 3e 00       >.
    exx                                                               ; 24ea: d9          .
    ld h,a                                                            ; 24eb: 67          g
    ld l,a                                                            ; 24ec: 6f          o
    exx                                                               ; 24ed: d9          .
    ld h,a                                                            ; 24ee: 67          g
    ld l,a                                                            ; 24ef: 6f          o
    ld c,a                                                            ; 24f0: 4f          O
    ret                                                               ; 24f1: c9          .

; $24f2 referenced 1 time by $24e5
scp0:
    inc b                                                             ; 24f2: 04          .
    inc c                                                             ; 24f3: 0c          .
; $24f4 referenced 1 time by $24ff
scp1:
    dec b                                                             ; 24f4: 05          .
    jr z,scp2                                                         ; 24f5: 28 0a       (.
    dec c                                                             ; 24f7: 0d          .
    jr z,scp3                                                         ; 24f8: 28 0c       (.
    ld a,(de)                                                         ; 24fa: 1a          .
    cp (hl)                                                           ; 24fb: be          .
    ret nz                                                            ; 24fc: c0          .
    inc de                                                            ; 24fd: 13          .
    inc hl                                                            ; 24fe: 23          #
    jr scp1                                                           ; 24ff: 18 f3       ..

; $2501 referenced 1 time by $24f5
scp2:
    or a                                                              ; 2501: b7          .
    dec c                                                             ; 2502: 0d          .
    ret z                                                             ; 2503: c8          .
    scf                                                               ; 2504: 37          7
    ret                                                               ; 2505: c9          .

; $2506 referenced 1 time by $24f8
scp3:
    or a                                                              ; 2506: b7          .
    inc c                                                             ; 2507: 0c          .
    ret                                                               ; 2508: c9          .

; $2509 referenced 8 times by $173c, $1f0a, $1f50, $2291, $2316, $2330, $23b1, $23e2
pushs:
    call check                                                        ; 2509: cd e9 16    ...
    pop ix                                                            ; 250c: dd e1       ..
    or a                                                              ; 250e: b7          .
    ld hl,$3d00                                                       ; 250f: 21 00 3d    !.=
    ld d,h                                                            ; 2512: 54          T
    ld b,l                                                            ; 2513: 45          E
    sbc hl,de                                                         ; 2514: ed 52       .R
    add hl,sp                                                         ; 2516: 39          9
    ld sp,hl                                                          ; 2517: f9          .
    ld d,a                                                            ; 2518: 57          W
    push de                                                           ; 2519: d5          .
    jr z,pushs1                                                       ; 251a: 28 0a       (.
    ld c,e                                                            ; 251c: 4b          K
    ld de,$3d00                                                       ; 251d: 11 00 3d    ..=
    ex de,hl                                                          ; 2520: eb          .
    ldir                                                              ; 2521: ed b0       ..
    call check                                                        ; 2523: cd e9 16    ...
; $2526 referenced 1 time by $251a
pushs1:
    jp (ix)                                                           ; 2526: dd e9       ..

; $2528 referenced 5 times by $1770, $1f76, $2337, $23b8, $23e9
pops:
    pop ix                                                            ; 2528: dd e1       ..
    ld hl,0                                                           ; 252a: 21 00 00    !..
    ld b,h                                                            ; 252d: 44          D
    add hl,sp                                                         ; 252e: 39          9
    ld de,$3d00                                                       ; 252f: 11 00 3d    ..=
    inc c                                                             ; 2532: 0c          .
    dec c                                                             ; 2533: 0d          .
    jr z,pops1                                                        ; 2534: 28 02       (.
    ldir                                                              ; 2536: ed b0       ..
; $2538 referenced 1 time by $2534
pops1:
    ld sp,hl                                                          ; 2538: f9          .
    jp (ix)                                                           ; 2539: dd e9       ..

; $253b referenced 2 times by $1ff3, $2009
hexdig:
    ld a,(iy+0)                                                       ; 253b: fd 7e 00    .~.
    cp $30                                                            ; 253e: fe 30       .0
    ret c                                                             ; 2540: d8          .
    cp $3a                                                            ; 2541: fe 3a       .:
    ccf                                                               ; 2543: 3f          ?
    ret nc                                                            ; 2544: d0          .
    cp $41                                                            ; 2545: fe 41       .A
    ret c                                                             ; 2547: d8          .
    sub $37                                                           ; 2548: d6 37       .7
    cp $10                                                            ; 254a: fe 10       ..
    ccf                                                               ; 254c: 3f          ?
    ret                                                               ; 254d: c9          .

; $254e referenced 2 times by $1ed7, $1ee1
relopq:
    cp $3e                                                            ; 254e: fe 3e       .>
    ret nc                                                            ; 2550: d0          .
    cp $3d                                                            ; 2551: fe 3d       .=
    ret nc                                                            ; 2553: d0          .
    cp $3c                                                            ; 2554: fe 3c       .<
    ret                                                               ; 2556: c9          .

; $2557 referenced 3 times by $2313, $23ae, $23df
exprsc:
    call exprs                                                        ; 2557: cd c7 1f    ...
; $255a referenced 5 times by $0a92, $15e8, $1667, $2411, $32a1
comma:
    call nxt                                                          ; 255a: cd a2 25    ..%
    inc iy                                                            ; 255d: fd 23       .#
    cp $2c                                                            ; 255f: fe 2c       .,
    ret z                                                             ; 2561: c8          .
    ld a,5                                                            ; 2562: 3e 05       >.
    jr error1_eval                                                    ; 2564: 18 0a       ..

; $2566 referenced 11 times by $0ab6, $0f7f, $12b5, $1751, $182a, $1845, $1feb, $2357, $23d9, $23ec, $241b
braket:
    call nxt                                                          ; 2566: cd a2 25    ..%
    inc iy                                                            ; 2569: fd 23       .#
    cp $29                                                            ; 256b: fe 29       .)
    ret z                                                             ; 256d: c8          .
    ld a,$1b                                                          ; 256e: 3e 1b       >.
; $2570 referenced 2 times by $2564, $259a
error1_eval:
    jp error_main                                                     ; 2570: c3 05 08    ...

; $2573 referenced 5 times by $1eb8, $1ec9, $1f42, $1f94, $1faa
save_eval:
    inc iy                                                            ; 2573: fd 23       .#
; $2575 referenced 1 time by $1efc
save1_eval:
    ex af,af'                                                         ; 2575: 08          .
    jp m,type_eval                                                    ; 2576: fa e3 1f    ...
    ex af,af'                                                         ; 2579: 08          .
    ex (sp),hl                                                        ; 257a: e3          .
    exx                                                               ; 257b: d9          .
    push hl                                                           ; 257c: e5          .
    exx                                                               ; 257d: d9          .
    push af                                                           ; 257e: f5          .
    push bc                                                           ; 257f: c5          .
    jp (hl)                                                           ; 2580: e9          .

; $2581 referenced 6 times by $1ebe, $1ecf, $1f02, $1f48, $1f9a, $1fb2
doit:
    ex af,af'                                                         ; 2581: 08          .
    jp m,type_eval                                                    ; 2582: fa e3 1f    ...
    exx                                                               ; 2585: d9          .
    pop bc                                                            ; 2586: c1          .
    exx                                                               ; 2587: d9          .
    ld a,c                                                            ; 2588: 79          y
    pop bc                                                            ; 2589: c1          .
    ld b,a                                                            ; 258a: 47          G
    pop af                                                            ; 258b: f1          .
    exx                                                               ; 258c: d9          .
    ex de,hl                                                          ; 258d: eb          .
    pop hl                                                            ; 258e: e1          .
    exx                                                               ; 258f: d9          .
    ex de,hl                                                          ; 2590: eb          .
    pop hl                                                            ; 2591: e1          .
    exx                                                               ; 2592: d9          .
    push bc                                                           ; 2593: c5          .
    exx                                                               ; 2594: d9          .
    and $0f                                                           ; 2595: e6 0f       ..
    call fpp                                                          ; 2597: cd c6 25    ..%
    jr c,error1_eval                                                  ; 259a: 38 d4       8.
    xor a                                                             ; 259c: af          .
    ex af,af'                                                         ; 259d: 08          .
    ld a,(iy+0)                                                       ; 259e: fd 7e 00    .~.
    ret                                                               ; 25a1: c9          .

; $25a2 referenced 43 times by $01e4, $0671, $067c, $0beb, $0e19, $0e36, $0fa9, $0fb3, $0fec, $10a7, $121a, $126f, $129b, $12a6, $1318, $1322, $135f, $1369, $1487, $1491, $14b4, $1601, $160b, $170c, $1740, $177d, $17cf, $17ec, $1800, $1877, $188c, $18e1, $1ede, $1fa4, $203d, $2148, $22ab, $2323, $23ce, $24a8, $255a, $2566, $25aa
nxt:
    ld a,(iy+0)                                                       ; 25a2: fd 7e 00    .~.
    cp $20                                                            ; 25a5: fe 20       .
    ret nz                                                            ; 25a7: c0          .
    inc iy                                                            ; 25a8: fd 23       .#
    jp nxt                                                            ; 25aa: c3 a2 25    ..%

; $25ad referenced 1 time by $1f22
dispt2:
    push hl                                                           ; 25ad: e5          .
    ld hl,$1ea2                                                       ; 25ae: 21 a2 1e    !..
    jr dispt0                                                         ; 25b1: 18 06       ..

; $25b3 referenced 1 time by $205d
dispat_eval:
    push hl                                                           ; 25b3: e5          .
    sub $8d                                                           ; 25b4: d6 8d       ..
    ld hl,$1e30                                                       ; 25b6: 21 30 1e    !0.
; $25b9 referenced 1 time by $25b1
dispt0:
    push bc                                                           ; 25b9: c5          .
    add a,a                                                           ; 25ba: 87          .
    ld c,a                                                            ; 25bb: 4f          O
    ld b,0                                                            ; 25bc: 06 00       ..
    add hl,bc                                                         ; 25be: 09          .
    ld a,(hl)                                                         ; 25bf: 7e          ~
    inc hl                                                            ; 25c0: 23          #
    ld h,(hl)                                                         ; 25c1: 66          f
    ld l,a                                                            ; 25c2: 6f          o
    pop bc                                                            ; 25c3: c1          .
    ex (sp),hl                                                        ; 25c4: e3          .
    ret                                                               ; 25c5: c9          .

; $25c6 referenced 7 times by $11f4, $120d, $20e4, $225d, $2307, $24c9, $2597
fpp:
    push iy                                                           ; 25c6: fd e5       ..
    ld iy,0                                                           ; 25c8: fd 21 00... .!.
    add iy,sp                                                         ; 25cc: fd 39       .9
    call op                                                           ; 25ce: cd dd 25    ..%
    cp a                                                              ; 25d1: bf          .
; $25d2 referenced 1 time by $25db
exit_fpp:
    pop iy                                                            ; 25d2: fd e1       ..
    ret                                                               ; 25d4: c9          .

; $25d5 referenced 1 time by $25df
bad_fpp:
    ld a,1                                                            ; 25d5: 3e 01       >.
; $25d7 referenced 7 times by $2760, $29ba, $2ae3, $2b5a, $2b5f, $2eee, $2fb6
error_fpp:
    ld sp,iy                                                          ; 25d7: fd f9       ..
    or a                                                              ; 25d9: b7          .
    scf                                                               ; 25da: 37          7
    jr exit_fpp                                                       ; 25db: 18 f5       ..

; $25dd referenced 3 times by $25ce, $2899, $28a0
op:
    cp $2a                                                            ; 25dd: fe 2a       .*
    jr nc,bad_fpp                                                     ; 25df: 30 f4       0.
    cp $10                                                            ; 25e1: fe 10       ..
    jr nc,dispat_fpp                                                  ; 25e3: 30 07       0.
    ex af,af'                                                         ; 25e5: 08          .
    ld a,b                                                            ; 25e6: 78          x
    or c                                                              ; 25e7: b1          .
    call nz,floata                                                    ; 25e8: c4 67 2f    .g/
    ex af,af'                                                         ; 25eb: 08          .
; $25ec referenced 1 time by $25e3
dispat_fpp:
    push hl                                                           ; 25ec: e5          .
    ld hl,$25fd                                                       ; 25ed: 21 fd 25    !.%
    push bc                                                           ; 25f0: c5          .
    add a,a                                                           ; 25f1: 87          .
    ld c,a                                                            ; 25f2: 4f          O
    ld b,0                                                            ; 25f3: 06 00       ..
    add hl,bc                                                         ; 25f5: 09          .
    ld a,(hl)                                                         ; 25f6: 7e          ~
    inc hl                                                            ; 25f7: 23          #
    ld h,(hl)                                                         ; 25f8: 66          f
    ld l,a                                                            ; 25f9: 6f          o
    pop bc                                                            ; 25fa: c1          .
    ex (sp),hl                                                        ; 25fb: e3          .
    ret                                                               ; 25fc: c9          .

dtable:
    dw iand                                                           ; 25fd: 74 26       t&
    dw ibdiv                                                          ; 25ff: d7 26       .&
    dw ieor                                                           ; 2601: 86 26       .&
    dw imod                                                           ; 2603: aa 26       .&
    dw ior                                                            ; 2605: 98 26       .&
    dw ile                                                            ; 2607: 06 29       .)
    dw ine                                                            ; 2609: 13 29       .)
    dw ige                                                            ; 260b: fb 28       .(
    dw ilt                                                            ; 260d: e4 28       .(
    dw ieq                                                            ; 260f: 1e 29       .)
    dw imul                                                           ; 2611: a1 27       .'
    dw iadd                                                           ; 2613: fa 26       .&
    dw igt                                                            ; 2615: ef 28       .(
    dw isub                                                           ; 2617: e4 26       .&
    dw ipow                                                           ; 2619: 3f 28       ?(
    dw idiv                                                           ; 261b: 59 27       Y'
ftable:
    dw abs_fpp                                                        ; 261d: 2d 29       -)
    dw acs_fpp                                                        ; 261f: 89 2c       .,
    dw asn_fpp                                                        ; 2621: e5 2b       .+
    dw atn_fpp                                                        ; 2623: 0a 2c       .,
    dw cos_fpp                                                        ; 2625: 23 2a       #*
    dw deg_fpp                                                        ; 2627: 57 29       W)
    dw exp_fpp                                                        ; 2629: c8 2a       .*
    dw int_fpp                                                        ; 262b: 9d 29       .)
    dw ln_fpp                                                         ; 262d: 53 2b       S+
    dw log_fpp                                                        ; 262f: d3 2b       .+
    dw not_fpp                                                        ; 2631: 38 29       8)
    dw rad_fpp                                                        ; 2633: 5f 29       _)
    dw sgn_fpp                                                        ; 2635: 75 29       u)
    dw sin_fpp                                                        ; 2637: 2e 2a       .*
    dw sqr_fpp                                                        ; 2639: b3 29       .)
    dw tan_fpp                                                        ; 263b: 06 2a       .*
    dw zero_fpp                                                       ; 263d: e3 2f       ./
    dw fone                                                           ; 263f: a7 2a       .*
    dw true_fpp                                                       ; 2641: 22 29       ")
    dw pi_fpp                                                         ; 2643: 4b 29       K)
    dw val_fpp                                                        ; 2645: 85 29       .)
    dw str_fpp                                                        ; 2647: 91 2c       .,
    dw sfix_fpp                                                       ; 2649: b8 2e       ..
    dw sfloat_fpp                                                     ; 264b: 74 2f       t/
    dw ftest                                                          ; 264d: b9 2f       ./
    dw fcomp                                                          ; 264f: ca 2f       ./
rtable:
    dw fand                                                           ; 2651: 71 26       q&
    dw fbdiv                                                          ; 2653: d4 26       .&
    dw feor                                                           ; 2655: 83 26       .&
    dw fmod                                                           ; 2657: a7 26       .&
    dw for_fpp                                                        ; 2659: 95 26       .&
    dw fle                                                            ; 265b: 01 29       .)
    dw fne                                                            ; 265d: 0e 29       .)
    dw fge                                                            ; 265f: f6 28       .(
    dw flt                                                            ; 2661: df 28       .(
    dw feq                                                            ; 2663: 19 29       .)
    dw fmul                                                           ; 2665: ef 27       .'
    dw fadd                                                           ; 2667: 04 27       .'
    dw fgt                                                            ; 2669: ea 28       .(
    dw fsub                                                           ; 266b: ee 26       .&
    dw fpow                                                           ; 266d: b5 28       .(
    dw fdiv                                                           ; 266f: 5c 27       \'

fand:
    call fix2                                                         ; 2671: cd af 2e    ...
iand:
    ld a,h                                                            ; 2674: 7c          |
    and d                                                             ; 2675: a2          .
    ld h,a                                                            ; 2676: 67          g
    ld a,l                                                            ; 2677: 7d          }
    and e                                                             ; 2678: a3          .
    ld l,a                                                            ; 2679: 6f          o
    exx                                                               ; 267a: d9          .
    ld a,h                                                            ; 267b: 7c          |
    and d                                                             ; 267c: a2          .
    ld h,a                                                            ; 267d: 67          g
    ld a,l                                                            ; 267e: 7d          }
    and e                                                             ; 267f: a3          .
    ld l,a                                                            ; 2680: 6f          o
    exx                                                               ; 2681: d9          .
    ret                                                               ; 2682: c9          .

feor:
    call fix2                                                         ; 2683: cd af 2e    ...
ieor:
    ld a,h                                                            ; 2686: 7c          |
    xor d                                                             ; 2687: aa          .
    ld h,a                                                            ; 2688: 67          g
    ld a,l                                                            ; 2689: 7d          }
    xor e                                                             ; 268a: ab          .
    ld l,a                                                            ; 268b: 6f          o
    exx                                                               ; 268c: d9          .
    ld a,h                                                            ; 268d: 7c          |
    xor d                                                             ; 268e: aa          .
    ld h,a                                                            ; 268f: 67          g
    ld a,l                                                            ; 2690: 7d          }
    xor e                                                             ; 2691: ab          .
    ld l,a                                                            ; 2692: 6f          o
    exx                                                               ; 2693: d9          .
    ret                                                               ; 2694: c9          .

for_fpp:
    call fix2                                                         ; 2695: cd af 2e    ...
ior:
    ld a,h                                                            ; 2698: 7c          |
    or d                                                              ; 2699: b2          .
    ld h,a                                                            ; 269a: 67          g
    ld a,l                                                            ; 269b: 7d          }
    or e                                                              ; 269c: b3          .
    ld l,a                                                            ; 269d: 6f          o
    exx                                                               ; 269e: d9          .
    ld a,h                                                            ; 269f: 7c          |
    or d                                                              ; 26a0: b2          .
    ld h,a                                                            ; 26a1: 67          g
    ld a,l                                                            ; 26a2: 7d          }
    or e                                                              ; 26a3: b3          .
    ld l,a                                                            ; 26a4: 6f          o
    exx                                                               ; 26a5: d9          .
    ret                                                               ; 26a6: c9          .

fmod:
    call fix2                                                         ; 26a7: cd af 2e    ...
; $26aa referenced 1 time by $26d7
imod:
    ld a,h                                                            ; 26aa: 7c          |
    xor d                                                             ; 26ab: aa          .
    bit 7,h                                                           ; 26ac: cb 7c       .|
    ex af,af'                                                         ; 26ae: 08          .
    bit 7,h                                                           ; 26af: cb 7c       .|
    call nz,negate_fpp                                                ; 26b1: c4 c7 2e    ...
    call swap_fpp                                                     ; 26b4: cd 9e 2f    ../
    bit 7,h                                                           ; 26b7: cb 7c       .|
    call nz,negate_fpp                                                ; 26b9: c4 c7 2e    ...
    ld b,h                                                            ; 26bc: 44          D
    ld c,l                                                            ; 26bd: 4d          M
    ld hl,0                                                           ; 26be: 21 00 00    !..
    exx                                                               ; 26c1: d9          .
    ld b,h                                                            ; 26c2: 44          D
    ld c,l                                                            ; 26c3: 4d          M
    ld hl,0                                                           ; 26c4: 21 00 00    !..
    ld a,$df                                                          ; 26c7: 3e df       >.
    call diva                                                         ; 26c9: cd f3 30    ..0
    exx                                                               ; 26cc: d9          .
    ld c,0                                                            ; 26cd: 0e 00       ..
    ex af,af'                                                         ; 26cf: 08          .
    ret z                                                             ; 26d0: c8          .
    jp negate_fpp                                                     ; 26d1: c3 c7 2e    ...

fbdiv:
    call fix2                                                         ; 26d4: cd af 2e    ...
ibdiv:
    call imod                                                         ; 26d7: cd aa 26    ..&
    or a                                                              ; 26da: b7          .
    call swap_fpp                                                     ; 26db: cd 9e 2f    ../
    ld c,0                                                            ; 26de: 0e 00       ..
    ret p                                                             ; 26e0: f0          .
    jp negate_fpp                                                     ; 26e1: c3 c7 2e    ...

isub:
    call sub                                                          ; 26e4: cd 26 30    .&0
    ret po                                                            ; 26e7: e0          .
    call add                                                          ; 26e8: cd 20 30    . 0
    call float2                                                       ; 26eb: cd 6b 2f    .k/
; $26ee referenced 1 time by $3087
fsub:
    ld a,d                                                            ; 26ee: 7a          z
    xor $80                                                           ; 26ef: ee 80       ..
    ld d,a                                                            ; 26f1: 57          W
    jr fadd                                                           ; 26f2: 18 10       ..

; $26f4 referenced 3 times by $2a43, $2bf4, $2c7f
rsub:
    ld a,h                                                            ; 26f4: 7c          |
    xor $80                                                           ; 26f5: ee 80       ..
    ld h,a                                                            ; 26f7: 67          g
    jr fadd                                                           ; 26f8: 18 0a       ..

iadd:
    call add                                                          ; 26fa: cd 20 30    . 0
    ret po                                                            ; 26fd: e0          .
    call sub                                                          ; 26fe: cd 26 30    .&0
    call float2                                                       ; 2701: cd 6b 2f    .k/
; $2704 referenced 7 times by $26f2, $26f8, $2bce, $2c79, $3078, $30aa, $30ad
fadd:
    dec b                                                             ; 2704: 05          .
    inc b                                                             ; 2705: 04          .
    ret z                                                             ; 2706: c8          .
    dec c                                                             ; 2707: 0d          .
    inc c                                                             ; 2708: 0c          .
    jp z,swap_fpp                                                     ; 2709: ca 9e 2f    ../
    exx                                                               ; 270c: d9          .
    ld bc,0                                                           ; 270d: 01 00 00    ...
    exx                                                               ; 2710: d9          .
    ld a,h                                                            ; 2711: 7c          |
    xor d                                                             ; 2712: aa          .
    push af                                                           ; 2713: f5          .
    ld a,b                                                            ; 2714: 78          x
    cp c                                                              ; 2715: b9          .
    call c,swap_fpp                                                   ; 2716: dc 9e 2f    ../
    ld a,b                                                            ; 2719: 78          x
    set 7,h                                                           ; 271a: cb fc       ..
    call nz,fix                                                       ; 271c: c4 9f 2e    ...
    pop af                                                            ; 271f: f1          .
    ld a,d                                                            ; 2720: 7a          z
    set 7,d                                                           ; 2721: cb fa       ..
    jp m,fadd3                                                        ; 2723: fa 30 27    .0'
    call add                                                          ; 2726: cd 20 30    . 0
    call c,div2                                                       ; 2729: dc a6 2f    ../
    set 7,h                                                           ; 272c: cb fc       ..
    jr fadd4                                                          ; 272e: 18 0a       ..

; $2730 referenced 1 time by $2723
fadd3:
    call sub                                                          ; 2730: cd 26 30    .&0
    call c,neg                                                        ; 2733: dc db 2e    ...
    call flo48                                                        ; 2736: cd 48 2f    .H/
    cpl                                                               ; 2739: 2f          /
; $273a referenced 1 time by $272e
fadd4:
    exx                                                               ; 273a: d9          .
    ex de,hl                                                          ; 273b: eb          .
    ld hl,$8000                                                       ; 273c: 21 00 80    !..
    or a                                                              ; 273f: b7          .
    sbc hl,bc                                                         ; 2740: ed 42       .B
    ex de,hl                                                          ; 2742: eb          .
    exx                                                               ; 2743: d9          .
    call z,odd                                                        ; 2744: cc 98 2f    ../
    call c,add1_fpp                                                   ; 2747: dc 8a 2f    ../
    call c,incc                                                       ; 274a: dc b2 2f    ../
    res 7,h                                                           ; 274d: cb bc       ..
    dec c                                                             ; 274f: 0d          .
    inc c                                                             ; 2750: 0c          .
    jp z,zero_fpp                                                     ; 2751: ca e3 2f    ../
    or a                                                              ; 2754: b7          .
    ret p                                                             ; 2755: f0          .
    set 7,h                                                           ; 2756: cb fc       ..
    ret                                                               ; 2758: c9          .

idiv:
    call float2                                                       ; 2759: cd 6b 2f    .k/
; $275c referenced 7 times by $2962, $2a1e, $2b45, $2ccc, $2e36, $2e41, $308d
fdiv:
    dec b                                                             ; 275c: 05          .
    inc b                                                             ; 275d: 04          .
    ld a,$12                                                          ; 275e: 3e 12       >.
    jp z,error_fpp                                                    ; 2760: ca d7 25    ..%
    dec c                                                             ; 2763: 0d          .
    inc c                                                             ; 2764: 0c          .
    ret z                                                             ; 2765: c8          .
    ld a,h                                                            ; 2766: 7c          |
    xor d                                                             ; 2767: aa          .
    ex af,af'                                                         ; 2768: 08          .
    set 7,d                                                           ; 2769: cb fa       ..
    set 7,h                                                           ; 276b: cb fc       ..
    push bc                                                           ; 276d: c5          .
    ld b,d                                                            ; 276e: 42          B
    ld c,e                                                            ; 276f: 4b          K
    ld de,0                                                           ; 2770: 11 00 00    ...
    exx                                                               ; 2773: d9          .
    ld b,d                                                            ; 2774: 42          B
    ld c,e                                                            ; 2775: 4b          K
    ld de,0                                                           ; 2776: 11 00 00    ...
    ld a,$e0                                                          ; 2779: 3e e0       >.
    call diva                                                         ; 277b: cd f3 30    ..0
    exx                                                               ; 277e: d9          .
    bit 7,d                                                           ; 277f: cb 7a       .z
    exx                                                               ; 2781: d9          .
    call z,divb                                                       ; 2782: cc 0e 31    ..1
    ex de,hl                                                          ; 2785: eb          .
    exx                                                               ; 2786: d9          .
    srl b                                                             ; 2787: cb 38       .8
    rr c                                                              ; 2789: cb 19       ..
    or a                                                              ; 278b: b7          .
    sbc hl,bc                                                         ; 278c: ed 42       .B
    ccf                                                               ; 278e: 3f          ?
    ex de,hl                                                          ; 278f: eb          .
    call z,odd                                                        ; 2790: cc 98 2f    ../
    call c,add1_fpp                                                   ; 2793: dc 8a 2f    ../
    pop bc                                                            ; 2796: c1          .
    call c,incc                                                       ; 2797: dc b2 2f    ../
    rra                                                               ; 279a: 1f          .
    ld a,c                                                            ; 279b: 79          y
    sbc a,b                                                           ; 279c: 98          .
    ccf                                                               ; 279d: 3f          ?
    jp chkovf                                                         ; 279e: c3 28 28    .((

imul:
    ld a,h                                                            ; 27a1: 7c          |
    xor d                                                             ; 27a2: aa          .
    ex af,af'                                                         ; 27a3: 08          .
    bit 7,h                                                           ; 27a4: cb 7c       .|
    call nz,negate_fpp                                                ; 27a6: c4 c7 2e    ...
    call swap_fpp                                                     ; 27a9: cd 9e 2f    ../
    bit 7,h                                                           ; 27ac: cb 7c       .|
    call nz,negate_fpp                                                ; 27ae: c4 c7 2e    ...
    ld b,h                                                            ; 27b1: 44          D
    ld c,l                                                            ; 27b2: 4d          M
    ld hl,0                                                           ; 27b3: 21 00 00    !..
    exx                                                               ; 27b6: d9          .
    ld b,h                                                            ; 27b7: 44          D
    ld c,l                                                            ; 27b8: 4d          M
    ld hl,0                                                           ; 27b9: 21 00 00    !..
    ld a,$df                                                          ; 27bc: 3e df       >.
    call mula                                                         ; 27be: cd 21 31    .!1
    exx                                                               ; 27c1: d9          .
    ld c,$bf                                                          ; 27c2: 0e bf       ..
    call test_fpp                                                     ; 27c4: cd c3 2f    ../
    jr nz,imul1                                                       ; 27c7: 20 0d        .
    bit 7,d                                                           ; 27c9: cb 7a       .z
    jr nz,imul1                                                       ; 27cb: 20 09        .
    call swap_fpp                                                     ; 27cd: cd 9e 2f    ../
    ld c,d                                                            ; 27d0: 4a          J
    ex af,af'                                                         ; 27d1: 08          .
    ret p                                                             ; 27d2: f0          .
    jp negate_fpp                                                     ; 27d3: c3 c7 2e    ...

; $27d6 referenced 3 times by $27c7, $27cb, $27e7
imul1:
    dec c                                                             ; 27d6: 0d          .
    exx                                                               ; 27d7: d9          .
    sla e                                                             ; 27d8: cb 23       .#
    rl d                                                              ; 27da: cb 12       ..
    exx                                                               ; 27dc: d9          .
    rl e                                                              ; 27dd: cb 13       ..
    rl d                                                              ; 27df: cb 12       ..
    exx                                                               ; 27e1: d9          .
    adc hl,hl                                                         ; 27e2: ed 6a       .j
    exx                                                               ; 27e4: d9          .
    adc hl,hl                                                         ; 27e5: ed 6a       .j
    jp p,imul1                                                        ; 27e7: f2 d6 27    ..'
    ex af,af'                                                         ; 27ea: 08          .
    ret m                                                             ; 27eb: f8          .
    res 7,h                                                           ; 27ec: cb bc       ..
    ret                                                               ; 27ee: c9          .

; $27ef referenced 12 times by $28d9, $295a, $2a75, $2ba0, $2bc0, $2be0, $2bee, $2c70, $2cbd, $2e28, $305a, $309b
fmul:
    dec b                                                             ; 27ef: 05          .
    inc b                                                             ; 27f0: 04          .
    jp z,zero_fpp                                                     ; 27f1: ca e3 2f    ../
    dec c                                                             ; 27f4: 0d          .
    inc c                                                             ; 27f5: 0c          .
    ret z                                                             ; 27f6: c8          .
    ld a,h                                                            ; 27f7: 7c          |
    xor d                                                             ; 27f8: aa          .
    ex af,af'                                                         ; 27f9: 08          .
    set 7,d                                                           ; 27fa: cb fa       ..
    set 7,h                                                           ; 27fc: cb fc       ..
    push bc                                                           ; 27fe: c5          .
    ld b,h                                                            ; 27ff: 44          D
    ld c,l                                                            ; 2800: 4d          M
    ld hl,0                                                           ; 2801: 21 00 00    !..
    exx                                                               ; 2804: d9          .
    ld b,h                                                            ; 2805: 44          D
    ld c,l                                                            ; 2806: 4d          M
    ld hl,0                                                           ; 2807: 21 00 00    !..
    ld a,$e0                                                          ; 280a: 3e e0       >.
    call mula                                                         ; 280c: cd 21 31    .!1
    call c,mulb                                                       ; 280f: dc 35 31    .51
    exx                                                               ; 2812: d9          .
    push hl                                                           ; 2813: e5          .
    ld hl,$8000                                                       ; 2814: 21 00 80    !..
    or a                                                              ; 2817: b7          .
    sbc hl,de                                                         ; 2818: ed 52       .R
    pop hl                                                            ; 281a: e1          .
    call z,odd                                                        ; 281b: cc 98 2f    ../
    call c,add1_fpp                                                   ; 281e: dc 8a 2f    ../
    pop bc                                                            ; 2821: c1          .
    call c,incc                                                       ; 2822: dc b2 2f    ../
    rra                                                               ; 2825: 1f          .
    ld a,c                                                            ; 2826: 79          y
    adc a,b                                                           ; 2827: 88          .
; $2828 referenced 1 time by $279e
chkovf:
    jr c,chko1                                                        ; 2828: 38 05       8.
    jp p,zero_fpp                                                     ; 282a: f2 e3 2f    ../
    jr chko2                                                          ; 282d: 18 03       ..

; $282f referenced 1 time by $2828
chko1:
    jp m,oflow                                                        ; 282f: fa b4 2f    ../
; $2832 referenced 1 time by $282d
chko2:
    add a,$80                                                         ; 2832: c6 80       ..
    ld c,a                                                            ; 2834: 4f          O
    jp z,zero_fpp                                                     ; 2835: ca e3 2f    ../
    ex af,af'                                                         ; 2838: 08          .
    res 7,h                                                           ; 2839: cb bc       ..
    ret p                                                             ; 283b: f0          .
    set 7,h                                                           ; 283c: cb fc       ..
    ret                                                               ; 283e: c9          .

ipow:
    call swap_fpp                                                     ; 283f: cd 9e 2f    ../
    bit 7,h                                                           ; 2842: cb 7c       .|
    push af                                                           ; 2844: f5          .
    call nz,negate_fpp                                                ; 2845: c4 c7 2e    ...
; $2848 referenced 1 time by $28b3
ipow0:
    ld c,b                                                            ; 2848: 48          H
    ld b,$20                                                          ; 2849: 06 20       .
; $284b referenced 1 time by $2850
ipow1:
    call x2                                                           ; 284b: cd 3d 30    .=0
    jr c,ipow2                                                        ; 284e: 38 08       8.
    djnz ipow1                                                        ; 2850: 10 f9       ..
    pop af                                                            ; 2852: f1          .
    exx                                                               ; 2853: d9          .
    inc l                                                             ; 2854: 2c          ,
    exx                                                               ; 2855: d9          .
    ld c,h                                                            ; 2856: 4c          L
    ret                                                               ; 2857: c9          .

; $2858 referenced 1 time by $284e
ipow2:
    pop af                                                            ; 2858: f1          .
    push bc                                                           ; 2859: c5          .
    ex de,hl                                                          ; 285a: eb          .
    push hl                                                           ; 285b: e5          .
    exx                                                               ; 285c: d9          .
    ex de,hl                                                          ; 285d: eb          .
    push hl                                                           ; 285e: e5          .
    exx                                                               ; 285f: d9          .
    ld ix,0                                                           ; 2860: dd 21 00... .!.
    add ix,sp                                                         ; 2864: dd 39       .9
    jr z,ipow4                                                        ; 2866: 28 42       (B
    push bc                                                           ; 2868: c5          .
    exx                                                               ; 2869: d9          .
    push de                                                           ; 286a: d5          .
    exx                                                               ; 286b: d9          .
    push de                                                           ; 286c: d5          .
    call sfloat_fpp                                                   ; 286d: cd 74 2f    .t/
    call recip                                                        ; 2870: cd 3f 2b    .?+
    ld (ix+4),c                                                       ; 2873: dd 71 04    .q.
    exx                                                               ; 2876: d9          .
    ld (ix+0),l                                                       ; 2877: dd 75 00    .u.
    ld (ix+1),h                                                       ; 287a: dd 74 01    .t.
    exx                                                               ; 287d: d9          .
    ld (ix+2),l                                                       ; 287e: dd 75 02    .u.
    ld (ix+3),h                                                       ; 2881: dd 74 03    .t.
    jr ipow5                                                          ; 2884: 18 1d       ..

; $2886 referenced 1 time by $28aa
ipow3:
    push bc                                                           ; 2886: c5          .
    exx                                                               ; 2887: d9          .
    sla e                                                             ; 2888: cb 23       .#
    rl d                                                              ; 288a: cb 12       ..
    push de                                                           ; 288c: d5          .
    exx                                                               ; 288d: d9          .
    rl e                                                              ; 288e: cb 13       ..
    rl d                                                              ; 2890: cb 12       ..
    push de                                                           ; 2892: d5          .
    ld a,$0a                                                          ; 2893: 3e 0a       >.
    push af                                                           ; 2895: f5          .
    call copy                                                         ; 2896: cd 4f 30    .O0
    call op                                                           ; 2899: cd dd 25    ..%
    pop af                                                            ; 289c: f1          .
    call dload5_fpp                                                   ; 289d: cd e3 2d    ..-
    call c,op                                                         ; 28a0: dc dd 25    ..%
; $28a3 referenced 1 time by $2884
ipow5:
    pop de                                                            ; 28a3: d1          .
    exx                                                               ; 28a4: d9          .
    pop de                                                            ; 28a5: d1          .
    exx                                                               ; 28a6: d9          .
    ld a,c                                                            ; 28a7: 79          y
    pop bc                                                            ; 28a8: c1          .
    ld c,a                                                            ; 28a9: 4f          O
; $28aa referenced 1 time by $2866
ipow4:
    djnz ipow3                                                        ; 28aa: 10 da       ..
    pop af                                                            ; 28ac: f1          .
    pop af                                                            ; 28ad: f1          .
    pop af                                                            ; 28ae: f1          .
    ret                                                               ; 28af: c9          .

; $28b0 referenced 2 times by $28c0, $28cc
fpow0:
    pop af                                                            ; 28b0: f1          .
    pop af                                                            ; 28b1: f1          .
    pop af                                                            ; 28b2: f1          .
    jr ipow0                                                          ; 28b3: 18 93       ..

fpow:
    bit 7,d                                                           ; 28b5: cb 7a       .z
    push af                                                           ; 28b7: f5          .
    call swap_fpp                                                     ; 28b8: cd 9e 2f    ../
    call push5                                                        ; 28bb: cd 5d 30    .]0
    dec c                                                             ; 28be: 0d          .
    inc c                                                             ; 28bf: 0c          .
    jr z,fpow0                                                        ; 28c0: 28 ee       (.
    ld a,$9e                                                          ; 28c2: 3e 9e       >.
    cp c                                                              ; 28c4: b9          .
    jr c,fpow1                                                        ; 28c5: 38 08       8.
    inc a                                                             ; 28c7: 3c          <
    call fix                                                          ; 28c8: cd 9f 2e    ...
    ex af,af'                                                         ; 28cb: 08          .
    jp p,fpow0                                                        ; 28cc: f2 b0 28    ..(
; $28cf referenced 1 time by $28c5
fpow1:
    call swap_fpp                                                     ; 28cf: cd 9e 2f    ../
    call ln0                                                          ; 28d2: cd 56 2b    .V+
    call pop5                                                         ; 28d5: cd 66 30    .f0
    pop af                                                            ; 28d8: f1          .
    call fmul                                                         ; 28d9: cd ef 27    ..'
    jp exp0                                                           ; 28dc: c3 cb 2a    ..*

flt:
    call fcp                                                          ; 28df: cd ed 2f    ../
    jr ilt1                                                           ; 28e2: 18 03       ..

ilt:
    call icp                                                          ; 28e4: cd e0 2f    ../
; $28e7 referenced 1 time by $28e2
ilt1:
    ret nc                                                            ; 28e7: d0          .
    jr true_fpp                                                       ; 28e8: 18 38       .8

fgt:
    call fcp                                                          ; 28ea: cd ed 2f    ../
    jr igt1                                                           ; 28ed: 18 03       ..

igt:
    call icp                                                          ; 28ef: cd e0 2f    ../
; $28f2 referenced 1 time by $28ed
igt1:
    ret z                                                             ; 28f2: c8          .
    ret c                                                             ; 28f3: d8          .
    jr true_fpp                                                       ; 28f4: 18 2c       .,

fge:
    call fcp                                                          ; 28f6: cd ed 2f    ../
    jr ige1                                                           ; 28f9: 18 03       ..

ige:
    call icp                                                          ; 28fb: cd e0 2f    ../
; $28fe referenced 1 time by $28f9
ige1:
    ret c                                                             ; 28fe: d8          .
    jr true_fpp                                                       ; 28ff: 18 21       .!

fle:
    call fcp                                                          ; 2901: cd ed 2f    ../
    jr ile1                                                           ; 2904: 18 03       ..

ile:
    call icp                                                          ; 2906: cd e0 2f    ../
; $2909 referenced 1 time by $2904
ile1:
    jr z,true_fpp                                                     ; 2909: 28 17       (.
    ret nc                                                            ; 290b: d0          .
    jr true_fpp                                                       ; 290c: 18 14       ..

fne:
    call fcp                                                          ; 290e: cd ed 2f    ../
    jr ine1                                                           ; 2911: 18 03       ..

ine:
    call icp                                                          ; 2913: cd e0 2f    ../
; $2916 referenced 1 time by $2911
ine1:
    ret z                                                             ; 2916: c8          .
    jr true_fpp                                                       ; 2917: 18 09       ..

feq:
    call fcp                                                          ; 2919: cd ed 2f    ../
    jr ieq1                                                           ; 291c: 18 03       ..

ieq:
    call icp                                                          ; 291e: cd e0 2f    ../
; $2921 referenced 1 time by $291c
ieq1:
    ret nz                                                            ; 2921: c0          .
; $2922 referenced 7 times by $28e8, $28f4, $28ff, $2909, $290c, $2917, $297c
true_fpp:
    ld hl,$ffff                                                       ; 2922: 21 ff ff    !..
    exx                                                               ; 2925: d9          .
    ld hl,$ffff                                                       ; 2926: 21 ff ff    !..
    exx                                                               ; 2929: d9          .
    xor a                                                             ; 292a: af          .
    ld c,a                                                            ; 292b: 4f          O
    ret                                                               ; 292c: c9          .

abs_fpp:
    bit 7,h                                                           ; 292d: cb 7c       .|
    ret z                                                             ; 292f: c8          .
    dec c                                                             ; 2930: 0d          .
    inc c                                                             ; 2931: 0c          .
    jp z,negate_fpp                                                   ; 2932: ca c7 2e    ...
    res 7,h                                                           ; 2935: cb bc       ..
    ret                                                               ; 2937: c9          .

not_fpp:
    call sfix_fpp                                                     ; 2938: cd b8 2e    ...
    ld a,h                                                            ; 293b: 7c          |
    cpl                                                               ; 293c: 2f          /
    ld h,a                                                            ; 293d: 67          g
    ld a,l                                                            ; 293e: 7d          }
    cpl                                                               ; 293f: 2f          /
    ld l,a                                                            ; 2940: 6f          o
    exx                                                               ; 2941: d9          .
    ld a,h                                                            ; 2942: 7c          |
    cpl                                                               ; 2943: 2f          /
    ld h,a                                                            ; 2944: 67          g
    ld a,l                                                            ; 2945: 7d          }
    cpl                                                               ; 2946: 2f          /
    ld l,a                                                            ; 2947: 6f          o
    exx                                                               ; 2948: d9          .
    xor a                                                             ; 2949: af          .
    ret                                                               ; 294a: c9          .

pi_fpp:
    ld hl,$490f                                                       ; 294b: 21 0f 49    !.I
    exx                                                               ; 294e: d9          .
    ld hl,$daa2                                                       ; 294f: 21 a2 da    !..
    exx                                                               ; 2952: d9          .
    ld c,$81                                                          ; 2953: 0e 81       ..
    xor a                                                             ; 2955: af          .
    ret                                                               ; 2956: c9          .

deg_fpp:
    call fpi180                                                       ; 2957: cd 67 29    .g)
    call fmul                                                         ; 295a: cd ef 27    ..'
    xor a                                                             ; 295d: af          .
    ret                                                               ; 295e: c9          .

rad_fpp:
    call fpi180                                                       ; 295f: cd 67 29    .g)
    call fdiv                                                         ; 2962: cd 5c 27    .\'
    xor a                                                             ; 2965: af          .
    ret                                                               ; 2966: c9          .

; $2967 referenced 2 times by $2957, $295f
fpi180:
    call sfloat_fpp                                                   ; 2967: cd 74 2f    .t/
    ld de,$652e                                                       ; 296a: 11 2e 65    ..e
    exx                                                               ; 296d: d9          .
    ld de,$e0d3                                                       ; 296e: 11 d3 e0    ...
    exx                                                               ; 2971: d9          .
    ld b,$85                                                          ; 2972: 06 85       ..
    ret                                                               ; 2974: c9          .

sgn_fpp:
    call test_fpp                                                     ; 2975: cd c3 2f    ../
    or c                                                              ; 2978: b1          .
    ret z                                                             ; 2979: c8          .
    bit 7,h                                                           ; 297a: cb 7c       .|
    jp nz,true_fpp                                                    ; 297c: c2 22 29    .")
    call zero_fpp                                                     ; 297f: cd e3 2f    ../
    jp add1_fpp                                                       ; 2982: c3 8a 2f    ../

val_fpp:
    call signq                                                        ; 2985: cd ae 31    ..1
    push af                                                           ; 2988: f5          .
    call con_fpp                                                      ; 2989: cd f5 2d    ..-
    pop af                                                            ; 298c: f1          .
    cp $2d                                                            ; 298d: fe 2d       .-
    ld a,0                                                            ; 298f: 3e 00       >.
    ret nz                                                            ; 2991: c0          .
    dec c                                                             ; 2992: 0d          .
    inc c                                                             ; 2993: 0c          .
    jp z,negate_fpp                                                   ; 2994: ca c7 2e    ...
    ld a,h                                                            ; 2997: 7c          |
    xor $80                                                           ; 2998: ee 80       ..
    ld h,a                                                            ; 299a: 67          g
    xor a                                                             ; 299b: af          .
    ret                                                               ; 299c: c9          .

int_fpp:
    dec c                                                             ; 299d: 0d          .
    inc c                                                             ; 299e: 0c          .
    ret z                                                             ; 299f: c8          .
    ld a,$9f                                                          ; 29a0: 3e 9f       >.
    ld b,h                                                            ; 29a2: 44          D
    call fix                                                          ; 29a3: cd 9f 2e    ...
    ex af,af'                                                         ; 29a6: 08          .
    and b                                                             ; 29a7: a0          .
    call m,add1_fpp                                                   ; 29a8: fc 8a 2f    ../
    ld a,b                                                            ; 29ab: 78          x
    or a                                                              ; 29ac: b7          .
    call m,negate_fpp                                                 ; 29ad: fc c7 2e    ...
    xor a                                                             ; 29b0: af          .
    ld c,a                                                            ; 29b1: 4f          O
    ret                                                               ; 29b2: c9          .

sqr_fpp:
    call sfloat_fpp                                                   ; 29b3: cd 74 2f    .t/
; $29b6 referenced 1 time by $2bf7
sqr0:
    bit 7,h                                                           ; 29b6: cb 7c       .|
    ld a,$15                                                          ; 29b8: 3e 15       >.
    jp nz,error_fpp                                                   ; 29ba: c2 d7 25    ..%
    dec c                                                             ; 29bd: 0d          .
    inc c                                                             ; 29be: 0c          .
    ret z                                                             ; 29bf: c8          .
    set 7,h                                                           ; 29c0: cb fc       ..
    bit 0,c                                                           ; 29c2: cb 41       .A
    call z,div2                                                       ; 29c4: cc a6 2f    ../
    ld a,c                                                            ; 29c7: 79          y
    sub $80                                                           ; 29c8: d6 80       ..
    sra a                                                             ; 29ca: cb 2f       ./
    add a,$80                                                         ; 29cc: c6 80       ..
    ld c,a                                                            ; 29ce: 4f          O
    push bc                                                           ; 29cf: c5          .
    ex de,hl                                                          ; 29d0: eb          .
    ld hl,0                                                           ; 29d1: 21 00 00    !..
    ld b,h                                                            ; 29d4: 44          D
    ld c,l                                                            ; 29d5: 4d          M
    exx                                                               ; 29d6: d9          .
    ex de,hl                                                          ; 29d7: eb          .
    ld hl,0                                                           ; 29d8: 21 00 00    !..
    ld b,h                                                            ; 29db: 44          D
    ld c,l                                                            ; 29dc: 4d          M
    ld a,$e1                                                          ; 29dd: 3e e1       >.
    call sqra                                                         ; 29df: cd 54 31    .T1
    exx                                                               ; 29e2: d9          .
    bit 7,b                                                           ; 29e3: cb 78       .x
    exx                                                               ; 29e5: d9          .
    call z,sqra                                                       ; 29e6: cc 54 31    .T1
    call sqrb                                                         ; 29e9: cd 8d 31    ..1
    or a                                                              ; 29ec: b7          .
    call divb                                                         ; 29ed: cd 0e 31    ..1
    rr e                                                              ; 29f0: cb 1b       ..
    ld h,b                                                            ; 29f2: 60          `
    ld l,c                                                            ; 29f3: 69          i
    exx                                                               ; 29f4: d9          .
    ld h,b                                                            ; 29f5: 60          `
    ld l,c                                                            ; 29f6: 69          i
    call c,add1_fpp                                                   ; 29f7: dc 8a 2f    ../
    pop bc                                                            ; 29fa: c1          .
    call c,incc                                                       ; 29fb: dc b2 2f    ../
    rra                                                               ; 29fe: 1f          .
    sbc a,a                                                           ; 29ff: 9f          .
    add a,c                                                           ; 2a00: 81          .
    ld c,a                                                            ; 2a01: 4f          O
    res 7,h                                                           ; 2a02: cb bc       ..
    xor a                                                             ; 2a04: af          .
    ret                                                               ; 2a05: c9          .

tan_fpp:
    call sfloat_fpp                                                   ; 2a06: cd 74 2f    .t/
    call push5                                                        ; 2a09: cd 5d 30    .]0
    call cos0                                                         ; 2a0c: cd 26 2a    .&*
    call pop5                                                         ; 2a0f: cd 66 30    .f0
    call push5                                                        ; 2a12: cd 5d 30    .]0
    call swap_fpp                                                     ; 2a15: cd 9e 2f    ../
    call sin0                                                         ; 2a18: cd 31 2a    .1*
    call pop5                                                         ; 2a1b: cd 66 30    .f0
    call fdiv                                                         ; 2a1e: cd 5c 27    .\'
    xor a                                                             ; 2a21: af          .
    ret                                                               ; 2a22: c9          .

cos_fpp:
    call sfloat_fpp                                                   ; 2a23: cd 74 2f    .t/
; $2a26 referenced 1 time by $2a0c
cos0:
    call scale                                                        ; 2a26: cd e9 2e    ...
    inc e                                                             ; 2a29: 1c          .
    inc e                                                             ; 2a2a: 1c          .
    ld a,e                                                            ; 2a2b: 7b          {
    jr sin1                                                           ; 2a2c: 18 0e       ..

sin_fpp:
    call sfloat_fpp                                                   ; 2a2e: cd 74 2f    .t/
; $2a31 referenced 1 time by $2a18
sin0:
    push hl                                                           ; 2a31: e5          .
    call scale                                                        ; 2a32: cd e9 2e    ...
    pop af                                                            ; 2a35: f1          .
    rlca                                                              ; 2a36: 07          .
    rlca                                                              ; 2a37: 07          .
    rlca                                                              ; 2a38: 07          .
    and 4                                                             ; 2a39: e6 04       ..
    xor e                                                             ; 2a3b: ab          .
; $2a3c referenced 1 time by $2a2c
sin1:
    push af                                                           ; 2a3c: f5          .
    res 7,h                                                           ; 2a3d: cb bc       ..
    rra                                                               ; 2a3f: 1f          .
    call piby4                                                        ; 2a40: cd bd 2a    ..*
    call c,rsub                                                       ; 2a43: dc f4 26    ..&
    pop af                                                            ; 2a46: f1          .
    push af                                                           ; 2a47: f5          .
    and 3                                                             ; 2a48: e6 03       ..
    jp po,sin2                                                        ; 2a4a: e2 7b 2a    .{*
    call push5                                                        ; 2a4d: cd 5d 30    .]0
    call square                                                       ; 2a50: cd 57 30    .W0
    call poly                                                         ; 2a53: cd 90 30    ..0
    db $b7, $a8, $11, $36, $6d                                        ; 2a56: b7 a8 11... ... ; coefficient
    db $26, $de, 5, $d0, $73                                          ; 2a5b: 26 de 05... &.. ; coefficient
    db $c0, $80, $88, 8, $79                                          ; 2a60: c0 80 88... ... ; coefficient
    db $9d, $aa, $aa, $aa, $7d                                        ; 2a65: 9d aa aa... ... ; coefficient

    nop                                                               ; 2a6a: 00          .  ; (the last coefficient, run as code)
    nop                                                               ; 2a6b: 00          .
    nop                                                               ; 2a6c: 00          .
    nop                                                               ; 2a6d: 00          .
    add a,b                                                           ; 2a6e: 80          .
    call pop5                                                         ; 2a6f: cd 66 30    .f0
    call pop5                                                         ; 2a72: cd 66 30    .f0
    call fmul                                                         ; 2a75: cd ef 27    ..'
    jp sin3                                                           ; 2a78: c3 9d 2a    ..*

; $2a7b referenced 1 time by $2a4a
sin2:
    call square                                                       ; 2a7b: cd 57 30    .W0
    call poly                                                         ; 2a7e: cd 90 30    ..0
    db $71, $d5, $78, $4c, $70                                        ; 2a81: 71 d5 78... q.x ; coefficient
    db $af, $94, 3, $b6, $76                                          ; 2a86: af 94 03... ... ; coefficient
    db $c8, $9c, $aa, $2a, $7b                                        ; 2a8b: c8 9c aa... ... ; coefficient
    db $dd, $ff, $ff, $ff, $7e                                        ; 2a90: dd ff ff... ... ; coefficient

    nop                                                               ; 2a95: 00          .  ; (the last coefficient, run as code)
    nop                                                               ; 2a96: 00          .
    nop                                                               ; 2a97: 00          .
    nop                                                               ; 2a98: 00          .
    add a,b                                                           ; 2a99: 80          .
    call pop5                                                         ; 2a9a: cd 66 30    .f0
; $2a9d referenced 1 time by $2a78
sin3:
    pop af                                                            ; 2a9d: f1          .
    and 4                                                             ; 2a9e: e6 04       ..
    ret z                                                             ; 2aa0: c8          .
    dec c                                                             ; 2aa1: 0d          .
    inc c                                                             ; 2aa2: 0c          .
    ret z                                                             ; 2aa3: c8          .
    set 7,h                                                           ; 2aa4: cb fc       ..
    ret                                                               ; 2aa6: c9          .

fone:
    ld hl,0                                                           ; 2aa7: 21 00 00    !..
    exx                                                               ; 2aaa: d9          .
    ld hl,0                                                           ; 2aab: 21 00 00    !..
    exx                                                               ; 2aae: d9          .
    ld c,$80                                                          ; 2aaf: 0e 80       ..
    ret                                                               ; 2ab1: c9          .

; $2ab2 referenced 5 times by $2b3f, $2bf1, $3075, $3084, $30bd
done:
    ld de,0                                                           ; 2ab2: 11 00 00    ...
    exx                                                               ; 2ab5: d9          .
    ld de,0                                                           ; 2ab6: 11 00 00    ...
    exx                                                               ; 2ab9: d9          .
    ld b,$80                                                          ; 2aba: 06 80       ..
    ret                                                               ; 2abc: c9          .

; $2abd referenced 3 times by $2a40, $2c74, $2ef1
piby4:
    ld de,$490f                                                       ; 2abd: 11 0f 49    ..I
    exx                                                               ; 2ac0: d9          .
    ld de,$daa2                                                       ; 2ac1: 11 a2 da    ...
    exx                                                               ; 2ac4: d9          .
    ld b,$7f                                                          ; 2ac5: 06 7f       ..
    ret                                                               ; 2ac7: c9          .

exp_fpp:
    call sfloat_fpp                                                   ; 2ac8: cd 74 2f    .t/
; $2acb referenced 1 time by $28dc
exp0:
    call ln2                                                          ; 2acb: cd 48 2b    .H+
    exx                                                               ; 2ace: d9          .
    dec e                                                             ; 2acf: 1d          .
    ld bc,$d1cf                                                       ; 2ad0: 01 cf d1    ...
    exx                                                               ; 2ad3: d9          .
    push hl                                                           ; 2ad4: e5          .
    call mod48                                                        ; 2ad5: cd f9 2e    ...
    pop af                                                            ; 2ad8: f1          .
    bit 7,e                                                           ; 2ad9: cb 7b       .{
    jr z,exp1                                                         ; 2adb: 28 09       (.
    rla                                                               ; 2add: 17          .
    jp c,zero_fpp                                                     ; 2ade: da e3 2f    ../
    ld a,$18                                                          ; 2ae1: 3e 18       >.
    jp error_fpp                                                      ; 2ae3: c3 d7 25    ..%

; $2ae6 referenced 1 time by $2adb
exp1:
    and $80                                                           ; 2ae6: e6 80       ..
    or e                                                              ; 2ae8: b3          .
    push af                                                           ; 2ae9: f5          .
    res 7,h                                                           ; 2aea: cb bc       ..
    call push5                                                        ; 2aec: cd 5d 30    .]0
    call poly                                                         ; 2aef: cd 90 30    ..0
    db $72, $40, $2e, $94, $73                                        ; 2af2: 72 40 2e... r@. ; coefficient
    db $65, $6f, $4f, $2e, $76                                        ; 2af7: 65 6f 4f... eoO ; coefficient
    db $37, $6d, 2, $88, $79                                          ; 2afc: 37 6d 02... 7m. ; coefficient
    db $12, $e5, $a0, $2a, $7b                                        ; 2b01: 12 e5 a0... ... ; coefficient
    db $14, $4f, $aa, $aa, $7d                                        ; 2b06: 14 4f aa... .O. ; coefficient
    db $56, $fd, $ff, $7f, $7e                                        ; 2b0b: 56 fd ff... V.. ; coefficient
    db $fe, $ff, $ff, $ff, $7f                                        ; 2b10: fe ff ff... ... ; coefficient

    nop                                                               ; 2b15: 00          .  ; (the last coefficient, run as code)
    nop                                                               ; 2b16: 00          .
    nop                                                               ; 2b17: 00          .
    nop                                                               ; 2b18: 00          .
    add a,b                                                           ; 2b19: 80          .
    call pop5                                                         ; 2b1a: cd 66 30    .f0
    pop af                                                            ; 2b1d: f1          .
    push af                                                           ; 2b1e: f5          .
    call p,recip                                                      ; 2b1f: f4 3f 2b    .?+
    pop af                                                            ; 2b22: f1          .
    jp p,exp4                                                         ; 2b23: f2 2a 2b    .*+
    and $7f                                                           ; 2b26: e6 7f       ..
    neg                                                               ; 2b28: ed 44       .D
; $2b2a referenced 1 time by $2b23
exp4:
    add a,$80                                                         ; 2b2a: c6 80       ..
    add a,c                                                           ; 2b2c: 81          .
    jr c,exp2                                                         ; 2b2d: 38 05       8.
    jp p,zero_fpp                                                     ; 2b2f: f2 e3 2f    ../
    jr exp3                                                           ; 2b32: 18 03       ..

; $2b34 referenced 1 time by $2b2d
exp2:
    jp m,oflow                                                        ; 2b34: fa b4 2f    ../
; $2b37 referenced 1 time by $2b32
exp3:
    add a,$80                                                         ; 2b37: c6 80       ..
    jp z,zero_fpp                                                     ; 2b39: ca e3 2f    ../
    ld c,a                                                            ; 2b3c: 4f          O
    xor a                                                             ; 2b3d: af          .
    ret                                                               ; 2b3e: c9          .

; $2b3f referenced 3 times by $2870, $2b1f, $2c30
recip:
    call done                                                         ; 2b3f: cd b2 2a    ..*
; $2b42 referenced 1 time by $2c05
rdiv:
    call swap_fpp                                                     ; 2b42: cd 9e 2f    ../
    jp fdiv                                                           ; 2b45: c3 5c 27    .\'

; $2b48 referenced 2 times by $2acb, $2bbd
ln2:
    ld de,$3172                                                       ; 2b48: 11 72 31    .r1
    exx                                                               ; 2b4b: d9          .
    ld de,$17f8                                                       ; 2b4c: 11 f8 17    ...
    exx                                                               ; 2b4f: d9          .
    ld b,$7f                                                          ; 2b50: 06 7f       ..
    ret                                                               ; 2b52: c9          .

; $2b53 referenced 1 time by $2bd3
ln_fpp:
    call sfloat_fpp                                                   ; 2b53: cd 74 2f    .t/
; $2b56 referenced 1 time by $28d2
ln0:
    ld a,$16                                                          ; 2b56: 3e 16       >.
    bit 7,h                                                           ; 2b58: cb 7c       .|
    jp nz,error_fpp                                                   ; 2b5a: c2 d7 25    ..%
    inc c                                                             ; 2b5d: 0c          .
    dec c                                                             ; 2b5e: 0d          .
    jp z,error_fpp                                                    ; 2b5f: ca d7 25    ..%
    ld de,$3504                                                       ; 2b62: 11 04 35    ..5
    exx                                                               ; 2b65: d9          .
    ld de,$f333                                                       ; 2b66: 11 33 f3    .3.
    exx                                                               ; 2b69: d9          .
    call icp0                                                         ; 2b6a: cd f5 2f    ../
    ld a,c                                                            ; 2b6d: 79          y
    ld c,$80                                                          ; 2b6e: 0e 80       ..
    jr c,ln4                                                          ; 2b70: 38 02       8.
    dec c                                                             ; 2b72: 0d          .
    inc a                                                             ; 2b73: 3c          <
; $2b74 referenced 1 time by $2b70
ln4:
    push af                                                           ; 2b74: f5          .
    call ratio                                                        ; 2b75: cd 72 30    .r0
    call push5                                                        ; 2b78: cd 5d 30    .]0
    call square                                                       ; 2b7b: cd 57 30    .W0
    call poly                                                         ; 2b7e: cd 90 30    ..0
    db $48, $cc, $fb, $74, $7d                                        ; 2b81: 48 cc fb... H.. ; coefficient
    db $af, $ae, $ff, $11, $7e                                        ; 2b86: af ae ff... ... ; coefficient
    db $8c, $d9, $cd, $4c, $7e                                        ; 2b8b: 8c d9 cd... ... ; coefficient
    db $e3, $a9, $aa, $2a, $7f                                        ; 2b90: e3 a9 aa... ... ; coefficient

    nop                                                               ; 2b95: 00          .  ; (the last coefficient, run as code)
    nop                                                               ; 2b96: 00          .
    nop                                                               ; 2b97: 00          .
    nop                                                               ; 2b98: 00          .
    add a,c                                                           ; 2b99: 81          .
    call pop5                                                         ; 2b9a: cd 66 30    .f0
    call pop5                                                         ; 2b9d: cd 66 30    .f0
    call fmul                                                         ; 2ba0: cd ef 27    ..'
    pop af                                                            ; 2ba3: f1          .
    call push5                                                        ; 2ba4: cd 5d 30    .]0
    ex af,af'                                                         ; 2ba7: 08          .
    call zero_fpp                                                     ; 2ba8: cd e3 2f    ../
    ex af,af'                                                         ; 2bab: 08          .
    sub $80                                                           ; 2bac: d6 80       ..
    jr z,ln3                                                          ; 2bae: 28 1b       (.
    jr nc,ln1                                                         ; 2bb0: 30 02       0.
    cpl                                                               ; 2bb2: 2f          /
    inc a                                                             ; 2bb3: 3c          <
; $2bb4 referenced 1 time by $2bb0
ln1:
    ld h,a                                                            ; 2bb4: 67          g
    ld c,$87                                                          ; 2bb5: 0e 87       ..
    push af                                                           ; 2bb7: f5          .
    call float                                                        ; 2bb8: cd 5a 2f    .Z/
    res 7,h                                                           ; 2bbb: cb bc       ..
    call ln2                                                          ; 2bbd: cd 48 2b    .H+
    call fmul                                                         ; 2bc0: cd ef 27    ..'
    pop af                                                            ; 2bc3: f1          .
    jr nc,ln3                                                         ; 2bc4: 30 05       0.
    jp m,ln3                                                          ; 2bc6: fa cb 2b    ..+
    set 7,h                                                           ; 2bc9: cb fc       ..
; $2bcb referenced 3 times by $2bae, $2bc4, $2bc6
ln3:
    call pop5                                                         ; 2bcb: cd 66 30    .f0
    call fadd                                                         ; 2bce: cd 04 27    ..'
    xor a                                                             ; 2bd1: af          .
    ret                                                               ; 2bd2: c9          .

log_fpp:
    call ln_fpp                                                       ; 2bd3: cd 53 2b    .S+
    ld de,$5e5b                                                       ; 2bd6: 11 5b 5e    .[^
    exx                                                               ; 2bd9: d9          .
    ld de,$d8a9                                                       ; 2bda: 11 a9 d8    ...
    exx                                                               ; 2bdd: d9          .
    ld b,$7e                                                          ; 2bde: 06 7e       .~
    call fmul                                                         ; 2be0: cd ef 27    ..'
    xor a                                                             ; 2be3: af          .
    ret                                                               ; 2be4: c9          .

; $2be5 referenced 1 time by $2c89
asn_fpp:
    call sfloat_fpp                                                   ; 2be5: cd 74 2f    .t/
    call push5                                                        ; 2be8: cd 5d 30    .]0
    call copy                                                         ; 2beb: cd 4f 30    .O0
    call fmul                                                         ; 2bee: cd ef 27    ..'
    call done                                                         ; 2bf1: cd b2 2a    ..*
    call rsub                                                         ; 2bf4: cd f4 26    ..&
    call sqr0                                                         ; 2bf7: cd b6 29    ..)
    call pop5                                                         ; 2bfa: cd 66 30    .f0
    inc c                                                             ; 2bfd: 0c          .
    dec c                                                             ; 2bfe: 0d          .
    ld a,2                                                            ; 2bff: 3e 02       >.
    push de                                                           ; 2c01: d5          .
    jr z,acs1                                                         ; 2c02: 28 70       (p
    pop de                                                            ; 2c04: d1          .
    call rdiv                                                         ; 2c05: cd 42 2b    .B+
    jr atn0                                                           ; 2c08: 18 03       ..

atn_fpp:
    call sfloat_fpp                                                   ; 2c0a: cd 74 2f    .t/
; $2c0d referenced 1 time by $2c08
atn0:
    push hl                                                           ; 2c0d: e5          .
    res 7,h                                                           ; 2c0e: cb bc       ..
    ld de,$5413                                                       ; 2c10: 11 13 54    ..T
    exx                                                               ; 2c13: d9          .
    ld de,$ccd0                                                       ; 2c14: 11 d0 cc    ...
    exx                                                               ; 2c17: d9          .
    ld b,$7e                                                          ; 2c18: 06 7e       .~
    call fcp0                                                         ; 2c1a: cd f2 2f    ../
    ld b,0                                                            ; 2c1d: 06 00       ..
    jr c,atn2                                                         ; 2c1f: 38 1c       8.
    ld de,$1a82                                                       ; 2c21: 11 82 1a    ...
    exx                                                               ; 2c24: d9          .
    ld de,$799a                                                       ; 2c25: 11 9a 79    ..y
    exx                                                               ; 2c28: d9          .
    ld b,$81                                                          ; 2c29: 06 81       ..
    call fcp0                                                         ; 2c2b: cd f2 2f    ../
    jr c,atn1                                                         ; 2c2e: 38 08       8.
    call recip                                                        ; 2c30: cd 3f 2b    .?+
    ld b,2                                                            ; 2c33: 06 02       ..
    jp atn2                                                           ; 2c35: c3 3d 2c    .=,

; $2c38 referenced 1 time by $2c2e
atn1:
    call ratio                                                        ; 2c38: cd 72 30    .r0
    ld b,1                                                            ; 2c3b: 06 01       ..
; $2c3d referenced 2 times by $2c1f, $2c35
atn2:
    push bc                                                           ; 2c3d: c5          .
    call push5                                                        ; 2c3e: cd 5d 30    .]0
    call square                                                       ; 2c41: cd 57 30    .W0
    call poly                                                         ; 2c44: cd 90 30    ..0
    db $35, $f3, $d8, $37, $7b                                        ; 2c47: 35 f3 d8... 5.. ; coefficient
    db $91, $6b, $b9, $aa, $7c                                        ; 2c4c: 91 6b b9... .k. ; coefficient
    db $de, $41, $97, $61, $7c                                        ; 2c51: de 41 97... .A. ; coefficient
    db $7b, $9d, $37, $92, $7d                                        ; 2c56: 7b 9d 37... {.7 ; coefficient
    db $5a, $2a, $cc, $4c, $7d                                        ; 2c5b: 5a 2a cc... Z*. ; coefficient
    db $5c, $a9, $aa, $aa, $7e                                        ; 2c60: 5c a9 aa... \.. ; coefficient

    nop                                                               ; 2c65: 00          .  ; (the last coefficient, run as code)
    nop                                                               ; 2c66: 00          .
    nop                                                               ; 2c67: 00          .
    nop                                                               ; 2c68: 00          .
    add a,b                                                           ; 2c69: 80          .
    call pop5                                                         ; 2c6a: cd 66 30    .f0
    call pop5                                                         ; 2c6d: cd 66 30    .f0
    call fmul                                                         ; 2c70: cd ef 27    ..'
    pop af                                                            ; 2c73: f1          .
; $2c74 referenced 2 times by $2c02, $2c8f
acs1:
    call piby4                                                        ; 2c74: cd bd 2a    ..*
    rra                                                               ; 2c77: 1f          .
    push af                                                           ; 2c78: f5          .
    call c,fadd                                                       ; 2c79: dc 04 27    ..'
    pop af                                                            ; 2c7c: f1          .
    inc b                                                             ; 2c7d: 04          .
    rra                                                               ; 2c7e: 1f          .
    call c,rsub                                                       ; 2c7f: dc f4 26    ..&
    pop af                                                            ; 2c82: f1          .
    or a                                                              ; 2c83: b7          .
    ret p                                                             ; 2c84: f0          .
    set 7,h                                                           ; 2c85: cb fc       ..
    xor a                                                             ; 2c87: af          .
    ret                                                               ; 2c88: c9          .

acs_fpp:
    call asn_fpp                                                      ; 2c89: cd e5 2b    ..+
    ld a,2                                                            ; 2c8c: 3e 02       >.
    push af                                                           ; 2c8e: f5          .
    jr acs1                                                           ; 2c8f: 18 e3       ..

str_fpp:
    call sfloat_fpp                                                   ; 2c91: cd 74 2f    .t/
    ld b,0                                                            ; 2c94: 06 00       ..
    bit 7,h                                                           ; 2c96: cb 7c       .|
    jr z,str10                                                        ; 2c98: 28 06       (.
    res 7,h                                                           ; 2c9a: cb bc       ..
    ld a,$2d                                                          ; 2c9c: 3e 2d       >-
    ld (de),a                                                         ; 2c9e: 12          .
    inc de                                                            ; 2c9f: 13          .
; $2ca0 referenced 1 time by $2c98
str10:
    xor a                                                             ; 2ca0: af          .
    cp c                                                              ; 2ca1: b9          .
    jr z,str2_fpp                                                     ; 2ca2: 28 47       (G
    push de                                                           ; 2ca4: d5          .
    ld a,b                                                            ; 2ca5: 78          x
; $2ca6 referenced 2 times by $2cc4, $2cd3
str11:
    push af                                                           ; 2ca6: f5          .
    ld a,c                                                            ; 2ca7: 79          y
    cp $a1                                                            ; 2ca8: fe a1       ..
    jr nc,str14                                                       ; 2caa: 30 1a       0.
    cp $9b                                                            ; 2cac: fe 9b       ..
    jr nc,str15                                                       ; 2cae: 30 25       0%
    cpl                                                               ; 2cb0: 2f          /
    cp $e1                                                            ; 2cb1: fe e1       ..
    jr c,str13                                                        ; 2cb3: 38 02       8.
    ld a,$f8                                                          ; 2cb5: 3e f8       >.
; $2cb7 referenced 1 time by $2cb3
str13:
    add a,$1c                                                         ; 2cb7: c6 1c       ..
    call powr10                                                       ; 2cb9: cd b7 30    ..0
    push af                                                           ; 2cbc: f5          .
    call fmul                                                         ; 2cbd: cd ef 27    ..'
    pop af                                                            ; 2cc0: f1          .
    ld b,a                                                            ; 2cc1: 47          G
    pop af                                                            ; 2cc2: f1          .
    sub b                                                             ; 2cc3: 90          .
    jr str11                                                          ; 2cc4: 18 e0       ..

; $2cc6 referenced 1 time by $2caa
str14:
    sub $20                                                           ; 2cc6: d6 20       .
    call powr10                                                       ; 2cc8: cd b7 30    ..0
    push af                                                           ; 2ccb: f5          .
    call fdiv                                                         ; 2ccc: cd 5c 27    .\'
    pop af                                                            ; 2ccf: f1          .
    ld b,a                                                            ; 2cd0: 47          G
    pop af                                                            ; 2cd1: f1          .
    add a,b                                                           ; 2cd2: 80          .
    jr str11                                                          ; 2cd3: 18 d1       ..

; $2cd5 referenced 1 time by $2cae
str15:
    ld a,9                                                            ; 2cd5: 3e 09       >.
    call powr10                                                       ; 2cd7: cd b7 30    ..0
    call fcp0                                                         ; 2cda: cd f2 2f    ../
    ld a,c                                                            ; 2cdd: 79          y
    pop bc                                                            ; 2cde: c1          .
    ld c,a                                                            ; 2cdf: 4f          O
    set 7,h                                                           ; 2ce0: cb fc       ..
    call c,x10b                                                       ; 2ce2: dc 14 30    ..0
    pop de                                                            ; 2ce5: d1          .
    res 7,c                                                           ; 2ce6: cb b9       ..
    ld a,0                                                            ; 2ce8: 3e 00       >.
    rla                                                               ; 2cea: 17          .
; $2ceb referenced 1 time by $2ca2
str2_fpp:
    inc c                                                             ; 2ceb: 0c          .
    ex af,af'                                                         ; 2cec: 08          .
    ld a,b                                                            ; 2ced: 78          x
    bit 1,(ix+2)                                                      ; 2cee: dd cb 02... ...
    jr nz,str20                                                       ; 2cf2: 20 08        .
    xor a                                                             ; 2cf4: af          .
    cp (ix+1)                                                         ; 2cf5: dd be 01    ...
    jr z,str21                                                        ; 2cf8: 28 0a       (.
    ld a,$f6                                                          ; 2cfa: 3e f6       >.
; $2cfc referenced 1 time by $2cf2
str20:
    add a,(ix+1)                                                      ; 2cfc: dd 86 01    ...
    or a                                                              ; 2cff: b7          .
    jp m,str21                                                        ; 2d00: fa 04 2d    ..-
    xor a                                                             ; 2d03: af          .
; $2d04 referenced 2 times by $2cf8, $2d00
str21:
    push af                                                           ; 2d04: f5          .
    ex af,af'                                                         ; 2d05: 08          .
; $2d06 referenced 3 times by $2d14, $2d49, $2d4f
str22:
    call x2                                                           ; 2d06: cd 3d 30    .=0
    adc a,a                                                           ; 2d09: 8f          .
    cp $0a                                                            ; 2d0a: fe 0a       ..
    jr c,str23                                                        ; 2d0c: 38 05       8.
    sub $0a                                                           ; 2d0e: d6 0a       ..
    exx                                                               ; 2d10: d9          .
    inc l                                                             ; 2d11: 2c          ,
    exx                                                               ; 2d12: d9          .
; $2d13 referenced 1 time by $2d0c
str23:
    dec c                                                             ; 2d13: 0d          .
    jr nz,str22                                                       ; 2d14: 20 f0        .
    ld c,a                                                            ; 2d16: 4f          O
    ld a,h                                                            ; 2d17: 7c          |
    and $3f                                                           ; 2d18: e6 3f       .?
    ld h,a                                                            ; 2d1a: 67          g
    pop af                                                            ; 2d1b: f1          .
    jp p,str24                                                        ; 2d1c: f2 29 2d    .)-
    inc a                                                             ; 2d1f: 3c          <
    jr nz,str26                                                       ; 2d20: 20 1c        .
    ld a,4                                                            ; 2d22: 3e 04       >.
    cp c                                                              ; 2d24: b9          .
    ld a,0                                                            ; 2d25: 3e 00       >.
    jr str26                                                          ; 2d27: 18 15       ..

; $2d29 referenced 1 time by $2d1c
str24:
    push af                                                           ; 2d29: f5          .
    ld a,c                                                            ; 2d2a: 79          y
    adc a,$30                                                         ; 2d2b: ce 30       .0
    cp $30                                                            ; 2d2d: fe 30       .0
    jr z,str25                                                        ; 2d2f: 28 05       (.
    cp $3a                                                            ; 2d31: fe 3a       .:
    ccf                                                               ; 2d33: 3f          ?
    jr nc,str26                                                       ; 2d34: 30 08       0.
; $2d36 referenced 1 time by $2d2f
str25:
    ex (sp),hl                                                        ; 2d36: e3          .
    bit 6,l                                                           ; 2d37: cb 75       .u
    ex (sp),hl                                                        ; 2d39: e3          .
    jr nz,str27                                                       ; 2d3a: 20 05        .
    ld a,$30                                                          ; 2d3c: 3e 30       >0
; $2d3e referenced 3 times by $2d20, $2d27, $2d34
str26:
    inc a                                                             ; 2d3e: 3c          <
    dec a                                                             ; 2d3f: 3d          =
    push af                                                           ; 2d40: f5          .
; $2d41 referenced 1 time by $2d3a
str27:
    inc b                                                             ; 2d41: 04          .
    call test_fpp                                                     ; 2d42: cd c3 2f    ../
    ld c,$20                                                          ; 2d45: 0e 20       .
    ld a,0                                                            ; 2d47: 3e 00       >.
    jr nz,str22                                                       ; 2d49: 20 bb        .
    pop af                                                            ; 2d4b: f1          .
    push af                                                           ; 2d4c: f5          .
    ld a,0                                                            ; 2d4d: 3e 00       >.
    jr c,str22                                                        ; 2d4f: 38 b5       8.
str3:
    ex de,hl                                                          ; 2d51: eb          .
    ld c,$ff                                                          ; 2d52: 0e ff       ..
    ld d,1                                                            ; 2d54: 16 01       ..
    ld e,(ix+1)                                                       ; 2d56: dd 5e 01    .^.
    bit 0,(ix+2)                                                      ; 2d59: dd cb 02... ...
    jr nz,str34                                                       ; 2d5d: 20 32        2
    bit 1,(ix+2)                                                      ; 2d5f: dd cb 02... ...
    jr z,str31                                                        ; 2d63: 28 11       (.
    ld a,b                                                            ; 2d65: 78          x
    or a                                                              ; 2d66: b7          .
    jr z,str30                                                        ; 2d67: 28 04       (.
    jp m,str30                                                        ; 2d69: fa 6d 2d    .m-
    ld d,b                                                            ; 2d6c: 50          P
; $2d6d referenced 2 times by $2d67, $2d69
str30:
    ld a,d                                                            ; 2d6d: 7a          z
    add a,(ix+1)                                                      ; 2d6e: dd 86 01    ...
    ld e,a                                                            ; 2d71: 5f          _
    cp $0b                                                            ; 2d72: fe 0b       ..
    jr c,str32                                                        ; 2d74: 38 17       8.
; $2d76 referenced 1 time by $2d63
str31:
    ld a,b                                                            ; 2d76: 78          x
    ld de,$0101                                                       ; 2d77: 11 01 01    ...
    or a                                                              ; 2d7a: b7          .
    jp m,str34                                                        ; 2d7b: fa 91 2d    ..-
    jr z,str32                                                        ; 2d7e: 28 0d       (.
    ld a,(ix+1)                                                       ; 2d80: dd 7e 01    .~.
    or a                                                              ; 2d83: b7          .
    jr nz,str3a                                                       ; 2d84: 20 02        .
    ld a,$0a                                                          ; 2d86: 3e 0a       >.
; $2d88 referenced 1 time by $2d84
str3a:
    cp b                                                              ; 2d88: b8          .
    jr c,str34                                                        ; 2d89: 38 06       8.
    ld d,b                                                            ; 2d8b: 50          P
    ld e,b                                                            ; 2d8c: 58          X
; $2d8d referenced 2 times by $2d74, $2d7e
str32:
    ld a,b                                                            ; 2d8d: 78          x
    add a,$81                                                         ; 2d8e: c6 81       ..
    ld c,a                                                            ; 2d90: 4f          O
; $2d91 referenced 3 times by $2d5d, $2d7b, $2d89
str34:
    set 7,d                                                           ; 2d91: cb fa       ..
    dec e                                                             ; 2d93: 1d          .
; $2d94 referenced 1 time by $2db0
str35:
    ld a,d                                                            ; 2d94: 7a          z
    cp c                                                              ; 2d95: b9          .
    jr nc,str33                                                       ; 2d96: 30 0c       0.
; $2d98 referenced 1 time by $2db3
str36:
    pop af                                                            ; 2d98: f1          .
    jr z,str37                                                        ; 2d99: 28 03       (.
    jp p,str38                                                        ; 2d9b: f2 a6 2d    ..-
; $2d9e referenced 1 time by $2d99
str37:
    push af                                                           ; 2d9e: f5          .
    inc e                                                             ; 2d9f: 1c          .
    dec e                                                             ; 2da0: 1d          .
    jp m,str4                                                         ; 2da1: fa b5 2d    ..-
; $2da4 referenced 1 time by $2d96
str33:
    ld a,$30                                                          ; 2da4: 3e 30       >0
; $2da6 referenced 1 time by $2d9b
str38:
    dec d                                                             ; 2da6: 15          .
    jp po,str39                                                       ; 2da7: e2 ad 2d    ..-
    ld (hl),$2e                                                       ; 2daa: 36 2e       6.
    inc hl                                                            ; 2dac: 23          #
; $2dad referenced 1 time by $2da7
str39:
    ld (hl),a                                                         ; 2dad: 77          w
    inc hl                                                            ; 2dae: 23          #
    dec e                                                             ; 2daf: 1d          .
    jp p,str35                                                        ; 2db0: f2 94 2d    ..-
    jr str36                                                          ; 2db3: 18 e3       ..

; $2db5 referenced 1 time by $2da1
str4:
    pop af                                                            ; 2db5: f1          .
str40:
    inc c                                                             ; 2db6: 0c          .
    ld c,l                                                            ; 2db7: 4d          M
    jr nz,str44                                                       ; 2db8: 20 27        '
    ld (hl),$45                                                       ; 2dba: 36 45       6E
    inc hl                                                            ; 2dbc: 23          #
    ld a,b                                                            ; 2dbd: 78          x
    dec a                                                             ; 2dbe: 3d          =
    jp p,str41                                                        ; 2dbf: f2 c7 2d    ..-
    ld (hl),$2d                                                       ; 2dc2: 36 2d       6-
    inc hl                                                            ; 2dc4: 23          #
    neg                                                               ; 2dc5: ed 44       .D
; $2dc7 referenced 1 time by $2dbf
str41:
    ld (hl),$30                                                       ; 2dc7: 36 30       60
    jr z,str47                                                        ; 2dc9: 28 15       (.
    cp $0a                                                            ; 2dcb: fe 0a       ..
    ld b,a                                                            ; 2dcd: 47          G
    ld a,$3a                                                          ; 2dce: 3e 3a       >:
    jr c,str42                                                        ; 2dd0: 38 03       8.
    inc hl                                                            ; 2dd2: 23          #
    ld (hl),$30                                                       ; 2dd3: 36 30       60
; $2dd5 referenced 2 times by $2dd0, $2dde
str42:
    inc (hl)                                                          ; 2dd5: 34          4
    cp (hl)                                                           ; 2dd6: be          .
    jr nz,str43                                                       ; 2dd7: 20 05        .
    ld (hl),$30                                                       ; 2dd9: 36 30       60
    dec hl                                                            ; 2ddb: 2b          +
    inc (hl)                                                          ; 2ddc: 34          4
    inc hl                                                            ; 2ddd: 23          #
; $2dde referenced 1 time by $2dd7
str43:
    djnz str42                                                        ; 2dde: 10 f5       ..
; $2de0 referenced 1 time by $2dc9
str47:
    inc hl                                                            ; 2de0: 23          #
; $2de1 referenced 1 time by $2db8
str44:
    ex de,hl                                                          ; 2de1: eb          .
    ret                                                               ; 2de2: c9          .

; $2de3 referenced 4 times by $289d, $3098, $30a3, $30b0
dload5_fpp:
    ld b,(ix+4)                                                       ; 2de3: dd 46 04    .F.
    exx                                                               ; 2de6: d9          .
    ld e,(ix+0)                                                       ; 2de7: dd 5e 00    .^.
    ld d,(ix+1)                                                       ; 2dea: dd 56 01    .V.
    exx                                                               ; 2ded: d9          .
    ld e,(ix+2)                                                       ; 2dee: dd 5e 02    .^.
    ld d,(ix+3)                                                       ; 2df1: dd 56 03    .V.
    ret                                                               ; 2df4: c9          .

; $2df5 referenced 1 time by $2989
con_fpp:
    call zero_fpp                                                     ; 2df5: cd e3 2f    ../
    ld c,0                                                            ; 2df8: 0e 00       ..
    call number_fpp                                                   ; 2dfa: cd 7a 2e    .z.
    cp $2e                                                            ; 2dfd: fe 2e       ..
    ld b,0                                                            ; 2dff: 06 00       ..
    call z,numbix                                                     ; 2e01: cc 78 2e    .x.
    cp $45                                                            ; 2e04: fe 45       .E
    ld a,0                                                            ; 2e06: 3e 00       >.
    call z,getexp                                                     ; 2e08: cc 49 2e    .I.
    bit 7,h                                                           ; 2e0b: cb 7c       .|
    jr nz,con0                                                        ; 2e0d: 20 08        .
    or a                                                              ; 2e0f: b7          .
    jr nz,con0                                                        ; 2e10: 20 05        .
    cp b                                                              ; 2e12: b8          .
    jr nz,con0                                                        ; 2e13: 20 02        .
    cp c                                                              ; 2e15: b9          .
    ret z                                                             ; 2e16: c8          .
; $2e17 referenced 3 times by $2e0d, $2e10, $2e13
con0:
    sub b                                                             ; 2e17: 90          .
    add a,c                                                           ; 2e18: 81          .
    ld c,$9f                                                          ; 2e19: 0e 9f       ..
    call float                                                        ; 2e1b: cd 5a 2f    .Z/
    res 7,h                                                           ; 2e1e: cb bc       ..
    or a                                                              ; 2e20: b7          .
    ret z                                                             ; 2e21: c8          .
    jp m,con2                                                         ; 2e22: fa 2d 2e    .-.
    call powr10                                                       ; 2e25: cd b7 30    ..0
    call fmul                                                         ; 2e28: cd ef 27    ..'
    xor a                                                             ; 2e2b: af          .
    ret                                                               ; 2e2c: c9          .

; $2e2d referenced 2 times by $2e22, $2e47
con2:
    cp $da                                                            ; 2e2d: fe da       ..
    jr c,con3                                                         ; 2e2f: 38 0a       8.
    neg                                                               ; 2e31: ed 44       .D
    call powr10                                                       ; 2e33: cd b7 30    ..0
    call fdiv                                                         ; 2e36: cd 5c 27    .\'
    xor a                                                             ; 2e39: af          .
    ret                                                               ; 2e3a: c9          .

; $2e3b referenced 1 time by $2e2f
con3:
    push af                                                           ; 2e3b: f5          .
    ld a,$26                                                          ; 2e3c: 3e 26       >&
    call powr10                                                       ; 2e3e: cd b7 30    ..0
    call fdiv                                                         ; 2e41: cd 5c 27    .\'
    pop af                                                            ; 2e44: f1          .
    add a,$26                                                         ; 2e45: c6 26       .&
    jr con2                                                           ; 2e47: 18 e4       ..

; $2e49 referenced 1 time by $2e08
getexp:
    push bc                                                           ; 2e49: c5          .
    ld b,a                                                            ; 2e4a: 47          G
    ld c,2                                                            ; 2e4b: 0e 02       ..
    inc ix                                                            ; 2e4d: dd 23       .#
    call signq                                                        ; 2e4f: cd ae 31    ..1
    ex af,af'                                                         ; 2e52: 08          .
; $2e53 referenced 2 times by $2e68, $2e6d
getex1:
    call digitq                                                       ; 2e53: cd a4 31    ..1
    jr c,getex2                                                       ; 2e56: 38 17       8.
    ld a,b                                                            ; 2e58: 78          x
    add a,a                                                           ; 2e59: 87          .
    add a,a                                                           ; 2e5a: 87          .
    add a,b                                                           ; 2e5b: 80          .
    add a,a                                                           ; 2e5c: 87          .
    ld b,a                                                            ; 2e5d: 47          G
    ld a,(ix+0)                                                       ; 2e5e: dd 7e 00    .~.
    inc ix                                                            ; 2e61: dd 23       .#
    and $0f                                                           ; 2e63: e6 0f       ..
    add a,b                                                           ; 2e65: 80          .
    ld b,a                                                            ; 2e66: 47          G
    dec c                                                             ; 2e67: 0d          .
    jp p,getex1                                                       ; 2e68: f2 53 2e    .S.
    ld b,$64                                                          ; 2e6b: 06 64       .d
    jr getex1                                                         ; 2e6d: 18 e4       ..

; $2e6f referenced 1 time by $2e56
getex2:
    ex af,af'                                                         ; 2e6f: 08          .
    cp $2d                                                            ; 2e70: fe 2d       .-
    ld a,b                                                            ; 2e72: 78          x
    pop bc                                                            ; 2e73: c1          .
    ret nz                                                            ; 2e74: c0          .
    neg                                                               ; 2e75: ed 44       .D
    ret                                                               ; 2e77: c9          .

; $2e78 referenced 1 time by $2e01
numbix:
    inc ix                                                            ; 2e78: dd 23       .#
; $2e7a referenced 4 times by $2dfa, $2e92, $2e97, $2e9d
number_fpp:
    call digitq                                                       ; 2e7a: cd a4 31    ..1
    ret c                                                             ; 2e7d: d8          .
    inc b                                                             ; 2e7e: 04          .
    inc ix                                                            ; 2e7f: dd 23       .#
    call x10                                                          ; 2e81: cd 2e 30    ..0
    jr c,numb1                                                        ; 2e84: 38 13       8.
    dec c                                                             ; 2e86: 0d          .
    inc c                                                             ; 2e87: 0c          .
    jr nz,numb1                                                       ; 2e88: 20 0f        .
    and $0f                                                           ; 2e8a: e6 0f       ..
    exx                                                               ; 2e8c: d9          .
    ld b,0                                                            ; 2e8d: 06 00       ..
    ld c,a                                                            ; 2e8f: 4f          O
    add hl,bc                                                         ; 2e90: 09          .
    exx                                                               ; 2e91: d9          .
    jr nc,number_fpp                                                  ; 2e92: 30 e6       0.
    inc hl                                                            ; 2e94: 23          #
    ld a,h                                                            ; 2e95: 7c          |
    or l                                                              ; 2e96: b5          .
    jr nz,number_fpp                                                  ; 2e97: 20 e1        .
; $2e99 referenced 2 times by $2e84, $2e88
numb1:
    inc c                                                             ; 2e99: 0c          .
    call swap1                                                        ; 2e9a: cd a1 2f    ../
    jr number_fpp                                                     ; 2e9d: 18 db       ..

; $2e9f referenced 4 times by $271c, $28c8, $29a3, $2ec0
fix:
    ex af,af'                                                         ; 2e9f: 08          .
    xor a                                                             ; 2ea0: af          .
    ex af,af'                                                         ; 2ea1: 08          .
    set 7,h                                                           ; 2ea2: cb fc       ..
; $2ea4 referenced 1 time by $2ea9
fix1:
    call div2                                                         ; 2ea4: cd a6 2f    ../
    cp c                                                              ; 2ea7: b9          .
    ret z                                                             ; 2ea8: c8          .
    jp nc,fix1                                                        ; 2ea9: d2 a4 2e    ...
    jp oflow                                                          ; 2eac: c3 b4 2f    ../

; $2eaf referenced 5 times by $2671, $2683, $2695, $26a7, $26d4
fix2:
    call swap_fpp                                                     ; 2eaf: cd 9e 2f    ../
    call sfix_fpp                                                     ; 2eb2: cd b8 2e    ...
    call swap_fpp                                                     ; 2eb5: cd 9e 2f    ../
; $2eb8 referenced 2 times by $2938, $2eb2
sfix_fpp:
    dec c                                                             ; 2eb8: 0d          .
    inc c                                                             ; 2eb9: 0c          .
    ret z                                                             ; 2eba: c8          .
    bit 7,h                                                           ; 2ebb: cb 7c       .|
    push af                                                           ; 2ebd: f5          .
    ld a,$9f                                                          ; 2ebe: 3e 9f       >.
    call fix                                                          ; 2ec0: cd 9f 2e    ...
    pop af                                                            ; 2ec3: f1          .
    ld c,0                                                            ; 2ec4: 0e 00       ..
    ret z                                                             ; 2ec6: c8          .
; $2ec7 referenced 12 times by $26b1, $26b9, $26d1, $26e1, $27a6, $27ae, $27d3, $2845, $2932, $2994, $29ad, $2f7d
negate_fpp:
    or a                                                              ; 2ec7: b7          .
    exx                                                               ; 2ec8: d9          .
; $2ec9 referenced 1 time by $2ee7
neg0:
    push de                                                           ; 2ec9: d5          .
    ex de,hl                                                          ; 2eca: eb          .
    ld hl,0                                                           ; 2ecb: 21 00 00    !..
    sbc hl,de                                                         ; 2ece: ed 52       .R
    pop de                                                            ; 2ed0: d1          .
    exx                                                               ; 2ed1: d9          .
    push de                                                           ; 2ed2: d5          .
    ex de,hl                                                          ; 2ed3: eb          .
    ld hl,0                                                           ; 2ed4: 21 00 00    !..
    sbc hl,de                                                         ; 2ed7: ed 52       .R
    pop de                                                            ; 2ed9: d1          .
    ret                                                               ; 2eda: c9          .

; $2edb referenced 1 time by $2733
neg:
    exx                                                               ; 2edb: d9          .
    cpl                                                               ; 2edc: 2f          /
    push hl                                                           ; 2edd: e5          .
    or a                                                              ; 2ede: b7          .
    ld hl,0                                                           ; 2edf: 21 00 00    !..
    sbc hl,bc                                                         ; 2ee2: ed 42       .B
    ld b,h                                                            ; 2ee4: 44          D
    ld c,l                                                            ; 2ee5: 4d          M
    pop hl                                                            ; 2ee6: e1          .
    jr neg0                                                           ; 2ee7: 18 e0       ..

; $2ee9 referenced 2 times by $2a26, $2a32
scale:
    ld a,$96                                                          ; 2ee9: 3e 96       >.
    cp c                                                              ; 2eeb: b9          .
    ld a,$17                                                          ; 2eec: 3e 17       >.
    jp c,error_fpp                                                    ; 2eee: da d7 25    ..%
    call piby4                                                        ; 2ef1: cd bd 2a    ..*
    exx                                                               ; 2ef4: d9          .
    ld bc,$2169                                                       ; 2ef5: 01 69 21    .i!
    exx                                                               ; 2ef8: d9          .
; $2ef9 referenced 1 time by $2ad5
mod48:
    set 7,d                                                           ; 2ef9: cb fa       ..
    set 7,h                                                           ; 2efb: cb fc       ..
    ld a,c                                                            ; 2efd: 79          y
    ld c,0                                                            ; 2efe: 0e 00       ..
    ld ix,0                                                           ; 2f00: dd 21 00... .!.
    push ix                                                           ; 2f04: dd e5       ..
    cp b                                                              ; 2f06: b8          .
    jr c,mod485                                                       ; 2f07: 38 3a       8:
; $2f09 referenced 1 time by $2f32
mod481:
    exx                                                               ; 2f09: d9          .
    ex (sp),hl                                                        ; 2f0a: e3          .
    sbc hl,bc                                                         ; 2f0b: ed 42       .B
    ex (sp),hl                                                        ; 2f0d: e3          .
    sbc hl,de                                                         ; 2f0e: ed 52       .R
    exx                                                               ; 2f10: d9          .
    sbc hl,de                                                         ; 2f11: ed 52       .R
    jr nc,mod482                                                      ; 2f13: 30 09       0.
    exx                                                               ; 2f15: d9          .
    ex (sp),hl                                                        ; 2f16: e3          .
    add hl,bc                                                         ; 2f17: 09          .
    ex (sp),hl                                                        ; 2f18: e3          .
    adc hl,de                                                         ; 2f19: ed 5a       .Z
    exx                                                               ; 2f1b: d9          .
    adc hl,de                                                         ; 2f1c: ed 5a       .Z
; $2f1e referenced 2 times by $2f13, $2f40
mod482:
    ccf                                                               ; 2f1e: 3f          ?
    rl c                                                              ; 2f1f: cb 11       ..
    jr nc,mod483                                                      ; 2f21: 30 02       0.
    set 7,c                                                           ; 2f23: cb f9       ..
; $2f25 referenced 1 time by $2f21
mod483:
    dec a                                                             ; 2f25: 3d          =
    cp b                                                              ; 2f26: b8          .
    jr c,mod484                                                       ; 2f27: 38 19       8.
    ex (sp),hl                                                        ; 2f29: e3          .
    add hl,hl                                                         ; 2f2a: 29          )
    ex (sp),hl                                                        ; 2f2b: e3          .
    exx                                                               ; 2f2c: d9          .
    adc hl,hl                                                         ; 2f2d: ed 6a       .j
    exx                                                               ; 2f2f: d9          .
    adc hl,hl                                                         ; 2f30: ed 6a       .j
    jr nc,mod481                                                      ; 2f32: 30 d5       0.
    or a                                                              ; 2f34: b7          .
    exx                                                               ; 2f35: d9          .
    ex (sp),hl                                                        ; 2f36: e3          .
    sbc hl,bc                                                         ; 2f37: ed 42       .B
    ex (sp),hl                                                        ; 2f39: e3          .
    sbc hl,de                                                         ; 2f3a: ed 52       .R
    exx                                                               ; 2f3c: d9          .
    sbc hl,de                                                         ; 2f3d: ed 52       .R
    or a                                                              ; 2f3f: b7          .
    jr mod482                                                         ; 2f40: 18 dc       ..

; $2f42 referenced 1 time by $2f27
mod484:
    inc a                                                             ; 2f42: 3c          <
; $2f43 referenced 1 time by $2f07
mod485:
    ld e,c                                                            ; 2f43: 59          Y
    ld c,a                                                            ; 2f44: 4f          O
    exx                                                               ; 2f45: d9          .
    pop bc                                                            ; 2f46: c1          .
    exx                                                               ; 2f47: d9          .
; $2f48 referenced 2 times by $2736, $2f56
flo48:
    bit 7,h                                                           ; 2f48: cb 7c       .|
    ret nz                                                            ; 2f4a: c0          .
    exx                                                               ; 2f4b: d9          .
    sla c                                                             ; 2f4c: cb 21       .!
    rl b                                                              ; 2f4e: cb 10       ..
    adc hl,hl                                                         ; 2f50: ed 6a       .j
    exx                                                               ; 2f52: d9          .
    adc hl,hl                                                         ; 2f53: ed 6a       .j
    dec c                                                             ; 2f55: 0d          .
    jp nz,flo48                                                       ; 2f56: c2 48 2f    .H/
    ret                                                               ; 2f59: c9          .

; $2f5a referenced 4 times by $2bb8, $2e1b, $2f63, $2f82
float:
    bit 7,h                                                           ; 2f5a: cb 7c       .|
    ret nz                                                            ; 2f5c: c0          .
    exx                                                               ; 2f5d: d9          .
    add hl,hl                                                         ; 2f5e: 29          )
    exx                                                               ; 2f5f: d9          .
    adc hl,hl                                                         ; 2f60: ed 6a       .j
    dec c                                                             ; 2f62: 0d          .
    jp nz,float                                                       ; 2f63: c2 5a 2f    .Z/
    ret                                                               ; 2f66: c9          .

; $2f67 referenced 1 time by $25e8
floata:
    ex af,af'                                                         ; 2f67: 08          .
    add a,$2a                                                         ; 2f68: c6 2a       .*
    ex af,af'                                                         ; 2f6a: 08          .
; $2f6b referenced 4 times by $26eb, $2701, $2759, $2fd8
float2:
    call swap_fpp                                                     ; 2f6b: cd 9e 2f    ../
    call sfloat_fpp                                                   ; 2f6e: cd 74 2f    .t/
    call swap_fpp                                                     ; 2f71: cd 9e 2f    ../
; $2f74 referenced 12 times by $286d, $2967, $29b3, $2a06, $2a23, $2a2e, $2ac8, $2b53, $2be5, $2c0a, $2c91, $2f6e
sfloat_fpp:
    dec c                                                             ; 2f74: 0d          .
    inc c                                                             ; 2f75: 0c          .
    ret nz                                                            ; 2f76: c0          .
    call test_fpp                                                     ; 2f77: cd c3 2f    ../
    ret z                                                             ; 2f7a: c8          .
    ld a,h                                                            ; 2f7b: 7c          |
    or a                                                              ; 2f7c: b7          .
    call m,negate_fpp                                                 ; 2f7d: fc c7 2e    ...
    ld c,$9f                                                          ; 2f80: 0e 9f       ..
    call float                                                        ; 2f82: cd 5a 2f    .Z/
    or a                                                              ; 2f85: b7          .
    ret m                                                             ; 2f86: f8          .
    res 7,h                                                           ; 2f87: cb bc       ..
    ret                                                               ; 2f89: c9          .

; $2f8a referenced 7 times by $2747, $2793, $281e, $2982, $29a8, $29f7, $30de
add1_fpp:
    exx                                                               ; 2f8a: d9          .
    ld bc,1                                                           ; 2f8b: 01 01 00    ...
    add hl,bc                                                         ; 2f8e: 09          .
    exx                                                               ; 2f8f: d9          .
    ret nc                                                            ; 2f90: d0          .
    push bc                                                           ; 2f91: c5          .
    ld bc,1                                                           ; 2f92: 01 01 00    ...
    add hl,bc                                                         ; 2f95: 09          .
    pop bc                                                            ; 2f96: c1          .
    ret                                                               ; 2f97: c9          .

; $2f98 referenced 3 times by $2744, $2790, $281b
odd:
    or a                                                              ; 2f98: b7          .
    exx                                                               ; 2f99: d9          .
    set 0,l                                                           ; 2f9a: cb c5       ..
    exx                                                               ; 2f9c: d9          .
    ret                                                               ; 2f9d: c9          .

; $2f9e referenced 18 times by $26b4, $26db, $2709, $2716, $27a9, $27cd, $283f, $28b8, $28cf, $2a15, $2b42, $2eaf, $2eb5, $2f6b, $2f71, $3081, $30c0, $30e8
swap_fpp:
    ld a,c                                                            ; 2f9e: 79          y
    ld c,b                                                            ; 2f9f: 48          H
    ld b,a                                                            ; 2fa0: 47          G
; $2fa1 referenced 1 time by $2e9a
swap1:
    ex de,hl                                                          ; 2fa1: eb          .
    exx                                                               ; 2fa2: d9          .
    ex de,hl                                                          ; 2fa3: eb          .
    exx                                                               ; 2fa4: d9          .
    ret                                                               ; 2fa5: c9          .

; $2fa6 referenced 3 times by $2729, $29c4, $2ea4
div2:
    call d2                                                           ; 2fa6: cd 44 30    .D0
    exx                                                               ; 2fa9: d9          .
    rr b                                                              ; 2faa: cb 18       ..
    rr c                                                              ; 2fac: cb 19       ..
    ex af,af'                                                         ; 2fae: 08          .
    or b                                                              ; 2faf: b0          .
    ex af,af'                                                         ; 2fb0: 08          .
    exx                                                               ; 2fb1: d9          .
; $2fb2 referenced 4 times by $274a, $2797, $2822, $29fb
incc:
    inc c                                                             ; 2fb2: 0c          .
    ret nz                                                            ; 2fb3: c0          .
; $2fb4 referenced 4 times by $282f, $2b34, $2eac, $30e5
oflow:
    ld a,$14                                                          ; 2fb4: 3e 14       >.
    jp error_fpp                                                      ; 2fb6: c3 d7 25    ..%

ftest:
    call test_fpp                                                     ; 2fb9: cd c3 2f    ../
    ret z                                                             ; 2fbc: c8          .
    ld a,h                                                            ; 2fbd: 7c          |
    and $80                                                           ; 2fbe: e6 80       ..
    or $40                                                            ; 2fc0: f6 40       .@
    ret                                                               ; 2fc2: c9          .

; $2fc3 referenced 5 times by $27c4, $2975, $2d42, $2f77, $2fb9
test_fpp:
    ld a,h                                                            ; 2fc3: 7c          |
    or l                                                              ; 2fc4: b5          .
    exx                                                               ; 2fc5: d9          .
    or h                                                              ; 2fc6: b4          .
    or l                                                              ; 2fc7: b5          .
    exx                                                               ; 2fc8: d9          .
    ret                                                               ; 2fc9: c9          .

fcomp:
    ld a,b                                                            ; 2fca: 78          x
    or c                                                              ; 2fcb: b1          .
    jr nz,fcomp1                                                      ; 2fcc: 20 0a        .
    call icp                                                          ; 2fce: cd e0 2f    ../
; $2fd1 referenced 1 time by $2fde
fcomp0:
    ld a,0                                                            ; 2fd1: 3e 00       >.
    ret z                                                             ; 2fd3: c8          .
    ld a,$80                                                          ; 2fd4: 3e 80       >.
    rra                                                               ; 2fd6: 1f          .
    ret                                                               ; 2fd7: c9          .

; $2fd8 referenced 1 time by $2fcc
fcomp1:
    call float2                                                       ; 2fd8: cd 6b 2f    .k/
    call fcp                                                          ; 2fdb: cd ed 2f    ../
    jr fcomp0                                                         ; 2fde: 18 f1       ..

; $2fe0 referenced 7 times by $28e4, $28ef, $28fb, $2906, $2913, $291e, $2fce
icp:
    call icp1                                                         ; 2fe0: cd 0c 30    ..0
; $2fe3 referenced 11 times by $2751, $27f1, $282a, $2835, $297f, $2ade, $2b2f, $2b39, $2ba8, $2df5, $2ff0
zero_fpp:
    ld a,0                                                            ; 2fe3: 3e 00       >.
    exx                                                               ; 2fe5: d9          .
    ld h,a                                                            ; 2fe6: 67          g
    ld l,a                                                            ; 2fe7: 6f          o
    exx                                                               ; 2fe8: d9          .
    ld h,a                                                            ; 2fe9: 67          g
    ld l,a                                                            ; 2fea: 6f          o
    ld c,a                                                            ; 2feb: 4f          O
    ret                                                               ; 2fec: c9          .

; $2fed referenced 7 times by $28df, $28ea, $28f6, $2901, $290e, $2919, $2fdb
fcp:
    call fcp1                                                         ; 2fed: cd ff 2f    ../
    jr zero_fpp                                                       ; 2ff0: 18 f1       ..

; $2ff2 referenced 5 times by $2c1a, $2c2b, $2cda, $3004, $3006
fcp0:
    ld a,c                                                            ; 2ff2: 79          y
    cp b                                                              ; 2ff3: b8          .
    ret nz                                                            ; 2ff4: c0          .
; $2ff5 referenced 2 times by $2b6a, $300e
icp0:
    sbc hl,de                                                         ; 2ff5: ed 52       .R
    add hl,de                                                         ; 2ff7: 19          .
    ret nz                                                            ; 2ff8: c0          .
    exx                                                               ; 2ff9: d9          .
    sbc hl,de                                                         ; 2ffa: ed 52       .R
    add hl,de                                                         ; 2ffc: 19          .
    exx                                                               ; 2ffd: d9          .
    ret                                                               ; 2ffe: c9          .

; $2fff referenced 1 time by $2fed
fcp1:
    ld a,h                                                            ; 2fff: 7c          |
    xor d                                                             ; 3000: aa          .
    ld a,h                                                            ; 3001: 7c          |
    rla                                                               ; 3002: 17          .
    ret m                                                             ; 3003: f8          .
    jr nc,fcp0                                                        ; 3004: 30 ec       0.
    call fcp0                                                         ; 3006: cd f2 2f    ../
    ret z                                                             ; 3009: c8          .
    ccf                                                               ; 300a: 3f          ?
    ret                                                               ; 300b: c9          .

; $300c referenced 1 time by $2fe0
icp1:
    ld a,h                                                            ; 300c: 7c          |
    xor d                                                             ; 300d: aa          .
    jp p,icp0                                                         ; 300e: f2 f5 2f    ../
    ld a,h                                                            ; 3011: 7c          |
    rla                                                               ; 3012: 17          .
    ret                                                               ; 3013: c9          .

; $3014 referenced 1 time by $2ce2
x10b:
    dec b                                                             ; 3014: 05          .
    inc c                                                             ; 3015: 0c          .
; $3016 referenced 1 time by $30d3
x5:
    call copy0                                                        ; 3016: cd 50 30    .P0
    call d2c                                                          ; 3019: cd 43 30    .C0
    call d2c                                                          ; 301c: cd 43 30    .C0
    ex af,af'                                                         ; 301f: 08          .
; $3020 referenced 4 times by $26e8, $26fa, $2726, $3039
add:
    exx                                                               ; 3020: d9          .
    add hl,de                                                         ; 3021: 19          .
    exx                                                               ; 3022: d9          .
    adc hl,de                                                         ; 3023: ed 5a       .Z
    ret                                                               ; 3025: c9          .

; $3026 referenced 3 times by $26e4, $26fe, $2730
sub:
    exx                                                               ; 3026: d9          .
    or a                                                              ; 3027: b7          .
    sbc hl,de                                                         ; 3028: ed 52       .R
    exx                                                               ; 302a: d9          .
    sbc hl,de                                                         ; 302b: ed 52       .R
    ret                                                               ; 302d: c9          .

; $302e referenced 1 time by $2e81
x10:
    call copy0                                                        ; 302e: cd 50 30    .P0
    call x2                                                           ; 3031: cd 3d 30    .=0
    ret c                                                             ; 3034: d8          .
    call x2                                                           ; 3035: cd 3d 30    .=0
    ret c                                                             ; 3038: d8          .
    call add                                                          ; 3039: cd 20 30    . 0
    ret c                                                             ; 303c: d8          .
; $303d referenced 4 times by $284b, $2d06, $3031, $3035
x2:
    exx                                                               ; 303d: d9          .
    add hl,hl                                                         ; 303e: 29          )
    exx                                                               ; 303f: d9          .
    adc hl,hl                                                         ; 3040: ed 6a       .j
    ret                                                               ; 3042: c9          .

; $3043 referenced 3 times by $3019, $301c, $30d9
d2c:
    inc c                                                             ; 3043: 0c          .
; $3044 referenced 1 time by $2fa6
d2:
    srl h                                                             ; 3044: cb 3c       .<
    rr l                                                              ; 3046: cb 1d       ..
    exx                                                               ; 3048: d9          .
    rr h                                                              ; 3049: cb 1c       ..
    rr l                                                              ; 304b: cb 1d       ..
    exx                                                               ; 304d: d9          .
    ret                                                               ; 304e: c9          .

; $304f referenced 3 times by $2896, $2beb, $3057
copy:
    ld b,c                                                            ; 304f: 41          A
; $3050 referenced 2 times by $3016, $302e
copy0:
    ld d,h                                                            ; 3050: 54          T
    ld e,l                                                            ; 3051: 5d          ]
    exx                                                               ; 3052: d9          .
    ld d,h                                                            ; 3053: 54          T
    ld e,l                                                            ; 3054: 5d          ]
    exx                                                               ; 3055: d9          .
    ret                                                               ; 3056: c9          .

; $3057 referenced 4 times by $2a50, $2a7b, $2b7b, $2c41
square:
    call copy                                                         ; 3057: cd 4f 30    .O0
    call fmul                                                         ; 305a: cd ef 27    ..'
; $305d referenced 11 times by $28bb, $2a09, $2a12, $2a4d, $2aec, $2b78, $2ba4, $2be8, $2c3e, $3072, $307e
push5:
    pop ix                                                            ; 305d: dd e1       ..
    push bc                                                           ; 305f: c5          .
    push hl                                                           ; 3060: e5          .
    exx                                                               ; 3061: d9          .
    push hl                                                           ; 3062: e5          .
    exx                                                               ; 3063: d9          .
    jp (ix)                                                           ; 3064: dd e9       ..

; $3066 referenced 15 times by $28d5, $2a0f, $2a1b, $2a6f, $2a72, $2a9a, $2b1a, $2b9a, $2b9d, $2bcb, $2bfa, $2c6a, $2c6d, $307b, $308a
pop5:
    pop ix                                                            ; 3066: dd e1       ..
    exx                                                               ; 3068: d9          .
    pop de                                                            ; 3069: d1          .
    exx                                                               ; 306a: d9          .
    pop de                                                            ; 306b: d1          .
    ld a,c                                                            ; 306c: 79          y
    pop bc                                                            ; 306d: c1          .
    ld b,c                                                            ; 306e: 41          A
    ld c,a                                                            ; 306f: 4f          O
    jp (ix)                                                           ; 3070: dd e9       ..

; $3072 referenced 2 times by $2b75, $2c38
ratio:
    call push5                                                        ; 3072: cd 5d 30    .]0
    call done                                                         ; 3075: cd b2 2a    ..*
    call fadd                                                         ; 3078: cd 04 27    ..'
    call pop5                                                         ; 307b: cd 66 30    .f0
    call push5                                                        ; 307e: cd 5d 30    .]0
    call swap_fpp                                                     ; 3081: cd 9e 2f    ../
    call done                                                         ; 3084: cd b2 2a    ..*
    call fsub                                                         ; 3087: cd ee 26    ..&
    call pop5                                                         ; 308a: cd 66 30    .f0
    jp fdiv                                                           ; 308d: c3 5c 27    .\'

; $3090 referenced 5 times by $2a53, $2a7e, $2aef, $2b7e, $2c44
poly:
    ld ix,2                                                           ; 3090: dd 21 02... .!.
    add ix,sp                                                         ; 3094: dd 39       .9
    ex (sp),ix                                                        ; 3096: dd e3       ..
    call dload5_fpp                                                   ; 3098: cd e3 2d    ..-
; $309b referenced 1 time by $30b5
poly1:
    call fmul                                                         ; 309b: cd ef 27    ..'
    ld de,5                                                           ; 309e: 11 05 00    ...
    add ix,de                                                         ; 30a1: dd 19       ..
    call dload5_fpp                                                   ; 30a3: cd e3 2d    ..-
    ex (sp),ix                                                        ; 30a6: dd e3       ..
    inc b                                                             ; 30a8: 04          .
    dec b                                                             ; 30a9: 05          .
    jp m,fadd                                                         ; 30aa: fa 04 27    ..'
    call fadd                                                         ; 30ad: cd 04 27    ..'
    call dload5_fpp                                                   ; 30b0: cd e3 2d    ..-
    ex (sp),ix                                                        ; 30b3: dd e3       ..
    jr poly1                                                          ; 30b5: 18 e4       ..

; $30b7 referenced 6 times by $2cb9, $2cc8, $2cd7, $2e25, $2e33, $2e3e
powr10:
    inc a                                                             ; 30b7: 3c          <
    ex af,af'                                                         ; 30b8: 08          .
    push hl                                                           ; 30b9: e5          .
    exx                                                               ; 30ba: d9          .
    push hl                                                           ; 30bb: e5          .
    exx                                                               ; 30bc: d9          .
    call done                                                         ; 30bd: cd b2 2a    ..*
    call swap_fpp                                                     ; 30c0: cd 9e 2f    ../
    xor a                                                             ; 30c3: af          .
; $30c4 referenced 1 time by $30e2
powr11:
    ex af,af'                                                         ; 30c4: 08          .
    dec a                                                             ; 30c5: 3d          =
    jr z,powr14                                                       ; 30c6: 28 20       (
    jp p,powr13                                                       ; 30c8: f2 cf 30    ..0
    cp c                                                              ; 30cb: b9          .
    jr c,powr14                                                       ; 30cc: 38 1a       8.
    inc a                                                             ; 30ce: 3c          <
; $30cf referenced 1 time by $30c8
powr13:
    ex af,af'                                                         ; 30cf: 08          .
    inc a                                                             ; 30d0: 3c          <
    set 7,h                                                           ; 30d1: cb fc       ..
    call x5                                                           ; 30d3: cd 16 30    ..0
    jr nc,powr12                                                      ; 30d6: 30 05       0.
    ex af,af'                                                         ; 30d8: 08          .
    call d2c                                                          ; 30d9: cd 43 30    .C0
    ex af,af'                                                         ; 30dc: 08          .
; $30dd referenced 1 time by $30d6
powr12:
    ex af,af'                                                         ; 30dd: 08          .
    call c,add1_fpp                                                   ; 30de: dc 8a 2f    ../
    inc c                                                             ; 30e1: 0c          .
    jp m,powr11                                                       ; 30e2: fa c4 30    ..0
    jp oflow                                                          ; 30e5: c3 b4 2f    ../

; $30e8 referenced 2 times by $30c6, $30cc
powr14:
    call swap_fpp                                                     ; 30e8: cd 9e 2f    ../
    res 7,d                                                           ; 30eb: cb ba       ..
    exx                                                               ; 30ed: d9          .
    pop hl                                                            ; 30ee: e1          .
    exx                                                               ; 30ef: d9          .
    pop hl                                                            ; 30f0: e1          .
    ex af,af'                                                         ; 30f1: 08          .
    ret                                                               ; 30f2: c9          .

; $30f3 referenced 2 times by $26c9, $277b
diva:
    or a                                                              ; 30f3: b7          .
; $30f4 referenced 1 time by $3114
div0:
    sbc hl,bc                                                         ; 30f4: ed 42       .B
    exx                                                               ; 30f6: d9          .
    sbc hl,bc                                                         ; 30f7: ed 42       .B
    exx                                                               ; 30f9: d9          .
    jr nc,div1                                                        ; 30fa: 30 05       0.
    add hl,bc                                                         ; 30fc: 09          .
    exx                                                               ; 30fd: d9          .
    adc hl,bc                                                         ; 30fe: ed 4a       .J
    exx                                                               ; 3100: d9          .
; $3101 referenced 1 time by $30fa
div1:
    ccf                                                               ; 3101: 3f          ?
; $3102 referenced 1 time by $311e
divc:
    rl e                                                              ; 3102: cb 13       ..
    rl d                                                              ; 3104: cb 12       ..
    exx                                                               ; 3106: d9          .
    rl e                                                              ; 3107: cb 13       ..
    rl d                                                              ; 3109: cb 12       ..
    exx                                                               ; 310b: d9          .
    inc a                                                             ; 310c: 3c          <
    ret p                                                             ; 310d: f0          .
; $310e referenced 2 times by $2782, $29ed
divb:
    adc hl,hl                                                         ; 310e: ed 6a       .j
    exx                                                               ; 3110: d9          .
    adc hl,hl                                                         ; 3111: ed 6a       .j
    exx                                                               ; 3113: d9          .
    jr nc,div0                                                        ; 3114: 30 de       0.
    or a                                                              ; 3116: b7          .
    sbc hl,bc                                                         ; 3117: ed 42       .B
    exx                                                               ; 3119: d9          .
    sbc hl,bc                                                         ; 311a: ed 42       .B
    exx                                                               ; 311c: d9          .
    scf                                                               ; 311d: 37          7
    jp divc                                                           ; 311e: c3 02 31    ..1

; $3121 referenced 2 times by $27be, $280c
mula:
    or a                                                              ; 3121: b7          .
; $3122 referenced 1 time by $313f
mul0:
    exx                                                               ; 3122: d9          .
    rr d                                                              ; 3123: cb 1a       ..
    rr e                                                              ; 3125: cb 1b       ..
    exx                                                               ; 3127: d9          .
    rr d                                                              ; 3128: cb 1a       ..
    rr e                                                              ; 312a: cb 1b       ..
    jr nc,mul1                                                        ; 312c: 30 05       0.
    add hl,bc                                                         ; 312e: 09          .
    exx                                                               ; 312f: d9          .
    adc hl,bc                                                         ; 3130: ed 4a       .J
    exx                                                               ; 3132: d9          .
; $3133 referenced 1 time by $312c
mul1:
    inc a                                                             ; 3133: 3c          <
    ret p                                                             ; 3134: f0          .
; $3135 referenced 1 time by $280f
mulb:
    exx                                                               ; 3135: d9          .
    rr h                                                              ; 3136: cb 1c       ..
    rr l                                                              ; 3138: cb 1d       ..
    exx                                                               ; 313a: d9          .
    rr h                                                              ; 313b: cb 1c       ..
    rr l                                                              ; 313d: cb 1d       ..
    jp mul0                                                           ; 313f: c3 22 31    ."1

; $3142 referenced 1 time by $317f
sqr1:
    sbc hl,bc                                                         ; 3142: ed 42       .B
    exx                                                               ; 3144: d9          .
    sbc hl,bc                                                         ; 3145: ed 42       .B
    exx                                                               ; 3147: d9          .
    inc c                                                             ; 3148: 0c          .
    jr nc,sqr2                                                        ; 3149: 30 07       0.
    dec c                                                             ; 314b: 0d          .
    add hl,bc                                                         ; 314c: 09          .
    exx                                                               ; 314d: d9          .
    adc hl,bc                                                         ; 314e: ed 4a       .J
    exx                                                               ; 3150: d9          .
    dec c                                                             ; 3151: 0d          .
; $3152 referenced 2 times by $3149, $318a
sqr2:
    inc a                                                             ; 3152: 3c          <
    ret p                                                             ; 3153: f0          .
; $3154 referenced 2 times by $29df, $29e6
sqra:
    sla c                                                             ; 3154: cb 21       .!
    rl b                                                              ; 3156: cb 10       ..
    exx                                                               ; 3158: d9          .
    rl c                                                              ; 3159: cb 11       ..
    rl b                                                              ; 315b: cb 10       ..
    exx                                                               ; 315d: d9          .
    inc c                                                             ; 315e: 0c          .
    sla e                                                             ; 315f: cb 23       .#
    rl d                                                              ; 3161: cb 12       ..
    exx                                                               ; 3163: d9          .
    rl e                                                              ; 3164: cb 13       ..
    rl d                                                              ; 3166: cb 12       ..
    exx                                                               ; 3168: d9          .
    adc hl,hl                                                         ; 3169: ed 6a       .j
    exx                                                               ; 316b: d9          .
    adc hl,hl                                                         ; 316c: ed 6a       .j
    exx                                                               ; 316e: d9          .
    sla e                                                             ; 316f: cb 23       .#
    rl d                                                              ; 3171: cb 12       ..
    exx                                                               ; 3173: d9          .
    rl e                                                              ; 3174: cb 13       ..
    rl d                                                              ; 3176: cb 12       ..
    exx                                                               ; 3178: d9          .
    adc hl,hl                                                         ; 3179: ed 6a       .j
    exx                                                               ; 317b: d9          .
    adc hl,hl                                                         ; 317c: ed 6a       .j
    exx                                                               ; 317e: d9          .
    jp nc,sqr1                                                        ; 317f: d2 42 31    .B1
; $3182 referenced 1 time by $3192
sqr3:
    or a                                                              ; 3182: b7          .
    sbc hl,bc                                                         ; 3183: ed 42       .B
    exx                                                               ; 3185: d9          .
    sbc hl,bc                                                         ; 3186: ed 42       .B
    exx                                                               ; 3188: d9          .
    inc c                                                             ; 3189: 0c          .
    jp sqr2                                                           ; 318a: c3 52 31    .R1

; $318d referenced 1 time by $29e9
sqrb:
    add hl,hl                                                         ; 318d: 29          )
    exx                                                               ; 318e: d9          .
    adc hl,hl                                                         ; 318f: ed 6a       .j
    exx                                                               ; 3191: d9          .
    jr c,sqr3                                                         ; 3192: 38 ee       8.
    inc a                                                             ; 3194: 3c          <
    inc c                                                             ; 3195: 0c          .
    sbc hl,bc                                                         ; 3196: ed 42       .B
    exx                                                               ; 3198: d9          .
    sbc hl,bc                                                         ; 3199: ed 42       .B
    exx                                                               ; 319b: d9          .
    ret nc                                                            ; 319c: d0          .
    add hl,bc                                                         ; 319d: 09          .
    exx                                                               ; 319e: d9          .
    adc hl,bc                                                         ; 319f: ed 4a       .J
    exx                                                               ; 31a1: d9          .
    dec c                                                             ; 31a2: 0d          .
    ret                                                               ; 31a3: c9          .

; $31a4 referenced 2 times by $2e53, $2e7a
digitq:
    ld a,(ix+0)                                                       ; 31a4: dd 7e 00    .~.
    cp $3a                                                            ; 31a7: fe 3a       .:
    ccf                                                               ; 31a9: 3f          ?
    ret c                                                             ; 31aa: d8          .
    cp $30                                                            ; 31ab: fe 30       .0
    ret                                                               ; 31ad: c9          .

; $31ae referenced 3 times by $2985, $2e4f, $31b5
signq:
    ld a,(ix+0)                                                       ; 31ae: dd 7e 00    .~.
    inc ix                                                            ; 31b1: dd 23       .#
    cp $20                                                            ; 31b3: fe 20       .
    jr z,signq                                                        ; 31b5: 28 f7       (.
    cp $2b                                                            ; 31b7: fe 2b       .+
    ret z                                                             ; 31b9: c8          .
    cp $2d                                                            ; 31ba: fe 2d       .-
    ret z                                                             ; 31bc: c8          .
    dec ix                                                            ; 31bd: dd 2b       .+
    ret                                                               ; 31bf: c9          .

; $31c0 referenced 1 time by $14cf
clrscn:
    push bc                                                           ; 31c0: c5          .
    call tell                                                         ; 31c1: cd 55 0d    .U.
    db $1b, "[;H", $1b, "[2J", 0                                      ; 31c4: 1b 5b 3b... .[;

    ld bc,0                                                           ; 31cd: 01 00 00    ...
    ld (textx),bc                                                     ; 31d0: ed 43 c7... .C.
    ld (texty),bc                                                     ; 31d4: ed 43 c9... .C.
    pop bc                                                            ; 31d8: c1          .
    ret                                                               ; 31d9: c9          .

; $31da referenced 1 time by $1848
putcsr:
    ld (textx),de                                                     ; 31da: ed 53 c7... .S.
    ld (texty),hl                                                     ; 31de: 22 c9 32    ".2
    ld a,$1b                                                          ; 31e1: 3e 1b       >.
    call outchr                                                       ; 31e3: cd 9e 09    ...
    ld a,$5b                                                          ; 31e6: 3e 5b       >[
    call outchr                                                       ; 31e8: cd 9e 09    ...
    ld de,(textx)                                                     ; 31eb: ed 5b c7... .[.
    call pbcdl                                                        ; 31ef: cd 2b 0a    .+.
    ld a,$3b                                                          ; 31f2: 3e 3b       >;
    call outchr                                                       ; 31f4: cd 9e 09    ...
    ld hl,(texty)                                                     ; 31f7: 2a c9 32    *.2
    call pbcdl                                                        ; 31fa: cd 2b 0a    .+.
    ld a,$48                                                          ; 31fd: 3e 48       >H
    call outchr                                                       ; 31ff: cd 9e 09    ...
    ret                                                               ; 3202: c9          .

; $3203 referenced 2 times by $2123, $2129
getcsr:
    ld de,(textx)                                                     ; 3203: ed 5b c7... .[.
    ld hl,(texty)                                                     ; 3207: 2a c9 32    *.2
    ret                                                               ; 320a: c9          .

; $320b referenced 1 time by $21d5
getime:
    ld de,0                                                           ; 320b: 11 00 00    ...
    ld hl,0                                                           ; 320e: 21 00 00    !..
    ret                                                               ; 3211: c9          .

; $3212 referenced 1 time by $1549
putime:
    ret                                                               ; 3212: c9          .

colour:
    call expri                                                        ; 3213: cd be 1f    ...
    exx                                                               ; 3216: d9          .
    ld a,l                                                            ; 3217: 7d          }
    and 7                                                             ; 3218: e6 07       ..
    bit 7,l                                                           ; 321a: cb 7d       .}
    jp z,fgclr                                                        ; 321c: ca 21 32    .!2
    add a,$0a                                                         ; 321f: c6 0a       ..
; $3221 referenced 1 time by $321c
fgclr:
    add a,$1e                                                         ; 3221: c6 1e       ..
    bit 3,l                                                           ; 3223: cb 5d       .]
    jp z,outclr                                                       ; 3225: ca 2a 32    .*2
    add a,$3c                                                         ; 3228: c6 3c       .<
; $322a referenced 1 time by $3225
outclr:
    ld l,a                                                            ; 322a: 6f          o
    ld a,$1b                                                          ; 322b: 3e 1b       >.
    call outchr                                                       ; 322d: cd 9e 09    ...
    ld a,$5b                                                          ; 3230: 3e 5b       >[
    call outchr                                                       ; 3232: cd 9e 09    ...
    call pbcdl                                                        ; 3235: cd 2b 0a    .+.
    ld a,$6d                                                          ; 3238: 3e 6d       >m
    call outchr                                                       ; 323a: cd 9e 09    ...
    jp xeq_exec                                                       ; 323d: c3 12 0e    ...

gcol:
    call expri                                                        ; 3240: cd be 1f    ...
    exx                                                               ; 3243: d9          .
    ld a,l                                                            ; 3244: 7d          }
    and $0f                                                           ; 3245: e6 0f       ..
    ld e,a                                                            ; 3247: 5f          _
    add a,a                                                           ; 3248: 87          .
    add a,a                                                           ; 3249: 87          .
    add a,a                                                           ; 324a: 87          .
    add a,a                                                           ; 324b: 87          .
    ld d,a                                                            ; 324c: 57          W
    bit 7,l                                                           ; 324d: cb 7d       .}
    jp nz,bdgcol                                                      ; 324f: c2 6f 32    .o2
    ld a,(cgcol)                                                      ; 3252: 3a c1 32    :.2
    bit 6,l                                                           ; 3255: cb 75       .u
    jp nz,bggcol                                                      ; 3257: c2 63 32    .c2
    and $0f                                                           ; 325a: e6 0f       ..
    or d                                                              ; 325c: b2          .
    ld (cgcol),a                                                      ; 325d: 32 c1 32    2.2
    jp xeq_exec                                                       ; 3260: c3 12 0e    ...

; $3263 referenced 1 time by $3257
bggcol:
    ld a,(cgcol)                                                      ; 3263: 3a c1 32    :.2
    and $f0                                                           ; 3266: e6 f0       ..
    or e                                                              ; 3268: b3          .
    ld (cgcol),a                                                      ; 3269: 32 c1 32    2.2
    jp xeq_exec                                                       ; 326c: c3 12 0e    ...

; $326f referenced 1 time by $324f
bdgcol:
    ld a,(ccolor)                                                     ; 326f: 3a c2 32    :.2
    and $f0                                                           ; 3272: e6 f0       ..
    or e                                                              ; 3274: b3          .
    ld (ccolor),a                                                     ; 3275: 32 c2 32    2.2
    ld bc,(vdpadr)                                                    ; 3278: ed 4b be... .K.
    inc c                                                             ; 327c: 0c          .
    ld b,$87                                                          ; 327d: 06 87       ..
    out (c),a                                                         ; 327f: ed 79       .y
    out (c),b                                                         ; 3281: ed 41       .A
    jp xeq_exec                                                       ; 3283: c3 12 0e    ...

mode:
    call expri                                                        ; 3286: cd be 1f    ...
    exx                                                               ; 3289: d9          .
    ld a,l                                                            ; 328a: 7d          }
    call vdpini                                                       ; 328b: cd da 32    ..2
    jp xeq_exec                                                       ; 328e: c3 12 0e    ...

plot:
    call getxy                                                        ; 3291: cd 9c 32    ..2
    ld b,l                                                            ; 3294: 45          E
    ld c,e                                                            ; 3295: 4b          K
    call bmplot                                                       ; 3296: cd 89 33    ..3
xeq1_hardware:
    jp xeq_exec                                                       ; 3299: c3 12 0e    ...

; $329c referenced 1 time by $3291
getxy:
    call expri                                                        ; 329c: cd be 1f    ...
    exx                                                               ; 329f: d9          .
    push hl                                                           ; 32a0: e5          .
    call comma                                                        ; 32a1: cd 5a 25    .Z%
    call expri                                                        ; 32a4: cd be 1f    ...
    exx                                                               ; 32a7: d9          .
    pop de                                                            ; 32a8: d1          .
    ret                                                               ; 32a9: c9          .

; $32aa referenced 2 times by $1557, $21e0
adval:
clg:
draw:
envel:
getims:
move:
point:
putims:
sound:
    xor a                                                             ; 32aa: af          .
    call exterr                                                       ; 32ab: cd 1a 08    ...
    db "Not implemented", 0                                           ; 32ae: 4e 6f 74... Not
; $32be referenced 3 times by $3278, $32df, $33ad
vdpadr:
    db $be                                                            ; 32be: be          .
vdpint:
    db 0                                                              ; 32bf: 00          .
; $32c0 referenced 4 times by $32dc, $330b, $3366, $3389
cmode:
    db 2                                                              ; 32c0: 02          .
; $32c1 referenced 5 times by $3252, $325d, $3263, $3269, $33d3
cgcol:
    db $f0                                                            ; 32c1: f0          .
; $32c2 referenced 3 times by $326f, $3275, $32f4
ccolor:
    db $f0                                                            ; 32c2: f0          .
graphx:
    db 0, 0                                                           ; 32c3: 00 00       ..
graphy:
    db 0, 0                                                           ; 32c5: 00 00       ..
; $32c7 referenced 4 times by $31d0, $31da, $31eb, $3203
textx:
    db 0, 0                                                           ; 32c7: 00 00       ..
; $32c9 referenced 4 times by $31d4, $31de, $31f7, $3207
texty:
    db 0, 0                                                           ; 32c9: 00 00       ..
defreg:
    db 0, $80, $0e, $80, 0, $77, 3                                    ; 32cb: 00 80 0e... ...
modreg:
    db 0, $d0, 0, $c0, 2, $c0, 0, $c8                                 ; 32d2: 00 d0 00... ...

; $32da referenced 1 time by $328b
vdpini:
    and 3                                                             ; 32da: e6 03       ..
    ld (cmode),a                                                      ; 32dc: 32 c0 32    2.2
    ld bc,(vdpadr)                                                    ; 32df: ed 4b be... .K.
    inc c                                                             ; 32e3: 0c          .
    ld hl,$32cb                                                       ; 32e4: 21 cb 32    !.2
    ld b,7                                                            ; 32e7: 06 07       ..
    ld d,$80                                                          ; 32e9: 16 80       ..
; $32eb referenced 1 time by $32f2
reglp:
    ld e,(hl)                                                         ; 32eb: 5e          ^
    out (c),e                                                         ; 32ec: ed 59       .Y
    out (c),d                                                         ; 32ee: ed 51       .Q
    inc hl                                                            ; 32f0: 23          #
    inc d                                                             ; 32f1: 14          .
    djnz reglp                                                        ; 32f2: 10 f7       ..
    ld a,(ccolor)                                                     ; 32f4: 3a c2 32    :.2
    out (c),a                                                         ; 32f7: ed 79       .y
    out (c),d                                                         ; 32f9: ed 51       .Q
    ld de,$4000                                                       ; 32fb: 11 00 40    ..@
    out (c),e                                                         ; 32fe: ed 59       .Y
    out (c),d                                                         ; 3300: ed 51       .Q
    dec c                                                             ; 3302: 0d          .
; $3303 referenced 1 time by $3308
clrlp:
    out (c),b                                                         ; 3303: ed 41       .A
    dec de                                                            ; 3305: 1b          .
    ld a,d                                                            ; 3306: 7a          z
    or e                                                              ; 3307: b3          .
    jp nz,clrlp                                                       ; 3308: c2 03 33    ..3
    ld a,(cmode)                                                      ; 330b: 3a c0 32    :.2
    cp 3                                                              ; 330e: fe 03       ..
    jp z,mode3                                                        ; 3310: ca 42 33    .B3
    cp 2                                                              ; 3313: fe 02       ..
    jp nz,setreg                                                      ; 3315: c2 66 33    .f3
    inc c                                                             ; 3318: 0c          .
    ld b,$83                                                          ; 3319: 06 83       ..
    ld a,$ff                                                          ; 331b: 3e ff       >.
    out (c),a                                                         ; 331d: ed 79       .y
    out (c),b                                                         ; 331f: ed 41       .A
    ld b,$84                                                          ; 3321: 06 84       ..
    ld a,3                                                            ; 3323: 3e 03       >.
    out (c),a                                                         ; 3325: ed 79       .y
    out (c),b                                                         ; 3327: ed 41       .A
    ld de,$3800                                                       ; 3329: 11 00 38    ..8
    set 6,d                                                           ; 332c: cb f2       ..
    out (c),e                                                         ; 332e: ed 59       .Y
    out (c),d                                                         ; 3330: ed 51       .Q
    dec c                                                             ; 3332: 0d          .
    ld b,3                                                            ; 3333: 06 03       ..
    xor a                                                             ; 3335: af          .
; $3336 referenced 2 times by $333a, $333d
m2loop:
    out (c),a                                                         ; 3336: ed 79       .y
    nop                                                               ; 3338: 00          .
    inc a                                                             ; 3339: 3c          <
    jp nz,m2loop                                                      ; 333a: c2 36 33    .63
    djnz m2loop                                                       ; 333d: 10 f7       ..
    jp setreg                                                         ; 333f: c3 66 33    .f3

; $3342 referenced 1 time by $3310
mode3:
    inc c                                                             ; 3342: 0c          .
    ld de,$3800                                                       ; 3343: 11 00 38    ..8
    set 6,d                                                           ; 3346: cb f2       ..
    out (c),e                                                         ; 3348: ed 59       .Y
    out (c),d                                                         ; 334a: ed 51       .Q
    dec c                                                             ; 334c: 0d          .
    xor a                                                             ; 334d: af          .
    ld d,6                                                            ; 334e: 16 06       ..
; $3350 referenced 1 time by $3363
m3lp1:
    ld e,4                                                            ; 3350: 1e 04       ..
; $3352 referenced 1 time by $335d
m3lp2:
    push af                                                           ; 3352: f5          .
    ld b,$20                                                          ; 3353: 06 20       .
; $3355 referenced 1 time by $3359
m3lp3:
    out (c),a                                                         ; 3355: ed 79       .y
    nop                                                               ; 3357: 00          .
    inc a                                                             ; 3358: 3c          <
    djnz m3lp3                                                        ; 3359: 10 fa       ..
    pop af                                                            ; 335b: f1          .
    dec e                                                             ; 335c: 1d          .
    jp nz,m3lp2                                                       ; 335d: c2 52 33    .R3
    add a,$20                                                         ; 3360: c6 20       .
    dec d                                                             ; 3362: 15          .
    jp nz,m3lp1                                                       ; 3363: c2 50 33    .P3
; $3366 referenced 2 times by $3315, $333f
setreg:
    ld a,(cmode)                                                      ; 3366: 3a c0 32    :.2
    ld d,0                                                            ; 3369: 16 00       ..
    ld e,a                                                            ; 336b: 5f          _
    ld hl,$32d2                                                       ; 336c: 21 d2 32    !.2
    add hl,de                                                         ; 336f: 19          .
    add hl,de                                                         ; 3370: 19          .
    inc c                                                             ; 3371: 0c          .
    ld a,(hl)                                                         ; 3372: 7e          ~
    ld b,$80                                                          ; 3373: 06 80       ..
    out (c),a                                                         ; 3375: ed 79       .y
    out (c),b                                                         ; 3377: ed 41       .A
    inc hl                                                            ; 3379: 23          #
    ld a,(hl)                                                         ; 337a: 7e          ~
    inc b                                                             ; 337b: 04          .
    out (c),a                                                         ; 337c: ed 79       .y
    out (c),b                                                         ; 337e: ed 41       .A
    ret                                                               ; 3380: c9          .

mask:
    db $80, $40, $20, $10, 8, 4, 2, 1                                 ; 3381: 80 40 20... .@

; $3389 referenced 1 time by $3296
bmplot:
    ld a,(cmode)                                                      ; 3389: 3a c0 32    :.2
    cp 2                                                              ; 338c: fe 02       ..
    ret nz                                                            ; 338e: c0          .
    ld a,b                                                            ; 338f: 78          x
    cp $c0                                                            ; 3390: fe c0       ..
    ret nc                                                            ; 3392: d0          .
    rrca                                                              ; 3393: 0f          .
    rrca                                                              ; 3394: 0f          .
    rrca                                                              ; 3395: 0f          .
    and $1f                                                           ; 3396: e6 1f       ..
    ld d,a                                                            ; 3398: 57          W
    ld a,c                                                            ; 3399: 79          y
    and $f8                                                           ; 339a: e6 f8       ..
    ld e,a                                                            ; 339c: 5f          _
    ld a,b                                                            ; 339d: 78          x
    and 7                                                             ; 339e: e6 07       ..
    or e                                                              ; 33a0: b3          .
    ld e,a                                                            ; 33a1: 5f          _
    ld hl,$3381                                                       ; 33a2: 21 81 33    !.3
    ld a,c                                                            ; 33a5: 79          y
    and 7                                                             ; 33a6: e6 07       ..
    ld b,0                                                            ; 33a8: 06 00       ..
    ld c,a                                                            ; 33aa: 4f          O
    add hl,bc                                                         ; 33ab: 09          .
    ld a,(hl)                                                         ; 33ac: 7e          ~
    ld bc,(vdpadr)                                                    ; 33ad: ed 4b be... .K.
    inc c                                                             ; 33b1: 0c          .
    ld hl,0                                                           ; 33b2: 21 00 00    !..
    add hl,de                                                         ; 33b5: 19          .
    out (c),l                                                         ; 33b6: ed 69       .i
    out (c),h                                                         ; 33b8: ed 61       .a
    dec c                                                             ; 33ba: 0d          .
    in b,(c)                                                          ; 33bb: ed 40       .@
maskop:
    or b                                                              ; 33bd: b0          .
    set 6,h                                                           ; 33be: cb f4       ..
    inc c                                                             ; 33c0: 0c          .
    out (c),l                                                         ; 33c1: ed 69       .i
    out (c),h                                                         ; 33c3: ed 61       .a
    dec c                                                             ; 33c5: 0d          .
    out (c),a                                                         ; 33c6: ed 79       .y
    inc c                                                             ; 33c8: 0c          .
    ld hl,$2000                                                       ; 33c9: 21 00 20    !.
    add hl,de                                                         ; 33cc: 19          .
    set 6,h                                                           ; 33cd: cb f4       ..
    out (c),l                                                         ; 33cf: ed 69       .i
    out (c),h                                                         ; 33d1: ed 61       .a
    ld a,(cgcol)                                                      ; 33d3: 3a c1 32    :.2
    dec c                                                             ; 33d6: 0d          .
    out (c),a                                                         ; 33d7: ed 79       .y
    ret                                                               ; 33d9: c9          .

stsave:
    call savlod                                                       ; 33da: cd 33 38    .38
    jp c,huh                                                          ; 33dd: da 01 38    ..8
    push hl                                                           ; 33e0: e5          .
    jr oss1                                                           ; 33e1: 18 04       ..

; $33e3 referenced 1 time by $07ff
ossave:
    push bc                                                           ; 33e3: c5          .
    call setup0                                                       ; 33e4: cd 9a 36    ..6
; $33e7 referenced 1 time by $33e1
oss1:
    ex de,hl                                                          ; 33e7: eb          .
    call create_cpm                                                   ; 33e8: cd 3c 36    .<6
    jr nz,save_cpm                                                    ; 33eb: 20 14        .
dirful:
    ld a,$be                                                          ; 33ed: 3e be       >.
    call exterr                                                       ; 33ef: cd 1a 08    ...
    db "Directory full", 0                                            ; 33f2: 44 69 72... Dir

; $3401 referenced 2 times by $33eb, $340b
save_cpm:
    call write                                                        ; 3401: cd 0e 36    ..6
    add hl,bc                                                         ; 3404: 09          .
    ex (sp),hl                                                        ; 3405: e3          .
    sbc hl,bc                                                         ; 3406: ed 42       .B
    ex (sp),hl                                                        ; 3408: e3          .
    jr z,save1_cpm                                                    ; 3409: 28 02       (.
    jr nc,save_cpm                                                    ; 340b: 30 f4       0.
; $340d referenced 1 time by $3409
save1_cpm:
    pop bc                                                            ; 340d: c1          .
; $340e referenced 3 times by $345a, $3460, $34b6
close_cpm:
    ld a,$10                                                          ; 340e: 3e 10       >.
    call bdos1                                                        ; 3410: cd e2 35    ..5
    inc a                                                             ; 3413: 3c          <
    ret nz                                                            ; 3414: c0          .
    ld a,$c8                                                          ; 3415: 3e c8       >.
    call exterr                                                       ; 3417: cd 1a 08    ...
    db "Close error", 0                                               ; 341a: 43 6c 6f... Clo

; $3426 referenced 6 times by $0127, $0850, $0e44, $15de, $3479, $347b
osshut:
    ld a,e                                                            ; 3426: 7b          {
    or a                                                              ; 3427: b7          .
    jr nz,shut1                                                       ; 3428: 20 14        .
; $342a referenced 1 time by $3433
shut0:
    inc e                                                             ; 342a: 1c          .
    bit 3,e                                                           ; 342b: cb 5b       .[
    ret nz                                                            ; 342d: c0          .
    push de                                                           ; 342e: d5          .
    call shut1                                                        ; 342f: cd 3e 34    .>4
    pop de                                                            ; 3432: d1          .
    jr shut0                                                          ; 3433: 18 f5       ..

; $3435 referenced 2 times by $38d8, $3a16
seshut:
    ld hl,$3c13                                                       ; 3435: 21 13 3c    !.<
    res 0,(hl)                                                        ; 3438: cb 86       ..
    res 1,(hl)                                                        ; 343a: cb 8e       ..
    ld e,8                                                            ; 343c: 1e 08       ..
; $343e referenced 2 times by $3428, $342f
shut1:
    call find1_cpm                                                    ; 343e: cd 89 36    ..6
    ret z                                                             ; 3441: c8          .
    xor a                                                             ; 3442: af          .
    ld (hl),a                                                         ; 3443: 77          w
    dec hl                                                            ; 3444: 2b          +
    ld (hl),a                                                         ; 3445: 77          w
    ld hl,$25                                                         ; 3446: 21 25 00    !%.
    add hl,de                                                         ; 3449: 19          .
    bit 7,(hl)                                                        ; 344a: cb 7e       .~
    inc hl                                                            ; 344c: 23          #
    call nz,write                                                     ; 344d: c4 0e 36    ..6
    ld hl,$a6                                                         ; 3450: 21 a6 00    !..
    add hl,de                                                         ; 3453: 19          .
    ld bc,(free)                                                      ; 3454: ed 4b e2... .K.
    sbc hl,bc                                                         ; 3458: ed 42       .B
    jr nz,close_cpm                                                   ; 345a: 20 b2        .
    ld (free),de                                                      ; 345c: ed 53 e2... .S.
    jr close_cpm                                                      ; 3460: 18 ac       ..

type_cpm:
    scf                                                               ; 3462: 37          7
    call osopen                                                       ; 3463: cd c8 34    ..4
    or a                                                              ; 3466: b7          .
    jr z,notfnd                                                       ; 3467: 28 28       ((
    ld e,a                                                            ; 3469: 5f          _
; $346a referenced 1 time by $3477
type1:
    ld a,(flags)                                                      ; 346a: 3a 13 3c    :.<
    bit 7,a                                                           ; 346d: cb 7f       ..
    jr nz,typesc                                                      ; 346f: 20 0a        .
    call osbget                                                       ; 3471: cd 34 35    .45
    call oswrch                                                       ; 3474: cd 5c 3a    .\:
    jr nc,type1                                                       ; 3477: 30 f1       0.
    jr osshut                                                         ; 3479: 18 ab       ..

; $347b referenced 1 time by $346f
typesc:
    call osshut                                                       ; 347b: cd 26 34    .&4
    jp abort                                                          ; 347e: c3 d2 39    ..9

stload:
    call savlod                                                       ; 3481: cd 33 38    .38
    push hl                                                           ; 3484: e5          .
    jr osl1                                                           ; 3485: 18 04       ..

; $3487 referenced 1 time by $08bc
osload:
    push bc                                                           ; 3487: c5          .
    call setup0                                                       ; 3488: cd 9a 36    ..6
; $348b referenced 1 time by $3485
osl1:
    ex de,hl                                                          ; 348b: eb          .
    call open                                                         ; 348c: cd 32 36    .26
    jr nz,load0_cpm                                                   ; 348f: 20 1d        .
; $3491 referenced 1 time by $3467
notfnd:
    ld a,$d6                                                          ; 3491: 3e d6       >.
    call exterr                                                       ; 3493: cd 1a 08    ...
    db "File not found", 0                                            ; 3496: 46 69 6c... Fil

; $34a5 referenced 1 time by $34b2
load_cpm:
    call read_cpm                                                     ; 34a5: cd dd 35    ..5
    jr nz,load1_cpm                                                   ; 34a8: 20 0a        .
    call incsec                                                       ; 34aa: cd 27 36    .'6
    add hl,bc                                                         ; 34ad: 09          .
; $34ae referenced 1 time by $348f
load0_cpm:
    ex (sp),hl                                                        ; 34ae: e3          .
    sbc hl,bc                                                         ; 34af: ed 42       .B
    ex (sp),hl                                                        ; 34b1: e3          .
    jr nc,load_cpm                                                    ; 34b2: 30 f1       0.
; $34b4 referenced 1 time by $34a8
load1_cpm:
    pop bc                                                            ; 34b4: c1          .
    push af                                                           ; 34b5: f5          .
    call close_cpm                                                    ; 34b6: cd 0e 34    ..4
    pop af                                                            ; 34b9: f1          .
    ccf                                                               ; 34ba: 3f          ?
; $34bb referenced 1 time by $163a
oscall:
    ret                                                               ; 34bb: c9          .

; $34bc referenced 2 times by $34c8, $38e9
openit:
    push af                                                           ; 34bc: f5          .
    call setup0                                                       ; 34bd: cd 9a 36    ..6
    pop af                                                            ; 34c0: f1          .
    call nc,create_cpm                                                ; 34c1: d4 3c 36    .<6
    call c,open                                                       ; 34c4: dc 32 36    .26
    ret                                                               ; 34c7: c9          .

; $34c8 referenced 2 times by $21b8, $3463
osopen:
    call openit                                                       ; 34c8: cd bc 34    ..4
    ret z                                                             ; 34cb: c8          .
    ld b,7                                                            ; 34cc: 06 07       ..
    ld hl,$3c12                                                       ; 34ce: 21 12 3c    !.<
; $34d1 referenced 1 time by $34d7
open1:
    ld a,(hl)                                                         ; 34d1: 7e          ~
    dec hl                                                            ; 34d2: 2b          +
    or (hl)                                                           ; 34d3: b6          .
    jr z,open2                                                        ; 34d4: 28 1c       (.
    dec hl                                                            ; 34d6: 2b          +
    djnz open1                                                        ; 34d7: 10 f8       ..
    ld a,$c0                                                          ; 34d9: 3e c0       >.
    call exterr                                                       ; 34db: cd 1a 08    ...
    db "Too many open files", 0                                       ; 34de: 54 6f 6f... Too

; $34f2 referenced 1 time by $34d4
open2:
    ld de,(free)                                                      ; 34f2: ed 5b e2... .[.
    ld (hl),e                                                         ; 34f6: 73          s
    inc hl                                                            ; 34f7: 23          #
    ld (hl),d                                                         ; 34f8: 72          r
    ld a,b                                                            ; 34f9: 78          x
    ld hl,$a6                                                         ; 34fa: 21 a6 00    !..
    add hl,de                                                         ; 34fd: 19          .
    ld (free),hl                                                      ; 34fe: 22 e2 3f    ".?
; $3501 referenced 1 time by $3904
open3:
    ld hl,$5c                                                         ; 3501: 21 5c 00    !\.
    push de                                                           ; 3504: d5          .
    ld bc,$24                                                         ; 3505: 01 24 00    .$.
    ldir                                                              ; 3508: ed b0       ..
    ex de,hl                                                          ; 350a: eb          .
    inc hl                                                            ; 350b: 23          #
    ld (hl),c                                                         ; 350c: 71          q
    inc hl                                                            ; 350d: 23          #
    pop de                                                            ; 350e: d1          .
    ld b,a                                                            ; 350f: 47          G
    call rdf                                                          ; 3510: cd bd 35    ..5
    ld a,b                                                            ; 3513: 78          x
    jp check                                                          ; 3514: c3 e9 16    ...

; $3517 referenced 10 times by $0121, $1003, $1009, $100d, $1011, $1016, $1027, $102f, $15f1, $3aa7
osbput:
    push de                                                           ; 3517: d5          .
    push hl                                                           ; 3518: e5          .
    ld b,a                                                            ; 3519: 47          G
    call find_cpm                                                     ; 351a: cd 74 36    .t6
    ld a,b                                                            ; 351d: 78          x
    ld b,0                                                            ; 351e: 06 00       ..
    dec hl                                                            ; 3520: 2b          +
    ld (hl),b                                                         ; 3521: 70          p
    inc hl                                                            ; 3522: 23          #
    ld c,(hl)                                                         ; 3523: 4e          N
    res 7,c                                                           ; 3524: cb b9       ..
    set 7,(hl)                                                        ; 3526: cb fe       ..
    inc (hl)                                                          ; 3528: 34          4
    inc hl                                                            ; 3529: 23          #
    push hl                                                           ; 352a: e5          .
    add hl,bc                                                         ; 352b: 09          .
    ld (hl),a                                                         ; 352c: 77          w
    pop hl                                                            ; 352d: e1          .
    call z,wrrdf                                                      ; 352e: cc ba 35    ..5
    pop hl                                                            ; 3531: e1          .
    pop de                                                            ; 3532: d1          .
    ret                                                               ; 3533: c9          .

; $3534 referenced 10 times by $011e, $1377, $137d, $1383, $1387, $138b, $139c, $213d, $3471, $3a10
osbget:
    push de                                                           ; 3534: d5          .
    push hl                                                           ; 3535: e5          .
    call find_cpm                                                     ; 3536: cd 74 36    .t6
    ld c,(hl)                                                         ; 3539: 4e          N
    res 7,c                                                           ; 353a: cb b9       ..
    inc (hl)                                                          ; 353c: 34          4
    inc hl                                                            ; 353d: 23          #
    push hl                                                           ; 353e: e5          .
    ld b,0                                                            ; 353f: 06 00       ..
    add hl,bc                                                         ; 3541: 09          .
    ld b,(hl)                                                         ; 3542: 46          F
    pop hl                                                            ; 3543: e1          .
    call pe,incrdf                                                    ; 3544: ec d5 35    ..5
    call z,wrrdf                                                      ; 3547: cc ba 35    ..5
    ld a,b                                                            ; 354a: 78          x
    pop hl                                                            ; 354b: e1          .
    pop de                                                            ; 354c: d1          .
    ret                                                               ; 354d: c9          .

; $354e referenced 2 times by $0124, $2131
osstat:
    call find_cpm                                                     ; 354e: cd 74 36    .t6
    dec hl                                                            ; 3551: 2b          +
    ld a,(hl)                                                         ; 3552: 7e          ~
    inc a                                                             ; 3553: 3c          <
    ret                                                               ; 3554: c9          .

; $3555 referenced 1 time by $21c1
getext:
    call find_cpm                                                     ; 3555: cd 74 36    .t6
    ex de,hl                                                          ; 3558: eb          .
    ld de,$5c                                                         ; 3559: 11 5c 00    .\.
    ld bc,$24                                                         ; 355c: 01 24 00    .$.
    push de                                                           ; 355f: d5          .
    ldir                                                              ; 3560: ed b0       ..
    ex de,hl                                                          ; 3562: eb          .
    ex (sp),hl                                                        ; 3563: e3          .
    ex de,hl                                                          ; 3564: eb          .
    ld a,$23                                                          ; 3565: 3e 23       >#
    call bdos1                                                        ; 3567: cd e2 35    ..5
    pop hl                                                            ; 356a: e1          .
    xor a                                                             ; 356b: af          .
    jr getpt1                                                         ; 356c: 18 06       ..

; $356e referenced 1 time by $21c9
getptr:
    call find_cpm                                                     ; 356e: cd 74 36    .t6
    ld a,(hl)                                                         ; 3571: 7e          ~
    add a,a                                                           ; 3572: 87          .
    dec hl                                                            ; 3573: 2b          +
; $3574 referenced 1 time by $356c
getpt1:
    dec hl                                                            ; 3574: 2b          +
    ld d,(hl)                                                         ; 3575: 56          V
    dec hl                                                            ; 3576: 2b          +
    ld e,(hl)                                                         ; 3577: 5e          ^
    dec hl                                                            ; 3578: 2b          +
    ld h,(hl)                                                         ; 3579: 66          f
    ld l,a                                                            ; 357a: 6f          o
    srl d                                                             ; 357b: cb 3a       .:
    rr e                                                              ; 357d: cb 1b       ..
    rr h                                                              ; 357f: cb 1c       ..
    rr l                                                              ; 3581: cb 1d       ..
    ret                                                               ; 3583: c9          .

; $3584 referenced 1 time by $1527
putptr:
    ld d,l                                                            ; 3584: 55          U
    add hl,hl                                                         ; 3585: 29          )
    rl e                                                              ; 3586: cb 13       ..
    ld b,e                                                            ; 3588: 43          C
    ld c,h                                                            ; 3589: 4c          L
    ld e,a                                                            ; 358a: 5f          _
    push de                                                           ; 358b: d5          .
    call find_cpm                                                     ; 358c: cd 74 36    .t6
    pop af                                                            ; 358f: f1          .
    and $7f                                                           ; 3590: e6 7f       ..
    bit 7,(hl)                                                        ; 3592: cb 7e       .~
    jr z,putpt1                                                       ; 3594: 28 02       (.
    or $80                                                            ; 3596: f6 80       ..
; $3598 referenced 1 time by $3594
putpt1:
    ld (hl),a                                                         ; 3598: 77          w
    push de                                                           ; 3599: d5          .
    push hl                                                           ; 359a: e5          .
    dec hl                                                            ; 359b: 2b          +
    dec hl                                                            ; 359c: 2b          +
    dec hl                                                            ; 359d: 2b          +
    ld d,(hl)                                                         ; 359e: 56          V
    dec hl                                                            ; 359f: 2b          +
    ld e,(hl)                                                         ; 35a0: 5e          ^
    ex de,hl                                                          ; 35a1: eb          .
    or a                                                              ; 35a2: b7          .
    sbc hl,bc                                                         ; 35a3: ed 42       .B
    pop hl                                                            ; 35a5: e1          .
    pop de                                                            ; 35a6: d1          .
    ret z                                                             ; 35a7: c8          .
    inc hl                                                            ; 35a8: 23          #
    or a                                                              ; 35a9: b7          .
    call m,write                                                      ; 35aa: fc 0e 36    ..6
    push hl                                                           ; 35ad: e5          .
    dec hl                                                            ; 35ae: 2b          +
    dec hl                                                            ; 35af: 2b          +
    dec hl                                                            ; 35b0: 2b          +
    ld (hl),0                                                         ; 35b1: 36 00       6.
    dec hl                                                            ; 35b3: 2b          +
    ld (hl),b                                                         ; 35b4: 70          p
    dec hl                                                            ; 35b5: 2b          +
    ld (hl),c                                                         ; 35b6: 71          q
    pop hl                                                            ; 35b7: e1          .
    jr rdf                                                            ; 35b8: 18 03       ..

; $35ba referenced 2 times by $352e, $3547
wrrdf:
    call write                                                        ; 35ba: cd 0e 36    ..6
; $35bd referenced 3 times by $3510, $35b8, $35d8
rdf:
    call read_cpm                                                     ; 35bd: cd dd 35    ..5
    dec hl                                                            ; 35c0: 2b          +
    res 7,(hl)                                                        ; 35c1: cb be       ..
    dec hl                                                            ; 35c3: 2b          +
    ld (hl),a                                                         ; 35c4: 77          w
    ret z                                                             ; 35c5: c8          .
    ld (hl),$ff                                                       ; 35c6: 36 ff       6.
    inc hl                                                            ; 35c8: 23          #
    inc hl                                                            ; 35c9: 23          #
    push bc                                                           ; 35ca: c5          .
    xor a                                                             ; 35cb: af          .
    ld b,$80                                                          ; 35cc: 06 80       ..
; $35ce referenced 1 time by $35d0
fill_cpm:
    ld (hl),a                                                         ; 35ce: 77          w
    inc hl                                                            ; 35cf: 23          #
    djnz fill_cpm                                                     ; 35d0: 10 fc       ..
    pop bc                                                            ; 35d2: c1          .
    scf                                                               ; 35d3: 37          7
    ret                                                               ; 35d4: c9          .

; $35d5 referenced 1 time by $3544
incrdf:
    call incsec                                                       ; 35d5: cd 27 36    .'6
    call rdf                                                          ; 35d8: cd bd 35    ..5
    inc a                                                             ; 35db: 3c          <
    ret                                                               ; 35dc: c9          .

; $35dd referenced 2 times by $34a5, $35bd
read_cpm:
    call setdma                                                       ; 35dd: cd 6c 36    .l6
    ld a,$21                                                          ; 35e0: 3e 21       >!
; $35e2 referenced 9 times by $3410, $3567, $3613, $3637, $3644, $3649, $37fd, $381d, $386c
bdos1:
    call bdos0                                                        ; 35e2: cd f9 35    ..5
    jr nz,cpmerr                                                      ; 35e5: 20 02        .
    or a                                                              ; 35e7: b7          .
    ret                                                               ; 35e8: c9          .

; $35e9 referenced 1 time by $35e5
cpmerr:
    ld a,$ff                                                          ; 35e9: 3e ff       >.
    call exterr                                                       ; 35eb: cd 1a 08    ...
    db "CP/M Error", 0                                                ; 35ee: 43 50 2f... CP/

; $35f9 referenced 5 times by $35e2, $366f, $39e1, $3a91, $3a9b
bdos0:
    push bc                                                           ; 35f9: c5          .
    push de                                                           ; 35fa: d5          .
    push hl                                                           ; 35fb: e5          .
    push ix                                                           ; 35fc: dd e5       ..
    push iy                                                           ; 35fe: fd e5       ..
    ld c,a                                                            ; 3600: 4f          O
    call bdos                                                         ; 3601: cd 05 00    ...
    inc h                                                             ; 3604: 24          $
    dec h                                                             ; 3605: 25          %
    pop iy                                                            ; 3606: fd e1       ..
    pop ix                                                            ; 3608: dd e1       ..
    pop hl                                                            ; 360a: e1          .
    pop de                                                            ; 360b: d1          .
    pop bc                                                            ; 360c: c1          .
    ret                                                               ; 360d: c9          .

; $360e referenced 4 times by $3401, $344d, $35aa, $35ba
write:
    call setdma                                                       ; 360e: cd 6c 36    .l6
    ld a,$28                                                          ; 3611: 3e 28       >(
    call bdos1                                                        ; 3613: cd e2 35    ..5
    jr z,incsec                                                       ; 3616: 28 0f       (.
    ld a,$c6                                                          ; 3618: 3e c6       >.
    call exterr                                                       ; 361a: cd 1a 08    ...
    db "Disk full", 0                                                 ; 361d: 44 69 73... Dis

; $3627 referenced 3 times by $34aa, $35d5, $3616
incsec:
    push hl                                                           ; 3627: e5          .
    ld hl,$21                                                         ; 3628: 21 21 00    !!.
    add hl,de                                                         ; 362b: 19          .
; $362c referenced 1 time by $362e
incs1:
    inc (hl)                                                          ; 362c: 34          4
    inc hl                                                            ; 362d: 23          #
    jr z,incs1                                                        ; 362e: 28 fc       (.
    pop hl                                                            ; 3630: e1          .
    ret                                                               ; 3631: c9          .

; $3632 referenced 2 times by $348c, $34c4
open:
    ld de,$5c                                                         ; 3632: 11 5c 00    .\.
    ld a,$0f                                                          ; 3635: 3e 0f       >.
    call bdos1                                                        ; 3637: cd e2 35    ..5
    inc a                                                             ; 363a: 3c          <
    ret                                                               ; 363b: c9          .

; $363c referenced 2 times by $33e8, $34c1
create_cpm:
    call chkamb                                                       ; 363c: cd 4e 36    .N6
    ld de,$5c                                                         ; 363f: 11 5c 00    .\.
    ld a,$13                                                          ; 3642: 3e 13       >.
    call bdos1                                                        ; 3644: cd e2 35    ..5
    ld a,$16                                                          ; 3647: 3e 16       >.
    call bdos1                                                        ; 3649: cd e2 35    ..5
    inc a                                                             ; 364c: 3c          <
    ret                                                               ; 364d: c9          .

; $364e referenced 2 times by $363c, $37ef
chkamb:
    push bc                                                           ; 364e: c5          .
    ld de,$5c                                                         ; 364f: 11 5c 00    .\.
    ld b,$0c                                                          ; 3652: 06 0c       ..
; $3654 referenced 1 time by $365a
chkam1:
    ld a,(de)                                                         ; 3654: 1a          .
    cp $3f                                                            ; 3655: fe 3f       .?
    jr z,ambig                                                        ; 3657: 28 05       (.
    inc de                                                            ; 3659: 13          .
    djnz chkam1                                                       ; 365a: 10 f8       ..
    pop bc                                                            ; 365c: c1          .
    ret                                                               ; 365d: c9          .

; $365e referenced 1 time by $3657
ambig:
    ld a,$cc                                                          ; 365e: 3e cc       >.
    call exterr                                                       ; 3660: cd 1a 08    ...
    db "Bad name", 0                                                  ; 3663: 42 61 64... Bad

; $366c referenced 4 times by $35dd, $360e, $3815, $3868
setdma:
    ld a,$1a                                                          ; 366c: 3e 1a       >.
    ex de,hl                                                          ; 366e: eb          .
    call bdos0                                                        ; 366f: cd f9 35    ..5
    ex de,hl                                                          ; 3672: eb          .
    ret                                                               ; 3673: c9          .

; $3674 referenced 6 times by $351a, $3536, $354e, $3555, $356e, $358c
find_cpm:
    call find1_cpm                                                    ; 3674: cd 89 36    ..6
    ld hl,$25                                                         ; 3677: 21 25 00    !%.
    add hl,de                                                         ; 367a: 19          .
    ret nz                                                            ; 367b: c0          .
    ld a,$de                                                          ; 367c: 3e de       >.
    call exterr                                                       ; 367e: cd 1a 08    ...
    db "Channel", 0                                                   ; 3681: 43 68 61... Cha

; $3689 referenced 2 times by $343e, $3674
find1_cpm:
    ld a,e                                                            ; 3689: 7b          {
    and 7                                                             ; 368a: e6 07       ..
    add a,a                                                           ; 368c: 87          .
    ld e,a                                                            ; 368d: 5f          _
    ld d,0                                                            ; 368e: 16 00       ..
    ld hl,$3c03                                                       ; 3690: 21 03 3c    !.<
    add hl,de                                                         ; 3693: 19          .
    ld e,(hl)                                                         ; 3694: 5e          ^
    inc hl                                                            ; 3695: 23          #
    ld d,(hl)                                                         ; 3696: 56          V
    ld a,d                                                            ; 3697: 7a          z
    or e                                                              ; 3698: b3          .
    ret                                                               ; 3699: c9          .

; $369a referenced 8 times by $33e4, $3488, $34bd, $37ba, $37c5, $37d4, $37ec, $3833
setup0:
    ld a,$20                                                          ; 369a: 3e 20       >
; $369c referenced 1 time by $3854
setup:
    push de                                                           ; 369c: d5          .
    push hl                                                           ; 369d: e5          .
    ld de,$65                                                         ; 369e: 11 65 00    .e.
    ld hl,$3745                                                       ; 36a1: 21 45 37    !E7
    ld bc,3                                                           ; 36a4: 01 03 00    ...
    ldir                                                              ; 36a7: ed b0       ..
    ld hl,$7c                                                         ; 36a9: 21 7c 00    !|.
    ld b,4                                                            ; 36ac: 06 04       ..
; $36ae referenced 1 time by $36b0
setup1:
    ld (hl),c                                                         ; 36ae: 71          q
    inc hl                                                            ; 36af: 23          #
    djnz setup1                                                       ; 36b0: 10 fc       ..
    pop hl                                                            ; 36b2: e1          .
    ld c,a                                                            ; 36b3: 4f          O
    xor a                                                             ; 36b4: af          .
    ld (de),a                                                         ; 36b5: 12          .
    pop de                                                            ; 36b6: d1          .
    call skipsp                                                       ; 36b7: cd 3e 37    .>7
    cp $22                                                            ; 36ba: fe 22       ."
    jr nz,setup2                                                      ; 36bc: 20 27        '
    inc hl                                                            ; 36be: 23          #
    call skipsp                                                       ; 36bf: cd 3e 37    .>7
    call setup2                                                       ; 36c2: cd e5 36    ..6
    cp $22                                                            ; 36c5: fe 22       ."
    inc hl                                                            ; 36c7: 23          #
    jr z,skipsp                                                       ; 36c8: 28 74       (t
badstr:
    ld a,$fd                                                          ; 36ca: 3e fd       >.
    call exterr                                                       ; 36cc: cd 1a 08    ...
    db "Bad string", 0                                                ; 36cf: 42 61 64... Bad

; $36da referenced 1 time by $371c
parse:
    ld a,(hl)                                                         ; 36da: 7e          ~
    inc hl                                                            ; 36db: 23          #
    cp $60                                                            ; 36dc: fe 60       .`
    ret nc                                                            ; 36de: d0          .
    cp $3f                                                            ; 36df: fe 3f       .?
    ret c                                                             ; 36e1: d8          .
    xor $40                                                           ; 36e2: ee 40       .@
    ret                                                               ; 36e4: c9          .

; $36e5 referenced 2 times by $36bc, $36c2
setup2:
    push de                                                           ; 36e5: d5          .
    inc hl                                                            ; 36e6: 23          #
    ld a,(hl)                                                         ; 36e7: 7e          ~
    cp $3a                                                            ; 36e8: fe 3a       .:
    dec hl                                                            ; 36ea: 2b          +
    ld a,b                                                            ; 36eb: 78          x
    jr nz,device                                                      ; 36ec: 20 05        .
    ld a,(hl)                                                         ; 36ee: 7e          ~
    and $1f                                                           ; 36ef: e6 1f       ..
    inc hl                                                            ; 36f1: 23          #
    inc hl                                                            ; 36f2: 23          #
; $36f3 referenced 1 time by $36ec
device:
    ld de,$5c                                                         ; 36f3: 11 5c 00    .\.
    ld (de),a                                                         ; 36f6: 12          .
    inc de                                                            ; 36f7: 13          .
    ld b,8                                                            ; 36f8: 06 08       ..
; $36fa referenced 2 times by $3727, $3737
copyf:
    ld a,(hl)                                                         ; 36fa: 7e          ~
    cp $2e                                                            ; 36fb: fe 2e       ..
    jr z,copyf1                                                       ; 36fd: 28 22       ("
    cp $20                                                            ; 36ff: fe 20       .
    jr z,copyf1                                                       ; 3701: 28 1e       (.
    cp $0d                                                            ; 3703: fe 0d       ..
    jr z,copyf1                                                       ; 3705: 28 1a       (.
    cp $3d                                                            ; 3707: fe 3d       .=
    jr z,copyf1                                                       ; 3709: 28 16       (.
    cp $22                                                            ; 370b: fe 22       ."
    jr z,copyf1                                                       ; 370d: 28 12       (.
    ld c,$3f                                                          ; 370f: 0e 3f       .?
    cp $2a                                                            ; 3711: fe 2a       .*
    jr z,copyf1                                                       ; 3713: 28 0c       (.
    ld c,$20                                                          ; 3715: 0e 20       .
    inc hl                                                            ; 3717: 23          #
    cp $7c                                                            ; 3718: fe 7c       .|
    jr nz,copyf2                                                      ; 371a: 20 06        .
    call parse                                                        ; 371c: cd da 36    ..6
    jr copyf0                                                         ; 371f: 18 04       ..

; $3721 referenced 6 times by $36fd, $3701, $3705, $3709, $370d, $3713
copyf1:
    ld a,c                                                            ; 3721: 79          y
; $3722 referenced 1 time by $371a
copyf2:
    call upprc                                                        ; 3722: cd 09 39    ..9
; $3725 referenced 1 time by $371f
copyf0:
    ld (de),a                                                         ; 3725: 12          .
    inc de                                                            ; 3726: 13          .
    djnz copyf                                                        ; 3727: 10 d1       ..
; $3729 referenced 1 time by $372d
copyf3:
    ld a,(hl)                                                         ; 3729: 7e          ~
    inc hl                                                            ; 372a: 23          #
    cp $2a                                                            ; 372b: fe 2a       .*
    jr z,copyf3                                                       ; 372d: 28 fa       (.
    cp $2e                                                            ; 372f: fe 2e       ..
    ld bc,$0320                                                       ; 3731: 01 20 03    . .
    ld de,$65                                                         ; 3734: 11 65 00    .e.
    jr z,copyf                                                        ; 3737: 28 c1       (.
    dec hl                                                            ; 3739: 2b          +
    pop de                                                            ; 373a: d1          .
    ld bc,$80                                                         ; 373b: 01 80 00    ...
; $373e referenced 10 times by $36b7, $36bf, $36c8, $3743, $374b, $3754, $375c, $3760, $3771, $37b7
skipsp:
    ld a,(hl)                                                         ; 373e: 7e          ~
    cp $20                                                            ; 373f: fe 20       .
    ret nz                                                            ; 3741: c0          .
    inc hl                                                            ; 3742: 23          #
    jr skipsp                                                         ; 3743: 18 f9       ..

bbc:
    db "BBC"                                                          ; 3745: 42 42 43    BBC

; $3748 referenced 4 times by $3836, $3840, $38c4, $391a
hex_cpm:
    ld de,0                                                           ; 3748: 11 00 00    ...
    call skipsp                                                       ; 374b: cd 3e 37    .>7
; $374e referenced 1 time by $376f
hex1_cpm:
    ld a,(hl)                                                         ; 374e: 7e          ~
    call upprc                                                        ; 374f: cd 09 39    ..9
    cp $30                                                            ; 3752: fe 30       .0
    jr c,skipsp                                                       ; 3754: 38 e8       8.
    cp $3a                                                            ; 3756: fe 3a       .:
    jr c,hex2_cpm                                                     ; 3758: 38 0a       8.
    cp $41                                                            ; 375a: fe 41       .A
    jr c,skipsp                                                       ; 375c: 38 e0       8.
    cp $47                                                            ; 375e: fe 47       .G
    jr nc,skipsp                                                      ; 3760: 30 dc       0.
    sub 7                                                             ; 3762: d6 07       ..
; $3764 referenced 1 time by $3758
hex2_cpm:
    and $0f                                                           ; 3764: e6 0f       ..
    ex de,hl                                                          ; 3766: eb          .
    add hl,hl                                                         ; 3767: 29          )
    add hl,hl                                                         ; 3768: 29          )
    add hl,hl                                                         ; 3769: 29          )
    add hl,hl                                                         ; 376a: 29          )
    ex de,hl                                                          ; 376b: eb          .
    or e                                                              ; 376c: b3          .
    ld e,a                                                            ; 376d: 5f          _
    inc hl                                                            ; 376e: 23          #
    jr hex1_cpm                                                       ; 376f: 18 dd       ..

; $3771 referenced 3 times by $011b, $0e80, $0e88
oscli:
    call skipsp                                                       ; 3771: cd 3e 37    .>7
    cp $0d                                                            ; 3774: fe 0d       ..
    ret z                                                             ; 3776: c8          .
    cp $7c                                                            ; 3777: fe 7c       .|
    ret z                                                             ; 3779: c8          .
    cp $2e                                                            ; 377a: fe 2e       ..
    jp z,dot                                                          ; 377c: ca 51 38    .Q8
    ex de,hl                                                          ; 377f: eb          .
    ld hl,$3928                                                       ; 3780: 21 28 39    !(9
; $3783 referenced 1 time by $3793
oscli0:
    ld a,(de)                                                         ; 3783: 1a          .
    call upprc                                                        ; 3784: cd 09 39    ..9
    cp (hl)                                                           ; 3787: be          .
    jr z,oscli2                                                       ; 3788: 28 0b       (.
    jr c,huh                                                          ; 378a: 38 75       8u
; $378c referenced 2 times by $378f, $37a8
oscli1:
    bit 7,(hl)                                                        ; 378c: cb 7e       .~
    inc hl                                                            ; 378e: 23          #
    jr z,oscli1                                                       ; 378f: 28 fb       (.
    inc hl                                                            ; 3791: 23          #
    inc hl                                                            ; 3792: 23          #
    jr oscli0                                                         ; 3793: 18 ee       ..

; $3795 referenced 1 time by $3788
oscli2:
    push de                                                           ; 3795: d5          .
; $3796 referenced 1 time by $37a1
oscli3:
    inc de                                                            ; 3796: 13          .
    inc hl                                                            ; 3797: 23          #
    ld a,(de)                                                         ; 3798: 1a          .
    call upprc                                                        ; 3799: cd 09 39    ..9
    cp $2e                                                            ; 379c: fe 2e       ..
    jr z,oscli4                                                       ; 379e: 28 0a       (.
    xor (hl)                                                          ; 37a0: ae          .
    jr z,oscli3                                                       ; 37a1: 28 f3       (.
    cp $80                                                            ; 37a3: fe 80       ..
    jr z,oscli4                                                       ; 37a5: 28 03       (.
    pop de                                                            ; 37a7: d1          .
    jr oscli1                                                         ; 37a8: 18 e2       ..

; $37aa referenced 2 times by $379e, $37a5
oscli4:
    pop af                                                            ; 37aa: f1          .
    inc de                                                            ; 37ab: 13          .
; $37ac referenced 1 time by $37af
oscli5:
    bit 7,(hl)                                                        ; 37ac: cb 7e       .~
    inc hl                                                            ; 37ae: 23          #
    jr z,oscli5                                                       ; 37af: 28 fb       (.
    ld a,(hl)                                                         ; 37b1: 7e          ~
    inc hl                                                            ; 37b2: 23          #
    ld h,(hl)                                                         ; 37b3: 66          f
    ld l,a                                                            ; 37b4: 6f          o
    push hl                                                           ; 37b5: e5          .
    ex de,hl                                                          ; 37b6: eb          .
    jp skipsp                                                         ; 37b7: c3 3e 37    .>7

era:
    call setup0                                                       ; 37ba: cd 9a 36    ..6
    ld c,$13                                                          ; 37bd: 0e 13       ..
    jr xeq_cpm                                                        ; 37bf: 18 33       .3

res:
    ld c,$0d                                                          ; 37c1: 0e 0d       ..
    jr xeq_cpm                                                        ; 37c3: 18 2f       ./

drv:
    call setup0                                                       ; 37c5: cd 9a 36    ..6
    ld a,(l005c)                                                      ; 37c8: 3a 5c 00    :\.
    dec a                                                             ; 37cb: 3d          =
    jp m,huh                                                          ; 37cc: fa 01 38    ..8
    ld e,a                                                            ; 37cf: 5f          _
    ld c,$0e                                                          ; 37d0: 0e 0e       ..
    jr xeq0_cpm                                                       ; 37d2: 18 23       .#

ren:
    call setup0                                                       ; 37d4: cd 9a 36    ..6
    cp $3d                                                            ; 37d7: fe 3d       .=
    jr nz,huh                                                         ; 37d9: 20 26        &
    inc hl                                                            ; 37db: 23          #
    push hl                                                           ; 37dc: e5          .
    call exists                                                       ; 37dd: cd 12 38    ..8
    ld hl,$5c                                                         ; 37e0: 21 5c 00    !\.
    ld de,$6c                                                         ; 37e3: 11 6c 00    .l.
    ld bc,$0c                                                         ; 37e6: 01 0c 00    ...
    ldir                                                              ; 37e9: ed b0       ..
    pop hl                                                            ; 37eb: e1          .
    call setup0                                                       ; 37ec: cd 9a 36    ..6
    call chkamb                                                       ; 37ef: cd 4e 36    .N6
    ld c,$17                                                          ; 37f2: 0e 17       ..
; $37f4 referenced 2 times by $37bf, $37c3
xeq_cpm:
    ld de,$5c                                                         ; 37f4: 11 5c 00    .\.
; $37f7 referenced 1 time by $37d2
xeq0_cpm:
    ld a,(hl)                                                         ; 37f7: 7e          ~
    cp $0d                                                            ; 37f8: fe 0d       ..
    jr nz,huh                                                         ; 37fa: 20 05        .
; $37fc referenced 1 time by $3893
bdc:
    ld a,c                                                            ; 37fc: 79          y
    call bdos1                                                        ; 37fd: cd e2 35    ..5
    ret p                                                             ; 3800: f0          .
; $3801 referenced 8 times by $33dd, $378a, $37cc, $37d9, $37fa, $3845, $384f, $3859
huh:
    ld a,$fe                                                          ; 3801: 3e fe       >.
    call exterr                                                       ; 3803: cd 1a 08    ...
    db "Bad command", 0                                               ; 3806: 42 61 64... Bad

; $3812 referenced 1 time by $37dd
exists:
    ld hl,$80                                                         ; 3812: 21 80 00    !..
    call setdma                                                       ; 3815: cd 6c 36    .l6
    ld de,$5c                                                         ; 3818: 11 5c 00    .\.
    ld a,$11                                                          ; 381b: 3e 11       >.
    call bdos1                                                        ; 381d: cd e2 35    ..5
    inc a                                                             ; 3820: 3c          <
    ret z                                                             ; 3821: c8          .
    ld a,$c4                                                          ; 3822: 3e c4       >.
    call exterr                                                       ; 3824: cd 1a 08    ...
    db "File exists", 0                                               ; 3827: 46 69 6c... Fil

; $3833 referenced 2 times by $33da, $3481
savlod:
    call setup0                                                       ; 3833: cd 9a 36    ..6
    call hex_cpm                                                      ; 3836: cd 48 37    .H7
    cp $2b                                                            ; 3839: fe 2b       .+
    push af                                                           ; 383b: f5          .
    push de                                                           ; 383c: d5          .
    jr nz,savlo1_cpm                                                  ; 383d: 20 01        .
    inc hl                                                            ; 383f: 23          #
; $3840 referenced 1 time by $383d
savlo1_cpm:
    call hex_cpm                                                      ; 3840: cd 48 37    .H7
    cp $0d                                                            ; 3843: fe 0d       ..
    jr nz,huh                                                         ; 3845: 20 ba        .
    ex de,hl                                                          ; 3847: eb          .
    pop de                                                            ; 3848: d1          .
    pop af                                                            ; 3849: f1          .
    ret z                                                             ; 384a: c8          .
    or a                                                              ; 384b: b7          .
    sbc hl,de                                                         ; 384c: ed 52       .R
    ret nz                                                            ; 384e: c0          .
    jr huh                                                            ; 384f: 18 b0       ..

; $3851 referenced 1 time by $377c
dot:
    inc hl                                                            ; 3851: 23          #
dir:
    ld a,$3f                                                          ; 3852: 3e 3f       >?
    call setup                                                        ; 3854: cd 9c 36    ..6
    cp $0d                                                            ; 3857: fe 0d       ..
    jr nz,huh                                                         ; 3859: 20 a6        .
    ld c,$11                                                          ; 385b: 0e 11       ..
; $385d referenced 1 time by $38b5
dir0:
    ld b,4                                                            ; 385d: 06 04       ..
; $385f referenced 2 times by $388a, $38c2
dir1:
    call ltrap                                                        ; 385f: cd cd 39    ..9
    ld de,$5c                                                         ; 3862: 11 5c 00    .\.
    ld hl,$80                                                         ; 3865: 21 80 00    !..
    call setdma                                                       ; 3868: cd 6c 36    .l6
    ld a,c                                                            ; 386b: 79          y
    call bdos1                                                        ; 386c: cd e2 35    ..5
    jp m,crlf                                                         ; 386f: fa 97 09    ...
    rrca                                                              ; 3872: 0f          .
    rrca                                                              ; 3873: 0f          .
    rrca                                                              ; 3874: 0f          .
    and $60                                                           ; 3875: e6 60       .`
    ld e,a                                                            ; 3877: 5f          _
    ld d,0                                                            ; 3878: 16 00       ..
    ld hl,$81                                                         ; 387a: 21 81 00    !..
    add hl,de                                                         ; 387d: 19          .
    push hl                                                           ; 387e: e5          .
    ld de,8                                                           ; 387f: 11 08 00    ...
    add hl,de                                                         ; 3882: 19          .
    ld e,(hl)                                                         ; 3883: 5e          ^
    inc hl                                                            ; 3884: 23          #
    bit 7,(hl)                                                        ; 3885: cb 7e       .~
    pop hl                                                            ; 3887: e1          .
    ld c,$12                                                          ; 3888: 0e 12       ..
    jr nz,dir1                                                        ; 388a: 20 d3        .
    push bc                                                           ; 388c: c5          .
    ld a,(l005c)                                                      ; 388d: 3a 5c 00    :\.
    dec a                                                             ; 3890: 3d          =
    ld c,$19                                                          ; 3891: 0e 19       ..
    call m,bdc                                                        ; 3893: fc fc 37    ..7
    add a,$41                                                         ; 3896: c6 41       .A
    call oswrch                                                       ; 3898: cd 5c 3a    .\:
    ld b,8                                                            ; 389b: 06 08       ..
    ld a,$20                                                          ; 389d: 3e 20       >
    bit 7,e                                                           ; 389f: cb 7b       .{
    jr z,dir3                                                         ; 38a1: 28 02       (.
    ld a,$2a                                                          ; 38a3: 3e 2a       >*
; $38a5 referenced 1 time by $38a1
dir3:
    call cptext                                                       ; 38a5: cd 88 39    ..9
    ld b,3                                                            ; 38a8: 06 03       ..
    ld a,$20                                                          ; 38aa: 3e 20       >
    call sptext                                                       ; 38ac: cd 8f 39    ..9
    pop bc                                                            ; 38af: c1          .
    djnz dir2                                                         ; 38b0: 10 05       ..
    call crlf                                                         ; 38b2: cd 97 09    ...
    jr dir0                                                           ; 38b5: 18 a6       ..

; $38b7 referenced 1 time by $38b0
dir2:
    push bc                                                           ; 38b7: c5          .
    ld b,5                                                            ; 38b8: 06 05       ..
; $38ba referenced 1 time by $38bf
pad:
    ld a,$20                                                          ; 38ba: 3e 20       >
    call oswrch                                                       ; 38bc: cd 5c 3a    .\:
    djnz pad                                                          ; 38bf: 10 f9       ..
    pop bc                                                            ; 38c1: c1          .
    jr dir1                                                           ; 38c2: 18 9b       ..

opt_cpm:
    call hex_cpm                                                      ; 38c4: cd 48 37    .H7
    ld a,e                                                            ; 38c7: 7b          {
    and 3                                                             ; 38c8: e6 03       ..
; $38ca referenced 1 time by $38cf
setopt:
    ld (optval),a                                                     ; 38ca: 32 17 3c    2.<
    ret                                                               ; 38cd: c9          .

; $38ce referenced 1 time by $0842
reset:
    xor a                                                             ; 38ce: af          .
    jr setopt                                                         ; 38cf: 18 f9       ..

exec:
    ld a,1                                                            ; 38d1: 3e 01       >.
; overlapping: ld bc,$023e                                            ; 38d3: 01 3e 02    .>.
    db 1                                                              ; 38d3: 01          .

spool:
    ld a,2                                                            ; 38d4: 3e 02       >.
    push af                                                           ; 38d6: f5          .
    push hl                                                           ; 38d7: e5          .
    call seshut                                                       ; 38d8: cd 35 34    .54
    pop hl                                                            ; 38db: e1          .
    pop bc                                                            ; 38dc: c1          .
    ld a,(hl)                                                         ; 38dd: 7e          ~
    cp $0d                                                            ; 38de: fe 0d       ..
    ret z                                                             ; 38e0: c8          .
    ld a,(flags)                                                      ; 38e1: 3a 13 3c    :.<
    or b                                                              ; 38e4: b0          .
    ld (flags),a                                                      ; 38e5: 32 13 3c    2.<
    rra                                                               ; 38e8: 1f          .
    call openit                                                       ; 38e9: cd bc 34    ..4
    ret z                                                             ; 38ec: c8          .
    pop ix                                                            ; 38ed: dd e1       ..
    ld hl,(himem)                                                     ; 38ef: 2a e4 3f    *.?
    or a                                                              ; 38f2: b7          .
    sbc hl,sp                                                         ; 38f3: ed 72       .r
    add hl,sp                                                         ; 38f5: 39          9
    jr nz,jpix                                                        ; 38f6: 20 0f        .
    ld bc,$ff5a                                                       ; 38f8: 01 5a ff    .Z.
    add hl,bc                                                         ; 38fb: 09          .
    ld (himem),hl                                                     ; 38fc: 22 e4 3f    ".?
    ld (table),hl                                                     ; 38ff: 22 03 3c    ".<
    ld sp,hl                                                          ; 3902: f9          .
    ex de,hl                                                          ; 3903: eb          .
    call open3                                                        ; 3904: cd 01 35    ..5
; $3907 referenced 1 time by $38f6
jpix:
    jp (ix)                                                           ; 3907: dd e9       ..

; $3909 referenced 5 times by $3722, $374f, $3784, $3799, $3912
upprc:
    and $7f                                                           ; 3909: e6 7f       ..
    cp $60                                                            ; 390b: fe 60       .`
    ret c                                                             ; 390d: d8          .
    and $5f                                                           ; 390e: e6 5f       ._
    ret                                                               ; 3910: c9          .

escctl:
    ld a,(hl)                                                         ; 3911: 7e          ~
    call upprc                                                        ; 3912: cd 09 39    ..9
    cp $4f                                                            ; 3915: fe 4f       .O
    jr nz,escc1                                                       ; 3917: 20 01        .
    inc hl                                                            ; 3919: 23          #
; $391a referenced 1 time by $3917
escc1:
    call hex_cpm                                                      ; 391a: cd 48 37    .H7
    ld a,e                                                            ; 391d: 7b          {
    or a                                                              ; 391e: b7          .
    ld hl,$3c13                                                       ; 391f: 21 13 3c    !.<
    res 6,(hl)                                                        ; 3922: cb b6       ..
    ret z                                                             ; 3924: c8          .
    set 6,(hl)                                                        ; 3925: cb f6       ..
    ret                                                               ; 3927: c9          .

comds:
    db "BY", $80 + 'E'                                                ; 3928: 42 59 c5    BY.
    dw bye                                                            ; 392b: c5 39       .9
    db "CP", $80 + 'M'                                                ; 392d: 43 50 cd    CP.
    dw bye                                                            ; 3930: c5 39       .9
    db "DI", $80 + 'R'                                                ; 3932: 44 49 d2    DI.
    dw dir                                                            ; 3935: 52 38       R8
    db "DRIV", $80 + 'E'                                              ; 3937: 44 52 49... DRI
    dw drv                                                            ; 393c: c5 37       .7
    db "ERAS", $80 + 'E'                                              ; 393e: 45 52 41... ERA
    dw era                                                            ; 3943: ba 37       .7
    db "ER", $80 + 'A'                                                ; 3945: 45 52 c1    ER.
    dw era                                                            ; 3948: ba 37       .7
    db "ES", $80 + 'C'                                                ; 394a: 45 53 c3    ES.
    dw escctl                                                         ; 394d: 11 39       .9
    db "EXE", $80 + 'C'                                               ; 394f: 45 58 45... EXE
    dw exec                                                           ; 3953: d1 38       .8
    db "LOA", $80 + 'D'                                               ; 3955: 4c 4f 41... LOA
    dw stload                                                         ; 3959: 81 34       .4
    db "OP", $80 + 'T'                                                ; 395b: 4f 50 d4    OP.
    dw opt_cpm                                                        ; 395e: c4 38       .8
    db "RENAM", $80 + 'E'                                             ; 3960: 52 45 4e... REN
    dw ren                                                            ; 3966: d4 37       .7
    db "RE", $80 + 'N'                                                ; 3968: 52 45 ce    RE.
    dw ren                                                            ; 396b: d4 37       .7
    db "RESE", $80 + 'T'                                              ; 396d: 52 45 53... RES
    dw res                                                            ; 3972: c1 37       .7
    db "SAV", $80 + 'E'                                               ; 3974: 53 41 56... SAV
    dw stsave                                                         ; 3978: da 33       .3
    db "SPOO", $80 + 'L'                                              ; 397a: 53 50 4f... SPO
    dw spool                                                          ; 397f: d4 38       .8
    db "TYP", $80 + 'E'                                               ; 3981: 54 59 50... TYP
    dw type_cpm                                                       ; 3985: 62 34       b4
    db $ff                                                            ; 3987: ff          .

; $3988 referenced 1 time by $38a5
cptext:
    push af                                                           ; 3988: f5          .
    ld a,$3a                                                          ; 3989: 3e 3a       >:
    call oswrch                                                       ; 398b: cd 5c 3a    .\:
    pop af                                                            ; 398e: f1          .
; $398f referenced 1 time by $38ac
sptext:
    call oswrch                                                       ; 398f: cd 5c 3a    .\:
; $3992 referenced 1 time by $3999
ptext_cpm:
    ld a,(hl)                                                         ; 3992: 7e          ~
    and $7f                                                           ; 3993: e6 7f       ..
    inc hl                                                            ; 3995: 23          #
    call oswrch                                                       ; 3996: cd 5c 3a    .\:
    djnz ptext_cpm                                                    ; 3999: 10 f7       ..
    ret                                                               ; 399b: c9          .

; $399c referenced 1 time by $0144
osinit:
    ld c,$2d                                                          ; 399c: 0e 2d       .-
    ld e,$fe                                                          ; 399e: 1e fe       ..
    call bdos                                                         ; 39a0: cd 05 00    ...
    ld b,$15                                                          ; 39a3: 06 15       ..
    ld hl,$3c03                                                       ; 39a5: 21 03 3c    !.<
; $39a8 referenced 1 time by $39aa
clrtab:
    ld (hl),a                                                         ; 39a8: 77          w
    inc hl                                                            ; 39a9: 23          #
    djnz clrtab                                                       ; 39aa: 10 fc       ..
    ld de,$3d00                                                       ; 39ac: 11 00 3d    ..=
    ld hl,$80                                                         ; 39af: 21 80 00    !..
    ld c,(hl)                                                         ; 39b2: 4e          N
    inc hl                                                            ; 39b3: 23          #
    cp c                                                              ; 39b4: b9          .
    jr z,noboot                                                       ; 39b5: 28 02       (.
    ldir                                                              ; 39b7: ed b0       ..
; $39b9 referenced 1 time by $39b5
noboot:
    ex de,hl                                                          ; 39b9: eb          .
    ld (hl),$0d                                                       ; 39ba: 36 0d       6.
    ld de,(l0006)                                                     ; 39bc: ed 5b 06... .[.
    ld e,a                                                            ; 39c0: 5f          _
    ld hl,$4000                                                       ; 39c1: 21 00 40    !.@
    ret                                                               ; 39c4: c9          .

bye:
    rst $00                                                           ; 39c5: c7          .
; $39c6 referenced 2 times by $0e16, $0ecb
trap:
    ld hl,$3c02                                                       ; 39c6: 21 02 3c    !.<
    dec (hl)                                                          ; 39c9: 35          5
    call z,test20                                                     ; 39ca: cc da 39    ..9
; $39cd referenced 2 times by $06dc, $385f
ltrap:
    ld a,(flags)                                                      ; 39cd: 3a 13 3c    :.<
    or a                                                              ; 39d0: b7          .
    ret p                                                             ; 39d1: f0          .
; $39d2 referenced 2 times by $347e, $3b60
abort:
    ld hl,$3c13                                                       ; 39d2: 21 13 3c    !.<
    res 7,(hl)                                                        ; 39d5: cb be       ..
    jp escape                                                         ; 39d7: c3 ec 0e    ...

; $39da referenced 1 time by $39ca
test20:
    ld (hl),$14                                                       ; 39da: 36 14       6.
; $39dc referenced 1 time by $3a60
test_cpm:
    push de                                                           ; 39dc: d5          .
    ld a,6                                                            ; 39dd: 3e 06       >.
    ld e,$ff                                                          ; 39df: 1e ff       ..
    call bdos0                                                        ; 39e1: cd f9 35    ..5
    pop de                                                            ; 39e4: d1          .
    or a                                                              ; 39e5: b7          .
    ret z                                                             ; 39e6: c8          .
    cp $13                                                            ; 39e7: fe 13       ..
    jr z,osrdch                                                       ; 39e9: 28 0b       (.
    cp $1b                                                            ; 39eb: fe 1b       ..
    jr z,escset                                                       ; 39ed: 28 44       (D
    ld (inkey_cpm),a                                                  ; 39ef: 32 14 3c    2.<
    ret                                                               ; 39f2: c9          .

; $39f3 referenced 1 time by $3afb
keyget:
    ld b,(ix-12)                                                      ; 39f3: dd 46 f4    .F.
; $39f6 referenced 3 times by $2398, $39e9, $3a04
osrdch:
    ld a,(flags)                                                      ; 39f6: 3a 13 3c    :.<
    rra                                                               ; 39f9: 1f          .
    jr c,execin                                                       ; 39fa: 38 0a       8.
    push hl                                                           ; 39fc: e5          .
    sbc hl,hl                                                         ; 39fd: ed 62       .b
    call oskey                                                        ; 39ff: cd 1e 3a    ..:
    pop hl                                                            ; 3a02: e1          .
    ret c                                                             ; 3a03: d8          .
    jr osrdch                                                         ; 3a04: 18 f0       ..

; $3a06 referenced 1 time by $39fa
execin:
    push bc                                                           ; 3a06: c5          .
    push de                                                           ; 3a07: d5          .
    push hl                                                           ; 3a08: e5          .
    ld e,8                                                            ; 3a09: 1e 08       ..
    ld hl,$3c13                                                       ; 3a0b: 21 13 3c    !.<
    res 0,(hl)                                                        ; 3a0e: cb 86       ..
    call osbget                                                       ; 3a10: cd 34 35    .45
    set 0,(hl)                                                        ; 3a13: cb c6       ..
    push af                                                           ; 3a15: f5          .
    call c,seshut                                                     ; 3a16: dc 35 34    .54
    pop af                                                            ; 3a19: f1          .
    pop hl                                                            ; 3a1a: e1          .
    pop de                                                            ; 3a1b: d1          .
    pop bc                                                            ; 3a1c: c1          .
    ret                                                               ; 3a1d: c9          .

; $3a1e referenced 2 times by $23a2, $39ff
oskey:
    push hl                                                           ; 3a1e: e5          .
    ld hl,$3c14                                                       ; 3a1f: 21 14 3c    !.<
    ld a,(hl)                                                         ; 3a22: 7e          ~
    ld (hl),0                                                         ; 3a23: 36 00       6.
    pop hl                                                            ; 3a25: e1          .
    or a                                                              ; 3a26: b7          .
    scf                                                               ; 3a27: 37          7
    ret nz                                                            ; 3a28: c0          .
    push de                                                           ; 3a29: d5          .
    call getkey                                                       ; 3a2a: cd 3f 3a    .?:
    pop de                                                            ; 3a2d: d1          .
    ret nc                                                            ; 3a2e: d0          .
    cp $1b                                                            ; 3a2f: fe 1b       ..
    scf                                                               ; 3a31: 37          7
    ret nz                                                            ; 3a32: c0          .
; $3a33 referenced 1 time by $39ed
escset:
    push hl                                                           ; 3a33: e5          .
    ld hl,$3c13                                                       ; 3a34: 21 13 3c    !.<
    bit 6,(hl)                                                        ; 3a37: cb 76       .v
    jr nz,escdis                                                      ; 3a39: 20 02        .
    set 7,(hl)                                                        ; 3a3b: cb fe       ..
; $3a3d referenced 1 time by $3a39
escdis:
    pop hl                                                            ; 3a3d: e1          .
    ret                                                               ; 3a3e: c9          .

; $3a3f referenced 2 times by $3a2a, $3a5a
getkey:
    push bc                                                           ; 3a3f: c5          .
    push hl                                                           ; 3a40: e5          .
    ld c,6                                                            ; 3a41: 0e 06       ..
    ld e,$ff                                                          ; 3a43: 1e ff       ..
    call bdos                                                         ; 3a45: cd 05 00    ...
    pop hl                                                            ; 3a48: e1          .
    pop bc                                                            ; 3a49: c1          .
    or a                                                              ; 3a4a: b7          .
    scf                                                               ; 3a4b: 37          7
    ret nz                                                            ; 3a4c: c0          .
    or h                                                              ; 3a4d: b4          .
    or l                                                              ; 3a4e: b5          .
    ret z                                                             ; 3a4f: c8          .
    push hl                                                           ; 3a50: e5          .
    ld hl,$3bfe                                                       ; 3a51: 21 fe 3b    !.;
    ld a,(hl)                                                         ; 3a54: 7e          ~
; $3a55 referenced 1 time by $3a56
wait1:
    cp (hl)                                                           ; 3a55: be          .
    jr z,wait1                                                        ; 3a56: 28 fd       (.
    pop hl                                                            ; 3a58: e1          .
    dec hl                                                            ; 3a59: 2b          +
    jr getkey                                                         ; 3a5a: 18 e3       ..

; $3a5c referenced 16 times by $099e, $15bf, $15ce, $3474, $3898, $38bc, $398b, $398f, $3996, $3ace, $3ae9, $3b56, $3b65, $3b9f, $3bd6, $3be4
oswrch:
    push af                                                           ; 3a5c: f5          .
    push de                                                           ; 3a5d: d5          .
    push hl                                                           ; 3a5e: e5          .
    ld e,a                                                            ; 3a5f: 5f          _
    call test_cpm                                                     ; 3a60: cd dc 39    ..9
    call edput                                                        ; 3a63: cd 6a 3a    .j:
    pop hl                                                            ; 3a66: e1          .
    pop de                                                            ; 3a67: d1          .
    pop af                                                            ; 3a68: f1          .
    ret                                                               ; 3a69: c9          .

; $3a6a referenced 1 time by $3a63
edput:
    ld a,(flags)                                                      ; 3a6a: 3a 13 3c    :.<
    bit 3,a                                                           ; 3a6d: cb 5f       ._
    jr z,wrch                                                         ; 3a6f: 28 10       (.
    ld a,e                                                            ; 3a71: 7b          {
    cp $20                                                            ; 3a72: fe 20       .
    ret c                                                             ; 3a74: d8          .
    ld hl,(edptr)                                                     ; 3a75: 2a 15 3c    *.<
    ld (hl),e                                                         ; 3a78: 73          s
    inc l                                                             ; 3a79: 2c          ,
    ret z                                                             ; 3a7a: c8          .
    ld (edptr),hl                                                     ; 3a7b: 22 15 3c    ".<
    ret                                                               ; 3a7e: c9          .

; $3a7f referenced 1 time by $019e
prompt:
    ld e,$3e                                                          ; 3a7f: 1e 3e       .>
; $3a81 referenced 3 times by $3a6f, $3ae0, $3aef
wrch:
    ld a,(optval)                                                     ; 3a81: 3a 17 3c    :.<
    add a,3                                                           ; 3a84: c6 03       ..
    cp 3                                                              ; 3a86: fe 03       ..
    jr nz,wrch1                                                       ; 3a88: 20 07        .
    add a,e                                                           ; 3a8a: 83          .
    ld a,2                                                            ; 3a8b: 3e 02       >.
    jr c,wrch1                                                        ; 3a8d: 38 02       8.
    ld a,6                                                            ; 3a8f: 3e 06       >.
; $3a91 referenced 2 times by $3a88, $3a8d
wrch1:
    call bdos0                                                        ; 3a91: cd f9 35    ..5
    ld hl,$3c13                                                       ; 3a94: 21 13 3c    !.<
    bit 2,(hl)                                                        ; 3a97: cb 56       .V
    ld a,5                                                            ; 3a99: 3e 05       >.
    call nz,bdos0                                                     ; 3a9b: c4 f9 35    ..5
    bit 1,(hl)                                                        ; 3a9e: cb 4e       .N
    ret z                                                             ; 3aa0: c8          .
    res 1,(hl)                                                        ; 3aa1: cb 8e       ..
    ld a,e                                                            ; 3aa3: 7b          {
    ld e,8                                                            ; 3aa4: 1e 08       ..
    push bc                                                           ; 3aa6: c5          .
    call osbput                                                       ; 3aa7: cd 17 35    ..5
    pop bc                                                            ; 3aaa: c1          .
    set 1,(hl)                                                        ; 3aab: cb ce       ..
    ret                                                               ; 3aad: c9          .

; $3aae referenced 1 time by $3b32
toggle:
    ld a,(flags)                                                      ; 3aae: 3a 13 3c    :.<
    xor 4                                                             ; 3ab1: ee 04       ..
    ld (flags),a                                                      ; 3ab3: 32 13 3c    2.<
    ret                                                               ; 3ab6: c9          .

; $3ab7 referenced 2 times by $01d6, $143b
osline:
    ld ix,$3bfe                                                       ; 3ab7: dd 21 fe... .!.
    ld a,(flags)                                                      ; 3abb: 3a 13 3c    :.<
    bit 3,a                                                           ; 3abe: cb 5f       ._
    jr z,oslin1                                                       ; 3ac0: 28 09       (.
    res 3,a                                                           ; 3ac2: cb 9f       ..
    ld (flags),a                                                      ; 3ac4: 32 13 3c    2.<
    ld hl,(edptr)                                                     ; 3ac7: 2a 15 3c    *.<
    cp l                                                              ; 3aca: bd          .
; $3acb referenced 1 time by $3ac0
oslin1:
    ld a,$0d                                                          ; 3acb: 3e 0d       >.
    ld (hl),a                                                         ; 3acd: 77          w
    call nz,oswrch                                                    ; 3ace: c4 5c 3a    .\:
    ld l,0                                                            ; 3ad1: 2e 00       ..
    ld c,l                                                            ; 3ad3: 4d          M
    jr z,oswait                                                       ; 3ad4: 28 20       (
; $3ad6 referenced 1 time by $3bb5
update:
    ld b,0                                                            ; 3ad6: 06 00       ..
; $3ad8 referenced 1 time by $3ae5
upd1:
    ld a,(hl)                                                         ; 3ad8: 7e          ~
    inc b                                                             ; 3ad9: 04          .
    inc hl                                                            ; 3ada: 23          #
    cp $0d                                                            ; 3adb: fe 0d       ..
    push af                                                           ; 3add: f5          .
    push hl                                                           ; 3ade: e5          .
    ld e,a                                                            ; 3adf: 5f          _
    call nz,wrch                                                      ; 3ae0: c4 81 3a    ..:
    pop hl                                                            ; 3ae3: e1          .
    pop af                                                            ; 3ae4: f1          .
    jr nz,upd1                                                        ; 3ae5: 20 f1        .
    ld a,$20                                                          ; 3ae7: 3e 20       >
    call oswrch                                                       ; 3ae9: cd 5c 3a    .\:
    ld e,8                                                            ; 3aec: 1e 08       ..
; $3aee referenced 1 time by $3af4
upd2:
    push hl                                                           ; 3aee: e5          .
    call wrch                                                         ; 3aef: cd 81 3a    ..:
    pop hl                                                            ; 3af2: e1          .
    dec hl                                                            ; 3af3: 2b          +
    djnz upd2                                                         ; 3af4: 10 f8       ..
; $3af6 referenced 1 time by $3ad4
oswait:
    ld a,c                                                            ; 3af6: 79          y
    dec b                                                             ; 3af7: 05          .
    jr z,limit                                                        ; 3af8: 28 01       (.
    or a                                                              ; 3afa: b7          .
; $3afb referenced 1 time by $3af8
limit:
    call z,keyget                                                     ; 3afb: cc f3 39    ..9
    ld c,a                                                            ; 3afe: 4f          O
    ld de,$3af6                                                       ; 3aff: 11 f6 3a    ..:
    push de                                                           ; 3b02: d5          .
    ld a,(flags)                                                      ; 3b03: 3a 13 3c    :.<
    or a                                                              ; 3b06: b7          .
    ld a,c                                                            ; 3b07: 79          y
    jp m,osexit                                                       ; 3b08: fa 55 3b    .U;
    cp (ix-11)                                                        ; 3b0b: dd be f5    ...
    jp z,left                                                         ; 3b0e: ca 99 3b    ..;
    cp (ix-10)                                                        ; 3b11: dd be f6    ...
    jp z,right                                                        ; 3b14: ca cc 3b    ..;
    ld b,0                                                            ; 3b17: 06 00       ..
    cp (ix-5)                                                         ; 3b19: dd be fb    ...
    jr z,back                                                         ; 3b1c: 28 7a       (z
    cp (ix-9)                                                         ; 3b1e: dd be f7    ...
    jr z,left                                                         ; 3b21: 28 76       (v
    cp (ix-7)                                                         ; 3b23: dd be f9    ...
    jr z,delete_cpm                                                   ; 3b26: 28 7c       (|
    cp (ix-8)                                                         ; 3b28: dd be f8    ...
    jp z,right                                                        ; 3b2b: ca cc 3b    ..;
    ld c,0                                                            ; 3b2e: 0e 00       ..
    cp $10                                                            ; 3b30: fe 10       ..
    jp z,toggle                                                       ; 3b32: ca ae 3a    ..:
    cp (ix-6)                                                         ; 3b35: dd be fa    ...
    jr z,back                                                         ; 3b38: 28 5e       (^
    cp (ix-4)                                                         ; 3b3a: dd be fc    ...
    jr z,left                                                         ; 3b3d: 28 5a       (Z
    cp (ix-2)                                                         ; 3b3f: dd be fe    ...
    jr z,delete_cpm                                                   ; 3b42: 28 60       (`
    cp (ix-1)                                                         ; 3b44: dd be ff    ...
    jr z,insert                                                       ; 3b47: 28 6f       (o
    cp (ix-3)                                                         ; 3b49: dd be fd    ...
    jr z,right                                                        ; 3b4c: 28 7e       (~
    cp $20                                                            ; 3b4e: fe 20       .
    jr nc,savech                                                      ; 3b50: 30 7f       0.
    cp $0d                                                            ; 3b52: fe 0d       ..
    ret nz                                                            ; 3b54: c0          .
; $3b55 referenced 2 times by $3b08, $3b5c
osexit:
    ld a,(hl)                                                         ; 3b55: 7e          ~
    call oswrch                                                       ; 3b56: cd 5c 3a    .\:
    inc hl                                                            ; 3b59: 23          #
    sub $0d                                                           ; 3b5a: d6 0d       ..
    jr nz,osexit                                                      ; 3b5c: 20 f7        .
    pop de                                                            ; 3b5e: d1          .
    cp c                                                              ; 3b5f: b9          .
    jp nz,abort                                                       ; 3b60: c2 d2 39    ..9
    ld a,$0a                                                          ; 3b63: 3e 0a       >.
    call oswrch                                                       ; 3b65: cd 5c 3a    .\:
    ld de,(errlin)                                                    ; 3b68: ed 5b f4... .[.
    xor a                                                             ; 3b6c: af          .
    ld l,a                                                            ; 3b6d: 6f          o
    ld (edptr),hl                                                     ; 3b6e: 22 15 3c    ".<
    cp d                                                              ; 3b71: ba          .
    ret nz                                                            ; 3b72: c0          .
    cp e                                                              ; 3b73: bb          .
    ret nz                                                            ; 3b74: c0          .
    ld de,$3bea                                                       ; 3b75: 11 ea 3b    ..;
    ld b,4                                                            ; 3b78: 06 04       ..
; $3b7a referenced 1 time by $3b86
cmpare:
    ld a,(de)                                                         ; 3b7a: 1a          .
    cp (hl)                                                           ; 3b7b: be          .
    ld a,0                                                            ; 3b7c: 3e 00       >.
    ret nz                                                            ; 3b7e: c0          .
    inc hl                                                            ; 3b7f: 23          #
    inc de                                                            ; 3b80: 13          .
    ld a,(hl)                                                         ; 3b81: 7e          ~
    cp $2e                                                            ; 3b82: fe 2e       ..
    jr z,abbr                                                         ; 3b84: 28 02       (.
    djnz cmpare                                                       ; 3b86: 10 f2       ..
; $3b88 referenced 1 time by $3b84
abbr:
    xor a                                                             ; 3b88: af          .
    ld b,a                                                            ; 3b89: 47          G
    ld c,l                                                            ; 3b8a: 4d          M
    ld l,a                                                            ; 3b8b: 6f          o
    ld de,$3bee                                                       ; 3b8c: 11 ee 3b    ..;
    ex de,hl                                                          ; 3b8f: eb          .
    ldir                                                              ; 3b90: ed b0       ..
    ld hl,$3c13                                                       ; 3b92: 21 13 3c    !.<
    set 3,(hl)                                                        ; 3b95: cb de       ..
    ret                                                               ; 3b97: c9          .

; $3b98 referenced 2 times by $3b1c, $3b38
back:
    scf                                                               ; 3b98: 37          7
; $3b99 referenced 3 times by $3b0e, $3b21, $3b3d
left:
    inc l                                                             ; 3b99: 2c          ,
    dec l                                                             ; 3b9a: 2d          -
    jr z,stop_cpm                                                     ; 3b9b: 28 4a       (J
    ld a,8                                                            ; 3b9d: 3e 08       >.
    call oswrch                                                       ; 3b9f: cd 5c 3a    .\:
    dec l                                                             ; 3ba2: 2d          -
    ret nc                                                            ; 3ba3: d0          .
; $3ba4 referenced 2 times by $3b26, $3b42
delete_cpm:
    ld a,(hl)                                                         ; 3ba4: 7e          ~
    cp $0d                                                            ; 3ba5: fe 0d       ..
    jr z,stop_cpm                                                     ; 3ba7: 28 3e       (>
    ld d,h                                                            ; 3ba9: 54          T
    ld e,l                                                            ; 3baa: 5d          ]
; $3bab referenced 1 time by $3bb2
del1:
    inc de                                                            ; 3bab: 13          .
    ld a,(de)                                                         ; 3bac: 1a          .
    dec de                                                            ; 3bad: 1b          .
    ld (de),a                                                         ; 3bae: 12          .
    inc de                                                            ; 3baf: 13          .
    cp $0d                                                            ; 3bb0: fe 0d       ..
    jr nz,del1                                                        ; 3bb2: 20 f7        .
; $3bb4 referenced 1 time by $3bca
del2:
    pop de                                                            ; 3bb4: d1          .
    jp update                                                         ; 3bb5: c3 d6 3a    ..:

; $3bb8 referenced 1 time by $3b47
insert:
    ld a,$0d                                                          ; 3bb8: 3e 0d       >.
    cp (hl)                                                           ; 3bba: be          .
    ret z                                                             ; 3bbb: c8          .
    ld d,h                                                            ; 3bbc: 54          T
    ld e,$fe                                                          ; 3bbd: 1e fe       ..
; $3bbf referenced 1 time by $3bc6
ins1:
    inc de                                                            ; 3bbf: 13          .
    ld (de),a                                                         ; 3bc0: 12          .
    dec de                                                            ; 3bc1: 1b          .
    ld a,e                                                            ; 3bc2: 7b          {
    cp l                                                              ; 3bc3: bd          .
    dec de                                                            ; 3bc4: 1b          .
    ld a,(de)                                                         ; 3bc5: 1a          .
    jr nz,ins1                                                        ; 3bc6: 20 f7        .
    ld (hl),$20                                                       ; 3bc8: 36 20       6
    jr del2                                                           ; 3bca: 18 e8       ..

; $3bcc referenced 3 times by $3b14, $3b2b, $3b4c
right:
    ld a,(hl)                                                         ; 3bcc: 7e          ~
    cp $0d                                                            ; 3bcd: fe 0d       ..
    jr z,stop_cpm                                                     ; 3bcf: 28 16       (.
; $3bd1 referenced 1 time by $3b50
savech:
    ld d,(hl)                                                         ; 3bd1: 56          V
    ld (hl),a                                                         ; 3bd2: 77          w
    inc l                                                             ; 3bd3: 2c          ,
    jr z,wontgo                                                       ; 3bd4: 28 09       (.
    call oswrch                                                       ; 3bd6: cd 5c 3a    .\:
    ld a,$0d                                                          ; 3bd9: 3e 0d       >.
    cp d                                                              ; 3bdb: ba          .
    ret nz                                                            ; 3bdc: c0          .
    ld (hl),a                                                         ; 3bdd: 77          w
    ret                                                               ; 3bde: c9          .

; $3bdf referenced 1 time by $3bd4
wontgo:
    dec l                                                             ; 3bdf: 2d          -
    ld (hl),$0d                                                       ; 3be0: 36 0d       6.
    ld a,7                                                            ; 3be2: 3e 07       >.
    call oswrch                                                       ; 3be4: cd 5c 3a    .\:
; $3be7 referenced 3 times by $3b9b, $3ba7, $3bcf
stop_cpm:
    ld c,0                                                            ; 3be7: 0e 00       ..
    ret                                                               ; 3be9: c9          .

editst:
    db "EDIT"                                                         ; 3bea: 45 44 49... EDI
listst:
    db "LISTP"                                                        ; 3bee: 4c 49 53... LIS
    db 5, $18, 1, 6, $14, 8, $15, $13, 4, 7, $16                      ; 3bf3: 05 18 01... ...
keys:
time:
    db 0, 0, 0, 0                                                     ; 3bfe: 00 00 00... ...
trpcnt:
    db $0a                                                            ; 3c02: 0a          .
; $3c03 referenced 1 time by $38ff
table:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                 ; 3c03: 00 00 00... ...
; $3c13 referenced 11 times by $346a, $38e1, $38e5, $39cd, $39f6, $3a6a, $3aae, $3ab3, $3abb, $3ac4, $3b03
flags:
    db 0                                                              ; 3c13: 00          .
; $3c14 referenced 1 time by $39ef
inkey_cpm:
    db 0                                                              ; 3c14: 00          .
; $3c15 referenced 4 times by $3a75, $3a7b, $3ac7, $3b6e
edptr:
    db 0, 0                                                           ; 3c15: 00 00       ..
; $3c17 referenced 2 times by $38ca, $3a81
optval:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c17: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c2c: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c41: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c56: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c6b: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c80: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3c95: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3caa: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3cbf: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3cd4: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3ce9: 00 00 00... ...
    db 0, 0                                                           ; 3cfe: 00 00       ..
; $3d00 referenced 1 time by $2166
accs:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d00: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d15: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d2a: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d3f: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d54: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d69: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d7e: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3d93: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3da8: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3dbd: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3dd2: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3de7: 00 00 00... ...
    db 0, 0, 0, 0                                                     ; 3dfc: 00 00 00... ...
; $3e00 referenced 1 time by $1620
buffer:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e00: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e15: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e2a: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e3f: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e54: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e69: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e7e: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3e93: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3ea8: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3ebd: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3ed2: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3ee7: 00 00 00... ...
    db 0, 0, 0, 0                                                     ; 3efc: 00 00 00... ...
; $3f00 referenced 1 time by $1054
stavar:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f00: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f15: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0           ; 3f2a: 00 00 00... ...
; $3f3c referenced 3 times by $190f, $1945, $1949
oc:
    db 0, 0, 0, 0                                                     ; 3f3c: 00 00 00... ...
; $3f40 referenced 5 times by $1904, $1939, $193e, $19b7, $1a89
pc:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f40: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f55: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f6a: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f7f: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3f94: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3fa9: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 3fbe: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0                                      ; 3fd3: 00 00 00... ...
; $3fdc referenced 17 times by $014b, $06ef, $0735, $07c0, $07f0, $08ad, $08d2, $08ee, $09d6, $09f4, $0e00, $0e0b, $1260, $14f5, $14fa, $1536, $217b
page:
    db 0, 0                                                           ; 3fdc: 00 00       ..
; $3fde referenced 8 times by $0220, $022e, $07f4, $089b, $08a6, $08ea, $08f7, $218a
top:
    db 0, 0                                                           ; 3fde: 00 00       ..
; $3fe0 referenced 6 times by $06f2, $0730, $0769, $08fa, $1567, $2171
lomem:
    db 0, 0                                                           ; 3fe0: 00 00       ..
; $3fe2 referenced 15 times by $08fd, $0ba8, $0be2, $0f9c, $0fcf, $0fe0, $156a, $1577, $16cb, $16e5, $16ea, $3454, $345c, $34f2, $34fe
free:
    db 0, 0                                                           ; 3fe2: 00 00       ..
; $3fe4 referenced 11 times by $0147, $019a, $0805, $081e, $0dda, $0de1, $1583, $1587, $2176, $38ef, $38fc
himem:
    db 0, 0                                                           ; 3fe4: 00 00       ..
; $3fe6 referenced 7 times by $01b5, $01eb, $01fc, $0748, $078c, $0a0f, $0a18
lineno:
    db 0, 0                                                           ; 3fe6: 00 00       ..
; $3fe8 referenced 3 times by $083f, $0e55, $15b4
tracen:
    db 0, 0                                                           ; 3fe8: 00 00       ..
; $3fea referenced 4 times by $01b2, $01cb, $07a4, $083c
autono:
    db 0, 0                                                           ; 3fea: 00 00       ..
; $3fec referenced 5 times by $01ac, $082e, $0dfd, $10a4, $10b3
errtrp:
    db 0, 0                                                           ; 3fec: 00 00       ..
; $3fee referenced 3 times by $0141, $081b, $0d49
errtxt:
    db 0, 0                                                           ; 3fee: 00 00       ..
; $3ff0 referenced 4 times by $0e08, $1456, $1484, $1512
datptr:
    db 0, 0                                                           ; 3ff0: 00 00       ..
; $3ff2 referenced 2 times by $0828, $218f
erl:
    db 0, 0                                                           ; 3ff2: 00 00       ..
; $3ff4 referenced 6 times by $01af, $09f0, $0e12, $0ec7, $0f0d, $3b68
errlin:
    db 0, 0, 0, 0, 0, 0, 0                                            ; 3ff4: 00 00 00... ...
; $3ffb referenced 8 times by $01da, $09a6, $09aa, $1044, $1444, $14d3, $195f, $2199
count:
    db 0                                                              ; 3ffb: 00          .
; $3ffc referenced 2 times by $09af, $159a
width:
    db 0                                                              ; 3ffc: 00          .
; $3ffd referenced 2 times by $0822, $2194
err:
    db 0                                                              ; 3ffd: 00          .
; $3ffe referenced 4 times by $013b, $0664, $192e, $20a1
liston:
    db 0                                                              ; 3ffe: 00          .
; $3fff referenced 2 times by $01c1, $07a8
increm:
    db 0                                                              ; 3fff: 00          .
pydis_end:

; ASSERT (($80 + 'A') == $c1)
; ASSERT (($80 + 'C') == $c3)
; ASSERT (($80 + 'D') == $c4)
; ASSERT (($80 + 'E') == $c5)
; ASSERT (($80 + 'L') == $cc)
; ASSERT (($80 + 'M') == $cd)
; ASSERT (($80 + 'N') == $ce)
; ASSERT (($80 + 'R') == $d2)
; ASSERT (($80 + 'T') == $d4)
; ASSERT ((abs_eval) == $221a)
; ASSERT ((abs_fpp) == $292d)
; ASSERT ((acs_eval) == $2256)
; ASSERT ((acs_fpp) == $2c89)
; ASSERT ((adval) == $32aa)
; ASSERT ((adval) == $32aa)
; ASSERT ((adval) == $32aa)
; ASSERT ((adval) == $32aa)
; ASSERT ((adval) == $32aa)
; ASSERT ((adval) == $32aa)
; ASSERT ((adval) == $32aa)
; ASSERT ((asc) == $215e)
; ASSERT ((asn_eval) == $224e)
; ASSERT ((asn_fpp) == $2be5)
; ASSERT ((atn_eval) == $2252)
; ASSERT ((atn_fpp) == $2c0a)
; ASSERT ((auto) == $07a1)
; ASSERT ((bget) == $213a)
; ASSERT ((bput) == $15e4)
; ASSERT ((bye) == $39c5)
; ASSERT ((bye) == $39c5)
; ASSERT ((call) == $15f7)
; ASSERT ((chain) == $0dd4)
; ASSERT ((chrs) == $2391)
; ASSERT ((cli) == $0e77)
; ASSERT ((close_exec) == $15db)
; ASSERT ((clr) == $14f2)
; ASSERT ((cls) == $14cf)
; ASSERT ((colour) == $3213)
; ASSERT ((cos_eval) == $223a)
; ASSERT ((cos_fpp) == $2a23)
; ASSERT ((countv) == $2199)
; ASSERT ((decode) == $2450)
; ASSERT ((deg_eval) == $2222)
; ASSERT ((deg_fpp) == $2957)
; ASSERT ((delete_main) == $063b)
; ASSERT ((dim) == $0f38)
; ASSERT ((dir) == $3852)
; ASSERT ((drv) == $37c5)
; ASSERT ((end) == $0e3a)
; ASSERT ((endpro) == $1327)
; ASSERT ((eof) == $212e)
; ASSERT ((era) == $37ba)
; ASSERT ((era) == $37ba)
; ASSERT ((erlv) == $218f)
; ASSERT ((errv) == $2194)
; ASSERT ((escctl) == $3911)
; ASSERT ((eval) == $227a)
; ASSERT ((exec) == $38d1)
; ASSERT ((exp_eval) == $2242)
; ASSERT ((exp_fpp) == $2ac8)
; ASSERT ((ext_eval) == $21be)
; ASSERT ((fadd) == $2704)
; ASSERT ((fand) == $2671)
; ASSERT ((fbdiv) == $26d4)
; ASSERT ((fcomp) == $2fca)
; ASSERT ((fdiv) == $275c)
; ASSERT ((feor) == $2683)
; ASSERT ((feq) == $2919)
; ASSERT ((fge) == $28f6)
; ASSERT ((fgt) == $28ea)
; ASSERT ((fle) == $2901)
; ASSERT ((flt) == $28df)
; ASSERT ((fmod) == $26a7)
; ASSERT ((fmul) == $27ef)
; ASSERT ((fn) == $1246)
; ASSERT ((fnchk) == $124a)
; ASSERT ((fne) == $290e)
; ASSERT ((fone) == $2aa7)
; ASSERT ((for_exec) == $117c)
; ASSERT ((for_fpp) == $2695)
; ASSERT ((forchk) == $11c1)
; ASSERT ((fpow) == $28b5)
; ASSERT ((fsub) == $26ee)
; ASSERT ((ftest) == $2fb9)
; ASSERT ((gcol) == $3240)
; ASSERT ((get) == $2148)
; ASSERT ((gets) == $2398)
; ASSERT ((goschk) == $1142)
; ASSERT ((gosub) == $1137)
; ASSERT ((goto) == $1120)
; ASSERT ((himemv_eval) == $2176)
; ASSERT ((himemv_exec) == $1570)
; ASSERT ((iadd) == $26fa)
; ASSERT ((iand) == $2674)
; ASSERT ((ibdiv) == $26d7)
; ASSERT ((idiv) == $2759)
; ASSERT ((ieor) == $2686)
; ASSERT ((ieq) == $291e)
; ASSERT ((if) == $14a2)
; ASSERT ((ige) == $28fb)
; ASSERT ((igt) == $28ef)
; ASSERT ((ile) == $2906)
; ASSERT ((ilt) == $28e4)
; ASSERT ((imod) == $26aa)
; ASSERT ((imul) == $27a1)
; ASSERT ((ine) == $2913)
; ASSERT ((inkey_eval) == $2143)
; ASSERT ((inkeys) == $239e)
; ASSERT ((input) == $13b2)
; ASSERT ((instr) == $2313)
; ASSERT ((int_eval) == $222e)
; ASSERT ((int_fpp) == $299d)
; ASSERT ((ior) == $2698)
; ASSERT ((ipow) == $283f)
; ASSERT ((isub) == $26e4)
; ASSERT ((lefts) == $23df)
; ASSERT ((len) == $216b)
; ASSERT ((let) == $0eab)
; ASSERT ((list) == $066a)
; ASSERT ((ln_eval) == $2246)
; ASSERT ((ln_fpp) == $2b53)
; ASSERT ((load_main) == $07d9)
; ASSERT ((local) == $12d9)
; ASSERT ((log_eval) == $224a)
; ASSERT ((log_fpp) == $2bd3)
; ASSERT ((lomemv_eval) == $2171)
; ASSERT ((lomemv_exec) == $155d)
; ASSERT ((mids) == $23ae)
; ASSERT ((mode) == $3286)
; ASSERT ((new) == $07bb)
; ASSERT ((not_eval) == $221e)
; ASSERT ((not_fpp) == $2938)
; ASSERT ((old) == $07c0)
; ASSERT ((on) == $10ba)
; ASSERT ((openin) == $21a9)
; ASSERT ((openot) == $21a4)
; ASSERT ((openup) == $21a6)
; ASSERT ((opt_cpm) == $38c4)
; ASSERT ((pagev_eval) == $217b)
; ASSERT ((pagev_exec) == $152d)
; ASSERT ((pi_eval) == $2216)
; ASSERT ((pi_fpp) == $294b)
; ASSERT ((plot) == $3291)
; ASSERT ((pos) == $2123)
; ASSERT ((print) == $0fe5)
; ASSERT ((ptr_eval) == $21c6)
; ASSERT ((ptr_exec) == $1518)
; ASSERT ((put) == $1662)
; ASSERT ((rad_eval) == $2226)
; ASSERT ((rad_fpp) == $295f)
; ASSERT ((read_exec) == $1451)
; ASSERT ((rem) == $0e8b)
; ASSERT ((rem) == $0e8b)
; ASSERT ((rem) == $0e8b)
; ASSERT ((ren) == $37d4)
; ASSERT ((ren) == $37d4)
; ASSERT ((renum) == $06e8)
; ASSERT ((repchk) == $115a)
; ASSERT ((repeat) == $1152)
; ASSERT ((repor) == $14ec)
; ASSERT ((res) == $37c1)
; ASSERT ((restor) == $14fa)
; ASSERT ((rights) == $23fa)
; ASSERT ((rnd) == $22a7)
; ASSERT ((run) == $0dcf)
; ASSERT ((save_main) == $07e7)
; ASSERT ((seq) == $2207)
; ASSERT ((sfix_fpp) == $2eb8)
; ASSERT ((sfloat_fpp) == $2f74)
; ASSERT ((sge) == $21f3)
; ASSERT ((sgn_eval) == $222a)
; ASSERT ((sgn_fpp) == $2975)
; ASSERT ((sgt) == $21ec)
; ASSERT ((sin_eval) == $223e)
; ASSERT ((sin_fpp) == $2a2e)
; ASSERT ((sle) == $21f9)
; ASSERT ((slt) == $21e6)
; ASSERT ((sne) == $2201)
; ASSERT ((spool) == $38d4)
; ASSERT ((sqr_eval) == $2232)
; ASSERT ((sqr_fpp) == $29b3)
; ASSERT ((stload) == $3481)
; ASSERT ((stop_exec) == $14d9)
; ASSERT ((str_fpp) == $2c91)
; ASSERT ((string) == $240e)
; ASSERT ((strs) == $24a8)
; ASSERT ((stsave) == $33da)
; ASSERT ((tan_eval) == $2236)
; ASSERT ((tan_fpp) == $2a06)
; ASSERT ((timev_eval) == $21ce)
; ASSERT ((timev_exec) == $153c)
; ASSERT ((topv) == $2180)
; ASSERT ((trace) == $15a0)
; ASSERT ((true_eval) == $220b)
; ASSERT ((true_fpp) == $2922)
; ASSERT ((type_cpm) == $3462)
; ASSERT ((usr) == $162a)
; ASSERT ((usr2) == $165d)
; ASSERT ((val_eval) == $226d)
; ASSERT ((val_fpp) == $2985)
; ASSERT ((vdu) == $15ba)
; ASSERT ((vpos) == $2129)
; ASSERT ((widthv) == $1595)
; ASSERT ((zero_eval) == $24e8)
; ASSERT ((zero_fpp) == $2fe3)

; Label references by decreasing frequency:
;     xeq_exec:     47
;     nxt:          43
;     expri:        31
;     error_main:   26
;     outchr:       21
;     swap_fpp:     18
;     page:         17
;     exterr:       16
;     oswrch:       16
;     fppn:         15
;     free:         15
;     pop5:         15
;     check:        12
;     crlf:         12
;     fmul:         12
;     itemi:        12
;     negate_fpp:   12
;     sfloat_fpp:   12
;     braket:       11
;     exprs:        11
;     flags:        11
;     himem:        11
;     push5:        11
;     termq:        11
;     zero_fpp:     11
;     osbget:       10
;     osbput:       10
;     skipsp:       10
;     store:        10
;     bdos1:         9
;     byte:          9
;     cloop:         9
;     syntax:        9
;     type_eval:     9
;     count:         8
;     count1:        8
;     equals:        8
;     expr:          8
;     huh:           8
;     number_exec:   8
;     pushs:         8
;     setup0:        8
;     top:           8
;     true_eval:     8
;     add1_fpp:      7
;     chanel:        7
;     clear:         7
;     error_fpp:     7
;     fadd:          7
;     fcp:           7
;     fdiv:          7
;     fpp:           7
;     getvar:        7
;     icp:           7
;     lineno:        7
;     skip:          7
;     tell:          7
;     true_fpp:      7
;     copyf1:        6
;     count0:        6
;     doit:          6
;     errlin:        6
;     error2_exec:   6
;     find_cpm:      6
;     linnum:        6
;     lomem:         6
;     osshut:        6
;     pbcdl:         6
;     powr10:        6
;     scp:           6
;     sfix_eval:     6
;     toobig:        6
;     var:           6
;     baddim:        5
;     bdos0:         5
;     cgcol:         5
;     comma:         5
;     done:          5
;     error3_exec:   5
;     errtrp:        5
;     exprn:         5
;     fcp0:          5
;     fill_exec:     5
;     fix2:          5
;     item:          5
;     itemn:         5
;     items:         5
;     noroom:        5
;     opnd:          5
;     pc:            5
;     poly:          5
;     pops:          5
;     range1:        5
;     save_eval:     5
;     settop:        5
;     staccs:        5
;     test_fpp:      5
;     upprc:         5
;     warm:          5
;     add:           4
;     assem:         4
;     autono:        4
;     byte0:         4
;     byte1:         4
;     byte2:         4
;     cmode:         4
;     datptr:        4
;     dload5_fpp:    4
;     ed:            4
;     edptr:         4
;     findl:         4
;     fix:           4
;     float:         4
;     float2:        4
;     fpp1:          4
;     hex_cpm:       4
;     incc:          4
;     indent:        4
;     lexan1:        4
;     liston:        4
;     load4:         4
;     number_fpp:    4
;     oflow:         4
;     on4:           4
;     out:           4
;     print0:        4
;     printc:        4
;     search_exec:   4
;     setdma:        4
;     shl3:          4
;     square:        4
;     textx:         4
;     texty:         4
;     write:         4
;     x2:            4
;     xeq0_exec:     4
;     zero_eval:     4
;     bdos:          3
;     bind:          3
;     ccolor:        3
;     close_cpm:     3
;     con0:          3
;     cond:          3
;     cons:          3
;     copy:          3
;     create_main:   3
;     d2c:           3
;     div2:          3
;     errtxt:        3
;     expr3:         3
;     expr4:         3
;     expr4b:        3
;     exprsc:        3
;     getdef:        3
;     grpb:          3
;     imul1:         3
;     incsec:        3
;     left:          3
;     lexan2:        3
;     lexan8:        3
;     ln3:           3
;     loadn:         3
;     loc2:          3
;     newit:         3
;     oc:            3
;     odd:           3
;     op:            3
;     oscli:         3
;     osrdch:        3
;     pair1_exec:    3
;     pair_exec:     3
;     piby4:         3
;     putvar:        3
;     range:         3
;     rdf:           3
;     recip:         3
;     reghi:         3
;     reglo:         3
;     right:         3
;     rsub:          3
;     setlin:        3
;     signq:         3
;     span:          3
;     srch4:         3
;     stop_cpm:      3
;     stores:        3
;     str22:         3
;     str26:         3
;     str34:         3
;     sub:           3
;     test_eval:     3
;     text:          3
;     tracen:        3
;     val8:          3
;     vdpadr:        3
;     warmnc:        3
;     wrch:          3
;     abort:         2
;     acs1:          2
;     addr:          2
;     adval:         2
;     argerr:        2
;     argue6:        2
;     assign:        2
;     atn2:          2
;     back:          2
;     bad_main:      2
;     chkamb:        2
;     chnl:          2
;     clean:         2
;     clg:           2
;     cloop0:        2
;     con2:          2
;     con_eval:      2
;     copy0:         2
;     copyf:         2
;     corn:          2
;     create_cpm:    2
;     decode:        2
;     del:           2
;     delete_cpm:    2
;     delim:         2
;     digitq:        2
;     dim4:          2
;     dir1:          2
;     diva:          2
;     divb:          2
;     dload5_eval:   2
;     dlp1:          2
;     dlpair:        2
;     draw:          2
;     encode:        2
;     endpro:        2
;     envel:         2
;     erl:           2
;     err:           2
;     error0_eval:   2
;     error0_main:   2
;     error1_eval:   2
;     escape:        2
;     expr1:         2
;     expr2:         2
;     expr3a:        2
;     expr5:         2
;     fetchs:        2
;     find0:         2
;     find1_cpm:     2
;     find1_exec:    2
;     find_exec:     2
;     flo48:         2
;     fnend5:        2
;     format:        2
;     fpi180:        2
;     fpow0:         2
;     g4:            2
;     getcsr:        2
;     getex1:        2
;     getims:        2
;     getkey:        2
;     getv7:         2
;     hex_exec:      2
;     hexdig:        2
;     hexsp:         2
;     hexst1:        2
;     hexst3:        2
;     hexstr:        2
;     icp0:          2
;     if1:           2
;     ifnot:         2
;     increm:        2
;     ind2:          2
;     ind4:          2
;     inpn1:         2
;     input0:        2
;     input3:        2
;     inputn:        2
;     instr1:        2
;     l005c:         2
;     ld16:          2
;     lex:           2
;     lex1:          2
;     lex6:          2
;     lexan9:        2
;     lexanb:        2
;     ln2:           2
;     load0_main:    2
;     load5:         2
;     loads:         2
;     loads2:        2
;     loc1:          2
;     loc4:          2
;     loc5a:         2
;     loc7:          2
;     loc8:          2
;     loc9:          2
;     local1:        2
;     ltrap:         2
;     m2loop:        2
;     mids1:         2
;     mod482:        2
;     move:          2
;     mul16:         2
;     mula:          2
;     newlin:        2
;     numb1:         2
;     on1:           2
;     on2:           2
;     open:          2
;     openit:        2
;     optval:        2
;     oscli1:        2
;     oscli4:        2
;     osexit:        2
;     oskey:         2
;     osline:        2
;     osopen:        2
;     osstat:        2
;     pair_main:     2
;     pbcd:          2
;     point:         2
;     powr14:        2
;     prntn1:        2
;     proc1:         2
;     prochk:        2
;     ptext_exec:    2
;     putims:        2
;     ratio:         2
;     read_cpm:      2
;     reg:           2
;     relopq:        2
;     rem:           2
;     report:        2
;     restr1:        2
;     run0:          2
;     save_cpm:      2
;     savlo4:        2
;     savloc:        2
;     savlod:        2
;     sayln:         2
;     scale:         2
;     search_eval:   2
;     seshut:        2
;     set3:          2
;     setop2:        2
;     setreg:        2
;     setup2:        2
;     sfix_fpp:      2
;     shut1:         2
;     sound:         2
;     sqr2:          2
;     sqra:          2
;     srch3:         2
;     store4:        2
;     stors1:        2
;     str11:         2
;     str21:         2
;     str30:         2
;     str32:         2
;     str42:         2
;     swap_eval:     2
;     tabit:         2
;     term0:         2
;     time0:         2
;     trap:          2
;     width:         2
;     wrch1:         2
;     wrrdf:         2
;     x4or5:         2
;     xeq_cpm:       2
;     abbr:          1
;     accs:          1
;     add1_eval:     1
;     ambig:         1
;     argue:         1
;     argue1:        1
;     argue2:        1
;     argue4:        1
;     argue5:        1
;     argue7:        1
;     array:         1
;     asc0:          1
;     asc1:          1
;     asm:           1
;     asm0:          1
;     asmb:          1
;     asmb1:         1
;     asn_fpp:       1
;     assem0:        1
;     assem1:        1
;     assem2:        1
;     assem3:        1
;     assem4:        1
;     assem5:        1
;     atend:         1
;     atn0:          1
;     atn1:          1
;     bad_fpp:       1
;     badhex:        1
;     bdc:           1
;     bdgcol:        1
;     bggcol:        1
;     bind1:         1
;     bit:           1
;     bmplot:        1
;     buffer:        1
;     call1:         1
;     call2:         1
;     carret:        1
;     cb:            1
;     chain0:        1
;     chkam1:        1
;     chko1:         1
;     chko2:         1
;     chkovf:        1
;     clear1:        1
;     cloop1:        1
;     clrlp:         1
;     clrscn:        1
;     clrtab:        1
;     cmpare:        1
;     cold:          1
;     con3:          1
;     con_fpp:       1
;     cons1:         1
;     cons2:         1
;     cons3:         1
;     copyf0:        1
;     copyf2:        1
;     copyf3:        1
;     cos0:          1
;     cpmerr:        1
;     cptext:        1
;     d2:            1
;     db:            1
;     defm1:         1
;     del1:          1
;     del2:          1
;     delet1:        1
;     device:        1
;     dim:           1
;     dim1:          1
;     dim2:          1
;     dim3:          1
;     dim5:          1
;     dir0:          1
;     dir2:          1
;     dir3:          1
;     dispat_eval:   1
;     dispat_fpp:    1
;     dispt0:        1
;     dispt2:        1
;     div0:          1
;     div1:          1
;     divc:          1
;     dospc:         1
;     dot:           1
;     dotab:         1
;     dotab1:        1
;     edput:         1
;     end:           1
;     error0_exec:   1
;     error1_main:   1
;     error2_main:   1
;     error3_main:   1
;     error4:        1
;     escc1:         1
;     escdis:        1
;     escset:        1
;     execin:        1
;     exists:        1
;     exit_exec:     1
;     exit_fpp:      1
;     exp0:          1
;     exp1:          1
;     exp2:          1
;     exp3:          1
;     exp3s3:        1
;     exp4:          1
;     expr0a:        1
;     expr0b:        1
;     expr1a:        1
;     expr2b:        1
;     expr2c:        1
;     expr2s:        1
;     expr3b:        1
;     expr3s:        1
;     expr4a:        1
;     expr5a:        1
;     ext_exec:      1
;     fadd3:         1
;     fadd4:         1
;     fcomp0:        1
;     fcomp1:        1
;     fcp1:          1
;     fgclr:         1
;     fill1:         1
;     fill_cpm:      1
;     find2:         1
;     find3:         1
;     find4:         1
;     find5:         1
;     findl1:        1
;     fix1:          1
;     floata:        1
;     fnchk:         1
;     fnend:         1
;     fnend0:        1
;     fnend1:        1
;     for1:          1
;     forchk:        1
;     forvar:        1
;     fpow1:         1
;     fsub:          1
;     g6:            1
;     g6hl:          1
;     get0:          1
;     get1:          1
;     getdat:        1
;     getex2:        1
;     getexp:        1
;     getext:        1
;     getime:        1
;     getpt1:        1
;     getptr:        1
;     gets:          1
;     getv0:         1
;     getv2:         1
;     getv3:         1
;     getv4:         1
;     getv5:         1
;     getv6:         1
;     getv8:         1
;     getv9:         1
;     getva:         1
;     getvx:         1
;     getvz:         1
;     getxy:         1
;     gosub1:        1
;     goto:          1
;     goto1:         1
;     goto2:         1
;     group2:        1
;     group4:        1
;     group5:        1
;     group7:        1
;     group8:        1
;     groupa:        1
;     groupb:        1
;     groupc:        1
;     groupd:        1
;     groupe:        1
;     groupf:        1
;     grpa:          1
;     grpc:          1
;     grpe:          1
;     hex1_cpm:      1
;     hex1_eval:     1
;     hex2_cpm:      1
;     hex2_eval:     1
;     hex_eval:      1
;     hexout:        1
;     hexst2:        1
;     hexsts:        1
;     icp1:          1
;     ieq1:          1
;     ige1:          1
;     igt1:          1
;     ile1:          1
;     ilt1:          1
;     imod:          1
;     incrdf:        1
;     incs1:         1
;     ind1:          1
;     ind3:          1
;     ine1:          1
;     inkey1:        1
;     inkey_cpm:     1
;     inkeys:        1
;     inpn2:         1
;     inpn3:         1
;     inpn4:         1
;     input1:        1
;     input2:        1
;     input4:        1
;     input5:        1
;     input6:        1
;     input9:        1
;     ins1:          1
;     insert:        1
;     instr2:        1
;     ipow0:         1
;     ipow1:         1
;     ipow2:         1
;     ipow3:         1
;     ipow4:         1
;     ipow5:         1
;     item1:         1
;     item2:         1
;     jpix:          1
;     keyget:        1
;     l0006:         1
;     ld8:           1
;     lda:           1
;     ldin:          1
;     ldop:          1
;     left1:         1
;     left2:         1
;     left3:         1
;     lefts:         1
;     let0:          1
;     lex0:          1
;     lex2:          1
;     lex3:          1
;     lex4:          1
;     lex5:          1
;     lexan3:        1
;     lexan4:        1
;     lexan5:        1
;     lexan6:        1
;     lexan7:        1
;     lexana:        1
;     lexanc:        1
;     lexand:        1
;     lexane:        1
;     lexanf:        1
;     limit:         1
;     line1s:        1
;     lines:         1
;     linnm1:        1
;     list7:         1
;     list8:         1
;     lista:         1
;     listb:         1
;     listc:         1
;     listit:        1
;     listo:         1
;     ln0:           1
;     ln1:           1
;     ln4:           1
;     ln_fpp:        1
;     lnzero:        1
;     load0_cpm:     1
;     load1_cpm:     1
;     load1_eval:    1
;     load_cpm:      1
;     loc0:          1
;     loc3:          1
;     loc5:          1
;     loc6:          1
;     local2:        1
;     locate:        1
;     locchk:        1
;     loop:          1
;     lout:          1
;     m3lp1:         1
;     m3lp2:         1
;     m3lp3:         1
;     minus:         1
;     misc:          1
;     mod48:         1
;     mod481:        1
;     mod483:        1
;     mod484:        1
;     mod485:        1
;     mode3:         1
;     mul0:          1
;     mul1:          1
;     mul161:        1
;     mul162:        1
;     mulb:          1
;     neg:           1
;     neg0:          1
;     negate_eval:   1
;     next:          1
;     next0:         1
;     next1:         1
;     noauto:        1
;     noboot:        1
;     nos1:          1
;     nosuch:        1
;     notfnd:        1
;     numbix:        1
;     offset:        1
;     on3:           1
;     onerr:         1
;     onproc:        1
;     op1:           1
;     open1:         1
;     open2:         1
;     open3:         1
;     opt_exec:      1
;     orc:           1
;     oscall:        1
;     oscli0:        1
;     oscli2:        1
;     oscli3:        1
;     oscli5:        1
;     osinit:        1
;     osl1:          1
;     oslin1:        1
;     osload:        1
;     oss1:          1
;     ossave:        1
;     oswait:        1
;     outch1:        1
;     outclr:        1
;     pad:           1
;     pair1_main:    1
;     parse:         1
;     pbcd0:         1
;     pbcd1:         1
;     pbcd2:         1
;     pbcd3:         1
;     pbcd4:         1
;     poly1:         1
;     pops1:         1
;     powr11:        1
;     powr12:        1
;     powr13:        1
;     print3:        1
;     print4:        1
;     print6:        1
;     print8:        1
;     print9:        1
;     printa:        1
;     prlino:        1
;     prntn2:        1
;     prntn3:        1
;     prntn4:        1
;     proc:          1
;     proc2:         1
;     proc3:         1
;     proc4:         1
;     proc5:         1
;     proc6:         1
;     prompt:        1
;     ptext1:        1
;     ptext_cpm:     1
;     purge:         1
;     pushs1:        1
;     putcsr:        1
;     putime:        1
;     putpt1:        1
;     putptr:        1
;     rand:          1
;     range2:        1
;     rdiv:          1
;     read0:         1
;     read1:         1
;     read2:         1
;     refil0:        1
;     refil1:        1
;     refill:        1
;     reglp:         1
;     renum1:        1
;     renum2:        1
;     renum3:        1
;     renum4:        1
;     renum5:        1
;     renum6:        1
;     renum7:        1
;     reset:         1
;     right1:        1
;     rnd1:          1
;     rnd2:          1
;     rnd3:          1
;     rnd4:          1
;     rnd5:          1
;     rnd6:          1
;     rnd7:          1
;     save1_cpm:     1
;     save1_eval:    1
;     savech:        1
;     savlo1_cpm:    1
;     savlo1_exec:   1
;     savlo2:        1
;     savlo5:        1
;     scp0:          1
;     scp1:          1
;     scp2:          1
;     scp3:          1
;     set1:          1
;     set2:          1
;     setop1:        1
;     setopt:        1
;     setup:         1
;     setup1:        1
;     shut0:         1
;     sign:          1
;     sin0:          1
;     sin1:          1
;     sin2:          1
;     sin3:          1
;     skip0:         1
;     space:         1
;     sptext:        1
;     sqr0:          1
;     sqr1:          1
;     sqr3:          1
;     sqrb:          1
;     srch1_eval:    1
;     srch1_exec:    1
;     srch2_eval:    1
;     srch2_exec:    1
;     stavar:        1
;     store5:        1
;     storei:        1
;     stors3:        1
;     stors5:        1
;     str0:          1
;     str1:          1
;     str10:         1
;     str13:         1
;     str14:         1
;     str15:         1
;     str20:         1
;     str23:         1
;     str24:         1
;     str25:         1
;     str27:         1
;     str2_eval:     1
;     str2_fpp:      1
;     str31:         1
;     str33:         1
;     str35:         1
;     str36:         1
;     str37:         1
;     str38:         1
;     str39:         1
;     str3a:         1
;     str4:          1
;     str41:         1
;     str43:         1
;     str44:         1
;     str47:         1
;     str_eval:      1
;     strin1:        1
;     strin2:        1
;     swap1:         1
;     table:         1
;     term:          1
;     test20:        1
;     test_cpm:      1
;     timevs_eval:   1
;     timevs_exec:   1
;     toggle:        1
;     token1:        1
;     toofar:        1
;     trace0:        1
;     trace1:        1
;     type1:         1
;     type_main:     1
;     typesc:        1
;     unstk:         1
;     unstk1:        1
;     upd1:          1
;     upd2:          1
;     update:        1
;     usr1:          1
;     val0:          1
;     val16:         1
;     vdpini:        1
;     vdu:           1
;     vdu2:          1
;     vdu3:          1
;     wait1:         1
;     warm0:         1
;     wontgo:        1
;     x10:           1
;     x10b:          1
;     x5:            1
;     xeq0_cpm:      1
;     xeq1_exec:     1
;     xeq2:          1
;     xeqr:          1
;     xtrac1:        1
;     xtract:        1

; Automatically generated labels:
;     c0fba
;     l0006
;     l005c
;     l0157

; Stats:
;
;     Total size (Code + Data) = 16128 bytes
;     Code                     = 12743 bytes (79%)
;     Data                     = 3385 bytes (21%)
;
;     Number of instructions   = 7139
;     Number of data bytes     = 1818 bytes
;     Number of data words     = 390 bytes
;     Number of string bytes   = 1177 bytes
;     Number of strings        = 225

