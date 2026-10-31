; Constants
ula_port    equ $fe

; Memory locations

; Printer buffer ($5b00-$5bff)
printer_buffer  equ $5b00

; System variables ($5c00-$5cb5)
kstate  equ $5c00
last_k  equ $5c08
repdel  equ $5c09
repper  equ $5c0a
defadd  equ $5c0b
k_data  equ $5c0d
tvdata  equ $5c0e
strms   equ $5c10
chars   equ $5c36
rasp    equ $5c38
pip     equ $5c39
err_nr  equ $5c3a
flags   equ $5c3b
tv_flag equ $5c3c
err_sp  equ $5c3d
list_sp equ $5c3f
mode    equ $5c41
newppc  equ $5c42
nsppc   equ $5c44
ppc     equ $5c45
subppc  equ $5c47
bordcr  equ $5c48
e_ppc   equ $5c49
vars    equ $5c4b
dest    equ $5c4d
chans   equ $5c4f
curchl  equ $5c51
prog    equ $5c53
nxtlin  equ $5c55
datadd  equ $5c57
e_line  equ $5c59
k_cur   equ $5c5b
ch_add  equ $5c5d
x_ptr   equ $5c5f
worksp  equ $5c61
stkbot  equ $5c63
stkend  equ $5c65
breg    equ $5c67
mem     equ $5c68
flags2  equ $5c6a
df_sz   equ $5c6b
s_top   equ $5c6c
oldppc  equ $5c6e
osppc   equ $5c70
flagx   equ $5c71
strlen  equ $5c72
t_addr  equ $5c74
seed    equ $5c76
frames  equ $5c78
udg     equ $5c7b
coords  equ $5c7d
p_posn  equ $5c7f
pr_cc   equ $5c80
echo_e  equ $5c82
df_cc   equ $5c84
df_ccl  equ $5c86
s_posn  equ $5c88
s_posnl equ $5c8a
scr_ct  equ $5c8c
attr_p  equ $5c8d
attr_t  equ $5c8f
p_flag  equ $5c91
membot  equ $5c92
ramtop  equ $5cb2
p_ramt  equ $5cb4

    org $00

; $00 referenced 1 time by $07
pydis_start:
_start:
    di                                                                ; 0000: f3          .
    xor a                                                             ; 0001: af          .
    jp ram_check                                                      ; 0002: c3 a7 03    ...

    db 0, 0                                                           ; 0005: 00 00       ..

l0007:
    rst $00                                                           ; 0007: c7          .
; $08 referenced 44 times by $046c, $04c0, $0552, $0642, $0670, $0806, $09b9, $0bb9, $0bd9, $0c86, $0d00, $15c4, $15e4, $160e, $1725, $1765, $18af, $1944, $1b7b, $1bae, $1bec, $1bfe, $1c2e, $1c8a, $1cee, $1d84, $1dd8, $1e08, $1e9f, $1eda, $1f38, $21ce, $21d4, $2244, $24f9, $2812, $288b, $2a20, $31ad, $34c3, $35af, $36d7, $36ee, $391b
_error_1:
    ld hl,(ch_add)                                                    ; 0008: 2a 5d 5c    *]\
    ld (x_ptr),hl                                                     ; 000b: 22 5f 5c    "_\
    jr l0013                                                          ; 000e: 18 03       ..

; $10 referenced 23 times by $07ad, $07b6, $0c3d, $134c, $134f, $1359, $1838, $18a3, $1928, $1ffa, $201e, $2020, $2022, $2042, $205e, $220d, $220f, $2df0, $2df6, $2f64, $2f75, $2f85, $39ca
_print_a:
    jp print_sp                                                       ; 0010: c3 f2 15    ...

; $13 referenced 1 time by $0e
l0013:
    ld (k_cur),hl                                                     ; 0013: 22 5b 5c    "[\
    jr error_2                                                        ; 0016: 18 3b       .;

; $18 referenced 54 times by $0652, $06e4, $09a1, $09a8, $09af, $09e5, $12db, $1805, $180b, $1937, $1b32, $1b6c, $1b6f, $1bf4, $1cd1, $1df5, $1e10, $1e1e, $1fdf, $1ffc, $204e, $20ce, $21bf, $21ca, $21e6, $2320, $2382, $24fb, $252a, $25b3, $2695, $26b5, $2712, $273a, $27dc, $2879, $2886, $28b6, $2935, $2942, $29aa, $29ba, $29c4, $29e0, $29f2, $2a1b, $2a3c, $2a64, $2a72, $2a8d, $2c41, $2cda, $35b1, $3abc
_get_ch:
    ld hl,(ch_add)                                                    ; 0018: 2a 5d 5c    *]\
    ld a,(hl)                                                         ; 001b: 7e          ~
; $1c referenced 1 time by $23
test_sp:
    call l007d                                                        ; 001c: cd 7d 00    .}.
    ret nc                                                            ; 001f: d0          .
; $20 referenced 90 times by $065f, $0693, $0698, $06ac, $06cf, $06f5, $072a, $09bb, $09c2, $0ec5, $0eed, $1819, $1946, $1959, $1992, $1a02, $1b28, $1b42, $1b74, $1c79, $1c81, $1d07, $1d73, $1d79, $1d7c, $1dec, $1e34, $1f73, $1f7c, $1f81, $1f8d, $1f93, $1fa3, $1faa, $1faf, $2012, $2067, $2074, $20ca, $20d4, $20dc, $21e1, $21fa, $2326, $238d, $2522, $25af, $25e8, $25f1, $2630, $2637, $266e, $2678, $2681, $270e, $2720, $2791, $27c2, $27c9, $27cf, $27d4, $27e1, $27e9, $27f7, $27fb, $2801, $2802, $287e, $289a, $289b, $28a7, $28c1, $28db, $28de, $2948, $29d6, $29eb, $2a22, $2a48, $2a58, $2a82, $2c2e, $2c4a, $2ca2, $2cc3, $2ccb, $2ce8, $2cf4, $2cfe, $3927
_next_ch:
    call ch_add_1                                                     ; 0020: cd 74 00    .t.
    jr test_sp                                                        ; 0023: 18 f7       ..

l0025:
    db "321"                                                          ; 0025: 33 32 31    321

; $28 referenced 79 times by $03f8, $0438, $043e, $044a, $0df5, $1736, $1cea, $1cf6, $1d13, $1d16, $1d35, $1dbd, $1dda, $232d, $2336, $233b, $2340, $2348, $2352, $235a, $2394, $23b8, $23f3, $23fe, $2425, $243a, $2447, $2456, $245f, $246a, $2474, $247d, $249b, $2604, $262c, $2756, $2b5a, $2cd2, $2cd5, $2ce0, $2d37, $2d3c, $2d44, $2d5c, $2d65, $2d74, $2d7b, $2da2, $2da8, $2dad, $2dcb, $2de3, $2df7, $2e01, $2e24, $2e3a, $2ecb, $2f30, $3561, $3675, $3684, $3699, $36e2, $36e7, $36f7, $370e, $3755, $377b, $3786, $37b3, $37c1, $37fc, $380c, $3813, $3832, $3846, $3ad6, $3ad9, $3adc
_fp_calc:
    jp calculate                                                      ; 0028: c3 62 33    .b3

l002b:
    db $53, $45                                                       ; 002b: 53 45       SE

; $2d referenced 3 times by $2564, $35a9, $35f3
bc_spaces1:
    ld bc,1                                                           ; 002d: 01 01 00    ...
; $30 referenced 10 times by $0621, $08be, $211c, $25c8, $265b, $2b83, $3583, $35bd, $3632, $3870
_bc_spaces:
    push bc                                                           ; 0030: c5          .
    ld hl,(worksp)                                                    ; 0031: 2a 61 5c    *a\
    push hl                                                           ; 0034: e5          .
    jp reserve                                                        ; 0035: c3 9e 16    ...

_interrupt:
    push hl                                                           ; 0038: e5          .
    push af                                                           ; 0039: f5          .
    ld hl,$5c78                                                       ; 003a: 21 78 5c    !x\
    inc (hl)                                                          ; 003d: 34          4
    jr nz,anyi                                                        ; 003e: 20 06        .
    inc l                                                             ; 0040: 2c          ,
    inc (hl)                                                          ; 0041: 34          4
    jr nz,anyi                                                        ; 0042: 20 02        .
    inc l                                                             ; 0044: 2c          ,
    inc (hl)                                                          ; 0045: 34          4
; $46 referenced 2 times by $3e, $42
anyi:
    push de                                                           ; 0046: d5          .
    push bc                                                           ; 0047: c5          .
    call l02bf                                                        ; 0048: cd bf 02    ...
    pop bc                                                            ; 004b: c1          .
    pop de                                                            ; 004c: d1          .
    pop af                                                            ; 004d: f1          .
    pop hl                                                            ; 004e: e1          .
    ei                                                                ; 004f: fb          .
    ret                                                               ; 0050: c9          .

l0051:
    db $4a, $47                                                       ; 0051: 4a 47       JG

; $53 referenced 1 time by $16
error_2:
    pop hl                                                            ; 0053: e1          .
    ld l,(hl)                                                         ; 0054: 6e          n
; $55 referenced 1 time by $1f17
error_3:
    ld (iy+err_nr - err_nr),l                                         ; 0055: fd 75 00    .u.
    ld sp,(err_sp)                                                    ; 0058: ed 7b 3d... .{=
    jp set_mem                                                        ; 005c: c3 c5 16    ...

; $5f referenced 1 time by $0d6b
l005f:
    set 0,(iy+flags - err_nr)                                         ; 005f: fd cb 01... ...
    jp l0daf                                                          ; 0063: c3 af 0d    ...

nmi:
    push af                                                           ; 0066: f5          .
    push hl                                                           ; 0067: e5          .
    ld hl,(printer_buffer+254)                                        ; 0068: 2a fe 5b    *.[
    ld a,h                                                            ; 006b: 7c          |
    or l                                                              ; 006c: b5          .
    jr z,nmi_ret                                                      ; 006d: 28 01       (.
    jp (hl)                                                           ; 006f: e9          .

; $70 referenced 1 time by $6d
nmi_ret:
    pop hl                                                            ; 0070: e1          .
    pop af                                                            ; 0071: f1          .
    retn                                                              ; 0072: ed 45       .E

; $74 referenced 4 times by $20, $250f, $251c, $2d4a
ch_add_1:
    ld hl,(ch_add)                                                    ; 0074: 2a 5d 5c    *]\
; $77 referenced 2 times by $1e0a, $26b0
cursor_so:
    inc hl                                                            ; 0077: 23          #
; $78 referenced 1 time by $1e1b
temp_ptr:
    ld (ch_add),hl                                                    ; 0078: 22 5d 5c    "]\
reentry:
    ld a,(hl)                                                         ; 007b: 7e          ~
    ret                                                               ; 007c: c9          .

; $7d referenced 1 time by $1c
l007d:
    cp $20                                                            ; 007d: fe 20       .
    scf                                                               ; 007f: 37          7
    ret z                                                             ; 0080: c8          .
    cp $18                                                            ; 0081: fe 18       ..
    ret nc                                                            ; 0083: d0          .
    cp $0d                                                            ; 0084: fe 0d       ..
    ret z                                                             ; 0086: c8          .
    cp 6                                                              ; 0087: fe 06       ..
    ccf                                                               ; 0089: 3f          ?
    ret nc                                                            ; 008a: d0          .
    cp $10                                                            ; 008b: fe 10       ..
    ret c                                                             ; 008d: d8          .
    inc hl                                                            ; 008e: 23          #
    cp $16                                                            ; 008f: fe 16       ..
    jr c,l0094                                                        ; 0091: 38 01       8.
    inc hl                                                            ; 0093: 23          #
; $94 referenced 1 time by $91
l0094:
    scf                                                               ; 0094: 37          7
    ld (ch_add),hl                                                    ; 0095: 22 5d 5c    "]\
    ret                                                               ; 0098: c9          .

; $99 referenced 1 time by $100b
l0099:
    ld a,(hl)                                                         ; 0099: 7e          ~
    cp $0d                                                            ; 009a: fe 0d       ..
    ret z                                                             ; 009c: c8          .
    call l100e                                                        ; 009d: cd 0e 10    ...
    cp $15                                                            ; 00a0: fe 15       ..
    ret nc                                                            ; 00a2: d0          .
    cp $10                                                            ; 00a3: fe 10       ..
    jp nc,l100e                                                       ; 00a5: d2 0e 10    ...
    ret                                                               ; 00a8: c9          .

k_token:
    db "RN", $80 + 'D'                                                ; 00a9: 52 4e c4    RN.
    db "INKEY", $80 + '$'                                             ; 00ac: 49 4e 4b... INK
    db "P", $80 + 'I'                                                 ; 00b2: 50 c9       P.
    db "F", $80 + 'N'                                                 ; 00b4: 46 ce       F.
    db "POIN", $80 + 'T'                                              ; 00b6: 50 4f 49... POI
    db "SCREEN", $80 + '$'                                            ; 00bb: 53 43 52... SCR
    db "ATT", $80 + 'R'                                               ; 00c2: 41 54 54... ATT
    db "A", $80 + 'T'                                                 ; 00c6: 41 d4       A.
    db "TA", $80 + 'B'                                                ; 00c8: 54 41 c2    TA.
    db "VAL", $80 + '$'                                               ; 00cb: 56 41 4c... VAL
    db "COD", $80 + 'E'                                               ; 00cf: 43 4f 44... COD
    db "VA", $80 + 'L'                                                ; 00d3: 56 41 cc    VA.
    db "LE", $80 + 'N'                                                ; 00d6: 4c 45 ce    LE.
    db "SI", $80 + 'N'                                                ; 00d9: 53 49 ce    SI.
    db "CO", $80 + 'S'                                                ; 00dc: 43 4f d3    CO.
    db "TA", $80 + 'N'                                                ; 00df: 54 41 ce    TA.
    db "AS", $80 + 'N'                                                ; 00e2: 41 53 ce    AS.
    db "AC", $80 + 'S'                                                ; 00e5: 41 43 d3    AC.
    db "AT", $80 + 'N'                                                ; 00e8: 41 54 ce    AT.
    db "L", $80 + 'N'                                                 ; 00eb: 4c ce       L.
    db "EX", $80 + 'P'                                                ; 00ed: 45 58 d0    EX.
    db "IN", $80 + 'T'                                                ; 00f0: 49 4e d4    IN.
    db "SQ", $80 + 'R'                                                ; 00f3: 53 51 d2    SQ.
    db "SG", $80 + 'N'                                                ; 00f6: 53 47 ce    SG.
    db "AB", $80 + 'S'                                                ; 00f9: 41 42 d3    AB.
    db "PEE", $80 + 'K'                                               ; 00fc: 50 45 45... PEE
    db "I", $80 + 'N'                                                 ; 0100: 49 ce       I.
    db "US", $80 + 'R'                                                ; 0102: 55 53 d2    US.
    db "STR", $80 + '$'                                               ; 0105: 53 54 52... STR
    db "CHR", $80 + '$'                                               ; 0109: 43 48 52... CHR
    db "NO", $80 + 'T'                                                ; 010d: 4e 4f d4    NO.
    db "BI", $80 + 'N'                                                ; 0110: 42 49 ce    BI.
    db "O", $80 + 'R'                                                 ; 0113: 4f d2       O.
    db "AN", $80 + 'D'                                                ; 0115: 41 4e c4    AN.
    db "<", $80 + '='                                                 ; 0118: 3c bd       <.
    db ">", $80 + '='                                                 ; 011a: 3e bd       >.
    db "<", $80 + '>'                                                 ; 011c: 3c be       <.
    db "LIN", $80 + 'E'                                               ; 011e: 4c 49 4e... LIN
    db "THE", $80 + 'N'                                               ; 0122: 54 48 45... THE
    db "T", $80 + 'O'                                                 ; 0126: 54 cf       T.
    db "STE", $80 + 'P'                                               ; 0128: 53 54 45... STE
    db "DEF F", $80 + 'N'                                             ; 012c: 44 45 46... DEF
    db "DI", $80 + 'R'                                                ; 0132: 44 49 d2    DI.
    db "FORMA", $80 + 'T'                                             ; 0135: 46 4f 52... FOR
    db "MOV", $80 + 'E'                                               ; 013b: 4d 4f 56... MOV
    db "ERAS", $80 + 'E'                                              ; 013f: 45 52 41... ERA
    db "OPEN ", $80 + '#'                                             ; 0144: 4f 50 45... OPE
    db "CLOSE ", $80 + '#'                                            ; 014a: 43 4c 4f... CLO
    db "MERG", $80 + 'E'                                              ; 0151: 4d 45 52... MER
    db "VERIF", $80 + 'Y'                                             ; 0156: 56 45 52... VER
    db "BEE", $80 + 'P'                                               ; 015c: 42 45 45... BEE
    db "CIRCL", $80 + 'E'                                             ; 0160: 43 49 52... CIR
    db "PE", $80 + 'N'                                                ; 0166: 50 45 ce    PE.
    db "PAPE", $80 + 'R'                                              ; 0169: 50 41 50... PAP
    db "FLAS", $80 + 'H'                                              ; 016e: 46 4c 41... FLA
    db "BRIGH", $80 + 'T'                                             ; 0173: 42 52 49... BRI
    db "INVERS", $80 + 'E'                                            ; 0179: 49 4e 56... INV
    db "OVE", $80 + 'R'                                               ; 0180: 4f 56 45... OVE
    db "OU", $80 + 'T'                                                ; 0184: 4f 55 d4    OU.
    db "LPRIN", $80 + 'T'                                             ; 0187: 4c 50 52... LPR
    db "LLIS", $80 + 'T'                                              ; 018d: 4c 4c 49... LLI
    db "STO", $80 + 'P'                                               ; 0192: 53 54 4f... STO
    db "REA", $80 + 'D'                                               ; 0196: 52 45 41... REA
    db "DAT", $80 + 'A'                                               ; 019a: 44 41 54... DAT
    db "RESTOR", $80 + 'E'                                            ; 019e: 52 45 53... RES
    db "NE", $80 + 'W'                                                ; 01a5: 4e 45 d7    NE.
    db "BORDE", $80 + 'R'                                             ; 01a8: 42 4f 52... BOR
    db "CONTINU", $80 + 'E'                                           ; 01ae: 43 4f 4e... CON
    db "DI", $80 + 'M'                                                ; 01b6: 44 49 cd    DI.
    db "RE", $80 + 'M'                                                ; 01b9: 52 45 cd    RE.
    db "FO", $80 + 'R'                                                ; 01bc: 46 4f d2    FO.
    db "GOT", $80 + 'O'                                               ; 01bf: 47 4f 54... GOT
    db "GOSU", $80 + 'B'                                              ; 01c3: 47 4f 53... GOS
    db "INPU", $80 + 'T'                                              ; 01c8: 49 4e 50... INP
    db "LOA", $80 + 'D'                                               ; 01cd: 4c 4f 41... LOA
    db "LIS", $80 + 'T'                                               ; 01d1: 4c 49 53... LIS
    db "LE", $80 + 'T'                                                ; 01d5: 4c 45 d4    LE.
    db "PAUS", $80 + 'E'                                              ; 01d8: 50 41 55... PAU
    db "NEX", $80 + 'T'                                               ; 01dd: 4e 45 58... NEX
    db "POK", $80 + 'E'                                               ; 01e1: 50 4f 4b... POK
    db "PRIN", $80 + 'T'                                              ; 01e5: 50 52 49... PRI
    db "PLO", $80 + 'T'                                               ; 01ea: 50 4c 4f... PLO
    db "RU", $80 + 'N'                                                ; 01ee: 52 55 ce    RU.
    db "SAV", $80 + 'E'                                               ; 01f1: 53 41 56... SAV
    db "RANDOMIZ", $80 + 'E'                                          ; 01f5: 52 41 4e... RAN
    db "I", $80 + 'F'                                                 ; 01fe: 49 c6       I.
    db "CL", $80 + 'S'                                                ; 0200: 43 4c d3    CL.
    db "DRA", $80 + 'W'                                               ; 0203: 44 52 41... DRA
    db "CLEA", $80 + 'R'                                              ; 0207: 43 4c 45... CLE
    db "RETUR", $80 + 'N'                                             ; 020c: 52 45 54... RET
    db "CAL", $80 + 'L'                                               ; 0212: 43 41 4c... CAL
    db "DELET", $80 + 'E'                                             ; 0216: 44 45 4c... DEL
    db "EDI", $80 + 'T'                                               ; 021c: 45 44 49... EDI
    db "RENU", $80 + 'M'                                              ; 0220: 52 45 4e... REN
    db "PALETT", $80 + 'E'                                            ; 0225: 50 41 4c... PAL
    db "SOUN", $80 + 'D'                                              ; 022c: 53 4f 55... SOU
    db "ON ERRO", $80 + 'R'                                           ; 0231: 4f 4e 20... ON
k_unshifted:
    db "BHY65TGVNJU74RFCMKI83EDX", $0e, "LO92WSZ ", $0d, "P01QA"      ; 0239: 42 48 59... BHY
k_shifted:
    db $0c, 7, 6, 4, 5, 8, $0a, $0b, 9, $0f                           ; 0260: 0c 07 06... ...
k_function:
    db "~*?\\", $f7, "{}^", $7f, "-+=.,;\"", $ef, "<|>]/", $af, "`[:" ; 026a: 7e 2a 3f... ~*?
k_graphic:
    db "_!@#$%&'()"                                                   ; 0284: 5f 21 40... _!@

; $028e referenced 2 times by $02bf, $2646
keyboard:
    ld l,$2f                                                          ; 028e: 2e 2f       ./
    ld de,$ffff                                                       ; 0290: 11 ff ff    ...
    ld bc,$fefe                                                       ; 0293: 01 fe fe    ...
; $0296 referenced 1 time by $02ae
l0296:
    in a,(c)                                                          ; 0296: ed 78       .x
    cpl                                                               ; 0298: 2f          /
    and $1f                                                           ; 0299: e6 1f       ..
    jr z,l02ab                                                        ; 029b: 28 0e       (.
    ld h,a                                                            ; 029d: 67          g
    ld a,l                                                            ; 029e: 7d          }
; $029f referenced 1 time by $02a9
l029f:
    inc d                                                             ; 029f: 14          .
    ret nz                                                            ; 02a0: c0          .
; $02a1 referenced 1 time by $02a5
l02a1:
    sub 8                                                             ; 02a1: d6 08       ..
    srl h                                                             ; 02a3: cb 3c       .<
    jr nc,l02a1                                                       ; 02a5: 30 fa       0.
    ld d,e                                                            ; 02a7: 53          S
    ld e,a                                                            ; 02a8: 5f          _
    jr nz,l029f                                                       ; 02a9: 20 f4        .
; $02ab referenced 1 time by $029b
l02ab:
    dec l                                                             ; 02ab: 2d          -
    rlc b                                                             ; 02ac: cb 00       ..
    jr c,l0296                                                        ; 02ae: 38 e6       8.
    ld a,d                                                            ; 02b0: 7a          z
    inc a                                                             ; 02b1: 3c          <
    ret z                                                             ; 02b2: c8          .
    cp $28                                                            ; 02b3: fe 28       .(
    ret z                                                             ; 02b5: c8          .
    cp $19                                                            ; 02b6: fe 19       ..
    ret z                                                             ; 02b8: c8          .
    ld a,e                                                            ; 02b9: 7b          {
    ld e,d                                                            ; 02ba: 5a          Z
    ld d,a                                                            ; 02bb: 57          W
    cp $18                                                            ; 02bc: fe 18       ..
    ret                                                               ; 02be: c9          .

; $02bf referenced 1 time by $48
l02bf:
    call keyboard                                                     ; 02bf: cd 8e 02    ...
    ret nz                                                            ; 02c2: c0          .
    ld hl,$5c00                                                       ; 02c3: 21 00 5c    !.\
; $02c6 referenced 1 time by $02d6
l02c6:
    bit 7,(hl)                                                        ; 02c6: cb 7e       .~
    jr nz,l02d1                                                       ; 02c8: 20 07        .
    inc hl                                                            ; 02ca: 23          #
    dec (hl)                                                          ; 02cb: 35          5
    dec hl                                                            ; 02cc: 2b          +
    jr nz,l02d1                                                       ; 02cd: 20 02        .
    ld (hl),$ff                                                       ; 02cf: 36 ff       6.
; $02d1 referenced 2 times by $02c8, $02cd
l02d1:
    ld a,l                                                            ; 02d1: 7d          }
    ld hl,$5c04                                                       ; 02d2: 21 04 5c    !.\
    cp l                                                              ; 02d5: bd          .
    jr nz,l02c6                                                       ; 02d6: 20 ee        .
    call l031e                                                        ; 02d8: cd 1e 03    ...
    ret nc                                                            ; 02db: d0          .
    ld hl,$5c00                                                       ; 02dc: 21 00 5c    !.\
    cp (hl)                                                           ; 02df: be          .
    jr z,l0310                                                        ; 02e0: 28 2e       (.
    ex de,hl                                                          ; 02e2: eb          .
    ld hl,$5c04                                                       ; 02e3: 21 04 5c    !.\
    cp (hl)                                                           ; 02e6: be          .
    jr z,l0310                                                        ; 02e7: 28 27       ('
    bit 7,(hl)                                                        ; 02e9: cb 7e       .~
    jr nz,l02f1                                                       ; 02eb: 20 04        .
    ex de,hl                                                          ; 02ed: eb          .
    bit 7,(hl)                                                        ; 02ee: cb 7e       .~
    ret z                                                             ; 02f0: c8          .
; $02f1 referenced 1 time by $02eb
l02f1:
    ld (hl),a                                                         ; 02f1: 77          w
    ld e,a                                                            ; 02f2: 5f          _
    inc hl                                                            ; 02f3: 23          #
    ld (hl),5                                                         ; 02f4: 36 05       6.
    ld a,(repdel)                                                     ; 02f6: 3a 09 5c    :.\
    inc hl                                                            ; 02f9: 23          #
    ld (hl),a                                                         ; 02fa: 77          w
    inc hl                                                            ; 02fb: 23          #
    ld d,(iy+flags - err_nr)                                          ; 02fc: fd 56 01    .V.
    ld c,(iy+mode - err_nr)                                           ; 02ff: fd 4e 07    .N.
    push hl                                                           ; 0302: e5          .
    call l0333                                                        ; 0303: cd 33 03    .3.
    pop hl                                                            ; 0306: e1          .
    ld (hl),a                                                         ; 0307: 77          w
; $0308 referenced 1 time by $031c
l0308:
    set 5,(iy+flags - err_nr)                                         ; 0308: fd cb 01... ...
    ld (last_k),a                                                     ; 030c: 32 08 5c    2.\
    ret                                                               ; 030f: c9          .

; $0310 referenced 2 times by $02e0, $02e7
l0310:
    inc hl                                                            ; 0310: 23          #
    ld (hl),5                                                         ; 0311: 36 05       6.
    inc hl                                                            ; 0313: 23          #
    dec (hl)                                                          ; 0314: 35          5
    ret nz                                                            ; 0315: c0          .
    ld a,(repper)                                                     ; 0316: 3a 0a 5c    :.\
    ld (hl),a                                                         ; 0319: 77          w
    inc hl                                                            ; 031a: 23          #
    ld a,(hl)                                                         ; 031b: 7e          ~
    jr l0308                                                          ; 031c: 18 ea       ..

; $031e referenced 2 times by $02d8, $264d
l031e:
    ld b,d                                                            ; 031e: 42          B
    ld a,e                                                            ; 031f: 7b          {
    ld d,0                                                            ; 0320: 16 00       ..
    cp $27                                                            ; 0322: fe 27       .'
    ret nc                                                            ; 0324: d0          .
    cp $18                                                            ; 0325: fe 18       ..
    jr nz,l032c                                                       ; 0327: 20 03        .
    bit 7,b                                                           ; 0329: cb 78       .x
    ret nz                                                            ; 032b: c0          .
; $032c referenced 1 time by $0327
l032c:
    ld hl,$0239                                                       ; 032c: 21 39 02    !9.
    add hl,de                                                         ; 032f: 19          .
    scf                                                               ; 0330: 37          7
    ld a,(hl)                                                         ; 0331: 7e          ~
    ret                                                               ; 0332: c9          .

; $0333 referenced 2 times by $0303, $2654
l0333:
    ld a,e                                                            ; 0333: 7b          {
    cp $3a                                                            ; 0334: fe 3a       .:
    jr c,l035f                                                        ; 0336: 38 27       8'
    dec c                                                             ; 0338: 0d          .
    jp m,l034b                                                        ; 0339: fa 4b 03    .K.
    jr z,l034b                                                        ; 033c: 28 0d       (.
    add a,$4f                                                         ; 033e: c6 4f       .O
    cp $a5                                                            ; 0340: fe a5       ..
    ret c                                                             ; 0342: d8          .
    add a,$0d                                                         ; 0343: c6 0d       ..
    call add_char                                                     ; 0345: cd 81 0f    ...
    ld a,$0f                                                          ; 0348: 3e 0f       >.
    ret                                                               ; 034a: c9          .

; $034b referenced 2 times by $0339, $033c
l034b:
    ld hl,$0229                                                       ; 034b: 21 29 02    !).
    bit 0,b                                                           ; 034e: cb 40       .@
    jr z,l03a1                                                        ; 0350: 28 4f       (O
    bit 3,(iy+flags2 - err_nr)                                        ; 0352: fd cb 30... ..0
    jr z,l035a                                                        ; 0356: 28 02       (.
    xor $20                                                           ; 0358: ee 20       .
; $035a referenced 1 time by $0356
l035a:
    inc b                                                             ; 035a: 04          .
    ret nz                                                            ; 035b: c0          .
    xor $20                                                           ; 035c: ee 20       .
    ret                                                               ; 035e: c9          .

; $035f referenced 1 time by $0336
l035f:
    cp $30                                                            ; 035f: fe 30       .0
    ret c                                                             ; 0361: d8          .
    dec c                                                             ; 0362: 0d          .
    jp m,l0395                                                        ; 0363: fa 95 03    ...
    jr nz,l0381                                                       ; 0366: 20 19        .
    ld hl,$0254                                                       ; 0368: 21 54 02    !T.
    bit 5,b                                                           ; 036b: cb 68       .h
    jr z,l03a1                                                        ; 036d: 28 32       (2
    cp $38                                                            ; 036f: fe 38       .8
    jr nc,l037a                                                       ; 0371: 30 07       0.
    sub $20                                                           ; 0373: d6 20       .
    inc b                                                             ; 0375: 04          .
    ret z                                                             ; 0376: c8          .
    add a,8                                                           ; 0377: c6 08       ..
    ret                                                               ; 0379: c9          .

; $037a referenced 1 time by $0371
l037a:
    sub $36                                                           ; 037a: d6 36       .6
    inc b                                                             ; 037c: 04          .
    ret z                                                             ; 037d: c8          .
    add a,$fe                                                         ; 037e: c6 fe       ..
    ret                                                               ; 0380: c9          .

; $0381 referenced 1 time by $0366
l0381:
    ld hl,$0230                                                       ; 0381: 21 30 02    !0.
    cp $39                                                            ; 0384: fe 39       .9
    jr z,l03a1                                                        ; 0386: 28 19       (.
    cp $30                                                            ; 0388: fe 30       .0
    jr z,l03a1                                                        ; 038a: 28 15       (.
    and 7                                                             ; 038c: e6 07       ..
    add a,$80                                                         ; 038e: c6 80       ..
    inc b                                                             ; 0390: 04          .
    ret z                                                             ; 0391: c8          .
    xor $0f                                                           ; 0392: ee 0f       ..
    ret                                                               ; 0394: c9          .

; $0395 referenced 1 time by $0363
l0395:
    inc b                                                             ; 0395: 04          .
    ret z                                                             ; 0396: c8          .
    bit 5,b                                                           ; 0397: cb 68       .h
    ld hl,$0230                                                       ; 0399: 21 30 02    !0.
    jr nz,l03a1                                                       ; 039c: 20 03        .
    ld hl,$0254                                                       ; 039e: 21 54 02    !T.
; $03a1 referenced 5 times by $0350, $036d, $0386, $038a, $039c
l03a1:
    ld d,0                                                            ; 03a1: 16 00       ..
    add hl,de                                                         ; 03a3: 19          .
    ld a,(hl)                                                         ; 03a4: 7e          ~
    ret                                                               ; 03a5: c9          .

    db $ff                                                            ; 03a6: ff          .

; $03a7 referenced 1 time by $02
ram_check:
    ld de,$ffff                                                       ; 03a7: 11 ff ff    ...
    ld (de),a                                                         ; 03aa: 12          .
    ld a,(de)                                                         ; 03ab: 1a          .
    and a                                                             ; 03ac: a7          .
    jr z,l03b2                                                        ; 03ad: 28 03       (.
    xor a                                                             ; 03af: af          .
    ld d,$7f                                                          ; 03b0: 16 7f       ..
; $03b2 referenced 1 time by $03ad
l03b2:
    jp l11cf                                                          ; 03b2: c3 cf 11    ...

; $03b5 referenced 3 times by $0469, $0f44, $1170
l03b5:
    di                                                                ; 03b5: f3          .
    ld a,l                                                            ; 03b6: 7d          }
    srl l                                                             ; 03b7: cb 3d       .=
    srl l                                                             ; 03b9: cb 3d       .=
    cpl                                                               ; 03bb: 2f          /
    and 3                                                             ; 03bc: e6 03       ..
    ld b,0                                                            ; 03be: 06 00       ..
    ld c,a                                                            ; 03c0: 4f          O
    ld ix,$03d1                                                       ; 03c1: dd 21 d1... .!.
    add ix,bc                                                         ; 03c5: dd 09       ..
    ld a,(bordcr)                                                     ; 03c7: 3a 48 5c    :H\
    and $38                                                           ; 03ca: e6 38       .8
    rrca                                                              ; 03cc: 0f          .
    rrca                                                              ; 03cd: 0f          .
    rrca                                                              ; 03ce: 0f          .
    or 8                                                              ; 03cf: f6 08       ..
l03d1:
    nop                                                               ; 03d1: 00          .
    nop                                                               ; 03d2: 00          .
    nop                                                               ; 03d3: 00          .
    inc c                                                             ; 03d4: 0c          .
    inc b                                                             ; 03d5: 04          .
; $03d6 referenced 2 times by $03d7, $03dc
l03d6:
    dec c                                                             ; 03d6: 0d          .
    jr nz,l03d6                                                       ; 03d7: 20 fd        .
    ld c,$3f                                                          ; 03d9: 0e 3f       .?
    dec b                                                             ; 03db: 05          .
    jp nz,l03d6                                                       ; 03dc: c2 d6 03    ...
    xor $10                                                           ; 03df: ee 10       ..
    out (ula_port),a                                                  ; 03e1: d3 fe       ..
    ld c,a                                                            ; 03e3: 4f          O
    ld b,h                                                            ; 03e4: 44          D
    bit 4,a                                                           ; 03e5: cb 67       .g
    jr nz,l03f2                                                       ; 03e7: 20 09        .
    ld a,d                                                            ; 03e9: 7a          z
    or e                                                              ; 03ea: b3          .
    jr z,l03f6                                                        ; 03eb: 28 09       (.
    dec de                                                            ; 03ed: 1b          .
    ld a,c                                                            ; 03ee: 79          y
    ld c,l                                                            ; 03ef: 4d          M
    jp (ix)                                                           ; 03f0: dd e9       ..

; $03f2 referenced 1 time by $03e7
l03f2:
    ld c,l                                                            ; 03f2: 4d          M
    inc c                                                             ; 03f3: 0c          .
    jp (ix)                                                           ; 03f4: dd e9       ..

; $03f6 referenced 1 time by $03eb
l03f6:
    ei                                                                ; 03f6: fb          .
    ret                                                               ; 03f7: c9          .

l03f8:
    rst $28                                                           ; 03f8: ef          .
    db $31                                                            ; 03f9: 31          1  ; duplicate
    db $27                                                            ; 03fa: 27          '  ; int
    db $c0                                                            ; 03fb: c0          .  ; st-mem-0
    db 3                                                              ; 03fc: 03          .  ; subtract
    db $34                                                            ; 03fd: 34          4  ; stk-data
    db $ec, $6c, $98, $1f, $f5                                        ; 03fe: ec 6c 98... .l. ; 0.05776226505
    db 4                                                              ; 0403: 04          .  ; multiply
    db $a1                                                            ; 0404: a1          .  ; stk-one
    db $0f                                                            ; 0405: 0f          .  ; addition
    db $38                                                            ; 0406: 38          8  ; end-calc

    ld hl,$5c92                                                       ; 0407: 21 92 5c    !.\
    ld a,(hl)                                                         ; 040a: 7e          ~
    and a                                                             ; 040b: a7          .
    jr nz,ioorerr                                                     ; 040c: 20 5e        ^
    inc hl                                                            ; 040e: 23          #
    ld c,(hl)                                                         ; 040f: 4e          N
    inc hl                                                            ; 0410: 23          #
    ld b,(hl)                                                         ; 0411: 46          F
    ld a,b                                                            ; 0412: 78          x
    rla                                                               ; 0413: 17          .
    sbc a,a                                                           ; 0414: 9f          .
    cp c                                                              ; 0415: b9          .
    jr nz,ioorerr                                                     ; 0416: 20 54        T
    inc hl                                                            ; 0418: 23          #
    cp (hl)                                                           ; 0419: be          .
    jr nz,ioorerr                                                     ; 041a: 20 50        P
    ld a,$3c                                                          ; 041c: 3e 3c       ><
    add a,b                                                           ; 041e: 80          .
    jp p,l0425                                                        ; 041f: f2 25 04    .%.
    jp po,ioorerr                                                     ; 0422: e2 6c 04    .l.
; $0425 referenced 1 time by $041f
l0425:
    ld b,$fa                                                          ; 0425: 06 fa       ..
; $0427 referenced 1 time by $042a
l0427:
    sub $0c                                                           ; 0427: d6 0c       ..
    inc b                                                             ; 0429: 04          .
    jr nc,l0427                                                       ; 042a: 30 fb       0.
    ld hl,$046e                                                       ; 042c: 21 6e 04    !n.
    push bc                                                           ; 042f: c5          .
    add a,$0c                                                         ; 0430: c6 0c       ..
    call loc_mem                                                      ; 0432: cd f7 33    ..3
    call l33b8                                                        ; 0435: cd b8 33    ..3
    rst $28                                                           ; 0438: ef          .
    db 4                                                              ; 0439: 04          .  ; multiply
    db $38                                                            ; 043a: 38          8  ; end-calc

    pop af                                                            ; 043b: f1          .
    add a,(hl)                                                        ; 043c: 86          .
    ld (hl),a                                                         ; 043d: 77          w
    rst $28                                                           ; 043e: ef          .
    db $c0                                                            ; 043f: c0          .  ; st-mem-0
    db 2                                                              ; 0440: 02          .  ; delete
    db $31                                                            ; 0441: 31          1  ; duplicate
    db $38                                                            ; 0442: 38          8  ; end-calc

    call getbyte                                                      ; 0443: cd 94 1e    ...
    cp $0b                                                            ; 0446: fe 0b       ..
    jr nc,ioorerr                                                     ; 0448: 30 22       0"
    rst $28                                                           ; 044a: ef          .
    db $e0                                                            ; 044b: e0          .  ; get-mem-0
    db 4                                                              ; 044c: 04          .  ; multiply
    db $e0                                                            ; 044d: e0          .  ; get-mem-0
    db $34                                                            ; 044e: 34          4  ; stk-data
    db $80, $43, $55, $9f, $80                                        ; 044f: 80 43 55... .CU ; 437500
    db 1                                                              ; 0454: 01          .  ; exchange
    db 5                                                              ; 0455: 05          .  ; division
    db $34                                                            ; 0456: 34          4  ; stk-data
    db $35, $6c                                                       ; 0457: 35 6c       5l ; 29.5
    db 3                                                              ; 0459: 03          .  ; subtract
    db $38                                                            ; 045a: 38          8  ; end-calc

    call find_int                                                     ; 045b: cd 99 1e    ...
    push bc                                                           ; 045e: c5          .
    call find_int                                                     ; 045f: cd 99 1e    ...
    pop hl                                                            ; 0462: e1          .
    ld e,c                                                            ; 0463: 59          Y
    ld d,b                                                            ; 0464: 50          P
    ld a,e                                                            ; 0465: 7b          {
    or d                                                              ; 0466: b2          .
    ret z                                                             ; 0467: c8          .
    dec de                                                            ; 0468: 1b          .
    jp l03b5                                                          ; 0469: c3 b5 03    ...

; $046c referenced 7 times by $040c, $0416, $041a, $0422, $0448, $09d4, $09d9
ioorerr:
    rst $08                                                           ; 046c: cf          .
    db $0a                                                            ; 046d: 0a          .  ; Report B Integer out of range
l046e:
    db $89, 2, $d0, $12, $86                                          ; 046e: 89 02 d0... ... ; C
    db $89, $0a, $97, $60, $73                                        ; 0473: 89 0a 97... ... ; C#
    db $89, $12, $d5, $17, $1d                                        ; 0478: 89 12 d5... ... ; D
    db $89, $1b, $90, $41, 0                                          ; 047d: 89 1b 90... ... ; D#
    db $89, $24, $d0, $53, $c8                                        ; 0482: 89 24 d0... .$. ; E
    db $89, $2e, $9d, $36, $b0                                        ; 0487: 89 2e 9d... ... ; F
    db $89, $38, $ff, $49, $3e                                        ; 048c: 89 38 ff... .8. ; F#
    db $89, $43, $ff, $6a, $72                                        ; 0491: 89 43 ff... .C. ; G
    db $89, $4f, $a7, 0, $54                                          ; 0496: 89 4f a7... .O. ; G#
    db $89, $5c, 0, 0, 0                                              ; 049b: 89 5c 00... .\. ; A
    db $89, $69, $14, $f6, $23                                        ; 04a0: 89 69 14... .i. ; A#
    db $89, $76, $f1, $10, 3                                          ; 04a5: 89 76 f1... .v. ; B

; $04aa referenced 1 time by $0c22
l04aa:
    ld a,(de)                                                         ; 04aa: 1a          .
    and $7f                                                           ; 04ab: e6 7f       ..
    cp $20                                                            ; 04ad: fe 20       .
    ret nc                                                            ; 04af: d0          .
    cp $0d                                                            ; 04b0: fe 0d       ..
    ret z                                                             ; 04b2: c8          .
    cp 8                                                              ; 04b3: fe 08       ..
    ret z                                                             ; 04b5: c8          .
    add a,$df                                                         ; 04b6: c6 df       ..
    ret                                                               ; 04b8: c9          .

; $04b9 referenced 1 time by $0675
l04b9:
    call syntax_z                                                     ; 04b9: cd 30 25    .0%
    ret z                                                             ; 04bc: c8          .
    bit 7,(hl)                                                        ; 04bd: cb 7e       .~
    ret nz                                                            ; 04bf: c0          .
    rst $08                                                           ; 04c0: cf          .
    db $0b                                                            ; 04c1: 0b          .  ; Report C Nonsense in BASIC

; $04c2 referenced 2 times by $098a, $099e
l04c2:
    ld hl,l053f                                                       ; 04c2: 21 3f 05    !?.
    push hl                                                           ; 04c5: e5          .
    bit 7,a                                                           ; 04c6: cb 7f       ..
    ld hl,$1f80                                                       ; 04c8: 21 80 1f    !..
    jr z,l04d0                                                        ; 04cb: 28 03       (.
    ld hl,$0c98                                                       ; 04cd: 21 98 0c    !..
; $04d0 referenced 1 time by $04cb
l04d0:
    ex af,af'                                                         ; 04d0: 08          .
    di                                                                ; 04d1: f3          .
    ld a,2                                                            ; 04d2: 3e 02       >.
    dec ix                                                            ; 04d4: dd 2b       .+
    inc de                                                            ; 04d6: 13          .
    ld b,a                                                            ; 04d7: 47          G
; $04d8 referenced 3 times by $04d8, $04e1, $04e5
l04d8:
    djnz l04d8                                                        ; 04d8: 10 fe       ..
    out (ula_port),a                                                  ; 04da: d3 fe       ..
    ld b,$a4                                                          ; 04dc: 06 a4       ..
    xor $0f                                                           ; 04de: ee 0f       ..
    dec l                                                             ; 04e0: 2d          -
    jr nz,l04d8                                                       ; 04e1: 20 f5        .
    dec b                                                             ; 04e3: 05          .
    dec h                                                             ; 04e4: 25          %
    jp p,l04d8                                                        ; 04e5: f2 d8 04    ...
    ld b,$2f                                                          ; 04e8: 06 2f       ./
; $04ea referenced 1 time by $04ea
l04ea:
    djnz l04ea                                                        ; 04ea: 10 fe       ..
    out (ula_port),a                                                  ; 04ec: d3 fe       ..
    ld b,$37                                                          ; 04ee: 06 37       .7
    ld a,$0d                                                          ; 04f0: 3e 0d       >.
; $04f2 referenced 1 time by $04f2
l04f2:
    djnz l04f2                                                        ; 04f2: 10 fe       ..
    out (ula_port),a                                                  ; 04f4: d3 fe       ..
    ex af,af'                                                         ; 04f6: 08          .
    ld l,a                                                            ; 04f7: 6f          o
    ld bc,$3b0e                                                       ; 04f8: 01 0e 3b    ..;
    jp l0507                                                          ; 04fb: c3 07 05    ...

; $04fe referenced 1 time by $0537
l04fe:
    ld a,e                                                            ; 04fe: 7b          {
    or d                                                              ; 04ff: b2          .
    jr z,l050e                                                        ; 0500: 28 0c       (.
    ld l,(ix+0)                                                       ; 0502: dd 6e 00    .n.
; $0505 referenced 1 time by $050f
l0505:
    ld a,h                                                            ; 0505: 7c          |
    xor l                                                             ; 0506: ad          .
; $0507 referenced 1 time by $04fb
l0507:
    ld h,a                                                            ; 0507: 67          g
    scf                                                               ; 0508: 37          7
    ld a,1                                                            ; 0509: 3e 01       >.
    jp l0525                                                          ; 050b: c3 25 05    .%.

; $050e referenced 1 time by $0500
l050e:
    ld l,h                                                            ; 050e: 6c          l
    jr l0505                                                          ; 050f: 18 f4       ..

; $0511 referenced 1 time by $0520
l0511:
    ld a,c                                                            ; 0511: 79          y
    bit 7,b                                                           ; 0512: cb 78       .x
; $0514 referenced 2 times by $0514, $0527
l0514:
    djnz l0514                                                        ; 0514: 10 fe       ..
    jr nc,l051c                                                       ; 0516: 30 04       0.
    ld b,$42                                                          ; 0518: 06 42       .B
; $051a referenced 1 time by $051a
l051a:
    djnz l051a                                                        ; 051a: 10 fe       ..
; $051c referenced 1 time by $0516
l051c:
    out (ula_port),a                                                  ; 051c: d3 fe       ..
    ld b,$3e                                                          ; 051e: 06 3e       .>
    jr nz,l0511                                                       ; 0520: 20 ef        .
    xor a                                                             ; 0522: af          .
    dec b                                                             ; 0523: 05          .
    inc a                                                             ; 0524: 3c          <
; $0525 referenced 1 time by $050b
l0525:
    rl l                                                              ; 0525: cb 15       ..
    jp nz,l0514                                                       ; 0527: c2 14 05    ...
    ld b,$31                                                          ; 052a: 06 31       .1
    inc ix                                                            ; 052c: dd 23       .#
    dec de                                                            ; 052e: 1b          .
    ld a,$7f                                                          ; 052f: 3e 7f       >.
    in a,(ula_port)                                                   ; 0531: db fe       .. ; Read the keyboard (SPACE-B)
    rra                                                               ; 0533: 1f          .
    ret nc                                                            ; 0534: d0          .
    ld a,d                                                            ; 0535: 7a          z
    inc a                                                             ; 0536: 3c          <
    jp nz,l04fe                                                       ; 0537: c2 fe 04    ...
    ld b,$3b                                                          ; 053a: 06 3b       .;
; $053c referenced 1 time by $053c
l053c:
    djnz l053c                                                        ; 053c: 10 fe       ..
    ret                                                               ; 053e: c9          .

l053f:
    push af                                                           ; 053f: f5          .
    ld a,(bordcr)                                                     ; 0540: 3a 48 5c    :H\
    and $38                                                           ; 0543: e6 38       .8
    rrca                                                              ; 0545: 0f          .
    rrca                                                              ; 0546: 0f          .
    rrca                                                              ; 0547: 0f          .
    out (ula_port),a                                                  ; 0548: d3 fe       ..
    ld a,$7f                                                          ; 054a: 3e 7f       >.
    in a,(ula_port)                                                   ; 054c: db fe       .. ; Read the keyboard (SPACE-B)
    rra                                                               ; 054e: 1f          .
    ei                                                                ; 054f: fb          .
    jr c,l0554                                                        ; 0550: 38 02       8.
    rst $08                                                           ; 0552: cf          .
    db $0c                                                            ; 0553: 0c          .  ; Report D BREAK - CONT repeats

; $0554 referenced 1 time by $0550
l0554:
    pop af                                                            ; 0554: f1          .
    ret                                                               ; 0555: c9          .

; $0556 referenced 2 times by $076e, $0802
l0556:
    di                                                                ; 0556: f3          .
    inc d                                                             ; 0557: 14          .
    ex af,af'                                                         ; 0558: 08          .
    dec d                                                             ; 0559: 15          .
    ld a,$0f                                                          ; 055a: 3e 0f       >.
    out (ula_port),a                                                  ; 055c: d3 fe       .. ; Border white, MIC on
    ld hl,l053f                                                       ; 055e: 21 3f 05    !?.
    push hl                                                           ; 0561: e5          .
    in a,(ula_port)                                                   ; 0562: db fe       .. ; Read the keyboard (0-6, P-Y, ENTER-H, SPACE-B)
    rra                                                               ; 0564: 1f          .
    and $20                                                           ; 0565: e6 20       .
    or 2                                                              ; 0567: f6 02       ..
    ld c,a                                                            ; 0569: 4f          O
    cp a                                                              ; 056a: bf          .
; $056b referenced 4 times by $056f, $057e, $0585, $0594
l056b:
    ret nz                                                            ; 056b: c0          .
; $056c referenced 1 time by $058a
l056c:
    call l05e7                                                        ; 056c: cd e7 05    ...
    jr nc,l056b                                                       ; 056f: 30 fa       0.
    ld hl,$0115                                                       ; 0571: 21 15 01    !..
; $0574 referenced 2 times by $0574, $0579
l0574:
    djnz l0574                                                        ; 0574: 10 fe       ..
    dec hl                                                            ; 0576: 2b          +
    ld a,l                                                            ; 0577: 7d          }
    or h                                                              ; 0578: b4          .
    jr nz,l0574                                                       ; 0579: 20 f9        .
    call l05e3                                                        ; 057b: cd e3 05    ...
    jr nc,l056b                                                       ; 057e: 30 eb       0.
; $0580 referenced 1 time by $058d
l0580:
    ld b,$9c                                                          ; 0580: 06 9c       ..
    call l05e3                                                        ; 0582: cd e3 05    ...
    jr nc,l056b                                                       ; 0585: 30 e4       0.
    ld a,$c6                                                          ; 0587: 3e c6       >.
    cp b                                                              ; 0589: b8          .
    jr nc,l056c                                                       ; 058a: 30 e0       0.
    inc h                                                             ; 058c: 24          $
    jr nz,l0580                                                       ; 058d: 20 f1        .
; $058f referenced 1 time by $0599
l058f:
    ld b,$c9                                                          ; 058f: 06 c9       ..
    call l05e7                                                        ; 0591: cd e7 05    ...
    jr nc,l056b                                                       ; 0594: 30 d5       0.
    ld a,b                                                            ; 0596: 78          x
    cp $d4                                                            ; 0597: fe d4       ..
    jr nc,l058f                                                       ; 0599: 30 f4       0.
    call l05e7                                                        ; 059b: cd e7 05    ...
    ret nc                                                            ; 059e: d0          .
    ld a,c                                                            ; 059f: 79          y
    xor 3                                                             ; 05a0: ee 03       ..
    ld c,a                                                            ; 05a2: 4f          O
    ld h,0                                                            ; 05a3: 26 00       &.
    ld b,$b0                                                          ; 05a5: 06 b0       ..
    jr l05c8                                                          ; 05a7: 18 1f       ..

; $05a9 referenced 1 time by $05dd
l05a9:
    ex af,af'                                                         ; 05a9: 08          .
    jr nz,l05b3                                                       ; 05aa: 20 07        .
    jr nc,l05bd                                                       ; 05ac: 30 0f       0.
    ld (ix+0),l                                                       ; 05ae: dd 75 00    .u.
    jr l05c2                                                          ; 05b1: 18 0f       ..

; $05b3 referenced 1 time by $05aa
l05b3:
    rl c                                                              ; 05b3: cb 11       ..
    xor l                                                             ; 05b5: ad          .
    ret nz                                                            ; 05b6: c0          .
    ld a,c                                                            ; 05b7: 79          y
    rra                                                               ; 05b8: 1f          .
    ld c,a                                                            ; 05b9: 4f          O
    jp l05c5                                                          ; 05ba: c3 c5 05    ...

; $05bd referenced 1 time by $05ac
l05bd:
    ld a,(ix+0)                                                       ; 05bd: dd 7e 00    .~.
    xor l                                                             ; 05c0: ad          .
    ret nz                                                            ; 05c1: c0          .
; $05c2 referenced 1 time by $05b1
l05c2:
    inc ix                                                            ; 05c2: dd 23       .#
l05c4:
    dec de                                                            ; 05c4: 1b          .
; $05c5 referenced 1 time by $05ba
l05c5:
    ex af,af'                                                         ; 05c5: 08          .
    ld b,$b2                                                          ; 05c6: 06 b2       ..
; $05c8 referenced 1 time by $05a7
l05c8:
    ld l,1                                                            ; 05c8: 2e 01       ..
; $05ca referenced 1 time by $05d5
l05ca:
    call l05e3                                                        ; 05ca: cd e3 05    ...
    ret nc                                                            ; 05cd: d0          .
    ld a,$cb                                                          ; 05ce: 3e cb       >.
    cp b                                                              ; 05d0: b8          .
    rl l                                                              ; 05d1: cb 15       ..
    ld b,$b0                                                          ; 05d3: 06 b0       ..
    jp nc,l05ca                                                       ; 05d5: d2 ca 05    ...
    ld a,h                                                            ; 05d8: 7c          |
    xor l                                                             ; 05d9: ad          .
    ld h,a                                                            ; 05da: 67          g
    ld a,d                                                            ; 05db: 7a          z
    or e                                                              ; 05dc: b3          .
    jr nz,l05a9                                                       ; 05dd: 20 ca        .
    ld a,h                                                            ; 05df: 7c          |
    cp 1                                                              ; 05e0: fe 01       ..
    ret                                                               ; 05e2: c9          .

; $05e3 referenced 3 times by $057b, $0582, $05ca
l05e3:
    call l05e7                                                        ; 05e3: cd e7 05    ...
    ret nc                                                            ; 05e6: d0          .
; $05e7 referenced 4 times by $056c, $0591, $059b, $05e3
l05e7:
    ld a,$16                                                          ; 05e7: 3e 16       >.
; $05e9 referenced 1 time by $05ea
l05e9:
    dec a                                                             ; 05e9: 3d          =
    jr nz,l05e9                                                       ; 05ea: 20 fd        .
    and a                                                             ; 05ec: a7          .
; $05ed referenced 1 time by $05f8
l05ed:
    inc b                                                             ; 05ed: 04          .
    ret z                                                             ; 05ee: c8          .
    ld a,$7f                                                          ; 05ef: 3e 7f       >.
    in a,(ula_port)                                                   ; 05f1: db fe       .. ; Read the keyboard (SPACE-B)
    rra                                                               ; 05f3: 1f          .
    ret nc                                                            ; 05f4: d0          .
    xor c                                                             ; 05f5: a9          .
    and $20                                                           ; 05f6: e6 20       .
    jr z,l05ed                                                        ; 05f8: 28 f3       (.
    ld a,c                                                            ; 05fa: 79          y
    cpl                                                               ; 05fb: 2f          /
    ld c,a                                                            ; 05fc: 4f          O
    and 7                                                             ; 05fd: e6 07       ..
    or 8                                                              ; 05ff: f6 08       ..
    out (ula_port),a                                                  ; 0601: d3 fe       ..
    scf                                                               ; 0603: 37          7
    ret                                                               ; 0604: c9          .

; $0605 referenced 1 time by $1cdb
l0605:
    pop af                                                            ; 0605: f1          .
    ld a,(t_addr)                                                     ; 0606: 3a 74 5c    :t\
    sub $0e                                                           ; 0609: d6 0e       ..
    ld (t_addr),a                                                     ; 060b: 32 74 5c    2t\
    call class_a                                                      ; 060e: cd 8c 1c    ...
    call syntax_z                                                     ; 0611: cd 30 25    .0%
    jr z,l0652                                                        ; 0614: 28 3c       (<
    ld a,(t_addr)                                                     ; 0616: 3a 74 5c    :t\
    ld bc,$11                                                         ; 0619: 01 11 00    ...
    and a                                                             ; 061c: a7          .
    jr z,l0621                                                        ; 061d: 28 02       (.
    ld c,$22                                                          ; 061f: 0e 22       ."
; $0621 referenced 1 time by $061d
l0621:
    rst $30                                                           ; 0621: f7          .
    push de                                                           ; 0622: d5          .
    pop ix                                                            ; 0623: dd e1       ..
    ld a,$20                                                          ; 0625: 3e 20       >
    ld b,$0b                                                          ; 0627: 06 0b       ..
; $0629 referenced 1 time by $062b
l0629:
    ld (de),a                                                         ; 0629: 12          .
    inc de                                                            ; 062a: 13          .
    djnz l0629                                                        ; 062b: 10 fc       ..
    ld (ix+1),$ff                                                     ; 062d: dd 36 01... .6.
    call stk_fetch                                                    ; 0631: cd f1 2b    ..+
    dec bc                                                            ; 0634: 0b          .
    ld hl,$fff6                                                       ; 0635: 21 f6 ff    !..
    add hl,bc                                                         ; 0638: 09          .
    inc bc                                                            ; 0639: 03          .
    jr nc,l064b                                                       ; 063a: 30 0f       0.
    ld a,(t_addr)                                                     ; 063c: 3a 74 5c    :t\
    and a                                                             ; 063f: a7          .
    jr nz,l0644                                                       ; 0640: 20 02        .
    rst $08                                                           ; 0642: cf          .
    db $0e                                                            ; 0643: 0e          .  ; Report F Invalid file name

; $0644 referenced 1 time by $0640
l0644:
    ld a,c                                                            ; 0644: 79          y
    or b                                                              ; 0645: b0          .
    jr z,l0652                                                        ; 0646: 28 0a       (.
    ld bc,$0a                                                         ; 0648: 01 0a 00    ...
; $064b referenced 1 time by $063a
l064b:
    push ix                                                           ; 064b: dd e5       ..
    pop hl                                                            ; 064d: e1          .
    ex de,hl                                                          ; 064e: eb          .
    inc de                                                            ; 064f: 13          .
    ldir                                                              ; 0650: ed b0       ..
; $0652 referenced 2 times by $0614, $0646
l0652:
    rst $18                                                           ; 0652: df          .
    cp $e4                                                            ; 0653: fe e4       ..
    jr nz,l06a0                                                       ; 0655: 20 49        I
    ld a,(t_addr)                                                     ; 0657: 3a 74 5c    :t\
    cp 3                                                              ; 065a: fe 03       ..
    jp z,report_c                                                     ; 065c: ca 8a 1c    ...
    rst $20                                                           ; 065f: e7          .
    call look_vars                                                    ; 0660: cd b2 28    ..(
    set 7,c                                                           ; 0663: cb f9       ..
    jr nc,l0672                                                       ; 0665: 30 0b       0.
    ld a,(t_addr)                                                     ; 0667: 3a 74 5c    :t\
    dec a                                                             ; 066a: 3d          =
    ld hl,0                                                           ; 066b: 21 00 00    !..
    jr z,l0685                                                        ; 066e: 28 15       (.
l0670:
    rst $08                                                           ; 0670: cf          .
    db 1                                                              ; 0671: 01          .  ; Report 2 Variable not found

; $0672 referenced 2 times by $0665, $0696
l0672:
    jp nz,report_c                                                    ; 0672: c2 8a 1c    ...
    call l04b9                                                        ; 0675: cd b9 04    ...
    jr z,l0692                                                        ; 0678: 28 18       (.
    inc hl                                                            ; 067a: 23          #
    ld a,(hl)                                                         ; 067b: 7e          ~
    ld (ix+11),a                                                      ; 067c: dd 77 0b    .w.
    inc hl                                                            ; 067f: 23          #
    ld a,(hl)                                                         ; 0680: 7e          ~
    ld (ix+12),a                                                      ; 0681: dd 77 0c    .w.
    inc hl                                                            ; 0684: 23          #
; $0685 referenced 1 time by $066e
l0685:
    ld a,1                                                            ; 0685: 3e 01       >.
    ld (ix+14),c                                                      ; 0687: dd 71 0e    .q.
    bit 6,c                                                           ; 068a: cb 71       .q
    jr z,l068f                                                        ; 068c: 28 01       (.
    inc a                                                             ; 068e: 3c          <
; $068f referenced 1 time by $068c
l068f:
    ld (ix+0),a                                                       ; 068f: dd 77 00    .w.
; $0692 referenced 1 time by $0678
l0692:
    ex de,hl                                                          ; 0692: eb          .
    rst $20                                                           ; 0693: e7          .
    cp $29                                                            ; 0694: fe 29       .)
    jr nz,l0672                                                       ; 0696: 20 da        .
    rst $20                                                           ; 0698: e7          .
    call check_end                                                    ; 0699: cd ee 1b    ...
    ex de,hl                                                          ; 069c: eb          .
    jp l075a                                                          ; 069d: c3 5a 07    .Z.

; $06a0 referenced 1 time by $0655
l06a0:
    cp $aa                                                            ; 06a0: fe aa       ..
    jr nz,l06c3                                                       ; 06a2: 20 1f        .
    ld a,(t_addr)                                                     ; 06a4: 3a 74 5c    :t\
    cp 3                                                              ; 06a7: fe 03       ..
    jp z,report_c                                                     ; 06a9: ca 8a 1c    ...
    rst $20                                                           ; 06ac: e7          .
    call check_end                                                    ; 06ad: cd ee 1b    ...
    ld hl,$4000                                                       ; 06b0: 21 00 40    !.@
    ld (ix+11),0                                                      ; 06b3: dd 36 0b... .6.
    ld (ix+12),$1b                                                    ; 06b7: dd 36 0c... .6.
    ld (ix+13),l                                                      ; 06bb: dd 75 0d    .u.
    ld (ix+14),h                                                      ; 06be: dd 74 0e    .t.
    jr l0710                                                          ; 06c1: 18 4d       .M

; $06c3 referenced 1 time by $06a2
l06c3:
    cp $af                                                            ; 06c3: fe af       ..
    jr nz,l0716                                                       ; 06c5: 20 4f        O
    ld a,(t_addr)                                                     ; 06c7: 3a 74 5c    :t\
    cp 3                                                              ; 06ca: fe 03       ..
    jp z,report_c                                                     ; 06cc: ca 8a 1c    ...
    rst $20                                                           ; 06cf: e7          .
    call l2048                                                        ; 06d0: cd 48 20    .H
    jr nz,l06e1                                                       ; 06d3: 20 0c        .
    ld a,(t_addr)                                                     ; 06d5: 3a 74 5c    :t\
    and a                                                             ; 06d8: a7          .
    jp z,report_c                                                     ; 06d9: ca 8a 1c    ...
    call no_to_stk                                                    ; 06dc: cd e6 1c    ...
    jr l06f0                                                          ; 06df: 18 0f       ..

; $06e1 referenced 1 time by $06d3
l06e1:
    call class_6                                                      ; 06e1: cd 82 1c    ...
    rst $18                                                           ; 06e4: df          .
    cp $2c                                                            ; 06e5: fe 2c       .,
    jr z,l06f5                                                        ; 06e7: 28 0c       (.
    ld a,(t_addr)                                                     ; 06e9: 3a 74 5c    :t\
    and a                                                             ; 06ec: a7          .
    jp z,report_c                                                     ; 06ed: ca 8a 1c    ...
; $06f0 referenced 1 time by $06df
l06f0:
    call no_to_stk                                                    ; 06f0: cd e6 1c    ...
    jr l06f9                                                          ; 06f3: 18 04       ..

; $06f5 referenced 1 time by $06e7
l06f5:
    rst $20                                                           ; 06f5: e7          .
    call class_6                                                      ; 06f6: cd 82 1c    ...
; $06f9 referenced 1 time by $06f3
l06f9:
    call check_end                                                    ; 06f9: cd ee 1b    ...
    call find_int                                                     ; 06fc: cd 99 1e    ...
    ld (ix+12),b                                                      ; 06ff: dd 70 0c    .p.
    ld (ix+11),c                                                      ; 0702: dd 71 0b    .q.
    call find_int                                                     ; 0705: cd 99 1e    ...
    ld h,b                                                            ; 0708: 60          `
    ld (ix+14),h                                                      ; 0709: dd 74 0e    .t.
    ld l,c                                                            ; 070c: 69          i
    ld (ix+13),l                                                      ; 070d: dd 75 0d    .u.
; $0710 referenced 1 time by $06c1
l0710:
    ld (ix+0),3                                                       ; 0710: dd 36 00... .6.
    jr l075a                                                          ; 0714: 18 44       .D

; $0716 referenced 1 time by $06c5
l0716:
    cp $ca                                                            ; 0716: fe ca       ..
    jr z,l0723                                                        ; 0718: 28 09       (.
    call check_end                                                    ; 071a: cd ee 1b    ...
    ld (ix+14),$80                                                    ; 071d: dd 36 0e... .6.
    jr l073a                                                          ; 0721: 18 17       ..

; $0723 referenced 1 time by $0718
l0723:
    ld a,(t_addr)                                                     ; 0723: 3a 74 5c    :t\
    and a                                                             ; 0726: a7          .
    jp nz,report_c                                                    ; 0727: c2 8a 1c    ...
    rst $20                                                           ; 072a: e7          .
    call class_6                                                      ; 072b: cd 82 1c    ...
    call check_end                                                    ; 072e: cd ee 1b    ...
    call syntax3                                                      ; 0731: cd 01 39    ..9
    ld (ix+14),b                                                      ; 0734: dd 70 0e    .p.
    ld (ix+13),c                                                      ; 0737: dd 71 0d    .q.
; $073a referenced 1 time by $0721
l073a:
    ld de,(prog)                                                      ; 073a: ed 5b 53... .[S
    ld hl,(e_line)                                                    ; 073e: 2a 59 5c    *Y\
    ld (ix+0),0                                                       ; 0741: dd 36 00... .6.
    scf                                                               ; 0745: 37          7
    sbc hl,de                                                         ; 0746: ed 52       .R
    ld (ix+12),h                                                      ; 0748: dd 74 0c    .t.
    ld (ix+11),l                                                      ; 074b: dd 75 0b    .u.
    ld hl,(vars)                                                      ; 074e: 2a 4b 5c    *K\
    sbc hl,de                                                         ; 0751: ed 52       .R
    ld (ix+16),h                                                      ; 0753: dd 74 10    .t.
    ld (ix+15),l                                                      ; 0756: dd 75 0f    .u.
    ex de,hl                                                          ; 0759: eb          .
; $075a referenced 2 times by $069d, $0714
l075a:
    ld a,(t_addr)                                                     ; 075a: 3a 74 5c    :t\
    and a                                                             ; 075d: a7          .
    jp z,l0970                                                        ; 075e: ca 70 09    .p.
    push hl                                                           ; 0761: e5          .
    ld bc,$11                                                         ; 0762: 01 11 00    ...
    add ix,bc                                                         ; 0765: dd 09       ..
; $0767 referenced 3 times by $0773, $078c, $07b2
l0767:
    xor a                                                             ; 0767: af          .
    push ix                                                           ; 0768: dd e5       ..
    ld de,$11                                                         ; 076a: 11 11 00    ...
    scf                                                               ; 076d: 37          7
    call l0556                                                        ; 076e: cd 56 05    .V.
    pop ix                                                            ; 0771: dd e1       ..
    jr nc,l0767                                                       ; 0773: 30 f2       0.
    ld a,$fe                                                          ; 0775: 3e fe       >.
    call l1601                                                        ; 0777: cd 01 16    ...
    ld a,(ix+0)                                                       ; 077a: dd 7e 00    .~.
    ld (iy+scr_ct - err_nr),$ff                                       ; 077d: fd 36 52... .6R
    ld c,$80                                                          ; 0781: 0e 80       ..
    cp (ix-17)                                                        ; 0783: dd be ef    ...
    jr nz,l078a                                                       ; 0786: 20 02        .
    ld c,$f6                                                          ; 0788: 0e f6       ..
; $078a referenced 1 time by $0786
l078a:
    cp 4                                                              ; 078a: fe 04       ..
    jr nc,l0767                                                       ; 078c: 30 d9       0.
    ld de,$13d4                                                       ; 078e: 11 d4 13    ...
    push bc                                                           ; 0791: c5          .
    call l0c0a                                                        ; 0792: cd 0a 0c    ...
    pop bc                                                            ; 0795: c1          .
    push ix                                                           ; 0796: dd e5       ..
    pop de                                                            ; 0798: d1          .
    ld hl,$fff0                                                       ; 0799: 21 f0 ff    !..
    add hl,de                                                         ; 079c: 19          .
    ld a,(hl)                                                         ; 079d: 7e          ~
    ld b,$0a                                                          ; 079e: 06 0a       ..
    inc a                                                             ; 07a0: 3c          <
    jr nz,l07a6                                                       ; 07a1: 20 03        .
    ld a,c                                                            ; 07a3: 79          y
    add a,b                                                           ; 07a4: 80          .
    ld c,a                                                            ; 07a5: 4f          O
; $07a6 referenced 2 times by $07a1, $07ae
l07a6:
    inc de                                                            ; 07a6: 13          .
    ld a,(de)                                                         ; 07a7: 1a          .
    cp (hl)                                                           ; 07a8: be          .
    inc hl                                                            ; 07a9: 23          #
    jr nz,l07ad                                                       ; 07aa: 20 01        .
    inc c                                                             ; 07ac: 0c          .
; $07ad referenced 1 time by $07aa
l07ad:
    rst $10                                                           ; 07ad: d7          .
    djnz l07a6                                                        ; 07ae: 10 f6       ..
    bit 7,c                                                           ; 07b0: cb 79       .y
    jr nz,l0767                                                       ; 07b2: 20 b3        .
    ld a,$0d                                                          ; 07b4: 3e 0d       >.
    rst $10                                                           ; 07b6: d7          .
    pop hl                                                            ; 07b7: e1          .
    ld a,(ix+0)                                                       ; 07b8: dd 7e 00    .~.
    cp 3                                                              ; 07bb: fe 03       ..
    jr z,l07cb                                                        ; 07bd: 28 0c       (.
    ld a,(t_addr)                                                     ; 07bf: 3a 74 5c    :t\
    dec a                                                             ; 07c2: 3d          =
    jp z,l0808                                                        ; 07c3: ca 08 08    ...
    cp 2                                                              ; 07c6: fe 02       ..
    jp z,l08b6                                                        ; 07c8: ca b6 08    ...
; $07cb referenced 1 time by $07bd
l07cb:
    push hl                                                           ; 07cb: e5          .
    ld h,(ix-5)                                                       ; 07cc: dd 66 fb    .f.
    ld l,(ix-6)                                                       ; 07cf: dd 6e fa    .n.
    ld d,(ix+12)                                                      ; 07d2: dd 56 0c    .V.
    ld e,(ix+11)                                                      ; 07d5: dd 5e 0b    .^.
    ld a,l                                                            ; 07d8: 7d          }
    or h                                                              ; 07d9: b4          .
    jr z,l07e9                                                        ; 07da: 28 0d       (.
    sbc hl,de                                                         ; 07dc: ed 52       .R
    jr c,terror                                                       ; 07de: 38 26       8&
    jr z,l07e9                                                        ; 07e0: 28 07       (.
    ld a,(ix+0)                                                       ; 07e2: dd 7e 00    .~.
    cp 3                                                              ; 07e5: fe 03       ..
    jr nz,terror                                                      ; 07e7: 20 1d        .
; $07e9 referenced 2 times by $07da, $07e0
l07e9:
    pop hl                                                            ; 07e9: e1          .
    ld a,l                                                            ; 07ea: 7d          }
    or h                                                              ; 07eb: b4          .
    jr nz,l07f4                                                       ; 07ec: 20 06        .
    ld h,(ix+14)                                                      ; 07ee: dd 66 0e    .f.
    ld l,(ix+13)                                                      ; 07f1: dd 6e 0d    .n.
; $07f4 referenced 1 time by $07ec
l07f4:
    push hl                                                           ; 07f4: e5          .
    pop ix                                                            ; 07f5: dd e1       ..
    ld a,(t_addr)                                                     ; 07f7: 3a 74 5c    :t\
    cp 2                                                              ; 07fa: fe 02       ..
    scf                                                               ; 07fc: 37          7
    jr nz,l0800                                                       ; 07fd: 20 01        .
    and a                                                             ; 07ff: a7          .
; $0800 referenced 1 time by $07fd
l0800:
    ld a,$ff                                                          ; 0800: 3e ff       >.
; $0802 referenced 3 times by $0870, $08b3, $08ca
l0802:
    call l0556                                                        ; 0802: cd 56 05    .V.
    ret c                                                             ; 0805: d8          .
; $0806 referenced 2 times by $07de, $07e7
terror:
    rst $08                                                           ; 0806: cf          .
    db $1a                                                            ; 0807: 1a          .  ; Report R Tape loading error

; $0808 referenced 1 time by $07c3
l0808:
    ld d,(ix+12)                                                      ; 0808: dd 56 0c    .V.
    ld e,(ix+11)                                                      ; 080b: dd 5e 0b    .^.
    push hl                                                           ; 080e: e5          .
    ld a,l                                                            ; 080f: 7d          }
    or h                                                              ; 0810: b4          .
    jr nz,l0819                                                       ; 0811: 20 06        .
    inc de                                                            ; 0813: 13          .
    inc de                                                            ; 0814: 13          .
    inc de                                                            ; 0815: 13          .
    ex de,hl                                                          ; 0816: eb          .
    jr l0825                                                          ; 0817: 18 0c       ..

; $0819 referenced 1 time by $0811
l0819:
    ld h,(ix-5)                                                       ; 0819: dd 66 fb    .f.
    ld l,(ix-6)                                                       ; 081c: dd 6e fa    .n.
    ex de,hl                                                          ; 081f: eb          .
    scf                                                               ; 0820: 37          7
    sbc hl,de                                                         ; 0821: ed 52       .R
    jr c,l082e                                                        ; 0823: 38 09       8.
; $0825 referenced 1 time by $0817
l0825:
    ld de,5                                                           ; 0825: 11 05 00    ...
    add hl,de                                                         ; 0828: 19          .
    ld c,l                                                            ; 0829: 4d          M
    ld b,h                                                            ; 082a: 44          D
    call test_room                                                    ; 082b: cd 05 1f    ...
; $082e referenced 1 time by $0823
l082e:
    pop hl                                                            ; 082e: e1          .
    ld a,(ix+0)                                                       ; 082f: dd 7e 00    .~.
    and a                                                             ; 0832: a7          .
    jr z,l0873                                                        ; 0833: 28 3e       (>
    ld a,l                                                            ; 0835: 7d          }
    or h                                                              ; 0836: b4          .
    jr z,l084c                                                        ; 0837: 28 13       (.
    dec hl                                                            ; 0839: 2b          +
    ld b,(hl)                                                         ; 083a: 46          F
    dec hl                                                            ; 083b: 2b          +
    ld c,(hl)                                                         ; 083c: 4e          N
    dec hl                                                            ; 083d: 2b          +
    inc bc                                                            ; 083e: 03          .
    inc bc                                                            ; 083f: 03          .
    inc bc                                                            ; 0840: 03          .
    ld (x_ptr),ix                                                     ; 0841: dd 22 5f... ."_
    call reclaim_2                                                    ; 0845: cd e8 19    ...
    ld ix,(x_ptr)                                                     ; 0848: dd 2a 5f... .*_
; $084c referenced 1 time by $0837
l084c:
    ld hl,(e_line)                                                    ; 084c: 2a 59 5c    *Y\
    dec hl                                                            ; 084f: 2b          +
    ld b,(ix+12)                                                      ; 0850: dd 46 0c    .F.
    ld c,(ix+11)                                                      ; 0853: dd 4e 0b    .N.
    push bc                                                           ; 0856: c5          .
    inc bc                                                            ; 0857: 03          .
    inc bc                                                            ; 0858: 03          .
    inc bc                                                            ; 0859: 03          .
    ld a,(ix-3)                                                       ; 085a: dd 7e fd    .~.
    push af                                                           ; 085d: f5          .
    call make_room                                                    ; 085e: cd 55 16    .U.
    inc hl                                                            ; 0861: 23          #
    pop af                                                            ; 0862: f1          .
    ld (hl),a                                                         ; 0863: 77          w
    pop de                                                            ; 0864: d1          .
    inc hl                                                            ; 0865: 23          #
    ld (hl),e                                                         ; 0866: 73          s
    inc hl                                                            ; 0867: 23          #
    ld (hl),d                                                         ; 0868: 72          r
    inc hl                                                            ; 0869: 23          #
    push hl                                                           ; 086a: e5          .
    pop ix                                                            ; 086b: dd e1       ..
    scf                                                               ; 086d: 37          7
    ld a,$ff                                                          ; 086e: 3e ff       >.
    jp l0802                                                          ; 0870: c3 02 08    ...

; $0873 referenced 1 time by $0833
l0873:
    ex de,hl                                                          ; 0873: eb          .
    ld hl,(e_line)                                                    ; 0874: 2a 59 5c    *Y\
    dec hl                                                            ; 0877: 2b          +
    ld (x_ptr),ix                                                     ; 0878: dd 22 5f... ."_
    ld b,(ix+12)                                                      ; 087c: dd 46 0c    .F.
    ld c,(ix+11)                                                      ; 087f: dd 4e 0b    .N.
    push bc                                                           ; 0882: c5          .
    call reclaim_1                                                    ; 0883: cd e5 19    ...
    pop bc                                                            ; 0886: c1          .
    push hl                                                           ; 0887: e5          .
    push bc                                                           ; 0888: c5          .
    call make_room                                                    ; 0889: cd 55 16    .U.
    ld ix,(x_ptr)                                                     ; 088c: dd 2a 5f... .*_
    inc hl                                                            ; 0890: 23          #
    ld b,(ix+16)                                                      ; 0891: dd 46 10    .F.
    ld c,(ix+15)                                                      ; 0894: dd 4e 0f    .N.
    add hl,bc                                                         ; 0897: 09          .
    ld (vars),hl                                                      ; 0898: 22 4b 5c    "K\
    ld h,(ix+14)                                                      ; 089b: dd 66 0e    .f.
    ld a,h                                                            ; 089e: 7c          |
    and $c0                                                           ; 089f: e6 c0       ..
    jr nz,l08ad                                                       ; 08a1: 20 0a        .
    ld l,(ix+13)                                                      ; 08a3: dd 6e 0d    .n.
    ld (newppc),hl                                                    ; 08a6: 22 42 5c    "B\
    ld (iy+nsppc - err_nr),0                                          ; 08a9: fd 36 0a... .6.
; $08ad referenced 1 time by $08a1
l08ad:
    pop de                                                            ; 08ad: d1          .
    pop ix                                                            ; 08ae: dd e1       ..
    scf                                                               ; 08b0: 37          7
    ld a,$ff                                                          ; 08b1: 3e ff       >.
    jp l0802                                                          ; 08b3: c3 02 08    ...

; $08b6 referenced 1 time by $07c8
l08b6:
    ld b,(ix+12)                                                      ; 08b6: dd 46 0c    .F.
    ld c,(ix+11)                                                      ; 08b9: dd 4e 0b    .N.
    push bc                                                           ; 08bc: c5          .
    inc bc                                                            ; 08bd: 03          .
    rst $30                                                           ; 08be: f7          .
    ld (hl),$80                                                       ; 08bf: 36 80       6.
    ex de,hl                                                          ; 08c1: eb          .
    pop de                                                            ; 08c2: d1          .
    push hl                                                           ; 08c3: e5          .
    push hl                                                           ; 08c4: e5          .
    pop ix                                                            ; 08c5: dd e1       ..
    scf                                                               ; 08c7: 37          7
    ld a,$ff                                                          ; 08c8: 3e ff       >.
    call l0802                                                        ; 08ca: cd 02 08    ...
    pop hl                                                            ; 08cd: e1          .
    ld de,(prog)                                                      ; 08ce: ed 5b 53... .[S
; $08d2 referenced 1 time by $08ee
l08d2:
    ld a,(hl)                                                         ; 08d2: 7e          ~
    and $c0                                                           ; 08d3: e6 c0       ..
    jr nz,l08f0                                                       ; 08d5: 20 19        .
; $08d7 referenced 1 time by $08e9
l08d7:
    ld a,(de)                                                         ; 08d7: 1a          .
    inc de                                                            ; 08d8: 13          .
    cp (hl)                                                           ; 08d9: be          .
    inc hl                                                            ; 08da: 23          #
    jr nz,l08df                                                       ; 08db: 20 02        .
    ld a,(de)                                                         ; 08dd: 1a          .
    cp (hl)                                                           ; 08de: be          .
; $08df referenced 1 time by $08db
l08df:
    dec hl                                                            ; 08df: 2b          +
    dec de                                                            ; 08e0: 1b          .
    jr nc,l08eb                                                       ; 08e1: 30 08       0.
    push hl                                                           ; 08e3: e5          .
    ex de,hl                                                          ; 08e4: eb          .
    call next_one                                                     ; 08e5: cd b8 19    ...
    pop hl                                                            ; 08e8: e1          .
    jr l08d7                                                          ; 08e9: 18 ec       ..

; $08eb referenced 1 time by $08e1
l08eb:
    call l092c                                                        ; 08eb: cd 2c 09    .,.
    jr l08d2                                                          ; 08ee: 18 e2       ..

; $08f0 referenced 2 times by $08d5, $092a
l08f0:
    ld a,(hl)                                                         ; 08f0: 7e          ~
    ld c,a                                                            ; 08f1: 4f          O
    cp $80                                                            ; 08f2: fe 80       ..
    ret z                                                             ; 08f4: c8          .
    push hl                                                           ; 08f5: e5          .
    ld hl,(vars)                                                      ; 08f6: 2a 4b 5c    *K\
; $08f9 referenced 1 time by $0907
l08f9:
    ld a,(hl)                                                         ; 08f9: 7e          ~
    cp $80                                                            ; 08fa: fe 80       ..
    jr z,l0923                                                        ; 08fc: 28 25       (%
    cp c                                                              ; 08fe: b9          .
    jr z,l0909                                                        ; 08ff: 28 08       (.
; $0901 referenced 1 time by $091f
l0901:
    push bc                                                           ; 0901: c5          .
    call next_one                                                     ; 0902: cd b8 19    ...
    pop bc                                                            ; 0905: c1          .
    ex de,hl                                                          ; 0906: eb          .
    jr l08f9                                                          ; 0907: 18 f0       ..

; $0909 referenced 1 time by $08ff
l0909:
    and $e0                                                           ; 0909: e6 e0       ..
    cp $a0                                                            ; 090b: fe a0       ..
    jr nz,l0921                                                       ; 090d: 20 12        .
    pop de                                                            ; 090f: d1          .
    push de                                                           ; 0910: d5          .
    push hl                                                           ; 0911: e5          .
; $0912 referenced 1 time by $0919
l0912:
    inc de                                                            ; 0912: 13          .
    ld a,(de)                                                         ; 0913: 1a          .
    inc hl                                                            ; 0914: 23          #
    cp (hl)                                                           ; 0915: be          .
    jr nz,l091e                                                       ; 0916: 20 06        .
    rla                                                               ; 0918: 17          .
    jr nc,l0912                                                       ; 0919: 30 f7       0.
    pop hl                                                            ; 091b: e1          .
    jr l0921                                                          ; 091c: 18 03       ..

; $091e referenced 1 time by $0916
l091e:
    pop hl                                                            ; 091e: e1          .
    jr l0901                                                          ; 091f: 18 e0       ..

; $0921 referenced 2 times by $090d, $091c
l0921:
    ld a,$ff                                                          ; 0921: 3e ff       >.
; $0923 referenced 1 time by $08fc
l0923:
    inc a                                                             ; 0923: 3c          <
    pop de                                                            ; 0924: d1          .
    ex de,hl                                                          ; 0925: eb          .
    scf                                                               ; 0926: 37          7
    call l092c                                                        ; 0927: cd 2c 09    .,.
    jr l08f0                                                          ; 092a: 18 c4       ..

; $092c referenced 2 times by $08eb, $0927
l092c:
    jr nz,l093e                                                       ; 092c: 20 10        .
    ld (x_ptr),hl                                                     ; 092e: 22 5f 5c    "_\
    ex af,af'                                                         ; 0931: 08          .
    ex de,hl                                                          ; 0932: eb          .
    call next_one                                                     ; 0933: cd b8 19    ...
    call reclaim_2                                                    ; 0936: cd e8 19    ...
    ex af,af'                                                         ; 0939: 08          .
    ex de,hl                                                          ; 093a: eb          .
    ld hl,(x_ptr)                                                     ; 093b: 2a 5f 5c    *_\
; $093e referenced 1 time by $092c
l093e:
    push de                                                           ; 093e: d5          .
    ex af,af'                                                         ; 093f: 08          .
    call next_one                                                     ; 0940: cd b8 19    ...
    ex af,af'                                                         ; 0943: 08          .
    ld (x_ptr),hl                                                     ; 0944: 22 5f 5c    "_\
    ld hl,(prog)                                                      ; 0947: 2a 53 5c    *S\
    ex (sp),hl                                                        ; 094a: e3          .
    push bc                                                           ; 094b: c5          .
    jr c,l0955                                                        ; 094c: 38 07       8.
    dec hl                                                            ; 094e: 2b          +
    call make_room                                                    ; 094f: cd 55 16    .U.
    inc hl                                                            ; 0952: 23          #
    jr l0958                                                          ; 0953: 18 03       ..

; $0955 referenced 1 time by $094c
l0955:
    call make_room                                                    ; 0955: cd 55 16    .U.
; $0958 referenced 1 time by $0953
l0958:
    pop bc                                                            ; 0958: c1          .
    pop de                                                            ; 0959: d1          .
    inc hl                                                            ; 095a: 23          #
    ld (prog),de                                                      ; 095b: ed 53 53... .SS
    ld de,(x_ptr)                                                     ; 095f: ed 5b 5f... .[_
    push bc                                                           ; 0963: c5          .
    push de                                                           ; 0964: d5          .
    ex de,hl                                                          ; 0965: eb          .
    ldir                                                              ; 0966: ed b0       ..
    pop hl                                                            ; 0968: e1          .
    pop bc                                                            ; 0969: c1          .
    push de                                                           ; 096a: d5          .
    call reclaim_2                                                    ; 096b: cd e8 19    ...
    pop de                                                            ; 096e: d1          .
    ret                                                               ; 096f: c9          .

; $0970 referenced 1 time by $075e
l0970:
    push hl                                                           ; 0970: e5          .
    ld a,$fd                                                          ; 0971: 3e fd       >.
    call l1601                                                        ; 0973: cd 01 16    ...
    xor a                                                             ; 0976: af          .
    ld de,$13b5                                                       ; 0977: 11 b5 13    ...
    call l0c0a                                                        ; 097a: cd 0a 0c    ...
    set 5,(iy+tv_flag - err_nr)                                       ; 097d: fd cb 02... ...
    call waitkey                                                      ; 0981: cd d4 15    ...
    push ix                                                           ; 0984: dd e5       ..
    ld de,$11                                                         ; 0986: 11 11 00    ...
    xor a                                                             ; 0989: af          .
    call l04c2                                                        ; 098a: cd c2 04    ...
    pop ix                                                            ; 098d: dd e1       ..
    ld b,$32                                                          ; 098f: 06 32       .2
; $0991 referenced 1 time by $0992
l0991:
    halt                                                              ; 0991: 76          v
    djnz l0991                                                        ; 0992: 10 fd       ..
    ld e,(ix+11)                                                      ; 0994: dd 5e 0b    .^.
    ld d,(ix+12)                                                      ; 0997: dd 56 0c    .V.
    ld a,$ff                                                          ; 099a: 3e ff       >.
    pop ix                                                            ; 099c: dd e1       ..
    jp l04c2                                                          ; 099e: c3 c2 04    ...

l09a1:
    rst $18                                                           ; 09a1: df          .
    dec hl                                                            ; 09a2: 2b          +
    ld a,(hl)                                                         ; 09a3: 7e          ~
    cp $d2                                                            ; 09a4: fe d2       ..
    jr nz,l09af                                                       ; 09a6: 20 07        .
    rst $18                                                           ; 09a8: df          .
    call check_end                                                    ; 09a9: cd ee 1b    ...
    jp l3954                                                          ; 09ac: c3 54 39    .T9

; $09af referenced 1 time by $09a6
l09af:
    rst $18                                                           ; 09af: df          .
    cp $37                                                            ; 09b0: fe 37       .7
    jr z,l09bb                                                        ; 09b2: 28 07       (.
    cp $38                                                            ; 09b4: fe 38       .8
    jp z,l3927                                                        ; 09b6: ca 27 39    .'9
    rst $08                                                           ; 09b9: cf          .
    db $0b                                                            ; 09ba: 0b          .  ; Report C Nonsense in BASIC

; $09bb referenced 1 time by $09b2
l09bb:
    rst $20                                                           ; 09bb: e7          .
    call check_end                                                    ; 09bc: cd ee 1b    ...
    jp l1f1a                                                          ; 09bf: c3 1a 1f    ...

; $09c2 referenced 1 time by $09e8
l09c2:
    rst $20                                                           ; 09c2: e7          .
l09c3:
    call class_8                                                      ; 09c3: cd 7a 1c    .z.
    call syntax_z                                                     ; 09c6: cd 30 25    .0%
    jr z,l09e5                                                        ; 09c9: 28 1a       (.
    call fp_to_a                                                      ; 09cb: cd d5 2d    ..-
    push af                                                           ; 09ce: f5          .
    call fp_to_a                                                      ; 09cf: cd d5 2d    ..-
    cp $11                                                            ; 09d2: fe 11       ..
    jp nc,ioorerr                                                     ; 09d4: d2 6c 04    .l.
    dec a                                                             ; 09d7: 3d          =
    inc a                                                             ; 09d8: 3c          <
    jp m,ioorerr                                                      ; 09d9: fa 6c 04    .l.
    ld bc,$c0f5                                                       ; 09dc: 01 f5 c0    ...
    out (c),a                                                         ; 09df: ed 79       .y
    pop af                                                            ; 09e1: f1          .
    call l38ce                                                        ; 09e2: cd ce 38    ..8
; $09e5 referenced 1 time by $09c9
l09e5:
    rst $18                                                           ; 09e5: df          .
    cp $3b                                                            ; 09e6: fe 3b       .;
    jr z,l09c2                                                        ; 09e8: 28 d8       (.
    call check_end                                                    ; 09ea: cd ee 1b    ...
    ret                                                               ; 09ed: c9          .

; $09ee referenced 1 time by $3ced
setudg1:
    ex de,hl                                                          ; 09ee: eb          .
    lddr                                                              ; 09ef: ed b8       ..
    jp setudg2                                                        ; 09f1: c3 d4 16    ...

; $09f4 referenced 2 times by $1161, $18f6
prmain:
    call l0b03                                                        ; 09f4: cd 03 0b    ...
    cp $18                                                            ; 09f7: fe 18       ..
    jr nc,l0a5b                                                       ; 09f9: 30 60       0`
    cp 6                                                              ; 09fb: fe 06       ..
    jp c,l0c81                                                        ; 09fd: da 81 0c    ...
    cp $18                                                            ; 0a00: fe 18       ..
    jr nc,l0a59                                                       ; 0a02: 30 55       0U
    ld d,0                                                            ; 0a04: 16 00       ..
    ld e,a                                                            ; 0a06: 5f          _
    ld hl,$0a0b                                                       ; 0a07: 21 0b 0a    !..
    add hl,de                                                         ; 0a0a: 19          .
    ld e,(hl)                                                         ; 0a0b: 5e          ^
    add hl,de                                                         ; 0a0c: 19          .
    push hl                                                           ; 0a0d: e5          .
    jp l0b03                                                          ; 0a0e: c3 03 0b    ...

l0a11:
    db l0a52 - $                                                      ; 0a11: 41          A
    db l0a59 - $                                                      ; 0a12: 47          G
    db l0a23 - $                                                      ; 0a13: 10          .
    db l0a37 - $                                                      ; 0a14: 23          #
    db l0a59 - $                                                      ; 0a15: 44          D
    db l0a59 - $                                                      ; 0a16: 43          C
    db l0a59 - $                                                      ; 0a17: 42          B
    db l0a49 - $                                                      ; 0a18: 31          1
    db l0a59 - $                                                      ; 0a19: 40          @
    db l0a59 - $                                                      ; 0a1a: 3f          ?
    db l0a6a - $                                                      ; 0a1b: 4f          O
    db l0a6a - $                                                      ; 0a1c: 4e          N
    db l0a6a - $                                                      ; 0a1d: 4d          M
    db l0a6a - $                                                      ; 0a1e: 4c          L
    db l0a6a - $                                                      ; 0a1f: 4b          K
    db l0a6a - $                                                      ; 0a20: 4a          J
    db l0a65 - $                                                      ; 0a21: 44          D
    db l0a65 - $                                                      ; 0a22: 43          C

l0a23:
    inc c                                                             ; 0a23: 0c          .
    ld a,$22                                                          ; 0a24: 3e 22       >"
    cp c                                                              ; 0a26: b9          .
    jp nz,l0dd9                                                       ; 0a27: c2 d9 0d    ...
    dec c                                                             ; 0a2a: 0d          .
    ld a,$18                                                          ; 0a2b: 3e 18       >.
    cp b                                                              ; 0a2d: b8          .
    jp nz,l0dd9                                                       ; 0a2e: c2 d9 0d    ...
    ld c,2                                                            ; 0a31: 0e 02       ..
    inc b                                                             ; 0a33: 04          .
    jp l0dd9                                                          ; 0a34: c3 d9 0d    ...

l0a37:
    ld a,(p_flag)                                                     ; 0a37: 3a 91 5c    :.\
    push af                                                           ; 0a3a: f5          .
    ld a,$20                                                          ; 0a3b: 3e 20       >
    ld (iy+p_flag - err_nr),1                                         ; 0a3d: fd 36 57... .6W
    call l0ad9                                                        ; 0a41: cd d9 0a    ...
    pop af                                                            ; 0a44: f1          .
    ld (p_flag),a                                                     ; 0a45: 32 91 5c    2.\
    ret                                                               ; 0a48: c9          .

l0a49:
    ld c,$21                                                          ; 0a49: 0e 21       .!
    call l0c55                                                        ; 0a4b: cd 55 0c    .U.
    dec b                                                             ; 0a4e: 05          .
    jp l0dd9                                                          ; 0a4f: c3 d9 0d    ...

l0a52:
    ld a,c                                                            ; 0a52: 79          y
    dec a                                                             ; 0a53: 3d          =
    dec a                                                             ; 0a54: 3d          =
    and $10                                                           ; 0a55: e6 10       ..
    jr l0ac3                                                          ; 0a57: 18 6a       .j

; $0a59 referenced 1 time by $0a02
l0a59:
    ld a,$3f                                                          ; 0a59: 3e 3f       >?
; $0a5b referenced 1 time by $09f9
l0a5b:
    jr l0ad9                                                          ; 0a5b: 18 7c       .|

l0a5d:
    ld (tvdata+1),a                                                   ; 0a5d: 32 0f 5c    2.\
    ld de,l0a87                                                       ; 0a60: 11 87 0a    ...
    jr l0a70                                                          ; 0a63: 18 0b       ..

l0a65:
    ld de,l0a5d                                                       ; 0a65: 11 5d 0a    .].
    jr l0a6d                                                          ; 0a68: 18 03       ..

l0a6a:
    ld de,l0a87                                                       ; 0a6a: 11 87 0a    ...
; $0a6d referenced 1 time by $0a68
l0a6d:
    ld (tvdata),a                                                     ; 0a6d: 32 0e 5c    2.\
; $0a70 referenced 2 times by $0a63, $0a8a
l0a70:
    ld hl,(curchl)                                                    ; 0a70: 2a 51 5c    *Q\
    ld (hl),e                                                         ; 0a73: 73          s
    inc hl                                                            ; 0a74: 23          #
    ld (hl),d                                                         ; 0a75: 72          r
    ret                                                               ; 0a76: c9          .

l0a58:
    call getbyte                                                      ; 0a77: cd 94 1e    ...
    ld (attr_p),a                                                     ; 0a7a: 32 8d 5c    2.\
    ret                                                               ; 0a7d: c9          .

; $0a7e referenced 1 time by $3ca5
l0a7e:
    sbc hl,bc                                                         ; 0a7e: ed 42       .B
    add a,$2f                                                         ; 0a80: c6 2f       ./
    ld (de),a                                                         ; 0a82: 12          .
    inc de                                                            ; 0a83: 13          .
    ret                                                               ; 0a84: c9          .

    db $53, $56                                                       ; 0a85: 53 56       SV

l0a87:
    ld de,$09f4                                                       ; 0a87: 11 f4 09    ...
    call l0a70                                                        ; 0a8a: cd 70 0a    .p.
    ld hl,(tvdata)                                                    ; 0a8d: 2a 0e 5c    *.\
    ld d,a                                                            ; 0a90: 57          W
    ld a,l                                                            ; 0a91: 7d          }
    cp $16                                                            ; 0a92: fe 16       ..
    jp c,l2211                                                        ; 0a94: da 11 22    .."
    jr nz,l0ac2                                                       ; 0a97: 20 29        )
    ld c,d                                                            ; 0a99: 4a          J
    ld b,h                                                            ; 0a9a: 44          D
    ld a,$1f                                                          ; 0a9b: 3e 1f       >.
    sub c                                                             ; 0a9d: 91          .
    jr c,l0aa6                                                        ; 0a9e: 38 06       8.
    add a,2                                                           ; 0aa0: c6 02       ..
    ld c,a                                                            ; 0aa2: 4f          O
    ld a,$16                                                          ; 0aa3: 3e 16       >.
    sub b                                                             ; 0aa5: 90          .
; $0aa6 referenced 1 time by $0a9e
l0aa6:
    jp c,report_b1                                                    ; 0aa6: da 9f 1e    ...
    inc a                                                             ; 0aa9: 3c          <
    ld b,a                                                            ; 0aaa: 47          G
    inc b                                                             ; 0aab: 04          .
    bit 0,(iy+tv_flag - err_nr)                                       ; 0aac: fd cb 02... ...
    jp nz,l0c55                                                       ; 0ab0: c2 55 0c    .U.
    cp (iy+df_sz - err_nr)                                            ; 0ab3: fd be 31    ..1
    jp c,oserror                                                      ; 0ab6: da 86 0c    ...
    jp l0dd9                                                          ; 0ab9: c3 d9 0d    ...

; $0abc referenced 1 time by $1f3a
l0abc:
    call pau2                                                         ; 0abc: cd 4f 1f    .O.
    jp find_int                                                       ; 0abf: c3 99 1e    ...

; $0ac2 referenced 1 time by $0a97
l0ac2:
    ld a,h                                                            ; 0ac2: 7c          |
; $0ac3 referenced 1 time by $0a57
l0ac3:
    call l0b03                                                        ; 0ac3: cd 03 0b    ...
    add a,c                                                           ; 0ac6: 81          .
    dec a                                                             ; 0ac7: 3d          =
    and $1f                                                           ; 0ac8: e6 1f       ..
    ret z                                                             ; 0aca: c8          .
    set 0,(iy+flags - err_nr)                                         ; 0acb: fd cb 01... ...
    ld d,a                                                            ; 0acf: 57          W
; $0ad0 referenced 1 time by $0ad6
l0ad0:
    ld a,$20                                                          ; 0ad0: 3e 20       >
    call l0c3b                                                        ; 0ad2: cd 3b 0c    .;.
    dec d                                                             ; 0ad5: 15          .
    jr nz,l0ad0                                                       ; 0ad6: 20 f8        .
    ret                                                               ; 0ad8: c9          .

; $0ad9 referenced 2 times by $0a41, $0a5b
l0ad9:
    call l391d                                                        ; 0ad9: cd 1d 39    ..9
; $0adc referenced 1 time by $0df2
l0adc:
    bit 0,(iy+tv_flag - err_nr)                                       ; 0adc: fd cb 02... ...
    jr nz,l0aea                                                       ; 0ae0: 20 08        .
    ld (s_posn),bc                                                    ; 0ae2: ed 43 88... .C.
    ld (df_cc),hl                                                     ; 0ae6: 22 84 5c    ".\
    ret                                                               ; 0ae9: c9          .

; $0aea referenced 1 time by $0ae0
l0aea:
    ld (s_posnl),bc                                                   ; 0aea: ed 43 8a... .C.
    ld (echo_e),bc                                                    ; 0aee: ed 43 82... .C.
    ld (df_ccl),hl                                                    ; 0af2: 22 86 5c    ".\
    ret                                                               ; 0af5: c9          .

; $0af6 referenced 2 times by $0ff2, $104f
l0af6:
    ld hl,(e_line)                                                    ; 0af6: 2a 59 5c    *Y\
    ld de,(k_cur)                                                     ; 0af9: ed 5b 5b... .[[
    and a                                                             ; 0afd: a7          .
    sbc hl,de                                                         ; 0afe: ed 52       .R
    ld b,$20                                                          ; 0b00: 06 20       .
    ret                                                               ; 0b02: c9          .

; $0b03 referenced 5 times by $09f4, $0a0e, $0ac3, $0b30, $0b62
l0b03:
    ld hl,(df_cc)                                                     ; 0b03: 2a 84 5c    *.\
    ld bc,(s_posn)                                                    ; 0b06: ed 4b 88... .K.
    bit 0,(iy+tv_flag - err_nr)                                       ; 0b0a: fd cb 02... ...
    ret z                                                             ; 0b0e: c8          .
    ld hl,(df_ccl)                                                    ; 0b0f: 2a 86 5c    *.\
    ld bc,(s_posnl)                                                   ; 0b12: ed 4b 8a... .K.
    ret                                                               ; 0b16: c9          .

; $0b17 referenced 3 times by $0dbc, $1c99, $1cc3
streamfe:
    ld a,$fe                                                          ; 0b17: 3e fe       >.
    jp l1601                                                          ; 0b19: c3 01 16    ...

copy:
    call find_int                                                     ; 0b1c: cd 99 1e    ...
    ld a,b                                                            ; 0b1f: 78          x
    or c                                                              ; 0b20: b1          .
    ret z                                                             ; 0b21: c8          .
    push bc                                                           ; 0b22: c5          .
    ret                                                               ; 0b23: c9          .

; $0b24 referenced 1 time by $3924
l0b24:
    cp $80                                                            ; 0b24: fe 80       ..
    jr c,l0b65                                                        ; 0b26: 38 3d       8=
    cp $90                                                            ; 0b28: fe 90       ..
    jr nc,l0b52                                                       ; 0b2a: 30 26       0&
    ld b,a                                                            ; 0b2c: 47          G
    call l0b38                                                        ; 0b2d: cd 38 0b    .8.
    call l0b03                                                        ; 0b30: cd 03 0b    ...
    ld de,$5c92                                                       ; 0b33: 11 92 5c    ..\
    jr l0b7f                                                          ; 0b36: 18 47       .G

; $0b38 referenced 1 time by $0b2d
l0b38:
    ld hl,$5c92                                                       ; 0b38: 21 92 5c    !.\
    call l0b3e                                                        ; 0b3b: cd 3e 0b    .>.
; $0b3e referenced 1 time by $0b3b
l0b3e:
    rr b                                                              ; 0b3e: cb 18       ..
    sbc a,a                                                           ; 0b40: 9f          .
    and $0f                                                           ; 0b41: e6 0f       ..
    ld c,a                                                            ; 0b43: 4f          O
    rr b                                                              ; 0b44: cb 18       ..
    sbc a,a                                                           ; 0b46: 9f          .
    and $f0                                                           ; 0b47: e6 f0       ..
    or c                                                              ; 0b49: b1          .
    ld c,4                                                            ; 0b4a: 0e 04       ..
; $0b4c referenced 1 time by $0b4f
l0b4c:
    ld (hl),a                                                         ; 0b4c: 77          w
    dec c                                                             ; 0b4d: 0d          .
    inc hl                                                            ; 0b4e: 23          #
    jr nz,l0b4c                                                       ; 0b4f: 20 fb        .
    ret                                                               ; 0b51: c9          .

; $0b52 referenced 1 time by $0b2a
l0b52:
    sub $a5                                                           ; 0b52: d6 a5       ..
    jr nc,l0b5f                                                       ; 0b54: 30 09       0.
    add a,$15                                                         ; 0b56: c6 15       ..
    push bc                                                           ; 0b58: c5          .
    ld bc,(udg)                                                       ; 0b59: ed 4b 7b... .K{
    jr l0b6a                                                          ; 0b5d: 18 0b       ..

; $0b5f referenced 2 times by $0b54, $0c83
l0b5f:
    call l0c10                                                        ; 0b5f: cd 10 0c    ...
    jp l0b03                                                          ; 0b62: c3 03 0b    ...

; $0b65 referenced 2 times by $0b26, $3921
l0b65:
    push bc                                                           ; 0b65: c5          .
    ld bc,(chars)                                                     ; 0b66: ed 4b 36... .K6
; $0b6a referenced 1 time by $0b5d
l0b6a:
    ex de,hl                                                          ; 0b6a: eb          .
    ld hl,$5c3b                                                       ; 0b6b: 21 3b 5c    !;\
    res 0,(hl)                                                        ; 0b6e: cb 86       ..
    cp $20                                                            ; 0b70: fe 20       .
    jr nz,l0b76                                                       ; 0b72: 20 02        .
    set 0,(hl)                                                        ; 0b74: cb c6       ..
; $0b76 referenced 1 time by $0b72
l0b76:
    ld l,a                                                            ; 0b76: 6f          o
    ld h,0                                                            ; 0b77: 26 00       &.
    add hl,hl                                                         ; 0b79: 29          )
    add hl,hl                                                         ; 0b7a: 29          )
    add hl,hl                                                         ; 0b7b: 29          )
    add hl,bc                                                         ; 0b7c: 09          .
    ex de,hl                                                          ; 0b7d: eb          .
    pop bc                                                            ; 0b7e: c1          .
; $0b7f referenced 1 time by $0b36
l0b7f:
    ld a,c                                                            ; 0b7f: 79          y
    dec a                                                             ; 0b80: 3d          =
    ld a,$21                                                          ; 0b81: 3e 21       >!
    jr nz,l0b87                                                       ; 0b83: 20 02        .
    ld c,a                                                            ; 0b85: 4f          O
    dec b                                                             ; 0b86: 05          .
; $0b87 referenced 1 time by $0b83
l0b87:
    cp c                                                              ; 0b87: b9          .
    push de                                                           ; 0b88: d5          .
    call z,l0c55                                                      ; 0b89: cc 55 0c    .U.
    pop de                                                            ; 0b8c: d1          .
    push bc                                                           ; 0b8d: c5          .
    push hl                                                           ; 0b8e: e5          .
    ld a,(p_flag)                                                     ; 0b8f: 3a 91 5c    :.\
    ld b,$ff                                                          ; 0b92: 06 ff       ..
    rra                                                               ; 0b94: 1f          .
    jr c,l0b98                                                        ; 0b95: 38 01       8.
    inc b                                                             ; 0b97: 04          .
; $0b98 referenced 1 time by $0b95
l0b98:
    rra                                                               ; 0b98: 1f          .
    rra                                                               ; 0b99: 1f          .
    sbc a,a                                                           ; 0b9a: 9f          .
    ld c,a                                                            ; 0b9b: 4f          O
    ld a,8                                                            ; 0b9c: 3e 08       >.
    and a                                                             ; 0b9e: a7          .
    ex de,hl                                                          ; 0b9f: eb          .
; $0ba0 referenced 1 time by $0baa
l0ba0:
    ex af,af'                                                         ; 0ba0: 08          .
    ld a,(de)                                                         ; 0ba1: 1a          .
    and b                                                             ; 0ba2: a0          .
    xor c                                                             ; 0ba3: a9          .
    xor (hl)                                                          ; 0ba4: ae          .
    ld (de),a                                                         ; 0ba5: 12          .
    ex af,af'                                                         ; 0ba6: 08          .
    inc d                                                             ; 0ba7: 14          .
    dec a                                                             ; 0ba8: 3d          =
    inc hl                                                            ; 0ba9: 23          #
    jr nz,l0ba0                                                       ; 0baa: 20 f4        .
    ex de,hl                                                          ; 0bac: eb          .
    dec h                                                             ; 0bad: 25          %
    call l0bdb                                                        ; 0bae: cd db 0b    ...
    pop hl                                                            ; 0bb1: e1          .
    pop bc                                                            ; 0bb2: c1          .
    dec c                                                             ; 0bb3: 0d          .
    inc hl                                                            ; 0bb4: 23          #
    ret                                                               ; 0bb5: c9          .

; $0bb6 referenced 1 time by $1b46
l0bb6:
    cp $38                                                            ; 0bb6: fe 38       .8
    ret c                                                             ; 0bb8: d8          .
    rst $08                                                           ; 0bb9: cf          .
    db $0b                                                            ; 0bba: 0b          .  ; Report C Nonsense in BASIC

l0bbb:
    call l0bd0                                                        ; 0bbb: cd d0 0b    ...
    call next_one                                                     ; 0bbe: cd b8 19    ...
    push de                                                           ; 0bc1: d5          .
    call l0bd0                                                        ; 0bc2: cd d0 0b    ...
    pop de                                                            ; 0bc5: d1          .
    and a                                                             ; 0bc6: a7          .
    sbc hl,de                                                         ; 0bc7: ed 52       .R
    jr nc,l0bdd9                                                      ; 0bc9: 30 0e       0.
    add hl,de                                                         ; 0bcb: 19          .
    ex de,hl                                                          ; 0bcc: eb          .
    jp reclaim_1                                                      ; 0bcd: c3 e5 19    ...

; $0bd0 referenced 2 times by $0bbb, $0bc2
l0bd0:
    call syntax3                                                      ; 0bd0: cd 01 39    ..9
    ld h,b                                                            ; 0bd3: 60          `
    ld l,c                                                            ; 0bd4: 69          i
    call line_addr                                                    ; 0bd5: cd 6e 19    .n.
    ret z                                                             ; 0bd8: c8          .
; $0bd9 referenced 1 time by $0bc9
l0bdd9:
    rst $08                                                           ; 0bd9: cf          .
    db 9                                                              ; 0bda: 09          .  ; Report A Invalid argument

; $0bdb referenced 2 times by $0bae, $2304
l0bdb:
    ld a,h                                                            ; 0bdb: 7c          |
    rrca                                                              ; 0bdc: 0f          .
    rrca                                                              ; 0bdd: 0f          .
    rrca                                                              ; 0bde: 0f          .
    and 3                                                             ; 0bdf: e6 03       ..
    or $58                                                            ; 0be1: f6 58       .X
    ld h,a                                                            ; 0be3: 67          g
    ld de,(attr_t)                                                    ; 0be4: ed 5b 8f... .[.
    ld a,(hl)                                                         ; 0be8: 7e          ~
    xor e                                                             ; 0be9: ab          .
    and d                                                             ; 0bea: a2          .
    xor e                                                             ; 0beb: ab          .
    bit 6,(iy+p_flag - err_nr)                                        ; 0bec: fd cb 57... ..W
    jr z,l0bfa                                                        ; 0bf0: 28 08       (.
    and $c7                                                           ; 0bf2: e6 c7       ..
    bit 2,a                                                           ; 0bf4: cb 57       .W
    jr nz,l0bfa                                                       ; 0bf6: 20 02        .
    xor $38                                                           ; 0bf8: ee 38       .8
; $0bfa referenced 2 times by $0bf0, $0bf6
l0bfa:
    bit 4,(iy+p_flag - err_nr)                                        ; 0bfa: fd cb 57... ..W
    jr z,l0c08                                                        ; 0bfe: 28 08       (.
    and $f8                                                           ; 0c00: e6 f8       ..
    bit 5,a                                                           ; 0c02: cb 6f       .o
    jr nz,l0c08                                                       ; 0c04: 20 02        .
    xor 7                                                             ; 0c06: ee 07       ..
; $0c08 referenced 2 times by $0bfe, $0c04
l0c08:
    ld (hl),a                                                         ; 0c08: 77          w
    ret                                                               ; 0c09: c9          .

; $0c0a referenced 5 times by $0792, $097a, $0ca4, $1299, $133e
l0c0a:
    push hl                                                           ; 0c0a: e5          .
    ld h,0                                                            ; 0c0b: 26 00       &.
    ex (sp),hl                                                        ; 0c0d: e3          .
    jr l0c14                                                          ; 0c0e: 18 04       ..

; $0c10 referenced 1 time by $0b5f
l0c10:
    ld de,$a8                                                         ; 0c10: 11 a8 00    ...
    push af                                                           ; 0c13: f5          .
; $0c14 referenced 1 time by $0c0e
l0c14:
    call l0c41                                                        ; 0c14: cd 41 0c    .A.
    jr c,l0c22                                                        ; 0c17: 38 09       8.
    ld a,$20                                                          ; 0c19: 3e 20       >
    bit 0,(iy+flags - err_nr)                                         ; 0c1b: fd cb 01... ...
    call z,l0c3b                                                      ; 0c1f: cc 3b 0c    .;.
; $0c22 referenced 2 times by $0c17, $0c2b
l0c22:
    call l04aa                                                        ; 0c22: cd aa 04    ...
    call l0c3b                                                        ; 0c25: cd 3b 0c    .;.
    ld a,(de)                                                         ; 0c28: 1a          .
    inc de                                                            ; 0c29: 13          .
    add a,a                                                           ; 0c2a: 87          .
    jr nc,l0c22                                                       ; 0c2b: 30 f5       0.
    pop de                                                            ; 0c2d: d1          .
    cp $48                                                            ; 0c2e: fe 48       .H
    jr z,l0c35                                                        ; 0c30: 28 03       (.
    cp $82                                                            ; 0c32: fe 82       ..
    ret c                                                             ; 0c34: d8          .
; $0c35 referenced 1 time by $0c30
l0c35:
    ld a,d                                                            ; 0c35: 7a          z
    cp 3                                                              ; 0c36: fe 03       ..
    ret c                                                             ; 0c38: d8          .
    ld a,$20                                                          ; 0c39: 3e 20       >
; $0c3b referenced 3 times by $0ad2, $0c1f, $0c25
l0c3b:
    push de                                                           ; 0c3b: d5          .
    exx                                                               ; 0c3c: d9          .
    rst $10                                                           ; 0c3d: d7          .
    exx                                                               ; 0c3e: d9          .
    pop de                                                            ; 0c3f: d1          .
    ret                                                               ; 0c40: c9          .

; $0c41 referenced 2 times by $0c14, $3999
l0c41:
    push af                                                           ; 0c41: f5          .
    ex de,hl                                                          ; 0c42: eb          .
    inc a                                                             ; 0c43: 3c          <
; $0c44 referenced 2 times by $0c47, $0c4a
words:
    bit 7,(hl)                                                        ; 0c44: cb 7e       .~
    inc hl                                                            ; 0c46: 23          #
    jr z,words                                                        ; 0c47: 28 fb       (.
    dec a                                                             ; 0c49: 3d          =
    jr nz,words                                                       ; 0c4a: 20 f8        .
    ex de,hl                                                          ; 0c4c: eb          .
    pop af                                                            ; 0c4d: f1          .
    cp $20                                                            ; 0c4e: fe 20       .
    ret c                                                             ; 0c50: d8          .
    ld a,(de)                                                         ; 0c51: 1a          .
    sub $41                                                           ; 0c52: d6 41       .A
    ret                                                               ; 0c54: c9          .

; $0c55 referenced 3 times by $0a4b, $0ab0, $0b89
l0c55:
    ld de,$0dd9                                                       ; 0c55: 11 d9 0d    ...
    push de                                                           ; 0c58: d5          .
    ld a,b                                                            ; 0c59: 78          x
    bit 0,(iy+tv_flag - err_nr)                                       ; 0c5a: fd cb 02... ...
    jp nz,l0d02                                                       ; 0c5e: c2 02 0d    ...
    cp (iy+df_sz - err_nr)                                            ; 0c61: fd be 31    ..1
    jr c,oserror                                                      ; 0c64: 38 20       8
    ret nz                                                            ; 0c66: c0          .
    bit 4,(iy+tv_flag - err_nr)                                       ; 0c67: fd cb 02... ...
    jr z,l0c88                                                        ; 0c6b: 28 1b       (.
    ld e,(iy+breg - err_nr)                                           ; 0c6d: fd 5e 2d    .^-
    dec e                                                             ; 0c70: 1d          .
    jp z,l0cce                                                        ; 0c71: ca ce 0c    ...
    xor a                                                             ; 0c74: af          .
    call l1601                                                        ; 0c75: cd 01 16    ...
    ld sp,(list_sp)                                                   ; 0c78: ed 7b 3f... .{?
    res 4,(iy+tv_flag - err_nr)                                       ; 0c7c: fd cb 02... ...
    ret                                                               ; 0c80: c9          .

; $0c81 referenced 1 time by $09fd
l0c81:
    add a,$5b                                                         ; 0c81: c6 5b       .[
    jp l0b5f                                                          ; 0c83: c3 5f 0b    ._.

; $0c86 referenced 3 times by $0ab6, $0c64, $0d04
oserror:
    rst $08                                                           ; 0c86: cf          .
    db 4                                                              ; 0c87: 04          .  ; Report 5 Out of screen

; $0c88 referenced 1 time by $0c6b
l0c88:
    dec (iy+scr_ct - err_nr)                                          ; 0c88: fd 35 52    .5R
    jr nz,l0cce                                                       ; 0c8b: 20 41        A
    ld a,$18                                                          ; 0c8d: 3e 18       >.
    sub b                                                             ; 0c8f: 90          .
    ld (scr_ct),a                                                     ; 0c90: 32 8c 5c    2.\
    ld hl,(attr_t)                                                    ; 0c93: 2a 8f 5c    *.\
    push hl                                                           ; 0c96: e5          .
    ld a,(p_flag)                                                     ; 0c97: 3a 91 5c    :.\
    push af                                                           ; 0c9a: f5          .
    ld a,$fd                                                          ; 0c9b: 3e fd       >.
    call l1601                                                        ; 0c9d: cd 01 16    ...
    xor a                                                             ; 0ca0: af          .
    ld de,$3235                                                       ; 0ca1: 11 35 32    .52
    call l0c0a                                                        ; 0ca4: cd 0a 0c    ...
    set 5,(iy+tv_flag - err_nr)                                       ; 0ca7: fd cb 02... ...
    ld hl,$5c3b                                                       ; 0cab: 21 3b 5c    !;\
    res 5,(hl)                                                        ; 0cae: cb ae       ..
    call l18ff                                                        ; 0cb0: cd ff 18    ...
    cp $20                                                            ; 0cb3: fe 20       .
    jr z,report_d                                                     ; 0cb5: 28 49       (I
    cp $e2                                                            ; 0cb7: fe e2       ..
    jr z,report_d                                                     ; 0cb9: 28 45       (E
    or $20                                                            ; 0cbb: f6 20       .
    cp $6e                                                            ; 0cbd: fe 6e       .n
    jr z,report_d                                                     ; 0cbf: 28 3f       (?
    ld a,$fe                                                          ; 0cc1: 3e fe       >.
    call l1601                                                        ; 0cc3: cd 01 16    ...
    pop af                                                            ; 0cc6: f1          .
    ld (p_flag),a                                                     ; 0cc7: 32 91 5c    2.\
    pop hl                                                            ; 0cca: e1          .
    ld (attr_t),hl                                                    ; 0ccb: 22 8f 5c    ".\
; $0cce referenced 2 times by $0c71, $0c8b
l0cce:
    call l0dfe                                                        ; 0cce: cd fe 0d    ...
    ld b,(iy+df_sz - err_nr)                                          ; 0cd1: fd 46 31    .F1
    inc b                                                             ; 0cd4: 04          .
    ld c,$21                                                          ; 0cd5: 0e 21       .!
    push bc                                                           ; 0cd7: c5          .
    call l0e9b                                                        ; 0cd8: cd 9b 0e    ...
    ld a,h                                                            ; 0cdb: 7c          |
    rrca                                                              ; 0cdc: 0f          .
    rrca                                                              ; 0cdd: 0f          .
    rrca                                                              ; 0cde: 0f          .
    and 3                                                             ; 0cdf: e6 03       ..
    or $58                                                            ; 0ce1: f6 58       .X
    ld h,a                                                            ; 0ce3: 67          g
    ld de,$5ae0                                                       ; 0ce4: 11 e0 5a    ..Z
    ld a,(de)                                                         ; 0ce7: 1a          .
    ld c,(hl)                                                         ; 0ce8: 4e          N
    ld b,$20                                                          ; 0ce9: 06 20       .
    ex de,hl                                                          ; 0ceb: eb          .
; $0cec referenced 1 time by $0cf0
l0cec:
    ld (de),a                                                         ; 0cec: 12          .
    ld (hl),c                                                         ; 0ced: 71          q
    inc de                                                            ; 0cee: 13          .
    inc hl                                                            ; 0cef: 23          #
    djnz l0cec                                                        ; 0cf0: 10 fa       ..
    pop bc                                                            ; 0cf2: c1          .
    ret                                                               ; 0cf3: c9          .

; $0cf4 referenced 1 time by $0f29
l0cf4:
    call out_digit                                                    ; 0cf4: cd 2a 19    .*.
    ld c,$f6                                                          ; 0cf7: 0e f6       ..
    call out_digit                                                    ; 0cf9: cd 2a 19    .*.
    ld a,l                                                            ; 0cfc: 7d          }
    ret                                                               ; 0cfd: c9          .

l0cfe:
    db $ff, 0                                                         ; 0cfe: ff 00       ..

; $0d00 referenced 3 times by $0cb5, $0cb9, $0cbf
report_d:
    rst $08                                                           ; 0d00: cf          .
    db $0c                                                            ; 0d01: 0c          .  ; Report D BREAK - CONT repeats

; $0d02 referenced 1 time by $0c5e
l0d02:
    cp 2                                                              ; 0d02: fe 02       ..
    jr c,oserror                                                      ; 0d04: 38 80       8.
    add a,(iy+df_sz - err_nr)                                         ; 0d06: fd 86 31    ..1
    sub $19                                                           ; 0d09: d6 19       ..
    ret nc                                                            ; 0d0b: d0          .
    neg                                                               ; 0d0c: ed 44       .D
    push bc                                                           ; 0d0e: c5          .
    ld b,a                                                            ; 0d0f: 47          G
    ld hl,(attr_t)                                                    ; 0d10: 2a 8f 5c    *.\
    push hl                                                           ; 0d13: e5          .
    ld hl,(p_flag)                                                    ; 0d14: 2a 91 5c    *.\
    push hl                                                           ; 0d17: e5          .
    call trcurp                                                       ; 0d18: cd 4d 0d    .M.
    ld a,b                                                            ; 0d1b: 78          x
; $0d1c referenced 1 time by $0d32
l0d1c:
    push af                                                           ; 0d1c: f5          .
    ld hl,$5c6b                                                       ; 0d1d: 21 6b 5c    !k\
    ld b,(hl)                                                         ; 0d20: 46          F
    ld a,b                                                            ; 0d21: 78          x
    inc a                                                             ; 0d22: 3c          <
    ld (hl),a                                                         ; 0d23: 77          w
    ld hl,$5c89                                                       ; 0d24: 21 89 5c    !.\
    cp (hl)                                                           ; 0d27: be          .
    jr c,l0d2d                                                        ; 0d28: 38 03       8.
    inc (hl)                                                          ; 0d2a: 34          4
    ld b,$17                                                          ; 0d2b: 06 17       ..
; $0d2d referenced 1 time by $0d28
l0d2d:
    call l0e00                                                        ; 0d2d: cd 00 0e    ...
    pop af                                                            ; 0d30: f1          .
    dec a                                                             ; 0d31: 3d          =
    jr nz,l0d1c                                                       ; 0d32: 20 e8        .
    pop hl                                                            ; 0d34: e1          .
    ld (iy+p_flag - err_nr),l                                         ; 0d35: fd 75 57    .uW
    pop hl                                                            ; 0d38: e1          .
    ld (attr_t),hl                                                    ; 0d39: 22 8f 5c    ".\
    ld bc,(s_posn)                                                    ; 0d3c: ed 4b 88... .K.
    res 0,(iy+tv_flag - err_nr)                                       ; 0d40: fd cb 02... ...
    call l0dd9                                                        ; 0d44: cd d9 0d    ...
    set 0,(iy+tv_flag - err_nr)                                       ; 0d47: fd cb 02... ...
    pop bc                                                            ; 0d4b: c1          .
    ret                                                               ; 0d4c: c9          .

; $0d4d referenced 7 times by $0d18, $111d, $114d, $1646, $1fd5, $22e2, $247a
trcurp:
    xor a                                                             ; 0d4d: af          .
    ld hl,(attr_p)                                                    ; 0d4e: 2a 8d 5c    *.\
    bit 0,(iy+tv_flag - err_nr)                                       ; 0d51: fd cb 02... ...
    jr z,l0d5b                                                        ; 0d55: 28 04       (.
    ld h,a                                                            ; 0d57: 67          g
    ld l,(iy+bordcr - err_nr)                                         ; 0d58: fd 6e 0e    .n.
; $0d5b referenced 1 time by $0d55
l0d5b:
    ld (attr_t),hl                                                    ; 0d5b: 22 8f 5c    ".\
    ld hl,$5c91                                                       ; 0d5e: 21 91 5c    !.\
    jr nz,l0d65                                                       ; 0d61: 20 02        .
    ld a,(hl)                                                         ; 0d63: 7e          ~
    rrca                                                              ; 0d64: 0f          .
; $0d65 referenced 1 time by $0d61
l0d65:
    xor (hl)                                                          ; 0d65: ae          .
    and $55                                                           ; 0d66: e6 55       .U
    xor (hl)                                                          ; 0d68: ae          .
    ld (hl),a                                                         ; 0d69: 77          w
    ret                                                               ; 0d6a: c9          .

; $0d6b referenced 2 times by $128f, $1347
cls:
    call l005f                                                        ; 0d6b: cd 5f 00    ._.
; $0d6e referenced 6 times by $10bf, $12e7, $132f, $208e, $20be, $38ee
clslower:
    ld hl,$5c3c                                                       ; 0d6e: 21 3c 5c    !<\
    res 5,(hl)                                                        ; 0d71: cb ae       ..
    set 0,(hl)                                                        ; 0d73: cb c6       ..
    ld b,(iy+df_sz - err_nr)                                          ; 0d75: fd 46 31    .F1
    call l0e44                                                        ; 0d78: cd 44 0e    .D.
    ld hl,$5ac0                                                       ; 0d7b: 21 c0 5a    !.Z
    ld a,(attr_p)                                                     ; 0d7e: 3a 8d 5c    :.\
    dec b                                                             ; 0d81: 05          .
    jr l0d8e                                                          ; 0d82: 18 0a       ..

l0d84:
    db "CMS"                                                          ; 0d84: 43 4d 53    CMS

; $0d87 referenced 1 time by $0d8e
l0d87:
    ld c,$20                                                          ; 0d87: 0e 20       .
; $0d89 referenced 1 time by $0d8c
l0d89:
    dec hl                                                            ; 0d89: 2b          +
    ld (hl),a                                                         ; 0d8a: 77          w
    dec c                                                             ; 0d8b: 0d          .
    jr nz,l0d89                                                       ; 0d8c: 20 fb        .
; $0d8e referenced 1 time by $0d82
l0d8e:
    djnz l0d87                                                        ; 0d8e: 10 f7       ..
    ld (iy+df_sz - err_nr),2                                          ; 0d90: fd 36 31... .61
; $0d94 referenced 1 time by $0db9
l0d94:
    ld a,$fd                                                          ; 0d94: 3e fd       >.
    call l1601                                                        ; 0d96: cd 01 16    ...
    ld hl,(curchl)                                                    ; 0d99: 2a 51 5c    *Q\
    ld de,$09f4                                                       ; 0d9c: 11 f4 09    ...
    and a                                                             ; 0d9f: a7          .
; $0da0 referenced 1 time by $0da8
l0da0:
    ld (hl),e                                                         ; 0da0: 73          s
    inc hl                                                            ; 0da1: 23          #
    ld (hl),d                                                         ; 0da2: 72          r
    inc hl                                                            ; 0da3: 23          #
    ld de,$10a6                                                       ; 0da4: 11 a6 10    ...
    ccf                                                               ; 0da7: 3f          ?
    jr c,l0da0                                                        ; 0da8: 38 f6       8.
    ld bc,$1721                                                       ; 0daa: 01 21 17    .!.
    jr l0dd9                                                          ; 0dad: 18 2a       .*

; $0daf referenced 3 times by $12e4, $179d, $63
l0daf:
    ld hl,0                                                           ; 0daf: 21 00 00    !..
    ld (coords),hl                                                    ; 0db2: 22 7d 5c    "}\
    res 0,(iy+flags2 - err_nr)                                        ; 0db5: fd cb 30... ..0
    call l0d94                                                        ; 0db9: cd 94 0d    ...
    call streamfe                                                     ; 0dbc: cd 17 0b    ...
    ld b,$18                                                          ; 0dbf: 06 18       ..
    call l0e44                                                        ; 0dc1: cd 44 0e    .D.
    ld hl,(curchl)                                                    ; 0dc4: 2a 51 5c    *Q\
    ld de,$09f4                                                       ; 0dc7: 11 f4 09    ...
    ld (hl),e                                                         ; 0dca: 73          s
    inc hl                                                            ; 0dcb: 23          #
    ld (hl),d                                                         ; 0dcc: 72          r
    ld (iy+scr_ct - err_nr),1                                         ; 0dcd: fd 36 52... .6R
    jr l0dd9                                                          ; 0dd1: 18 06       ..

; $0dd3 referenced 1 time by $1a09
l0dd3:
    call numeric                                                      ; 0dd3: cd 1b 2d    ..-
    jp l1068                                                          ; 0dd6: c3 68 10    .h.

; $0dd9 referenced 11 times by $0a27, $0a2e, $0a34, $0a4f, $0ab9, $0d44, $0dad, $0dd1, $1184, $20bb, $2171
l0dd9:
    ld a,b                                                            ; 0dd9: 78          x
    bit 0,(iy+tv_flag - err_nr)                                       ; 0dda: fd cb 02... ...
    jr z,l0de5                                                        ; 0dde: 28 05       (.
    add a,(iy+df_sz - err_nr)                                         ; 0de0: fd 86 31    ..1
    sub $18                                                           ; 0de3: d6 18       ..
; $0de5 referenced 1 time by $0dde
l0de5:
    push bc                                                           ; 0de5: c5          .
    ld b,a                                                            ; 0de6: 47          G
    call l0e9b                                                        ; 0de7: cd 9b 0e    ...
    pop bc                                                            ; 0dea: c1          .
    ld a,$21                                                          ; 0deb: 3e 21       >!
    sub c                                                             ; 0ded: 91          .
    ld e,a                                                            ; 0dee: 5f          _
    ld d,0                                                            ; 0def: 16 00       ..
    add hl,de                                                         ; 0df1: 19          .
    jp l0adc                                                          ; 0df2: c3 dc 0a    ...

x80_ftan:
    rst $28                                                           ; 0df5: ef          .
    db $31                                                            ; 0df6: 31          1  ; duplicate
    db $1f                                                            ; 0df7: 1f          .  ; sin
    db 1                                                              ; 0df8: 01          .  ; exchange
    db $20                                                            ; 0df9: 20             ; cos
    db 5                                                              ; 0dfa: 05          .  ; division
    db $38                                                            ; 0dfb: 38          8  ; end-calc

    ret                                                               ; 0dfc: c9          .

    db $ff                                                            ; 0dfd: ff          .

; $0dfe referenced 1 time by $0cce
l0dfe:
    ld b,$17                                                          ; 0dfe: 06 17       ..
; $0e00 referenced 1 time by $0d2d
l0e00:
    call l0e9b                                                        ; 0e00: cd 9b 0e    ...
    ld c,8                                                            ; 0e03: 0e 08       ..
; $0e05 referenced 1 time by $0e36
l0e05:
    push bc                                                           ; 0e05: c5          .
    push hl                                                           ; 0e06: e5          .
    ld a,b                                                            ; 0e07: 78          x
    and 7                                                             ; 0e08: e6 07       ..
    ld a,b                                                            ; 0e0a: 78          x
    jr nz,l0e19                                                       ; 0e0b: 20 0c        .
; $0e0d referenced 1 time by $0e30
l0e0d:
    ex de,hl                                                          ; 0e0d: eb          .
    ld hl,$f8e0                                                       ; 0e0e: 21 e0 f8    !..
    add hl,de                                                         ; 0e11: 19          .
    ex de,hl                                                          ; 0e12: eb          .
    ld bc,$20                                                         ; 0e13: 01 20 00    . .
    dec a                                                             ; 0e16: 3d          =
    ldir                                                              ; 0e17: ed b0       ..
; $0e19 referenced 1 time by $0e0b
l0e19:
    ex de,hl                                                          ; 0e19: eb          .
    ld hl,$ffe0                                                       ; 0e1a: 21 e0 ff    !..
    add hl,de                                                         ; 0e1d: 19          .
    ex de,hl                                                          ; 0e1e: eb          .
    ld b,a                                                            ; 0e1f: 47          G
    and 7                                                             ; 0e20: e6 07       ..
    rrca                                                              ; 0e22: 0f          .
    rrca                                                              ; 0e23: 0f          .
    rrca                                                              ; 0e24: 0f          .
    ld c,a                                                            ; 0e25: 4f          O
    ld a,b                                                            ; 0e26: 78          x
    ld b,0                                                            ; 0e27: 06 00       ..
    ldir                                                              ; 0e29: ed b0       ..
    ld b,7                                                            ; 0e2b: 06 07       ..
    add hl,bc                                                         ; 0e2d: 09          .
    and $f8                                                           ; 0e2e: e6 f8       ..
    jr nz,l0e0d                                                       ; 0e30: 20 db        .
    pop hl                                                            ; 0e32: e1          .
    inc h                                                             ; 0e33: 24          $
    pop bc                                                            ; 0e34: c1          .
    dec c                                                             ; 0e35: 0d          .
    jr nz,l0e05                                                       ; 0e36: 20 cd        .
    call l0e88                                                        ; 0e38: cd 88 0e    ...
    ld hl,$ffe0                                                       ; 0e3b: 21 e0 ff    !..
    add hl,de                                                         ; 0e3e: 19          .
    ex de,hl                                                          ; 0e3f: eb          .
    ldir                                                              ; 0e40: ed b0       ..
    ld b,1                                                            ; 0e42: 06 01       ..
; $0e44 referenced 3 times by $0d78, $0dc1, $17a7
l0e44:
    push bc                                                           ; 0e44: c5          .
    call l0e9b                                                        ; 0e45: cd 9b 0e    ...
    ld c,8                                                            ; 0e48: 0e 08       ..
; $0e4a referenced 1 time by $0e6b
l0e4a:
    push bc                                                           ; 0e4a: c5          .
    push hl                                                           ; 0e4b: e5          .
    ld a,b                                                            ; 0e4c: 78          x
; $0e4d referenced 1 time by $0e65
l0e4d:
    and 7                                                             ; 0e4d: e6 07       ..
    rrca                                                              ; 0e4f: 0f          .
    rrca                                                              ; 0e50: 0f          .
    rrca                                                              ; 0e51: 0f          .
    ld c,a                                                            ; 0e52: 4f          O
    ld a,b                                                            ; 0e53: 78          x
    ld b,0                                                            ; 0e54: 06 00       ..
    dec c                                                             ; 0e56: 0d          .
    ld d,h                                                            ; 0e57: 54          T
    ld e,l                                                            ; 0e58: 5d          ]
    ld (hl),b                                                         ; 0e59: 70          p
    inc de                                                            ; 0e5a: 13          .
    ldir                                                              ; 0e5b: ed b0       ..
    ld de,$0701                                                       ; 0e5d: 11 01 07    ...
    add hl,de                                                         ; 0e60: 19          .
    dec a                                                             ; 0e61: 3d          =
    and $f8                                                           ; 0e62: e6 f8       ..
    ld b,a                                                            ; 0e64: 47          G
    jr nz,l0e4d                                                       ; 0e65: 20 e6        .
    pop hl                                                            ; 0e67: e1          .
    inc h                                                             ; 0e68: 24          $
    pop bc                                                            ; 0e69: c1          .
    dec c                                                             ; 0e6a: 0d          .
    jp nz,l0e4a                                                       ; 0e6b: c2 4a 0e    .J.
    call l0e88                                                        ; 0e6e: cd 88 0e    ...
screen2:
    ld h,d                                                            ; 0e71: 62          b
    ld l,e                                                            ; 0e72: 6b          k
    inc de                                                            ; 0e73: 13          .
    ld a,(attr_p)                                                     ; 0e74: 3a 8d 5c    :.\
    bit 0,(iy+tv_flag - err_nr)                                       ; 0e77: fd cb 02... ...
    jr z,l0e80                                                        ; 0e7b: 28 03       (.
    ld a,(bordcr)                                                     ; 0e7d: 3a 48 5c    :H\
; $0e80 referenced 1 time by $0e7b
l0e80:
    ld (hl),a                                                         ; 0e80: 77          w
    dec bc                                                            ; 0e81: 0b          .
    ldir                                                              ; 0e82: ed b0       ..
    pop bc                                                            ; 0e84: c1          .
    ld c,$21                                                          ; 0e85: 0e 21       .!
    ret                                                               ; 0e87: c9          .

; $0e88 referenced 2 times by $0e38, $0e6e
l0e88:
    ld a,h                                                            ; 0e88: 7c          |
    rrca                                                              ; 0e89: 0f          .
    rrca                                                              ; 0e8a: 0f          .
    rrca                                                              ; 0e8b: 0f          .
    dec a                                                             ; 0e8c: 3d          =
    or $50                                                            ; 0e8d: f6 50       .P
    ld h,a                                                            ; 0e8f: 67          g
    ex de,hl                                                          ; 0e90: eb          .
    ld h,c                                                            ; 0e91: 61          a
    ld l,b                                                            ; 0e92: 68          h
    add hl,hl                                                         ; 0e93: 29          )
    add hl,hl                                                         ; 0e94: 29          )
    add hl,hl                                                         ; 0e95: 29          )
    add hl,hl                                                         ; 0e96: 29          )
    add hl,hl                                                         ; 0e97: 29          )
    ld b,h                                                            ; 0e98: 44          D
    ld c,l                                                            ; 0e99: 4d          M
    ret                                                               ; 0e9a: c9          .

; $0e9b referenced 4 times by $0cd8, $0de7, $0e00, $0e45
l0e9b:
    ld a,$18                                                          ; 0e9b: 3e 18       >.
    sub b                                                             ; 0e9d: 90          .
    ld d,a                                                            ; 0e9e: 57          W
    rrca                                                              ; 0e9f: 0f          .
    rrca                                                              ; 0ea0: 0f          .
    rrca                                                              ; 0ea1: 0f          .
    and $e0                                                           ; 0ea2: e6 e0       ..
    ld l,a                                                            ; 0ea4: 6f          o
    ld a,d                                                            ; 0ea5: 7a          z
    and $18                                                           ; 0ea6: e6 18       ..
    or $40                                                            ; 0ea8: f6 40       .@
    ld h,a                                                            ; 0eaa: 67          g
    ret                                                               ; 0eab: c9          .

; $0eac referenced 1 time by $2503
l0eac:
    cp $5c                                                            ; 0eac: fe 5c       .\
    jr z,l0ebb                                                        ; 0eae: 28 0b       (.
    cp $7e                                                            ; 0eb0: fe 7e       .~
    jr nz,l0ede                                                       ; 0eb2: 20 2a        *
    pop af                                                            ; 0eb4: f1          .
    ld bc,$107c                                                       ; 0eb5: 01 7c 10    .|.
    jp s_push_po                                                      ; 0eb8: c3 0d 27    ..'

; $0ebb referenced 1 time by $0eae
l0ebb:
    pop af                                                            ; 0ebb: f1          .
    call syntax_z                                                     ; 0ebc: cd 30 25    .0%
    jp nz,s_stk_dec                                                   ; 0ebf: c2 b5 26    ..&
    ld de,0                                                           ; 0ec2: 11 00 00    ...
; $0ec5 referenced 1 time by $0edc
l0ec5:
    rst $20                                                           ; 0ec5: e7          .
    sub $30                                                           ; 0ec6: d6 30       .0
    cp 8                                                              ; 0ec8: fe 08       ..
    jr nc,l0f14                                                       ; 0eca: 30 48       0H
    ex de,hl                                                          ; 0ecc: eb          .
    add hl,hl                                                         ; 0ecd: 29          )
    jr c,l0ed4                                                        ; 0ece: 38 04       8.
    add hl,hl                                                         ; 0ed0: 29          )
    jr c,l0ed4                                                        ; 0ed1: 38 01       8.
    add hl,hl                                                         ; 0ed3: 29          )
; $0ed4 referenced 2 times by $0ece, $0ed1
l0ed4:
    jp c,report_6                                                     ; 0ed4: da ad 31    ..1
    ld d,0                                                            ; 0ed7: 16 00       ..
    ld e,a                                                            ; 0ed9: 5f          _
    add hl,de                                                         ; 0eda: 19          .
    ex de,hl                                                          ; 0edb: eb          .
    jr l0ec5                                                          ; 0edc: 18 e7       ..

; $0ede referenced 1 time by $0eb2
l0ede:
    cp $26                                                            ; 0ede: fe 26       .&
    jp nz,l16dc                                                       ; 0ee0: c2 dc 16    ...
    pop af                                                            ; 0ee3: f1          .
    call syntax_z                                                     ; 0ee4: cd 30 25    .0%
    jp nz,s_stk_dec                                                   ; 0ee7: c2 b5 26    ..&
    ld de,0                                                           ; 0eea: 11 00 00    ...
; $0eed referenced 1 time by $0f12
l0eed:
    rst $20                                                           ; 0eed: e7          .
    call alphanum                                                     ; 0eee: cd 88 2c    ..,
    jr nc,l0f14                                                       ; 0ef1: 30 21       0!
    cp $41                                                            ; 0ef3: fe 41       .A
    jp c,l0f00                                                        ; 0ef5: da 00 0f    ...
    or $20                                                            ; 0ef8: f6 20       .
    cp $67                                                            ; 0efa: fe 67       .g
    jr nc,l0f14                                                       ; 0efc: 30 16       0.
    sub $27                                                           ; 0efe: d6 27       .'
; $0f00 referenced 1 time by $0ef5
l0f00:
    and $0f                                                           ; 0f00: e6 0f       ..
    ld c,a                                                            ; 0f02: 4f          O
    ld a,d                                                            ; 0f03: 7a          z
    and $f0                                                           ; 0f04: e6 f0       ..
    jp nz,report_6                                                    ; 0f06: c2 ad 31    ..1
    ld a,c                                                            ; 0f09: 79          y
    ex de,hl                                                          ; 0f0a: eb          .
    add hl,hl                                                         ; 0f0b: 29          )
    add hl,hl                                                         ; 0f0c: 29          )
    add hl,hl                                                         ; 0f0d: 29          )
    add hl,hl                                                         ; 0f0e: 29          )
    or l                                                              ; 0f0f: b5          .
    ld l,a                                                            ; 0f10: 6f          o
    ex de,hl                                                          ; 0f11: eb          .
    jr l0eed                                                          ; 0f12: 18 d9       ..

; $0f14 referenced 3 times by $0eca, $0ef1, $0efc
l0f14:
    call l2cb3                                                        ; 0f14: cd b3 2c    ..,
    jp l2695                                                          ; 0f17: c3 95 26    ..&

; $0f1a referenced 1 time by $1a30
l0f1a:
    ld bc,$d8f0                                                       ; 0f1a: 01 f0 d8    ...
    call out_digit                                                    ; 0f1d: cd 2a 19    .*.
    ld bc,$fc18                                                       ; 0f20: 01 18 fc    ...
    call out_digit                                                    ; 0f23: cd 2a 19    .*.
    ld bc,$ff9c                                                       ; 0f26: 01 9c ff    ...
    jp l0cf4                                                          ; 0f29: c3 f4 0c    ...

; $0f2c referenced 3 times by $2152, $215e, $39d4
editor:
    ld hl,(err_sp)                                                    ; 0f2c: 2a 3d 5c    *=\
    push hl                                                           ; 0f2f: e5          .
; $0f30 referenced 1 time by $1088
edag:
    ld hl,eder                                                        ; 0f30: 21 7f 10    !..
    push hl                                                           ; 0f33: e5          .
    ld (err_sp),sp                                                    ; 0f34: ed 73 3d... .s=
l0f38:
    call waitkey                                                      ; 0f38: cd d4 15    ...
    push af                                                           ; 0f3b: f5          .
    ld hl,$c8                                                         ; 0f3c: 21 c8 00    !..
    ld a,(pip)                                                        ; 0f3f: 3a 39 5c    :9\
    ld e,a                                                            ; 0f42: 5f          _
    and a                                                             ; 0f43: a7          .
    call nz,l03b5                                                     ; 0f44: c4 b5 03    ...
    pop af                                                            ; 0f47: f1          .
    ld hl,$0f38                                                       ; 0f48: 21 38 0f    !8.
    push hl                                                           ; 0f4b: e5          .
    cp $18                                                            ; 0f4c: fe 18       ..
    jr nc,add_char                                                    ; 0f4e: 30 31       01
    cp 7                                                              ; 0f50: fe 07       ..
    jr c,add_char                                                     ; 0f52: 38 2d       8-
    cp $10                                                            ; 0f54: fe 10       ..
    jr c,l0f92                                                        ; 0f56: 38 3a       8:
    ld bc,2                                                           ; 0f58: 01 02 00    ...
    ld d,a                                                            ; 0f5b: 57          W
    cp $16                                                            ; 0f5c: fe 16       ..
    jr c,l0f6c                                                        ; 0f5e: 38 0c       8.
    inc bc                                                            ; 0f60: 03          .
    call waitkey                                                      ; 0f61: cd d4 15    ...
    bit 7,(iy+flagx - err_nr)                                         ; 0f64: fd cb 37... ..7
    jp z,l101a                                                        ; 0f68: ca 1a 10    ...
    ld e,a                                                            ; 0f6b: 5f          _
; $0f6c referenced 1 time by $0f5e
l0f6c:
    call waitkey                                                      ; 0f6c: cd d4 15    ...
    push de                                                           ; 0f6f: d5          .
    ld hl,(k_cur)                                                     ; 0f70: 2a 5b 5c    *[\
    res 0,(iy+mode - err_nr)                                          ; 0f73: fd cb 07... ...
    call make_room                                                    ; 0f77: cd 55 16    .U.
    pop bc                                                            ; 0f7a: c1          .
    inc hl                                                            ; 0f7b: 23          #
    ld (hl),b                                                         ; 0f7c: 70          p
    inc hl                                                            ; 0f7d: 23          #
    ld (hl),c                                                         ; 0f7e: 71          q
    jr l0f87                                                          ; 0f7f: 18 06       ..

; $0f81 referenced 6 times by $0345, $0f4e, $0f52, $107c, $240a, $398d
add_char:
    ld hl,(k_cur)                                                     ; 0f81: 2a 5b 5c    *[\
    call one_space                                                    ; 0f84: cd 52 16    .R.
; $0f87 referenced 1 time by $0f7f
l0f87:
    ld (de),a                                                         ; 0f87: 12          .
    inc de                                                            ; 0f88: 13          .
    ld (k_cur),de                                                     ; 0f89: ed 53 5b... .S[
    ret                                                               ; 0f8d: c9          .

; $0f8e referenced 1 time by $38fc
l0f8e:
    pop af                                                            ; 0f8e: f1          .
    jp l12ac                                                          ; 0f8f: c3 ac 12    ...

; $0f92 referenced 1 time by $0f56
l0f92:
    ld e,a                                                            ; 0f92: 5f          _
    ld d,0                                                            ; 0f93: 16 00       ..
    ld hl,$0f99                                                       ; 0f95: 21 99 0f    !..
    add hl,de                                                         ; 0f98: 19          .
    ld e,(hl)                                                         ; 0f99: 5e          ^
    add hl,de                                                         ; 0f9a: 19          .
    push hl                                                           ; 0f9b: e5          .
    ld hl,(k_cur)                                                     ; 0f9c: 2a 5b 5c    *[\
    ret                                                               ; 0f9f: c9          .

cursor:
    db edit_key - $                                                   ; 0fa0: 09          .
    db left_key - $                                                   ; 0fa1: 65          e
    db right_key - $                                                  ; 0fa2: 69          i
    db down_key - $                                                   ; 0fa3: 48          H
    db up_key - $                                                     ; 0fa4: a6          .
    db rubout - $                                                     ; 0fa5: 6e          n
    db n_l_key - $                                                    ; 0fa6: 77          w
    db function - $                                                   ; 0fa7: cf          .
    db graphics - $                                                   ; 0fa8: d4          .

; $0fa9 referenced 1 time by $38f5
edit_key:
    ld hl,(e_ppc)                                                     ; 0fa9: 2a 49 5c    *I\
    bit 5,(iy+flagx - err_nr)                                         ; 0fac: fd cb 37... ..7
    jp nz,l1095                                                       ; 0fb0: c2 95 10    ...
    call line_addr                                                    ; 0fb3: cd 6e 19    .n.
    call line_no                                                      ; 0fb6: cd 95 16    ...
    ld a,d                                                            ; 0fb9: 7a          z
    or e                                                              ; 0fba: b3          .
    jp z,l1095                                                        ; 0fbb: ca 95 10    ...
    push hl                                                           ; 0fbe: e5          .
    inc hl                                                            ; 0fbf: 23          #
    ld c,(hl)                                                         ; 0fc0: 4e          N
    inc hl                                                            ; 0fc1: 23          #
    ld b,(hl)                                                         ; 0fc2: 46          F
    ld hl,$0a                                                         ; 0fc3: 21 0a 00    !..
    add hl,bc                                                         ; 0fc6: 09          .
    ld b,h                                                            ; 0fc7: 44          D
    ld c,l                                                            ; 0fc8: 4d          M
    call test_room                                                    ; 0fc9: cd 05 1f    ...
    call l1095                                                        ; 0fcc: cd 95 10    ...
    ld hl,(curchl)                                                    ; 0fcf: 2a 51 5c    *Q\
    ex (sp),hl                                                        ; 0fd2: e3          .
    push hl                                                           ; 0fd3: e5          .
    ld a,$ff                                                          ; 0fd4: 3e ff       >.
    call l1601                                                        ; 0fd6: cd 01 16    ...
    pop hl                                                            ; 0fd9: e1          .
    dec hl                                                            ; 0fda: 2b          +
    call l1860                                                        ; 0fdb: cd 60 18    .`.
    ld hl,(e_line)                                                    ; 0fde: 2a 59 5c    *Y\
    call l18b5                                                        ; 0fe1: cd b5 18    ...
    ld (k_cur),hl                                                     ; 0fe4: 22 5b 5c    "[\
    pop hl                                                            ; 0fe7: e1          .
    jp chanflag                                                       ; 0fe8: c3 15 16    ...

down_key:
    bit 5,(iy+flagx - err_nr)                                         ; 0feb: fd cb 37... ..7
    jp nz,l2408                                                       ; 0fef: c2 08 24    ..$
    call l0af6                                                        ; 0ff2: cd f6 0a    ...
    ld hl,$5c49                                                       ; 0ff5: 21 49 5c    !I\
    ex de,hl                                                          ; 0ff8: eb          .
; $0ff9 referenced 1 time by $0ffc
l0ff9:
    call right_key                                                    ; 0ff9: cd 0b 10    ...
    djnz l0ff9                                                        ; 0ffc: 10 fb       ..
    ret                                                               ; 0ffe: c9          .

; $0fff referenced 1 time by $10dc
l0fff:
    ld a,8                                                            ; 0fff: 3e 08       >.
    xor (hl)                                                          ; 1001: ae          .
    ld (hl),a                                                         ; 1002: 77          w
    jp l10f4                                                          ; 1003: c3 f4 10    ...

; $1006 referenced 1 time by $1057
left_key:
    call left_edge                                                    ; 1006: cd 2a 10    .*.
    jr l100f                                                          ; 1009: 18 04       ..

; $100b referenced 1 time by $0ff9
right_key:
    jp l0099                                                          ; 100b: c3 99 00    ...

; $100e referenced 2 times by $9d, $a5
l100e:
    inc hl                                                            ; 100e: 23          #
; $100f referenced 1 time by $1009
l100f:
    ld (k_cur),hl                                                     ; 100f: 22 5b 5c    "[\
    ret                                                               ; 1012: c9          .

rubout:
    call left_edge                                                    ; 1013: cd 2a 10    .*.
    ex de,hl                                                          ; 1016: eb          .
    jp reclaim_1                                                      ; 1017: c3 e5 19    ...

; $101a referenced 1 time by $0f68
l101a:
    call waitkey                                                      ; 101a: cd d4 15    ...
; $101d referenced 2 times by $107a, $2411
n_l_key:
    pop hl                                                            ; 101d: e1          .
    pop hl                                                            ; 101e: e1          .
; $101f referenced 1 time by $1083
l101f:
    pop hl                                                            ; 101f: e1          .
    ld (err_sp),hl                                                    ; 1020: 22 3d 5c    "=\
    bit 7,(iy+err_nr - err_nr)                                        ; 1023: fd cb 00... ...
    ret nz                                                            ; 1027: c0          .
    ld sp,hl                                                          ; 1028: f9          .
    ret                                                               ; 1029: c9          .

; $102a referenced 2 times by $1006, $1013
left_edge:
    scf                                                               ; 102a: 37          7
    call l1195                                                        ; 102b: cd 95 11    ...
    sbc hl,de                                                         ; 102e: ed 52       .R
    add hl,de                                                         ; 1030: 19          .
    inc hl                                                            ; 1031: 23          #
    pop bc                                                            ; 1032: c1          .
    ret c                                                             ; 1033: d8          .
    push bc                                                           ; 1034: c5          .
    ld b,h                                                            ; 1035: 44          D
    ld c,l                                                            ; 1036: 4d          M
; $1037 referenced 1 time by $1047
l1037:
    ld h,d                                                            ; 1037: 62          b
    ld l,e                                                            ; 1038: 6b          k
    inc hl                                                            ; 1039: 23          #
    ld a,(de)                                                         ; 103a: 1a          .
    and $f0                                                           ; 103b: e6 f0       ..
    cp $10                                                            ; 103d: fe 10       ..
    jr nz,l1042                                                       ; 103f: 20 01        .
    inc hl                                                            ; 1041: 23          #
; $1042 referenced 1 time by $103f
l1042:
    and a                                                             ; 1042: a7          .
    sbc hl,bc                                                         ; 1043: ed 42       .B
    add hl,bc                                                         ; 1045: 09          .
    ex de,hl                                                          ; 1046: eb          .
    jr c,l1037                                                        ; 1047: 38 ee       8.
    ret                                                               ; 1049: c9          .

up_key:
    bit 5,(iy+flagx - err_nr)                                         ; 104a: fd cb 37... ..7
    ret nz                                                            ; 104e: c0          .
    call l0af6                                                        ; 104f: cd f6 0a    ...
    ld hl,(e_ppc)                                                     ; 1052: 2a 49 5c    *I\
    ex de,hl                                                          ; 1055: eb          .
; $1056 referenced 1 time by $105b
l1056:
    push bc                                                           ; 1056: c5          .
    call left_key                                                     ; 1057: cd 06 10    ...
    pop bc                                                            ; 105a: c1          .
    djnz l1056                                                        ; 105b: 10 f9       ..
    ret                                                               ; 105d: c9          .

; $105e referenced 1 time by $38e4
l105e:
    call syntax3                                                      ; 105e: cd 01 39    ..9
    ld a,b                                                            ; 1061: 78          x
    or c                                                              ; 1062: b1          .
    ret nz                                                            ; 1063: c0          .
    pop bc                                                            ; 1064: c1          .
    jp l38ec                                                          ; 1065: c3 eb 38    ..8

; $1068 referenced 1 time by $0dd6
l1068:
    push af                                                           ; 1068: f5          .
    call int_to_fp                                                    ; 1069: cd 3b 2d    .;-
    pop af                                                            ; 106c: f1          .
    ret nc                                                            ; 106d: d0          .
    pop bc                                                            ; 106e: c1          .
    call fp_to_bc                                                     ; 106f: cd a2 2d    ..-
    scf                                                               ; 1072: 37          7
    jp set_mem                                                        ; 1073: c3 c5 16    ...

function:
    bit 7,(iy+flagx - err_nr)                                         ; 1076: fd cb 37... ..7
    jr z,n_l_key                                                      ; 107a: 28 a1       (.
graphics:
    jp add_char                                                       ; 107c: c3 81 0f    ...

eder:
    bit 4,(iy+flags2 - err_nr)                                        ; 107f: fd cb 30... ..0
    jr z,l101f                                                        ; 1083: 28 9a       (.
    call l1167                                                        ; 1085: cd 67 11    .g.
    jp edag                                                           ; 1088: c3 30 0f    .0.

l108b:
    call l1167                                                        ; 108b: cd 67 11    .g.
    ld de,(s_posnl)                                                   ; 108e: ed 5b 8a... .[.
    jp l117e                                                          ; 1092: c3 7e 11    .~.

; $1095 referenced 4 times by $0fb0, $0fbb, $0fcc, $1362
l1095:
    push hl                                                           ; 1095: e5          .
    call l1190                                                        ; 1096: cd 90 11    ...
    dec hl                                                            ; 1099: 2b          +
    call reclaim_1                                                    ; 109a: cd e5 19    ...
    ld (k_cur),hl                                                     ; 109d: 22 5b 5c    "[\
    ld (iy+mode - err_nr),0                                           ; 10a0: fd 36 07... .6.
    pop hl                                                            ; 10a4: e1          .
    ret                                                               ; 10a5: c9          .

kyip:
    bit 3,(iy+tv_flag - err_nr)                                       ; 10a6: fd cb 02... ...
    call nz,l111d                                                     ; 10aa: c4 1d 11    ...
    and a                                                             ; 10ad: a7          .
    bit 5,(iy+flags - err_nr)                                         ; 10ae: fd cb 01... ...
    ret z                                                             ; 10b2: c8          .
; $10b3 referenced 1 time by $190c
l10b3:
    ld a,(last_k)                                                     ; 10b3: 3a 08 5c    :.\
    res 5,(iy+flags - err_nr)                                         ; 10b6: fd cb 01... ...
    push af                                                           ; 10ba: f5          .
    bit 5,(iy+tv_flag - err_nr)                                       ; 10bb: fd cb 02... ...
    call nz,clslower                                                  ; 10bf: c4 6e 0d    .n.
    pop af                                                            ; 10c2: f1          .
    cp $20                                                            ; 10c3: fe 20       .
    jr nc,l111b                                                       ; 10c5: 30 54       0T
    cp $10                                                            ; 10c7: fe 10       ..
    jr nc,l10fa                                                       ; 10c9: 30 2f       0/
    cp 6                                                              ; 10cb: fe 06       ..
    jr nc,l10d9                                                       ; 10cd: 30 0a       0.
    ld b,a                                                            ; 10cf: 47          G
    and 1                                                             ; 10d0: e6 01       ..
    ld c,a                                                            ; 10d2: 4f          O
    ld a,b                                                            ; 10d3: 78          x
    rra                                                               ; 10d4: 1f          .
    add a,$12                                                         ; 10d5: c6 12       ..
    jr l1105                                                          ; 10d7: 18 2c       .,

; $10d9 referenced 1 time by $10cd
l10d9:
    ld hl,$5c6a                                                       ; 10d9: 21 6a 5c    !j\
    jp z,l0fff                                                        ; 10dc: ca ff 0f    ...
    cp 7                                                              ; 10df: fe 07       ..
    jr nz,l10e6                                                       ; 10e1: 20 03        .
    dec a                                                             ; 10e3: 3d          =
    scf                                                               ; 10e4: 37          7
    ret                                                               ; 10e5: c9          .

; $10e6 referenced 1 time by $10e1
l10e6:
    cp $0e                                                            ; 10e6: fe 0e       ..
    ret c                                                             ; 10e8: d8          .
    sub $0d                                                           ; 10e9: d6 0d       ..
    ld hl,$5c41                                                       ; 10eb: 21 41 5c    !A\
    cp (hl)                                                           ; 10ee: be          .
    ld (hl),a                                                         ; 10ef: 77          w
    jr nz,l10f4                                                       ; 10f0: 20 02        .
    ld (hl),0                                                         ; 10f2: 36 00       6.
; $10f4 referenced 2 times by $1003, $10f0
l10f4:
    set 3,(iy+tv_flag - err_nr)                                       ; 10f4: fd cb 02... ...
    cp a                                                              ; 10f8: bf          .
    ret                                                               ; 10f9: c9          .

; $10fa referenced 1 time by $10c9
l10fa:
    ld b,a                                                            ; 10fa: 47          G
    and 7                                                             ; 10fb: e6 07       ..
    ld c,a                                                            ; 10fd: 4f          O
    ld a,$10                                                          ; 10fe: 3e 10       >.
    bit 3,b                                                           ; 1100: cb 58       .X
    jr nz,l1105                                                       ; 1102: 20 01        .
    inc a                                                             ; 1104: 3c          <
; $1105 referenced 2 times by $10d7, $1102
l1105:
    ld (iy+k_data - err_nr),c                                         ; 1105: fd 71 d3    .q.
    ld de,l110d                                                       ; 1108: 11 0d 11    ...
    jr l1113                                                          ; 110b: 18 06       ..

l110d:
    ld a,(k_data)                                                     ; 110d: 3a 0d 5c    :.\
    ld de,$10a6                                                       ; 1110: 11 a6 10    ...
; $1113 referenced 1 time by $110b
l1113:
    ld hl,(chans)                                                     ; 1113: 2a 4f 5c    *O\
    inc hl                                                            ; 1116: 23          #
    inc hl                                                            ; 1117: 23          #
    ld (hl),e                                                         ; 1118: 73          s
    inc hl                                                            ; 1119: 23          #
    ld (hl),d                                                         ; 111a: 72          r
; $111b referenced 1 time by $10c5
l111b:
    scf                                                               ; 111b: 37          7
    ret                                                               ; 111c: c9          .

; $111d referenced 2 times by $10aa, $216a
l111d:
    call trcurp                                                       ; 111d: cd 4d 0d    .M.
    res 3,(iy+tv_flag - err_nr)                                       ; 1120: fd cb 02... ...
    res 5,(iy+tv_flag - err_nr)                                       ; 1124: fd cb 02... ...
    ld hl,(s_posnl)                                                   ; 1128: 2a 8a 5c    *.\
    push hl                                                           ; 112b: e5          .
    ld hl,(err_sp)                                                    ; 112c: 2a 3d 5c    *=\
    push hl                                                           ; 112f: e5          .
    ld hl,l108b                                                       ; 1130: 21 8b 10    !..
    push hl                                                           ; 1133: e5          .
    ld (err_sp),sp                                                    ; 1134: ed 73 3d... .s=
    ld hl,(echo_e)                                                    ; 1138: 2a 82 5c    *.\
    push hl                                                           ; 113b: e5          .
    scf                                                               ; 113c: 37          7
    call l1195                                                        ; 113d: cd 95 11    ...
    ex de,hl                                                          ; 1140: eb          .
    call l187f                                                        ; 1141: cd 7f 18    ...
    ex de,hl                                                          ; 1144: eb          .
    call opcursor                                                     ; 1145: cd d3 18    ...
    ld hl,(s_posnl)                                                   ; 1148: 2a 8a 5c    *.\
    ex (sp),hl                                                        ; 114b: e3          .
    ex de,hl                                                          ; 114c: eb          .
    call trcurp                                                       ; 114d: cd 4d 0d    .M.
; $1150 referenced 1 time by $1165
l1150:
    ld a,(s_posnl+1)                                                  ; 1150: 3a 8b 5c    :.\
    sub d                                                             ; 1153: 92          .
    jr c,l117c                                                        ; 1154: 38 26       8&
    jr nz,l115e                                                       ; 1156: 20 06        .
    ld a,e                                                            ; 1158: 7b          {
    sub (iy+s_posnl - err_nr)                                         ; 1159: fd 96 50    ..P
    jr nc,l117c                                                       ; 115c: 30 1e       0.
; $115e referenced 1 time by $1156
l115e:
    ld a,$20                                                          ; 115e: 3e 20       >
    push de                                                           ; 1160: d5          .
    call prmain                                                       ; 1161: cd f4 09    ...
    pop de                                                            ; 1164: d1          .
    jr l1150                                                          ; 1165: 18 e9       ..

; $1167 referenced 3 times by $1085, $108b, $1892
l1167:
    exx                                                               ; 1167: d9          .
    ld d,0                                                            ; 1168: 16 00       ..
    ld e,(iy+rasp - err_nr)                                           ; 116a: fd 5e fe    .^.
    ld hl,$0864                                                       ; 116d: 21 64 08    !d.
    call l03b5                                                        ; 1170: cd b5 03    ...
    exx                                                               ; 1173: d9          .
    ld (iy+err_nr - err_nr),$ff                                       ; 1174: fd 36 00... .6.
    ret                                                               ; 1178: c9          .

; $1179 referenced 1 time by $11b9
l1179:
    pop hl                                                            ; 1179: e1          .
    ld sp,hl                                                          ; 117a: f9          .
    ret                                                               ; 117b: c9          .

; $117c referenced 2 times by $1154, $115c
l117c:
    pop de                                                            ; 117c: d1          .
    pop hl                                                            ; 117d: e1          .
; $117e referenced 1 time by $1092
l117e:
    pop hl                                                            ; 117e: e1          .
    ld (err_sp),hl                                                    ; 117f: 22 3d 5c    "=\
    pop bc                                                            ; 1182: c1          .
    push de                                                           ; 1183: d5          .
    call l0dd9                                                        ; 1184: cd d9 0d    ...
    pop hl                                                            ; 1187: e1          .
    ld (echo_e),hl                                                    ; 1188: 22 82 5c    ".\
    ld (iy+(x_ptr+1) - err_nr),0                                      ; 118b: fd 36 26... .6&
    ret                                                               ; 118f: c9          .

; $1190 referenced 1 time by $1096
l1190:
    ld hl,(worksp)                                                    ; 1190: 2a 61 5c    *a\
    dec hl                                                            ; 1193: 2b          +
    and a                                                             ; 1194: a7          .
; $1195 referenced 2 times by $102b, $113d
l1195:
    ld de,(e_line)                                                    ; 1195: ed 5b 59... .[Y
    bit 5,(iy+flagx - err_nr)                                         ; 1199: fd cb 37... ..7
    ret z                                                             ; 119d: c8          .
    ld de,(worksp)                                                    ; 119e: ed 5b 61... .[a
    ret c                                                             ; 11a2: d8          .
    ld hl,(stkbot)                                                    ; 11a3: 2a 63 5c    *c\
    ret                                                               ; 11a6: c9          .

; $11a7 referenced 3 times by $11b4, $12c5, $214b
l11a7:
    ld a,(hl)                                                         ; 11a7: 7e          ~
    cp $0e                                                            ; 11a8: fe 0e       ..
    ld bc,6                                                           ; 11aa: 01 06 00    ...
    call z,reclaim_2                                                  ; 11ad: cc e8 19    ...
    ld a,(hl)                                                         ; 11b0: 7e          ~
    inc hl                                                            ; 11b1: 23          #
    cp $0d                                                            ; 11b2: fe 0d       ..
    jr nz,l11a7                                                       ; 11b4: 20 f1        .
    ret                                                               ; 11b6: c9          .

; $11b7 referenced 1 time by $3ce4
l11cb:
    ldir                                                              ; 11b7: ed b0       ..
    jr l1179                                                          ; 11b9: 18 be       ..

new:
    di                                                                ; 11bb: f3          .
    xor a                                                             ; 11bc: af          .
    dec a                                                             ; 11bd: 3d          =
    ld de,(ramtop)                                                    ; 11be: ed 5b b2... .[.
    exx                                                               ; 11c2: d9          .
    ld bc,(udg)                                                       ; 11c3: ed 4b 7b... .K{
    ld de,(printer_buffer+254)                                        ; 11c7: ed 5b fe... .[.
    ld hl,(p_ramt)                                                    ; 11cb: 2a b4 5c    *.\
    exx                                                               ; 11ce: d9          .
; $11cf referenced 1 time by $03b2
l11cf:
    ex af,af'                                                         ; 11cf: 08          .
    xor a                                                             ; 11d0: af          .
    out ($ff),a                                                       ; 11d1: d3 ff       ..
    ld a,6                                                            ; 11d3: 3e 06       >.
    ld i,a                                                            ; 11d5: ed 47       .G
    ld iyh,d                                                          ; 11d7: fd 62       .b
    ld iyl,e                                                          ; 11d9: fd 6b       .k
    ex de,hl                                                          ; 11db: eb          .
    ld de,$5c00                                                       ; 11dc: 11 00 5c    ..\
    sbc hl,de                                                         ; 11df: ed 52       .R
    ld b,h                                                            ; 11e1: 44          D
    ld c,l                                                            ; 11e2: 4d          M
    ld h,d                                                            ; 11e3: 62          b
    ld l,e                                                            ; 11e4: 6b          k
    ld (hl),l                                                         ; 11e5: 75          u
    inc e                                                             ; 11e6: 1c          .
    ldir                                                              ; 11e7: ed b0       ..
    exx                                                               ; 11e9: d9          .
    ld (udg),bc                                                       ; 11ea: ed 43 7b... .C{
    ld (printer_buffer+254),de                                        ; 11ee: ed 53 fe... .S.
    ld (p_ramt),hl                                                    ; 11f2: 22 b4 5c    ".\
    exx                                                               ; 11f5: d9          .
    ex af,af'                                                         ; 11f6: 08          .
    inc a                                                             ; 11f7: 3c          <
    jp z,set_top                                                      ; 11f8: ca 13 12    ...
    ld iyh,iyh                                                        ; 11fb: fd 64       .d
    ld iyl,iyl                                                        ; 11fd: fd 6d       .m
    ld (p_ramt),hl                                                    ; 11ff: 22 b4 5c    ".\
    ld hl,$0cf7                                                       ; 1202: 21 f7 0c    !..
    ld de,$5b00                                                       ; 1205: 11 00 5b    ..[
    ld bc,$40                                                         ; 1208: 01 40 00    .@.
    ldir                                                              ; 120b: ed b0       ..
    ld hl,(p_ramt)                                                    ; 120d: 2a b4 5c    *.\
    jp setudg                                                         ; 1210: c3 e7 3c    ..<

; $1213 referenced 2 times by $11f8, $1391
set_top:
    ld (ramtop),hl                                                    ; 1213: 22 b2 5c    ".\
initial:
    ld hl,$3c00                                                       ; 1216: 21 00 3c    !.<
    ld (chars),hl                                                     ; 1219: 22 36 5c    "6\
    ld hl,$3c                                                         ; 121c: 21 3c 00    !<.
    ld (rasp),hl                                                      ; 121f: 22 38 5c    "8\
    ld hl,(ramtop)                                                    ; 1222: 2a b2 5c    *.\
    ld (hl),$3e                                                       ; 1225: 36 3e       6>
    dec hl                                                            ; 1227: 2b          +
    ld sp,hl                                                          ; 1228: f9          .
    dec hl                                                            ; 1229: 2b          +
    dec hl                                                            ; 122a: 2b          +
    ld (err_sp),hl                                                    ; 122b: 22 3d 5c    "=\
    im 1                                                              ; 122e: ed 56       .V
    ld iy,$5c3a                                                       ; 1230: fd 21 3a... .!:
    ei                                                                ; 1234: fb          .
    ld a,(chans)                                                      ; 1235: 3a 4f 5c    :O\
    and a                                                             ; 1238: a7          .
    ld (iy+pr_cc - err_nr),$ff                                        ; 1239: fd 36 46... .6F
    ld a,$15                                                          ; 123d: 3e 15       >.
    jp nz,l130f                                                       ; 123f: c2 0f 13    ...
    ld bc,$15                                                         ; 1242: 01 15 00    ...
    ld de,$15af                                                       ; 1245: 11 af 15    ...
    ld hl,$5cb6                                                       ; 1248: 21 b6 5c    !.\
    ld (chans),hl                                                     ; 124b: 22 4f 5c    "O\
    ex de,hl                                                          ; 124e: eb          .
    ldir                                                              ; 124f: ed b0       ..
    ex de,hl                                                          ; 1251: eb          .
    dec hl                                                            ; 1252: 2b          +
    ld (datadd),hl                                                    ; 1253: 22 57 5c    "W\
    inc hl                                                            ; 1256: 23          #
    ld (vars),hl                                                      ; 1257: 22 4b 5c    "K\
    ld (prog),hl                                                      ; 125a: 22 53 5c    "S\
    ld (hl),$80                                                       ; 125d: 36 80       6.
    inc hl                                                            ; 125f: 23          #
    ld (e_line),hl                                                    ; 1260: 22 59 5c    "Y\
    ld a,$38                                                          ; 1263: 3e 38       >8
    ld (bordcr),a                                                     ; 1265: 32 48 5c    2H\
    ld (attr_p),a                                                     ; 1268: 32 8d 5c    2.\
    ld hl,$0219                                                       ; 126b: 21 19 02    !..
    ld (repdel),hl                                                    ; 126e: 22 09 5c    ".\
    ld hl,$1216                                                       ; 1271: 21 16 12    !..
    ld (printer_buffer+254),hl                                        ; 1274: 22 fe 5b    ".[
    dec (iy+(kstate+4) - err_nr)                                      ; 1277: fd 35 ca    .5.
    dec (iy+kstate - err_nr)                                          ; 127a: fd 35 c6    .5.
    ld c,$0e                                                          ; 127d: 0e 0e       ..
    ld de,$5c10                                                       ; 127f: 11 10 5c    ..\
    ld hl,$15c6                                                       ; 1282: 21 c6 15    !..
    ldir                                                              ; 1285: ed b0       ..
    ld (iy+df_sz - err_nr),2                                          ; 1287: fd 36 31... .61
    ld a,7                                                            ; 128b: 3e 07       >.
    out (ula_port),a                                                  ; 128d: d3 fe       .. ; Border white
    call cls                                                          ; 128f: cd 6b 0d    .k.
    call l394d                                                        ; 1292: cd 4d 39    .M9
    xor a                                                             ; 1295: af          .
    ld de,$1396                                                       ; 1296: 11 96 13    ...
    call l0c0a                                                        ; 1299: cd 0a 0c    ...
    set 5,(iy+tv_flag - err_nr)                                       ; 129c: fd cb 02... ...
    jr l12a9                                                          ; 12a0: 18 07       ..

; $12a2 referenced 2 times by $12de, $15ac
l12a2:
    ld (iy+df_sz - err_nr),2                                          ; 12a2: fd 36 31... .61
    call autolist                                                     ; 12a6: cd 95 17    ...
; $12a9 referenced 1 time by $12a0
l12a9:
    call setmin                                                       ; 12a9: cd b0 16    ...
; $12ac referenced 3 times by $0f8f, $12cc, $138a
l12ac:
    xor a                                                             ; 12ac: af          .
    call l1601                                                        ; 12ad: cd 01 16    ...
    call l39d0                                                        ; 12b0: cd d0 39    ..9
    call l1b17                                                        ; 12b3: cd 17 1b    ...
    bit 7,(iy+err_nr - err_nr)                                        ; 12b6: fd cb 00... ...
    jr nz,l12cf                                                       ; 12ba: 20 13        .
    bit 4,(iy+flags2 - err_nr)                                        ; 12bc: fd cb 30... ..0
    jr z,l1301                                                        ; 12c0: 28 3f       (?
    ld hl,(e_line)                                                    ; 12c2: 2a 59 5c    *Y\
    call l11a7                                                        ; 12c5: cd a7 11    ...
    ld (iy+err_nr - err_nr),$ff                                       ; 12c8: fd 36 00... .6.
    jp l12ac                                                          ; 12cc: c3 ac 12    ...

; $12cf referenced 1 time by $12ba
l12cf:
    ld (iy+mode - err_nr),0                                           ; 12cf: fd 36 07... .6.
    call eline_no                                                     ; 12d3: cd fb 19    ...
    ld a,c                                                            ; 12d6: 79          y
    or b                                                              ; 12d7: b0          .
    jp nz,n_l_line                                                    ; 12d8: c2 5d 15    .].
    rst $18                                                           ; 12db: df          .
    cp $0d                                                            ; 12dc: fe 0d       ..
    jr z,l12a2                                                        ; 12de: 28 c2       (.
    bit 0,(iy+flags2 - err_nr)                                        ; 12e0: fd cb 30... ..0
    call nz,l0daf                                                     ; 12e4: c4 af 0d    ...
    call clslower                                                     ; 12e7: cd 6e 0d    .n.
    ld a,$19                                                          ; 12ea: 3e 19       >.
    sub (iy+(s_posn+1) - err_nr)                                      ; 12ec: fd 96 4f    ..O
    ld (scr_ct),a                                                     ; 12ef: 32 8c 5c    2.\
    set 7,(iy+flags - err_nr)                                         ; 12f2: fd cb 01... ...
    ld (iy+nsppc - err_nr),1                                          ; 12f6: fd 36 0a... .6.
    ld (iy+err_nr - err_nr),$ff                                       ; 12fa: fd 36 00... .6.
    call linerun                                                      ; 12fe: cd 8a 1b    ...
; $1301 referenced 1 time by $12c0
l1301:
    ld a,(err_nr)                                                     ; 1301: 3a 3a 5c    ::\
    res 5,(iy+flags - err_nr)                                         ; 1304: fd cb 01... ...
    call l38af                                                        ; 1308: cd af 38    ..8
    ld a,(err_nr)                                                     ; 130b: 3a 3a 5c    ::\
    inc a                                                             ; 130e: 3c          <
; $130f referenced 2 times by $123f, $18d0
l130f:
    push af                                                           ; 130f: f5          .
    ld bc,$c0f5                                                       ; 1310: 01 f5 c0    ...
    ld a,7                                                            ; 1313: 3e 07       >.
    out (c),a                                                         ; 1315: ed 79       .y
    ld a,$ff                                                          ; 1317: 3e ff       >.
    call l38ce                                                        ; 1319: cd ce 38    ..8
    ld hl,0                                                           ; 131c: 21 00 00    !..
    ld (defadd),hl                                                    ; 131f: 22 0b 5c    ".\
    ld (iy+(x_ptr+1) - err_nr),l                                      ; 1322: fd 75 26    .u&
    ld (iy+flagx - err_nr),l                                          ; 1325: fd 75 37    .u7
    inc hl                                                            ; 1328: 23          #
    ld (strms+6),hl                                                   ; 1329: 22 16 5c    ".\
    call setmin                                                       ; 132c: cd b0 16    ...
    call clslower                                                     ; 132f: cd 6e 0d    .n.
    pop af                                                            ; 1332: f1          .
    set 5,(iy+tv_flag - err_nr)                                       ; 1333: fd cb 02... ...
    ld de,$1402                                                       ; 1337: 11 02 14    ...
    set 0,(iy+flags - err_nr)                                         ; 133a: fd cb 01... ...
    call l0c0a                                                        ; 133e: cd 0a 0c    ...
    jp l134a                                                          ; 1341: c3 4a 13    .J.

; $1344 referenced 1 time by $1ec3
l1344:
    call restorez                                                     ; 1344: cd 45 1e    .E.
    jp cls                                                            ; 1347: c3 6b 0d    .k.

; $134a referenced 1 time by $1341
l134a:
    ld a,$2c                                                          ; 134a: 3e 2c       >,
    rst $10                                                           ; 134c: d7          .
    ld a,$20                                                          ; 134d: 3e 20       >
    rst $10                                                           ; 134f: d7          .
    ld bc,(ppc)                                                       ; 1350: ed 4b 45... .KE
    call out_num                                                      ; 1354: cd 1b 1a    ...
    ld a,$3a                                                          ; 1357: 3e 3a       >:
    rst $10                                                           ; 1359: d7          .
    ld b,0                                                            ; 135a: 06 00       ..
    ld c,(iy+subppc - err_nr)                                         ; 135c: fd 4e 0d    .N.
    call out_num                                                      ; 135f: cd 1b 1a    ...
    call l1095                                                        ; 1362: cd 95 10    ...
    ld a,(err_nr)                                                     ; 1365: 3a 3a 5c    ::\
    inc a                                                             ; 1368: 3c          <
    jr z,l1386                                                        ; 1369: 28 1b       (.
    cp 9                                                              ; 136b: fe 09       ..
    jr z,l1373                                                        ; 136d: 28 04       (.
    cp $15                                                            ; 136f: fe 15       ..
    jr nz,l1376                                                       ; 1371: 20 03        .
; $1373 referenced 1 time by $136d
l1373:
    inc (iy+subppc - err_nr)                                          ; 1373: fd 34 0d    .4.
; $1376 referenced 1 time by $1371
l1376:
    ld hl,$5c44                                                       ; 1376: 21 44 5c    !D\
    ld de,$5c70                                                       ; 1379: 11 70 5c    .p\
    ld bc,3                                                           ; 137c: 01 03 00    ...
    bit 7,(hl)                                                        ; 137f: cb 7e       .~
    jr z,l1384                                                        ; 1381: 28 01       (.
    add hl,bc                                                         ; 1383: 09          .
; $1384 referenced 1 time by $1381
l1384:
    lddr                                                              ; 1384: ed b8       ..
; $1386 referenced 1 time by $1369
l1386:
    ld (iy+nsppc - err_nr),$ff                                        ; 1386: fd 36 0a... .6.
    jp l12ac                                                          ; 138a: c3 ac 12    ...

; $138d referenced 1 time by $16d6
setudg3:
    ld (udg),hl                                                       ; 138d: 22 7b 5c    "{\
    dec hl                                                            ; 1390: 2b          +
    jp set_top                                                        ; 1391: c3 13 12    ...

    db 0, 0                                                           ; 1394: 00 00       ..
l1396:
    db $80                                                            ; 1396: 80          .
    db " ", $7f, " 1981 Nine Tiles Networks Lt", $80 + 'd'            ; 1397: 20 7f 20...  .
l13b6:
    db "Start tape and then press a ke", $80 + 'y'                    ; 13b6: 53 74 61... Sta
l13d5:
    db $0d, "Basic:", $80 + ' '                                       ; 13d5: 0d 42 61... .Ba
    db $0d, "Numeric array:", $80 + ' '                               ; 13dd: 0d 4e 75... .Nu
    db $0d, "String array:", $80 + ' '                                ; 13ed: 0d 53 74... .St
    db $0d, "Code:", $80 + ' '                                        ; 13fc: 0d 43 6f... .Co
l140c:
    db "O", $80 + 'K'                                                 ; 1403: 4f cb       O.
    db $14, "without", $0c, $80 + $08                                 ; 1405: 14 77 69... .wi
    db "Undefined variabl", $80 + 'e'                                 ; 140f: 55 6e 64... Und
    db "Bad subscrip", $80 + 't'                                      ; 1421: 42 61 64... Bad
    db "Out of memor", $80 + 'y'                                      ; 142e: 4f 75 74... Out
    db "Off scree", $80 + 'n'                                         ; 143b: 4f 66 66... Off
    db "Number too larg", $80 + 'e'                                   ; 1445: 4e 75 6d... Num
    db $1f, "without", $0e, $80 + $08                                 ; 1455: 1f 77 69... .wi
    db "End of fil", $80 + 'e'                                        ; 145f: 45 6e 64... End
    db 3, "statemen", $80 + 't'                                       ; 146a: 03 73 74... .st
    db "Bad argumen", $80 + 't'                                       ; 1474: 42 61 64... Bad
    db "Integer out of rang", $80 + 'e'                               ; 1480: 49 6e 74... Int
    db "Syntax erro", $80 + 'r'                                       ; 1494: 53 79 6e... Syn
    db "BREAK,", 9, "repeat", $80 + 's'                               ; 14a0: 42 52 45... BRE
    db "End of", 5, $80 + $08                                         ; 14ae: 45 6e 64... End
    db "Bad filenam", $80 + 'e'                                       ; 14b6: 42 61 64... Bad
    db "No room for lin", $80 + 'e'                                   ; 14c2: 4e 6f 20... No
    db 3, "in", $0f, $80 + $08                                        ; 14d2: 03 69 6e... .in
    db $0c, "without", $14, $80 + $08                                 ; 14d7: 0c 77 69... .wi
    db "Bad devic", $80 + 'e'                                         ; 14e1: 42 61 64... Bad
    db "Bad colou", $80 + 'r'                                         ; 14eb: 42 61 64... Bad
    db "BREAK into progra", $80 + 'm'                                 ; 14f5: 42 52 45... BRE
    db "Bad", $1e, "addres", $80 + 's'                                ; 1507: 42 61 64... Bad
    db "Missing statemen", $80 + 't'                                  ; 1512: 4d 69 73... Mis
    db "Bad strea", $80 + 'm'                                         ; 1523: 42 61 64... Bad
    db "Undefined F", $80 + 'N'                                       ; 152d: 55 6e 64... Und
    db "Parameter erro", $80 + 'r'                                    ; 1539: 50 61 72... Par
    db "Loading erro", $80 + 'r'                                      ; 1548: 4c 6f 61... Loa

; $1555 referenced 1 time by $38cb
l1555:
    pop hl                                                            ; 1555: e1          .
    ld hl,$1301                                                       ; 1556: 21 01 13    !..
    push hl                                                           ; 1559: e5          .
    jp nextstat                                                       ; 155a: c3 76 1b    .v.

; $155d referenced 1 time by $12d8
n_l_line:
    ld (e_ppc),bc                                                     ; 155d: ed 43 49... .CI
    ld hl,(ch_add)                                                    ; 1561: 2a 5d 5c    *]\
    ex de,hl                                                          ; 1564: eb          .
    ld hl,n_l_only                                                    ; 1565: 21 ce 18    !..
    push hl                                                           ; 1568: e5          .
    ld hl,(worksp)                                                    ; 1569: 2a 61 5c    *a\
    scf                                                               ; 156c: 37          7
    sbc hl,de                                                         ; 156d: ed 52       .R
    push hl                                                           ; 156f: e5          .
    ld h,b                                                            ; 1570: 60          `
    ld l,c                                                            ; 1571: 69          i
    call line_addr                                                    ; 1572: cd 6e 19    .n.
    jr nz,copy_over                                                   ; 1575: 20 06        .
    call next_one                                                     ; 1577: cd b8 19    ...
    call reclaim_2                                                    ; 157a: cd e8 19    ...
; $157d referenced 1 time by $1575
copy_over:
    pop bc                                                            ; 157d: c1          .
    ld a,c                                                            ; 157e: 79          y
    dec a                                                             ; 157f: 3d          =
    or b                                                              ; 1580: b0          .
    jr z,l15ab                                                        ; 1581: 28 28       ((
    push bc                                                           ; 1583: c5          .
    inc bc                                                            ; 1584: 03          .
    inc bc                                                            ; 1585: 03          .
    inc bc                                                            ; 1586: 03          .
    inc bc                                                            ; 1587: 03          .
    dec hl                                                            ; 1588: 2b          +
    ld de,(prog)                                                      ; 1589: ed 5b 53... .[S
    push de                                                           ; 158d: d5          .
    call make_room                                                    ; 158e: cd 55 16    .U.
    pop hl                                                            ; 1591: e1          .
    ld (prog),hl                                                      ; 1592: 22 53 5c    "S\
    pop bc                                                            ; 1595: c1          .
    push bc                                                           ; 1596: c5          .
    inc de                                                            ; 1597: 13          .
    ld hl,(worksp)                                                    ; 1598: 2a 61 5c    *a\
    dec hl                                                            ; 159b: 2b          +
    dec hl                                                            ; 159c: 2b          +
    lddr                                                              ; 159d: ed b8       ..
    ld hl,(e_ppc)                                                     ; 159f: 2a 49 5c    *I\
    ex de,hl                                                          ; 15a2: eb          .
    pop bc                                                            ; 15a3: c1          .
    ld (hl),b                                                         ; 15a4: 70          p
    dec hl                                                            ; 15a5: 2b          +
    ld (hl),c                                                         ; 15a6: 71          q
    dec hl                                                            ; 15a7: 2b          +
    ld (hl),e                                                         ; 15a8: 73          s
    dec hl                                                            ; 15a9: 2b          +
    ld (hl),d                                                         ; 15aa: 72          r
; $15ab referenced 1 time by $1581
l15ab:
    pop af                                                            ; 15ab: f1          .
    jp l12a2                                                          ; 15ac: c3 a2 12    ...

chantab:
    dw prmain                                                         ; 15af: f4 09       ..
    dw kyip                                                           ; 15b1: a6 10       ..
    db $4b                                                            ; 15b3: 4b          K
    dw prmain                                                         ; 15b4: f4 09       ..
    dw iderr                                                          ; 15b6: c4 15       ..
    db $53                                                            ; 15b8: 53          S
    dw l3963                                                          ; 15b9: 63 39       c9
    dw iderr                                                          ; 15bb: c4 15       ..
    db $52                                                            ; 15bd: 52          R
    dw x80_fdel                                                       ; 15be: a5 33       .3
    dw iderr                                                          ; 15c0: c4 15       ..
    db $50                                                            ; 15c2: 50          P
    db $80                                                            ; 15c3: 80          .

iderr:
    rst $08                                                           ; 15c4: cf          .
    db $12                                                            ; 15c5: 12          .  ; Report J Invalid I/O device
strmtab:
    db 1, 0, 6, 0, $0b, 0, 1, 0, 1, 0, 6, 0, $10, 0                   ; 15c6: 01 00 06... ...

; $15d4 referenced 5 times by $0981, $0f38, $0f61, $0f6c, $101a
waitkey:
    bit 5,(iy+tv_flag - err_nr)                                       ; 15d4: fd cb 02... ...
    jr nz,wtky2                                                       ; 15d8: 20 04        .
    set 3,(iy+tv_flag - err_nr)                                       ; 15da: fd cb 02... ...
; $15de referenced 2 times by $15d8, $15e2
wtky2:
    call inputad                                                      ; 15de: cd e6 15    ...
    ret c                                                             ; 15e1: d8          .
    jr z,wtky2                                                        ; 15e2: 28 fa       (.
    rst $08                                                           ; 15e4: cf          .
    db 7                                                              ; 15e5: 07          .  ; Report 8 End of file

; $15e6 referenced 2 times by $15de, $3629
inputad:
    exx                                                               ; 15e6: d9          .
    push hl                                                           ; 15e7: e5          .
    ld hl,(curchl)                                                    ; 15e8: 2a 51 5c    *Q\
    inc hl                                                            ; 15eb: 23          #
    inc hl                                                            ; 15ec: 23          #
    jr l15f7                                                          ; 15ed: 18 08       ..

; $15ef referenced 4 times by $1934, $1a33, $2f47, $2f59
out_code:
    ld e,$30                                                          ; 15ef: 1e 30       .0
    add a,e                                                           ; 15f1: 83          .
; $15f2 referenced 1 time by $10
print_sp:
    exx                                                               ; 15f2: d9          .
    push hl                                                           ; 15f3: e5          .
    ld hl,(curchl)                                                    ; 15f4: 2a 51 5c    *Q\
; $15f7 referenced 1 time by $15ed
l15f7:
    ld e,(hl)                                                         ; 15f7: 5e          ^
    inc hl                                                            ; 15f8: 23          #
    ld d,(hl)                                                         ; 15f9: 56          V
    ex de,hl                                                          ; 15fa: eb          .
    call l162c                                                        ; 15fb: cd 2c 16    .,.
    pop hl                                                            ; 15fe: e1          .
    exx                                                               ; 15ff: d9          .
    ret                                                               ; 1600: c9          .

; $1601 referenced 14 times by $0777, $0973, $0b19, $0c75, $0c9d, $0cc3, $0d96, $0fd6, $12ad, $1802, $1fd2, $2084, $2093, $3600
l1601:
    add a,a                                                           ; 1601: 87          .
    add a,$16                                                         ; 1602: c6 16       ..
    ld h,$5c                                                          ; 1604: 26 5c       &\
    ld l,a                                                            ; 1606: 6f          o
    ld e,(hl)                                                         ; 1607: 5e          ^
    inc hl                                                            ; 1608: 23          #
    ld d,(hl)                                                         ; 1609: 56          V
    ld a,e                                                            ; 160a: 7b          {
    or d                                                              ; 160b: b2          .
    jr nz,l1610                                                       ; 160c: 20 02        .
; $160e referenced 1 time by $2081
invstrm:
    rst $08                                                           ; 160e: cf          .
    db $17                                                            ; 160f: 17          .  ; Report O Invalid stream

; $1610 referenced 1 time by $160c
l1610:
    dec de                                                            ; 1610: 1b          .
    ld hl,(chans)                                                     ; 1611: 2a 4f 5c    *O\
    add hl,de                                                         ; 1614: 19          .
; $1615 referenced 3 times by $0fe8, $3607, $3638
chanflag:
    res 4,(iy+flags2 - err_nr)                                        ; 1615: fd cb 30... ..0
    ld (curchl),hl                                                    ; 1619: 22 51 5c    "Q\
    inc hl                                                            ; 161c: 23          #
    inc hl                                                            ; 161d: 23          #
    inc hl                                                            ; 161e: 23          #
    inc hl                                                            ; 161f: 23          #
    ld c,(hl)                                                         ; 1620: 4e          N
    ld hl,$162d                                                       ; 1621: 21 2d 16    !-.
    call l16dc                                                        ; 1624: cd dc 16    ...
    ret nc                                                            ; 1627: d0          .
    ld e,(hl)                                                         ; 1628: 5e          ^
    ld d,0                                                            ; 1629: 16 00       ..
    add hl,de                                                         ; 162b: 19          .
; $162c referenced 1 time by $15fb
l162c:
    jp (hl)                                                           ; 162c: e9          .

cltab:
    db $4b                                                            ; 162d: 4b          K
    db l1634 - $                                                      ; 162e: 06          .
    db $53                                                            ; 162f: 53          S
    db l1642 - $                                                      ; 1630: 12          .
    db $52                                                            ; 1631: 52          R
    db l1651 - $                                                      ; 1632: 1f          .
    db 0                                                              ; 1633: 00          .

l1634:
    res 5,(iy+flags - err_nr)                                         ; 1634: fd cb 01... ...
    set 4,(iy+flags2 - err_nr)                                        ; 1638: fd cb 30... ..0
    set 0,(iy+tv_flag - err_nr)                                       ; 163c: fd cb 02... ...
    jr l1646                                                          ; 1640: 18 04       ..

l1642:
    res 0,(iy+tv_flag - err_nr)                                       ; 1642: fd cb 02... ...
; $1646 referenced 1 time by $1640
l1646:
    jp trcurp                                                         ; 1646: c3 4d 0d    .M.

l1649:
    db $4b                                                            ; 1649: 4b          K
    db l1650 - $                                                      ; 164a: 06          .
    db $53                                                            ; 164b: 53          S
    db l1650 - $                                                      ; 164c: 04          .
    db $52                                                            ; 164d: 52          R
    db l1650 - $                                                      ; 164e: 02          .
    db 0                                                              ; 164f: 00          .

l1650:
    pop hl                                                            ; 1650: e1          .
l1651:
    ret                                                               ; 1651: c9          .

; $1652 referenced 1 time by $0f84
one_space:
    ld bc,1                                                           ; 1652: 01 01 00    ...
; $1655 referenced 14 times by $085e, $0889, $094f, $0955, $0f77, $158e, $16a2, $1d30, $1f98, $2699, $2b2e, $2bd8, $2c60, $3bfa
make_room:
    push hl                                                           ; 1655: e5          .
    call test_room                                                    ; 1656: cd 05 1f    ...
    pop hl                                                            ; 1659: e1          .
    call pointers                                                     ; 165a: cd 64 16    .d.
    ld hl,(stkend)                                                    ; 165d: 2a 65 5c    *e\
    ex de,hl                                                          ; 1660: eb          .
    lddr                                                              ; 1661: ed b8       ..
    ret                                                               ; 1663: c9          .

; $1664 referenced 2 times by $165a, $19f0
pointers:
    push af                                                           ; 1664: f5          .
    push hl                                                           ; 1665: e5          .
    ld hl,$5c4b                                                       ; 1666: 21 4b 5c    !K\
    ld a,$0e                                                          ; 1669: 3e 0e       >.
; $166b referenced 1 time by $1681
next_ptr:
    ld e,(hl)                                                         ; 166b: 5e          ^
    inc hl                                                            ; 166c: 23          #
    ld d,(hl)                                                         ; 166d: 56          V
    ex (sp),hl                                                        ; 166e: e3          .
    and a                                                             ; 166f: a7          .
    sbc hl,de                                                         ; 1670: ed 52       .R
    add hl,de                                                         ; 1672: 19          .
    ex (sp),hl                                                        ; 1673: e3          .
    jr nc,ptr_done                                                    ; 1674: 30 09       0.
    push de                                                           ; 1676: d5          .
    ex de,hl                                                          ; 1677: eb          .
    add hl,bc                                                         ; 1678: 09          .
    ex de,hl                                                          ; 1679: eb          .
    ld (hl),d                                                         ; 167a: 72          r
    dec hl                                                            ; 167b: 2b          +
    ld (hl),e                                                         ; 167c: 73          s
    inc hl                                                            ; 167d: 23          #
    pop de                                                            ; 167e: d1          .
; $167f referenced 1 time by $1674
ptr_done:
    inc hl                                                            ; 167f: 23          #
    dec a                                                             ; 1680: 3d          =
    jr nz,next_ptr                                                    ; 1681: 20 e8        .
    ex de,hl                                                          ; 1683: eb          .
    pop de                                                            ; 1684: d1          .
    pop af                                                            ; 1685: f1          .
    and a                                                             ; 1686: a7          .
    sbc hl,de                                                         ; 1687: ed 52       .R
    ld b,h                                                            ; 1689: 44          D
    ld c,l                                                            ; 168a: 4d          M
    inc bc                                                            ; 168b: 03          .
    add hl,de                                                         ; 168c: 19          .
    ex de,hl                                                          ; 168d: eb          .
    ret                                                               ; 168e: c9          .

l168f:
    db 0, 0                                                           ; 168f: 00 00       ..

; $1691 referenced 1 time by $1698
zero_de:
    ex de,hl                                                          ; 1691: eb          .
    ld de,$168f                                                       ; 1692: 11 8f 16    ...
; $1695 referenced 2 times by $0fb6, $1918
line_no:
    ld a,(hl)                                                         ; 1695: 7e          ~
    and $c0                                                           ; 1696: e6 c0       ..
    jr nz,zero_de                                                     ; 1698: 20 f7        .
    ld d,(hl)                                                         ; 169a: 56          V
    inc hl                                                            ; 169b: 23          #
    ld e,(hl)                                                         ; 169c: 5e          ^
    ret                                                               ; 169d: c9          .

; $169e referenced 1 time by $35
reserve:
    ld hl,(stkbot)                                                    ; 169e: 2a 63 5c    *c\
    dec hl                                                            ; 16a1: 2b          +
    call make_room                                                    ; 16a2: cd 55 16    .U.
    inc hl                                                            ; 16a5: 23          #
    inc hl                                                            ; 16a6: 23          #
    pop bc                                                            ; 16a7: c1          .
    ld (worksp),bc                                                    ; 16a8: ed 43 61... .Ca
    pop bc                                                            ; 16ac: c1          .
    ex de,hl                                                          ; 16ad: eb          .
    inc hl                                                            ; 16ae: 23          #
    ret                                                               ; 16af: c9          .

; $16b0 referenced 3 times by $12a9, $132c, $38eb
setmin:
    ld hl,(e_line)                                                    ; 16b0: 2a 59 5c    *Y\
    ld (hl),$0d                                                       ; 16b3: 36 0d       6.
    ld (k_cur),hl                                                     ; 16b5: 22 5b 5c    "[\
    inc hl                                                            ; 16b8: 23          #
    ld (hl),$80                                                       ; 16b9: 36 80       6.
    inc hl                                                            ; 16bb: 23          #
    ld (worksp),hl                                                    ; 16bc: 22 61 5c    "a\
; $16bf referenced 2 times by $1b29, $2100
setwork:
    ld hl,(worksp)                                                    ; 16bf: 2a 61 5c    *a\
    ld (stkbot),hl                                                    ; 16c2: 22 63 5c    "c\
; $16c5 referenced 3 times by $1073, $1a18, $5c
set_mem:
    ld hl,(stkbot)                                                    ; 16c5: 2a 63 5c    *c\
    ld (stkend),hl                                                    ; 16c8: 22 65 5c    "e\
    push hl                                                           ; 16cb: e5          .
    ld hl,$5c92                                                       ; 16cc: 21 92 5c    !.\
    ld (mem),hl                                                       ; 16cf: 22 68 5c    "h\
    pop hl                                                            ; 16d2: e1          .
    ret                                                               ; 16d3: c9          .

; $16d4 referenced 1 time by $09f1
setudg2:
    ex de,hl                                                          ; 16d4: eb          .
    inc hl                                                            ; 16d5: 23          #
    jp setudg3                                                        ; 16d6: c3 8d 13    ...

    db 0, 0                                                           ; 16d9: 00 00       ..

; $16db referenced 1 time by $16e1
l16db:
    inc hl                                                            ; 16db: 23          #
; $16dc referenced 5 times by $0ee0, $1624, $170e, $176f, $2729
l16dc:
    ld a,(hl)                                                         ; 16dc: 7e          ~
    and a                                                             ; 16dd: a7          .
    ret z                                                             ; 16de: c8          .
    cp c                                                              ; 16df: b9          .
    inc hl                                                            ; 16e0: 23          #
    jr nz,l16db                                                       ; 16e1: 20 f8        .
    scf                                                               ; 16e3: 37          7
    ret                                                               ; 16e4: c9          .

l16e5:
    call l171e                                                        ; 16e5: cd 1e 17    ...
    call l18a8                                                        ; 16e8: cd a8 18    ...
    ld bc,0                                                           ; 16eb: 01 00 00    ...
    ld de,$a3e2                                                       ; 16ee: 11 e2 a3    ...
    ex de,hl                                                          ; 16f1: eb          .
    add hl,de                                                         ; 16f2: 19          .
    jr c,l16fc                                                        ; 16f3: 38 07       8.
    ld bc,$15d4                                                       ; 16f5: 01 d4 15    ...
    add hl,bc                                                         ; 16f8: 09          .
    ld c,(hl)                                                         ; 16f9: 4e          N
    inc hl                                                            ; 16fa: 23          #
    ld b,(hl)                                                         ; 16fb: 46          F
; $16fc referenced 1 time by $16f3
l16fc:
    ex de,hl                                                          ; 16fc: eb          .
    ld (hl),c                                                         ; 16fd: 71          q
    inc hl                                                            ; 16fe: 23          #
    ld (hl),b                                                         ; 16ff: 70          p
    ret                                                               ; 1700: c9          .

; $1701 referenced 1 time by $18ac
l1701:
    push hl                                                           ; 1701: e5          .
    ld hl,(chans)                                                     ; 1702: 2a 4f 5c    *O\
    add hl,bc                                                         ; 1705: 09          .
    inc hl                                                            ; 1706: 23          #
    inc hl                                                            ; 1707: 23          #
    inc hl                                                            ; 1708: 23          #
    ld c,(hl)                                                         ; 1709: 4e          N
    ex de,hl                                                          ; 170a: eb          .
    ld hl,$1649                                                       ; 170b: 21 49 16    !I.
    call l16dc                                                        ; 170e: cd dc 16    ...
    ld c,(hl)                                                         ; 1711: 4e          N
    jr l1716                                                          ; 1712: 18 02       ..

; $1714 referenced 1 time by $1718
l1714:
    add hl,bc                                                         ; 1714: 09          .
    jp (hl)                                                           ; 1715: e9          .

; $1716 referenced 1 time by $1712
l1716:
    ld b,0                                                            ; 1716: 06 00       ..
    jr c,l1714                                                        ; 1718: 38 fa       8.
    jr invstrm2                                                       ; 171a: 18 09       ..

    pop hl                                                            ; 171c: e1          .
    ret                                                               ; 171d: c9          .

; $171e referenced 2 times by $16e5, $1739
l171e:
    call getbyte                                                      ; 171e: cd 94 1e    ...
    cp $10                                                            ; 1721: fe 10       ..
    jr c,l1727                                                        ; 1723: 38 02       8.
; $1725 referenced 3 times by $171a, $1754, $1793
invstrm2:
    rst $08                                                           ; 1725: cf          .
    db $17                                                            ; 1726: 17          .  ; Report O Invalid stream

; $1727 referenced 1 time by $1723
l1727:
    add a,3                                                           ; 1727: c6 03       ..
    rlca                                                              ; 1729: 07          .
    ld hl,$5c10                                                       ; 172a: 21 10 5c    !.\
    ld b,0                                                            ; 172d: 06 00       ..
    ld c,a                                                            ; 172f: 4f          O
    add hl,bc                                                         ; 1730: 09          .
    ld c,(hl)                                                         ; 1731: 4e          N
    inc hl                                                            ; 1732: 23          #
    ld b,(hl)                                                         ; 1733: 46          F
    dec hl                                                            ; 1734: 2b          +
    ret                                                               ; 1735: c9          .

l1736:
    rst $28                                                           ; 1736: ef          .
    db 1                                                              ; 1737: 01          .  ; exchange
    db $38                                                            ; 1738: 38          8  ; end-calc

    call l171e                                                        ; 1739: cd 1e 17    ...
    ld a,c                                                            ; 173c: 79          y
    or b                                                              ; 173d: b0          .
    jr z,l1756                                                        ; 173e: 28 16       (.
    ex de,hl                                                          ; 1740: eb          .
    ld hl,(chans)                                                     ; 1741: 2a 4f 5c    *O\
    add hl,bc                                                         ; 1744: 09          .
    inc hl                                                            ; 1745: 23          #
    inc hl                                                            ; 1746: 23          #
    inc hl                                                            ; 1747: 23          #
    ld a,(hl)                                                         ; 1748: 7e          ~
    ex de,hl                                                          ; 1749: eb          .
    cp $4b                                                            ; 174a: fe 4b       .K
    jr z,l1756                                                        ; 174c: 28 08       (.
    cp $53                                                            ; 174e: fe 53       .S
    jr z,l1756                                                        ; 1750: 28 04       (.
    cp $52                                                            ; 1752: fe 52       .R
    jr nz,invstrm2                                                    ; 1754: 20 cf        .
; $1756 referenced 3 times by $173e, $174c, $1750
l1756:
    call l175d                                                        ; 1756: cd 5d 17    .].
    ld (hl),e                                                         ; 1759: 73          s
    inc hl                                                            ; 175a: 23          #
    ld (hl),d                                                         ; 175b: 72          r
    ret                                                               ; 175c: c9          .

; $175d referenced 1 time by $1756
l175d:
    push hl                                                           ; 175d: e5          .
    call stk_fetch                                                    ; 175e: cd f1 2b    ..+
    ld a,c                                                            ; 1761: 79          y
    or b                                                              ; 1762: b0          .
    jr nz,l1767                                                       ; 1763: 20 02        .
; $1765 referenced 2 times by $1772, $178e
report_f:
    rst $08                                                           ; 1765: cf          .
    db $0e                                                            ; 1766: 0e          .  ; Report F Invalid file name

; $1767 referenced 1 time by $1763
l1767:
    push bc                                                           ; 1767: c5          .
    ld a,(de)                                                         ; 1768: 1a          .
    and $df                                                           ; 1769: e6 df       ..
    ld c,a                                                            ; 176b: 4f          O
    ld hl,$177a                                                       ; 176c: 21 7a 17    !z.
    call l16dc                                                        ; 176f: cd dc 16    ...
    jr nc,report_f                                                    ; 1772: 30 f1       0.
    ld b,0                                                            ; 1774: 06 00       ..
    ld c,(hl)                                                         ; 1776: 4e          N
    add hl,bc                                                         ; 1777: 09          .
    pop bc                                                            ; 1778: c1          .
    jp (hl)                                                           ; 1779: e9          .

l177a:
    db $4b                                                            ; 177a: 4b          K
    db l1781 - $                                                      ; 177b: 06          .
    db $53                                                            ; 177c: 53          S
    db l1785 - $                                                      ; 177d: 08          .
    db $52                                                            ; 177e: 52          R
    db l1789 - $                                                      ; 177f: 0a          .
    db 0                                                              ; 1780: 00          .

l1781:
    ld e,1                                                            ; 1781: 1e 01       ..
    jr l178b                                                          ; 1783: 18 06       ..

l1785:
    ld e,6                                                            ; 1785: 1e 06       ..
    jr l178b                                                          ; 1787: 18 02       ..

l1789:
    ld e,$0b                                                          ; 1789: 1e 0b       ..
; $178b referenced 2 times by $1783, $1787
l178b:
    dec bc                                                            ; 178b: 0b          .
    ld a,b                                                            ; 178c: 78          x
    or c                                                              ; 178d: b1          .
    jr nz,report_f                                                    ; 178e: 20 d5        .
    ld d,a                                                            ; 1790: 57          W
    pop hl                                                            ; 1791: e1          .
    ret                                                               ; 1792: c9          .

l1793:
    jr invstrm2                                                       ; 1793: 18 90       ..

; $1795 referenced 1 time by $12a6
autolist:
    ld (iy+tv_flag - err_nr),$10                                      ; 1795: fd 36 02... .6.
    ld (list_sp),sp                                                   ; 1799: ed 73 3f... .s?
    call l0daf                                                        ; 179d: cd af 0d    ...
    ld b,(iy+df_sz - err_nr)                                          ; 17a0: fd 46 31    .F1
    set 0,(iy+tv_flag - err_nr)                                       ; 17a3: fd cb 02... ...
    call l0e44                                                        ; 17a7: cd 44 0e    .D.
    res 0,(iy+tv_flag - err_nr)                                       ; 17aa: fd cb 02... ...
    set 0,(iy+flags2 - err_nr)                                        ; 17ae: fd cb 30... ..0
    ld de,(s_top)                                                     ; 17b2: ed 5b 6c... .[l
    ld hl,(e_ppc)                                                     ; 17b6: 2a 49 5c    *I\
    and a                                                             ; 17b9: a7          .
    sbc hl,de                                                         ; 17ba: ed 52       .R
    add hl,de                                                         ; 17bc: 19          .
    jr c,aul4                                                         ; 17bd: 38 22       8"
    push de                                                           ; 17bf: d5          .
    call line_addr                                                    ; 17c0: cd 6e 19    .n.
    ld de,$02c0                                                       ; 17c3: 11 c0 02    ...
    ex de,hl                                                          ; 17c6: eb          .
    sbc hl,de                                                         ; 17c7: ed 52       .R
    ex (sp),hl                                                        ; 17c9: e3          .
    call line_addr                                                    ; 17ca: cd 6e 19    .n.
    pop bc                                                            ; 17cd: c1          .
; $17ce referenced 1 time by $17df
l17ce:
    push bc                                                           ; 17ce: c5          .
    call next_one                                                     ; 17cf: cd b8 19    ...
    pop bc                                                            ; 17d2: c1          .
    add hl,bc                                                         ; 17d3: 09          .
    jr c,l17e4                                                        ; 17d4: 38 0e       8.
    ex de,hl                                                          ; 17d6: eb          .
    ld d,(hl)                                                         ; 17d7: 56          V
    inc hl                                                            ; 17d8: 23          #
    ld e,(hl)                                                         ; 17d9: 5e          ^
    dec hl                                                            ; 17da: 2b          +
    ld (s_top),de                                                     ; 17db: ed 53 6c... .Sl
    jr l17ce                                                          ; 17df: 18 ed       ..

; $17e1 referenced 1 time by $17bd
aul4:
    ld (s_top),hl                                                     ; 17e1: 22 6c 5c    "l\
; $17e4 referenced 1 time by $17d4
l17e4:
    ld hl,(s_top)                                                     ; 17e4: 2a 6c 5c    *l\
    call line_addr                                                    ; 17e7: cd 6e 19    .n.
    jr z,l17ed                                                        ; 17ea: 28 01       (.
    ex de,hl                                                          ; 17ec: eb          .
; $17ed referenced 1 time by $17ea
l17ed:
    call l1833                                                        ; 17ed: cd 33 18    .3.
    res 4,(iy+tv_flag - err_nr)                                       ; 17f0: fd cb 02... ...
    ret                                                               ; 17f4: c9          .

llist:
    ld a,3                                                            ; 17f5: 3e 03       >.
    jr l17fb                                                          ; 17f7: 18 02       ..

list:
    ld a,2                                                            ; 17f9: 3e 02       >.
; $17fb referenced 1 time by $17f7
l17fb:
    ld (iy+tv_flag - err_nr),0                                        ; 17fb: fd 36 02... .6.
    call syntax_z                                                     ; 17ff: cd 30 25    .0%
    call nz,l1601                                                     ; 1802: c4 01 16    ...
    rst $18                                                           ; 1805: df          .
    call l2070                                                        ; 1806: cd 70 20    .p
    jr c,l181f                                                        ; 1809: 38 14       8.
    rst $18                                                           ; 180b: df          .
    cp $2c                                                            ; 180c: fe 2c       .,
    jr z,l1819                                                        ; 180e: 28 09       (.
    cp $3b                                                            ; 1810: fe 3b       .;
    jr z,l1819                                                        ; 1812: 28 05       (.
l1814:
    call no_to_stk                                                    ; 1814: cd e6 1c    ...
    jr l1822                                                          ; 1817: 18 09       ..

; $1819 referenced 2 times by $180e, $1812
l1819:
    rst $20                                                           ; 1819: e7          .
    call class_6                                                      ; 181a: cd 82 1c    ...
    jr l1822                                                          ; 181d: 18 03       ..

; $181f referenced 1 time by $1809
l181f:
    call l1cde                                                        ; 181f: cd de 1c    ...
; $1822 referenced 2 times by $1817, $181d
l1822:
    call check_end                                                    ; 1822: cd ee 1b    ...
    call syntax3                                                      ; 1825: cd 01 39    ..9
    ld a,b                                                            ; 1828: 78          x
    and $3f                                                           ; 1829: e6 3f       .?
    ld h,a                                                            ; 182b: 67          g
    ld l,c                                                            ; 182c: 69          i
    ld (e_ppc),hl                                                     ; 182d: 22 49 5c    "I\
    call line_addr                                                    ; 1830: cd 6e 19    .n.
; $1833 referenced 1 time by $17ed
l1833:
    ld e,1                                                            ; 1833: 1e 01       ..
; $1835 referenced 3 times by $183d, $1845, $1853
l1835:
    call out_line                                                     ; 1835: cd 55 18    .U.
    rst $10                                                           ; 1838: d7          .
    bit 4,(iy+tv_flag - err_nr)                                       ; 1839: fd cb 02... ...
    jr z,l1835                                                        ; 183d: 28 f6       (.
    ld a,(df_sz)                                                      ; 183f: 3a 6b 5c    :k\
    sub (iy+(s_posn+1) - err_nr)                                      ; 1842: fd 96 4f    ..O
    jr nz,l1835                                                       ; 1845: 20 ee        .
    xor e                                                             ; 1847: ab          .
    ret z                                                             ; 1848: c8          .
    push de                                                           ; 1849: d5          .
    push hl                                                           ; 184a: e5          .
    ld hl,$5c6c                                                       ; 184b: 21 6c 5c    !l\
    call ln_fetch                                                     ; 184e: cd 0f 19    ...
    pop hl                                                            ; 1851: e1          .
    pop de                                                            ; 1852: d1          .
    jr l1835                                                          ; 1853: 18 e0       ..

; $1855 referenced 1 time by $1835
out_line:
    ld bc,(e_ppc)                                                     ; 1855: ed 4b 49... .KI
    call cp_lines                                                     ; 1859: cd 80 19    ...
    ld d,$8f                                                          ; 185c: 16 8f       ..
    jr z,test_end                                                     ; 185e: 28 05       (.
; $1860 referenced 1 time by $0fdb
l1860:
    ld de,0                                                           ; 1860: 11 00 00    ...
    rl e                                                              ; 1863: cb 13       ..
; $1865 referenced 1 time by $185e
test_end:
    ld (iy+breg - err_nr),e                                           ; 1865: fd 73 2d    .s-
    ld a,(hl)                                                         ; 1868: 7e          ~
    cp $40                                                            ; 1869: fe 40       .@
    pop bc                                                            ; 186b: c1          .
    ret nc                                                            ; 186c: d0          .
    push bc                                                           ; 186d: c5          .
    call out_no                                                       ; 186e: cd 28 1a    .(.
    inc hl                                                            ; 1871: 23          #
    inc hl                                                            ; 1872: 23          #
    inc hl                                                            ; 1873: 23          #
    ld a,d                                                            ; 1874: 7a          z
    and a                                                             ; 1875: a7          .
    res 0,(iy+flags - err_nr)                                         ; 1876: fd cb 01... ...
    jr z,l1883                                                        ; 187a: 28 07       (.
    call l18ee                                                        ; 187c: cd ee 18    ...
; $187f referenced 1 time by $1141
l187f:
    set 0,(iy+flags - err_nr)                                         ; 187f: fd cb 01... ...
; $1883 referenced 1 time by $187a
l1883:
    push de                                                           ; 1883: d5          .
    ex de,hl                                                          ; 1884: eb          .
; $1885 referenced 1 time by $18a4
l1885:
    ld hl,(x_ptr)                                                     ; 1885: 2a 5f 5c    *_\
    and a                                                             ; 1888: a7          .
    sbc hl,de                                                         ; 1889: ed 52       .R
    jr nz,l1895                                                       ; 188b: 20 08        .
    ld a,$3f                                                          ; 188d: 3e 3f       >?
    call l18ee                                                        ; 188f: cd ee 18    ...
    call l1167                                                        ; 1892: cd 67 11    .g.
; $1895 referenced 1 time by $188b
l1895:
    call opcursor                                                     ; 1895: cd d3 18    ...
    ex de,hl                                                          ; 1898: eb          .
    ld a,(hl)                                                         ; 1899: 7e          ~
    call number                                                       ; 189a: cd b1 18    ...
    inc hl                                                            ; 189d: 23          #
    cp $0d                                                            ; 189e: fe 0d       ..
    jr z,l18a6                                                        ; 18a0: 28 04       (.
    ex de,hl                                                          ; 18a2: eb          .
    rst $10                                                           ; 18a3: d7          .
    jr l1885                                                          ; 18a4: 18 df       ..

; $18a6 referenced 1 time by $18a0
l18a6:
    pop de                                                            ; 18a6: d1          .
    ret                                                               ; 18a7: c9          .

; $18a8 referenced 1 time by $16e8
l18a8:
    ld d,a                                                            ; 18a8: 57          W
    ld a,b                                                            ; 18a9: 78          x
    or c                                                              ; 18aa: b1          .
    ld a,d                                                            ; 18ab: 7a          z
    jp nz,l1701                                                       ; 18ac: c2 01 17    ...
    rst $08                                                           ; 18af: cf          .
    db $17                                                            ; 18b0: 17          .  ; Report O Invalid stream

; $18b1 referenced 4 times by $189a, $199a, $3b1d, $3b9d
number:
    cp $0e                                                            ; 18b1: fe 0e       ..
    ret nz                                                            ; 18b3: c0          .
; $18b4 referenced 1 time by $3cbf
l18b4:
    inc hl                                                            ; 18b4: 23          #
; $18b5 referenced 1 time by $0fe1
l18b5:
    inc hl                                                            ; 18b5: 23          #
    inc hl                                                            ; 18b6: 23          #
    inc hl                                                            ; 18b7: 23          #
    inc hl                                                            ; 18b8: 23          #
    inc hl                                                            ; 18b9: 23          #
    ld a,(hl)                                                         ; 18ba: 7e          ~
    ret                                                               ; 18bb: c9          .

l18bc:
    call find_int                                                     ; 18bc: cd 99 1e    ...
    push bc                                                           ; 18bf: c5          .
    call find_int                                                     ; 18c0: cd 99 1e    ...
    push bc                                                           ; 18c3: c5          .
    call find_int                                                     ; 18c4: cd 99 1e    ...
    push bc                                                           ; 18c7: c5          .
    pop hl                                                            ; 18c8: e1          .
    pop de                                                            ; 18c9: d1          .
    pop bc                                                            ; 18ca: c1          .
    ldir                                                              ; 18cb: ed b0       ..
    ret                                                               ; 18cd: c9          .

n_l_only:
    ld a,$10                                                          ; 18ce: 3e 10       >.
    jp l130f                                                          ; 18d0: c3 0f 13    ...

; $18d3 referenced 2 times by $1145, $1895
opcursor:
    ld hl,(k_cur)                                                     ; 18d3: 2a 5b 5c    *[\
    and a                                                             ; 18d6: a7          .
    sbc hl,de                                                         ; 18d7: ed 52       .R
    ret nz                                                            ; 18d9: c0          .
    ld a,(mode)                                                       ; 18da: 3a 41 5c    :A\
    cp 2                                                              ; 18dd: fe 02       ..
    jr c,l18e5                                                        ; 18df: 38 04       8.
    ld a,$47                                                          ; 18e1: 3e 47       >G
    jr l18ee                                                          ; 18e3: 18 09       ..

; $18e5 referenced 1 time by $18df
l18e5:
    ld a,$1e                                                          ; 18e5: 3e 1e       >.
    bit 3,(iy+flags2 - err_nr)                                        ; 18e7: fd cb 30... ..0
    jr z,l18ee                                                        ; 18eb: 28 01       (.
    inc a                                                             ; 18ed: 3c          <
; $18ee referenced 4 times by $187c, $188f, $18e3, $18eb
l18ee:
    exx                                                               ; 18ee: d9          .
    ld hl,$5c91                                                       ; 18ef: 21 91 5c    !.\
    ld d,(hl)                                                         ; 18f2: 56          V
    push de                                                           ; 18f3: d5          .
    ld (hl),$0c                                                       ; 18f4: 36 0c       6.
    call prmain                                                       ; 18f6: cd f4 09    ...
    pop hl                                                            ; 18f9: e1          .
    ld (iy+p_flag - err_nr),h                                         ; 18fa: fd 74 57    .tW
    exx                                                               ; 18fd: d9          .
    ret                                                               ; 18fe: c9          .

; $18ff referenced 1 time by $0cb0
l18ff:
    ld hl,$5c08                                                       ; 18ff: 21 08 5c    !.\
    ld (hl),l                                                         ; 1902: 75          u
; $1903 referenced 1 time by $190a
l1903:
    ld a,(hl)                                                         ; 1903: 7e          ~
    cp $0d                                                            ; 1904: fe 0d       ..
    jr z,l190c                                                        ; 1906: 28 04       (.
    cp $20                                                            ; 1908: fe 20       .
    jr c,l1903                                                        ; 190a: 38 f7       8.
; $190c referenced 1 time by $1906
l190c:
    jp l10b3                                                          ; 190c: c3 b3 10    ...

; $190f referenced 1 time by $184e
ln_fetch:
    ld e,(hl)                                                         ; 190f: 5e          ^
    inc hl                                                            ; 1910: 23          #
    ld d,(hl)                                                         ; 1911: 56          V
    push hl                                                           ; 1912: e5          .
    ex de,hl                                                          ; 1913: eb          .
    inc hl                                                            ; 1914: 23          #
    call line_addr                                                    ; 1915: cd 6e 19    .n.
    call line_no                                                      ; 1918: cd 95 16    ...
    pop hl                                                            ; 191b: e1          .
ln_store:
    bit 5,(iy+flagx - err_nr)                                         ; 191c: fd cb 37... ..7
    ret nz                                                            ; 1920: c0          .
    ld (hl),d                                                         ; 1921: 72          r
    dec hl                                                            ; 1922: 2b          +
    ld (hl),e                                                         ; 1923: 73          s
    ret                                                               ; 1924: c9          .

; $1925 referenced 1 time by $1932
lead_sp:
    ld a,e                                                            ; 1925: 7b          {
    and a                                                             ; 1926: a7          .
    ret m                                                             ; 1927: f8          .
    rst $10                                                           ; 1928: d7          .
    ret                                                               ; 1929: c9          .

; $192a referenced 4 times by $0cf4, $0cf9, $0f1d, $0f23
out_digit:
    xor a                                                             ; 192a: af          .
; $192b referenced 1 time by $192d
digit_inc:
    add hl,bc                                                         ; 192b: 09          .
    inc a                                                             ; 192c: 3c          <
    jr c,digit_inc                                                    ; 192d: 38 fc       8.
    sbc hl,bc                                                         ; 192f: ed 42       .B
    dec a                                                             ; 1931: 3d          =
    jr z,lead_sp                                                      ; 1932: 28 f1       (.
    jp out_code                                                       ; 1934: c3 ef 15    ...

l1937:
    rst $18                                                           ; 1937: df          .
    cp $ec                                                            ; 1938: fe ec       ..
    jr z,l1946                                                        ; 193a: 28 0a       (.
    cp $e8                                                            ; 193c: fe e8       ..
    jr z,l1959                                                        ; 193e: 28 19       (.
    cp $e2                                                            ; 1940: fe e2       ..
    jr z,l1967                                                        ; 1942: 28 23       (#
    rst $08                                                           ; 1944: cf          .
    db $0b                                                            ; 1945: 0b          .  ; Report C Nonsense in BASIC

; $1946 referenced 1 time by $193a
l1946:
    rst $20                                                           ; 1946: e7          .
    call class_6                                                      ; 1947: cd 82 1c    ...
    call check_end                                                    ; 194a: cd ee 1b    ...
    call syntax3                                                      ; 194d: cd 01 39    ..9
    call syntax_z                                                     ; 1950: cd 30 25    .0%
    ret z                                                             ; 1953: c8          .
    ld (p_posn),bc                                                    ; 1954: ed 43 7f... .C.
    ret                                                               ; 1958: c9          .

; $1959 referenced 2 times by $193e, $1967
l1959:
    rst $20                                                           ; 1959: e7          .
    call check_end                                                    ; 195a: cd ee 1b    ...
    call syntax_z                                                     ; 195d: cd 30 25    .0%
    ret z                                                             ; 1960: c8          .
    ld a,$fe                                                          ; 1961: 3e fe       >.
; $1963 referenced 1 time by $196c
l1963:
    ld (pr_cc),a                                                      ; 1963: 32 80 5c    2.\
    ret                                                               ; 1966: c9          .

; $1967 referenced 1 time by $1942
l1967:
    call l1959                                                        ; 1967: cd 59 19    .Y.
    ret z                                                             ; 196a: c8          .
    inc a                                                             ; 196b: 3c          <
    jr l1963                                                          ; 196c: 18 f5       ..

; $196e referenced 11 times by $0bd5, $0fb3, $1572, $17c0, $17ca, $17e7, $1830, $1915, $1b9e, $1e47, $3bb5
line_addr:
    push hl                                                           ; 196e: e5          .
    ld hl,(prog)                                                      ; 196f: 2a 53 5c    *S\
    ld d,h                                                            ; 1972: 54          T
    ld e,l                                                            ; 1973: 5d          ]
; $1974 referenced 1 time by $197e
next_test:
    pop bc                                                            ; 1974: c1          .
    call cp_lines                                                     ; 1975: cd 80 19    ...
    ret nc                                                            ; 1978: d0          .
    push bc                                                           ; 1979: c5          .
    call next_one                                                     ; 197a: cd b8 19    ...
    ex de,hl                                                          ; 197d: eb          .
    jr next_test                                                      ; 197e: 18 f4       ..

; $1980 referenced 2 times by $1859, $1975
cp_lines:
    ld a,(hl)                                                         ; 1980: 7e          ~
    cp b                                                              ; 1981: b8          .
    ret nz                                                            ; 1982: c0          .
    inc hl                                                            ; 1983: 23          #
    ld a,(hl)                                                         ; 1984: 7e          ~
    dec hl                                                            ; 1985: 2b          +
    cp c                                                              ; 1986: b9          .
    ret                                                               ; 1987: c9          .

l1988:
    db "MGT"                                                          ; 1988: 4d 47 54    MGT

; $198b referenced 4 times by $1be7, $1da4, $1e3f, $282b
skipstats:
    ld (ch_add),hl                                                    ; 198b: 22 5d 5c    "]\
    ld c,0                                                            ; 198e: 0e 00       ..
; $1990 referenced 1 time by $19af
l1990:
    dec d                                                             ; 1990: 15          .
    ret z                                                             ; 1991: c8          .
    rst $20                                                           ; 1992: e7          .
    cp e                                                              ; 1993: bb          .
    jr nz,l199a                                                       ; 1994: 20 04        .
    and a                                                             ; 1996: a7          .
    ret                                                               ; 1997: c9          .

; $1998 referenced 1 time by $19b3
l1998:
    inc hl                                                            ; 1998: 23          #
    ld a,(hl)                                                         ; 1999: 7e          ~
; $199a referenced 1 time by $1994
l199a:
    call number                                                       ; 199a: cd b1 18    ...
    ld (ch_add),hl                                                    ; 199d: 22 5d 5c    "]\
    cp $22                                                            ; 19a0: fe 22       ."
    jr nz,l19a5                                                       ; 19a2: 20 01        .
    dec c                                                             ; 19a4: 0d          .
; $19a5 referenced 1 time by $19a2
l19a5:
    cp $3a                                                            ; 19a5: fe 3a       .:
    jr z,fincstat                                                     ; 19a7: 28 04       (.
    cp $cb                                                            ; 19a9: fe cb       ..
    jr nz,l19b1                                                       ; 19ab: 20 04        .
; $19ad referenced 1 time by $19a7
fincstat:
    bit 0,c                                                           ; 19ad: cb 41       .A
    jr z,l1990                                                        ; 19af: 28 df       (.
; $19b1 referenced 1 time by $19ab
l19b1:
    cp $0d                                                            ; 19b1: fe 0d       ..
    jr nz,l1998                                                       ; 19b3: 20 e3        .
    dec d                                                             ; 19b5: 15          .
    scf                                                               ; 19b6: 37          7
    ret                                                               ; 19b7: c9          .

; $19b8 referenced 12 times by $08e5, $0902, $0933, $0940, $0bbe, $1577, $17cf, $197a, $292b, $2c18, $3b0e, $3c5f
next_one:
    push hl                                                           ; 19b8: e5          .
    ld a,(hl)                                                         ; 19b9: 7e          ~
    cp $40                                                            ; 19ba: fe 40       .@
    jr c,lines                                                        ; 19bc: 38 17       8.
    bit 5,a                                                           ; 19be: cb 6f       .o
    jr z,bit_5_nil                                                    ; 19c0: 28 14       (.
    add a,a                                                           ; 19c2: 87          .
    jp m,next_five                                                    ; 19c3: fa c7 19    ...
    ccf                                                               ; 19c6: 3f          ?
; $19c7 referenced 1 time by $19c3
next_five:
    ld bc,5                                                           ; 19c7: 01 05 00    ...
    jr nc,next_lett                                                   ; 19ca: 30 02       0.
    ld c,$12                                                          ; 19cc: 0e 12       ..
; $19ce referenced 2 times by $19ca, $19d1
next_lett:
    rla                                                               ; 19ce: 17          .
    inc hl                                                            ; 19cf: 23          #
    ld a,(hl)                                                         ; 19d0: 7e          ~
    jr nc,next_lett                                                   ; 19d1: 30 fb       0.
    jr next_add                                                       ; 19d3: 18 06       ..

; $19d5 referenced 1 time by $19bc
lines:
    inc hl                                                            ; 19d5: 23          #
; $19d6 referenced 1 time by $19c0
bit_5_nil:
    inc hl                                                            ; 19d6: 23          #
    ld c,(hl)                                                         ; 19d7: 4e          N
    inc hl                                                            ; 19d8: 23          #
    ld b,(hl)                                                         ; 19d9: 46          F
    inc hl                                                            ; 19da: 23          #
; $19db referenced 1 time by $19d3
next_add:
    add hl,bc                                                         ; 19db: 09          .
    pop de                                                            ; 19dc: d1          .
; $19dd referenced 1 time by $19e5
differ:
    and a                                                             ; 19dd: a7          .
    sbc hl,de                                                         ; 19de: ed 52       .R
    ld b,h                                                            ; 19e0: 44          D
    ld c,l                                                            ; 19e1: 4d          M
    add hl,de                                                         ; 19e2: 19          .
    ex de,hl                                                          ; 19e3: eb          .
    ret                                                               ; 19e4: c9          .

; $19e5 referenced 6 times by $0883, $0bcd, $1017, $109a, $1ec0, $3a96
reclaim_1:
    call differ                                                       ; 19e5: cd dd 19    ...
; $19e8 referenced 8 times by $0845, $0936, $096b, $11ad, $157a, $2bbd, $2c1b, $3c08
reclaim_2:
    push bc                                                           ; 19e8: c5          .
    ld a,b                                                            ; 19e9: 78          x
    cpl                                                               ; 19ea: 2f          /
    ld b,a                                                            ; 19eb: 47          G
    ld a,c                                                            ; 19ec: 79          y
    cpl                                                               ; 19ed: 2f          /
    ld c,a                                                            ; 19ee: 4f          O
    inc bc                                                            ; 19ef: 03          .
    call pointers                                                     ; 19f0: cd 64 16    .d.
    ex de,hl                                                          ; 19f3: eb          .
    pop hl                                                            ; 19f4: e1          .
    add hl,de                                                         ; 19f5: 19          .
    push de                                                           ; 19f6: d5          .
    ldir                                                              ; 19f7: ed b0       ..
    pop hl                                                            ; 19f9: e1          .
    ret                                                               ; 19fa: c9          .

; $19fb referenced 2 times by $12d3, $1b1b
eline_no:
    ld hl,(e_line)                                                    ; 19fb: 2a 59 5c    *Y\
    dec hl                                                            ; 19fe: 2b          +
    ld (ch_add),hl                                                    ; 19ff: 22 5d 5c    "]\
    rst $20                                                           ; 1a02: e7          .
    ld hl,$5c92                                                       ; 1a03: 21 92 5c    !.\
    ld (stkend),hl                                                    ; 1a06: 22 65 5c    "e\
    call l0dd3                                                        ; 1a09: cd d3 0d    ...
    call fp_to_bc                                                     ; 1a0c: cd a2 2d    ..-
    jr c,no_number                                                    ; 1a0f: 38 04       8.
    ld hl,$c000                                                       ; 1a11: 21 00 c0    !..
    add hl,bc                                                         ; 1a14: 09          .
; $1a15 referenced 1 time by $1a0f
no_number:
    jp c,report_c                                                     ; 1a15: da 8a 1c    ...
    jp set_mem                                                        ; 1a18: c3 c5 16    ...

; $1a1b referenced 3 times by $1354, $135f, $2f88
out_num:
    push de                                                           ; 1a1b: d5          .
    push hl                                                           ; 1a1c: e5          .
    xor a                                                             ; 1a1d: af          .
    bit 7,b                                                           ; 1a1e: cb 78       .x
    jr nz,units                                                       ; 1a20: 20 11        .
    ld h,b                                                            ; 1a22: 60          `
    ld l,c                                                            ; 1a23: 69          i
    ld e,$ff                                                          ; 1a24: 1e ff       ..
    jr thousand                                                       ; 1a26: 18 08       ..

; $1a28 referenced 1 time by $186e
out_no:
    push de                                                           ; 1a28: d5          .
    ld d,(hl)                                                         ; 1a29: 56          V
    inc hl                                                            ; 1a2a: 23          #
    ld e,(hl)                                                         ; 1a2b: 5e          ^
    push hl                                                           ; 1a2c: e5          .
    ex de,hl                                                          ; 1a2d: eb          .
    ld e,$20                                                          ; 1a2e: 1e 20       .
; $1a30 referenced 1 time by $1a26
thousand:
    call l0f1a                                                        ; 1a30: cd 1a 0f    ...
; $1a33 referenced 1 time by $1a20
units:
    call out_code                                                     ; 1a33: cd ef 15    ...
    pop hl                                                            ; 1a36: e1          .
    pop de                                                            ; 1a37: d1          .
    ret                                                               ; 1a38: c9          .

syntax:
    db p_deffn - $                                                    ; 1a39: 9e          .
    db p_cat - $                                                      ; 1a3a: d0          .
    db p_format - $                                                   ; 1a3b: aa          .
    db p_move - $                                                     ; 1a3c: ac          .
    db p_cat - $                                                      ; 1a3d: cd          .
    db p_open - $                                                     ; 1a3e: b2          .
    db p_close - $                                                    ; 1a3f: 92          .
    db p_merge - $                                                    ; 1a40: d0          .
    db p_verify - $                                                   ; 1a41: ce          .
    db p_beep - $                                                     ; 1a42: 84          .
    db p_circle - $                                                   ; 1a43: 8a          .
    db p_pen - $                                                      ; 1a44: cd          .
    db p_paper - $                                                    ; 1a45: cd          .
    db p_flash - $                                                    ; 1a46: cd          .
    db p_bright - $                                                   ; 1a47: cd          .
    db p_inverse - $                                                  ; 1a48: cd          .
    db p_over - $                                                     ; 1a49: cd          .
    db p_out - $                                                      ; 1a4a: ac          .
    db p_lprint - $                                                   ; 1a4b: 75          u
    db p_llist - $                                                    ; 1a4c: 77          w
    db p_stop - $                                                     ; 1a4d: 32          2
    db p_read - $                                                     ; 1a4e: b0          .
    db p_data - $                                                     ; 1a4f: 85          .
    db p_restore - $                                                  ; 1a50: b4          .
    db p_new - $                                                      ; 1a51: 4c          L
    db p_border - $                                                   ; 1a52: 78          x
    db p_cont - $                                                     ; 1a53: 5a          Z
    db p_dim - $                                                      ; 1a54: 43          C
    db p_rem - $                                                      ; 1a55: 45          E
    db p_for - $                                                      ; 1a56: 2f          /
    db p_goto - $                                                     ; 1a57: 1d          .
    db p_gosub - $                                                    ; 1a58: 24          $
    db p_input - $                                                    ; 1a59: 3b          ;
    db p_load - $                                                     ; 1a5a: b4          .
    db p_list - $                                                     ; 1a5b: 48          H
    db p_let - $                                                      ; 1a5c: 15          .
    db p_pause - $                                                    ; 1a5d: 5d          ]
    db p_next - $                                                     ; 1a5e: 2f          /
    db p_poke - $                                                     ; 1a5f: 47          G
    db p_print - $                                                    ; 1a60: 31          1
    db p_plot - $                                                     ; 1a61: 55          U
    db p_run - $                                                      ; 1a62: 3e          >
    db p_save - $                                                     ; 1a63: aa          .
    db p_rand - $                                                     ; 1a64: 46          F
    db p_if - $                                                       ; 1a65: 12          .
    db p_cls - $                                                      ; 1a66: 4d          M
    db p_draw - $                                                     ; 1a67: 77          w
    db p_clear - $                                                    ; 1a68: 48          H
    db p_return - $                                                   ; 1a69: 19          .
    db p_copy - $                                                     ; 1a6a: 53          S
    db p_delete - $                                                   ; 1a6b: 6f          o
    db p_edit - $                                                     ; 1a6c: 76          v
    db p_renum - $                                                    ; 1a6d: 94          .
    db p_palette - $                                                  ; 1a6e: 8c          .
    db p_sound - $                                                    ; 1a6f: 98          .
    db p_onerr - $                                                    ; 1a70: 7d          }
p_let:
    db 1                                                              ; 1a71: 01          .
    db $3d                                                            ; 1a72: 3d          =
    db 2                                                              ; 1a73: 02          .
p_goto:
    db $0c                                                            ; 1a74: 0c          .
    dw goto                                                           ; 1a75: 67 1e       g.
p_if:
    db 6                                                              ; 1a77: 06          .
    db $cb                                                            ; 1a78: cb          .
    db 5                                                              ; 1a79: 05          .
    dw _if                                                            ; 1a7a: f0 1c       ..
p_gosub:
    db $0c                                                            ; 1a7c: 0c          .
    dw gosub                                                          ; 1a7d: ed 1e       ..
p_stop:
    db 0                                                              ; 1a7f: 00          .
    dw stop                                                           ; 1a80: ee 1c       ..
p_return:
    db 0                                                              ; 1a82: 00          .
    dw return                                                         ; 1a83: 23 1f       #.
p_for:
    db 4                                                              ; 1a85: 04          .
    db $3d                                                            ; 1a86: 3d          =
    db 6                                                              ; 1a87: 06          .
    db $cc                                                            ; 1a88: cc          .
    db 6                                                              ; 1a89: 06          .
    db 5                                                              ; 1a8a: 05          .
    dw for                                                            ; 1a8b: 03 1d       ..
p_next:
    db 4                                                              ; 1a8d: 04          .
    db 0                                                              ; 1a8e: 00          .
    dw next                                                           ; 1a8f: ab 1d       ..
p_print:
    db 5                                                              ; 1a91: 05          .
    dw print                                                          ; 1a92: cd 1f       ..
p_input:
    db 5                                                              ; 1a94: 05          .
    dw input                                                          ; 1a95: 89 20       .
p_dim:
    db 5                                                              ; 1a97: 05          .
    dw dim                                                            ; 1a98: 02 2c       .,
p_rem:
    db 5                                                              ; 1a9a: 05          .
    dw rem                                                            ; 1a9b: b2 1b       ..
p_new:
    db 0                                                              ; 1a9d: 00          .
    dw new                                                            ; 1a9e: bb 11       ..
p_run:
    db 3                                                              ; 1aa0: 03          .
    dw run                                                            ; 1aa1: a1 1e       ..
p_list:
    db 5                                                              ; 1aa3: 05          .
    dw list                                                           ; 1aa4: f9 17       ..
p_poke:
    db 8                                                              ; 1aa6: 08          .
    db 0                                                              ; 1aa7: 00          .
    dw poke                                                           ; 1aa8: 80 1e       ..
p_rand:
    db 3                                                              ; 1aaa: 03          .
    dw rand                                                           ; 1aab: 4f 1e       O.
p_cont:
    db 0                                                              ; 1aad: 00          .
    dw cont                                                           ; 1aae: 5f 1e       _.
p_clear:
    db 3                                                              ; 1ab0: 03          .
    dw clear                                                          ; 1ab1: ac 1e       ..
p_cls:
    db 0                                                              ; 1ab3: 00          .
    dw cls                                                            ; 1ab4: 6b 0d       k.
p_plot:
    db 9                                                              ; 1ab6: 09          .
    db 0                                                              ; 1ab7: 00          .
    dw plot                                                           ; 1ab8: dc 22       ."
p_pause:
    db $0c                                                            ; 1aba: 0c          .
    dw pause                                                          ; 1abb: 3a 1f       :.
p_copy:
    db 3                                                              ; 1abd: 03          .
    dw copy                                                           ; 1abe: 1c 0b       ..
p_lprint:
    db 5                                                              ; 1ac0: 05          .
    dw lprint                                                         ; 1ac1: c9 1f       ..
p_llist:
    db 5                                                              ; 1ac3: 05          .
    dw llist                                                          ; 1ac4: f5 17       ..
p_beep:
    db 8                                                              ; 1ac6: 08          .
    db 0                                                              ; 1ac7: 00          .
    dw l03f8                                                          ; 1ac8: f8 03       ..
p_border:
    db $0c                                                            ; 1aca: 0c          .
    dw l2294                                                          ; 1acb: 94 22       ."
p_circle:
    db 9                                                              ; 1acd: 09          .
    db 5                                                              ; 1ace: 05          .
    dw circle                                                         ; 1acf: 20 23        #
p_close:
    db $0c                                                            ; 1ad1: 0c          .
    dw l16e5                                                          ; 1ad2: e5 16       ..
p_data:
    db 5                                                              ; 1ad4: 05          .
    dw l1e27                                                          ; 1ad5: 27 1e       '.
p_deffn:
    db 5                                                              ; 1ad7: 05          .
    dw l1f60                                                          ; 1ad8: 60 1f       `.
p_delete:
    db 8                                                              ; 1ada: 08          .
    db 0                                                              ; 1adb: 00          .
    dw l0bbb                                                          ; 1adc: bb 0b       ..
p_draw:
    db 9                                                              ; 1ade: 09          .
    db 5                                                              ; 1adf: 05          .
    dw l2382                                                          ; 1ae0: 82 23       .#
p_edit:
    db 3                                                              ; 1ae2: 03          .
    dw l38e6                                                          ; 1ae3: e4 38       .8
p_format:
    db $0c                                                            ; 1ae5: 0c          .
    dw l0a58                                                          ; 1ae6: 77 0a       w.
p_move:
    db 8                                                              ; 1ae8: 08          .
    db $2c                                                            ; 1ae9: 2c          ,
    db $0c                                                            ; 1aea: 0c          .
    dw l18bc                                                          ; 1aeb: bc 18       ..
p_onerr:
    db 5                                                              ; 1aed: 05          .
    dw l1937                                                          ; 1aee: 37 19       7.
p_open:
    db 6                                                              ; 1af0: 06          .
    db $2c                                                            ; 1af1: 2c          ,
    db $0a                                                            ; 1af2: 0a          .
    db 0                                                              ; 1af3: 00          .
    dw l1736                                                          ; 1af4: 36 17       6.
p_out:
    db 8                                                              ; 1af6: 08          .
    db 0                                                              ; 1af7: 00          .
    dw _out                                                           ; 1af8: 7a 1e       z.
p_palette:
    db 8                                                              ; 1afa: 08          .
    db 0                                                              ; 1afb: 00          .
    dw l3934                                                          ; 1afc: 33 39       39
p_read:
    db 5                                                              ; 1afe: 05          .
    dw l1ded                                                          ; 1aff: ed 1d       ..
p_renum:
    db 5                                                              ; 1b01: 05          .
    dw l3aa9                                                          ; 1b02: aa 3a       .:
p_restore:
    db 3                                                              ; 1b04: 03          .
    dw restore                                                        ; 1b05: 42 1e       B.
p_sound:
    db 5                                                              ; 1b07: 05          .
    dw l09c3                                                          ; 1b08: c3 09       ..
p_cat:
p_erase:
    db 5                                                              ; 1b0a: 05          .
    dw l09a1                                                          ; 1b0b: a1 09       ..
p_save:
    db $0b                                                            ; 1b0d: 0b          .
p_load:
    db $0b                                                            ; 1b0e: 0b          .
p_verify:
    db $0b                                                            ; 1b0f: 0b          .
p_merge:
    db $0b                                                            ; 1b10: 0b          .
p_pen:
    db 7                                                              ; 1b11: 07          .
p_paper:
    db 7                                                              ; 1b12: 07          .
p_flash:
    db 7                                                              ; 1b13: 07          .
p_bright:
    db 7                                                              ; 1b14: 07          .
p_inverse:
    db 7                                                              ; 1b15: 07          .
p_over:
    db 7                                                              ; 1b16: 07          .

; $1b17 referenced 1 time by $12b3
l1b17:
    res 7,(iy+flags - err_nr)                                         ; 1b17: fd cb 01... ...
    call eline_no                                                     ; 1b1b: cd fb 19    ...
    xor a                                                             ; 1b1e: af          .
    ld (subppc),a                                                     ; 1b1f: 32 47 5c    2G\
    dec a                                                             ; 1b22: 3d          =
    ld (err_nr),a                                                     ; 1b23: 32 3a 5c    2:\
    jr line_null                                                      ; 1b26: 18 01       ..

; $1b28 referenced 3 times by $1b3b, $1be3, $1bfb
stmtlp:
    rst $20                                                           ; 1b28: e7          .
; $1b29 referenced 2 times by $1b26, $1d00
line_null:
    call setwork                                                      ; 1b29: cd bf 16    ...
    inc (iy+subppc - err_nr)                                          ; 1b2c: fd 34 0d    .4.
    jp m,report_c                                                     ; 1b2f: fa 8a 1c    ...
    rst $18                                                           ; 1b32: df          .
    ld b,0                                                            ; 1b33: 06 00       ..
    cp $0d                                                            ; 1b35: fe 0d       ..
    jr z,lineend                                                      ; 1b37: 28 7a       (z
    cp $3a                                                            ; 1b39: fe 3a       .:
    jr z,stmtlp                                                       ; 1b3b: 28 eb       (.
    ld hl,$1b76                                                       ; 1b3d: 21 76 1b    !v.
    push hl                                                           ; 1b40: e5          .
    ld c,a                                                            ; 1b41: 4f          O
    rst $20                                                           ; 1b42: e7          .
    ld a,c                                                            ; 1b43: 79          y
    sub $ce                                                           ; 1b44: d6 ce       ..
    call c,l0bb6                                                      ; 1b46: dc b6 0b    ...
    ld c,a                                                            ; 1b49: 4f          O
    ld hl,$1a39                                                       ; 1b4a: 21 39 1a    !9.
    add hl,bc                                                         ; 1b4d: 09          .
    ld c,(hl)                                                         ; 1b4e: 4e          N
    add hl,bc                                                         ; 1b4f: 09          .
    jr get_param                                                      ; 1b50: 18 03       ..

scan_loop:
    ld hl,(t_addr)                                                    ; 1b52: 2a 74 5c    *t\
; $1b55 referenced 1 time by $1b50
get_param:
    ld a,(hl)                                                         ; 1b55: 7e          ~
    inc hl                                                            ; 1b56: 23          #
    ld (t_addr),hl                                                    ; 1b57: 22 74 5c    "t\
    ld bc,scan_loop                                                   ; 1b5a: 01 52 1b    .R.
    push bc                                                           ; 1b5d: c5          .
    ld c,a                                                            ; 1b5e: 4f          O
    cp $20                                                            ; 1b5f: fe 20       .
    jr nc,separator                                                   ; 1b61: 30 0c       0.
    ld hl,$1c00                                                       ; 1b63: 21 00 1c    !..
    ld b,0                                                            ; 1b66: 06 00       ..
    add hl,bc                                                         ; 1b68: 09          .
    ld c,(hl)                                                         ; 1b69: 4e          N
    add hl,bc                                                         ; 1b6a: 09          .
    push hl                                                           ; 1b6b: e5          .
    rst $18                                                           ; 1b6c: df          .
    dec b                                                             ; 1b6d: 05          .
    ret                                                               ; 1b6e: c9          .

; $1b6f referenced 1 time by $1b61
separator:
    rst $18                                                           ; 1b6f: df          .
    cp c                                                              ; 1b70: b9          .
    jp nz,report_c                                                    ; 1b71: c2 8a 1c    ...
    rst $20                                                           ; 1b74: e7          .
    ret                                                               ; 1b75: c9          .

; $1b76 referenced 1 time by $155a
nextstat:
    call break_1                                                      ; 1b76: cd 54 1f    .T.
    jr c,l1b7d                                                        ; 1b79: 38 02       8.
    rst $08                                                           ; 1b7b: cf          .
    db $14                                                            ; 1b7c: 14          .  ; Report L BREAK into program

; $1b7d referenced 1 time by $1b79
l1b7d:
    bit 7,(iy+nsppc - err_nr)                                         ; 1b7d: fd cb 0a... ...
    jr nz,stmtnext1                                                   ; 1b81: 20 71        q
    ld hl,(newppc)                                                    ; 1b83: 2a 42 5c    *B\
    bit 7,h                                                           ; 1b86: cb 7c       .|
    jr z,l1b9e                                                        ; 1b88: 28 14       (.
; $1b8a referenced 1 time by $12fe
linerun:
    ld hl,$fffe                                                       ; 1b8a: 21 fe ff    !..
    ld (ppc),hl                                                       ; 1b8d: 22 45 5c    "E\
    ld hl,(worksp)                                                    ; 1b90: 2a 61 5c    *a\
    dec hl                                                            ; 1b93: 2b          +
    ld de,(e_line)                                                    ; 1b94: ed 5b 59... .[Y
    dec de                                                            ; 1b98: 1b          .
    ld a,(nsppc)                                                      ; 1b99: 3a 44 5c    :D\
    jr next_line                                                      ; 1b9c: 18 33       .3

; $1b9e referenced 1 time by $1b88
l1b9e:
    call line_addr                                                    ; 1b9e: cd 6e 19    .n.
    ld a,(nsppc)                                                      ; 1ba1: 3a 44 5c    :D\
    jr z,lineuse                                                      ; 1ba4: 28 19       (.
    and a                                                             ; 1ba6: a7          .
    jr nz,statlost                                                    ; 1ba7: 20 43        C
    ld a,(hl)                                                         ; 1ba9: 7e          ~
    and $c0                                                           ; 1baa: e6 c0       ..
    jr z,lineuse                                                      ; 1bac: 28 11       (.
    rst $08                                                           ; 1bae: cf          .
    db $ff                                                            ; 1baf: ff          .  ; Report 0 OK
l1bb0:
    db $41, $57                                                       ; 1bb0: 41 57       AW

rem:
    pop af                                                            ; 1bb2: f1          .
; $1bb3 referenced 3 times by $1b37, $1bf7, $1cfd
lineend:
    call syntax_z                                                     ; 1bb3: cd 30 25    .0%
    ret z                                                             ; 1bb6: c8          .
    ld hl,(nxtlin)                                                    ; 1bb7: 2a 55 5c    *U\
    ld a,$c0                                                          ; 1bba: 3e c0       >.
    and (hl)                                                          ; 1bbc: a6          .
    ret nz                                                            ; 1bbd: c0          .
    xor a                                                             ; 1bbe: af          .
; $1bbf referenced 2 times by $1ba4, $1bac
lineuse:
    cp 1                                                              ; 1bbf: fe 01       ..
    adc a,0                                                           ; 1bc1: ce 00       ..
    ld d,(hl)                                                         ; 1bc3: 56          V
    inc hl                                                            ; 1bc4: 23          #
    ld e,(hl)                                                         ; 1bc5: 5e          ^
    inc hl                                                            ; 1bc6: 23          #
    ld (ppc),de                                                       ; 1bc7: ed 53 45... .SE
    ld e,(hl)                                                         ; 1bcb: 5e          ^
    inc hl                                                            ; 1bcc: 23          #
    ld d,(hl)                                                         ; 1bcd: 56          V
    ex de,hl                                                          ; 1bce: eb          .
    add hl,de                                                         ; 1bcf: 19          .
    inc hl                                                            ; 1bd0: 23          #
; $1bd1 referenced 1 time by $1b9c
next_line:
    ld (nxtlin),hl                                                    ; 1bd1: 22 55 5c    "U\
    ex de,hl                                                          ; 1bd4: eb          .
    ld (ch_add),hl                                                    ; 1bd5: 22 5d 5c    "]\
    ld e,0                                                            ; 1bd8: 1e 00       ..
    ld d,a                                                            ; 1bda: 57          W
    ld (iy+nsppc - err_nr),$ff                                        ; 1bdb: fd 36 0a... .6.
    dec d                                                             ; 1bdf: 15          .
    ld (iy+subppc - err_nr),d                                         ; 1be0: fd 72 0d    .r.
    jp z,stmtlp                                                       ; 1be3: ca 28 1b    .(.
    inc d                                                             ; 1be6: 14          .
    call skipstats                                                    ; 1be7: cd 8b 19    ...
    jr z,stmtnext1                                                    ; 1bea: 28 08       (.
; $1bec referenced 1 time by $1ba7
statlost:
    rst $08                                                           ; 1bec: cf          .
    db $16                                                            ; 1bed: 16          .  ; Report N Statement lost

; $1bee referenced 27 times by $0699, $06ad, $06f9, $071a, $072e, $09a9, $09bc, $09ea, $1822, $194a, $195a, $1c12, $1ca5, $1cd7, $1d0b, $1d10, $1e23, $1e31, $1fc0, $1fdb, $209d, $232a, $2387, $2391, $2c12, $3928, $3ac8
check_end:
    call syntax_z                                                     ; 1bee: cd 30 25    .0%
    ret nz                                                            ; 1bf1: c0          .
    pop bc                                                            ; 1bf2: c1          .
    pop bc                                                            ; 1bf3: c1          .
; $1bf4 referenced 2 times by $1b81, $1bea
stmtnext1:
    rst $18                                                           ; 1bf4: df          .
    cp $0d                                                            ; 1bf5: fe 0d       ..
    jr z,lineend                                                      ; 1bf7: 28 ba       (.
    cp $3a                                                            ; 1bf9: fe 3a       .:
    jp z,stmtlp                                                       ; 1bfb: ca 28 1b    .(.
    rst $08                                                           ; 1bfe: cf          .
    db $0b                                                            ; 1bff: 0b          .  ; Report C Nonsense in BASIC
command:
    db class_0 - $                                                    ; 1c00: 10          .
    db class_1 - $                                                    ; 1c01: 1e          .
    db class_2 - $                                                    ; 1c02: 4c          L
    db class_3 - $                                                    ; 1c03: 0a          .
    db class_4 - $                                                    ; 1c04: 68          h
    db class_5 - $                                                    ; 1c05: 0c          .
    db class_6 - $                                                    ; 1c06: 7c          |
    db class_7 - $                                                    ; 1c07: 8f          .
    db class_8 - $                                                    ; 1c08: 72          r
    db class_9 - $                                                    ; 1c09: b5          .
    db class_a - $                                                    ; 1c0a: 82          .
    db class_b - $                                                    ; 1c0b: d0          .
    db class_c - $                                                    ; 1c0c: 45          E

class_3:
    call l1cde                                                        ; 1c0d: cd de 1c    ...
; $1c10 referenced 1 time by $1c54
class_0:
    cp a                                                              ; 1c10: bf          .
class_5:
    pop bc                                                            ; 1c11: c1          .
    call z,check_end                                                  ; 1c12: cc ee 1b    ...
    ex de,hl                                                          ; 1c15: eb          .
    ld hl,(t_addr)                                                    ; 1c16: 2a 74 5c    *t\
    ld c,(hl)                                                         ; 1c19: 4e          N
    inc hl                                                            ; 1c1a: 23          #
    ld b,(hl)                                                         ; 1c1b: 46          F
    ex de,hl                                                          ; 1c1c: eb          .
    push bc                                                           ; 1c1d: c5          .
    ret                                                               ; 1c1e: c9          .

; $1c1f referenced 3 times by $1ded, $20dd, $20f3
class_1:
    call look_vars                                                    ; 1c1f: cd b2 28    ..(
; $1c22 referenced 1 time by $1c77
class_4_2:
    ld (iy+flagx - err_nr),0                                          ; 1c22: fd 36 37... .67
    jr nc,set_stk                                                     ; 1c26: 30 08       0.
    set 1,(iy+flagx - err_nr)                                         ; 1c28: fd cb 37... ..7
    jr nz,set_strln                                                   ; 1c2c: 20 18        .
; $1c2e referenced 2 times by $1daf, $26cc
report_2:
    rst $08                                                           ; 1c2e: cf          .
    db 1                                                              ; 1c2f: 01          .  ; Report 2 Variable not found

; $1c30 referenced 1 time by $1c26
set_stk:
    call z,stk_var                                                    ; 1c30: cc 96 29    ..)
    bit 6,(iy+flags - err_nr)                                         ; 1c33: fd cb 01... ...
    jr nz,set_strln                                                   ; 1c37: 20 0d        .
    xor a                                                             ; 1c39: af          .
    call syntax_z                                                     ; 1c3a: cd 30 25    .0%
    call nz,stk_fetch                                                 ; 1c3d: c4 f1 2b    ..+
    ld hl,$5c71                                                       ; 1c40: 21 71 5c    !q\
    or (hl)                                                           ; 1c43: b6          .
    ld (hl),a                                                         ; 1c44: 77          w
    ex de,hl                                                          ; 1c45: eb          .
; $1c46 referenced 2 times by $1c2c, $1c37
set_strln:
    ld (strlen),bc                                                    ; 1c46: ed 43 72... .Cr
    ld (dest),hl                                                      ; 1c4a: 22 4d 5c    "M\
    ret                                                               ; 1c4d: c9          .

class_2:
    pop bc                                                            ; 1c4e: c1          .
    jr l1cb9                                                          ; 1c4f: 18 68       .h

class_c:
    call class_6                                                      ; 1c51: cd 82 1c    ...
    jr class_0                                                        ; 1c54: 18 ba       ..

; $1c56 referenced 2 times by $1cb9, $1e0d
l1c56:
    ld a,(flags)                                                      ; 1c56: 3a 3b 5c    :;\
; $1c59 referenced 1 time by $21c7
input_rep:
    push af                                                           ; 1c59: f5          .
    call scanning                                                     ; 1c5a: cd fb 24    ..$
    pop af                                                            ; 1c5d: f1          .
    ld d,(iy+flags - err_nr)                                          ; 1c5e: fd 56 01    .V.
    xor d                                                             ; 1c61: aa          .
    and $40                                                           ; 1c62: e6 40       .@
    jr nz,report_c                                                    ; 1c64: 20 24        $
    bit 7,d                                                           ; 1c66: cb 7a       .z
    jp nz,let                                                         ; 1c68: c2 ff 2a    ..*
    ret                                                               ; 1c6b: c9          .

class_4:
    call look_vars                                                    ; 1c6c: cd b2 28    ..(
    push af                                                           ; 1c6f: f5          .
    ld a,c                                                            ; 1c70: 79          y
    or $9f                                                            ; 1c71: f6 9f       ..
    inc a                                                             ; 1c73: 3c          <
    jr nz,report_c                                                    ; 1c74: 20 14        .
    pop af                                                            ; 1c76: f1          .
    jr class_4_2                                                      ; 1c77: 18 a9       ..

; $1c79 referenced 2 times by $2001, $2527
sexpt2nums:
    rst $20                                                           ; 1c79: e7          .
; $1c7a referenced 2 times by $09c3, $1cd5
class_8:
    call class_6                                                      ; 1c7a: cd 82 1c    ...
    cp $2c                                                            ; 1c7d: fe 2c       .,
    jr nz,report_c                                                    ; 1c7f: 20 09        .
; $1c81 referenced 1 time by $3ac2
sexpt1num:
    rst $20                                                           ; 1c81: e7          .
; $1c82 referenced 16 times by $06e1, $06f6, $072b, $181a, $1947, $1c51, $1c7a, $1ce4, $1d08, $2013, $2075, $21ff, $2327, $238e, $2ad0, $3ab7
class_6:
    call scanning                                                     ; 1c82: cd fb 24    ..$
    bit 6,(iy+flags - err_nr)                                         ; 1c85: fd cb 01... ...
    ret nz                                                            ; 1c89: c0          .
; $1c8a referenced 33 times by $065c, $0672, $06a9, $06cc, $06d9, $06ed, $0727, $1a15, $1b2f, $1b71, $1c64, $1c74, $1c7f, $1c94, $1f89, $1fbd, $20d1, $20e8, $21ef, $2323, $2515, $252d, $25ee, $26ef, $26f9, $2761, $27c6, $27e6, $28ba, $2a7a, $2c05, $2ccf, $35dc
report_c:
    rst $08                                                           ; 1c8a: cf          .
    db $0b                                                            ; 1c8b: 0b          .  ; Report C Nonsense in BASIC

; $1c8c referenced 1 time by $060e
class_a:
    call scanning                                                     ; 1c8c: cd fb 24    ..$
    bit 6,(iy+flags - err_nr)                                         ; 1c8f: fd cb 01... ...
    ret z                                                             ; 1c93: c8          .
    jr report_c                                                       ; 1c94: 18 f4       ..

class_7:
    call syntax_z                                                     ; 1c96: cd 30 25    .0%
    call nz,streamfe                                                  ; 1c99: c4 17 0b    ...
    pop af                                                            ; 1c9c: f1          .
    ld a,(t_addr)                                                     ; 1c9d: 3a 74 5c    :t\
    sub $39                                                           ; 1ca0: d6 39       .9
    call cotemp4                                                      ; 1ca2: cd fc 21    ..!
    call check_end                                                    ; 1ca5: cd ee 1b    ...
    ld hl,(attr_t)                                                    ; 1ca8: 2a 8f 5c    *.\
    ld (attr_p),hl                                                    ; 1cab: 22 8d 5c    ".\
    ld hl,$5c91                                                       ; 1cae: 21 91 5c    !.\
    ld a,(hl)                                                         ; 1cb1: 7e          ~
    rlca                                                              ; 1cb2: 07          .
    xor (hl)                                                          ; 1cb3: ae          .
    and $aa                                                           ; 1cb4: e6 aa       ..
    xor (hl)                                                          ; 1cb6: ae          .
    ld (hl),a                                                         ; 1cb7: 77          w
    ret                                                               ; 1cb8: c9          .

; $1cb9 referenced 1 time by $1c4f
l1cb9:
    call l1c56                                                        ; 1cb9: cd 56 1c    .V.
    jr l1cd7                                                          ; 1cbc: 18 19       ..

class_9:
    call syntax_z                                                     ; 1cbe: cd 30 25    .0%
    jr z,l1cd2                                                        ; 1cc1: 28 0f       (.
    call streamfe                                                     ; 1cc3: cd 17 0b    ...
    ld hl,$5c90                                                       ; 1cc6: 21 90 5c    !.\
    ld a,(hl)                                                         ; 1cc9: 7e          ~
    or $f8                                                            ; 1cca: f6 f8       ..
    ld (hl),a                                                         ; 1ccc: 77          w
    res 6,(iy+p_flag - err_nr)                                        ; 1ccd: fd cb 57... ..W
    rst $18                                                           ; 1cd1: df          .
; $1cd2 referenced 1 time by $1cc1
l1cd2:
    call citem                                                        ; 1cd2: cd e2 21    ..!
    jr class_8                                                        ; 1cd5: 18 a3       ..

; $1cd7 referenced 1 time by $1cbc
l1cd7:
    call check_end                                                    ; 1cd7: cd ee 1b    ...
    ret                                                               ; 1cda: c9          .

class_b:
    jp l0605                                                          ; 1cdb: c3 05 06    ...

; $1cde referenced 2 times by $181f, $1c0d
l1cde:
    cp $0d                                                            ; 1cde: fe 0d       ..
    jr z,no_to_stk                                                    ; 1ce0: 28 04       (.
    cp $3a                                                            ; 1ce2: fe 3a       .:
    jr nz,class_6                                                     ; 1ce4: 20 9c        .
; $1ce6 referenced 4 times by $06dc, $06f0, $1814, $1ce0
no_to_stk:
    call syntax_z                                                     ; 1ce6: cd 30 25    .0%
    ret z                                                             ; 1ce9: c8          .
    rst $28                                                           ; 1cea: ef          .
    db $a0                                                            ; 1ceb: a0          .  ; stk-zero
    db $38                                                            ; 1cec: 38          8  ; end-calc

    ret                                                               ; 1ced: c9          .

stop:
    rst $08                                                           ; 1cee: cf          .
    db 8                                                              ; 1cef: 08          .  ; Report 9 STOP statement

_if:
    pop bc                                                            ; 1cf0: c1          .
    call syntax_z                                                     ; 1cf1: cd 30 25    .0%
    jr z,l1d00                                                        ; 1cf4: 28 0a       (.
    rst $28                                                           ; 1cf6: ef          .
    db 2                                                              ; 1cf7: 02          .  ; delete
    db $38                                                            ; 1cf8: 38          8  ; end-calc

    ex de,hl                                                          ; 1cf9: eb          .
    call tstzero                                                      ; 1cfa: cd c5 34    ..4
    jp c,lineend                                                      ; 1cfd: da b3 1b    ...
; $1d00 referenced 1 time by $1cf4
l1d00:
    jp line_null                                                      ; 1d00: c3 29 1b    .).

for:
    cp $cd                                                            ; 1d03: fe cd       ..
    jr nz,use_one                                                     ; 1d05: 20 09        .
    rst $20                                                           ; 1d07: e7          .
    call class_6                                                      ; 1d08: cd 82 1c    ...
    call check_end                                                    ; 1d0b: cd ee 1b    ...
    jr reorder                                                        ; 1d0e: 18 06       ..

; $1d10 referenced 1 time by $1d05
use_one:
    call check_end                                                    ; 1d10: cd ee 1b    ...
    rst $28                                                           ; 1d13: ef          .
    db $a1                                                            ; 1d14: a1          .  ; stk-one
    db $38                                                            ; 1d15: 38          8  ; end-calc

; $1d16 referenced 1 time by $1d0e
reorder:
    rst $28                                                           ; 1d16: ef          .
    db $c0                                                            ; 1d17: c0          .  ; st-mem-0
    db 2                                                              ; 1d18: 02          .  ; delete
    db 1                                                              ; 1d19: 01          .  ; exchange
    db $e0                                                            ; 1d1a: e0          .  ; get-mem-0
    db 1                                                              ; 1d1b: 01          .  ; exchange
    db $38                                                            ; 1d1c: 38          8  ; end-calc

    call let                                                          ; 1d1d: cd ff 2a    ..*
    ld (mem),hl                                                       ; 1d20: 22 68 5c    "h\
    dec hl                                                            ; 1d23: 2b          +
    ld a,(hl)                                                         ; 1d24: 7e          ~
    set 7,(hl)                                                        ; 1d25: cb fe       ..
    ld bc,6                                                           ; 1d27: 01 06 00    ...
    add hl,bc                                                         ; 1d2a: 09          .
    rlca                                                              ; 1d2b: 07          .
    jr c,lmt_step                                                     ; 1d2c: 38 06       8.
    ld c,$0d                                                          ; 1d2e: 0e 0d       ..
    call make_room                                                    ; 1d30: cd 55 16    .U.
    inc hl                                                            ; 1d33: 23          #
; $1d34 referenced 1 time by $1d2c
lmt_step:
    push hl                                                           ; 1d34: e5          .
    rst $28                                                           ; 1d35: ef          .
    db 2                                                              ; 1d36: 02          .  ; delete
    db 2                                                              ; 1d37: 02          .  ; delete
    db $38                                                            ; 1d38: 38          8  ; end-calc

    pop hl                                                            ; 1d39: e1          .
    ex de,hl                                                          ; 1d3a: eb          .
    ld c,$0a                                                          ; 1d3b: 0e 0a       ..
    ldir                                                              ; 1d3d: ed b0       ..
    ld hl,(ppc)                                                       ; 1d3f: 2a 45 5c    *E\
    ex de,hl                                                          ; 1d42: eb          .
    ld (hl),e                                                         ; 1d43: 73          s
    inc hl                                                            ; 1d44: 23          #
    ld (hl),d                                                         ; 1d45: 72          r
    ld d,(iy+subppc - err_nr)                                         ; 1d46: fd 56 0d    .V.
    inc hl                                                            ; 1d49: 23          #
    inc d                                                             ; 1d4a: 14          .
    ld (hl),d                                                         ; 1d4b: 72          r
    call next_loop                                                    ; 1d4c: cd da 1d    ...
    ret nc                                                            ; 1d4f: d0          .
    ld a,(subppc)                                                     ; 1d50: 3a 47 5c    :G\
    ld hl,(ppc)                                                       ; 1d53: 2a 45 5c    *E\
    ld (newppc),hl                                                    ; 1d56: 22 42 5c    "B\
    ld b,(iy+strlen - err_nr)                                         ; 1d59: fd 46 38    .F8
    neg                                                               ; 1d5c: ed 44       .D
    ld hl,(ch_add)                                                    ; 1d5e: 2a 5d 5c    *]\
    ld d,a                                                            ; 1d61: 57          W
    ld e,$f3                                                          ; 1d62: 1e f3       ..
; $1d64 referenced 1 time by $1d7a
l1d64:
    push bc                                                           ; 1d64: c5          .
    ld bc,(nxtlin)                                                    ; 1d65: ed 4b 55... .KU
    call l1d86                                                        ; 1d69: cd 86 1d    ...
    ld (nxtlin),bc                                                    ; 1d6c: ed 43 55... .CU
    pop bc                                                            ; 1d70: c1          .
    jr c,l1d84                                                        ; 1d71: 38 11       8.
    rst $20                                                           ; 1d73: e7          .
    or $20                                                            ; 1d74: f6 20       .
    cp b                                                              ; 1d76: b8          .
    jr z,l1d7c                                                        ; 1d77: 28 03       (.
    rst $20                                                           ; 1d79: e7          .
    jr l1d64                                                          ; 1d7a: 18 e8       ..

; $1d7c referenced 1 time by $1d77
l1d7c:
    rst $20                                                           ; 1d7c: e7          .
    ld a,1                                                            ; 1d7d: 3e 01       >.
    sub d                                                             ; 1d7f: 92          .
    ld (nsppc),a                                                      ; 1d80: 32 44 5c    2D\
    ret                                                               ; 1d83: c9          .

; $1d84 referenced 1 time by $1d71
l1d84:
    rst $08                                                           ; 1d84: cf          .
    db $11                                                            ; 1d85: 11          .  ; Report I FOR without NEXT

; $1d86 referenced 3 times by $1d69, $1e03, $280c
l1d86:
    ld a,(hl)                                                         ; 1d86: 7e          ~
    cp $3a                                                            ; 1d87: fe 3a       .:
    jr z,l1da3                                                        ; 1d89: 28 18       (.
; $1d8b referenced 1 time by $1da9
l1d8b:
    inc hl                                                            ; 1d8b: 23          #
    ld a,(hl)                                                         ; 1d8c: 7e          ~
    and $c0                                                           ; 1d8d: e6 c0       ..
    scf                                                               ; 1d8f: 37          7
    ret nz                                                            ; 1d90: c0          .
    ld b,(hl)                                                         ; 1d91: 46          F
    inc hl                                                            ; 1d92: 23          #
    ld c,(hl)                                                         ; 1d93: 4e          N
    ld (newppc),bc                                                    ; 1d94: ed 43 42... .CB
    inc hl                                                            ; 1d98: 23          #
    ld c,(hl)                                                         ; 1d99: 4e          N
    inc hl                                                            ; 1d9a: 23          #
    ld b,(hl)                                                         ; 1d9b: 46          F
    push hl                                                           ; 1d9c: e5          .
    add hl,bc                                                         ; 1d9d: 09          .
    ld c,l                                                            ; 1d9e: 4d          M
    ld b,h                                                            ; 1d9f: 44          D
    pop hl                                                            ; 1da0: e1          .
    ld d,0                                                            ; 1da1: 16 00       ..
; $1da3 referenced 1 time by $1d89
l1da3:
    push bc                                                           ; 1da3: c5          .
    call skipstats                                                    ; 1da4: cd 8b 19    ...
    pop bc                                                            ; 1da7: c1          .
    ret nc                                                            ; 1da8: d0          .
    jr l1d8b                                                          ; 1da9: 18 e0       ..

next:
    bit 1,(iy+flagx - err_nr)                                         ; 1dab: fd cb 37... ..7
    jp nz,report_2                                                    ; 1daf: c2 2e 1c    ...
    ld hl,(dest)                                                      ; 1db2: 2a 4d 5c    *M\
    bit 7,(hl)                                                        ; 1db5: cb 7e       .~
    jr z,report_1                                                     ; 1db7: 28 1f       (.
    inc hl                                                            ; 1db9: 23          #
    ld (mem),hl                                                       ; 1dba: 22 68 5c    "h\
    rst $28                                                           ; 1dbd: ef          .
    db $e0                                                            ; 1dbe: e0          .  ; get-mem-0
    db $e2                                                            ; 1dbf: e2          .  ; get-mem-2
    db $0f                                                            ; 1dc0: 0f          .  ; addition
    db $c0                                                            ; 1dc1: c0          .  ; st-mem-0
    db 2                                                              ; 1dc2: 02          .  ; delete
    db $38                                                            ; 1dc3: 38          8  ; end-calc

    call next_loop                                                    ; 1dc4: cd da 1d    ...
    ret c                                                             ; 1dc7: d8          .
    ld hl,(mem)                                                       ; 1dc8: 2a 68 5c    *h\
    ld de,$0f                                                         ; 1dcb: 11 0f 00    ...
    add hl,de                                                         ; 1dce: 19          .
    ld e,(hl)                                                         ; 1dcf: 5e          ^
    inc hl                                                            ; 1dd0: 23          #
    ld d,(hl)                                                         ; 1dd1: 56          V
    inc hl                                                            ; 1dd2: 23          #
    ld h,(hl)                                                         ; 1dd3: 66          f
    ex de,hl                                                          ; 1dd4: eb          .
    jp goto_2                                                         ; 1dd5: c3 73 1e    .s.

; $1dd8 referenced 1 time by $1db7
report_1:
    rst $08                                                           ; 1dd8: cf          .
    db 0                                                              ; 1dd9: 00          .  ; Report 1 NEXT without FOR

; $1dda referenced 2 times by $1d4c, $1dc4
next_loop:
    rst $28                                                           ; 1dda: ef          .
    db $e1                                                            ; 1ddb: e1          .  ; get-mem-1
    db $e0                                                            ; 1ddc: e0          .  ; get-mem-0
    db $e2                                                            ; 1ddd: e2          .  ; get-mem-2
    db $36                                                            ; 1dde: 36          6  ; less-0
    db 0                                                              ; 1ddf: 00          .  ; jump-true
    db lmt_v_val - $                                                  ; 1de0: 02          .
    db 1                                                              ; 1de1: 01          .  ; exchange
lmt_v_val:
    db 3                                                              ; 1de2: 03          .  ; subtract
    db $37                                                            ; 1de3: 37          7  ; greater-0
    db 0                                                              ; 1de4: 00          .  ; jump-true
    db imposs - $                                                     ; 1de5: 04          .
    db $38                                                            ; 1de6: 38          8  ; end-calc

    and a                                                             ; 1de7: a7          .
    ret                                                               ; 1de8: c9          .

imposs:
    db $38                                                            ; 1de9: 38          8  ; end-calc

    scf                                                               ; 1dea: 37          7
    ret                                                               ; 1deb: c9          .

; $1dec referenced 1 time by $1e21
l1dec:
    rst $20                                                           ; 1dec: e7          .
l1ded:
    call class_1                                                      ; 1ded: cd 1f 1c    ...
    call syntax_z                                                     ; 1df0: cd 30 25    .0%
    jr z,l1e1e                                                        ; 1df3: 28 29       ()
    rst $18                                                           ; 1df5: df          .
    ld (x_ptr),hl                                                     ; 1df6: 22 5f 5c    "_\
    ld hl,(datadd)                                                    ; 1df9: 2a 57 5c    *W\
    ld a,(hl)                                                         ; 1dfc: 7e          ~
    cp $2c                                                            ; 1dfd: fe 2c       .,
    jr z,l1e0a                                                        ; 1dff: 28 09       (.
    ld e,$e4                                                          ; 1e01: 1e e4       ..
    call l1d86                                                        ; 1e03: cd 86 1d    ...
    jr nc,l1e0a                                                       ; 1e06: 30 02       0.
    rst $08                                                           ; 1e08: cf          .
    db $0d                                                            ; 1e09: 0d          .  ; Report E Out of DATA

; $1e0a referenced 2 times by $1dff, $1e06
l1e0a:
    call cursor_so                                                    ; 1e0a: cd 77 00    .w.
    call l1c56                                                        ; 1e0d: cd 56 1c    .V.
    rst $18                                                           ; 1e10: df          .
    ld (datadd),hl                                                    ; 1e11: 22 57 5c    "W\
    ld hl,(x_ptr)                                                     ; 1e14: 2a 5f 5c    *_\
    ld (iy+(x_ptr+1) - err_nr),0                                      ; 1e17: fd 36 26... .6&
    call temp_ptr                                                     ; 1e1b: cd 78 00    .x.
; $1e1e referenced 1 time by $1df3
l1e1e:
    rst $18                                                           ; 1e1e: df          .
    cp $2c                                                            ; 1e1f: fe 2c       .,
    jr z,l1dec                                                        ; 1e21: 28 c9       (.
    call check_end                                                    ; 1e23: cd ee 1b    ...
    ret                                                               ; 1e26: c9          .

l1e27:
    call syntax_z                                                     ; 1e27: cd 30 25    .0%
    jr nz,l1e37                                                       ; 1e2a: 20 0b        .
; $1e2c referenced 1 time by $1e35
l1e2c:
    call scanning                                                     ; 1e2c: cd fb 24    ..$
    cp $2c                                                            ; 1e2f: fe 2c       .,
    call nz,check_end                                                 ; 1e31: c4 ee 1b    ...
    rst $20                                                           ; 1e34: e7          .
    jr l1e2c                                                          ; 1e35: 18 f5       ..

; $1e37 referenced 1 time by $1e2a
l1e37:
    ld a,$e4                                                          ; 1e37: 3e e4       >.
; $1e39 referenced 1 time by $1f67
l1e39:
    ld b,a                                                            ; 1e39: 47          G
    cpdr                                                              ; 1e3a: ed b9       ..
    ld de,$0200                                                       ; 1e3c: 11 00 02    ...
    jp skipstats                                                      ; 1e3f: c3 8b 19    ...

restore:
    call syntax3                                                      ; 1e42: cd 01 39    ..9
; $1e45 referenced 2 times by $1344, $1ea7
restorez:
    ld l,c                                                            ; 1e45: 69          i
    ld h,b                                                            ; 1e46: 60          `
    call line_addr                                                    ; 1e47: cd 6e 19    .n.
    dec hl                                                            ; 1e4a: 2b          +
    ld (datadd),hl                                                    ; 1e4b: 22 57 5c    "W\
    ret                                                               ; 1e4e: c9          .

rand:
    call find_int                                                     ; 1e4f: cd 99 1e    ...
    ld a,b                                                            ; 1e52: 78          x
    or c                                                              ; 1e53: b1          .
    jr nz,set_seed                                                    ; 1e54: 20 04        .
    ld bc,(frames)                                                    ; 1e56: ed 4b 78... .Kx
; $1e5a referenced 1 time by $1e54
set_seed:
    ld (seed),bc                                                      ; 1e5a: ed 43 76... .Cv
    ret                                                               ; 1e5e: c9          .

cont:
    ld hl,(oldppc)                                                    ; 1e5f: 2a 6e 5c    *n\
    ld d,(iy+osppc - err_nr)                                          ; 1e62: fd 56 36    .V6
    jr goto_2                                                         ; 1e65: 18 0c       ..

; $1e67 referenced 2 times by $1ea1, $1eff
goto:
    call syntax3                                                      ; 1e67: cd 01 39    ..9
    ld h,b                                                            ; 1e6a: 60          `
    ld l,c                                                            ; 1e6b: 69          i
    ld d,0                                                            ; 1e6c: 16 00       ..
    ld a,h                                                            ; 1e6e: 7c          |
    cp $f0                                                            ; 1e6f: fe f0       ..
    jr nc,report_b1                                                   ; 1e71: 30 2c       0,
; $1e73 referenced 3 times by $1dd5, $1e65, $1f33
goto_2:
    ld (iy+nsppc - err_nr),d                                          ; 1e73: fd 72 0a    .r.
    ld (newppc),hl                                                    ; 1e76: 22 42 5c    "B\
    ret                                                               ; 1e79: c9          .

_out:
    call poke1                                                        ; 1e7a: cd 85 1e    ...
    out (c),a                                                         ; 1e7d: ed 79       .y
    ret                                                               ; 1e7f: c9          .

poke:
    call poke1                                                        ; 1e80: cd 85 1e    ...
    ld (bc),a                                                         ; 1e83: 02          .
    ret                                                               ; 1e84: c9          .

; $1e85 referenced 3 times by $1e7a, $1e80, $3933
poke1:
    call fp_to_a                                                      ; 1e85: cd d5 2d    ..-
    jr c,report_b1                                                    ; 1e88: 38 15       8.
    jr z,poke_save                                                    ; 1e8a: 28 02       (.
    neg                                                               ; 1e8c: ed 44       .D
; $1e8e referenced 1 time by $1e8a
poke_save:
    push af                                                           ; 1e8e: f5          .
    call find_int                                                     ; 1e8f: cd 99 1e    ...
    pop af                                                            ; 1e92: f1          .
    ret                                                               ; 1e93: c9          .

; $1e94 referenced 8 times by $0443, $0a77, $171e, $207c, $2208, $2294, $2371, $2376
getbyte:
    call fp_to_a                                                      ; 1e94: cd d5 2d    ..-
    jr getibc                                                         ; 1e97: 18 03       ..

; $1e99 referenced 18 times by $045b, $045f, $06fc, $0705, $0abf, $0b1c, $18bc, $18c0, $18c4, $1e4f, $1e8f, $1eac, $2019, $2ada, $3485, $348c, $3493, $3901
find_int:
    call fp_to_bc                                                     ; 1e99: cd a2 2d    ..-
; $1e9c referenced 1 time by $1e97
getibc:
    jr c,report_b1                                                    ; 1e9c: 38 01       8.
    ret z                                                             ; 1e9e: c8          .
; $1e9f referenced 4 times by $0aa6, $1e71, $1e88, $1e9c
report_b1:
    rst $08                                                           ; 1e9f: cf          .
    db $0a                                                            ; 1ea0: 0a          .  ; Report B Integer out of range

run:
    call goto                                                         ; 1ea1: cd 67 1e    .g.
    ld bc,0                                                           ; 1ea4: 01 00 00    ...
    call restorez                                                     ; 1ea7: cd 45 1e    .E.
    jr clr1                                                           ; 1eaa: 18 03       ..

clear:
    call find_int                                                     ; 1eac: cd 99 1e    ...
; $1eaf referenced 1 time by $1eaa
clr1:
    ld a,c                                                            ; 1eaf: 79          y
    or b                                                              ; 1eb0: b0          .
    jr nz,clr3                                                        ; 1eb1: 20 04        .
    ld bc,(ramtop)                                                    ; 1eb3: ed 4b b2... .K.
; $1eb7 referenced 1 time by $1eb1
clr3:
    push bc                                                           ; 1eb7: c5          .
    ld hl,(e_line)                                                    ; 1eb8: 2a 59 5c    *Y\
    ld de,(vars)                                                      ; 1ebb: ed 5b 4b... .[K
    dec hl                                                            ; 1ebf: 2b          +
    call reclaim_1                                                    ; 1ec0: cd e5 19    ...
    call l1344                                                        ; 1ec3: cd 44 13    .D.
    ld de,$32                                                         ; 1ec6: 11 32 00    .2.
    ld hl,(stkend)                                                    ; 1ec9: 2a 65 5c    *e\
    add hl,de                                                         ; 1ecc: 19          .
    pop de                                                            ; 1ecd: d1          .
    sbc hl,de                                                         ; 1ece: ed 52       .R
    jr nc,rterr                                                       ; 1ed0: 30 08       0.
    and a                                                             ; 1ed2: a7          .
    ld hl,(p_ramt)                                                    ; 1ed3: 2a b4 5c    *.\
    sbc hl,de                                                         ; 1ed6: ed 52       .R
    jr nc,clr4                                                        ; 1ed8: 30 02       0.
; $1eda referenced 1 time by $1ed0
rterr:
    rst $08                                                           ; 1eda: cf          .
    db $15                                                            ; 1edb: 15          .  ; Report M RAMTOP no good

; $1edc referenced 1 time by $1ed8
clr4:
    ex de,hl                                                          ; 1edc: eb          .
    ld (ramtop),hl                                                    ; 1edd: 22 b2 5c    ".\
    pop de                                                            ; 1ee0: d1          .
    pop bc                                                            ; 1ee1: c1          .
    ld (hl),$3e                                                       ; 1ee2: 36 3e       6>
    dec hl                                                            ; 1ee4: 2b          +
    ld sp,hl                                                          ; 1ee5: f9          .
    push bc                                                           ; 1ee6: c5          .
    ld (err_sp),sp                                                    ; 1ee7: ed 73 3d... .s=
    ex de,hl                                                          ; 1eeb: eb          .
    jp (hl)                                                           ; 1eec: e9          .

gosub:
    pop de                                                            ; 1eed: d1          .
    ld h,(iy+subppc - err_nr)                                         ; 1eee: fd 66 0d    .f.
    inc h                                                             ; 1ef1: 24          $
    ex (sp),hl                                                        ; 1ef2: e3          .
    inc sp                                                            ; 1ef3: 33          3
    ld bc,(ppc)                                                       ; 1ef4: ed 4b 45... .KE
    push bc                                                           ; 1ef8: c5          .
    push hl                                                           ; 1ef9: e5          .
    ld (err_sp),sp                                                    ; 1efa: ed 73 3d... .s=
    push de                                                           ; 1efe: d5          .
    call goto                                                         ; 1eff: cd 67 1e    .g.
    ld bc,$14                                                         ; 1f02: 01 14 00    ...
; $1f05 referenced 4 times by $082b, $0fc9, $1656, $33b2
test_room:
    ld hl,(stkend)                                                    ; 1f05: 2a 65 5c    *e\
    add hl,bc                                                         ; 1f08: 09          .
    jr c,report_4                                                     ; 1f09: 38 0a       8.
    ex de,hl                                                          ; 1f0b: eb          .
    ld hl,$50                                                         ; 1f0c: 21 50 00    !P.
    add hl,de                                                         ; 1f0f: 19          .
    jr c,report_4                                                     ; 1f10: 38 03       8.
    sbc hl,sp                                                         ; 1f12: ed 72       .r
    ret c                                                             ; 1f14: d8          .
; $1f15 referenced 4 times by $1f09, $1f10, $2afb, $2c54
report_4:
    ld l,3                                                            ; 1f15: 2e 03       ..
    jp error_3                                                        ; 1f17: c3 55 00    .U.

; $1f1a referenced 1 time by $09bf
l1f1a:
    ld a,(flags)                                                      ; 1f1a: 3a 3b 5c    :;\
    and $f7                                                           ; 1f1d: e6 f7       ..
; $1f1f referenced 1 time by $3930
l1f1f:
    ld (flags),a                                                      ; 1f1f: 32 3b 5c    2;\
    ret                                                               ; 1f22: c9          .

return:
    pop bc                                                            ; 1f23: c1          .
    pop hl                                                            ; 1f24: e1          .
    pop de                                                            ; 1f25: d1          .
    ld a,d                                                            ; 1f26: 7a          z
    cp $3e                                                            ; 1f27: fe 3e       .>
    jr z,report_7                                                     ; 1f29: 28 0b       (.
    dec sp                                                            ; 1f2b: 3b          ;
    ex (sp),hl                                                        ; 1f2c: e3          .
    ex de,hl                                                          ; 1f2d: eb          .
    ld (err_sp),sp                                                    ; 1f2e: ed 73 3d... .s=
    push bc                                                           ; 1f32: c5          .
    jp goto_2                                                         ; 1f33: c3 73 1e    .s.

; $1f36 referenced 1 time by $1f29
report_7:
    push de                                                           ; 1f36: d5          .
    push hl                                                           ; 1f37: e5          .
    rst $08                                                           ; 1f38: cf          .
    db 6                                                              ; 1f39: 06          .  ; Report 7 RETURN without GOSUB

pause:
    call l0abc                                                        ; 1f3a: cd bc 0a    ...
; $1f3d referenced 1 time by $1f4d
pau1:
    halt                                                              ; 1f3d: 76          v
    dec bc                                                            ; 1f3e: 0b          .
    ld a,b                                                            ; 1f3f: 78          x
    or c                                                              ; 1f40: b1          .
    jr z,pau2                                                         ; 1f41: 28 0c       (.
    ld a,c                                                            ; 1f43: 79          y
    and b                                                             ; 1f44: a0          .
    inc a                                                             ; 1f45: 3c          <
    jr nz,l1f49                                                       ; 1f46: 20 01        .
    inc bc                                                            ; 1f48: 03          .
; $1f49 referenced 1 time by $1f46
l1f49:
    bit 5,(iy+flags - err_nr)                                         ; 1f49: fd cb 01... ...
    jr z,pau1                                                         ; 1f4d: 28 ee       (.
; $1f4f referenced 2 times by $0abc, $1f41
pau2:
    res 5,(iy+flags - err_nr)                                         ; 1f4f: fd cb 01... ...
    ret                                                               ; 1f53: c9          .

; $1f54 referenced 1 time by $1b76
break_1:
    ld a,$7f                                                          ; 1f54: 3e 7f       >.
    in a,(ula_port)                                                   ; 1f56: db fe       .. ; Read the keyboard (SPACE-B)
    rra                                                               ; 1f58: 1f          .
    ret c                                                             ; 1f59: d8          .
    ld a,$fe                                                          ; 1f5a: 3e fe       >.
    in a,(ula_port)                                                   ; 1f5c: db fe       .. ; Read the keyboard (CAPS SHIFT-V)
    rra                                                               ; 1f5e: 1f          .
    ret                                                               ; 1f5f: c9          .

l1f60:
    call syntax_z                                                     ; 1f60: cd 30 25    .0%
    jr z,l1f6a                                                        ; 1f63: 28 05       (.
    ld a,$ce                                                          ; 1f65: 3e ce       >.
    jp l1e39                                                          ; 1f67: c3 39 1e    .9.

; $1f6a referenced 1 time by $1f63
l1f6a:
    set 6,(iy+flags - err_nr)                                         ; 1f6a: fd cb 01... ...
    call alpha                                                        ; 1f6e: cd 8d 2c    ..,
    jr nc,l1f89                                                       ; 1f71: 30 16       0.
    rst $20                                                           ; 1f73: e7          .
    cp $24                                                            ; 1f74: fe 24       .$
    jr nz,l1f7d                                                       ; 1f76: 20 05        .
    res 6,(iy+flags - err_nr)                                         ; 1f78: fd cb 01... ...
    rst $20                                                           ; 1f7c: e7          .
; $1f7d referenced 1 time by $1f76
l1f7d:
    cp $28                                                            ; 1f7d: fe 28       .(
    jr nz,l1fbd                                                       ; 1f7f: 20 3c        <
    rst $20                                                           ; 1f81: e7          .
    cp $29                                                            ; 1f82: fe 29       .)
    jr z,l1fa6                                                        ; 1f84: 28 20       (
; $1f86 referenced 1 time by $1fa4
l1f86:
    call alpha                                                        ; 1f86: cd 8d 2c    ..,
; $1f89 referenced 1 time by $1f71
l1f89:
    jp nc,report_c                                                    ; 1f89: d2 8a 1c    ...
    ex de,hl                                                          ; 1f8c: eb          .
    rst $20                                                           ; 1f8d: e7          .
    cp $24                                                            ; 1f8e: fe 24       .$
    jr nz,l1f94                                                       ; 1f90: 20 02        .
    ex de,hl                                                          ; 1f92: eb          .
    rst $20                                                           ; 1f93: e7          .
; $1f94 referenced 1 time by $1f90
l1f94:
    ex de,hl                                                          ; 1f94: eb          .
    ld bc,6                                                           ; 1f95: 01 06 00    ...
    call make_room                                                    ; 1f98: cd 55 16    .U.
    inc hl                                                            ; 1f9b: 23          #
    inc hl                                                            ; 1f9c: 23          #
    ld (hl),$0e                                                       ; 1f9d: 36 0e       6.
    cp $2c                                                            ; 1f9f: fe 2c       .,
    jr nz,l1fa6                                                       ; 1fa1: 20 03        .
    rst $20                                                           ; 1fa3: e7          .
    jr l1f86                                                          ; 1fa4: 18 e0       ..

; $1fa6 referenced 2 times by $1f84, $1fa1
l1fa6:
    cp $29                                                            ; 1fa6: fe 29       .)
    jr nz,l1fbd                                                       ; 1fa8: 20 13        .
    rst $20                                                           ; 1faa: e7          .
    cp $3d                                                            ; 1fab: fe 3d       .=
    jr nz,l1fbd                                                       ; 1fad: 20 0e        .
    rst $20                                                           ; 1faf: e7          .
    ld a,(flags)                                                      ; 1fb0: 3a 3b 5c    :;\
    push af                                                           ; 1fb3: f5          .
    call scanning                                                     ; 1fb4: cd fb 24    ..$
    pop af                                                            ; 1fb7: f1          .
    xor (iy+flags - err_nr)                                           ; 1fb8: fd ae 01    ...
    and $40                                                           ; 1fbb: e6 40       .@
; $1fbd referenced 3 times by $1f7f, $1fa8, $1fad
l1fbd:
    jp nz,report_c                                                    ; 1fbd: c2 8a 1c    ...
    call check_end                                                    ; 1fc0: cd ee 1b    ...
; $1fc3 referenced 6 times by $1ff5, $2004, $2016, $202f, $2079, $2204
unstack_z:
    call syntax_z                                                     ; 1fc3: cd 30 25    .0%
    pop hl                                                            ; 1fc6: e1          .
    ret z                                                             ; 1fc7: c8          .
    jp (hl)                                                           ; 1fc8: e9          .

lprint:
    ld a,3                                                            ; 1fc9: 3e 03       >.
    jr l1fcf                                                          ; 1fcb: 18 02       ..

print:
    ld a,2                                                            ; 1fcd: 3e 02       >.
; $1fcf referenced 1 time by $1fcb
l1fcf:
    call syntax_z                                                     ; 1fcf: cd 30 25    .0%
    call nz,l1601                                                     ; 1fd2: c4 01 16    ...
    call trcurp                                                       ; 1fd5: cd 4d 0d    .M.
    call print2                                                       ; 1fd8: cd df 1f    ...
    call check_end                                                    ; 1fdb: cd ee 1b    ...
    ret                                                               ; 1fde: c9          .

; $1fdf referenced 2 times by $1fd8, $20cb
print2:
    rst $18                                                           ; 1fdf: df          .
    call prterm                                                       ; 1fe0: cd 45 20    .E
    jr z,print3                                                       ; 1fe3: 28 0d       (.
; $1fe5 referenced 2 times by $1fe8, $1ff0
mprseplp:
    call prsepr                                                       ; 1fe5: cd 4e 20    .N
    jr z,mprseplp                                                     ; 1fe8: 28 fb       (.
    call pritem                                                       ; 1fea: cd fc 1f    ...
    call prsepr                                                       ; 1fed: cd 4e 20    .N
    jr z,mprseplp                                                     ; 1ff0: 28 f3       (.
; $1ff2 referenced 1 time by $1fe3
print3:
    cp $29                                                            ; 1ff2: fe 29       .)
    ret z                                                             ; 1ff4: c8          .
; $1ff5 referenced 1 time by $2064
prcifrn:
    call unstack_z                                                    ; 1ff5: cd c3 1f    ...
    ld a,$0d                                                          ; 1ff8: 3e 0d       >.
    rst $10                                                           ; 1ffa: d7          .
    ret                                                               ; 1ffb: c9          .

; $1ffc referenced 2 times by $1fea, $21af
pritem:
    rst $18                                                           ; 1ffc: df          .
    cp $ac                                                            ; 1ffd: fe ac       ..
    jr nz,pritem2                                                     ; 1fff: 20 0d        .
    call sexpt2nums                                                   ; 2001: cd 79 1c    .y.
    call unstack_z                                                    ; 2004: cd c3 1f    ...
    call stk_to_bc                                                    ; 2007: cd 07 23    ..#
    ld a,$16                                                          ; 200a: 3e 16       >.
    jr atsr4                                                          ; 200c: 18 10       ..

; $200e referenced 1 time by $1fff
pritem2:
    cp $ad                                                            ; 200e: fe ad       ..
    jr nz,pritem4                                                     ; 2010: 20 12        .
    rst $20                                                           ; 2012: e7          .
    call class_6                                                      ; 2013: cd 82 1c    ...
    call unstack_z                                                    ; 2016: cd c3 1f    ...
    call find_int                                                     ; 2019: cd 99 1e    ...
    ld a,$17                                                          ; 201c: 3e 17       >.
; $201e referenced 1 time by $200c
atsr4:
    rst $10                                                           ; 201e: d7          .
    ld a,c                                                            ; 201f: 79          y
    rst $10                                                           ; 2020: d7          .
    ld a,b                                                            ; 2021: 78          x
    rst $10                                                           ; 2022: d7          .
    ret                                                               ; 2023: c9          .

; $2024 referenced 1 time by $2010
pritem4:
    call citemsr                                                      ; 2024: cd f2 21    ..!
    ret nc                                                            ; 2027: d0          .
    call l2070                                                        ; 2028: cd 70 20    .p
    ret nc                                                            ; 202b: d0          .
    call scanning                                                     ; 202c: cd fb 24    ..$
    call unstack_z                                                    ; 202f: cd c3 1f    ...
    bit 6,(iy+flags - err_nr)                                         ; 2032: fd cb 01... ...
    call z,stk_fetch                                                  ; 2036: cc f1 2b    ..+
    jp nz,print_fp                                                    ; 2039: c2 e3 2d    ..-
; $203c referenced 1 time by $2043
l203c:
    ld a,b                                                            ; 203c: 78          x
    or c                                                              ; 203d: b1          .
    dec bc                                                            ; 203e: 0b          .
    ret z                                                             ; 203f: c8          .
    ld a,(de)                                                         ; 2040: 1a          .
    inc de                                                            ; 2041: 13          .
    rst $10                                                           ; 2042: d7          .
    jr l203c                                                          ; 2043: 18 f7       ..

; $2045 referenced 2 times by $1fe0, $2068
prterm:
    cp $29                                                            ; 2045: fe 29       .)
    ret z                                                             ; 2047: c8          .
; $2048 referenced 1 time by $06d0
l2048:
    cp $0d                                                            ; 2048: fe 0d       ..
    ret z                                                             ; 204a: c8          .
    cp $3a                                                            ; 204b: fe 3a       .:
    ret                                                               ; 204d: c9          .

; $204e referenced 4 times by $1fe5, $1fed, $20c1, $21b2
prsepr:
    rst $18                                                           ; 204e: df          .
    cp $3b                                                            ; 204f: fe 3b       .;
    jr z,prserp3                                                      ; 2051: 28 14       (.
    cp $2c                                                            ; 2053: fe 2c       .,
    jr nz,l2061                                                       ; 2055: 20 0a        .
    call syntax_z                                                     ; 2057: cd 30 25    .0%
    jr z,prserp3                                                      ; 205a: 28 0b       (.
    ld a,6                                                            ; 205c: 3e 06       >.
    rst $10                                                           ; 205e: d7          .
    jr prserp3                                                        ; 205f: 18 06       ..

; $2061 referenced 1 time by $2055
l2061:
    cp $27                                                            ; 2061: fe 27       .'
    ret nz                                                            ; 2063: c0          .
    call prcifrn                                                      ; 2064: cd f5 1f    ...
; $2067 referenced 3 times by $2051, $205a, $205f
prserp3:
    rst $20                                                           ; 2067: e7          .
    call prterm                                                       ; 2068: cd 45 20    .E
    jr nz,l206e                                                       ; 206b: 20 01        .
    pop bc                                                            ; 206d: c1          .
; $206e referenced 1 time by $206b
l206e:
    cp a                                                              ; 206e: bf          .
    ret                                                               ; 206f: c9          .

; $2070 referenced 2 times by $1806, $2028
l2070:
    cp $23                                                            ; 2070: fe 23       .#
    scf                                                               ; 2072: 37          7
    ret nz                                                            ; 2073: c0          .
    rst $20                                                           ; 2074: e7          .
    call class_6                                                      ; 2075: cd 82 1c    ...
    and a                                                             ; 2078: a7          .
    call unstack_z                                                    ; 2079: cd c3 1f    ...
; $207c referenced 1 time by $3620
l207c:
    call getbyte                                                      ; 207c: cd 94 1e    ...
    cp $10                                                            ; 207f: fe 10       ..
    jp nc,invstrm                                                     ; 2081: d2 0e 16    ...
    call l1601                                                        ; 2084: cd 01 16    ...
    and a                                                             ; 2087: a7          .
    ret                                                               ; 2088: c9          .

input:
    call syntax_z                                                     ; 2089: cd 30 25    .0%
    jr z,l2096                                                        ; 208c: 28 08       (.
    call clslower                                                     ; 208e: cd 6e 0d    .n.
    ld a,1                                                            ; 2091: 3e 01       >.
    call l1601                                                        ; 2093: cd 01 16    ...
; $2096 referenced 1 time by $208c
l2096:
    ld (iy+tv_flag - err_nr),1                                        ; 2096: fd 36 02... .6.
    call ipitem                                                       ; 209a: cd c1 20    ..
    call check_end                                                    ; 209d: cd ee 1b    ...
    ld bc,(s_posn)                                                    ; 20a0: ed 4b 88... .K.
    ld a,(df_sz)                                                      ; 20a4: 3a 6b 5c    :k\
    cp b                                                              ; 20a7: b8          .
    jr c,l20ad                                                        ; 20a8: 38 03       8.
    ld b,a                                                            ; 20aa: 47          G
    ld c,$21                                                          ; 20ab: 0e 21       .!
; $20ad referenced 1 time by $20a8
l20ad:
    ld (s_posn),bc                                                    ; 20ad: ed 43 88... .C.
    ld a,$19                                                          ; 20b1: 3e 19       >.
    sub b                                                             ; 20b3: 90          .
    ld (scr_ct),a                                                     ; 20b4: 32 8c 5c    2.\
    res 0,(iy+tv_flag - err_nr)                                       ; 20b7: fd cb 02... ...
    call l0dd9                                                        ; 20bb: cd d9 0d    ...
    jp clslower                                                       ; 20be: c3 6e 0d    .n.

; $20c1 referenced 3 times by $209a, $20c4, $21b5
ipitem:
    call prsepr                                                       ; 20c1: cd 4e 20    .N
    jr z,ipitem                                                       ; 20c4: 28 fb       (.
    cp $28                                                            ; 20c6: fe 28       .(
    jr nz,inp2                                                        ; 20c8: 20 0e        .
    rst $20                                                           ; 20ca: e7          .
    call print2                                                       ; 20cb: cd df 1f    ...
    rst $18                                                           ; 20ce: df          .
    cp $29                                                            ; 20cf: fe 29       .)
    jp nz,report_c                                                    ; 20d1: c2 8a 1c    ...
    rst $20                                                           ; 20d4: e7          .
    jp l21b2                                                          ; 20d5: c3 b2 21    ..!

; $20d8 referenced 1 time by $20c8
inp2:
    cp $ca                                                            ; 20d8: fe ca       ..
    jr nz,l20ed                                                       ; 20da: 20 11        .
    rst $20                                                           ; 20dc: e7          .
    call class_1                                                      ; 20dd: cd 1f 1c    ...
    set 7,(iy+flagx - err_nr)                                         ; 20e0: fd cb 37... ..7
    bit 6,(iy+flags - err_nr)                                         ; 20e4: fd cb 01... ...
    jp nz,report_c                                                    ; 20e8: c2 8a 1c    ...
    jr l20fa                                                          ; 20eb: 18 0d       ..

; $20ed referenced 1 time by $20da
l20ed:
    call alpha                                                        ; 20ed: cd 8d 2c    ..,
    jp nc,l21af                                                       ; 20f0: d2 af 21    ..!
    call class_1                                                      ; 20f3: cd 1f 1c    ...
    res 7,(iy+flagx - err_nr)                                         ; 20f6: fd cb 37... ..7
; $20fa referenced 1 time by $20eb
l20fa:
    call syntax_z                                                     ; 20fa: cd 30 25    .0%
    jp z,l21b2                                                        ; 20fd: ca b2 21    ..!
    call setwork                                                      ; 2100: cd bf 16    ...
    ld bc,1                                                           ; 2103: 01 01 00    ...
    ld hl,$5c71                                                       ; 2106: 21 71 5c    !q\
    set 5,(hl)                                                        ; 2109: cb ee       ..
    res 6,(hl)                                                        ; 210b: cb b6       ..
    bit 7,(hl)                                                        ; 210d: cb 7e       .~
    jr nz,l211c                                                       ; 210f: 20 0b        .
    ld a,(flags)                                                      ; 2111: 3a 3b 5c    :;\
    and $40                                                           ; 2114: e6 40       .@
    jr nz,prompt                                                      ; 2116: 20 02        .
    ld c,3                                                            ; 2118: 0e 03       ..
; $211a referenced 1 time by $2116
prompt:
    or (hl)                                                           ; 211a: b6          .
    ld (hl),a                                                         ; 211b: 77          w
; $211c referenced 1 time by $210f
l211c:
    rst $30                                                           ; 211c: f7          .
    ld (hl),$0d                                                       ; 211d: 36 0d       6.
    ld a,c                                                            ; 211f: 79          y
    rrca                                                              ; 2120: 0f          .
    rrca                                                              ; 2121: 0f          .
    jr nc,inp7                                                        ; 2122: 30 05       0.
    ld a,$22                                                          ; 2124: 3e 22       >"
    ld (de),a                                                         ; 2126: 12          .
    dec hl                                                            ; 2127: 2b          +
    ld (hl),a                                                         ; 2128: 77          w
; $2129 referenced 1 time by $2122
inp7:
    ld (k_cur),hl                                                     ; 2129: 22 5b 5c    "[\
    bit 7,(iy+flagx - err_nr)                                         ; 212c: fd cb 37... ..7
    jr nz,inp9                                                        ; 2130: 20 2c        ,
    ld hl,(ch_add)                                                    ; 2132: 2a 5d 5c    *]\
    push hl                                                           ; 2135: e5          .
    ld hl,(err_sp)                                                    ; 2136: 2a 3d 5c    *=\
    push hl                                                           ; 2139: e5          .
inperr:
    ld hl,$213a                                                       ; 213a: 21 3a 21    !:!
    push hl                                                           ; 213d: e5          .
    bit 4,(iy+flags2 - err_nr)                                        ; 213e: fd cb 30... ..0
    jr z,l2148                                                        ; 2142: 28 04       (.
    ld (err_sp),sp                                                    ; 2144: ed 73 3d... .s=
; $2148 referenced 1 time by $2142
l2148:
    ld hl,(worksp)                                                    ; 2148: 2a 61 5c    *a\
    call l11a7                                                        ; 214b: cd a7 11    ...
    ld (iy+err_nr - err_nr),$ff                                       ; 214e: fd 36 00... .6.
    call editor                                                       ; 2152: cd 2c 0f    .,.
    res 7,(iy+flags - err_nr)                                         ; 2155: fd cb 01... ...
    call inpas                                                        ; 2159: cd b9 21    ..!
    jr l2161                                                          ; 215c: 18 03       ..

; $215e referenced 1 time by $2130
inp9:
    call editor                                                       ; 215e: cd 2c 0f    .,.
; $2161 referenced 1 time by $215c
l2161:
    ld (iy+(k_cur+1) - err_nr),0                                      ; 2161: fd 36 22... .6"
    call chltchk                                                      ; 2165: cd d6 21    ..!
    jr nz,l2174                                                       ; 2168: 20 0a        .
    call l111d                                                        ; 216a: cd 1d 11    ...
    ld bc,(echo_e)                                                    ; 216d: ed 4b 82... .K.
    call l0dd9                                                        ; 2171: cd d9 0d    ...
; $2174 referenced 1 time by $2168
l2174:
    ld hl,$5c71                                                       ; 2174: 21 71 5c    !q\
    res 5,(hl)                                                        ; 2177: cb ae       ..
    bit 7,(hl)                                                        ; 2179: cb 7e       .~
    res 7,(hl)                                                        ; 217b: cb be       ..
    jr nz,l219b                                                       ; 217d: 20 1c        .
    pop hl                                                            ; 217f: e1          .
    pop hl                                                            ; 2180: e1          .
    ld (err_sp),hl                                                    ; 2181: 22 3d 5c    "=\
    set 7,(iy+flags - err_nr)                                         ; 2184: fd cb 01... ...
    pop hl                                                            ; 2188: e1          .
    ld (x_ptr),hl                                                     ; 2189: 22 5f 5c    "_\
    call inpas                                                        ; 218c: cd b9 21    ..!
    ld hl,(x_ptr)                                                     ; 218f: 2a 5f 5c    *_\
    ld (iy+(x_ptr+1) - err_nr),0                                      ; 2192: fd 36 26... .6&
    ld (ch_add),hl                                                    ; 2196: 22 5d 5c    "]\
    jr l21b2                                                          ; 2199: 18 17       ..

; $219b referenced 1 time by $217d
l219b:
    ld hl,(stkbot)                                                    ; 219b: 2a 63 5c    *c\
    ld de,(worksp)                                                    ; 219e: ed 5b 61... .[a
    scf                                                               ; 21a2: 37          7
    sbc hl,de                                                         ; 21a3: ed 52       .R
    ld c,l                                                            ; 21a5: 4d          M
    ld b,h                                                            ; 21a6: 44          D
    call stk_store                                                    ; 21a7: cd b2 2a    ..*
    call let                                                          ; 21aa: cd ff 2a    ..*
    jr l21b2                                                          ; 21ad: 18 03       ..

; $21af referenced 1 time by $20f0
l21af:
    call pritem                                                       ; 21af: cd fc 1f    ...
; $21b2 referenced 4 times by $20d5, $20fd, $2199, $21ad
l21b2:
    call prsepr                                                       ; 21b2: cd 4e 20    .N
    jp z,ipitem                                                       ; 21b5: ca c1 20    ..
    ret                                                               ; 21b8: c9          .

; $21b9 referenced 2 times by $2159, $218c
inpas:
    ld hl,(worksp)                                                    ; 21b9: 2a 61 5c    *a\
    ld (ch_add),hl                                                    ; 21bc: 22 5d 5c    "]\
    rst $18                                                           ; 21bf: df          .
    cp $e2                                                            ; 21c0: fe e2       ..
    jr z,l21d0                                                        ; 21c2: 28 0c       (.
    ld a,(flagx)                                                      ; 21c4: 3a 71 5c    :q\
    call input_rep                                                    ; 21c7: cd 59 1c    .Y.
    rst $18                                                           ; 21ca: df          .
    cp $0d                                                            ; 21cb: fe 0d       ..
    ret z                                                             ; 21cd: c8          .
    rst $08                                                           ; 21ce: cf          .
    db $0b                                                            ; 21cf: 0b          .  ; Report C Nonsense in BASIC

; $21d0 referenced 1 time by $21c2
l21d0:
    call syntax_z                                                     ; 21d0: cd 30 25    .0%
    ret z                                                             ; 21d3: c8          .
    rst $08                                                           ; 21d4: cf          .
    db $10                                                            ; 21d5: 10          .  ; Report H STOP in INPUT

; $21d6 referenced 2 times by $2165, $3623
chltchk:
    ld hl,(curchl)                                                    ; 21d6: 2a 51 5c    *Q\
    inc hl                                                            ; 21d9: 23          #
    inc hl                                                            ; 21da: 23          #
    inc hl                                                            ; 21db: 23          #
    inc hl                                                            ; 21dc: 23          #
    ld a,(hl)                                                         ; 21dd: 7e          ~
    cp $4b                                                            ; 21de: fe 4b       .K
    ret                                                               ; 21e0: c9          .

; $21e1 referenced 2 times by $21e9, $21ed
l21e1:
    rst $20                                                           ; 21e1: e7          .
; $21e2 referenced 1 time by $1cd2
citem:
    call citemsr                                                      ; 21e2: cd f2 21    ..!
    ret c                                                             ; 21e5: d8          .
    rst $18                                                           ; 21e6: df          .
    cp $3b                                                            ; 21e7: fe 3b       .;
    jr z,l21e1                                                        ; 21e9: 28 f6       (.
    cp $2c                                                            ; 21eb: fe 2c       .,
    jr z,l21e1                                                        ; 21ed: 28 f2       (.
    jp report_c                                                       ; 21ef: c3 8a 1c    ...

; $21f2 referenced 2 times by $2024, $21e2
citemsr:
    cp $d9                                                            ; 21f2: fe d9       ..
    ret c                                                             ; 21f4: d8          .
    cp $df                                                            ; 21f5: fe df       ..
    ccf                                                               ; 21f7: 3f          ?
    ret c                                                             ; 21f8: d8          .
    ld c,a                                                            ; 21f9: 4f          O
    rst $20                                                           ; 21fa: e7          .
    ld a,c                                                            ; 21fb: 79          y
; $21fc referenced 1 time by $1ca2
cotemp4:
    sub $c9                                                           ; 21fc: d6 c9       ..
    push af                                                           ; 21fe: f5          .
    call class_6                                                      ; 21ff: cd 82 1c    ...
    pop af                                                            ; 2202: f1          .
    and a                                                             ; 2203: a7          .
    call unstack_z                                                    ; 2204: cd c3 1f    ...
    push af                                                           ; 2207: f5          .
    call getbyte                                                      ; 2208: cd 94 1e    ...
    ld d,a                                                            ; 220b: 57          W
    pop af                                                            ; 220c: f1          .
    rst $10                                                           ; 220d: d7          .
    ld a,d                                                            ; 220e: 7a          z
    rst $10                                                           ; 220f: d7          .
    ret                                                               ; 2210: c9          .

; $2211 referenced 1 time by $0a94
l2211:
    sub $11                                                           ; 2211: d6 11       ..
    adc a,0                                                           ; 2213: ce 00       ..
    jr z,l2234                                                        ; 2215: 28 1d       (.
    sub 2                                                             ; 2217: d6 02       ..
    adc a,0                                                           ; 2219: ce 00       ..
    jr z,l2273                                                        ; 221b: 28 56       (V
    cp 1                                                              ; 221d: fe 01       ..
    ld b,1                                                            ; 221f: 06 01       ..
    ld a,d                                                            ; 2221: 7a          z
    jr nz,coinverse                                                   ; 2222: 20 04        .
    rlca                                                              ; 2224: 07          .
    rlca                                                              ; 2225: 07          .
    ld b,4                                                            ; 2226: 06 04       ..
; $2228 referenced 1 time by $2222
coinverse:
    ld c,a                                                            ; 2228: 4f          O
    ld a,d                                                            ; 2229: 7a          z
    cp 2                                                              ; 222a: fe 02       ..
    jr nc,invcolerr                                                   ; 222c: 30 16       0.
    ld a,c                                                            ; 222e: 79          y
    ld hl,$5c91                                                       ; 222f: 21 91 5c    !.\
    jr cochng                                                         ; 2232: 18 38       .8

; $2234 referenced 1 time by $2215
l2234:
    ld a,d                                                            ; 2234: 7a          z
    ld b,7                                                            ; 2235: 06 07       ..
    jr c,l223e                                                        ; 2237: 38 05       8.
    rlca                                                              ; 2239: 07          .
    rlca                                                              ; 223a: 07          .
    rlca                                                              ; 223b: 07          .
    ld b,$38                                                          ; 223c: 06 38       .8
; $223e referenced 1 time by $2237
l223e:
    ld c,a                                                            ; 223e: 4f          O
    ld a,d                                                            ; 223f: 7a          z
    cp $0a                                                            ; 2240: fe 0a       ..
    jr c,l2246                                                        ; 2242: 38 02       8.
; $2244 referenced 5 times by $222c, $2285, $2299, $393a, $3940
invcolerr:
    rst $08                                                           ; 2244: cf          .
    db $13                                                            ; 2245: 13          .  ; Report K Invalid colour

; $2246 referenced 1 time by $2242
l2246:
    ld hl,$5c8f                                                       ; 2246: 21 8f 5c    !.\
    cp 8                                                              ; 2249: fe 08       ..
    jr c,l2258                                                        ; 224b: 38 0b       8.
    ld a,(hl)                                                         ; 224d: 7e          ~
    jr z,l2257                                                        ; 224e: 28 07       (.
    or b                                                              ; 2250: b0          .
    cpl                                                               ; 2251: 2f          /
    and $24                                                           ; 2252: e6 24       .$
    jr z,l2257                                                        ; 2254: 28 01       (.
    ld a,b                                                            ; 2256: 78          x
; $2257 referenced 2 times by $224e, $2254
l2257:
    ld c,a                                                            ; 2257: 4f          O
; $2258 referenced 1 time by $224b
l2258:
    ld a,c                                                            ; 2258: 79          y
    call cochng                                                       ; 2259: cd 6c 22    .l"
    ld a,7                                                            ; 225c: 3e 07       >.
    cp d                                                              ; 225e: ba          .
    sbc a,a                                                           ; 225f: 9f          .
    call cochng                                                       ; 2260: cd 6c 22    .l"
    rlca                                                              ; 2263: 07          .
    rlca                                                              ; 2264: 07          .
    and $50                                                           ; 2265: e6 50       .P
    ld b,a                                                            ; 2267: 47          G
    ld a,8                                                            ; 2268: 3e 08       >.
    cp d                                                              ; 226a: ba          .
    sbc a,a                                                           ; 226b: 9f          .
; $226c referenced 5 times by $2232, $2259, $2260, $228b, $2292
cochng:
    xor (hl)                                                          ; 226c: ae          .
    and b                                                             ; 226d: a0          .
    xor (hl)                                                          ; 226e: ae          .
    ld (hl),a                                                         ; 226f: 77          w
    ld a,b                                                            ; 2270: 78          x
    inc hl                                                            ; 2271: 23          #
    ret                                                               ; 2272: c9          .

; $2273 referenced 1 time by $221b
l2273:
    sbc a,a                                                           ; 2273: 9f          .
    ld a,d                                                            ; 2274: 7a          z
    rrca                                                              ; 2275: 0f          .
    ld b,$80                                                          ; 2276: 06 80       ..
    jr nz,l227d                                                       ; 2278: 20 03        .
    rrca                                                              ; 227a: 0f          .
    ld b,$40                                                          ; 227b: 06 40       .@
; $227d referenced 1 time by $2278
l227d:
    ld c,a                                                            ; 227d: 4f          O
    ld a,d                                                            ; 227e: 7a          z
    cp 8                                                              ; 227f: fe 08       ..
    jr z,cofbok                                                       ; 2281: 28 04       (.
    cp 2                                                              ; 2283: fe 02       ..
    jr nc,invcolerr                                                   ; 2285: 30 bd       0.
; $2287 referenced 1 time by $2281
cofbok:
    ld a,c                                                            ; 2287: 79          y
    ld hl,$5c8f                                                       ; 2288: 21 8f 5c    !.\
    call cochng                                                       ; 228b: cd 6c 22    .l"
    ld a,c                                                            ; 228e: 79          y
    rrca                                                              ; 228f: 0f          .
    rrca                                                              ; 2290: 0f          .
    rrca                                                              ; 2291: 0f          .
    jr cochng                                                         ; 2292: 18 d8       ..

l2294:
    call getbyte                                                      ; 2294: cd 94 1e    ...
    cp 8                                                              ; 2297: fe 08       ..
    jr nc,invcolerr                                                   ; 2299: 30 a9       0.
    out (ula_port),a                                                  ; 229b: d3 fe       ..
    rlca                                                              ; 229d: 07          .
    rlca                                                              ; 229e: 07          .
    rlca                                                              ; 229f: 07          .
    bit 5,a                                                           ; 22a0: cb 6f       .o
    jr nz,l22a6                                                       ; 22a2: 20 02        .
    xor 7                                                             ; 22a4: ee 07       ..
; $22a6 referenced 1 time by $22a2
l22a6:
    ld (bordcr),a                                                     ; 22a6: 32 48 5c    2H\
    ret                                                               ; 22a9: c9          .

; $22aa referenced 2 times by $22ce, $22e9
l22aa:
    ld a,$af                                                          ; 22aa: 3e af       >.
    sub b                                                             ; 22ac: 90          .
    jp c,report_b                                                     ; 22ad: da f9 24    ..$
    ld b,a                                                            ; 22b0: 47          G
    and a                                                             ; 22b1: a7          .
    rra                                                               ; 22b2: 1f          .
    scf                                                               ; 22b3: 37          7
    rra                                                               ; 22b4: 1f          .
    and a                                                             ; 22b5: a7          .
    rra                                                               ; 22b6: 1f          .
    xor b                                                             ; 22b7: a8          .
    and $f8                                                           ; 22b8: e6 f8       ..
    xor b                                                             ; 22ba: a8          .
    ld h,a                                                            ; 22bb: 67          g
    ld a,c                                                            ; 22bc: 79          y
    rlca                                                              ; 22bd: 07          .
    rlca                                                              ; 22be: 07          .
    rlca                                                              ; 22bf: 07          .
    xor b                                                             ; 22c0: a8          .
    and $c7                                                           ; 22c1: e6 c7       ..
    xor b                                                             ; 22c3: a8          .
    rlca                                                              ; 22c4: 07          .
    rlca                                                              ; 22c5: 07          .
    ld l,a                                                            ; 22c6: 6f          o
    ld a,c                                                            ; 22c7: 79          y
    and 7                                                             ; 22c8: e6 07       ..
    ret                                                               ; 22ca: c9          .

; $22cb referenced 1 time by $267e
l22cb:
    call l3915                                                        ; 22cb: cd 15 39    ..9
    call l22aa                                                        ; 22ce: cd aa 22    .."
    inc a                                                             ; 22d1: 3c          <
    ld b,a                                                            ; 22d2: 47          G
    ld a,(hl)                                                         ; 22d3: 7e          ~
; $22d4 referenced 1 time by $22d5
l22d4:
    rlca                                                              ; 22d4: 07          .
    djnz l22d4                                                        ; 22d5: 10 fd       ..
    and 1                                                             ; 22d7: e6 01       ..
    jp stack_a                                                        ; 22d9: c3 28 2d    .(-

; $22dc referenced 2 times by $2339, $2357
plot:
    call l3915                                                        ; 22dc: cd 15 39    ..9
    call l22e5                                                        ; 22df: cd e5 22    .."
    jp trcurp                                                         ; 22e2: c3 4d 0d    .M.

; $22e5 referenced 2 times by $22df, $24ee
l22e5:
    ld (coords),bc                                                    ; 22e5: ed 43 7d... .C}
    call l22aa                                                        ; 22e9: cd aa 22    .."
    inc a                                                             ; 22ec: 3c          <
    ld b,a                                                            ; 22ed: 47          G
    ld a,$fe                                                          ; 22ee: 3e fe       >.
; $22f0 referenced 1 time by $22f1
l22f0:
    rrca                                                              ; 22f0: 0f          .
    djnz l22f0                                                        ; 22f1: 10 fd       ..
    ld b,a                                                            ; 22f3: 47          G
    ld a,(hl)                                                         ; 22f4: 7e          ~
    ld c,(iy+p_flag - err_nr)                                         ; 22f5: fd 4e 57    .NW
    bit 0,c                                                           ; 22f8: cb 41       .A
    jr nz,l22fd                                                       ; 22fa: 20 01        .
    and b                                                             ; 22fc: a0          .
; $22fd referenced 1 time by $22fa
l22fd:
    bit 2,c                                                           ; 22fd: cb 51       .Q
    jr nz,l2303                                                       ; 22ff: 20 02        .
    xor b                                                             ; 2301: a8          .
    cpl                                                               ; 2302: 2f          /
; $2303 referenced 1 time by $22ff
l2303:
    ld (hl),a                                                         ; 2303: 77          w
    jp l0bdb                                                          ; 2304: c3 db 0b    ...

; $2307 referenced 3 times by $2007, $24b7, $3915
stk_to_bc:
    call stk_to_a                                                     ; 2307: cd 14 23    ..#
    ld b,a                                                            ; 230a: 47          G
    push bc                                                           ; 230b: c5          .
    call stk_to_a                                                     ; 230c: cd 14 23    ..#
    ld e,c                                                            ; 230f: 59          Y
    pop bc                                                            ; 2310: c1          .
    ld d,c                                                            ; 2311: 51          Q
    ld c,a                                                            ; 2312: 4f          O
    ret                                                               ; 2313: c9          .

; $2314 referenced 2 times by $2307, $230c
stk_to_a:
    call fp_to_a                                                      ; 2314: cd d5 2d    ..-
    jp c,report_b                                                     ; 2317: da f9 24    ..$
    ld c,1                                                            ; 231a: 0e 01       ..
    ret z                                                             ; 231c: c8          .
    ld c,$ff                                                          ; 231d: 0e ff       ..
    ret                                                               ; 231f: c9          .

circle:
    rst $18                                                           ; 2320: df          .
    cp $2c                                                            ; 2321: fe 2c       .,
    jp nz,report_c                                                    ; 2323: c2 8a 1c    ...
    rst $20                                                           ; 2326: e7          .
    call class_6                                                      ; 2327: cd 82 1c    ...
    call check_end                                                    ; 232a: cd ee 1b    ...
    rst $28                                                           ; 232d: ef          .
    db $2a                                                            ; 232e: 2a          *  ; abs
    db $3d                                                            ; 232f: 3d          =  ; re-stack
    db $38                                                            ; 2330: 38          8  ; end-calc

    ld a,(hl)                                                         ; 2331: 7e          ~
    cp $81                                                            ; 2332: fe 81       ..
    jr nc,l233b                                                       ; 2334: 30 05       0.
    rst $28                                                           ; 2336: ef          .
    db 2                                                              ; 2337: 02          .  ; delete
    db $38                                                            ; 2338: 38          8  ; end-calc

    jr plot                                                           ; 2339: 18 a1       ..

; $233b referenced 1 time by $2334
l233b:
    rst $28                                                           ; 233b: ef          .
    db $a3                                                            ; 233c: a3          .  ; stk-pi/2
    db $38                                                            ; 233d: 38          8  ; end-calc

    ld (hl),$83                                                       ; 233e: 36 83       6.
    rst $28                                                           ; 2340: ef          .
    db $c5                                                            ; 2341: c5          .  ; st-mem-5
    db 2                                                              ; 2342: 02          .  ; delete
    db $38                                                            ; 2343: 38          8  ; end-calc

    call l247d                                                        ; 2344: cd 7d 24    .}$
    push bc                                                           ; 2347: c5          .
    rst $28                                                           ; 2348: ef          .
    db $31                                                            ; 2349: 31          1  ; duplicate
    db $e1                                                            ; 234a: e1          .  ; get-mem-1
    db 4                                                              ; 234b: 04          .  ; multiply
    db $38                                                            ; 234c: 38          8  ; end-calc

    ld a,(hl)                                                         ; 234d: 7e          ~
    cp $80                                                            ; 234e: fe 80       ..
    jr nc,l235a                                                       ; 2350: 30 08       0.
    rst $28                                                           ; 2352: ef          .
    db 2                                                              ; 2353: 02          .  ; delete
    db 2                                                              ; 2354: 02          .  ; delete
    db $38                                                            ; 2355: 38          8  ; end-calc

    pop bc                                                            ; 2356: c1          .
    jp plot                                                           ; 2357: c3 dc 22    .."

; $235a referenced 1 time by $2350
l235a:
    rst $28                                                           ; 235a: ef          .
    db $c2                                                            ; 235b: c2          .  ; st-mem-2
    db 1                                                              ; 235c: 01          .  ; exchange
    db $c0                                                            ; 235d: c0          .  ; st-mem-0
    db 2                                                              ; 235e: 02          .  ; delete
    db 3                                                              ; 235f: 03          .  ; subtract
    db 1                                                              ; 2360: 01          .  ; exchange
    db $e0                                                            ; 2361: e0          .  ; get-mem-0
    db $0f                                                            ; 2362: 0f          .  ; addition
    db $c0                                                            ; 2363: c0          .  ; st-mem-0
    db 1                                                              ; 2364: 01          .  ; exchange
    db $31                                                            ; 2365: 31          1  ; duplicate
    db $e0                                                            ; 2366: e0          .  ; get-mem-0
    db 1                                                              ; 2367: 01          .  ; exchange
    db $31                                                            ; 2368: 31          1  ; duplicate
    db $e0                                                            ; 2369: e0          .  ; get-mem-0
    db $a0                                                            ; 236a: a0          .  ; stk-zero
    db $c1                                                            ; 236b: c1          .  ; st-mem-1
    db 2                                                              ; 236c: 02          .  ; delete
    db $38                                                            ; 236d: 38          8  ; end-calc

    inc (iy+(membot+10) - err_nr)                                     ; 236e: fd 34 62    .4b
    call getbyte                                                      ; 2371: cd 94 1e    ...
    ld l,a                                                            ; 2374: 6f          o
    push hl                                                           ; 2375: e5          .
    call getbyte                                                      ; 2376: cd 94 1e    ...
    pop hl                                                            ; 2379: e1          .
    ld h,a                                                            ; 237a: 67          g
    ld (coords),hl                                                    ; 237b: 22 7d 5c    "}\
    pop bc                                                            ; 237e: c1          .
    jp l2405                                                          ; 237f: c3 05 24    ..$

l2382:
    rst $18                                                           ; 2382: df          .
    cp $2c                                                            ; 2383: fe 2c       .,
    jr z,l238d                                                        ; 2385: 28 06       (.
    call check_end                                                    ; 2387: cd ee 1b    ...
    jp linedraw                                                       ; 238a: c3 77 24    .w$

; $238d referenced 1 time by $2385
l238d:
    rst $20                                                           ; 238d: e7          .
    call class_6                                                      ; 238e: cd 82 1c    ...
    call check_end                                                    ; 2391: cd ee 1b    ...
    rst $28                                                           ; 2394: ef          .
    db $c5                                                            ; 2395: c5          .  ; st-mem-5
    db $a2                                                            ; 2396: a2          .  ; stk-half
    db 4                                                              ; 2397: 04          .  ; multiply
    db $1f                                                            ; 2398: 1f          .  ; sin
    db $31                                                            ; 2399: 31          1  ; duplicate
    db $30                                                            ; 239a: 30          0  ; not
    db $30                                                            ; 239b: 30          0  ; not
    db 0                                                              ; 239c: 00          .  ; jump-true
    db l23a3 - $                                                      ; 239d: 06          .
    db 2                                                              ; 239e: 02          .  ; delete
    db $38                                                            ; 239f: 38          8  ; end-calc

    jp linedraw                                                       ; 23a0: c3 77 24    .w$

l23a3:
    db $c0                                                            ; 23a3: c0          .  ; st-mem-0
    db 2                                                              ; 23a4: 02          .  ; delete
    db $c1                                                            ; 23a5: c1          .  ; st-mem-1
    db 2                                                              ; 23a6: 02          .  ; delete
    db $31                                                            ; 23a7: 31          1  ; duplicate
    db $2a                                                            ; 23a8: 2a          *  ; abs
    db $e1                                                            ; 23a9: e1          .  ; get-mem-1
    db 1                                                              ; 23aa: 01          .  ; exchange
    db $e1                                                            ; 23ab: e1          .  ; get-mem-1
    db $2a                                                            ; 23ac: 2a          *  ; abs
    db $0f                                                            ; 23ad: 0f          .  ; addition
    db $e0                                                            ; 23ae: e0          .  ; get-mem-0
    db 5                                                              ; 23af: 05          .  ; division
    db $2a                                                            ; 23b0: 2a          *  ; abs
    db $e0                                                            ; 23b1: e0          .  ; get-mem-0
    db 1                                                              ; 23b2: 01          .  ; exchange
    db $38                                                            ; 23b3: 38          8  ; end-calc

    call l247d                                                        ; 23b4: cd 7d 24    .}$
    push bc                                                           ; 23b7: c5          .
    rst $28                                                           ; 23b8: ef          .
    db 2                                                              ; 23b9: 02          .  ; delete
    db $e1                                                            ; 23ba: e1          .  ; get-mem-1
    db 1                                                              ; 23bb: 01          .  ; exchange
    db 5                                                              ; 23bc: 05          .  ; division
    db $c1                                                            ; 23bd: c1          .  ; st-mem-1
    db 2                                                              ; 23be: 02          .  ; delete
    db 1                                                              ; 23bf: 01          .  ; exchange
    db $31                                                            ; 23c0: 31          1  ; duplicate
    db $e1                                                            ; 23c1: e1          .  ; get-mem-1
    db 4                                                              ; 23c2: 04          .  ; multiply
    db $c2                                                            ; 23c3: c2          .  ; st-mem-2
    db 2                                                              ; 23c4: 02          .  ; delete
    db 1                                                              ; 23c5: 01          .  ; exchange
    db $31                                                            ; 23c6: 31          1  ; duplicate
    db $e1                                                            ; 23c7: e1          .  ; get-mem-1
    db 4                                                              ; 23c8: 04          .  ; multiply
    db $e2                                                            ; 23c9: e2          .  ; get-mem-2
    db $e5                                                            ; 23ca: e5          .  ; get-mem-5
    db $e0                                                            ; 23cb: e0          .  ; get-mem-0
    db 3                                                              ; 23cc: 03          .  ; subtract
    db $a2                                                            ; 23cd: a2          .  ; stk-half
    db 4                                                              ; 23ce: 04          .  ; multiply
    db $31                                                            ; 23cf: 31          1  ; duplicate
    db $1f                                                            ; 23d0: 1f          .  ; sin
    db $c5                                                            ; 23d1: c5          .  ; st-mem-5
    db 2                                                              ; 23d2: 02          .  ; delete
    db $20                                                            ; 23d3: 20             ; cos
    db $c0                                                            ; 23d4: c0          .  ; st-mem-0
    db 2                                                              ; 23d5: 02          .  ; delete
    db $c2                                                            ; 23d6: c2          .  ; st-mem-2
    db 2                                                              ; 23d7: 02          .  ; delete
    db $c1                                                            ; 23d8: c1          .  ; st-mem-1
    db $e5                                                            ; 23d9: e5          .  ; get-mem-5
    db 4                                                              ; 23da: 04          .  ; multiply
    db $e0                                                            ; 23db: e0          .  ; get-mem-0
    db $e2                                                            ; 23dc: e2          .  ; get-mem-2
    db 4                                                              ; 23dd: 04          .  ; multiply
    db $0f                                                            ; 23de: 0f          .  ; addition
    db $e1                                                            ; 23df: e1          .  ; get-mem-1
    db 1                                                              ; 23e0: 01          .  ; exchange
    db $c1                                                            ; 23e1: c1          .  ; st-mem-1
    db 2                                                              ; 23e2: 02          .  ; delete
    db $e0                                                            ; 23e3: e0          .  ; get-mem-0
    db 4                                                              ; 23e4: 04          .  ; multiply
    db $e2                                                            ; 23e5: e2          .  ; get-mem-2
    db $e5                                                            ; 23e6: e5          .  ; get-mem-5
    db 4                                                              ; 23e7: 04          .  ; multiply
    db 3                                                              ; 23e8: 03          .  ; subtract
    db $c2                                                            ; 23e9: c2          .  ; st-mem-2
    db 2                                                              ; 23ea: 02          .  ; delete
    db 1                                                              ; 23eb: 01          .  ; exchange
    db $38                                                            ; 23ec: 38          8  ; end-calc

    ld a,(coords)                                                     ; 23ed: 3a 7d 5c    :}\
    call stack_a                                                      ; 23f0: cd 28 2d    .(-
    rst $28                                                           ; 23f3: ef          .
    db $c0                                                            ; 23f4: c0          .  ; st-mem-0
    db $0f                                                            ; 23f5: 0f          .  ; addition
    db 1                                                              ; 23f6: 01          .  ; exchange
    db $38                                                            ; 23f7: 38          8  ; end-calc

    ld a,(coords+1)                                                   ; 23f8: 3a 7e 5c    :~\
    call stack_a                                                      ; 23fb: cd 28 2d    .(-
    rst $28                                                           ; 23fe: ef          .
    db $c5                                                            ; 23ff: c5          .  ; st-mem-5
    db $0f                                                            ; 2400: 0f          .  ; addition
    db $e0                                                            ; 2401: e0          .  ; get-mem-0
    db $e5                                                            ; 2402: e5          .  ; get-mem-5
    db $38                                                            ; 2403: 38          8  ; end-calc

    pop bc                                                            ; 2404: c1          .
; $2405 referenced 1 time by $237f
l2405:
    dec b                                                             ; 2405: 05          .
    jr l2439                                                          ; 2406: 18 31       .1

; $2408 referenced 1 time by $0fef
l2408:
    ld a,$e2                                                          ; 2408: 3e e2       >.
    call add_char                                                     ; 240a: cd 81 0f    ...
    ld (iy+err_nr - err_nr),$10                                       ; 240d: fd 36 00... .6.
    jp n_l_key                                                        ; 2411: c3 1d 10    ...

; $2414 referenced 2 times by $241b, $3c9d
l2414:
    ld a,(hl)                                                         ; 2414: 7e          ~
    cp $30                                                            ; 2415: fe 30       .0
    ret nz                                                            ; 2417: c0          .
    ld (hl),$20                                                       ; 2418: 36 20       6
    inc hl                                                            ; 241a: 23          #
    djnz l2414                                                        ; 241b: 10 f7       ..
    ret                                                               ; 241d: c9          .

l241e:
    db $ca, $f0, $e1, $ec, $ed, $e5, $f7                              ; 241e: ca f0 e1... ...

; $2425 referenced 1 time by $245d
l2425:
    rst $28                                                           ; 2425: ef          .
    db $e1                                                            ; 2426: e1          .  ; get-mem-1
    db $31                                                            ; 2427: 31          1  ; duplicate
    db $e3                                                            ; 2428: e3          .  ; get-mem-3
    db 4                                                              ; 2429: 04          .  ; multiply
    db $e2                                                            ; 242a: e2          .  ; get-mem-2
    db $e4                                                            ; 242b: e4          .  ; get-mem-4
    db 4                                                              ; 242c: 04          .  ; multiply
    db 3                                                              ; 242d: 03          .  ; subtract
    db $c1                                                            ; 242e: c1          .  ; st-mem-1
    db 2                                                              ; 242f: 02          .  ; delete
    db $e4                                                            ; 2430: e4          .  ; get-mem-4
    db 4                                                              ; 2431: 04          .  ; multiply
    db $e2                                                            ; 2432: e2          .  ; get-mem-2
    db $e3                                                            ; 2433: e3          .  ; get-mem-3
    db 4                                                              ; 2434: 04          .  ; multiply
    db $0f                                                            ; 2435: 0f          .  ; addition
    db $c2                                                            ; 2436: c2          .  ; st-mem-2
    db 2                                                              ; 2437: 02          .  ; delete
    db $38                                                            ; 2438: 38          8  ; end-calc

; $2439 referenced 1 time by $2406
l2439:
    push bc                                                           ; 2439: c5          .
    rst $28                                                           ; 243a: ef          .
    db $c0                                                            ; 243b: c0          .  ; st-mem-0
    db 2                                                              ; 243c: 02          .  ; delete
    db $e1                                                            ; 243d: e1          .  ; get-mem-1
    db $0f                                                            ; 243e: 0f          .  ; addition
    db $31                                                            ; 243f: 31          1  ; duplicate
    db $38                                                            ; 2440: 38          8  ; end-calc

    ld a,(coords)                                                     ; 2441: 3a 7d 5c    :}\
    call stack_a                                                      ; 2444: cd 28 2d    .(-
    rst $28                                                           ; 2447: ef          .
    db 3                                                              ; 2448: 03          .  ; subtract
    db $e0                                                            ; 2449: e0          .  ; get-mem-0
    db $e2                                                            ; 244a: e2          .  ; get-mem-2
    db $0f                                                            ; 244b: 0f          .  ; addition
    db $c0                                                            ; 244c: c0          .  ; st-mem-0
    db 1                                                              ; 244d: 01          .  ; exchange
    db $e0                                                            ; 244e: e0          .  ; get-mem-0
    db $38                                                            ; 244f: 38          8  ; end-calc

    ld a,(coords+1)                                                   ; 2450: 3a 7e 5c    :~\
    call stack_a                                                      ; 2453: cd 28 2d    .(-
    rst $28                                                           ; 2456: ef          .
    db 3                                                              ; 2457: 03          .  ; subtract
    db $38                                                            ; 2458: 38          8  ; end-calc

    call r1offcl                                                      ; 2459: cd b7 24    ..$
    pop bc                                                            ; 245c: c1          .
    djnz l2425                                                        ; 245d: 10 c6       ..
    rst $28                                                           ; 245f: ef          .
    db 2                                                              ; 2460: 02          .  ; delete
    db 2                                                              ; 2461: 02          .  ; delete
    db 1                                                              ; 2462: 01          .  ; exchange
    db $38                                                            ; 2463: 38          8  ; end-calc

    ld a,(coords)                                                     ; 2464: 3a 7d 5c    :}\
    call stack_a                                                      ; 2467: cd 28 2d    .(-
    rst $28                                                           ; 246a: ef          .
    db 3                                                              ; 246b: 03          .  ; subtract
    db 1                                                              ; 246c: 01          .  ; exchange
    db $38                                                            ; 246d: 38          8  ; end-calc

    ld a,(coords+1)                                                   ; 246e: 3a 7e 5c    :~\
    call stack_a                                                      ; 2471: cd 28 2d    .(-
    rst $28                                                           ; 2474: ef          .
    db 3                                                              ; 2475: 03          .  ; subtract
    db $38                                                            ; 2476: 38          8  ; end-calc

; $2477 referenced 2 times by $238a, $23a0
linedraw:
    call r1offcl                                                      ; 2477: cd b7 24    ..$
    jp trcurp                                                         ; 247a: c3 4d 0d    .M.

; $247d referenced 2 times by $2344, $23b4
l247d:
    rst $28                                                           ; 247d: ef          .
    db $31                                                            ; 247e: 31          1  ; duplicate
    db $28                                                            ; 247f: 28          (  ; sqr
    db $34                                                            ; 2480: 34          4  ; stk-data
    db $32, 0                                                         ; 2481: 32 00       2. ; 2
    db 1                                                              ; 2483: 01          .  ; exchange
    db 5                                                              ; 2484: 05          .  ; division
    db $e5                                                            ; 2485: e5          .  ; get-mem-5
    db 1                                                              ; 2486: 01          .  ; exchange
    db 5                                                              ; 2487: 05          .  ; division
    db $2a                                                            ; 2488: 2a          *  ; abs
    db $38                                                            ; 2489: 38          8  ; end-calc

    call fp_to_a                                                      ; 248a: cd d5 2d    ..-
    jr c,l2495                                                        ; 248d: 38 06       8.
    and $fc                                                           ; 248f: e6 fc       ..
    add a,4                                                           ; 2491: c6 04       ..
    jr nc,l2497                                                       ; 2493: 30 02       0.
; $2495 referenced 1 time by $248d
l2495:
    ld a,$fc                                                          ; 2495: 3e fc       >.
; $2497 referenced 1 time by $2493
l2497:
    push af                                                           ; 2497: f5          .
    call stack_a                                                      ; 2498: cd 28 2d    .(-
    rst $28                                                           ; 249b: ef          .
    db $e5                                                            ; 249c: e5          .  ; get-mem-5
    db 1                                                              ; 249d: 01          .  ; exchange
    db 5                                                              ; 249e: 05          .  ; division
    db $31                                                            ; 249f: 31          1  ; duplicate
    db $1f                                                            ; 24a0: 1f          .  ; sin
    db $c4                                                            ; 24a1: c4          .  ; st-mem-4
    db 2                                                              ; 24a2: 02          .  ; delete
    db $31                                                            ; 24a3: 31          1  ; duplicate
    db $a2                                                            ; 24a4: a2          .  ; stk-half
    db 4                                                              ; 24a5: 04          .  ; multiply
    db $1f                                                            ; 24a6: 1f          .  ; sin
    db $c1                                                            ; 24a7: c1          .  ; st-mem-1
    db 1                                                              ; 24a8: 01          .  ; exchange
    db $c0                                                            ; 24a9: c0          .  ; st-mem-0
    db 2                                                              ; 24aa: 02          .  ; delete
    db $31                                                            ; 24ab: 31          1  ; duplicate
    db 4                                                              ; 24ac: 04          .  ; multiply
    db $31                                                            ; 24ad: 31          1  ; duplicate
    db $0f                                                            ; 24ae: 0f          .  ; addition
    db $a1                                                            ; 24af: a1          .  ; stk-one
    db 3                                                              ; 24b0: 03          .  ; subtract
    db $1b                                                            ; 24b1: 1b          .  ; negate
    db $c3                                                            ; 24b2: c3          .  ; st-mem-3
    db 2                                                              ; 24b3: 02          .  ; delete
    db $38                                                            ; 24b4: 38          8  ; end-calc

    pop bc                                                            ; 24b5: c1          .
    ret                                                               ; 24b6: c9          .

; $24b7 referenced 2 times by $2459, $2477
r1offcl:
    call stk_to_bc                                                    ; 24b7: cd 07 23    ..#
    ld a,c                                                            ; 24ba: 79          y
    cp b                                                              ; 24bb: b8          .
    jr nc,l24c4                                                       ; 24bc: 30 06       0.
    xor a                                                             ; 24be: af          .
    ld l,c                                                            ; 24bf: 69          i
    push de                                                           ; 24c0: d5          .
    ld e,a                                                            ; 24c1: 5f          _
    jr l24cb                                                          ; 24c2: 18 07       ..

; $24c4 referenced 1 time by $24bc
l24c4:
    or c                                                              ; 24c4: b1          .
    ret z                                                             ; 24c5: c8          .
    ld l,b                                                            ; 24c6: 68          h
    ld b,c                                                            ; 24c7: 41          A
    push de                                                           ; 24c8: d5          .
    ld d,0                                                            ; 24c9: 16 00       ..
; $24cb referenced 1 time by $24c2
l24cb:
    ld h,b                                                            ; 24cb: 60          `
    ld a,b                                                            ; 24cc: 78          x
    rra                                                               ; 24cd: 1f          .
; $24ce referenced 1 time by $24f3
l24ce:
    add a,l                                                           ; 24ce: 85          .
    jr c,l24d4                                                        ; 24cf: 38 03       8.
    cp h                                                              ; 24d1: bc          .
    jr c,l24db                                                        ; 24d2: 38 07       8.
; $24d4 referenced 1 time by $24cf
l24d4:
    sub h                                                             ; 24d4: 94          .
    ld c,a                                                            ; 24d5: 4f          O
    exx                                                               ; 24d6: d9          .
    pop bc                                                            ; 24d7: c1          .
    push bc                                                           ; 24d8: c5          .
    jr l24df                                                          ; 24d9: 18 04       ..

; $24db referenced 1 time by $24d2
l24db:
    ld c,a                                                            ; 24db: 4f          O
    push de                                                           ; 24dc: d5          .
    exx                                                               ; 24dd: d9          .
    pop bc                                                            ; 24de: c1          .
; $24df referenced 1 time by $24d9
l24df:
    ld hl,(coords)                                                    ; 24df: 2a 7d 5c    *}\
    ld a,b                                                            ; 24e2: 78          x
    add a,h                                                           ; 24e3: 84          .
    ld b,a                                                            ; 24e4: 47          G
    ld a,c                                                            ; 24e5: 79          y
    inc a                                                             ; 24e6: 3c          <
    add a,l                                                           ; 24e7: 85          .
    jr c,l24f7                                                        ; 24e8: 38 0d       8.
    jr z,report_b                                                     ; 24ea: 28 0d       (.
; $24ec referenced 1 time by $24f7
l24ec:
    dec a                                                             ; 24ec: 3d          =
    ld c,a                                                            ; 24ed: 4f          O
    call l22e5                                                        ; 24ee: cd e5 22    .."
    exx                                                               ; 24f1: d9          .
    ld a,c                                                            ; 24f2: 79          y
    djnz l24ce                                                        ; 24f3: 10 d9       ..
    pop de                                                            ; 24f5: d1          .
    ret                                                               ; 24f6: c9          .

; $24f7 referenced 1 time by $24e8
l24f7:
    jr z,l24ec                                                        ; 24f7: 28 f3       (.
; $24f9 referenced 3 times by $22ad, $2317, $24ea
report_b:
    rst $08                                                           ; 24f9: cf          .
    db $0a                                                            ; 24fa: 0a          .  ; Report B Integer out of range

; $24fb referenced 12 times by $1c5a, $1c82, $1c8c, $1e2c, $1fb4, $202c, $25e9, $27d9, $289c, $35ce, $35e6, $3cde
scanning:
    rst $18                                                           ; 24fb: df          .
    ld b,0                                                            ; 24fc: 06 00       ..
    push bc                                                           ; 24fe: c5          .
; $24ff referenced 3 times by $25b0, $270f, $2792
l24ff:
    ld c,a                                                            ; 24ff: 4f          O
    ld hl,$2596                                                       ; 2500: 21 96 25    !.%
    call l0eac                                                        ; 2503: cd ac 0e    ...
    ld a,c                                                            ; 2506: 79          y
    jp nc,l2684                                                       ; 2507: d2 84 26    ..&
    ld c,(hl)                                                         ; 250a: 4e          N
    ld b,0                                                            ; 250b: 06 00       ..
    add hl,bc                                                         ; 250d: 09          .
    jp (hl)                                                           ; 250e: e9          .

; $250f referenced 3 times by $251a, $25b9, $25be
l250f:
    call ch_add_1                                                     ; 250f: cd 74 00    .t.
    inc bc                                                            ; 2512: 03          .
    cp $0d                                                            ; 2513: fe 0d       ..
    jp z,report_c                                                     ; 2515: ca 8a 1c    ...
    cp $22                                                            ; 2518: fe 22       ."
    jr nz,l250f                                                       ; 251a: 20 f3        .
    call ch_add_1                                                     ; 251c: cd 74 00    .t.
    cp $22                                                            ; 251f: fe 22       ."
    ret                                                               ; 2521: c9          .

; $2522 referenced 3 times by $2668, $2672, $267b
l2522:
    rst $20                                                           ; 2522: e7          .
    cp $28                                                            ; 2523: fe 28       .(
    jr nz,l252d                                                       ; 2525: 20 06        .
    call sexpt2nums                                                   ; 2527: cd 79 1c    .y.
    rst $18                                                           ; 252a: df          .
    cp $29                                                            ; 252b: fe 29       .)
; $252d referenced 1 time by $2525
l252d:
    jp nz,report_c                                                    ; 252d: c2 8a 1c    ...
; $2530 referenced 37 times by $04b9, $0611, $09c6, $0ebc, $0ee4, $17ff, $1950, $195d, $1bb3, $1bee, $1c3a, $1c96, $1cbe, $1ce6, $1cf1, $1df0, $1e27, $1f60, $1fc3, $1fcf, $2057, $2089, $20fa, $21d0, $25c3, $25f8, $2627, $268d, $274d, $27bd, $28e9, $28f0, $2a52, $2aad, $2ad4, $2af4, $2c08
syntax_z:
    bit 7,(iy+flags - err_nr)                                         ; 2530: fd cb 01... ...
    ret                                                               ; 2534: c9          .

; $2535 referenced 1 time by $266b
l2535:
    call l3909                                                        ; 2535: cd 09 39    ..9
l2538:
    jp l3898                                                          ; 2538: c3 98 38    ..8

; $253b referenced 1 time by $38ac
l253b:
    push bc                                                           ; 253b: c5          .
    ld b,$e0                                                          ; 253c: 06 e0       ..
; $253e referenced 2 times by $2570, $257c
l253e:
    push bc                                                           ; 253e: c5          .
    push de                                                           ; 253f: d5          .
    push hl                                                           ; 2540: e5          .
    ld a,(de)                                                         ; 2541: 1a          .
    xor (hl)                                                          ; 2542: ae          .
    jr z,l2549                                                        ; 2543: 28 04       (.
    inc a                                                             ; 2545: 3c          <
    jr nz,l2569                                                       ; 2546: 20 21        !
    dec a                                                             ; 2548: 3d          =
; $2549 referenced 1 time by $2543
l2549:
    ld c,a                                                            ; 2549: 4f          O
    ld b,7                                                            ; 254a: 06 07       ..
; $254c referenced 1 time by $2553
l254c:
    inc d                                                             ; 254c: 14          .
    inc hl                                                            ; 254d: 23          #
    ld a,(de)                                                         ; 254e: 1a          .
    xor (hl)                                                          ; 254f: ae          .
    xor c                                                             ; 2550: a9          .
    jr nz,l2569                                                       ; 2551: 20 16        .
    djnz l254c                                                        ; 2553: 10 f7       ..
    pop bc                                                            ; 2555: c1          .
    pop bc                                                            ; 2556: c1          .
    pop bc                                                            ; 2557: c1          .
    pop hl                                                            ; 2558: e1          .
    ld a,h                                                            ; 2559: 7c          |
    dec h                                                             ; 255a: 25          %
    jr nz,l2562                                                       ; 255b: 20 05        .
    ld a,$a5                                                          ; 255d: 3e a5       >.
    jp l2563                                                          ; 255f: c3 63 25    .c%

; $2562 referenced 1 time by $255b
l2562:
    xor a                                                             ; 2562: af          .
; $2563 referenced 1 time by $255f
l2563:
    sub b                                                             ; 2563: 90          .
    call bc_spaces1                                                   ; 2564: cd 2d 00    .-.
    ld (de),a                                                         ; 2567: 12          .
    ret                                                               ; 2568: c9          .

; $2569 referenced 2 times by $2546, $2551
l2569:
    pop hl                                                            ; 2569: e1          .
    ld de,8                                                           ; 256a: 11 08 00    ...
    add hl,de                                                         ; 256d: 19          .
    pop de                                                            ; 256e: d1          .
    pop bc                                                            ; 256f: c1          .
    djnz l253e                                                        ; 2570: 10 cc       ..
    pop bc                                                            ; 2572: c1          .
    dec b                                                             ; 2573: 05          .
    jr z,l257e                                                        ; 2574: 28 08       (.
    push bc                                                           ; 2576: c5          .
    ld b,$15                                                          ; 2577: 06 15       ..
    ld hl,(udg)                                                       ; 2579: 2a 7b 5c    *{\
    jr l253e                                                          ; 257c: 18 c0       ..

; $257e referenced 1 time by $2574
l257e:
    ld c,b                                                            ; 257e: 48          H
    ret                                                               ; 257f: c9          .

; $2580 referenced 1 time by $2675
l2580:
    call l3909                                                        ; 2580: cd 09 39    ..9
    ld a,c                                                            ; 2583: 79          y
    rrca                                                              ; 2584: 0f          .
    rrca                                                              ; 2585: 0f          .
    rrca                                                              ; 2586: 0f          .
    ld c,a                                                            ; 2587: 4f          O
    and $e0                                                           ; 2588: e6 e0       ..
    xor b                                                             ; 258a: a8          .
    ld l,a                                                            ; 258b: 6f          o
    ld a,c                                                            ; 258c: 79          y
    and 3                                                             ; 258d: e6 03       ..
    xor $58                                                           ; 258f: ee 58       .X
    ld h,a                                                            ; 2591: 67          g
    ld a,(hl)                                                         ; 2592: 7e          ~
    jp stack_a                                                        ; 2593: c3 28 2d    .(-

l2596:
    db $22                                                            ; 2596: 22          "
    db l25b3 - $                                                      ; 2597: 1c          .
    db $28                                                            ; 2598: 28          (
    db l25e8 - $                                                      ; 2599: 4f          O
    db $2e                                                            ; 259a: 2e          .
    db s_decimal - $                                                  ; 259b: f2          .
    db $2b                                                            ; 259c: 2b          +
    db l25af - $                                                      ; 259d: 12          .
    db $a8                                                            ; 259e: a8          .
    db l25f5 - $                                                      ; 259f: 56          V
    db $a5                                                            ; 25a0: a5          .
    db s_rnd - $                                                      ; 25a1: 57          W
    db $a7                                                            ; 25a2: a7          .
    db s_pi - $                                                       ; 25a3: 84          .
    db $a6                                                            ; 25a4: a6          .
    db iminkeys - $                                                   ; 25a5: 8f          .
    db $c4                                                            ; 25a6: c4          .
    db s_decimal - $                                                  ; 25a7: e6          .
    db $aa                                                            ; 25a8: aa          .
    db l2668 - $                                                      ; 25a9: bf          .
    db $ab                                                            ; 25aa: ab          .
    db l2672 - $                                                      ; 25ab: c7          .
    db $a9                                                            ; 25ac: a9          .
    db l267b - $                                                      ; 25ad: ce          .
    db 0                                                              ; 25ae: 00          .

l25af:
    rst $20                                                           ; 25af: e7          .
    jp l24ff                                                          ; 25b0: c3 ff 24    ..$

l25b3:
    rst $18                                                           ; 25b3: df          .
    inc hl                                                            ; 25b4: 23          #
    push hl                                                           ; 25b5: e5          .
    ld bc,0                                                           ; 25b6: 01 00 00    ...
    call l250f                                                        ; 25b9: cd 0f 25    ..%
    jr nz,l25d9                                                       ; 25bc: 20 1b        .
; $25be referenced 1 time by $25c1
l25be:
    call l250f                                                        ; 25be: cd 0f 25    ..%
    jr z,l25be                                                        ; 25c1: 28 fb       (.
    call syntax_z                                                     ; 25c3: cd 30 25    .0%
    jr z,l25d9                                                        ; 25c6: 28 11       (.
    rst $30                                                           ; 25c8: f7          .
    pop hl                                                            ; 25c9: e1          .
    push de                                                           ; 25ca: d5          .
; $25cb referenced 2 times by $25d1, $25d7
l25cb:
    ld a,(hl)                                                         ; 25cb: 7e          ~
    inc hl                                                            ; 25cc: 23          #
    ld (de),a                                                         ; 25cd: 12          .
    inc de                                                            ; 25ce: 13          .
    cp $22                                                            ; 25cf: fe 22       ."
    jr nz,l25cb                                                       ; 25d1: 20 f8        .
    ld a,(hl)                                                         ; 25d3: 7e          ~
    inc hl                                                            ; 25d4: 23          #
    cp $22                                                            ; 25d5: fe 22       ."
    jr z,l25cb                                                        ; 25d7: 28 f2       (.
; $25d9 referenced 2 times by $25bc, $25c6
l25d9:
    dec bc                                                            ; 25d9: 0b          .
    pop de                                                            ; 25da: d1          .
; $25db referenced 1 time by $266f
s_string:
    ld hl,$5c3b                                                       ; 25db: 21 3b 5c    !;\
    res 6,(hl)                                                        ; 25de: cb b6       ..
    bit 7,(hl)                                                        ; 25e0: cb 7e       .~
    call nz,stk_store                                                 ; 25e2: c4 b2 2a    ..*
    jp s_cont_2                                                       ; 25e5: c3 12 27    ..'

l25e8:
    rst $20                                                           ; 25e8: e7          .
    call scanning                                                     ; 25e9: cd fb 24    ..$
    cp $29                                                            ; 25ec: fe 29       .)
    jp nz,report_c                                                    ; 25ee: c2 8a 1c    ...
    rst $20                                                           ; 25f1: e7          .
    jp s_cont_2                                                       ; 25f2: c3 12 27    ..'

l25f5:
    jp l27bd                                                          ; 25f5: c3 bd 27    ..'

s_rnd:
    call syntax_z                                                     ; 25f8: cd 30 25    .0%
    jr z,s_rnd_end                                                    ; 25fb: 28 28       ((
    ld bc,(seed)                                                      ; 25fd: ed 4b 76... .Kv
    call stack_bc1                                                    ; 2601: cd 2f 2d    ./-
    rst $28                                                           ; 2604: ef          .
    db $a1                                                            ; 2605: a1          .  ; stk-one
    db $0f                                                            ; 2606: 0f          .  ; addition
    db $34                                                            ; 2607: 34          4  ; stk-data
    db $37, $16                                                       ; 2608: 37 16       7. ; 75
    db 4                                                              ; 260a: 04          .  ; multiply
    db $34                                                            ; 260b: 34          4  ; stk-data
    db $80, $41, 0, 0, $80                                            ; 260c: 80 41 00... .A. ; 65537
    db $32                                                            ; 2611: 32          2  ; n-mod-m
    db 2                                                              ; 2612: 02          .  ; delete
    db $a1                                                            ; 2613: a1          .  ; stk-one
    db 3                                                              ; 2614: 03          .  ; subtract
    db $31                                                            ; 2615: 31          1  ; duplicate
    db $38                                                            ; 2616: 38          8  ; end-calc

    call fp_to_bc                                                     ; 2617: cd a2 2d    ..-
    ld (seed),bc                                                      ; 261a: ed 43 76... .Cv
    ld a,(hl)                                                         ; 261e: 7e          ~
    and a                                                             ; 261f: a7          .
    jr z,s_rnd_end                                                    ; 2620: 28 03       (.
    sub $10                                                           ; 2622: d6 10       ..
    ld (hl),a                                                         ; 2624: 77          w
; $2625 referenced 2 times by $25fb, $2620
s_rnd_end:
    jr s_pi_end                                                       ; 2625: 18 09       ..

s_pi:
    call syntax_z                                                     ; 2627: cd 30 25    .0%
    jr z,s_pi_end                                                     ; 262a: 28 04       (.
    rst $28                                                           ; 262c: ef          .
    db $a3                                                            ; 262d: a3          .  ; stk-pi/2
    db $38                                                            ; 262e: 38          8  ; end-calc

    inc (hl)                                                          ; 262f: 34          4
; $2630 referenced 2 times by $2625, $262a
s_pi_end:
    rst $20                                                           ; 2630: e7          .
    jp s_numeric                                                      ; 2631: c3 c3 26    ..&

iminkeys:
    ld bc,$105a                                                       ; 2634: 01 5a 10    .Z.
    rst $20                                                           ; 2637: e7          .
    cp $23                                                            ; 2638: fe 23       .#
    jp z,s_push_po                                                    ; 263a: ca 0d 27    ..'
    ld hl,$5c3b                                                       ; 263d: 21 3b 5c    !;\
    res 6,(hl)                                                        ; 2640: cb b6       ..
    bit 7,(hl)                                                        ; 2642: cb 7e       .~
    jr z,l2665                                                        ; 2644: 28 1f       (.
    call keyboard                                                     ; 2646: cd 8e 02    ...
    ld c,0                                                            ; 2649: 0e 00       ..
    jr nz,l2660                                                       ; 264b: 20 13        .
    call l031e                                                        ; 264d: cd 1e 03    ...
    jr nc,l2660                                                       ; 2650: 30 0e       0.
    ld e,a                                                            ; 2652: 5f          _
    dec d                                                             ; 2653: 15          .
    call l0333                                                        ; 2654: cd 33 03    .3.
    ld bc,1                                                           ; 2657: 01 01 00    ...
    push af                                                           ; 265a: f5          .
    rst $30                                                           ; 265b: f7          .
    pop af                                                            ; 265c: f1          .
    ld c,1                                                            ; 265d: 0e 01       ..
    ld (de),a                                                         ; 265f: 12          .
; $2660 referenced 2 times by $264b, $2650
l2660:
    ld b,0                                                            ; 2660: 06 00       ..
    call stk_store                                                    ; 2662: cd b2 2a    ..*
; $2665 referenced 1 time by $2644
l2665:
    jp s_cont_2                                                       ; 2665: c3 12 27    ..'

l2668:
    call l2522                                                        ; 2668: cd 22 25    ."%
    call nz,l2535                                                     ; 266b: c4 35 25    .5%
    rst $20                                                           ; 266e: e7          .
    jp s_string                                                       ; 266f: c3 db 25    ..%

l2672:
    call l2522                                                        ; 2672: cd 22 25    ."%
    call nz,l2580                                                     ; 2675: c4 80 25    ..%
    rst $20                                                           ; 2678: e7          .
    jr s_numeric                                                      ; 2679: 18 48       .H

l267b:
    call l2522                                                        ; 267b: cd 22 25    ."%
    call nz,l22cb                                                     ; 267e: c4 cb 22    .."
    rst $20                                                           ; 2681: e7          .
    jr s_numeric                                                      ; 2682: 18 3f       .?

; $2684 referenced 1 time by $2507
l2684:
    call alphanum                                                     ; 2684: cd 88 2c    ..,
    jr nc,l26df                                                       ; 2687: 30 56       0V
    cp $41                                                            ; 2689: fe 41       .A
    jr nc,s_let_num                                                   ; 268b: 30 3c       0<
s_decimal:
    call syntax_z                                                     ; 268d: cd 30 25    .0%
    jr nz,s_stk_dec                                                   ; 2690: 20 23        #
    call dec_to_fp                                                    ; 2692: cd 9b 2c    ..,
; $2695 referenced 1 time by $0f17
l2695:
    rst $18                                                           ; 2695: df          .
    ld bc,6                                                           ; 2696: 01 06 00    ...
    call make_room                                                    ; 2699: cd 55 16    .U.
    inc hl                                                            ; 269c: 23          #
    ld (hl),$0e                                                       ; 269d: 36 0e       6.
    inc hl                                                            ; 269f: 23          #
    ex de,hl                                                          ; 26a0: eb          .
    ld hl,(stkend)                                                    ; 26a1: 2a 65 5c    *e\
    ld c,5                                                            ; 26a4: 0e 05       ..
    and a                                                             ; 26a6: a7          .
    sbc hl,bc                                                         ; 26a7: ed 42       .B
    ld (stkend),hl                                                    ; 26a9: 22 65 5c    "e\
    ldir                                                              ; 26ac: ed b0       ..
    ex de,hl                                                          ; 26ae: eb          .
    dec hl                                                            ; 26af: 2b          +
    call cursor_so                                                    ; 26b0: cd 77 00    .w.
    jr s_numeric                                                      ; 26b3: 18 0e       ..

; $26b5 referenced 3 times by $0ebf, $0ee7, $2690
s_stk_dec:
    rst $18                                                           ; 26b5: df          .
; $26b6 referenced 1 time by $26ba
l26b6:
    inc hl                                                            ; 26b6: 23          #
    ld a,(hl)                                                         ; 26b7: 7e          ~
    cp $0e                                                            ; 26b8: fe 0e       ..
    jr nz,l26b6                                                       ; 26ba: 20 fa        .
    inc hl                                                            ; 26bc: 23          #
    call l33b8                                                        ; 26bd: cd b8 33    ..3
    ld (ch_add),hl                                                    ; 26c0: 22 5d 5c    "]\
; $26c3 referenced 4 times by $2631, $2679, $2682, $26b3
s_numeric:
    set 6,(iy+flags - err_nr)                                         ; 26c3: fd cb 01... ...
    jr l26dd                                                          ; 26c7: 18 14       ..

; $26c9 referenced 1 time by $268b
s_let_num:
    call look_vars                                                    ; 26c9: cd b2 28    ..(
    jp c,report_2                                                     ; 26cc: da 2e 1c    ...
    call z,stk_var                                                    ; 26cf: cc 96 29    ..)
    ld a,(flags)                                                      ; 26d2: 3a 3b 5c    :;\
    cp $c0                                                            ; 26d5: fe c0       ..
    jr c,l26dd                                                        ; 26d7: 38 04       8.
    inc hl                                                            ; 26d9: 23          #
    call l33b8                                                        ; 26da: cd b8 33    ..3
; $26dd referenced 2 times by $26c7, $26d7
l26dd:
    jr s_cont_2                                                       ; 26dd: 18 33       .3

; $26df referenced 1 time by $2687
l26df:
    ld bc,$09db                                                       ; 26df: 01 db 09    ...
    cp $2d                                                            ; 26e2: fe 2d       .-
    jr z,s_push_po                                                    ; 26e4: 28 27       ('
    ld bc,$1018                                                       ; 26e6: 01 18 10    ...
    cp $ae                                                            ; 26e9: fe ae       ..
    jr z,s_push_po                                                    ; 26eb: 28 20       (
    sub $af                                                           ; 26ed: d6 af       ..
    jp c,report_c                                                     ; 26ef: da 8a 1c    ...
    ld bc,$04f0                                                       ; 26f2: 01 f0 04    ...
    cp $14                                                            ; 26f5: fe 14       ..
    jr z,s_push_po                                                    ; 26f7: 28 14       (.
    jp nc,report_c                                                    ; 26f9: d2 8a 1c    ...
    add a,$dc                                                         ; 26fc: c6 dc       ..
    ld c,a                                                            ; 26fe: 4f          O
    ld b,$10                                                          ; 26ff: 06 10       ..
    cp $df                                                            ; 2701: fe df       ..
    jr nc,s_no_to_s                                                   ; 2703: 30 02       0.
    res 6,c                                                           ; 2705: cb b1       ..
; $2707 referenced 1 time by $2703
s_no_to_s:
    cp $ee                                                            ; 2707: fe ee       ..
    jr c,s_push_po                                                    ; 2709: 38 02       8.
    res 7,c                                                           ; 270b: cb b9       ..
; $270d referenced 6 times by $0eb8, $263a, $26e4, $26eb, $26f7, $2709
s_push_po:
    push bc                                                           ; 270d: c5          .
    rst $20                                                           ; 270e: e7          .
    jp l24ff                                                          ; 270f: c3 ff 24    ..$

; $2712 referenced 6 times by $25e5, $25f2, $2665, $26dd, $27f4, $28a8
s_cont_2:
    rst $18                                                           ; 2712: df          .
; $2713 referenced 1 time by $2721
s_cont_3:
    cp $28                                                            ; 2713: fe 28       .(
    jr nz,s_opertr                                                    ; 2715: 20 0c        .
    bit 6,(iy+flags - err_nr)                                         ; 2717: fd cb 01... ...
    jr nz,s_loop                                                      ; 271b: 20 17        .
    call slicing                                                      ; 271d: cd 52 2a    .R*
    rst $20                                                           ; 2720: e7          .
    jr s_cont_3                                                       ; 2721: 18 f0       ..

; $2723 referenced 1 time by $2715
s_opertr:
    ld hl,$2795                                                       ; 2723: 21 95 27    !.'
    ld b,0                                                            ; 2726: 06 00       ..
    ld c,a                                                            ; 2728: 4f          O
    call l16dc                                                        ; 2729: cd dc 16    ...
    jr nc,s_loop                                                      ; 272c: 30 06       0.
    ld c,(hl)                                                         ; 272e: 4e          N
    ld hl,$26ed                                                       ; 272f: 21 ed 26    !.&
    add hl,bc                                                         ; 2732: 09          .
    ld b,(hl)                                                         ; 2733: 46          F
; $2734 referenced 3 times by $271b, $272c, $2771
s_loop:
    pop de                                                            ; 2734: d1          .
    ld a,d                                                            ; 2735: 7a          z
    cp b                                                              ; 2736: b8          .
    jr c,s_tighter                                                    ; 2737: 38 3a       8:
    and a                                                             ; 2739: a7          .
    jp z,_get_ch                                                      ; 273a: ca 18 00    ...
    push bc                                                           ; 273d: c5          .
    ld hl,$5c3b                                                       ; 273e: 21 3b 5c    !;\
    ld a,e                                                            ; 2741: 7b          {
    cp $ed                                                            ; 2742: fe ed       ..
    jr nz,l274c                                                       ; 2744: 20 06        .
    bit 6,(hl)                                                        ; 2746: cb 76       .v
    jr nz,l274c                                                       ; 2748: 20 02        .
    ld e,$99                                                          ; 274a: 1e 99       ..
; $274c referenced 2 times by $2744, $2748
l274c:
    push de                                                           ; 274c: d5          .
    call syntax_z                                                     ; 274d: cd 30 25    .0%
    jr z,s_syntest                                                    ; 2750: 28 09       (.
    ld a,e                                                            ; 2752: 7b          {
    and $3f                                                           ; 2753: e6 3f       .?
    ld b,a                                                            ; 2755: 47          G
    rst $28                                                           ; 2756: ef          .
    db $3b                                                            ; 2757: 3b          ;  ; fp-calc-2
    db $38                                                            ; 2758: 38          8  ; end-calc

    jr s_runtest                                                      ; 2759: 18 09       ..

; $275b referenced 1 time by $2750
s_syntest:
    ld a,e                                                            ; 275b: 7b          {
    xor (iy+flags - err_nr)                                           ; 275c: fd ae 01    ...
    and $40                                                           ; 275f: e6 40       .@
; $2761 referenced 1 time by $2788
s_rprt_c2:
    jp nz,report_c                                                    ; 2761: c2 8a 1c    ...
; $2764 referenced 1 time by $2759
s_runtest:
    pop de                                                            ; 2764: d1          .
    ld hl,$5c3b                                                       ; 2765: 21 3b 5c    !;\
    set 6,(hl)                                                        ; 2768: cb f6       ..
    bit 7,e                                                           ; 276a: cb 7b       .{
    jr nz,s_endloop                                                   ; 276c: 20 02        .
    res 6,(hl)                                                        ; 276e: cb b6       ..
; $2770 referenced 1 time by $276c
s_endloop:
    pop bc                                                            ; 2770: c1          .
    jr s_loop                                                         ; 2771: 18 c1       ..

; $2773 referenced 1 time by $2737
s_tighter:
    push de                                                           ; 2773: d5          .
    ld a,c                                                            ; 2774: 79          y
    bit 6,(iy+flags - err_nr)                                         ; 2775: fd cb 01... ...
    jr nz,s_next                                                      ; 2779: 20 15        .
    and $3f                                                           ; 277b: e6 3f       .?
    add a,8                                                           ; 277d: c6 08       ..
    ld c,a                                                            ; 277f: 4f          O
    cp $10                                                            ; 2780: fe 10       ..
    jr nz,s_not_and                                                   ; 2782: 20 04        .
    set 6,c                                                           ; 2784: cb f1       ..
    jr s_next                                                         ; 2786: 18 08       ..

; $2788 referenced 1 time by $2782
s_not_and:
    jr c,s_rprt_c2                                                    ; 2788: 38 d7       8.
    cp $17                                                            ; 278a: fe 17       ..
    jr z,s_next                                                       ; 278c: 28 02       (.
    set 7,c                                                           ; 278e: cb f9       ..
; $2790 referenced 3 times by $2779, $2786, $278c
s_next:
    push bc                                                           ; 2790: c5          .
    rst $20                                                           ; 2791: e7          .
    jp l24ff                                                          ; 2792: c3 ff 24    ..$

l2795:
    db $2b, $cf, $2d, $c3, $2a, $c4, $2f, $c5, $5e, $c6, $3d, $ce     ; 2795: 2b cf 2d... +.-
    db $3e, $cc, $3c, $cd, $c7, $c9, $c8, $ca, $c9, $cb, $c5, $c7     ; 27a1: 3e cc 3c... >.<
    db $c6, $c8,   0                                                  ; 27ad: c6 c8 00    ...
priority:
    db 6, 8, 8, $0a, 2, 3, 5, 5, 5, 5, 5, 5, 6                        ; 27b0: 06 08 08... ...

; $27bd referenced 1 time by $25f5
l27bd:
    call syntax_z                                                     ; 27bd: cd 30 25    .0%
    jr nz,l27f7                                                       ; 27c0: 20 35        5
    rst $20                                                           ; 27c2: e7          .
    call alpha                                                        ; 27c3: cd 8d 2c    ..,
    jp nc,report_c                                                    ; 27c6: d2 8a 1c    ...
    rst $20                                                           ; 27c9: e7          .
    cp $24                                                            ; 27ca: fe 24       .$
    push af                                                           ; 27cc: f5          .
    jr nz,fnsyn                                                       ; 27cd: 20 01        .
    rst $20                                                           ; 27cf: e7          .
; $27d0 referenced 1 time by $27cd
fnsyn:
    cp $28                                                            ; 27d0: fe 28       .(
    jr nz,fnsy5                                                       ; 27d2: 20 12        .
    rst $20                                                           ; 27d4: e7          .
    cp $29                                                            ; 27d5: fe 29       .)
    jr z,fnsy4                                                        ; 27d7: 28 10       (.
; $27d9 referenced 1 time by $27e2
l27d9:
    call scanning                                                     ; 27d9: cd fb 24    ..$
    rst $18                                                           ; 27dc: df          .
    cp $2c                                                            ; 27dd: fe 2c       .,
    jr nz,l27e4                                                       ; 27df: 20 03        .
    rst $20                                                           ; 27e1: e7          .
    jr l27d9                                                          ; 27e2: 18 f5       ..

; $27e4 referenced 1 time by $27df
l27e4:
    cp $29                                                            ; 27e4: fe 29       .)
; $27e6 referenced 1 time by $27d2
fnsy5:
    jp nz,report_c                                                    ; 27e6: c2 8a 1c    ...
; $27e9 referenced 1 time by $27d7
fnsy4:
    rst $20                                                           ; 27e9: e7          .
    ld hl,$5c3b                                                       ; 27ea: 21 3b 5c    !;\
    res 6,(hl)                                                        ; 27ed: cb b6       ..
    pop af                                                            ; 27ef: f1          .
    jr z,l27f4                                                        ; 27f0: 28 02       (.
    set 6,(hl)                                                        ; 27f2: cb f6       ..
; $27f4 referenced 1 time by $27f0
l27f4:
    jp s_cont_2                                                       ; 27f4: c3 12 27    ..'

; $27f7 referenced 1 time by $27c0
l27f7:
    rst $20                                                           ; 27f7: e7          .
    and $df                                                           ; 27f8: e6 df       ..
    ld b,a                                                            ; 27fa: 47          G
    rst $20                                                           ; 27fb: e7          .
    sub $24                                                           ; 27fc: d6 24       .$
    ld c,a                                                            ; 27fe: 4f          O
    jr nz,l2802                                                       ; 27ff: 20 01        .
    rst $20                                                           ; 2801: e7          .
; $2802 referenced 1 time by $27ff
l2802:
    rst $20                                                           ; 2802: e7          .
    push hl                                                           ; 2803: e5          .
    ld hl,(prog)                                                      ; 2804: 2a 53 5c    *S\
    dec hl                                                            ; 2807: 2b          +
; $2808 referenced 1 time by $282f
l2808:
    ld de,$ce                                                         ; 2808: 11 ce 00    ...
    push bc                                                           ; 280b: c5          .
    call l1d86                                                        ; 280c: cd 86 1d    ...
    pop bc                                                            ; 280f: c1          .
    jr nc,l2814                                                       ; 2810: 30 02       0.
    rst $08                                                           ; 2812: cf          .
    db $18                                                            ; 2813: 18          .  ; Report P FN without DEF

; $2814 referenced 1 time by $2810
l2814:
    push hl                                                           ; 2814: e5          .
    call l28ab                                                        ; 2815: cd ab 28    ..(
    and $df                                                           ; 2818: e6 df       ..
    cp b                                                              ; 281a: b8          .
    jr nz,l2825                                                       ; 281b: 20 08        .
    call l28ab                                                        ; 281d: cd ab 28    ..(
    sub $24                                                           ; 2820: d6 24       .$
    cp c                                                              ; 2822: b9          .
    jr z,l2831                                                        ; 2823: 28 0c       (.
; $2825 referenced 1 time by $281b
l2825:
    pop hl                                                            ; 2825: e1          .
    dec hl                                                            ; 2826: 2b          +
    ld de,$0200                                                       ; 2827: 11 00 02    ...
    push bc                                                           ; 282a: c5          .
    call skipstats                                                    ; 282b: cd 8b 19    ...
    pop bc                                                            ; 282e: c1          .
    jr l2808                                                          ; 282f: 18 d7       ..

; $2831 referenced 1 time by $2823
l2831:
    and a                                                             ; 2831: a7          .
    call z,l28ab                                                      ; 2832: cc ab 28    ..(
    pop de                                                            ; 2835: d1          .
    pop de                                                            ; 2836: d1          .
    ld (ch_add),de                                                    ; 2837: ed 53 5d... .S]
    call l28ab                                                        ; 283b: cd ab 28    ..(
    push hl                                                           ; 283e: e5          .
    cp $29                                                            ; 283f: fe 29       .)
    jr z,l2885                                                        ; 2841: 28 42       (B
; $2843 referenced 1 time by $2883
l2843:
    inc hl                                                            ; 2843: 23          #
    ld a,(hl)                                                         ; 2844: 7e          ~
    cp $0e                                                            ; 2845: fe 0e       ..
    ld d,$40                                                          ; 2847: 16 40       .@
    jr z,l2852                                                        ; 2849: 28 07       (.
    dec hl                                                            ; 284b: 2b          +
    call l28ab                                                        ; 284c: cd ab 28    ..(
    ld d,0                                                            ; 284f: 16 00       ..
    inc hl                                                            ; 2851: 23          #
; $2852 referenced 1 time by $2849
l2852:
    inc hl                                                            ; 2852: 23          #
    push hl                                                           ; 2853: e5          .
    push de                                                           ; 2854: d5          .
    call scanfix                                                      ; 2855: cd a8 3c    ..<
    pop af                                                            ; 2858: f1          .
    xor (iy+flags - err_nr)                                           ; 2859: fd ae 01    ...
    and $40                                                           ; 285c: e6 40       .@
    jr nz,parerr                                                      ; 285e: 20 2b        +
    pop hl                                                            ; 2860: e1          .
    ex de,hl                                                          ; 2861: eb          .
    ld hl,(stkend)                                                    ; 2862: 2a 65 5c    *e\
    ld bc,5                                                           ; 2865: 01 05 00    ...
    sbc hl,bc                                                         ; 2868: ed 42       .B
    ld (stkend),hl                                                    ; 286a: 22 65 5c    "e\
    ldir                                                              ; 286d: ed b0       ..
    ex de,hl                                                          ; 286f: eb          .
    dec hl                                                            ; 2870: 2b          +
    call l28ab                                                        ; 2871: cd ab 28    ..(
    cp $29                                                            ; 2874: fe 29       .)
    jr z,l2885                                                        ; 2876: 28 0d       (.
    push hl                                                           ; 2878: e5          .
    rst $18                                                           ; 2879: df          .
    cp $2c                                                            ; 287a: fe 2c       .,
    jr nz,parerr                                                      ; 287c: 20 0d        .
    rst $20                                                           ; 287e: e7          .
    pop hl                                                            ; 287f: e1          .
    call l28ab                                                        ; 2880: cd ab 28    ..(
    jr l2843                                                          ; 2883: 18 be       ..

; $2885 referenced 2 times by $2841, $2876
l2885:
    push hl                                                           ; 2885: e5          .
    rst $18                                                           ; 2886: df          .
    cp $29                                                            ; 2887: fe 29       .)
    jr z,l288d                                                        ; 2889: 28 02       (.
; $288b referenced 4 times by $285e, $287c, $3af6, $3b08
parerr:
    rst $08                                                           ; 288b: cf          .
    db $19                                                            ; 288c: 19          .  ; Report Q Parameter error

; $288d referenced 1 time by $2889
l288d:
    pop de                                                            ; 288d: d1          .
    ex de,hl                                                          ; 288e: eb          .
    ld (ch_add),hl                                                    ; 288f: 22 5d 5c    "]\
    ld hl,(defadd)                                                    ; 2892: 2a 0b 5c    *.\
    ex (sp),hl                                                        ; 2895: e3          .
    ld (defadd),hl                                                    ; 2896: 22 0b 5c    ".\
    push de                                                           ; 2899: d5          .
    rst $20                                                           ; 289a: e7          .
    rst $20                                                           ; 289b: e7          .
    call scanning                                                     ; 289c: cd fb 24    ..$
    pop hl                                                            ; 289f: e1          .
    ld (ch_add),hl                                                    ; 28a0: 22 5d 5c    "]\
    pop hl                                                            ; 28a3: e1          .
    ld (defadd),hl                                                    ; 28a4: 22 0b 5c    ".\
    rst $20                                                           ; 28a7: e7          .
    jp s_cont_2                                                       ; 28a8: c3 12 27    ..'

; $28ab referenced 11 times by $2815, $281d, $2832, $283b, $284c, $2871, $2880, $28af, $2965, $2974, $297c
l28ab:
    inc hl                                                            ; 28ab: 23          #
    ld a,(hl)                                                         ; 28ac: 7e          ~
    cp $21                                                            ; 28ad: fe 21       .!
    jr c,l28ab                                                        ; 28af: 38 fa       8.
    ret                                                               ; 28b1: c9          .

; $28b2 referenced 5 times by $0660, $1c1f, $1c6c, $26c9, $2c02
look_vars:
    set 6,(iy+flags - err_nr)                                         ; 28b2: fd cb 01... ...
    rst $18                                                           ; 28b6: df          .
    call alpha                                                        ; 28b7: cd 8d 2c    ..,
    jp nc,report_c                                                    ; 28ba: d2 8a 1c    ...
    push hl                                                           ; 28bd: e5          .
    and $1f                                                           ; 28be: e6 1f       ..
    ld c,a                                                            ; 28c0: 4f          O
    rst $20                                                           ; 28c1: e7          .
    push hl                                                           ; 28c2: e5          .
    cp $28                                                            ; 28c3: fe 28       .(
    jr z,v_run_syn                                                    ; 28c5: 28 28       ((
    set 6,c                                                           ; 28c7: cb f1       ..
    cp $24                                                            ; 28c9: fe 24       .$
    jr z,v_str_var                                                    ; 28cb: 28 11       (.
    set 5,c                                                           ; 28cd: cb e9       ..
    call alphanum                                                     ; 28cf: cd 88 2c    ..,
    jr nc,l28e3                                                       ; 28d2: 30 0f       0.
; $28d4 referenced 1 time by $28dc
v_char:
    call alphanum                                                     ; 28d4: cd 88 2c    ..,
    jr nc,v_run_syn                                                   ; 28d7: 30 16       0.
    res 6,c                                                           ; 28d9: cb b1       ..
    rst $20                                                           ; 28db: e7          .
    jr v_char                                                         ; 28dc: 18 f6       ..

; $28de referenced 1 time by $28cb
v_str_var:
    rst $20                                                           ; 28de: e7          .
    res 6,(iy+flags - err_nr)                                         ; 28df: fd cb 01... ...
; $28e3 referenced 1 time by $28d2
l28e3:
    ld a,(defadd+1)                                                   ; 28e3: 3a 0c 5c    :.\
    and a                                                             ; 28e6: a7          .
    jr z,v_run_syn                                                    ; 28e7: 28 06       (.
    call syntax_z                                                     ; 28e9: cd 30 25    .0%
    jp nz,l2951                                                       ; 28ec: c2 51 29    .Q)
; $28ef referenced 5 times by $28c5, $28d7, $28e7, $2957, $2979
v_run_syn:
    ld b,c                                                            ; 28ef: 41          A
    call syntax_z                                                     ; 28f0: cd 30 25    .0%
    jr nz,v_run                                                       ; 28f3: 20 08        .
    ld a,c                                                            ; 28f5: 79          y
    and $e0                                                           ; 28f6: e6 e0       ..
    or $80                                                            ; 28f8: f6 80       ..
    ld c,a                                                            ; 28fa: 4f          O
    jr v_syntax                                                       ; 28fb: 18 37       .7

; $28fd referenced 1 time by $28f3
v_run:
    ld hl,(vars)                                                      ; 28fd: 2a 4b 5c    *K\
; $2900 referenced 1 time by $2930
v_each:
    ld a,(hl)                                                         ; 2900: 7e          ~
    and $7f                                                           ; 2901: e6 7f       ..
    jr z,v_80_byte                                                    ; 2903: 28 2d       (-
    cp c                                                              ; 2905: b9          .
    jr nz,v_next                                                      ; 2906: 20 22        "
    rla                                                               ; 2908: 17          .
    add a,a                                                           ; 2909: 87          .
    jp p,v_found_2                                                    ; 290a: f2 3f 29    .?)
    jr c,v_found_2                                                    ; 290d: 38 30       80
    pop de                                                            ; 290f: d1          .
    push de                                                           ; 2910: d5          .
    push hl                                                           ; 2911: e5          .
; $2912 referenced 1 time by $291c
v_matches:
    inc hl                                                            ; 2912: 23          #
; $2913 referenced 1 time by $2917
v_spaces:
    ld a,(de)                                                         ; 2913: 1a          .
    inc de                                                            ; 2914: 13          .
    cp $20                                                            ; 2915: fe 20       .
    jr z,v_spaces                                                     ; 2917: 28 fa       (.
    or $20                                                            ; 2919: f6 20       .
    cp (hl)                                                           ; 291b: be          .
    jr z,v_matches                                                    ; 291c: 28 f4       (.
    or $80                                                            ; 291e: f6 80       ..
    cp (hl)                                                           ; 2920: be          .
    jr nz,v_get_ptr                                                   ; 2921: 20 06        .
    ld a,(de)                                                         ; 2923: 1a          .
    call alphanum                                                     ; 2924: cd 88 2c    ..,
    jr nc,v_found_1                                                   ; 2927: 30 15       0.
; $2929 referenced 1 time by $2921
v_get_ptr:
    pop hl                                                            ; 2929: e1          .
; $292a referenced 1 time by $2906
v_next:
    push bc                                                           ; 292a: c5          .
    call next_one                                                     ; 292b: cd b8 19    ...
    ex de,hl                                                          ; 292e: eb          .
    pop bc                                                            ; 292f: c1          .
    jr v_each                                                         ; 2930: 18 ce       ..

; $2932 referenced 1 time by $2903
v_80_byte:
    set 7,b                                                           ; 2932: cb f8       ..
; $2934 referenced 1 time by $28fb
v_syntax:
    pop de                                                            ; 2934: d1          .
    rst $18                                                           ; 2935: df          .
    cp $28                                                            ; 2936: fe 28       .(
    jr z,v_pass                                                       ; 2938: 28 09       (.
    set 5,b                                                           ; 293a: cb e8       ..
    jr v_end                                                          ; 293c: 18 0d       ..

; $293e referenced 1 time by $2927
v_found_1:
    pop de                                                            ; 293e: d1          .
; $293f referenced 2 times by $290a, $290d
v_found_2:
    pop de                                                            ; 293f: d1          .
    pop de                                                            ; 2940: d1          .
    push hl                                                           ; 2941: e5          .
    rst $18                                                           ; 2942: df          .
; $2943 referenced 2 times by $2938, $2949
v_pass:
    call alphanum                                                     ; 2943: cd 88 2c    ..,
    jr nc,v_end                                                       ; 2946: 30 03       0.
    rst $20                                                           ; 2948: e7          .
    jr v_pass                                                         ; 2949: 18 f8       ..

; $294b referenced 2 times by $293c, $2946
v_end:
    pop hl                                                            ; 294b: e1          .
    rl b                                                              ; 294c: cb 10       ..
    bit 6,b                                                           ; 294e: cb 70       .p
    ret                                                               ; 2950: c9          .

; $2951 referenced 1 time by $28ec
l2951:
    ld hl,(defadd)                                                    ; 2951: 2a 0b 5c    *.\
    ld a,(hl)                                                         ; 2954: 7e          ~
    cp $29                                                            ; 2955: fe 29       .)
    jp z,v_run_syn                                                    ; 2957: ca ef 28    ..(
; $295a referenced 1 time by $297f
l295a:
    ld a,(hl)                                                         ; 295a: 7e          ~
    or $60                                                            ; 295b: f6 60       .`
    inc hl                                                            ; 295d: 23          #
    ld b,a                                                            ; 295e: 47          G
    ld a,(hl)                                                         ; 295f: 7e          ~
    cp $0e                                                            ; 2960: fe 0e       ..
    jr z,l296b                                                        ; 2962: 28 07       (.
    dec hl                                                            ; 2964: 2b          +
    call l28ab                                                        ; 2965: cd ab 28    ..(
    res 5,b                                                           ; 2968: cb a8       ..
    inc hl                                                            ; 296a: 23          #
; $296b referenced 1 time by $2962
l296b:
    ld a,b                                                            ; 296b: 78          x
    cp c                                                              ; 296c: b9          .
    jr z,l2981                                                        ; 296d: 28 12       (.
    inc hl                                                            ; 296f: 23          #
    inc hl                                                            ; 2970: 23          #
    inc hl                                                            ; 2971: 23          #
    inc hl                                                            ; 2972: 23          #
    inc hl                                                            ; 2973: 23          #
    call l28ab                                                        ; 2974: cd ab 28    ..(
    cp $29                                                            ; 2977: fe 29       .)
    jp z,v_run_syn                                                    ; 2979: ca ef 28    ..(
    call l28ab                                                        ; 297c: cd ab 28    ..(
    jr l295a                                                          ; 297f: 18 d9       ..

; $2981 referenced 1 time by $296d
l2981:
    bit 5,c                                                           ; 2981: cb 69       .i
    jr nz,l2991                                                       ; 2983: 20 0c        .
    inc hl                                                            ; 2985: 23          #
    ld de,(stkend)                                                    ; 2986: ed 5b 65... .[e
    call x80_fmove                                                    ; 298a: cd c4 33    ..3
    ex de,hl                                                          ; 298d: eb          .
    ld (stkend),hl                                                    ; 298e: 22 65 5c    "e\
; $2991 referenced 1 time by $2983
l2991:
    pop de                                                            ; 2991: d1          .
    pop de                                                            ; 2992: d1          .
    xor a                                                             ; 2993: af          .
    inc a                                                             ; 2994: 3c          <
    ret                                                               ; 2995: c9          .

; $2996 referenced 3 times by $1c30, $26cf, $2c0f
stk_var:
    xor a                                                             ; 2996: af          .
    ld b,a                                                            ; 2997: 47          G
    bit 7,c                                                           ; 2998: cb 79       .y
    jr nz,sv_count                                                    ; 299a: 20 4b        K
    bit 7,(hl)                                                        ; 299c: cb 7e       .~
    jr nz,sv_arrays                                                   ; 299e: 20 0e        .
    inc a                                                             ; 29a0: 3c          <
; $29a1 referenced 1 time by $29b7
sv_smples:
    inc hl                                                            ; 29a1: 23          #
    ld c,(hl)                                                         ; 29a2: 4e          N
    inc hl                                                            ; 29a3: 23          #
    ld b,(hl)                                                         ; 29a4: 46          F
    inc hl                                                            ; 29a5: 23          #
    ex de,hl                                                          ; 29a6: eb          .
    call stk_store                                                    ; 29a7: cd b2 2a    ..*
    rst $18                                                           ; 29aa: df          .
    jp sv_sliceq                                                      ; 29ab: c3 49 2a    .I*

; $29ae referenced 1 time by $299e
sv_arrays:
    inc hl                                                            ; 29ae: 23          #
    inc hl                                                            ; 29af: 23          #
    inc hl                                                            ; 29b0: 23          #
    ld b,(hl)                                                         ; 29b1: 46          F
    bit 6,c                                                           ; 29b2: cb 71       .q
    jr z,sv_ptr                                                       ; 29b4: 28 0a       (.
    dec b                                                             ; 29b6: 05          .
    jr z,sv_smples                                                    ; 29b7: 28 e8       (.
    ex de,hl                                                          ; 29b9: eb          .
    rst $18                                                           ; 29ba: df          .
    cp $28                                                            ; 29bb: fe 28       .(
    jr nz,report_3                                                    ; 29bd: 20 61        a
    ex de,hl                                                          ; 29bf: eb          .
; $29c0 referenced 1 time by $29b4
sv_ptr:
    ex de,hl                                                          ; 29c0: eb          .
    jr sv_count                                                       ; 29c1: 18 24       .$

; $29c3 referenced 1 time by $2a0e
sv_comma:
    push hl                                                           ; 29c3: e5          .
    rst $18                                                           ; 29c4: df          .
    pop hl                                                            ; 29c5: e1          .
    cp $2c                                                            ; 29c6: fe 2c       .,
    jr z,sv_loop                                                      ; 29c8: 28 20       (
    bit 7,c                                                           ; 29ca: cb 79       .y
    jr z,report_3                                                     ; 29cc: 28 52       (R
    bit 6,c                                                           ; 29ce: cb 71       .q
    jr nz,sv_close                                                    ; 29d0: 20 06        .
    cp $29                                                            ; 29d2: fe 29       .)
    jr nz,sv_rpt_c                                                    ; 29d4: 20 3c        <
    rst $20                                                           ; 29d6: e7          .
    ret                                                               ; 29d7: c9          .

; $29d8 referenced 1 time by $29d0
sv_close:
    cp $29                                                            ; 29d8: fe 29       .)
    jr z,sv_dim                                                       ; 29da: 28 6c       (l
    cp $cc                                                            ; 29dc: fe cc       ..
    jr nz,sv_rpt_c                                                    ; 29de: 20 32        2
; $29e0 referenced 1 time by $29f9
sv_chadd:
    rst $18                                                           ; 29e0: df          .
    dec hl                                                            ; 29e1: 2b          +
    ld (ch_add),hl                                                    ; 29e2: 22 5d 5c    "]\
    jr sv_slice                                                       ; 29e5: 18 5e       .^

; $29e7 referenced 2 times by $299a, $29c1
sv_count:
    ld hl,0                                                           ; 29e7: 21 00 00    !..
; $29ea referenced 1 time by $29c8
sv_loop:
    push hl                                                           ; 29ea: e5          .
    rst $20                                                           ; 29eb: e7          .
    pop hl                                                            ; 29ec: e1          .
    ld a,c                                                            ; 29ed: 79          y
    cp $c0                                                            ; 29ee: fe c0       ..
    jr nz,sv_mult                                                     ; 29f0: 20 09        .
    rst $18                                                           ; 29f2: df          .
    cp $29                                                            ; 29f3: fe 29       .)
    jr z,sv_dim                                                       ; 29f5: 28 51       (Q
    cp $cc                                                            ; 29f7: fe cc       ..
    jr z,sv_chadd                                                     ; 29f9: 28 e5       (.
; $29fb referenced 1 time by $29f0
sv_mult:
    push bc                                                           ; 29fb: c5          .
    push hl                                                           ; 29fc: e5          .
    call de_de_1                                                      ; 29fd: cd ee 2a    ..*
    ex (sp),hl                                                        ; 2a00: e3          .
    ex de,hl                                                          ; 2a01: eb          .
    call int_exp1                                                     ; 2a02: cd cc 2a    ..*
    jr c,report_3                                                     ; 2a05: 38 19       8.
    dec bc                                                            ; 2a07: 0b          .
    call hl_hl_de                                                     ; 2a08: cd f4 2a    ..*
    add hl,bc                                                         ; 2a0b: 09          .
    pop de                                                            ; 2a0c: d1          .
    pop bc                                                            ; 2a0d: c1          .
    djnz sv_comma                                                     ; 2a0e: 10 b3       ..
    bit 7,c                                                           ; 2a10: cb 79       .y
; $2a12 referenced 2 times by $29d4, $29de
sv_rpt_c:
    jr nz,sl_rpt_c                                                    ; 2a12: 20 66        f
    push hl                                                           ; 2a14: e5          .
    bit 6,c                                                           ; 2a15: cb 71       .q
    jr nz,sv_elems                                                    ; 2a17: 20 13        .
    ld b,d                                                            ; 2a19: 42          B
    ld c,e                                                            ; 2a1a: 4b          K
    rst $18                                                           ; 2a1b: df          .
    cp $29                                                            ; 2a1c: fe 29       .)
    jr z,sv_number                                                    ; 2a1e: 28 02       (.
; $2a20 referenced 6 times by $29bd, $29cc, $2a05, $2a43, $2aa3, $2c34
report_3:
    rst $08                                                           ; 2a20: cf          .
    db 2                                                              ; 2a21: 02          .  ; Report 3 Subscript wrong

; $2a22 referenced 1 time by $2a1e
sv_number:
    rst $20                                                           ; 2a22: e7          .
    pop hl                                                            ; 2a23: e1          .
    ld de,5                                                           ; 2a24: 11 05 00    ...
    call hl_hl_de                                                     ; 2a27: cd f4 2a    ..*
    add hl,bc                                                         ; 2a2a: 09          .
    ret                                                               ; 2a2b: c9          .

; $2a2c referenced 1 time by $2a17
sv_elems:
    call de_de_1                                                      ; 2a2c: cd ee 2a    ..*
    ex (sp),hl                                                        ; 2a2f: e3          .
    call hl_hl_de                                                     ; 2a30: cd f4 2a    ..*
    pop bc                                                            ; 2a33: c1          .
    add hl,bc                                                         ; 2a34: 09          .
    inc hl                                                            ; 2a35: 23          #
    ld b,d                                                            ; 2a36: 42          B
    ld c,e                                                            ; 2a37: 4b          K
    ex de,hl                                                          ; 2a38: eb          .
    call stk_st_0                                                     ; 2a39: cd b1 2a    ..*
    rst $18                                                           ; 2a3c: df          .
    cp $29                                                            ; 2a3d: fe 29       .)
    jr z,sv_dim                                                       ; 2a3f: 28 07       (.
    cp $2c                                                            ; 2a41: fe 2c       .,
    jr nz,report_3                                                    ; 2a43: 20 db        .
; $2a45 referenced 2 times by $29e5, $2a4b
sv_slice:
    call slicing                                                      ; 2a45: cd 52 2a    .R*
; $2a48 referenced 3 times by $29da, $29f5, $2a3f
sv_dim:
    rst $20                                                           ; 2a48: e7          .
; $2a49 referenced 1 time by $29ab
sv_sliceq:
    cp $28                                                            ; 2a49: fe 28       .(
    jr z,sv_slice                                                     ; 2a4b: 28 f8       (.
    res 6,(iy+flags - err_nr)                                         ; 2a4d: fd cb 01... ...
    ret                                                               ; 2a51: c9          .

; $2a52 referenced 2 times by $271d, $2a45
slicing:
    call syntax_z                                                     ; 2a52: cd 30 25    .0%
    call nz,stk_fetch                                                 ; 2a55: c4 f1 2b    ..+
    rst $20                                                           ; 2a58: e7          .
    cp $29                                                            ; 2a59: fe 29       .)
    jr z,sl_store                                                     ; 2a5b: 28 50       (P
    push de                                                           ; 2a5d: d5          .
    xor a                                                             ; 2a5e: af          .
    push af                                                           ; 2a5f: f5          .
    push bc                                                           ; 2a60: c5          .
    ld de,1                                                           ; 2a61: 11 01 00    ...
    rst $18                                                           ; 2a64: df          .
    pop hl                                                            ; 2a65: e1          .
    cp $cc                                                            ; 2a66: fe cc       ..
    jr z,sl_second                                                    ; 2a68: 28 17       (.
    pop af                                                            ; 2a6a: f1          .
    call int_exp2                                                     ; 2a6b: cd cd 2a    ..*
    push af                                                           ; 2a6e: f5          .
    ld d,b                                                            ; 2a6f: 50          P
    ld e,c                                                            ; 2a70: 59          Y
    push hl                                                           ; 2a71: e5          .
    rst $18                                                           ; 2a72: df          .
    pop hl                                                            ; 2a73: e1          .
    cp $cc                                                            ; 2a74: fe cc       ..
    jr z,sl_second                                                    ; 2a76: 28 09       (.
    cp $29                                                            ; 2a78: fe 29       .)
; $2a7a referenced 2 times by $2a12, $2a92
sl_rpt_c:
    jp nz,report_c                                                    ; 2a7a: c2 8a 1c    ...
    ld h,d                                                            ; 2a7d: 62          b
    ld l,e                                                            ; 2a7e: 6b          k
    jr sl_define                                                      ; 2a7f: 18 13       ..

; $2a81 referenced 2 times by $2a68, $2a76
sl_second:
    push hl                                                           ; 2a81: e5          .
    rst $20                                                           ; 2a82: e7          .
    pop hl                                                            ; 2a83: e1          .
    cp $29                                                            ; 2a84: fe 29       .)
    jr z,sl_define                                                    ; 2a86: 28 0c       (.
    pop af                                                            ; 2a88: f1          .
    call int_exp2                                                     ; 2a89: cd cd 2a    ..*
    push af                                                           ; 2a8c: f5          .
    rst $18                                                           ; 2a8d: df          .
    ld h,b                                                            ; 2a8e: 60          `
    ld l,c                                                            ; 2a8f: 69          i
    cp $29                                                            ; 2a90: fe 29       .)
    jr nz,sl_rpt_c                                                    ; 2a92: 20 e6        .
; $2a94 referenced 2 times by $2a7f, $2a86
sl_define:
    pop af                                                            ; 2a94: f1          .
    ex (sp),hl                                                        ; 2a95: e3          .
    add hl,de                                                         ; 2a96: 19          .
    dec hl                                                            ; 2a97: 2b          +
    ex (sp),hl                                                        ; 2a98: e3          .
    and a                                                             ; 2a99: a7          .
    sbc hl,de                                                         ; 2a9a: ed 52       .R
    ld bc,0                                                           ; 2a9c: 01 00 00    ...
    jr c,sl_over                                                      ; 2a9f: 38 07       8.
    inc hl                                                            ; 2aa1: 23          #
    and a                                                             ; 2aa2: a7          .
    jp m,report_3                                                     ; 2aa3: fa 20 2a    . *
    ld b,h                                                            ; 2aa6: 44          D
    ld c,l                                                            ; 2aa7: 4d          M
; $2aa8 referenced 1 time by $2a9f
sl_over:
    pop de                                                            ; 2aa8: d1          .
    res 6,(iy+flags - err_nr)                                         ; 2aa9: fd cb 01... ...
; $2aad referenced 1 time by $2a5b
sl_store:
    call syntax_z                                                     ; 2aad: cd 30 25    .0%
    ret z                                                             ; 2ab0: c8          .
; $2ab1 referenced 1 time by $2a39
stk_st_0:
    xor a                                                             ; 2ab1: af          .
; $2ab2 referenced 8 times by $21a7, $25e2, $2662, $29a7, $3584, $3617, $3634, $387c
stk_store:
    res 6,(iy+flags - err_nr)                                         ; 2ab2: fd cb 01... ...
; $2ab6 referenced 2 times by $2d34, $2dc8
l2ab6:
    push bc                                                           ; 2ab6: c5          .
    call test_5_sp                                                    ; 2ab7: cd ad 33    ..3
    pop bc                                                            ; 2aba: c1          .
    ld hl,(stkend)                                                    ; 2abb: 2a 65 5c    *e\
    ld (hl),a                                                         ; 2abe: 77          w
    inc hl                                                            ; 2abf: 23          #
    ld (hl),e                                                         ; 2ac0: 73          s
    inc hl                                                            ; 2ac1: 23          #
    ld (hl),d                                                         ; 2ac2: 72          r
    inc hl                                                            ; 2ac3: 23          #
    ld (hl),c                                                         ; 2ac4: 71          q
    inc hl                                                            ; 2ac5: 23          #
    ld (hl),b                                                         ; 2ac6: 70          p
    inc hl                                                            ; 2ac7: 23          #
    ld (stkend),hl                                                    ; 2ac8: 22 65 5c    "e\
    ret                                                               ; 2acb: c9          .

; $2acc referenced 2 times by $2a02, $2c31
int_exp1:
    xor a                                                             ; 2acc: af          .
; $2acd referenced 2 times by $2a6b, $2a89
int_exp2:
    push de                                                           ; 2acd: d5          .
    push hl                                                           ; 2ace: e5          .
    push af                                                           ; 2acf: f5          .
    call class_6                                                      ; 2ad0: cd 82 1c    ...
    pop af                                                            ; 2ad3: f1          .
    call syntax_z                                                     ; 2ad4: cd 30 25    .0%
    jr z,i_restore                                                    ; 2ad7: 28 12       (.
    push af                                                           ; 2ad9: f5          .
    call find_int                                                     ; 2ada: cd 99 1e    ...
    pop de                                                            ; 2add: d1          .
    ld a,b                                                            ; 2ade: 78          x
    or c                                                              ; 2adf: b1          .
    scf                                                               ; 2ae0: 37          7
    jr z,i_carry                                                      ; 2ae1: 28 05       (.
    pop hl                                                            ; 2ae3: e1          .
    push hl                                                           ; 2ae4: e5          .
    and a                                                             ; 2ae5: a7          .
    sbc hl,bc                                                         ; 2ae6: ed 42       .B
; $2ae8 referenced 1 time by $2ae1
i_carry:
    ld a,d                                                            ; 2ae8: 7a          z
    sbc a,0                                                           ; 2ae9: de 00       ..
; $2aeb referenced 1 time by $2ad7
i_restore:
    pop hl                                                            ; 2aeb: e1          .
    pop de                                                            ; 2aec: d1          .
    ret                                                               ; 2aed: c9          .

; $2aee referenced 2 times by $29fd, $2a2c
de_de_1:
    ex de,hl                                                          ; 2aee: eb          .
    inc hl                                                            ; 2aef: 23          #
    ld e,(hl)                                                         ; 2af0: 5e          ^
    inc hl                                                            ; 2af1: 23          #
    ld d,(hl)                                                         ; 2af2: 56          V
    ret                                                               ; 2af3: c9          .

; $2af4 referenced 4 times by $2a08, $2a27, $2a30, $2c3d
hl_hl_de:
    call syntax_z                                                     ; 2af4: cd 30 25    .0%
    ret z                                                             ; 2af7: c8          .
    call l30a9                                                        ; 2af8: cd a9 30    ..0
    jp c,report_4                                                     ; 2afb: da 15 1f    ...
    ret                                                               ; 2afe: c9          .

; $2aff referenced 3 times by $1c68, $1d1d, $21aa
let:
    ld hl,(dest)                                                      ; 2aff: 2a 4d 5c    *M\
    bit 1,(iy+flagx - err_nr)                                         ; 2b02: fd cb 37... ..7
    jr z,l_exists                                                     ; 2b06: 28 5e       (^
    ld bc,5                                                           ; 2b08: 01 05 00    ...
; $2b0b referenced 1 time by $2b22
l_each_ch:
    inc bc                                                            ; 2b0b: 03          .
; $2b0c referenced 2 times by $2b10, $2b1d
l_no_sp:
    inc hl                                                            ; 2b0c: 23          #
    ld a,(hl)                                                         ; 2b0d: 7e          ~
    cp $20                                                            ; 2b0e: fe 20       .
    jr z,l_no_sp                                                      ; 2b10: 28 fa       (.
    jr nc,l2b1f                                                       ; 2b12: 30 0b       0.
    cp $10                                                            ; 2b14: fe 10       ..
    jr c,l2b29                                                        ; 2b16: 38 11       8.
    cp $16                                                            ; 2b18: fe 16       ..
    jr nc,l2b29                                                       ; 2b1a: 30 0d       0.
    inc hl                                                            ; 2b1c: 23          #
    jr l_no_sp                                                        ; 2b1d: 18 ed       ..

; $2b1f referenced 1 time by $2b12
l2b1f:
    call alphanum                                                     ; 2b1f: cd 88 2c    ..,
    jr c,l_each_ch                                                    ; 2b22: 38 e7       8.
    cp $24                                                            ; 2b24: fe 24       .$
    jp z,l_news                                                       ; 2b26: ca c0 2b    ..+
; $2b29 referenced 2 times by $2b16, $2b1a
l2b29:
    ld a,c                                                            ; 2b29: 79          y
    ld hl,(e_line)                                                    ; 2b2a: 2a 59 5c    *Y\
    dec hl                                                            ; 2b2d: 2b          +
    call make_room                                                    ; 2b2e: cd 55 16    .U.
    ex de,hl                                                          ; 2b31: eb          .
    inc de                                                            ; 2b32: 13          .
    inc de                                                            ; 2b33: 13          .
    push de                                                           ; 2b34: d5          .
    ld hl,(dest)                                                      ; 2b35: 2a 4d 5c    *M\
    dec de                                                            ; 2b38: 1b          .
    sub 6                                                             ; 2b39: d6 06       ..
    ld b,a                                                            ; 2b3b: 47          G
    jr z,l_single                                                     ; 2b3c: 28 11       (.
; $2b3e referenced 2 times by $2b42, $2b48
l_char:
    inc hl                                                            ; 2b3e: 23          #
    ld a,(hl)                                                         ; 2b3f: 7e          ~
    cp $21                                                            ; 2b40: fe 21       .!
    jr c,l_char                                                       ; 2b42: 38 fa       8.
    inc de                                                            ; 2b44: 13          .
    or $20                                                            ; 2b45: f6 20       .
    ld (de),a                                                         ; 2b47: 12          .
    djnz l_char                                                       ; 2b48: 10 f4       ..
    or $80                                                            ; 2b4a: f6 80       ..
    ld (de),a                                                         ; 2b4c: 12          .
    ld a,$c0                                                          ; 2b4d: 3e c0       >.
; $2b4f referenced 1 time by $2b3c
l_single:
    ld hl,(dest)                                                      ; 2b4f: 2a 4d 5c    *M\
    xor (hl)                                                          ; 2b52: ae          .
    or $20                                                            ; 2b53: f6 20       .
    pop hl                                                            ; 2b55: e1          .
    call l2bea                                                        ; 2b56: cd ea 2b    ..+
; $2b59 referenced 1 time by $2b70
l_numeric:
    push hl                                                           ; 2b59: e5          .
    rst $28                                                           ; 2b5a: ef          .
    db 2                                                              ; 2b5b: 02          .  ; delete
    db $38                                                            ; 2b5c: 38          8  ; end-calc

    pop hl                                                            ; 2b5d: e1          .
    ld bc,5                                                           ; 2b5e: 01 05 00    ...
    and a                                                             ; 2b61: a7          .
    sbc hl,bc                                                         ; 2b62: ed 42       .B
    jr l_enter                                                        ; 2b64: 18 40       .@

; $2b66 referenced 1 time by $2b06
l_exists:
    bit 6,(iy+flags - err_nr)                                         ; 2b66: fd cb 01... ...
    jr z,l_deletes                                                    ; 2b6a: 28 06       (.
    ld de,6                                                           ; 2b6c: 11 06 00    ...
    add hl,de                                                         ; 2b6f: 19          .
    jr l_numeric                                                      ; 2b70: 18 e7       ..

; $2b72 referenced 1 time by $2b6a
l_deletes:
    ld hl,(dest)                                                      ; 2b72: 2a 4d 5c    *M\
    ld bc,(strlen)                                                    ; 2b75: ed 4b 72... .Kr
    bit 0,(iy+flagx - err_nr)                                         ; 2b79: fd cb 37... ..7
    jr nz,l_adds                                                      ; 2b7d: 20 30        0
    ld a,b                                                            ; 2b7f: 78          x
    or c                                                              ; 2b80: b1          .
    ret z                                                             ; 2b81: c8          .
    push hl                                                           ; 2b82: e5          .
    rst $30                                                           ; 2b83: f7          .
    push de                                                           ; 2b84: d5          .
    push bc                                                           ; 2b85: c5          .
    ld d,h                                                            ; 2b86: 54          T
    ld e,l                                                            ; 2b87: 5d          ]
    inc hl                                                            ; 2b88: 23          #
    ld (hl),$20                                                       ; 2b89: 36 20       6
    lddr                                                              ; 2b8b: ed b8       ..
    push hl                                                           ; 2b8d: e5          .
    call stk_fetch                                                    ; 2b8e: cd f1 2b    ..+
    pop hl                                                            ; 2b91: e1          .
    ex (sp),hl                                                        ; 2b92: e3          .
    and a                                                             ; 2b93: a7          .
    sbc hl,bc                                                         ; 2b94: ed 42       .B
    add hl,bc                                                         ; 2b96: 09          .
    jr nc,l_length                                                    ; 2b97: 30 02       0.
    ld b,h                                                            ; 2b99: 44          D
    ld c,l                                                            ; 2b9a: 4d          M
; $2b9b referenced 1 time by $2b97
l_length:
    ex (sp),hl                                                        ; 2b9b: e3          .
    ex de,hl                                                          ; 2b9c: eb          .
    ld a,b                                                            ; 2b9d: 78          x
    or c                                                              ; 2b9e: b1          .
    jr z,l_in_w_s                                                     ; 2b9f: 28 02       (.
    ldir                                                              ; 2ba1: ed b0       ..
; $2ba3 referenced 1 time by $2b9f
l_in_w_s:
    pop bc                                                            ; 2ba3: c1          .
    pop de                                                            ; 2ba4: d1          .
    pop hl                                                            ; 2ba5: e1          .
; $2ba6 referenced 1 time by $2b64
l_enter:
    ex de,hl                                                          ; 2ba6: eb          .
    ld a,b                                                            ; 2ba7: 78          x
    or c                                                              ; 2ba8: b1          .
    ret z                                                             ; 2ba9: c8          .
    push de                                                           ; 2baa: d5          .
    ldir                                                              ; 2bab: ed b0       ..
    pop hl                                                            ; 2bad: e1          .
    ret                                                               ; 2bae: c9          .

; $2baf referenced 1 time by $2b7d
l_adds:
    dec hl                                                            ; 2baf: 2b          +
    dec hl                                                            ; 2bb0: 2b          +
    dec hl                                                            ; 2bb1: 2b          +
    ld a,(hl)                                                         ; 2bb2: 7e          ~
    push hl                                                           ; 2bb3: e5          .
    push bc                                                           ; 2bb4: c5          .
    call l_string                                                     ; 2bb5: cd c6 2b    ..+
    pop bc                                                            ; 2bb8: c1          .
    pop hl                                                            ; 2bb9: e1          .
    inc bc                                                            ; 2bba: 03          .
    inc bc                                                            ; 2bbb: 03          .
    inc bc                                                            ; 2bbc: 03          .
    jp reclaim_2                                                      ; 2bbd: c3 e8 19    ...

; $2bc0 referenced 1 time by $2b26
l_news:
    ld a,$df                                                          ; 2bc0: 3e df       >.
    ld hl,(dest)                                                      ; 2bc2: 2a 4d 5c    *M\
    and (hl)                                                          ; 2bc5: a6          .
; $2bc6 referenced 1 time by $2bb5
l_string:
    push af                                                           ; 2bc6: f5          .
    call stk_fetch                                                    ; 2bc7: cd f1 2b    ..+
    ex de,hl                                                          ; 2bca: eb          .
    add hl,bc                                                         ; 2bcb: 09          .
    dec hl                                                            ; 2bcc: 2b          +
    ld (dest),hl                                                      ; 2bcd: 22 4d 5c    "M\
    push bc                                                           ; 2bd0: c5          .
    inc bc                                                            ; 2bd1: 03          .
    inc bc                                                            ; 2bd2: 03          .
    inc bc                                                            ; 2bd3: 03          .
    ld hl,(e_line)                                                    ; 2bd4: 2a 59 5c    *Y\
    dec hl                                                            ; 2bd7: 2b          +
    call make_room                                                    ; 2bd8: cd 55 16    .U.
    ld hl,(dest)                                                      ; 2bdb: 2a 4d 5c    *M\
    pop bc                                                            ; 2bde: c1          .
    push bc                                                           ; 2bdf: c5          .
    inc bc                                                            ; 2be0: 03          .
    lddr                                                              ; 2be1: ed b8       ..
    ex de,hl                                                          ; 2be3: eb          .
    pop bc                                                            ; 2be4: c1          .
    inc hl                                                            ; 2be5: 23          #
    ld (hl),b                                                         ; 2be6: 70          p
    dec hl                                                            ; 2be7: 2b          +
    ld (hl),c                                                         ; 2be8: 71          q
    pop af                                                            ; 2be9: f1          .
; $2bea referenced 1 time by $2b56
l2bea:
    dec hl                                                            ; 2bea: 2b          +
    ld (hl),a                                                         ; 2beb: 77          w
    ld hl,(e_line)                                                    ; 2bec: 2a 59 5c    *Y\
    dec hl                                                            ; 2bef: 2b          +
    ret                                                               ; 2bf0: c9          .

; $2bf1 referenced 15 times by $0631, $175e, $1c3d, $2036, $2a55, $2b8e, $2bc7, $349c, $3533, $3538, $3574, $3579, $35b8, $363e, $3649
stk_fetch:
    ld hl,(stkend)                                                    ; 2bf1: 2a 65 5c    *e\
    dec hl                                                            ; 2bf4: 2b          +
    ld b,(hl)                                                         ; 2bf5: 46          F
    dec hl                                                            ; 2bf6: 2b          +
    ld c,(hl)                                                         ; 2bf7: 4e          N
    dec hl                                                            ; 2bf8: 2b          +
    ld d,(hl)                                                         ; 2bf9: 56          V
    dec hl                                                            ; 2bfa: 2b          +
    ld e,(hl)                                                         ; 2bfb: 5e          ^
    dec hl                                                            ; 2bfc: 2b          +
    ld a,(hl)                                                         ; 2bfd: 7e          ~
    ld (stkend),hl                                                    ; 2bfe: 22 65 5c    "e\
    ret                                                               ; 2c01: c9          .

dim:
    call look_vars                                                    ; 2c02: cd b2 28    ..(
; $2c05 referenced 1 time by $2c48
d_rport_c:
    jp nz,report_c                                                    ; 2c05: c2 8a 1c    ...
    call syntax_z                                                     ; 2c08: cd 30 25    .0%
    jr nz,d_run                                                       ; 2c0b: 20 08        .
    res 6,c                                                           ; 2c0d: cb b1       ..
    call stk_var                                                      ; 2c0f: cd 96 29    ..)
    call check_end                                                    ; 2c12: cd ee 1b    ...
; $2c15 referenced 1 time by $2c0b
d_run:
    jr c,d_letter                                                     ; 2c15: 38 08       8.
    push bc                                                           ; 2c17: c5          .
    call next_one                                                     ; 2c18: cd b8 19    ...
    call reclaim_2                                                    ; 2c1b: cd e8 19    ...
    pop bc                                                            ; 2c1e: c1          .
; $2c1f referenced 1 time by $2c15
d_letter:
    set 7,c                                                           ; 2c1f: cb f9       ..
    ld b,0                                                            ; 2c21: 06 00       ..
    push bc                                                           ; 2c23: c5          .
    ld hl,1                                                           ; 2c24: 21 01 00    !..
    bit 6,c                                                           ; 2c27: cb 71       .q
    jr nz,d_size                                                      ; 2c29: 20 02        .
    ld l,5                                                            ; 2c2b: 2e 05       ..
; $2c2d referenced 1 time by $2c29
d_size:
    ex de,hl                                                          ; 2c2d: eb          .
; $2c2e referenced 1 time by $2c44
d_no_loop:
    rst $20                                                           ; 2c2e: e7          .
    ld h,$ff                                                          ; 2c2f: 26 ff       &.
    call int_exp1                                                     ; 2c31: cd cc 2a    ..*
    jp c,report_3                                                     ; 2c34: da 20 2a    . *
    pop hl                                                            ; 2c37: e1          .
    push bc                                                           ; 2c38: c5          .
    inc h                                                             ; 2c39: 24          $
    push hl                                                           ; 2c3a: e5          .
    ld h,b                                                            ; 2c3b: 60          `
    ld l,c                                                            ; 2c3c: 69          i
    call hl_hl_de                                                     ; 2c3d: cd f4 2a    ..*
    ex de,hl                                                          ; 2c40: eb          .
    rst $18                                                           ; 2c41: df          .
    cp $2c                                                            ; 2c42: fe 2c       .,
    jr z,d_no_loop                                                    ; 2c44: 28 e8       (.
    cp $29                                                            ; 2c46: fe 29       .)
    jr nz,d_rport_c                                                   ; 2c48: 20 bb        .
    rst $20                                                           ; 2c4a: e7          .
    pop bc                                                            ; 2c4b: c1          .
    ld a,c                                                            ; 2c4c: 79          y
    ld l,b                                                            ; 2c4d: 68          h
    ld h,0                                                            ; 2c4e: 26 00       &.
    inc hl                                                            ; 2c50: 23          #
    inc hl                                                            ; 2c51: 23          #
    add hl,hl                                                         ; 2c52: 29          )
    add hl,de                                                         ; 2c53: 19          .
    jp c,report_4                                                     ; 2c54: da 15 1f    ...
    push de                                                           ; 2c57: d5          .
    push bc                                                           ; 2c58: c5          .
    push hl                                                           ; 2c59: e5          .
    ld b,h                                                            ; 2c5a: 44          D
    ld c,l                                                            ; 2c5b: 4d          M
    ld hl,(e_line)                                                    ; 2c5c: 2a 59 5c    *Y\
    dec hl                                                            ; 2c5f: 2b          +
    call make_room                                                    ; 2c60: cd 55 16    .U.
    inc hl                                                            ; 2c63: 23          #
    ld (hl),a                                                         ; 2c64: 77          w
    pop bc                                                            ; 2c65: c1          .
    dec bc                                                            ; 2c66: 0b          .
    dec bc                                                            ; 2c67: 0b          .
    dec bc                                                            ; 2c68: 0b          .
    inc hl                                                            ; 2c69: 23          #
    ld (hl),c                                                         ; 2c6a: 71          q
    inc hl                                                            ; 2c6b: 23          #
    ld (hl),b                                                         ; 2c6c: 70          p
    pop bc                                                            ; 2c6d: c1          .
    ld a,b                                                            ; 2c6e: 78          x
    inc hl                                                            ; 2c6f: 23          #
    ld (hl),a                                                         ; 2c70: 77          w
    ld h,d                                                            ; 2c71: 62          b
    ld l,e                                                            ; 2c72: 6b          k
    dec de                                                            ; 2c73: 1b          .
    ld (hl),0                                                         ; 2c74: 36 00       6.
    bit 6,c                                                           ; 2c76: cb 71       .q
    jr z,l2c7c                                                        ; 2c78: 28 02       (.
    ld (hl),$20                                                       ; 2c7a: 36 20       6
; $2c7c referenced 1 time by $2c78
l2c7c:
    pop bc                                                            ; 2c7c: c1          .
    lddr                                                              ; 2c7d: ed b8       ..
; $2c7f referenced 1 time by $2c85
dim_sizes:
    pop bc                                                            ; 2c7f: c1          .
    ld (hl),b                                                         ; 2c80: 70          p
    dec hl                                                            ; 2c81: 2b          +
    ld (hl),c                                                         ; 2c82: 71          q
    dec hl                                                            ; 2c83: 2b          +
    dec a                                                             ; 2c84: 3d          =
    jr nz,dim_sizes                                                   ; 2c85: 20 f8        .
    ret                                                               ; 2c87: c9          .

; $2c88 referenced 7 times by $0eee, $2684, $28cf, $28d4, $2924, $2943, $2b1f
alphanum:
    call numeric                                                      ; 2c88: cd 1b 2d    ..-
    ccf                                                               ; 2c8b: 3f          ?
    ret c                                                             ; 2c8c: d8          .
; $2c8d referenced 7 times by $1f6e, $1f86, $20ed, $27c3, $28b7, $34a5, $3aa3
alpha:
    cp $41                                                            ; 2c8d: fe 41       .A
    ccf                                                               ; 2c8f: 3f          ?
    ret nc                                                            ; 2c90: d0          .
    cp $7b                                                            ; 2c91: fe 7b       .{
    ret nc                                                            ; 2c93: d0          .
    cp $5b                                                            ; 2c94: fe 5b       .[
    ret c                                                             ; 2c96: d8          .
    cp $61                                                            ; 2c97: fe 61       .a
    ccf                                                               ; 2c99: 3f          ?
    ret                                                               ; 2c9a: c9          .

; $2c9b referenced 1 time by $2692
dec_to_fp:
    cp $c4                                                            ; 2c9b: fe c4       ..
    jr nz,l2cb8                                                       ; 2c9d: 20 19        .
    ld de,0                                                           ; 2c9f: 11 00 00    ...
; $2ca2 referenced 1 time by $2cb1
l2ca2:
    rst $20                                                           ; 2ca2: e7          .
    sub $31                                                           ; 2ca3: d6 31       .1
    adc a,0                                                           ; 2ca5: ce 00       ..
    jr nz,l2cb3                                                       ; 2ca7: 20 0a        .
    ex de,hl                                                          ; 2ca9: eb          .
    ccf                                                               ; 2caa: 3f          ?
    adc hl,hl                                                         ; 2cab: ed 6a       .j
    jp c,report_6                                                     ; 2cad: da ad 31    ..1
    ex de,hl                                                          ; 2cb0: eb          .
    jr l2ca2                                                          ; 2cb1: 18 ef       ..

; $2cb3 referenced 2 times by $0f14, $2ca7
l2cb3:
    ld c,e                                                            ; 2cb3: 4b          K
    ld b,d                                                            ; 2cb4: 42          B
    jp stack_bc1                                                      ; 2cb5: c3 2f 2d    ./-

; $2cb8 referenced 1 time by $2c9d
l2cb8:
    cp $2e                                                            ; 2cb8: fe 2e       ..
    jr z,decint                                                       ; 2cba: 28 0f       (.
    call int_to_fp                                                    ; 2cbc: cd 3b 2d    .;-
    cp $2e                                                            ; 2cbf: fe 2e       ..
    jr nz,e_format                                                    ; 2cc1: 20 28        (
    rst $20                                                           ; 2cc3: e7          .
    call numeric                                                      ; 2cc4: cd 1b 2d    ..-
    jr c,e_format                                                     ; 2cc7: 38 22       8"
    jr l2cd5                                                          ; 2cc9: 18 0a       ..

; $2ccb referenced 1 time by $2cba
decint:
    rst $20                                                           ; 2ccb: e7          .
    call numeric                                                      ; 2ccc: cd 1b 2d    ..-
; $2ccf referenced 1 time by $2d02
nonsense:
    jp c,report_c                                                     ; 2ccf: da 8a 1c    ...
    rst $28                                                           ; 2cd2: ef          .
    db $a0                                                            ; 2cd3: a0          .  ; stk-zero
    db $38                                                            ; 2cd4: 38          8  ; end-calc

; $2cd5 referenced 1 time by $2cc9
l2cd5:
    rst $28                                                           ; 2cd5: ef          .
    db $a1                                                            ; 2cd6: a1          .  ; stk-one
    db $c0                                                            ; 2cd7: c0          .  ; st-mem-0
    db 2                                                              ; 2cd8: 02          .  ; delete
    db $38                                                            ; 2cd9: 38          8  ; end-calc

; $2cda referenced 1 time by $2ce9
nxt_dgt_1:
    rst $18                                                           ; 2cda: df          .
    call stk_digit                                                    ; 2cdb: cd 22 2d    ."-
    jr c,e_format                                                     ; 2cde: 38 0b       8.
    rst $28                                                           ; 2ce0: ef          .
    db $e0                                                            ; 2ce1: e0          .  ; get-mem-0
    db $a4                                                            ; 2ce2: a4          .  ; stk-ten
    db 4                                                              ; 2ce3: 04          .  ; multiply
    db $c0                                                            ; 2ce4: c0          .  ; st-mem-0
    db 5                                                              ; 2ce5: 05          .  ; division
    db $0f                                                            ; 2ce6: 0f          .  ; addition
    db $38                                                            ; 2ce7: 38          8  ; end-calc

    rst $20                                                           ; 2ce8: e7          .
    jr nxt_dgt_1                                                      ; 2ce9: 18 ef       ..

; $2ceb referenced 3 times by $2cc1, $2cc7, $2cde
e_format:
    cp $45                                                            ; 2ceb: fe 45       .E
    jr z,l2cf2                                                        ; 2ced: 28 03       (.
    cp $65                                                            ; 2cef: fe 65       .e
    ret nz                                                            ; 2cf1: c0          .
; $2cf2 referenced 1 time by $2ced
l2cf2:
    ld b,$ff                                                          ; 2cf2: 06 ff       ..
    rst $20                                                           ; 2cf4: e7          .
    cp $2b                                                            ; 2cf5: fe 2b       .+
    jr z,sign_done                                                    ; 2cf7: 28 05       (.
    cp $2d                                                            ; 2cf9: fe 2d       .-
    jr nz,st_e_part                                                   ; 2cfb: 20 02        .
    inc b                                                             ; 2cfd: 04          .
; $2cfe referenced 1 time by $2cf7
sign_done:
    rst $20                                                           ; 2cfe: e7          .
; $2cff referenced 1 time by $2cfb
st_e_part:
    call numeric                                                      ; 2cff: cd 1b 2d    ..-
    jr c,nonsense                                                     ; 2d02: 38 cb       8.
    push bc                                                           ; 2d04: c5          .
    call int_to_fp                                                    ; 2d05: cd 3b 2d    .;-
    call fp_to_a                                                      ; 2d08: cd d5 2d    ..-
    pop bc                                                            ; 2d0b: c1          .
    jp c,report_6                                                     ; 2d0c: da ad 31    ..1
    and a                                                             ; 2d0f: a7          .
    jp m,report_6                                                     ; 2d10: fa ad 31    ..1
    inc b                                                             ; 2d13: 04          .
    jr z,e_fp                                                         ; 2d14: 28 02       (.
    neg                                                               ; 2d16: ed 44       .D
; $2d18 referenced 1 time by $2d14
e_fp:
    jr e_to_fp                                                        ; 2d18: 18 35       .5

    db $ff                                                            ; 2d1a: ff          .

; $2d1b referenced 7 times by $0dd3, $2c88, $2cc4, $2ccc, $2cff, $2d22, $3b79
numeric:
    cp $30                                                            ; 2d1b: fe 30       .0
    ret c                                                             ; 2d1d: d8          .
    cp $3a                                                            ; 2d1e: fe 3a       .:
    ccf                                                               ; 2d20: 3f          ?
    ret                                                               ; 2d21: c9          .

; $2d22 referenced 2 times by $2cdb, $2d40
stk_digit:
    call numeric                                                      ; 2d22: cd 1b 2d    ..-
    ret c                                                             ; 2d25: d8          .
    sub $30                                                           ; 2d26: d6 30       .0
; $2d28 referenced 12 times by $22d9, $23f0, $23fb, $2444, $2453, $2467, $2471, $2498, $2593, $3490, $3646, $36f4
stack_a:
    ld c,a                                                            ; 2d28: 4f          O
    ld b,0                                                            ; 2d29: 06 00       ..
stack_bc:
    ld iy,$5c3a                                                       ; 2d2b: fd 21 3a... .!:
; $2d2f referenced 5 times by $2601, $2cb5, $34c0, $364c, $3c19
stack_bc1:
    ld d,c                                                            ; 2d2f: 51          Q
    xor a                                                             ; 2d30: af          .
    ld e,a                                                            ; 2d31: 5f          _
    ld c,b                                                            ; 2d32: 48          H
    ld b,e                                                            ; 2d33: 43          C
    call l2ab6                                                        ; 2d34: cd b6 2a    ..*
    rst $28                                                           ; 2d37: ef          .
    db $38                                                            ; 2d38: 38          8  ; end-calc

    and a                                                             ; 2d39: a7          .
    ret                                                               ; 2d3a: c9          .

; $2d3b referenced 3 times by $1069, $2cbc, $2d05
int_to_fp:
    push af                                                           ; 2d3b: f5          .
    rst $28                                                           ; 2d3c: ef          .
    db $a0                                                            ; 2d3d: a0          .  ; stk-zero
    db $38                                                            ; 2d3e: 38          8  ; end-calc

    pop af                                                            ; 2d3f: f1          .
; $2d40 referenced 1 time by $2d4d
nxt_dgt_2:
    call stk_digit                                                    ; 2d40: cd 22 2d    ."-
    ret c                                                             ; 2d43: d8          .
    rst $28                                                           ; 2d44: ef          .
    db 1                                                              ; 2d45: 01          .  ; exchange
    db $a4                                                            ; 2d46: a4          .  ; stk-ten
    db 4                                                              ; 2d47: 04          .  ; multiply
    db $0f                                                            ; 2d48: 0f          .  ; addition
    db $38                                                            ; 2d49: 38          8  ; end-calc

    call ch_add_1                                                     ; 2d4a: cd 74 00    .t.
    jr nxt_dgt_2                                                      ; 2d4d: 18 f1       ..

; $2d4f referenced 3 times by $2d18, $2e37, $2e6a
e_to_fp:
    rlca                                                              ; 2d4f: 07          .
    rrca                                                              ; 2d50: 0f          .
    jr nc,l2d55                                                       ; 2d51: 30 02       0.
    cpl                                                               ; 2d53: 2f          /
    inc a                                                             ; 2d54: 3c          <
; $2d55 referenced 1 time by $2d51
l2d55:
    push af                                                           ; 2d55: f5          .
    ld hl,$5c92                                                       ; 2d56: 21 92 5c    !.\
    call fp_0_1                                                       ; 2d59: cd e7 34    ..4
    rst $28                                                           ; 2d5c: ef          .
    db $a4                                                            ; 2d5d: a4          .  ; stk-ten
    db $38                                                            ; 2d5e: 38          8  ; end-calc

    pop af                                                            ; 2d5f: f1          .
; $2d60 referenced 1 time by $2d79
l2d60:
    srl a                                                             ; 2d60: cb 3f       .?
    jr nc,l2d71                                                       ; 2d62: 30 0d       0.
    push af                                                           ; 2d64: f5          .
    rst $28                                                           ; 2d65: ef          .
    db $c1                                                            ; 2d66: c1          .  ; st-mem-1
    db $e0                                                            ; 2d67: e0          .  ; get-mem-0
    db 0                                                              ; 2d68: 00          .  ; jump-true
    db l2d6d - $                                                      ; 2d69: 04          .
    db 4                                                              ; 2d6a: 04          .  ; multiply
    db $33                                                            ; 2d6b: 33          3  ; jump
    db l2d6e - $                                                      ; 2d6c: 02          .
l2d6d:
    db 5                                                              ; 2d6d: 05          .  ; division
l2d6e:
    db $e1                                                            ; 2d6e: e1          .  ; get-mem-1
    db $38                                                            ; 2d6f: 38          8  ; end-calc

    pop af                                                            ; 2d70: f1          .
; $2d71 referenced 1 time by $2d62
l2d71:
    jr z,l2d7b                                                        ; 2d71: 28 08       (.
    push af                                                           ; 2d73: f5          .
    rst $28                                                           ; 2d74: ef          .
    db $31                                                            ; 2d75: 31          1  ; duplicate
    db 4                                                              ; 2d76: 04          .  ; multiply
    db $38                                                            ; 2d77: 38          8  ; end-calc

    pop af                                                            ; 2d78: f1          .
    jr l2d60                                                          ; 2d79: 18 e5       ..

; $2d7b referenced 1 time by $2d71
l2d7b:
    rst $28                                                           ; 2d7b: ef          .
    db 2                                                              ; 2d7c: 02          .  ; delete
    db $38                                                            ; 2d7d: 38          8  ; end-calc

    ret                                                               ; 2d7e: c9          .

; $2d7f referenced 6 times by $2db4, $2e0f, $30d1, $30d7, $329b, $3469
fetchi:
    inc hl                                                            ; 2d7f: 23          #
    ld c,(hl)                                                         ; 2d80: 4e          N
    inc hl                                                            ; 2d81: 23          #
    ld a,(hl)                                                         ; 2d82: 7e          ~
    xor c                                                             ; 2d83: a9          .
    sub c                                                             ; 2d84: 91          .
    ld e,a                                                            ; 2d85: 5f          _
    inc hl                                                            ; 2d86: 23          #
    ld a,(hl)                                                         ; 2d87: 7e          ~
    adc a,c                                                           ; 2d88: 89          .
    xor c                                                             ; 2d89: a9          .
    ld d,a                                                            ; 2d8a: 57          W
    ret                                                               ; 2d8b: c9          .

l2d8c:
    db $4d, $42                                                       ; 2d8c: 4d 42       MB

; $2d8e referenced 3 times by $30ea, $3267, $3480
l2d8e:
    push hl                                                           ; 2d8e: e5          .
    inc hl                                                            ; 2d8f: 23          #
    ld (hl),c                                                         ; 2d90: 71          q
    inc hl                                                            ; 2d91: 23          #
    ld a,e                                                            ; 2d92: 7b          {
    xor c                                                             ; 2d93: a9          .
    sub c                                                             ; 2d94: 91          .
    ld (hl),a                                                         ; 2d95: 77          w
    inc hl                                                            ; 2d96: 23          #
    ld a,d                                                            ; 2d97: 7a          z
    adc a,c                                                           ; 2d98: 89          .
    xor c                                                             ; 2d99: a9          .
    ld (hl),a                                                         ; 2d9a: 77          w
    inc hl                                                            ; 2d9b: 23          #
    xor a                                                             ; 2d9c: af          .
    ld (hl),a                                                         ; 2d9d: 77          w
    pop hl                                                            ; 2d9e: e1          .
    ld (hl),a                                                         ; 2d9f: 77          w
    ret                                                               ; 2da0: c9          .

    db $ff                                                            ; 2da1: ff          .

; $2da2 referenced 8 times by $106f, $1a0c, $1e99, $2617, $2dd5, $3863, $3bb0, $3c24
fp_to_bc:
    rst $28                                                           ; 2da2: ef          .
    db $38                                                            ; 2da3: 38          8  ; end-calc

    ld a,(hl)                                                         ; 2da4: 7e          ~
    and a                                                             ; 2da5: a7          .
    jr z,fpbcint                                                      ; 2da6: 28 05       (.
    rst $28                                                           ; 2da8: ef          .
    db $a2                                                            ; 2da9: a2          .  ; stk-half
    db $0f                                                            ; 2daa: 0f          .  ; addition
    db $27                                                            ; 2dab: 27          '  ; int
    db $38                                                            ; 2dac: 38          8  ; end-calc

; $2dad referenced 1 time by $2da6
fpbcint:
    rst $28                                                           ; 2dad: ef          .
    db 2                                                              ; 2dae: 02          .  ; delete
    db $38                                                            ; 2daf: 38          8  ; end-calc

    push de                                                           ; 2db0: d5          .
    push hl                                                           ; 2db1: e5          .
    ex de,hl                                                          ; 2db2: eb          .
    ld b,(hl)                                                         ; 2db3: 46          F
    call fetchi                                                       ; 2db4: cd 7f 2d    ..-
    xor a                                                             ; 2db7: af          .
    sub b                                                             ; 2db8: 90          .
    bit 7,c                                                           ; 2db9: cb 79       .y
    ld a,e                                                            ; 2dbb: 7b          {
    ld b,d                                                            ; 2dbc: 42          B
    ld c,a                                                            ; 2dbd: 4f          O
    pop hl                                                            ; 2dbe: e1          .
    pop de                                                            ; 2dbf: d1          .
    ret                                                               ; 2dc0: c9          .

; $2dc1 referenced 2 times by $2e2b, $2e5c
l2dc1:
    ld d,a                                                            ; 2dc1: 57          W
    rla                                                               ; 2dc2: 17          .
    sbc a,a                                                           ; 2dc3: 9f          .
    ld e,a                                                            ; 2dc4: 5f          _
    ld c,a                                                            ; 2dc5: 4f          O
    xor a                                                             ; 2dc6: af          .
    ld b,a                                                            ; 2dc7: 47          G
    call l2ab6                                                        ; 2dc8: cd b6 2a    ..*
    rst $28                                                           ; 2dcb: ef          .
    db $34                                                            ; 2dcc: 34          4  ; stk-data
    db $ef, $1a, $20, $9a, $85                                        ; 2dcd: ef 1a 20... .. ; 0.3010299957
    db 4                                                              ; 2dd2: 04          .  ; multiply
    db $27                                                            ; 2dd3: 27          '  ; int
    db $38                                                            ; 2dd4: 38          8  ; end-calc

; $2dd5 referenced 10 times by $09cb, $09cf, $1e85, $1e94, $2314, $248a, $2d08, $2e41, $35a2, $36cd
fp_to_a:
    call fp_to_bc                                                     ; 2dd5: cd a2 2d    ..-
    ret c                                                             ; 2dd8: d8          .
    push af                                                           ; 2dd9: f5          .
    dec b                                                             ; 2dda: 05          .
    inc b                                                             ; 2ddb: 04          .
    jr z,fp_a_end                                                     ; 2ddc: 28 03       (.
    pop af                                                            ; 2dde: f1          .
    scf                                                               ; 2ddf: 37          7
    ret                                                               ; 2de0: c9          .

; $2de1 referenced 1 time by $2ddc
fp_a_end:
    pop af                                                            ; 2de1: f1          .
    ret                                                               ; 2de2: c9          .

; $2de3 referenced 2 times by $2039, $3603
print_fp:
    rst $28                                                           ; 2de3: ef          .
    db $31                                                            ; 2de4: 31          1  ; duplicate
    db $36                                                            ; 2de5: 36          6  ; less-0
    db 0                                                              ; 2de6: 00          .  ; jump-true
    db p_neg - $                                                      ; 2de7: 0b          .
    db $31                                                            ; 2de8: 31          1  ; duplicate
    db $37                                                            ; 2de9: 37          7  ; greater-0
    db 0                                                              ; 2dea: 00          .  ; jump-true
    db p_pos - $                                                      ; 2deb: 0d          .
    db 2                                                              ; 2dec: 02          .  ; delete
    db $38                                                            ; 2ded: 38          8  ; end-calc

    ld a,$30                                                          ; 2dee: 3e 30       >0
    rst $10                                                           ; 2df0: d7          .
    ret                                                               ; 2df1: c9          .

p_neg:
    db $2a                                                            ; 2df2: 2a          *  ; abs
    db $38                                                            ; 2df3: 38          8  ; end-calc

    ld a,$2d                                                          ; 2df4: 3e 2d       >-
    rst $10                                                           ; 2df6: d7          .
    rst $28                                                           ; 2df7: ef          .
p_pos:
    db $a0                                                            ; 2df8: a0          .  ; stk-zero
    db $c3                                                            ; 2df9: c3          .  ; st-mem-3
    db $c4                                                            ; 2dfa: c4          .  ; st-mem-4
    db $c5                                                            ; 2dfb: c5          .  ; st-mem-5
    db 2                                                              ; 2dfc: 02          .  ; delete
    db $38                                                            ; 2dfd: 38          8  ; end-calc

    exx                                                               ; 2dfe: d9          .
    push hl                                                           ; 2dff: e5          .
    exx                                                               ; 2e00: d9          .
; $2e01 referenced 1 time by $2e6d
l2e01:
    rst $28                                                           ; 2e01: ef          .
    db $31                                                            ; 2e02: 31          1  ; duplicate
    db $27                                                            ; 2e03: 27          '  ; int
    db $c2                                                            ; 2e04: c2          .  ; st-mem-2
    db 3                                                              ; 2e05: 03          .  ; subtract
    db $e2                                                            ; 2e06: e2          .  ; get-mem-2
    db 1                                                              ; 2e07: 01          .  ; exchange
    db $c2                                                            ; 2e08: c2          .  ; st-mem-2
    db 2                                                              ; 2e09: 02          .  ; delete
    db $38                                                            ; 2e0a: 38          8  ; end-calc

    ld a,(hl)                                                         ; 2e0b: 7e          ~
    and a                                                             ; 2e0c: a7          .
    jr nz,l2e56                                                       ; 2e0d: 20 47        G
    call fetchi                                                       ; 2e0f: cd 7f 2d    ..-
    ld b,$10                                                          ; 2e12: 06 10       ..
    ld a,d                                                            ; 2e14: 7a          z
    and a                                                             ; 2e15: a7          .
    jr nz,l2e1e                                                       ; 2e16: 20 06        .
    or e                                                              ; 2e18: b3          .
    jr z,l2e24                                                        ; 2e19: 28 09       (.
    ld b,8                                                            ; 2e1b: 06 08       ..
    ld d,e                                                            ; 2e1d: 53          S
; $2e1e referenced 1 time by $2e16
l2e1e:
    push de                                                           ; 2e1e: d5          .
    exx                                                               ; 2e1f: d9          .
    pop de                                                            ; 2e20: d1          .
    exx                                                               ; 2e21: d9          .
    jr l2e7b                                                          ; 2e22: 18 57       .W

; $2e24 referenced 1 time by $2e19
l2e24:
    rst $28                                                           ; 2e24: ef          .
    db 2                                                              ; 2e25: 02          .  ; delete
    db $e2                                                            ; 2e26: e2          .  ; get-mem-2
    db $38                                                            ; 2e27: 38          8  ; end-calc

    ld a,(hl)                                                         ; 2e28: 7e          ~
    sub $7e                                                           ; 2e29: d6 7e       .~
    call l2dc1                                                        ; 2e2b: cd c1 2d    ..-
    ld d,a                                                            ; 2e2e: 57          W
    ld a,(membot+26)                                                  ; 2e2f: 3a ac 5c    :.\
    sub d                                                             ; 2e32: 92          .
    ld (membot+26),a                                                  ; 2e33: 32 ac 5c    2.\
    ld a,d                                                            ; 2e36: 7a          z
    call e_to_fp                                                      ; 2e37: cd 4f 2d    .O-
    rst $28                                                           ; 2e3a: ef          .
    db $31                                                            ; 2e3b: 31          1  ; duplicate
    db $27                                                            ; 2e3c: 27          '  ; int
    db $c1                                                            ; 2e3d: c1          .  ; st-mem-1
    db 3                                                              ; 2e3e: 03          .  ; subtract
    db $e1                                                            ; 2e3f: e1          .  ; get-mem-1
    db $38                                                            ; 2e40: 38          8  ; end-calc

    call fp_to_a                                                      ; 2e41: cd d5 2d    ..-
    push hl                                                           ; 2e44: e5          .
    ld (membot+15),a                                                  ; 2e45: 32 a1 5c    2.\
    dec a                                                             ; 2e48: 3d          =
    rla                                                               ; 2e49: 17          .
    sbc a,a                                                           ; 2e4a: 9f          .
    inc a                                                             ; 2e4b: 3c          <
    ld hl,$5cab                                                       ; 2e4c: 21 ab 5c    !.\
    ld (hl),a                                                         ; 2e4f: 77          w
    inc hl                                                            ; 2e50: 23          #
    add a,(hl)                                                        ; 2e51: 86          .
    ld (hl),a                                                         ; 2e52: 77          w
    pop hl                                                            ; 2e53: e1          .
    jr l2ecf                                                          ; 2e54: 18 79       .y

; $2e56 referenced 1 time by $2e0d
l2e56:
    sub $80                                                           ; 2e56: d6 80       ..
    cp $1c                                                            ; 2e58: fe 1c       ..
    jr c,l2e6f                                                        ; 2e5a: 38 13       8.
    call l2dc1                                                        ; 2e5c: cd c1 2d    ..-
    sub 7                                                             ; 2e5f: d6 07       ..
    ld hl,$5cac                                                       ; 2e61: 21 ac 5c    !.\
    ld b,a                                                            ; 2e64: 47          G
    add a,(hl)                                                        ; 2e65: 86          .
    ld (hl),a                                                         ; 2e66: 77          w
    ld a,b                                                            ; 2e67: 78          x
    neg                                                               ; 2e68: ed 44       .D
    call e_to_fp                                                      ; 2e6a: cd 4f 2d    .O-
    jr l2e01                                                          ; 2e6d: 18 92       ..

; $2e6f referenced 1 time by $2e5a
l2e6f:
    ex de,hl                                                          ; 2e6f: eb          .
    call fetch_two                                                    ; 2e70: cd ba 2f    ../
    exx                                                               ; 2e73: d9          .
    ld a,l                                                            ; 2e74: 7d          }
    set 7,d                                                           ; 2e75: cb fa       ..
    exx                                                               ; 2e77: d9          .
    sub $80                                                           ; 2e78: d6 80       ..
    ld b,a                                                            ; 2e7a: 47          G
; $2e7b referenced 2 times by $2e22, $2e92
l2e7b:
    sla e                                                             ; 2e7b: cb 23       .#
    rl d                                                              ; 2e7d: cb 12       ..
    exx                                                               ; 2e7f: d9          .
    rl e                                                              ; 2e80: cb 13       ..
    rl d                                                              ; 2e82: cb 12       ..
    exx                                                               ; 2e84: d9          .
    ld hl,$5caa                                                       ; 2e85: 21 aa 5c    !.\
    ld c,5                                                            ; 2e88: 0e 05       ..
; $2e8a referenced 1 time by $2e90
l2e8a:
    ld a,(hl)                                                         ; 2e8a: 7e          ~
    adc a,a                                                           ; 2e8b: 8f          .
    daa                                                               ; 2e8c: 27          '
    ld (hl),a                                                         ; 2e8d: 77          w
    dec hl                                                            ; 2e8e: 2b          +
    dec c                                                             ; 2e8f: 0d          .
    jr nz,l2e8a                                                       ; 2e90: 20 f8        .
    djnz l2e7b                                                        ; 2e92: 10 e7       ..
    ld de,$5ca1                                                       ; 2e94: 11 a1 5c    ..\
    ld hl,$5ca6                                                       ; 2e97: 21 a6 5c    !.\
    ld b,9                                                            ; 2e9a: 06 09       ..
    xor a                                                             ; 2e9c: af          .
    rld                                                               ; 2e9d: ed 6f       .o
    ld c,$ff                                                          ; 2e9f: 0e ff       ..
; $2ea1 referenced 1 time by $2eb8
l2ea1:
    rld                                                               ; 2ea1: ed 6f       .o
    jr nz,l2ea9                                                       ; 2ea3: 20 04        .
    dec c                                                             ; 2ea5: 0d          .
    inc c                                                             ; 2ea6: 0c          .
    jr nz,l2eb3                                                       ; 2ea7: 20 0a        .
; $2ea9 referenced 1 time by $2ea3
l2ea9:
    ld (de),a                                                         ; 2ea9: 12          .
    ld c,0                                                            ; 2eaa: 0e 00       ..
    inc (iy+(membot+26) - err_nr)                                     ; 2eac: fd 34 72    .4r
    inc (iy+(membot+25) - err_nr)                                     ; 2eaf: fd 34 71    .4q
    inc de                                                            ; 2eb2: 13          .
; $2eb3 referenced 1 time by $2ea7
l2eb3:
    bit 0,b                                                           ; 2eb3: cb 40       .@
    jr z,l2eb8                                                        ; 2eb5: 28 01       (.
    inc hl                                                            ; 2eb7: 23          #
; $2eb8 referenced 1 time by $2eb5
l2eb8:
    djnz l2ea1                                                        ; 2eb8: 10 e7       ..
    ld a,(membot+25)                                                  ; 2eba: 3a ab 5c    :.\
    sub 9                                                             ; 2ebd: d6 09       ..
    jr c,l2ecb                                                        ; 2ebf: 38 0a       8.
    dec (iy+(membot+25) - err_nr)                                     ; 2ec1: fd 35 71    .5q
    ld a,4                                                            ; 2ec4: 3e 04       >.
    cp (iy+(membot+23) - err_nr)                                      ; 2ec6: fd be 6f    ..o
    jr l2f0c                                                          ; 2ec9: 18 41       .A

; $2ecb referenced 1 time by $2ebf
l2ecb:
    rst $28                                                           ; 2ecb: ef          .
    db 2                                                              ; 2ecc: 02          .  ; delete
    db $e2                                                            ; 2ecd: e2          .  ; get-mem-2
    db $38                                                            ; 2ece: 38          8  ; end-calc

; $2ecf referenced 1 time by $2e54
l2ecf:
    ex de,hl                                                          ; 2ecf: eb          .
    call fetch_two                                                    ; 2ed0: cd ba 2f    ../
    exx                                                               ; 2ed3: d9          .
    ld a,$80                                                          ; 2ed4: 3e 80       >.
    sub l                                                             ; 2ed6: 95          .
    set 7,d                                                           ; 2ed7: cb fa       ..
    ld l,0                                                            ; 2ed9: 2e 00       ..
    exx                                                               ; 2edb: d9          .
    call shift_fp                                                     ; 2edc: cd dd 2f    ../
; $2edf referenced 1 time by $2f0a
l2edf:
    ld a,(iy+(membot+25) - err_nr)                                    ; 2edf: fd 7e 71    .~q
    cp 8                                                              ; 2ee2: fe 08       ..
    jr c,l2eec                                                        ; 2ee4: 38 06       8.
    exx                                                               ; 2ee6: d9          .
    rl d                                                              ; 2ee7: cb 12       ..
    exx                                                               ; 2ee9: d9          .
    jr l2f0c                                                          ; 2eea: 18 20       .

; $2eec referenced 1 time by $2ee4
l2eec:
    ld bc,$0200                                                       ; 2eec: 01 00 02    ...
; $2eef referenced 1 time by $2efc
l2eef:
    ld a,e                                                            ; 2eef: 7b          {
    call l2f8b                                                        ; 2ef0: cd 8b 2f    ../
    ld e,a                                                            ; 2ef3: 5f          _
    ld a,d                                                            ; 2ef4: 7a          z
    call l2f8b                                                        ; 2ef5: cd 8b 2f    ../
    ld d,a                                                            ; 2ef8: 57          W
    push bc                                                           ; 2ef9: c5          .
    exx                                                               ; 2efa: d9          .
    pop bc                                                            ; 2efb: c1          .
    djnz l2eef                                                        ; 2efc: 10 f1       ..
    ld hl,$5ca1                                                       ; 2efe: 21 a1 5c    !.\
    ld a,c                                                            ; 2f01: 79          y
    ld c,(iy+(membot+25) - err_nr)                                    ; 2f02: fd 4e 71    .Nq
    add hl,bc                                                         ; 2f05: 09          .
    ld (hl),a                                                         ; 2f06: 77          w
    inc (iy+(membot+25) - err_nr)                                     ; 2f07: fd 34 71    .4q
    jr l2edf                                                          ; 2f0a: 18 d3       ..

; $2f0c referenced 2 times by $2ec9, $2eea
l2f0c:
    push af                                                           ; 2f0c: f5          .
    ld b,0                                                            ; 2f0d: 06 00       ..
    ld c,(iy+(membot+25) - err_nr)                                    ; 2f0f: fd 4e 71    .Nq
    ld hl,$5ca1                                                       ; 2f12: 21 a1 5c    !.\
    add hl,bc                                                         ; 2f15: 09          .
    ld b,c                                                            ; 2f16: 41          A
    pop af                                                            ; 2f17: f1          .
; $2f18 referenced 1 time by $2f25
l2f18:
    dec hl                                                            ; 2f18: 2b          +
    ld a,(hl)                                                         ; 2f19: 7e          ~
    adc a,0                                                           ; 2f1a: ce 00       ..
    ld (hl),a                                                         ; 2f1c: 77          w
    and a                                                             ; 2f1d: a7          .
    jr z,l2f25                                                        ; 2f1e: 28 05       (.
    cp $0a                                                            ; 2f20: fe 0a       ..
    ccf                                                               ; 2f22: 3f          ?
    jr nc,l2f2d                                                       ; 2f23: 30 08       0.
; $2f25 referenced 1 time by $2f1e
l2f25:
    djnz l2f18                                                        ; 2f25: 10 f1       ..
    inc (iy+(membot+26) - err_nr)                                     ; 2f27: fd 34 72    .4r
    inc b                                                             ; 2f2a: 04          .
    ld (hl),1                                                         ; 2f2b: 36 01       6.
; $2f2d referenced 1 time by $2f23
l2f2d:
    ld (iy+(membot+25) - err_nr),b                                    ; 2f2d: fd 70 71    .pq
    rst $28                                                           ; 2f30: ef          .
    db 2                                                              ; 2f31: 02          .  ; delete
    db $38                                                            ; 2f32: 38          8  ; end-calc

    exx                                                               ; 2f33: d9          .
    pop hl                                                            ; 2f34: e1          .
    exx                                                               ; 2f35: d9          .
    ld bc,(membot+25)                                                 ; 2f36: ed 4b ab... .K.
    ld hl,$5ca1                                                       ; 2f3a: 21 a1 5c    !.\
    ld a,b                                                            ; 2f3d: 78          x
    cp 9                                                              ; 2f3e: fe 09       ..
    jr c,l2f46                                                        ; 2f40: 38 04       8.
    cp $fc                                                            ; 2f42: fe fc       ..
    jr c,l2f6c                                                        ; 2f44: 38 26       8&
; $2f46 referenced 1 time by $2f40
l2f46:
    and a                                                             ; 2f46: a7          .
    call z,out_code                                                   ; 2f47: cc ef 15    ...
; $2f4a referenced 1 time by $2f70
l2f4a:
    xor a                                                             ; 2f4a: af          .
    sub b                                                             ; 2f4b: 90          .
    jp m,l2f52                                                        ; 2f4c: fa 52 2f    .R/
    ld b,a                                                            ; 2f4f: 47          G
    jr l2f5e                                                          ; 2f50: 18 0c       ..

; $2f52 referenced 3 times by $2f4c, $2f5c, $2f6a
l2f52:
    ld a,c                                                            ; 2f52: 79          y
    and a                                                             ; 2f53: a7          .
    jr z,l2f59                                                        ; 2f54: 28 03       (.
    ld a,(hl)                                                         ; 2f56: 7e          ~
    inc hl                                                            ; 2f57: 23          #
    dec c                                                             ; 2f58: 0d          .
; $2f59 referenced 1 time by $2f54
l2f59:
    call out_code                                                     ; 2f59: cd ef 15    ...
    djnz l2f52                                                        ; 2f5c: 10 f4       ..
; $2f5e referenced 1 time by $2f50
l2f5e:
    ld a,c                                                            ; 2f5e: 79          y
    and a                                                             ; 2f5f: a7          .
    ret z                                                             ; 2f60: c8          .
    ld a,$2e                                                          ; 2f61: 3e 2e       >.
    inc b                                                             ; 2f63: 04          .
; $2f64 referenced 1 time by $2f67
l2f64:
    rst $10                                                           ; 2f64: d7          .
    ld a,$30                                                          ; 2f65: 3e 30       >0
    djnz l2f64                                                        ; 2f67: 10 fb       ..
    ld b,c                                                            ; 2f69: 41          A
    jr l2f52                                                          ; 2f6a: 18 e6       ..

; $2f6c referenced 1 time by $2f44
l2f6c:
    ld d,b                                                            ; 2f6c: 50          P
    ld b,1                                                            ; 2f6d: 06 01       ..
    dec d                                                             ; 2f6f: 15          .
    call l2f4a                                                        ; 2f70: cd 4a 2f    .J/
    ld a,$45                                                          ; 2f73: 3e 45       >E
    rst $10                                                           ; 2f75: d7          .
    ld c,d                                                            ; 2f76: 4a          J
    ld a,d                                                            ; 2f77: 7a          z
    and a                                                             ; 2f78: a7          .
    jp p,l2f83                                                        ; 2f79: f2 83 2f    ../
    neg                                                               ; 2f7c: ed 44       .D
    ld c,a                                                            ; 2f7e: 4f          O
    ld a,$2d                                                          ; 2f7f: 3e 2d       >-
    jr l2f85                                                          ; 2f81: 18 02       ..

; $2f83 referenced 1 time by $2f79
l2f83:
    ld a,$2b                                                          ; 2f83: 3e 2b       >+
; $2f85 referenced 1 time by $2f81
l2f85:
    rst $10                                                           ; 2f85: d7          .
    ld b,0                                                            ; 2f86: 06 00       ..
    jp out_num                                                        ; 2f88: c3 1b 1a    ...

; $2f8b referenced 2 times by $2ef0, $2ef5
l2f8b:
    ld h,0                                                            ; 2f8b: 26 00       &.
    ld l,a                                                            ; 2f8d: 6f          o
    push de                                                           ; 2f8e: d5          .
    ld d,h                                                            ; 2f8f: 54          T
    ld e,a                                                            ; 2f90: 5f          _
    add hl,hl                                                         ; 2f91: 29          )
    add hl,hl                                                         ; 2f92: 29          )
    add hl,de                                                         ; 2f93: 19          .
    add hl,hl                                                         ; 2f94: 29          )
    ld e,c                                                            ; 2f95: 59          Y
    add hl,de                                                         ; 2f96: 19          .
    pop de                                                            ; 2f97: d1          .
    ld a,l                                                            ; 2f98: 7d          }
    ld c,h                                                            ; 2f99: 4c          L
    ret                                                               ; 2f9a: c9          .

; $2f9b referenced 2 times by $3046, $304b
prep_add:
    ld a,(hl)                                                         ; 2f9b: 7e          ~
    and a                                                             ; 2f9c: a7          .
    ret z                                                             ; 2f9d: c8          .
    ld (hl),0                                                         ; 2f9e: 36 00       6.
    inc hl                                                            ; 2fa0: 23          #
    bit 7,(hl)                                                        ; 2fa1: cb 7e       .~
    set 7,(hl)                                                        ; 2fa3: cb fe       ..
    dec hl                                                            ; 2fa5: 2b          +
    ret z                                                             ; 2fa6: c8          .
    push bc                                                           ; 2fa7: c5          .
    ld bc,5                                                           ; 2fa8: 01 05 00    ...
    add hl,bc                                                         ; 2fab: 09          .
    ld b,c                                                            ; 2fac: 41          A
    ld c,a                                                            ; 2fad: 4f          O
    scf                                                               ; 2fae: 37          7
; $2faf referenced 1 time by $2fb5
neg_byte:
    dec hl                                                            ; 2faf: 2b          +
    ld a,(hl)                                                         ; 2fb0: 7e          ~
    cpl                                                               ; 2fb1: 2f          /
    adc a,0                                                           ; 2fb2: ce 00       ..
    ld (hl),a                                                         ; 2fb4: 77          w
    djnz neg_byte                                                     ; 2fb5: 10 f8       ..
    ld a,c                                                            ; 2fb7: 79          y
    pop bc                                                            ; 2fb8: c1          .
    ret                                                               ; 2fb9: c9          .

; $2fba referenced 5 times by $2e70, $2ed0, $3057, $3104, $31c3
fetch_two:
    push hl                                                           ; 2fba: e5          .
    push af                                                           ; 2fbb: f5          .
    ld c,(hl)                                                         ; 2fbc: 4e          N
    inc hl                                                            ; 2fbd: 23          #
    ld b,(hl)                                                         ; 2fbe: 46          F
    ld (hl),a                                                         ; 2fbf: 77          w
    inc hl                                                            ; 2fc0: 23          #
    ld a,c                                                            ; 2fc1: 79          y
    ld c,(hl)                                                         ; 2fc2: 4e          N
    push bc                                                           ; 2fc3: c5          .
    inc hl                                                            ; 2fc4: 23          #
    ld c,(hl)                                                         ; 2fc5: 4e          N
    inc hl                                                            ; 2fc6: 23          #
    ld b,(hl)                                                         ; 2fc7: 46          F
    ex de,hl                                                          ; 2fc8: eb          .
    ld d,a                                                            ; 2fc9: 57          W
    ld e,(hl)                                                         ; 2fca: 5e          ^
    push de                                                           ; 2fcb: d5          .
    inc hl                                                            ; 2fcc: 23          #
    ld d,(hl)                                                         ; 2fcd: 56          V
    inc hl                                                            ; 2fce: 23          #
    ld e,(hl)                                                         ; 2fcf: 5e          ^
    push de                                                           ; 2fd0: d5          .
    exx                                                               ; 2fd1: d9          .
    pop de                                                            ; 2fd2: d1          .
    pop hl                                                            ; 2fd3: e1          .
    pop bc                                                            ; 2fd4: c1          .
    exx                                                               ; 2fd5: d9          .
    inc hl                                                            ; 2fd6: 23          #
    ld d,(hl)                                                         ; 2fd7: 56          V
    inc hl                                                            ; 2fd8: 23          #
    ld e,(hl)                                                         ; 2fd9: 5e          ^
    pop af                                                            ; 2fda: f1          .
    pop hl                                                            ; 2fdb: e1          .
    ret                                                               ; 2fdc: c9          .

; $2fdd referenced 3 times by $2edc, $305a, $3076
shift_fp:
    and a                                                             ; 2fdd: a7          .
    ret z                                                             ; 2fde: c8          .
    cp $21                                                            ; 2fdf: fe 21       .!
    jr nc,addend_0                                                    ; 2fe1: 30 16       0.
    push bc                                                           ; 2fe3: c5          .
    ld b,a                                                            ; 2fe4: 47          G
; $2fe5 referenced 1 time by $2ff1
one_shift:
    exx                                                               ; 2fe5: d9          .
    sra l                                                             ; 2fe6: cb 2d       .-
    rr d                                                              ; 2fe8: cb 1a       ..
    rr e                                                              ; 2fea: cb 1b       ..
    exx                                                               ; 2fec: d9          .
    rr d                                                              ; 2fed: cb 1a       ..
    rr e                                                              ; 2fef: cb 1b       ..
    djnz one_shift                                                    ; 2ff1: 10 f2       ..
    pop bc                                                            ; 2ff3: c1          .
    ret nc                                                            ; 2ff4: d0          .
    call add_back                                                     ; 2ff5: cd 04 30    ..0
    ret nz                                                            ; 2ff8: c0          .
; $2ff9 referenced 1 time by $2fe1
addend_0:
    exx                                                               ; 2ff9: d9          .
    xor a                                                             ; 2ffa: af          .
; $2ffb referenced 1 time by $3160
zeros_4_5:
    ld l,0                                                            ; 2ffb: 2e 00       ..
    ld d,a                                                            ; 2ffd: 57          W
    ld e,l                                                            ; 2ffe: 5d          ]
    exx                                                               ; 2fff: d9          .
    ld de,0                                                           ; 3000: 11 00 00    ...
    ret                                                               ; 3003: c9          .

; $3004 referenced 2 times by $2ff5, $3189
add_back:
    inc e                                                             ; 3004: 1c          .
    ret nz                                                            ; 3005: c0          .
    inc d                                                             ; 3006: 14          .
    ret nz                                                            ; 3007: c0          .
    exx                                                               ; 3008: d9          .
    inc e                                                             ; 3009: 1c          .
    jr nz,all_added                                                   ; 300a: 20 01        .
    inc d                                                             ; 300c: 14          .
; $300d referenced 1 time by $300a
all_added:
    exx                                                               ; 300d: d9          .
    ret                                                               ; 300e: c9          .

; $300f referenced 1 time by $352e
x80_fsub:
    ex de,hl                                                          ; 300f: eb          .
    call x80_fneg                                                     ; 3010: cd 52 34    .R4
    ex de,hl                                                          ; 3013: eb          .
x80_fadd:
    ld a,(de)                                                         ; 3014: 1a          .
    or (hl)                                                           ; 3015: b6          .
    jr nz,addition                                                    ; 3016: 20 26        &
    push de                                                           ; 3018: d5          .
    inc hl                                                            ; 3019: 23          #
    push hl                                                           ; 301a: e5          .
    inc hl                                                            ; 301b: 23          #
    ld c,(hl)                                                         ; 301c: 4e          N
    inc hl                                                            ; 301d: 23          #
    ld b,(hl)                                                         ; 301e: 46          F
    inc hl                                                            ; 301f: 23          #
    inc hl                                                            ; 3020: 23          #
    inc hl                                                            ; 3021: 23          #
    ld a,(hl)                                                         ; 3022: 7e          ~
    inc hl                                                            ; 3023: 23          #
    ld e,(hl)                                                         ; 3024: 5e          ^
    inc hl                                                            ; 3025: 23          #
    ld d,(hl)                                                         ; 3026: 56          V
    ex de,hl                                                          ; 3027: eb          .
    add hl,bc                                                         ; 3028: 09          .
    ex de,hl                                                          ; 3029: eb          .
    pop hl                                                            ; 302a: e1          .
    adc a,(hl)                                                        ; 302b: 8e          .
    rrca                                                              ; 302c: 0f          .
    adc a,0                                                           ; 302d: ce 00       ..
    jp l3221                                                          ; 302f: c3 21 32    .!2

; $3032 referenced 1 time by $3232
l3032:
    ld (hl),a                                                         ; 3032: 77          w
    inc hl                                                            ; 3033: 23          #
    ld (hl),e                                                         ; 3034: 73          s
    inc hl                                                            ; 3035: 23          #
    ld (hl),d                                                         ; 3036: 72          r
    dec hl                                                            ; 3037: 2b          +
    dec hl                                                            ; 3038: 2b          +
    dec hl                                                            ; 3039: 2b          +
    pop de                                                            ; 303a: d1          .
    ret                                                               ; 303b: c9          .

; $303c referenced 1 time by $3221
l303c:
    dec hl                                                            ; 303c: 2b          +
    pop de                                                            ; 303d: d1          .
; $303e referenced 1 time by $3016
addition:
    call l3293                                                        ; 303e: cd 93 32    ..2
    exx                                                               ; 3041: d9          .
    push hl                                                           ; 3042: e5          .
    exx                                                               ; 3043: d9          .
    push de                                                           ; 3044: d5          .
    push hl                                                           ; 3045: e5          .
    call prep_add                                                     ; 3046: cd 9b 2f    ../
    ld b,a                                                            ; 3049: 47          G
    ex de,hl                                                          ; 304a: eb          .
    call prep_add                                                     ; 304b: cd 9b 2f    ../
    ld c,a                                                            ; 304e: 4f          O
    cp b                                                              ; 304f: b8          .
    jr nc,shift_len                                                   ; 3050: 30 03       0.
    ld a,b                                                            ; 3052: 78          x
    ld b,c                                                            ; 3053: 41          A
    ex de,hl                                                          ; 3054: eb          .
; $3055 referenced 1 time by $3050
shift_len:
    push af                                                           ; 3055: f5          .
    sub b                                                             ; 3056: 90          .
    call fetch_two                                                    ; 3057: cd ba 2f    ../
    call shift_fp                                                     ; 305a: cd dd 2f    ../
    pop af                                                            ; 305d: f1          .
    pop hl                                                            ; 305e: e1          .
    ld (hl),a                                                         ; 305f: 77          w
    push hl                                                           ; 3060: e5          .
    ld l,b                                                            ; 3061: 68          h
    ld h,c                                                            ; 3062: 61          a
    add hl,de                                                         ; 3063: 19          .
    exx                                                               ; 3064: d9          .
    ex de,hl                                                          ; 3065: eb          .
    adc hl,bc                                                         ; 3066: ed 4a       .J
    ex de,hl                                                          ; 3068: eb          .
    ld a,h                                                            ; 3069: 7c          |
    adc a,l                                                           ; 306a: 8d          .
    ld l,a                                                            ; 306b: 6f          o
    rra                                                               ; 306c: 1f          .
    xor l                                                             ; 306d: ad          .
    exx                                                               ; 306e: d9          .
    ex de,hl                                                          ; 306f: eb          .
    pop hl                                                            ; 3070: e1          .
    rra                                                               ; 3071: 1f          .
    jr nc,test_neg                                                    ; 3072: 30 08       0.
    ld a,1                                                            ; 3074: 3e 01       >.
    call shift_fp                                                     ; 3076: cd dd 2f    ../
    inc (hl)                                                          ; 3079: 34          4
    jr z,add_rep_6                                                    ; 307a: 28 23       (#
; $307c referenced 1 time by $3072
test_neg:
    exx                                                               ; 307c: d9          .
    ld a,l                                                            ; 307d: 7d          }
    and $80                                                           ; 307e: e6 80       ..
    exx                                                               ; 3080: d9          .
    inc hl                                                            ; 3081: 23          #
    ld (hl),a                                                         ; 3082: 77          w
    dec hl                                                            ; 3083: 2b          +
    jr z,go_nc_mlt                                                    ; 3084: 28 1f       (.
    ld a,e                                                            ; 3086: 7b          {
    neg                                                               ; 3087: ed 44       .D
    ccf                                                               ; 3089: 3f          ?
    ld e,a                                                            ; 308a: 5f          _
    ld a,d                                                            ; 308b: 7a          z
    cpl                                                               ; 308c: 2f          /
    adc a,0                                                           ; 308d: ce 00       ..
    ld d,a                                                            ; 308f: 57          W
    exx                                                               ; 3090: d9          .
    ld a,e                                                            ; 3091: 7b          {
    cpl                                                               ; 3092: 2f          /
    adc a,0                                                           ; 3093: ce 00       ..
    ld e,a                                                            ; 3095: 5f          _
    ld a,d                                                            ; 3096: 7a          z
    cpl                                                               ; 3097: 2f          /
    adc a,0                                                           ; 3098: ce 00       ..
    jr nc,end_compl                                                   ; 309a: 30 07       0.
    rra                                                               ; 309c: 1f          .
    exx                                                               ; 309d: d9          .
    inc (hl)                                                          ; 309e: 34          4
; $309f referenced 1 time by $307a
add_rep_6:
    jp z,report_6                                                     ; 309f: ca ad 31    ..1
    exx                                                               ; 30a2: d9          .
; $30a3 referenced 1 time by $309a
end_compl:
    ld d,a                                                            ; 30a3: 57          W
    exx                                                               ; 30a4: d9          .
; $30a5 referenced 1 time by $3084
go_nc_mlt:
    xor a                                                             ; 30a5: af          .
    jp test_norm                                                      ; 30a6: c3 55 31    .U1

; $30a9 referenced 5 times by $2af8, $30de, $3af3, $3b47, $3bcf
l30a9:
    push bc                                                           ; 30a9: c5          .
    ld b,$10                                                          ; 30aa: 06 10       ..
    ld a,h                                                            ; 30ac: 7c          |
    ld c,l                                                            ; 30ad: 4d          M
    ld hl,0                                                           ; 30ae: 21 00 00    !..
; $30b1 referenced 1 time by $30bc
hl_loop:
    add hl,hl                                                         ; 30b1: 29          )
    jr c,hl_over                                                      ; 30b2: 38 0a       8.
    rl c                                                              ; 30b4: cb 11       ..
    rla                                                               ; 30b6: 17          .
    jr nc,hl_again                                                    ; 30b7: 30 03       0.
    add hl,de                                                         ; 30b9: 19          .
    jr c,hl_over                                                      ; 30ba: 38 02       8.
; $30bc referenced 1 time by $30b7
hl_again:
    djnz hl_loop                                                      ; 30bc: 10 f3       ..
; $30be referenced 2 times by $30b2, $30ba
hl_over:
    pop bc                                                            ; 30be: c1          .
    ret                                                               ; 30bf: c9          .

; $30c0 referenced 4 times by $30f4, $30fd, $31b4, $31ba
prep_m_d:
    call tstzero                                                      ; 30c0: cd c5 34    ..4
    ret c                                                             ; 30c3: d8          .
    inc hl                                                            ; 30c4: 23          #
    xor (hl)                                                          ; 30c5: ae          .
    set 7,(hl)                                                        ; 30c6: cb fe       ..
    dec hl                                                            ; 30c8: 2b          +
    ret                                                               ; 30c9: c9          .

x80_fmul:
    ld a,(de)                                                         ; 30ca: 1a          .
    or (hl)                                                           ; 30cb: b6          .
    jr nz,multiply                                                    ; 30cc: 20 22        "
    push de                                                           ; 30ce: d5          .
    push hl                                                           ; 30cf: e5          .
    push de                                                           ; 30d0: d5          .
    call fetchi                                                       ; 30d1: cd 7f 2d    ..-
    ex de,hl                                                          ; 30d4: eb          .
    ex (sp),hl                                                        ; 30d5: e3          .
    ld b,c                                                            ; 30d6: 41          A
    call fetchi                                                       ; 30d7: cd 7f 2d    ..-
    ld a,c                                                            ; 30da: 79          y
    xor b                                                             ; 30db: a8          .
    ld c,a                                                            ; 30dc: 4f          O
    pop hl                                                            ; 30dd: e1          .
    call l30a9                                                        ; 30de: cd a9 30    ..0
    pop de                                                            ; 30e1: d1          .
    ex de,hl                                                          ; 30e2: eb          .
    jr c,qmult                                                        ; 30e3: 38 0a       8.
    ld a,e                                                            ; 30e5: 7b          {
    or d                                                              ; 30e6: b2          .
    jr nz,l30ea                                                       ; 30e7: 20 01        .
    ld c,a                                                            ; 30e9: 4f          O
; $30ea referenced 1 time by $30e7
l30ea:
    call l2d8e                                                        ; 30ea: cd 8e 2d    ..-
    pop de                                                            ; 30ed: d1          .
    ret                                                               ; 30ee: c9          .

; $30ef referenced 1 time by $30e3
qmult:
    pop de                                                            ; 30ef: d1          .
; $30f0 referenced 1 time by $30cc
multiply:
    call l3293                                                        ; 30f0: cd 93 32    ..2
    xor a                                                             ; 30f3: af          .
    call prep_m_d                                                     ; 30f4: cd c0 30    ..0
    ret c                                                             ; 30f7: d8          .
    exx                                                               ; 30f8: d9          .
    push hl                                                           ; 30f9: e5          .
    exx                                                               ; 30fa: d9          .
    push de                                                           ; 30fb: d5          .
    ex de,hl                                                          ; 30fc: eb          .
    call prep_m_d                                                     ; 30fd: cd c0 30    ..0
    ex de,hl                                                          ; 3100: eb          .
    jr c,zero_rslt                                                    ; 3101: 38 5a       8Z
    push hl                                                           ; 3103: e5          .
    call fetch_two                                                    ; 3104: cd ba 2f    ../
    ld a,b                                                            ; 3107: 78          x
    and a                                                             ; 3108: a7          .
    sbc hl,hl                                                         ; 3109: ed 62       .b
    exx                                                               ; 310b: d9          .
    push hl                                                           ; 310c: e5          .
    sbc hl,hl                                                         ; 310d: ed 62       .b
    exx                                                               ; 310f: d9          .
    ld b,$21                                                          ; 3110: 06 21       .!
    jr strt_mlt                                                       ; 3112: 18 11       ..

; $3114 referenced 1 time by $312e
mlt_loop:
    jr nc,no_add                                                      ; 3114: 30 05       0.
    add hl,de                                                         ; 3116: 19          .
    exx                                                               ; 3117: d9          .
    adc hl,de                                                         ; 3118: ed 5a       .Z
    exx                                                               ; 311a: d9          .
; $311b referenced 1 time by $3114
no_add:
    exx                                                               ; 311b: d9          .
    rr h                                                              ; 311c: cb 1c       ..
    rr l                                                              ; 311e: cb 1d       ..
    exx                                                               ; 3120: d9          .
    rr h                                                              ; 3121: cb 1c       ..
    rr l                                                              ; 3123: cb 1d       ..
; $3125 referenced 1 time by $3112
strt_mlt:
    exx                                                               ; 3125: d9          .
    rr b                                                              ; 3126: cb 18       ..
    rr c                                                              ; 3128: cb 19       ..
    exx                                                               ; 312a: d9          .
    rr c                                                              ; 312b: cb 19       ..
    rra                                                               ; 312d: 1f          .
    djnz mlt_loop                                                     ; 312e: 10 e4       ..
    ex de,hl                                                          ; 3130: eb          .
    exx                                                               ; 3131: d9          .
    ex de,hl                                                          ; 3132: eb          .
    exx                                                               ; 3133: d9          .
    pop bc                                                            ; 3134: c1          .
    pop hl                                                            ; 3135: e1          .
    ld a,b                                                            ; 3136: 78          x
    add a,c                                                           ; 3137: 81          .
    jr nz,make_expt                                                   ; 3138: 20 01        .
    and a                                                             ; 313a: a7          .
; $313b referenced 1 time by $3138
make_expt:
    dec a                                                             ; 313b: 3d          =
    ccf                                                               ; 313c: 3f          ?
; $313d referenced 1 time by $3211
divn_expt:
    rla                                                               ; 313d: 17          .
    ccf                                                               ; 313e: 3f          ?
    rra                                                               ; 313f: 1f          .
    jp p,oflw1_clr                                                    ; 3140: f2 46 31    .F1
    jr nc,report_6                                                    ; 3143: 30 68       0h
    and a                                                             ; 3145: a7          .
; $3146 referenced 1 time by $3140
oflw1_clr:
    inc a                                                             ; 3146: 3c          <
    jr nz,oflw2_clr                                                   ; 3147: 20 08        .
    jr c,oflw2_clr                                                    ; 3149: 38 06       8.
    exx                                                               ; 314b: d9          .
    bit 7,d                                                           ; 314c: cb 7a       .z
    exx                                                               ; 314e: d9          .
    jr nz,report_6                                                    ; 314f: 20 5c        \
; $3151 referenced 2 times by $3147, $3149
oflw2_clr:
    ld (hl),a                                                         ; 3151: 77          w
    exx                                                               ; 3152: d9          .
    ld a,b                                                            ; 3153: 78          x
    exx                                                               ; 3154: d9          .
; $3155 referenced 1 time by $30a6
test_norm:
    jr nc,normalize                                                   ; 3155: 30 15       0.
    ld a,(hl)                                                         ; 3157: 7e          ~
    and a                                                             ; 3158: a7          .
; $3159 referenced 1 time by $3180
near_zero:
    ld a,$80                                                          ; 3159: 3e 80       >.
    jr z,skip_zero                                                    ; 315b: 28 01       (.
; $315d referenced 2 times by $3101, $3184
zero_rslt:
    xor a                                                             ; 315d: af          .
; $315e referenced 1 time by $315b
skip_zero:
    exx                                                               ; 315e: d9          .
    and d                                                             ; 315f: a2          .
    call zeros_4_5                                                    ; 3160: cd fb 2f    ../
    rlca                                                              ; 3163: 07          .
    ld (hl),a                                                         ; 3164: 77          w
    jr c,oflow_clr                                                    ; 3165: 38 2e       8.
    inc hl                                                            ; 3167: 23          #
    ld (hl),a                                                         ; 3168: 77          w
    dec hl                                                            ; 3169: 2b          +
    jr oflow_clr                                                      ; 316a: 18 29       .)

; $316c referenced 1 time by $3155
normalize:
    ld b,$20                                                          ; 316c: 06 20       .
; $316e referenced 1 time by $3182
shift_one:
    exx                                                               ; 316e: d9          .
    bit 7,d                                                           ; 316f: cb 7a       .z
    exx                                                               ; 3171: d9          .
    jr nz,norml_now                                                   ; 3172: 20 12        .
    rlca                                                              ; 3174: 07          .
    rl e                                                              ; 3175: cb 13       ..
    rl d                                                              ; 3177: cb 12       ..
    exx                                                               ; 3179: d9          .
    rl e                                                              ; 317a: cb 13       ..
    rl d                                                              ; 317c: cb 12       ..
    exx                                                               ; 317e: d9          .
    dec (hl)                                                          ; 317f: 35          5
    jr z,near_zero                                                    ; 3180: 28 d7       (.
    djnz shift_one                                                    ; 3182: 10 ea       ..
    jr zero_rslt                                                      ; 3184: 18 d7       ..

; $3186 referenced 1 time by $3172
norml_now:
    rla                                                               ; 3186: 17          .
    jr nc,oflow_clr                                                   ; 3187: 30 0c       0.
    call add_back                                                     ; 3189: cd 04 30    ..0
    jr nz,oflow_clr                                                   ; 318c: 20 07        .
    exx                                                               ; 318e: d9          .
    ld d,$80                                                          ; 318f: 16 80       ..
    exx                                                               ; 3191: d9          .
    inc (hl)                                                          ; 3192: 34          4
    jr z,report_6                                                     ; 3193: 28 18       (.
; $3195 referenced 4 times by $3165, $316a, $3187, $318c
oflow_clr:
    push hl                                                           ; 3195: e5          .
    inc hl                                                            ; 3196: 23          #
    exx                                                               ; 3197: d9          .
    push de                                                           ; 3198: d5          .
    exx                                                               ; 3199: d9          .
    pop bc                                                            ; 319a: c1          .
    ld a,b                                                            ; 319b: 78          x
    rla                                                               ; 319c: 17          .
    rl (hl)                                                           ; 319d: cb 16       ..
    rra                                                               ; 319f: 1f          .
    ld (hl),a                                                         ; 31a0: 77          w
    inc hl                                                            ; 31a1: 23          #
    ld (hl),c                                                         ; 31a2: 71          q
    inc hl                                                            ; 31a3: 23          #
    ld (hl),d                                                         ; 31a4: 72          r
    inc hl                                                            ; 31a5: 23          #
    ld (hl),e                                                         ; 31a6: 73          s
    pop hl                                                            ; 31a7: e1          .
    pop de                                                            ; 31a8: d1          .
    exx                                                               ; 31a9: d9          .
    pop hl                                                            ; 31aa: e1          .
    exx                                                               ; 31ab: d9          .
    ret                                                               ; 31ac: c9          .

; $31ad referenced 10 times by $0ed4, $0f06, $2cad, $2d0c, $2d10, $309f, $3143, $314f, $3193, $31b7
report_6:
    rst $08                                                           ; 31ad: cf          .
    db 5                                                              ; 31ae: 05          .  ; Report 6 Number too big

x80_fdiv:
    call l3293                                                        ; 31af: cd 93 32    ..2
    ex de,hl                                                          ; 31b2: eb          .
    xor a                                                             ; 31b3: af          .
    call prep_m_d                                                     ; 31b4: cd c0 30    ..0
    jr c,report_6                                                     ; 31b7: 38 f4       8.
    ex de,hl                                                          ; 31b9: eb          .
    call prep_m_d                                                     ; 31ba: cd c0 30    ..0
    ret c                                                             ; 31bd: d8          .
    exx                                                               ; 31be: d9          .
    push hl                                                           ; 31bf: e5          .
    exx                                                               ; 31c0: d9          .
    push de                                                           ; 31c1: d5          .
    push hl                                                           ; 31c2: e5          .
    call fetch_two                                                    ; 31c3: cd ba 2f    ../
    exx                                                               ; 31c6: d9          .
    push hl                                                           ; 31c7: e5          .
    ld h,b                                                            ; 31c8: 60          `
    ld l,c                                                            ; 31c9: 69          i
    exx                                                               ; 31ca: d9          .
    ld h,c                                                            ; 31cb: 61          a
    ld l,b                                                            ; 31cc: 68          h
    xor a                                                             ; 31cd: af          .
    ld b,$df                                                          ; 31ce: 06 df       ..
    jr div_start                                                      ; 31d0: 18 10       ..

; $31d2 referenced 1 time by $31fb
div_loop:
    rla                                                               ; 31d2: 17          .
    rl c                                                              ; 31d3: cb 11       ..
    exx                                                               ; 31d5: d9          .
    rl c                                                              ; 31d6: cb 11       ..
    rl b                                                              ; 31d8: cb 10       ..
    exx                                                               ; 31da: d9          .
l31db:
    add hl,hl                                                         ; 31db: 29          )
    exx                                                               ; 31dc: d9          .
    adc hl,hl                                                         ; 31dd: ed 6a       .j
    exx                                                               ; 31df: d9          .
    jr c,subn_only                                                    ; 31e0: 38 10       8.
; $31e2 referenced 2 times by $31d0, $31ff
div_start:
    sbc hl,de                                                         ; 31e2: ed 52       .R
    exx                                                               ; 31e4: d9          .
    sbc hl,de                                                         ; 31e5: ed 52       .R
    exx                                                               ; 31e7: d9          .
    jr nc,no_rstore                                                   ; 31e8: 30 0f       0.
    add hl,de                                                         ; 31ea: 19          .
    exx                                                               ; 31eb: d9          .
    adc hl,de                                                         ; 31ec: ed 5a       .Z
    exx                                                               ; 31ee: d9          .
    and a                                                             ; 31ef: a7          .
    jr count_one                                                      ; 31f0: 18 08       ..

; $31f2 referenced 1 time by $31e0
subn_only:
    and a                                                             ; 31f2: a7          .
    sbc hl,de                                                         ; 31f3: ed 52       .R
    exx                                                               ; 31f5: d9          .
    sbc hl,de                                                         ; 31f6: ed 52       .R
    exx                                                               ; 31f8: d9          .
; $31f9 referenced 1 time by $31e8
no_rstore:
    scf                                                               ; 31f9: 37          7
; $31fa referenced 1 time by $31f0
count_one:
    inc b                                                             ; 31fa: 04          .
    jp m,div_loop                                                     ; 31fb: fa d2 31    ..1
    push af                                                           ; 31fe: f5          .
    jr z,div_start                                                    ; 31ff: 28 e1       (.
    ld e,a                                                            ; 3201: 5f          _
    ld d,c                                                            ; 3202: 51          Q
    exx                                                               ; 3203: d9          .
    ld e,c                                                            ; 3204: 59          Y
    ld d,b                                                            ; 3205: 50          P
    pop af                                                            ; 3206: f1          .
    rr b                                                              ; 3207: cb 18       ..
    pop af                                                            ; 3209: f1          .
    rr b                                                              ; 320a: cb 18       ..
    exx                                                               ; 320c: d9          .
    pop bc                                                            ; 320d: c1          .
    pop hl                                                            ; 320e: e1          .
    ld a,b                                                            ; 320f: 78          x
    sub c                                                             ; 3210: 91          .
    jp divn_expt                                                      ; 3211: c3 3d 31    .=1

x80_ftrn:
    ld a,(hl)                                                         ; 3214: 7e          ~
    and a                                                             ; 3215: a7          .
    ret z                                                             ; 3216: c8          .
    cp $81                                                            ; 3217: fe 81       ..
    jr nc,fptrunct                                                    ; 3219: 30 22       0"
    ld (hl),0                                                         ; 321b: 36 00       6.
    ld a,$20                                                          ; 321d: 3e 20       >
    jr nil_bytes                                                      ; 321f: 18 51       .Q

; $3221 referenced 1 time by $302f
l3221:
    jp nz,l303c                                                       ; 3221: c2 3c 30    .<0
    sbc a,a                                                           ; 3224: 9f          .
    ld c,a                                                            ; 3225: 4f          O
    inc a                                                             ; 3226: 3c          <
    or e                                                              ; 3227: b3          .
    or d                                                              ; 3228: b2          .
    ld a,c                                                            ; 3229: 79          y
    jr nz,l3232                                                       ; 322a: 20 06        .
    dec hl                                                            ; 322c: 2b          +
    ld (hl),$91                                                       ; 322d: 36 91       6.
    inc hl                                                            ; 322f: 23          #
    and $80                                                           ; 3230: e6 80       ..
; $3232 referenced 1 time by $322a
l3232:
    jp l3032                                                          ; 3232: c3 32 30    .20

l3235:
    db $80                                                            ; 3235: 80          .
    db "Scroll", $80 + '?'                                            ; 3236: 53 63 72... Scr

; $323d referenced 1 time by $3219
fptrunct:
    cp $91                                                            ; 323d: fe 91       ..
    jr nc,x_large                                                     ; 323f: 30 2c       0,
    push de                                                           ; 3241: d5          .
    cpl                                                               ; 3242: 2f          /
    add a,$91                                                         ; 3243: c6 91       ..
    inc hl                                                            ; 3245: 23          #
    ld d,(hl)                                                         ; 3246: 56          V
    inc hl                                                            ; 3247: 23          #
    ld e,(hl)                                                         ; 3248: 5e          ^
    dec hl                                                            ; 3249: 2b          +
    dec hl                                                            ; 324a: 2b          +
    ld c,$ff                                                          ; 324b: 0e ff       ..
    bit 7,d                                                           ; 324d: cb 7a       .z
    jr nz,trunct2                                                     ; 324f: 20 01        .
    inc c                                                             ; 3251: 0c          .
; $3252 referenced 1 time by $324f
trunct2:
    set 7,d                                                           ; 3252: cb fa       ..
    ld b,8                                                            ; 3254: 06 08       ..
    sub b                                                             ; 3256: 90          .
    add a,b                                                           ; 3257: 80          .
    jr c,trunct3                                                      ; 3258: 38 04       8.
    ld e,d                                                            ; 325a: 5a          Z
    ld d,0                                                            ; 325b: 16 00       ..
    sub b                                                             ; 325d: 90          .
; $325e referenced 1 time by $3258
trunct3:
    jr z,trunct5                                                      ; 325e: 28 07       (.
    ld b,a                                                            ; 3260: 47          G
; $3261 referenced 1 time by $3265
trunct4:
    srl d                                                             ; 3261: cb 3a       .:
    rr e                                                              ; 3263: cb 1b       ..
    djnz trunct4                                                      ; 3265: 10 fa       ..
; $3267 referenced 1 time by $325e
trunct5:
    call l2d8e                                                        ; 3267: cd 8e 2d    ..-
    pop de                                                            ; 326a: d1          .
    ret                                                               ; 326b: c9          .

    db $ff                                                            ; 326c: ff          .

; $326d referenced 1 time by $323f
x_large:
    sub $a0                                                           ; 326d: d6 a0       ..
    ret p                                                             ; 326f: f0          .
    neg                                                               ; 3270: ed 44       .D
; $3272 referenced 1 time by $321f
nil_bytes:
    push de                                                           ; 3272: d5          .
    ex de,hl                                                          ; 3273: eb          .
    dec hl                                                            ; 3274: 2b          +
    ld b,a                                                            ; 3275: 47          G
    srl b                                                             ; 3276: cb 38       .8
    srl b                                                             ; 3278: cb 38       .8
    srl b                                                             ; 327a: cb 38       .8
    jr z,bits_zero                                                    ; 327c: 28 05       (.
; $327e referenced 1 time by $3281
byte_zero:
    ld (hl),0                                                         ; 327e: 36 00       6.
    dec hl                                                            ; 3280: 2b          +
    djnz byte_zero                                                    ; 3281: 10 fb       ..
; $3283 referenced 1 time by $327c
bits_zero:
    and 7                                                             ; 3283: e6 07       ..
    jr z,ix_end                                                       ; 3285: 28 09       (.
    ld b,a                                                            ; 3287: 47          G
    ld a,$ff                                                          ; 3288: 3e ff       >.
; $328a referenced 1 time by $328c
less_mask:
    sla a                                                             ; 328a: cb 27       .'
    djnz less_mask                                                    ; 328c: 10 fc       ..
    and (hl)                                                          ; 328e: a6          .
    ld (hl),a                                                         ; 328f: 77          w
; $3290 referenced 1 time by $3285
ix_end:
    ex de,hl                                                          ; 3290: eb          .
    pop de                                                            ; 3291: d1          .
    ret                                                               ; 3292: c9          .

; $3293 referenced 3 times by $303e, $30f0, $31af
l3293:
    call l3296                                                        ; 3293: cd 96 32    ..2
; $3296 referenced 1 time by $3293
l3296:
    ex de,hl                                                          ; 3296: eb          .
; $3297 referenced 1 time by $37ab
x80_frstk:
    ld a,(hl)                                                         ; 3297: 7e          ~
    and a                                                             ; 3298: a7          .
    ret nz                                                            ; 3299: c0          .
    push de                                                           ; 329a: d5          .
    call fetchi                                                       ; 329b: cd 7f 2d    ..-
    xor a                                                             ; 329e: af          .
    inc hl                                                            ; 329f: 23          #
    ld (hl),a                                                         ; 32a0: 77          w
    dec hl                                                            ; 32a1: 2b          +
    ld (hl),a                                                         ; 32a2: 77          w
    ld b,$91                                                          ; 32a3: 06 91       ..
    ld a,d                                                            ; 32a5: 7a          z
    and a                                                             ; 32a6: a7          .
    jr nz,l32b1                                                       ; 32a7: 20 08        .
    ld b,d                                                            ; 32a9: 42          B
    or e                                                              ; 32aa: b3          .
    jr z,l32bd                                                        ; 32ab: 28 10       (.
    ld d,e                                                            ; 32ad: 53          S
    ld e,b                                                            ; 32ae: 58          X
    ld b,$89                                                          ; 32af: 06 89       ..
; $32b1 referenced 1 time by $32a7
l32b1:
    ex de,hl                                                          ; 32b1: eb          .
; $32b2 referenced 1 time by $32b4
l32b2:
    dec b                                                             ; 32b2: 05          .
    add hl,hl                                                         ; 32b3: 29          )
    jr nc,l32b2                                                       ; 32b4: 30 fc       0.
    rrc c                                                             ; 32b6: cb 09       ..
    rr h                                                              ; 32b8: cb 1c       ..
    rr l                                                              ; 32ba: cb 1d       ..
    ex de,hl                                                          ; 32bc: eb          .
; $32bd referenced 1 time by $32ab
l32bd:
    dec hl                                                            ; 32bd: 2b          +
    ld (hl),e                                                         ; 32be: 73          s
    dec hl                                                            ; 32bf: 2b          +
    ld (hl),d                                                         ; 32c0: 72          r
    dec hl                                                            ; 32c1: 2b          +
    ld (hl),b                                                         ; 32c2: 70          p
    pop de                                                            ; 32c3: d1          .
    ret                                                               ; 32c4: c9          .

constants:
    db 0, 0, 0, 0, 0                                                  ; 32c5: 00 00 00... ...
    db 0, 0, 1, 0, 0                                                  ; 32ca: 00 00 01... ...
    db $80, 0, 0, 0, 0                                                ; 32cf: 80 00 00... ...
    db $81, $49, $0f, $da, $a2                                        ; 32d4: 81 49 0f... .I.
    db 0, 0, $0a, 0, 0                                                ; 32d9: 00 00 0a... ...
addresses:
    dw x80_fjpt                                                       ; 32de: 64 36       d6
    dw x80_fxch                                                       ; 32e0: 21 34       !4
    dw x80_fdel                                                       ; 32e2: a5 33       .3
    dw x80_fsub                                                       ; 32e4: 0f 30       .0
    dw x80_fmul                                                       ; 32e6: ca 30       .0
    dw x80_fdiv                                                       ; 32e8: af 31       .1
    dw x80_ftop                                                       ; 32ea: 46 38       F8
    dw x80_fbor                                                       ; 32ec: f7 34       .4
    dw x80_fband                                                      ; 32ee: 00 35       .5
    dw x80_fcp                                                        ; 32f0: 17 35       .5
    dw x80_fcp                                                        ; 32f2: 17 35       .5
    dw x80_fcp                                                        ; 32f4: 17 35       .5
    dw x80_fcp                                                        ; 32f6: 17 35       .5
    dw x80_fcp                                                        ; 32f8: 17 35       .5
    dw x80_fcp                                                        ; 32fa: 17 35       .5
    dw x80_fadd                                                       ; 32fc: 14 30       .0
    dw x80_fbands                                                     ; 32fe: 09 35       .5
    dw x80_fcp                                                        ; 3300: 17 35       .5
    dw x80_fcp                                                        ; 3302: 17 35       .5
    dw x80_fcp                                                        ; 3304: 17 35       .5
    dw x80_fcp                                                        ; 3306: 17 35       .5
    dw x80_fcp                                                        ; 3308: 17 35       .5
    dw x80_fcp                                                        ; 330a: 17 35       .5
    dw x80_fcat                                                       ; 330c: 74 35       t5
    dw x80_fval                                                       ; 330e: b1 35       .5
    dw x80_fusrs                                                      ; 3310: 9c 34       .4
    dw x80_fread                                                      ; 3312: 1c 36       .6
    dw x80_fneg                                                       ; 3314: 52 34       R4
    dw x80_fasc                                                       ; 3316: 3e 36       >6
    dw x80_fval                                                       ; 3318: b1 35       .5
    dw x80_flen                                                       ; 331a: 49 36       I6
    dw x80_fsin                                                       ; 331c: 86 37       .7
    dw x80_fcos                                                       ; 331e: 7b 37       {7
    dw x80_ftan                                                       ; 3320: f5 0d       ..
    dw x80_fasin                                                      ; 3322: fc 37       .7
    dw x80_facos                                                      ; 3324: 0c 38       .8
    dw x80_fatan                                                      ; 3326: ab 37       .7
    dw x80_flogn                                                      ; 3328: e7 36       .6
    dw x80_fexp                                                       ; 332a: 99 36       .6
    dw x80_fint                                                       ; 332c: 84 36       .6
    dw x80_fsqrt                                                      ; 332e: 13 38       .8
    dw x80_fsgn                                                       ; 3330: 72 34       r4
    dw x80_fabs                                                       ; 3332: 4e 34       N4
    dw x80_fpeek                                                      ; 3334: 8c 34       .4
    dw x80_fin                                                        ; 3336: 85 34       .4
    dw x80_fusr                                                       ; 3338: 93 34       .4
    dw x80_fstrs                                                      ; 333a: ef 35       .5
    dw x80_fchrs                                                      ; 333c: a2 35       .5
    dw x80_fnot                                                       ; 333e: dd 34       .4
    dw x80_fmove                                                      ; 3340: c4 33       .3
    dw x80_fmod                                                       ; 3342: 75 36       u6
    dw x80_fjp                                                        ; 3344: 5b 36       [6
    dw x80_fstk                                                       ; 3346: ca 33       .3
    dw x80_fdjnz                                                      ; 3348: 4f 36       O6
    dw x80_fcp_lz                                                     ; 334a: e2 34       .4
    dw x80_fcp_gz                                                     ; 334c: d5 34       .4
    dw x80_fce                                                        ; 334e: 70 36       p6
    dw x80_fget                                                       ; 3350: 55 37       U7
    dw x80_ftrn                                                       ; 3352: 14 32       .2
    dw x80_fsgl                                                       ; 3354: a6 33       .3
    dw x80_fhexs                                                      ; 3356: 63 38       c8
    dw x80_frstk                                                      ; 3358: 97 32       .2
    dw x80_fsgen                                                      ; 335a: 2d 34       -4
    dw x80_fstkc                                                      ; 335c: 0c 34       .4
    dw x80_fst                                                        ; 335e: 11 34       .4
    dw x80_fgt                                                        ; 3360: 00 34       .4

; $3362 referenced 1 time by $28
calculate:
    call stk_pntrs                                                    ; 3362: cd 97 35    ..5
; $3365 referenced 1 time by $342e
gen_ent_1:
    ld a,b                                                            ; 3365: 78          x
    ld (breg),a                                                       ; 3366: 32 67 5c    2g\
; $3369 referenced 1 time by $3441
gen_ent_2:
    exx                                                               ; 3369: d9          .
    ex (sp),hl                                                        ; 336a: e3          .
    exx                                                               ; 336b: d9          .
re_entry:
    ld (stkend),de                                                    ; 336c: ed 53 65... .Se
    exx                                                               ; 3370: d9          .
    ld a,(hl)                                                         ; 3371: 7e          ~
    inc hl                                                            ; 3372: 23          #
; $3373 referenced 1 time by $33ab
scan_ent:
    push hl                                                           ; 3373: e5          .
    and a                                                             ; 3374: a7          .
    jp p,first_38                                                     ; 3375: f2 87 33    ..3
    ld d,a                                                            ; 3378: 57          W
    and $60                                                           ; 3379: e6 60       .`
    rrca                                                              ; 337b: 0f          .
    rrca                                                              ; 337c: 0f          .
    rrca                                                              ; 337d: 0f          .
    rrca                                                              ; 337e: 0f          .
    add a,$7c                                                         ; 337f: c6 7c       .|
    ld l,a                                                            ; 3381: 6f          o
    ld a,d                                                            ; 3382: 7a          z
    and $1f                                                           ; 3383: e6 1f       ..
    jr ent_table                                                      ; 3385: 18 0b       ..

; $3387 referenced 1 time by $3375
first_38:
    cp $18                                                            ; 3387: fe 18       ..
    jr nc,double_a                                                    ; 3389: 30 05       0.
    exx                                                               ; 338b: d9          .
    call l359a                                                        ; 338c: cd 9a 35    ..5
    exx                                                               ; 338f: d9          .
; $3390 referenced 1 time by $3389
double_a:
    rlca                                                              ; 3390: 07          .
    ld l,a                                                            ; 3391: 6f          o
; $3392 referenced 1 time by $3385
ent_table:
    ld de,$32de                                                       ; 3392: 11 de 32    ..2
    ld h,0                                                            ; 3395: 26 00       &.
    add hl,de                                                         ; 3397: 19          .
    ld e,(hl)                                                         ; 3398: 5e          ^
    inc hl                                                            ; 3399: 23          #
    ld d,(hl)                                                         ; 339a: 56          V
    ld hl,$336c                                                       ; 339b: 21 6c 33    !l3
    ex (sp),hl                                                        ; 339e: e3          .
    push de                                                           ; 339f: d5          .
    exx                                                               ; 33a0: d9          .
    ld bc,(stkend+1)                                                  ; 33a1: ed 4b 66... .Kf
x80_fdel:
    ret                                                               ; 33a5: c9          .

x80_fsgl:
    pop af                                                            ; 33a6: f1          .
    ld a,(breg)                                                       ; 33a7: 3a 67 5c    :g\
    exx                                                               ; 33aa: d9          .
    jr scan_ent                                                       ; 33ab: 18 c6       ..

; $33ad referenced 3 times by $2ab7, $33c4, $33cc
test_5_sp:
    push de                                                           ; 33ad: d5          .
    push hl                                                           ; 33ae: e5          .
    ld bc,5                                                           ; 33af: 01 05 00    ...
    call test_room                                                    ; 33b2: cd 05 1f    ...
    pop hl                                                            ; 33b5: e1          .
    pop de                                                            ; 33b6: d1          .
    ret                                                               ; 33b7: c9          .

; $33b8 referenced 4 times by $0435, $26bd, $26da, $3bad
l33b8:
    ld de,(stkend)                                                    ; 33b8: ed 5b 65... .[e
    call x80_fmove                                                    ; 33bc: cd c4 33    ..3
    ld (stkend),de                                                    ; 33bf: ed 53 65... .Se
    ret                                                               ; 33c3: c9          .

; $33c4 referenced 3 times by $298a, $33bc, $3407
x80_fmove:
    call test_5_sp                                                    ; 33c4: cd ad 33    ..3
    ldir                                                              ; 33c7: ed b0       ..
    ret                                                               ; 33c9: c9          .

; $33ca referenced 1 time by $343e
x80_fstk:
    ld h,d                                                            ; 33ca: 62          b
    ld l,e                                                            ; 33cb: 6b          k
stk_const:
    call test_5_sp                                                    ; 33cc: cd ad 33    ..3
    exx                                                               ; 33cf: d9          .
    push hl                                                           ; 33d0: e5          .
    exx                                                               ; 33d1: d9          .
    ex (sp),hl                                                        ; 33d2: e3          .
    ld a,(hl)                                                         ; 33d3: 7e          ~
    and $c0                                                           ; 33d4: e6 c0       ..
    rlca                                                              ; 33d6: 07          .
    rlca                                                              ; 33d7: 07          .
    ld c,a                                                            ; 33d8: 4f          O
    inc c                                                             ; 33d9: 0c          .
    ld a,(hl)                                                         ; 33da: 7e          ~
    and $3f                                                           ; 33db: e6 3f       .?
    jr nz,form_exp                                                    ; 33dd: 20 02        .
    inc hl                                                            ; 33df: 23          #
    ld a,(hl)                                                         ; 33e0: 7e          ~
; $33e1 referenced 1 time by $33dd
form_exp:
    add a,$50                                                         ; 33e1: c6 50       .P
    ld (de),a                                                         ; 33e3: 12          .
    ld a,5                                                            ; 33e4: 3e 05       >.
    sub c                                                             ; 33e6: 91          .
    inc hl                                                            ; 33e7: 23          #
    inc de                                                            ; 33e8: 13          .
    ldir                                                              ; 33e9: ed b0       ..
    ex (sp),hl                                                        ; 33eb: e3          .
    exx                                                               ; 33ec: d9          .
    pop hl                                                            ; 33ed: e1          .
    exx                                                               ; 33ee: d9          .
    ld b,a                                                            ; 33ef: 47          G
    xor a                                                             ; 33f0: af          .
; $33f1 referenced 1 time by $33f5
stk_zeros:
    dec b                                                             ; 33f1: 05          .
    ret z                                                             ; 33f2: c8          .
    ld (de),a                                                         ; 33f3: 12          .
    inc de                                                            ; 33f4: 13          .
    jr stk_zeros                                                      ; 33f5: 18 fa       ..

; $33f7 referenced 3 times by $0432, $3404, $3416
loc_mem:
    ld c,a                                                            ; 33f7: 4f          O
    rlca                                                              ; 33f8: 07          .
    rlca                                                              ; 33f9: 07          .
    add a,c                                                           ; 33fa: 81          .
    ld c,a                                                            ; 33fb: 4f          O
    ld b,0                                                            ; 33fc: 06 00       ..
    add hl,bc                                                         ; 33fe: 09          .
    ret                                                               ; 33ff: c9          .

x80_fgt:
    ld hl,(mem)                                                       ; 3400: 2a 68 5c    *h\
; $3403 referenced 1 time by $340f
l3403:
    push de                                                           ; 3403: d5          .
    call loc_mem                                                      ; 3404: cd f7 33    ..3
    call x80_fmove                                                    ; 3407: cd c4 33    ..3
    pop hl                                                            ; 340a: e1          .
    ret                                                               ; 340b: c9          .

x80_fstkc:
    ld hl,$32c5                                                       ; 340c: 21 c5 32    !.2
    jr l3403                                                          ; 340f: 18 f2       ..

x80_fst:
    push hl                                                           ; 3411: e5          .
    ex de,hl                                                          ; 3412: eb          .
    ld hl,(mem)                                                       ; 3413: 2a 68 5c    *h\
    call loc_mem                                                      ; 3416: cd f7 33    ..3
    ex de,hl                                                          ; 3419: eb          .
    ld c,5                                                            ; 341a: 0e 05       ..
    ldir                                                              ; 341c: ed b0       ..
    ex de,hl                                                          ; 341e: eb          .
    pop hl                                                            ; 341f: e1          .
    ret                                                               ; 3420: c9          .

; $3421 referenced 1 time by $3522
x80_fxch:
    ld b,5                                                            ; 3421: 06 05       ..
; $3423 referenced 1 time by $342a
swap_byte:
    ld a,(de)                                                         ; 3423: 1a          .
    ld c,a                                                            ; 3424: 4f          O
    ld a,(hl)                                                         ; 3425: 7e          ~
    ld (de),a                                                         ; 3426: 12          .
    ld (hl),c                                                         ; 3427: 71          q
    inc hl                                                            ; 3428: 23          #
    inc de                                                            ; 3429: 13          .
    djnz swap_byte                                                    ; 342a: 10 f7       ..
    ret                                                               ; 342c: c9          .

x80_fsgen:
    ld b,a                                                            ; 342d: 47          G
    call gen_ent_1                                                    ; 342e: cd 65 33    .e3
    db $31                                                            ; 3431: 31          1  ; duplicate
    db $0f                                                            ; 3432: 0f          .  ; addition
    db $c0                                                            ; 3433: c0          .  ; st-mem-0
    db 2                                                              ; 3434: 02          .  ; delete
    db $a0                                                            ; 3435: a0          .  ; stk-zero
    db $c2                                                            ; 3436: c2          .  ; st-mem-2
g_loop:
    db $31                                                            ; 3437: 31          1  ; duplicate
    db $e0                                                            ; 3438: e0          .  ; get-mem-0
    db 4                                                              ; 3439: 04          .  ; multiply
    db $e2                                                            ; 343a: e2          .  ; get-mem-2
    db $c1                                                            ; 343b: c1          .  ; st-mem-1
    db 3                                                              ; 343c: 03          .  ; subtract
    db $38                                                            ; 343d: 38          8  ; end-calc

    call x80_fstk                                                     ; 343e: cd ca 33    ..3
    call gen_ent_2                                                    ; 3441: cd 69 33    .i3
    db $0f                                                            ; 3444: 0f          .  ; addition
    db 1                                                              ; 3445: 01          .  ; exchange
    db $c2                                                            ; 3446: c2          .  ; st-mem-2
    db 2                                                              ; 3447: 02          .  ; delete
    db $35                                                            ; 3448: 35          5  ; dec-jr-nz
    db g_loop - $                                                     ; 3449: ee          .
    db $e1                                                            ; 344a: e1          .  ; get-mem-1
    db 3                                                              ; 344b: 03          .  ; subtract
    db $38                                                            ; 344c: 38          8  ; end-calc

    ret                                                               ; 344d: c9          .

x80_fabs:
    ld b,$ff                                                          ; 344e: 06 ff       ..
    jr negate                                                         ; 3450: 18 06       ..

; $3452 referenced 1 time by $3010
x80_fneg:
    call tstzero                                                      ; 3452: cd c5 34    ..4
    ret c                                                             ; 3455: d8          .
    ld b,0                                                            ; 3456: 06 00       ..
; $3458 referenced 1 time by $3450
negate:
    ld a,(hl)                                                         ; 3458: 7e          ~
    and a                                                             ; 3459: a7          .
    jr z,l3468                                                        ; 345a: 28 0b       (.
    inc hl                                                            ; 345c: 23          #
    ld a,b                                                            ; 345d: 78          x
    and $80                                                           ; 345e: e6 80       ..
    or (hl)                                                           ; 3460: b6          .
    rla                                                               ; 3461: 17          .
    ccf                                                               ; 3462: 3f          ?
    rra                                                               ; 3463: 1f          .
    ld (hl),a                                                         ; 3464: 77          w
    dec hl                                                            ; 3465: 2b          +
    ret                                                               ; 3466: c9          .

; $3467 referenced 1 time by $345a
l3468:
    push de                                                           ; 3467: d5          .
    push hl                                                           ; 3468: e5          .
    call fetchi                                                       ; 3469: cd 7f 2d    ..-
    pop hl                                                            ; 346c: e1          .
    ld a,c                                                            ; 346d: 79          y
    or b                                                              ; 346e: b0          .
    cpl                                                               ; 346f: 2f          /
    jr l347f                                                          ; 3470: 18 0d       ..

x80_fsgn:
    call tstzero                                                      ; 3472: cd c5 34    ..4
    ret c                                                             ; 3475: d8          .
    push de                                                           ; 3476: d5          .
    ld de,1                                                           ; 3477: 11 01 00    ...
    inc hl                                                            ; 347a: 23          #
    rl (hl)                                                           ; 347b: cb 16       ..
    dec hl                                                            ; 347d: 2b          +
    sbc a,a                                                           ; 347e: 9f          .
; $347f referenced 1 time by $3470
l347f:
    ld c,a                                                            ; 347f: 4f          O
    call l2d8e                                                        ; 3480: cd 8e 2d    ..-
    pop de                                                            ; 3483: d1          .
    ret                                                               ; 3484: c9          .

x80_fin:
    call find_int                                                     ; 3485: cd 99 1e    ...
    in a,(c)                                                          ; 3488: ed 78       .x
    jr stacka                                                         ; 348a: 18 04       ..

x80_fpeek:
    call find_int                                                     ; 348c: cd 99 1e    ...
    ld a,(bc)                                                         ; 348f: 0a          .
; $3490 referenced 1 time by $348a
stacka:
    jp stack_a                                                        ; 3490: c3 28 2d    .(-

x80_fusr:
    call find_int                                                     ; 3493: cd 99 1e    ...
    ld hl,$2d2b                                                       ; 3496: 21 2b 2d    !+-
    push hl                                                           ; 3499: e5          .
    push bc                                                           ; 349a: c5          .
    ret                                                               ; 349b: c9          .

x80_fusrs:
    call stk_fetch                                                    ; 349c: cd f1 2b    ..+
    dec bc                                                            ; 349f: 0b          .
    ld a,c                                                            ; 34a0: 79          y
    or b                                                              ; 34a1: b0          .
    jr nz,invarg                                                      ; 34a2: 20 1f        .
    ld a,(de)                                                         ; 34a4: 1a          .
    call alpha                                                        ; 34a5: cd 8d 2c    ..,
    jr c,l34af                                                        ; 34a8: 38 05       8.
    sub $90                                                           ; 34aa: d6 90       ..
    jr c,invarg                                                       ; 34ac: 38 15       8.
    inc a                                                             ; 34ae: 3c          <
; $34af referenced 1 time by $34a8
l34af:
    dec a                                                             ; 34af: 3d          =
    add a,a                                                           ; 34b0: 87          .
    add a,a                                                           ; 34b1: 87          .
    add a,a                                                           ; 34b2: 87          .
    cp $a8                                                            ; 34b3: fe a8       ..
    jr nc,invarg                                                      ; 34b5: 30 0c       0.
    ld bc,(udg)                                                       ; 34b7: ed 4b 7b... .K{
    add a,c                                                           ; 34bb: 81          .
    ld c,a                                                            ; 34bc: 4f          O
    jr nc,l34c0                                                       ; 34bd: 30 01       0.
    inc b                                                             ; 34bf: 04          .
; $34c0 referenced 1 time by $34bd
l34c0:
    jp stack_bc1                                                      ; 34c0: c3 2f 2d    ./-

; $34c3 referenced 3 times by $34a2, $34ac, $34b5
invarg:
    rst $08                                                           ; 34c3: cf          .
    db 9                                                              ; 34c4: 09          .  ; Report A Invalid argument

; $34c5 referenced 9 times by $1cfa, $30c0, $3452, $3472, $34d5, $34dd, $34f8, $3501, $350a
tstzero:
    push bc                                                           ; 34c5: c5          .
    push hl                                                           ; 34c6: e5          .
    ld c,a                                                            ; 34c7: 4f          O
    ld a,(hl)                                                         ; 34c8: 7e          ~
    inc hl                                                            ; 34c9: 23          #
    or (hl)                                                           ; 34ca: b6          .
    inc hl                                                            ; 34cb: 23          #
    or (hl)                                                           ; 34cc: b6          .
    inc hl                                                            ; 34cd: 23          #
    or (hl)                                                           ; 34ce: b6          .
    ld a,c                                                            ; 34cf: 79          y
    pop hl                                                            ; 34d0: e1          .
    pop bc                                                            ; 34d1: c1          .
    ret nz                                                            ; 34d2: c0          .
    scf                                                               ; 34d3: 37          7
    ret                                                               ; 34d4: c9          .

; $34d5 referenced 1 time by $356b
x80_fcp_gz:
    call tstzero                                                      ; 34d5: cd c5 34    ..4
    ret c                                                             ; 34d8: d8          .
    ld a,$ff                                                          ; 34d9: 3e ff       >.
    jr sign_to_c                                                      ; 34db: 18 06       ..

; $34dd referenced 2 times by $3566, $3570
x80_fnot:
    call tstzero                                                      ; 34dd: cd c5 34    ..4
    jr fp_0_1                                                         ; 34e0: 18 05       ..

x80_fcp_lz:
    xor a                                                             ; 34e2: af          .
; $34e3 referenced 1 time by $34db
sign_to_c:
    inc hl                                                            ; 34e3: 23          #
    xor (hl)                                                          ; 34e4: ae          .
    dec hl                                                            ; 34e5: 2b          +
    rlca                                                              ; 34e6: 07          .
; $34e7 referenced 4 times by $2d59, $34e0, $34fe, $3507
fp_0_1:
    push hl                                                           ; 34e7: e5          .
    ld a,0                                                            ; 34e8: 3e 00       >.
    ld (hl),a                                                         ; 34ea: 77          w
    inc hl                                                            ; 34eb: 23          #
    ld (hl),a                                                         ; 34ec: 77          w
    inc hl                                                            ; 34ed: 23          #
    rla                                                               ; 34ee: 17          .
    ld (hl),a                                                         ; 34ef: 77          w
    rra                                                               ; 34f0: 1f          .
    inc hl                                                            ; 34f1: 23          #
    ld (hl),a                                                         ; 34f2: 77          w
    inc hl                                                            ; 34f3: 23          #
    ld (hl),a                                                         ; 34f4: 77          w
    pop hl                                                            ; 34f5: e1          .
    ret                                                               ; 34f6: c9          .

x80_fbor:
    ex de,hl                                                          ; 34f7: eb          .
    call tstzero                                                      ; 34f8: cd c5 34    ..4
    ex de,hl                                                          ; 34fb: eb          .
    ret c                                                             ; 34fc: d8          .
    scf                                                               ; 34fd: 37          7
    jr fp_0_1                                                         ; 34fe: 18 e7       ..

x80_fband:
    ex de,hl                                                          ; 3500: eb          .
    call tstzero                                                      ; 3501: cd c5 34    ..4
    ex de,hl                                                          ; 3504: eb          .
    ret nc                                                            ; 3505: d0          .
    and a                                                             ; 3506: a7          .
    jr fp_0_1                                                         ; 3507: 18 de       ..

x80_fbands:
    ex de,hl                                                          ; 3509: eb          .
    call tstzero                                                      ; 350a: cd c5 34    ..4
    ex de,hl                                                          ; 350d: eb          .
    ret nc                                                            ; 350e: d0          .
    dec de                                                            ; 350f: 1b          .
    xor a                                                             ; 3510: af          .
    ld (de),a                                                         ; 3511: 12          .
    dec de                                                            ; 3512: 1b          .
    ld (de),a                                                         ; 3513: 12          .
    inc de                                                            ; 3514: 13          .
    inc de                                                            ; 3515: 13          .
    ret                                                               ; 3516: c9          .

x80_fcp:
    ld a,b                                                            ; 3517: 78          x
    bit 2,a                                                           ; 3518: cb 57       .W
    jr nz,ex_or_not                                                   ; 351a: 20 01        .
    dec a                                                             ; 351c: 3d          =
; $351d referenced 1 time by $351a
ex_or_not:
    rrca                                                              ; 351d: 0f          .
    jr nc,nu_or_str                                                   ; 351e: 30 08       0.
    push af                                                           ; 3520: f5          .
    push hl                                                           ; 3521: e5          .
    call x80_fxch                                                     ; 3522: cd 21 34    .!4
    pop de                                                            ; 3525: d1          .
    ex de,hl                                                          ; 3526: eb          .
    pop af                                                            ; 3527: f1          .
; $3528 referenced 1 time by $351e
nu_or_str:
    rrca                                                              ; 3528: 0f          .
    push af                                                           ; 3529: f5          .
    bit 2,a                                                           ; 352a: cb 57       .W
    jr nz,strings                                                     ; 352c: 20 05        .
    call x80_fsub                                                     ; 352e: cd 0f 30    ..0
    jr end_tests                                                      ; 3531: 18 31       .1

; $3533 referenced 1 time by $352c
strings:
    call stk_fetch                                                    ; 3533: cd f1 2b    ..+
    push de                                                           ; 3536: d5          .
    push bc                                                           ; 3537: c5          .
    call stk_fetch                                                    ; 3538: cd f1 2b    ..+
    pop hl                                                            ; 353b: e1          .
; $353c referenced 1 time by $355b
byte_comp:
    ld a,h                                                            ; 353c: 7c          |
    or l                                                              ; 353d: b5          .
    ex (sp),hl                                                        ; 353e: e3          .
    ld a,b                                                            ; 353f: 78          x
    jr nz,sec_plus                                                    ; 3540: 20 0b        .
    or c                                                              ; 3542: b1          .
; $3543 referenced 1 time by $3554
secnd_low:
    pop bc                                                            ; 3543: c1          .
    jr z,both_null                                                    ; 3544: 28 04       (.
    pop af                                                            ; 3546: f1          .
    ccf                                                               ; 3547: 3f          ?
    jr str_test                                                       ; 3548: 18 16       ..

; $354a referenced 1 time by $3544
both_null:
    pop af                                                            ; 354a: f1          .
    jr str_test                                                       ; 354b: 18 13       ..

; $354d referenced 1 time by $3540
sec_plus:
    or c                                                              ; 354d: b1          .
    jr z,frst_less                                                    ; 354e: 28 0d       (.
    ld a,(de)                                                         ; 3550: 1a          .
    sub (hl)                                                          ; 3551: 96          .
    jr c,frst_less                                                    ; 3552: 38 09       8.
    jr nz,secnd_low                                                   ; 3554: 20 ed        .
    dec bc                                                            ; 3556: 0b          .
    inc de                                                            ; 3557: 13          .
    inc hl                                                            ; 3558: 23          #
    ex (sp),hl                                                        ; 3559: e3          .
    dec hl                                                            ; 355a: 2b          +
    jr byte_comp                                                      ; 355b: 18 df       ..

; $355d referenced 2 times by $354e, $3552
frst_less:
    pop bc                                                            ; 355d: c1          .
    pop af                                                            ; 355e: f1          .
    and a                                                             ; 355f: a7          .
; $3560 referenced 2 times by $3548, $354b
str_test:
    push af                                                           ; 3560: f5          .
    rst $28                                                           ; 3561: ef          .
    db $a0                                                            ; 3562: a0          .  ; stk-zero
    db $38                                                            ; 3563: 38          8  ; end-calc

; $3564 referenced 1 time by $3531
end_tests:
    pop af                                                            ; 3564: f1          .
    push af                                                           ; 3565: f5          .
    call c,x80_fnot                                                   ; 3566: dc dd 34    ..4
    pop af                                                            ; 3569: f1          .
    push af                                                           ; 356a: f5          .
    call nc,x80_fcp_gz                                                ; 356b: d4 d5 34    ..4
    pop af                                                            ; 356e: f1          .
    rrca                                                              ; 356f: 0f          .
    call nc,x80_fnot                                                  ; 3570: d4 dd 34    ..4
    ret                                                               ; 3573: c9          .

x80_fcat:
    call stk_fetch                                                    ; 3574: cd f1 2b    ..+
    push de                                                           ; 3577: d5          .
    push bc                                                           ; 3578: c5          .
    call stk_fetch                                                    ; 3579: cd f1 2b    ..+
    pop hl                                                            ; 357c: e1          .
    push hl                                                           ; 357d: e5          .
    push de                                                           ; 357e: d5          .
    push bc                                                           ; 357f: c5          .
    add hl,bc                                                         ; 3580: 09          .
    ld b,h                                                            ; 3581: 44          D
    ld c,l                                                            ; 3582: 4d          M
    rst $30                                                           ; 3583: f7          .
    call stk_store                                                    ; 3584: cd b2 2a    ..*
    pop bc                                                            ; 3587: c1          .
    pop hl                                                            ; 3588: e1          .
    ld a,b                                                            ; 3589: 78          x
    or c                                                              ; 358a: b1          .
    jr z,other_str                                                    ; 358b: 28 02       (.
    ldir                                                              ; 358d: ed b0       ..
; $358f referenced 1 time by $358b
other_str:
    pop bc                                                            ; 358f: c1          .
    pop hl                                                            ; 3590: e1          .
    ld a,b                                                            ; 3591: 78          x
    or c                                                              ; 3592: b1          .
    jr z,stk_pntrs                                                    ; 3593: 28 02       (.
    ldir                                                              ; 3595: ed b0       ..
; $3597 referenced 5 times by $3362, $3593, $35ed, $363b, $387f
stk_pntrs:
    ld hl,(stkend)                                                    ; 3597: 2a 65 5c    *e\
; $359a referenced 1 time by $338c
l359a:
    ld d,h                                                            ; 359a: 54          T
    ld e,l                                                            ; 359b: 5d          ]
    dec hl                                                            ; 359c: 2b          +
    dec hl                                                            ; 359d: 2b          +
    dec hl                                                            ; 359e: 2b          +
    dec hl                                                            ; 359f: 2b          +
    dec hl                                                            ; 35a0: 2b          +
    ret                                                               ; 35a1: c9          .

x80_fchrs:
    call fp_to_a                                                      ; 35a2: cd d5 2d    ..-
    jr c,report_b2                                                    ; 35a5: 38 08       8.
    jr nz,report_b2                                                   ; 35a7: 20 06        .
    call bc_spaces1                                                   ; 35a9: cd 2d 00    .-.
    ld (de),a                                                         ; 35ac: 12          .
    jr x360f                                                          ; 35ad: 18 68       .h

; $35af referenced 4 times by $35a5, $35a7, $3866, $3869
report_b2:
    rst $08                                                           ; 35af: cf          .
    db $0a                                                            ; 35b0: 0a          .  ; Report B Integer out of range

x80_fval:
    rst $18                                                           ; 35b1: df          .
    push hl                                                           ; 35b2: e5          .
    ld a,b                                                            ; 35b3: 78          x
    add a,$e3                                                         ; 35b4: c6 e3       ..
    sbc a,a                                                           ; 35b6: 9f          .
    push af                                                           ; 35b7: f5          .
    call stk_fetch                                                    ; 35b8: cd f1 2b    ..+
    push de                                                           ; 35bb: d5          .
    inc bc                                                            ; 35bc: 03          .
    rst $30                                                           ; 35bd: f7          .
    pop hl                                                            ; 35be: e1          .
    ld (ch_add),de                                                    ; 35bf: ed 53 5d... .S]
    push de                                                           ; 35c3: d5          .
    ldir                                                              ; 35c4: ed b0       ..
    ex de,hl                                                          ; 35c6: eb          .
    dec hl                                                            ; 35c7: 2b          +
    ld (hl),$0d                                                       ; 35c8: 36 0d       6.
    res 7,(iy+flags - err_nr)                                         ; 35ca: fd cb 01... ...
    call scanning                                                     ; 35ce: cd fb 24    ..$
    cp $0d                                                            ; 35d1: fe 0d       ..
    jr nz,l35dc                                                       ; 35d3: 20 07        .
    pop hl                                                            ; 35d5: e1          .
    pop af                                                            ; 35d6: f1          .
    xor (iy+flags - err_nr)                                           ; 35d7: fd ae 01    ...
    and $40                                                           ; 35da: e6 40       .@
; $35dc referenced 1 time by $35d3
l35dc:
    jp nz,report_c                                                    ; 35dc: c2 8a 1c    ...
    ld (ch_add),hl                                                    ; 35df: 22 5d 5c    "]\
    set 7,(iy+flags - err_nr)                                         ; 35e2: fd cb 01... ...
    call scanning                                                     ; 35e6: cd fb 24    ..$
    pop hl                                                            ; 35e9: e1          .
    ld (ch_add),hl                                                    ; 35ea: 22 5d 5c    "]\
    jr stk_pntrs                                                      ; 35ed: 18 a8       ..

x80_fstrs:
    ld a,(attr_t)                                                     ; 35ef: 3a 8f 5c    :.\
    ex af,af'                                                         ; 35f2: 08          .
    call bc_spaces1                                                   ; 35f3: cd 2d 00    .-.
    ld (k_cur),hl                                                     ; 35f6: 22 5b 5c    "[\
    push hl                                                           ; 35f9: e5          .
    ld hl,(curchl)                                                    ; 35fa: 2a 51 5c    *Q\
    push hl                                                           ; 35fd: e5          .
    ld a,$ff                                                          ; 35fe: 3e ff       >.
    call l1601                                                        ; 3600: cd 01 16    ...
    call print_fp                                                     ; 3603: cd e3 2d    ..-
    pop hl                                                            ; 3606: e1          .
    call chanflag                                                     ; 3607: cd 15 16    ...
    ex af,af'                                                         ; 360a: 08          .
    ld (attr_t),a                                                     ; 360b: 32 8f 5c    2.\
    pop de                                                            ; 360e: d1          .
    ld hl,(k_cur)                                                     ; 360f: 2a 5b 5c    *[\
    and a                                                             ; 3612: a7          .
    sbc hl,de                                                         ; 3613: ed 52       .R
    ld b,h                                                            ; 3615: 44          D
    ld c,l                                                            ; 3616: 4d          M
; $3617 referenced 1 time by $35ad
x360f:
    call stk_store                                                    ; 3617: cd b2 2a    ..*
    ex de,hl                                                          ; 361a: eb          .
    ret                                                               ; 361b: c9          .

x80_fread:
    ld hl,(curchl)                                                    ; 361c: 2a 51 5c    *Q\
    push hl                                                           ; 361f: e5          .
    call l207c                                                        ; 3620: cd 7c 20    .|
    call chltchk                                                      ; 3623: cd d6 21    ..!
    jr nz,x3621                                                       ; 3626: 20 01        .
    halt                                                              ; 3628: 76          v
; $3629 referenced 1 time by $3626
x3621:
    call inputad                                                      ; 3629: cd e6 15    ...
    ld bc,0                                                           ; 362c: 01 00 00    ...
    jr nc,x362c                                                       ; 362f: 30 03       0.
    inc c                                                             ; 3631: 0c          .
    rst $30                                                           ; 3632: f7          .
    ld (de),a                                                         ; 3633: 12          .
; $3634 referenced 1 time by $362f
x362c:
    call stk_store                                                    ; 3634: cd b2 2a    ..*
    pop hl                                                            ; 3637: e1          .
    call chanflag                                                     ; 3638: cd 15 16    ...
    jp stk_pntrs                                                      ; 363b: c3 97 35    ..5

x80_fasc:
    call stk_fetch                                                    ; 363e: cd f1 2b    ..+
    ld a,b                                                            ; 3641: 78          x
    or c                                                              ; 3642: b1          .
    jr z,stk_code                                                     ; 3643: 28 01       (.
    ld a,(de)                                                         ; 3645: 1a          .
; $3646 referenced 1 time by $3643
stk_code:
    jp stack_a                                                        ; 3646: c3 28 2d    .(-

x80_flen:
    call stk_fetch                                                    ; 3649: cd f1 2b    ..+
    jp stack_bc1                                                      ; 364c: c3 2f 2d    ./-

x80_fdjnz:
    exx                                                               ; 364f: d9          .
    push hl                                                           ; 3650: e5          .
    ld hl,$5c67                                                       ; 3651: 21 67 5c    !g\
    dec (hl)                                                          ; 3654: 35          5
    pop hl                                                            ; 3655: e1          .
    jr nz,jump_2                                                      ; 3656: 20 04        .
    inc hl                                                            ; 3658: 23          #
    exx                                                               ; 3659: d9          .
    ret                                                               ; 365a: c9          .

; $365b referenced 1 time by $366a
x80_fjp:
    exx                                                               ; 365b: d9          .
; $365c referenced 1 time by $3656
jump_2:
    ld e,(hl)                                                         ; 365c: 5e          ^
    ld a,e                                                            ; 365d: 7b          {
    rla                                                               ; 365e: 17          .
    sbc a,a                                                           ; 365f: 9f          .
    ld d,a                                                            ; 3660: 57          W
    add hl,de                                                         ; 3661: 19          .
    exx                                                               ; 3662: d9          .
    ret                                                               ; 3663: c9          .

x80_fjpt:
    inc de                                                            ; 3664: 13          .
    inc de                                                            ; 3665: 13          .
    ld a,(de)                                                         ; 3666: 1a          .
    dec de                                                            ; 3667: 1b          .
    dec de                                                            ; 3668: 1b          .
    and a                                                             ; 3669: a7          .
    jr nz,x80_fjp                                                     ; 366a: 20 ef        .
    exx                                                               ; 366c: d9          .
    inc hl                                                            ; 366d: 23          #
    exx                                                               ; 366e: d9          .
    ret                                                               ; 366f: c9          .

x80_fce:
    pop af                                                            ; 3670: f1          .
    exx                                                               ; 3671: d9          .
    ex (sp),hl                                                        ; 3672: e3          .
    exx                                                               ; 3673: d9          .
    ret                                                               ; 3674: c9          .

x80_fmod:
    rst $28                                                           ; 3675: ef          .
    db $c1                                                            ; 3676: c1          .  ; st-mem-1
    db 2                                                              ; 3677: 02          .  ; delete
    db $31                                                            ; 3678: 31          1  ; duplicate
    db $e1                                                            ; 3679: e1          .  ; get-mem-1
    db 5                                                              ; 367a: 05          .  ; division
    db $27                                                            ; 367b: 27          '  ; int
    db $e1                                                            ; 367c: e1          .  ; get-mem-1
    db 1                                                              ; 367d: 01          .  ; exchange
    db $c1                                                            ; 367e: c1          .  ; st-mem-1
    db 4                                                              ; 367f: 04          .  ; multiply
    db 3                                                              ; 3680: 03          .  ; subtract
    db $e1                                                            ; 3681: e1          .  ; get-mem-1
    db $38                                                            ; 3682: 38          8  ; end-calc

    ret                                                               ; 3683: c9          .

x80_fint:
    rst $28                                                           ; 3684: ef          .
    db $31                                                            ; 3685: 31          1  ; duplicate
    db $36                                                            ; 3686: 36          6  ; less-0
    db 0                                                              ; 3687: 00          .  ; jump-true
    db x_neg - $                                                      ; 3688: 04          .
    db $3a                                                            ; 3689: 3a          :  ; truncate
    db $38                                                            ; 368a: 38          8  ; end-calc

    ret                                                               ; 368b: c9          .

x_neg:
    db $31                                                            ; 368c: 31          1  ; duplicate
    db $3a                                                            ; 368d: 3a          :  ; truncate
    db $c0                                                            ; 368e: c0          .  ; st-mem-0
    db 3                                                              ; 368f: 03          .  ; subtract
    db $e0                                                            ; 3690: e0          .  ; get-mem-0
    db 1                                                              ; 3691: 01          .  ; exchange
    db $30                                                            ; 3692: 30          0  ; not
    db 0                                                              ; 3693: 00          .  ; jump-true
    db exit - $                                                       ; 3694: 03          .
    db $a1                                                            ; 3695: a1          .  ; stk-one
    db 3                                                              ; 3696: 03          .  ; subtract
exit:
    db $38                                                            ; 3697: 38          8  ; end-calc

    ret                                                               ; 3698: c9          .

; $3699 referenced 1 time by $384f
x80_fexp:
    rst $28                                                           ; 3699: ef          .
    db $34                                                            ; 369a: 34          4  ; stk-data
    db $f1, $38, $aa, $3b, $29                                        ; 369b: f1 38 aa... .8. ; 1.442695041
    db 4                                                              ; 36a0: 04          .  ; multiply
    db $31                                                            ; 36a1: 31          1  ; duplicate
    db $27                                                            ; 36a2: 27          '  ; int
    db $c3                                                            ; 36a3: c3          .  ; st-mem-3
    db 3                                                              ; 36a4: 03          .  ; subtract
    db $31                                                            ; 36a5: 31          1  ; duplicate
    db $0f                                                            ; 36a6: 0f          .  ; addition
    db $a1                                                            ; 36a7: a1          .  ; stk-one
    db 3                                                              ; 36a8: 03          .  ; subtract
    db $88                                                            ; 36a9: 88          .  ; series-08
    db $13, $36                                                       ; 36aa: 13 36       .6 ; 1.324224286e-09
    db $58, $65, $66                                                  ; 36ac: 58 65 66    Xef ; 5.341098586e-08
    db $9d, $78, $65, $40                                             ; 36af: 9d 78 65... .xe ; 1.850690751e-06
    db $a2, $60, $32, $c9                                             ; 36b3: a2 60 32... .`2 ; 5.345305908e-05
    db $e7, $21, $f7, $af, $24                                        ; 36b7: e7 21 f7... .!. ; 0.001235714082
    db $eb, $2f, $b0, $b0, $14                                        ; 36bc: eb 2f b0... ./. ; 0.021446556
    db $ee, $7e, $bb, $94, $58                                        ; 36c1: ee 7e bb... .~. ; 0.2487624339
    db $f1, $3a, $7e, $f8, $cf                                        ; 36c6: f1 3a 7e... .:~ ; 1.456999875
    db $e3                                                            ; 36cb: e3          .  ; get-mem-3
    db $38                                                            ; 36cc: 38          8  ; end-calc

    call fp_to_a                                                      ; 36cd: cd d5 2d    ..-
    jr nz,n_negtv                                                     ; 36d0: 20 07        .
    jr c,report6_2                                                    ; 36d2: 38 03       8.
    add a,(hl)                                                        ; 36d4: 86          .
    jr nc,result_ok                                                   ; 36d5: 30 09       0.
; $36d7 referenced 1 time by $36d2
report6_2:
    rst $08                                                           ; 36d7: cf          .
    db 5                                                              ; 36d8: 05          .  ; Report 6 Number too big

; $36d9 referenced 1 time by $36d0
n_negtv:
    jr c,rslt_zero                                                    ; 36d9: 38 07       8.
    sub (hl)                                                          ; 36db: 96          .
    jr nc,rslt_zero                                                   ; 36dc: 30 04       0.
    neg                                                               ; 36de: ed 44       .D
; $36e0 referenced 1 time by $36d5
result_ok:
    ld (hl),a                                                         ; 36e0: 77          w
    ret                                                               ; 36e1: c9          .

; $36e2 referenced 2 times by $36d9, $36dc
rslt_zero:
    rst $28                                                           ; 36e2: ef          .
    db 2                                                              ; 36e3: 02          .  ; delete
    db $a0                                                            ; 36e4: a0          .  ; stk-zero
    db $38                                                            ; 36e5: 38          8  ; end-calc

    ret                                                               ; 36e6: c9          .

x80_flogn:
    rst $28                                                           ; 36e7: ef          .
    db $3d                                                            ; 36e8: 3d          =  ; re-stack
    db $31                                                            ; 36e9: 31          1  ; duplicate
    db $37                                                            ; 36ea: 37          7  ; greater-0
    db 0                                                              ; 36eb: 00          .  ; jump-true
    db valid - $                                                      ; 36ec: 04          .
    db $38                                                            ; 36ed: 38          8  ; end-calc

; $36ee referenced 1 time by $381d
x36e6:
    rst $08                                                           ; 36ee: cf          .
    db 9                                                              ; 36ef: 09          .  ; Report A Invalid argument
valid:
    db $38                                                            ; 36f0: 38          8  ; end-calc

    ld a,(hl)                                                         ; 36f1: 7e          ~
    ld (hl),$80                                                       ; 36f2: 36 80       6.
    call stack_a                                                      ; 36f4: cd 28 2d    .(-
    rst $28                                                           ; 36f7: ef          .
    db $34                                                            ; 36f8: 34          4  ; stk-data
    db $38, 0                                                         ; 36f9: 38 00       8. ; 128
    db 3                                                              ; 36fb: 03          .  ; subtract
    db 1                                                              ; 36fc: 01          .  ; exchange
    db $31                                                            ; 36fd: 31          1  ; duplicate
    db $34                                                            ; 36fe: 34          4  ; stk-data
    db $f0, $4c, $cc, $cc, $cd                                        ; 36ff: f0 4c cc... .L. ; 0.8
    db 3                                                              ; 3704: 03          .  ; subtract
    db $37                                                            ; 3705: 37          7  ; greater-0
    db 0                                                              ; 3706: 00          .  ; jump-true
    db gre_8 - $                                                      ; 3707: 08          .
    db 1                                                              ; 3708: 01          .  ; exchange
    db $a1                                                            ; 3709: a1          .  ; stk-one
    db 3                                                              ; 370a: 03          .  ; subtract
    db 1                                                              ; 370b: 01          .  ; exchange
    db $38                                                            ; 370c: 38          8  ; end-calc

    inc (hl)                                                          ; 370d: 34          4
    rst $28                                                           ; 370e: ef          .
gre_8:
    db 1                                                              ; 370f: 01          .  ; exchange
    db $34                                                            ; 3710: 34          4  ; stk-data
    db $f0, $31, $72, $17, $f8                                        ; 3711: f0 31 72... .1r ; 0.6931471806
    db 4                                                              ; 3716: 04          .  ; multiply
    db 1                                                              ; 3717: 01          .  ; exchange
    db $a2                                                            ; 3718: a2          .  ; stk-half
    db 3                                                              ; 3719: 03          .  ; subtract
    db $a2                                                            ; 371a: a2          .  ; stk-half
    db 3                                                              ; 371b: 03          .  ; subtract
    db $31                                                            ; 371c: 31          1  ; duplicate
    db $34                                                            ; 371d: 34          4  ; stk-data
    db $32, $20                                                       ; 371e: 32 20       2  ; 2.5
    db 4                                                              ; 3720: 04          .  ; multiply
    db $a2                                                            ; 3721: a2          .  ; stk-half
    db 3                                                              ; 3722: 03          .  ; subtract
    db $8c                                                            ; 3723: 8c          .  ; series-0C
    db $11, $ac                                                       ; 3724: 11 ac       .. ; -3.128661774e-10
    db $14, 9                                                         ; 3726: 14 09       .. ; 1.993612386e-09
    db $56, $da, $a5                                                  ; 3728: 56 da a5    V.. ; -1.272678674e-08
    db $59, $30, $c5                                                  ; 372b: 59 30 c5    Y0. ; 8.231472748e-08
    db $5c, $90, $aa                                                  ; 372e: 5c 90 aa    \.. ; -5.389156286e-07
    db $9e, $70, $6f, $61                                             ; 3731: 9e 70 6f... .po ; 3.582761792e-06
    db $a1, $cb, $da, $96                                             ; 3735: a1 cb da... ... ; -2.430127279e-05
    db $a4, $31, $9f, $b4                                             ; 3739: a4 31 9f... .1. ; 0.0001693952945
    db $e7, $a0, $fe, $5c, $fc                                        ; 373d: e7 a0 fe... ... ; -0.00122828374
    db $ea, $1b, $43, $ca, $36                                        ; 3742: ea 1b 43... ..C ; 0.009476611587
    db $ed, $a7, $9c, $7e, $5e                                        ; 3747: ed a7 9c... ... ; -0.08184145665
    db $f0, $6e, $23, $80, $93                                        ; 374c: f0 6e 23... .n# ; 0.9302292212
    db 4                                                              ; 3751: 04          .  ; multiply
    db $0f                                                            ; 3752: 0f          .  ; addition
    db $38                                                            ; 3753: 38          8  ; end-calc

    ret                                                               ; 3754: c9          .

x80_fget:
    rst $28                                                           ; 3755: ef          .
    db $34                                                            ; 3756: 34          4  ; stk-data
    db $ee, $22, $f9, $83, $6e                                        ; 3757: ee 22 f9... .". ; 0.1591549431
    db 4                                                              ; 375c: 04          .  ; multiply
    db $31                                                            ; 375d: 31          1  ; duplicate
    db $a2                                                            ; 375e: a2          .  ; stk-half
    db $0f                                                            ; 375f: 0f          .  ; addition
    db $27                                                            ; 3760: 27          '  ; int
    db 3                                                              ; 3761: 03          .  ; subtract
    db $31                                                            ; 3762: 31          1  ; duplicate
    db $0f                                                            ; 3763: 0f          .  ; addition
    db $31                                                            ; 3764: 31          1  ; duplicate
    db $0f                                                            ; 3765: 0f          .  ; addition
    db $31                                                            ; 3766: 31          1  ; duplicate
    db $2a                                                            ; 3767: 2a          *  ; abs
    db $a1                                                            ; 3768: a1          .  ; stk-one
    db 3                                                              ; 3769: 03          .  ; subtract
    db $31                                                            ; 376a: 31          1  ; duplicate
    db $37                                                            ; 376b: 37          7  ; greater-0
    db $c0                                                            ; 376c: c0          .  ; st-mem-0
    db 0                                                              ; 376d: 00          .  ; jump-true
    db zplus - $                                                      ; 376e: 04          .
    db 2                                                              ; 376f: 02          .  ; delete
    db $38                                                            ; 3770: 38          8  ; end-calc

    ret                                                               ; 3771: c9          .

zplus:
    db $a1                                                            ; 3772: a1          .  ; stk-one
    db 3                                                              ; 3773: 03          .  ; subtract
    db 1                                                              ; 3774: 01          .  ; exchange
    db $36                                                            ; 3775: 36          6  ; less-0
    db 0                                                              ; 3776: 00          .  ; jump-true
    db yneg - $                                                       ; 3777: 02          .
    db $1b                                                            ; 3778: 1b          .  ; negate
yneg:
    db $38                                                            ; 3779: 38          8  ; end-calc

    ret                                                               ; 377a: c9          .

x80_fcos:
    rst $28                                                           ; 377b: ef          .
    db $39                                                            ; 377c: 39          9  ; get-argt
    db $2a                                                            ; 377d: 2a          *  ; abs
    db $a1                                                            ; 377e: a1          .  ; stk-one
    db 3                                                              ; 377f: 03          .  ; subtract
    db $e0                                                            ; 3780: e0          .  ; get-mem-0
    db 0                                                              ; 3781: 00          .  ; jump-true
    db c_ent - $                                                      ; 3782: 06          .
    db $1b                                                            ; 3783: 1b          .  ; negate
    db $33                                                            ; 3784: 33          3  ; jump
    db c_ent - $                                                      ; 3785: 03          .

x80_fsin:
    rst $28                                                           ; 3786: ef          .
    db $39                                                            ; 3787: 39          9  ; get-argt
c_ent:
    db $31                                                            ; 3788: 31          1  ; duplicate
    db $31                                                            ; 3789: 31          1  ; duplicate
    db 4                                                              ; 378a: 04          .  ; multiply
    db $31                                                            ; 378b: 31          1  ; duplicate
    db $0f                                                            ; 378c: 0f          .  ; addition
    db $a1                                                            ; 378d: a1          .  ; stk-one
    db 3                                                              ; 378e: 03          .  ; subtract
    db $86                                                            ; 378f: 86          .  ; series-06
    db $14, $e6                                                       ; 3790: 14 e6       .. ; -3.346940503e-09
    db $5c, $1f, $0b                                                  ; 3792: 5c 1f 0b    \.. ; 5.924812285e-07
    db $a3, $8f, $38, $ee                                             ; 3795: a3 8f 38... ..8 ; -6.829375343e-05
    db $e9, $15, $63, $bb, $23                                        ; 3799: e9 15 63... ..c ; 0.004559008003
    db $ee, $92, $0d, $cd, $ed                                        ; 379e: ee 92 0d... ... ; -0.1426307846
    db $f1, $23, $5d, $1b, $ea                                        ; 37a3: f1 23 5d... .#] ; 1.276278962
    db 4                                                              ; 37a8: 04          .  ; multiply
    db $38                                                            ; 37a9: 38          8  ; end-calc

    ret                                                               ; 37aa: c9          .

x80_fatan:
    call x80_frstk                                                    ; 37ab: cd 97 32    ..2
    ld a,(hl)                                                         ; 37ae: 7e          ~
    cp $81                                                            ; 37af: fe 81       ..
    jr c,small                                                        ; 37b1: 38 0e       8.
    rst $28                                                           ; 37b3: ef          .
    db $a1                                                            ; 37b4: a1          .  ; stk-one
    db $1b                                                            ; 37b5: 1b          .  ; negate
    db 1                                                              ; 37b6: 01          .  ; exchange
    db 5                                                              ; 37b7: 05          .  ; division
    db $31                                                            ; 37b8: 31          1  ; duplicate
    db $36                                                            ; 37b9: 36          6  ; less-0
    db $a3                                                            ; 37ba: a3          .  ; stk-pi/2
    db 1                                                              ; 37bb: 01          .  ; exchange
    db 0                                                              ; 37bc: 00          .  ; jump-true
    db cases - $                                                      ; 37bd: 06          .
    db $1b                                                            ; 37be: 1b          .  ; negate
    db $33                                                            ; 37bf: 33          3  ; jump
    db cases - $                                                      ; 37c0: 03          .

; $37c1 referenced 1 time by $37b1
small:
    rst $28                                                           ; 37c1: ef          .
    db $a0                                                            ; 37c2: a0          .  ; stk-zero
cases:
    db 1                                                              ; 37c3: 01          .  ; exchange
    db $31                                                            ; 37c4: 31          1  ; duplicate
    db $31                                                            ; 37c5: 31          1  ; duplicate
    db 4                                                              ; 37c6: 04          .  ; multiply
    db $31                                                            ; 37c7: 31          1  ; duplicate
    db $0f                                                            ; 37c8: 0f          .  ; addition
    db $a1                                                            ; 37c9: a1          .  ; stk-one
    db 3                                                              ; 37ca: 03          .  ; subtract
    db $8c                                                            ; 37cb: 8c          .  ; series-0C
    db $10, $b2                                                       ; 37cc: 10 b2       .. ; -1.618900569e-10
    db $13, $0e                                                       ; 37ce: 13 0e       .. ; 1.033185981e-09
    db $55, $e4, $8d                                                  ; 37d0: 55 e4 8d    U.. ; -6.651703188e-09
    db $58, $39, $bc                                                  ; 37d3: 58 39 bc    X9. ; 4.324465408e-08
    db $5b, $98, $fd                                                  ; 37d6: 5b 98 fd    [.. ; -2.8496288e-07
    db $9e, 0, $36, $75                                               ; 37d9: 9e 00 36... ..6 ; 1.910518449e-06
    db $a0, $db, $e8, $b4                                             ; 37dd: a0 db e8... ... ; -1.310759762e-05
    db $63, $42, $c4                                                  ; 37e1: 63 42 c4    cB. ; 9.287148714e-05
    db $e6, $b5, 9, $36, $be                                          ; 37e4: e6 b5 09... ... ; -0.0006905975019
    db $e9, $36, $73, $1b, $5d                                        ; 37e9: e9 36 73... .6s ; 0.005567921029
    db $ec, $d8, $de, $63, $be                                        ; 37ee: ec d8 de... ... ; -0.05294646227
    db $f0, $61, $a1, $b3, $0c                                        ; 37f3: f0 61 a1... .a. ; 0.8813735871
    db 4                                                              ; 37f8: 04          .  ; multiply
    db $0f                                                            ; 37f9: 0f          .  ; addition
    db $38                                                            ; 37fa: 38          8  ; end-calc

    ret                                                               ; 37fb: c9          .

x80_fasin:
    rst $28                                                           ; 37fc: ef          .
    db $31                                                            ; 37fd: 31          1  ; duplicate
    db $31                                                            ; 37fe: 31          1  ; duplicate
    db 4                                                              ; 37ff: 04          .  ; multiply
    db $a1                                                            ; 3800: a1          .  ; stk-one
    db 3                                                              ; 3801: 03          .  ; subtract
    db $1b                                                            ; 3802: 1b          .  ; negate
    db $28                                                            ; 3803: 28          (  ; sqr
    db $a1                                                            ; 3804: a1          .  ; stk-one
    db $0f                                                            ; 3805: 0f          .  ; addition
    db 5                                                              ; 3806: 05          .  ; division
    db $24                                                            ; 3807: 24          $  ; atn
    db $31                                                            ; 3808: 31          1  ; duplicate
    db $0f                                                            ; 3809: 0f          .  ; addition
    db $38                                                            ; 380a: 38          8  ; end-calc

    ret                                                               ; 380b: c9          .

x80_facos:
    rst $28                                                           ; 380c: ef          .
    db $22                                                            ; 380d: 22          "  ; asn
    db $a3                                                            ; 380e: a3          .  ; stk-pi/2
    db 3                                                              ; 380f: 03          .  ; subtract
    db $1b                                                            ; 3810: 1b          .  ; negate
    db $38                                                            ; 3811: 38          8  ; end-calc

    ret                                                               ; 3812: c9          .

x80_fsqrt:
    rst $28                                                           ; 3813: ef          .
    db $3d                                                            ; 3814: 3d          =  ; re-stack
    db $c3                                                            ; 3815: c3          .  ; st-mem-3
    db $38                                                            ; 3816: 38          8  ; end-calc

    ld a,(hl)                                                         ; 3817: 7e          ~
    and a                                                             ; 3818: a7          .
    ret z                                                             ; 3819: c8          .
    inc hl                                                            ; 381a: 23          #
    bit 7,(hl)                                                        ; 381b: cb 7e       .~
    jp nz,x36e6                                                       ; 381d: c2 ee 36    ..6
    ld hl,$5ca1                                                       ; 3820: 21 a1 5c    !.\
    ld a,(hl)                                                         ; 3823: 7e          ~
    xor $80                                                           ; 3824: ee 80       ..
    sra a                                                             ; 3826: cb 2f       ./
    inc a                                                             ; 3828: 3c          <
    jr z,l382f                                                        ; 3829: 28 04       (.
    jp p,l382f                                                        ; 382b: f2 2f 38    ./8
    dec a                                                             ; 382e: 3d          =
; $382f referenced 2 times by $3829, $382b
l382f:
    xor $80                                                           ; 382f: ee 80       ..
    ld (hl),a                                                         ; 3831: 77          w
    rst $28                                                           ; 3832: ef          .
l3833:
    db $31                                                            ; 3833: 31          1  ; duplicate
    db $e3                                                            ; 3834: e3          .  ; get-mem-3
    db $c4                                                            ; 3835: c4          .  ; st-mem-4
    db 5                                                              ; 3836: 05          .  ; division
    db $e3                                                            ; 3837: e3          .  ; get-mem-3
    db $0f                                                            ; 3838: 0f          .  ; addition
    db $a2                                                            ; 3839: a2          .  ; stk-half
    db 4                                                              ; 383a: 04          .  ; multiply
    db $c3                                                            ; 383b: c3          .  ; st-mem-3
    db $e4                                                            ; 383c: e4          .  ; get-mem-4
    db 3                                                              ; 383d: 03          .  ; subtract
    db $2a                                                            ; 383e: 2a          *  ; abs
    db $37                                                            ; 383f: 37          7  ; greater-0
    db 0                                                              ; 3840: 00          .  ; jump-true
    db l3833 - $                                                      ; 3841: f2          .
    db 2                                                              ; 3842: 02          .  ; delete
    db $e3                                                            ; 3843: e3          .  ; get-mem-3
    db $38                                                            ; 3844: 38          8  ; end-calc

    ret                                                               ; 3845: c9          .

x80_ftop:
    rst $28                                                           ; 3846: ef          .
    db 1                                                              ; 3847: 01          .  ; exchange
    db $31                                                            ; 3848: 31          1  ; duplicate
    db $30                                                            ; 3849: 30          0  ; not
    db 0                                                              ; 384a: 00          .  ; jump-true
    db xis0 - $                                                       ; 384b: 07          .
    db $25                                                            ; 384c: 25          %  ; ln
    db 4                                                              ; 384d: 04          .  ; multiply
    db $38                                                            ; 384e: 38          8  ; end-calc

    jp x80_fexp                                                       ; 384f: c3 99 36    ..6

xis0:
    db 2                                                              ; 3852: 02          .  ; delete
    db $31                                                            ; 3853: 31          1  ; duplicate
    db $30                                                            ; 3854: 30          0  ; not
    db 0                                                              ; 3855: 00          .  ; jump-true
    db one - $                                                        ; 3856: 09          .
    db $a0                                                            ; 3857: a0          .  ; stk-zero
    db 1                                                              ; 3858: 01          .  ; exchange
    db $37                                                            ; 3859: 37          7  ; greater-0
    db 0                                                              ; 385a: 00          .  ; jump-true
    db last - $                                                       ; 385b: 06          .
    db $a1                                                            ; 385c: a1          .  ; stk-one
    db 1                                                              ; 385d: 01          .  ; exchange
    db 5                                                              ; 385e: 05          .  ; division
one:
    db 2                                                              ; 385f: 02          .  ; delete
    db $a1                                                            ; 3860: a1          .  ; stk-one
last:
    db $38                                                            ; 3861: 38          8  ; end-calc

    ret                                                               ; 3862: c9          .

x80_fhexs:
    call fp_to_bc                                                     ; 3863: cd a2 2d    ..-
    jp c,report_b2                                                    ; 3866: da af 35    ..5
    jp nz,report_b2                                                   ; 3869: c2 af 35    ..5
    push bc                                                           ; 386c: c5          .
    ld bc,4                                                           ; 386d: 01 04 00    ...
    rst $30                                                           ; 3870: f7          .
    pop hl                                                            ; 3871: e1          .
    push de                                                           ; 3872: d5          .
    ld a,h                                                            ; 3873: 7c          |
    call l3882                                                        ; 3874: cd 82 38    ..8
    ld a,l                                                            ; 3877: 7d          }
    call l3882                                                        ; 3878: cd 82 38    ..8
    pop de                                                            ; 387b: d1          .
    call stk_store                                                    ; 387c: cd b2 2a    ..*
    jp stk_pntrs                                                      ; 387f: c3 97 35    ..5

; $3882 referenced 2 times by $3874, $3878
l3882:
    ld h,a                                                            ; 3882: 67          g
    rlca                                                              ; 3883: 07          .
    rlca                                                              ; 3884: 07          .
    rlca                                                              ; 3885: 07          .
    rlca                                                              ; 3886: 07          .
    call l388b                                                        ; 3887: cd 8b 38    ..8
    ld a,h                                                            ; 388a: 7c          |
; $388b referenced 1 time by $3887
l388b:
    and $0f                                                           ; 388b: e6 0f       ..
    cp $0a                                                            ; 388d: fe 0a       ..
    jr c,l3893                                                        ; 388f: 38 02       8.
    add a,7                                                           ; 3891: c6 07       ..
; $3893 referenced 1 time by $388f
l3893:
    add a,$30                                                         ; 3893: c6 30       .0
    ld (de),a                                                         ; 3895: 12          .
    inc de                                                            ; 3896: 13          .
    ret                                                               ; 3897: c9          .

; $3898 referenced 1 time by $2538
l3898:
    ld hl,(chars)                                                     ; 3898: 2a 36 5c    *6\
    inc h                                                             ; 389b: 24          $
    ld a,c                                                            ; 389c: 79          y
    rrca                                                              ; 389d: 0f          .
    rrca                                                              ; 389e: 0f          .
    rrca                                                              ; 389f: 0f          .
    and $e0                                                           ; 38a0: e6 e0       ..
    xor b                                                             ; 38a2: a8          .
    ld e,a                                                            ; 38a3: 5f          _
    ld a,c                                                            ; 38a4: 79          y
    and $18                                                           ; 38a5: e6 18       ..
    xor $40                                                           ; 38a7: ee 40       .@
    ld d,a                                                            ; 38a9: 57          W
    ld b,2                                                            ; 38aa: 06 02       ..
    jp l253b                                                          ; 38ac: c3 3b 25    .;%

; $38af referenced 1 time by $1308
l38af:
    cp $ff                                                            ; 38af: fe ff       ..
    ret z                                                             ; 38b1: c8          .
    cp 8                                                              ; 38b2: fe 08       ..
    ret z                                                             ; 38b4: c8          .
    ld hl,(p_posn)                                                    ; 38b5: 2a 7f 5c    *.\
    ld a,h                                                            ; 38b8: 7c          |
    cp $ff                                                            ; 38b9: fe ff       ..
    ret z                                                             ; 38bb: c8          .
    cp $fe                                                            ; 38bc: fe fe       ..
    jr z,l38c7                                                        ; 38be: 28 07       (.
    ld (newppc),hl                                                    ; 38c0: 22 42 5c    "B\
    ld (iy+nsppc - err_nr),0                                          ; 38c3: fd 36 0a... .6.
; $38c7 referenced 1 time by $38be
l38c7:
    ld (iy+err_nr - err_nr),$ff                                       ; 38c7: fd 36 00... .6.
    jp l1555                                                          ; 38cb: c3 55 15    .U.

; $38ce referenced 2 times by $09e2, $1319
l38ce:
    ld bc,$bffd                                                       ; 38ce: 01 fd bf    ...
    out (c),a                                                         ; 38d1: ed 79       .y
    ld e,a                                                            ; 38d3: 5f          _
    ld a,(iy+bordcr - err_nr)                                         ; 38d4: fd 7e 0e    .~.
    rrca                                                              ; 38d7: 0f          .
    rrca                                                              ; 38d8: 0f          .
    rrca                                                              ; 38d9: 0f          .
    and 7                                                             ; 38da: e6 07       ..
    ld bc,$f6                                                         ; 38dc: 01 f6 00    ...
    out (c),e                                                         ; 38df: ed 59       .Y
    out (ula_port),a                                                  ; 38e1: d3 fe       ..
    ret                                                               ; 38e3: c9          .

l38e6:
    call l105e                                                        ; 38e4: cd 5e 10    .^.
    ld (e_ppc),bc                                                     ; 38e7: ed 43 49... .CI
; $38eb referenced 1 time by $1065
l38ec:
    call setmin                                                       ; 38eb: cd b0 16    ...
    call clslower                                                     ; 38ee: cd 6e 0d    .n.
    res 5,(iy+flagx - err_nr)                                         ; 38f1: fd cb 37... ..7
    call edit_key                                                     ; 38f5: cd a9 0f    ...
    ld sp,(err_sp)                                                    ; 38f8: ed 7b 3d... .{=
    jp l0f8e                                                          ; 38fc: c3 8e 0f    ...

l38ff:
    db $ff, $ff                                                       ; 38ff: ff ff       ..

; $3901 referenced 7 times by $0731, $0bd0, $105e, $1825, $194d, $1e42, $1e67
syntax3:
    call find_int                                                     ; 3901: cd 99 1e    ...
    ld a,b                                                            ; 3904: 78          x
    cp $40                                                            ; 3905: fe 40       .@
    jr l3914                                                          ; 3907: 18 0b       ..

; $3909 referenced 2 times by $2535, $2580
l3909:
    call l3915                                                        ; 3909: cd 15 39    ..9
    ld a,b                                                            ; 390c: 78          x
    cp $20                                                            ; 390d: fe 20       .
    jr nc,l391b                                                       ; 390f: 30 0a       0.
    ld a,c                                                            ; 3911: 79          y
    cp $18                                                            ; 3912: fe 18       ..
; $3914 referenced 1 time by $3907
l3914:
    ret c                                                             ; 3914: d8          .
; $3915 referenced 3 times by $22cb, $22dc, $3909
l3915:
    call stk_to_bc                                                    ; 3915: cd 07 23    ..#
    ld a,d                                                            ; 3918: 7a          z
    add a,e                                                           ; 3919: 83          .
    ret nc                                                            ; 391a: d0          .
; $391b referenced 1 time by $390f
l391b:
    rst $08                                                           ; 391b: cf          .
    db $0a                                                            ; 391c: 0a          .  ; Report B Integer out of range

; $391d referenced 1 time by $0ad9
l391d:
    bit 3,(iy+flags - err_nr)                                         ; 391d: fd cb 01... ...
    jp nz,l0b65                                                       ; 3921: c2 65 0b    .e.
    jp l0b24                                                          ; 3924: c3 24 0b    .$.

; $3927 referenced 1 time by $09b6
l3927:
    rst $20                                                           ; 3927: e7          .
    call check_end                                                    ; 3928: cd ee 1b    ...
    ld a,(flags)                                                      ; 392b: 3a 3b 5c    :;\
    or 8                                                              ; 392e: f6 08       ..
    jp l1f1f                                                          ; 3930: c3 1f 1f    ...

l3934:
    call poke1                                                        ; 3933: cd 85 1e    ...
    ld e,a                                                            ; 3936: 5f          _
    ld d,c                                                            ; 3937: 51          Q
    ld a,b                                                            ; 3938: 78          x
    and a                                                             ; 3939: a7          .
    jp nz,invcolerr                                                   ; 393a: c2 44 22    .D"
    ld a,c                                                            ; 393d: 79          y
    cp $41                                                            ; 393e: fe 41       .A
    jp nc,invcolerr                                                   ; 3940: d2 44 22    .D"
; $3943 referenced 2 times by $3951, $3959
l3943:
    ld bc,$bf3b                                                       ; 3943: 01 3b bf    .;.
    out (c),a                                                         ; 3946: ed 79       .y
    ld b,$ff                                                          ; 3948: 06 ff       ..
    out (c),e                                                         ; 394a: ed 59       .Y
    ret                                                               ; 394c: c9          .

; $394d referenced 1 time by $1292
l394d:
    ld a,$40                                                          ; 394d: 3e 40       >@
    ld e,0                                                            ; 394f: 1e 00       ..
    call l3943                                                        ; 3951: cd 43 39    .C9
; $3954 referenced 1 time by $09ac
l3954:
    xor a                                                             ; 3954: af          .
    ld hl,$5b00                                                       ; 3955: 21 00 5b    !.[
; $3958 referenced 1 time by $3960
l3958:
    ld e,(hl)                                                         ; 3958: 5e          ^
    call l3943                                                        ; 3959: cd 43 39    .C9
    inc a                                                             ; 395c: 3c          <
    inc l                                                             ; 395d: 2c          ,
    cp $40                                                            ; 395e: fe 40       .@
    jr c,l3958                                                        ; 3960: 38 f6       8.
    ret                                                               ; 3962: c9          .

l3963:
    bit 2,(iy+flags - err_nr)                                         ; 3963: fd cb 01... ...
    jr nz,l3989                                                       ; 3967: 20 20
    cp $15                                                            ; 3969: fe 15       ..
    jr nc,l3977                                                       ; 396b: 30 0a       0.
    cp $0f                                                            ; 396d: fe 0f       ..
    jr c,l3977                                                        ; 396f: 38 06       8.
    set 2,(iy+flags - err_nr)                                         ; 3971: fd cb 01... ...
    jr l398d                                                          ; 3975: 18 16       ..

; $3977 referenced 2 times by $396b, $396f
l3977:
    cp 6                                                              ; 3977: fe 06       ..
    jr c,l397f                                                        ; 3979: 38 04       8.
    cp $a5                                                            ; 397b: fe a5       ..
    jr c,l398d                                                        ; 397d: 38 0e       8.
; $397f referenced 1 time by $3979
l397f:
    exx                                                               ; 397f: d9          .
    push de                                                           ; 3980: d5          .
    exx                                                               ; 3981: d9          .
    call l3990                                                        ; 3982: cd 90 39    ..9
    exx                                                               ; 3985: d9          .
    pop de                                                            ; 3986: d1          .
    exx                                                               ; 3987: d9          .
    ret                                                               ; 3988: c9          .

; $3989 referenced 1 time by $3967
l3989:
    res 2,(iy+flags - err_nr)                                         ; 3989: fd cb 01... ...
; $398d referenced 2 times by $3975, $397d
l398d:
    jp add_char                                                       ; 398d: c3 81 0f    ...

; $3990 referenced 1 time by $3982
l3990:
    push de                                                           ; 3990: d5          .
    pop ix                                                            ; 3991: dd e1       ..
    sub $a5                                                           ; 3993: d6 a5       ..
    ld de,$a8                                                         ; 3995: 11 a8 00    ...
    push af                                                           ; 3998: f5          .
    call l0c41                                                        ; 3999: cd 41 0c    .A.
    jr c,l39a7                                                        ; 399c: 38 09       8.
    ld a,$20                                                          ; 399e: 3e 20       >
    bit 0,(iy+flags - err_nr)                                         ; 39a0: fd cb 01... ...
    call z,l39c6                                                      ; 39a4: cc c6 39    ..9
; $39a7 referenced 2 times by $399c, $39b0
l39a7:
    ld a,(de)                                                         ; 39a7: 1a          .
    and $7f                                                           ; 39a8: e6 7f       ..
    call l39c6                                                        ; 39aa: cd c6 39    ..9
    ld a,(de)                                                         ; 39ad: 1a          .
    inc de                                                            ; 39ae: 13          .
    add a,a                                                           ; 39af: 87          .
    jr nc,l39a7                                                       ; 39b0: 30 f5       0.
    pop de                                                            ; 39b2: d1          .
    cp $24                                                            ; 39b3: fe 24       .$
    jr z,l39ba                                                        ; 39b5: 28 03       (.
    cp $82                                                            ; 39b7: fe 82       ..
    ret c                                                             ; 39b9: d8          .
; $39ba referenced 1 time by $39b5
l39ba:
    ld a,d                                                            ; 39ba: 7a          z
    cp $26                                                            ; 39bb: fe 26       .&
    ret z                                                             ; 39bd: c8          .
    cp $60                                                            ; 39be: fe 60       .`
    ret z                                                             ; 39c0: c8          .
    cp 3                                                              ; 39c1: fe 03       ..
    ret c                                                             ; 39c3: d8          .
    ld a,$20                                                          ; 39c4: 3e 20       >
; $39c6 referenced 2 times by $39a4, $39aa
l39c6:
    push de                                                           ; 39c6: d5          .
    push ix                                                           ; 39c7: dd e5       ..
    pop de                                                            ; 39c9: d1          .
    rst $10                                                           ; 39ca: d7          .
    push de                                                           ; 39cb: d5          .
    pop ix                                                            ; 39cc: dd e1       ..
    pop de                                                            ; 39ce: d1          .
    ret                                                               ; 39cf: c9          .

; $39d0 referenced 1 time by $12b0
l39d0:
    set 7,(iy+err_nr - err_nr)                                        ; 39d0: fd cb 00... ...
    call editor                                                       ; 39d4: cd 2c 0f    .,.
    ld ix,(e_line)                                                    ; 39d7: dd 2a 59... .*Y
; $39db referenced 1 time by $3a4f
l39db:
    push ix                                                           ; 39db: dd e5       ..
    ld hl,$0102                                                       ; 39dd: 21 02 01    !..
    ld c,$ba                                                          ; 39e0: 0e ba       ..
    call l3a9b                                                        ; 39e2: cd 9b 3a    ..:
    cp $49                                                            ; 39e5: fe 49       .I
    jr nz,l39ec                                                       ; 39e7: 20 03        .
    call l3a15                                                        ; 39e9: cd 15 3a    ..:
; $39ec referenced 1 time by $39e7
l39ec:
    pop ix                                                            ; 39ec: dd e1       ..
    ld hl,$a9                                                         ; 39ee: 21 a9 00    !..
    ld c,$9f                                                          ; 39f1: 0e 9f       ..
; $39f3 referenced 2 times by $3a13, $3a4b
l39f3:
    call l3a9b                                                        ; 39f3: cd 9b 3a    ..:
    cp $0d                                                            ; 39f6: fe 0d       ..
    ret z                                                             ; 39f8: c8          .
    cp $ea                                                            ; 39f9: fe ea       ..
    ret z                                                             ; 39fb: c8          .
    jp l3a01                                                          ; 39fc: c3 01 3a    ..:

l39ff:
    db $ff, $ff                                                       ; 39ff: ff ff       ..

; $3a01 referenced 1 time by $39fc
l3a01:
    cp $22                                                            ; 3a01: fe 22       ."
    jr nz,l3a15                                                       ; 3a03: 20 10        .
; $3a05 referenced 1 time by $3a0f
l3a05:
    inc ix                                                            ; 3a05: dd 23       .#
    ld a,(ix+0)                                                       ; 3a07: dd 7e 00    .~.
    cp $0d                                                            ; 3a0a: fe 0d       ..
    ret z                                                             ; 3a0c: c8          .
    cp $22                                                            ; 3a0d: fe 22       ."
    jr nz,l3a05                                                       ; 3a0f: 20 f4        .
    inc ix                                                            ; 3a11: dd 23       .#
    jr l39f3                                                          ; 3a13: 18 de       ..

; $3a15 referenced 2 times by $39e9, $3a03
l3a15:
    push ix                                                           ; 3a15: dd e5       ..
    pop de                                                            ; 3a17: d1          .
    cp (hl)                                                           ; 3a18: be          .
    jr nz,l3a40                                                       ; 3a19: 20 25        %
; $3a1b referenced 1 time by $3a36
l3a1b:
    inc ix                                                            ; 3a1b: dd 23       .#
; $3a1d referenced 1 time by $3a5d
l3a1d:
    inc hl                                                            ; 3a1d: 23          #
; $3a1e referenced 1 time by $3a32
l3a1e:
    call l3a9b                                                        ; 3a1e: cd 9b 3a    ..:
    cp $2e                                                            ; 3a21: fe 2e       ..
    jr z,l3a5f                                                        ; 3a23: 28 3a       (:
    ld b,(hl)                                                         ; 3a25: 46          F
    cp $20                                                            ; 3a26: fe 20       .
    jr z,l3a52                                                        ; 3a28: 28 28       ((
    push af                                                           ; 3a2a: f5          .
    ld a,b                                                            ; 3a2b: 78          x
    cp $20                                                            ; 3a2c: fe 20       .
    jr nz,l3a51                                                       ; 3a2e: 20 21        !
    pop af                                                            ; 3a30: f1          .
    inc hl                                                            ; 3a31: 23          #
    jr l3a1e                                                          ; 3a32: 18 ea       ..

; $3a34 referenced 1 time by $3a55
l3a34:
    bit 7,(hl)                                                        ; 3a34: cb 7e       .~
    jr z,l3a1b                                                        ; 3a36: 28 e3       (.
    ld a,(ix+1)                                                       ; 3a38: dd 7e 01    .~.
    call l3a9e                                                        ; 3a3b: cd 9e 3a    ..:
    jr nc,l3a5f                                                       ; 3a3e: 30 1f       0.
; $3a40 referenced 3 times by $3a19, $3a5a, $3a72
l3a40:
    inc c                                                             ; 3a40: 0c          .
    push de                                                           ; 3a41: d5          .
    pop ix                                                            ; 3a42: dd e1       ..
; $3a44 referenced 1 time by $3a47
l3a44:
    bit 7,(hl)                                                        ; 3a44: cb 7e       .~
    inc hl                                                            ; 3a46: 23          #
    jr z,l3a44                                                        ; 3a47: 28 fb       (.
    ld a,c                                                            ; 3a49: 79          y
    and a                                                             ; 3a4a: a7          .
    jr nz,l39f3                                                       ; 3a4b: 20 a6        .
    inc ix                                                            ; 3a4d: dd 23       .#
; $3a4f referenced 1 time by $3a99
l3a4f:
    jr l39db                                                          ; 3a4f: 18 8a       ..

; $3a51 referenced 1 time by $3a2e
l3a51:
    pop af                                                            ; 3a51: f1          .
; $3a52 referenced 1 time by $3a28
l3a52:
    res 7,b                                                           ; 3a52: cb b8       ..
    cp b                                                              ; 3a54: b8          .
    jr z,l3a34                                                        ; 3a55: 28 dd       (.
    ld a,b                                                            ; 3a57: 78          x
    cp $20                                                            ; 3a58: fe 20       .
    jr nz,l3a40                                                       ; 3a5a: 20 e4        .
    inc hl                                                            ; 3a5c: 23          #
    jr l3a1d                                                          ; 3a5d: 18 be       ..

; $3a5f referenced 2 times by $3a23, $3a3e
l3a5f:
    ld a,(ix+1)                                                       ; 3a5f: dd 7e 01    .~.
    cp $20                                                            ; 3a62: fe 20       .
    jr nz,l3a68                                                       ; 3a64: 20 02        .
    inc ix                                                            ; 3a66: dd 23       .#
; $3a68 referenced 1 time by $3a64
l3a68:
    dec de                                                            ; 3a68: 1b          .
    ld a,(de)                                                         ; 3a69: 1a          .
    cp $20                                                            ; 3a6a: fe 20       .
    jr z,l3a74                                                        ; 3a6c: 28 06       (.
    inc de                                                            ; 3a6e: 13          .
    call l3a9e                                                        ; 3a6f: cd 9e 3a    ..:
    jr c,l3a40                                                        ; 3a72: 38 cc       8.
; $3a74 referenced 1 time by $3a6c
l3a74:
    inc c                                                             ; 3a74: 0c          .
    inc c                                                             ; 3a75: 0c          .
    inc c                                                             ; 3a76: 0c          .
    inc c                                                             ; 3a77: 0c          .
    inc c                                                             ; 3a78: 0c          .
    inc c                                                             ; 3a79: 0c          .
    ld (ix+0),c                                                       ; 3a7a: dd 71 00    .q.
    ld hl,(k_cur)                                                     ; 3a7d: 2a 5b 5c    *[\
    and a                                                             ; 3a80: a7          .
    sbc hl,de                                                         ; 3a81: ed 52       .R
    jr c,l3a92                                                        ; 3a83: 38 0d       8.
    add hl,de                                                         ; 3a85: 19          .
    push ix                                                           ; 3a86: dd e5       ..
    pop bc                                                            ; 3a88: c1          .
    scf                                                               ; 3a89: 37          7
    sbc hl,bc                                                         ; 3a8a: ed 42       .B
    jr nc,l3a92                                                       ; 3a8c: 30 04       0.
    ld (k_cur),de                                                     ; 3a8e: ed 53 5b... .S[
; $3a92 referenced 2 times by $3a83, $3a8c
l3a92:
    push de                                                           ; 3a92: d5          .
    ex (sp),ix                                                        ; 3a93: dd e3       ..
    pop hl                                                            ; 3a95: e1          .
    call reclaim_1                                                    ; 3a96: cd e5 19    ...
    jr l3a4f                                                          ; 3a99: 18 b4       ..

; $3a9b referenced 3 times by $39e2, $39f3, $3a1e
l3a9b:
    ld a,(ix+0)                                                       ; 3a9b: dd 7e 00    .~.
; $3a9e referenced 2 times by $3a3b, $3a6f
l3a9e:
    bit 1,(iy+mode - err_nr)                                          ; 3a9e: fd cb 07... ...
    ret nz                                                            ; 3aa2: c0          .
    call alpha                                                        ; 3aa3: cd 8d 2c    ..,
    ret nc                                                            ; 3aa6: d0          .
    and $df                                                           ; 3aa7: e6 df       ..
    ret                                                               ; 3aa9: c9          .

l3aa9:
    ld hl,(stkend)                                                    ; 3aaa: 2a 65 5c    *e\
    ld b,2                                                            ; 3aad: 06 02       ..
    cp $0d                                                            ; 3aaf: fe 0d       ..
    jr z,l3ac8                                                        ; 3ab1: 28 15       (.
    cp $3a                                                            ; 3ab3: fe 3a       .:
    jr z,l3ac8                                                        ; 3ab5: 28 11       (.
    call class_6                                                      ; 3ab7: cd 82 1c    ...
    ld b,1                                                            ; 3aba: 06 01       ..
; $3abc referenced 1 time by $3ac6
l3abc:
    rst $18                                                           ; 3abc: df          .
    cp $2c                                                            ; 3abd: fe 2c       .,
    jr nz,l3ac8                                                       ; 3abf: 20 07        .
    push bc                                                           ; 3ac1: c5          .
    call sexpt1num                                                    ; 3ac2: cd 81 1c    ...
    pop bc                                                            ; 3ac5: c1          .
    djnz l3abc                                                        ; 3ac6: 10 f4       ..
; $3ac8 referenced 3 times by $3ab1, $3ab5, $3abf
l3ac8:
    call check_end                                                    ; 3ac8: cd ee 1b    ...
    ld a,b                                                            ; 3acb: 78          x
    cp 2                                                              ; 3acc: fe 02       ..
    jr z,l3ad6                                                        ; 3ace: 28 06       (.
    cp 1                                                              ; 3ad0: fe 01       ..
    jr z,l3ad9                                                        ; 3ad2: 28 05       (.
    jr l3adc                                                          ; 3ad4: 18 06       ..

; $3ad6 referenced 1 time by $3ace
l3ad6:
    rst $28                                                           ; 3ad6: ef          .
    db $a4                                                            ; 3ad7: a4          .  ; stk-ten
    db $38                                                            ; 3ad8: 38          8  ; end-calc

; $3ad9 referenced 1 time by $3ad2
l3ad9:
    rst $28                                                           ; 3ad9: ef          .
    db $a4                                                            ; 3ada: a4          .  ; stk-ten
    db $38                                                            ; 3adb: 38          8  ; end-calc

; $3adc referenced 1 time by $3ad4
l3adc:
    rst $28                                                           ; 3adc: ef          .
    db $c1                                                            ; 3add: c1          .  ; st-mem-1
    db 2                                                              ; 3ade: 02          .  ; delete
    db $c0                                                            ; 3adf: c0          .  ; st-mem-0
    db 2                                                              ; 3ae0: 02          .  ; delete
    db $38                                                            ; 3ae1: 38          8  ; end-calc

    ld de,(prog)                                                      ; 3ae2: ed 5b 53... .[S
    ld hl,(vars)                                                      ; 3ae6: 2a 4b 5c    *K\
    or a                                                              ; 3ae9: b7          .
    sbc hl,de                                                         ; 3aea: ed 52       .R
    ret z                                                             ; 3aec: c8          .
    call l3c44                                                        ; 3aed: cd 44 3c    .D<
    ld hl,(membot+7)                                                  ; 3af0: 2a 99 5c    *.\
    call l30a9                                                        ; 3af3: cd a9 30    ..0
    jp c,parerr                                                       ; 3af6: da 8b 28    ..(
    ex de,hl                                                          ; 3af9: eb          .
    ld hl,(membot+2)                                                  ; 3afa: 2a 94 5c    *.\
    jr l3b01                                                          ; 3afd: 18 02       ..

l3aff:
    db $ff, $ff                                                       ; 3aff: ff ff       ..

; $3b01 referenced 1 time by $3afd
l3b01:
    add hl,de                                                         ; 3b01: 19          .
    ld de,$4000                                                       ; 3b02: 11 00 40    ..@
    or a                                                              ; 3b05: b7          .
    sbc hl,de                                                         ; 3b06: ed 52       .R
    jp nc,parerr                                                      ; 3b08: d2 8b 28    ..(
    ld hl,(prog)                                                      ; 3b0b: 2a 53 5c    *S\
; $3b0e referenced 1 time by $3b34
l3b0e:
    call next_one                                                     ; 3b0e: cd b8 19    ...
    inc hl                                                            ; 3b11: 23          #
    inc hl                                                            ; 3b12: 23          #
    ld (membot+23),hl                                                 ; 3b13: 22 a9 5c    ".\
    inc hl                                                            ; 3b16: 23          #
    inc hl                                                            ; 3b17: 23          #
    ld (membot+10),de                                                 ; 3b18: ed 53 9c... .S.
; $3b1c referenced 1 time by $3b27
l3b1c:
    ld a,(hl)                                                         ; 3b1c: 7e          ~
    call number                                                       ; 3b1d: cd b1 18    ...
    cp $0d                                                            ; 3b20: fe 0d       ..
    jr z,l3b29                                                        ; 3b22: 28 05       (.
    call l3b63                                                        ; 3b24: cd 63 3b    .c;
    jr l3b1c                                                          ; 3b27: 18 f3       ..

; $3b29 referenced 1 time by $3b22
l3b29:
    ld de,(membot+10)                                                 ; 3b29: ed 5b 9c... .[.
    ld hl,(vars)                                                      ; 3b2d: 2a 4b 5c    *K\
    and a                                                             ; 3b30: a7          .
    sbc hl,de                                                         ; 3b31: ed 52       .R
    ex de,hl                                                          ; 3b33: eb          .
    jr nz,l3b0e                                                       ; 3b34: 20 d8        .
    call l3c44                                                        ; 3b36: cd 44 3c    .D<
    ld b,d                                                            ; 3b39: 42          B
    ld c,e                                                            ; 3b3a: 4b          K
    ld de,0                                                           ; 3b3b: 11 00 00    ...
    ld hl,(prog)                                                      ; 3b3e: 2a 53 5c    *S\
; $3b41 referenced 1 time by $3b60
l3b41:
    push bc                                                           ; 3b41: c5          .
    push de                                                           ; 3b42: d5          .
    push hl                                                           ; 3b43: e5          .
    ld hl,(membot+7)                                                  ; 3b44: 2a 99 5c    *.\
    call l30a9                                                        ; 3b47: cd a9 30    ..0
    ld de,(membot+2)                                                  ; 3b4a: ed 5b 94... .[.
    add hl,de                                                         ; 3b4e: 19          .
    ex de,hl                                                          ; 3b4f: eb          .
    pop hl                                                            ; 3b50: e1          .
    ld (hl),d                                                         ; 3b51: 72          r
    inc hl                                                            ; 3b52: 23          #
    ld (hl),e                                                         ; 3b53: 73          s
    inc hl                                                            ; 3b54: 23          #
    ld c,(hl)                                                         ; 3b55: 4e          N
    inc hl                                                            ; 3b56: 23          #
    ld b,(hl)                                                         ; 3b57: 46          F
    inc hl                                                            ; 3b58: 23          #
    add hl,bc                                                         ; 3b59: 09          .
    pop de                                                            ; 3b5a: d1          .
    inc de                                                            ; 3b5b: 13          .
    pop bc                                                            ; 3b5c: c1          .
    dec bc                                                            ; 3b5d: 0b          .
    ld a,b                                                            ; 3b5e: 78          x
    or c                                                              ; 3b5f: b1          .
    jr nz,l3b41                                                       ; 3b60: 20 df        .
    ret                                                               ; 3b62: c9          .

; $3b63 referenced 1 time by $3b24
l3b63:
    inc hl                                                            ; 3b63: 23          #
    ld (membot+21),hl                                                 ; 3b64: 22 a7 5c    ".\
    ex de,hl                                                          ; 3b67: eb          .
    ld bc,7                                                           ; 3b68: 01 07 00    ...
    ld hl,$241e                                                       ; 3b6b: 21 1e 24    !.$
    cpir                                                              ; 3b6e: ed b1       ..
    ex de,hl                                                          ; 3b70: eb          .
    ret nz                                                            ; 3b71: c0          .
    ld c,0                                                            ; 3b72: 0e 00       ..
; $3b74 referenced 1 time by $3b96
l3b74:
    ld a,(hl)                                                         ; 3b74: 7e          ~
    cp $20                                                            ; 3b75: fe 20       .
    jr z,l3b94                                                        ; 3b77: 28 1b       (.
    call numeric                                                      ; 3b79: cd 1b 2d    ..-
    jr nc,l3b94                                                       ; 3b7c: 30 16       0.
    cp $2e                                                            ; 3b7e: fe 2e       ..
    jr z,l3b94                                                        ; 3b80: 28 12       (.
    cp $0e                                                            ; 3b82: fe 0e       ..
    jr z,l3b98                                                        ; 3b84: 28 12       (.
    or $20                                                            ; 3b86: f6 20       .
    cp $65                                                            ; 3b88: fe 65       .e
    jr nz,l3b90                                                       ; 3b8a: 20 04        .
    ld a,b                                                            ; 3b8c: 78          x
    or c                                                              ; 3b8d: b1          .
    jr nz,l3b94                                                       ; 3b8e: 20 04        .
; $3b90 referenced 1 time by $3b8a
l3b90:
    ld hl,(membot+21)                                                 ; 3b90: 2a a7 5c    *.\
    ret                                                               ; 3b93: c9          .

; $3b94 referenced 4 times by $3b77, $3b7c, $3b80, $3b8e
l3b94:
    inc bc                                                            ; 3b94: 03          .
    inc hl                                                            ; 3b95: 23          #
    jr l3b74                                                          ; 3b96: 18 dc       ..

; $3b98 referenced 1 time by $3b84
l3b98:
    ld (membot+12),bc                                                 ; 3b98: ed 43 9e... .C.
    push hl                                                           ; 3b9c: e5          .
    call number                                                       ; 3b9d: cd b1 18    ...
    call l3c77                                                        ; 3ba0: cd 77 3c    .w<
    ld a,(hl)                                                         ; 3ba3: 7e          ~
    pop hl                                                            ; 3ba4: e1          .
    cp $3a                                                            ; 3ba5: fe 3a       .:
    jr z,l3bac                                                        ; 3ba7: 28 03       (.
    cp $0d                                                            ; 3ba9: fe 0d       ..
    ret nz                                                            ; 3bab: c0          .
; $3bac referenced 1 time by $3ba7
l3bac:
    inc hl                                                            ; 3bac: 23          #
    call l33b8                                                        ; 3bad: cd b8 33    ..3
    call fp_to_bc                                                     ; 3bb0: cd a2 2d    ..-
    ld h,b                                                            ; 3bb3: 60          `
    ld l,c                                                            ; 3bb4: 69          i
    call line_addr                                                    ; 3bb5: cd 6e 19    .n.
    jr c,l3bc1                                                        ; 3bb8: 38 07       8.
    jr z,l3bc6                                                        ; 3bba: 28 0a       (.
    ld a,(hl)                                                         ; 3bbc: 7e          ~
    and $c0                                                           ; 3bbd: e6 c0       ..
    jr z,l3bc6                                                        ; 3bbf: 28 05       (.
; $3bc1 referenced 1 time by $3bb8
l3bc1:
    ld hl,$3fff                                                       ; 3bc1: 21 ff 3f    !.?
    jr l3bd7                                                          ; 3bc4: 18 11       ..

; $3bc6 referenced 2 times by $3bba, $3bbf
l3bc6:
    ld (membot+19),hl                                                 ; 3bc6: 22 a5 5c    ".\
    call l3c4c                                                        ; 3bc9: cd 4c 3c    .L<
    ld hl,(membot+7)                                                  ; 3bcc: 2a 99 5c    *.\
    call l30a9                                                        ; 3bcf: cd a9 30    ..0
    ld de,(membot+2)                                                  ; 3bd2: ed 5b 94... .[.
    add hl,de                                                         ; 3bd6: 19          .
; $3bd7 referenced 1 time by $3bc4
l3bd7:
    ld de,$5ca0                                                       ; 3bd7: 11 a0 5c    ..\
    push hl                                                           ; 3bda: e5          .
    call l3c7d                                                        ; 3bdb: cd 7d 3c    .}<
    ld e,b                                                            ; 3bde: 58          X
    inc e                                                             ; 3bdf: 1c          .
    ld d,0                                                            ; 3be0: 16 00       ..
    push de                                                           ; 3be2: d5          .
    push hl                                                           ; 3be3: e5          .
    ld l,e                                                            ; 3be4: 6b          k
    ld h,0                                                            ; 3be5: 26 00       &.
    ld bc,(membot+12)                                                 ; 3be7: ed 4b 9e... .K.
    or a                                                              ; 3beb: b7          .
    sbc hl,bc                                                         ; 3bec: ed 42       .B
    ld (membot+12),hl                                                 ; 3bee: 22 9e 5c    ".\
    jr z,l3c0b                                                        ; 3bf1: 28 18       (.
    jr c,l3c01                                                        ; 3bf3: 38 0c       8.
    ld b,h                                                            ; 3bf5: 44          D
    ld c,l                                                            ; 3bf6: 4d          M
    ld hl,(membot+21)                                                 ; 3bf7: 2a a7 5c    *.\
    call make_room                                                    ; 3bfa: cd 55 16    .U.
    jr l3c0b                                                          ; 3bfd: 18 0c       ..

l3bff:
    db $ff, $ff                                                       ; 3bff: ff ff       ..

; $3c01 referenced 2 times by $3bf3, $3c03
l3c01:
    dec bc                                                            ; 3c01: 0b          .
    dec e                                                             ; 3c02: 1d          .
    jr nz,l3c01                                                       ; 3c03: 20 fc        .
    ld hl,(membot+21)                                                 ; 3c05: 2a a7 5c    *.\
    call reclaim_2                                                    ; 3c08: cd e8 19    ...
; $3c0b referenced 2 times by $3bf1, $3bfd
l3c0b:
    ld de,(membot+21)                                                 ; 3c0b: ed 5b a7... .[.
    pop hl                                                            ; 3c0f: e1          .
    pop bc                                                            ; 3c10: c1          .
    ldir                                                              ; 3c11: ed b0       ..
    ex de,hl                                                          ; 3c13: eb          .
    ld (hl),$0e                                                       ; 3c14: 36 0e       6.
    pop bc                                                            ; 3c16: c1          .
    inc hl                                                            ; 3c17: 23          #
    push hl                                                           ; 3c18: e5          .
    call stack_bc1                                                    ; 3c19: cd 2f 2d    ./-
    pop de                                                            ; 3c1c: d1          .
    ld bc,5                                                           ; 3c1d: 01 05 00    ...
    ldir                                                              ; 3c20: ed b0       ..
    ex de,hl                                                          ; 3c22: eb          .
    push hl                                                           ; 3c23: e5          .
    call fp_to_bc                                                     ; 3c24: cd a2 2d    ..-
    ld hl,(membot+23)                                                 ; 3c27: 2a a9 5c    *.\
    push hl                                                           ; 3c2a: e5          .
    ld e,(hl)                                                         ; 3c2b: 5e          ^
    inc hl                                                            ; 3c2c: 23          #
    ld d,(hl)                                                         ; 3c2d: 56          V
    ld hl,(membot+12)                                                 ; 3c2e: 2a 9e 5c    *.\
    add hl,de                                                         ; 3c31: 19          .
    ex de,hl                                                          ; 3c32: eb          .
    pop hl                                                            ; 3c33: e1          .
    ld (hl),e                                                         ; 3c34: 73          s
    inc hl                                                            ; 3c35: 23          #
    ld (hl),d                                                         ; 3c36: 72          r
    ld hl,(membot+10)                                                 ; 3c37: 2a 9c 5c    *.\
    ld de,(membot+12)                                                 ; 3c3a: ed 5b 9e... .[.
    add hl,de                                                         ; 3c3e: 19          .
    ld (membot+10),hl                                                 ; 3c3f: 22 9c 5c    ".\
    pop hl                                                            ; 3c42: e1          .
    ret                                                               ; 3c43: c9          .

; $3c44 referenced 2 times by $3aed, $3b36
l3c44:
    ld hl,(vars)                                                      ; 3c44: 2a 4b 5c    *K\
    ld (membot+19),hl                                                 ; 3c47: 22 a5 5c    ".\
    jr l3c58                                                          ; 3c4a: 18 0c       ..

; $3c4c referenced 1 time by $3bc9
l3c4c:
    ld hl,(prog)                                                      ; 3c4c: 2a 53 5c    *S\
    ld de,(membot+19)                                                 ; 3c4f: ed 5b a5... .[.
    or a                                                              ; 3c53: b7          .
    sbc hl,de                                                         ; 3c54: ed 52       .R
    jr z,l3c72                                                        ; 3c56: 28 1a       (.
; $3c58 referenced 1 time by $3c4a
l3c58:
    ld hl,(prog)                                                      ; 3c58: 2a 53 5c    *S\
    ld bc,0                                                           ; 3c5b: 01 00 00    ...
; $3c5e referenced 1 time by $3c6d
l3c5e:
    push bc                                                           ; 3c5e: c5          .
    call next_one                                                     ; 3c5f: cd b8 19    ...
    ld hl,(membot+19)                                                 ; 3c62: 2a a5 5c    *.\
    and a                                                             ; 3c65: a7          .
    sbc hl,de                                                         ; 3c66: ed 52       .R
    jr z,l3c6f                                                        ; 3c68: 28 05       (.
    ex de,hl                                                          ; 3c6a: eb          .
    pop bc                                                            ; 3c6b: c1          .
    inc bc                                                            ; 3c6c: 03          .
    jr l3c5e                                                          ; 3c6d: 18 ef       ..

; $3c6f referenced 1 time by $3c68
l3c6f:
    pop de                                                            ; 3c6f: d1          .
    inc de                                                            ; 3c70: 13          .
    ret                                                               ; 3c71: c9          .

; $3c72 referenced 1 time by $3c56
l3c72:
    ld de,0                                                           ; 3c72: 11 00 00    ...
    ret                                                               ; 3c75: c9          .

; $3c76 referenced 1 time by $3c7a
l3c76:
    inc hl                                                            ; 3c76: 23          #
; $3c77 referenced 1 time by $3ba0
l3c77:
    ld a,(hl)                                                         ; 3c77: 7e          ~
    cp $20                                                            ; 3c78: fe 20       .
    jr z,l3c76                                                        ; 3c7a: 28 fa       (.
    ret                                                               ; 3c7c: c9          .

; $3c7d referenced 1 time by $3bdb
l3c7d:
    push de                                                           ; 3c7d: d5          .
    ld bc,$d8f0                                                       ; 3c7e: 01 f0 d8    ...
    call l3ca0                                                        ; 3c81: cd a0 3c    ..<
    ld bc,$fc18                                                       ; 3c84: 01 18 fc    ...
    call l3ca0                                                        ; 3c87: cd a0 3c    ..<
    ld bc,$ff9c                                                       ; 3c8a: 01 9c ff    ...
    call l3ca0                                                        ; 3c8d: cd a0 3c    ..<
    ld c,$f6                                                          ; 3c90: 0e f6       ..
    call l3ca0                                                        ; 3c92: cd a0 3c    ..<
    ld a,l                                                            ; 3c95: 7d          }
    add a,$30                                                         ; 3c96: c6 30       .0
    ld (de),a                                                         ; 3c98: 12          .
    inc de                                                            ; 3c99: 13          .
    ld b,4                                                            ; 3c9a: 06 04       ..
    pop hl                                                            ; 3c9c: e1          .
    jp l2414                                                          ; 3c9d: c3 14 24    ..$

; $3ca0 referenced 4 times by $3c81, $3c87, $3c8d, $3c92
l3ca0:
    xor a                                                             ; 3ca0: af          .
; $3ca1 referenced 1 time by $3ca3
l3ca1:
    add hl,bc                                                         ; 3ca1: 09          .
    inc a                                                             ; 3ca2: 3c          <
    jr c,l3ca1                                                        ; 3ca3: 38 fc       8.
    jp l0a7e                                                          ; 3ca5: c3 7e 0a    .~.

; $3ca8 referenced 1 time by $2855
scanfix:
    ld (printer_buffer+252),sp                                        ; 3ca8: ed 73 fc... .s.
    ld hl,6                                                           ; 3cac: 21 06 00    !..
    add hl,sp                                                         ; 3caf: 39          9
    ld e,(hl)                                                         ; 3cb0: 5e          ^
    inc hl                                                            ; 3cb1: 23          #
    ld d,(hl)                                                         ; 3cb2: 56          V
    ld h,d                                                            ; 3cb3: 62          b
    ld l,e                                                            ; 3cb4: 6b          k
; $3cb5 referenced 1 time by $3cbd
nextchar:
    inc hl                                                            ; 3cb5: 23          #
    ld a,(hl)                                                         ; 3cb6: 7e          ~
; $3cb7 referenced 1 time by $3cc2
nextchar2:
    cp $29                                                            ; 3cb7: fe 29       .)
    jr z,endfn                                                        ; 3cb9: 28 09       (.
    cp $0e                                                            ; 3cbb: fe 0e       ..
    jr nz,nextchar                                                    ; 3cbd: 20 f6        .
    call l18b4                                                        ; 3cbf: cd b4 18    ...
    jr nextchar2                                                      ; 3cc2: 18 f3       ..

; $3cc4 referenced 1 time by $3cb9
endfn:
    or a                                                              ; 3cc4: b7          .
    sbc hl,de                                                         ; 3cc5: ed 52       .R
    ld b,h                                                            ; 3cc7: 44          D
    ld c,l                                                            ; 3cc8: 4d          M
    ld a,h                                                            ; 3cc9: 7c          |
    cpl                                                               ; 3cca: 2f          /
    ld h,a                                                            ; 3ccb: 67          g
    ld a,l                                                            ; 3ccc: 7d          }
    cpl                                                               ; 3ccd: 2f          /
    ld l,a                                                            ; 3cce: 6f          o
    inc hl                                                            ; 3ccf: 23          #
    add hl,sp                                                         ; 3cd0: 39          9
    ld sp,hl                                                          ; 3cd1: f9          .
    ex de,hl                                                          ; 3cd2: eb          .
    ld ix,(printer_buffer+252)                                        ; 3cd3: dd 2a fc... .*.
    push ix                                                           ; 3cd7: dd e5       ..
    push de                                                           ; 3cd9: d5          .
    push hl                                                           ; 3cda: e5          .
    push bc                                                           ; 3cdb: c5          .
    ldir                                                              ; 3cdc: ed b0       ..
    call scanning                                                     ; 3cde: cd fb 24    ..$
    pop bc                                                            ; 3ce1: c1          .
    pop de                                                            ; 3ce2: d1          .
    pop hl                                                            ; 3ce3: e1          .
    jp l11cb                                                          ; 3ce4: c3 b7 11    ...

; $3ce7 referenced 1 time by $1210
setudg:
    ld de,$3eaf                                                       ; 3ce7: 11 af 3e    ..>
    ld bc,$a8                                                         ; 3cea: 01 a8 00    ...
    jp setudg1                                                        ; 3ced: c3 ee 09    ...

cursors:
    db %"--------"                                                    ; 3cf0: 00          .
    db %"--------"                                                    ; 3cf1: 00          .
    db %"--------"                                                    ; 3cf2: 00          .
    db %"--------"                                                    ; 3cf3: 00          .
    db %"--####--"                                                    ; 3cf4: 3c          <
    db %"--####--"                                                    ; 3cf5: 3c          <
    db %"--####--"                                                    ; 3cf6: 3c          <
    db %"--------"                                                    ; 3cf7: 00          .
    db %"--------"                                                    ; 3cf8: 00          .
    db %"--####--"                                                    ; 3cf9: 3c          <
    db %"--####--"                                                    ; 3cfa: 3c          <
    db %"--####--"                                                    ; 3cfb: 3c          <
    db %"--------"                                                    ; 3cfc: 00          .
    db %"--------"                                                    ; 3cfd: 00          .
    db %"--------"                                                    ; 3cfe: 00          .
    db %"--------"                                                    ; 3cff: 00          .
font:
    db %"--------"                                                    ; 3d00: 00          .  ; ' '
    db %"--------"                                                    ; 3d01: 00          .
    db %"--------"                                                    ; 3d02: 00          .
    db %"--------"                                                    ; 3d03: 00          .
    db %"--------"                                                    ; 3d04: 00          .
    db %"--------"                                                    ; 3d05: 00          .
    db %"--------"                                                    ; 3d06: 00          .
    db %"--------"                                                    ; 3d07: 00          .
    db %"--------"                                                    ; 3d08: 00          .  ; '!'
    db %"---#----"                                                    ; 3d09: 10          .
    db %"---#----"                                                    ; 3d0a: 10          .
    db %"---#----"                                                    ; 3d0b: 10          .
    db %"---#----"                                                    ; 3d0c: 10          .
    db %"--------"                                                    ; 3d0d: 00          .
    db %"---#----"                                                    ; 3d0e: 10          .
    db %"--------"                                                    ; 3d0f: 00          .
    db %"--------"                                                    ; 3d10: 00          .  ; '"'
    db %"--#--#--"                                                    ; 3d11: 24          $
    db %"--#--#--"                                                    ; 3d12: 24          $
    db %"--------"                                                    ; 3d13: 00          .
    db %"--------"                                                    ; 3d14: 00          .
    db %"--------"                                                    ; 3d15: 00          .
    db %"--------"                                                    ; 3d16: 00          .
    db %"--------"                                                    ; 3d17: 00          .
    db %"--------"                                                    ; 3d18: 00          .  ; '#'
    db %"--#--#--"                                                    ; 3d19: 24          $
    db %"-######-"                                                    ; 3d1a: 7e          ~
    db %"--#--#--"                                                    ; 3d1b: 24          $
    db %"--#--#--"                                                    ; 3d1c: 24          $
    db %"-######-"                                                    ; 3d1d: 7e          ~
    db %"--#--#--"                                                    ; 3d1e: 24          $
    db %"--------"                                                    ; 3d1f: 00          .
    db %"--------"                                                    ; 3d20: 00          .  ; '$'
    db %"----#---"                                                    ; 3d21: 08          .
    db %"--#####-"                                                    ; 3d22: 3e          >
    db %"--#-#---"                                                    ; 3d23: 28          (
    db %"--#####-"                                                    ; 3d24: 3e          >
    db %"----#-#-"                                                    ; 3d25: 0a          .
    db %"--#####-"                                                    ; 3d26: 3e          >
    db %"----#---"                                                    ; 3d27: 08          .
    db %"--------"                                                    ; 3d28: 00          .  ; '%'
    db %"-##---#-"                                                    ; 3d29: 62          b
    db %"-##--#--"                                                    ; 3d2a: 64          d
    db %"----#---"                                                    ; 3d2b: 08          .
    db %"---#----"                                                    ; 3d2c: 10          .
    db %"--#--##-"                                                    ; 3d2d: 26          &
    db %"-#---##-"                                                    ; 3d2e: 46          F
    db %"--------"                                                    ; 3d2f: 00          .
    db %"--------"                                                    ; 3d30: 00          .  ; '&'
    db %"---#----"                                                    ; 3d31: 10          .
    db %"--#-#---"                                                    ; 3d32: 28          (
    db %"---#----"                                                    ; 3d33: 10          .
    db %"--#-#-#-"                                                    ; 3d34: 2a          *
    db %"-#---#--"                                                    ; 3d35: 44          D
    db %"--###-#-"                                                    ; 3d36: 3a          :
    db %"--------"                                                    ; 3d37: 00          .
    db %"--------"                                                    ; 3d38: 00          .  ; '''
    db %"----#---"                                                    ; 3d39: 08          .
    db %"---#----"                                                    ; 3d3a: 10          .
    db %"--------"                                                    ; 3d3b: 00          .
    db %"--------"                                                    ; 3d3c: 00          .
    db %"--------"                                                    ; 3d3d: 00          .
    db %"--------"                                                    ; 3d3e: 00          .
    db %"--------"                                                    ; 3d3f: 00          .
    db %"--------"                                                    ; 3d40: 00          .  ; '('
    db %"-----#--"                                                    ; 3d41: 04          .
    db %"----#---"                                                    ; 3d42: 08          .
    db %"----#---"                                                    ; 3d43: 08          .
    db %"----#---"                                                    ; 3d44: 08          .
    db %"----#---"                                                    ; 3d45: 08          .
    db %"-----#--"                                                    ; 3d46: 04          .
    db %"--------"                                                    ; 3d47: 00          .
    db %"--------"                                                    ; 3d48: 00          .  ; ')'
    db %"--#-----"                                                    ; 3d49: 20
    db %"---#----"                                                    ; 3d4a: 10          .
    db %"---#----"                                                    ; 3d4b: 10          .
    db %"---#----"                                                    ; 3d4c: 10          .
    db %"---#----"                                                    ; 3d4d: 10          .
    db %"--#-----"                                                    ; 3d4e: 20
    db %"--------"                                                    ; 3d4f: 00          .
    db %"--------"                                                    ; 3d50: 00          .  ; '*'
    db %"--------"                                                    ; 3d51: 00          .
    db %"---#-#--"                                                    ; 3d52: 14          .
    db %"----#---"                                                    ; 3d53: 08          .
    db %"--#####-"                                                    ; 3d54: 3e          >
    db %"----#---"                                                    ; 3d55: 08          .
    db %"---#-#--"                                                    ; 3d56: 14          .
    db %"--------"                                                    ; 3d57: 00          .
    db %"--------"                                                    ; 3d58: 00          .  ; '+'
    db %"--------"                                                    ; 3d59: 00          .
    db %"----#---"                                                    ; 3d5a: 08          .
    db %"----#---"                                                    ; 3d5b: 08          .
    db %"--#####-"                                                    ; 3d5c: 3e          >
    db %"----#---"                                                    ; 3d5d: 08          .
    db %"----#---"                                                    ; 3d5e: 08          .
    db %"--------"                                                    ; 3d5f: 00          .
    db %"--------"                                                    ; 3d60: 00          .  ; ','
    db %"--------"                                                    ; 3d61: 00          .
    db %"--------"                                                    ; 3d62: 00          .
    db %"--------"                                                    ; 3d63: 00          .
    db %"--------"                                                    ; 3d64: 00          .
    db %"----#---"                                                    ; 3d65: 08          .
    db %"----#---"                                                    ; 3d66: 08          .
    db %"---#----"                                                    ; 3d67: 10          .
    db %"--------"                                                    ; 3d68: 00          .  ; '-'
    db %"--------"                                                    ; 3d69: 00          .
    db %"--------"                                                    ; 3d6a: 00          .
    db %"--------"                                                    ; 3d6b: 00          .
    db %"--#####-"                                                    ; 3d6c: 3e          >
    db %"--------"                                                    ; 3d6d: 00          .
    db %"--------"                                                    ; 3d6e: 00          .
    db %"--------"                                                    ; 3d6f: 00          .
    db %"--------"                                                    ; 3d70: 00          .  ; '.'
    db %"--------"                                                    ; 3d71: 00          .
    db %"--------"                                                    ; 3d72: 00          .
    db %"--------"                                                    ; 3d73: 00          .
    db %"--------"                                                    ; 3d74: 00          .
    db %"---##---"                                                    ; 3d75: 18          .
    db %"---##---"                                                    ; 3d76: 18          .
    db %"--------"                                                    ; 3d77: 00          .
    db %"--------"                                                    ; 3d78: 00          .  ; '/'
    db %"--------"                                                    ; 3d79: 00          .
    db %"------#-"                                                    ; 3d7a: 02          .
    db %"-----#--"                                                    ; 3d7b: 04          .
    db %"----#---"                                                    ; 3d7c: 08          .
    db %"---#----"                                                    ; 3d7d: 10          .
    db %"--#-----"                                                    ; 3d7e: 20
    db %"--------"                                                    ; 3d7f: 00          .
    db %"--------"                                                    ; 3d80: 00          .  ; '0'
    db %"--####--"                                                    ; 3d81: 3c          <
    db %"-#---##-"                                                    ; 3d82: 46          F
    db %"-#--#-#-"                                                    ; 3d83: 4a          J
    db %"-#-#--#-"                                                    ; 3d84: 52          R
    db %"-##---#-"                                                    ; 3d85: 62          b
    db %"--####--"                                                    ; 3d86: 3c          <
    db %"--------"                                                    ; 3d87: 00          .
    db %"--------"                                                    ; 3d88: 00          .  ; '1'
    db %"---##---"                                                    ; 3d89: 18          .
    db %"--#-#---"                                                    ; 3d8a: 28          (
    db %"----#---"                                                    ; 3d8b: 08          .
    db %"----#---"                                                    ; 3d8c: 08          .
    db %"----#---"                                                    ; 3d8d: 08          .
    db %"--#####-"                                                    ; 3d8e: 3e          >
    db %"--------"                                                    ; 3d8f: 00          .
    db %"--------"                                                    ; 3d90: 00          .  ; '2'
    db %"--####--"                                                    ; 3d91: 3c          <
    db %"-#----#-"                                                    ; 3d92: 42          B
    db %"------#-"                                                    ; 3d93: 02          .
    db %"--####--"                                                    ; 3d94: 3c          <
    db %"-#------"                                                    ; 3d95: 40          @
    db %"-######-"                                                    ; 3d96: 7e          ~
    db %"--------"                                                    ; 3d97: 00          .
    db %"--------"                                                    ; 3d98: 00          .  ; '3'
    db %"--####--"                                                    ; 3d99: 3c          <
    db %"-#----#-"                                                    ; 3d9a: 42          B
    db %"----##--"                                                    ; 3d9b: 0c          .
    db %"------#-"                                                    ; 3d9c: 02          .
    db %"-#----#-"                                                    ; 3d9d: 42          B
    db %"--####--"                                                    ; 3d9e: 3c          <
    db %"--------"                                                    ; 3d9f: 00          .
    db %"--------"                                                    ; 3da0: 00          .  ; '4'
    db %"----#---"                                                    ; 3da1: 08          .
    db %"---##---"                                                    ; 3da2: 18          .
    db %"--#-#---"                                                    ; 3da3: 28          (
    db %"-#--#---"                                                    ; 3da4: 48          H
    db %"-######-"                                                    ; 3da5: 7e          ~
    db %"----#---"                                                    ; 3da6: 08          .
    db %"--------"                                                    ; 3da7: 00          .
    db %"--------"                                                    ; 3da8: 00          .  ; '5'
    db %"-######-"                                                    ; 3da9: 7e          ~
    db %"-#------"                                                    ; 3daa: 40          @
    db %"-#####--"                                                    ; 3dab: 7c          |
    db %"------#-"                                                    ; 3dac: 02          .
    db %"-#----#-"                                                    ; 3dad: 42          B
    db %"--####--"                                                    ; 3dae: 3c          <
    db %"--------"                                                    ; 3daf: 00          .
    db %"--------"                                                    ; 3db0: 00          .  ; '6'
    db %"--####--"                                                    ; 3db1: 3c          <
    db %"-#------"                                                    ; 3db2: 40          @
    db %"-#####--"                                                    ; 3db3: 7c          |
    db %"-#----#-"                                                    ; 3db4: 42          B
    db %"-#----#-"                                                    ; 3db5: 42          B
    db %"--####--"                                                    ; 3db6: 3c          <
    db %"--------"                                                    ; 3db7: 00          .
    db %"--------"                                                    ; 3db8: 00          .  ; '7'
    db %"-######-"                                                    ; 3db9: 7e          ~
    db %"------#-"                                                    ; 3dba: 02          .
    db %"-----#--"                                                    ; 3dbb: 04          .
    db %"----#---"                                                    ; 3dbc: 08          .
    db %"---#----"                                                    ; 3dbd: 10          .
    db %"---#----"                                                    ; 3dbe: 10          .
    db %"--------"                                                    ; 3dbf: 00          .
    db %"--------"                                                    ; 3dc0: 00          .  ; '8'
    db %"--####--"                                                    ; 3dc1: 3c          <
    db %"-#----#-"                                                    ; 3dc2: 42          B
    db %"--####--"                                                    ; 3dc3: 3c          <
    db %"-#----#-"                                                    ; 3dc4: 42          B
    db %"-#----#-"                                                    ; 3dc5: 42          B
    db %"--####--"                                                    ; 3dc6: 3c          <
    db %"--------"                                                    ; 3dc7: 00          .
    db %"--------"                                                    ; 3dc8: 00          .  ; '9'
    db %"--####--"                                                    ; 3dc9: 3c          <
    db %"-#----#-"                                                    ; 3dca: 42          B
    db %"-#----#-"                                                    ; 3dcb: 42          B
    db %"--#####-"                                                    ; 3dcc: 3e          >
    db %"------#-"                                                    ; 3dcd: 02          .
    db %"--####--"                                                    ; 3dce: 3c          <
    db %"--------"                                                    ; 3dcf: 00          .
    db %"--------"                                                    ; 3dd0: 00          .  ; ':'
    db %"--------"                                                    ; 3dd1: 00          .
    db %"--------"                                                    ; 3dd2: 00          .
    db %"---#----"                                                    ; 3dd3: 10          .
    db %"--------"                                                    ; 3dd4: 00          .
    db %"--------"                                                    ; 3dd5: 00          .
    db %"---#----"                                                    ; 3dd6: 10          .
    db %"--------"                                                    ; 3dd7: 00          .
    db %"--------"                                                    ; 3dd8: 00          .  ; ';'
    db %"--------"                                                    ; 3dd9: 00          .
    db %"---#----"                                                    ; 3dda: 10          .
    db %"--------"                                                    ; 3ddb: 00          .
    db %"--------"                                                    ; 3ddc: 00          .
    db %"---#----"                                                    ; 3ddd: 10          .
    db %"---#----"                                                    ; 3dde: 10          .
    db %"--#-----"                                                    ; 3ddf: 20
    db %"--------"                                                    ; 3de0: 00          .  ; '<'
    db %"--------"                                                    ; 3de1: 00          .
    db %"-----#--"                                                    ; 3de2: 04          .
    db %"----#---"                                                    ; 3de3: 08          .
    db %"---#----"                                                    ; 3de4: 10          .
    db %"----#---"                                                    ; 3de5: 08          .
    db %"-----#--"                                                    ; 3de6: 04          .
    db %"--------"                                                    ; 3de7: 00          .
    db %"--------"                                                    ; 3de8: 00          .  ; '='
    db %"--------"                                                    ; 3de9: 00          .
    db %"--------"                                                    ; 3dea: 00          .
    db %"--#####-"                                                    ; 3deb: 3e          >
    db %"--------"                                                    ; 3dec: 00          .
    db %"--#####-"                                                    ; 3ded: 3e          >
    db %"--------"                                                    ; 3dee: 00          .
    db %"--------"                                                    ; 3def: 00          .
    db %"--------"                                                    ; 3df0: 00          .  ; '>'
    db %"--------"                                                    ; 3df1: 00          .
    db %"---#----"                                                    ; 3df2: 10          .
    db %"----#---"                                                    ; 3df3: 08          .
    db %"-----#--"                                                    ; 3df4: 04          .
    db %"----#---"                                                    ; 3df5: 08          .
    db %"---#----"                                                    ; 3df6: 10          .
    db %"--------"                                                    ; 3df7: 00          .
    db %"--------"                                                    ; 3df8: 00          .  ; '?'
    db %"--####--"                                                    ; 3df9: 3c          <
    db %"-#----#-"                                                    ; 3dfa: 42          B
    db %"-----#--"                                                    ; 3dfb: 04          .
    db %"----#---"                                                    ; 3dfc: 08          .
    db %"--------"                                                    ; 3dfd: 00          .
    db %"----#---"                                                    ; 3dfe: 08          .
    db %"--------"                                                    ; 3dff: 00          .
    db %"--------"                                                    ; 3e00: 00          .  ; '@'
    db %"--####--"                                                    ; 3e01: 3c          <
    db %"-#--#-#-"                                                    ; 3e02: 4a          J
    db %"-#-#-##-"                                                    ; 3e03: 56          V
    db %"-#-####-"                                                    ; 3e04: 5e          ^
    db %"-#------"                                                    ; 3e05: 40          @
    db %"--####--"                                                    ; 3e06: 3c          <
    db %"--------"                                                    ; 3e07: 00          .
    db %"--------"                                                    ; 3e08: 00          .  ; 'A'
    db %"--####--"                                                    ; 3e09: 3c          <
    db %"-#----#-"                                                    ; 3e0a: 42          B
    db %"-#----#-"                                                    ; 3e0b: 42          B
    db %"-######-"                                                    ; 3e0c: 7e          ~
    db %"-#----#-"                                                    ; 3e0d: 42          B
    db %"-#----#-"                                                    ; 3e0e: 42          B
    db %"--------"                                                    ; 3e0f: 00          .
    db %"--------"                                                    ; 3e10: 00          .  ; 'B'
    db %"-#####--"                                                    ; 3e11: 7c          |
    db %"-#----#-"                                                    ; 3e12: 42          B
    db %"-#####--"                                                    ; 3e13: 7c          |
    db %"-#----#-"                                                    ; 3e14: 42          B
    db %"-#----#-"                                                    ; 3e15: 42          B
    db %"-#####--"                                                    ; 3e16: 7c          |
    db %"--------"                                                    ; 3e17: 00          .
    db %"--------"                                                    ; 3e18: 00          .  ; 'C'
    db %"--####--"                                                    ; 3e19: 3c          <
    db %"-#----#-"                                                    ; 3e1a: 42          B
    db %"-#------"                                                    ; 3e1b: 40          @
    db %"-#------"                                                    ; 3e1c: 40          @
    db %"-#----#-"                                                    ; 3e1d: 42          B
    db %"--####--"                                                    ; 3e1e: 3c          <
    db %"--------"                                                    ; 3e1f: 00          .
    db %"--------"                                                    ; 3e20: 00          .  ; 'D'
    db %"-####---"                                                    ; 3e21: 78          x
    db %"-#---#--"                                                    ; 3e22: 44          D
    db %"-#----#-"                                                    ; 3e23: 42          B
    db %"-#----#-"                                                    ; 3e24: 42          B
    db %"-#---#--"                                                    ; 3e25: 44          D
    db %"-####---"                                                    ; 3e26: 78          x
    db %"--------"                                                    ; 3e27: 00          .
    db %"--------"                                                    ; 3e28: 00          .  ; 'E'
    db %"-######-"                                                    ; 3e29: 7e          ~
    db %"-#------"                                                    ; 3e2a: 40          @
    db %"-#####--"                                                    ; 3e2b: 7c          |
    db %"-#------"                                                    ; 3e2c: 40          @
    db %"-#------"                                                    ; 3e2d: 40          @
    db %"-######-"                                                    ; 3e2e: 7e          ~
    db %"--------"                                                    ; 3e2f: 00          .
    db %"--------"                                                    ; 3e30: 00          .  ; 'F'
    db %"-######-"                                                    ; 3e31: 7e          ~
    db %"-#------"                                                    ; 3e32: 40          @
    db %"-#####--"                                                    ; 3e33: 7c          |
    db %"-#------"                                                    ; 3e34: 40          @
    db %"-#------"                                                    ; 3e35: 40          @
    db %"-#------"                                                    ; 3e36: 40          @
    db %"--------"                                                    ; 3e37: 00          .
    db %"--------"                                                    ; 3e38: 00          .  ; 'G'
    db %"--####--"                                                    ; 3e39: 3c          <
    db %"-#----#-"                                                    ; 3e3a: 42          B
    db %"-#------"                                                    ; 3e3b: 40          @
    db %"-#--###-"                                                    ; 3e3c: 4e          N
    db %"-#----#-"                                                    ; 3e3d: 42          B
    db %"--####--"                                                    ; 3e3e: 3c          <
    db %"--------"                                                    ; 3e3f: 00          .
    db %"--------"                                                    ; 3e40: 00          .  ; 'H'
    db %"-#----#-"                                                    ; 3e41: 42          B
    db %"-#----#-"                                                    ; 3e42: 42          B
    db %"-######-"                                                    ; 3e43: 7e          ~
    db %"-#----#-"                                                    ; 3e44: 42          B
    db %"-#----#-"                                                    ; 3e45: 42          B
    db %"-#----#-"                                                    ; 3e46: 42          B
    db %"--------"                                                    ; 3e47: 00          .
    db %"--------"                                                    ; 3e48: 00          .  ; 'I'
    db %"--#####-"                                                    ; 3e49: 3e          >
    db %"----#---"                                                    ; 3e4a: 08          .
    db %"----#---"                                                    ; 3e4b: 08          .
    db %"----#---"                                                    ; 3e4c: 08          .
    db %"----#---"                                                    ; 3e4d: 08          .
    db %"--#####-"                                                    ; 3e4e: 3e          >
    db %"--------"                                                    ; 3e4f: 00          .
    db %"--------"                                                    ; 3e50: 00          .  ; 'J'
    db %"------#-"                                                    ; 3e51: 02          .
    db %"------#-"                                                    ; 3e52: 02          .
    db %"------#-"                                                    ; 3e53: 02          .
    db %"-#----#-"                                                    ; 3e54: 42          B
    db %"-#----#-"                                                    ; 3e55: 42          B
    db %"--####--"                                                    ; 3e56: 3c          <
    db %"--------"                                                    ; 3e57: 00          .
    db %"--------"                                                    ; 3e58: 00          .  ; 'K'
    db %"-#---#--"                                                    ; 3e59: 44          D
    db %"-#--#---"                                                    ; 3e5a: 48          H
    db %"-###----"                                                    ; 3e5b: 70          p
    db %"-#--#---"                                                    ; 3e5c: 48          H
    db %"-#---#--"                                                    ; 3e5d: 44          D
    db %"-#----#-"                                                    ; 3e5e: 42          B
    db %"--------"                                                    ; 3e5f: 00          .
    db %"--------"                                                    ; 3e60: 00          .  ; 'L'
    db %"-#------"                                                    ; 3e61: 40          @
    db %"-#------"                                                    ; 3e62: 40          @
    db %"-#------"                                                    ; 3e63: 40          @
    db %"-#------"                                                    ; 3e64: 40          @
    db %"-#------"                                                    ; 3e65: 40          @
    db %"-######-"                                                    ; 3e66: 7e          ~
    db %"--------"                                                    ; 3e67: 00          .
    db %"--------"                                                    ; 3e68: 00          .  ; 'M'
    db %"-#----#-"                                                    ; 3e69: 42          B
    db %"-##--##-"                                                    ; 3e6a: 66          f
    db %"-#-##-#-"                                                    ; 3e6b: 5a          Z
    db %"-#----#-"                                                    ; 3e6c: 42          B
    db %"-#----#-"                                                    ; 3e6d: 42          B
    db %"-#----#-"                                                    ; 3e6e: 42          B
    db %"--------"                                                    ; 3e6f: 00          .
    db %"--------"                                                    ; 3e70: 00          .  ; 'N'
    db %"-#----#-"                                                    ; 3e71: 42          B
    db %"-##---#-"                                                    ; 3e72: 62          b
    db %"-#-#--#-"                                                    ; 3e73: 52          R
    db %"-#--#-#-"                                                    ; 3e74: 4a          J
    db %"-#---##-"                                                    ; 3e75: 46          F
    db %"-#----#-"                                                    ; 3e76: 42          B
    db %"--------"                                                    ; 3e77: 00          .
    db %"--------"                                                    ; 3e78: 00          .  ; 'O'
    db %"--####--"                                                    ; 3e79: 3c          <
    db %"-#----#-"                                                    ; 3e7a: 42          B
    db %"-#----#-"                                                    ; 3e7b: 42          B
    db %"-#----#-"                                                    ; 3e7c: 42          B
    db %"-#----#-"                                                    ; 3e7d: 42          B
    db %"--####--"                                                    ; 3e7e: 3c          <
    db %"--------"                                                    ; 3e7f: 00          .
    db %"--------"                                                    ; 3e80: 00          .  ; 'P'
    db %"-#####--"                                                    ; 3e81: 7c          |
    db %"-#----#-"                                                    ; 3e82: 42          B
    db %"-#----#-"                                                    ; 3e83: 42          B
    db %"-#####--"                                                    ; 3e84: 7c          |
    db %"-#------"                                                    ; 3e85: 40          @
    db %"-#------"                                                    ; 3e86: 40          @
    db %"--------"                                                    ; 3e87: 00          .
    db %"--------"                                                    ; 3e88: 00          .  ; 'Q'
    db %"--####--"                                                    ; 3e89: 3c          <
    db %"-#----#-"                                                    ; 3e8a: 42          B
    db %"-#----#-"                                                    ; 3e8b: 42          B
    db %"-#-#--#-"                                                    ; 3e8c: 52          R
    db %"-#--#-#-"                                                    ; 3e8d: 4a          J
    db %"--####--"                                                    ; 3e8e: 3c          <
    db %"--------"                                                    ; 3e8f: 00          .
    db %"--------"                                                    ; 3e90: 00          .  ; 'R'
    db %"-#####--"                                                    ; 3e91: 7c          |
    db %"-#----#-"                                                    ; 3e92: 42          B
    db %"-#----#-"                                                    ; 3e93: 42          B
    db %"-#####--"                                                    ; 3e94: 7c          |
    db %"-#---#--"                                                    ; 3e95: 44          D
    db %"-#----#-"                                                    ; 3e96: 42          B
    db %"--------"                                                    ; 3e97: 00          .
    db %"--------"                                                    ; 3e98: 00          .  ; 'S'
    db %"--####--"                                                    ; 3e99: 3c          <
    db %"-#------"                                                    ; 3e9a: 40          @
    db %"--####--"                                                    ; 3e9b: 3c          <
    db %"------#-"                                                    ; 3e9c: 02          .
    db %"-#----#-"                                                    ; 3e9d: 42          B
    db %"--####--"                                                    ; 3e9e: 3c          <
    db %"--------"                                                    ; 3e9f: 00          .
    db %"--------"                                                    ; 3ea0: 00          .  ; 'T'
    db %"#######-"                                                    ; 3ea1: fe          .
    db %"---#----"                                                    ; 3ea2: 10          .
    db %"---#----"                                                    ; 3ea3: 10          .
    db %"---#----"                                                    ; 3ea4: 10          .
    db %"---#----"                                                    ; 3ea5: 10          .
    db %"---#----"                                                    ; 3ea6: 10          .
    db %"--------"                                                    ; 3ea7: 00          .
    db %"--------"                                                    ; 3ea8: 00          .  ; 'U'
    db %"-#----#-"                                                    ; 3ea9: 42          B
    db %"-#----#-"                                                    ; 3eaa: 42          B
    db %"-#----#-"                                                    ; 3eab: 42          B
    db %"-#----#-"                                                    ; 3eac: 42          B
    db %"-#----#-"                                                    ; 3ead: 42          B
    db %"--####--"                                                    ; 3eae: 3c          <
    db %"--------"                                                    ; 3eaf: 00          .
    db %"--------"                                                    ; 3eb0: 00          .  ; 'V'
    db %"-#----#-"                                                    ; 3eb1: 42          B
    db %"-#----#-"                                                    ; 3eb2: 42          B
    db %"-#----#-"                                                    ; 3eb3: 42          B
    db %"-#----#-"                                                    ; 3eb4: 42          B
    db %"--#--#--"                                                    ; 3eb5: 24          $
    db %"---##---"                                                    ; 3eb6: 18          .
    db %"--------"                                                    ; 3eb7: 00          .
    db %"--------"                                                    ; 3eb8: 00          .  ; 'W'
    db %"-#----#-"                                                    ; 3eb9: 42          B
    db %"-#----#-"                                                    ; 3eba: 42          B
    db %"-#----#-"                                                    ; 3ebb: 42          B
    db %"-#----#-"                                                    ; 3ebc: 42          B
    db %"-#-##-#-"                                                    ; 3ebd: 5a          Z
    db %"--#--#--"                                                    ; 3ebe: 24          $
    db %"--------"                                                    ; 3ebf: 00          .
    db %"--------"                                                    ; 3ec0: 00          .  ; 'X'
    db %"-#----#-"                                                    ; 3ec1: 42          B
    db %"--#--#--"                                                    ; 3ec2: 24          $
    db %"---##---"                                                    ; 3ec3: 18          .
    db %"---##---"                                                    ; 3ec4: 18          .
    db %"--#--#--"                                                    ; 3ec5: 24          $
    db %"-#----#-"                                                    ; 3ec6: 42          B
    db %"--------"                                                    ; 3ec7: 00          .
    db %"--------"                                                    ; 3ec8: 00          .  ; 'Y'
    db %"#-----#-"                                                    ; 3ec9: 82          .
    db %"-#---#--"                                                    ; 3eca: 44          D
    db %"--#-#---"                                                    ; 3ecb: 28          (
    db %"---#----"                                                    ; 3ecc: 10          .
    db %"---#----"                                                    ; 3ecd: 10          .
    db %"---#----"                                                    ; 3ece: 10          .
    db %"--------"                                                    ; 3ecf: 00          .
    db %"--------"                                                    ; 3ed0: 00          .  ; 'Z'
    db %"-######-"                                                    ; 3ed1: 7e          ~
    db %"-----#--"                                                    ; 3ed2: 04          .
    db %"----#---"                                                    ; 3ed3: 08          .
    db %"---#----"                                                    ; 3ed4: 10          .
    db %"--#-----"                                                    ; 3ed5: 20
    db %"-######-"                                                    ; 3ed6: 7e          ~
    db %"--------"                                                    ; 3ed7: 00          .
    db %"--------"                                                    ; 3ed8: 00          .  ; '['
    db %"----###-"                                                    ; 3ed9: 0e          .
    db %"----#---"                                                    ; 3eda: 08          .
    db %"----#---"                                                    ; 3edb: 08          .
    db %"----#---"                                                    ; 3edc: 08          .
    db %"----#---"                                                    ; 3edd: 08          .
    db %"----###-"                                                    ; 3ede: 0e          .
    db %"--------"                                                    ; 3edf: 00          .
    db %"--------"                                                    ; 3ee0: 00          .  ; '\'
    db %"--------"                                                    ; 3ee1: 00          .
    db %"-#------"                                                    ; 3ee2: 40          @
    db %"--#-----"                                                    ; 3ee3: 20
    db %"---#----"                                                    ; 3ee4: 10          .
    db %"----#---"                                                    ; 3ee5: 08          .
    db %"-----#--"                                                    ; 3ee6: 04          .
    db %"--------"                                                    ; 3ee7: 00          .
    db %"--------"                                                    ; 3ee8: 00          .  ; ']'
    db %"-###----"                                                    ; 3ee9: 70          p
    db %"---#----"                                                    ; 3eea: 10          .
    db %"---#----"                                                    ; 3eeb: 10          .
    db %"---#----"                                                    ; 3eec: 10          .
    db %"---#----"                                                    ; 3eed: 10          .
    db %"-###----"                                                    ; 3eee: 70          p
    db %"--------"                                                    ; 3eef: 00          .
    db %"--------"                                                    ; 3ef0: 00          .  ; '^'
    db %"---#----"                                                    ; 3ef1: 10          .
    db %"--###---"                                                    ; 3ef2: 38          8
    db %"-#-#-#--"                                                    ; 3ef3: 54          T
    db %"---#----"                                                    ; 3ef4: 10          .
    db %"---#----"                                                    ; 3ef5: 10          .
    db %"---#----"                                                    ; 3ef6: 10          .
    db %"--------"                                                    ; 3ef7: 00          .
    db %"--------"                                                    ; 3ef8: 00          .  ; '_'
    db %"--------"                                                    ; 3ef9: 00          .
    db %"--------"                                                    ; 3efa: 00          .
    db %"--------"                                                    ; 3efb: 00          .
    db %"--------"                                                    ; 3efc: 00          .
    db %"--------"                                                    ; 3efd: 00          .
    db %"--------"                                                    ; 3efe: 00          .
    db %"########"                                                    ; 3eff: ff          .
    db %"--------"                                                    ; 3f00: 00          .  ; $60 (pound sign)
    db %"---###--"                                                    ; 3f01: 1c          .
    db %"--#---#-"                                                    ; 3f02: 22          "
    db %"-####---"                                                    ; 3f03: 78          x
    db %"--#-----"                                                    ; 3f04: 20
    db %"--#-----"                                                    ; 3f05: 20
    db %"-######-"                                                    ; 3f06: 7e          ~
    db %"--------"                                                    ; 3f07: 00          .
    db %"--------"                                                    ; 3f08: 00          .  ; 'a'
    db %"--------"                                                    ; 3f09: 00          .
    db %"--###---"                                                    ; 3f0a: 38          8
    db %"-----#--"                                                    ; 3f0b: 04          .
    db %"--####--"                                                    ; 3f0c: 3c          <
    db %"-#---#--"                                                    ; 3f0d: 44          D
    db %"--#####-"                                                    ; 3f0e: 3e          >
    db %"--------"                                                    ; 3f0f: 00          .
    db %"--------"                                                    ; 3f10: 00          .  ; 'b'
    db %"--#-----"                                                    ; 3f11: 20
    db %"--#-----"                                                    ; 3f12: 20
    db %"--####--"                                                    ; 3f13: 3c          <
    db %"--#---#-"                                                    ; 3f14: 22          "
    db %"--#---#-"                                                    ; 3f15: 22          "
    db %"--####--"                                                    ; 3f16: 3c          <
    db %"--------"                                                    ; 3f17: 00          .
    db %"--------"                                                    ; 3f18: 00          .  ; 'c'
    db %"--------"                                                    ; 3f19: 00          .
    db %"---###--"                                                    ; 3f1a: 1c          .
    db %"--#-----"                                                    ; 3f1b: 20
    db %"--#-----"                                                    ; 3f1c: 20
    db %"--#-----"                                                    ; 3f1d: 20
    db %"---###--"                                                    ; 3f1e: 1c          .
    db %"--------"                                                    ; 3f1f: 00          .
    db %"--------"                                                    ; 3f20: 00          .  ; 'd'
    db %"-----#--"                                                    ; 3f21: 04          .
    db %"-----#--"                                                    ; 3f22: 04          .
    db %"--####--"                                                    ; 3f23: 3c          <
    db %"-#---#--"                                                    ; 3f24: 44          D
    db %"-#---#--"                                                    ; 3f25: 44          D
    db %"--#####-"                                                    ; 3f26: 3e          >
    db %"--------"                                                    ; 3f27: 00          .
    db %"--------"                                                    ; 3f28: 00          .  ; 'e'
    db %"--------"                                                    ; 3f29: 00          .
    db %"--###---"                                                    ; 3f2a: 38          8
    db %"-#---#--"                                                    ; 3f2b: 44          D
    db %"-####---"                                                    ; 3f2c: 78          x
    db %"-#------"                                                    ; 3f2d: 40          @
    db %"--####--"                                                    ; 3f2e: 3c          <
    db %"--------"                                                    ; 3f2f: 00          .
    db %"--------"                                                    ; 3f30: 00          .  ; 'f'
    db %"----##--"                                                    ; 3f31: 0c          .
    db %"---#----"                                                    ; 3f32: 10          .
    db %"---##---"                                                    ; 3f33: 18          .
    db %"---#----"                                                    ; 3f34: 10          .
    db %"---#----"                                                    ; 3f35: 10          .
    db %"---#----"                                                    ; 3f36: 10          .
    db %"--------"                                                    ; 3f37: 00          .
    db %"--------"                                                    ; 3f38: 00          .  ; 'g'
    db %"--------"                                                    ; 3f39: 00          .
    db %"--####--"                                                    ; 3f3a: 3c          <
    db %"-#---#--"                                                    ; 3f3b: 44          D
    db %"-#---#--"                                                    ; 3f3c: 44          D
    db %"--####--"                                                    ; 3f3d: 3c          <
    db %"-----#--"                                                    ; 3f3e: 04          .
    db %"--###---"                                                    ; 3f3f: 38          8
    db %"--------"                                                    ; 3f40: 00          .  ; 'h'
    db %"-#------"                                                    ; 3f41: 40          @
    db %"-#------"                                                    ; 3f42: 40          @
    db %"-####---"                                                    ; 3f43: 78          x
    db %"-#---#--"                                                    ; 3f44: 44          D
    db %"-#---#--"                                                    ; 3f45: 44          D
    db %"-#---#--"                                                    ; 3f46: 44          D
    db %"--------"                                                    ; 3f47: 00          .
    db %"--------"                                                    ; 3f48: 00          .  ; 'i'
    db %"---#----"                                                    ; 3f49: 10          .
    db %"--------"                                                    ; 3f4a: 00          .
    db %"--##----"                                                    ; 3f4b: 30          0
    db %"---#----"                                                    ; 3f4c: 10          .
    db %"---#----"                                                    ; 3f4d: 10          .
    db %"--###---"                                                    ; 3f4e: 38          8
    db %"--------"                                                    ; 3f4f: 00          .
    db %"--------"                                                    ; 3f50: 00          .  ; 'j'
    db %"-----#--"                                                    ; 3f51: 04          .
    db %"--------"                                                    ; 3f52: 00          .
    db %"-----#--"                                                    ; 3f53: 04          .
    db %"-----#--"                                                    ; 3f54: 04          .
    db %"-----#--"                                                    ; 3f55: 04          .
    db %"--#--#--"                                                    ; 3f56: 24          $
    db %"---##---"                                                    ; 3f57: 18          .
    db %"--------"                                                    ; 3f58: 00          .  ; 'k'
    db %"--#-----"                                                    ; 3f59: 20
    db %"--#-#---"                                                    ; 3f5a: 28          (
    db %"--##----"                                                    ; 3f5b: 30          0
    db %"--##----"                                                    ; 3f5c: 30          0
    db %"--#-#---"                                                    ; 3f5d: 28          (
    db %"--#--#--"                                                    ; 3f5e: 24          $
    db %"--------"                                                    ; 3f5f: 00          .
    db %"--------"                                                    ; 3f60: 00          .  ; 'l'
    db %"---#----"                                                    ; 3f61: 10          .
    db %"---#----"                                                    ; 3f62: 10          .
    db %"---#----"                                                    ; 3f63: 10          .
    db %"---#----"                                                    ; 3f64: 10          .
    db %"---#----"                                                    ; 3f65: 10          .
    db %"----##--"                                                    ; 3f66: 0c          .
    db %"--------"                                                    ; 3f67: 00          .
    db %"--------"                                                    ; 3f68: 00          .  ; 'm'
    db %"--------"                                                    ; 3f69: 00          .
    db %"-##-#---"                                                    ; 3f6a: 68          h
    db %"-#-#-#--"                                                    ; 3f6b: 54          T
    db %"-#-#-#--"                                                    ; 3f6c: 54          T
    db %"-#-#-#--"                                                    ; 3f6d: 54          T
    db %"-#-#-#--"                                                    ; 3f6e: 54          T
    db %"--------"                                                    ; 3f6f: 00          .
    db %"--------"                                                    ; 3f70: 00          .  ; 'n'
    db %"--------"                                                    ; 3f71: 00          .
    db %"-####---"                                                    ; 3f72: 78          x
    db %"-#---#--"                                                    ; 3f73: 44          D
    db %"-#---#--"                                                    ; 3f74: 44          D
    db %"-#---#--"                                                    ; 3f75: 44          D
    db %"-#---#--"                                                    ; 3f76: 44          D
    db %"--------"                                                    ; 3f77: 00          .
    db %"--------"                                                    ; 3f78: 00          .  ; 'o'
    db %"--------"                                                    ; 3f79: 00          .
    db %"--###---"                                                    ; 3f7a: 38          8
    db %"-#---#--"                                                    ; 3f7b: 44          D
    db %"-#---#--"                                                    ; 3f7c: 44          D
    db %"-#---#--"                                                    ; 3f7d: 44          D
    db %"--###---"                                                    ; 3f7e: 38          8
    db %"--------"                                                    ; 3f7f: 00          .
    db %"--------"                                                    ; 3f80: 00          .  ; 'p'
    db %"--------"                                                    ; 3f81: 00          .
    db %"-####---"                                                    ; 3f82: 78          x
    db %"-#---#--"                                                    ; 3f83: 44          D
    db %"-#---#--"                                                    ; 3f84: 44          D
    db %"-####---"                                                    ; 3f85: 78          x
    db %"-#------"                                                    ; 3f86: 40          @
    db %"-#------"                                                    ; 3f87: 40          @
    db %"--------"                                                    ; 3f88: 00          .  ; 'q'
    db %"--------"                                                    ; 3f89: 00          .
    db %"--####--"                                                    ; 3f8a: 3c          <
    db %"-#---#--"                                                    ; 3f8b: 44          D
    db %"-#---#--"                                                    ; 3f8c: 44          D
    db %"--####--"                                                    ; 3f8d: 3c          <
    db %"-----#--"                                                    ; 3f8e: 04          .
    db %"-----##-"                                                    ; 3f8f: 06          .
    db %"--------"                                                    ; 3f90: 00          .  ; 'r'
    db %"--------"                                                    ; 3f91: 00          .
    db %"---###--"                                                    ; 3f92: 1c          .
    db %"--#-----"                                                    ; 3f93: 20
    db %"--#-----"                                                    ; 3f94: 20
    db %"--#-----"                                                    ; 3f95: 20
    db %"--#-----"                                                    ; 3f96: 20
    db %"--------"                                                    ; 3f97: 00          .
    db %"--------"                                                    ; 3f98: 00          .  ; 's'
    db %"--------"                                                    ; 3f99: 00          .
    db %"--###---"                                                    ; 3f9a: 38          8
    db %"-#------"                                                    ; 3f9b: 40          @
    db %"--###---"                                                    ; 3f9c: 38          8
    db %"-----#--"                                                    ; 3f9d: 04          .
    db %"-####---"                                                    ; 3f9e: 78          x
    db %"--------"                                                    ; 3f9f: 00          .
    db %"--------"                                                    ; 3fa0: 00          .  ; 't'
    db %"---#----"                                                    ; 3fa1: 10          .
    db %"--###---"                                                    ; 3fa2: 38          8
    db %"---#----"                                                    ; 3fa3: 10          .
    db %"---#----"                                                    ; 3fa4: 10          .
    db %"---#----"                                                    ; 3fa5: 10          .
    db %"----##--"                                                    ; 3fa6: 0c          .
    db %"--------"                                                    ; 3fa7: 00          .
    db %"--------"                                                    ; 3fa8: 00          .  ; 'u'
    db %"--------"                                                    ; 3fa9: 00          .
    db %"-#---#--"                                                    ; 3faa: 44          D
    db %"-#---#--"                                                    ; 3fab: 44          D
    db %"-#---#--"                                                    ; 3fac: 44          D
    db %"-#---#--"                                                    ; 3fad: 44          D
    db %"--####--"                                                    ; 3fae: 3c          <
    db %"--------"                                                    ; 3faf: 00          .
    db %"--------"                                                    ; 3fb0: 00          .  ; 'v'
    db %"--------"                                                    ; 3fb1: 00          .
    db %"-#---#--"                                                    ; 3fb2: 44          D
    db %"-#---#--"                                                    ; 3fb3: 44          D
    db %"--#-#---"                                                    ; 3fb4: 28          (
    db %"--#-#---"                                                    ; 3fb5: 28          (
    db %"---#----"                                                    ; 3fb6: 10          .
    db %"--------"                                                    ; 3fb7: 00          .
    db %"--------"                                                    ; 3fb8: 00          .  ; 'w'
    db %"--------"                                                    ; 3fb9: 00          .
    db %"-#---#--"                                                    ; 3fba: 44          D
    db %"-#-#-#--"                                                    ; 3fbb: 54          T
    db %"-#-#-#--"                                                    ; 3fbc: 54          T
    db %"-#-#-#--"                                                    ; 3fbd: 54          T
    db %"--#-#---"                                                    ; 3fbe: 28          (
    db %"--------"                                                    ; 3fbf: 00          .
    db %"--------"                                                    ; 3fc0: 00          .  ; 'x'
    db %"--------"                                                    ; 3fc1: 00          .
    db %"-#---#--"                                                    ; 3fc2: 44          D
    db %"--#-#---"                                                    ; 3fc3: 28          (
    db %"---#----"                                                    ; 3fc4: 10          .
    db %"--#-#---"                                                    ; 3fc5: 28          (
    db %"-#---#--"                                                    ; 3fc6: 44          D
    db %"--------"                                                    ; 3fc7: 00          .
    db %"--------"                                                    ; 3fc8: 00          .  ; 'y'
    db %"--------"                                                    ; 3fc9: 00          .
    db %"-#---#--"                                                    ; 3fca: 44          D
    db %"-#---#--"                                                    ; 3fcb: 44          D
    db %"-#---#--"                                                    ; 3fcc: 44          D
    db %"--####--"                                                    ; 3fcd: 3c          <
    db %"-----#--"                                                    ; 3fce: 04          .
    db %"--###---"                                                    ; 3fcf: 38          8
    db %"--------"                                                    ; 3fd0: 00          .  ; 'z'
    db %"--------"                                                    ; 3fd1: 00          .
    db %"-#####--"                                                    ; 3fd2: 7c          |
    db %"----#---"                                                    ; 3fd3: 08          .
    db %"---#----"                                                    ; 3fd4: 10          .
    db %"--#-----"                                                    ; 3fd5: 20
    db %"-#####--"                                                    ; 3fd6: 7c          |
    db %"--------"                                                    ; 3fd7: 00          .
    db %"--------"                                                    ; 3fd8: 00          .  ; '{'
    db %"----###-"                                                    ; 3fd9: 0e          .
    db %"----#---"                                                    ; 3fda: 08          .
    db %"--##----"                                                    ; 3fdb: 30          0
    db %"--##----"                                                    ; 3fdc: 30          0
    db %"----#---"                                                    ; 3fdd: 08          .
    db %"----###-"                                                    ; 3fde: 0e          .
    db %"--------"                                                    ; 3fdf: 00          .
    db %"--------"                                                    ; 3fe0: 00          .  ; '|'
    db %"----#---"                                                    ; 3fe1: 08          .
    db %"----#---"                                                    ; 3fe2: 08          .
    db %"----#---"                                                    ; 3fe3: 08          .
    db %"----#---"                                                    ; 3fe4: 08          .
    db %"----#---"                                                    ; 3fe5: 08          .
    db %"----#---"                                                    ; 3fe6: 08          .
    db %"--------"                                                    ; 3fe7: 00          .
    db %"--------"                                                    ; 3fe8: 00          .  ; '}'
    db %"-###----"                                                    ; 3fe9: 70          p
    db %"---#----"                                                    ; 3fea: 10          .
    db %"----##--"                                                    ; 3feb: 0c          .
    db %"----##--"                                                    ; 3fec: 0c          .
    db %"---#----"                                                    ; 3fed: 10          .
    db %"-###----"                                                    ; 3fee: 70          p
    db %"--------"                                                    ; 3fef: 00          .
    db %"--##--#-"                                                    ; 3ff0: 32          2  ; '~'
    db %"-#--##--"                                                    ; 3ff1: 4c          L
    db %"--------"                                                    ; 3ff2: 00          .
    db %"--------"                                                    ; 3ff3: 00          .
    db %"--------"                                                    ; 3ff4: 00          .
    db %"--------"                                                    ; 3ff5: 00          .
    db %"--------"                                                    ; 3ff6: 00          .
    db %"--------"                                                    ; 3ff7: 00          .
    db %"--####--"                                                    ; 3ff8: 3c          <  ; $7F (copyright sign)
    db %"-#----#-"                                                    ; 3ff9: 42          B
    db %"#--##--#"                                                    ; 3ffa: 99          .
    db %"#-#----#"                                                    ; 3ffb: a1          .
    db %"#-#----#"                                                    ; 3ffc: a1          .
    db %"#--##--#"                                                    ; 3ffd: 99          .
    db %"-#----#-"                                                    ; 3ffe: 42          B
    db %"--####--"                                                    ; 3fff: 3c          <
pydis_end:

; ASSERT (($80 + $08) == $88)
; ASSERT (($80 + ' ') == $a0)
; ASSERT (($80 + '#') == $a3)
; ASSERT (($80 + '$') == $a4)
; ASSERT (($80 + '=') == $bd)
; ASSERT (($80 + '>') == $be)
; ASSERT (($80 + '?') == $bf)
; ASSERT (($80 + 'A') == $c1)
; ASSERT (($80 + 'B') == $c2)
; ASSERT (($80 + 'D') == $c4)
; ASSERT (($80 + 'E') == $c5)
; ASSERT (($80 + 'F') == $c6)
; ASSERT (($80 + 'H') == $c8)
; ASSERT (($80 + 'I') == $c9)
; ASSERT (($80 + 'K') == $cb)
; ASSERT (($80 + 'L') == $cc)
; ASSERT (($80 + 'M') == $cd)
; ASSERT (($80 + 'N') == $ce)
; ASSERT (($80 + 'O') == $cf)
; ASSERT (($80 + 'P') == $d0)
; ASSERT (($80 + 'R') == $d2)
; ASSERT (($80 + 'S') == $d3)
; ASSERT (($80 + 'T') == $d4)
; ASSERT (($80 + 'W') == $d7)
; ASSERT (($80 + 'Y') == $d9)
; ASSERT (($80 + 'd') == $e4)
; ASSERT (($80 + 'e') == $e5)
; ASSERT (($80 + 'm') == $ed)
; ASSERT (($80 + 'n') == $ee)
; ASSERT (($80 + 'r') == $f2)
; ASSERT (($80 + 's') == $f3)
; ASSERT (($80 + 't') == $f4)
; ASSERT (($80 + 'y') == $f9)
; ASSERT (((k_cur+1) - err_nr) == $22)
; ASSERT (((kstate+4) - err_nr) == -$36)
; ASSERT (((membot+10) - err_nr) == $62)
; ASSERT (((membot+23) - err_nr) == $6f)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+25) - err_nr) == $71)
; ASSERT (((membot+26) - err_nr) == $72)
; ASSERT (((membot+26) - err_nr) == $72)
; ASSERT (((s_posn+1) - err_nr) == $4f)
; ASSERT (((s_posn+1) - err_nr) == $4f)
; ASSERT (((x_ptr+1) - err_nr) == $26)
; ASSERT (((x_ptr+1) - err_nr) == $26)
; ASSERT (((x_ptr+1) - err_nr) == $26)
; ASSERT (((x_ptr+1) - err_nr) == $26)
; ASSERT ((_if) == $1cf0)
; ASSERT ((_out) == $1e7a)
; ASSERT ((bordcr - err_nr) == $0e)
; ASSERT ((bordcr - err_nr) == $0e)
; ASSERT ((breg - err_nr) == $2d)
; ASSERT ((breg - err_nr) == $2d)
; ASSERT ((circle) == $2320)
; ASSERT ((clear) == $1eac)
; ASSERT ((cls) == $0d6b)
; ASSERT ((cont) == $1e5f)
; ASSERT ((copy) == $0b1c)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((df_sz - err_nr) == $31)
; ASSERT ((dim) == $2c02)
; ASSERT ((eder) == $107f)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((err_nr - err_nr) == $00)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags - err_nr) == $01)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flags2 - err_nr) == $30)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((flagx - err_nr) == $37)
; ASSERT ((for) == $1d03)
; ASSERT ((gosub) == $1eed)
; ASSERT ((goto) == $1e67)
; ASSERT ((iderr) == $15c4)
; ASSERT ((iderr) == $15c4)
; ASSERT ((iderr) == $15c4)
; ASSERT ((input) == $2089)
; ASSERT ((k_data - err_nr) == -$2d)
; ASSERT ((kstate - err_nr) == -$3a)
; ASSERT ((kyip) == $10a6)
; ASSERT ((l03f8) == $03f8)
; ASSERT ((l053f) == $053f)
; ASSERT ((l053f) == $053f)
; ASSERT ((l09a1) == $09a1)
; ASSERT ((l09c3) == $09c3)
; ASSERT ((l0a58) == $0a77)
; ASSERT ((l0a5d) == $0a5d)
; ASSERT ((l0a87) == $0a87)
; ASSERT ((l0a87) == $0a87)
; ASSERT ((l0bbb) == $0bbb)
; ASSERT ((l108b) == $108b)
; ASSERT ((l110d) == $110d)
; ASSERT ((l16e5) == $16e5)
; ASSERT ((l1736) == $1736)
; ASSERT ((l18bc) == $18bc)
; ASSERT ((l1937) == $1937)
; ASSERT ((l1ded) == $1ded)
; ASSERT ((l1e27) == $1e27)
; ASSERT ((l1f60) == $1f60)
; ASSERT ((l2294) == $2294)
; ASSERT ((l2382) == $2382)
; ASSERT ((l38e6) == $38e4)
; ASSERT ((l3934) == $3933)
; ASSERT ((l3963) == $3963)
; ASSERT ((l3aa9) == $3aaa)
; ASSERT ((list) == $17f9)
; ASSERT ((llist) == $17f5)
; ASSERT ((lprint) == $1fc9)
; ASSERT ((mode - err_nr) == $07)
; ASSERT ((mode - err_nr) == $07)
; ASSERT ((mode - err_nr) == $07)
; ASSERT ((mode - err_nr) == $07)
; ASSERT ((mode - err_nr) == $07)
; ASSERT ((n_l_only) == $18ce)
; ASSERT ((new) == $11bb)
; ASSERT ((next) == $1dab)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((nsppc - err_nr) == $0a)
; ASSERT ((osppc - err_nr) == $36)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((p_flag - err_nr) == $57)
; ASSERT ((pause) == $1f3a)
; ASSERT ((plot) == $22dc)
; ASSERT ((poke) == $1e80)
; ASSERT ((pr_cc - err_nr) == $46)
; ASSERT ((print) == $1fcd)
; ASSERT ((prmain) == $09f4)
; ASSERT ((prmain) == $09f4)
; ASSERT ((rand) == $1e4f)
; ASSERT ((rasp - err_nr) == -$02)
; ASSERT ((rem) == $1bb2)
; ASSERT ((restore) == $1e42)
; ASSERT ((return) == $1f23)
; ASSERT ((run) == $1ea1)
; ASSERT ((s_posnl - err_nr) == $50)
; ASSERT ((scan_loop) == $1b52)
; ASSERT ((scr_ct - err_nr) == $52)
; ASSERT ((scr_ct - err_nr) == $52)
; ASSERT ((scr_ct - err_nr) == $52)
; ASSERT ((stop) == $1cee)
; ASSERT ((strlen - err_nr) == $38)
; ASSERT ((subppc - err_nr) == $0d)
; ASSERT ((subppc - err_nr) == $0d)
; ASSERT ((subppc - err_nr) == $0d)
; ASSERT ((subppc - err_nr) == $0d)
; ASSERT ((subppc - err_nr) == $0d)
; ASSERT ((subppc - err_nr) == $0d)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((tv_flag - err_nr) == $02)
; ASSERT ((x80_fabs) == $344e)
; ASSERT ((x80_facos) == $380c)
; ASSERT ((x80_fadd) == $3014)
; ASSERT ((x80_fasc) == $363e)
; ASSERT ((x80_fasin) == $37fc)
; ASSERT ((x80_fatan) == $37ab)
; ASSERT ((x80_fband) == $3500)
; ASSERT ((x80_fbands) == $3509)
; ASSERT ((x80_fbor) == $34f7)
; ASSERT ((x80_fcat) == $3574)
; ASSERT ((x80_fce) == $3670)
; ASSERT ((x80_fchrs) == $35a2)
; ASSERT ((x80_fcos) == $377b)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp) == $3517)
; ASSERT ((x80_fcp_gz) == $34d5)
; ASSERT ((x80_fcp_lz) == $34e2)
; ASSERT ((x80_fdel) == $33a5)
; ASSERT ((x80_fdel) == $33a5)
; ASSERT ((x80_fdiv) == $31af)
; ASSERT ((x80_fdjnz) == $364f)
; ASSERT ((x80_fexp) == $3699)
; ASSERT ((x80_fget) == $3755)
; ASSERT ((x80_fgt) == $3400)
; ASSERT ((x80_fhexs) == $3863)
; ASSERT ((x80_fin) == $3485)
; ASSERT ((x80_fint) == $3684)
; ASSERT ((x80_fjp) == $365b)
; ASSERT ((x80_fjpt) == $3664)
; ASSERT ((x80_flen) == $3649)
; ASSERT ((x80_flogn) == $36e7)
; ASSERT ((x80_fmod) == $3675)
; ASSERT ((x80_fmove) == $33c4)
; ASSERT ((x80_fmul) == $30ca)
; ASSERT ((x80_fneg) == $3452)
; ASSERT ((x80_fnot) == $34dd)
; ASSERT ((x80_fpeek) == $348c)
; ASSERT ((x80_fread) == $361c)
; ASSERT ((x80_frstk) == $3297)
; ASSERT ((x80_fsgen) == $342d)
; ASSERT ((x80_fsgl) == $33a6)
; ASSERT ((x80_fsgn) == $3472)
; ASSERT ((x80_fsin) == $3786)
; ASSERT ((x80_fsqrt) == $3813)
; ASSERT ((x80_fst) == $3411)
; ASSERT ((x80_fstk) == $33ca)
; ASSERT ((x80_fstkc) == $340c)
; ASSERT ((x80_fstrs) == $35ef)
; ASSERT ((x80_fsub) == $300f)
; ASSERT ((x80_ftan) == $0df5)
; ASSERT ((x80_ftop) == $3846)
; ASSERT ((x80_ftrn) == $3214)
; ASSERT ((x80_fusr) == $3493)
; ASSERT ((x80_fusrs) == $349c)
; ASSERT ((x80_fval) == $35b1)
; ASSERT ((x80_fval) == $35b1)
; ASSERT ((x80_fxch) == $3421)

; Label references by decreasing frequency:
;     _next_ch:     90
;     _fp_calc:     79
;     _get_ch:      54
;     _error_1:     44
;     syntax_z:     37
;     report_c:     33
;     check_end:    27
;     _print_a:     23
;     ch_add:       22
;     stkend:       20
;     find_int:     18
;     t_addr:       18
;     e_line:       17
;     class_6:      16
;     k_cur:        16
;     err_sp:       15
;     stk_fetch:    15
;     l1601:        14
;     make_room:    14
;     prog:         14
;     x_ptr:        14
;     next_one:     12
;     scanning:     12
;     stack_a:      12
;     worksp:       12
;     l0dd9:        11
;     l28ab:        11
;     line_addr:    11
;     _bc_spaces:   10
;     curchl:       10
;     fp_to_a:      10
;     report_6:     10
;     attr_t:        9
;     dest:          9
;     tstzero:       9
;     vars:          9
;     e_ppc:         8
;     fp_to_bc:      8
;     getbyte:       8
;     reclaim_2:     8
;     stk_store:     8
;     alpha:         7
;     alphanum:      7
;     coords:        7
;     flags:         7
;     ioorerr:       7
;     numeric:       7
;     syntax3:       7
;     trcurp:        7
;     add_char:      6
;     attr_p:        6
;     chans:         6
;     clslower:      6
;     fetchi:        6
;     mem:           6
;     newppc:        6
;     p_flag:        6
;     ppc:           6
;     reclaim_1:     6
;     report_3:      6
;     s_cont_2:      6
;     s_push_po:     6
;     udg:           6
;     unstack_z:     6
;     bordcr:        5
;     cochng:        5
;     defadd:        5
;     fetch_two:     5
;     invcolerr:     5
;     l03a1:         5
;     l0b03:         5
;     l0c0a:         5
;     l16dc:         5
;     l30a9:         5
;     look_vars:     5
;     p_ramt:        5
;     ramtop:        5
;     s_posn:        5
;     s_posnl:       5
;     stack_bc1:     5
;     stk_pntrs:     5
;     stkbot:        5
;     v_run_syn:     5
;     waitkey:       5
;     ch_add_1:      4
;     datadd:        4
;     echo_e:        4
;     err_nr:        4
;     fp_0_1:        4
;     hl_hl_de:      4
;     l056b:         4
;     l05e7:         4
;     l0e9b:         4
;     l1095:         4
;     l18ee:         4
;     l21b2:         4
;     l33b8:         4
;     l3b94:         4
;     l3ca0:         4
;     no_to_stk:     4
;     number:        4
;     nxtlin:        4
;     oflow_clr:     4
;     out_code:      4
;     out_digit:     4
;     parerr:        4
;     prep_m_d:      4
;     prsepr:        4
;     report_4:      4
;     report_b1:     4
;     report_b2:     4
;     s_numeric:     4
;     s_top:         4
;     skipstats:     4
;     test_room:     4
;     bc_spaces1:    3
;     chanflag:      3
;     chars:         3
;     class_1:       3
;     e_format:      3
;     e_to_fp:       3
;     editor:        3
;     goto_2:        3
;     int_to_fp:     3
;     invarg:        3
;     invstrm2:      3
;     ipitem:        3
;     l03b5:         3
;     l04d8:         3
;     l05e3:         3
;     l0767:         3
;     l0802:         3
;     l0c3b:         3
;     l0c55:         3
;     l0daf:         3
;     l0e44:         3
;     l0f14:         3
;     l1167:         3
;     l11a7:         3
;     l12ac:         3
;     l1756:         3
;     l1835:         3
;     l1d86:         3
;     l1fbd:         3
;     l24ff:         3
;     l250f:         3
;     l2522:         3
;     l2d8e:         3
;     l2f52:         3
;     l3293:         3
;     l3915:         3
;     l3a40:         3
;     l3a9b:         3
;     l3ac8:         3
;     let:           3
;     lineend:       3
;     loc_mem:       3
;     nsppc:         3
;     oserror:       3
;     out_num:       3
;     poke1:         3
;     prserp3:       3
;     report_b:      3
;     report_d:      3
;     s_loop:        3
;     s_next:        3
;     s_stk_dec:     3
;     scr_ct:        3
;     seed:          3
;     set_mem:       3
;     setmin:        3
;     shift_fp:      3
;     stk_to_bc:     3
;     stk_var:       3
;     stmtlp:        3
;     streamfe:      3
;     sv_dim:        3
;     test_5_sp:     3
;     x80_fmove:     3
;     add_back:      2
;     anyi:          2
;     breg:          2
;     chltchk:       2
;     citemsr:       2
;     class_8:       2
;     cls:           2
;     cp_lines:      2
;     cursor_so:     2
;     de_de_1:       2
;     df_cc:         2
;     df_ccl:        2
;     df_sz:         2
;     div_start:     2
;     eline_no:      2
;     frst_less:     2
;     goto:          2
;     hl_over:       2
;     inpas:         2
;     inputad:       2
;     int_exp1:      2
;     int_exp2:      2
;     keyboard:      2
;     l02d1:         2
;     l0310:         2
;     l031e:         2
;     l0333:         2
;     l034b:         2
;     l03d6:         2
;     l04c2:         2
;     l0514:         2
;     l0556:         2
;     l0574:         2
;     l0652:         2
;     l0672:         2
;     l075a:         2
;     l07a6:         2
;     l07e9:         2
;     l08f0:         2
;     l0921:         2
;     l092c:         2
;     l0a70:         2
;     l0ad9:         2
;     l0af6:         2
;     l0b5f:         2
;     l0b65:         2
;     l0bd0:         2
;     l0bdb:         2
;     l0bfa:         2
;     l0c08:         2
;     l0c22:         2
;     l0c41:         2
;     l0cce:         2
;     l0e88:         2
;     l0ed4:         2
;     l100e:         2
;     l10f4:         2
;     l1105:         2
;     l111d:         2
;     l117c:         2
;     l1195:         2
;     l12a2:         2
;     l130f:         2
;     l171e:         2
;     l178b:         2
;     l1819:         2
;     l1822:         2
;     l1959:         2
;     l1c56:         2
;     l1cde:         2
;     l1e0a:         2
;     l1fa6:         2
;     l2070:         2
;     l21e1:         2
;     l2257:         2
;     l22aa:         2
;     l22e5:         2
;     l2414:         2
;     l247d:         2
;     l253e:         2
;     l2569:         2
;     l25cb:         2
;     l25d9:         2
;     l2660:         2
;     l26dd:         2
;     l274c:         2
;     l2885:         2
;     l2ab6:         2
;     l2b29:         2
;     l2cb3:         2
;     l2dc1:         2
;     l2e7b:         2
;     l2f0c:         2
;     l2f8b:         2
;     l382f:         2
;     l3882:         2
;     l38ce:         2
;     l3909:         2
;     l3943:         2
;     l3977:         2
;     l398d:         2
;     l39a7:         2
;     l39c6:         2
;     l39f3:         2
;     l3a15:         2
;     l3a5f:         2
;     l3a92:         2
;     l3a9e:         2
;     l3bc6:         2
;     l3c01:         2
;     l3c0b:         2
;     l3c44:         2
;     l_char:        2
;     l_no_sp:       2
;     last_k:        2
;     left_edge:     2
;     line_no:       2
;     line_null:     2
;     linedraw:      2
;     lineuse:       2
;     list_sp:       2
;     mprseplp:      2
;     n_l_key:       2
;     next_lett:     2
;     next_loop:     2
;     oflw2_clr:     2
;     opcursor:      2
;     p_posn:        2
;     pau2:          2
;     plot:          2
;     pointers:      2
;     prep_add:      2
;     print2:        2
;     print_fp:      2
;     pritem:        2
;     prmain:        2
;     prterm:        2
;     r1offcl:       2
;     repdel:        2
;     report_2:      2
;     report_f:      2
;     restorez:      2
;     rslt_zero:     2
;     s_pi_end:      2
;     s_rnd_end:     2
;     set_strln:     2
;     set_top:       2
;     setwork:       2
;     sexpt2nums:    2
;     sl_define:     2
;     sl_rpt_c:      2
;     sl_second:     2
;     slicing:       2
;     stk_digit:     2
;     stk_to_a:      2
;     stmtnext1:     2
;     str_test:      2
;     strlen:        2
;     subppc:        2
;     sv_count:      2
;     sv_rpt_c:      2
;     sv_slice:      2
;     terror:        2
;     tvdata:        2
;     v_end:         2
;     v_found_2:     2
;     v_pass:        2
;     words:         2
;     wtky2:         2
;     x80_fnot:      2
;     zero_rslt:     2
;     _start:        1
;     add_rep_6:     1
;     addend_0:      1
;     addition:      1
;     all_added:     1
;     atsr4:         1
;     aul4:          1
;     autolist:      1
;     bit_5_nil:     1
;     bits_zero:     1
;     both_null:     1
;     break_1:       1
;     byte_comp:     1
;     byte_zero:     1
;     calculate:     1
;     citem:         1
;     class_0:       1
;     class_4_2:     1
;     class_a:       1
;     clr1:          1
;     clr3:          1
;     clr4:          1
;     cofbok:        1
;     coinverse:     1
;     copy_over:     1
;     cotemp4:       1
;     count_one:     1
;     d_letter:      1
;     d_no_loop:     1
;     d_rport_c:     1
;     d_run:         1
;     d_size:        1
;     dec_to_fp:     1
;     decint:        1
;     differ:        1
;     digit_inc:     1
;     dim_sizes:     1
;     div_loop:      1
;     divn_expt:     1
;     double_a:      1
;     e_fp:          1
;     edag:          1
;     edit_key:      1
;     end_compl:     1
;     end_tests:     1
;     endfn:         1
;     ent_table:     1
;     error_2:       1
;     error_3:       1
;     ex_or_not:     1
;     fincstat:      1
;     first_38:      1
;     flagx:         1
;     fnsy4:         1
;     fnsy5:         1
;     fnsyn:         1
;     form_exp:      1
;     fp_a_end:      1
;     fpbcint:       1
;     fptrunct:      1
;     frames:        1
;     gen_ent_1:     1
;     gen_ent_2:     1
;     get_param:     1
;     getibc:        1
;     go_nc_mlt:     1
;     hl_again:      1
;     hl_loop:       1
;     i_carry:       1
;     i_restore:     1
;     inp2:          1
;     inp7:          1
;     inp9:          1
;     input_rep:     1
;     invstrm:       1
;     ix_end:        1
;     jump_2:        1
;     k_data:        1
;     l0013:         1
;     l005f:         1
;     l007d:         1
;     l0094:         1
;     l0099:         1
;     l0296:         1
;     l029f:         1
;     l02a1:         1
;     l02ab:         1
;     l02bf:         1
;     l02c6:         1
;     l02f1:         1
;     l0308:         1
;     l032c:         1
;     l035a:         1
;     l035f:         1
;     l037a:         1
;     l0381:         1
;     l0395:         1
;     l03b2:         1
;     l03f2:         1
;     l03f6:         1
;     l0425:         1
;     l0427:         1
;     l04aa:         1
;     l04b9:         1
;     l04d0:         1
;     l04ea:         1
;     l04f2:         1
;     l04fe:         1
;     l0505:         1
;     l0507:         1
;     l050e:         1
;     l0511:         1
;     l051a:         1
;     l051c:         1
;     l0525:         1
;     l053c:         1
;     l0554:         1
;     l056c:         1
;     l0580:         1
;     l058f:         1
;     l05a9:         1
;     l05b3:         1
;     l05bd:         1
;     l05c2:         1
;     l05c5:         1
;     l05c8:         1
;     l05ca:         1
;     l05e9:         1
;     l05ed:         1
;     l0605:         1
;     l0621:         1
;     l0629:         1
;     l0644:         1
;     l064b:         1
;     l0685:         1
;     l068f:         1
;     l0692:         1
;     l06a0:         1
;     l06c3:         1
;     l06e1:         1
;     l06f0:         1
;     l06f5:         1
;     l06f9:         1
;     l0710:         1
;     l0716:         1
;     l0723:         1
;     l073a:         1
;     l078a:         1
;     l07ad:         1
;     l07cb:         1
;     l07f4:         1
;     l0800:         1
;     l0808:         1
;     l0819:         1
;     l0825:         1
;     l082e:         1
;     l084c:         1
;     l0873:         1
;     l08ad:         1
;     l08b6:         1
;     l08d2:         1
;     l08d7:         1
;     l08df:         1
;     l08eb:         1
;     l08f9:         1
;     l0901:         1
;     l0909:         1
;     l0912:         1
;     l091e:         1
;     l0923:         1
;     l093e:         1
;     l0955:         1
;     l0958:         1
;     l0970:         1
;     l0991:         1
;     l09af:         1
;     l09bb:         1
;     l09c2:         1
;     l09e5:         1
;     l0a59:         1
;     l0a5b:         1
;     l0a6d:         1
;     l0a7e:         1
;     l0aa6:         1
;     l0abc:         1
;     l0ac2:         1
;     l0ac3:         1
;     l0ad0:         1
;     l0adc:         1
;     l0aea:         1
;     l0b24:         1
;     l0b38:         1
;     l0b3e:         1
;     l0b4c:         1
;     l0b52:         1
;     l0b6a:         1
;     l0b76:         1
;     l0b7f:         1
;     l0b87:         1
;     l0b98:         1
;     l0ba0:         1
;     l0bb6:         1
;     l0bdd9:        1
;     l0c10:         1
;     l0c14:         1
;     l0c35:         1
;     l0c81:         1
;     l0c88:         1
;     l0cec:         1
;     l0cf4:         1
;     l0d02:         1
;     l0d1c:         1
;     l0d2d:         1
;     l0d5b:         1
;     l0d65:         1
;     l0d87:         1
;     l0d89:         1
;     l0d8e:         1
;     l0d94:         1
;     l0da0:         1
;     l0dd3:         1
;     l0de5:         1
;     l0dfe:         1
;     l0e00:         1
;     l0e05:         1
;     l0e0d:         1
;     l0e19:         1
;     l0e4a:         1
;     l0e4d:         1
;     l0e80:         1
;     l0eac:         1
;     l0ebb:         1
;     l0ec5:         1
;     l0ede:         1
;     l0eed:         1
;     l0f00:         1
;     l0f1a:         1
;     l0f6c:         1
;     l0f87:         1
;     l0f8e:         1
;     l0f92:         1
;     l0ff9:         1
;     l0fff:         1
;     l100f:         1
;     l101a:         1
;     l101f:         1
;     l1037:         1
;     l1042:         1
;     l1056:         1
;     l105e:         1
;     l1068:         1
;     l10b3:         1
;     l10d9:         1
;     l10e6:         1
;     l10fa:         1
;     l1113:         1
;     l111b:         1
;     l1150:         1
;     l115e:         1
;     l1179:         1
;     l117e:         1
;     l1190:         1
;     l11cb:         1
;     l11cf:         1
;     l12a9:         1
;     l12cf:         1
;     l1301:         1
;     l1344:         1
;     l134a:         1
;     l1373:         1
;     l1376:         1
;     l1384:         1
;     l1386:         1
;     l1555:         1
;     l15ab:         1
;     l15f7:         1
;     l1610:         1
;     l162c:         1
;     l1646:         1
;     l16db:         1
;     l16fc:         1
;     l1701:         1
;     l1714:         1
;     l1716:         1
;     l1727:         1
;     l175d:         1
;     l1767:         1
;     l17ce:         1
;     l17e4:         1
;     l17ed:         1
;     l17fb:         1
;     l181f:         1
;     l1833:         1
;     l1860:         1
;     l187f:         1
;     l1883:         1
;     l1885:         1
;     l1895:         1
;     l18a6:         1
;     l18a8:         1
;     l18b4:         1
;     l18b5:         1
;     l18e5:         1
;     l18ff:         1
;     l1903:         1
;     l190c:         1
;     l1946:         1
;     l1963:         1
;     l1967:         1
;     l1990:         1
;     l1998:         1
;     l199a:         1
;     l19a5:         1
;     l19b1:         1
;     l1b17:         1
;     l1b7d:         1
;     l1b9e:         1
;     l1cb9:         1
;     l1cd2:         1
;     l1cd7:         1
;     l1d00:         1
;     l1d64:         1
;     l1d7c:         1
;     l1d84:         1
;     l1d8b:         1
;     l1da3:         1
;     l1dec:         1
;     l1e1e:         1
;     l1e2c:         1
;     l1e37:         1
;     l1e39:         1
;     l1f1a:         1
;     l1f1f:         1
;     l1f49:         1
;     l1f6a:         1
;     l1f7d:         1
;     l1f86:         1
;     l1f89:         1
;     l1f94:         1
;     l1fcf:         1
;     l203c:         1
;     l2048:         1
;     l2061:         1
;     l206e:         1
;     l207c:         1
;     l2096:         1
;     l20ad:         1
;     l20ed:         1
;     l20fa:         1
;     l211c:         1
;     l2148:         1
;     l2161:         1
;     l2174:         1
;     l219b:         1
;     l21af:         1
;     l21d0:         1
;     l2211:         1
;     l2234:         1
;     l223e:         1
;     l2246:         1
;     l2258:         1
;     l2273:         1
;     l227d:         1
;     l22a6:         1
;     l22cb:         1
;     l22d4:         1
;     l22f0:         1
;     l22fd:         1
;     l2303:         1
;     l233b:         1
;     l235a:         1
;     l238d:         1
;     l2405:         1
;     l2408:         1
;     l2425:         1
;     l2439:         1
;     l2495:         1
;     l2497:         1
;     l24c4:         1
;     l24cb:         1
;     l24ce:         1
;     l24d4:         1
;     l24db:         1
;     l24df:         1
;     l24ec:         1
;     l24f7:         1
;     l252d:         1
;     l2535:         1
;     l253b:         1
;     l2549:         1
;     l254c:         1
;     l2562:         1
;     l2563:         1
;     l257e:         1
;     l2580:         1
;     l25be:         1
;     l2665:         1
;     l2684:         1
;     l2695:         1
;     l26b6:         1
;     l26df:         1
;     l27bd:         1
;     l27d9:         1
;     l27e4:         1
;     l27f4:         1
;     l27f7:         1
;     l2802:         1
;     l2808:         1
;     l2814:         1
;     l2825:         1
;     l2831:         1
;     l2843:         1
;     l2852:         1
;     l288d:         1
;     l28e3:         1
;     l2951:         1
;     l295a:         1
;     l296b:         1
;     l2981:         1
;     l2991:         1
;     l2b1f:         1
;     l2bea:         1
;     l2c7c:         1
;     l2ca2:         1
;     l2cb8:         1
;     l2cd5:         1
;     l2cf2:         1
;     l2d55:         1
;     l2d60:         1
;     l2d71:         1
;     l2d7b:         1
;     l2e01:         1
;     l2e1e:         1
;     l2e24:         1
;     l2e56:         1
;     l2e6f:         1
;     l2e8a:         1
;     l2ea1:         1
;     l2ea9:         1
;     l2eb3:         1
;     l2eb8:         1
;     l2ecb:         1
;     l2ecf:         1
;     l2edf:         1
;     l2eec:         1
;     l2eef:         1
;     l2f18:         1
;     l2f25:         1
;     l2f2d:         1
;     l2f46:         1
;     l2f4a:         1
;     l2f59:         1
;     l2f5e:         1
;     l2f64:         1
;     l2f6c:         1
;     l2f83:         1
;     l2f85:         1
;     l3032:         1
;     l303c:         1
;     l30ea:         1
;     l3221:         1
;     l3232:         1
;     l3296:         1
;     l32b1:         1
;     l32b2:         1
;     l32bd:         1
;     l3403:         1
;     l3468:         1
;     l347f:         1
;     l34af:         1
;     l34c0:         1
;     l359a:         1
;     l35dc:         1
;     l388b:         1
;     l3893:         1
;     l3898:         1
;     l38af:         1
;     l38c7:         1
;     l38ec:         1
;     l3914:         1
;     l391b:         1
;     l391d:         1
;     l3927:         1
;     l394d:         1
;     l3954:         1
;     l3958:         1
;     l397f:         1
;     l3989:         1
;     l3990:         1
;     l39ba:         1
;     l39d0:         1
;     l39db:         1
;     l39ec:         1
;     l3a01:         1
;     l3a05:         1
;     l3a1b:         1
;     l3a1d:         1
;     l3a1e:         1
;     l3a34:         1
;     l3a44:         1
;     l3a4f:         1
;     l3a51:         1
;     l3a52:         1
;     l3a68:         1
;     l3a74:         1
;     l3abc:         1
;     l3ad6:         1
;     l3ad9:         1
;     l3adc:         1
;     l3b01:         1
;     l3b0e:         1
;     l3b1c:         1
;     l3b29:         1
;     l3b41:         1
;     l3b63:         1
;     l3b74:         1
;     l3b90:         1
;     l3b98:         1
;     l3bac:         1
;     l3bc1:         1
;     l3bd7:         1
;     l3c4c:         1
;     l3c58:         1
;     l3c5e:         1
;     l3c6f:         1
;     l3c72:         1
;     l3c76:         1
;     l3c77:         1
;     l3c7d:         1
;     l3ca1:         1
;     l_adds:        1
;     l_deletes:     1
;     l_each_ch:     1
;     l_enter:       1
;     l_exists:      1
;     l_in_w_s:      1
;     l_length:      1
;     l_news:        1
;     l_numeric:     1
;     l_single:      1
;     l_string:      1
;     lead_sp:       1
;     left_key:      1
;     less_mask:     1
;     linerun:       1
;     lines:         1
;     lmt_step:      1
;     ln_fetch:      1
;     make_expt:     1
;     mlt_loop:      1
;     mode:          1
;     multiply:      1
;     n_l_line:      1
;     n_negtv:       1
;     near_zero:     1
;     neg_byte:      1
;     negate:        1
;     next_add:      1
;     next_five:     1
;     next_line:     1
;     next_ptr:      1
;     next_test:     1
;     nextchar:      1
;     nextchar2:     1
;     nextstat:      1
;     nil_bytes:     1
;     nmi_ret:       1
;     no_add:        1
;     no_number:     1
;     no_rstore:     1
;     nonsense:      1
;     normalize:     1
;     norml_now:     1
;     nu_or_str:     1
;     nxt_dgt_1:     1
;     nxt_dgt_2:     1
;     oflw1_clr:     1
;     oldppc:        1
;     one_shift:     1
;     one_space:     1
;     other_str:     1
;     out_line:      1
;     out_no:        1
;     pau1:          1
;     pip:           1
;     poke_save:     1
;     pr_cc:         1
;     prcifrn:       1
;     print3:        1
;     print_sp:      1
;     pritem2:       1
;     pritem4:       1
;     prompt:        1
;     ptr_done:      1
;     pydis_start:   1
;     qmult:         1
;     ram_check:     1
;     rasp:          1
;     reorder:       1
;     report6_2:     1
;     report_1:      1
;     report_7:      1
;     repper:        1
;     reserve:       1
;     result_ok:     1
;     right_key:     1
;     rterr:         1
;     s_cont_3:      1
;     s_endloop:     1
;     s_let_num:     1
;     s_no_to_s:     1
;     s_not_and:     1
;     s_opertr:      1
;     s_rprt_c2:     1
;     s_runtest:     1
;     s_string:      1
;     s_syntest:     1
;     s_tighter:     1
;     scan_ent:      1
;     scanfix:       1
;     sec_plus:      1
;     secnd_low:     1
;     separator:     1
;     set_seed:      1
;     set_stk:       1
;     setudg:        1
;     setudg1:       1
;     setudg2:       1
;     setudg3:       1
;     sexpt1num:     1
;     shift_len:     1
;     shift_one:     1
;     sign_done:     1
;     sign_to_c:     1
;     skip_zero:     1
;     sl_over:       1
;     sl_store:      1
;     small:         1
;     st_e_part:     1
;     stacka:        1
;     statlost:      1
;     stk_code:      1
;     stk_st_0:      1
;     stk_zeros:     1
;     strings:       1
;     strt_mlt:      1
;     subn_only:     1
;     sv_arrays:     1
;     sv_chadd:      1
;     sv_close:      1
;     sv_comma:      1
;     sv_elems:      1
;     sv_loop:       1
;     sv_mult:       1
;     sv_number:     1
;     sv_ptr:        1
;     sv_sliceq:     1
;     sv_smples:     1
;     swap_byte:     1
;     temp_ptr:      1
;     test_end:      1
;     test_neg:      1
;     test_norm:     1
;     test_sp:       1
;     thousand:      1
;     trunct2:       1
;     trunct3:       1
;     trunct4:       1
;     trunct5:       1
;     units:         1
;     use_one:       1
;     v_80_byte:     1
;     v_char:        1
;     v_each:        1
;     v_found_1:     1
;     v_get_ptr:     1
;     v_matches:     1
;     v_next:        1
;     v_run:         1
;     v_spaces:      1
;     v_str_var:     1
;     v_syntax:      1
;     x360f:         1
;     x3621:         1
;     x362c:         1
;     x36e6:         1
;     x80_fcp_gz:    1
;     x80_fexp:      1
;     x80_fjp:       1
;     x80_fneg:      1
;     x80_frstk:     1
;     x80_fstk:      1
;     x80_fsub:      1
;     x80_fxch:      1
;     x_large:       1
;     zero_de:       1
;     zeros_4_5:     1

; Stats:
;
;     Total size (Code + Data) = 16384 bytes
;     Code                     = 13135 bytes (80%)
;     Data                     = 3249 bytes (20%)
;
;     Number of instructions   = 7453
;     Number of data bytes     = 2066 bytes
;     Number of data words     = 236 bytes
;     Number of string bytes   = 947 bytes
;     Number of strings        = 139

