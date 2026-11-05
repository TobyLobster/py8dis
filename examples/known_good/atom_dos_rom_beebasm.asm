; Memory locations

; Zero page (&0000-&00ff)
basic_error_number  = &0000
basic_line_number   = &0001
l009a               = &009a
l009b               = &009b
l009c               = &009c
l009d               = &009d
l009e               = &009e
l009f               = &009f
l00a0               = &00a0
l00a1               = &00a1
l00a2               = &00a2
l00a3               = &00a3
l00a4               = &00a4
l00a5               = &00a5
l00ac               = &00ac
l00ad               = &00ad
l00ae               = &00ae
l00b5               = &00b5
l00b6               = &00b6
l00b7               = &00b7
l00b8               = &00b8
l00b9               = &00b9
l00ba               = &00ba
l00bb               = &00bb
l00bf               = &00bf
l00c0               = &00c0
l00c1               = &00c1
l00c2               = &00c2
l00c3               = &00c3
l00c4               = &00c4
l00c5               = &00c5
l00c6               = &00c6
l00c7               = &00c7
l00c8               = &00c8
l00c9               = &00c9
l00ca               = &00ca
l00cb               = &00cb
l00cc               = &00cc
l00cd               = &00cd
l00ce               = &00ce
l00cf               = &00cf
l00d0               = &00d0
l00d1               = &00d1
l00d2               = &00d2
l00d3               = &00d3
l00d4               = &00d4
l00d5               = &00d5
l00d6               = &00d6
l00e2               = &00e2
l00e3               = &00e3
l00e4               = &00e4
l00e5               = &00e5
l00e9               = &00e9
nomon_flag          = &00ea
l00eb               = &00eb
l00ec               = &00ec
l00ed               = &00ed
l00ee               = &00ee
l00ef               = &00ef
l00f0               = &00f0
l00f1               = &00f1
nmi_buffer_address  = &00f6
l00f7               = &00f7
irq_save_a          = &00ff

; Input buffer (&0100-&013f)
input_buffer = &0100

; String buffer (&0140-&017f)
string_buffer   = &0140

; OS vectors (&0200-&021f)
nmivec  = &0200
comvec  = &0206
wrcvec  = &0208
rdcvec  = &020a
lodvec  = &020c

; Extension memory (&0400-&27ff)
l0400               = &0400
l0500               = &0500
l0600               = &0600
l0700               = &0700
crtc_address        = &0800
crtc_data           = &0801
fdc_command_status  = &0a00
fdc_parameter_result = &0a01
fdc_reset           = &0a02
fdc_data            = &0a04
l1fff               = &1fff
l2000               = &2000
l2007               = &2007
l2008               = &2008
l200e               = &200e
l200f               = &200f
l2010               = &2010
l20f8               = &20f8
l2101               = &2101
l2102               = &2102
l2103               = &2103
l2104               = &2104
l2105               = &2105
l2106               = &2106
l2107               = &2107
l2108               = &2108
l210c               = &210c
l210d               = &210d
l210e               = &210e
l210f               = &210f
l2110               = &2110
l2200               = &2200
l2209               = &2209
l220b               = &220b
l220c               = &220c
l220d               = &220d
l220e               = &220e
l220f               = &220f
l2210               = &2210
l2211               = &2211
l2212               = &2212
l2213               = &2213
l2214               = &2214
l2215               = &2215
l2216               = &2216
l2217               = &2217
l2219               = &2219
l221a               = &221a
l221b               = &221b
l221c               = &221c
l221d               = &221d
l221f               = &221f

; I/O (&b000-&bfff)
ppi_port_b  = &b001
ppi_port_c  = &b002

; Kernel ROM (&f000-&ffca)
print_hex           = &f802
lf80b               = &f80b
lf876               = &f876
lfb8a               = &fb8a
lfd1a               = &fd1a
rdch_lock           = &fd9a
rdch_delete         = &fdc0
rdch_keys_59_to_63  = &fdc2
rdch_letters        = &fdc6
rdch_at             = &fdc8
rdch_keys_1_to_4    = &fdd2
rdch_keys_28_to_31  = &fdd6
rdch_digits         = &fdd8
rdch_space_or_zero  = &fddf
rdch_keys_8_to_13   = &fde2
kernel_wrch         = &fe52
lfe60               = &fe60
scan_keyboard       = &fe71
kernel_rdch         = &fe94
lfec5               = &fec5
lfefb               = &fefb

; OS entry points (&ffcb-&fff9)
OSSHUT  = &ffcb
OSFIND  = &ffce
OSBPUT  = &ffd1
OSBGET  = &ffd4
OSSAVE  = &ffdd
OSECHO  = &ffe6
OSASCI  = &ffe9
OSCRLF  = &ffed
OSWRCH  = &fff4

    org &e000

.pydis_start
.dos
    lda #1                                                            ; e000: a9 01       ..
    sta fdc_reset                                                     ; e002: 8d 02 0a    ...
    lda #0                                                            ; e005: a9 00       ..
    sta fdc_reset                                                     ; e007: 8d 02 0a    ...
    jmp ceee2                                                         ; e00a: 4c e2 ee    L..

; &e00d referenced 3 times by &e7ad, &e7b9, &e7c3
.print_disk_and_inline_string
    jsr print_inline_string                                           ; e00d: 20 16 e0     ..
    equs "DISK "                                                      ; e010: 44 49 53... DIS

    nop                                                               ; e015: ea          .
; &e016 referenced 12 times by &e00d, &e0ab, &e154, &e1aa, &e250, &e25f, &e44f, &e4e8, &e5d3, &e5de, &e65c, &e6e2
.print_inline_string
    pla                                                               ; e016: 68          h
    sta nomon_flag                                                    ; e017: 85 ea       ..
    pla                                                               ; e019: 68          h
    sta l00eb                                                         ; e01a: 85 eb       ..
    ldy #0                                                            ; e01c: a0 00       ..
; &e01e referenced 1 time by &e02d
.loop_ce01e
    inc nomon_flag                                                    ; e01e: e6 ea       ..
    bne ce024                                                         ; e020: d0 02       ..
    inc l00eb                                                         ; e022: e6 eb       ..
; &e024 referenced 1 time by &e020
.ce024
    lda (nomon_flag),y                                                ; e024: b1 ea       ..
    bmi ce030                                                         ; e026: 30 08       0.
    beq ce030                                                         ; e028: f0 06       ..
    jsr OSWRCH                                                        ; e02a: 20 f4 ff     ..            ; Write character
    jmp loop_ce01e                                                    ; e02d: 4c 1e e0    L..

; &e030 referenced 2 times by &e026, &e028
.ce030
    jmp (nomon_flag)                                                  ; e030: 6c ea 00    l..

; &e033 referenced 2 times by &e4c5, &e50a
.sub_ce033
    sty l00e9                                                         ; e033: 84 e9       ..
    jsr sub_ce041                                                     ; e035: 20 41 e0     A.
    jsr sub_ce5c9                                                     ; e038: 20 c9 e5     ..
    ldy l00e9                                                         ; e03b: a4 e9       ..
    ldx #0                                                            ; e03d: a2 00       ..
    beq ce043                                                         ; e03f: f0 02       ..             ; ALWAYS branch

; &e041 referenced 5 times by &e035, &e465, &e578, &e5c9, &e5e6
.sub_ce041
    ldx #&40 ; '@'                                                    ; e041: a2 40       .@
; &e043 referenced 1 time by &e03f
.ce043
    jsr lf876                                                         ; e043: 20 76 f8     v.
    stx l009a                                                         ; e046: 86 9a       ..
    cmp #&22 ; '"'                                                    ; e048: c9 22       ."
    beq ce08f                                                         ; e04a: f0 43       .C
; &e04c referenced 1 time by &e05a
.loop_ce04c
    cmp #&0d                                                          ; e04c: c9 0d       ..
    beq ce05c                                                         ; e04e: f0 0c       ..
    sta input_buffer,x                                                ; e050: 9d 00 01    ...
    inx                                                               ; e053: e8          .
    iny                                                               ; e054: c8          .
    lda input_buffer,y                                                ; e055: b9 00 01    ...
    cmp #&20 ; ' '                                                    ; e058: c9 20       .
    bne loop_ce04c                                                    ; e05a: d0 f0       ..
; &e05c referenced 2 times by &e04e, &e0a6
.ce05c
    lda #&0d                                                          ; e05c: a9 0d       ..
    sta input_buffer,x                                                ; e05e: 9d 00 01    ...
    lda #1                                                            ; e061: a9 01       ..
    sta l009b                                                         ; e063: 85 9b       ..
    ldx #&9a                                                          ; e065: a2 9a       ..
; &e067 referenced 1 time by &e084
.return_1
    rts                                                               ; e067: 60          `

; &e068 referenced 3 times by &e14c, &e4dd, &e61a
.sub_ce068
    ldy #0                                                            ; e068: a0 00       ..
; &e06a referenced 1 time by &e073
.loop_ce06a
    lda basic_error_number,x                                          ; e06a: b5 00       ..
    sta l009a,y                                                       ; e06c: 99 9a 00    ...
    inx                                                               ; e06f: e8          .
    iny                                                               ; e070: c8          .
    cpy #&0a                                                          ; e071: c0 0a       ..
    bcc loop_ce06a                                                    ; e073: 90 f5       ..
; &e075 referenced 1 time by &e961
.sub_ce075
    lda #&20 ; ' '                                                    ; e075: a9 20       .
    ldy #6                                                            ; e077: a0 06       ..
; &e079 referenced 1 time by &e07d
.loop_ce079
    sta l00a5,y                                                       ; e079: 99 a5 00    ...
    dey                                                               ; e07c: 88          .
    bpl loop_ce079                                                    ; e07d: 10 fa       ..
; &e07f referenced 1 time by &e08d
.loop_ce07f
    iny                                                               ; e07f: c8          .
    lda (l009a),y                                                     ; e080: b1 9a       ..
    cmp #&0d                                                          ; e082: c9 0d       ..
    beq return_1                                                      ; e084: f0 e1       ..
    cpy #7                                                            ; e086: c0 07       ..
    bcs ce0ab                                                         ; e088: b0 21       .!
    sta l00a5,y                                                       ; e08a: 99 a5 00    ...
    bne loop_ce07f                                                    ; e08d: d0 f0       ..             ; ALWAYS branch

; &e08f referenced 3 times by &e04a, &e09d, &e0a9
.ce08f
    iny                                                               ; e08f: c8          .
    lda input_buffer,y                                                ; e090: b9 00 01    ...
    cmp #&0d                                                          ; e093: c9 0d       ..
    beq ce0ab                                                         ; e095: f0 14       ..
    sta input_buffer,x                                                ; e097: 9d 00 01    ...
    inx                                                               ; e09a: e8          .
    cmp #&22 ; '"'                                                    ; e09b: c9 22       ."
    bne ce08f                                                         ; e09d: d0 f0       ..
    dex                                                               ; e09f: ca          .
    iny                                                               ; e0a0: c8          .
    lda input_buffer,y                                                ; e0a1: b9 00 01    ...
    cmp #&22 ; '"'                                                    ; e0a4: c9 22       ."
    bne ce05c                                                         ; e0a6: d0 b4       ..
    inx                                                               ; e0a8: e8          .
    bcs ce08f                                                         ; e0a9: b0 e4       ..             ; ALWAYS branch

; &e0ab referenced 2 times by &e088, &e095
.ce0ab
    jsr print_inline_string                                           ; e0ab: 20 16 e0     ..
    equs "NAME?"                                                      ; e0ae: 4e 41 4d... NAM

    brk                                                               ; e0b3: 00          .

; &e0b4 referenced 4 times by &e468, &e565, &e5e9, &e6b8
.sub_ce0b4
    ldx #&9c                                                          ; e0b4: a2 9c       ..
; &e0b6 referenced 2 times by &e5f0, &e5f7
.sub_ce0b6
    lda #0                                                            ; e0b6: a9 00       ..
    sta basic_error_number,x                                          ; e0b8: 95 00       ..
    sta basic_line_number,x                                           ; e0ba: 95 01       ..
    sta basic_line_number+1,x                                         ; e0bc: 95 02       ..
    jsr lf876                                                         ; e0be: 20 76 f8     v.
; &e0c1 referenced 1 time by &e0e7
.ce0c1
    lda input_buffer,y                                                ; e0c1: b9 00 01    ...
    cmp #&30 ; '0'                                                    ; e0c4: c9 30       .0
    bcc ce0e9                                                         ; e0c6: 90 21       .!
    cmp #&3a ; ':'                                                    ; e0c8: c9 3a       .:
    bcc ce0d4                                                         ; e0ca: 90 08       ..
    sbc #7                                                            ; e0cc: e9 07       ..
    bcc ce0e9                                                         ; e0ce: 90 19       ..
    cmp #&40 ; '@'                                                    ; e0d0: c9 40       .@
    bcs ce0e9                                                         ; e0d2: b0 15       ..
; &e0d4 referenced 1 time by &e0ca
.ce0d4
    asl a                                                             ; e0d4: 0a          .
    asl a                                                             ; e0d5: 0a          .
    asl a                                                             ; e0d6: 0a          .
    asl a                                                             ; e0d7: 0a          .
    sty basic_line_number+1,x                                         ; e0d8: 94 02       ..
    ldy #4                                                            ; e0da: a0 04       ..
; &e0dc referenced 1 time by &e0e2
.loop_ce0dc
    asl a                                                             ; e0dc: 0a          .
    rol basic_error_number,x                                          ; e0dd: 36 00       6.
    rol basic_line_number,x                                           ; e0df: 36 01       6.
    dey                                                               ; e0e1: 88          .
    bne loop_ce0dc                                                    ; e0e2: d0 f8       ..
    ldy basic_line_number+1,x                                         ; e0e4: b4 02       ..
    iny                                                               ; e0e6: c8          .
    bne ce0c1                                                         ; e0e7: d0 d8       ..
; &e0e9 referenced 3 times by &e0c6, &e0ce, &e0d2
.ce0e9
    lda basic_line_number+1,x                                         ; e0e9: b5 02       ..
    rts                                                               ; e0eb: 60          `

; &e0ec referenced 6 times by &e0f3, &e1c7, &e1e0, &e1f6, &e1f9, &e211
.sub_ce0ec
    lda #&20 ; ' '                                                    ; e0ec: a9 20       .
    jmp OSWRCH                                                        ; e0ee: 4c f4 ff    L..            ; Write character 32

; &e0f1 referenced 1 time by &e29f
.sub_ce0f1
    ldy #6                                                            ; e0f1: a0 06       ..
; &e0f3 referenced 2 times by &e0f7, &e312
.ce0f3
    jsr sub_ce0ec                                                     ; e0f3: 20 ec e0     ..
    dey                                                               ; e0f6: 88          .
    bne ce0f3                                                         ; e0f7: d0 fa       ..
    rts                                                               ; e0f9: 60          `

; &e0fa referenced 2 times by &e9fd, &ea86
.sub_ce0fa
    lsr a                                                             ; e0fa: 4a          J
; &e0fb referenced 6 times by &e12e, &e1ff, &e31c, &e788, &ea22, &ea3a
.sub_ce0fb
    lsr a                                                             ; e0fb: 4a          J
    lsr a                                                             ; e0fc: 4a          J
    lsr a                                                             ; e0fd: 4a          J
    lsr a                                                             ; e0fe: 4a          J
    rts                                                               ; e0ff: 60          `

; &e100 referenced 4 times by &e162, &e285, &e2ec, &e6a1
.sub_ce100
    iny                                                               ; e100: c8          .
; &e101 referenced 2 times by &e173, &e2e0
.sub_ce101
    iny                                                               ; e101: c8          .
    iny                                                               ; e102: c8          .
    iny                                                               ; e103: c8          .
; &e104 referenced 1 time by &ecab
.sub_ce104
    iny                                                               ; e104: c8          .
    iny                                                               ; e105: c8          .
    iny                                                               ; e106: c8          .
    iny                                                               ; e107: c8          .
    rts                                                               ; e108: 60          `

; &e109 referenced 2 times by &e274, &e64f
.sub_ce109
    dey                                                               ; e109: 88          .
    dey                                                               ; e10a: 88          .
    dey                                                               ; e10b: 88          .
    dey                                                               ; e10c: 88          .
    dey                                                               ; e10d: 88          .
    dey                                                               ; e10e: 88          .
    dey                                                               ; e10f: 88          .
    dey                                                               ; e110: 88          .
    rts                                                               ; e111: 60          `

; &e112 referenced 1 time by &e4aa
.sub_ce112
    lda l009c                                                         ; e112: a5 9c       ..
    sec                                                               ; e114: 38          8
    sbc #1                                                            ; e115: e9 01       ..
    sta l00c9                                                         ; e117: 85 c9       ..
    lda l009d                                                         ; e119: a5 9d       ..
    sbc #0                                                            ; e11b: e9 00       ..
    sta l00ca                                                         ; e11d: 85 ca       ..
    lda #&ff                                                          ; e11f: a9 ff       ..
    sta l00ec                                                         ; e121: 85 ec       ..
    clc                                                               ; e123: 18          .
    adc l00a0                                                         ; e124: 65 a0       e.
    lda l00a1                                                         ; e126: a5 a1       ..
    adc #0                                                            ; e128: 69 00       i.
    sta l00cb                                                         ; e12a: 85 cb       ..
    lda l00a2                                                         ; e12c: a5 a2       ..
    jsr sub_ce0fb                                                     ; e12e: 20 fb e0     ..
    sta l00cc                                                         ; e131: 85 cc       ..
    lda l00a2                                                         ; e133: a5 a2       ..
    and #&0f                                                          ; e135: 29 0f       ).
    tax                                                               ; e137: aa          .
    lda l00a3                                                         ; e138: a5 a3       ..
; &e13a referenced 1 time by &e142
.loop_ce13a
    sec                                                               ; e13a: 38          8
; &e13b referenced 1 time by &e13f
.loop_ce13b
    inc l00ec                                                         ; e13b: e6 ec       ..
    sbc #&0a                                                          ; e13d: e9 0a       ..
    bcs loop_ce13b                                                    ; e13f: b0 fa       ..
    dex                                                               ; e141: ca          .
    bpl loop_ce13a                                                    ; e142: 10 f6       ..
    adc #&0a                                                          ; e144: 69 0a       i.
    sta l00ed                                                         ; e146: 85 ed       ..
; &e148 referenced 1 time by &e152
.return_2
    rts                                                               ; e148: 60          `

; &e149 referenced 3 times by &e1b2, &e41a, &e59b
.sub_ce149
    jsr sub_ce5c9                                                     ; e149: 20 c9 e5     ..
; &e14c referenced 1 time by &e484
.sub_ce14c
    jsr sub_ce068                                                     ; e14c: 20 68 e0     h.
    jsr sub_ce15d                                                     ; e14f: 20 5d e1     ].
    bcs return_2                                                      ; e152: b0 f4       ..
; &e154 referenced 1 time by &e516
.ce154
    jsr print_inline_string                                           ; e154: 20 16 e0     ..
    equs "FILE?"                                                      ; e157: 46 49 4c... FIL

    brk                                                               ; e15c: 00          .

; &e15d referenced 5 times by &e14f, &e4e0, &e61d, &e921, &e964
.sub_ce15d
    jsr read_catalogue_and_wait                                       ; e15d: 20 23 e2     #.
    ldy #&f8                                                          ; e160: a0 f8       ..
; &e162 referenced 2 times by &e171, &e188
.ce162
    jsr sub_ce100                                                     ; e162: 20 00 e1     ..
    cpy l2105                                                         ; e165: cc 05 21    ..!
    bcs ce18a                                                         ; e168: b0 20       .
    lda l200f,y                                                       ; e16a: b9 0f 20    ..
    and #&7f                                                          ; e16d: 29 7f       ).
    cmp l00ac                                                         ; e16f: c5 ac       ..
    bne ce162                                                         ; e171: d0 ef       ..
    jsr sub_ce101                                                     ; e173: 20 01 e1     ..
    ldx #6                                                            ; e176: a2 06       ..
; &e178 referenced 1 time by &e181
.loop_ce178
    lda l2007,y                                                       ; e178: b9 07 20    ..
    cmp l00a5,x                                                       ; e17b: d5 a5       ..
    bne ce184                                                         ; e17d: d0 05       ..
    dey                                                               ; e17f: 88          .
    dex                                                               ; e180: ca          .
    bpl loop_ce178                                                    ; e181: 10 f5       ..
    rts                                                               ; e183: 60          `

; &e184 referenced 2 times by &e17d, &e186
.ce184
    dey                                                               ; e184: 88          .
    dex                                                               ; e185: ca          .
    bpl ce184                                                         ; e186: 10 fc       ..
    bmi ce162                                                         ; e188: 30 d8       0.             ; ALWAYS branch

; &e18a referenced 1 time by &e168
.ce18a
    clc                                                               ; e18a: 18          .
    rts                                                               ; e18b: 60          `

; &e18c referenced 2 times by &e424, &e622
.sub_ce18c
    lda l200f,y                                                       ; e18c: b9 0f 20    ..
    bmi ce1aa                                                         ; e18f: 30 19       0.
; &e191 referenced 1 time by &e1a1
.loop_ce191
    lda l2010,y                                                       ; e191: b9 10 20    ..
    sta l2008,y                                                       ; e194: 99 08 20    ..
    lda l2110,y                                                       ; e197: b9 10 21    ..!
    sta l2108,y                                                       ; e19a: 99 08 21    ..!
    iny                                                               ; e19d: c8          .
    cpy l2105                                                         ; e19e: cc 05 21    ..!
    bcc loop_ce191                                                    ; e1a1: 90 ee       ..
    tya                                                               ; e1a3: 98          .
    sbc #8                                                            ; e1a4: e9 08       ..
    sta l2105                                                         ; e1a6: 8d 05 21    ..!
    rts                                                               ; e1a9: 60          `

; &e1aa referenced 1 time by &e18f
.ce1aa
    jsr print_inline_string                                           ; e1aa: 20 16 e0     ..
    equs "PROT"                                                       ; e1ad: 50 52 4f... PRO

    brk                                                               ; e1b1: 00          .

.star_info
    jsr sub_ce149                                                     ; e1b2: 20 49 e1     I.
    jsr sub_ce1bf                                                     ; e1b5: 20 bf e1     ..
    jmp ce460                                                         ; e1b8: 4c 60 e4    L`.

; &e1bb referenced 4 times by &e41f, &e4a0, &e5a6, &e695
.sub_ce1bb
    lda l00ef                                                         ; e1bb: a5 ef       ..
    bne return_3                                                      ; e1bd: d0 71       .q
; &e1bf referenced 1 time by &e1b5
.sub_ce1bf
    lda l200f,y                                                       ; e1bf: b9 0f 20    ..
    and #&7f                                                          ; e1c2: 29 7f       ).
    jsr OSWRCH                                                        ; e1c4: 20 f4 ff     ..            ; Write character
    jsr sub_ce0ec                                                     ; e1c7: 20 ec e0     ..
    ldx l200f,y                                                       ; e1ca: be 0f 20    ..
    bpl ce1d1                                                         ; e1cd: 10 02       ..
    lda #&23 ; '#'                                                    ; e1cf: a9 23       .#
; &e1d1 referenced 1 time by &e1cd
.ce1d1
    jsr OSWRCH                                                        ; e1d1: 20 f4 ff     ..            ; Write character 35
    ldx #7                                                            ; e1d4: a2 07       ..
; &e1d6 referenced 1 time by &e1de
.loop_ce1d6
    lda l2008,y                                                       ; e1d6: b9 08 20    ..
    jsr OSWRCH                                                        ; e1d9: 20 f4 ff     ..            ; Write character
    iny                                                               ; e1dc: c8          .
    dex                                                               ; e1dd: ca          .
    bne loop_ce1d6                                                    ; e1de: d0 f6       ..
; &e1e0 referenced 1 time by &e1f4
.loop_ce1e0
    jsr sub_ce0ec                                                     ; e1e0: 20 ec e0     ..
    lda l2102,y                                                       ; e1e3: b9 02 21    ..!            ; A=byte to print
    jsr print_hex                                                     ; e1e6: 20 02 f8     ..            ; Print A in hex
    lda l2101,y                                                       ; e1e9: b9 01 21    ..!            ; A=byte to print
    jsr print_hex                                                     ; e1ec: 20 02 f8     ..            ; Print A in hex
    iny                                                               ; e1ef: c8          .
    inx                                                               ; e1f0: e8          .
    iny                                                               ; e1f1: c8          .
    cpx #2                                                            ; e1f2: e0 02       ..
    bcc loop_ce1e0                                                    ; e1f4: 90 ea       ..
    jsr sub_ce0ec                                                     ; e1f6: 20 ec e0     ..
    jsr sub_ce0ec                                                     ; e1f9: 20 ec e0     ..
    lda l2103,y                                                       ; e1fc: b9 03 21    ..!
    jsr sub_ce0fb                                                     ; e1ff: 20 fb e0     ..
    jsr lf80b                                                         ; e202: 20 0b f8     ..
    lda l2102,y                                                       ; e205: b9 02 21    ..!            ; A=byte to print
    jsr print_hex                                                     ; e208: 20 02 f8     ..            ; Print A in hex
    lda l2101,y                                                       ; e20b: b9 01 21    ..!            ; A=byte to print
    jsr print_hex                                                     ; e20e: 20 02 f8     ..            ; Print A in hex
    jsr sub_ce0ec                                                     ; e211: 20 ec e0     ..
    lda l2103,y                                                       ; e214: b9 03 21    ..!
    jsr lf80b                                                         ; e217: 20 0b f8     ..
    lda l2104,y                                                       ; e21a: b9 04 21    ..!            ; A=byte to print
    jsr print_hex                                                     ; e21d: 20 02 f8     ..            ; Print A in hex
    jsr OSCRLF                                                        ; e220: 20 ed ff     ..            ; Write newline (characters 10 and 13)
; &e223 referenced 2 times by &e15d, &e234
.read_catalogue_and_wait
    jsr read_catalogue                                                ; e223: 20 31 e7     1.
; &e226 referenced 9 times by &e229, &e22e, &e443, &e47e, &e4f7, &e510, &e6aa, &ebb2, &ec26
.wait_for_fdc
    bit fdc_command_status                                            ; e226: 2c 00 0a    ,..
    bmi wait_for_fdc                                                  ; e229: 30 fb       0.
    bit fdc_command_status                                            ; e22b: 2c 00 0a    ,..
    bmi wait_for_fdc                                                  ; e22e: 30 f6       0.
; &e230 referenced 1 time by &e1bd
.return_3
    rts                                                               ; e230: 60          `

; &e231 referenced 2 times by &e237, &e57b
.star_dir
    jsr star_drive                                                    ; e231: 20 2a e4     *.
    jmp read_catalogue_and_wait                                       ; e234: 4c 23 e2    L#.

.star_cat
    jsr star_dir                                                      ; e237: 20 31 e2     1.
    ldx #0                                                            ; e23a: a2 00       ..
    stx l00b6                                                         ; e23c: 86 b6       ..
; &e23e referenced 1 time by &e24e
.loop_ce23e
    lda l2000,x                                                       ; e23e: bd 00 20    ..
    cpx #8                                                            ; e241: e0 08       ..
    bcc ce248                                                         ; e243: 90 03       ..
    lda l20f8,x                                                       ; e245: bd f8 20    ..
; &e248 referenced 1 time by &e243
.ce248
    jsr OSWRCH                                                        ; e248: 20 f4 ff     ..            ; Write character
    inx                                                               ; e24b: e8          .
    cpx #&0d                                                          ; e24c: e0 0d       ..
    bne loop_ce23e                                                    ; e24e: d0 ee       ..
    jsr print_inline_string                                           ; e250: 20 16 e0     ..
    equs " DRIVE "                                                    ; e253: 20 44 52...  DR

    lda l00ee                                                         ; e25a: a5 ee       ..
    jsr lf80b                                                         ; e25c: 20 0b f8     ..
    jsr print_inline_string                                           ; e25f: 20 16 e0     ..
    equs " QUAL "                                                     ; e262: 20 51 55...  QU

    lda l00ac                                                         ; e268: a5 ac       ..
    jsr OSWRCH                                                        ; e26a: 20 f4 ff     ..            ; Write character
; &e26d referenced 1 time by &e2bc
.ce26d
    ldy #0                                                            ; e26d: a0 00       ..
    jsr sub_ce288                                                     ; e26f: 20 88 e2     ..
    bcc ce2be                                                         ; e272: 90 4a       .J
; &e274 referenced 1 time by &e280
.loop_ce274
    jsr sub_ce109                                                     ; e274: 20 09 e1     ..
    lda l2008,y                                                       ; e277: b9 08 20    ..
    and #&7f                                                          ; e27a: 29 7f       ).
    sta l2008,y                                                       ; e27c: 99 08 20    ..
    tya                                                               ; e27f: 98          .
    bne loop_ce274                                                    ; e280: d0 f2       ..
    jmp OSCRLF                                                        ; e282: 4c ed ff    L..            ; Write newline (characters 10 and 13)

; &e285 referenced 1 time by &e290
.loop_ce285
    jsr sub_ce100                                                     ; e285: 20 00 e1     ..
; &e288 referenced 2 times by &e26f, &e2cf
.sub_ce288
    cpy l2105                                                         ; e288: cc 05 21    ..!
    bcs return_4                                                      ; e28b: b0 05       ..
    lda l2008,y                                                       ; e28d: b9 08 20    ..
    bmi loop_ce285                                                    ; e290: 30 f3       0.
; &e292 referenced 1 time by &e28b
.return_4
    rts                                                               ; e292: 60          `

; &e293 referenced 1 time by &e2ff
.ce293
    ldy l00b8                                                         ; e293: a4 b8       ..
    beq ce29c                                                         ; e295: f0 05       ..
    jsr OSCRLF                                                        ; e297: 20 ed ff     ..            ; Write newline (characters 10 and 13)
    ldy #&ff                                                          ; e29a: a0 ff       ..
; &e29c referenced 1 time by &e295
.ce29c
    iny                                                               ; e29c: c8          .
    sty l00b8                                                         ; e29d: 84 b8       ..
    jsr sub_ce0f1                                                     ; e29f: 20 f1 e0     ..
; &e2a2 referenced 1 time by &e317
.ce2a2
    lda #&23 ; '#'                                                    ; e2a2: a9 23       .#
    ldy l00b7                                                         ; e2a4: a4 b7       ..
    ldx l200f,y                                                       ; e2a6: be 0f 20    ..
    bmi ce2ad                                                         ; e2a9: 30 02       0.
    lda #&20 ; ' '                                                    ; e2ab: a9 20       .
; &e2ad referenced 1 time by &e2a9
.ce2ad
    jsr OSWRCH                                                        ; e2ad: 20 f4 ff     ..            ; Write character 32
    ; print message
    ldx #0                                                            ; e2b0: a2 00       ..
; &e2b2 referenced 1 time by &e2ba
.loop_ce2b2
    lda l00ae,x                                                       ; e2b2: b5 ae       ..
    jsr OSWRCH                                                        ; e2b4: 20 f4 ff     ..            ; Write character
    inx                                                               ; e2b7: e8          .
    cpx #7                                                            ; e2b8: e0 07       ..
    bne loop_ce2b2                                                    ; e2ba: d0 f6       ..
    beq ce26d                                                         ; e2bc: f0 af       ..             ; ALWAYS branch

; &e2be referenced 2 times by &e272, &e2ea
.ce2be
    sty l00b7                                                         ; e2be: 84 b7       ..
    ldx #0                                                            ; e2c0: a2 00       ..
; &e2c2 referenced 1 time by &e2cd
.loop_ce2c2
    lda l2008,y                                                       ; e2c2: b9 08 20    ..
    and #&7f                                                          ; e2c5: 29 7f       ).
    sta l00ae,x                                                       ; e2c7: 95 ae       ..
    iny                                                               ; e2c9: c8          .
    inx                                                               ; e2ca: e8          .
    cpx #8                                                            ; e2cb: e0 08       ..
    bne loop_ce2c2                                                    ; e2cd: d0 f3       ..
; &e2cf referenced 1 time by &e2ef
.ce2cf
    jsr sub_ce288                                                     ; e2cf: 20 88 e2     ..
    bcs ce2f1                                                         ; e2d2: b0 1d       ..
    ldx #6                                                            ; e2d4: a2 06       ..
    sec                                                               ; e2d6: 38          8
; &e2d7 referenced 1 time by &e2de
.loop_ce2d7
    lda l200e,y                                                       ; e2d7: b9 0e 20    ..
    sbc l00ae,x                                                       ; e2da: f5 ae       ..
    dey                                                               ; e2dc: 88          .
    dex                                                               ; e2dd: ca          .
    bpl loop_ce2d7                                                    ; e2de: 10 f7       ..
    jsr sub_ce101                                                     ; e2e0: 20 01 e1     ..
    lda l200f,y                                                       ; e2e3: b9 0f 20    ..
    and #&7f                                                          ; e2e6: 29 7f       ).
    sbc l00b5                                                         ; e2e8: e5 b5       ..
    bcc ce2be                                                         ; e2ea: 90 d2       ..
    jsr sub_ce100                                                     ; e2ec: 20 00 e1     ..
    bcs ce2cf                                                         ; e2ef: b0 de       ..
; &e2f1 referenced 1 time by &e2d2
.ce2f1
    ldy l00b7                                                         ; e2f1: a4 b7       ..
    lda l2008,y                                                       ; e2f3: b9 08 20    ..
    ora #&80                                                          ; e2f6: 09 80       ..
    sta l2008,y                                                       ; e2f8: 99 08 20    ..
    lda l00b5                                                         ; e2fb: a5 b5       ..
    cmp l00b6                                                         ; e2fd: c5 b6       ..
    beq ce293                                                         ; e2ff: f0 92       ..
    sta l00b6                                                         ; e301: 85 b6       ..
    jsr OSCRLF                                                        ; e303: 20 ed ff     ..            ; Write newline (characters 10 and 13)
    lda l00b5                                                         ; e306: a5 b5       ..
    jsr OSWRCH                                                        ; e308: 20 f4 ff     ..            ; Write character
    lda #&3a ; ':'                                                    ; e30b: a9 3a       .:
    jsr OSWRCH                                                        ; e30d: 20 f4 ff     ..            ; Write character 58
    ldy #4                                                            ; e310: a0 04       ..
    jsr ce0f3                                                         ; e312: 20 f3 e0     ..
    sty l00b8                                                         ; e315: 84 b8       ..
    beq ce2a2                                                         ; e317: f0 89       ..
; &e319 referenced 1 time by &e652
.sub_ce319
    lda l210e,y                                                       ; e319: b9 0e 21    ..!
    jsr sub_ce0fb                                                     ; e31c: 20 fb e0     ..
    sta l00a2                                                         ; e31f: 85 a2       ..
    clc                                                               ; e321: 18          .
    lda #&ff                                                          ; e322: a9 ff       ..
    adc l210c,y                                                       ; e324: 79 0c 21    y.!
    lda l210f,y                                                       ; e327: b9 0f 21    ..!
    adc l210d,y                                                       ; e32a: 79 0d 21    y.!
    sta l00a3                                                         ; e32d: 85 a3       ..
    lda l210e,y                                                       ; e32f: b9 0e 21    ..!
    and #&0f                                                          ; e332: 29 0f       ).
    adc l00a2                                                         ; e334: 65 a2       e.
    sta l00a2                                                         ; e336: 85 a2       ..
; &e338 referenced 1 time by &e649
.sub_ce338
    sec                                                               ; e338: 38          8
    lda l2107,y                                                       ; e339: b9 07 21    ..!
    sbc l00a3                                                         ; e33c: e5 a3       ..
    pha                                                               ; e33e: 48          H
    lda l2106,y                                                       ; e33f: b9 06 21    ..!
    and #&0f                                                          ; e342: 29 0f       ).
    sbc l00a2                                                         ; e344: e5 a2       ..
    tax                                                               ; e346: aa          .
    lda #0                                                            ; e347: a9 00       ..
    cmp l00a0                                                         ; e349: c5 a0       ..
    pla                                                               ; e34b: 68          h
    sbc l00a1                                                         ; e34c: e5 a1       ..
    txa                                                               ; e34e: 8a          .
    sbc #0                                                            ; e34f: e9 00       ..
    rts                                                               ; e351: 60          `

; &e352 referenced 2 times by &e524, &e8bb
.sub_ce352
    ldx #2                                                            ; e352: a2 02       ..
    bne ce358                                                         ; e354: d0 02       ..             ; ALWAYS branch

; &e356 referenced 2 times by &e550, &e8c5
.sub_ce356
    ldx #0                                                            ; e356: a2 00       ..
; &e358 referenced 1 time by &e354
.ce358
    sty l00bf                                                         ; e358: 84 bf       ..
; &e35a referenced 1 time by &e367
.loop_ce35a
    ldy wrcvec,x                                                      ; e35a: bc 08 02    ...
    lda l00bb,x                                                       ; e35d: b5 bb       ..
    sty l00bb,x                                                       ; e35f: 94 bb       ..
    sta wrcvec,x                                                      ; e361: 9d 08 02    ...
    inx                                                               ; e364: e8          .
    txa                                                               ; e365: 8a          .
    lsr a                                                             ; e366: 4a          J
    bcs loop_ce35a                                                    ; e367: b0 f1       ..
    ldy l00bf                                                         ; e369: a4 bf       ..
    rts                                                               ; e36b: 60          `

; &e36c referenced 2 times by &e3f0, &e3fc
.command_table
    equs "CAT"                                                        ; e36c: 43 41 54    CAT
; &e36d referenced 1 time by &e40f
    equb >star_cat                                                    ; e36f: e2          .
    equb <star_cat                                                    ; e370: 37          7
    equs "DIR"                                                        ; e371: 44 49 52    DIR
    equb >star_dir                                                    ; e374: e2          .
    equb <star_dir                                                    ; e375: 31          1
    equs "INFO"                                                       ; e376: 49 4e 46... INF
    equb >star_info                                                   ; e37a: e1          .
    equb <star_info                                                   ; e37b: b2          .
    equs "LOAD"                                                       ; e37c: 4c 4f 41... LOA
    equb >star_load                                                   ; e380: e4          .
    equb <star_load                                                   ; e381: 65          e
    equs "SAVE"                                                       ; e382: 53 41 56... SAV
    equb >star_save                                                   ; e386: e5          .
    equb <star_save                                                   ; e387: e6          .
    equs "DELETE"                                                     ; e388: 44 45 4c... DEL
    equb >star_delete                                                 ; e38e: e4          .
    equb <star_delete                                                 ; e38f: 1a          .
    equs "RUN"                                                        ; e390: 52 55 4e    RUN
    equb >star_run                                                    ; e393: e5          .
    equb <star_run                                                    ; e394: 0a          .
    equs "LOCK"                                                       ; e395: 4c 4f 43... LOC
    equb >star_lock                                                   ; e399: e5          .
    equb <star_lock                                                   ; e39a: 99          .
    equs "UNLOCK"                                                     ; e39b: 55 4e 4c... UNL
    equb >star_unlock                                                 ; e3a1: e5          .
    equb <star_unlock                                                 ; e3a2: 9a          .
    equs "MON"                                                        ; e3a3: 4d 4f 4e    MON
    equb >star_mon                                                    ; e3a6: e4          .
    equb <star_mon                                                    ; e3a7: 5b          [
    equs "NOMON"                                                      ; e3a8: 4e 4f 4d... NOM
    equb >star_nomon                                                  ; e3ad: e4          .
    equb <star_nomon                                                  ; e3ae: 59          Y
    equs "SET"                                                        ; e3af: 53 45 54    SET
    equb >star_set                                                    ; e3b2: e5          .
    equb <star_set                                                    ; e3b3: 72          r
    equs "DRIVE"                                                      ; e3b4: 44 52 49... DRI
    equb >star_drive                                                  ; e3b9: e4          .
    equb <star_drive                                                  ; e3ba: 2a          *
    equs "TITLE"                                                      ; e3bb: 54 49 54... TIT
    equb >star_title                                                  ; e3c0: e5          .
    equb <star_title                                                  ; e3c1: 78          x
    equs "USE"                                                        ; e3c2: 55 53 45    USE
    equb >star_use                                                    ; e3c5: e5          .
    equb <star_use                                                    ; e3c6: af          .
    equs "EXEC"                                                       ; e3c7: 45 58 45... EXE
    equb >star_exec                                                   ; e3cb: e5          .
    equb <star_exec                                                   ; e3cc: 19          .
    equs "SHUT"                                                       ; e3cd: 53 48 55... SHU
    equb >star_shut                                                   ; e3d1: e8          .
    equb <star_shut                                                   ; e3d2: 9c          .
    equs "GO"                                                         ; e3d3: 47 4f       GO
    equb >star_go                                                     ; e3d5: e5          .
    equb <star_go                                                     ; e3d6: 65          e
    equs "SPOOL"                                                      ; e3d7: 53 50 4f... SPO
    equb >star_spool                                                  ; e3dc: e5          .
    equb <star_spool                                                  ; e3dd: 47          G
    equs "VDU"                                                        ; e3de: 56 44 55    VDU
    equb >star_vdu                                                    ; e3e1: e6          .
    equb <star_vdu                                                    ; e3e2: b8          .
    equb >unknown_command                                             ; e3e3: e4          .
    equb <unknown_command                                             ; e3e4: c5          .

.dos_cli
    ldx #&ff                                                          ; e3e5: a2 ff       ..
    cld                                                               ; e3e7: d8          .
; &e3e8 referenced 1 time by &e407
.loop_ce3e8
    ldy #0                                                            ; e3e8: a0 00       ..
    jsr lf876                                                         ; e3ea: 20 76 f8     v.
    dey                                                               ; e3ed: 88          .
; &e3ee referenced 1 time by &e3f8
.loop_ce3ee
    iny                                                               ; e3ee: c8          .
    inx                                                               ; e3ef: e8          .
; &e3f0 referenced 1 time by &e40b
.loop_ce3f0
    lda command_table,x                                               ; e3f0: bd 6c e3    .l.
    bmi ce40d                                                         ; e3f3: 30 18       0.
    cmp input_buffer,y                                                ; e3f5: d9 00 01    ...
    beq loop_ce3ee                                                    ; e3f8: f0 f4       ..
    dex                                                               ; e3fa: ca          .
; &e3fb referenced 1 time by &e3ff
.loop_ce3fb
    inx                                                               ; e3fb: e8          .
    lda command_table,x                                               ; e3fc: bd 6c e3    .l.
    bpl loop_ce3fb                                                    ; e3ff: 10 fa       ..
    inx                                                               ; e401: e8          .
    lda input_buffer,y                                                ; e402: b9 00 01    ...
    cmp #&2e ; '.'                                                    ; e405: c9 2e       ..
    bne loop_ce3e8                                                    ; e407: d0 df       ..
    iny                                                               ; e409: c8          .
    dex                                                               ; e40a: ca          .
    bcs loop_ce3f0                                                    ; e40b: b0 e3       ..             ; ALWAYS branch

; &e40d referenced 1 time by &e3f3
.ce40d
    sta l009b                                                         ; e40d: 85 9b       ..
    lda command_table+1,x                                             ; e40f: bd 6d e3    .m.
    sta l009a                                                         ; e412: 85 9a       ..
    clc                                                               ; e414: 18          .
    ldx #0                                                            ; e415: a2 00       ..
    jmp (l009a)                                                       ; e417: 6c 9a 00    l..

.star_delete
    jsr sub_ce149                                                     ; e41a: 20 49 e1     I.
    sty l009a                                                         ; e41d: 84 9a       ..
    jsr sub_ce1bb                                                     ; e41f: 20 bb e1     ..
    ldy l009a                                                         ; e422: a4 9a       ..
    jsr sub_ce18c                                                     ; e424: 20 8c e1     ..
    jmp ce5a9                                                         ; e427: 4c a9 e5    L..

; &e42a referenced 1 time by &e231
.star_drive
    jsr lf876                                                         ; e42a: 20 76 f8     v.
    cmp #&0d                                                          ; e42d: c9 0d       ..
    beq return_5                                                      ; e42f: f0 1d       ..
    iny                                                               ; e431: c8          .
    pha                                                               ; e432: 48          H
    jsr sub_ce5cc                                                     ; e433: 20 cc e5     ..
    pla                                                               ; e436: 68          h
    cmp #&30 ; '0'                                                    ; e437: c9 30       .0
    bcc ce44f                                                         ; e439: 90 14       ..
    cmp #&34 ; '4'                                                    ; e43b: c9 34       .4
    bcs ce44f                                                         ; e43d: b0 10       ..
; &e43f referenced 3 times by &e4d8, &e502, &e950
.ce43f
    and #3                                                            ; e43f: 29 03       ).
    eor l00ee                                                         ; e441: 45 ee       E.
    jsr wait_for_fdc                                                  ; e443: 20 26 e2     &.
    cmp #&80                                                          ; e446: c9 80       ..
    beq return_5                                                      ; e448: f0 04       ..
    eor l00ee                                                         ; e44a: 45 ee       E.
    sta l00ee                                                         ; e44c: 85 ee       ..
; &e44e referenced 2 times by &e42f, &e448
.return_5
    rts                                                               ; e44e: 60          `

; &e44f referenced 2 times by &e439, &e43d
.ce44f
    jsr print_inline_string                                           ; e44f: 20 16 e0     ..
    equs "DRIVE?"                                                     ; e452: 44 52 49... DRI

    brk                                                               ; e458: 00          .

.star_nomon
    ldx #&ff                                                          ; e459: a2 ff       ..
.star_mon
    jsr sub_ce5cc                                                     ; e45b: 20 cc e5     ..
    stx l00ef                                                         ; e45e: 86 ef       ..
; &e460 referenced 3 times by &e1b8, &e481, &e5ac
.ce460
    lda l00cd                                                         ; e460: a5 cd       ..
    sta l00ac                                                         ; e462: 85 ac       ..
    rts                                                               ; e464: 60          `

.star_load
    jsr sub_ce041                                                     ; e465: 20 41 e0     A.
    jsr sub_ce0b4                                                     ; e468: 20 b4 e0     ..
    beq ce471                                                         ; e46b: f0 04       ..
    lda #&ff                                                          ; e46d: a9 ff       ..
; &e46f referenced 1 time by &e50d
.sub_ce46f
    sta l009e                                                         ; e46f: 85 9e       ..
; &e471 referenced 1 time by &e46b
.ce471
    ldx #&9a                                                          ; e471: a2 9a       ..
    clc                                                               ; e473: 18          .
    jmp (lodvec)                                                      ; e474: 6c 0c 02    l..

.dos_load
    php                                                               ; e477: 08          .
    jsr sub_ce484                                                     ; e478: 20 84 e4     ..
; &e47b referenced 1 time by &e617
.ce47b
    plp                                                               ; e47b: 28          (
    bcc ce481                                                         ; e47c: 90 03       ..
    jsr wait_for_fdc                                                  ; e47e: 20 26 e2     &.
; &e481 referenced 1 time by &e47c
.ce481
    jmp ce460                                                         ; e481: 4c 60 e4    L`.

; &e484 referenced 1 time by &e478
.sub_ce484
    jsr sub_ce14c                                                     ; e484: 20 4c e1     L.
; &e487 referenced 1 time by &e4f4
.sub_ce487
    sty l009a                                                         ; e487: 84 9a       ..
    ldx #0                                                            ; e489: a2 00       ..
    lda l009e                                                         ; e48b: a5 9e       ..
    bpl ce493                                                         ; e48d: 10 04       ..
    ldx #2                                                            ; e48f: a2 02       ..
    iny                                                               ; e491: c8          .
    iny                                                               ; e492: c8          .
; &e493 referenced 2 times by &e48d, &e49c
.ce493
    lda l2108,y                                                       ; e493: b9 08 21    ..!
    sta l009c,x                                                       ; e496: 95 9c       ..
    iny                                                               ; e498: c8          .
    inx                                                               ; e499: e8          .
    cpx #8                                                            ; e49a: e0 08       ..
    bne ce493                                                         ; e49c: d0 f5       ..
    ldy l009a                                                         ; e49e: a4 9a       ..
    jsr sub_ce1bb                                                     ; e4a0: 20 bb e1     ..
; &e4a3 referenced 1 time by &ebaf
.sub_ce4a3
    jsr copy_nmi_read_byte                                            ; e4a3: 20 92 e7     ..
    lda #&53 ; 'S'                                                    ; e4a6: a9 53       .S
; &e4a8 referenced 1 time by &e6b5
.ce4a8
    sta l00ad                                                         ; e4a8: 85 ad       ..
    jsr sub_ce112                                                     ; e4aa: 20 12 e1     ..
; &e4ad referenced 1 time by &e4c2
.loop_ce4ad
    jsr sub_ce816                                                     ; e4ad: 20 16 e8     ..
    beq return_6                                                      ; e4b0: f0 12       ..
; &e4b2 referenced 1 time by &e4bd
.loop_ce4b2
    jsr sub_ce846                                                     ; e4b2: 20 46 e8     F.
    lda l00ad                                                         ; e4b5: a5 ad       ..
    jsr fdc_transfer                                                  ; e4b7: 20 ed e7     ..
    jsr check_fdc_result                                              ; e4ba: 20 a4 e7     ..
    bne loop_ce4b2                                                    ; e4bd: d0 f3       ..
    jsr sub_ce839                                                     ; e4bf: 20 39 e8     9.
    bne loop_ce4ad                                                    ; e4c2: d0 e9       ..
; &e4c4 referenced 1 time by &e4b0
.return_6
    rts                                                               ; e4c4: 60          `

.unknown_command
    ; A command that isn't in the table: look for a file of that name (COMMAND? if
    ; there isn't one)
    jsr sub_ce033                                                     ; e4c5: 20 33 e0     3.
    lda l00ee                                                         ; e4c8: a5 ee       ..
    sta l00c7                                                         ; e4ca: 85 c7       ..
    lda l00ac                                                         ; e4cc: a5 ac       ..
    sta l00c8                                                         ; e4ce: 85 c8       ..
    lda #&20 ; ' '                                                    ; e4d0: a9 20       .
    sta l00ac                                                         ; e4d2: 85 ac       ..
    lda #0                                                            ; e4d4: a9 00       ..
    sta l009e                                                         ; e4d6: 85 9e       ..
    jsr ce43f                                                         ; e4d8: 20 3f e4     ?.
    ldx #&9a                                                          ; e4db: a2 9a       ..
    jsr sub_ce068                                                     ; e4dd: 20 68 e0     h.
    jsr sub_ce15d                                                     ; e4e0: 20 5d e1     ].
    bcs ce4f4                                                         ; e4e3: b0 0f       ..
    jsr sub_ce500                                                     ; e4e5: 20 00 e5     ..
    jsr print_inline_string                                           ; e4e8: 20 16 e0     ..
    equs "COMMAND?"                                                   ; e4eb: 43 4f 4d... COM

    brk                                                               ; e4f3: 00          .

; &e4f4 referenced 1 time by &e4e3
.ce4f4
    jsr sub_ce487                                                     ; e4f4: 20 87 e4     ..
    jsr wait_for_fdc                                                  ; e4f7: 20 26 e2     &.
    jsr sub_ce500                                                     ; e4fa: 20 00 e5     ..
    jmp (l009e)                                                       ; e4fd: 6c 9e 00    l..

; &e500 referenced 6 times by &e4e5, &e4fa, &e903, &eb26, &ec0b, &ec9a
.sub_ce500
    lda l00c7                                                         ; e500: a5 c7       ..
    jsr ce43f                                                         ; e502: 20 3f e4     ?.
    lda l00c8                                                         ; e505: a5 c8       ..
    sta l00ac                                                         ; e507: 85 ac       ..
    rts                                                               ; e509: 60          `

.star_run
    jsr sub_ce033                                                     ; e50a: 20 33 e0     3.
    jsr sub_ce46f                                                     ; e50d: 20 6f e4     o.
; &e510 referenced 1 time by &e56d
.ce510
    jsr wait_for_fdc                                                  ; e510: 20 26 e2     &.
    jmp (l009e)                                                       ; e513: 6c 9e 00    l..

; &e516 referenced 1 time by &e520
.loop_ce516
    jmp ce154                                                         ; e516: 4c 54 e1    LT.

.star_exec
    jsr sub_ce5c9                                                     ; e519: 20 c9 e5     ..
    jsr OSFIND                                                        ; e51c: 20 ce ff     ..            ; Open a file (for input if C=1, output if C=0)
    tay                                                               ; e51f: a8          .              ; A=file handle (or zero if not found)
    beq loop_ce516                                                    ; e520: f0 f4       ..
    sta l00b9                                                         ; e522: 85 b9       ..
    jsr sub_ce352                                                     ; e524: 20 52 e3     R.
    lda #&33 ; '3'                                                    ; e527: a9 33       .3
    ldy #&e5                                                          ; e529: a0 e5       ..
; &e52b referenced 1 time by &e557
.ce52b
    sta comvec,x                                                      ; e52b: 9d 06 02    ...
    tya                                                               ; e52e: 98          .
    sta comvec+1,x                                                    ; e52f: 9d 07 02    ...
    rts                                                               ; e532: 60          `

.exec_rdch
    sty l00e9                                                         ; e533: 84 e9       ..
    ldy l00b9                                                         ; e535: a4 b9       ..             ; Y=file handle
    jsr OSBGET                                                        ; e537: 20 d4 ff     ..            ; Read a byte from file Y
    bcc ce544                                                         ; e53a: 90 08       ..
    jsr OSSHUT                                                        ; e53c: 20 cb ff     ..            ; Close file Y
    ldy l00e9                                                         ; e53f: a4 e9       ..
    jmp (rdcvec)                                                      ; e541: 6c 0a 02    l..

; &e544 referenced 1 time by &e53a
.ce544
    ldy l00e9                                                         ; e544: a4 e9       ..
    rts                                                               ; e546: 60          `

.star_spool
    jsr sub_ce5c9                                                     ; e547: 20 c9 e5     ..
    clc                                                               ; e54a: 18          .
    jsr OSFIND                                                        ; e54b: 20 ce ff     ..            ; Open file for output (C=0)
    sta l00ba                                                         ; e54e: 85 ba       ..             ; A=file handle (or zero if not found)
    jsr sub_ce356                                                     ; e550: 20 56 e3     V.
    lda #&59 ; 'Y'                                                    ; e553: a9 59       .Y
    ldy #&e5                                                          ; e555: a0 e5       ..
    bne ce52b                                                         ; e557: d0 d2       ..             ; ALWAYS branch

.spool_wrch
    sty l00e9                                                         ; e559: 84 e9       ..
    ldy l00ba                                                         ; e55b: a4 ba       ..             ; Y=file handle
    jsr OSBPUT                                                        ; e55d: 20 d1 ff     ..            ; Write byte A to file Y
    ldy l00e9                                                         ; e560: a4 e9       ..
    jmp (l00bb)                                                       ; e562: 6c bb 00    l..

.star_go
    jsr sub_ce0b4                                                     ; e565: 20 b4 e0     ..
    php                                                               ; e568: 08          .
    jsr sub_ce5cc                                                     ; e569: 20 cc e5     ..
    plp                                                               ; e56c: 28          (
    beq ce510                                                         ; e56d: f0 a1       ..
    jmp (l009c)                                                       ; e56f: 6c 9c 00    l..

.star_set
    jsr sub_ce5b3                                                     ; e572: 20 b3 e5     ..
    sta l00cd                                                         ; e575: 85 cd       ..
    rts                                                               ; e577: 60          `

.star_title
    jsr sub_ce041                                                     ; e578: 20 41 e0     A.
    jsr star_dir                                                      ; e57b: 20 31 e2     1.
    ldx #&0c                                                          ; e57e: a2 0c       ..
    lda #&20 ; ' '                                                    ; e580: a9 20       .
; &e582 referenced 1 time by &e586
.loop_ce582
    jsr sub_ce5bd                                                     ; e582: 20 bd e5     ..
    dex                                                               ; e585: ca          .
    bpl loop_ce582                                                    ; e586: 10 fa       ..
; &e588 referenced 1 time by &e595
.loop_ce588
    inx                                                               ; e588: e8          .
    lda string_buffer,x                                               ; e589: bd 40 01    .@.
    cmp #&0d                                                          ; e58c: c9 0d       ..
    beq ce5a9                                                         ; e58e: f0 19       ..
    jsr sub_ce5bd                                                     ; e590: 20 bd e5     ..
    cpx #&0c                                                          ; e593: e0 0c       ..
    bcc loop_ce588                                                    ; e595: 90 f1       ..
    bcs ce5a9                                                         ; e597: b0 10       ..             ; ALWAYS branch

.star_lock
    sec                                                               ; e599: 38          8
.star_unlock
    php                                                               ; e59a: 08          .
    jsr sub_ce149                                                     ; e59b: 20 49 e1     I.
    lda l00ac                                                         ; e59e: a5 ac       ..
    rol a                                                             ; e5a0: 2a          *
    plp                                                               ; e5a1: 28          (
    ror a                                                             ; e5a2: 6a          j
    sta l200f,y                                                       ; e5a3: 99 0f 20    ..
    jsr sub_ce1bb                                                     ; e5a6: 20 bb e1     ..
; &e5a9 referenced 3 times by &e427, &e58e, &e597
.ce5a9
    jsr write_catalogue                                               ; e5a9: 20 4a e7     J.
    jmp ce460                                                         ; e5ac: 4c 60 e4    L`.

.star_use
    lda l00ac                                                         ; e5af: a5 ac       ..
    sta l00cd                                                         ; e5b1: 85 cd       ..
; &e5b3 referenced 1 time by &e572
.sub_ce5b3
    iny                                                               ; e5b3: c8          .
    jsr sub_ce5cc                                                     ; e5b4: 20 cc e5     ..
    lda irq_save_a,y                                                  ; e5b7: b9 ff 00    ...
    sta l00ac                                                         ; e5ba: 85 ac       ..
    rts                                                               ; e5bc: 60          `

; &e5bd referenced 2 times by &e582, &e590
.sub_ce5bd
    cpx #8                                                            ; e5bd: e0 08       ..
    bcc ce5c5                                                         ; e5bf: 90 04       ..
    sta l20f8,x                                                       ; e5c1: 9d f8 20    ..
    rts                                                               ; e5c4: 60          `

; &e5c5 referenced 1 time by &e5bf
.ce5c5
    sta l2000,x                                                       ; e5c5: 9d 00 20    ..
; &e5c8 referenced 1 time by &e5d1
.return_7
    rts                                                               ; e5c8: 60          `

; &e5c9 referenced 4 times by &e038, &e149, &e519, &e547
.sub_ce5c9
    jsr sub_ce041                                                     ; e5c9: 20 41 e0     A.
; &e5cc referenced 6 times by &e433, &e45b, &e569, &e5b4, &e60a, &e6bc
.sub_ce5cc
    jsr lf876                                                         ; e5cc: 20 76 f8     v.
    cmp #&0d                                                          ; e5cf: c9 0d       ..
    beq return_7                                                      ; e5d1: f0 f5       ..
; &e5d3 referenced 2 times by &e5ec, &e5f3
.ce5d3
    jsr print_inline_string                                           ; e5d3: 20 16 e0     ..
    equs "SYNTAX?"                                                    ; e5d6: 53 59 4e... SYN

    brk                                                               ; e5dd: 00          .

; &e5de referenced 1 time by &e647
.ce5de
    jsr print_inline_string                                           ; e5de: 20 16 e0     ..
    equs "FULL"                                                       ; e5e1: 46 55 4c... FUL

    brk                                                               ; e5e5: 00          .

.star_save
    jsr sub_ce041                                                     ; e5e6: 20 41 e0     A.
    jsr sub_ce0b4                                                     ; e5e9: 20 b4 e0     ..
    beq ce5d3                                                         ; e5ec: f0 e5       ..
    ldx #&a2                                                          ; e5ee: a2 a2       ..
    jsr sub_ce0b6                                                     ; e5f0: 20 b6 e0     ..
    beq ce5d3                                                         ; e5f3: f0 de       ..
    ldx #&9e                                                          ; e5f5: a2 9e       ..
    jsr sub_ce0b6                                                     ; e5f7: 20 b6 e0     ..
    php                                                               ; e5fa: 08          .
    lda l009c                                                         ; e5fb: a5 9c       ..
    ldx l009d                                                         ; e5fd: a6 9d       ..
    plp                                                               ; e5ff: 28          (
    bne ce606                                                         ; e600: d0 04       ..
    sta l009e                                                         ; e602: 85 9e       ..
    stx l009f                                                         ; e604: 86 9f       ..
; &e606 referenced 1 time by &e600
.ce606
    sta l00a0                                                         ; e606: 85 a0       ..
    stx l00a1                                                         ; e608: 86 a1       ..
    jsr sub_ce5cc                                                     ; e60a: 20 cc e5     ..
    ldx #&9a                                                          ; e60d: a2 9a       ..             ; X=zero page address of the save parameter block
    clc                                                               ; e60f: 18          .
    jmp OSSAVE                                                        ; e610: 4c dd ff    L..            ; Save a file

.dos_save
    php                                                               ; e613: 08          .
    jsr sub_ce6ad                                                     ; e614: 20 ad e6     ..
    jmp ce47b                                                         ; e617: 4c 7b e4    L{.

; &e61a referenced 2 times by &e6ad, &e980
.sub_ce61a
    jsr sub_ce068                                                     ; e61a: 20 68 e0     h.
    jsr sub_ce15d                                                     ; e61d: 20 5d e1     ].
    bcc ce625                                                         ; e620: 90 03       ..
    jsr sub_ce18c                                                     ; e622: 20 8c e1     ..
; &e625 referenced 1 time by &e620
.ce625
    lda l00a0                                                         ; e625: a5 a0       ..
    pha                                                               ; e627: 48          H
    lda l00a1                                                         ; e628: a5 a1       ..
    pha                                                               ; e62a: 48          H
    sec                                                               ; e62b: 38          8
    lda l00a2                                                         ; e62c: a5 a2       ..
    sbc l00a0                                                         ; e62e: e5 a0       ..
    sta l00a0                                                         ; e630: 85 a0       ..
    lda l00a3                                                         ; e632: a5 a3       ..
    sbc l00a1                                                         ; e634: e5 a1       ..
    sta l00a1                                                         ; e636: 85 a1       ..
    lda #0                                                            ; e638: a9 00       ..
    sta l00a2                                                         ; e63a: 85 a2       ..
    lda #2                                                            ; e63c: a9 02       ..
    sta l00a3                                                         ; e63e: 85 a3       ..
    ldy l2105                                                         ; e640: ac 05 21    ..!
    beq ce67f                                                         ; e643: f0 3a       .:
    cpy #&f8                                                          ; e645: c0 f8       ..
    bcs ce5de                                                         ; e647: b0 95       ..
    jsr sub_ce338                                                     ; e649: 20 38 e3     8.
    jmp ce655                                                         ; e64c: 4c 55 e6    LU.

; &e64f referenced 1 time by &e658
.loop_ce64f
    jsr sub_ce109                                                     ; e64f: 20 09 e1     ..
    jsr sub_ce319                                                     ; e652: 20 19 e3     ..
; &e655 referenced 1 time by &e64c
.ce655
    tya                                                               ; e655: 98          .
    beq ce65a                                                         ; e656: f0 02       ..
    bcc loop_ce64f                                                    ; e658: 90 f5       ..
; &e65a referenced 1 time by &e656
.ce65a
    bcs ce667                                                         ; e65a: b0 0b       ..
    jsr print_inline_string                                           ; e65c: 20 16 e0     ..
    equs "NO ROOM"                                                    ; e65f: 4e 4f 20... NO

    brk                                                               ; e666: 00          .

; &e667 referenced 1 time by &e65a
.ce667
    sty nomon_flag                                                    ; e667: 84 ea       ..
    ldy l2105                                                         ; e669: ac 05 21    ..!
; &e66c referenced 1 time by &e67d
.loop_ce66c
    cpy nomon_flag                                                    ; e66c: c4 ea       ..
    beq ce67f                                                         ; e66e: f0 0f       ..
    lda l2007,y                                                       ; e670: b9 07 20    ..
    sta l200f,y                                                       ; e673: 99 0f 20    ..
    lda l2107,y                                                       ; e676: b9 07 21    ..!
    sta l210f,y                                                       ; e679: 99 0f 21    ..!
    dey                                                               ; e67c: 88          .
    bcs loop_ce66c                                                    ; e67d: b0 ed       ..
; &e67f referenced 2 times by &e643, &e66e
.ce67f
    ldx #0                                                            ; e67f: a2 00       ..
; &e681 referenced 1 time by &e68a
.loop_ce681
    lda l00a5,x                                                       ; e681: b5 a5       ..
    sta l2008,y                                                       ; e683: 99 08 20    ..
    iny                                                               ; e686: c8          .
    inx                                                               ; e687: e8          .
    cpx #8                                                            ; e688: e0 08       ..
    bne loop_ce681                                                    ; e68a: d0 f5       ..
; &e68c referenced 1 time by &e693
.loop_ce68c
    lda l009b,x                                                       ; e68c: b5 9b       ..
    dey                                                               ; e68e: 88          .
    sta l2108,y                                                       ; e68f: 99 08 21    ..!
    dex                                                               ; e692: ca          .
    bne loop_ce68c                                                    ; e693: d0 f7       ..
    jsr sub_ce1bb                                                     ; e695: 20 bb e1     ..
    pla                                                               ; e698: 68          h
    sta l009d                                                         ; e699: 85 9d       ..
    pla                                                               ; e69b: 68          h
    sta l009c                                                         ; e69c: 85 9c       ..
    ldy l2105                                                         ; e69e: ac 05 21    ..!
    jsr sub_ce100                                                     ; e6a1: 20 00 e1     ..
    sty l2105                                                         ; e6a4: 8c 05 21    ..!
    jsr write_catalogue                                               ; e6a7: 20 4a e7     J.
    jmp wait_for_fdc                                                  ; e6aa: 4c 26 e2    L&.

; &e6ad referenced 1 time by &e614
.sub_ce6ad
    jsr sub_ce61a                                                     ; e6ad: 20 1a e6     ..
; &e6b0 referenced 1 time by &eba0
.sub_ce6b0
    jsr copy_nmi_write_byte                                           ; e6b0: 20 96 e7     ..
    lda #&4b ; 'K'                                                    ; e6b3: a9 4b       .K
    jmp ce4a8                                                         ; e6b5: 4c a8 e4    L..

.star_vdu
    jsr sub_ce0b4                                                     ; e6b8: 20 b4 e0     ..
    php                                                               ; e6bb: 08          .
    jsr sub_ce5cc                                                     ; e6bc: 20 cc e5     ..
    ldx #0                                                            ; e6bf: a2 00       ..
    plp                                                               ; e6c1: 28          (
    beq ce6ca                                                         ; e6c2: f0 06       ..
    lda l009c                                                         ; e6c4: a5 9c       ..
    beq ce6ca                                                         ; e6c6: f0 02       ..
    ldx #4                                                            ; e6c8: a2 04       ..
; &e6ca referenced 2 times by &e6c2, &e6c6
.ce6ca
    lda vdu_vectors,x                                                 ; e6ca: bd f7 e6    ...
    sta wrcvec                                                        ; e6cd: 8d 08 02    ...
    lda le6f8,x                                                       ; e6d0: bd f8 e6    ...
    sta wrcvec+1                                                      ; e6d3: 8d 09 02    ...
    lda le6f9,x                                                       ; e6d6: bd f9 e6    ...
    sta rdcvec                                                        ; e6d9: 8d 0a 02    ...
    lda le6fa,x                                                       ; e6dc: bd fa e6    ...
    sta rdcvec+1                                                      ; e6df: 8d 0b 02    ...
    jsr print_inline_string                                           ; e6e2: 20 16 e0     ..
    equs 6, &0f, &0c, "ACORN ATOM", &0a, &0a, &0d                     ; e6e5: 06 0f 0c... ...

    nop                                                               ; e6f5: ea          .
    rts                                                               ; e6f6: 60          `

; &e6f7 referenced 1 time by &e6ca
.vdu_vectors
le6f8 = vdu_vectors+1
    equw kernel_wrch                                                  ; e6f7: 52 fe       R.
; &e6f8 referenced 1 time by &e6d0
; &e6f9 referenced 1 time by &e6d6
.le6f9
le6fa = le6f9+1
    equw kernel_rdch                                                  ; e6f9: 94 fe       ..
; &e6fa referenced 1 time by &e6dc
    equw vdu_wrch                                                     ; e6fb: 94 ed       ..
    equw vdu_rdch                                                     ; e6fd: 22 ed       ".

; &e6ff referenced 2 times by &e739, &e74a
.seek_catalogue
    lda #0                                                            ; e6ff: a9 00       ..
    sta l00ec                                                         ; e701: 85 ec       ..
    sta l00ed                                                         ; e703: 85 ed       ..
    lda #2                                                            ; e705: a9 02       ..
    sta l00f1                                                         ; e707: 85 f1       ..
    ldy #&16                                                          ; e709: a0 16       ..
    lda #<seek_done                                                   ; e70b: a9 29       .)
    sta l00d5                                                         ; e70d: 85 d5       ..
    lda #>seek_done                                                   ; e70f: a9 e7       ..
    sta l00d6                                                         ; e711: 85 d6       ..
; &e713 referenced 1 time by &ef15
.fdc_send_commands
    ; Send the command at fdc_initialisation+Y, and its parameters
    lda fdc_initialisation,y                                          ; e713: b9 62 e8    .b.
    jsr fdc_command                                                   ; e716: 20 d2 e7     ..
; &e719 referenced 1 time by &e724
.loop_ce719
    iny                                                               ; e719: c8          .
    lda fdc_initialisation,y                                          ; e71a: b9 62 e8    .b.
    cmp #&ea                                                          ; e71d: c9 ea       ..
    beq ce727                                                         ; e71f: f0 06       ..
    jsr fdc_write_parameter                                           ; e721: 20 09 e8     ..
    jmp loop_ce719                                                    ; e724: 4c 19 e7    L..

; &e727 referenced 1 time by &e71f
.ce727
    iny                                                               ; e727: c8          .
    rts                                                               ; e728: 60          `

.seek_done
    jsr fdc_read_result                                               ; e729: 20 e4 e7     ..
    lda #&0a                                                          ; e72c: a9 0a       ..
    sta l00f0                                                         ; e72e: 85 f0       ..
    rts                                                               ; e730: 60          `

; &e731 referenced 1 time by &e223
.read_catalogue
    jsr read_drive_status                                             ; e731: 20 7a e7     z.
    bne return_8                                                      ; e734: d0 13       ..
    jsr select_drive                                                  ; e736: 20 5b e7     [.
    jsr seek_catalogue                                                ; e739: 20 ff e6     ..
; &e73c referenced 1 time by &e747
.loop_ce73c
    jsr copy_nmi_read_byte                                            ; e73c: 20 92 e7     ..
    lda #&53 ; 'S'                                                    ; e73f: a9 53       .S
    jsr fdc_transfer                                                  ; e741: 20 ed e7     ..
    jsr check_fdc_result                                              ; e744: 20 a4 e7     ..
    bne loop_ce73c                                                    ; e747: d0 f3       ..
; &e749 referenced 1 time by &e734
.return_8
    rts                                                               ; e749: 60          `

; &e74a referenced 4 times by &e5a9, &e6a7, &e8fb, &ec23
.write_catalogue
    jsr seek_catalogue                                                ; e74a: 20 ff e6     ..
; &e74d referenced 1 time by &e758
.loop_ce74d
    jsr copy_nmi_write_byte                                           ; e74d: 20 96 e7     ..
    lda #&4b ; 'K'                                                    ; e750: a9 4b       .K
    jsr fdc_transfer                                                  ; e752: 20 ed e7     ..
    jsr check_fdc_result                                              ; e755: 20 a4 e7     ..
    bne loop_ce74d                                                    ; e758: d0 f3       ..
    rts                                                               ; e75a: 60          `

; &e75b referenced 2 times by &e736, &eb7f
.select_drive
    lda l00ee                                                         ; e75b: a5 ee       ..
    and #3                                                            ; e75d: 29 03       ).
    tay                                                               ; e75f: a8          .
    ora #&80                                                          ; e760: 09 80       ..
    sta l00ee                                                         ; e762: 85 ee       ..
    lda #&3a ; ':'                                                    ; e764: a9 3a       .:
    jsr fdc_write_command                                             ; e766: 20 db e7     ..
    lda #&23 ; '#'                                                    ; e769: a9 23       .#
    jsr fdc_write_parameter                                           ; e76b: 20 09 e8     ..
    lda drive_control_bits,y                                          ; e76e: b9 8e e7    ...
    jsr fdc_write_parameter                                           ; e771: 20 09 e8     ..
; &e774 referenced 1 time by &e777
.loop_ce774
    jsr read_drive_status                                             ; e774: 20 7a e7     z.
    beq loop_ce774                                                    ; e777: f0 fb       ..
    rts                                                               ; e779: 60          `

; &e77a referenced 2 times by &e731, &e774
.read_drive_status
    lda l00ee                                                         ; e77a: a5 ee       ..
    bpl ce78b                                                         ; e77c: 10 0d       ..
    lda #&6c ; 'l'                                                    ; e77e: a9 6c       .l
    jsr fdc_command                                                   ; e780: 20 d2 e7     ..
    jsr fdc_read_result                                               ; e783: 20 e4 e7     ..
    bcc ce78b                                                         ; e786: 90 03       ..
    jsr sub_ce0fb                                                     ; e788: 20 fb e0     ..
; &e78b referenced 2 times by &e77c, &e786
.ce78b
    and #4                                                            ; e78b: 29 04       ).
    rts                                                               ; e78d: 60          `

; &e78e referenced 1 time by &e76e
.drive_control_bits
    equb &48, &88, &68, &a8                                           ; e78e: 48 88 68... H.h

; &e792 referenced 2 times by &e4a3, &e73c
.copy_nmi_read_byte
    ldy #&0a                                                          ; e792: a0 0a       ..
    bne ce798                                                         ; e794: d0 02       ..             ; ALWAYS branch

; &e796 referenced 2 times by &e6b0, &e74d
.copy_nmi_write_byte
    ldy #&12                                                          ; e796: a0 12       ..
; &e798 referenced 1 time by &e794
.ce798
    ldx #&0b                                                          ; e798: a2 0b       ..
; &e79a referenced 1 time by &e7a1
.loop_ce79a
    lda nmi_routines,y                                                ; e79a: b9 4f e8    .O.
    sta l00f1,x                                                       ; e79d: 95 f1       ..
    dey                                                               ; e79f: 88          .
    dex                                                               ; e7a0: ca          .
    bne loop_ce79a                                                    ; e7a1: d0 f7       ..
; &e7a3 referenced 2 times by &e7a7, &e7c0
.return_9
    rts                                                               ; e7a3: 60          `

; &e7a4 referenced 3 times by &e4ba, &e744, &e755
.check_fdc_result
    jsr fdc_read_result                                               ; e7a4: 20 e4 e7     ..
    beq return_9                                                      ; e7a7: f0 fa       ..
    cmp #&12                                                          ; e7a9: c9 12       ..
    bne ce7b5                                                         ; e7ab: d0 08       ..
    jsr print_disk_and_inline_string                                  ; e7ad: 20 0d e0     ..
    equs "PROT"                                                       ; e7b0: 50 52 4f... PRO

    brk                                                               ; e7b4: 00          .

; &e7b5 referenced 1 time by &e7ab
.ce7b5
    cmp #&16                                                          ; e7b5: c9 16       ..
    bne ce7be                                                         ; e7b7: d0 05       ..
    jsr print_disk_and_inline_string                                  ; e7b9: 20 0d e0     ..
    equs "?"                                                          ; e7bc: 3f          ?

    brk                                                               ; e7bd: 00          .

; &e7be referenced 1 time by &e7b7
.ce7be
    dec l00f0                                                         ; e7be: c6 f0       ..
    bne return_9                                                      ; e7c0: d0 e1       ..
    pha                                                               ; e7c2: 48          H
    jsr print_disk_and_inline_string                                  ; e7c3: 20 0d e0     ..
    equs "ERROR "                                                     ; e7c6: 45 52 52... ERR

    nop                                                               ; e7cc: ea          .
    pla                                                               ; e7cd: 68          h              ; A=byte to print
    jsr print_hex                                                     ; e7ce: 20 02 f8     ..            ; Print A in hex
    brk                                                               ; e7d1: 00          .

; &e7d2 referenced 3 times by &e716, &e780, &e7ed
.fdc_command
    pha                                                               ; e7d2: 48          H
    lda l00ee                                                         ; e7d3: a5 ee       ..
    ror a                                                             ; e7d5: 6a          j
    pla                                                               ; e7d6: 68          h
    bcc fdc_write_command                                             ; e7d7: 90 02       ..
    eor #&c0                                                          ; e7d9: 49 c0       I.
; &e7db referenced 3 times by &e766, &e7d7, &e7de
.fdc_write_command
    bit fdc_command_status                                            ; e7db: 2c 00 0a    ,..
    bmi fdc_write_command                                             ; e7de: 30 fb       0.
    sta fdc_command_status                                            ; e7e0: 8d 00 0a    ...
    rts                                                               ; e7e3: 60          `

; &e7e4 referenced 4 times by &e729, &e783, &e7a4, &e7e7
.fdc_read_result
    lda fdc_command_status                                            ; e7e4: ad 00 0a    ...
    bmi fdc_read_result                                               ; e7e7: 30 fb       0.
    lda fdc_parameter_result                                          ; e7e9: ad 01 0a    ...
    rts                                                               ; e7ec: 60          `

; &e7ed referenced 3 times by &e4b7, &e741, &e752
.fdc_transfer
    ; Send command A, then the track (#EC), the sector (#ED) and the number of sectors
    ; (#F1, of 256 bytes), and return to the caller's caller: the code after the JSR
    ; runs when the command is done (dos_nmi jumps through #D5)
    jsr fdc_command                                                   ; e7ed: 20 d2 e7     ..
    clc                                                               ; e7f0: 18          .
    pla                                                               ; e7f1: 68          h
    adc #1                                                            ; e7f2: 69 01       i.
    sta l00d5                                                         ; e7f4: 85 d5       ..
    pla                                                               ; e7f6: 68          h
    adc #0                                                            ; e7f7: 69 00       i.
    sta l00d6                                                         ; e7f9: 85 d6       ..
    lda l00ec                                                         ; e7fb: a5 ec       ..
    jsr fdc_write_parameter                                           ; e7fd: 20 09 e8     ..
    lda l00ed                                                         ; e800: a5 ed       ..
    jsr fdc_write_parameter                                           ; e802: 20 09 e8     ..
    lda l00f1                                                         ; e805: a5 f1       ..
    ora #&20 ; ' '                                                    ; e807: 09 20       .
; &e809 referenced 5 times by &e721, &e76b, &e771, &e7fd, &e802
.fdc_write_parameter
    pha                                                               ; e809: 48          H
; &e80a referenced 1 time by &e80f
.loop_ce80a
    lda fdc_command_status                                            ; e80a: ad 00 0a    ...
    and #&20 ; ' '                                                    ; e80d: 29 20       )
    bne loop_ce80a                                                    ; e80f: d0 f9       ..
    pla                                                               ; e811: 68          h
    sta fdc_parameter_result                                          ; e812: 8d 01 0a    ...
    rts                                                               ; e815: 60          `

; &e816 referenced 1 time by &e4ad
.sub_ce816
    lda #&0a                                                          ; e816: a9 0a       ..
    sta l00f0                                                         ; e818: 85 f0       ..
    sec                                                               ; e81a: 38          8
    lda #&0a                                                          ; e81b: a9 0a       ..
    sbc l00ed                                                         ; e81d: e5 ed       ..
    ldy l00cc                                                         ; e81f: a4 cc       ..
    bne ce829                                                         ; e821: d0 06       ..
    cmp l00cb                                                         ; e823: c5 cb       ..
    bcc ce829                                                         ; e825: 90 02       ..
    lda l00cb                                                         ; e827: a5 cb       ..
; &e829 referenced 2 times by &e821, &e825
.ce829
    sta l00f1                                                         ; e829: 85 f1       ..
    sec                                                               ; e82b: 38          8
    lda l00cb                                                         ; e82c: a5 cb       ..
    sbc l00f1                                                         ; e82e: e5 f1       ..
    sta l00cb                                                         ; e830: 85 cb       ..
    bcs ce836                                                         ; e832: b0 02       ..
    dec l00cc                                                         ; e834: c6 cc       ..
; &e836 referenced 1 time by &e832
.ce836
    lda l00f1                                                         ; e836: a5 f1       ..
    rts                                                               ; e838: 60          `

; &e839 referenced 1 time by &e4bf
.sub_ce839
    sta l00ed                                                         ; e839: 85 ed       ..
    lda nmi_buffer_address                                            ; e83b: a5 f6       ..
    sta l00c9                                                         ; e83d: 85 c9       ..
    lda l00f7                                                         ; e83f: a5 f7       ..
    sta l00ca                                                         ; e841: 85 ca       ..
    inc l00ec                                                         ; e843: e6 ec       ..
    rts                                                               ; e845: 60          `

; &e846 referenced 1 time by &e4b2
.sub_ce846
    lda l00c9                                                         ; e846: a5 c9       ..
    sta nmi_buffer_address                                            ; e848: 85 f6       ..
    lda l00ca                                                         ; e84a: a5 ca       ..
    sta l00f7                                                         ; e84c: 85 f7       ..
    rts                                                               ; e84e: 60          `

; &e84f referenced 1 time by &e79a
.nmi_routines

; Move 1: &e84f to &f2 for length 8
    org &f2
; &e84f referenced 1 time by &e888
.nmi_read_byte
.nmi_transfer_byte
    lda fdc_data                                                      ; e84f: ad 04 0a    ... :00f2[1]
    sta l1fff                                                         ; e852: 8d ff 1f    ... :00f5[1]
    pla                                                               ; e855: 68          h   :00f8[1]
    rti                                                               ; e856: 40          @   :00f9[1]


    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock nmi_read_byte, *, nmi_routines

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear nmi_read_byte, &00fa

    ; Set the program counter to the next position in the binary file.
    org nmi_routines + (* - nmi_read_byte)


; Move 2: &e857 to &f2 for length 11
    org &f2
.nmi_write_byte
    jmp c00f5                                                         ; e857: 4c f5 00    L.. :00f2[2]

; &e85a referenced 1 time by &00f2[2]
.c00f5
    lda l1fff                                                         ; e85a: ad ff 1f    ... :00f5[2]
    sta fdc_data                                                      ; e85d: 8d 04 0a    ... :00f8[2]
    pla                                                               ; e860: 68          h   :00fb[2]
    rti                                                               ; e861: 40          @   :00fc[2]


    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock nmi_read_byte, *, &e857

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear nmi_read_byte, &00fd

    ; Set the program counter to the next position in the binary file.
    org &e857 + (* - nmi_read_byte)

.fdc_initialisation
    ; Specify the initialisation: the step rate (#14), the head settling time (#05),
    ; and the head load and unload times (#CA)
; &e862 referenced 2 times by &e713, &e71a
    equb &35, &0d, &14, 5, &ca, &ea                                   ; e862: 35 0d 14... 5..
    ; Specify the bad tracks for surface 0 (none), and the current track (0)
    equb &35, &10, &ff, &ff, 0, &ea                                   ; e868: 35 10 ff... 5..
    ; Specify the bad tracks for surface 1 (none), and the current track (0)
    equb &35, &18, &ff, &ff, 0, &ea                                   ; e86e: 35 18 ff... 5..
    ; Write the special register #17 (the mode register): #C1 (non-DMA mode)
    equb &3a, &17, &c1, &ea                                           ; e874: 3a 17 c1... :..
    ; Seek track 0
    equb &69, 0, &ea                                                  ; e878: 69 00 ea    i..

.dos_nmi
    lda fdc_command_status                                            ; e87b: ad 00 0a    ...
    and #4                                                            ; e87e: 29 04       ).
    beq ce88b                                                         ; e880: f0 09       ..
    inc nmi_buffer_address                                            ; e882: e6 f6       ..
    bne ce888                                                         ; e884: d0 02       ..
    inc l00f7                                                         ; e886: e6 f7       ..
; &e888 referenced 1 time by &e884
.ce888
    jmp nmi_transfer_byte                                             ; e888: 4c f2 00    L..

; &e88b referenced 1 time by &e880
.ce88b
    ; push X,Y onto the stack
    txa                                                               ; e88b: 8a          .
    pha                                                               ; e88c: 48          H
    tya                                                               ; e88d: 98          .
    pha                                                               ; e88e: 48          H
    cld                                                               ; e88f: d8          .
    jsr sub_ce899                                                     ; e890: 20 99 e8     ..
    ; pull A,X,Y from the stack
    pla                                                               ; e893: 68          h
    tay                                                               ; e894: a8          .
    pla                                                               ; e895: 68          h
    tax                                                               ; e896: aa          .
    pla                                                               ; e897: 68          h
    rti                                                               ; e898: 40          @

; &e899 referenced 1 time by &e890
.sub_ce899
    jmp (l00d5)                                                       ; e899: 6c d5 00    l..

.star_shut
    ldy #0                                                            ; e89c: a0 00       ..
; &e89e referenced 3 times by &e8a9, &e9ba, &ec0e
.dos_shut
    pha                                                               ; e89e: 48          H
    cld                                                               ; e89f: d8          .
    tya                                                               ; e8a0: 98          .
    bne ce8b2                                                         ; e8a1: d0 0f       ..
; &e8a3 referenced 1 time by &e8ac
.loop_ce8a3
    clc                                                               ; e8a3: 18          .
    adc #&20 ; ' '                                                    ; e8a4: 69 20       i
    beq ce8b0                                                         ; e8a6: f0 08       ..
    tay                                                               ; e8a8: a8          .
    jsr dos_shut                                                      ; e8a9: 20 9e e8     ..
    bne loop_ce8a3                                                    ; e8ac: d0 f5       ..
; &e8ae referenced 3 times by &e8b5, &e90f, &eb62
.ce8ae
    ldx l00c6                                                         ; e8ae: a6 c6       ..
; &e8b0 referenced 1 time by &e8a6
.ce8b0
    pla                                                               ; e8b0: 68          h
    rts                                                               ; e8b1: 60          `

; &e8b2 referenced 1 time by &e8a1
.ce8b2
    jsr sub_cea7c                                                     ; e8b2: 20 7c ea     |.
    bcs ce8ae                                                         ; e8b5: b0 f7       ..
    cpy l00b9                                                         ; e8b7: c4 b9       ..
    bne ce8c1                                                         ; e8b9: d0 06       ..
    jsr sub_ce352                                                     ; e8bb: 20 52 e3     R.
    lsr a                                                             ; e8be: 4a          J
    sta l00b9                                                         ; e8bf: 85 b9       ..
; &e8c1 referenced 1 time by &e8b9
.ce8c1
    cpy l00ba                                                         ; e8c1: c4 ba       ..
    bne ce8ca                                                         ; e8c3: d0 05       ..
    jsr sub_ce356                                                     ; e8c5: 20 56 e3     V.
    sta l00ba                                                         ; e8c8: 85 ba       ..
; &e8ca referenced 1 time by &e8c3
.ce8ca
    lda l2217,y                                                       ; e8ca: b9 17 22    .."
    and #&60 ; '`'                                                    ; e8cd: 29 60       )`
    beq ce906                                                         ; e8cf: f0 35       .5
    jsr sub_ce912                                                     ; e8d1: 20 12 e9     ..
    lda l2217,y                                                       ; e8d4: b9 17 22    .."
    and #&20 ; ' '                                                    ; e8d7: 29 20       )
    beq ce900                                                         ; e8d9: f0 25       .%
    ldx l00c4                                                         ; e8db: a6 c4       ..
    lda l2214,y                                                       ; e8dd: b9 14 22    .."
    sta l210c,x                                                       ; e8e0: 9d 0c 21    ..!
    lda l2215,y                                                       ; e8e3: b9 15 22    .."
    sta l210d,x                                                       ; e8e6: 9d 0d 21    ..!
    lda l2216,y                                                       ; e8e9: b9 16 22    .."
    asl a                                                             ; e8ec: 0a          .
    asl a                                                             ; e8ed: 0a          .
    asl a                                                             ; e8ee: 0a          .
    asl a                                                             ; e8ef: 0a          .
    eor l210e,x                                                       ; e8f0: 5d 0e 21    ].!
    and #&f0                                                          ; e8f3: 29 f0       ).
    eor l210e,x                                                       ; e8f5: 5d 0e 21    ].!
    sta l210e,x                                                       ; e8f8: 9d 0e 21    ..!
    jsr write_catalogue                                               ; e8fb: 20 4a e7     J.
    ldy l00c2                                                         ; e8fe: a4 c2       ..
; &e900 referenced 1 time by &e8d9
.ce900
    jsr sub_ceb76                                                     ; e900: 20 76 eb     v.
    jsr sub_ce500                                                     ; e903: 20 00 e5     ..
; &e906 referenced 1 time by &e8cf
.ce906
    lda l221b,y                                                       ; e906: b9 1b 22    .."
    eor #&ff                                                          ; e909: 49 ff       I.
    and l00c0                                                         ; e90b: 25 c0       %.
    sta l00c0                                                         ; e90d: 85 c0       ..
    jmp ce8ae                                                         ; e90f: 4c ae e8    L..

; &e912 referenced 1 time by &e8d1
.sub_ce912
    jsr sub_ce93e                                                     ; e912: 20 3e e9     >.
; &e915 referenced 1 time by &ebda
.sub_ce915
    ldx #7                                                            ; e915: a2 07       ..
; &e917 referenced 1 time by &e91f
.loop_ce917
    lda l220c,y                                                       ; e917: b9 0c 22    .."
    sta l00a4,x                                                       ; e91a: 95 a4       ..
    dey                                                               ; e91c: 88          .
    dey                                                               ; e91d: 88          .
    dex                                                               ; e91e: ca          .
    bne loop_ce917                                                    ; e91f: d0 f6       ..
    jsr sub_ce15d                                                     ; e921: 20 5d e1     ].
    bcc le95a                                                         ; e924: 90 34       .4
    sty l00c4                                                         ; e926: 84 c4       ..
    lda l210e,y                                                       ; e928: b9 0e 21    ..!
    ldx l210f,y                                                       ; e92b: be 0f 21    ..!
    ldy l00c2                                                         ; e92e: a4 c2       ..
    eor l220d,y                                                       ; e930: 59 0d 22    Y."
    and #&0f                                                          ; e933: 29 0f       ).
    bne le95a                                                         ; e935: d0 23       .#
    txa                                                               ; e937: 8a          .
    cmp l220f,y                                                       ; e938: d9 0f 22    .."
    bne le95a                                                         ; e93b: d0 1d       ..
    rts                                                               ; e93d: 60          `

; &e93e referenced 3 times by &e912, &eb1c, &ebce
.sub_ce93e
    lda l00ee                                                         ; e93e: a5 ee       ..
    sta l00c7                                                         ; e940: 85 c7       ..
    lda l00ac                                                         ; e942: a5 ac       ..
    sta l00c8                                                         ; e944: 85 c8       ..
    lda l220e,y                                                       ; e946: b9 0e 22    .."
    and #&7f                                                          ; e949: 29 7f       ).
    sta l00ac                                                         ; e94b: 85 ac       ..
    lda l2217,y                                                       ; e94d: b9 17 22    .."
    jmp ce43f                                                         ; e950: 4c 3f e4    L?.

.dos_find
    cld                                                               ; e953: d8          .
    tya                                                               ; e954: 98          .
    pha                                                               ; e955: 48          H
    stx l00c6                                                         ; e956: 86 c6       ..
; &e958 referenced 1 time by &e986
.ce958
    php                                                               ; e958: 08          .
.ce959
le95a = ce959+1
    lda basic_error_number,x                                          ; e959: b5 00       ..
; overlapping: brk                                                    ; e95a: 00          .
; &e95a referenced 3 times by &e924, &e935, &e93b
    sta l009a                                                         ; e95b: 85 9a       ..
    lda basic_line_number,x                                           ; e95d: b5 01       ..
    sta l009b                                                         ; e95f: 85 9b       ..
    jsr sub_ce075                                                     ; e961: 20 75 e0     u.
    jsr sub_ce15d                                                     ; e964: 20 5d e1     ].
    bcs ce988                                                         ; e967: b0 1f       ..
    plp                                                               ; e969: 28          (
    bcc ce971                                                         ; e96a: 90 05       ..
    ldy #0                                                            ; e96c: a0 00       ..
    jmp cea51                                                         ; e96e: 4c 51 ea    LQ.

; &e971 referenced 1 time by &e96a
.ce971
    lda #0                                                            ; e971: a9 00       ..
    ldx #8                                                            ; e973: a2 08       ..
; &e975 referenced 1 time by &e978
.loop_ce975
    sta l009b,x                                                       ; e975: 95 9b       ..
    dex                                                               ; e977: ca          .
    bne loop_ce975                                                    ; e978: d0 fb       ..
    lda #&40 ; '@'                                                    ; e97a: a9 40       .@
    sta l00a3                                                         ; e97c: 85 a3       ..
    ldx #&9a                                                          ; e97e: a2 9a       ..
    jsr sub_ce61a                                                     ; e980: 20 1a e6     ..
    ldx l00c6                                                         ; e983: a6 c6       ..
    clc                                                               ; e985: 18          .
    bcc ce958                                                         ; e986: 90 d0       ..             ; ALWAYS branch

; &e988 referenced 1 time by &e967
.ce988
    sty l00c3                                                         ; e988: 84 c3       ..
.ce98a
le98b = ce98a+1
    lda #0                                                            ; e98a: a9 00       ..
; overlapping: brk                                                    ; e98b: 00          .
; &e98b referenced 1 time by &e9d4
    sta l00c2                                                         ; e98c: 85 c2       ..
    ldy #&a0                                                          ; e98e: a0 a0       ..
    lda #8                                                            ; e990: a9 08       ..
; &e992 referenced 1 time by &e9d0
.ce992
    bit l00c0                                                         ; e992: 24 c0       $.
    beq ce9be                                                         ; e994: f0 28       .(
    pha                                                               ; e996: 48          H
    sty l00c4                                                         ; e997: 84 c4       ..
    ldx l00c3                                                         ; e999: a6 c3       ..
    lda #8                                                            ; e99b: a9 08       ..
    sta l00c5                                                         ; e99d: 85 c5       ..
; &e99f referenced 1 time by &e9b4
.loop_ce99f
    lda l2200,y                                                       ; e99f: b9 00 22    .."
    cmp l2008,x                                                       ; e9a2: dd 08 20    ..
    bne ce9c5                                                         ; e9a5: d0 1e       ..
    iny                                                               ; e9a7: c8          .
    lda l2200,y                                                       ; e9a8: b9 00 22    .."
    cmp l2108,x                                                       ; e9ab: dd 08 21    ..!
    bne ce9c5                                                         ; e9ae: d0 15       ..
    iny                                                               ; e9b0: c8          .
    inx                                                               ; e9b1: e8          .
    dec l00c5                                                         ; e9b2: c6 c5       ..
    bne loop_ce99f                                                    ; e9b4: d0 e9       ..
    ldy l00c4                                                         ; e9b6: a4 c4       ..
    ldx l00c6                                                         ; e9b8: a6 c6       ..
    jsr dos_shut                                                      ; e9ba: 20 9e e8     ..
    pla                                                               ; e9bd: 68          h
; &e9be referenced 1 time by &e994
.ce9be
    sty l00c2                                                         ; e9be: 84 c2       ..
    sta l00c1                                                         ; e9c0: 85 c1       ..
    jmp ce9c8                                                         ; e9c2: 4c c8 e9    L..

; &e9c5 referenced 2 times by &e9a5, &e9ae
.ce9c5
    ldy l00c4                                                         ; e9c5: a4 c4       ..
    pla                                                               ; e9c7: 68          h
; &e9c8 referenced 1 time by &e9c2
.ce9c8
    pha                                                               ; e9c8: 48          H
    tya                                                               ; e9c9: 98          .
    sec                                                               ; e9ca: 38          8
    sbc #&20 ; ' '                                                    ; e9cb: e9 20       .
    tay                                                               ; e9cd: a8          .
    pla                                                               ; e9ce: 68          h
    asl a                                                             ; e9cf: 0a          .
    bne ce992                                                         ; e9d0: d0 c0       ..
    ldy l00c2                                                         ; e9d2: a4 c2       ..
    beq le98b                                                         ; e9d4: f0 b5       ..
    ldx l00c3                                                         ; e9d6: a6 c3       ..
    lda #8                                                            ; e9d8: a9 08       ..
    sta l00c5                                                         ; e9da: 85 c5       ..
; &e9dc referenced 1 time by &e9ed
.loop_ce9dc
    lda l2008,x                                                       ; e9dc: bd 08 20    ..
    sta l2200,y                                                       ; e9df: 99 00 22    .."
    iny                                                               ; e9e2: c8          .
    lda l2108,x                                                       ; e9e3: bd 08 21    ..!
    sta l2200,y                                                       ; e9e6: 99 00 22    .."
    iny                                                               ; e9e9: c8          .
    inx                                                               ; e9ea: e8          .
    dec l00c5                                                         ; e9eb: c6 c5       ..
    bne loop_ce9dc                                                    ; e9ed: d0 ed       ..
    ; Clear 16 bytes of memory at l2200+Y
    ldx #&10                                                          ; e9ef: a2 10       ..
    lda #0                                                            ; e9f1: a9 00       ..
; &e9f3 referenced 1 time by &e9f8
.loop_ce9f3
    sta l2200,y                                                       ; e9f3: 99 00 22    .."
    iny                                                               ; e9f6: c8          .
    dex                                                               ; e9f7: ca          .
    bne loop_ce9f3                                                    ; e9f8: d0 f9       ..
    lda l00c2                                                         ; e9fa: a5 c2       ..
    tay                                                               ; e9fc: a8          .
    jsr sub_ce0fa                                                     ; e9fd: 20 fa e0     ..
    adc #&22 ; '"'                                                    ; ea00: 69 22       i"
    sta l2213,y                                                       ; ea02: 99 13 22    .."
    lda l00c1                                                         ; ea05: a5 c1       ..
    sta l221b,y                                                       ; ea07: 99 1b 22    .."
    ora l00c0                                                         ; ea0a: 05 c0       ..
    sta l00c0                                                         ; ea0c: 85 c0       ..
    lda l2209,y                                                       ; ea0e: b9 09 22    .."
    adc #&ff                                                          ; ea11: 69 ff       i.
    lda l220b,y                                                       ; ea13: b9 0b 22    .."
    adc #0                                                            ; ea16: 69 00       i.
    sta l2219,y                                                       ; ea18: 99 19 22    .."
    lda l220d,y                                                       ; ea1b: b9 0d 22    .."
    ora #&0f                                                          ; ea1e: 09 0f       ..
    adc #0                                                            ; ea20: 69 00       i.
    jsr sub_ce0fb                                                     ; ea22: 20 fb e0     ..
    sta l221a,y                                                       ; ea25: 99 1a 22    .."
    plp                                                               ; ea28: 28          (
    bcc cea5a                                                         ; ea29: 90 2f       ./
    lda l2209,y                                                       ; ea2b: b9 09 22    .."
    sta l2214,y                                                       ; ea2e: 99 14 22    .."
    lda l220b,y                                                       ; ea31: b9 0b 22    .."
    sta l2215,y                                                       ; ea34: 99 15 22    .."
    lda l220d,y                                                       ; ea37: b9 0d 22    .."
    jsr sub_ce0fb                                                     ; ea3a: 20 fb e0     ..
    sta l2216,y                                                       ; ea3d: 99 16 22    .."
; &ea40 referenced 1 time by &ea5f
.loop_cea40
    lda l00ee                                                         ; ea40: a5 ee       ..
    and #&0f                                                          ; ea42: 29 0f       ).
    ora l2217,y                                                       ; ea44: 19 17 22    .."
    sta l2217,y                                                       ; ea47: 99 17 22    .."
    jsr sub_cead1                                                     ; ea4a: 20 d1 ea     ..
    lda l00cd                                                         ; ea4d: a5 cd       ..
    sta l00ac                                                         ; ea4f: 85 ac       ..
; &ea51 referenced 1 time by &e96e
.cea51
    sty l00c3                                                         ; ea51: 84 c3       ..
    ldx l00c6                                                         ; ea53: a6 c6       ..
    pla                                                               ; ea55: 68          h
    tay                                                               ; ea56: a8          .
    lda l00c3                                                         ; ea57: a5 c3       ..
    rts                                                               ; ea59: 60          `

; &ea5a referenced 1 time by &ea29
.cea5a
    lda #&20 ; ' '                                                    ; ea5a: a9 20       .
    sta l2217,y                                                       ; ea5c: 99 17 22    .."
    bne loop_cea40                                                    ; ea5f: d0 df       ..             ; ALWAYS branch

.dos_rdar
    pha                                                               ; ea61: 48          H
    sty l00c2                                                         ; ea62: 84 c2       ..
    asl a                                                             ; ea64: 0a          .
    asl a                                                             ; ea65: 0a          .
    adc l00c2                                                         ; ea66: 65 c2       e.
    tay                                                               ; ea68: a8          .
    lda l2210,y                                                       ; ea69: b9 10 22    .."
    sta basic_error_number,x                                          ; ea6c: 95 00       ..
    lda l2211,y                                                       ; ea6e: b9 11 22    .."
    sta basic_line_number,x                                           ; ea71: 95 01       ..
    lda l2212,y                                                       ; ea73: b9 12 22    .."
    sta basic_line_number+1,x                                         ; ea76: 95 02       ..
    ldy l00c2                                                         ; ea78: a4 c2       ..
    pla                                                               ; ea7a: 68          h
    rts                                                               ; ea7b: 60          `

; &ea7c referenced 4 times by &e8b2, &eaf4, &ebc1, &eca1
.sub_cea7c
    pha                                                               ; ea7c: 48          H
    stx l00c6                                                         ; ea7d: 86 c6       ..
    tya                                                               ; ea7f: 98          .
    and #&e0                                                          ; ea80: 29 e0       ).
    sta l00c2                                                         ; ea82: 85 c2       ..
    beq cea97                                                         ; ea84: f0 11       ..
    jsr sub_ce0fa                                                     ; ea86: 20 fa e0     ..
    tay                                                               ; ea89: a8          .
    lda #0                                                            ; ea8a: a9 00       ..
    sec                                                               ; ea8c: 38          8
; &ea8d referenced 1 time by &ea8f
.loop_cea8d
    ror a                                                             ; ea8d: 6a          j
    dey                                                               ; ea8e: 88          .
    bne loop_cea8d                                                    ; ea8f: d0 fc       ..
    ldy l00c2                                                         ; ea91: a4 c2       ..
    bit l00c0                                                         ; ea93: 24 c0       $.
    bne cea9a                                                         ; ea95: d0 03       ..
; &ea97 referenced 1 time by &ea84
.cea97
    pla                                                               ; ea97: 68          h
    sec                                                               ; ea98: 38          8
    rts                                                               ; ea99: 60          `

; &ea9a referenced 1 time by &ea95
.cea9a
    pla                                                               ; ea9a: 68          h
    clc                                                               ; ea9b: 18          .
; &ea9c referenced 1 time by &eab2
.return_10
    rts                                                               ; ea9c: 60          `

; &ea9d referenced 2 times by &eaad, &ead6
.sub_cea9d
    ldx #&20 ; ' '                                                    ; ea9d: a2 20       .
    txa                                                               ; ea9f: 8a          .              ; A=&20
    clc                                                               ; eaa0: 18          .
; &eaa1 referenced 1 time by &eaa6
.loop_ceaa1
    adc l2200,y                                                       ; eaa1: 79 00 22    y."
    iny                                                               ; eaa4: c8          .
    dex                                                               ; eaa5: ca          .
    bne loop_ceaa1                                                    ; eaa6: d0 f9       ..
    adc #0                                                            ; eaa8: 69 00       i.
    ldy l00c2                                                         ; eaaa: a4 c2       ..
    rts                                                               ; eaac: 60          `

; &eaad referenced 3 times by &eb19, &ebc6, &eca6
.sub_ceaad
    jsr sub_cea9d                                                     ; eaad: 20 9d ea     ..
    cmp #&ff                                                          ; eab0: c9 ff       ..
    beq return_10                                                     ; eab2: f0 e8       ..
    brk                                                               ; eab4: 00          .

; &eab5 referenced 2 times by &ebac, &ec3e
.sub_ceab5
    clc                                                               ; eab5: 18          .
    lda l220f,y                                                       ; eab6: b9 0f 22    .."
    adc l2211,y                                                       ; eab9: 79 11 22    y."
    sta l00a3                                                         ; eabc: 85 a3       ..
    sta l221c,y                                                       ; eabe: 99 1c 22    .."
    lda l220d,y                                                       ; eac1: b9 0d 22    .."
    and #&0f                                                          ; eac4: 29 0f       ).
    adc l2212,y                                                       ; eac6: 79 12 22    y."
    sta l00a2                                                         ; eac9: 85 a2       ..
    sta l221d,y                                                       ; eacb: 99 1d 22    .."
    jsr sub_ceb65                                                     ; eace: 20 65 eb     e.
; &ead1 referenced 4 times by &ea4a, &eb0b, &ec97, &ecf4
.sub_cead1
    lda #&ff                                                          ; ead1: a9 ff       ..
    sta l221f,y                                                       ; ead3: 99 1f 22    .."
    jsr sub_cea9d                                                     ; ead6: 20 9d ea     ..
    eor #&ff                                                          ; ead9: 49 ff       I.
; &eadb referenced 1 time by &eae5
.loop_ceadb
    sta l221f,y                                                       ; eadb: 99 1f 22    .."
    rts                                                               ; eade: 60          `

; &eadf referenced 2 times by &eb3c, &eb5e
.sub_ceadf
    clc                                                               ; eadf: 18          .
    adc l221f,y                                                       ; eae0: 79 1f 22    y."
    adc #0                                                            ; eae3: 69 00       i.
    bne loop_ceadb                                                    ; eae5: d0 f4       ..
; &eae7 referenced 1 time by &eaf2
.loop_ceae7
    jsr OSECHO                                                        ; eae7: 20 e6 ff     ..            ; Read a character and write it
    cmp #4                                                            ; eaea: c9 04       ..             ; A=character read
    beq ceb10                                                         ; eaec: f0 22       ."
    clc                                                               ; eaee: 18          .
    rts                                                               ; eaef: 60          `

.dos_bget
    cld                                                               ; eaf0: d8          .
    tya                                                               ; eaf1: 98          .
    beq loop_ceae7                                                    ; eaf2: f0 f3       ..
    jsr sub_cea7c                                                     ; eaf4: 20 7c ea     |.
    bcs ceb34                                                         ; eaf7: b0 3b       .;
    tya                                                               ; eaf9: 98          .
    jsr sub_cecfa                                                     ; eafa: 20 fa ec     ..
    bne ceb14                                                         ; eafd: d0 15       ..
    lda l2217,y                                                       ; eaff: b9 17 22    .."
    and #&10                                                          ; eb02: 29 10       ).
    bne ceb55                                                         ; eb04: d0 4f       .O
    lda #&10                                                          ; eb06: a9 10       ..
    jsr sub_ceb67                                                     ; eb08: 20 67 eb     g.
    jsr sub_cead1                                                     ; eb0b: 20 d1 ea     ..
    ldx l00c6                                                         ; eb0e: a6 c6       ..
; &eb10 referenced 1 time by &eaec
.ceb10
    lda #&ff                                                          ; eb10: a9 ff       ..
    sec                                                               ; eb12: 38          8
    rts                                                               ; eb13: 60          `

; &eb14 referenced 1 time by &eafd
.ceb14
    lda l2217,y                                                       ; eb14: b9 17 22    .."
    bmi ceb29                                                         ; eb17: 30 10       0.
    jsr sub_ceaad                                                     ; eb19: 20 ad ea     ..
    jsr sub_ce93e                                                     ; eb1c: 20 3e e9     >.
    jsr sub_ceb76                                                     ; eb1f: 20 76 eb     v.
    sec                                                               ; eb22: 38          8
    jsr sub_ceb7e                                                     ; eb23: 20 7e eb     ~.
    jsr sub_ce500                                                     ; eb26: 20 00 e5     ..
; &eb29 referenced 1 time by &eb17
.ceb29
    lda l2210,y                                                       ; eb29: b9 10 22    .."
    sta l009a                                                         ; eb2c: 85 9a       ..
    lda l2213,y                                                       ; eb2e: b9 13 22    .."
    sta l009b                                                         ; eb31: 85 9b       ..
; overlapping: ldy #0                                                 ; eb33: a0 00       ..
    equb &a0                                                          ; eb33: a0          .

; &eb34 referenced 1 time by &eaf7
.ceb34
    brk                                                               ; eb34: 00          .

    lda (l009a),y                                                     ; eb35: b1 9a       ..
    pha                                                               ; eb37: 48          H
    ldy l00c2                                                         ; eb38: a4 c2       ..
    lda #&fe                                                          ; eb3a: a9 fe       ..
    jsr sub_ceadf                                                     ; eb3c: 20 df ea     ..
    ldx l009a                                                         ; eb3f: a6 9a       ..
    inx                                                               ; eb41: e8          .
    txa                                                               ; eb42: 8a          .
    sta l2210,y                                                       ; eb43: 99 10 22    .."
    bne ceb61                                                         ; eb46: d0 19       ..
    clc                                                               ; eb48: 18          .
    lda l2211,y                                                       ; eb49: b9 11 22    .."
    adc #1                                                            ; eb4c: 69 01       i.
    sta l2211,y                                                       ; eb4e: 99 11 22    .."
    lda l2212,y                                                       ; eb51: b9 12 22    .."
; overlapping: adc #0                                                 ; eb54: 69 00       i.
    equb &69                                                          ; eb54: 69          i

; &eb55 referenced 1 time by &eb04
.ceb55
    brk                                                               ; eb55: 00          .

    sta l2212,y                                                       ; eb56: 99 12 22    .."
    jsr sub_ceb6c                                                     ; eb59: 20 6c eb     l.
    lda #&80                                                          ; eb5c: a9 80       ..
    jsr sub_ceadf                                                     ; eb5e: 20 df ea     ..
; &eb61 referenced 3 times by &eb46, &ec9d, &ecf7
.ceb61
    clc                                                               ; eb61: 18          .
    jmp ce8ae                                                         ; eb62: 4c ae e8    L..

; &eb65 referenced 2 times by &eace, &ecf1
.sub_ceb65
    lda #&80                                                          ; eb65: a9 80       ..
; &eb67 referenced 3 times by &eb08, &ec5b, &ec82
.sub_ceb67
    ora l2217,y                                                       ; eb67: 19 17 22    .."
    bne ceb71                                                         ; eb6a: d0 05       ..
; &eb6c referenced 2 times by &eb59, &ec67
.sub_ceb6c
    lda #&7f                                                          ; eb6c: a9 7f       ..
; &eb6e referenced 2 times by &eba7, &ecd2
.sub_ceb6e
    and l2217,y                                                       ; eb6e: 39 17 22    9."
; &eb71 referenced 1 time by &eb6a
.ceb71
    sta l2217,y                                                       ; eb71: 99 17 22    .."
    clc                                                               ; eb74: 18          .
    rts                                                               ; eb75: 60          `

; &eb76 referenced 3 times by &e900, &eb1f, &ec30
.sub_ceb76
    lda l2217,y                                                       ; eb76: b9 17 22    .."
    and #&40 ; '@'                                                    ; eb79: 29 40       )@
    beq return_11                                                     ; eb7b: f0 3a       .:
    clc                                                               ; eb7d: 18          .
; &eb7e referenced 2 times by &eb23, &ec44
.sub_ceb7e
    php                                                               ; eb7e: 08          .
    jsr select_drive                                                  ; eb7f: 20 5b e7     [.
    ldy l00c2                                                         ; eb82: a4 c2       ..
    lda l2213,y                                                       ; eb84: b9 13 22    .."
    sta l009d                                                         ; eb87: 85 9d       ..
; overlapping: lda #0                                                 ; eb89: a9 00       ..
    equb &a9                                                          ; eb89: a9          .

; &eb8a referenced 1 time by &ebcc
.ceb8a
    brk                                                               ; eb8a: 00          .

    sta l009c                                                         ; eb8b: 85 9c       ..
    sta l00a0                                                         ; eb8d: 85 a0       ..
    lda #1                                                            ; eb8f: a9 01       ..
    sta l00a1                                                         ; eb91: 85 a1       ..
    plp                                                               ; eb93: 28          (
    bcs cebac                                                         ; eb94: b0 16       ..
    lda l221c,y                                                       ; eb96: b9 1c 22    .."
    sta l00a3                                                         ; eb99: 85 a3       ..
    lda l221d,y                                                       ; eb9b: b9 1d 22    .."
    sta l00a2                                                         ; eb9e: 85 a2       ..
    jsr sub_ce6b0                                                     ; eba0: 20 b0 e6     ..
    ldy l00c2                                                         ; eba3: a4 c2       ..
    lda #&bf                                                          ; eba5: a9 bf       ..
    jsr sub_ceb6e                                                     ; eba7: 20 6e eb     n.
    bcc cebb2                                                         ; ebaa: 90 06       ..
; &ebac referenced 1 time by &eb94
.cebac
    jsr sub_ceab5                                                     ; ebac: 20 b5 ea     ..
    jsr sub_ce4a3                                                     ; ebaf: 20 a3 e4     ..
; &ebb2 referenced 1 time by &ebaa
.cebb2
    jsr wait_for_fdc                                                  ; ebb2: 20 26 e2     &.
    ldy l00c2                                                         ; ebb5: a4 c2       ..
; &ebb7 referenced 1 time by &eb7b
.return_11
    rts                                                               ; ebb7: 60          `

; &ebb8 referenced 1 time by &ebbf
.loop_cebb8
    pla                                                               ; ebb8: 68          h
    jmp OSASCI                                                        ; ebb9: 4c e9 ff    L..            ; Write character

; &ebbc referenced 1 time by &ecbc
.dos_bput
    cld                                                               ; ebbc: d8          .
    pha                                                               ; ebbd: 48          H
    tya                                                               ; ebbe: 98          .
    beq loop_cebb8                                                    ; ebbf: f0 f7       ..
    jsr sub_cea7c                                                     ; ebc1: 20 7c ea     |.
    bcs cec1f                                                         ; ebc4: b0 59       .Y
    jsr sub_ceaad                                                     ; ebc6: 20 ad ea     ..
    lda l220e,y                                                       ; ebc9: b9 0e 22    .."
    bmi ceb8a                                                         ; ebcc: 30 bc       0.
    jsr sub_ce93e                                                     ; ebce: 20 3e e9     >.
    tya                                                               ; ebd1: 98          .
    clc                                                               ; ebd2: 18          .
    adc #4                                                            ; ebd3: 69 04       i.
    jsr sub_cecfa                                                     ; ebd5: 20 fa ec     ..
    bne cec2b                                                         ; ebd8: d0 51       .Q
    jsr sub_ce915                                                     ; ebda: 20 15 e9     ..
    ldx l00c4                                                         ; ebdd: a6 c4       ..
    sec                                                               ; ebdf: 38          8
    lda l2107,x                                                       ; ebe0: bd 07 21    ..!
    sbc l210f,x                                                       ; ebe3: fd 0f 21    ..!
    pha                                                               ; ebe6: 48          H
    lda l2106,x                                                       ; ebe7: bd 06 21    ..!
    sbc l210e,x                                                       ; ebea: fd 0e 21    ..!
    and #&0f                                                          ; ebed: 29 0f       ).
    sta l00c3                                                         ; ebef: 85 c3       ..
    asl a                                                             ; ebf1: 0a          .
    asl a                                                             ; ebf2: 0a          .
    asl a                                                             ; ebf3: 0a          .
    asl a                                                             ; ebf4: 0a          .
    eor l210e,x                                                       ; ebf5: 5d 0e 21    ].!
    and #&f0                                                          ; ebf8: 29 f0       ).
    eor l210e,x                                                       ; ebfa: 5d 0e 21    ].!
    cmp l210e,x                                                       ; ebfd: dd 0e 21    ..!
    sta l210e,x                                                       ; ec00: 9d 0e 21    ..!
    bne cec12                                                         ; ec03: d0 0d       ..
    pla                                                               ; ec05: 68          h
    cmp l210d,x                                                       ; ec06: dd 0d 21    ..!
    bne cec13                                                         ; ec09: d0 08       ..
    jsr sub_ce500                                                     ; ec0b: 20 00 e5     ..
    jsr dos_shut                                                      ; ec0e: 20 9e e8     ..
    brk                                                               ; ec11: 00          .

; &ec12 referenced 1 time by &ec03
.cec12
    pla                                                               ; ec12: 68          h
; &ec13 referenced 1 time by &ec09
.cec13
    sta l210d,x                                                       ; ec13: 9d 0d 21    ..!
    sta l2219,y                                                       ; ec16: 99 19 22    .."
    lda l00c3                                                         ; ec19: a5 c3       ..
    sta l221a,y                                                       ; ec1b: 99 1a 22    .."
; overlapping: lda #0                                                 ; ec1e: a9 00       ..
    equb &a9                                                          ; ec1e: a9          .

; &ec1f referenced 1 time by &ebc4
.cec1f
    brk                                                               ; ec1f: 00          .

    sta l210c,x                                                       ; ec20: 9d 0c 21    ..!
    jsr write_catalogue                                               ; ec23: 20 4a e7     J.
    jsr wait_for_fdc                                                  ; ec26: 20 26 e2     &.
    ldy l00c2                                                         ; ec29: a4 c2       ..
; &ec2b referenced 1 time by &ebd8
.cec2b
    lda l2217,y                                                       ; ec2b: b9 17 22    .."
    bmi cec47                                                         ; ec2e: 30 17       0.
    jsr sub_ceb76                                                     ; ec30: 20 76 eb     v.
    lda l2214,y                                                       ; ec33: b9 14 22    .."
    bne cec43                                                         ; ec36: d0 0b       ..
    tya                                                               ; ec38: 98          .
    jsr sub_cecfa                                                     ; ec39: 20 fa ec     ..
    bne cec43                                                         ; ec3c: d0 05       ..
    jsr sub_ceab5                                                     ; ec3e: 20 b5 ea     ..
    bne cec47                                                         ; ec41: d0 04       ..
; &ec43 referenced 2 times by &ec36, &ec3c
.cec43
    sec                                                               ; ec43: 38          8
    jsr sub_ceb7e                                                     ; ec44: 20 7e eb     ~.
; &ec47 referenced 2 times by &ec2e, &ec41
.cec47
    lda l2210,y                                                       ; ec47: b9 10 22    .."
    sta l009a                                                         ; ec4a: 85 9a       ..
    lda l2213,y                                                       ; ec4c: b9 13 22    .."
    sta l009b                                                         ; ec4f: 85 9b       ..
    pla                                                               ; ec51: 68          h
    ldy #0                                                            ; ec52: a0 00       ..
    sta (l009a),y                                                     ; ec54: 91 9a       ..
    pha                                                               ; ec56: 48          H
    ldy l00c2                                                         ; ec57: a4 c2       ..
    lda #&40 ; '@'                                                    ; ec59: a9 40       .@
    jsr sub_ceb67                                                     ; ec5b: 20 67 eb     g.
    inc l009a                                                         ; ec5e: e6 9a       ..
    lda l009a                                                         ; ec60: a5 9a       ..
    sta l2210,y                                                       ; ec62: 99 10 22    .."
    bne cec7a                                                         ; ec65: d0 13       ..
    jsr sub_ceb6c                                                     ; ec67: 20 6c eb     l.
    lda l2211,y                                                       ; ec6a: b9 11 22    .."
    adc #1                                                            ; ec6d: 69 01       i.
    sta l2211,y                                                       ; ec6f: 99 11 22    .."
    lda l2212,y                                                       ; ec72: b9 12 22    .."
; overlapping: adc #0                                                 ; ec75: 69 00       i.
    equb &69                                                          ; ec75: 69          i

; &ec76 referenced 1 time by &eca4
.cec76
    brk                                                               ; ec76: 00          .

    sta l2212,y                                                       ; ec77: 99 12 22    .."
; &ec7a referenced 1 time by &ec65
.cec7a
    tya                                                               ; ec7a: 98          .
    jsr sub_cecfa                                                     ; ec7b: 20 fa ec     ..
    bcc cec97                                                         ; ec7e: 90 17       ..
    lda #&20 ; ' '                                                    ; ec80: a9 20       .
    jsr sub_ceb67                                                     ; ec82: 20 67 eb     g.
    lda l2210,y                                                       ; ec85: b9 10 22    .."
    sta l2214,y                                                       ; ec88: 99 14 22    .."
    lda l2211,y                                                       ; ec8b: b9 11 22    .."
    sta l2215,y                                                       ; ec8e: 99 15 22    .."
    lda l2212,y                                                       ; ec91: b9 12 22    .."
    sta l2216,y                                                       ; ec94: 99 16 22    .."
; &ec97 referenced 1 time by &ec7e
.cec97
    jsr sub_cead1                                                     ; ec97: 20 d1 ea     ..
    jsr sub_ce500                                                     ; ec9a: 20 00 e5     ..
    jmp ceb61                                                         ; ec9d: 4c 61 eb    La.

.dos_star
    pha                                                               ; eca0: 48          H
    jsr sub_cea7c                                                     ; eca1: 20 7c ea     |.
    bcs cec76                                                         ; eca4: b0 d0       ..
    jsr sub_ceaad                                                     ; eca6: 20 ad ea     ..
    ldx l00c6                                                         ; eca9: a6 c6       ..
    jsr sub_ce104                                                     ; ecab: 20 04 e1     ..
    jsr sub_ced12                                                     ; ecae: 20 12 ed     ..
    bcc ced16                                                         ; ecb1: 90 63       .c
    ldy l00c2                                                         ; ecb3: a4 c2       ..
; &ecb5 referenced 1 time by &ecbf
.loop_cecb5
    jsr sub_ced12                                                     ; ecb5: 20 12 ed     ..
    bcs cecc1                                                         ; ecb8: b0 07       ..
    lda #&ff                                                          ; ecba: a9 ff       ..
    jsr dos_bput                                                      ; ecbc: 20 bc eb     ..
    bne loop_cecb5                                                    ; ecbf: d0 f4       ..
; &ecc1 referenced 1 time by &ecb8
.cecc1
    lda basic_error_number,x                                          ; ecc1: b5 00       ..
    sta l2210,y                                                       ; ecc3: 99 10 22    .."
    lda basic_line_number,x                                           ; ecc6: b5 01       ..
    sta l2211,y                                                       ; ecc8: 99 11 22    .."
    lda basic_line_number+1,x                                         ; eccb: b5 02       ..
    sta l2212,y                                                       ; eccd: 99 12 22    .."
    lda #&6f ; 'o'                                                    ; ecd0: a9 6f       .o
    jsr sub_ceb6e                                                     ; ecd2: 20 6e eb     n.
    lda l220f,y                                                       ; ecd5: b9 0f 22    .."
    adc l2211,y                                                       ; ecd8: 79 11 22    y."
    sta l00c5                                                         ; ecdb: 85 c5       ..
    lda l220d,y                                                       ; ecdd: b9 0d 22    .."
    and #&0f                                                          ; ece0: 29 0f       ).
    adc l2212,y                                                       ; ece2: 79 12 22    y."
    cmp l221d,y                                                       ; ece5: d9 1d 22    .."
    bne cecf4                                                         ; ece8: d0 0a       ..
    lda l00c5                                                         ; ecea: a5 c5       ..
    cmp l221c,y                                                       ; ecec: d9 1c 22    .."
    bne cecf4                                                         ; ecef: d0 03       ..
    jsr sub_ceb65                                                     ; ecf1: 20 65 eb     e.
; &ecf4 referenced 2 times by &ece8, &ecef
.cecf4
    jsr sub_cead1                                                     ; ecf4: 20 d1 ea     ..
    jmp ceb61                                                         ; ecf7: 4c 61 eb    La.

; &ecfa referenced 4 times by &eafa, &ebd5, &ec39, &ec7b
.sub_cecfa
    tax                                                               ; ecfa: aa          .
    lda l2212,y                                                       ; ecfb: b9 12 22    .."
    cmp l2216,x                                                       ; ecfe: dd 16 22    .."
    bne return_12                                                     ; ed01: d0 0e       ..
    lda l2211,y                                                       ; ed03: b9 11 22    .."
    cmp l2215,x                                                       ; ed06: dd 15 22    .."
    bne return_12                                                     ; ed09: d0 06       ..
    lda l2210,y                                                       ; ed0b: b9 10 22    .."
    cmp l2214,x                                                       ; ed0e: dd 14 22    .."
; &ed11 referenced 2 times by &ed01, &ed09
.return_12
    rts                                                               ; ed11: 60          `

; &ed12 referenced 2 times by &ecae, &ecb5
.sub_ced12
    lda l2214,y                                                       ; ed12: b9 14 22    .."
; overlapping: cmp basic_error_number,x                               ; ed15: d5 00       ..
    equb &d5                                                          ; ed15: d5          .

; &ed16 referenced 1 time by &ecb1
.ced16
    brk                                                               ; ed16: 00          .

    lda l2215,y                                                       ; ed17: b9 15 22    .."
    sbc basic_line_number,x                                           ; ed1a: f5 01       ..
    lda l2216,y                                                       ; ed1c: b9 16 22    .."
    sbc basic_line_number+1,x                                         ; ed1f: f5 02       ..
    rts                                                               ; ed21: 60          `

; &ed22 referenced 1 time by &ed7e
.vdu_rdch
    php                                                               ; ed22: 08          .
    cld                                                               ; ed23: d8          .
    stx l00e4                                                         ; ed24: 86 e4       ..
    sty l00e5                                                         ; ed26: 84 e5       ..
; &ed28 referenced 2 times by &ed30, &ed91
.ced28
    bit ppi_port_c                                                    ; ed28: 2c 02 b0    ,..            ; Test the REPT key
    bvc ced32                                                         ; ed2b: 50 05       P.
    jsr scan_keyboard                                                 ; ed2d: 20 71 fe     q.            ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcc ced28                                                         ; ed30: 90 f6       ..
; &ed32 referenced 1 time by &ed2b
.ced32
    jsr lfb8a                                                         ; ed32: 20 8a fb     ..
; &ed35 referenced 2 times by &ed38, &ed3d
.ced35
    jsr scan_keyboard                                                 ; ed35: 20 71 fe     q.            ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcs ced35                                                         ; ed38: b0 fb       ..
    jsr scan_keyboard                                                 ; ed3a: 20 71 fe     q.            ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcs ced35                                                         ; ed3d: b0 f6       ..
    tya                                                               ; ed3f: 98          .
    ldx #&17                                                          ; ed40: a2 17       ..
    jsr lfec5                                                         ; ed42: 20 c5 fe     ..
    lda vdu_rdch_handlers_low-11,x                                    ; ed45: bd 48 ed    .H.
; &ed48 referenced 1 time by &ed45
    sta l00e2                                                         ; ed48: 85 e2       ..
    lda vdu_rdch_handlers_high-11,x                                   ; ed4a: bd 55 ed    .U.
    sta l00e3                                                         ; ed4d: 85 e3       ..
    tya                                                               ; ed4f: 98          .
    jmp (l00e2)                                                       ; ed50: 6c e2 00    l..

.vdu_rdch_handlers_low
    equb <rdch_space_or_zero                                          ; ed53: df          .
    equb <rdch_keys_1_to_4                                            ; ed54: d2          .
; &ed55 referenced 1 time by &ed4a
    equb <rdch_lock                                                   ; ed55: 9a          .
    equb <vdu_rdch_cursor                                             ; ed56: 88          .
    equb <rdch_keys_8_to_13                                           ; ed57: e2          .
    equb <vdu_rdch_copy                                               ; ed58: 81          .
    equb <rdch_delete                                                 ; ed59: c0          .
    equb <rdch_space_or_zero                                          ; ed5a: df          .
    equb <rdch_digits                                                 ; ed5b: d8          .
    equb <rdch_keys_28_to_31                                          ; ed5c: d6          .
    equb <rdch_at                                                     ; ed5d: c8          .
    equb <rdch_letters                                                ; ed5e: c6          .
    equb <rdch_keys_59_to_63                                          ; ed5f: c2          .
.vdu_rdch_handlers_high
    equb >rdch_space_or_zero                                          ; ed60: fd          .
    equb >rdch_keys_1_to_4                                            ; ed61: fd          .
    equb >rdch_lock                                                   ; ed62: fd          .
    equb >vdu_rdch_cursor                                             ; ed63: ed          .
    equb >rdch_keys_8_to_13                                           ; ed64: fd          .
    equb >vdu_rdch_copy                                               ; ed65: ed          .
    equb >rdch_delete                                                 ; ed66: fd          .
    equb >rdch_space_or_zero                                          ; ed67: fd          .
    equb >rdch_digits                                                 ; ed68: fd          .
    equb >rdch_keys_28_to_31                                          ; ed69: fd          .
    equb >rdch_at                                                     ; ed6a: fd          .
    equb >rdch_letters                                                ; ed6b: fd          .
    equb >rdch_keys_59_to_63                                          ; ed6c: fd          .

    ; Not used: write a cursor key's control code to the screen (11, 8, 9 or 10), then
    ; read another key
    lda #&0b                                                          ; ed6d: a9 0b       ..
    bne ced7b                                                         ; ed6f: d0 0a       ..             ; ALWAYS branch

    lda #8                                                            ; ed71: a9 08       ..
    bne ced7b                                                         ; ed73: d0 06       ..             ; ALWAYS branch

    lda #9                                                            ; ed75: a9 09       ..
    bne ced7b                                                         ; ed77: d0 02       ..             ; ALWAYS branch

    lda #&0a                                                          ; ed79: a9 0a       ..
; &ed7b referenced 3 times by &ed6f, &ed73, &ed77
.ced7b
    jsr sub_ced97                                                     ; ed7b: 20 97 ed     ..
    jmp vdu_rdch                                                      ; ed7e: 4c 22 ed    L".

.vdu_rdch_copy
    ldy #0                                                            ; ed81: a0 00       ..
    lda (l00d2),y                                                     ; ed83: b1 d2       ..
    jmp lfe60                                                         ; ed85: 4c 60 fe    L`.

.vdu_rdch_cursor
    and #5                                                            ; ed88: 29 05       ).
    rol ppi_port_b                                                    ; ed8a: 2e 01 b0    ...
    rol a                                                             ; ed8d: 2a          *
    jsr sub_cee1f                                                     ; ed8e: 20 1f ee     ..
    jmp ced28                                                         ; ed91: 4c 28 ed    L(.

.vdu_wrch
    jsr lfefb                                                         ; ed94: 20 fb fe     ..
; &ed97 referenced 1 time by &ed7b
.sub_ced97
    php                                                               ; ed97: 08          .
    pha                                                               ; ed98: 48          H
    cld                                                               ; ed99: d8          .
    sty l00e9                                                         ; ed9a: 84 e9       ..
    jsr sub_cee1f                                                     ; ed9c: 20 1f ee     ..
    pla                                                               ; ed9f: 68          h
    ldy l00e9                                                         ; eda0: a4 e9       ..
    plp                                                               ; eda2: 28          (
    rts                                                               ; eda3: 60          `

; &eda4 referenced 1 time by &edb0
.loop_ceda4
    pla                                                               ; eda4: 68          h
    pla                                                               ; eda5: 68          h
    rts                                                               ; eda6: 60          `

; &eda7 referenced 2 times by &ee59, &ee85
.sub_ceda7
    dey                                                               ; eda7: 88          .
    bpl return_13                                                     ; eda8: 10 14       ..
    ldy #&27 ; '''                                                    ; edaa: a0 27       .'
; &edac referenced 1 time by &eea4
.sub_cedac
    lda l00ce                                                         ; edac: a5 ce       ..
    cmp #&18                                                          ; edae: c9 18       ..
    bcs loop_ceda4                                                    ; edb0: b0 f2       ..
    inc l00ce                                                         ; edb2: e6 ce       ..
; &edb4 referenced 1 time by &ee9e
.sub_cedb4
    lda l00cf                                                         ; edb4: a5 cf       ..
    sbc #&27 ; '''                                                    ; edb6: e9 27       .'
    sta l00cf                                                         ; edb8: 85 cf       ..
    bcs return_13                                                     ; edba: b0 02       ..
    dec l00d0                                                         ; edbc: c6 d0       ..
; &edbe referenced 2 times by &eda8, &edba
.return_13
    rts                                                               ; edbe: 60          `

; &edbf referenced 1 time by &edd1
.loop_cedbf
    dec l00ce                                                         ; edbf: c6 ce       ..
    rts                                                               ; edc1: 60          `

; &edc2 referenced 2 times by &ee3b, &ee8b
.sub_cedc2
    ldy #&28 ; '('                                                    ; edc2: a0 28       .(
    jsr sub_cedf6                                                     ; edc4: 20 f6 ed     ..
    lda l00d2                                                         ; edc7: a5 d2       ..
    sta l00cf                                                         ; edc9: 85 cf       ..
    lda l00d4                                                         ; edcb: a5 d4       ..
    sta l00d0                                                         ; edcd: 85 d0       ..
    lda l00ce                                                         ; edcf: a5 ce       ..
    bne loop_cedbf                                                    ; edd1: d0 ec       ..
    ldy #&0d                                                          ; edd3: a0 0d       ..
    sty crtc_address                                                  ; edd5: 8c 00 08    ...
    lda l00cf                                                         ; edd8: a5 cf       ..
    sec                                                               ; edda: 38          8
    sbc #&c0                                                          ; eddb: e9 c0       ..
    sta crtc_data                                                     ; eddd: 8d 01 08    ...
    dey                                                               ; ede0: 88          .              ; Y=&0c
    sty crtc_address                                                  ; ede1: 8c 00 08    ...
    lda l00d0                                                         ; ede4: a5 d0       ..
    sbc #3                                                            ; ede6: e9 03       ..
    sta crtc_data                                                     ; ede8: 8d 01 08    ...
    ldy #&27 ; '''                                                    ; edeb: a0 27       .'
    lda #&20 ; ' '                                                    ; eded: a9 20       .
; &edef referenced 1 time by &edf3
.loop_cedef
    jsr sub_cee0b                                                     ; edef: 20 0b ee     ..
    dey                                                               ; edf2: 88          .
    bpl loop_cedef                                                    ; edf3: 10 fa       ..
    rts                                                               ; edf5: 60          `

; &edf6 referenced 3 times by &edc4, &ee0b, &ee40
.sub_cedf6
    pha                                                               ; edf6: 48          H
    clc                                                               ; edf7: 18          .
    tya                                                               ; edf8: 98          .
    adc l00cf                                                         ; edf9: 65 cf       e.
    sta l00d2                                                         ; edfb: 85 d2       ..
    lda l00d0                                                         ; edfd: a5 d0       ..
    adc #0                                                            ; edff: 69 00       i.
    sta l00d4                                                         ; ee01: 85 d4       ..
    and #7                                                            ; ee03: 29 07       ).
    ora #4                                                            ; ee05: 09 04       ..
    sta l00d3                                                         ; ee07: 85 d3       ..
    pla                                                               ; ee09: 68          h
    rts                                                               ; ee0a: 60          `

; &ee0b referenced 3 times by &edef, &ee33, &ee5e
.sub_cee0b
    jsr sub_cedf6                                                     ; ee0b: 20 f6 ed     ..
    sty l00d4                                                         ; ee0e: 84 d4       ..
    ldy #0                                                            ; ee10: a0 00       ..
    sta (l00d2),y                                                     ; ee12: 91 d2       ..
    ldy l00d4                                                         ; ee14: a4 d4       ..
    rts                                                               ; ee16: 60          `

; &ee17 referenced 1 time by &ee21
.loop_cee17
    clc                                                               ; ee17: 18          .
; &ee18 referenced 1 time by &ee25
.loop_cee18
    php                                                               ; ee18: 08          .
    asl l00d1                                                         ; ee19: 06 d1       ..
    plp                                                               ; ee1b: 28          (
    ror l00d1                                                         ; ee1c: 66 d1       f.
    rts                                                               ; ee1e: 60          `

; &ee1f referenced 2 times by &ed8e, &ed9c
.sub_cee1f
    cmp #6                                                            ; ee1f: c9 06       ..
    beq loop_cee17                                                    ; ee21: f0 f4       ..
    cmp #&15                                                          ; ee23: c9 15       ..
    beq loop_cee18                                                    ; ee25: f0 f1       ..
    ldy l00d1                                                         ; ee27: a4 d1       ..
    bmi return_14                                                     ; ee29: 30 2d       0-
    cmp #&20 ; ' '                                                    ; ee2b: c9 20       .
    bcc cee63                                                         ; ee2d: 90 34       .4
    cmp #&7f                                                          ; ee2f: c9 7f       ..
    beq cee59                                                         ; ee31: f0 26       .&
; &ee33 referenced 1 time by &ee81
.cee33
    jsr sub_cee0b                                                     ; ee33: 20 0b ee     ..
; &ee36 referenced 1 time by &ee83
.cee36
    iny                                                               ; ee36: c8          .
    cpy #&28 ; '('                                                    ; ee37: c0 28       .(
    bcc cee40                                                         ; ee39: 90 05       ..
    jsr sub_cedc2                                                     ; ee3b: 20 c2 ed     ..
; &ee3e referenced 3 times by &ee65, &ee9b, &eed7
.cee3e
    ldy #0                                                            ; ee3e: a0 00       ..
; &ee40 referenced 5 times by &ee39, &ee61, &ee88, &ee90, &eea7
.cee40
    jsr sub_cedf6                                                     ; ee40: 20 f6 ed     ..
    sty l00d1                                                         ; ee43: 84 d1       ..
    ldy #&0f                                                          ; ee45: a0 0f       ..
    sty crtc_address                                                  ; ee47: 8c 00 08    ...
    lda l00d2                                                         ; ee4a: a5 d2       ..
    sta crtc_data                                                     ; ee4c: 8d 01 08    ...
    dey                                                               ; ee4f: 88          .              ; Y=&0e
    sty crtc_address                                                  ; ee50: 8c 00 08    ...
    ldy l00d4                                                         ; ee53: a4 d4       ..
    sty crtc_data                                                     ; ee55: 8c 01 08    ...
; &ee58 referenced 1 time by &ee29
.return_14
    rts                                                               ; ee58: 60          `

; &ee59 referenced 1 time by &ee31
.cee59
    jsr sub_ceda7                                                     ; ee59: 20 a7 ed     ..
    lda #&20 ; ' '                                                    ; ee5c: a9 20       .
    jsr sub_cee0b                                                     ; ee5e: 20 0b ee     ..
    bpl cee40                                                         ; ee61: 10 dd       ..
; &ee63 referenced 1 time by &ee2d
.cee63
    cmp #&0d                                                          ; ee63: c9 0d       ..
    beq cee3e                                                         ; ee65: f0 d7       ..
    cmp #&0a                                                          ; ee67: c9 0a       ..
    beq cee8b                                                         ; ee69: f0 20       .
    cmp #&0c                                                          ; ee6b: c9 0c       ..
    beq ceeaa                                                         ; ee6d: f0 3b       .;
    cmp #8                                                            ; ee6f: c9 08       ..
    beq cee85                                                         ; ee71: f0 12       ..
    cmp #&1e                                                          ; ee73: c9 1e       ..
    beq cee93                                                         ; ee75: f0 1c       ..
    cmp #&0b                                                          ; ee77: c9 0b       ..
    beq ceea4                                                         ; ee79: f0 29       .)
    cmp #7                                                            ; ee7b: c9 07       ..
    beq ceeda                                                         ; ee7d: f0 5b       .[
    cmp #9                                                            ; ee7f: c9 09       ..
    bne cee33                                                         ; ee81: d0 b0       ..
    bcs cee36                                                         ; ee83: b0 b1       ..             ; ALWAYS branch

; &ee85 referenced 1 time by &ee71
.cee85
    jsr sub_ceda7                                                     ; ee85: 20 a7 ed     ..
    jmp cee40                                                         ; ee88: 4c 40 ee    L@.

; &ee8b referenced 1 time by &ee69
.cee8b
    jsr sub_cedc2                                                     ; ee8b: 20 c2 ed     ..
    ldy l00d1                                                         ; ee8e: a4 d1       ..
    jmp cee40                                                         ; ee90: 4c 40 ee    L@.

; &ee93 referenced 1 time by &ee75
.cee93
    lda #&18                                                          ; ee93: a9 18       ..
    ldy l00ce                                                         ; ee95: a4 ce       ..
    sta l00ce                                                         ; ee97: 85 ce       ..
; &ee99 referenced 1 time by &eea1
.loop_cee99
    cpy #&18                                                          ; ee99: c0 18       ..
    bcs cee3e                                                         ; ee9b: b0 a1       ..
    iny                                                               ; ee9d: c8          .
    jsr sub_cedb4                                                     ; ee9e: 20 b4 ed     ..
    jmp loop_cee99                                                    ; eea1: 4c 99 ee    L..

; &eea4 referenced 1 time by &ee79
.ceea4
    jsr sub_cedac                                                     ; eea4: 20 ac ed     ..
    jmp cee40                                                         ; eea7: 4c 40 ee    L@.

; &eeaa referenced 1 time by &ee6d
.ceeaa
    lda #&20 ; ' '                                                    ; eeaa: a9 20       .
    ldy #0                                                            ; eeac: a0 00       ..
; &eeae referenced 1 time by &eebb
.loop_ceeae
    sta l0400,y                                                       ; eeae: 99 00 04    ...
    sta l0500,y                                                       ; eeb1: 99 00 05    ...
    sta l0600,y                                                       ; eeb4: 99 00 06    ...
    sta l0700,y                                                       ; eeb7: 99 00 07    ...
    iny                                                               ; eeba: c8          .
    bne loop_ceeae                                                    ; eebb: d0 f1       ..
    sty l00cf                                                         ; eebd: 84 cf       ..
    sty l00d1                                                         ; eebf: 84 d1       ..
    ldy #&0d                                                          ; eec1: a0 0d       ..
; &eec3 referenced 1 time by &eecd
.loop_ceec3
    sty crtc_address                                                  ; eec3: 8c 00 08    ...
    lda crtc_registers,y                                              ; eec6: b9 1c ef    ...
    sta crtc_data                                                     ; eec9: 8d 01 08    ...
    dey                                                               ; eecc: 88          .
    bpl loop_ceec3                                                    ; eecd: 10 f4       ..
    lda #&18                                                          ; eecf: a9 18       ..
    sta l00ce                                                         ; eed1: 85 ce       ..
    lda #4                                                            ; eed3: a9 04       ..
    sta l00d0                                                         ; eed5: 85 d0       ..
    jmp cee3e                                                         ; eed7: 4c 3e ee    L>.

; &eeda referenced 1 time by &ee7d
.ceeda
    stx l00d2                                                         ; eeda: 86 d2       ..
    jsr lfd1a                                                         ; eedc: 20 1a fd     ..
    ldx l00d2                                                         ; eedf: a6 d2       ..
    rts                                                               ; eee1: 60          `

; &eee2 referenced 1 time by &e00a
.ceee2
    ; Copy 16 bytes of memory from default_vectors to lodvec
    ldx #&0c                                                          ; eee2: a2 0c       ..
; &eee4 referenced 1 time by &eeed
.loop_ceee4
    lda default_vectors - 12,x                                        ; eee4: bd 1e ef    ...
    sta lodvec - 12,x                                                 ; eee7: 9d 00 02    ...
    inx                                                               ; eeea: e8          .
    cpx #&1c                                                          ; eeeb: e0 1c       ..
    bne loop_ceee4                                                    ; eeed: d0 f5       ..

    ; Set NMI vector to 'dos_nmi'
    lda #<dos_nmi                                                     ; eeef: a9 7b       .{
    sta nmivec                                                        ; eef1: 8d 00 02    ...
    lda #>dos_nmi                                                     ; eef4: a9 e8       ..
    sta nmivec+1                                                      ; eef6: 8d 01 02    ...

    ; Set command line vector to 'dos_cli'
    lda #<dos_cli                                                     ; eef9: a9 e5       ..
    sta comvec                                                        ; eefb: 8d 06 02    ...
    lda #>dos_cli                                                     ; eefe: a9 e3       ..
    sta comvec+1                                                      ; ef00: 8d 07 02    ...

    lda #&20 ; ' '                                                    ; ef03: a9 20       .
    sta l00cd                                                         ; ef05: 85 cd       ..
    sta l00ac                                                         ; ef07: 85 ac       ..
    ldy #0                                                            ; ef09: a0 00       ..
    sty l00ee                                                         ; ef0b: 84 ee       ..
    sty l00c0                                                         ; ef0d: 84 c0       ..
    sty l00b9                                                         ; ef0f: 84 b9       ..
    sty l00ba                                                         ; ef11: 84 ba       ..
    ldx #4                                                            ; ef13: a2 04       ..
; &ef15 referenced 1 time by &ef19
.loop_cef15
    jsr fdc_send_commands                                             ; ef15: 20 13 e7     ..
    dex                                                               ; ef18: ca          .
    bne loop_cef15                                                    ; ef19: d0 fa       ..
    rts                                                               ; ef1b: 60          `

    ; The 6845's registers R0-R13 (40 by 25 characters, with the screen at #0400)
; &ef1c referenced 1 time by &eec6
.crtc_registers
    equb &3f, &28, &33, &44, &1e, 2, &19, &1b, 3, &12, &72, &13, 4, 0 ; ef1c: 3f 28 33... ?(3
; &ef1e referenced 1 time by &eee4
.default_vectors
    equw dos_load                                                     ; ef2a: 77 e4       w.
    equw dos_save                                                     ; ef2c: 13 e6       ..
    equw dos_rdar                                                     ; ef2e: 61 ea       a.
    equw dos_star                                                     ; ef30: a0 ec       ..
    equw dos_bget                                                     ; ef32: f0 ea       ..
    equw dos_bput                                                     ; ef34: bc eb       ..
    equw dos_find                                                     ; ef36: 53 e9       S.
    equw dos_shut                                                     ; ef38: 9e e8       ..
    ; Not used: left over from the assembler source of vdu_rdch (each line a line
    ; number in BCD, the text and a CR)
.unused
    equs "ICES."                                                      ; ef3a: 49 43 45... ICE
    equb &0d                                                          ; ef3f: 0d          .
    equb 0, &20                                                       ; ef40: 00 20       .
    equs "SCRA * $0400"                                               ; ef42: 53 43 52... SCR
    equb &0d                                                          ; ef4e: 0d          .
    equb 0, &30                                                       ; ef4f: 00 30       .0
    equs "SCRB * $0500"                                               ; ef51: 53 43 52... SCR
    equb &0d                                                          ; ef5d: 0d          .
    equb 0, &40                                                       ; ef5e: 00 40       .@
    equs "SCRC * $0600"                                               ; ef60: 53 43 52... SCR
    equb &0d                                                          ; ef6c: 0d          .
    equb 0, &50                                                       ; ef6d: 00 50       .P
    equs "SCRD * $0700"                                               ; ef6f: 53 43 52... SCR
    equb &0d                                                          ; ef7b: 0d          .
    equb 0, &60                                                       ; ef7c: 00 60       .`
    equs "HSYNC * $33"                                                ; ef7e: 48 53 59... HSY
    equb &0d                                                          ; ef89: 0d          .
    equb 0, &70                                                       ; ef8a: 00 70       .p
    equs "KBIN PHP"                                                   ; ef8c: 4b 42 49... KBI
    equb &0d                                                          ; ef94: 0d          .
    equb 0, &80                                                       ; ef95: 00 80       ..
    equs " CLD"                                                       ; ef97: 20 43 4c...  CL
    equb &0d                                                          ; ef9b: 0d          .
    equb 0, &90                                                       ; ef9c: 00 90       ..
    equs " STX $00E4"                                                 ; ef9e: 20 53 54...  ST
    equb &0d                                                          ; efa8: 0d          .
    equb 1, 0                                                         ; efa9: 01 00       ..
    equs " STY $00E5"                                                 ; efab: 20 53 54...  ST
    equb &0d                                                          ; efb5: 0d          .
    equb 1, &10                                                       ; efb6: 01 10       ..
    equs "FINDKY BIT $B002"                                           ; efb8: 46 49 4e... FIN
    equb &0d                                                          ; efc8: 0d          .
    equb 1, &20                                                       ; efc9: 01 20       .
    equs " BVC REPTTT"                                                ; efcb: 20 42 56...  BV
    equb &0d                                                          ; efd6: 0d          .
    equb 1, &30                                                       ; efd7: 01 30       .0
    equs "NOREPT JSR $FE71"                                           ; efd9: 4e 4f 52... NOR
    equb &0d                                                          ; efe9: 0d          .
    equb 1, &40                                                       ; efea: 01 40       .@
    equs " BCC FINDKY"                                                ; efec: 20 42 43...  BC
    equb &0d                                                          ; eff7: 0d          .
    equb 0, 0, 0, 0, &40, &40, &40, &40                               ; eff8: 00 00 00... ...
.pydis_end

    assert &e5 == <dos_cli
    assert &7b == <dos_nmi
    assert &c8 == <rdch_at
    assert &c0 == <rdch_delete
    assert &d8 == <rdch_digits
    assert &d2 == <rdch_keys_1_to_4
    assert &d6 == <rdch_keys_28_to_31
    assert &c2 == <rdch_keys_59_to_63
    assert &e2 == <rdch_keys_8_to_13
    assert &c6 == <rdch_letters
    assert &9a == <rdch_lock
    assert &df == <rdch_space_or_zero
    assert &29 == <seek_done
    assert &37 == <star_cat
    assert &1a == <star_delete
    assert &31 == <star_dir
    assert &2a == <star_drive
    assert &19 == <star_exec
    assert &65 == <star_go
    assert &b2 == <star_info
    assert &65 == <star_load
    assert &99 == <star_lock
    assert &5b == <star_mon
    assert &59 == <star_nomon
    assert &0a == <star_run
    assert &e6 == <star_save
    assert &72 == <star_set
    assert &9c == <star_shut
    assert &47 == <star_spool
    assert &78 == <star_title
    assert &9a == <star_unlock
    assert &af == <star_use
    assert &b8 == <star_vdu
    assert &c5 == <unknown_command
    assert &81 == <vdu_rdch_copy
    assert &88 == <vdu_rdch_cursor
    assert &e3 == >dos_cli
    assert &e8 == >dos_nmi
    assert &fd == >rdch_at
    assert &fd == >rdch_delete
    assert &fd == >rdch_digits
    assert &fd == >rdch_keys_1_to_4
    assert &fd == >rdch_keys_28_to_31
    assert &fd == >rdch_keys_59_to_63
    assert &fd == >rdch_keys_8_to_13
    assert &fd == >rdch_letters
    assert &fd == >rdch_lock
    assert &fd == >rdch_space_or_zero
    assert &e7 == >seek_done
    assert &e2 == >star_cat
    assert &e4 == >star_delete
    assert &e2 == >star_dir
    assert &e4 == >star_drive
    assert &e5 == >star_exec
    assert &e5 == >star_go
    assert &e1 == >star_info
    assert &e4 == >star_load
    assert &e5 == >star_lock
    assert &e4 == >star_mon
    assert &e4 == >star_nomon
    assert &e5 == >star_run
    assert &e5 == >star_save
    assert &e5 == >star_set
    assert &e8 == >star_shut
    assert &e5 == >star_spool
    assert &e5 == >star_title
    assert &e5 == >star_unlock
    assert &e5 == >star_use
    assert &e6 == >star_vdu
    assert &e4 == >unknown_command
    assert &ed == >vdu_rdch_copy
    assert &ed == >vdu_rdch_cursor
    assert &ef1e == default_vectors - 12
    assert &eaf0 == dos_bget
    assert &ebbc == dos_bput
    assert &e953 == dos_find
    assert &e477 == dos_load
    assert &ea61 == dos_rdar
    assert &e613 == dos_save
    assert &e89e == dos_shut
    assert &eca0 == dos_star
    assert &fe94 == kernel_rdch
    assert &fe52 == kernel_wrch
    assert &0200 == lodvec - 12
    assert &f2 == nmi_transfer_byte
    assert &ed22 == vdu_rdch
    assert &ed55 == vdu_rdch_handlers_high-11
    assert &ed48 == vdu_rdch_handlers_low-11
    assert &ed94 == vdu_wrch

save pydis_start, pydis_end

; Label references by decreasing frequency:
;     l00c2:                         19
;     l009a:                         17
;     l00ac:                         13
;     l2217:                         13
;     l00ee:                         12
;     print_inline_string:           12
;     OSWRCH:                        11
;     l2008:                         11
;     l210e:                         11
;     l00a2:                         10
;     l2211:                         10
;     l2212:                         10
;     input_buffer:                   9
;     l00e9:                          9
;     wait_for_fdc:                   9
;     l00a3:                          8
;     l00c6:                          8
;     l200f:                          8
;     l2105:                          8
;     l2210:                          8
;     fdc_command_status:             7
;     l009b:                          7
;     l009c:                          7
;     l00a0:                          7
;     l00a1:                          7
;     l00c0:                          7
;     l00c3:                          7
;     l00ce:                          7
;     l00d2:                          7
;     basic_error_number:             6
;     basic_line_number:              6
;     l009e:                          6
;     l00c4:                          6
;     l00c5:                          6
;     l00cf:                          6
;     l00d1:                          6
;     l00f1:                          6
;     l2200:                          6
;     l2214:                          6
;     nomon_flag:                     6
;     print_hex:                      6
;     sub_ce0ec:                      6
;     sub_ce0fb:                      6
;     sub_ce500:                      6
;     sub_ce5cc:                      6
;     cee40:                          5
;     crtc_address:                   5
;     crtc_data:                      5
;     fdc_write_parameter:            5
;     l00b9:                          5
;     l00ba:                          5
;     l00cb:                          5
;     l00cd:                          5
;     l00d0:                          5
;     l00d4:                          5
;     l00ec:                          5
;     l00ed:                          5
;     l2108:                          5
;     l220d:                          5
;     l2215:                          5
;     l2216:                          5
;     lf876:                          5
;     sub_ce041:                      5
;     sub_ce15d:                      5
;     OSCRLF:                         4
;     fdc_read_result:                4
;     l009d:                          4
;     l00a5:                          4
;     l210d:                          4
;     l210f:                          4
;     l2213:                          4
;     sub_ce0b4:                      4
;     sub_ce100:                      4
;     sub_ce1bb:                      4
;     sub_ce5c9:                      4
;     sub_cea7c:                      4
;     sub_cead1:                      4
;     sub_cecfa:                      4
;     write_catalogue:                4
;     ce08f:                          3
;     ce0e9:                          3
;     ce43f:                          3
;     ce460:                          3
;     ce5a9:                          3
;     ce8ae:                          3
;     ceb61:                          3
;     ced7b:                          3
;     cee3e:                          3
;     check_fdc_result:               3
;     dos_shut:                       3
;     fdc_command:                    3
;     fdc_transfer:                   3
;     fdc_write_command:              3
;     l00ae:                          3
;     l00b5:                          3
;     l00b6:                          3
;     l00b7:                          3
;     l00b8:                          3
;     l00bb:                          3
;     l00c7:                          3
;     l00c8:                          3
;     l00c9:                          3
;     l00ca:                          3
;     l00cc:                          3
;     l00d5:                          3
;     l00f0:                          3
;     l00f7:                          3
;     l2107:                          3
;     l210c:                          3
;     l220f:                          3
;     l221c:                          3
;     l221d:                          3
;     l221f:                          3
;     le95a:                          3
;     lf80b:                          3
;     nmi_buffer_address:             3
;     print_disk_and_inline_string:   3
;     scan_keyboard:                  3
;     sub_ce068:                      3
;     sub_ce149:                      3
;     sub_ce93e:                      3
;     sub_ceaad:                      3
;     sub_ceb67:                      3
;     sub_ceb76:                      3
;     sub_cedf6:                      3
;     sub_cee0b:                      3
;     wrcvec:                         3
;     OSFIND:                         2
;     ce030:                          2
;     ce05c:                          2
;     ce0ab:                          2
;     ce0f3:                          2
;     ce162:                          2
;     ce184:                          2
;     ce2be:                          2
;     ce44f:                          2
;     ce493:                          2
;     ce5d3:                          2
;     ce67f:                          2
;     ce6ca:                          2
;     ce78b:                          2
;     ce829:                          2
;     ce9c5:                          2
;     cec43:                          2
;     cec47:                          2
;     cecf4:                          2
;     ced28:                          2
;     ced35:                          2
;     command_table:                  2
;     comvec:                         2
;     copy_nmi_read_byte:             2
;     copy_nmi_write_byte:            2
;     fdc_data:                       2
;     fdc_initialisation:             2
;     fdc_parameter_result:           2
;     fdc_reset:                      2
;     l00ad:                          2
;     l00bf:                          2
;     l00c1:                          2
;     l00d6:                          2
;     l00e2:                          2
;     l00eb:                          2
;     l00ef:                          2
;     l1fff:                          2
;     l2000:                          2
;     l2007:                          2
;     l20f8:                          2
;     l2101:                          2
;     l2102:                          2
;     l2103:                          2
;     l2106:                          2
;     l2209:                          2
;     l220b:                          2
;     l220e:                          2
;     l2219:                          2
;     l221a:                          2
;     l221b:                          2
;     nmivec:                         2
;     rdcvec:                         2
;     read_catalogue_and_wait:        2
;     read_drive_status:              2
;     return_12:                      2
;     return_13:                      2
;     return_5:                       2
;     return_9:                       2
;     seek_catalogue:                 2
;     select_drive:                   2
;     star_dir:                       2
;     sub_ce033:                      2
;     sub_ce0b6:                      2
;     sub_ce0fa:                      2
;     sub_ce101:                      2
;     sub_ce109:                      2
;     sub_ce18c:                      2
;     sub_ce288:                      2
;     sub_ce352:                      2
;     sub_ce356:                      2
;     sub_ce5bd:                      2
;     sub_ce61a:                      2
;     sub_cea9d:                      2
;     sub_ceab5:                      2
;     sub_ceadf:                      2
;     sub_ceb65:                      2
;     sub_ceb6c:                      2
;     sub_ceb6e:                      2
;     sub_ceb7e:                      2
;     sub_ced12:                      2
;     sub_ceda7:                      2
;     sub_cedc2:                      2
;     sub_cee1f:                      2
;     OSASCI:                         1
;     OSBGET:                         1
;     OSBPUT:                         1
;     OSECHO:                         1
;     OSSAVE:                         1
;     OSSHUT:                         1
;     c00f5:                          1
;     ce024:                          1
;     ce043:                          1
;     ce0c1:                          1
;     ce0d4:                          1
;     ce154:                          1
;     ce18a:                          1
;     ce1aa:                          1
;     ce1d1:                          1
;     ce248:                          1
;     ce26d:                          1
;     ce293:                          1
;     ce29c:                          1
;     ce2a2:                          1
;     ce2ad:                          1
;     ce2cf:                          1
;     ce2f1:                          1
;     ce358:                          1
;     ce40d:                          1
;     ce471:                          1
;     ce47b:                          1
;     ce481:                          1
;     ce4a8:                          1
;     ce4f4:                          1
;     ce510:                          1
;     ce52b:                          1
;     ce544:                          1
;     ce5c5:                          1
;     ce5de:                          1
;     ce606:                          1
;     ce625:                          1
;     ce655:                          1
;     ce65a:                          1
;     ce667:                          1
;     ce727:                          1
;     ce798:                          1
;     ce7b5:                          1
;     ce7be:                          1
;     ce836:                          1
;     ce888:                          1
;     ce88b:                          1
;     ce8b0:                          1
;     ce8b2:                          1
;     ce8c1:                          1
;     ce8ca:                          1
;     ce900:                          1
;     ce906:                          1
;     ce958:                          1
;     ce971:                          1
;     ce988:                          1
;     ce992:                          1
;     ce9be:                          1
;     ce9c8:                          1
;     cea51:                          1
;     cea5a:                          1
;     cea97:                          1
;     cea9a:                          1
;     ceb10:                          1
;     ceb14:                          1
;     ceb29:                          1
;     ceb34:                          1
;     ceb55:                          1
;     ceb71:                          1
;     ceb8a:                          1
;     cebac:                          1
;     cebb2:                          1
;     cec12:                          1
;     cec13:                          1
;     cec1f:                          1
;     cec2b:                          1
;     cec76:                          1
;     cec7a:                          1
;     cec97:                          1
;     cecc1:                          1
;     ced16:                          1
;     ced32:                          1
;     cee33:                          1
;     cee36:                          1
;     cee59:                          1
;     cee63:                          1
;     cee85:                          1
;     cee8b:                          1
;     cee93:                          1
;     ceea4:                          1
;     ceeaa:                          1
;     ceeda:                          1
;     ceee2:                          1
;     command_table+1:                1
;     crtc_registers:                 1
;     dos_bput:                       1
;     drive_control_bits:             1
;     fdc_send_commands:              1
;     irq_save_a:                     1
;     l009f:                          1
;     l00a4:                          1
;     l00d3:                          1
;     l00e3:                          1
;     l00e4:                          1
;     l00e5:                          1
;     l0400:                          1
;     l0500:                          1
;     l0600:                          1
;     l0700:                          1
;     l200e:                          1
;     l2010:                          1
;     l2104:                          1
;     l2110:                          1
;     l220c:                          1
;     le6f8:                          1
;     le6f9:                          1
;     le6fa:                          1
;     le98b:                          1
;     lfb8a:                          1
;     lfd1a:                          1
;     lfe60:                          1
;     lfec5:                          1
;     lfefb:                          1
;     lodvec:                         1
;     loop_ce01e:                     1
;     loop_ce04c:                     1
;     loop_ce06a:                     1
;     loop_ce079:                     1
;     loop_ce07f:                     1
;     loop_ce0dc:                     1
;     loop_ce13a:                     1
;     loop_ce13b:                     1
;     loop_ce178:                     1
;     loop_ce191:                     1
;     loop_ce1d6:                     1
;     loop_ce1e0:                     1
;     loop_ce23e:                     1
;     loop_ce274:                     1
;     loop_ce285:                     1
;     loop_ce2b2:                     1
;     loop_ce2c2:                     1
;     loop_ce2d7:                     1
;     loop_ce35a:                     1
;     loop_ce3e8:                     1
;     loop_ce3ee:                     1
;     loop_ce3f0:                     1
;     loop_ce3fb:                     1
;     loop_ce4ad:                     1
;     loop_ce4b2:                     1
;     loop_ce516:                     1
;     loop_ce582:                     1
;     loop_ce588:                     1
;     loop_ce64f:                     1
;     loop_ce66c:                     1
;     loop_ce681:                     1
;     loop_ce68c:                     1
;     loop_ce719:                     1
;     loop_ce73c:                     1
;     loop_ce74d:                     1
;     loop_ce774:                     1
;     loop_ce79a:                     1
;     loop_ce80a:                     1
;     loop_ce8a3:                     1
;     loop_ce917:                     1
;     loop_ce975:                     1
;     loop_ce99f:                     1
;     loop_ce9dc:                     1
;     loop_ce9f3:                     1
;     loop_cea40:                     1
;     loop_cea8d:                     1
;     loop_ceaa1:                     1
;     loop_ceadb:                     1
;     loop_ceae7:                     1
;     loop_cebb8:                     1
;     loop_cecb5:                     1
;     loop_ceda4:                     1
;     loop_cedbf:                     1
;     loop_cedef:                     1
;     loop_cee17:                     1
;     loop_cee18:                     1
;     loop_cee99:                     1
;     loop_ceeae:                     1
;     loop_ceec3:                     1
;     loop_ceee4:                     1
;     loop_cef15:                     1
;     nmi_read_byte:                  1
;     nmi_routines:                   1
;     nmi_transfer_byte:              1
;     nmi_write_byte:                 1
;     ppi_port_b:                     1
;     ppi_port_c:                     1
;     read_catalogue:                 1
;     return_1:                       1
;     return_10:                      1
;     return_11:                      1
;     return_14:                      1
;     return_2:                       1
;     return_3:                       1
;     return_4:                       1
;     return_6:                       1
;     return_7:                       1
;     return_8:                       1
;     star_drive:                     1
;     string_buffer:                  1
;     sub_ce075:                      1
;     sub_ce0f1:                      1
;     sub_ce104:                      1
;     sub_ce112:                      1
;     sub_ce14c:                      1
;     sub_ce1bf:                      1
;     sub_ce319:                      1
;     sub_ce338:                      1
;     sub_ce46f:                      1
;     sub_ce484:                      1
;     sub_ce487:                      1
;     sub_ce4a3:                      1
;     sub_ce5b3:                      1
;     sub_ce6ad:                      1
;     sub_ce6b0:                      1
;     sub_ce816:                      1
;     sub_ce839:                      1
;     sub_ce846:                      1
;     sub_ce899:                      1
;     sub_ce912:                      1
;     sub_ce915:                      1
;     sub_ced97:                      1
;     sub_cedac:                      1
;     sub_cedb4:                      1
;     vdu_rdch:                       1
;     vdu_vectors:                    1

; Automatically generated labels:
;     c00f5
;     ce024
;     ce030
;     ce043
;     ce05c
;     ce08f
;     ce0ab
;     ce0c1
;     ce0d4
;     ce0e9
;     ce0f3
;     ce154
;     ce162
;     ce184
;     ce18a
;     ce1aa
;     ce1d1
;     ce248
;     ce26d
;     ce293
;     ce29c
;     ce2a2
;     ce2ad
;     ce2be
;     ce2cf
;     ce2f1
;     ce358
;     ce40d
;     ce43f
;     ce44f
;     ce460
;     ce471
;     ce47b
;     ce481
;     ce493
;     ce4a8
;     ce4f4
;     ce510
;     ce52b
;     ce544
;     ce5a9
;     ce5c5
;     ce5d3
;     ce5de
;     ce606
;     ce625
;     ce655
;     ce65a
;     ce667
;     ce67f
;     ce6ca
;     ce727
;     ce78b
;     ce798
;     ce7b5
;     ce7be
;     ce829
;     ce836
;     ce888
;     ce88b
;     ce8ae
;     ce8b0
;     ce8b2
;     ce8c1
;     ce8ca
;     ce900
;     ce906
;     ce958
;     ce959
;     ce971
;     ce988
;     ce98a
;     ce992
;     ce9be
;     ce9c5
;     ce9c8
;     cea51
;     cea5a
;     cea97
;     cea9a
;     ceb10
;     ceb14
;     ceb29
;     ceb34
;     ceb55
;     ceb61
;     ceb71
;     ceb8a
;     cebac
;     cebb2
;     cec12
;     cec13
;     cec1f
;     cec2b
;     cec43
;     cec47
;     cec76
;     cec7a
;     cec97
;     cecc1
;     cecf4
;     ced16
;     ced28
;     ced32
;     ced35
;     ced7b
;     cee33
;     cee36
;     cee3e
;     cee40
;     cee59
;     cee63
;     cee85
;     cee8b
;     cee93
;     ceea4
;     ceeaa
;     ceeda
;     ceee2
;     l009a
;     l009b
;     l009c
;     l009d
;     l009e
;     l009f
;     l00a0
;     l00a1
;     l00a2
;     l00a3
;     l00a4
;     l00a5
;     l00ac
;     l00ad
;     l00ae
;     l00b5
;     l00b6
;     l00b7
;     l00b8
;     l00b9
;     l00ba
;     l00bb
;     l00bf
;     l00c0
;     l00c1
;     l00c2
;     l00c3
;     l00c4
;     l00c5
;     l00c6
;     l00c7
;     l00c8
;     l00c9
;     l00ca
;     l00cb
;     l00cc
;     l00cd
;     l00ce
;     l00cf
;     l00d0
;     l00d1
;     l00d2
;     l00d3
;     l00d4
;     l00d5
;     l00d6
;     l00e2
;     l00e3
;     l00e4
;     l00e5
;     l00e9
;     l00eb
;     l00ec
;     l00ed
;     l00ee
;     l00ef
;     l00f0
;     l00f1
;     l00f7
;     l0400
;     l0500
;     l0600
;     l0700
;     l1fff
;     l2000
;     l2007
;     l2008
;     l200e
;     l200f
;     l2010
;     l20f8
;     l2101
;     l2102
;     l2103
;     l2104
;     l2105
;     l2106
;     l2107
;     l2108
;     l210c
;     l210d
;     l210e
;     l210f
;     l2110
;     l2200
;     l2209
;     l220b
;     l220c
;     l220d
;     l220e
;     l220f
;     l2210
;     l2211
;     l2212
;     l2213
;     l2214
;     l2215
;     l2216
;     l2217
;     l2219
;     l221a
;     l221b
;     l221c
;     l221d
;     l221f
;     le6f8
;     le6f9
;     le6fa
;     le95a
;     le98b
;     lf80b
;     lf876
;     lfb8a
;     lfd1a
;     lfe60
;     lfec5
;     lfefb
;     loop_ce01e
;     loop_ce04c
;     loop_ce06a
;     loop_ce079
;     loop_ce07f
;     loop_ce0dc
;     loop_ce13a
;     loop_ce13b
;     loop_ce178
;     loop_ce191
;     loop_ce1d6
;     loop_ce1e0
;     loop_ce23e
;     loop_ce274
;     loop_ce285
;     loop_ce2b2
;     loop_ce2c2
;     loop_ce2d7
;     loop_ce35a
;     loop_ce3e8
;     loop_ce3ee
;     loop_ce3f0
;     loop_ce3fb
;     loop_ce4ad
;     loop_ce4b2
;     loop_ce516
;     loop_ce582
;     loop_ce588
;     loop_ce64f
;     loop_ce66c
;     loop_ce681
;     loop_ce68c
;     loop_ce719
;     loop_ce73c
;     loop_ce74d
;     loop_ce774
;     loop_ce79a
;     loop_ce80a
;     loop_ce8a3
;     loop_ce917
;     loop_ce975
;     loop_ce99f
;     loop_ce9dc
;     loop_ce9f3
;     loop_cea40
;     loop_cea8d
;     loop_ceaa1
;     loop_ceadb
;     loop_ceae7
;     loop_cebb8
;     loop_cecb5
;     loop_ceda4
;     loop_cedbf
;     loop_cedef
;     loop_cee17
;     loop_cee18
;     loop_cee99
;     loop_ceeae
;     loop_ceec3
;     loop_ceee4
;     loop_cef15
;     return_1
;     return_10
;     return_11
;     return_12
;     return_13
;     return_14
;     return_2
;     return_3
;     return_4
;     return_5
;     return_6
;     return_7
;     return_8
;     return_9
;     sub_ce033
;     sub_ce041
;     sub_ce068
;     sub_ce075
;     sub_ce0b4
;     sub_ce0b6
;     sub_ce0ec
;     sub_ce0f1
;     sub_ce0fa
;     sub_ce0fb
;     sub_ce100
;     sub_ce101
;     sub_ce104
;     sub_ce109
;     sub_ce112
;     sub_ce149
;     sub_ce14c
;     sub_ce15d
;     sub_ce18c
;     sub_ce1bb
;     sub_ce1bf
;     sub_ce288
;     sub_ce319
;     sub_ce338
;     sub_ce352
;     sub_ce356
;     sub_ce46f
;     sub_ce484
;     sub_ce487
;     sub_ce4a3
;     sub_ce500
;     sub_ce5b3
;     sub_ce5bd
;     sub_ce5c9
;     sub_ce5cc
;     sub_ce61a
;     sub_ce6ad
;     sub_ce6b0
;     sub_ce816
;     sub_ce839
;     sub_ce846
;     sub_ce899
;     sub_ce912
;     sub_ce915
;     sub_ce93e
;     sub_cea7c
;     sub_cea9d
;     sub_ceaad
;     sub_ceab5
;     sub_cead1
;     sub_ceadf
;     sub_ceb65
;     sub_ceb67
;     sub_ceb6c
;     sub_ceb6e
;     sub_ceb76
;     sub_ceb7e
;     sub_cecfa
;     sub_ced12
;     sub_ced97
;     sub_ceda7
;     sub_cedac
;     sub_cedb4
;     sub_cedc2
;     sub_cedf6
;     sub_cee0b
;     sub_cee1f

; Stats:
;
;     Total size (Code + Data) = 4096 bytes
;     Code                     = 3587 bytes (88%)
;     Data                     = 509 bytes (12%)
;
;     Number of instructions   = 1706
;     Number of data bytes     = 165 bytes
;     Number of data words     = 24 bytes
;     Number of string bytes   = 320 bytes
;     Number of strings        = 49

