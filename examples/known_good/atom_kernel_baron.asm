; Assemble with Baron, which writes the program to the file named in its
; section (atom_kernel_baron), in the folder given with -p:
;     baron -p . atom_kernel_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
basic_error_number      = &0000
basic_line_number       = &0001
parsing_ptr_offset      = &0003
workspace_stack_pointer = &0004
parsing_ptr_low         = &0005
parsing_ptr_high        = &0006
l000d                   = &000d
l000e                   = &000e
l000f                   = &000f
text_space_page         = &0012
int_workspace_stack_low = &0016
int_workspace_stack_mid1 = &0025
int_workspace_stack_mid2 = &0034
int_workspace_stack_high = &0043
l0052                   = &0052
l0053                   = &0053
l0054                   = &0054
l0055                   = &0055
l0056                   = &0056
l0057                   = &0057
l0059                   = &0059
l005a                   = &005a
l005b                   = &005b
l005c                   = &005c
l005d                   = &005d
l005e                   = &005e
l005f                   = &005f
l0060                   = &0060
l0061                   = &0061
l0064                   = &0064
l0065                   = &0065
l0066                   = &0066
l0067                   = &0067
l0068                   = &0068
l0069                   = &0069
l006a                   = &006a
l0086                   = &0086
l00c0                   = &00c0
l00c1                   = &00c1
l00c2                   = &00c2
l00c3                   = &00c3
l00c4                   = &00c4
l00c5                   = &00c5
l00c9                   = &00c9
l00ca                   = &00ca
l00cb                   = &00cb
l00cc                   = &00cc
l00cd                   = &00cd
l00ce                   = &00ce
l00cf                   = &00cf
l00d0                   = &00d0
l00d1                   = &00d1
l00d2                   = &00d2
l00d3                   = &00d3
l00d4                   = &00d4
l00d5                   = &00d5
l00d6                   = &00d6
l00d8                   = &00d8
l00db                   = &00db
l00dc                   = &00dc
l00dd                   = &00dd
screen_line_address     = &00de
cursor_column           = &00e0
cursor_mask             = &00e1
l00e2                   = &00e2
l00e3                   = &00e3
l00e4                   = &00e4
l00e5                   = &00e5
page_mode_count         = &00e6
lock_flag               = &00e7
l00e8                   = &00e8
l00e9                   = &00e9
nomon_flag              = &00ea
l00ec                   = &00ec
l00ed                   = &00ed
l00fd                   = &00fd
printer_ignore_char     = &00fe
irq_save_a              = &00ff

; Input buffer (&0100-&013f)
input_buffer = &0100
l013f       = &013f

; String buffer (&0140-&017f)
string_buffer   = &0140

; OS vectors (&0200-&021f)
nmivec  = &0200
brkvec  = &0202
irqvec  = &0204
comvec  = &0206
wrcvec  = &0208
rdcvec  = &020a
lodvec  = &020c
savvec  = &020e
rdrvec  = &0210
strvec  = &0212
bgtvec  = &0214
bptvec  = &0216
fndvec  = &0218
shtvec  = &021a

; Workspace (&0220-&03ff)
l02eb       = &02eb
l0306       = &0306
l0321       = &0321
l0331       = &0331
l033c       = &033c
l034c       = &034c
l03c1       = &03c1
l03c2       = &03c2
l03c3       = &03c3
l03c4       = &03c4
plot_vector = &03fe

; User memory (&2800-&7fff)
l2901   = &2901
l7fe0   = &7fe0

; Screen memory (&8000-&97ff)
l8000   = &8000
l80e0   = &80e0
l8100   = &8100

; Utility ROM (&a000-&afff)
la000   = &a000

; I/O (&b000-&bfff)
ppi_port_a      = &b000
ppi_port_b      = &b001
ppi_port_c      = &b002
ppi_control     = &b003
via_register_a  = &b801
via_ddra        = &b803
via_pcr         = &b80c

; BASIC ROM (&c000-&cfff)
lc231                   = &c231
lc278                   = &c278
lc2ac                   = &c2ac
lc2b2                   = &c2b2
lc2b6                   = &c2b6
lc2cf                   = &c2cf
lc31b                   = &c31b
lc3c8                   = &c3c8
lc3cb                   = &c3cb
lc3f1                   = &c3f1
lc434                   = &c434
lc4e4                   = &c4e4
lc4f6                   = &c4f6
lc51d                   = &c51d
basic_unknown_command   = &c550
lc558                   = &c558
lc55b                   = &c55b
lc589                   = &c589
lc5f9                   = &c5f9
lc78b                   = &c78b
lc8bc                   = &c8bc
lc94f                   = &c94f
lc962                   = &c962
lca24                   = &ca24
lca4c                   = &ca4c
lcd54                   = &cd54
lcd9b                   = &cd9b
lce83                   = &ce83

; DOS ROM (&e000-&efff)
dos     = &e000
le298   = &e298
lefff   = &efff

section pydis, org = &f000, filename = "atom_kernel_baron"

; &f000 referenced 1 time by &f064
.pydis_start
.basic_command_table
lf001 = basic_command_table+1
    equs "PLOT"                                                       ; f000: 50 4c 4f... PLO
; &f001 referenced 1 time by &f077
    equb >command_plot                                                ; f004: f5          .
    equb <command_plot                                                ; f005: 4e          N
    equs "DRAW"                                                       ; f006: 44 52 41... DRA
    equb >command_draw                                                ; f00a: f5          .
    equb <command_draw                                                ; f00b: 42          B
    equs "MOVE"                                                       ; f00c: 4d 4f 56... MOV
    equb >command_move                                                ; f010: f5          .
    equb <command_move                                                ; f011: 46          F
    equs "CLEAR"                                                      ; f012: 43 4c 45... CLE
    equb >command_clear                                               ; f017: f6          .
    equb <command_clear                                               ; f018: 7b          {
    equs "DIM"                                                        ; f019: 44 49 4d    DIM
    equb >command_dim                                                 ; f01c: f0          .
    equb <command_dim                                                 ; f01d: ae          .
    equs "["                                                          ; f01e: 5b          [
    equb >command_assembler                                           ; f01f: f2          .
    equb <command_assembler                                           ; f020: a1          .
    equs "OLD"                                                        ; f021: 4f 4c 44    OLD
    equb >command_old                                                 ; f024: f5          .
    equb <command_old                                                 ; f025: 31          1
    equs "WAIT"                                                       ; f026: 57 41 49... WAI
    equb >command_wait                                                ; f02a: f1          .
    equb <command_wait                                                ; f02b: 4c          L
    equb >basic_unknown_command                                       ; f02c: c5          .
    equb <basic_unknown_command                                       ; f02d: 50          P

.test_array_variable
    ldy l005e                                                         ; f02e: a4 5e       .^
.test_array_variable_y
    lda (parsing_ptr_low),y                                           ; f030: b1 05       ..
    cmp #&40 ; '@'                                                    ; f032: c9 40       .@
    bcc cf048                                                         ; f034: 90 12       ..
    cmp #&5b ; '['                                                    ; f036: c9 5b       .[
    bcs cf048                                                         ; f038: b0 0e       ..
    iny                                                               ; f03a: c8          .
    cmp (parsing_ptr_low),y                                           ; f03b: d1 05       ..
    bne cf048                                                         ; f03d: d0 09       ..
    jsr sub_cf08b                                                     ; f03f: 20 8b f0     ..
    jsr lc94f                                                         ; f042: 20 4f c9     O.
    jmp lc962                                                         ; f045: 4c 62 c9    Lb.

; &f048 referenced 3 times by &f034, &f038, &f03d
.cf048
    jmp lca24                                                         ; f048: 4c 24 ca    L$.

.interpret_command
    ldx #&ff                                                          ; f04b: a2 ff       ..
    ldy l005e                                                         ; f04d: a4 5e       .^
    dec l005e                                                         ; f04f: c6 5e       .^
    lda (parsing_ptr_low),y                                           ; f051: b1 05       ..
    cmp #&40 ; '@'                                                    ; f053: c9 40       .@
    bcc cf060                                                         ; f055: 90 09       ..
    cmp #&5b ; '['                                                    ; f057: c9 5b       .[
    bcs cf060                                                         ; f059: b0 05       ..
    iny                                                               ; f05b: c8          .
    cmp (parsing_ptr_low),y                                           ; f05c: d1 05       ..
    beq assign_array_variable                                         ; f05e: f0 25       .%
; &f060 referenced 3 times by &f055, &f059, &f073
.cf060
    ldy l005e                                                         ; f060: a4 5e       .^
; &f062 referenced 1 time by &f06b
.loop_cf062
    inx                                                               ; f062: e8          .
    iny                                                               ; f063: c8          .
    lda basic_command_table,x                                         ; f064: bd 00 f0    ...
    bmi cf075                                                         ; f067: 30 0c       0.
    cmp (parsing_ptr_low),y                                           ; f069: d1 05       ..
    beq loop_cf062                                                    ; f06b: f0 f5       ..
; &f06d referenced 1 time by &f071
.loop_cf06d
    inx                                                               ; f06d: e8          .
    lda lefff,x                                                       ; f06e: bd ff ef    ...
    bpl loop_cf06d                                                    ; f071: 10 fa       ..
    bne cf060                                                         ; f073: d0 eb       ..
; &f075 referenced 1 time by &f067
.cf075
    sta l0053                                                         ; f075: 85 53       .S
    lda lf001,x                                                       ; f077: bd 01 f0    ...
    sta l0052                                                         ; f07a: 85 52       .R
    sty parsing_ptr_offset                                            ; f07c: 84 03       ..
    ldx workspace_stack_pointer                                       ; f07e: a6 04       ..
    inc l005e                                                         ; f080: e6 5e       .^
.cf082
lf084 = cf082+2
    jmp (l0052)                                                       ; f082: 6c 52 00    lR.

; overlapping: brk                                                    ; f084: 00          .
; &f084 referenced 1 time by &f0ab
; &f085 referenced 1 time by &f05e
.assign_array_variable
    jsr sub_cf08b                                                     ; f085: 20 8b f0     ..
    jmp lc3f1                                                         ; f088: 4c f1 c3    L..

; &f08b referenced 2 times by &f03f, &f085
.sub_cf08b
    iny                                                               ; f08b: c8          .
    sty parsing_ptr_offset                                            ; f08c: 84 03       ..
; &f08e referenced 1 time by &f343
.sub_cf08e
    sbc #&40 ; '@'                                                    ; f08e: e9 40       .@
    pha                                                               ; f090: 48          H
    jsr lc8bc                                                         ; f091: 20 bc c8     ..
    pla                                                               ; f094: 68          h
    tay                                                               ; f095: a8          .
    lda int_workspace_stack_low-1,x                                   ; f096: b5 15       ..
    asl a                                                             ; f098: 0a          .
    rol int_workspace_stack_mid1-1,x                                  ; f099: 36 24       6$
    asl a                                                             ; f09b: 0a          .
    rol int_workspace_stack_mid1-1,x                                  ; f09c: 36 24       6$
    clc                                                               ; f09e: 18          .
    adc l02eb,y                                                       ; f09f: 79 eb 02    y..
    sta int_workspace_stack_low-1,x                                   ; f0a2: 95 15       ..
    lda int_workspace_stack_mid1-1,x                                  ; f0a4: b5 24       .$
    adc l0306,y                                                       ; f0a6: 79 06 03    y..
    sta int_workspace_stack_mid1-1,x                                  ; f0a9: 95 24       .$
    bcs lf084                                                         ; f0ab: b0 d7       ..
    rts                                                               ; f0ad: 60          `

; &f0ae referenced 1 time by &f13b
.command_dim
    lda basic_line_number                                             ; f0ae: a5 01       ..
    ora basic_line_number+1                                           ; f0b0: 05 02       ..
    beq cf0d6                                                         ; f0b2: f0 22       ."
    jsr lc434                                                         ; f0b4: 20 34 c4     4.
    bcc cf0d7                                                         ; f0b7: 90 1e       ..
    jsr lc8bc                                                         ; f0b9: 20 bc c8     ..
    dex                                                               ; f0bc: ca          .
    dex                                                               ; f0bd: ca          .
    stx workspace_stack_pointer                                       ; f0be: 86 04       ..
    ldy int_workspace_stack_low,x                                     ; f0c0: b4 16       ..
    sec                                                               ; f0c2: 38          8
    lda int_workspace_stack_mid1-2                                    ; f0c3: a5 23       .#
    sta l0321,y                                                       ; f0c5: 99 21 03    .!.
    adc int_workspace_stack_low+1,x                                   ; f0c8: 75 17       u. ; +1 because carry is set
    sta int_workspace_stack_mid1-2                                    ; f0ca: 85 23       .#
    lda int_workspace_stack_mid1-1                                    ; f0cc: a5 24       .$
    sta l033c,y                                                       ; f0ce: 99 3c 03    .<.
    adc int_workspace_stack_mid1+1,x                                  ; f0d1: 75 26       u&
    jmp cf119                                                         ; f0d3: 4c 19 f1    L..

; &f0d6 referenced 6 times by &f0b2, &f0dd, &f0e1, &f0e6, &f117, &f12f
.cf0d6
    brk                                                               ; f0d6: 00          .

; &f0d7 referenced 1 time by &f0b7
.cf0d7
    ldy parsing_ptr_offset                                            ; f0d7: a4 03       ..
    lda (parsing_ptr_low),y                                           ; f0d9: b1 05       ..
    cmp #&40 ; '@'                                                    ; f0db: c9 40       .@
    bcc cf0d6                                                         ; f0dd: 90 f7       ..
    cmp #&5b ; '['                                                    ; f0df: c9 5b       .[
    bcs cf0d6                                                         ; f0e1: b0 f3       ..
    iny                                                               ; f0e3: c8          .
    cmp (parsing_ptr_low),y                                           ; f0e4: d1 05       ..
    bne cf0d6                                                         ; f0e6: d0 ee       ..
    sbc #&40 ; '@'                                                    ; f0e8: e9 40       .@
    pha                                                               ; f0ea: 48          H
    iny                                                               ; f0eb: c8          .
    sty parsing_ptr_offset                                            ; f0ec: 84 03       ..
    jsr lc8bc                                                         ; f0ee: 20 bc c8     ..
    pla                                                               ; f0f1: 68          h
    tay                                                               ; f0f2: a8          .
    lda int_workspace_stack_mid1-2                                    ; f0f3: a5 23       .#
    sta l02eb,y                                                       ; f0f5: 99 eb 02    ...
    lda int_workspace_stack_mid1-1                                    ; f0f8: a5 24       .$
    sta l0306,y                                                       ; f0fa: 99 06 03    ...
    dex                                                               ; f0fd: ca          .
    stx workspace_stack_pointer                                       ; f0fe: 86 04       ..
    ldy int_workspace_stack_low,x                                     ; f100: b4 16       ..
    iny                                                               ; f102: c8          .
    bne cf107                                                         ; f103: d0 02       ..
    inc int_workspace_stack_mid1,x                                    ; f105: f6 25       .%
; &f107 referenced 1 time by &f103
.cf107
    tya                                                               ; f107: 98          .
    asl a                                                             ; f108: 0a          .
    rol int_workspace_stack_mid1,x                                    ; f109: 36 25       6%
    asl a                                                             ; f10b: 0a          .
    rol int_workspace_stack_mid1,x                                    ; f10c: 36 25       6%
    clc                                                               ; f10e: 18          .
    adc int_workspace_stack_mid1-2                                    ; f10f: 65 23       e#
    sta int_workspace_stack_mid1-2                                    ; f111: 85 23       .#
    lda int_workspace_stack_mid1,x                                    ; f113: b5 25       .%
    adc int_workspace_stack_mid1-1                                    ; f115: 65 24       e$
    bcs cf0d6                                                         ; f117: b0 bd       ..
; &f119 referenced 1 time by &f0d3
.cf119
    sta int_workspace_stack_mid1-1                                    ; f119: 85 24       .$
.cf11b
lf11c = cf11b+1
    ldy #0                                                            ; f11b: a0 00       ..
; overlapping: brk                                                    ; f11c: 00          .
; &f11c referenced 2 times by &f123, &f12a
    lda #&aa                                                          ; f11d: a9 aa       ..
    sta (int_workspace_stack_mid1-2),y                                ; f11f: 91 23       .#
    cmp (int_workspace_stack_mid1-2),y                                ; f121: d1 23       .#
    bne lf11c                                                         ; f123: d0 f7       ..
    lsr a                                                             ; f125: 4a          J
    sta (int_workspace_stack_mid1-2),y                                ; f126: 91 23       .#
    cmp (int_workspace_stack_mid1-2),y                                ; f128: d1 23       .#
    bne lf11c                                                         ; f12a: d0 f0       ..
    jsr lc434                                                         ; f12c: 20 34 c4     4.
    bcs cf0d6                                                         ; f12f: b0 a5       ..
    ldy parsing_ptr_offset                                            ; f131: a4 03       ..
    lda (parsing_ptr_low),y                                           ; f133: b1 05       ..
    cmp #&2c ; ','                                                    ; f135: c9 2c       .,
    bne cf13e                                                         ; f137: d0 05       ..
    inc parsing_ptr_offset                                            ; f139: e6 03       ..
    jmp command_dim                                                   ; f13b: 4c ae f0    L..

; &f13e referenced 1 time by &f137
.cf13e
    jmp lc558                                                         ; f13e: 4c 58 c5    LX.

.command_run
    lda l000d                                                         ; f141: a5 0d       ..
    sta int_workspace_stack_mid1-2                                    ; f143: 85 23       .#
    lda l000e                                                         ; f145: a5 0e       ..
    sta int_workspace_stack_mid1-1                                    ; f147: 85 24       .$
    jmp lce83                                                         ; f149: 4c 83 ce    L..

.command_wait
    jsr lc4e4                                                         ; f14c: 20 e4 c4     ..
    jsr wait_for_flyback                                              ; f14f: 20 66 fe     f. ; Wait for the start of the next field flyback
.cf152
lf154 = cf152+2
    jmp lc55b                                                         ; f152: 4c 5b c5    L[.

; &f154 referenced 1 time by &f3c6
.assembler_mnemonics_high
lf194 = assembler_mnemonics_high+63
    equb &1c, &8a, &1c, &23, &5d, &8b, &1b, &a1, &9d, &8a, &1d, &23   ; f155: 1c 8a 1c... ...
    equb &9d, &8b, &1d, &a1,   0, &29, &19, &ae, &69, &a8, &19, &23   ; f161: 9d 8b 1d... ...
    equb &24, &53, &1b, &23, &24, &53, &19, &a1,   0, &1a, &5b, &5b   ; f16d: 24 53 1b... $S.
    equb &a5, &69, &24, &24, &ae, &ae, &a8, &ad, &29,   0, &7c,   0   ; f179: a5 69 24... .i$
    equb &15, &9c, &6d, &9c, &a5, &69, &29, &53, &84, &13, &34, &11   ; f185: 15 9c 6d... ..m
    equb &a5, &69, &23, &a0                                           ; f191: a5 69 23... .i#
; &f194 referenced 1 time by &f3cf
.assembler_mnemonics_low
    equb &d8, &62, &5a, &48, &26, &62, &94, &88, &54, &44, &c8, &54   ; f195: d8 62 5a... .bZ
    equb &68, &44, &e8, &94,   0, &b4,   8, &84, &74, &b4, &28, &6e   ; f1a1: 68 44 e8... hD.
    equb &74, &f4, &cc, &4a, &72, &f2, &a4, &8a,   0, &aa, &a2, &a2   ; f1ad: 74 f4 cc... t..
    equb &74, &74, &74, &72, &44, &68, &b2, &32, &b2,   0, &22,   0   ; f1b9: 74 74 74... ttt
    equb &1a, &1a, &26, &26, &72, &72, &88, &c8, &c4, &ca, &26, &48   ; f1c5: 1a 1a 26... ..&
    equb &44, &44, &a2, &c8                                           ; f1d1: 44 44 a2... DD.
; &f1d5 referenced 1 time by &f49e
.assembler_mode_masks_low
    equb 0, 2, 0, 8, &f2, &ff, &80, 1, &c0, &e2, &c0, &c0, &ff, 0, 0  ; f1d5: 00 02 00... ...
; &f1e4 referenced 1 time by &f4a7
.assembler_mode_masks_high
    equb   8, 0, &10, &80, &40, &c0, 0, &c0, 0, &40, 0, 0, &e4, &20   ; f1e4: 08 00 10... ...
    equb &80                                                          ; f1f2: 80          .
; &f1f3 referenced 1 time by &f4af
.assembler_mode_offsets
    equb   0, &fc, 0, 8, 8, &f8, &fc, &f4, &0c, &10, 4, &f4, 0, &20   ; f1f3: 00 fc 00... ...
    equb &10                                                          ; f201: 10          .
; &f202 referenced 1 time by &f4b6
.assembler_mode_offsets_2
lf210 = assembler_mode_offsets_2+14
    equb 0, 0, &0f, 1, 1, 1, &11, &11, 2, 2, &11, &11, 2, &12, 2      ; f202: 00 00 0f... ...
; &f210 referenced 1 time by &f3d6
.assembler_mode_base_opcodes
lf250 = assembler_mode_base_opcodes+63
    equb   0,   8, &10, &18, &20, &28, &30, &38, &40, &48, &50, &58   ; f211: 00 08 10... ...
    equb &60, &68, &70, &78, &80, &88, &90, &98, &a0, &a8, &b0, &b8   ; f21d: 60 68 70... `hp
    equb &c0, &c8, &d0, &d8, &e0, &e8, &f0, &f8, &0c, &2c, &4c, &4c   ; f229: c0 c8 d0... ...
    equb &8c, &ac, &cc, &ec, &8a, &9a, &aa, &ba, &ca, &da, &ea, &fa   ; f235: 8c ac cc... ...
    equb &0e, &2e, &4e, &6e, &8e, &ae, &ce, &ee, &0d, &2d, &4d, &6d   ; f241: 0e 2e 4e... ..N
    equb &8d, &ad, &cd, &ed                                           ; f24d: 8d ad cd... ...
; &f250 referenced 1 time by &f3db
.assembler_base_opcodes
    equb &0d, &0d, &0c, &0d, &0e, &0d, &0c, &0d, &0d, &0d, &0c, &0d   ; f251: 0d 0d 0c... ...
    equb &0d, &0d, &0c, &0d, &0f, &0d, &0c, &0d,   9, &0d, &0c, &0d   ; f25d: 0d 0d 0c... ...
    equb   8, &0d, &0c, &0d,   8, &0d, &0c, &0d, &0f,   6, &0b, &0b   ; f269: 08 0d 0c... ...
    equb   4, &0a,   8,   8, &0d, &0d, &0d, &0d, &0d, &0f, &0d, &0f   ; f275: 04 0a 08... ...
    equb   7,   7,   7,   7,   5,   9,   3,   3,   1,   1,   1,   1   ; f281: 07 07 07... ...
    equb   2,   1,   1,   1                                           ; f28d: 02 01 01... ...

; &f291 referenced 13 times by &f299, &f32e, &f333, &f360, &f396, &f3f2, &f408, &f40f, &f465, &f470, &f477, &f48c, &f493
.cf291
    ldy parsing_ptr_offset                                            ; f291: a4 03       ..
    lda (parsing_ptr_low),y                                           ; f293: b1 05       ..
    inc parsing_ptr_offset                                            ; f295: e6 03       ..
    cmp #&20 ; ' '                                                    ; f297: c9 20       .
    beq cf291                                                         ; f299: f0 f6       ..
    rts                                                               ; f29b: 60          `

; &f29c referenced 1 time by &f2a5
.loop_cf29c
    inc parsing_ptr_offset                                            ; f29c: e6 03       ..
    jmp lc31b                                                         ; f29e: 4c 1b c3    L..

; &f2a1 referenced 1 time by &f32b
.command_assembler
    lda (parsing_ptr_low),y                                           ; f2a1: b1 05       ..
    cmp #&5d ; ']'                                                    ; f2a3: c9 5d       .]
    beq loop_cf29c                                                    ; f2a5: f0 f5       ..
    jsr lc4f6                                                         ; f2a7: 20 f6 c4     ..
    dec parsing_ptr_offset                                            ; f2aa: c6 03       ..
    jsr sub_cf38e                                                     ; f2ac: 20 8e f3     ..
    dec parsing_ptr_offset                                            ; f2af: c6 03       ..
    lda l0052                                                         ; f2b1: a5 52       .R
    pha                                                               ; f2b3: 48          H
    lda l0053                                                         ; f2b4: a5 53       .S
    pha                                                               ; f2b6: 48          H
    lda l0321                                                         ; f2b7: ad 21 03    .!.
    pha                                                               ; f2ba: 48          H
    lda #0                                                            ; f2bb: a9 00       ..
    sta int_workspace_stack_mid2                                      ; f2bd: 85 34       .4
    sta int_workspace_stack_high                                      ; f2bf: 85 43       .C
    lda #5                                                            ; f2c1: a9 05       ..
    sta l0321                                                         ; f2c3: 8d 21 03    .!.
    lda basic_line_number                                             ; f2c6: a5 01       ..
    sta int_workspace_stack_low                                       ; f2c8: 85 16       ..
    lda basic_line_number+1                                           ; f2ca: a5 02       ..
    sta int_workspace_stack_mid1                                      ; f2cc: 85 25       .%
    jsr lc589                                                         ; f2ce: 20 89 c5     ..
    jsr sub_cf379                                                     ; f2d1: 20 79 f3     y.
    pla                                                               ; f2d4: 68          h
    sta l0321                                                         ; f2d5: 8d 21 03    .!.
    pla                                                               ; f2d8: 68          h
    jsr sub_cf37e                                                     ; f2d9: 20 7e f3     ~.
    pla                                                               ; f2dc: 68          h
    jsr sub_cf376                                                     ; f2dd: 20 76 f3     v.
    ldy #0                                                            ; f2e0: a0 00       ..
; &f2e2 referenced 1 time by &f2ed
.loop_cf2e2
    cpy basic_error_number                                            ; f2e2: c4 00       ..
    beq cf2ef                                                         ; f2e4: f0 09       ..
    lda l0066,y                                                       ; f2e6: b9 66 00    .f.
    jsr sub_cf376                                                     ; f2e9: 20 76 f3     v.
    iny                                                               ; f2ec: c8          .
    bne loop_cf2e2                                                    ; f2ed: d0 f3       ..
; &f2ef referenced 2 times by &f2e4, &f2fd
.cf2ef
    cpy #3                                                            ; f2ef: c0 03       ..
    beq cf2ff                                                         ; f2f1: f0 0c       ..
    jsr sub_cf379                                                     ; f2f3: 20 79 f3     y.
    jsr lca4c                                                         ; f2f6: 20 4c ca     L.
    jsr lca4c                                                         ; f2f9: 20 4c ca     L.
    iny                                                               ; f2fc: c8          .
    bne cf2ef                                                         ; f2fd: d0 f0       ..
; &f2ff referenced 1 time by &f2f1
.cf2ff
    ldy #0                                                            ; f2ff: a0 00       ..
; &f301 referenced 1 time by &f30f
.loop_cf301
    lda (parsing_ptr_low),y                                           ; f301: b1 05       ..
    cmp #&3b ; ';'                                                    ; f303: c9 3b       .;
    beq cf311                                                         ; f305: f0 0a       ..
    cmp #&0d                                                          ; f307: c9 0d       ..
    beq cf311                                                         ; f309: f0 06       ..
    jsr lca4c                                                         ; f30b: 20 4c ca     L.
    iny                                                               ; f30e: c8          .
    bne loop_cf301                                                    ; f30f: d0 f0       ..
; &f311 referenced 2 times by &f305, &f309
.cf311
    jsr lcd54                                                         ; f311: 20 54 cd     T.
    jsr lc4e4                                                         ; f314: 20 e4 c4     ..
    dey                                                               ; f317: 88          .
    lda (parsing_ptr_low),y                                           ; f318: b1 05       ..
    iny                                                               ; f31a: c8          .
    cmp #&3b ; ';'                                                    ; f31b: c9 3b       .;
    beq cf32b                                                         ; f31d: f0 0c       ..
    lda parsing_ptr_high                                              ; f31f: a5 06       ..
    cmp #1                                                            ; f321: c9 01       ..
    bne cf328                                                         ; f323: d0 03       ..
    jmp lc2cf                                                         ; f325: 4c cf c2    L..

; &f328 referenced 1 time by &f323
.cf328
    jsr lc51d                                                         ; f328: 20 1d c5     ..
; &f32b referenced 1 time by &f31d
.cf32b
    jmp command_assembler                                             ; f32b: 4c a1 f2    L..

; &f32e referenced 1 time by &f39b
.cf32e
    jsr cf291                                                         ; f32e: 20 91 f2     ..
    sta l0066                                                         ; f331: 85 66       .f
    jsr cf291                                                         ; f333: 20 91 f2     ..
    cmp l0066                                                         ; f336: c5 66       .f
    bne cf34a                                                         ; f338: d0 10       ..
    cmp #&40 ; '@'                                                    ; f33a: c9 40       .@
    bcc cf34a                                                         ; f33c: 90 0c       ..
    cmp #&5b ; '['                                                    ; f33e: c9 5b       .[
    bcs cf34a                                                         ; f340: b0 08       ..
    sec                                                               ; f342: 38          8
    jsr sub_cf08e                                                     ; f343: 20 8e f0     ..
    jsr lc3cb                                                         ; f346: 20 cb c3     ..
; overlapping: ldy #0                                                 ; f349: a0 00       ..
    equb &a0                                                          ; f349: a0          .

; &f34a referenced 3 times by &f338, &f33c, &f340
.cf34a
    brk                                                               ; f34a: 00          .

    lda l0331                                                         ; f34b: ad 31 03    .1.
    sta (l0052),y                                                     ; f34e: 91 52       .R
    lda l034c                                                         ; f350: ad 4c 03    .L.
    iny                                                               ; f353: c8          .
    sta (l0052),y                                                     ; f354: 91 52       .R
    lda #0                                                            ; f356: a9 00       ..
    iny                                                               ; f358: c8          .
    sta (l0052),y                                                     ; f359: 91 52       .R
    iny                                                               ; f35b: c8          .
    sta (l0052),y                                                     ; f35c: 91 52       .R
    bne cf396                                                         ; f35e: d0 36       .6
; &f360 referenced 3 times by &f369, &f3a7, &f49b
.cf360
    jsr cf291                                                         ; f360: 20 91 f2     ..
    cmp #&3b ; ';'                                                    ; f363: c9 3b       .;
    beq cf36b                                                         ; f365: f0 04       ..
    cmp #&0d                                                          ; f367: c9 0d       ..
    bne cf360                                                         ; f369: d0 f5       ..
; &f36b referenced 3 times by &f365, &f39f, &f3a3
.cf36b
    lda l0331                                                         ; f36b: ad 31 03    .1.
    sta l0052                                                         ; f36e: 85 52       .R
    lda l034c                                                         ; f370: ad 4c 03    .L.
    sta l0053                                                         ; f373: 85 53       .S
    rts                                                               ; f375: 60          `

; &f376 referenced 2 times by &f2dd, &f2e9
.sub_cf376
    jsr sub_cf37e                                                     ; f376: 20 7e f3     ~.
; &f379 referenced 2 times by &f2d1, &f2f3
.sub_cf379
    lda #&20 ; ' '                                                    ; f379: a9 20       .
    jmp lca4c                                                         ; f37b: 4c 4c ca    LL.

; &f37e referenced 2 times by &f2d9, &f376
.sub_cf37e
    ldx #&ff                                                          ; f37e: a2 ff       ..
    pha                                                               ; f380: 48          H
    lsr a                                                             ; f381: 4a          J
    lsr a                                                             ; f382: 4a          J
    lsr a                                                             ; f383: 4a          J
    lsr a                                                             ; f384: 4a          J
    jsr lc5f9                                                         ; f385: 20 f9 c5     ..
    pla                                                               ; f388: 68          h
    and #&0f                                                          ; f389: 29 0f       ).
    jmp lc5f9                                                         ; f38b: 4c f9 c5    L..

; &f38e referenced 1 time by &f2ac
.sub_cf38e
    ldx #0                                                            ; f38e: a2 00       ..
    stx basic_error_number                                            ; f390: 86 00       ..
    stx l0064                                                         ; f392: 86 64       .d
    stx l0065                                                         ; f394: 86 65       .e
; &f396 referenced 2 times by &f35e, &f3bc
.cf396
    jsr cf291                                                         ; f396: 20 91 f2     ..
    cmp #&3a ; ':'                                                    ; f399: c9 3a       .:
    beq cf32e                                                         ; f39b: f0 91       ..
    cmp #&3b ; ';'                                                    ; f39d: c9 3b       .;
    beq cf36b                                                         ; f39f: f0 ca       ..
    cmp #&0d                                                          ; f3a1: c9 0d       ..
    beq cf36b                                                         ; f3a3: f0 c6       ..
    cmp #&5c ; '\'                                                    ; f3a5: c9 5c       .\
    beq cf360                                                         ; f3a7: f0 b7       ..
    ldy #5                                                            ; f3a9: a0 05       ..
    sec                                                               ; f3ab: 38          8
    adc #0                                                            ; f3ac: 69 00       i. ; Carry is set, so adding 1
    asl a                                                             ; f3ae: 0a          .
    asl a                                                             ; f3af: 0a          .
    asl a                                                             ; f3b0: 0a          .
; &f3b1 referenced 1 time by &f3b7
.loop_cf3b1
    asl a                                                             ; f3b1: 0a          .
    rol l006a                                                         ; f3b2: 26 6a       &j
    rol l0069                                                         ; f3b4: 26 69       &i
    dey                                                               ; f3b6: 88          .
    bne loop_cf3b1                                                    ; f3b7: d0 f8       ..
    inx                                                               ; f3b9: e8          .
    cpx #3                                                            ; f3ba: e0 03       ..
    bne cf396                                                         ; f3bc: d0 d8       ..
    asl l006a                                                         ; f3be: 06 6a       .j
    rol l0069                                                         ; f3c0: 26 69       &i
    ldx #&40 ; '@'                                                    ; f3c2: a2 40       .@
    lda l0069                                                         ; f3c4: a5 69       .i
; &f3c6 referenced 1 time by &f3cc
.loop_cf3c6
    cmp lf154,x                                                       ; f3c6: dd 54 f1    .T.
    beq cf3cf                                                         ; f3c9: f0 04       ..
; &f3cb referenced 1 time by &f3d4
.loop_cf3cb
    dex                                                               ; f3cb: ca          .
    bne loop_cf3c6                                                    ; f3cc: d0 f8       ..
    brk                                                               ; f3ce: 00          .

; &f3cf referenced 1 time by &f3c9
.cf3cf
    ldy lf194,x                                                       ; f3cf: bc 94 f1    ...
    cpy l006a                                                         ; f3d2: c4 6a       .j
    bne loop_cf3cb                                                    ; f3d4: d0 f5       ..
    lda lf210,x                                                       ; f3d6: bd 10 f2    ...
    sta l0066                                                         ; f3d9: 85 66       .f
    ldy lf250,x                                                       ; f3db: bc 50 f2    .P.
    sty l000f                                                         ; f3de: 84 0f       ..
; &f3e0 referenced 1 time by &f3e5
.loop_cf3e0
    ror l0064                                                         ; f3e0: 66 64       fd
    ror l0065                                                         ; f3e2: 66 65       fe
    dey                                                               ; f3e4: 88          .
    bne loop_cf3e0                                                    ; f3e5: d0 f9       ..
    ldy l000f                                                         ; f3e7: a4 0f       ..
    cpy #&0d                                                          ; f3e9: c0 0d       ..
    bne cf3f2                                                         ; f3eb: d0 05       ..
    ldx #0                                                            ; f3ed: a2 00       ..
; &f3ef referenced 1 time by &f401
.loop_cf3ef
    jmp cf49b                                                         ; f3ef: 4c 9b f4    L..

; &f3f2 referenced 1 time by &f3eb
.cf3f2
    jsr cf291                                                         ; f3f2: 20 91 f2     ..
    cmp #&40 ; '@'                                                    ; f3f5: c9 40       .@
    beq cf454                                                         ; f3f7: f0 5b       .[
    cmp #&28 ; '('                                                    ; f3f9: c9 28       .(
    beq cf462                                                         ; f3fb: f0 65       .e
    ldx #1                                                            ; f3fd: a2 01       ..
    cmp #&41 ; 'A'                                                    ; f3ff: c9 41       .A
    beq loop_cf3ef                                                    ; f401: f0 ec       ..
    dec parsing_ptr_offset                                            ; f403: c6 03       ..
    jsr lc78b                                                         ; f405: 20 8b c7     ..
    jsr cf291                                                         ; f408: 20 91 f2     ..
    cmp #&2c ; ','                                                    ; f40b: c9 2c       .,
    bne cf440                                                         ; f40d: d0 31       .1
    jsr cf291                                                         ; f40f: 20 91 f2     ..
    ldy int_workspace_stack_mid1                                      ; f412: a4 25       .%
    beq cf42b                                                         ; f414: f0 15       ..
    ldx #9                                                            ; f416: a2 09       ..
    cmp #&58 ; 'X'                                                    ; f418: c9 58       .X
    beq cf49b                                                         ; f41a: f0 7f       ..
    dex                                                               ; f41c: ca          .  ; X=8
    cmp #&59 ; 'Y'                                                    ; f41d: c9 59       .Y
    bne cf49a                                                         ; f41f: d0 79       .y
    lda l000f                                                         ; f421: a5 0f       ..
    cmp #9                                                            ; f423: c9 09       ..
    bne cf49b                                                         ; f425: d0 74       .t
    ldx #&0e                                                          ; f427: a2 0e       ..
    bne cf49b                                                         ; f429: d0 70       .p ; ALWAYS branch

; &f42b referenced 1 time by &f414
.cf42b
    ldx #4                                                            ; f42b: a2 04       ..
    cmp #&58 ; 'X'                                                    ; f42d: c9 58       .X
    beq cf49b                                                         ; f42f: f0 6a       .j
    cmp #&59 ; 'Y'                                                    ; f431: c9 59       .Y
    bne cf49a                                                         ; f433: d0 65       .e
    dex                                                               ; f435: ca          .  ; X=3
    ldy l000f                                                         ; f436: a4 0f       ..
    cpy #3                                                            ; f438: c0 03       ..
    bcs cf49b                                                         ; f43a: b0 5f       ._
    ldx #8                                                            ; f43c: a2 08       ..
    bne cf49b                                                         ; f43e: d0 5b       .[ ; ALWAYS branch

; &f440 referenced 1 time by &f40d
.cf440
    dec parsing_ptr_offset                                            ; f440: c6 03       ..
    ldx #2                                                            ; f442: a2 02       ..
    ldy l000f                                                         ; f444: a4 0f       ..
    cpy #&0c                                                          ; f446: c0 0c       ..
    beq cf49b                                                         ; f448: f0 51       .Q
    ldx #5                                                            ; f44a: a2 05       ..
    lda int_workspace_stack_mid1                                      ; f44c: a5 25       .%
    beq cf49b                                                         ; f44e: f0 4b       .K
    ldx #&0c                                                          ; f450: a2 0c       ..
    bne cf49b                                                         ; f452: d0 47       .G ; ALWAYS branch

; &f454 referenced 1 time by &f3f7
.cf454
    jsr lc78b                                                         ; f454: 20 8b c7     ..
    lda l000f                                                         ; f457: a5 0f       ..
    ldx #6                                                            ; f459: a2 06       ..
    cmp #1                                                            ; f45b: c9 01       ..
    beq cf49b                                                         ; f45d: f0 3c       .<
    inx                                                               ; f45f: e8          .  ; X=7
    bne cf49b                                                         ; f460: d0 39       .9 ; ALWAYS branch

; &f462 referenced 1 time by &f3fb
.cf462
    jsr lc78b                                                         ; f462: 20 8b c7     ..
    jsr cf291                                                         ; f465: 20 91 f2     ..
    cmp #&29 ; ')'                                                    ; f468: c9 29       .)
    beq cf482                                                         ; f46a: f0 16       ..
    cmp #&2c ; ','                                                    ; f46c: c9 2c       .,
    bne cf49a                                                         ; f46e: d0 2a       .*
    jsr cf291                                                         ; f470: 20 91 f2     ..
    cmp #&58 ; 'X'                                                    ; f473: c9 58       .X
    bne cf49a                                                         ; f475: d0 23       .#
    jsr cf291                                                         ; f477: 20 91 f2     ..
    cmp #&29 ; ')'                                                    ; f47a: c9 29       .)
    bne cf49a                                                         ; f47c: d0 1c       ..
    ldx #&0b                                                          ; f47e: a2 0b       ..
    bne cf49b                                                         ; f480: d0 19       .. ; ALWAYS branch

; &f482 referenced 1 time by &f46a
.cf482
    ldx #&0d                                                          ; f482: a2 0d       ..
    lda l000f                                                         ; f484: a5 0f       ..
    cmp #&0b                                                          ; f486: c9 0b       ..
    beq cf49b                                                         ; f488: f0 11       ..
    ldx #&0a                                                          ; f48a: a2 0a       ..
    jsr cf291                                                         ; f48c: 20 91 f2     ..
    cmp #&2c ; ','                                                    ; f48f: c9 2c       .,
    bne cf49a                                                         ; f491: d0 07       ..
    jsr cf291                                                         ; f493: 20 91 f2     ..
    cmp #&59 ; 'Y'                                                    ; f496: c9 59       .Y
    beq cf49b                                                         ; f498: f0 01       ..
; &f49a referenced 8 times by &f41f, &f433, &f46e, &f475, &f47c, &f491, &f4ac, &f4d5
.cf49a
    brk                                                               ; f49a: 00          .

; &f49b referenced 15 times by &f3ef, &f41a, &f425, &f429, &f42f, &f43a, &f43e, &f448, &f44e, &f452, &f45d, &f460, &f480, &f488, &f498
.cf49b
    jsr cf360                                                         ; f49b: 20 60 f3     `.
    lda assembler_mode_masks_low,x                                    ; f49e: bd d5 f1    ...
    beq cf4a7                                                         ; f4a1: f0 04       ..
    and l0064                                                         ; f4a3: 25 64       %d
    bne cf4ae                                                         ; f4a5: d0 07       ..
; &f4a7 referenced 1 time by &f4a1
.cf4a7
    lda assembler_mode_masks_high,x                                   ; f4a7: bd e4 f1    ...
    and l0065                                                         ; f4aa: 25 65       %e
    beq cf49a                                                         ; f4ac: f0 ec       ..
; &f4ae referenced 1 time by &f4a5
.cf4ae
    clc                                                               ; f4ae: 18          .
    lda assembler_mode_offsets,x                                      ; f4af: bd f3 f1    ...
    adc l0066                                                         ; f4b2: 65 66       ef
    sta l0066                                                         ; f4b4: 85 66       .f
    lda assembler_mode_offsets_2,x                                    ; f4b6: bd 02 f2    ...
    ldx #0                                                            ; f4b9: a2 00       ..
    stx workspace_stack_pointer                                       ; f4bb: 86 04       ..
    ldy int_workspace_stack_low                                       ; f4bd: a4 16       ..
    sty l0067                                                         ; f4bf: 84 67       .g
    ldy int_workspace_stack_mid1                                      ; f4c1: a4 25       .%
    sty l0068                                                         ; f4c3: 84 68       .h
    cmp #&0f                                                          ; f4c5: c9 0f       ..
    beq cf4ec                                                         ; f4c7: f0 23       .#
    and #&0f                                                          ; f4c9: 29 0f       ).
    tay                                                               ; f4cb: a8          .
    iny                                                               ; f4cc: c8          .
    sty basic_error_number                                            ; f4cd: 84 00       ..
    cpy #2                                                            ; f4cf: c0 02       ..
    bne cf4d7                                                         ; f4d1: d0 04       ..
    ldy l0068                                                         ; f4d3: a4 68       .h
    bne cf49a                                                         ; f4d5: d0 c3       ..
; &f4d7 referenced 4 times by &f4d1, &f525, &f528, &f52d
.cf4d7
    ldy #0                                                            ; f4d7: a0 00       ..
; &f4d9 referenced 1 time by &f4e9
.loop_cf4d9
    lda l0066,y                                                       ; f4d9: b9 66 00    .f.
    sta (l0052),y                                                     ; f4dc: 91 52       .R
    iny                                                               ; f4de: c8          .
    inc l0331                                                         ; f4df: ee 31 03    .1.
    bne cf4e7                                                         ; f4e2: d0 03       ..
    inc l034c                                                         ; f4e4: ee 4c 03    .L.
; &f4e7 referenced 1 time by &f4e2
.cf4e7
    cpy basic_error_number                                            ; f4e7: c4 00       ..
    bne loop_cf4d9                                                    ; f4e9: d0 ee       ..
    rts                                                               ; f4eb: 60          `

; &f4ec referenced 1 time by &f4c7
.cf4ec
    lda #2                                                            ; f4ec: a9 02       ..
    sta basic_error_number                                            ; f4ee: 85 00       ..
    sec                                                               ; f4f0: 38          8
    lda l0067                                                         ; f4f1: a5 67       .g
    sbc l0331                                                         ; f4f3: ed 31 03    .1.
    sta l0067                                                         ; f4f6: 85 67       .g
    lda l0068                                                         ; f4f8: a5 68       .h
    sbc l034c                                                         ; f4fa: ed 4c 03    .L.
    sta l0068                                                         ; f4fd: 85 68       .h
    sec                                                               ; f4ff: 38          8
    lda l0067                                                         ; f500: a5 67       .g
    sbc #2                                                            ; f502: e9 02       ..
    sta l0067                                                         ; f504: 85 67       .g
    tay                                                               ; f506: a8          .
    lda l0068                                                         ; f507: a5 68       .h
    sbc #0                                                            ; f509: e9 00       ..
    beq cf52c                                                         ; f50b: f0 1f       ..
    cmp #&ff                                                          ; f50d: c9 ff       ..
    beq cf527                                                         ; f50f: f0 16       ..
; &f511 referenced 2 times by &f52a, &f52f
.cf511
    jsr print_inline_string                                           ; f511: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "OUT OF RANGE:", &0a, &0d                                    ; f514: 4f 55 54... OUT

    sty l0067                                                         ; f523: 84 67       .g
    bmi cf4d7                                                         ; f525: 30 b0       0.
; &f527 referenced 1 time by &f50f
.cf527
    tya                                                               ; f527: 98          .
    bmi cf4d7                                                         ; f528: 30 ad       0.
    bpl cf511                                                         ; f52a: 10 e5       .. ; ALWAYS branch

; &f52c referenced 1 time by &f50b
.cf52c
    tya                                                               ; f52c: 98          .
    bpl cf4d7                                                         ; f52d: 10 a8       ..
    bmi cf511                                                         ; f52f: 30 e0       0. ; ALWAYS branch

.command_old
    jsr lc4e4                                                         ; f531: 20 e4 c4     ..
    dey                                                               ; f534: 88          .
    sty l0052                                                         ; f535: 84 52       .R
    lda text_space_page                                               ; f537: a5 12       ..
    sta l0053                                                         ; f539: 85 53       .S
    tya                                                               ; f53b: 98          .
    iny                                                               ; f53c: c8          .
    sta (l0052),y                                                     ; f53d: 91 52       .R
    jmp lcd9b                                                         ; f53f: 4c 9b cd    L..

.command_draw
    ldx #5                                                            ; f542: a2 05       ..
    bne cf548                                                         ; f544: d0 02       .. ; ALWAYS branch

.command_move
    ldx #&0c                                                          ; f546: a2 0c       ..
; &f548 referenced 1 time by &f544
.cf548
    stx int_workspace_stack_low                                       ; f548: 86 16       ..
    inc workspace_stack_pointer                                       ; f54a: e6 04       ..
    bne cf554                                                         ; f54c: d0 06       ..
.command_plot
    jsr lc8bc                                                         ; f54e: 20 bc c8     ..
    jsr lc231                                                         ; f551: 20 31 c2     1.
; &f554 referenced 1 time by &f54c
.cf554
    jsr lc8bc                                                         ; f554: 20 bc c8     ..
    jsr lc231                                                         ; f557: 20 31 c2     1.
    jsr lc8bc                                                         ; f55a: 20 bc c8     ..
    jsr lc4e4                                                         ; f55d: 20 e4 c4     ..
    lda int_workspace_stack_low-1,x                                   ; f560: b5 15       ..
    sta l005c                                                         ; f562: 85 5c       .\
    lda int_workspace_stack_mid1-1,x                                  ; f564: b5 24       .$
    sta l005d                                                         ; f566: 85 5d       .]
    lda int_workspace_stack_low-2,x                                   ; f568: b5 14       ..
    sta l005a                                                         ; f56a: 85 5a       .Z
    lda int_workspace_stack_mid1-2,x                                  ; f56c: b5 23       .#
    sta l005b                                                         ; f56e: 85 5b       .[
    ldx #0                                                            ; f570: a2 00       ..
    stx workspace_stack_pointer                                       ; f572: 86 04       ..
    ldx #3                                                            ; f574: a2 03       ..
; &f576 referenced 1 time by &f57c
.loop_cf576
    lda l03c1,x                                                       ; f576: bd c1 03    ...
    sta l0052,x                                                       ; f579: 95 52       .R
    dex                                                               ; f57b: ca          .
    bpl loop_cf576                                                    ; f57c: 10 f8       ..
    lda int_workspace_stack_low                                       ; f57e: a5 16       ..
    and #4                                                            ; f580: 29 04       ).
    bne cf597                                                         ; f582: d0 13       ..
    ldx #2                                                            ; f584: a2 02       ..
; &f586 referenced 1 time by &f595
.loop_cf586
    clc                                                               ; f586: 18          .
    lda l005a,x                                                       ; f587: b5 5a       .Z
    adc l0052,x                                                       ; f589: 75 52       uR
    sta l005a,x                                                       ; f58b: 95 5a       .Z
    lda l005b,x                                                       ; f58d: b5 5b       .[
    adc l0053,x                                                       ; f58f: 75 53       uS
    sta l005b,x                                                       ; f591: 95 5b       .[
    dex                                                               ; f593: ca          .
    dex                                                               ; f594: ca          .
    bpl loop_cf586                                                    ; f595: 10 ef       ..
; &f597 referenced 1 time by &f582
.cf597
    ldx #3                                                            ; f597: a2 03       ..
; &f599 referenced 1 time by &f59f
.loop_cf599
    lda l005a,x                                                       ; f599: b5 5a       .Z
    sta l03c1,x                                                       ; f59b: 9d c1 03    ...
    dex                                                               ; f59e: ca          .
    bpl loop_cf599                                                    ; f59f: 10 f8       ..
    lda int_workspace_stack_low                                       ; f5a1: a5 16       ..
    and #3                                                            ; f5a3: 29 03       ).
    beq cf5b2                                                         ; f5a5: f0 0b       ..
    sta l005e                                                         ; f5a7: 85 5e       .^
    lda int_workspace_stack_low                                       ; f5a9: a5 16       ..
    and #8                                                            ; f5ab: 29 08       ).
    beq cf5b5                                                         ; f5ad: f0 06       ..
    jsr sub_cf678                                                     ; f5af: 20 78 f6     x.
; &f5b2 referenced 1 time by &f5a5
.cf5b2
    jmp lc55b                                                         ; f5b2: 4c 5b c5    L[.

; &f5b5 referenced 1 time by &f5ad
.cf5b5
    ldx #2                                                            ; f5b5: a2 02       ..
; &f5b7 referenced 1 time by &f5df
.cf5b7
    sec                                                               ; f5b7: 38          8
    lda l005a,x                                                       ; f5b8: b5 5a       .Z
    sbc l0052,x                                                       ; f5ba: f5 52       .R
    ldy l0052,x                                                       ; f5bc: b4 52       .R
    sty l005a,x                                                       ; f5be: 94 5a       .Z
    sta l0052,x                                                       ; f5c0: 95 52       .R
    ldy l0053,x                                                       ; f5c2: b4 53       .S
    lda l005b,x                                                       ; f5c4: b5 5b       .[
    sbc l0053,x                                                       ; f5c6: f5 53       .S
    sty l005b,x                                                       ; f5c8: 94 5b       .[
    sta l0053,x                                                       ; f5ca: 95 53       .S
    sta l0056,x                                                       ; f5cc: 95 56       .V
    bpl cf5dd                                                         ; f5ce: 10 0d       ..
    lda #0                                                            ; f5d0: a9 00       ..
    sec                                                               ; f5d2: 38          8
    sbc l0052,x                                                       ; f5d3: f5 52       .R
    sta l0052,x                                                       ; f5d5: 95 52       .R
    lda #0                                                            ; f5d7: a9 00       ..
    sbc l0053,x                                                       ; f5d9: f5 53       .S
    sta l0053,x                                                       ; f5db: 95 53       .S
; &f5dd referenced 1 time by &f5ce
.cf5dd
    dex                                                               ; f5dd: ca          .
    dex                                                               ; f5de: ca          .
    bpl cf5b7                                                         ; f5df: 10 d6       ..
    lda l0054                                                         ; f5e1: a5 54       .T
    cmp l0052                                                         ; f5e3: c5 52       .R
    lda l0055                                                         ; f5e5: a5 55       .U
    sbc l0053                                                         ; f5e7: e5 53       .S
    bcc cf61c                                                         ; f5e9: 90 31       .1
    lda #0                                                            ; f5eb: a9 00       ..
    sbc l0054                                                         ; f5ed: e5 54       .T
    sta l0057                                                         ; f5ef: 85 57       .W
    lda #0                                                            ; f5f1: a9 00       ..
    sbc l0055                                                         ; f5f3: e5 55       .U
    sec                                                               ; f5f5: 38          8
    ror a                                                             ; f5f6: 6a          j
    sta l0059                                                         ; f5f7: 85 59       .Y
    ror l0057                                                         ; f5f9: 66 57       fW
; &f5fb referenced 2 times by &f614, &f619
.cf5fb
    jsr sub_cf678                                                     ; f5fb: 20 78 f6     x.
    lda l005c                                                         ; f5fe: a5 5c       .\
    cmp l03c3                                                         ; f600: cd c3 03    ...
    bne cf60f                                                         ; f603: d0 0a       ..
    lda l005d                                                         ; f605: a5 5d       .]
    cmp l03c4                                                         ; f607: cd c4 03    ...
    bne cf60f                                                         ; f60a: d0 03       ..
; &f60c referenced 1 time by &f635
.cf60c
    jmp lc55b                                                         ; f60c: 4c 5b c5    L[.

; &f60f referenced 2 times by &f603, &f60a
.cf60f
    jsr sub_cf655                                                     ; f60f: 20 55 f6     U.
    lda l0059                                                         ; f612: a5 59       .Y
    bmi cf5fb                                                         ; f614: 30 e5       0.
    jsr sub_cf644                                                     ; f616: 20 44 f6     D.
    jmp cf5fb                                                         ; f619: 4c fb f5    L..

; &f61c referenced 1 time by &f5e9
.cf61c
    lda l0053                                                         ; f61c: a5 53       .S
    lsr a                                                             ; f61e: 4a          J
    sta l0059                                                         ; f61f: 85 59       .Y
    lda l0052                                                         ; f621: a5 52       .R
    ror a                                                             ; f623: 6a          j
    sta l0057                                                         ; f624: 85 57       .W
; &f626 referenced 2 times by &f63c, &f641
.cf626
    jsr sub_cf678                                                     ; f626: 20 78 f6     x.
    lda l005a                                                         ; f629: a5 5a       .Z
    cmp l03c1                                                         ; f62b: cd c1 03    ...
    bne cf637                                                         ; f62e: d0 07       ..
    lda l005b                                                         ; f630: a5 5b       .[
    cmp l03c2                                                         ; f632: cd c2 03    ...
    beq cf60c                                                         ; f635: f0 d5       ..
; &f637 referenced 1 time by &f62e
.cf637
    jsr sub_cf644                                                     ; f637: 20 44 f6     D.
    lda l0059                                                         ; f63a: a5 59       .Y
    bpl cf626                                                         ; f63c: 10 e8       ..
    jsr sub_cf655                                                     ; f63e: 20 55 f6     U.
    jmp cf626                                                         ; f641: 4c 26 f6    L&.

; &f644 referenced 2 times by &f616, &f637
.sub_cf644
    sec                                                               ; f644: 38          8
    lda l0057                                                         ; f645: a5 57       .W
    sbc l0054                                                         ; f647: e5 54       .T
    sta l0057                                                         ; f649: 85 57       .W
    lda l0059                                                         ; f64b: a5 59       .Y
    sbc l0055                                                         ; f64d: e5 55       .U
    sta l0059                                                         ; f64f: 85 59       .Y
    ldx #0                                                            ; f651: a2 00       ..
    beq cf664                                                         ; f653: f0 0f       .. ; ALWAYS branch

; &f655 referenced 2 times by &f60f, &f63e
.sub_cf655
    clc                                                               ; f655: 18          .
    lda l0057                                                         ; f656: a5 57       .W
    adc l0052                                                         ; f658: 65 52       eR
    sta l0057                                                         ; f65a: 85 57       .W
    lda l0059                                                         ; f65c: a5 59       .Y
    adc l0053                                                         ; f65e: 65 53       eS
    sta l0059                                                         ; f660: 85 59       .Y
    ldx #2                                                            ; f662: a2 02       ..
; &f664 referenced 1 time by &f653
.cf664
    lda l0056,x                                                       ; f664: b5 56       .V
    bpl cf671                                                         ; f666: 10 09       ..
    lda l005a,x                                                       ; f668: b5 5a       .Z
    bne cf66e                                                         ; f66a: d0 02       ..
    dec l005b,x                                                       ; f66c: d6 5b       .[
; &f66e referenced 1 time by &f66a
.cf66e
    dec l005a,x                                                       ; f66e: d6 5a       .Z
; &f670 referenced 1 time by &f673
.return_1
    rts                                                               ; f670: 60          `

; &f671 referenced 1 time by &f666
.cf671
    inc l005a,x                                                       ; f671: f6 5a       .Z
    bne return_1                                                      ; f673: d0 fb       ..
    inc l005b,x                                                       ; f675: f6 5b       .[
    rts                                                               ; f677: 60          `

; &f678 referenced 3 times by &f5af, &f5fb, &f626
.sub_cf678
    jmp (plot_vector)                                                 ; f678: 6c fe 03    l..

.command_clear
    jsr lc3c8                                                         ; f67b: 20 c8 c3     ..
.cf67e
lf67f = cf67e+1
    ldy #0                                                            ; f67e: a0 00       ..
; overlapping: brk                                                    ; f67f: 00          .
; &f67f referenced 1 time by &f69c
    lda l0052                                                         ; f680: a5 52       .R
    beq cf6c2                                                         ; f682: f0 3e       .>
    cmp #5                                                            ; f684: c9 05       ..
    bcc cf68a                                                         ; f686: 90 02       ..
    lda #4                                                            ; f688: a9 04       ..
; &f68a referenced 1 time by &f686
.cf68a
    ldx #&80                                                          ; f68a: a2 80       ..
    stx l0054                                                         ; f68c: 86 54       .T
    sty l0053                                                         ; f68e: 84 53       .S
    sta l0052                                                         ; f690: 85 52       .R
    tax                                                               ; f692: aa          .
    lda lf6ce,x                                                       ; f693: bd ce f6    ...
    ldx text_space_page                                               ; f696: a6 12       ..
    bpl cf69e                                                         ; f698: 10 04       ..
    cmp text_space_page                                               ; f69a: c5 12       ..
    bcs lf67f                                                         ; f69c: b0 e1       ..
; &f69e referenced 1 time by &f698
.cf69e
    tax                                                               ; f69e: aa          .
    tya                                                               ; f69f: 98          .
; &f6a0 referenced 2 times by &f6a3, &f6a9
.cf6a0
    sta (l0053),y                                                     ; f6a0: 91 53       .S
    dey                                                               ; f6a2: 88          .
    bne cf6a0                                                         ; f6a3: d0 fb       ..
    inc l0054                                                         ; f6a5: e6 54       .T
    cpx l0054                                                         ; f6a7: e4 54       .T
    bne cf6a0                                                         ; f6a9: d0 f5       ..
; &f6ab referenced 1 time by &f6cd
.cf6ab
    ldy l0052                                                         ; f6ab: a4 52       .R
    lda plot_routines_high,y                                          ; f6ad: b9 d8 f6    ...
    sta plot_vector+1                                                 ; f6b0: 8d ff 03    ...
    lda plot_routines_low,y                                           ; f6b3: b9 d3 f6    ...
    sta plot_vector                                                   ; f6b6: 8d fe 03    ...
    lda graphics_mode_bytes,y                                         ; f6b9: b9 dd f6    ...
    sta ppi_port_a                                                    ; f6bc: 8d 00 b0    ...
    jmp lc558                                                         ; f6bf: 4c 58 c5    LX.

; &f6c2 referenced 1 time by &f682
.cf6c2
    lda #&40 ; '@'                                                    ; f6c2: a9 40       .@
; &f6c4 referenced 1 time by &f6cb
.loop_cf6c4
    sta l8000,y                                                       ; f6c4: 99 00 80    ...
    sta l8100,y                                                       ; f6c7: 99 00 81    ...
    dey                                                               ; f6ca: 88          .
    bne loop_cf6c4                                                    ; f6cb: d0 f7       ..
.cf6cd
lf6ce = cf6cd+1
    beq cf6ab                                                         ; f6cd: f0 dc       .. ; ALWAYS branch

; &f6ce referenced 1 time by &f693
; overlapping: sty l0086                                              ; f6cf: 84 86       ..
.graphics_mode_end_pages
    equb &84, &86, &8c, &98                                           ; f6cf: 84 86 8c... ...
; overlapping: sty le298                                              ; f6d1: 8c 98 e2    ...
; &f6d3 referenced 1 time by &f6b3
.plot_routines_low
    equb <plot_mode_0                                                 ; f6d3: e2          .
    equb <plot_mode_1                                                 ; f6d4: 3b          ;
    equb <plot_mode_2                                                 ; f6d5: 54          T
    equb <plot_mode_3                                                 ; f6d6: 6d          m
    equb <plot_mode_4                                                 ; f6d7: aa          .
; &f6d8 referenced 1 time by &f6ad
.plot_routines_high
    equb >plot_mode_0                                                 ; f6d8: f6          .
    equb >plot_mode_1                                                 ; f6d9: f7          .
    equb >plot_mode_2                                                 ; f6da: f7          .
    equb >plot_mode_3                                                 ; f6db: f7          .
    equb >plot_mode_4                                                 ; f6dc: f7          .
; &f6dd referenced 1 time by &f6b9
.graphics_mode_bytes
    equb 0, &30, &70, &b0, &f0                                        ; f6dd: 00 30 70... .0p

.plot_mode_0
    lda l005b                                                         ; f6e2: a5 5b       .[
    ora l005d                                                         ; f6e4: 05 5d       .]
    bne return_2                                                      ; f6e6: d0 52       .R
    lda l005a                                                         ; f6e8: a5 5a       .Z
    cmp #&40 ; '@'                                                    ; f6ea: c9 40       .@
    bcs return_2                                                      ; f6ec: b0 4c       .L
    lsr a                                                             ; f6ee: 4a          J
    sta l005f                                                         ; f6ef: 85 5f       ._
    lda #&2f ; '/'                                                    ; f6f1: a9 2f       ./
    sec                                                               ; f6f3: 38          8
    sbc l005c                                                         ; f6f4: e5 5c       .\
    cmp #&30 ; '0'                                                    ; f6f6: c9 30       .0
    bcs return_2                                                      ; f6f8: b0 40       .@
    ldx #&ff                                                          ; f6fa: a2 ff       ..
    sec                                                               ; f6fc: 38          8
; &f6fd referenced 1 time by &f700
.loop_cf6fd
    inx                                                               ; f6fd: e8          .
    sbc #3                                                            ; f6fe: e9 03       ..
    bcs loop_cf6fd                                                    ; f700: b0 fb       ..
    adc #3                                                            ; f702: 69 03       i.
    sta l0061                                                         ; f704: 85 61       .a
    txa                                                               ; f706: 8a          .
    asl a                                                             ; f707: 0a          .
    asl a                                                             ; f708: 0a          .
    asl a                                                             ; f709: 0a          .
    asl a                                                             ; f70a: 0a          .
    asl a                                                             ; f70b: 0a          .
    ora l005f                                                         ; f70c: 05 5f       ._
    sta l005f                                                         ; f70e: 85 5f       ._
    lda #&80                                                          ; f710: a9 80       ..
    adc #0                                                            ; f712: 69 00       i.
    sta l0060                                                         ; f714: 85 60       .`
    lda l005a                                                         ; f716: a5 5a       .Z
    lsr a                                                             ; f718: 4a          J
    lda l0061                                                         ; f719: a5 61       .a
    rol a                                                             ; f71b: 2a          *
    tay                                                               ; f71c: a8          .
    lda lf7cb,y                                                       ; f71d: b9 cb f7    ...
; &f720 referenced 1 time by &f7a7
.cf720
    ldy #0                                                            ; f720: a0 00       ..
    ldx l005e                                                         ; f722: a6 5e       .^
    dex                                                               ; f724: ca          .
    beq cf736                                                         ; f725: f0 0f       ..
    dex                                                               ; f727: ca          .
    beq cf731                                                         ; f728: f0 07       ..
    eor #&ff                                                          ; f72a: 49 ff       I.
    and (l005f),y                                                     ; f72c: 31 5f       1_
    sta (l005f),y                                                     ; f72e: 91 5f       ._
    rts                                                               ; f730: 60          `

; &f731 referenced 1 time by &f728
.cf731
    eor (l005f),y                                                     ; f731: 51 5f       Q_
    sta (l005f),y                                                     ; f733: 91 5f       ._
    rts                                                               ; f735: 60          `

; &f736 referenced 1 time by &f725
.cf736
    ora (l005f),y                                                     ; f736: 11 5f       ._
    sta (l005f),y                                                     ; f738: 91 5f       ._
; &f73a referenced 10 times by &f6e6, &f6ec, &f6f8, &f73f, &f743, &f758, &f75c, &f771, &f775, &f783
.return_2
    rts                                                               ; f73a: 60          `

.plot_mode_1
    lda l005b                                                         ; f73b: a5 5b       .[
    ora l005d                                                         ; f73d: 05 5d       .]
    bne return_2                                                      ; f73f: d0 f9       ..
    lda l005a                                                         ; f741: a5 5a       .Z
    bmi return_2                                                      ; f743: 30 f5       0.
    lsr a                                                             ; f745: 4a          J
    lsr a                                                             ; f746: 4a          J
    lsr a                                                             ; f747: 4a          J
    sta l005f                                                         ; f748: 85 5f       ._
    lda #&3f ; '?'                                                    ; f74a: a9 3f       .?
    sec                                                               ; f74c: 38          8
    sbc l005c                                                         ; f74d: e5 5c       .\
    cmp #&40 ; '@'                                                    ; f74f: c9 40       .@
    bcc cf785                                                         ; f751: 90 32       .2
    rts                                                               ; f753: 60          `

.plot_mode_2
    lda l005b                                                         ; f754: a5 5b       .[
    ora l005d                                                         ; f756: 05 5d       .]
    bne return_2                                                      ; f758: d0 e0       ..
    lda l005a                                                         ; f75a: a5 5a       .Z
    bmi return_2                                                      ; f75c: 30 dc       0.
    lsr a                                                             ; f75e: 4a          J
    lsr a                                                             ; f75f: 4a          J
    lsr a                                                             ; f760: 4a          J
    sta l005f                                                         ; f761: 85 5f       ._
    lda #&5f ; '_'                                                    ; f763: a9 5f       ._
    sec                                                               ; f765: 38          8
    sbc l005c                                                         ; f766: e5 5c       .\
    cmp #&60 ; '`'                                                    ; f768: c9 60       .`
    bcc cf785                                                         ; f76a: 90 19       ..
; &f76c referenced 2 times by &f7ae, &f7be
.return_3
    rts                                                               ; f76c: 60          `

.plot_mode_3
    lda l005b                                                         ; f76d: a5 5b       .[
    ora l005d                                                         ; f76f: 05 5d       .]
    bne return_2                                                      ; f771: d0 c7       ..
    lda l005a                                                         ; f773: a5 5a       .Z
    bmi return_2                                                      ; f775: 30 c3       0.
    lsr a                                                             ; f777: 4a          J
    lsr a                                                             ; f778: 4a          J
    lsr a                                                             ; f779: 4a          J
    sta l005f                                                         ; f77a: 85 5f       ._
    lda #&bf                                                          ; f77c: a9 bf       ..
    sec                                                               ; f77e: 38          8
    sbc l005c                                                         ; f77f: e5 5c       .\
    cmp #&c0                                                          ; f781: c9 c0       ..
    bcs return_2                                                      ; f783: b0 b5       ..
; &f785 referenced 2 times by &f751, &f76a
.cf785
    ldy #0                                                            ; f785: a0 00       ..
    sty l0060                                                         ; f787: 84 60       .`
; &f789 referenced 1 time by &f7c7
.cf789
    asl a                                                             ; f789: 0a          .
    rol l0060                                                         ; f78a: 26 60       &`
    asl a                                                             ; f78c: 0a          .
    rol l0060                                                         ; f78d: 26 60       &`
    asl a                                                             ; f78f: 0a          .
    rol l0060                                                         ; f790: 26 60       &`
    asl a                                                             ; f792: 0a          .
    rol l0060                                                         ; f793: 26 60       &`
    adc l005f                                                         ; f795: 65 5f       e_
    sta l005f                                                         ; f797: 85 5f       ._
    lda l0060                                                         ; f799: a5 60       .`
    adc #&80                                                          ; f79b: 69 80       i.
    sta l0060                                                         ; f79d: 85 60       .`
    lda l005a                                                         ; f79f: a5 5a       .Z
    and #7                                                            ; f7a1: 29 07       ).
    tay                                                               ; f7a3: a8          .
    lda bit_masks,y                                                   ; f7a4: b9 c9 f7    ...
    jmp cf720                                                         ; f7a7: 4c 20 f7    L .

.plot_mode_4
    lda l005b                                                         ; f7aa: a5 5b       .[
    ora l005d                                                         ; f7ac: 05 5d       .]
    bne return_3                                                      ; f7ae: d0 bc       ..
    lda l005a                                                         ; f7b0: a5 5a       .Z
    lsr a                                                             ; f7b2: 4a          J
    lsr a                                                             ; f7b3: 4a          J
    lsr a                                                             ; f7b4: 4a          J
    sta l005f                                                         ; f7b5: 85 5f       ._
    lda #&bf                                                          ; f7b7: a9 bf       ..
    sec                                                               ; f7b9: 38          8
    sbc l005c                                                         ; f7ba: e5 5c       .\
    cmp #&c0                                                          ; f7bc: c9 c0       ..
    bcs return_3                                                      ; f7be: b0 ac       ..
    ldy #0                                                            ; f7c0: a0 00       ..
    sty l0060                                                         ; f7c2: 84 60       .`
    asl a                                                             ; f7c4: 0a          .
    rol l0060                                                         ; f7c5: 26 60       &`
    bpl cf789                                                         ; f7c7: 10 c0       ..
; &f7c9 referenced 1 time by &f7a4
.bit_masks
lf7cb = bit_masks+2
    equb &80, &40, &20, &10, 8, 4, 2, 1                               ; f7c9: 80 40 20... .@ ; bitmask
; &f7cb referenced 1 time by &f71d

; ***************************************************************************************
; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
; ***************************************************************************************
; &f7d1 referenced 10 times by &f511, &f86c, &f926, &f9fd, &fa7d, &fc4f, &fc58, &fc63, &fc6d, &ff69
.print_inline_string
    pla                                                               ; f7d1: 68          h
    sta l00e8                                                         ; f7d2: 85 e8       ..
    pla                                                               ; f7d4: 68          h
    sta l00e9                                                         ; f7d5: 85 e9       ..
; &f7d7 referenced 1 time by &f7e6
.loop_cf7d7
    ldy #0                                                            ; f7d7: a0 00       ..
    inc l00e8                                                         ; f7d9: e6 e8       ..
    bne cf7df                                                         ; f7db: d0 02       ..
    inc l00e9                                                         ; f7dd: e6 e9       ..
; &f7df referenced 1 time by &f7db
.cf7df
    lda (l00e8),y                                                     ; f7df: b1 e8       ..
    bmi cf7e9                                                         ; f7e1: 30 06       0.
    jsr OSWRCH                                                        ; f7e3: 20 f4 ff     .. ; Write character
    jmp loop_cf7d7                                                    ; f7e6: 4c d7 f7    L..

; &f7e9 referenced 1 time by &f7e1
.cf7e9
    jmp (l00e8)                                                       ; f7e9: 6c e8 00    l..

; &f7ec referenced 2 times by &fa3f, &fa4d
.sub_cf7ec
    ldx #&d4                                                          ; f7ec: a2 d4       .. ; X=zero page address
; ***************************************************************************************
; Print the four bytes at X in hex: X+1, X, a space, X+3, X+2 and a space
; 
; On Entry:
;     X: zero page address
; ***************************************************************************************
.print_hex_4_bytes
    jsr print_hex_2_bytes                                             ; f7ee: 20 f1 f7     .. ; Print the two bytes at X in hex, high byte first, and a space
; ***************************************************************************************
; Print the two bytes at X in hex, high byte first, and a space
; 
; On Entry:
;     X: zero page address
; ***************************************************************************************
; &f7f1 referenced 2 times by &f7ee, &fa55
.print_hex_2_bytes
    lda basic_line_number,x                                           ; f7f1: b5 01       .. ; A=byte to print
    jsr print_hex                                                     ; f7f3: 20 02 f8     .. ; Print A in hex
    inx                                                               ; f7f6: e8          .
    inx                                                               ; f7f7: e8          .
    lda printer_ignore_char,x                                         ; f7f8: b5 fe       .. ; A=byte to print
; ***************************************************************************************
; Print A in hex, and a space
; 
; On Entry:
;     A: byte to print
; ***************************************************************************************
.print_hex_space
    jsr print_hex                                                     ; f7fa: 20 02 f8     .. ; Print A in hex
; ***************************************************************************************
; Print a space
; ***************************************************************************************
; &f7fd referenced 1 time by &f99a
.print_space
    lda #&20 ; ' '                                                    ; f7fd: a9 20       .
    jmp OSWRCH                                                        ; f7ff: 4c f4 ff    L.. ; Write character 32

; ***************************************************************************************
; Print A in hex
; 
; On Entry:
;     A: byte to print
; ***************************************************************************************
; &f802 referenced 3 times by &f7f3, &f7fa, &fa5a
.print_hex
    pha                                                               ; f802: 48          H
    lsr a                                                             ; f803: 4a          J
    lsr a                                                             ; f804: 4a          J
    lsr a                                                             ; f805: 4a          J
    lsr a                                                             ; f806: 4a          J  ; A=value to print (bits 0-3)
    jsr print_hex_digit                                               ; f807: 20 0b f8     .. ; Print the low four bits of A as a hex digit
    pla                                                               ; f80a: 68          h  ; A=value to print (bits 0-3)
; ***************************************************************************************
; Print the low four bits of A as a hex digit
; 
; On Entry:
;     A: value to print (bits 0-3)
; ***************************************************************************************
; &f80b referenced 1 time by &f807
.print_hex_digit
    and #&0f                                                          ; f80b: 29 0f       ).
    cmp #&0a                                                          ; f80d: c9 0a       ..
    bcc cf813                                                         ; f80f: 90 02       ..
    adc #6                                                            ; f811: 69 06       i. ; Carry is set, so adding 7
; &f813 referenced 1 time by &f80f
.cf813
    adc #&30 ; '0'                                                    ; f813: 69 30       i0
    jmp OSWRCH                                                        ; f815: 4c f4 ff    L.. ; Write character

; &f818 referenced 2 times by &f958, &fabb
.sub_cf818
    jsr skip_input_buffer_spaces                                      ; f818: 20 76 f8     v. ; Skip spaces in the input buffer from #0100+Y (A is the next character)
    ldx #0                                                            ; f81b: a2 00       ..
    cmp #&22 ; '"'                                                    ; f81d: c9 22       ."
    beq cf827                                                         ; f81f: f0 06       ..
    inx                                                               ; f821: e8          .  ; X=1
    bne cf83f                                                         ; f822: d0 1b       .. ; ALWAYS branch

; &f824 referenced 1 time by &f82d
.loop_cf824
    jmp cfa7d                                                         ; f824: 4c 7d fa    L}.

; &f827 referenced 3 times by &f81f, &f835, &f83d
.cf827
    iny                                                               ; f827: c8          .
    lda input_buffer,y                                                ; f828: b9 00 01    ...
    cmp #&0d                                                          ; f82b: c9 0d       ..
    beq loop_cf824                                                    ; f82d: f0 f5       ..
    sta string_buffer,x                                               ; f82f: 9d 40 01    .@.
    inx                                                               ; f832: e8          .
    cmp #&22 ; '"'                                                    ; f833: c9 22       ."
    bne cf827                                                         ; f835: d0 f0       ..
    iny                                                               ; f837: c8          .
    lda input_buffer,y                                                ; f838: b9 00 01    ...
    cmp #&22 ; '"'                                                    ; f83b: c9 22       ."
    beq cf827                                                         ; f83d: f0 e8       ..
; &f83f referenced 1 time by &f822
.cf83f
    lda #&0d                                                          ; f83f: a9 0d       ..
    sta l013f,x                                                       ; f841: 9d 3f 01    .?.
    lda #&40 ; '@'                                                    ; f844: a9 40       .@
    sta l00c9                                                         ; f846: 85 c9       ..
    lda #1                                                            ; f848: a9 01       ..
    sta l00ca                                                         ; f84a: 85 ca       ..
    ldx #&c9                                                          ; f84c: a2 c9       ..
    rts                                                               ; f84e: 60          `

; &f84f referenced 2 times by &f970, &fae7
.sub_cf84f
    ldy #0                                                            ; f84f: a0 00       ..
; &f851 referenced 1 time by &f85a
.loop_cf851
    lda basic_error_number,x                                          ; f851: b5 00       ..
    sta l00c9,y                                                       ; f853: 99 c9 00    ...
    inx                                                               ; f856: e8          .
    iny                                                               ; f857: c8          .
    cpy #&0a                                                          ; f858: c0 0a       ..
    bcc loop_cf851                                                    ; f85a: 90 f5       ..
    ldy #&ff                                                          ; f85c: a0 ff       ..
    lda #&0d                                                          ; f85e: a9 0d       ..
; &f860 referenced 1 time by &f867
.loop_cf860
    iny                                                               ; f860: c8          .
    cpy #&0e                                                          ; f861: c0 0e       ..
    bcs cf86c                                                         ; f863: b0 07       ..
    cmp (l00c9),y                                                     ; f865: d1 c9       ..
    bne loop_cf860                                                    ; f867: d0 f7       ..
    cpy #0                                                            ; f869: c0 00       ..
    rts                                                               ; f86b: 60          `

; &f86c referenced 1 time by &f863
.cf86c
    jsr print_inline_string                                           ; f86c: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "NAME"                                                       ; f86f: 4e 41 4d... NAM

    nop                                                               ; f873: ea          .
    brk                                                               ; f874: 00          .

; &f875 referenced 1 time by &f87b
.loop_cf875
    iny                                                               ; f875: c8          .  ; Y=offset in the input buffer
; ***************************************************************************************
; Skip spaces in the input buffer from #0100+Y (A is the next character)
; 
; On Entry:
;     Y: offset in the input buffer
; ***************************************************************************************
; &f876 referenced 4 times by &f818, &f89b, &f8f6, &fa76
.skip_input_buffer_spaces
    lda input_buffer,y                                                ; f876: b9 00 01    ...
    cmp #&20 ; ' '                                                    ; f879: c9 20       .
    beq loop_cf875                                                    ; f87b: f0 f8       ..
    rts                                                               ; f87d: 60          `

; &f87e referenced 1 time by &f8a1
.sub_cf87e
    cmp #&30 ; '0'                                                    ; f87e: c9 30       .0
    bcc cf891                                                         ; f880: 90 0f       ..
    cmp #&3a ; ':'                                                    ; f882: c9 3a       .:
    bcc cf88e                                                         ; f884: 90 08       ..
    sbc #7                                                            ; f886: e9 07       ..
    bcc cf891                                                         ; f888: 90 07       ..
    cmp #&40 ; '@'                                                    ; f88a: c9 40       .@
    bcs return_4                                                      ; f88c: b0 02       ..
; &f88e referenced 1 time by &f884
.cf88e
    and #&0f                                                          ; f88e: 29 0f       ).
; &f890 referenced 1 time by &f88c
.return_4
    rts                                                               ; f890: 60          `

; &f891 referenced 2 times by &f880, &f888
.cf891
    sec                                                               ; f891: 38          8
    rts                                                               ; f892: 60          `

; &f893 referenced 3 times by &f95d, &fa65, &faca
.sub_cf893
    lda #0                                                            ; f893: a9 00       ..
    sta basic_error_number,x                                          ; f895: 95 00       ..
    sta basic_line_number,x                                           ; f897: 95 01       ..
    sta basic_line_number+1,x                                         ; f899: 95 02       ..
    jsr skip_input_buffer_spaces                                      ; f89b: 20 76 f8     v. ; Skip spaces in the input buffer from #0100+Y (A is the next character)
; &f89e referenced 1 time by &f8b9
.loop_cf89e
    lda input_buffer,y                                                ; f89e: b9 00 01    ...
    jsr sub_cf87e                                                     ; f8a1: 20 7e f8     ~.
    bcs cf8bb                                                         ; f8a4: b0 15       ..
    asl a                                                             ; f8a6: 0a          .
    asl a                                                             ; f8a7: 0a          .
    asl a                                                             ; f8a8: 0a          .
    asl a                                                             ; f8a9: 0a          .
    sty basic_line_number+1,x                                         ; f8aa: 94 02       ..
    ldy #4                                                            ; f8ac: a0 04       ..
; &f8ae referenced 1 time by &f8b4
.loop_cf8ae
    asl a                                                             ; f8ae: 0a          .
    rol basic_error_number,x                                          ; f8af: 36 00       6.
    rol basic_line_number,x                                           ; f8b1: 36 01       6.
    dey                                                               ; f8b3: 88          .
    bne loop_cf8ae                                                    ; f8b4: d0 f8       ..
    ldy basic_line_number+1,x                                         ; f8b6: b4 02       ..
    iny                                                               ; f8b8: c8          .
    bne loop_cf89e                                                    ; f8b9: d0 e3       ..
; &f8bb referenced 1 time by &f8a4
.cf8bb
    lda basic_line_number+1,x                                         ; f8bb: b5 02       ..
    rts                                                               ; f8bd: 60          `

; &f8be referenced 2 times by &f8fc, &f908
.cos_command_table
lf8bf = cos_command_table+1
    equs "CAT"                                                        ; f8be: 43 41 54    CAT
; &f8bf referenced 1 time by &f91b
    equb >star_cat                                                    ; f8c1: fa          .
    equb <star_cat                                                    ; f8c2: 2a          *
    equs "LOAD"                                                       ; f8c3: 4c 4f 41... LOA
    equb >star_load                                                   ; f8c7: f9          .
    equb <star_load                                                   ; f8c8: 58          X
    equs "SAVE"                                                       ; f8c9: 53 41 56... SAV
    equb >star_save                                                   ; f8cd: fa          .
    equb <star_save                                                   ; f8ce: bb          .
    equs "RUN"                                                        ; f8cf: 52 55 4e    RUN
    equb >star_run                                                    ; f8d2: fa          .
    equb <star_run                                                    ; f8d3: 20
    equs "MON"                                                        ; f8d4: 4d 4f 4e    MON
    equb >star_mon                                                    ; f8d7: fa          .
    equb <star_mon                                                    ; f8d8: 1a          .
    equs "NOMON"                                                      ; f8d9: 4e 4f 4d... NOM
    equb >star_nomon                                                  ; f8de: fa          .
    equb <star_nomon                                                  ; f8df: 19          .
    equs "FLOAD"                                                      ; f8e0: 46 4c 4f... FLO
    equb >star_fload                                                  ; f8e5: f9          .
    equb <star_fload                                                  ; f8e6: 55          U
    equs "DOS", &0d                                                   ; f8e7: 44 4f 53... DOS
    equb >dos                                                         ; f8eb: e0          .
    equb <dos                                                         ; f8ec: 00          .
    equb >cos_error                                                   ; f8ed: f9          .
    equb <cos_error                                                   ; f8ee: 26          &

; ***************************************************************************************
; Run the command in the input buffer (the kernel's OSCLI, COMVEC's default)
; ***************************************************************************************
.kernel_cli
    ldx #&ff                                                          ; f8ef: a2 ff       ..
    cld                                                               ; f8f1: d8          .
; &f8f2 referenced 1 time by &f913
.cf8f2
    ldy #0                                                            ; f8f2: a0 00       .. ; Y=offset in the input buffer
    sty l00dd                                                         ; f8f4: 84 dd       ..
    jsr skip_input_buffer_spaces                                      ; f8f6: 20 76 f8     v. ; Skip spaces in the input buffer from #0100+Y (A is the next character)
    dey                                                               ; f8f9: 88          .
; &f8fa referenced 1 time by &f904
.loop_cf8fa
    iny                                                               ; f8fa: c8          .
    inx                                                               ; f8fb: e8          .
; &f8fc referenced 1 time by &f917
.loop_cf8fc
    lda cos_command_table,x                                           ; f8fc: bd be f8    ...
    bmi cf919                                                         ; f8ff: 30 18       0.
    cmp input_buffer,y                                                ; f901: d9 00 01    ...
    beq loop_cf8fa                                                    ; f904: f0 f4       ..
    dex                                                               ; f906: ca          .
; &f907 referenced 1 time by &f90b
.loop_cf907
    inx                                                               ; f907: e8          .
    lda cos_command_table,x                                           ; f908: bd be f8    ...
    bpl loop_cf907                                                    ; f90b: 10 fa       ..
    inx                                                               ; f90d: e8          .
    lda input_buffer,y                                                ; f90e: b9 00 01    ...
    cmp #&2e ; '.'                                                    ; f911: c9 2e       ..
    bne cf8f2                                                         ; f913: d0 dd       ..
    iny                                                               ; f915: c8          .
    dex                                                               ; f916: ca          .
    bcs loop_cf8fc                                                    ; f917: b0 e3       .. ; ALWAYS branch

; &f919 referenced 1 time by &f8ff
.cf919
    sta l00ca                                                         ; f919: 85 ca       ..
    lda lf8bf,x                                                       ; f91b: bd bf f8    ...
    sta l00c9                                                         ; f91e: 85 c9       ..
    clc                                                               ; f920: 18          .
    ldx #0                                                            ; f921: a2 00       ..
    jmp (l00c9)                                                       ; f923: 6c c9 00    l..

.cos_error
    jsr print_inline_string                                           ; f926: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "COM?"                                                       ; f929: 43 4f 4d... COM

    nop                                                               ; f92d: ea          .
; &f92e referenced 1 time by &f932
.loop_cf92e
    brk                                                               ; f92e: 00          .

; &f92f referenced 2 times by &f934, &f978
.cf92f
    jsr cfb8e                                                         ; f92f: 20 8e fb     ..
    bvc loop_cf92e                                                    ; f932: 50 fa       P.
    beq cf92f                                                         ; f934: f0 f9       ..
    jsr sub_cfc2b                                                     ; f936: 20 2b fc     +.
    ldy #0                                                            ; f939: a0 00       .. ; Y=file handle
; &f93b referenced 1 time by &f94b
.loop_cf93b
    jsr OSBGET                                                        ; f93b: 20 d4 ff     .. ; Read a byte from file Y
    sta (l00cb),y                                                     ; f93e: 91 cb       .. ; A=byte read
    inc l00cb                                                         ; f940: e6 cb       ..
    bne cf946                                                         ; f942: d0 02       ..
    inc l00cc                                                         ; f944: e6 cc       ..
; &f946 referenced 1 time by &f942
.cf946
    ldx #&d4                                                          ; f946: a2 d4       ..
    jsr sub_cfa08                                                     ; f948: 20 08 fa     ..
    bne loop_cf93b                                                    ; f94b: d0 ee       ..
    sec                                                               ; f94d: 38          8
; &f94e referenced 2 times by &f983, &f98c
.cf94e
    ror l00dd                                                         ; f94e: 66 dd       f.
    clc                                                               ; f950: 18          .
    ror l00dd                                                         ; f951: 66 dd       f.
    plp                                                               ; f953: 28          (
    rts                                                               ; f954: 60          `

.star_fload
    sec                                                               ; f955: 38          8
    ror l00dd                                                         ; f956: 66 dd       f.
; &f958 referenced 1 time by &fa20
.star_load
    jsr sub_cf818                                                     ; f958: 20 18 f8     ..
    ldx #&cb                                                          ; f95b: a2 cb       ..
    jsr sub_cf893                                                     ; f95d: 20 93 f8     ..
    beq cf966                                                         ; f960: f0 04       ..
    lda #&ff                                                          ; f962: a9 ff       ..
    sta l00cd                                                         ; f964: 85 cd       ..
; &f966 referenced 1 time by &f960
.cf966
    jsr sub_cfa76                                                     ; f966: 20 76 fa     v.
    ldx #&c9                                                          ; f969: a2 c9       ..
    jmp (lodvec)                                                      ; f96b: 6c 0c 02    l..

; ***************************************************************************************
; Load a file (the kernel's OSLOAD, LODVEC's default)
; ***************************************************************************************
.kernel_load
    php                                                               ; f96e: 08          .
    sei                                                               ; f96f: 78          x
    jsr sub_cf84f                                                     ; f970: 20 4f f8     O.
    php                                                               ; f973: 08          .
    jsr cfc3e                                                         ; f974: 20 3e fc     >.
    plp                                                               ; f977: 28          (
    beq cf92f                                                         ; f978: f0 b5       ..
    lda #0                                                            ; f97a: a9 00       ..
    sta l00d0                                                         ; f97c: 85 d0       ..
    sta l00d1                                                         ; f97e: 85 d1       ..
; &f980 referenced 1 time by &f989
.loop_cf980
    jsr cf9a2                                                         ; f980: 20 a2 f9     ..
    bcc cf94e                                                         ; f983: 90 c9       ..
    inc l00d0                                                         ; f985: e6 d0       ..
    inc l00cc                                                         ; f987: e6 cc       ..
    bne loop_cf980                                                    ; f989: d0 f5       ..
    clc                                                               ; f98b: 18          .
    bcc cf94e                                                         ; f98c: 90 c0       .. ; ALWAYS branch

; &f98e referenced 1 time by &f997
.loop_cf98e
    jsr OSWRCH                                                        ; f98e: 20 f4 ff     .. ; Write character
    iny                                                               ; f991: c8          .
; &f992 referenced 2 times by &f9bf, &fa4a
.sub_cf992
    lda l00ed,y                                                       ; f992: b9 ed 00    ...
    cmp #&0d                                                          ; f995: c9 0d       ..
    bne loop_cf98e                                                    ; f997: d0 f5       ..
; &f999 referenced 2 times by &f99f, &fa3c
.cf999
    iny                                                               ; f999: c8          .
    jsr print_space                                                   ; f99a: 20 fd f7     .. ; Print a space
    cpy #&0e                                                          ; f99d: c0 0e       ..
    bcc cf999                                                         ; f99f: 90 f8       ..
    rts                                                               ; f9a1: 60          `

; &f9a2 referenced 5 times by &f980, &f9ab, &f9bd, &f9c5, &f9db
.cf9a2
lf9a3 = cf9a2+1
    lda #0                                                            ; f9a2: a9 00       ..
; overlapping: brk                                                    ; f9a3: 00          .
; &f9a3 referenced 1 time by &f9a9
    sta l00dc                                                         ; f9a4: 85 dc       ..
    jsr cfb8e                                                         ; f9a6: 20 8e fb     ..
    bvc lf9a3                                                         ; f9a9: 50 f8       P.
    bne cf9a2                                                         ; f9ab: d0 f5       ..
    jsr sub_cfbc9                                                     ; f9ad: 20 c9 fb     ..
    php                                                               ; f9b0: 08          .
    jsr sub_cfbe2                                                     ; f9b1: 20 e2 fb     ..
    plp                                                               ; f9b4: 28          (
    beq cf9c7                                                         ; f9b5: f0 10       ..
    lda l00db                                                         ; f9b7: a5 db       ..
    and #&20 ; ' '                                                    ; f9b9: 29 20       )
    ora nomon_flag                                                    ; f9bb: 05 ea       ..
    bne cf9a2                                                         ; f9bd: d0 e3       ..
    jsr sub_cf992                                                     ; f9bf: 20 92 f9     ..
    jsr OSCRLF                                                        ; f9c2: 20 ed ff     .. ; Write newline (characters 10 and 13)
    bne cf9a2                                                         ; f9c5: d0 db       ..
; &f9c7 referenced 1 time by &f9b5
.cf9c7
    ldx #2                                                            ; f9c7: a2 02       ..
    lda l00dd                                                         ; f9c9: a5 dd       ..
    bmi cf9e0                                                         ; f9cb: 30 13       0.
; &f9cd referenced 1 time by &f9de
.loop_cf9cd
    lda l00cf,x                                                       ; f9cd: b5 cf       ..
    cmp l00d8,x                                                       ; f9cf: d5 d8       ..
    bcs cf9db                                                         ; f9d1: b0 08       ..
    lda #5                                                            ; f9d3: a9 05       ..
    jsr cfc40                                                         ; f9d5: 20 40 fc     @.
    jsr cfc3e                                                         ; f9d8: 20 3e fc     >.
; &f9db referenced 1 time by &f9d1
.cf9db
    bne cf9a2                                                         ; f9db: d0 c5       ..
    dex                                                               ; f9dd: ca          .
    bne loop_cf9cd                                                    ; f9de: d0 ed       ..
; &f9e0 referenced 1 time by &f9cb
.cf9e0
    jsr sub_cfc2b                                                     ; f9e0: 20 2b fc     +.
    bit l00db                                                         ; f9e3: 24 db       $.
    bvc cf9f2                                                         ; f9e5: 50 0b       P.
    dey                                                               ; f9e7: 88          .
; &f9e8 referenced 1 time by &f9f0
.loop_cf9e8
    iny                                                               ; f9e8: c8          .  ; Y=file handle
    jsr OSBGET                                                        ; f9e9: 20 d4 ff     .. ; Read a byte from file Y
    sta (l00cb),y                                                     ; f9ec: 91 cb       .. ; A=byte read
    cpy l00d8                                                         ; f9ee: c4 d8       ..
    bne loop_cf9e8                                                    ; f9f0: d0 f6       ..
; &f9f2 referenced 1 time by &f9e5
.cf9f2
    lda l00dc                                                         ; f9f2: a5 dc       ..
    sta l00ce                                                         ; f9f4: 85 ce       ..
    jsr OSBGET                                                        ; f9f6: 20 d4 ff     .. ; Read a byte from file Y
    cmp l00ce                                                         ; f9f9: c5 ce       .. ; A=byte read
    beq cfa05                                                         ; f9fb: f0 08       ..
    jsr print_inline_string                                           ; f9fd: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "SUM"                                                        ; fa00: 53 55 4d    SUM

    nop                                                               ; fa03: ea          .
    brk                                                               ; fa04: 00          .

; &fa05 referenced 1 time by &f9fb
.cfa05
    rol l00db                                                         ; fa05: 26 db       &.
    rts                                                               ; fa07: 60          `

; &fa08 referenced 2 times by &f948, &fab4
.sub_cfa08
    inc basic_error_number,x                                          ; fa08: f6 00       ..
    bne cfa0e                                                         ; fa0a: d0 02       ..
    inc basic_line_number,x                                           ; fa0c: f6 01       ..
; &fa0e referenced 1 time by &fa0a
.cfa0e
    lda basic_error_number,x                                          ; fa0e: b5 00       ..
    cmp basic_line_number+1,x                                         ; fa10: d5 02       ..
    bne return_5                                                      ; fa12: d0 04       ..
    lda basic_line_number,x                                           ; fa14: b5 01       ..
    cmp parsing_ptr_offset,x                                          ; fa16: d5 03       ..
; &fa18 referenced 1 time by &fa12
.return_5
    rts                                                               ; fa18: 60          `

.star_nomon
    dex                                                               ; fa19: ca          .
.star_mon
    jsr sub_cfa76                                                     ; fa1a: 20 76 fa     v.
    stx nomon_flag                                                    ; fa1d: 86 ea       ..
; &fa1f referenced 1 time by &fa7b
.return_6
    rts                                                               ; fa1f: 60          `

.star_run
    jsr star_load                                                     ; fa20: 20 58 f9     X.
    bit l00dd                                                         ; fa23: 24 dd       $.
    bvs cfa73                                                         ; fa25: 70 4c       pL
    jmp (l00d6)                                                       ; fa27: 6c d6 00    l..

.star_cat
    php                                                               ; fa2a: 08          .
    jsr sub_cfa76                                                     ; fa2b: 20 76 fa     v.
    jsr cfc3e                                                         ; fa2e: 20 3e fc     >.
; &fa31 referenced 1 time by &fa60
.cfa31
    jsr cfb8e                                                         ; fa31: 20 8e fb     ..
    bvs cfa38                                                         ; fa34: 70 02       p.
    plp                                                               ; fa36: 28          (
    rts                                                               ; fa37: 60          `

; &fa38 referenced 1 time by &fa34
.cfa38
    beq cfa44                                                         ; fa38: f0 0a       ..
    ldy #0                                                            ; fa3a: a0 00       ..
    jsr cf999                                                         ; fa3c: 20 99 f9     ..
    jsr sub_cf7ec                                                     ; fa3f: 20 ec f7     ..
    bne cfa5d                                                         ; fa42: d0 19       ..
; &fa44 referenced 1 time by &fa38
.cfa44
    jsr sub_cfbc9                                                     ; fa44: 20 c9 fb     ..
    jsr sub_cfbe2                                                     ; fa47: 20 e2 fb     ..
    jsr sub_cf992                                                     ; fa4a: 20 92 f9     ..
    jsr sub_cf7ec                                                     ; fa4d: 20 ec f7     ..
    rol l00db                                                         ; fa50: 26 db       &.
    bpl cfa5d                                                         ; fa52: 10 09       ..
    inx                                                               ; fa54: e8          .  ; X=zero page address
    jsr print_hex_2_bytes                                             ; fa55: 20 f1 f7     .. ; Print the two bytes at X in hex, high byte first, and a space
    lda l00fd,x                                                       ; fa58: b5 fd       .. ; A=byte to print
    jsr print_hex                                                     ; fa5a: 20 02 f8     .. ; Print A in hex
; &fa5d referenced 2 times by &fa42, &fa52
.cfa5d
    jsr OSCRLF                                                        ; fa5d: 20 ed ff     .. ; Write newline (characters 10 and 13)
    bne cfa31                                                         ; fa60: d0 cf       ..
    jmp OSCRLF                                                        ; fa62: 4c ed ff    L.. ; Write newline (characters 10 and 13)

; &fa65 referenced 3 times by &fa6d, &fac0, &fac5
.sub_cfa65
    jsr sub_cf893                                                     ; fa65: 20 93 f8     ..
    beq cfa7d                                                         ; fa68: f0 13       ..
    rts                                                               ; fa6a: 60          `

.jump_to_hex_address
    ldx #&cb                                                          ; fa6b: a2 cb       ..
    jsr sub_cfa65                                                     ; fa6d: 20 65 fa     e.
    jsr sub_cfa76                                                     ; fa70: 20 76 fa     v.
; &fa73 referenced 1 time by &fa25
.cfa73
    jmp (l00cb)                                                       ; fa73: 6c cb 00    l..

; &fa76 referenced 5 times by &f966, &fa1a, &fa2b, &fa70, &fadd
.sub_cfa76
    jsr skip_input_buffer_spaces                                      ; fa76: 20 76 f8     v. ; Skip spaces in the input buffer from #0100+Y (A is the next character)
    cmp #&0d                                                          ; fa79: c9 0d       ..
    beq return_6                                                      ; fa7b: f0 a2       ..
; &fa7d referenced 2 times by &f824, &fa68
.cfa7d
    jsr print_inline_string                                           ; fa7d: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "SYN?"                                                       ; fa80: 53 59 4e... SYN

    nop                                                               ; fa84: ea          .
    brk                                                               ; fa85: 00          .

; &fa86 referenced 1 time by &faf6
.cfa86
    sec                                                               ; fa86: 38          8
    lda l00d1                                                         ; fa87: a5 d1       ..
    sbc l00cf                                                         ; fa89: e5 cf       ..
    pha                                                               ; fa8b: 48          H
    lda l00d2                                                         ; fa8c: a5 d2       ..
    sbc l00d0                                                         ; fa8e: e5 d0       ..
    tay                                                               ; fa90: a8          .
    pla                                                               ; fa91: 68          h
    clc                                                               ; fa92: 18          .
    adc l00cb                                                         ; fa93: 65 cb       e.
    sta l00cd                                                         ; fa95: 85 cd       ..
    tya                                                               ; fa97: 98          .
    adc l00cc                                                         ; fa98: 65 cc       e.
    sta l00ce                                                         ; fa9a: 85 ce       ..
    ldy #4                                                            ; fa9c: a0 04       .. ; Y=file handle
; &fa9e referenced 1 time by &faa5
.loop_cfa9e
    lda l00ca,y                                                       ; fa9e: b9 ca 00    ...
    jsr OSBPUT                                                        ; faa1: 20 d1 ff     .. ; Write byte A to file Y
    dey                                                               ; faa4: 88          .
    bne loop_cfa9e                                                    ; faa5: d0 f7       ..
; &faa7 referenced 1 time by &fab7
.loop_cfaa7
    lda (l00cf),y                                                     ; faa7: b1 cf       ..
    jsr OSBPUT                                                        ; faa9: 20 d1 ff     .. ; Write byte A to file Y
    inc l00cf                                                         ; faac: e6 cf       ..
    bne cfab2                                                         ; faae: d0 02       ..
    inc l00d0                                                         ; fab0: e6 d0       ..
; &fab2 referenced 1 time by &faae
.cfab2
    ldx #&cb                                                          ; fab2: a2 cb       ..
    jsr sub_cfa08                                                     ; fab4: 20 08 fa     ..
    bne loop_cfaa7                                                    ; fab7: d0 ee       ..
    plp                                                               ; fab9: 28          (
    rts                                                               ; faba: 60          `

.star_save
    jsr sub_cf818                                                     ; fabb: 20 18 f8     ..
    ldx #&cb                                                          ; fabe: a2 cb       ..
    jsr sub_cfa65                                                     ; fac0: 20 65 fa     e.
    ldx #&d1                                                          ; fac3: a2 d1       ..
    jsr sub_cfa65                                                     ; fac5: 20 65 fa     e.
    ldx #&cd                                                          ; fac8: a2 cd       ..
    jsr sub_cf893                                                     ; faca: 20 93 f8     ..
    php                                                               ; facd: 08          .
    lda l00cb                                                         ; face: a5 cb       ..
    ldx l00cc                                                         ; fad0: a6 cc       ..
    plp                                                               ; fad2: 28          (
    bne cfad9                                                         ; fad3: d0 04       ..
    sta l00cd                                                         ; fad5: 85 cd       ..
    stx l00ce                                                         ; fad7: 86 ce       ..
; &fad9 referenced 1 time by &fad3
.cfad9
    sta l00cf                                                         ; fad9: 85 cf       ..
    stx l00d0                                                         ; fadb: 86 d0       ..
    jsr sub_cfa76                                                     ; fadd: 20 76 fa     v.
    ldx #&c9                                                          ; fae0: a2 c9       ..
    jmp (savvec)                                                      ; fae2: 6c 0e 02    l..

; ***************************************************************************************
; Save a file (the kernel's OSSAVE, SAVVEC's default)
; ***************************************************************************************
.kernel_save
    php                                                               ; fae5: 08          .
    sei                                                               ; fae6: 78          x
    jsr sub_cf84f                                                     ; fae7: 20 4f f8     O.
    php                                                               ; faea: 08          .
    lda #6                                                            ; faeb: a9 06       ..
    jsr cfc40                                                         ; faed: 20 40 fc     @.
    ldx #7                                                            ; faf0: a2 07       ..
    jsr sub_cfb7a                                                     ; faf2: 20 7a fb     z.
    plp                                                               ; faf5: 28          (
    beq cfa86                                                         ; faf6: f0 8e       ..
    ldx #4                                                            ; faf8: a2 04       ..
; &fafa referenced 1 time by &faff
.loop_cfafa
    lda l00ce,x                                                       ; fafa: b5 ce       ..
    sta l00d2,x                                                       ; fafc: 95 d2       ..
    dex                                                               ; fafe: ca          .
    bne loop_cfafa                                                    ; faff: d0 f9       ..
    stx l00d0                                                         ; fb01: 86 d0       ..
    stx l00d1                                                         ; fb03: 86 d1       ..
    lda l00d5                                                         ; fb05: a5 d5       ..
    bne cfb0b                                                         ; fb07: d0 02       ..
    dec l00d6                                                         ; fb09: c6 d6       ..
; &fb0b referenced 1 time by &fb07
.cfb0b
    dec l00d5                                                         ; fb0b: c6 d5       ..
    clc                                                               ; fb0d: 18          .
; &fb0e referenced 1 time by &fb37
.cfb0e
    ror l00d2                                                         ; fb0e: 66 d2       f.
    sec                                                               ; fb10: 38          8
    ldx #&ff                                                          ; fb11: a2 ff       ..
    lda l00d5                                                         ; fb13: a5 d5       ..
    sbc l00d3                                                         ; fb15: e5 d3       ..
    sta l00cf                                                         ; fb17: 85 cf       ..
    lda l00d6                                                         ; fb19: a5 d6       ..
    sbc l00d4                                                         ; fb1b: e5 d4       ..
    php                                                               ; fb1d: 08          .
    ror l00d2                                                         ; fb1e: 66 d2       f.
    plp                                                               ; fb20: 28          (
    bcc cfb29                                                         ; fb21: 90 06       ..
    clc                                                               ; fb23: 18          .
    beq cfb29                                                         ; fb24: f0 03       ..
    stx l00cf                                                         ; fb26: 86 cf       ..
    sec                                                               ; fb28: 38          8
; &fb29 referenced 2 times by &fb21, &fb24
.cfb29
    ror l00d2                                                         ; fb29: 66 d2       f.
    inx                                                               ; fb2b: e8          .
    jsr sub_cfb3b                                                     ; fb2c: 20 3b fb     ;.
    inc l00d0                                                         ; fb2f: e6 d0       ..
    inc l00d4                                                         ; fb31: e6 d4       ..
    inc l00cc                                                         ; fb33: e6 cc       ..
    rol l00d2                                                         ; fb35: 26 d2       &.
    bcs cfb0e                                                         ; fb37: b0 d5       ..
    plp                                                               ; fb39: 28          (
    rts                                                               ; fb3a: 60          `

; &fb3b referenced 1 time by &fb2c
.sub_cfb3b
    ldx #7                                                            ; fb3b: a2 07       ..
    jsr sub_cfb7a                                                     ; fb3d: 20 7a fb     z.
    stx l00dc                                                         ; fb40: 86 dc       ..
    ldy #4                                                            ; fb42: a0 04       .. ; Y=file handle
; &fb44 referenced 1 time by &fb4a
.loop_cfb44
    lda #&2a ; '*'                                                    ; fb44: a9 2a       .*
    jsr OSBPUT                                                        ; fb46: 20 d1 ff     .. ; Write byte A=42 to file Y
    dey                                                               ; fb49: 88          .
    bne loop_cfb44                                                    ; fb4a: d0 f8       ..
; &fb4c referenced 1 time by &fb54
.loop_cfb4c
    lda (l00c9),y                                                     ; fb4c: b1 c9       ..
    jsr OSBPUT                                                        ; fb4e: 20 d1 ff     .. ; Write byte A to file Y
    iny                                                               ; fb51: c8          .
    cmp #&0d                                                          ; fb52: c9 0d       ..
    bne loop_cfb4c                                                    ; fb54: d0 f6       ..
    ldy #8                                                            ; fb56: a0 08       .. ; Y=file handle
; &fb58 referenced 1 time by &fb5f
.loop_cfb58
    lda l00ca,y                                                       ; fb58: b9 ca 00    ...
    jsr OSBPUT                                                        ; fb5b: 20 d1 ff     .. ; Write byte A to file Y
    dey                                                               ; fb5e: 88          .
    bne loop_cfb58                                                    ; fb5f: d0 f7       ..
    jsr sub_cfb81                                                     ; fb61: 20 81 fb     ..
    bit l00d2                                                         ; fb64: 24 d2       $.
    bvc cfb73                                                         ; fb66: 50 0b       P.
    dey                                                               ; fb68: 88          .
; &fb69 referenced 1 time by &fb71
.loop_cfb69
    iny                                                               ; fb69: c8          .  ; Y=file handle
    lda (l00d3),y                                                     ; fb6a: b1 d3       ..
    jsr OSBPUT                                                        ; fb6c: 20 d1 ff     .. ; Write byte A to file Y
    cpy l00cf                                                         ; fb6f: c4 cf       ..
    bne loop_cfb69                                                    ; fb71: d0 f6       ..
; &fb73 referenced 1 time by &fb66
.cfb73
    lda l00dc                                                         ; fb73: a5 dc       ..
    jsr OSBPUT                                                        ; fb75: 20 d1 ff     .. ; Write byte A to file Y
    ldx #4                                                            ; fb78: a2 04       ..
; &fb7a referenced 2 times by &faf2, &fb3d
.sub_cfb7a
    stx ppi_port_c                                                    ; fb7a: 8e 02 b0    ...
    ldx #&78 ; 'x'                                                    ; fb7d: a2 78       .x
    bne cfb83                                                         ; fb7f: d0 02       .. ; ALWAYS branch

; &fb81 referenced 1 time by &fb61
.sub_cfb81
    ldx #&1e                                                          ; fb81: a2 1e       ..
; &fb83 referenced 3 times by &fb7f, &fb87, &fb8c
.cfb83
    jsr wait_for_flyback                                              ; fb83: 20 66 fe     f. ; Wait for the start of the next field flyback
    dex                                                               ; fb86: ca          .
    bne cfb83                                                         ; fb87: d0 fa       ..
    rts                                                               ; fb89: 60          `

; ***************************************************************************************
; Wait for six field flybacks (a tenth of a second)
; ***************************************************************************************
; &fb8a referenced 1 time by &fea4
.wait_tenth_second
    ldx #6                                                            ; fb8a: a2 06       ..
    bne cfb83                                                         ; fb8c: d0 f5       .. ; ALWAYS branch

; &fb8e referenced 5 times by &f92f, &f9a6, &fa31, &fb91, &fb93
.cfb8e
    bit ppi_port_b                                                    ; fb8e: 2c 01 b0    ,.. ; Test the SHIFT key and the CTRL key
    bpl cfb8e                                                         ; fb91: 10 fb       ..
    bvc cfb8e                                                         ; fb93: 50 f9       P.
; &fb95 referenced 1 time by &fba7
.loop_cfb95
    ldy #0                                                            ; fb95: a0 00       ..
    sta l00c3                                                         ; fb97: 85 c3       ..
    lda #&10                                                          ; fb99: a9 10       ..
    sta l00c2                                                         ; fb9b: 85 c2       ..
; &fb9d referenced 2 times by &fbab, &fbaf
.cfb9d
    bit ppi_port_b                                                    ; fb9d: 2c 01 b0    ,.. ; Test the SHIFT key and the CTRL key
    bpl cfbb1                                                         ; fba0: 10 0f       ..
    bvc cfbb1                                                         ; fba2: 50 0d       P.
    jsr sub_cfcbd                                                     ; fba4: 20 bd fc     ..
    bcs loop_cfb95                                                    ; fba7: b0 ec       ..
    dec l00c3                                                         ; fba9: c6 c3       ..
    bne cfb9d                                                         ; fbab: d0 f0       ..
    dec l00c2                                                         ; fbad: c6 c2       ..
    bne cfb9d                                                         ; fbaf: d0 ec       ..
; &fbb1 referenced 2 times by &fba0, &fba2
.cfbb1
    bvs cfbb4                                                         ; fbb1: 70 01       p.
    rts                                                               ; fbb3: 60          `

; &fbb4 referenced 1 time by &fbb1
.cfbb4
    ldy #4                                                            ; fbb4: a0 04       ..
    php                                                               ; fbb6: 08          .
    jsr cfbe4                                                         ; fbb7: 20 e4 fb     ..
    plp                                                               ; fbba: 28          (
    ldy #4                                                            ; fbbb: a0 04       ..
    lda #&2a ; '*'                                                    ; fbbd: a9 2a       .*
; &fbbf referenced 1 time by &fbc5
.loop_cfbbf
    cmp l00d3,y                                                       ; fbbf: d9 d3 00    ...
    bne return_7                                                      ; fbc2: d0 03       ..
    dey                                                               ; fbc4: 88          .
    bne loop_cfbbf                                                    ; fbc5: d0 f8       ..
; &fbc7 referenced 2 times by &fbc2, &fbdb
.return_7
    rts                                                               ; fbc7: 60          `

; &fbc8 referenced 1 time by &fbd1
.loop_cfbc8
    iny                                                               ; fbc8: c8          .  ; Y=file handle
; &fbc9 referenced 2 times by &f9ad, &fa44
.sub_cfbc9
    jsr OSBGET                                                        ; fbc9: 20 d4 ff     .. ; Read a byte from file Y
    sta l00ed,y                                                       ; fbcc: 99 ed 00    ... ; A=byte read
    cmp #&0d                                                          ; fbcf: c9 0d       ..
    bne loop_cfbc8                                                    ; fbd1: d0 f5       ..
    ldy #&ff                                                          ; fbd3: a0 ff       ..
; &fbd5 referenced 1 time by &fbdf
.loop_cfbd5
    iny                                                               ; fbd5: c8          .
    lda (l00c9),y                                                     ; fbd6: b1 c9       ..
    cmp l00ed,y                                                       ; fbd8: d9 ed 00    ...
    bne return_7                                                      ; fbdb: d0 ea       ..
    cmp #&0d                                                          ; fbdd: c9 0d       ..
    bne loop_cfbd5                                                    ; fbdf: d0 f4       ..
    rts                                                               ; fbe1: 60          `

; &fbe2 referenced 2 times by &f9b1, &fa47
.sub_cfbe2
    ldy #8                                                            ; fbe2: a0 08       .. ; Y=file handle
; &fbe4 referenced 2 times by &fbb7, &fbeb
.cfbe4
    jsr OSBGET                                                        ; fbe4: 20 d4 ff     .. ; Read a byte from file Y
    sta l00d3,y                                                       ; fbe7: 99 d3 00    ... ; A=byte read
    dey                                                               ; fbea: 88          .
    bne cfbe4                                                         ; fbeb: d0 f7       ..
    rts                                                               ; fbed: 60          `

; ***************************************************************************************
; Read a byte from tape (the kernel's OSBGET, BGTVEC's default)
; ***************************************************************************************
.kernel_bget
    stx l00ec                                                         ; fbee: 86 ec       ..
    sty l00c3                                                         ; fbf0: 84 c3       ..
    php                                                               ; fbf2: 08          .
    sei                                                               ; fbf3: 78          x
; &fbf4 referenced 1 time by &fbfb
.loop_cfbf4
    lda #&78 ; 'x'                                                    ; fbf4: a9 78       .x
    sta l00c0                                                         ; fbf6: 85 c0       ..
; &fbf8 referenced 1 time by &fbff
.loop_cfbf8
    jsr sub_cfcbd                                                     ; fbf8: 20 bd fc     ..
    bcc loop_cfbf4                                                    ; fbfb: 90 f7       ..
    inc l00c0                                                         ; fbfd: e6 c0       ..
    bpl loop_cfbf8                                                    ; fbff: 10 f7       ..
; &fc01 referenced 1 time by &fc1a
.loop_cfc01
    lda #&53 ; 'S'                                                    ; fc01: a9 53       .S
    sta l00c4                                                         ; fc03: 85 c4       ..
    ldx #0                                                            ; fc05: a2 00       ..
    ldy ppi_port_c                                                    ; fc07: ac 02 b0    ...
; &fc0a referenced 1 time by &fc14
.loop_cfc0a
    jsr sub_cfccd                                                     ; fc0a: 20 cd fc     ..
    beq cfc0f                                                         ; fc0d: f0 00       ..
; &fc0f referenced 1 time by &fc0d
.cfc0f
    beq cfc12                                                         ; fc0f: f0 01       ..
    inx                                                               ; fc11: e8          .
; &fc12 referenced 1 time by &fc0f
.cfc12
    dec l00c4                                                         ; fc12: c6 c4       ..
    bne loop_cfc0a                                                    ; fc14: d0 f4       ..
    cpx #&0c                                                          ; fc16: e0 0c       ..
    ror l00c0                                                         ; fc18: 66 c0       f.
    bcc loop_cfc01                                                    ; fc1a: 90 e5       ..
    lda l00c0                                                         ; fc1c: a5 c0       ..
    plp                                                               ; fc1e: 28          (
    ldy l00c3                                                         ; fc1f: a4 c3       ..
    ldx l00ec                                                         ; fc21: a6 ec       ..
; &fc23 referenced 1 time by &fc83
.sub_cfc23
    pha                                                               ; fc23: 48          H
    clc                                                               ; fc24: 18          .
    adc l00dc                                                         ; fc25: 65 dc       e.
    sta l00dc                                                         ; fc27: 85 dc       ..
    pla                                                               ; fc29: 68          h
    rts                                                               ; fc2a: 60          `

; &fc2b referenced 2 times by &f936, &f9e0
.sub_cfc2b
    lda l00cd                                                         ; fc2b: a5 cd       ..
    bmi return_8                                                      ; fc2d: 30 08       0.
    lda l00d4                                                         ; fc2f: a5 d4       ..
    sta l00cb                                                         ; fc31: 85 cb       ..
    lda l00d5                                                         ; fc33: a5 d5       ..
    sta l00cc                                                         ; fc35: 85 cc       ..
; &fc37 referenced 1 time by &fc2d
.return_8
    rts                                                               ; fc37: 60          `

; ***************************************************************************************
; Print 'PLAY TAPE' or 'RECORD TAPE' (the kernel's OSFIND, FNDVEC's default)
; ***************************************************************************************
.kernel_find
    bcs cfc3e                                                         ; fc38: b0 04       ..
    lda #6                                                            ; fc3a: a9 06       ..
    bne cfc40                                                         ; fc3c: d0 02       .. ; ALWAYS branch

; &fc3e referenced 4 times by &f974, &f9d8, &fa2e, &fc38
.cfc3e
    lda #4                                                            ; fc3e: a9 04       ..
; &fc40 referenced 3 times by &f9d5, &faed, &fc3c
.cfc40
    ldx #7                                                            ; fc40: a2 07       ..
    stx ppi_port_c                                                    ; fc42: 8e 02 b0    ... ; Tape output high, turn the 2.4 kHz tape tone on, speaker high, select colour set 0
    bit nomon_flag                                                    ; fc45: 24 ea       $.
    bne cfc76                                                         ; fc47: d0 2d       .-
    cmp #5                                                            ; fc49: c9 05       ..
    beq cfc63                                                         ; fc4b: f0 16       ..
    bcs cfc58                                                         ; fc4d: b0 09       ..
    jsr print_inline_string                                           ; fc4f: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "PLAY"                                                       ; fc52: 50 4c 41... PLA

    bne cfc6d                                                         ; fc56: d0 15       ..
; &fc58 referenced 1 time by &fc4d
.cfc58
    jsr print_inline_string                                           ; fc58: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "RECORD"                                                     ; fc5b: 52 45 43... REC

    bne cfc6d                                                         ; fc61: d0 0a       ..
; &fc63 referenced 1 time by &fc4b
.cfc63
    jsr print_inline_string                                           ; fc63: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "REWIND"                                                     ; fc66: 52 45 57... REW

    nop                                                               ; fc6c: ea          .
; &fc6d referenced 2 times by &fc56, &fc61
.cfc6d
    jsr print_inline_string                                           ; fc6d: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs " TAPE"                                                      ; fc70: 20 54 41...  TA

    nop                                                               ; fc75: ea          .
; &fc76 referenced 1 time by &fc47
.cfc76
    jsr OSRDCH                                                        ; fc76: 20 e3 ff     .. ; Read a character
    jmp OSCRLF                                                        ; fc79: 4c ed ff    L.. ; Write newline (characters 10 and 13)

; ***************************************************************************************
; Write a byte to tape (the kernel's OSBPUT, BPTVEC's default)
; ***************************************************************************************
.kernel_bput
    stx l00ec                                                         ; fc7c: 86 ec       ..
    sty l00c3                                                         ; fc7e: 84 c3       ..
    php                                                               ; fc80: 08          .
    sei                                                               ; fc81: 78          x
    pha                                                               ; fc82: 48          H
    jsr sub_cfc23                                                     ; fc83: 20 23 fc     #.
    sta l00c0                                                         ; fc86: 85 c0       ..
    jsr sub_cfcd8                                                     ; fc88: 20 d8 fc     ..
    lda #&0a                                                          ; fc8b: a9 0a       ..
    sta l00c1                                                         ; fc8d: 85 c1       ..
    clc                                                               ; fc8f: 18          .
; &fc90 referenced 1 time by &fcb4
.cfc90
    bcc cfc9c                                                         ; fc90: 90 0a       ..
    ldx #7                                                            ; fc92: a2 07       ..
    stx ppi_port_c                                                    ; fc94: 8e 02 b0    ... ; Tape output high, turn the 2.4 kHz tape tone on, speaker high, select colour set 0
    jsr sub_cfcda                                                     ; fc97: 20 da fc     ..
    bmi cfcaf                                                         ; fc9a: 30 13       0.
; &fc9c referenced 1 time by &fc90
.cfc9c
    ldy #4                                                            ; fc9c: a0 04       ..
; &fc9e referenced 1 time by &fcad
.loop_cfc9e
    lda #4                                                            ; fc9e: a9 04       ..
    sta ppi_port_c                                                    ; fca0: 8d 02 b0    ... ; Tape output low, turn the 2.4 kHz tape tone off, speaker high, select colour set 0
    jsr sub_cfcd8                                                     ; fca3: 20 d8 fc     ..
    inc ppi_port_c                                                    ; fca6: ee 02 b0    ...
    jsr sub_cfcd8                                                     ; fca9: 20 d8 fc     ..
    dey                                                               ; fcac: 88          .
    bne loop_cfc9e                                                    ; fcad: d0 ef       ..
; &fcaf referenced 1 time by &fc9a
.cfcaf
    sec                                                               ; fcaf: 38          8
    ror l00c0                                                         ; fcb0: 66 c0       f.
    dec l00c1                                                         ; fcb2: c6 c1       ..
    bne cfc90                                                         ; fcb4: d0 da       ..
    ldy l00c3                                                         ; fcb6: a4 c3       ..
    ldx l00ec                                                         ; fcb8: a6 ec       ..
    pla                                                               ; fcba: 68          h
    plp                                                               ; fcbb: 28          (
    rts                                                               ; fcbc: 60          `

; &fcbd referenced 2 times by &fba4, &fbf8
.sub_cfcbd
    ldx #0                                                            ; fcbd: a2 00       ..
    ldy ppi_port_c                                                    ; fcbf: ac 02 b0    ...
; &fcc2 referenced 1 time by &fcc8
.loop_cfcc2
    inx                                                               ; fcc2: e8          .
    beq return_9                                                      ; fcc3: f0 07       ..
    jsr sub_cfccd                                                     ; fcc5: 20 cd fc     ..
    beq loop_cfcc2                                                    ; fcc8: f0 f8       ..
    cpx #8                                                            ; fcca: e0 08       ..
; &fccc referenced 1 time by &fcc3
.return_9
    rts                                                               ; fccc: 60          `

; &fccd referenced 2 times by &fc0a, &fcc5
.sub_cfccd
    sty l00c5                                                         ; fccd: 84 c5       ..
    lda ppi_port_c                                                    ; fccf: ad 02 b0    ...
    tay                                                               ; fcd2: a8          .
    eor l00c5                                                         ; fcd3: 45 c5       E.
    and #&20 ; ' '                                                    ; fcd5: 29 20       )
    rts                                                               ; fcd7: 60          `

; &fcd8 referenced 3 times by &fc88, &fca3, &fca9
.sub_cfcd8
    ldx #0                                                            ; fcd8: a2 00       ..
; &fcda referenced 1 time by &fc97
.sub_cfcda
    lda #&10                                                          ; fcda: a9 10       ..
; &fcdc referenced 2 times by &fcdf, &fce7
.cfcdc
    bit ppi_port_c                                                    ; fcdc: 2c 02 b0    ,..
    beq cfcdc                                                         ; fcdf: f0 fb       ..
; &fce1 referenced 1 time by &fce4
.loop_cfce1
    bit ppi_port_c                                                    ; fce1: 2c 02 b0    ,..
    bne loop_cfce1                                                    ; fce4: d0 fb       ..
    dex                                                               ; fce6: ca          .
    bpl cfcdc                                                         ; fce7: 10 f3       ..
    rts                                                               ; fce9: 60          `

; &fcea referenced 2 times by &fda8, &fe5c
.sub_cfcea
    cmp #6                                                            ; fcea: c9 06       ..
    beq cfd0b                                                         ; fcec: f0 1d       ..
    cmp #&15                                                          ; fcee: c9 15       ..
    beq cfd11                                                         ; fcf0: f0 1f       ..
    ldy cursor_column                                                 ; fcf2: a4 e0       ..
    bmi return_10                                                     ; fcf4: 30 23       0#
    cmp #&1b                                                          ; fcf6: c9 1b       ..
    beq cfd0b                                                         ; fcf8: f0 11       ..
    cmp #7                                                            ; fcfa: c9 07       ..
    beq wrch_bell                                                     ; fcfc: f0 1c       .. ; Sound the bell (as OSWRCH does for character 7)
    jsr wrch_invert_cursor                                            ; fcfe: 20 44 fd     D.
    ldx #&0a                                                          ; fd01: a2 0a       .. ; X=index to search down from (#0A for OSWRCH's control codes, #17 for OSRDCH's keys)
    jsr find_control_code                                             ; fd03: 20 c5 fe     .. ; Find A in the table of control codes and keys at #FECB, from X down (X is its index)
    bne cfd29                                                         ; fd06: d0 21       .!
    jmp cfeb7                                                         ; fd08: 4c b7 fe    L..

; &fd0b referenced 2 times by &fcec, &fcf8
.cfd0b
    clc                                                               ; fd0b: 18          .
    ldx #0                                                            ; fd0c: a2 00       ..
    stx ppi_port_a                                                    ; fd0e: 8e 00 b0    ... ; Select text mode
; &fd11 referenced 1 time by &fcf0
.cfd11
    ldx #2                                                            ; fd11: a2 02       ..
; &fd13 referenced 1 time by &fd94
.sub_cfd13
    php                                                               ; fd13: 08          .
    asl screen_line_address,x                                         ; fd14: 16 de       ..
    plp                                                               ; fd16: 28          (
    ror screen_line_address,x                                         ; fd17: 76 de       v.
; &fd19 referenced 1 time by &fcf4
.return_10
    rts                                                               ; fd19: 60          `

; ***************************************************************************************
; Sound the bell (as OSWRCH does for character 7)
; ***************************************************************************************
; &fd1a referenced 1 time by &fcfc
.wrch_bell
    lda #5                                                            ; fd1a: a9 05       ..
    tay                                                               ; fd1c: a8          .  ; Y=5
; &fd1d referenced 1 time by &fd26
.loop_cfd1d
    sta ppi_control                                                   ; fd1d: 8d 03 b0    ...
; &fd20 referenced 1 time by &fd21
.loop_cfd20
    dex                                                               ; fd20: ca          .
    bne loop_cfd20                                                    ; fd21: d0 fd       ..
    eor #1                                                            ; fd23: 49 01       I.
    iny                                                               ; fd25: c8          .
    bpl loop_cfd1d                                                    ; fd26: 10 f5       ..
    rts                                                               ; fd28: 60          `

; &fd29 referenced 1 time by &fd06
.cfd29
    cmp #&20 ; ' '                                                    ; fd29: c9 20       .
    bcc wrch_invert_cursor                                            ; fd2b: 90 17       ..
    adc #&1f                                                          ; fd2d: 69 1f       i. ; Carry is set, so adding 32
    bmi cfd33                                                         ; fd2f: 30 02       0.
    eor #&60 ; '`'                                                    ; fd31: 49 60       I`
; &fd33 referenced 1 time by &fd2f
.cfd33
    jsr wait_for_flyback_or_now                                       ; fd33: 20 6b fe     k. ; Wait for the field flyback, unless it's under way
    sta (screen_line_address),y                                       ; fd36: 91 de       ..
.wrch_forward_space
    iny                                                               ; fd38: c8          .
    cpy #&20 ; ' '                                                    ; fd39: c0 20       .
    bcc cfd42                                                         ; fd3b: 90 05       ..
    jsr sub_cfdec                                                     ; fd3d: 20 ec fd     ..
.wrch_return
    ldy #0                                                            ; fd40: a0 00       ..
; &fd42 referenced 6 times by &fd3b, &fd5a, &fd5f, &fd67, &fd85, &fd8a
.cfd42
    sty cursor_column                                                 ; fd42: 84 e0       ..
; &fd44 referenced 3 times by &fcfe, &fd2b, &fd97
.wrch_invert_cursor
    pha                                                               ; fd44: 48          H
    jsr wait_for_flyback_or_now                                       ; fd45: 20 6b fe     k. ; Wait for the field flyback, unless it's under way
    lda (screen_line_address),y                                       ; fd48: b1 de       ..
    eor cursor_mask                                                   ; fd4a: 45 e1       E.
    sta (screen_line_address),y                                       ; fd4c: 91 de       ..
    pla                                                               ; fd4e: 68          h
    rts                                                               ; fd4f: 60          `

.wrch_delete
    jsr sub_cfe35                                                     ; fd50: 20 35 fe     5.
    lda #&20 ; ' '                                                    ; fd53: a9 20       .
    jsr wait_for_flyback_or_now                                       ; fd55: 20 6b fe     k. ; Wait for the field flyback, unless it's under way
    sta (screen_line_address),y                                       ; fd58: 91 de       ..
    bpl cfd42                                                         ; fd5a: 10 e6       ..
.wrch_backspace
    jsr sub_cfe35                                                     ; fd5c: 20 35 fe     5.
    jmp cfd42                                                         ; fd5f: 4c 42 fd    LB.

.wrch_line_feed
    jsr sub_cfdec                                                     ; fd62: 20 ec fd     ..
; &fd65 referenced 1 time by &fe46
.cfd65
    ldy cursor_column                                                 ; fd65: a4 e0       ..
    bpl cfd42                                                         ; fd67: 10 d9       ..
.wrch_clear_screen
    ldy #&80                                                          ; fd69: a0 80       ..
    sty cursor_mask                                                   ; fd6b: 84 e1       ..
    ldy #0                                                            ; fd6d: a0 00       ..
    sty ppi_port_a                                                    ; fd6f: 8c 00 b0    ... ; Select text mode
    lda #&20 ; ' '                                                    ; fd72: a9 20       .
; &fd74 referenced 1 time by &fd7b
.loop_cfd74
    sta l8000,y                                                       ; fd74: 99 00 80    ...
    sta l8100,y                                                       ; fd77: 99 00 81    ...
    iny                                                               ; fd7a: c8          .
    bne loop_cfd74                                                    ; fd7b: d0 f7       ..
.wrch_home
    lda #&80                                                          ; fd7d: a9 80       ..
    ldy #0                                                            ; fd7f: a0 00       ..
    sta screen_line_address+1                                         ; fd81: 85 df       ..
    sty screen_line_address                                           ; fd83: 84 de       ..
    beq cfd42                                                         ; fd85: f0 bb       .. ; ALWAYS branch

.wrch_up
    jsr sub_cfe3a                                                     ; fd87: 20 3a fe     :.
    jmp cfd42                                                         ; fd8a: 4c 42 fd    LB.

.wrch_page_mode_on
    clc                                                               ; fd8d: 18          .
    lda #&10                                                          ; fd8e: a9 10       ..
    sta page_mode_count                                               ; fd90: 85 e6       ..
.wrch_page_mode_off
    ldx #8                                                            ; fd92: a2 08       ..
    jsr sub_cfd13                                                     ; fd94: 20 13 fd     ..
    jmp wrch_invert_cursor                                            ; fd97: 4c 44 fd    LD.

.rdch_lock
    lda lock_flag                                                     ; fd9a: a5 e7       ..
    eor #&60 ; '`'                                                    ; fd9c: 49 60       I`
    sta lock_flag                                                     ; fd9e: 85 e7       ..
    bcs cfdab                                                         ; fda0: b0 09       ..
.rdch_cursor
    and #5                                                            ; fda2: 29 05       ).
    rol ppi_port_b                                                    ; fda4: 2e 01 b0    ...
    rol a                                                             ; fda7: 2a          *
    jsr sub_cfcea                                                     ; fda8: 20 ea fc     ..
; &fdab referenced 1 time by &fda0
.cfdab
    jmp cfe9a                                                         ; fdab: 4c 9a fe    L..

.rdch_copy
    ldy cursor_column                                                 ; fdae: a4 e0       ..
    jsr wait_for_flyback_or_now                                       ; fdb0: 20 6b fe     k. ; Wait for the field flyback, unless it's under way
    lda (screen_line_address),y                                       ; fdb3: b1 de       ..
    eor cursor_mask                                                   ; fdb5: 45 e1       E.
    bmi cfdbb                                                         ; fdb7: 30 02       0.
    eor #&60 ; '`'                                                    ; fdb9: 49 60       I`
; &fdbb referenced 1 time by &fdb7
.cfdbb
    sbc #&20 ; ' '                                                    ; fdbb: e9 20       .
    jmp cfde9                                                         ; fdbd: 4c e9 fd    L..

.rdch_delete
    lda #&5f ; '_'                                                    ; fdc0: a9 5f       ._
.rdch_keys_59_to_63
    eor #&20 ; ' '                                                    ; fdc2: 49 20       I
    bne cfde9                                                         ; fdc4: d0 23       .#
.rdch_letters
    eor lock_flag                                                     ; fdc6: 45 e7       E.
; &fdc8 referenced 1 time by &fdd4
.rdch_at
    bit ppi_port_b                                                    ; fdc8: 2c 01 b0    ,.. ; Test the SHIFT key
    bmi cfdcf                                                         ; fdcb: 30 02       0.
    eor #&60 ; '`'                                                    ; fdcd: 49 60       I`
; &fdcf referenced 1 time by &fdcb
.cfdcf
    jmp rdch_space_or_zero                                            ; fdcf: 4c df fd    L..

.rdch_keys_1_to_4
    adc #&39 ; '9'                                                    ; fdd2: 69 39       i9
    bcc rdch_at                                                       ; fdd4: 90 f2       ..
.rdch_keys_28_to_31
    eor #&10                                                          ; fdd6: 49 10       I.
.rdch_digits
    bit ppi_port_b                                                    ; fdd8: 2c 01 b0    ,.. ; Test the SHIFT key
    bmi rdch_space_or_zero                                            ; fddb: 30 02       0.
    eor #&10                                                          ; fddd: 49 10       I.
; &fddf referenced 2 times by &fdcf, &fddb
.rdch_space_or_zero
    clc                                                               ; fddf: 18          .
    adc #&20 ; ' '                                                    ; fde0: 69 20       i
.rdch_keys_8_to_13
    bit ppi_port_b                                                    ; fde2: 2c 01 b0    ,.. ; Test the CTRL key
    bvs cfde9                                                         ; fde5: 70 02       p.
    and #&1f                                                          ; fde7: 29 1f       ).
; &fde9 referenced 3 times by &fdbd, &fdc4, &fde5
.cfde9
    jmp restore_xy_and_return                                         ; fde9: 4c 60 fe    L`. ; Restore X and Y from #E4 and #E5, pull the flags and return (as OSWRCH and OSRDCH end)

; &fdec referenced 2 times by &fd3d, &fd62
.sub_cfdec
    lda screen_line_address                                           ; fdec: a5 de       ..
    ldy screen_line_address+1                                         ; fdee: a4 df       ..
    cpy #&81                                                          ; fdf0: c0 81       ..
    bcc cfe2c                                                         ; fdf2: 90 38       .8
    cmp #&e0                                                          ; fdf4: c9 e0       ..
    bcc cfe2c                                                         ; fdf6: 90 34       .4
    ldy page_mode_count                                               ; fdf8: a4 e6       ..
    bmi cfe08                                                         ; fdfa: 30 0c       0.
    dey                                                               ; fdfc: 88          .
    bne cfe06                                                         ; fdfd: d0 07       ..
; &fdff referenced 1 time by &fe02
.loop_cfdff
    jsr scan_keyboard                                                 ; fdff: 20 71 fe     q. ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcs loop_cfdff                                                    ; fe02: b0 fb       ..
    ldy #&10                                                          ; fe04: a0 10       ..
; &fe06 referenced 1 time by &fdfd
.cfe06
    sty page_mode_count                                               ; fe06: 84 e6       ..
; &fe08 referenced 1 time by &fdfa
.cfe08
    ldy #&20 ; ' '                                                    ; fe08: a0 20       .
    jsr wait_for_flyback                                              ; fe0a: 20 66 fe     f. ; Wait for the start of the next field flyback
; &fe0d referenced 1 time by &fe14
.loop_cfe0d
    lda l8000,y                                                       ; fe0d: b9 00 80    ...
    sta l7fe0,y                                                       ; fe10: 99 e0 7f    ...
    iny                                                               ; fe13: c8          .
    bne loop_cfe0d                                                    ; fe14: d0 f7       ..
    jsr wait_for_flyback_or_now                                       ; fe16: 20 6b fe     k. ; Wait for the field flyback, unless it's under way
; &fe19 referenced 1 time by &fe20
.loop_cfe19
    lda l8100,y                                                       ; fe19: b9 00 81    ...
    sta l80e0,y                                                       ; fe1c: 99 e0 80    ...
    iny                                                               ; fe1f: c8          .
    bne loop_cfe19                                                    ; fe20: d0 f7       ..
    ldy #&1f                                                          ; fe22: a0 1f       ..
    lda #&20 ; ' '                                                    ; fe24: a9 20       .
; &fe26 referenced 1 time by &fe29
.loop_cfe26
    sta (screen_line_address),y                                       ; fe26: 91 de       ..
    dey                                                               ; fe28: 88          .
    bpl loop_cfe26                                                    ; fe29: 10 fb       ..
    rts                                                               ; fe2b: 60          `

; &fe2c referenced 2 times by &fdf2, &fdf6
.cfe2c
    adc #&20 ; ' '                                                    ; fe2c: 69 20       i
    sta screen_line_address                                           ; fe2e: 85 de       ..
    bne return_11                                                     ; fe30: d0 02       ..
    inc screen_line_address+1                                         ; fe32: e6 df       ..
; &fe34 referenced 1 time by &fe30
.return_11
    rts                                                               ; fe34: 60          `

; &fe35 referenced 2 times by &fd50, &fd5c
.sub_cfe35
    dey                                                               ; fe35: 88          .
    bpl return_12                                                     ; fe36: 10 19       ..
    ldy #&1f                                                          ; fe38: a0 1f       ..
; &fe3a referenced 1 time by &fd87
.sub_cfe3a
    lda screen_line_address                                           ; fe3a: a5 de       ..
    bne cfe49                                                         ; fe3c: d0 0b       ..
    ldx screen_line_address+1                                         ; fe3e: a6 df       ..
    cpx #&80                                                          ; fe40: e0 80       ..
    bne cfe49                                                         ; fe42: d0 05       ..
    pla                                                               ; fe44: 68          h
    pla                                                               ; fe45: 68          h
    jmp cfd65                                                         ; fe46: 4c 65 fd    Le.

; &fe49 referenced 2 times by &fe3c, &fe42
.cfe49
    sbc #&20 ; ' '                                                    ; fe49: e9 20       .
    sta screen_line_address                                           ; fe4b: 85 de       ..
    bcs return_12                                                     ; fe4d: b0 02       ..
    dec screen_line_address+1                                         ; fe4f: c6 df       ..
; &fe51 referenced 2 times by &fe36, &fe4d
.return_12
    rts                                                               ; fe51: 60          `

; ***************************************************************************************
; Write character A (the kernel's OSWRCH, WRCVEC's default)
; ***************************************************************************************
.kernel_wrch
    jsr send_to_printer                                               ; fe52: 20 fb fe     .. ; Send A to the printer if it's on (2 turns it on and 3 off; the character at #FE isn't sent)
    php                                                               ; fe55: 08          .
    pha                                                               ; fe56: 48          H
    cld                                                               ; fe57: d8          .
    sty l00e5                                                         ; fe58: 84 e5       ..
    stx l00e4                                                         ; fe5a: 86 e4       ..
    jsr sub_cfcea                                                     ; fe5c: 20 ea fc     ..
    pla                                                               ; fe5f: 68          h
; ***************************************************************************************
; Restore X and Y from #E4 and #E5, pull the flags and return (as OSWRCH and OSRDCH
; end)
; ***************************************************************************************
; &fe60 referenced 1 time by &fde9
.restore_xy_and_return
    ldx l00e4                                                         ; fe60: a6 e4       ..
    ldy l00e5                                                         ; fe62: a4 e5       ..
    plp                                                               ; fe64: 28          (
    rts                                                               ; fe65: 60          `

; ***************************************************************************************
; Wait for the start of the next field flyback
; ***************************************************************************************
; &fe66 referenced 4 times by &f14f, &fb83, &fe0a, &fe69
.wait_for_flyback
    bit ppi_port_c                                                    ; fe66: 2c 02 b0    ,.. ; Test the field sync
    bpl wait_for_flyback                                              ; fe69: 10 fb       .. ; Wait for the start of the next field flyback
; ***************************************************************************************
; Wait for the field flyback, unless it's under way
; ***************************************************************************************
; &fe6b referenced 6 times by &fd33, &fd45, &fd55, &fdb0, &fe16, &fe6e
.wait_for_flyback_or_now
    bit ppi_port_c                                                    ; fe6b: 2c 02 b0    ,.. ; Test the field sync
    bmi wait_for_flyback_or_now                                       ; fe6e: 30 fb       0. ; Wait for the field flyback, unless it's under way
    rts                                                               ; fe70: 60          `

; ***************************************************************************************
; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus
; 32
; ***************************************************************************************
; &fe71 referenced 4 times by &fdff, &fe9f, &fea7, &feac
.scan_keyboard
    ldy #&3b ; ';'                                                    ; fe71: a0 3b       .;
    clc                                                               ; fe73: 18          .
    lda #&20 ; ' '                                                    ; fe74: a9 20       .
; &fe76 referenced 1 time by &fe91
.loop_cfe76
    ldx #&0a                                                          ; fe76: a2 0a       ..
; &fe78 referenced 1 time by &fe82
.loop_cfe78
    bit ppi_port_b                                                    ; fe78: 2c 01 b0    ,..
    beq cfe85                                                         ; fe7b: f0 08       ..
    inc ppi_port_a                                                    ; fe7d: ee 00 b0    ... ; Select the next keyboard row
    dey                                                               ; fe80: 88          .
    dex                                                               ; fe81: ca          .
    bne loop_cfe78                                                    ; fe82: d0 f4       ..
    lsr a                                                             ; fe84: 4a          J
; &fe85 referenced 1 time by &fe7b
.cfe85
    php                                                               ; fe85: 08          .
    pha                                                               ; fe86: 48          H
    lda ppi_port_a                                                    ; fe87: ad 00 b0    ...
    and #&f0                                                          ; fe8a: 29 f0       ).
    sta ppi_port_a                                                    ; fe8c: 8d 00 b0    ... ; Select keyboard row 0
    pla                                                               ; fe8f: 68          h
    plp                                                               ; fe90: 28          (
    bne loop_cfe76                                                    ; fe91: d0 e3       ..
    rts                                                               ; fe93: 60          `

; ***************************************************************************************
; Read a character into A (the kernel's OSRDCH, RDCVEC's default)
; ***************************************************************************************
.kernel_rdch
    php                                                               ; fe94: 08          .
    cld                                                               ; fe95: d8          .
    stx l00e4                                                         ; fe96: 86 e4       ..
    sty l00e5                                                         ; fe98: 84 e5       ..
; &fe9a referenced 2 times by &fdab, &fea2
.cfe9a
    bit ppi_port_c                                                    ; fe9a: 2c 02 b0    ,.. ; Test the REPT key
    bvc cfea4                                                         ; fe9d: 50 05       P.
    jsr scan_keyboard                                                 ; fe9f: 20 71 fe     q. ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcc cfe9a                                                         ; fea2: 90 f6       ..
; &fea4 referenced 1 time by &fe9d
.cfea4
    jsr wait_tenth_second                                             ; fea4: 20 8a fb     .. ; Wait for six field flybacks (a tenth of a second)
; &fea7 referenced 2 times by &feaa, &feaf
.cfea7
    jsr scan_keyboard                                                 ; fea7: 20 71 fe     q. ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcs cfea7                                                         ; feaa: b0 fb       ..
    jsr scan_keyboard                                                 ; feac: 20 71 fe     q. ; Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32
    bcs cfea7                                                         ; feaf: b0 f6       ..
    tya                                                               ; feb1: 98          .  ; A=character
    ldx #&17                                                          ; feb2: a2 17       .. ; X=index to search down from (#0A for OSWRCH's control codes, #17 for OSRDCH's keys)
    jsr find_control_code                                             ; feb4: 20 c5 fe     .. ; Find A in the table of control codes and keys at #FECB, from X down (X is its index)
; &feb7 referenced 1 time by &fd08
.cfeb7
    lda wrch_control_code_handlers,x                                  ; feb7: bd e3 fe    ...
    sta l00e2                                                         ; feba: 85 e2       ..
    lda #&fd                                                          ; febc: a9 fd       ..
    sta l00e3                                                         ; febe: 85 e3       ..
    tya                                                               ; fec0: 98          .
    jmp (l00e2)                                                       ; fec1: 6c e2 00    l..

; &fec4 referenced 1 time by &fec8
.loop_cfec4
    dex                                                               ; fec4: ca          .  ; X=index to search down from (#0A for OSWRCH's control codes, #17 for OSRDCH's keys)
; ***************************************************************************************
; Find A in the table of control codes and keys at #FECB, from X down (X is its index)
; 
; On Entry:
;     A: character
;     X: index to search down from (#0A for OSWRCH's control codes, #17 for OSRDCH's
;        keys)
; ***************************************************************************************
; &fec5 referenced 2 times by &fd03, &feb4
.find_control_code
    cmp wrch_control_codes,x                                          ; fec5: dd cb fe    ...
    bcc loop_cfec4                                                    ; fec8: 90 fa       ..
    rts                                                               ; feca: 60          `

; &fecb referenced 1 time by &fec5
.wrch_control_codes
    equb 0, 8, 9, &0a, &0b, &0c, &0d, &0e, &0f, &1e, &7f              ; fecb: 00 08 09... ...
.rdch_keys
    equb 0, 1, 5, 6, 8, &0e, &0f, &10, &11, &1c, &20, &21, &3b        ; fed6: 00 01 05... ...
; &fee3 referenced 1 time by &feb7
.wrch_control_code_handlers
    equb <wrch_invert_cursor                                          ; fee3: 44          D
    equb <wrch_backspace                                              ; fee4: 5c          \
    equb <wrch_forward_space                                          ; fee5: 38          8
    equb <wrch_line_feed                                              ; fee6: 62          b
    equb <wrch_up                                                     ; fee7: 87          .
    equb <wrch_clear_screen                                           ; fee8: 69          i
    equb <wrch_return                                                 ; fee9: 40          @
    equb <wrch_page_mode_on                                           ; feea: 8d          .
    equb <wrch_page_mode_off                                          ; feeb: 92          .
    equb <wrch_home                                                   ; feec: 7d          }
    equb <wrch_delete                                                 ; feed: 50          P
.rdch_key_handlers
    equb <rdch_space_or_zero                                          ; feee: df          .
    equb <rdch_keys_1_to_4                                            ; feef: d2          .
    equb <rdch_lock                                                   ; fef0: 9a          .
    equb <rdch_cursor                                                 ; fef1: a2          .
    equb <rdch_keys_8_to_13                                           ; fef2: e2          .
    equb <rdch_copy                                                   ; fef3: ae          .
    equb <rdch_delete                                                 ; fef4: c0          .
    equb <rdch_space_or_zero                                          ; fef5: df          .
    equb <rdch_digits                                                 ; fef6: d8          .
    equb <rdch_keys_28_to_31                                          ; fef7: d6          .
    equb <rdch_at                                                     ; fef8: c8          .
    equb <rdch_letters                                                ; fef9: c6          .
    equb <rdch_keys_59_to_63                                          ; fefa: c2          .

; ***************************************************************************************
; Send A to the printer if it's on (2 turns it on and 3 off; the character at #FE isn't
; sent)
; 
; On Entry:
;     A: character
; ***************************************************************************************
; &fefb referenced 1 time by &fe52
.send_to_printer
    pha                                                               ; fefb: 48          H
    cmp #2                                                            ; fefc: c9 02       ..
    beq cff27                                                         ; fefe: f0 27       .'
    cmp #3                                                            ; ff00: c9 03       ..
    beq cff38                                                         ; ff02: f0 34       .4
    cmp printer_ignore_char                                           ; ff04: c5 fe       ..
    beq cff36                                                         ; ff06: f0 2e       ..
    lda via_pcr                                                       ; ff08: ad 0c b8    ...
    and #&0e                                                          ; ff0b: 29 0e       ).
    beq cff36                                                         ; ff0d: f0 27       .'
    pla                                                               ; ff0f: 68          h
; &ff10 referenced 1 time by &ff13
.loop_cff10
    bit via_register_a                                                ; ff10: 2c 01 b8    ,..
    bmi loop_cff10                                                    ; ff13: 30 fb       0.
    sta via_register_a                                                ; ff15: 8d 01 b8    ...
    pha                                                               ; ff18: 48          H
    lda via_pcr                                                       ; ff19: ad 0c b8    ...
    and #&f0                                                          ; ff1c: 29 f0       ).
    ora #&0c                                                          ; ff1e: 09 0c       ..
    sta via_pcr                                                       ; ff20: 8d 0c b8    ...
    ora #2                                                            ; ff23: 09 02       ..
    bne cff33                                                         ; ff25: d0 0c       .. ; ALWAYS branch

; &ff27 referenced 1 time by &fefe
.cff27
    lda #&7f                                                          ; ff27: a9 7f       ..
    sta via_ddra                                                      ; ff29: 8d 03 b8    ...
    lda via_pcr                                                       ; ff2c: ad 0c b8    ...
    and #&f0                                                          ; ff2f: 29 f0       ).
    ora #&0e                                                          ; ff31: 09 0e       ..
; &ff33 referenced 2 times by &ff25, &ff3d
.cff33
    sta via_pcr                                                       ; ff33: 8d 0c b8    ...
; &ff36 referenced 2 times by &ff06, &ff0d
.cff36
    pla                                                               ; ff36: 68          h
    rts                                                               ; ff37: 60          `

; &ff38 referenced 1 time by &ff02
.cff38
    lda via_pcr                                                       ; ff38: ad 0c b8    ...
    and #&f0                                                          ; ff3b: 29 f0       ).
    bcs cff33                                                         ; ff3d: b0 f4       ..
.reset
    ; Copy 24 bytes of memory from default_vectors to irqvec
    ldx #&17                                                          ; ff3f: a2 17       ..
; &ff41 referenced 1 time by &ff48
.loop_cff41
    lda default_vectors,x                                             ; ff41: bd 9a ff    ...
    sta irqvec,x                                                      ; ff44: 9d 04 02    ...
    dex                                                               ; ff47: ca          .
    bpl loop_cff41                                                    ; ff48: 10 f7       ..
    txs                                                               ; ff4a: 9a          .
    txa                                                               ; ff4b: 8a          .
    inx                                                               ; ff4c: e8          .
    stx nomon_flag                                                    ; ff4d: 86 ea       ..
    stx cursor_mask                                                   ; ff4f: 86 e1       ..
    stx lock_flag                                                     ; ff51: 86 e7       ..
    ldx #&33 ; '3'                                                    ; ff53: a2 33       .3
; &ff55 referenced 1 time by &ff59
.loop_cff55
    sta l02eb,x                                                       ; ff55: 9d eb 02    ...
    dex                                                               ; ff58: ca          .
    bpl loop_cff55                                                    ; ff59: 10 fa       ..
    lda #&0a                                                          ; ff5b: a9 0a       ..
    sta printer_ignore_char                                           ; ff5d: 85 fe       ..
    lda #&8a                                                          ; ff5f: a9 8a       ..
    sta ppi_control                                                   ; ff61: 8d 03 b0    ... ; Set the 8255's modes: port A output, port B input, port C bits 4-7 input, bits 0-3 output
    lda #7                                                            ; ff64: a9 07       ..
    sta ppi_port_c                                                    ; ff66: 8d 02 b0    ... ; Tape output high, turn the 2.4 kHz tape tone on, speaker high, select colour set 0
    jsr print_inline_string                                           ; ff69: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs 6, &0c, &0f, "ACORN ATOM", &0a, &0a, &0d                     ; ff6c: 06 0c 0f... ...

    lda #&82                                                          ; ff7c: a9 82       ..
    sta text_space_page                                               ; ff7e: 85 12       ..
    cli                                                               ; ff80: 58          X
    lda #&55 ; 'U'                                                    ; ff81: a9 55       .U
    sta l2901                                                         ; ff83: 8d 01 29    ..)
    cmp l2901                                                         ; ff86: cd 01 29    ..)
    bne cff97                                                         ; ff89: d0 0c       ..
    asl a                                                             ; ff8b: 0a          .
    sta l2901                                                         ; ff8c: 8d 01 29    ..)
    cmp l2901                                                         ; ff8f: cd 01 29    ..)
    bne cff97                                                         ; ff92: d0 03       ..
    jmp lc2b2                                                         ; ff94: 4c b2 c2    L..

; &ff97 referenced 2 times by &ff89, &ff92
.cff97
    jmp lc2b6                                                         ; ff97: 4c b6 c2    L..

; &ff9a referenced 1 time by &ff41
.default_vectors
    equw la000                                                        ; ff9a: 00 a0       ..
    equw kernel_cli                                                   ; ff9c: ef f8       ..
    equw kernel_wrch                                                  ; ff9e: 52 fe       R.
    equw kernel_rdch                                                  ; ffa0: 94 fe       ..
    equw kernel_load                                                  ; ffa2: 6e f9       n.
    equw kernel_save                                                  ; ffa4: e5 fa       ..
    equw lc2ac                                                        ; ffa6: ac c2       ..
    equw lc2ac                                                        ; ffa8: ac c2       ..
    equw kernel_bget                                                  ; ffaa: ee fb       ..
    equw kernel_bput                                                  ; ffac: 7c fc       |.
    equw kernel_find                                                  ; ffae: 38 fc       8.
    equw lc278                                                        ; ffb0: 78 c2       x.

.irq_handler
    sta irq_save_a                                                    ; ffb2: 85 ff       ..
    pla                                                               ; ffb4: 68          h
    pha                                                               ; ffb5: 48          H
    and #&10                                                          ; ffb6: 29 10       ).
    bne cffc0                                                         ; ffb8: d0 06       ..
    lda irq_save_a                                                    ; ffba: a5 ff       ..
    pha                                                               ; ffbc: 48          H
    jmp (irqvec)                                                      ; ffbd: 6c 04 02    l..

; &ffc0 referenced 1 time by &ffb8
.cffc0
    lda irq_save_a                                                    ; ffc0: a5 ff       ..
    plp                                                               ; ffc2: 28          (
    php                                                               ; ffc3: 08          .
    jmp (brkvec)                                                      ; ffc4: 6c 02 02    l..

.nmi_handler
    pha                                                               ; ffc7: 48          H
    jmp (nmivec)                                                      ; ffc8: 6c 00 02    l..

; ***************************************************************************************
.OSSHUT
    jmp (shtvec)                                                      ; ffcb: 6c 1a 02    l.. ; Close file Y

; ***************************************************************************************
.OSFIND
    jmp (fndvec)                                                      ; ffce: 6c 18 02    l.. ; Open a file (for input if C=1, output if C=0)

; ***************************************************************************************
; &ffd1 referenced 7 times by &faa1, &faa9, &fb46, &fb4e, &fb5b, &fb6c, &fb75
.OSBPUT
    jmp (bptvec)                                                      ; ffd1: 6c 16 02    l.. ; Write byte A to file Y

; ***************************************************************************************
; &ffd4 referenced 5 times by &f93b, &f9e9, &f9f6, &fbc9, &fbe4
.OSBGET
    jmp (bgtvec)                                                      ; ffd4: 6c 14 02    l.. ; Read a byte from file Y

; ***************************************************************************************
.OSSTAR
    jmp (strvec)                                                      ; ffd7: 6c 12 02    l.. ; Store a file's arguments

; ***************************************************************************************
.OSRDAR
    jmp (rdrvec)                                                      ; ffda: 6c 10 02    l.. ; Read a file's arguments

; ***************************************************************************************
.OSSAVE
    jmp (savvec)                                                      ; ffdd: 6c 0e 02    l.. ; Save a file

; ***************************************************************************************
.OSLOAD
    jmp (lodvec)                                                      ; ffe0: 6c 0c 02    l.. ; Load a file

; ***************************************************************************************
; &ffe3 referenced 2 times by &fc76, &ffe6
.OSRDCH
    jmp (rdcvec)                                                      ; ffe3: 6c 0a 02    l.. ; Read a character

; ***************************************************************************************
.OSECHO
    jsr OSRDCH                                                        ; ffe6: 20 e3 ff     .. ; Read a character ; Read a character and write it
; ***************************************************************************************
.OSASCI
    cmp #&0d                                                          ; ffe9: c9 0d       .. ; A=character read ; Write character
    bne OSWRCH                                                        ; ffeb: d0 07       .. ; Write character
; ***************************************************************************************
; &ffed referenced 4 times by &f9c2, &fa5d, &fa62, &fc79
.OSCRLF
    ; Move the cursor down one line
    lda #&0a                                                          ; ffed: a9 0a       .. ; Write newline (characters 10 and 13)
    jsr OSWRCH                                                        ; ffef: 20 f4 ff     .. ; Write character 10
    lda #&0d                                                          ; fff2: a9 0d       ..
; ***************************************************************************************
; &fff4 referenced 6 times by &f7e3, &f7ff, &f815, &f98e, &ffeb, &ffef
.OSWRCH
    jmp (wrcvec)                                                      ; fff4: 6c 08 02    l.. ; Write character 13

; ***************************************************************************************
.OSCLI
    jmp (comvec)                                                      ; fff7: 6c 06 02    l.. ; Run the command in the input buffer

    equw nmi_handler                                                  ; fffa: c7 ff       ..
    equw reset                                                        ; fffc: 3f ff       ?.
    equw irq_handler                                                  ; fffe: b2 ff       ..
.pydis_end

    assert (<basic_unknown_command) = &50
    assert (<command_assembler) = &a1
    assert (<command_clear) = &7b
    assert (<command_dim) = &ae
    assert (<command_draw) = &42
    assert (<command_move) = &46
    assert (<command_old) = &31
    assert (<command_plot) = &4e
    assert (<command_wait) = &4c
    assert (<cos_error) = &26
    assert (<dos) = &00
    assert (<plot_mode_0) = &e2
    assert (<plot_mode_1) = &3b
    assert (<plot_mode_2) = &54
    assert (<plot_mode_3) = &6d
    assert (<plot_mode_4) = &aa
    assert (<rdch_at) = &c8
    assert (<rdch_copy) = &ae
    assert (<rdch_cursor) = &a2
    assert (<rdch_delete) = &c0
    assert (<rdch_digits) = &d8
    assert (<rdch_keys_1_to_4) = &d2
    assert (<rdch_keys_28_to_31) = &d6
    assert (<rdch_keys_59_to_63) = &c2
    assert (<rdch_keys_8_to_13) = &e2
    assert (<rdch_letters) = &c6
    assert (<rdch_lock) = &9a
    assert (<rdch_space_or_zero) = &df
    assert (<star_cat) = &2a
    assert (<star_fload) = &55
    assert (<star_load) = &58
    assert (<star_mon) = &1a
    assert (<star_nomon) = &19
    assert (<star_run) = &20
    assert (<star_save) = &bb
    assert (<wrch_backspace) = &5c
    assert (<wrch_clear_screen) = &69
    assert (<wrch_delete) = &50
    assert (<wrch_forward_space) = &38
    assert (<wrch_home) = &7d
    assert (<wrch_invert_cursor) = &44
    assert (<wrch_line_feed) = &62
    assert (<wrch_page_mode_off) = &92
    assert (<wrch_page_mode_on) = &8d
    assert (<wrch_return) = &40
    assert (<wrch_up) = &87
    assert (>basic_unknown_command) = &c5
    assert (>command_assembler) = &f2
    assert (>command_clear) = &f6
    assert (>command_dim) = &f0
    assert (>command_draw) = &f5
    assert (>command_move) = &f5
    assert (>command_old) = &f5
    assert (>command_plot) = &f5
    assert (>command_wait) = &f1
    assert (>cos_error) = &f9
    assert (>dos) = &e0
    assert (>plot_mode_0) = &f6
    assert (>plot_mode_1) = &f7
    assert (>plot_mode_2) = &f7
    assert (>plot_mode_3) = &f7
    assert (>plot_mode_4) = &f7
    assert (>star_cat) = &fa
    assert (>star_fload) = &f9
    assert (>star_load) = &f9
    assert (>star_mon) = &fa
    assert (>star_nomon) = &fa
    assert (>star_run) = &fa
    assert (>star_save) = &fa
    assert (irq_handler) = &ffb2
    assert (kernel_bget) = &fbee
    assert (kernel_bput) = &fc7c
    assert (kernel_cli) = &f8ef
    assert (kernel_find) = &fc38
    assert (kernel_load) = &f96e
    assert (kernel_rdch) = &fe94
    assert (kernel_save) = &fae5
    assert (kernel_wrch) = &fe52
    assert (la000) = &a000
    assert (lc278) = &c278
    assert (lc2ac) = &c2ac
    assert (nmi_handler) = &ffc7
    assert (reset) = &ff3f

endsection

; Label references by decreasing frequency:
;     l0052:                       24
;     l005a:                       17
;     cf49b:                       15
;     l0053:                       15
;     l005f:                       15
;     parsing_ptr_offset:          14
;     ppi_port_c:                  14
;     cf291:                       13
;     l005b:                       13
;     screen_line_address:         13
;     parsing_ptr_low:             12
;     basic_error_number:          10
;     l0060:                       10
;     print_inline_string:         10
;     return_2:                    10
;     cf49a:                        8
;     int_workspace_stack_low:      8
;     int_workspace_stack_mid1:     8
;     l0059:                        8
;     l00cf:                        8
;     OSBPUT:                       7
;     basic_line_number:            7
;     l000f:                        7
;     l0057:                        7
;     l005c:                        7
;     l005d:                        7
;     l005e:                        7
;     l0066:                        7
;     l00c9:                        7
;     l00cb:                        7
;     l00d0:                        7
;     l00d2:                        7
;     ppi_port_b:                   7
;     OSWRCH:                       6
;     cf0d6:                        6
;     cfd42:                        6
;     input_buffer:                 6
;     l0054:                        6
;     l0067:                        6
;     l00c0:                        6
;     l00c3:                        6
;     l00cc:                        6
;     l00dc:                        6
;     l00dd:                        6
;     lc8bc:                        6
;     ppi_port_a:                   6
;     via_pcr:                      6
;     wait_for_flyback_or_now:      6
;     workspace_stack_pointer:      6
;     OSBGET:                       5
;     cf9a2:                        5
;     cfb8e:                        5
;     l0068:                        5
;     l00ce:                        5
;     sub_cfa76:                    5
;     OSCRLF:                       4
;     cf4d7:                        4
;     cfc3e:                        4
;     cursor_column:                4
;     cursor_mask:                  4
;     l00ca:                        4
;     l00cd:                        4
;     l00d3:                        4
;     l00d5:                        4
;     l00db:                        4
;     l00e8:                        4
;     l00ec:                        4
;     l0321:                        4
;     l0331:                        4
;     l034c:                        4
;     l2901:                        4
;     lc4e4:                        4
;     lca4c:                        4
;     lock_flag:                    4
;     nomon_flag:                   4
;     scan_keyboard:                4
;     skip_input_buffer_spaces:     4
;     text_space_page:              4
;     wait_for_flyback:             4
;     cf048:                        3
;     cf060:                        3
;     cf34a:                        3
;     cf360:                        3
;     cf36b:                        3
;     cf827:                        3
;     cfb83:                        3
;     cfc40:                        3
;     cfde9:                        3
;     irq_save_a:                   3
;     l0055:                        3
;     l0064:                        3
;     l0065:                        3
;     l0069:                        3
;     l006a:                        3
;     l00d1:                        3
;     l00d4:                        3
;     l00d6:                        3
;     l00e4:                        3
;     l00e5:                        3
;     l00ed:                        3
;     l02eb:                        3
;     l03c1:                        3
;     l8000:                        3
;     l8100:                        3
;     lc55b:                        3
;     lc78b:                        3
;     page_mode_count:              3
;     print_hex:                    3
;     printer_ignore_char:          3
;     sub_cf678:                    3
;     sub_cf893:                    3
;     sub_cfa65:                    3
;     sub_cfcd8:                    3
;     wrch_invert_cursor:           3
;     OSRDCH:                       2
;     cf2ef:                        2
;     cf311:                        2
;     cf396:                        2
;     cf511:                        2
;     cf5fb:                        2
;     cf60f:                        2
;     cf626:                        2
;     cf6a0:                        2
;     cf785:                        2
;     cf891:                        2
;     cf92f:                        2
;     cf94e:                        2
;     cf999:                        2
;     cfa5d:                        2
;     cfa7d:                        2
;     cfb29:                        2
;     cfb9d:                        2
;     cfbb1:                        2
;     cfbe4:                        2
;     cfc6d:                        2
;     cfcdc:                        2
;     cfd0b:                        2
;     cfe2c:                        2
;     cfe49:                        2
;     cfe9a:                        2
;     cfea7:                        2
;     cff33:                        2
;     cff36:                        2
;     cff97:                        2
;     cos_command_table:            2
;     find_control_code:            2
;     irqvec:                       2
;     l0056:                        2
;     l0061:                        2
;     l00c1:                        2
;     l00c2:                        2
;     l00c4:                        2
;     l00c5:                        2
;     l00d8:                        2
;     l00e2:                        2
;     l00e9:                        2
;     l0306:                        2
;     lc231:                        2
;     lc434:                        2
;     lc558:                        2
;     lc5f9:                        2
;     lf11c:                        2
;     lodvec:                       2
;     plot_vector:                  2
;     ppi_control:                  2
;     print_hex_2_bytes:            2
;     rdch_space_or_zero:           2
;     return_12:                    2
;     return_3:                     2
;     return_7:                     2
;     savvec:                       2
;     sub_cf08b:                    2
;     sub_cf376:                    2
;     sub_cf379:                    2
;     sub_cf37e:                    2
;     sub_cf644:                    2
;     sub_cf655:                    2
;     sub_cf7ec:                    2
;     sub_cf818:                    2
;     sub_cf84f:                    2
;     sub_cf992:                    2
;     sub_cfa08:                    2
;     sub_cfb7a:                    2
;     sub_cfbc9:                    2
;     sub_cfbe2:                    2
;     sub_cfc2b:                    2
;     sub_cfcbd:                    2
;     sub_cfccd:                    2
;     sub_cfcea:                    2
;     sub_cfdec:                    2
;     sub_cfe35:                    2
;     via_register_a:               2
;     assembler_mode_masks_high:    1
;     assembler_mode_masks_low:     1
;     assembler_mode_offsets:       1
;     assembler_mode_offsets_2:     1
;     assign_array_variable:        1
;     basic_command_table:          1
;     bgtvec:                       1
;     bit_masks:                    1
;     bptvec:                       1
;     brkvec:                       1
;     cf075:                        1
;     cf0d7:                        1
;     cf107:                        1
;     cf119:                        1
;     cf13e:                        1
;     cf2ff:                        1
;     cf328:                        1
;     cf32b:                        1
;     cf32e:                        1
;     cf3cf:                        1
;     cf3f2:                        1
;     cf42b:                        1
;     cf440:                        1
;     cf454:                        1
;     cf462:                        1
;     cf482:                        1
;     cf4a7:                        1
;     cf4ae:                        1
;     cf4e7:                        1
;     cf4ec:                        1
;     cf527:                        1
;     cf52c:                        1
;     cf548:                        1
;     cf554:                        1
;     cf597:                        1
;     cf5b2:                        1
;     cf5b5:                        1
;     cf5b7:                        1
;     cf5dd:                        1
;     cf60c:                        1
;     cf61c:                        1
;     cf637:                        1
;     cf664:                        1
;     cf66e:                        1
;     cf671:                        1
;     cf68a:                        1
;     cf69e:                        1
;     cf6ab:                        1
;     cf6c2:                        1
;     cf720:                        1
;     cf731:                        1
;     cf736:                        1
;     cf789:                        1
;     cf7df:                        1
;     cf7e9:                        1
;     cf813:                        1
;     cf83f:                        1
;     cf86c:                        1
;     cf88e:                        1
;     cf8bb:                        1
;     cf8f2:                        1
;     cf919:                        1
;     cf946:                        1
;     cf966:                        1
;     cf9c7:                        1
;     cf9db:                        1
;     cf9e0:                        1
;     cf9f2:                        1
;     cfa05:                        1
;     cfa0e:                        1
;     cfa31:                        1
;     cfa38:                        1
;     cfa44:                        1
;     cfa73:                        1
;     cfa86:                        1
;     cfab2:                        1
;     cfad9:                        1
;     cfb0b:                        1
;     cfb0e:                        1
;     cfb73:                        1
;     cfbb4:                        1
;     cfc0f:                        1
;     cfc12:                        1
;     cfc58:                        1
;     cfc63:                        1
;     cfc76:                        1
;     cfc90:                        1
;     cfc9c:                        1
;     cfcaf:                        1
;     cfd11:                        1
;     cfd29:                        1
;     cfd33:                        1
;     cfd65:                        1
;     cfdab:                        1
;     cfdbb:                        1
;     cfdcf:                        1
;     cfe06:                        1
;     cfe08:                        1
;     cfe85:                        1
;     cfea4:                        1
;     cfeb7:                        1
;     cff27:                        1
;     cff38:                        1
;     cffc0:                        1
;     command_assembler:            1
;     command_dim:                  1
;     comvec:                       1
;     default_vectors:              1
;     fndvec:                       1
;     graphics_mode_bytes:          1
;     int_workspace_stack_high:     1
;     int_workspace_stack_mid2:     1
;     l000d:                        1
;     l000e:                        1
;     l00e3:                        1
;     l00fd:                        1
;     l013f:                        1
;     l033c:                        1
;     l03c2:                        1
;     l03c3:                        1
;     l03c4:                        1
;     l7fe0:                        1
;     l80e0:                        1
;     lc2b2:                        1
;     lc2b6:                        1
;     lc2cf:                        1
;     lc31b:                        1
;     lc3c8:                        1
;     lc3cb:                        1
;     lc3f1:                        1
;     lc4f6:                        1
;     lc51d:                        1
;     lc589:                        1
;     lc94f:                        1
;     lc962:                        1
;     lca24:                        1
;     lcd54:                        1
;     lcd9b:                        1
;     lce83:                        1
;     lefff:                        1
;     lf001:                        1
;     lf084:                        1
;     lf154:                        1
;     lf194:                        1
;     lf210:                        1
;     lf250:                        1
;     lf67f:                        1
;     lf6ce:                        1
;     lf7cb:                        1
;     lf8bf:                        1
;     lf9a3:                        1
;     loop_cf062:                   1
;     loop_cf06d:                   1
;     loop_cf29c:                   1
;     loop_cf2e2:                   1
;     loop_cf301:                   1
;     loop_cf3b1:                   1
;     loop_cf3c6:                   1
;     loop_cf3cb:                   1
;     loop_cf3e0:                   1
;     loop_cf3ef:                   1
;     loop_cf4d9:                   1
;     loop_cf576:                   1
;     loop_cf586:                   1
;     loop_cf599:                   1
;     loop_cf6c4:                   1
;     loop_cf6fd:                   1
;     loop_cf7d7:                   1
;     loop_cf824:                   1
;     loop_cf851:                   1
;     loop_cf860:                   1
;     loop_cf875:                   1
;     loop_cf89e:                   1
;     loop_cf8ae:                   1
;     loop_cf8fa:                   1
;     loop_cf8fc:                   1
;     loop_cf907:                   1
;     loop_cf92e:                   1
;     loop_cf93b:                   1
;     loop_cf980:                   1
;     loop_cf98e:                   1
;     loop_cf9cd:                   1
;     loop_cf9e8:                   1
;     loop_cfa9e:                   1
;     loop_cfaa7:                   1
;     loop_cfafa:                   1
;     loop_cfb44:                   1
;     loop_cfb4c:                   1
;     loop_cfb58:                   1
;     loop_cfb69:                   1
;     loop_cfb95:                   1
;     loop_cfbbf:                   1
;     loop_cfbc8:                   1
;     loop_cfbd5:                   1
;     loop_cfbf4:                   1
;     loop_cfbf8:                   1
;     loop_cfc01:                   1
;     loop_cfc0a:                   1
;     loop_cfc9e:                   1
;     loop_cfcc2:                   1
;     loop_cfce1:                   1
;     loop_cfd1d:                   1
;     loop_cfd20:                   1
;     loop_cfd74:                   1
;     loop_cfdff:                   1
;     loop_cfe0d:                   1
;     loop_cfe19:                   1
;     loop_cfe26:                   1
;     loop_cfe76:                   1
;     loop_cfe78:                   1
;     loop_cfec4:                   1
;     loop_cff10:                   1
;     loop_cff41:                   1
;     loop_cff55:                   1
;     nmivec:                       1
;     parsing_ptr_high:             1
;     plot_routines_high:           1
;     plot_routines_low:            1
;     print_hex_digit:              1
;     print_space:                  1
;     pydis_start:                  1
;     rdch_at:                      1
;     rdcvec:                       1
;     rdrvec:                       1
;     restore_xy_and_return:        1
;     return_1:                     1
;     return_10:                    1
;     return_11:                    1
;     return_4:                     1
;     return_5:                     1
;     return_6:                     1
;     return_8:                     1
;     return_9:                     1
;     send_to_printer:              1
;     shtvec:                       1
;     star_load:                    1
;     string_buffer:                1
;     strvec:                       1
;     sub_cf08e:                    1
;     sub_cf38e:                    1
;     sub_cf87e:                    1
;     sub_cfb3b:                    1
;     sub_cfb81:                    1
;     sub_cfc23:                    1
;     sub_cfcda:                    1
;     sub_cfd13:                    1
;     sub_cfe3a:                    1
;     via_ddra:                     1
;     wait_tenth_second:            1
;     wrch_bell:                    1
;     wrch_control_code_handlers:   1
;     wrch_control_codes:           1
;     wrcvec:                       1

; Automatically generated labels:
;     cf048
;     cf060
;     cf075
;     cf082
;     cf0d6
;     cf0d7
;     cf107
;     cf119
;     cf11b
;     cf13e
;     cf152
;     cf291
;     cf2ef
;     cf2ff
;     cf311
;     cf328
;     cf32b
;     cf32e
;     cf34a
;     cf360
;     cf36b
;     cf396
;     cf3cf
;     cf3f2
;     cf42b
;     cf440
;     cf454
;     cf462
;     cf482
;     cf49a
;     cf49b
;     cf4a7
;     cf4ae
;     cf4d7
;     cf4e7
;     cf4ec
;     cf511
;     cf527
;     cf52c
;     cf548
;     cf554
;     cf597
;     cf5b2
;     cf5b5
;     cf5b7
;     cf5dd
;     cf5fb
;     cf60c
;     cf60f
;     cf61c
;     cf626
;     cf637
;     cf664
;     cf66e
;     cf671
;     cf67e
;     cf68a
;     cf69e
;     cf6a0
;     cf6ab
;     cf6c2
;     cf6cd
;     cf720
;     cf731
;     cf736
;     cf785
;     cf789
;     cf7df
;     cf7e9
;     cf813
;     cf827
;     cf83f
;     cf86c
;     cf88e
;     cf891
;     cf8bb
;     cf8f2
;     cf919
;     cf92f
;     cf946
;     cf94e
;     cf966
;     cf999
;     cf9a2
;     cf9c7
;     cf9db
;     cf9e0
;     cf9f2
;     cfa05
;     cfa0e
;     cfa31
;     cfa38
;     cfa44
;     cfa5d
;     cfa73
;     cfa7d
;     cfa86
;     cfab2
;     cfad9
;     cfb0b
;     cfb0e
;     cfb29
;     cfb73
;     cfb83
;     cfb8e
;     cfb9d
;     cfbb1
;     cfbb4
;     cfbe4
;     cfc0f
;     cfc12
;     cfc3e
;     cfc40
;     cfc58
;     cfc63
;     cfc6d
;     cfc76
;     cfc90
;     cfc9c
;     cfcaf
;     cfcdc
;     cfd0b
;     cfd11
;     cfd29
;     cfd33
;     cfd42
;     cfd65
;     cfdab
;     cfdbb
;     cfdcf
;     cfde9
;     cfe06
;     cfe08
;     cfe2c
;     cfe49
;     cfe85
;     cfe9a
;     cfea4
;     cfea7
;     cfeb7
;     cff27
;     cff33
;     cff36
;     cff38
;     cff97
;     cffc0
;     l000d
;     l000e
;     l000f
;     l0052
;     l0053
;     l0054
;     l0055
;     l0056
;     l0057
;     l0059
;     l005a
;     l005b
;     l005c
;     l005d
;     l005e
;     l005f
;     l0060
;     l0061
;     l0064
;     l0065
;     l0066
;     l0067
;     l0068
;     l0069
;     l006a
;     l0086
;     l00c0
;     l00c1
;     l00c2
;     l00c3
;     l00c4
;     l00c5
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
;     l00d8
;     l00db
;     l00dc
;     l00dd
;     l00e2
;     l00e3
;     l00e4
;     l00e5
;     l00e8
;     l00e9
;     l00ec
;     l00ed
;     l00fd
;     l013f
;     l02eb
;     l0306
;     l0321
;     l0331
;     l033c
;     l034c
;     l03c1
;     l03c2
;     l03c3
;     l03c4
;     l2901
;     l7fe0
;     l8000
;     l80e0
;     l8100
;     la000
;     lc231
;     lc278
;     lc2ac
;     lc2b2
;     lc2b6
;     lc2cf
;     lc31b
;     lc3c8
;     lc3cb
;     lc3f1
;     lc434
;     lc4e4
;     lc4f6
;     lc51d
;     lc558
;     lc55b
;     lc589
;     lc5f9
;     lc78b
;     lc8bc
;     lc94f
;     lc962
;     lca24
;     lca4c
;     lcd54
;     lcd9b
;     lce83
;     le298
;     lefff
;     lf001
;     lf084
;     lf11c
;     lf154
;     lf194
;     lf210
;     lf250
;     lf67f
;     lf6ce
;     lf7cb
;     lf8bf
;     lf9a3
;     loop_cf062
;     loop_cf06d
;     loop_cf29c
;     loop_cf2e2
;     loop_cf301
;     loop_cf3b1
;     loop_cf3c6
;     loop_cf3cb
;     loop_cf3e0
;     loop_cf3ef
;     loop_cf4d9
;     loop_cf576
;     loop_cf586
;     loop_cf599
;     loop_cf6c4
;     loop_cf6fd
;     loop_cf7d7
;     loop_cf824
;     loop_cf851
;     loop_cf860
;     loop_cf875
;     loop_cf89e
;     loop_cf8ae
;     loop_cf8fa
;     loop_cf8fc
;     loop_cf907
;     loop_cf92e
;     loop_cf93b
;     loop_cf980
;     loop_cf98e
;     loop_cf9cd
;     loop_cf9e8
;     loop_cfa9e
;     loop_cfaa7
;     loop_cfafa
;     loop_cfb44
;     loop_cfb4c
;     loop_cfb58
;     loop_cfb69
;     loop_cfb95
;     loop_cfbbf
;     loop_cfbc8
;     loop_cfbd5
;     loop_cfbf4
;     loop_cfbf8
;     loop_cfc01
;     loop_cfc0a
;     loop_cfc9e
;     loop_cfcc2
;     loop_cfce1
;     loop_cfd1d
;     loop_cfd20
;     loop_cfd74
;     loop_cfdff
;     loop_cfe0d
;     loop_cfe19
;     loop_cfe26
;     loop_cfe76
;     loop_cfe78
;     loop_cfec4
;     loop_cff10
;     loop_cff41
;     loop_cff55
;     return_1
;     return_10
;     return_11
;     return_12
;     return_2
;     return_3
;     return_4
;     return_5
;     return_6
;     return_7
;     return_8
;     return_9
;     sub_cf08b
;     sub_cf08e
;     sub_cf376
;     sub_cf379
;     sub_cf37e
;     sub_cf38e
;     sub_cf644
;     sub_cf655
;     sub_cf678
;     sub_cf7ec
;     sub_cf818
;     sub_cf84f
;     sub_cf87e
;     sub_cf893
;     sub_cf992
;     sub_cfa08
;     sub_cfa65
;     sub_cfa76
;     sub_cfb3b
;     sub_cfb7a
;     sub_cfb81
;     sub_cfbc9
;     sub_cfbe2
;     sub_cfc23
;     sub_cfc2b
;     sub_cfcbd
;     sub_cfccd
;     sub_cfcd8
;     sub_cfcda
;     sub_cfcea
;     sub_cfd13
;     sub_cfdec
;     sub_cfe35
;     sub_cfe3a

; Stats:
;
;     Total size (Code + Data) = 4096 bytes
;     Code                     = 3512 bytes (86%)
;     Data                     = 584 bytes (14%)
;
;     Number of instructions   = 1756
;     Number of data bytes     = 428 bytes
;     Number of data words     = 30 bytes
;     Number of string bytes   = 126 bytes
;     Number of strings        = 26
