; Memory locations

; 6510 I/O port ($0000-$0001)
cpu_port_direction  = $0000

; Zero page ($0000-$00ff)
basic_float_to_int_vector   = $0003
basic_int_to_float_vector   = $0005
basic_search_char           = $0007
basic_end_char              = $0008
basic_load_verify_flag      = $000a
basic_input_buffer_index    = $000b
basic_dim_flag              = $000c
basic_value_type            = $000d
basic_garbage_flag          = $000f
basic_line_number           = $0014
basic_temp_string_index     = $0016
basic_index1                = $0022
basic_index2                = $0024
basic_multiply_result       = $0026
basic_program_start         = $002b
basic_variables_start       = $002d
basic_arrays_start          = $002f
basic_arrays_end            = $0031
basic_strings_bottom        = $0033
basic_string_temp_ptr       = $0035
basic_memory_top            = $0037
basic_current_line          = $0039
basic_previous_line         = $003b
basic_statement_ptr         = $003d
basic_data_ptr              = $0041
basic_variable_name         = $0045
basic_variable_ptr          = $0047
basic_operator_ptr          = $004b
basic_string_descriptor_ptr = $0050
basic_garbage_step          = $0053
fac1_exponent               = $0061
fac1_mantissa               = $0062
fac1_sign                   = $0066
fac2_exponent               = $0069
fac2_mantissa               = $006a
fac1_rounding               = $0070
basic_text_ptr              = $007a
io_status                   = $0090
stop_key_flag               = $0091
rs232_start_bit_flag        = $00a9
tape_timing_constant        = $00b0
filename_length             = $00b7
secondary_address           = $00b9
device_number               = $00ba
filename_ptr                = $00bb
quote_mode_flag             = $00d4
screen_line_links           = $00d9

; Stack ($0100-$01ff)
l0100   = $0100
l0101   = $0101
l0102   = $0102
l0103   = $0103
l0104   = $0104
l0105   = $0105
l0106   = $0106
l01ff   = $01ff

; OS workspace ($0200-$02ff)
basic_input_buffer  = $0200

; Vectors ($0300-$0333)
basic_error_vector  = $0300
sys_a               = $030c
sys_x               = $030d
sys_y               = $030e
sys_p               = $030f
usr_jmp             = $0310
usr_address         = $0311

; BASIC program area ($0800-$9fff)
l0ea0   = $0ea0
l99a9   = $99a9

; VIC-II ($d000-$d3ff)
ld030   = $d030
ld07a   = $d07a
ld07b   = $d07b

; Kernal ROM ($e000-$ff80)
basic_command_poke  = $e000
le023               = $e023
le02f               = $e02f
le044               = $e044
le060               = $e060
le080               = $e080
le089               = $e089
le0ab               = $e0ab
le107               = $e107
le132               = $e132
le146               = $e146
le163               = $e163
le188               = $e188
le195               = $e195
le19e               = $e19e
le1b0               = $e1b0
le1c7               = $e1c7
le1e1               = $e1e1
le214               = $e214
le217               = $e217
le265               = $e265
le28b               = $e28b
le28e               = $e28e
le2b5               = $e2b5
basic_command_save  = $e2be
le312               = $e312
le339               = $e339
le34d               = $e34d
le366               = $e366
le376               = $e376
le38c               = $e38c
basic_cold_start    = $e394
le3a9               = $e3a9
basic_warm_start    = $e3b7
le3ba               = $e3ba
basic_command_list  = $e3cc
le3eb               = $e3eb
le404               = $e404
le422               = $e422
le457               = $e457
le480               = $e480
le4cd               = $e4cd
leb8c               = $eb8c
lf7c1               = $f7c1
lf7c6               = $f7c6

; Kernal entry points ($ff81-$fff9)
setmsg  = $ff90
lffa9   = $ffa9
readst  = $ffb7
setlfs  = $ffba
setnam  = $ffbd
open    = $ffc0
chkin   = $ffc6
chrin   = $ffcf
chrout  = $ffd2
load    = $ffd5
settim  = $ffdb
rdtim   = $ffde
clall   = $ffe7

    * = $a000

pydis_start
basic_cold_start_vector
    .word basic_cold_start                                            ; a000: 94 e3       ..
basic_warm_start_vector
    .word basic_warm_start                                            ; a002: b7 e3       ..
basic_signature
    .byte $4f, $52, $47, $42, $41, $53, $49, $43 ; petscii "orgbasic" ; a004: 4f 52 47... org
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a00c: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a020: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a034: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a048: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a05c: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a070: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a084: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a098: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a0ac: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a0c0: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a0d4: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a0e8: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a0fc: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a110: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a124: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; a138: 00 00 00... ...
    .byte 0, 0, 0                                                     ; a14c: 00 00 00    ...

; $a14f referenced 16 times by $a19e, $a1a1, $a40c, $a427, $a439, $a4ce, $a759, $a763, $a89a, $adb9, $adf9, $ae25, $af7f, $b3ef, $ba3d, $bf84
sub_ca14f
    ldy #0                                                            ; a14f: a0 00       ..
    jsr le188                                                         ; a151: 20 88 e1     ..
    inc basic_text_ptr                                                ; a154: e6 7a       ..
    bne return_1                                                      ; a156: d0 02       P.
    inc basic_text_ptr+1                                              ; a158: e6 7b       ..
; $a15a referenced 1 time by $a156
return_1
    rts                                                               ; a15a: 60          .

; $a15b referenced 2 times by $a3e3, $a3ea
ca15b
    clc                                                               ; a15b: 18          .
    lda basic_strings_bottom                                          ; a15c: a5 33       .3
    adc basic_string_descriptor_ptr                                   ; a15e: 65 50       .p
    sta basic_strings_bottom                                          ; a160: 85 33       .3
    bcc return_2                                                      ; a162: 90 02       ..
    inc basic_strings_bottom+1                                        ; a164: e6 34       .4
; $a166 referenced 1 time by $a162
return_2
    rts                                                               ; a166: 60          .

; $a167 referenced 4 times by $acf8, $ad4f, $ad85, $ad98
sub_ca167
    sta basic_string_descriptor_ptr                                   ; a167: 85 50       .p
    sec                                                               ; a169: 38          8
    lda basic_text_ptr                                                ; a16a: a5 7a       ..
    sbc basic_string_descriptor_ptr                                   ; a16c: e5 50       .p
    sta basic_text_ptr                                                ; a16e: 85 7a       ..
    bcs return_3                                                      ; a170: b0 02       ..
    dec basic_text_ptr+1                                              ; a172: c6 7b       F.
; $a174 referenced 1 time by $a170
return_3
    rts                                                               ; a174: 60          .

; $a175 referenced 1 time by $b3a5
la175
    .byte $8b, $e3, $83, $a4, $7c, $a5, $1a, $a7, $e4, $a7, $86, $ae  ; a175: 8b e3 83... ...
; $a181 referenced 1 time by $b3b0
la181
    .byte $8f, $ba, $a5, $bb                                          ; a181: 8f ba a5... ...

; $a185 referenced 2 times by $a75c, $a766
sub_ca185
    jsr sub_ca192                                                     ; a185: 20 92 a1     ..
    bcs ca18b                                                         ; a188: b0 01       ..
    rts                                                               ; a18a: 60          .

; $a18b referenced 2 times by $a188, $a8ad
ca18b
    cmp #$30 ; '0'                                                    ; a18b: c9 30       I0
    bcc ca199                                                         ; a18d: 90 0a       ..
    cmp #$3a ; ':'                                                    ; a18f: c9 3a       I:
    rts                                                               ; a191: 60          .

; $a192 referenced 2 times by $a185, $a74d
sub_ca192
    cmp #$41 ; 'a'                                                    ; a192: c9 41       Ia
    bcc ca199                                                         ; a194: 90 03       ..
    cmp #$7b                                                          ; a196: c9 7b       I.
    rts                                                               ; a198: 60          .

; $a199 referenced 2 times by $a18d, $a194
ca199
    sec                                                               ; a199: 38          8
    rts                                                               ; a19a: 60          .

; $a19b referenced 1 time by $ac60
ca19b
    jsr sub_cbc45                                                     ; a19b: 20 45 bc     e.
    jsr sub_ca14f                                                     ; a19e: 20 4f a1     o.
    jsr sub_ca14f                                                     ; a1a1: 20 4f a1     o.
    cmp #$4c ; 'l'                                                    ; a1a4: c9 4c       Il
    beq ca1ab                                                         ; a1a6: f0 03       ..
    jmp ca6cf                                                         ; a1a8: 4c cf a6    lO.

; $a1ab referenced 1 time by $a1a6
ca1ab
    jsr sub_cb3d7                                                     ; a1ab: 20 d7 b3     W.
    jmp cbab3                                                         ; a1ae: 4c b3 ba    l..

    .byte $a9,   0, $85, $26, $85, $27, $85, $28, $85, $29, $85, $2a  ; a1b1: a9 00 85... ...
    .byte $60, $18, $65, $26, $85, $26, $90,   2, $e6, $27, $60, $a5  ; a1bd: 60 18 65... ...
    .byte $62, $85, $8f, $45, $63, $85, $8e, $45, $64, $85, $8d, $45  ; a1c9: 62 85 8f... ...
    .byte $65, $85, $8c, $45, $61, $85, $8b, $4c, $be, $e0            ; a1d5: 65 85 8c... ...

; $a1df referenced 3 times by $a48b, $a668, $a671
sub_ca1df
    jsr sub_cb1b1                                                     ; a1df: 20 b1 b1     ..
    bcs return_4                                                      ; a1e2: b0 11       ..
; $a1e4 referenced 1 time by $a8d5
sub_ca1e4
    lda #$0d                                                          ; a1e4: a9 0d       ..
    jsr sub_cba2e                                                     ; a1e6: 20 2e ba     ..
    bcs return_4                                                      ; a1e9: b0 0a       ..
    lda basic_line_number+1                                           ; a1eb: a5 15       ..
    beq ca1f2                                                         ; a1ed: f0 03       ..
    jmp la6cc                                                         ; a1ef: 4c cc a6    lL.

; $a1f2 referenced 1 time by $a1ed
ca1f2
    lda basic_line_number                                             ; a1f2: a5 14       ..
    clc                                                               ; a1f4: 18          .
; $a1f5 referenced 2 times by $a1e2, $a1e9
return_4
    rts                                                               ; a1f5: 60          .

; $a1f6 referenced 1 time by $bac9
ca1f6
    jsr le060                                                         ; a1f6: 20 60 e0     ..
    jsr caf7f                                                         ; a1f9: 20 7f af     ..
    cmp #$3a ; ':'                                                    ; a1fc: c9 3a       I:
    bne ca203                                                         ; a1fe: d0 03       P.
    jmp ca493                                                         ; a200: 4c 93 a4    l..

; $a203 referenced 1 time by $a1fe
ca203
    cmp #0                                                            ; a203: c9 00       I.
    bne ca20a                                                         ; a205: d0 03       P.
    jmp ca4e9                                                         ; a207: 4c e9 a4    l..

; $a20a referenced 1 time by $a205
ca20a
    jmp ca6cf                                                         ; a20a: 4c cf a6    lO.

    .byte $a5, $b0,   5, $b1, $f0, $0f, $a2,   6, $20, $59, $b9, $a5  ; a20d: a5 b0 05... ...
    .byte $b1, $20, $f1, $fa, $a5, $b0, $20, $f1, $fa, $4c,   3, $ac  ; a219: b1 20 f1... . .

; $a225 referenced 2 times by $b4e1, $b4f6
sub_ca225
    sta basic_string_descriptor_ptr                                   ; a225: 85 50       .p
    sec                                                               ; a227: 38          8
    lda basic_strings_bottom                                          ; a228: a5 33       .3
    sbc basic_string_descriptor_ptr                                   ; a22a: e5 50       .p
    sta basic_strings_bottom                                          ; a22c: 85 33       .3
    bcs ca232                                                         ; a22e: b0 02       ..
    dec basic_strings_bottom+1                                        ; a230: c6 34       F4
; $a232 referenced 1 time by $a22e
ca232
    lda basic_arrays_end+1                                            ; a232: a5 32       .2
    cmp basic_strings_bottom+1                                        ; a234: c5 34       E4
    beq ca239                                                         ; a236: f0 01       ..
    rts                                                               ; a238: 60          .

; $a239 referenced 1 time by $a236
ca239
    lda basic_arrays_end                                              ; a239: a5 31       .1
    cmp basic_strings_bottom                                          ; a23b: c5 33       E3
    rts                                                               ; a23d: 60          .

    .byte $4d,   4, $dc, $85, $8e, $8a, $4d, $12, $d0, $85, $8c, $98  ; a23e: 4d 04 dc... m..
    .byte $4d,   5, $dc, $85, $8f, $a5, $a2, $4d, $1b, $d4, $85, $8d  ; a24a: 4d 05 dc... m..
    .byte $4c, $be, $e0                                               ; a256: 4c be e0    l..

; $a259 referenced 2 times by $b1c2, $bffa
sub_ca259
    sty basic_multiply_result+4                                       ; a259: 84 2a       .*
    sec                                                               ; a25b: 38          8
    lda basic_index2                                                  ; a25c: a5 24       .$
    sbc basic_multiply_result+4                                       ; a25e: e5 2a       .*
    sta basic_index2                                                  ; a260: 85 24       .$
    bcs ca266                                                         ; a262: b0 02       ..
    dec basic_index2+1                                                ; a264: c6 25       F%
; $a266 referenced 1 time by $a262
ca266
    sec                                                               ; a266: 38          8
    lda basic_multiply_result                                         ; a267: a5 26       .&
    sbc basic_multiply_result+4                                       ; a269: e5 2a       .*
    sta basic_multiply_result                                         ; a26b: 85 26       .&
    bcs ca271                                                         ; a26d: b0 02       ..
    dec basic_multiply_result+1                                       ; a26f: c6 27       F'
; $a271 referenced 1 time by $a26d
ca271
    inc basic_multiply_result+3                                       ; a271: e6 29       .)
; $a273 referenced 3 times by $affd, $b998, $b9b2
return_14
    rts                                                               ; a273: 60          .

    .byte $3e, $3d, $3c, $2f, $2d, $2a ; petscii ">=</-*"             ; a274: 3e 3d 3c... >=<
    .byte $5e                                                         ; a27a: 5e          .
    .byte $2b, $51, $23, $28, $4b, $58, $59, $57 ; petscii "+q#(kxyw" ; a27b: 2b 51 23... +q#
    .byte $48, $56, $42, $4d, $24, $47, $43 ; petscii "hvbm$gc"       ; a283: 48 56 42... hvb
    .byte $0d                                                         ; a28a: 0d          .
    .byte $27, $5a, $2e, $4a, $3f ; petscii "'z.j?"                   ; a28b: 27 5a 2e... 'z.

; $a290 referenced 3 times by $aee2, $bd0f, $be0b
sub_ca290
    jsr sub_cbc1e                                                     ; a290: 20 1e bc     ..
    jsr sub_cba2e                                                     ; a293: 20 2e ba     ..
    bcs ca2a3                                                         ; a296: b0 0b       ..
    jsr caf7f                                                         ; a298: 20 7f af     ..
    cmp #$2c ; ','                                                    ; a29b: c9 2c       I,
    beq ca2a6                                                         ; a29d: f0 07       ..
    cmp #$29 ; ')'                                                    ; a29f: c9 29       I)
    beq ca2a9                                                         ; a2a1: f0 06       ..
; $a2a3 referenced 1 time by $a296
ca2a3
    jmp ca6cf                                                         ; a2a3: 4c cf a6    lO.

; $a2a6 referenced 1 time by $a29d
ca2a6
    ldy #0                                                            ; a2a6: a0 00       ..
    rts                                                               ; a2a8: 60          .

; $a2a9 referenced 1 time by $a2a1
ca2a9
    ldy #$ff                                                          ; a2a9: a0 ff       ..
    rts                                                               ; a2ab: 60          .

; $a2ac referenced 1 time by $a497
basic_command_stop
    jsr lf7c1                                                         ; a2ac: 20 c1 f7     A.
    ldx #$1d                                                          ; a2af: a2 1d       ..
    jsr sub_cb953                                                     ; a2b1: 20 53 b9     s.
    lda basic_current_line+1                                          ; a2b4: a5 3a       .:
    cmp #$ff                                                          ; a2b6: c9 ff       I.
    beq basic_command_end                                             ; a2b8: f0 0c       ..
    ldx #4                                                            ; a2ba: a2 04       ..
    jsr sub_cb959                                                     ; a2bc: 20 59 b9     y.
    lda basic_current_line+1                                          ; a2bf: a5 3a       .:
    ldx basic_current_line                                            ; a2c1: a6 39       .9
    jsr sub_cb40e                                                     ; a2c3: 20 0e b4     ..
; $a2c6 referenced 1 time by $a2b8
basic_command_end
    jmp cac01                                                         ; a2c6: 4c 01 ac    l..

    .byte $a5, $61, $f0, $22, $a5, $70, $10, $1a, $e6, $65, $d0, $16  ; a2c9: a5 61 f0... ...
    .byte $e6, $64, $d0, $12, $e6, $63, $d0, $0e, $e6, $62, $d0, $0a  ; a2d5: e6 64 d0... ..P
    .byte $a9, $80, $85, $62, $e6, $61, $d0,   2, $c6, $61, $a9,   0  ; a2e1: a9 80 85... ...
    .byte $85, $70, $60                                               ; a2ed: 85 70 60    ...

; $a2f0 referenced 1 time by $ac9e
sub_ca2f0
    ldy #0                                                            ; a2f0: a0 00       ..
    jsr le195                                                         ; a2f2: 20 95 e1     ..
    sta basic_input_buffer_index                                      ; a2f5: 85 0b       ..
    iny                                                               ; a2f7: c8          H
    jsr le195                                                         ; a2f8: 20 95 e1     ..
    sta basic_garbage_flag                                            ; a2fb: 85 0f       ..
    lda basic_input_buffer_index                                      ; a2fd: a5 0b       ..
    sec                                                               ; a2ff: 38          8
    sbc basic_statement_ptr                                           ; a300: e5 3d       .=
    sta basic_input_buffer_index                                      ; a302: 85 0b       ..
    lda basic_garbage_flag                                            ; a304: a5 0f       ..
    sbc basic_statement_ptr+1                                         ; a306: e5 3e       .>
    sta basic_garbage_flag                                            ; a308: 85 0f       ..
    lda basic_garbage_flag                                            ; a30a: a5 0f       ..
    sbc #0                                                            ; a30c: e9 00       ..
    cmp #0                                                            ; a30e: c9 00       I.
    beq ca315                                                         ; a310: f0 03       ..
    jmp ca6b0                                                         ; a312: 4c b0 a6    l..

; $a315 referenced 1 time by $a310
ca315
    ldx basic_input_buffer_index                                      ; a315: a6 0b       ..
    jsr sub_cbfc4                                                     ; a317: 20 c4 bf     D.
    jmp ca7de                                                         ; a31a: 4c de a7    l..

    .byte $a9, 1, $85, $2b, $a9, 8, $85                               ; a31d: a9 01 85... ...
    .byte $2c, $38, $20 ; petscii ",8 "                               ; a324: 2c 38 20    ,8
    .byte $99, $ff, $c0, $80, $f0,   3, $a9, $d0, $2c, $a9, $80, $85  ; a327: 99 ff c0... ...
    .byte $38, $a9,   0, $85, $37, $38, $a5, $37, $e5, $2b, $aa, $a5  ; a333: 38 a9 00... 8..
    .byte $38, $e5, $2c, $20, $0e, $b4, $a2,   1, $4c, $59, $b9       ; a33f: 38 e5 2c... 8.,
; $a34a referenced 2 times by $ae47, $ae75
la34a
    .byte 5, 5, 6, 6, 8, 2, 1, 4, 4, 4, 4, 4, 4, 7, 3                 ; a34a: 05 05 06... ...
; $a359 referenced 1 time by $ae71
la359
    .byte $c1, $7b, $53, $0e, $59, $f5, $5c                           ; a359: c1 7b 53... A.s
    .byte $35, $cc, $cf ; petscii "5LO"                               ; a360: 35 cc cf    5LO
    .byte $74, $ad, $aa, $be, $bb                                     ; a363: 74 ad aa... ...
; $a368 referenced 1 time by $ae6d
la368
    .byte $aa, $bf, $e4, $e3, $e0, $ba, $e0, $bc, $bb, $bd, $bf, $b1  ; a368: aa bf e4... ...
    .byte $b1, $b8, $b8, $ee, $ef, $f0, $f1, $f2, $f3, $f4, $f5, $f6  ; a374: b1 b8 b8... ...
    .byte $f7, $f8, $f9, $fa, $fb, $fc, $fd, $fe, $ff,   0,   1,   2  ; a380: f7 f8 f9... ...
    .byte   3,   4, $e2, $e2, $e2, $e2, $e2, $e2, $e2, $e2, $e2, $e2  ; a38c: 03 04 e2... ...
    .byte $e2, $e2, $e2, $e2, $e2, $e2, $e2, $e2, $e3, $e3, $e3, $e3  ; a398: e2 e2 e2... ...
    .byte $e3,   8, $18, $a5, $2a, $10,   1, $38, $a5, $29, $85, $2a  ; a3a4: e3 08 18... ...
    .byte $a5, $28, $85, $29, $a5, $27, $85, $28, $a5, $26, $85, $27  ; a3b0: a5 28 85... .(.
    .byte $a9,   0, $85, $26, $90, $12, $e6, $2a, $d0, $0e, $e6, $29  ; a3bc: a9 00 85... ...
    .byte $d0, $0a, $e6, $28, $d0,   6, $e6, $27, $d0,   2, $e6, $26  ; a3c8: d0 0a e6... P..
    .byte $28, $60                                                    ; a3d4: 28 60       (.

; $a3d6 referenced 2 times by $beaf, $bf02
sub_ca3d6
    lda basic_string_descriptor_ptr                                   ; a3d6: a5 50       .p
    bne ca3db                                                         ; a3d8: d0 01       P.
    rts                                                               ; a3da: 60          .

; $a3db referenced 1 time by $a3d8
ca3db
    jsr sub_cb948                                                     ; a3db: 20 48 b9     h.
    bcs ca3e1                                                         ; a3de: b0 01       ..
    rts                                                               ; a3e0: 60          .

; $a3e1 referenced 2 times by $a3de, $bc8a
ca3e1
    bne ca3ed                                                         ; a3e1: d0 0a       P.
    jsr ca15b                                                         ; a3e3: 20 5b a1     [.
    lda #2                                                            ; a3e6: a9 02       ..
    sta basic_string_descriptor_ptr                                   ; a3e8: 85 50       .p
    jmp ca15b                                                         ; a3ea: 4c 5b a1    l[.

; $a3ed referenced 1 time by $a3e1
ca3ed
    dec basic_string_descriptor_ptr                                   ; a3ed: c6 50       Fp
    clc                                                               ; a3ef: 18          .
    lda basic_string_descriptor_ptr+1                                 ; a3f0: a5 51       .q
    adc basic_string_descriptor_ptr                                   ; a3f2: 65 50       .p
    sta basic_string_descriptor_ptr+1                                 ; a3f4: 85 51       .q
    bcc ca3fa                                                         ; a3f6: 90 02       ..
    inc basic_string_descriptor_ptr+2                                 ; a3f8: e6 52       .r
; $a3fa referenced 1 time by $a3f6
ca3fa
    lda basic_string_descriptor_ptr                                   ; a3fa: a5 50       .p
    ldy #0                                                            ; a3fc: a0 00       ..
    sta (basic_string_descriptor_ptr+1),y                             ; a3fe: 91 51       .q
    tya                                                               ; a400: 98          .  ; A=0
    iny                                                               ; a401: c8          H  ; Y=1
    sta (basic_string_descriptor_ptr+1),y                             ; a402: 91 51       .q
    iny                                                               ; a404: c8          H  ; Y=2
    sta (basic_string_descriptor_ptr+1),y                             ; a405: 91 51       .q
    rts                                                               ; a407: 60          .

    .byte $60                                                         ; a408: 60          .

; $a409 referenced 1 time by $a5aa
ca409
    jmp ca6b2                                                         ; a409: 4c b2 a6    l..

; $a40c referenced 1 time by $ae3f
sub_ca40c
    jsr sub_ca14f                                                     ; a40c: 20 4f a1     o.
    sec                                                               ; a40f: 38          8
    sbc #$aa                                                          ; a410: e9 aa       ..
    bcc ca422                                                         ; a412: 90 0e       ..
    cmp #$0a                                                          ; a414: c9 0a       I.
    bcs ca422                                                         ; a416: b0 0a       ..
    cmp #7                                                            ; a418: c9 07       I.
    beq ca427                                                         ; a41a: f0 0b       ..
    cmp #9                                                            ; a41c: c9 09       I.
    beq ca439                                                         ; a41e: f0 19       ..
; $a420 referenced 5 times by $a433, $a437, $a449, $a44d, $a451
ca420
    clc                                                               ; a420: 18          .
    rts                                                               ; a421: 60          .

; $a422 referenced 2 times by $a412, $a416
ca422
    jsr sub_ca71b                                                     ; a422: 20 1b a7     ..
    sec                                                               ; a425: 38          8
    rts                                                               ; a426: 60          .

; $a427 referenced 1 time by $a41a
ca427
    jsr sub_ca14f                                                     ; a427: 20 4f a1     o.
    cmp #$b2                                                          ; a42a: c9 b2       I.
    beq ca435                                                         ; a42c: f0 07       ..
    jsr sub_ca71b                                                     ; a42e: 20 1b a7     ..
    lda #7                                                            ; a431: a9 07       ..
    bne ca420                                                         ; a433: d0 eb       P. ; ALWAYS branch

; $a435 referenced 1 time by $a42c
ca435
    lda #$0a                                                          ; a435: a9 0a       ..
    bne ca420                                                         ; a437: d0 e7       P. ; ALWAYS branch

; $a439 referenced 1 time by $a41e
ca439
    jsr sub_ca14f                                                     ; a439: 20 4f a1     o.
    cmp #$b2                                                          ; a43c: c9 b2       I.
    beq ca44b                                                         ; a43e: f0 0b       ..
    cmp #$b1                                                          ; a440: c9 b1       I.
    beq ca44f                                                         ; a442: f0 0b       ..
    jsr sub_ca71b                                                     ; a444: 20 1b a7     ..
    lda #9                                                            ; a447: a9 09       ..
    bne ca420                                                         ; a449: d0 d5       PU ; ALWAYS branch

; $a44b referenced 1 time by $a43e
ca44b
    lda #$0b                                                          ; a44b: a9 0b       ..
    bne ca420                                                         ; a44d: d0 d1       PQ ; ALWAYS branch

; $a44f referenced 1 time by $a442
ca44f
    lda #$0c                                                          ; a44f: a9 0c       ..
    bne ca420                                                         ; a451: d0 cd       PM ; ALWAYS branch

    rts                                                               ; a453: 60          .

; $a454 referenced 2 times by $af09, $af32
sub_ca454
    sec                                                               ; a454: 38          8
    lda basic_strings_bottom                                          ; a455: a5 33       .3
    sbc basic_arrays_end                                              ; a457: e5 31       .1
    sta basic_index2                                                  ; a459: 85 24       .$
    lda basic_strings_bottom+1                                        ; a45b: a5 34       .4
    sbc basic_arrays_end+1                                            ; a45d: e5 32       .2
    sta basic_index2+1                                                ; a45f: 85 25       .%
    bcc ca480                                                         ; a461: 90 1d       ..
    lda basic_index2                                                  ; a463: a5 24       .$
    sbc fac1_mantissa                                                 ; a465: e5 62       ..
    sta basic_index2                                                  ; a467: 85 24       .$
    lda basic_index2+1                                                ; a469: a5 25       .%
    sbc fac1_mantissa+1                                               ; a46b: e5 63       ..
    sta basic_index2+1                                                ; a46d: 85 25       .%
    bcc ca480                                                         ; a46f: 90 0f       ..
    lda basic_index2+1                                                ; a471: a5 25       .%
    bne return_5                                                      ; a473: d0 0a       P.
    lda fac1_exponent                                                 ; a475: a5 61       ..
    asl a                                                             ; a477: 0a          .
    clc                                                               ; a478: 18          .
    adc #4                                                            ; a479: 69 04       ..
    cmp basic_index2                                                  ; a47b: c5 24       E$
    bcs ca480                                                         ; a47d: b0 01       ..
; $a47f referenced 1 time by $a473
return_5
    rts                                                               ; a47f: 60          .

; $a480 referenced 3 times by $a461, $a46f, $a47d
ca480
    jmp la6ca                                                         ; a480: 4c ca a6    lJ.

    .byte $60, $a0, 0, $a2, $5c, $4c, $d4, $bb                        ; a483: 60 a0 00... ...

; $a48b referenced 1 time by $bab0
sub_ca48b
    jsr sub_ca1df                                                     ; a48b: 20 df a1     ..
    bcs return_6                                                      ; a48e: b0 02       ..
    sta secondary_address                                             ; a490: 85 b9       ..
; $a492 referenced 1 time by $a48e
return_6
    rts                                                               ; a492: 60          .

; $a493 referenced 3 times by $a200, $acb3, $bbc4
ca493
    lda stop_key_flag                                                 ; a493: a5 91       ..
    bmi ca49a                                                         ; a495: 30 03       0.
    jmp basic_command_stop                                            ; a497: 4c ac a2    l..

; $a49a referenced 2 times by $a495, $a49f
ca49a
    jsr caf7f                                                         ; a49a: 20 7f af     ..
    cmp #$3a ; ':'                                                    ; a49d: c9 3a       I:
    beq ca49a                                                         ; a49f: f0 f9       ..
    cmp #0                                                            ; a4a1: c9 00       I.
    beq ca4e9                                                         ; a4a3: f0 44       .d
    tax                                                               ; a4a5: aa          .
    lda #$a1                                                          ; a4a6: a9 a1       ..
    pha                                                               ; a4a8: 48          h
    lda #$f5                                                          ; a4a9: a9 f5       ..
    pha                                                               ; a4ab: 48          h
    cpx #1                                                            ; a4ac: e0 01       ..
    beq ca4ce                                                         ; a4ae: f0 1e       ..
    cpx #$cb ; 'K'                                                    ; a4b0: e0 cb       .K
    bne ca4b7                                                         ; a4b2: d0 03       P.
    jmp cb48c                                                         ; a4b4: 4c 8c b4    l..

; $a4b7 referenced 1 time by $a4b2
ca4b7
    cpx #$7f                                                          ; a4b7: e0 7f       ..
    bcs ca4be                                                         ; a4b9: b0 03       ..
    jmp ca51f                                                         ; a4bb: 4c 1f a5    l..

; $a4be referenced 1 time by $a4b9
ca4be
    cpx #$a7                                                          ; a4be: e0 a7       ..
    bcc ca4c5                                                         ; a4c0: 90 03       ..
    jmp ca6cf                                                         ; a4c2: 4c cf a6    lO.

; $a4c5 referenced 1 time by $a4c0
ca4c5
    lda lbd26,x                                                       ; a4c5: bd 26 bd    .&.
    pha                                                               ; a4c8: 48          h
    lda cbcff,x                                                       ; a4c9: bd ff bc    ...
    pha                                                               ; a4cc: 48          h
    rts                                                               ; a4cd: 60          .

; $a4ce referenced 1 time by $a4ae
ca4ce
    jsr sub_ca14f                                                     ; a4ce: 20 4f a1     o.
    cmp #0                                                            ; a4d1: c9 00       I.
    bne ca4d8                                                         ; a4d3: d0 03       P.
    jmp ca6cf                                                         ; a4d5: 4c cf a6    lO.

; $a4d8 referenced 1 time by $a4d3
ca4d8
    cmp #4                                                            ; a4d8: c9 04       I.
    bcc ca4df                                                         ; a4da: 90 03       ..
    jmp ca6cf                                                         ; a4dc: 4c cf a6    lO.

; $a4df referenced 1 time by $a4da
ca4df
    tax                                                               ; a4df: aa          .
    lda lbff0,x                                                       ; a4e0: bd f0 bf    ...
    pha                                                               ; a4e3: 48          h
    lda lbfed,x                                                       ; a4e4: bd ed bf    ...
    pha                                                               ; a4e7: 48          h
    rts                                                               ; a4e8: 60          .

; $a4e9 referenced 3 times by $a207, $a4a3, $ada3
ca4e9
    ldx basic_current_line+1                                          ; a4e9: a6 3a       .:
    inx                                                               ; a4eb: e8          .
    bne ca4f1                                                         ; a4ec: d0 03       P.
    jmp cac03                                                         ; a4ee: 4c 03 ac    l..

; $a4f1 referenced 1 time by $a4ec
ca4f1
    lda basic_current_line                                            ; a4f1: a5 39       .9
    sta basic_previous_line                                           ; a4f3: 85 3b       .;
    lda basic_current_line+1                                          ; a4f5: a5 3a       .:
    sta basic_previous_line+1                                         ; a4f7: 85 3c       .<
    jsr le132                                                         ; a4f9: 20 32 e1     2.
    lda basic_statement_ptr                                           ; a4fc: a5 3d       .=
    ora basic_statement_ptr+1                                         ; a4fe: 05 3e       .>
    bne ca505                                                         ; a500: d0 03       P.
    jmp cac03                                                         ; a502: 4c 03 ac    l..

; $a505 referenced 3 times by $a500, $b4d0, $badf
ca505
    jsr le3a9                                                         ; a505: 20 a9 e3     ..
    bne ca50d                                                         ; a508: d0 03       P.
    jmp cac03                                                         ; a50a: 4c 03 ac    l..

; $a50d referenced 1 time by $a508
ca50d
    lda basic_statement_ptr                                           ; a50d: a5 3d       .=
    clc                                                               ; a50f: 18          .
    adc #4                                                            ; a510: 69 04       ..
    sta basic_text_ptr                                                ; a512: 85 7a       ..
    lda basic_statement_ptr+1                                         ; a514: a5 3e       .>
    adc #0                                                            ; a516: 69 00       ..
    sta basic_text_ptr+1                                              ; a518: 85 7b       ..
    ldy #2                                                            ; a51a: a0 02       ..
    jmp le480                                                         ; a51c: 4c 80 e4    l..

; $a51f referenced 1 time by $a4bb
ca51f
    cpx #$40 ; '@'                                                    ; a51f: e0 40       .@
    bne ca526                                                         ; a521: d0 03       P.
    jmp ca6b8                                                         ; a523: 4c b8 a6    l..

; $a526 referenced 1 time by $a521
ca526
    cpx #$5f                                                          ; a526: e0 5f       ..
    bne ca52d                                                         ; a528: d0 03       P.
    jmp ca6b8                                                         ; a52a: 4c b8 a6    l..

; $a52d referenced 1 time by $a528
ca52d
    jsr sub_ca71b                                                     ; a52d: 20 1b a7     ..
    jmp basic_command_let                                             ; a530: 4c f3 bd    l..

; $a533 referenced 2 times by $a7de, $bacf
sub_ca533
    jsr sub_cbc12                                                     ; a533: 20 12 bc     ..
; $a536 referenced 1 time by $a568
ca536
    ldy #1                                                            ; a536: a0 01       ..
    jsr le195                                                         ; a538: 20 95 e1     ..
    cmp #0                                                            ; a53b: c9 00       I.
    bne ca540                                                         ; a53d: d0 01       P.
    rts                                                               ; a53f: 60          .

; $a540 referenced 1 time by $a53d
ca540
    ldy #4                                                            ; a540: a0 04       ..
; $a542 referenced 1 time by $a54a
loop_ca542
    jsr le195                                                         ; a542: 20 95 e1     ..
    cmp #0                                                            ; a545: c9 00       I.
    beq ca54f                                                         ; a547: f0 06       ..
    iny                                                               ; a549: c8          H
    bne loop_ca542                                                    ; a54a: d0 f6       P.
    jmp la6c3                                                         ; a54c: 4c c3 a6    lC.

; $a54f referenced 1 time by $a547
ca54f
    iny                                                               ; a54f: c8          H
    tya                                                               ; a550: 98          .
    clc                                                               ; a551: 18          .
    adc basic_statement_ptr                                           ; a552: 65 3d       .=
    pha                                                               ; a554: 48          h
    php                                                               ; a555: 08          .
    ldy #0                                                            ; a556: a0 00       ..
    sta (basic_statement_ptr),y                                       ; a558: 91 3d       .=
    plp                                                               ; a55a: 28          (
    lda basic_statement_ptr+1                                         ; a55b: a5 3e       .>
    adc #0                                                            ; a55d: 69 00       ..
    ldy #1                                                            ; a55f: a0 01       ..
    sta (basic_statement_ptr),y                                       ; a561: 91 3d       .=
    sta basic_statement_ptr+1                                         ; a563: 85 3e       .>
    pla                                                               ; a565: 68          .
    sta basic_statement_ptr                                           ; a566: 85 3d       .=
    jmp ca536                                                         ; a568: 4c 36 a5    l6.

    .byte $a2,   9, $20, $59, $b9, $a2, 8, $ad, $a6, 2, $f0, 2, $a2   ; a56b: a2 09 20... ..
    .byte   7, $4c, $59, $b9, $60                                     ; a578: 07 4c 59... .ly

; $a57d referenced 2 times by $be1a, $be22
sub_ca57d
    jsr caf7f                                                         ; a57d: 20 7f af     ..
    cmp #$b2                                                          ; a580: c9 b2       I.
    beq return_7                                                      ; a582: f0 03       ..
    jmp ca6cf                                                         ; a584: 4c cf a6    lO.

; $a587 referenced 1 time by $a582
return_7
    rts                                                               ; a587: 60          .

; $a588 referenced 1 time by $ade0
sub_ca588
    jsr sub_ca746                                                     ; a588: 20 46 a7     f.
    bcc ca58e                                                         ; a58b: 90 01       ..
    rts                                                               ; a58d: 60          .

; $a58e referenced 1 time by $a58b
ca58e
    bit basic_dim_flag                                                ; a58e: 24 0c       $.
    bpl ca595                                                         ; a590: 10 03       ..
    jmp cbd01                                                         ; a592: 4c 01 bd    l..

; $a595 referenced 1 time by $a590
ca595
    jsr sub_cb1c8                                                     ; a595: 20 c8 b1     H.
    bne ca59d                                                         ; a598: d0 03       P.
    jmp cb60d                                                         ; a59a: 4c 0d b6    l..

; $a59d referenced 1 time by $a598
ca59d
    jsr sub_caead                                                     ; a59d: 20 ad ae     ..
    bne ca5a5                                                         ; a5a0: d0 03       P.
    jmp cbcf4                                                         ; a5a2: 4c f4 bc    l..

; $a5a5 referenced 1 time by $a5a0
ca5a5
    jsr sub_cbf66                                                     ; a5a5: 20 66 bf     ..
    bne ca5ad                                                         ; a5a8: d0 03       P.
    jmp ca409                                                         ; a5aa: 4c 09 a4    l..

; $a5ad referenced 2 times by $a5a8, $be77
ca5ad
    lda basic_variables_start                                         ; a5ad: a5 2d       .-
    sta basic_variable_ptr                                            ; a5af: 85 47       .g
    lda basic_variables_start+1                                       ; a5b1: a5 2e       ..
    sta basic_variable_ptr+1                                          ; a5b3: 85 48       .h
; $a5b5 referenced 1 time by $a5d2
loop_ca5b5
    lda basic_variable_ptr+1                                          ; a5b5: a5 48       .h
    cmp basic_arrays_start+1                                          ; a5b7: c5 30       E0
    bne ca5c1                                                         ; a5b9: d0 06       P.
    lda basic_variable_ptr                                            ; a5bb: a5 47       .g
    cmp basic_arrays_start                                            ; a5bd: c5 2f       E/
    beq ca5d5                                                         ; a5bf: f0 14       ..
; $a5c1 referenced 1 time by $a5b9
ca5c1
    jsr le339                                                         ; a5c1: 20 39 e3     9.
    bne ca5cd                                                         ; a5c4: d0 07       P.
; $a5c6 referenced 1 time by $a641
ca5c6
    lda #2                                                            ; a5c6: a9 02       ..
    jsr sub_cbdd3                                                     ; a5c8: 20 d3 bd     S.
    clc                                                               ; a5cb: 18          .
    rts                                                               ; a5cc: 60          .

; $a5cd referenced 1 time by $a5c4
ca5cd
    lda #7                                                            ; a5cd: a9 07       ..
    jsr sub_cbdd3                                                     ; a5cf: 20 d3 bd     S.
    jmp loop_ca5b5                                                    ; a5d2: 4c b5 a5    l..

; $a5d5 referenced 1 time by $a5bf
ca5d5
    sec                                                               ; a5d5: 38          8
    lda basic_strings_bottom                                          ; a5d6: a5 33       .3
    sbc basic_arrays_end                                              ; a5d8: e5 31       .1
    pha                                                               ; a5da: 48          h
    lda basic_strings_bottom+1                                        ; a5db: a5 34       .4
    sbc basic_arrays_end+1                                            ; a5dd: e5 32       .2
    bne ca5e9                                                         ; a5df: d0 08       P.
    pla                                                               ; a5e1: 68          .
    cmp #7                                                            ; a5e2: c9 07       I.
    bcs ca5ea                                                         ; a5e4: b0 04       ..
    jmp la6ca                                                         ; a5e6: 4c ca a6    lJ.

; $a5e9 referenced 1 time by $a5df
ca5e9
    pla                                                               ; a5e9: 68          .
; $a5ea referenced 1 time by $a5e4
ca5ea
    sec                                                               ; a5ea: 38          8
    lda basic_arrays_end                                              ; a5eb: a5 31       .1
    sta basic_index2                                                  ; a5ed: 85 24       .$
    sbc basic_arrays_start                                            ; a5ef: e5 2f       ./
    sta basic_multiply_result+2                                       ; a5f1: 85 28       .(
    lda basic_arrays_end+1                                            ; a5f3: a5 32       .2
    sta basic_index2+1                                                ; a5f5: 85 25       .%
    sbc basic_arrays_start+1                                          ; a5f7: e5 30       .0
    sta basic_multiply_result+3                                       ; a5f9: 85 29       .)
    ora basic_multiply_result+2                                       ; a5fb: 05 28       .(
    beq ca615                                                         ; a5fd: f0 16       ..
    inc basic_multiply_result+2                                       ; a5ff: e6 28       .(
    bne ca605                                                         ; a601: d0 02       P.
    inc basic_multiply_result+3                                       ; a603: e6 29       .)
; $a605 referenced 1 time by $a601
ca605
    clc                                                               ; a605: 18          .
    lda basic_index2                                                  ; a606: a5 24       .$
    adc #7                                                            ; a608: 69 07       ..
    sta basic_multiply_result                                         ; a60a: 85 26       .&
    lda basic_index2+1                                                ; a60c: a5 25       .%
    adc #0                                                            ; a60e: 69 00       ..
    sta basic_multiply_result+1                                       ; a610: 85 27       .'
    jsr sub_cb1c0                                                     ; a612: 20 c0 b1     ..
; $a615 referenced 1 time by $a5fd
ca615
    clc                                                               ; a615: 18          .
    lda basic_arrays_end                                              ; a616: a5 31       .1
    adc #7                                                            ; a618: 69 07       ..
    sta basic_arrays_end                                              ; a61a: 85 31       .1
    bcc ca620                                                         ; a61c: 90 02       ..
    inc basic_arrays_end+1                                            ; a61e: e6 32       .2
; $a620 referenced 1 time by $a61c
ca620
    clc                                                               ; a620: 18          .
    lda basic_arrays_start                                            ; a621: a5 2f       ./
    adc #7                                                            ; a623: 69 07       ..
    sta basic_arrays_start                                            ; a625: 85 2f       ./
    bcc ca62b                                                         ; a627: 90 02       ..
    inc basic_arrays_start+1                                          ; a629: e6 30       .0
; $a62b referenced 1 time by $a627
ca62b
    jsr sub_caf9b                                                     ; a62b: 20 9b af     ..
    ldy #0                                                            ; a62e: a0 00       ..
    lda basic_variable_name                                           ; a630: a5 45       .e
    sta (basic_variable_ptr),y                                        ; a632: 91 47       .g
    iny                                                               ; a634: c8          H  ; Y=1
    lda basic_variable_name+1                                         ; a635: a5 46       .f
    sta (basic_variable_ptr),y                                        ; a637: 91 47       .g
    iny                                                               ; a639: c8          H  ; Y=2
    lda #0                                                            ; a63a: a9 00       ..
    sta (basic_variable_ptr),y                                        ; a63c: 91 47       .g
    iny                                                               ; a63e: c8          H  ; Y=3
    sta (basic_variable_ptr),y                                        ; a63f: 91 47       .g
    jmp ca5c6                                                         ; a641: 4c c6 a5    lF.

    .byte $60                                                         ; a644: 60          .

; $a645 referenced 2 times by $ac81, $b4a6
sub_ca645
    lda #$25 ; '%'                                                    ; a645: a9 25       .%
    jsr sub_cba2e                                                     ; a647: 20 2e ba     ..
    bcc ca64f                                                         ; a64a: 90 03       ..
    jmp ca6cf                                                         ; a64c: 4c cf a6    lO.

; $a64f referenced 1 time by $a64a
ca64f
    lda basic_line_number+1                                           ; a64f: a5 15       ..
    cmp #$ff                                                          ; a651: c9 ff       I.
    bne return_8                                                      ; a653: d0 03       P.
    jmp ca6b4                                                         ; a655: 4c b4 a6    l..

; $a658 referenced 1 time by $a653
return_8
    rts                                                               ; a658: 60          .

    .byte $60                                                         ; a659: 60          .

basic_command_wait
    jsr sub_cba2e                                                     ; a65a: 20 2e ba     ..
    bcc ca662                                                         ; a65d: 90 03       ..
    jmp ca6cf                                                         ; a65f: 4c cf a6    lO.

; $a662 referenced 1 time by $a65d
ca662
    lda basic_line_number                                             ; a662: a5 14       ..
    pha                                                               ; a664: 48          h
    lda basic_line_number+1                                           ; a665: a5 15       ..
    pha                                                               ; a667: 48          h
    jsr sub_ca1df                                                     ; a668: 20 df a1     ..
    bcc ca670                                                         ; a66b: 90 03       ..
    jmp ca6cf                                                         ; a66d: 4c cf a6    lO.

; $a670 referenced 1 time by $a66b
ca670
    pha                                                               ; a670: 48          h
    jsr sub_ca1df                                                     ; a671: 20 df a1     ..
    bcc ca678                                                         ; a674: 90 02       ..
    lda #0                                                            ; a676: a9 00       ..
; $a678 referenced 1 time by $a674
ca678
    sta basic_index2+1                                                ; a678: 85 25       .%
    pla                                                               ; a67a: 68          .
    sta basic_index2                                                  ; a67b: 85 24       .$
    pla                                                               ; a67d: 68          .
    sta basic_index1+1                                                ; a67e: 85 23       .#
    pla                                                               ; a680: 68          .
    sta basic_index1                                                  ; a681: 85 22       ."
    ldy #0                                                            ; a683: a0 00       ..
; $a685 referenced 1 time by $a68b
loop_ca685
    lda (basic_index1),y                                              ; a685: b1 22       ."
    eor basic_index2+1                                                ; a687: 45 25       e%
    and basic_index2                                                  ; a689: 25 24       %$
    beq loop_ca685                                                    ; a68b: f0 f8       ..
    rts                                                               ; a68d: 60          .

    .byte $a5, $2b, $38, $e9, 1, $85, $7a, $a5, $2c, $e9, 0, $85, $7b ; a68e: a5 2b 38... .+8
; $a69b referenced 3 times by $aff3, $b979, $b98e
la69b
    .byte $60                                                         ; a69b: 60          .
    .byte $20, $55, $46, $4c, $44, $50, $49, $41 ; petscii " ufldpia" ; a69c: 20 55 46...  uf
    .byte $52, $4f, $53, $4e, $45, $54 ; petscii "rosnet"             ; a6a4: 52 4f 53... ros

; $a6aa referenced 2 times by $a9b2, $babe
ca6aa
    tax                                                               ; a6aa: aa          .
    beq ca6bc                                                         ; a6ab: f0 0f       ..
    dex                                                               ; a6ad: ca          J
    bpl ca6ee                                                         ; a6ae: 10 3e       .>
; $a6b0 referenced 1 time by $a312
ca6b0
    inc screen_line_links+13                                          ; a6b0: e6 e6       ..
; $a6b2 referenced 10 times by $a409, $adeb, $ae0d, $bcf4, $bd06, $bdf0, $be62, $be94, $be9e, $bf9e
ca6b2
    inc screen_line_links+13                                          ; a6b2: e6 e6       ..
; $a6b4 referenced 1 time by $a655
ca6b4
    inc screen_line_links+13                                          ; a6b4: e6 e6       ..
    inc screen_line_links+13                                          ; a6b6: e6 e6       ..
; $a6b8 referenced 3 times by $a523, $a52a, $a7ea
ca6b8
    inc screen_line_links+13                                          ; a6b8: e6 e6       ..
    inc screen_line_links+13                                          ; a6ba: e6 e6       ..
; $a6bc referenced 1 time by $a6ab
ca6bc
    inc screen_line_links+13                                          ; a6bc: e6 e6       ..
    inc screen_line_links+13                                          ; a6be: e6 e6       ..
ca6c0
la6c1 = ca6c0+1
    inc screen_line_links+13                                          ; a6c0: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6c1: e6 e6       ..
; $a6c1 referenced 1 time by $bc25
ca6c2
la6c3 = ca6c2+1
    inc screen_line_links+13                                          ; a6c2: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6c3: e6 e6       ..
; $a6c3 referenced 3 times by $a54c, $ac20, $ae34
; $a6c4 referenced 4 times by $b7ff, $be91, $be9b, $bea5
ca6c4
    inc screen_line_links+13                                          ; a6c4: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6c5: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6c6: e6 e6       ..
    .byte $e6                                                         ; a6c6: e6          .

; $a6c7 referenced 1 time by $aec5
ca6c7
la6c8 = ca6c7+1
    inc screen_line_links+13                                          ; a6c7: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6c8: e6 e6       ..
; $a6c8 referenced 1 time by $bd7b
; $a6c9 referenced 1 time by $b4cb
ca6c9
la6ca = ca6c9+1
    inc screen_line_links+13                                          ; a6c9: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6ca: e6 e6       ..
; $a6ca referenced 5 times by $a480, $a5e6, $aeed, $b513, $b92a
; $a6cb referenced 2 times by $a911, $a976
ca6cb
la6cc = ca6cb+1
    inc screen_line_links+13                                          ; a6cb: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6cc: e6 e6       ..
; $a6cc referenced 3 times by $a1ef, $b808, $b81a
    inc screen_line_links+13                                          ; a6cd: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6ce: e6 e6       ..
; $a6cf referenced 23 times by $a1a8, $a20a, $a2a3, $a4c2, $a4d5, $a4dc, $a584, $a64c, $a65f, $a66d, $a735, $a8eb, $adb6, $ae00, $aebd, $b3e2, $b493, $b5c0, $b5e4, $bbbf, $bdf8, $be32, $be3a
ca6cf
    inc screen_line_links+13                                          ; a6cf: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6d0: e6 e6       ..
; $a6d1 referenced 1 time by $a8dc
ca6d1
    inc screen_line_links+13                                          ; a6d1: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6d2: e6 e6       ..
    inc screen_line_links+13                                          ; a6d3: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6d4: e6 e6       ..
    inc screen_line_links+13                                          ; a6d5: e6 e6       ..
; overlapping: inc screen_line_links+13                               ; a6d6: e6 e6       ..
    inc screen_line_links+13                                          ; a6d7: e6 e6       ..
; overlapping: inc screen_line_links+17                               ; a6d8: e6 ea       ..
    nop                                                               ; a6d9: ea          .
    lda screen_line_links+13                                          ; a6da: a5 e6       ..
    pha                                                               ; a6dc: 48          h
    and #$80                                                          ; a6dd: 29 80       ).
    sta screen_line_links+13                                          ; a6df: 85 e6       ..
    pla                                                               ; a6e1: 68          .
    asl a                                                             ; a6e2: 0a          .
    ora screen_line_links+17                                          ; a6e3: 05 ea       ..
    and #$7f                                                          ; a6e5: 29 7f       ).
    tax                                                               ; a6e7: aa          .
    lda screen_line_links+17                                          ; a6e8: a5 ea       ..
    and #$80                                                          ; a6ea: 29 80       ).
    sta screen_line_links+17                                          ; a6ec: 85 ea       ..
; $a6ee referenced 2 times by $a6ae, $ba89
ca6ee
    txa                                                               ; a6ee: 8a          .
    pha                                                               ; a6ef: 48          h
    jsr le060                                                         ; a6f0: 20 60 e0     ..
    ldx #0                                                            ; a6f3: a2 00       ..
    jsr sub_cb959                                                     ; a6f5: 20 59 b9     y.
    pla                                                               ; a6f8: 68          .
    tax                                                               ; a6f9: aa          .
    jsr sub_cb953                                                     ; a6fa: 20 53 b9     s.
    ldx #3                                                            ; a6fd: a2 03       ..
    jsr sub_cb959                                                     ; a6ff: 20 59 b9     y.
    lda basic_current_line+1                                          ; a702: a5 3a       .:
    cmp #$ff                                                          ; a704: c9 ff       I.
    beq ca714                                                         ; a706: f0 0c       ..
    ldx #4                                                            ; a708: a2 04       ..
    jsr sub_cb959                                                     ; a70a: 20 59 b9     y.
    lda basic_current_line+1                                          ; a70d: a5 3a       .:
    ldx basic_current_line                                            ; a70f: a6 39       .9
    jsr sub_cb40e                                                     ; a711: 20 0e b4     ..
; $a714 referenced 1 time by $a706
ca714
    ldx #$fe                                                          ; a714: a2 fe       ..
    txs                                                               ; a716: 9a          .
    jmp cac03                                                         ; a717: 4c 03 ac    l..

    .byte $60                                                         ; a71a: 60          .

; $a71b referenced 14 times by $a422, $a42e, $a444, $a52d, $a752, $a777, $a7a2, $addd, $ae37, $b1b8, $b9cc, $b9d1, $ba79, $bf8b
sub_ca71b
    lda basic_text_ptr                                                ; a71b: a5 7a       ..
    sec                                                               ; a71d: 38          8
    sbc #1                                                            ; a71e: e9 01       ..
    sta basic_text_ptr                                                ; a720: 85 7a       ..
    lda basic_text_ptr+1                                              ; a722: a5 7b       ..
    sbc #0                                                            ; a724: e9 00       ..
    sta basic_text_ptr+1                                              ; a726: 85 7b       ..
    rts                                                               ; a728: 60          .

; $a729 referenced 1 time by $baa6
sub_ca729
    jsr sub_cb9c1                                                     ; a729: 20 c1 b9     A.
    bcs return_9                                                      ; a72c: b0 17       ..
    jsr sub_cadae                                                     ; a72e: 20 ae ad     ..
    lda basic_value_type                                              ; a731: a5 0d       ..
    bmi ca738                                                         ; a733: 30 03       0.
    jmp ca6cf                                                         ; a735: 4c cf a6    lO.

; $a738 referenced 1 time by $a733
ca738
    lda fac1_exponent                                                 ; a738: a5 61       ..
    sta filename_length                                               ; a73a: 85 b7       ..
    lda fac1_mantissa                                                 ; a73c: a5 62       ..
    sta filename_ptr                                                  ; a73e: 85 bb       ..
    lda fac1_mantissa+1                                               ; a740: a5 63       ..
    sta filename_ptr+1                                                ; a742: 85 bc       ..
    clc                                                               ; a744: 18          .
; $a745 referenced 1 time by $a72c
return_9
    rts                                                               ; a745: 60          .

; $a746 referenced 3 times by $a588, $aeb8, $bdf3
sub_ca746
    lda #0                                                            ; a746: a9 00       ..
    sta basic_variable_name+1                                         ; a748: 85 46       .f
    jsr caf7f                                                         ; a74a: 20 7f af     ..
    jsr sub_ca192                                                     ; a74d: 20 92 a1     ..
    bcc ca757                                                         ; a750: 90 05       ..
    jsr sub_ca71b                                                     ; a752: 20 1b a7     ..
    sec                                                               ; a755: 38          8
    rts                                                               ; a756: 60          .

; $a757 referenced 1 time by $a750
ca757
    sta basic_variable_name                                           ; a757: 85 45       .e
    jsr sub_ca14f                                                     ; a759: 20 4f a1     o.
    jsr sub_ca185                                                     ; a75c: 20 85 a1     ..
    bcs ca76b                                                         ; a75f: b0 0a       ..
    sta basic_variable_name+1                                         ; a761: 85 46       .f
; $a763 referenced 1 time by $a769
loop_ca763
    jsr sub_ca14f                                                     ; a763: 20 4f a1     o.
    jsr sub_ca185                                                     ; a766: 20 85 a1     ..
    bcc loop_ca763                                                    ; a769: 90 f8       ..
; $a76b referenced 1 time by $a75f
ca76b
    cmp #$24 ; '$'                                                    ; a76b: c9 24       I$
    beq ca78d                                                         ; a76d: f0 1e       ..
    cmp #$25 ; '%'                                                    ; a76f: c9 25       I%
    beq ca77d                                                         ; a771: f0 0a       ..
    lda #5                                                            ; a773: a9 05       ..
    sta basic_garbage_step                                            ; a775: 85 53       .s
    jsr sub_ca71b                                                     ; a777: 20 1b a7     ..
    jmp ca79b                                                         ; a77a: 4c 9b a7    l..

; $a77d referenced 1 time by $a771
ca77d
    ldy #2                                                            ; a77d: a0 02       ..
    lda #2                                                            ; a77f: a9 02       ..
    sta basic_garbage_step                                            ; a781: 85 53       .s
    lda basic_variable_name                                           ; a783: a5 45       .e
    ora #$80                                                          ; a785: 09 80       ..
    sta basic_variable_name                                           ; a787: 85 45       .e
    lda #0                                                            ; a789: a9 00       ..
    beq ca791                                                         ; a78b: f0 04       .. ; ALWAYS branch

; $a78d referenced 1 time by $a76d
ca78d
    ldy #3                                                            ; a78d: a0 03       ..
    lda #$ff                                                          ; a78f: a9 ff       ..
; $a791 referenced 1 time by $a78b
ca791
    sta basic_value_type                                              ; a791: 85 0d       ..
    sty basic_garbage_step                                            ; a793: 84 53       .s
    lda basic_variable_name+1                                         ; a795: a5 46       .f
    ora #$80                                                          ; a797: 09 80       ..
    sta basic_variable_name+1                                         ; a799: 85 46       .f
; $a79b referenced 1 time by $a77a
ca79b
    jsr caf7f                                                         ; a79b: 20 7f af     ..
    cmp #$28 ; '('                                                    ; a79e: c9 28       I(
    beq ca7a8                                                         ; a7a0: f0 06       ..
    jsr sub_ca71b                                                     ; a7a2: 20 1b a7     ..
    lda #0                                                            ; a7a5: a9 00       ..
; overlapping: bit lffa9                                              ; a7a7: 2c a9 ff    ,..
    .byte $2c                                                         ; a7a7: 2c          ,

; $a7a8 referenced 1 time by $a7a0
ca7a8
    lda #$ff                                                          ; a7a8: a9 ff       ..
    sta basic_dim_flag                                                ; a7aa: 85 0c       ..
    clc                                                               ; a7ac: 18          .
    rts                                                               ; a7ad: 60          .

    .byte $4c, $96, $b4                                               ; a7ae: 4c 96 b4    l..

; $a7b1 referenced 1 time by $acaa
sub_ca7b1
    lda basic_end_char                                                ; a7b1: a5 08       ..
    sec                                                               ; a7b3: 38          8
    sbc basic_search_char                                             ; a7b4: e5 07       ..
    clc                                                               ; a7b6: 18          .
    adc #5                                                            ; a7b7: 69 05       ..
    tax                                                               ; a7b9: aa          .
    jsr le457                                                         ; a7ba: 20 57 e4     w.
    ldy #1                                                            ; a7bd: a0 01       ..
    tya                                                               ; a7bf: 98          .  ; A=1
    sta (basic_statement_ptr),y                                       ; a7c0: 91 3d       .=
    iny                                                               ; a7c2: c8          H  ; Y=2
    lda basic_line_number                                             ; a7c3: a5 14       ..
    sta (basic_statement_ptr),y                                       ; a7c5: 91 3d       .=
    iny                                                               ; a7c7: c8          H  ; Y=3
    lda basic_line_number+1                                           ; a7c8: a5 15       ..
    sta (basic_statement_ptr),y                                       ; a7ca: 91 3d       .=
    inc basic_end_char                                                ; a7cc: e6 08       ..
; $a7ce referenced 1 time by $a7dc
loop_ca7ce
    ldx basic_search_char                                             ; a7ce: a6 07       ..
    lda basic_input_buffer,x                                          ; a7d0: bd 00 02    ...
    inc basic_search_char                                             ; a7d3: e6 07       ..
    iny                                                               ; a7d5: c8          H
    sta (basic_statement_ptr),y                                       ; a7d6: 91 3d       .=
    lda basic_search_char                                             ; a7d8: a5 07       ..
    cmp basic_end_char                                                ; a7da: c5 08       E.
    bne loop_ca7ce                                                    ; a7dc: d0 f0       P.
; $a7de referenced 2 times by $a31a, $af94
ca7de
    jsr sub_ca533                                                     ; a7de: 20 33 a5     3.
    jmp le312                                                         ; a7e1: 4c 12 e3    l..

    .byte $60                                                         ; a7e4: 60          .

; $a7e5 referenced 1 time by $af8c
sub_ca7e5
    ldx basic_current_line+1                                          ; a7e5: a6 3a       .:
    inx                                                               ; a7e7: e8          .
    beq return_10                                                     ; a7e8: f0 03       ..
    jmp ca6b8                                                         ; a7ea: 4c b8 a6    l..

; $a7ed referenced 1 time by $a7e8
return_10
    rts                                                               ; a7ed: 60          .

    .byte $84, $23, $86, $22, $a0,   0, $a5, $61, $91, $22, $f0, $22  ; a7ee: 84 23 86... .#.
    .byte $c8, $a5, $6d, $91, $22, $a5, $66, $d0,   6, $a5, $6d, $29  ; a7fa: c8 a5 6d... H..
    .byte $7f, $91, $22, $c8, $a5, $6c, $91, $22, $c8, $a5, $6b, $91  ; a806: 7f 91 22... .."
    .byte $22, $c8, $a5, $6a, $91, $22, $a0,   0, $84, $70, $a5, $61  ; a812: 22 c8 a5... "H.
    .byte $60, $a5, $62, $c5, $6a, $90, $3b, $d0, $1d, $a5, $63, $c5  ; a81e: 60 a5 62... ...
    .byte $6b, $90, $33, $d0, $15, $a5, $64, $c5, $6c, $90, $2b, $d0  ; a82a: 6b 90 33... ..3
    .byte $0d, $a5, $65, $c5, $6d, $90, $23, $d0,   5, $a9,   0, $85  ; a836: 0d a5 65... ...
    .byte $61, $60, $38, $a5, $65, $e5, $6d, $85, $65, $a5, $64, $e5  ; a842: 61 60 38... ..8
    .byte $6c, $85, $64, $a5, $63, $e5, $6b, $85, $63, $a5, $62, $e5  ; a84e: 6c 85 64... ...
    .byte $6a, $85, $62, $4c, $1e, $b5, $20, $b8, $bf, $38, $a9,   0  ; a85a: 6a 85 62... ...
    .byte $e5, $70, $85, $70, $a5, $6d, $e5, $65, $85, $65, $a5, $6c  ; a866: e5 70 85... ...
    .byte $e5, $64, $85, $64, $a5, $6b, $e5, $63, $85, $63, $a5, $6a  ; a872: e5 64 85... ...
    .byte $e5, $62, $85, $62, $4c, $1e, $b5                           ; a87e: e5 62 85... ...

; $a885 referenced 1 time by $ac59
ca885
    lda #0                                                            ; a885: a9 00       ..
    sta basic_input_buffer,x                                          ; a887: 9d 00 02    ...
    jsr clall                                                         ; a88a: 20 e7 ff     .. ; Close all files
    jsr leb8c                                                         ; a88d: 20 8c eb     ..
    lda #$0f                                                          ; a890: a9 0f       .. ; A=logical file number
    ldy #$0f                                                          ; a892: a0 0f       .. ; Y=secondary address
    jsr setlfs                                                        ; a894: 20 ba ff     .. ; Set the logical file number, device number and secondary address
    jsr sub_cbc45                                                     ; a897: 20 45 bc     e.
    jsr sub_ca14f                                                     ; a89a: 20 4f a1     o.
    ldy #0                                                            ; a89d: a0 00       ..
    lda (basic_text_ptr),y                                            ; a89f: b1 7a       ..
    bne ca8a6                                                         ; a8a1: d0 03       P.
    jmp ca929                                                         ; a8a3: 4c 29 a9    l).

; $a8a6 referenced 1 time by $a8a1
ca8a6
    cmp #$24 ; '$'                                                    ; a8a6: c9 24       I$
    bne ca8ad                                                         ; a8a8: d0 03       P.
    jmp ca945                                                         ; a8aa: 4c 45 a9    le.

; $a8ad referenced 1 time by $a8a8
ca8ad
    jsr ca18b                                                         ; a8ad: 20 8b a1     ..
    bcc ca8d5                                                         ; a8b0: 90 23       .#
    jsr sub_ca9b5                                                     ; a8b2: 20 b5 a9     ..
    jsr setnam                                                        ; a8b5: 20 bd ff     .. ; Set the filename
    jsr open                                                          ; a8b8: 20 c0 ff     .. ; Open a logical file (set up with SETLFS and SETNAM)
    bcc ca8c0                                                         ; a8bb: 90 03       ..
    jmp ca9ad                                                         ; a8bd: 4c ad a9    l..

; $a8c0 referenced 1 time by $a8bb
ca8c0
    jsr clall                                                         ; a8c0: 20 e7 ff     .. ; Close all files
    jsr sub_ca8f4                                                     ; a8c3: 20 f4 a8     ..
    lda basic_input_buffer                                            ; a8c6: ad 00 02    ...
    cmp #$30 ; '0'                                                    ; a8c9: c9 30       I0
    bne ca92c                                                         ; a8cb: d0 5f       P.
    eor basic_input_buffer+1                                          ; a8cd: 4d 01 02    m..
    bne ca92c                                                         ; a8d0: d0 5a       Pz
    jmp ca9a7                                                         ; a8d2: 4c a7 a9    l..

; $a8d5 referenced 1 time by $a8b0
ca8d5
    jsr sub_ca1e4                                                     ; a8d5: 20 e4 a1     ..
    cmp #8                                                            ; a8d8: c9 08       I.
    bcs ca8df                                                         ; a8da: b0 03       ..
    jmp ca6d1                                                         ; a8dc: 4c d1 a6    lQ.

; $a8df referenced 1 time by $a8da
ca8df
    pha                                                               ; a8df: 48          h
    jsr caf7f                                                         ; a8e0: 20 7f af     ..
    cmp #$24 ; '$'                                                    ; a8e3: c9 24       I$
    beq ca940                                                         ; a8e5: f0 59       .y
    cmp #0                                                            ; a8e7: c9 00       I.
    beq ca8ee                                                         ; a8e9: f0 03       ..
    jmp ca6cf                                                         ; a8eb: 4c cf a6    lO.

; $a8ee referenced 1 time by $a8e9
ca8ee
    pla                                                               ; a8ee: 68          .
    sta device_number                                                 ; a8ef: 85 ba       ..
    jmp cac03                                                         ; a8f1: 4c 03 ac    l..

; $a8f4 referenced 2 times by $a8c3, $a929
sub_ca8f4
    lda #0                                                            ; a8f4: a9 00       .. ; A=filename length
    jsr setnam                                                        ; a8f6: 20 bd ff     .. ; Set no filename
    jsr open                                                          ; a8f9: 20 c0 ff     .. ; Open a logical file (set up with SETLFS and SETNAM)
    bcc ca901                                                         ; a8fc: 90 03       ..
    jmp ca9ad                                                         ; a8fe: 4c ad a9    l..

; $a901 referenced 1 time by $a8fc
ca901
    ldx #$0f                                                          ; a901: a2 0f       .. ; X=logical file number
    jsr chkin                                                         ; a903: 20 c6 ff     F. ; Open a channel for input
    bcc ca90b                                                         ; a906: 90 03       ..
    jmp ca9ad                                                         ; a908: 4c ad a9    l..

; $a90b referenced 1 time by $a906
ca90b
    ldy #0                                                            ; a90b: a0 00       ..
; $a90d referenced 1 time by $a925
loop_ca90d
    cpy #$50 ; 'p'                                                    ; a90d: c0 50       .p
    bne ca914                                                         ; a90f: d0 03       P.
    jmp ca6cb                                                         ; a911: 4c cb a6    lK.

; $a914 referenced 1 time by $a90f
ca914
    jsr readst                                                        ; a914: 20 b7 ff     .. ; Read the I/O status
    bne ca927                                                         ; a917: d0 0e       P.
    jsr chrin                                                         ; a919: 20 cf ff     O. ; Read a character from the input channel
    bcc ca921                                                         ; a91c: 90 03       ..
    jmp ca9ad                                                         ; a91e: 4c ad a9    l..

; $a921 referenced 1 time by $a91c
ca921
    sta basic_input_buffer,y                                          ; a921: 99 00 02    ...
    iny                                                               ; a924: c8          H
    bne loop_ca90d                                                    ; a925: d0 e6       P.
; $a927 referenced 1 time by $a917
ca927
    dey                                                               ; a927: 88          .
    rts                                                               ; a928: 60          .

; $a929 referenced 1 time by $a8a3
ca929
    jsr sub_ca8f4                                                     ; a929: 20 f4 a8     ..
; $a92c referenced 2 times by $a8cb, $a8d0
ca92c
    jsr lf7c1                                                         ; a92c: 20 c1 f7     A.
    ldx #0                                                            ; a92f: a2 00       ..
; $a931 referenced 1 time by $a93b
loop_ca931
    dey                                                               ; a931: 88          .
    bmi ca93d                                                         ; a932: 30 09       0.
    lda basic_input_buffer,x                                          ; a934: bd 00 02    ... ; A=character to output
    jsr chrout                                                        ; a937: 20 d2 ff     R. ; Output a character
    inx                                                               ; a93a: e8          .
    bne loop_ca931                                                    ; a93b: d0 f4       P.
; $a93d referenced 1 time by $a932
ca93d
    jmp ca9a7                                                         ; a93d: 4c a7 a9    l..

; $a940 referenced 1 time by $a8e5
ca940
    pla                                                               ; a940: 68          .
    sta device_number                                                 ; a941: 85 ba       ..
    dec basic_text_ptr                                                ; a943: c6 7a       F.
; $a945 referenced 1 time by $a8aa
ca945
    lda #0                                                            ; a945: a9 00       .. ; A=logical file number
    ldx device_number                                                 ; a947: a6 ba       .. ; X=device number
    ldy #$60                                                          ; a949: a0 60       .. ; Y=secondary address
    jsr setlfs                                                        ; a94b: 20 ba ff     .. ; Set the logical file number, device number and secondary address
    jsr sub_ca9b5                                                     ; a94e: 20 b5 a9     ..
    jsr open                                                          ; a951: 20 c0 ff     .. ; Open a logical file (set up with SETLFS and SETNAM)
    bcs ca9ad                                                         ; a954: b0 57       .w
    ldx #0                                                            ; a956: a2 00       .. ; X=logical file number
    jsr chkin                                                         ; a958: 20 c6 ff     F. ; Open a channel for input
    bcs ca9ad                                                         ; a95b: b0 50       .p
    jsr chrin                                                         ; a95d: 20 cf ff     O. ; Read a character from the input channel
    bcs ca9ad                                                         ; a960: b0 4b       .k
    jsr chrin                                                         ; a962: 20 cf ff     O. ; Read a character from the input channel
    bcs ca9ad                                                         ; a965: b0 46       .f
; $a967 referenced 1 time by $a9a5
ca967
    ldy #$ff                                                          ; a967: a0 ff       ..
; $a969 referenced 2 times by $a980, $a985
ca969
    iny                                                               ; a969: c8          H
    jsr chrin                                                         ; a96a: 20 cf ff     O. ; Read a character from the input channel
    bcs ca9ad                                                         ; a96d: b0 3e       .>
    sta basic_input_buffer,y                                          ; a96f: 99 00 02    ... ; A=character read
    cpy #$50 ; 'p'                                                    ; a972: c0 50       .p
    bne ca979                                                         ; a974: d0 03       P.
    jmp ca6cb                                                         ; a976: 4c cb a6    lK.

; $a979 referenced 1 time by $a974
ca979
    jsr readst                                                        ; a979: 20 b7 ff     .. ; Read the I/O status
    bne ca989                                                         ; a97c: d0 0b       P.
    cpy #4                                                            ; a97e: c0 04       ..
    bcc ca969                                                         ; a980: 90 e7       ..
    lda basic_input_buffer,y                                          ; a982: b9 00 02    ...
    bne ca969                                                         ; a985: d0 e2       P.
    beq ca98d                                                         ; a987: f0 04       .. ; ALWAYS branch

; $a989 referenced 1 time by $a97c
ca989
    lda #$40 ; '@'                                                    ; a989: a9 40       .@
    sta io_status                                                     ; a98b: 85 90       ..
; $a98d referenced 1 time by $a987
ca98d
    cpy #5                                                            ; a98d: c0 05       ..
    bcc ca9a7                                                         ; a98f: 90 16       ..
    lda #0                                                            ; a991: a9 00       ..
    sta basic_input_buffer,y                                          ; a993: 99 00 02    ...
    ldx #0                                                            ; a996: a2 00       ..
    stx basic_statement_ptr                                           ; a998: 86 3d       .=
    ldx #2                                                            ; a99a: a2 02       ..
    stx basic_statement_ptr+1                                         ; a99c: 86 3e       .>
    ldx #$3d ; '='                                                    ; a99e: a2 3d       .=
    jsr sub_cab54                                                     ; a9a0: 20 54 ab     t.
    lda io_status                                                     ; a9a3: a5 90       ..
    beq ca967                                                         ; a9a5: f0 c0       ..
; $a9a7 referenced 3 times by $a8d2, $a93d, $a98f
ca9a7
    jsr clall                                                         ; a9a7: 20 e7 ff     .. ; Close all files
    jmp cac03                                                         ; a9aa: 4c 03 ac    l..

; $a9ad referenced 9 times by $a8bd, $a8fe, $a908, $a91e, $a954, $a95b, $a960, $a965, $a96d
ca9ad
    pha                                                               ; a9ad: 48          h
    jsr clall                                                         ; a9ae: 20 e7 ff     .. ; Close all files
    pla                                                               ; a9b1: 68          .
    jmp ca6aa                                                         ; a9b2: 4c aa a6    l..

; $a9b5 referenced 2 times by $a8b2, $a94e
sub_ca9b5
    ldy #$ff                                                          ; a9b5: a0 ff       ..
; $a9b7 referenced 1 time by $a9ba
loop_ca9b7
    iny                                                               ; a9b7: c8          H
    lda (basic_text_ptr),y                                            ; a9b8: b1 7a       ..
    bne loop_ca9b7                                                    ; a9ba: d0 fb       P.
    tya                                                               ; a9bc: 98          .  ; A=filename length
    ldx basic_text_ptr                                                ; a9bd: a6 7a       .. ; X=filename address (low byte)
    ldy basic_text_ptr+1                                              ; a9bf: a4 7b       .. ; Y=filename address (high byte)
    jmp setnam                                                        ; a9c1: 4c bd ff    l.. ; Set the filename

    .byte $60, $a9,   0, $85, $61, $60, $a5, $61, $f0, $fb, $a5, $69  ; a9c4: 60 a9 00... ...
    .byte $d0,   4, $85, $61, $f0, $f3, $a5, $66, $45, $6e, $85, $66  ; a9d0: d0 04 85... P..
    .byte $20, $b1, $a1, $a5, $61, $20, $be, $a1, $a5, $69, $20, $be  ; a9dc: 20 b1 a1...  ..
    .byte $a1, $a5, $26, $e9, $80, $85, $26, $b0,   8, $a5, $27, $e9  ; a9e8: a1 a5 26... ..&
    .byte   0, $90, $ce, $85, $27, $a5, $27, $f0,   3, $4c, $a3, $b8  ; a9f4: 00 90 ce... ..N
    .byte $a5, $26, $85, $61, $20, $b1, $a1, $18, $a5, $70, $20, $67  ; aa00: a5 26 85... .&.
    .byte $aa, $20, $a5, $a3, $90,   2, $e6, $26, $a5, $65, $20, $67  ; aa0c: aa 20 a5... . .
    .byte $aa, $20, $a5, $a3, $90,   2, $e6, $26, $a5, $64, $20, $67  ; aa18: aa 20 a5... . .
    .byte $aa, $20, $a5, $a3, $90,   2, $e6, $26, $a5, $63, $20, $67  ; aa24: aa 20 a5... . .
    .byte $aa, $20, $a5, $a3, $90,   2, $e6, $26, $a5, $62, $20, $67  ; aa30: aa 20 a5... . .
    .byte $aa, $20, $a5, $a3, $90,   2, $e6, $26, $a5, $2a, $85, $70  ; aa3c: aa 20 a5... . .
    .byte $a5, $29, $85, $65, $a5, $28, $85, $64, $a5, $27, $85, $63  ; aa48: a5 29 85... .).
    .byte $a5, $26, $85, $62, $a5, $61, $18, $69,   8, $90,   3, $4c  ; aa54: a5 26 85... .&.
    .byte $a3, $b8, $85, $61, $4c, $1e, $b5, $f0, $52, $85, $25, $a5  ; aa60: a3 b8 85... ...
    .byte $6d, $20, $cd, $bc, $65, $2a, $85, $2a, $8a, $65, $29, $85  ; aa6c: 6d 20 cd... . M
    .byte $29, $90, $0a, $e6, $28, $d0,   6, $e6, $27, $d0,   2, $e6  ; aa78: 29 90 0a... )..
    .byte $26, $a5, $6c, $20, $cd, $bc, $65, $29, $85, $29, $8a, $65  ; aa84: 26 a5 6c... &..
    .byte $28, $85, $28, $90,   6, $e6, $27, $d0,   2, $e6, $26, $a5  ; aa90: 28 85 28... (.(
    .byte $6b, $20, $cd, $bc, $65, $28, $85, $28, $8a, $65, $27, $85  ; aa9c: 6b 20 cd... . M
    .byte $27, $90,   2, $e6, $26, $a5, $6a, $20, $cd, $bc, $65, $27  ; aaa8: 27 90 02... '..
    .byte $85, $27, $8a, $65, $26, $85, $26, $60, $60                 ; aab4: 85 27 8a... .'.
; $aabd referenced 2 times by $b437, $bc01
laabd
    .byte   0,   0,   0,   3, $27, $68, $45, $0d, $10,   3, $4c, $c4  ; aabd: 00 00 00... ...
    .byte $a6, $a5, $0d, $30,   3, $4c, $b2, $a6, $68, $85, $6b, $68  ; aac9: a6 a5 0d... ...
    .byte $85, $6a, $68, $85, $69, $f0, $3c, $a5, $61, $d0, $12, $20  ; aad5: 85 6a 68... ...
    .byte $5c, $bc, $a5, $69, $85, $61, $a5, $6a, $85, $62, $a5, $6b  ; aae1: 5c bc a5... ...
    .byte $85, $63, $4c, $80, $ae, $18, $65, $69, $90,   3, $4c, $c3  ; aaed: 85 63 4c... ..l
    .byte $a6, $20,   7, $e1, $a0,   1, $b1, $47, $85, $22, $c8, $b1  ; aaf9: a6 20 07... . .
    .byte $47, $85, $23, $20, $94, $e4, $20, $5c, $bc                 ; ab05: 47 85 23... g.#

    ; Copy 3 bytes of memory to fac1_exponent
    ldy #2                                                            ; ab0e: a0 02       ..
; $ab10 referenced 1 time by $ab16
loop_cab10
    lda (basic_variable_ptr),y                                        ; ab10: b1 47       .g
    sta fac1_exponent,y                                               ; ab12: 99 61 00    ...
    dey                                                               ; ab15: 88          .
    bpl loop_cab10                                                    ; ab16: 10 f8       ..
    jsr sub_cbc65                                                     ; ab18: 20 65 bc     ..
    jmp cae80                                                         ; ab1b: 4c 80 ae    l..

; $ab1e referenced 1 time by $abc9
sub_cab1e
    sty basic_string_temp_ptr+1                                       ; ab1e: 84 36       .6
    sta basic_string_temp_ptr                                         ; ab20: 85 35       .5
    txa                                                               ; ab22: 8a          .
    pha                                                               ; ab23: 48          h
    ldy #0                                                            ; ab24: a0 00       ..
; $ab26 referenced 1 time by $ab32
loop_cab26
    tya                                                               ; ab26: 98          .
    tax                                                               ; ab27: aa          .
    lda (basic_string_temp_ptr),y                                     ; ab28: b1 35       .5 ; A=character to output
    beq cab34                                                         ; ab2a: f0 08       ..
    jsr chrout                                                        ; ab2c: 20 d2 ff     R. ; Output a character
    txa                                                               ; ab2f: 8a          .
    tay                                                               ; ab30: a8          .
    iny                                                               ; ab31: c8          H
    bne loop_cab26                                                    ; ab32: d0 f2       P.
; $ab34 referenced 1 time by $ab2a
cab34
    pla                                                               ; ab34: 68          .
    tax                                                               ; ab35: aa          .
    rts                                                               ; ab36: 60          .

    .byte $a5, $6d, $85, $65, $a5, $6c, $85, $64, $a5, $6b, $85, $63  ; ab37: a5 6d 85... ...
    .byte $a5, $6a, $85, $62, $a5, $6e, $85, $66, $a5, $69, $85, $61  ; ab43: a5 6a 85... ...
    .byte $a2,   0, $86, $70, $60                                     ; ab4f: a2 00 86... ...

; $ab54 referenced 1 time by $a9a0
sub_cab54
    jsr lf7c1                                                         ; ab54: 20 c1 f7     A.
    ldy #3                                                            ; ab57: a0 03       ..
    jsr le195                                                         ; ab59: 20 95 e1     ..
    pha                                                               ; ab5c: 48          h
    dey                                                               ; ab5d: 88          .
    jsr le195                                                         ; ab5e: 20 95 e1     ..
    tax                                                               ; ab61: aa          .
    pla                                                               ; ab62: 68          .
    jsr sub_cb40e                                                     ; ab63: 20 0e b4     ..
    jsr lf7c6                                                         ; ab66: 20 c6 f7     F.
    lda #0                                                            ; ab69: a9 00       ..
    sta quote_mode_flag                                               ; ab6b: 85 d4       .T
    ldy #4                                                            ; ab6d: a0 04       ..
; $ab6f referenced 2 times by $abaf, $abd8
cab6f
    jsr le195                                                         ; ab6f: 20 95 e1     ..
    cmp #0                                                            ; ab72: c9 00       I.
    bne cab77                                                         ; ab74: d0 01       P.
    rts                                                               ; ab76: 60          .

; $ab77 referenced 1 time by $ab74
cab77
    cmp #$22 ; '"'                                                    ; ab77: c9 22       I"
    bne cab86                                                         ; ab79: d0 0b       P.
    lda quote_mode_flag                                               ; ab7b: a5 d4       .T
    eor #$ff                                                          ; ab7d: 49 ff       i.
    sta quote_mode_flag                                               ; ab7f: 85 d4       .T
    lda #$22 ; '"'                                                    ; ab81: a9 22       ."
    jmp cabb3                                                         ; ab83: 4c b3 ab    l..

; $ab86 referenced 1 time by $ab79
cab86
    ldx quote_mode_flag                                               ; ab86: a6 d4       .T
    bne cabb3                                                         ; ab88: d0 29       P)
    cmp #$ff                                                          ; ab8a: c9 ff       I.
    beq cabb1                                                         ; ab8c: f0 23       .#
    cmp #1                                                            ; ab8e: c9 01       I.
    beq cabe1                                                         ; ab90: f0 4f       .o
    cmp #$7f                                                          ; ab92: c9 7f       I.
    bcc cabb3                                                         ; ab94: 90 1d       ..
    tax                                                               ; ab96: aa          .
    ; push A,Y onto the stack
    pha                                                               ; ab97: 48          h
    tya                                                               ; ab98: 98          .
    pha                                                               ; ab99: 48          h
    txa                                                               ; ab9a: 8a          .
    and #$7f                                                          ; ab9b: 29 7f       ).
    tax                                                               ; ab9d: aa          .
    cpx #$4c ; 'l'                                                    ; ab9e: e0 4c       .l
    bcs cabdc                                                         ; aba0: b0 3a       .:
    jsr sub_cb965                                                     ; aba2: 20 65 b9     ..
    ; pull A,Y from the stack
    pla                                                               ; aba5: 68          .
    tay                                                               ; aba6: a8          .
    pla                                                               ; aba7: 68          .
    cmp #$8f                                                          ; aba8: c9 8f       I.
    bne cabae                                                         ; abaa: d0 02       P.
    sta quote_mode_flag                                               ; abac: 85 d4       .T
; $abae referenced 2 times by $abaa, $abef
cabae
    iny                                                               ; abae: c8          H
    bne cab6f                                                         ; abaf: d0 be       P.
; $abb1 referenced 1 time by $ab8c
cabb1
    lda #$7e                                                          ; abb1: a9 7e       ..
; $abb3 referenced 3 times by $ab83, $ab88, $ab94
cabb3
    pha                                                               ; abb3: 48          h
    bit quote_mode_flag                                               ; abb4: 24 d4       $T
    bpl cabd1                                                         ; abb6: 10 19       ..
    and #$7f                                                          ; abb8: 29 7f       ).
    cmp #$12                                                          ; abba: c9 12       I.
    beq cabd1                                                         ; abbc: f0 13       ..
    and #$60                                                          ; abbe: 29 60       ).
    bne cabd1                                                         ; abc0: d0 0f       P.
    pla                                                               ; abc2: 68          .
; $abc3 referenced 2 times by $abde, $abe6
cabc3
    tya                                                               ; abc3: 98          .
    pha                                                               ; abc4: 48          h
    lda #$88                                                          ; abc5: a9 88       ..
    ldy #$af                                                          ; abc7: a0 af       ..
    jsr sub_cab1e                                                     ; abc9: 20 1e ab     ..
    pla                                                               ; abcc: 68          .
    tay                                                               ; abcd: a8          .
    jmp cabd5                                                         ; abce: 4c d5 ab    lU.

; $abd1 referenced 3 times by $abb6, $abbc, $abc0
cabd1
    pla                                                               ; abd1: 68          .  ; A=character to output
    jsr chrout                                                        ; abd2: 20 d2 ff     R. ; Output a character
; $abd5 referenced 1 time by $abce
cabd5
    iny                                                               ; abd5: c8          H
    beq return_11                                                     ; abd6: f0 03       ..
    jmp cab6f                                                         ; abd8: 4c 6f ab    l..

; $abdb referenced 1 time by $abd6
return_11
    rts                                                               ; abdb: 60          .

; $abdc referenced 2 times by $aba0, $abfe
cabdc
    pla                                                               ; abdc: 68          .
    pla                                                               ; abdd: 68          .
    jmp cabc3                                                         ; abde: 4c c3 ab    lC.

; $abe1 referenced 1 time by $ab90
cabe1
    jsr sub_cabf2                                                     ; abe1: 20 f2 ab     ..
    cpx #3                                                            ; abe4: e0 03       ..
    bcs cabc3                                                         ; abe6: b0 db       ..
    tya                                                               ; abe8: 98          .
    pha                                                               ; abe9: 48          h
    jsr sub_cb95f                                                     ; abea: 20 5f b9     ..
    pla                                                               ; abed: 68          .
    tay                                                               ; abee: a8          .
    jmp cabae                                                         ; abef: 4c ae ab    l..

; $abf2 referenced 1 time by $abe1
sub_cabf2
    iny                                                               ; abf2: c8          H
    jsr le195                                                         ; abf3: 20 95 e1     ..
    cmp #0                                                            ; abf6: c9 00       I.
    tax                                                               ; abf8: aa          .
    beq cabfd                                                         ; abf9: f0 02       ..
    dex                                                               ; abfb: ca          J
    rts                                                               ; abfc: 60          .

; $abfd referenced 1 time by $abf9
cabfd
    dey                                                               ; abfd: 88          .
    jmp cabdc                                                         ; abfe: 4c dc ab    l..

; $ac01 referenced 4 times by $a2c6, $af97, $bada, $bb0c
cac01
    pha                                                               ; ac01: 48          h
    pha                                                               ; ac02: 48          h
; $ac03 referenced 6 times by $a4ee, $a502, $a50a, $a717, $a8f1, $a9aa
cac03
    ldx #2                                                            ; ac03: a2 02       ..
    jsr sub_cb959                                                     ; ac05: 20 59 b9     y.
    lda #$ff                                                          ; ac08: a9 ff       ..
    sta basic_current_line+1                                          ; ac0a: 85 3a       .:
    lda #$80                                                          ; ac0c: a9 80       .. ; A=message flags
    jsr setmsg                                                        ; ac0e: 20 90 ff     .. ; Show only Kernal control messages
; $ac11 referenced 2 times by $ac4e, $acad
cac11
    ldx #0                                                            ; ac11: a2 00       ..
; $ac13 referenced 2 times by $ac16, $ac27
cac13
    jsr chrin                                                         ; ac13: 20 cf ff     O. ; Read a character from the input channel
    bcs cac13                                                         ; ac16: b0 fb       ..
    cmp #$0d                                                          ; ac18: c9 0d       I. ; A=character read
    beq cac2a                                                         ; ac1a: f0 0e       ..
    cpx #$50 ; 'p'                                                    ; ac1c: e0 50       .p
    bcc cac23                                                         ; ac1e: 90 03       ..
    jmp la6c3                                                         ; ac20: 4c c3 a6    lC.

; $ac23 referenced 1 time by $ac1e
cac23
    sta basic_input_buffer,x                                          ; ac23: 9d 00 02    ...
    inx                                                               ; ac26: e8          .
    jmp cac13                                                         ; ac27: 4c 13 ac    l..

; $ac2a referenced 1 time by $ac1a
cac2a
    stx basic_search_char                                             ; ac2a: 86 07       ..
    lda #0                                                            ; ac2c: a9 00       ..
    sta basic_input_buffer,x                                          ; ac2e: 9d 00 02    ...
; $ac31 referenced 1 time by $ac47
loop_cac31
    lda basic_input_buffer                                            ; ac31: ad 00 02    ...
    cmp #$20 ; ' '                                                    ; ac34: c9 20       I
    bne cac49                                                         ; ac36: d0 11       P.
    ldx #1                                                            ; ac38: a2 01       ..
; $ac3a referenced 1 time by $ac43
loop_cac3a
    lda basic_input_buffer,x                                          ; ac3a: bd 00 02    ...
    sta l01ff,x                                                       ; ac3d: 9d ff 01    ...
    inx                                                               ; ac40: e8          .
    cpx basic_search_char                                             ; ac41: e4 07       ..
    bne loop_cac3a                                                    ; ac43: d0 f5       P.
    dec basic_search_char                                             ; ac45: c6 07       F.
    bne loop_cac31                                                    ; ac47: d0 e8       P.
; $ac49 referenced 1 time by $ac36
cac49
    jsr lf7c1                                                         ; ac49: 20 c1 f7     A.
    lda basic_search_char                                             ; ac4c: a5 07       ..
    beq cac11                                                         ; ac4e: f0 c1       .A
    ldx basic_search_char                                             ; ac50: a6 07       ..
    lda basic_input_buffer                                            ; ac52: ad 00 02    ...
    cmp #$40 ; '@'                                                    ; ac55: c9 40       I@
    bne cac5c                                                         ; ac57: d0 03       P.
    jmp ca885                                                         ; ac59: 4c 85 a8    l..

; $ac5c referenced 1 time by $ac57
cac5c
    cmp #$5f                                                          ; ac5c: c9 5f       I.
    bne cac63                                                         ; ac5e: d0 03       P.
    jmp ca19b                                                         ; ac60: 4c 9b a1    l..

; $ac63 referenced 1 time by $ac5e
cac63
    jsr sub_cb662                                                     ; ac63: 20 62 b6     ..
    lda basic_input_buffer                                            ; ac66: ad 00 02    ...
    cmp #$30 ; '0'                                                    ; ac69: c9 30       I0
    bcc cacb0                                                         ; ac6b: 90 43       .c
    cmp #$3a ; ':'                                                    ; ac6d: c9 3a       I:
    bcs cacb0                                                         ; ac6f: b0 3f       .?
    lda basic_search_char                                             ; ac71: a5 07       ..
    sta basic_end_char                                                ; ac73: 85 08       ..
    lda #0                                                            ; ac75: a9 00       ..
    sta basic_search_char                                             ; ac77: 85 07       ..
    lda #0                                                            ; ac79: a9 00       ..
    sta basic_text_ptr                                                ; ac7b: 85 7a       ..
    lda #2                                                            ; ac7d: a9 02       ..
    sta basic_text_ptr+1                                              ; ac7f: 85 7b       ..
    jsr sub_ca645                                                     ; ac81: 20 45 a6     e.
    lda basic_text_ptr                                                ; ac84: a5 7a       ..
    sta basic_search_char                                             ; ac86: 85 07       ..
    ldx basic_search_char                                             ; ac88: a6 07       ..
; $ac8a referenced 1 time by $ac92
loop_cac8a
    lda basic_input_buffer,x                                          ; ac8a: bd 00 02    ...
    cmp #$20 ; ' '                                                    ; ac8d: c9 20       I
    bne cac94                                                         ; ac8f: d0 03       P.
    inx                                                               ; ac91: e8          .
    bne loop_cac8a                                                    ; ac92: d0 f6       P.
; $ac94 referenced 1 time by $ac8f
cac94
    stx basic_search_char                                             ; ac94: 86 07       ..
    jsr le312                                                         ; ac96: 20 12 e3     ..
    jsr le214                                                         ; ac99: 20 14 e2     ..
    bcs caca4                                                         ; ac9c: b0 06       ..
    jsr sub_ca2f0                                                     ; ac9e: 20 f0 a2     ..
    jsr le214                                                         ; aca1: 20 14 e2     ..
; $aca4 referenced 1 time by $ac9c
caca4
    lda basic_search_char                                             ; aca4: a5 07       ..
    cmp basic_end_char                                                ; aca6: c5 08       E.
    beq cacad                                                         ; aca8: f0 03       ..
    jsr sub_ca7b1                                                     ; acaa: 20 b1 a7     ..
; $acad referenced 1 time by $aca8
cacad
    jmp cac11                                                         ; acad: 4c 11 ac    l..

; $acb0 referenced 2 times by $ac6b, $ac6f
cacb0
    jsr sub_cbc45                                                     ; acb0: 20 45 bc     e.
    jmp ca493                                                         ; acb3: 4c 93 a4    l..

; $acb6 referenced 2 times by $aefc, $b518
sub_cacb6
    lda basic_text_ptr                                                ; acb6: a5 7a       ..
    pha                                                               ; acb8: 48          h
    lda basic_text_ptr+1                                              ; acb9: a5 7b       ..
    pha                                                               ; acbb: 48          h
    lda basic_statement_ptr                                           ; acbc: a5 3d       .=
    pha                                                               ; acbe: 48          h
    lda basic_statement_ptr+1                                         ; acbf: a5 3e       .>
    pha                                                               ; acc1: 48          h
    lda #0                                                            ; acc2: a9 00       ..
    sta basic_index1                                                  ; acc4: 85 22       ."
    sta basic_index1+1                                                ; acc6: 85 23       .#
    lda basic_memory_top                                              ; acc8: a5 37       .7
    sta basic_text_ptr                                                ; acca: 85 7a       ..
    lda basic_memory_top+1                                            ; accc: a5 38       .8
    sta basic_text_ptr+1                                              ; acce: 85 7b       ..
; $acd0 referenced 2 times by $ad80, $ad9b
cacd0
    lda basic_strings_bottom+1                                        ; acd0: a5 34       .4
    cmp basic_text_ptr+1                                              ; acd2: c5 7b       E.
    bne cacf6                                                         ; acd4: d0 20       P
    lda basic_strings_bottom                                          ; acd6: a5 33       .3
    cmp basic_text_ptr                                                ; acd8: c5 7a       E.
    bne cacf6                                                         ; acda: d0 1a       P.
    clc                                                               ; acdc: 18          .
    lda basic_index1                                                  ; acdd: a5 22       ."
    adc basic_strings_bottom                                          ; acdf: 65 33       .3
    sta basic_strings_bottom                                          ; ace1: 85 33       .3
    lda basic_index1+1                                                ; ace3: a5 23       .#
    adc basic_strings_bottom+1                                        ; ace5: 65 34       .4
    sta basic_strings_bottom+1                                        ; ace7: 85 34       .4
    pla                                                               ; ace9: 68          .
    sta basic_statement_ptr+1                                         ; acea: 85 3e       .>
    pla                                                               ; acec: 68          .
    sta basic_statement_ptr                                           ; aced: 85 3d       .=
    pla                                                               ; acef: 68          .
    sta basic_text_ptr+1                                              ; acf0: 85 7b       ..
    pla                                                               ; acf2: 68          .
    sta basic_text_ptr                                                ; acf3: 85 7a       ..
    rts                                                               ; acf5: 60          .

; $acf6 referenced 2 times by $acd4, $acda
cacf6
    lda #2                                                            ; acf6: a9 02       ..
    jsr sub_ca167                                                     ; acf8: 20 67 a1     ..
    jsr le02f                                                         ; acfb: 20 2f e0     /.
    bne cad03                                                         ; acfe: d0 03       P.
    jmp cad83                                                         ; ad00: 4c 83 ad    l..

; $ad03 referenced 1 time by $acfe
cad03
    ldy #0                                                            ; ad03: a0 00       ..
    jsr le195                                                         ; ad05: 20 95 e1     ..
    sta basic_multiply_result+2                                       ; ad08: 85 28       .(
    lda #0                                                            ; ad0a: a9 00       ..
    sta basic_multiply_result+3                                       ; ad0c: 85 29       .)
    clc                                                               ; ad0e: 18          .
    lda basic_multiply_result+2                                       ; ad0f: a5 28       .(
    adc #2                                                            ; ad11: 69 02       ..
    sta basic_multiply_result+2                                       ; ad13: 85 28       .(
    bcc cad19                                                         ; ad15: 90 02       ..
    inc basic_multiply_result+3                                       ; ad17: e6 29       .)
; $ad19 referenced 1 time by $ad15
cad19
    iny                                                               ; ad19: c8          H
    jsr le366                                                         ; ad1a: 20 66 e3     ..
    clc                                                               ; ad1d: 18          .
    lda basic_index2                                                  ; ad1e: a5 24       .$
    adc basic_multiply_result+2                                       ; ad20: 65 28       .(
    sta basic_index2                                                  ; ad22: 85 24       .$
    lda basic_index2+1                                                ; ad24: a5 25       .%
    adc basic_multiply_result+3                                       ; ad26: 65 29       .)
    sta basic_index2+1                                                ; ad28: 85 25       .%
    sec                                                               ; ad2a: 38          8
    lda basic_index2                                                  ; ad2b: a5 24       .$
    sbc #1                                                            ; ad2d: e9 01       ..
    sta basic_index2                                                  ; ad2f: 85 24       .$
    bcs cad35                                                         ; ad31: b0 02       ..
    dec basic_index2+1                                                ; ad33: c6 25       F%
; $ad35 referenced 1 time by $ad31
cad35
    clc                                                               ; ad35: 18          .
    lda basic_index2                                                  ; ad36: a5 24       .$
    adc basic_index1                                                  ; ad38: 65 22       ."
    sta basic_multiply_result                                         ; ad3a: 85 26       .&
    lda basic_index2+1                                                ; ad3c: a5 25       .%
    adc basic_index1+1                                                ; ad3e: 65 23       .#
    sta basic_multiply_result+1                                       ; ad40: 85 27       .'
    ldy #1                                                            ; ad42: a0 01       ..
    jsr le376                                                         ; ad44: 20 76 e3     ..
    jsr sub_cb1c0                                                     ; ad47: 20 c0 b1     ..
    ldy #0                                                            ; ad4a: a0 00       ..
    jsr le195                                                         ; ad4c: 20 95 e1     ..
    jsr sub_ca167                                                     ; ad4f: 20 67 a1     ..
    lda fac1_mantissa+1                                               ; ad52: a5 63       ..
    cmp basic_text_ptr+1                                              ; ad54: c5 7b       E.
    bne cad69                                                         ; ad56: d0 11       P.
    lda fac1_mantissa                                                 ; ad58: a5 62       ..
    cmp basic_text_ptr                                                ; ad5a: c5 7a       E.
    bne cad69                                                         ; ad5c: d0 0b       P.
    clc                                                               ; ad5e: 18          .
    adc basic_index1                                                  ; ad5f: 65 22       ."
    sta fac1_mantissa                                                 ; ad61: 85 62       ..
    lda fac1_mantissa+1                                               ; ad63: a5 63       ..
    adc basic_index1+1                                                ; ad65: 65 23       .#
    sta fac1_mantissa+1                                               ; ad67: 85 63       ..
; $ad69 referenced 2 times by $ad56, $ad5c
cad69
    lda fac2_mantissa+1                                               ; ad69: a5 6b       ..
    cmp basic_text_ptr+1                                              ; ad6b: c5 7b       E.
    bne cad80                                                         ; ad6d: d0 11       P.
    lda fac2_mantissa                                                 ; ad6f: a5 6a       ..
    cmp basic_text_ptr                                                ; ad71: c5 7a       E.
    bne cad80                                                         ; ad73: d0 0b       P.
    clc                                                               ; ad75: 18          .
    adc basic_index1                                                  ; ad76: 65 22       ."
    sta fac2_mantissa                                                 ; ad78: 85 6a       ..
    lda fac2_mantissa+1                                               ; ad7a: a5 6b       ..
    adc basic_index1+1                                                ; ad7c: 65 23       .#
    sta fac2_mantissa+1                                               ; ad7e: 85 6b       ..
; $ad80 referenced 2 times by $ad6d, $ad73
cad80
    jmp cacd0                                                         ; ad80: 4c d0 ac    lP.

; $ad83 referenced 1 time by $ad00
cad83
    lda #1                                                            ; ad83: a9 01       ..
    jsr sub_ca167                                                     ; ad85: 20 67 a1     ..
    ldy #0                                                            ; ad88: a0 00       ..
    jsr le188                                                         ; ad8a: 20 88 e1     ..
    tax                                                               ; ad8d: aa          .
    lda #3                                                            ; ad8e: a9 03       ..
    jsr le089                                                         ; ad90: 20 89 e0     ..
    txa                                                               ; ad93: 8a          .
    jsr le089                                                         ; ad94: 20 89 e0     ..
    txa                                                               ; ad97: 8a          .
    jsr sub_ca167                                                     ; ad98: 20 67 a1     ..
    jmp cacd0                                                         ; ad9b: 4c d0 ac    lP.

    .byte $4c, $ae, $ad                                               ; ad9e: 4c ae ad    l..

; $ada1 referenced 1 time by $bbae
basic_command_rem
    pha                                                               ; ada1: 48          h
    pha                                                               ; ada2: 48          h
    jmp ca4e9                                                         ; ada3: 4c e9 a4    l..

    .byte $e6, $61, $d0, 3, $4c, $a3, $b8, $60                        ; ada6: e6 61 d0... ..P

; $adae referenced 6 times by $a72e, $adf6, $b7f8, $bba7, $be46, $bf91
sub_cadae
    lda #0                                                            ; adae: a9 00       ..
    pha                                                               ; adb0: 48          h
; $adb1 referenced 1 time by $ae79
cadb1
    jsr sub_cb9c1                                                     ; adb1: 20 c1 b9     A.
    bcc cadb9                                                         ; adb4: 90 03       ..
    jmp ca6cf                                                         ; adb6: 4c cf a6    lO.

; $adb9 referenced 1 time by $adb4
cadb9
    jsr sub_ca14f                                                     ; adb9: 20 4f a1     o.
    cmp #$22 ; '"'                                                    ; adbc: c9 22       I"
    beq cae16                                                         ; adbe: f0 56       .v
    cmp #$28 ; '('                                                    ; adc0: c9 28       I(
    beq cadf6                                                         ; adc2: f0 32       .2
    cmp #$ab                                                          ; adc4: c9 ab       I.
    bne cadcb                                                         ; adc6: d0 03       P.
    jmp cadf1                                                         ; adc8: 4c f1 ad    l..

; $adcb referenced 1 time by $adc6
cadcb
    cmp #$a8                                                          ; adcb: c9 a8       I.
    bne cadd2                                                         ; adcd: d0 03       P.
    jmp cadee                                                         ; adcf: 4c ee ad    l..

; $add2 referenced 1 time by $adcd
cadd2
    cmp #$ff                                                          ; add2: c9 ff       I.
    bne cadd9                                                         ; add4: d0 03       P.
    jmp cae03                                                         ; add6: 4c 03 ae    l..

; $add9 referenced 1 time by $add4
cadd9
    cmp #$80                                                          ; add9: c9 80       I.
    bcs cadeb                                                         ; addb: b0 0e       ..
    jsr sub_ca71b                                                     ; addd: 20 1b a7     ..
    jsr sub_ca588                                                     ; ade0: 20 88 a5     ..
    bcs cae0d                                                         ; ade3: b0 28       .(
    jsr le34d                                                         ; ade5: 20 4d e3     m.
    jmp cae3a                                                         ; ade8: 4c 3a ae    l:.

; $adeb referenced 1 time by $addb
cadeb
    jmp ca6b2                                                         ; adeb: 4c b2 a6    l..

; $adee referenced 1 time by $adcf
cadee
    ldy #$0d                                                          ; adee: a0 0d       ..
; overlapping: bit l0ea0                                              ; adf0: 2c a0 0e    ,..
    .byte $2c                                                         ; adf0: 2c          ,

; $adf1 referenced 1 time by $adc8
cadf1
    ldy #$0e                                                          ; adf1: a0 0e       ..
    jmp cae6a                                                         ; adf3: 4c 6a ae    l..

; $adf6 referenced 1 time by $adc2
cadf6
    jsr sub_cadae                                                     ; adf6: 20 ae ad     ..
    jsr sub_ca14f                                                     ; adf9: 20 4f a1     o.
    cmp #$29 ; ')'                                                    ; adfc: c9 29       I)
    beq cae3a                                                         ; adfe: f0 3a       .:
    jmp ca6cf                                                         ; ae00: 4c cf a6    lO.

; $ae03 referenced 1 time by $add6
cae03
    lda #$a8                                                          ; ae03: a9 a8       ..
    ldy #$ae                                                          ; ae05: a0 ae       ..
    jsr sub_cbc9c                                                     ; ae07: 20 9c bc     ..
    jmp cae10                                                         ; ae0a: 4c 10 ae    l..

; $ae0d referenced 1 time by $ade3
cae0d
    jmp ca6b2                                                         ; ae0d: 4c b2 a6    l..

; $ae10 referenced 1 time by $ae0a
cae10
    lda #0                                                            ; ae10: a9 00       ..
    sta basic_value_type                                              ; ae12: 85 0d       ..
    beq cae3a                                                         ; ae14: f0 24       .$ ; ALWAYS branch

; $ae16 referenced 1 time by $adbe
cae16
    ldx #$ff                                                          ; ae16: a2 ff       ..
    stx basic_value_type                                              ; ae18: 86 0d       ..
    inx                                                               ; ae1a: e8          .  ; X=0
    stx fac1_exponent                                                 ; ae1b: 86 61       ..
    ldx basic_text_ptr                                                ; ae1d: a6 7a       ..
    stx fac1_mantissa                                                 ; ae1f: 86 62       ..
    ldx basic_text_ptr+1                                              ; ae21: a6 7b       ..
    stx fac1_mantissa+1                                               ; ae23: 86 63       ..
; $ae25 referenced 1 time by $ae32
loop_cae25
    jsr sub_ca14f                                                     ; ae25: 20 4f a1     o.
    cmp #$22 ; '"'                                                    ; ae28: c9 22       I"
    beq cae3a                                                         ; ae2a: f0 0e       ..
    cmp #0                                                            ; ae2c: c9 00       I.
    beq cae37                                                         ; ae2e: f0 07       ..
    inc fac1_exponent                                                 ; ae30: e6 61       ..
    bne loop_cae25                                                    ; ae32: d0 f1       P.
    jmp la6c3                                                         ; ae34: 4c c3 a6    lC.

; $ae37 referenced 1 time by $ae2e
cae37
    jsr sub_ca71b                                                     ; ae37: 20 1b a7     ..
; $ae3a referenced 4 times by $ade8, $adfe, $ae14, $ae2a
cae3a
    jsr sub_cb9c1                                                     ; ae3a: 20 c1 b9     A.
    bcs cae7c                                                         ; ae3d: b0 3d       .=
    jsr sub_ca40c                                                     ; ae3f: 20 0c a4     ..
    bcs cae7c                                                         ; ae42: b0 38       .8
    tay                                                               ; ae44: a8          .
    pla                                                               ; ae45: 68          .
    pha                                                               ; ae46: 48          h
    cmp la34a,y                                                       ; ae47: d9 4a a3    Yj.
    bcc cae5b                                                         ; ae4a: 90 0f       ..
    sty basic_operator_ptr+1                                          ; ae4c: 84 4c       .l
    lda #$ff                                                          ; ae4e: a9 ff       ..
    sta basic_operator_ptr                                            ; ae50: 85 4b       .k
; $ae52 referenced 1 time by $ae57
loop_cae52
    jmp cae84                                                         ; ae52: 4c 84 ae    l..

; $ae55 referenced 1 time by $ae82
cae55
    pla                                                               ; ae55: 68          .
    pha                                                               ; ae56: 48          h
    bne loop_cae52                                                    ; ae57: d0 f9       P.
    ldy basic_operator_ptr+1                                          ; ae59: a4 4c       .l
; $ae5b referenced 1 time by $ae4a
cae5b
    ldx basic_value_type                                              ; ae5b: a6 0d       ..
    bmi cae5f                                                         ; ae5d: 30 00       0.
; $ae5f referenced 1 time by $ae5d
cae5f
    lda fac1_exponent                                                 ; ae5f: a5 61       ..
    pha                                                               ; ae61: 48          h
    lda fac1_mantissa                                                 ; ae62: a5 62       ..
    pha                                                               ; ae64: 48          h
    lda fac1_mantissa+1                                               ; ae65: a5 63       ..
    ; push A,X onto the stack
    pha                                                               ; ae67: 48          h
    txa                                                               ; ae68: 8a          .
    pha                                                               ; ae69: 48          h
; $ae6a referenced 1 time by $adf3
cae6a
    jsr sub_cbc1e                                                     ; ae6a: 20 1e bc     ..
    lda la368,y                                                       ; ae6d: b9 68 a3    ...
    pha                                                               ; ae70: 48          h
    lda la359,y                                                       ; ae71: b9 59 a3    .y.
    pha                                                               ; ae74: 48          h
    lda la34a,y                                                       ; ae75: b9 4a a3    .j.
    pha                                                               ; ae78: 48          h
    jmp cadb1                                                         ; ae79: 4c b1 ad    l..

; $ae7c referenced 2 times by $ae3d, $ae42
cae7c
    lda #0                                                            ; ae7c: a9 00       ..
    sta basic_operator_ptr                                            ; ae7e: 85 4b       .k
; $ae80 referenced 1 time by $ab1b
cae80
    lda basic_operator_ptr                                            ; ae80: a5 4b       .k
    bne cae55                                                         ; ae82: d0 d1       PQ
; $ae84 referenced 1 time by $ae52
cae84
    pla                                                               ; ae84: 68          .
    rts                                                               ; ae85: 60          .

    .byte $60, $a5, $61, $85, $69, $f0, $16, $a5, $62, $85, $6a, $a5  ; ae86: 60 a5 61... ...
    .byte $63, $85, $6b, $a5, $64, $85, $6c, $a5, $65, $85, $6d, $a5  ; ae92: 63 85 6b... ...
    .byte $66, $85, $6e, $a5, $61, $a2,   0, $86, $70, $60, $82, $49  ; ae9e: 66 85 6e... ...
    .byte $0f, $da, $a2                                               ; aeaa: 0f da a2    .Z.

; $aead referenced 2 times by $a59d, $be2d
sub_caead
    lda basic_variable_name+1                                         ; aead: a5 46       .f
    cmp #$49 ; 'i'                                                    ; aeaf: c9 49       Ii
    bne return_12                                                     ; aeb1: d0 04       P.
    lda basic_variable_name                                           ; aeb3: a5 45       .e
    cmp #$54 ; 't'                                                    ; aeb5: c9 54       It
; $aeb7 referenced 1 time by $aeb1
return_12
    rts                                                               ; aeb7: 60          .

basic_command_dim
    jsr sub_ca746                                                     ; aeb8: 20 46 a7     f.
    bcc caec0                                                         ; aebb: 90 03       ..
    jmp ca6cf                                                         ; aebd: 4c cf a6    lO.

; $aec0 referenced 1 time by $aebb
caec0
    jsr sub_cb795                                                     ; aec0: 20 95 b7     ..
    bcs caec8                                                         ; aec3: b0 03       ..
    jmp ca6c7                                                         ; aec5: 4c c7 a6    lG.

; $aec8 referenced 1 time by $aec3
caec8
    lda basic_variable_name+1                                         ; aec8: a5 46       .f
    pha                                                               ; aeca: 48          h
    lda basic_variable_name                                           ; aecb: a5 45       .e
    pha                                                               ; aecd: 48          h
    lda basic_garbage_step                                            ; aece: a5 53       .s
    pha                                                               ; aed0: 48          h
    bit basic_dim_flag                                                ; aed1: 24 0c       $.
    bmi caedf                                                         ; aed3: 30 0a       0.
    lda #$0a                                                          ; aed5: a9 0a       ..
    pha                                                               ; aed7: 48          h
    lda #0                                                            ; aed8: a9 00       ..
    pha                                                               ; aeda: 48          h
    ldx #1                                                            ; aedb: a2 01       ..
    bne caefa                                                         ; aedd: d0 1b       P. ; ALWAYS branch

; $aedf referenced 1 time by $aed3
caedf
    ldx #0                                                            ; aedf: a2 00       ..
; $aee1 referenced 1 time by $aef8
loop_caee1
    inx                                                               ; aee1: e8          .
    jsr sub_ca290                                                     ; aee2: 20 90 a2     ..
    inc basic_line_number                                             ; aee5: e6 14       ..
    bne caeeb                                                         ; aee7: d0 02       P.
    inc basic_line_number+1                                           ; aee9: e6 15       ..
; $aeeb referenced 1 time by $aee7
caeeb
    bne caef0                                                         ; aeeb: d0 03       P.
    jmp la6ca                                                         ; aeed: 4c ca a6    lJ.

; $aef0 referenced 1 time by $aeeb
caef0
    lda basic_line_number                                             ; aef0: a5 14       ..
    pha                                                               ; aef2: 48          h
    lda basic_line_number+1                                           ; aef3: a5 15       ..
    pha                                                               ; aef5: 48          h
    cpy #0                                                            ; aef6: c0 00       ..
    beq loop_caee1                                                    ; aef8: f0 e7       ..
; $aefa referenced 1 time by $aedd
caefa
    txa                                                               ; aefa: 8a          .
    pha                                                               ; aefb: 48          h
    jsr sub_cacb6                                                     ; aefc: 20 b6 ac     ..
    ldy #1                                                            ; aeff: a0 01       ..
    sty fac1_mantissa                                                 ; af01: 84 62       ..
    dey                                                               ; af03: 88          .  ; Y=0
    sty fac1_mantissa+1                                               ; af04: 84 63       ..
    pla                                                               ; af06: 68          .
    sta fac1_exponent                                                 ; af07: 85 61       ..
    jsr sub_ca454                                                     ; af09: 20 54 a4     t.
    lda fac1_exponent                                                 ; af0c: a5 61       ..
    ldy #4                                                            ; af0e: a0 04       ..
    sta (basic_arrays_end),y                                          ; af10: 91 31       .1
    iny                                                               ; af12: c8          H  ; Y=5
    tax                                                               ; af13: aa          .
; $af14 referenced 1 time by $af24
loop_caf14
    pla                                                               ; af14: 68          .
    sta (basic_arrays_end),y                                          ; af15: 91 31       .1
    sta fac1_mantissa+3                                               ; af17: 85 65       ..
    iny                                                               ; af19: c8          H
    pla                                                               ; af1a: 68          .
    sta (basic_arrays_end),y                                          ; af1b: 91 31       .1
    sta fac1_mantissa+2                                               ; af1d: 85 64       ..
    iny                                                               ; af1f: c8          H
    jsr sub_cb901                                                     ; af20: 20 01 b9     ..
    dex                                                               ; af23: ca          J
    bne loop_caf14                                                    ; af24: d0 ee       P.
    sty fac1_sign                                                     ; af26: 84 66       ..
    pla                                                               ; af28: 68          .
    sta basic_garbage_step                                            ; af29: 85 53       .s
    sta fac1_mantissa+2                                               ; af2b: 85 64       ..
    stx fac1_mantissa+3                                               ; af2d: 86 65       ..
    jsr sub_cb901                                                     ; af2f: 20 01 b9     ..
    jsr sub_ca454                                                     ; af32: 20 54 a4     t.
    ldy #0                                                            ; af35: a0 00       ..
    pla                                                               ; af37: 68          .
    sta (basic_arrays_end),y                                          ; af38: 91 31       .1
    iny                                                               ; af3a: c8          H  ; Y=1
    pla                                                               ; af3b: 68          .
    sta (basic_arrays_end),y                                          ; af3c: 91 31       .1
    lda #5                                                            ; af3e: a9 05       ..
    jsr le089                                                         ; af40: 20 89 e0     ..
    lda fac1_exponent                                                 ; af43: a5 61       ..
    asl a                                                             ; af45: 0a          .
    jsr le089                                                         ; af46: 20 89 e0     ..
    ldy #2                                                            ; af49: a0 02       ..
    lda basic_index1                                                  ; af4b: a5 22       ."
    sta (basic_arrays_end),y                                          ; af4d: 91 31       .1
    iny                                                               ; af4f: c8          H  ; Y=3
    lda basic_index1+1                                                ; af50: a5 23       .#
    sta (basic_arrays_end),y                                          ; af52: 91 31       .1
    clc                                                               ; af54: 18          .
    lda fac1_sign                                                     ; af55: a5 66       ..
    adc basic_arrays_end                                              ; af57: 65 31       .1
    sta basic_arrays_end                                              ; af59: 85 31       .1
    bcc caf5f                                                         ; af5b: 90 02       ..
    inc basic_arrays_end+1                                            ; af5d: e6 32       .2
; $af5f referenced 1 time by $af5b
caf5f
    ldy #0                                                            ; af5f: a0 00       ..
; $af61 referenced 1 time by $af78
loop_caf61
    lda #0                                                            ; af61: a9 00       ..
    sta (basic_arrays_end),y                                          ; af63: 91 31       .1
    inc basic_arrays_end                                              ; af65: e6 31       .1
    bne caf6b                                                         ; af67: d0 02       P.
    inc basic_arrays_end+1                                            ; af69: e6 32       .2
; $af6b referenced 1 time by $af67
caf6b
    sec                                                               ; af6b: 38          8
    lda fac1_mantissa                                                 ; af6c: a5 62       ..
    sbc #1                                                            ; af6e: e9 01       ..
    sta fac1_mantissa                                                 ; af70: 85 62       ..
    bcs caf76                                                         ; af72: b0 02       ..
    dec fac1_mantissa+1                                               ; af74: c6 63       F.
; $af76 referenced 1 time by $af72
caf76
    ora fac1_mantissa+1                                               ; af76: 05 63       ..
    bne loop_caf61                                                    ; af78: d0 e7       P.
    rts                                                               ; af7a: 60          .

    .byte $60, 0, 0, $60                                              ; af7b: 60 00 00... ...

; $af7f referenced 14 times by $a1f9, $a298, $a49a, $a57d, $a74a, $a79b, $a8e0, $af84, $b1b1, $b3d7, $b48c, $b9c1, $ba2f, $bbb1
caf7f
    jsr sub_ca14f                                                     ; af7f: 20 4f a1     o.
    cmp #$20 ; ' '                                                    ; af82: c9 20       I
    beq caf7f                                                         ; af84: f0 f9       ..
    rts                                                               ; af86: 60          .

    .byte $60, $12, $3f, $92, 0                                       ; af87: 60 12 3f... ..?

sub_caf8c
    jsr sub_ca7e5                                                     ; af8c: 20 e5 a7     ..
    ldy #1                                                            ; af8f: a0 01       ..
    tya                                                               ; af91: 98          .  ; A=1
    sta (basic_program_start),y                                       ; af92: 91 2b       .+
    jsr ca7de                                                         ; af94: 20 de a7     ..
    jmp cac01                                                         ; af97: 4c 01 ac    l..

    .byte $60                                                         ; af9a: 60          .

; $af9b referenced 1 time by $a62b
sub_caf9b
    lda basic_arrays_start                                            ; af9b: a5 2f       ./
    sta basic_index1                                                  ; af9d: 85 22       ."
    lda basic_arrays_start+1                                          ; af9f: a5 30       .0
    sta basic_index1+1                                                ; afa1: 85 23       .#
; $afa3 referenced 1 time by $afd1
cafa3
    lda basic_index1+1                                                ; afa3: a5 23       .#
    cmp basic_arrays_end+1                                            ; afa5: c5 32       E2
    bne cafb0                                                         ; afa7: d0 07       P.
    lda basic_index1                                                  ; afa9: a5 22       ."
    cmp basic_arrays_end                                              ; afab: c5 31       E1
    bne cafb0                                                         ; afad: d0 01       P.
    rts                                                               ; afaf: 60          .

; $afb0 referenced 2 times by $afa7, $afad
cafb0
    jsr le1e1                                                         ; afb0: 20 e1 e1     ..
    bcs cafc9                                                         ; afb3: b0 14       ..
; $afb5 referenced 2 times by $afc1, $afc7
cafb5
    jsr le163                                                         ; afb5: 20 63 e1     ..
    lda #3                                                            ; afb8: a9 03       ..
    jsr le089                                                         ; afba: 20 89 e0     ..
    lda basic_index1                                                  ; afbd: a5 22       ."
    cmp basic_index2                                                  ; afbf: c5 24       E$
    bne cafb5                                                         ; afc1: d0 f2       P.
    lda basic_index1+1                                                ; afc3: a5 23       .#
    cmp basic_index2+1                                                ; afc5: c5 25       E%
    bne cafb5                                                         ; afc7: d0 ec       P.
; $afc9 referenced 1 time by $afb3
cafc9
    lda basic_index2+1                                                ; afc9: a5 25       .%
    sta basic_index1+1                                                ; afcb: 85 23       .#
    lda basic_index2                                                  ; afcd: a5 24       .$
    sta basic_index1                                                  ; afcf: 85 22       ."
    jmp cafa3                                                         ; afd1: 4c a3 af    l..

; $afd4 referenced 1 time by $b685
sub_cafd4
    lda #0                                                            ; afd4: a9 00       ..
    ldy #$1d                                                          ; afd6: a0 1d       ..
; $afd8 referenced 1 time by $afdc
loop_cafd8
    sta l0101,y                                                       ; afd8: 99 01 01    ...
    dey                                                               ; afdb: 88          .
    bpl loop_cafd8                                                    ; afdc: 10 fa       ..
; $afde referenced 1 time by $b036
cafde
    lda basic_input_buffer,x                                          ; afde: bd 00 02    ...
    cmp #$23 ; '#'                                                    ; afe1: c9 23       I#
    bcc return_13                                                     ; afe3: 90 20       .
    cmp #$7b                                                          ; afe5: c9 7b       I.
    bcs return_13                                                     ; afe7: b0 1c       ..
    cmp #$30 ; '0'                                                    ; afe9: c9 30       I0
    bcc caff1                                                         ; afeb: 90 04       ..
    cmp #$3c ; '<'                                                    ; afed: c9 3c       I<
    bcc return_13                                                     ; afef: 90 14       ..
; $aff1 referenced 1 time by $afeb
caff1
    ldy #$0e                                                          ; aff1: a0 0e       ..
; $aff3 referenced 1 time by $aff9
loop_caff3
    cmp la69b,y                                                       ; aff3: d9 9b a6    Y..
    beq cb006                                                         ; aff6: f0 0e       ..
    dey                                                               ; aff8: 88          .
    bne loop_caff3                                                    ; aff9: d0 f8       P.
    ldy #$16                                                          ; affb: a0 16       ..
; $affd referenced 1 time by $b003
loop_caffd
    cmp return_14,y                                                   ; affd: d9 73 a2    Y..
    beq cb045                                                         ; b000: f0 43       .c
    dey                                                               ; b002: 88          .
    bne loop_caffd                                                    ; b003: d0 f8       P.
; $b005 referenced 3 times by $afe3, $afe7, $afef
return_13
    rts                                                               ; b005: 60          .

; $b006 referenced 1 time by $aff6
cb006
    bit l0104                                                         ; b006: 2c 04 01    ,..
    bpl cb039                                                         ; b009: 10 2e       ..
    tya                                                               ; b00b: 98          .
    asl a                                                             ; b00c: 0a          .
    asl a                                                             ; b00d: 0a          .
    asl a                                                             ; b00e: 0a          .
    asl a                                                             ; b00f: 0a          .
    ldy l0105                                                         ; b010: ac 05 01    ...
    ora l0106,y                                                       ; b013: 19 06 01    ...
    sta l0106,y                                                       ; b016: 99 06 01    ...
    inc l0105                                                         ; b019: ee 05 01    ...
    inc l0104                                                         ; b01c: ee 04 01    ...
; $b01f referenced 1 time by $b043
cb01f
    clc                                                               ; b01f: 18          .
    ror l0102                                                         ; b020: 6e 02 01    ...
    ror l0103                                                         ; b023: 6e 03 01    ...
; $b026 referenced 1 time by $b06a
cb026
    inx                                                               ; b026: e8          .
    inc l0101                                                         ; b027: ee 01 01    ...
    lda l0101                                                         ; b02a: ad 01 01    ...
    cmp #7                                                            ; b02d: c9 07       I.
    beq return_15                                                     ; b02f: f0 07       ..
    lda l01ff,x                                                       ; b031: bd ff 01    ...
    cmp #$41 ; 'a'                                                    ; b034: c9 41       Ia
    bcs cafde                                                         ; b036: b0 a6       ..
; $b038 referenced 1 time by $b02f
return_15
    rts                                                               ; b038: 60          .

; $b039 referenced 1 time by $b009
cb039
    tya                                                               ; b039: 98          .
    ldy l0105                                                         ; b03a: ac 05 01    ...
    sta l0106,y                                                       ; b03d: 99 06 01    ...
    dec l0104                                                         ; b040: ce 04 01    N..
    bmi cb01f                                                         ; b043: 30 da       0Z
; $b045 referenced 1 time by $b000
cb045
    bit l0104                                                         ; b045: 2c 04 01    ,..
    bpl cb06c                                                         ; b048: 10 22       ."
    tya                                                               ; b04a: 98          .
    pha                                                               ; b04b: 48          h
    lda #$f0                                                          ; b04c: a9 f0       ..
    ldy l0105                                                         ; b04e: ac 05 01    ...
    ora l0106,y                                                       ; b051: 19 06 01    ...
    sta l0106,y                                                       ; b054: 99 06 01    ...
    iny                                                               ; b057: c8          H
    pla                                                               ; b058: 68          .
    sta l0106,y                                                       ; b059: 99 06 01    ...
    iny                                                               ; b05c: c8          H
    sty l0105                                                         ; b05d: 8c 05 01    ...
    inc l0104                                                         ; b060: ee 04 01    ...
; $b063 referenced 1 time by $b089
cb063
    sec                                                               ; b063: 38          8
    ror l0102                                                         ; b064: 6e 02 01    ...
    ror l0103                                                         ; b067: 6e 03 01    ...
    bcc cb026                                                         ; b06a: 90 ba       ..
; $b06c referenced 1 time by $b048
cb06c
    tya                                                               ; b06c: 98          .
    ldy l0105                                                         ; b06d: ac 05 01    ...
    sta l0106,y                                                       ; b070: 99 06 01    ...
    iny                                                               ; b073: c8          H
    and #$0f                                                          ; b074: 29 0f       ).
    sta l0106,y                                                       ; b076: 99 06 01    ...
    dey                                                               ; b079: 88          .
    lda l0106,y                                                       ; b07a: b9 06 01    ...
    ora #$0f                                                          ; b07d: 09 0f       ..
    sta l0106,y                                                       ; b07f: 99 06 01    ...
    iny                                                               ; b082: c8          H
    sty l0105                                                         ; b083: 8c 05 01    ...
    dec l0104                                                         ; b086: ce 04 01    N..
    bmi cb063                                                         ; b089: 30 d8       0X
    cmp @w basic_int_to_float_vector                                  ; b08b: cd 05 00    M..
    .byte $a3,   9,   0, $dc, $0f, $ed,   0, $85, $8e,   0, $c7, $26  ; b08e: a3 09 00... ...
    .byte $fe, $0a,   0, $c7, $26, $0e,   0, $75, $1f,   3,   0, $d9  ; b09a: fe 0a 00... ...
    .byte $58,   0, $d4, $0e,   0, $1f, $a5, $ae,   0, $29, $0c,   0  ; b0a6: 58 00 d4... x.T
    .byte $37,   0, $d9, $eb, $9a, $0d,   0, $1f, $a5, $2b, $1f,   2  ; b0b2: 37 00 d9... 7.Y
    .byte   0                                                         ; b0be: 00          .
    .byte $d9, $2e, $c9 ; petscii "Y.I"                               ; b0bf: d9 2e c9    Y.I
    .byte   0, $d9, $1f,   3,   0, $eb, $6a,   0, $ca,   0, $0f, $8f  ; b0c2: 00 d9 1f... .Y.
    .byte $e7,   0, $a4, $58,   0, $8b, $1f, $d1,   0, $1f, $d1, $79  ; b0ce: e7 00 a4... ...
    .byte $f3, $0e,   0, $d5,   3,   0, $a6, $0f, $dc,   0, $96, $c7  ; b0da: f3 0e 00... ...
    .byte $fe, $0a,   0, $96, $c7, $0e,   0, $1f, $a6, $ec,   0, $74  ; b0e6: fe 0a 00... ...
    .byte $eb,   0, $1f, $46,   9,   0, $1f, $f6, $13,   5,   0, $fb  ; b0f2: eb 00 1f... ...
    .byte $0e, $0b,   0, $6a, $cd,   0, $1f, $46, $ba, $0d,   0, $1f  ; b0fe: 0e 0b 00... ...
    .byte $d5, $0e,   0, $dc, $0f, $0f,   0, $8e, $1f, $f2, $0b,   0  ; b10a: d5 0e 00... U..
    .byte $ae,   0, $c3,   0, $6b, $1f, $f6, $0b,   0, $fe, $10, $cd  ; b116: ae 00 c3... ..C
    .byte   0, $ac, $0e,   0, $eb, $6d,   0, $0f,   8,   0, $0f,   5  ; b122: 00 ac 0e... ...
    .byte   0, $0f,   6,   0, $0f,   4,   0, $0f,   7,   0, $c8,   5  ; b12e: 00 0f 06... ...
    .byte   0, $9a,   0, $0f,   1,   0, $0f,   2,   0, $0f,   3,   0  ; b13a: 00 9a 00... ...
    .byte $fb, $15, $0c,   0, $c7, $0e,   0, $f8, $12, $0b,   0, $b2  ; b146: fb 15 0c... ...
    .byte   9,   0, $93, $0d,   0, $a6, $0b,   0, $fb,   9,   9,   0  ; b152: 09 00 93... ...
    .byte $c9,   5,   0, $a4, $1f,   5,   0, $fd, $0d,   6,   0, $1f  ; b15e: c9 05 00... I..
    .byte $a6, $0b,   0, $7b, $0c,   0, $8e, $0c,   0, $e8, $0c,   0  ; b16a: a6 0b 00... ...
    .byte $d6, $fd, $0c,   0, $d4, $0c,   0, $eb, $f9, $14,   0, $1f  ; b176: d6 fd 0c... V..
    .byte $81,   4,   0, $b8, $1f,   6,   0, $1f, $f6, $10, $f9, $14  ; b182: 81 04 00... ...
    .byte   0, $d4, $e3, $1f,   4,   0, $79, $1f, $f5, $10, $fe, $14  ; b18e: 00 d4 e3... .T.
    .byte   0, $1f, $73, $f5, $14,   0, $1f, $a5,   0, $ff, $ff, $90  ; b19a: 00 1f 73... ...
    .byte $80,   0,   0,   0, $60, $4c, $b2, $a6, $4c, $b2, $a6       ; b1a6: 80 00 00... ...

; $b1b1 referenced 1 time by $a1df
sub_cb1b1
    jsr caf7f                                                         ; b1b1: 20 7f af     ..
    cmp #$2c ; ','                                                    ; b1b4: c9 2c       I,
    beq cb1bd                                                         ; b1b6: f0 05       ..
    jsr sub_ca71b                                                     ; b1b8: 20 1b a7     ..
    sec                                                               ; b1bb: 38          8
    rts                                                               ; b1bc: 60          .

; $b1bd referenced 1 time by $b1b6
cb1bd
    clc                                                               ; b1bd: 18          .
    rts                                                               ; b1be: 60          .

    .byte $60                                                         ; b1bf: 60          .

; $b1c0 referenced 2 times by $a612, $ad47
sub_cb1c0
    ldy basic_multiply_result+2                                       ; b1c0: a4 28       .(
    jsr sub_ca259                                                     ; b1c2: 20 59 a2     y.
    jmp le1b0                                                         ; b1c5: 4c b0 e1    l..

; $b1c8 referenced 2 times by $a595, $be25
sub_cb1c8
    lda basic_variable_name+1                                         ; b1c8: a5 46       .f
    cmp #$c9 ; 'I'                                                    ; b1ca: c9 c9       II
    bne return_16                                                     ; b1cc: d0 04       P.
    lda basic_variable_name                                           ; b1ce: a5 45       .e
    cmp #$54 ; 't'                                                    ; b1d0: c9 54       It
; $b1d2 referenced 1 time by $b1cc
return_16
    rts                                                               ; b1d2: 60          .

    .byte $1f, $f7, $1c,   0, $f1, $12, $b8, $f7, $16, $f1, $12, $0f  ; b1d3: 1f f7 1c... ...
    .byte $ee, $bd, $31, $d9, $0d,   0, $1f, $97, $8d, $f5, $0e, $1f  ; b1df: ee bd 31... ..1
    .byte $fa, $17,   0, $d1, $99, $9a,   0, $71, $1c,   0,   0, $1f  ; b1eb: fa 17 00... ...
    .byte $f7, $12, $f9, $0c, $81, $1e, $1f,   4,   0, $86, $f4, $17  ; b1f7: f7 12 f9... ...
    .byte   0, $ec, $fb, $16, $1f,   7,   0, $8e, $d6, $41, $8a, $15  ; b203: 00 ec fb... ...
    .byte $ac, $f9, $13, $48, $e1, $92, $1f, $a2, $1f, $77, $fd, $16  ; b20f: ac f9 13... ...
    .byte $51, $4a, $f6, $10, $c7, $f1, $1b, $37, $f3, $0e, $1f,   7  ; b21b: 51 4a f6... qj.
    .byte   0, $d9, $d4, $b8, $1d,   0, $ae, $1a, $1f, $83, $fc, $0e  ; b227: 00 d9 d4... .YT
    .byte $31, $47, $bd,   0, $73, $d4, $a1, $d6, $0c,   0, $73, $d4  ; b233: 31 47 bd... 1g.
    .byte $c1, $ea, $a1, $d6, $0c,   0, $73, $d4, $c1, $ea, $31, $2a  ; b23f: c1 ea a1... A..
    .byte $5c,   0, $d5, $1f, $71, $1f, $d6, $c1, $ea, $61, $d9, $db  ; b24b: 5c 00 d5... ..U
    .byte $ec,   0, $ac, $1e, $c7, $26, $1e, $73, $d4,   0, $ac, $1e  ; b257: ec 00 ac... ...
    .byte $2a, $6e, $e2, $31, $47, $0d,   0, $1f, $73, $bb, $c7, $1f  ; b263: 2a 6e e2... *..
    .byte $15, $73, $d4, $8c, $1f, $d3,   0, $47, $d4, $1f, $85, $14  ; b26f: 15 73 d4... ..T
    .byte $d5, $1f, $71, $1f, $d6, $c1, $f2, $13, $1f, $d2,   9,   0  ; b27b: d5 1f 71... U..
    .byte $dc, $0f, $ed, $f1, $0f, $e7, $1f, $a0, $e2, $31, $9a,   0  ; b287: dc 0f ed... ...
    .byte $fb, $0e, $ec, $f8, $0d,   0                                ; b293: fb 0e ec... ...
    .byte $d9, $2e, $c9 ; petscii "Y.I"                               ; b299: d9 2e c9    Y.I
    .byte $f1, $0f, $e7, $1f, $a0, $e2, $f1, $15, $ba, $f2, $12,   0  ; b29c: f1 0f e7... ...
    .byte $2a, $1e, $3a, $51, $e8,   8,   0, $47, $d4, $1f, $85, $14  ; b2a8: 2a 1e 3a... *.:
    .byte $0f, $29, $c8, $7e, $fe, $0e,   0, $fa, $11, $9d, $43, $fa  ; b2b4: 0f 29 c8... .)H
    .byte $0f,   0, $2a, $1e, $3a, $f1, $13, $fd, $13, $9a, $0f, $0e  ; b2c0: 0f 00 2a... ..*
    .byte   0, $c2, $d5, $f3, $18, $15, $eb, $e8, $fd, $13, $cd, $0e  ; b2cc: 00 c2 d5... .BU
    .byte   0, $1f, $82, $15, $2b, $1f, $b2, $1f, $96, $67, $0e,   0  ; b2d8: 00 1f 82... ...
    .byte $d9, $75, $1f, $f3, $18, $15, $98, $89, $0f, $0e,   0, $75  ; b2e4: d9 75 1f... Y..
    .byte $1f, $71, $7b, $ca, $f1, $12, $0f, $1e, $1f, $d9, $a9,   0  ; b2f0: 1f 71 7b... ...
    .byte $47, $d4, $1f, $85, $14, $75, $d9, $1f, $e6,   0, $fe, $0e  ; b2fc: 47 d4 1f... gT.
    .byte $d6, $f1, $13, $b7, $1f, $83, $fe, $16, $1f,   0, $eb, $79  ; b308: d6 f1 13... V..
    .byte $fc, $15, $e1, $aa, $41, $ca, $1f,   5,   0, $73, $d4, $51  ; b314: fc 15 e1... ...
    .byte $e8,   8,   0, $a3, $f9, $13, $42, $18, $ae, $1a, $1f, $a6  ; b320: e8 08 00... ...
    .byte $1f, $63, $d4, $0f, $0d,   0, $1f, $86, $fc, $18, $1e, $1f  ; b32c: 1f 63 d4... ..T
    .byte $a6, $ec, $c7, $d2,   0, $c2, $d5, $f3, $18, $15, $23, $fc  ; b338: a6 ec c7... ..G
    .byte $16, $7e, $ca,   0, $1f, $d1, $79, $f3, $0e,   0, $a4, $58  ; b344: 16 7e ca... ..J
    .byte   0, $1f, $92, $8d, $0f, $0c,   0,   0,   0,   0, $75, $d9  ; b350: 00 1f 92... ...
    .byte $1f, $e6, $f1, $13, $5a, $1d, $ca, $f4, $0e,   0,   0,   0  ; b35c: 1f e6 f1... ...
    .byte   0, $74, $dc, $c1, $f2, $13, $1f, $d2, $19, $ae, $1a, $84  ; b368: 00 74 dc... ...
    .byte $f9, $15, $0d,   0,   0, $ac, $1e, $f7, $13, $46, $fd, $13  ; b374: f9 15 0d... ...
    .byte $cd, $de,   5,   0,   0, $1f, $d3, $1f, $a3, $f9, $0e, $f1  ; b380: cd de 05... M..
    .byte $16, $9a, $29, $e6,   0, $60                                ; b38c: 16 9a 29... ..)

sub_cb392
    sta ld07a                                                         ; b392: 8d 7a d0    ..P
    lda #0                                                            ; b395: a9 00       ..
    beq cb39e                                                         ; b397: f0 05       .. ; ALWAYS branch

sub_cb399
    sta ld07b                                                         ; b399: 8d 7b d0    ..P
    lda #1                                                            ; b39c: a9 01       ..
; $b39e referenced 1 time by $b397
cb39e
    sta ld030                                                         ; b39e: 8d 30 d0    .0P
    rts                                                               ; b3a1: 60          .

    .byte $60                                                         ; b3a2: 60          .

    ; Copy 12 bytes of memory from la175 to basic_error_vector
    ldy #$0b                                                          ; b3a3: a0 0b       ..
; $b3a5 referenced 1 time by $b3ac
loop_cb3a5
    lda la175,y                                                       ; b3a5: b9 75 a1    ...
    sta basic_error_vector,y                                          ; b3a8: 99 00 03    ...
    dey                                                               ; b3ab: 88          .
    bpl loop_cb3a5                                                    ; b3ac: 10 f7       ..
    ; Copy 5 bytes of memory from la181 to basic_float_to_int_vector
    ldy #4                                                            ; b3ae: a0 04       ..
; $b3b0 referenced 1 time by $b3b7
loop_cb3b0
    lda la181,y                                                       ; b3b0: b9 81 a1    ...
    sta basic_float_to_int_vector,y                                   ; b3b3: 99 03 00    ...
    dey                                                               ; b3b6: 88          .
    bpl loop_cb3b0                                                    ; b3b7: 10 f7       ..
    lda #$4c ; 'l'                                                    ; b3b9: a9 4c       .l
    sta usr_jmp                                                       ; b3bb: 8d 10 03    ...
    lda #$cc ; 'L'                                                    ; b3be: a9 cc       .L
    sta usr_address                                                   ; b3c0: 8d 11 03    ...
    lda #$a6                                                          ; b3c3: a9 a6       ..
    sta usr_address+1                                                 ; b3c5: 8d 12 03    ...
    lda #0                                                            ; b3c8: a9 00       ..
    sta tape_timing_constant                                          ; b3ca: 85 b0       ..
    sta tape_timing_constant+1                                        ; b3cc: 85 b1       ..
    jsr le422                                                         ; b3ce: 20 22 e4     ".
    jsr sub_cb9eb                                                     ; b3d1: 20 eb b9     ..
    jmp basic_warm_start                                              ; b3d4: 4c b7 e3    l..

; $b3d7 referenced 1 time by $a1ab
sub_cb3d7
    jsr caf7f                                                         ; b3d7: 20 7f af     ..
    cmp #0                                                            ; b3da: c9 00       I.
    beq cb403                                                         ; b3dc: f0 25       .%
    cmp #$22 ; '"'                                                    ; b3de: c9 22       I"
    beq cb3e5                                                         ; b3e0: f0 03       ..
    jmp ca6cf                                                         ; b3e2: 4c cf a6    lO.

; $b3e5 referenced 1 time by $b3e0
cb3e5
    lda basic_text_ptr                                                ; b3e5: a5 7a       ..
    sta filename_ptr                                                  ; b3e7: 85 bb       ..
    lda basic_text_ptr+1                                              ; b3e9: a5 7b       ..
    sta filename_ptr+1                                                ; b3eb: 85 bc       ..
    ldx #0                                                            ; b3ed: a2 00       ..
; $b3ef referenced 1 time by $b3fb
loop_cb3ef
    jsr sub_ca14f                                                     ; b3ef: 20 4f a1     o.
    cmp #0                                                            ; b3f2: c9 00       I.
    beq cb3fd                                                         ; b3f4: f0 07       ..
    cmp #$22 ; '"'                                                    ; b3f6: c9 22       I"
    beq cb3fd                                                         ; b3f8: f0 03       ..
    inx                                                               ; b3fa: e8          .
    bne loop_cb3ef                                                    ; b3fb: d0 f2       P.
; $b3fd referenced 2 times by $b3f4, $b3f8
cb3fd
    stx filename_length                                               ; b3fd: 86 b7       ..
    lda #0                                                            ; b3ff: a9 00       ..
    beq cb405                                                         ; b401: f0 02       .. ; ALWAYS branch

; $b403 referenced 1 time by $b3dc
cb403
    sta filename_length                                               ; b403: 85 b7       ..
; $b405 referenced 1 time by $b401
cb405
    sta basic_load_verify_flag                                        ; b405: 85 0a       ..
    ldy #1                                                            ; b407: a0 01       .. ; Y=secondary address
    ldx #7                                                            ; b409: a2 07       .. ; X=device number
    jmp setlfs                                                        ; b40b: 4c ba ff    l.. ; Set the logical file number, device number and secondary address

; $b40e referenced 3 times by $a2c3, $a711, $ab63
sub_cb40e
    sta fac1_mantissa                                                 ; b40e: 85 62       ..
    stx fac1_exponent                                                 ; b410: 86 61       ..
    ora fac1_exponent                                                 ; b412: 05 61       ..
    bne cb41b                                                         ; b414: d0 05       P.
    lda #$30 ; '0'                                                    ; b416: a9 30       .0 ; A=character to output
    jmp chrout                                                        ; b418: 4c d2 ff    lR. ; Output '0'

; $b41b referenced 1 time by $b414
cb41b
    ldy #4                                                            ; b41b: a0 04       ..
; $b41d referenced 1 time by $b423
loop_cb41d
    jsr sub_cbbff                                                     ; b41d: 20 ff bb     ..
    bcs cb425                                                         ; b420: b0 03       ..
    dey                                                               ; b422: 88          .
    bpl loop_cb41d                                                    ; b423: 10 f8       ..
; $b425 referenced 2 times by $b420, $b446
cb425
    ldx #0                                                            ; b425: a2 00       ..
; $b427 referenced 1 time by $b43c
loop_cb427
    jsr sub_cbbff                                                     ; b427: 20 ff bb     ..
    bcc cb43e                                                         ; b42a: 90 12       ..
    inx                                                               ; b42c: e8          .
    sec                                                               ; b42d: 38          8
    lda fac1_exponent                                                 ; b42e: a5 61       ..
    sbc le3ba,y                                                       ; b430: f9 ba e3    ...
    sta fac1_exponent                                                 ; b433: 85 61       ..
    lda fac1_mantissa                                                 ; b435: a5 62       ..
    sbc laabd,y                                                       ; b437: f9 bd aa    ...
    sta fac1_mantissa                                                 ; b43a: 85 62       ..
    bcs loop_cb427                                                    ; b43c: b0 e9       ..
; $b43e referenced 1 time by $b42a
cb43e
    txa                                                               ; b43e: 8a          .
    clc                                                               ; b43f: 18          .
    adc #$30 ; '0'                                                    ; b440: 69 30       .0 ; A=character to output
    jsr chrout                                                        ; b442: 20 d2 ff     R. ; Output a character
    dey                                                               ; b445: 88          .
    bpl cb425                                                         ; b446: 10 dd       ..
    rts                                                               ; b448: 60          .

    .byte $a2, $20, 6, $6d, $26, $6c, $26, $6b, $26, $6a              ; b449: a2 20 06... . .
    .byte $26, $29, $26, $28, $26, $27, $26, $26 ; petscii "&)&(&'&&" ; b453: 26 29 26... &)&
    .byte $38 ; petscii "8"                                           ; b45b: 38          8
    .byte $a5, $29, $e5, $65, $85, $25, $a5, $28, $e5, $64, $85, $24  ; b45c: a5 29 e5... .).
    .byte $a5, $27, $e5, $63, $85, $23, $a5, $26, $e5, $62, $90, $14  ; b468: a5 27 e5... .'.
    .byte $85, $22, $a5, $25, $85, $29, $a5, $24, $85, $28, $a5, $23  ; b474: 85 22 a5... .".
    .byte $85, $27, $a5, $22, $85, $26, $e6, $6d, $ca, $d0, $c0, $60  ; b480: 85 27 a5... .'.

; $b48c referenced 1 time by $a4b4
cb48c
    jsr caf7f                                                         ; b48c: 20 7f af     ..
    cmp #$a4                                                          ; b48f: c9 a4       I.
    beq basic_command_goto                                            ; b491: f0 13       ..
; $b493 referenced 1 time by $b4a9
loop_cb493
    jmp ca6cf                                                         ; b493: 4c cf a6    lO.

basic_command_run
    jsr basic_command_clr                                             ; b496: 20 00 ba     ..
    jsr sub_cbc12                                                     ; b499: 20 12 bc     ..
    lda #0                                                            ; b49c: a9 00       .. ; A=message flags
    jsr setmsg                                                        ; b49e: 20 90 ff     .. ; Turn off Kernal messages
    jsr sub_cb9c1                                                     ; b4a1: 20 c1 b9     A.
    bcs cb4ce                                                         ; b4a4: b0 28       .(
; $b4a6 referenced 2 times by $b491, $bbb8
basic_command_goto
    jsr sub_ca645                                                     ; b4a6: 20 45 a6     e.
    bcs loop_cb493                                                    ; b4a9: b0 e8       ..
    lda basic_current_line+1                                          ; b4ab: a5 3a       .:
    bmi cb4c1                                                         ; b4ad: 30 12       0.
    lda basic_line_number+1                                           ; b4af: a5 15       ..
    cmp basic_current_line+1                                          ; b4b1: c5 3a       E:
    bne cb4b9                                                         ; b4b3: d0 04       P.
    lda basic_line_number                                             ; b4b5: a5 14       ..
    cmp basic_current_line                                            ; b4b7: c5 39       E9
; $b4b9 referenced 1 time by $b4b3
cb4b9
    bcc cb4c6                                                         ; b4b9: 90 0b       ..
    jsr le217                                                         ; b4bb: 20 17 e2     ..
    jmp cb4c9                                                         ; b4be: 4c c9 b4    lI.

; $b4c1 referenced 1 time by $b4ad
cb4c1
    lda #0                                                            ; b4c1: a9 00       .. ; A=message flags
    jsr setmsg                                                        ; b4c3: 20 90 ff     .. ; Turn off Kernal messages
; $b4c6 referenced 1 time by $b4b9
cb4c6
    jsr le214                                                         ; b4c6: 20 14 e2     ..
; $b4c9 referenced 1 time by $b4be
cb4c9
    bcc cb4ce                                                         ; b4c9: 90 03       ..
    jmp ca6c9                                                         ; b4cb: 4c c9 a6    lI.

; $b4ce referenced 2 times by $b4a4, $b4c9
cb4ce
    pha                                                               ; b4ce: 48          h
    pha                                                               ; b4cf: 48          h
    jmp ca505                                                         ; b4d0: 4c 05 a5    l..

; $b4d3 referenced 1 time by $bf0b
sub_cb4d3
    lda #0                                                            ; b4d3: a9 00       ..
; $b4d5 referenced 1 time by $b51b
cb4d5
    sta basic_garbage_flag                                            ; b4d5: 85 0f       ..
    lda basic_strings_bottom                                          ; b4d7: a5 33       .3
    sta basic_index1                                                  ; b4d9: 85 22       ."
    lda basic_strings_bottom+1                                        ; b4db: a5 34       .4
    sta basic_index1+1                                                ; b4dd: 85 23       .#
    lda #2                                                            ; b4df: a9 02       ..
    jsr sub_ca225                                                     ; b4e1: 20 25 a2     %.
    bcs cb507                                                         ; b4e4: b0 21       .!
    ldy #0                                                            ; b4e6: a0 00       ..
    lda basic_variable_ptr                                            ; b4e8: a5 47       .g
    sta (basic_strings_bottom),y                                      ; b4ea: 91 33       .3
    iny                                                               ; b4ec: c8          H  ; Y=1
    lda basic_variable_ptr+1                                          ; b4ed: a5 48       .h
    sta (basic_strings_bottom),y                                      ; b4ef: 91 33       .3
    ldy #0                                                            ; b4f1: a0 00       ..
    jsr le19e                                                         ; b4f3: 20 9e e1     ..
    jsr sub_ca225                                                     ; b4f6: 20 25 a2     %.
    bcs cb507                                                         ; b4f9: b0 0c       ..
    ldy #1                                                            ; b4fb: a0 01       ..
    lda basic_strings_bottom                                          ; b4fd: a5 33       .3
    sta (basic_variable_ptr),y                                        ; b4ff: 91 47       .g
    iny                                                               ; b501: c8          H  ; Y=2
    lda basic_strings_bottom+1                                        ; b502: a5 34       .4
    sta (basic_variable_ptr),y                                        ; b504: 91 47       .g
    rts                                                               ; b506: 60          .

; $b507 referenced 2 times by $b4e4, $b4f9
cb507
    lda basic_index1                                                  ; b507: a5 22       ."
    sta basic_strings_bottom                                          ; b509: 85 33       .3
    lda basic_index1+1                                                ; b50b: a5 23       .#
    sta basic_strings_bottom+1                                        ; b50d: 85 34       .4
    bit basic_garbage_flag                                            ; b50f: 24 0f       $.
    bmi cb516                                                         ; b511: 30 03       0.
    jmp la6ca                                                         ; b513: 4c ca a6    lJ.

; $b516 referenced 1 time by $b511
cb516
    dec basic_garbage_flag                                            ; b516: c6 0f       F.
    jsr sub_cacb6                                                     ; b518: 20 b6 ac     ..
    jmp cb4d5                                                         ; b51b: 4c d5 b4    lU.

    .byte $a5, $61, $f0, $48, $a5, $62, $f0, $17, $a5, $62, $29, $80  ; b51e: a5 61 f0... ...
    .byte $d0, $3e, $c6 ; petscii "P>F"                               ; b52a: d0 3e c6    P>F
    .byte $61, $f0, $3a,   6, $70, $26, $65, $26, $64, $26, $63, $26  ; b52d: 61 f0 3a... ..:
    .byte $62, $90, $ea, $60, $a5, $61, $38, $e9,   8, $b0,   2, $a9  ; b539: 62 90 ea... ...
    .byte   0, $85, $61, $f0, $20, $a5, $63, $85, $62, $a5, $64, $85  ; b545: 00 85 61... ...
    .byte $63, $a5, $65, $85, $64, $a5, $70, $85, $65, $a9,   0, $85  ; b551: 63 a5 65... ...
    .byte $70,   5, $62,   5, $63,   5, $64,   5, $65, $d0, $ba, $85  ; b55d: 70 05 62... ...
    .byte $61, $60                                                    ; b569: 61 60       ..

; $b56b referenced 1 time by $b6a7
sub_cb56b
    dec l0101                                                         ; b56b: ce 01 01    N..
    beq return_17                                                     ; b56e: f0 1f       ..
    asl l0103                                                         ; b570: 0e 03 01    ...
    rol l0102                                                         ; b573: 2e 02 01    ...
    bcs cb599                                                         ; b576: b0 21       .!
    ldy l0105                                                         ; b578: ac 05 01    ...
    bit l0104                                                         ; b57b: 2c 04 01    ,..
    bmi cb590                                                         ; b57e: 30 10       0.
; $b580 referenced 1 time by $b5aa
cb580
    dey                                                               ; b580: 88          .
    sty l0105                                                         ; b581: 8c 05 01    ...
    lda l0106,y                                                       ; b584: b9 06 01    ...
    and #$0f                                                          ; b587: 29 0f       ).
    sta l0106,y                                                       ; b589: 99 06 01    ...
    dec l0104                                                         ; b58c: ce 04 01    N..
; $b58f referenced 1 time by $b56e
return_17
    rts                                                               ; b58f: 60          .

; $b590 referenced 1 time by $b57e
cb590
    lda #0                                                            ; b590: a9 00       ..
    sta l0106,y                                                       ; b592: 99 06 01    ...
    inc l0104                                                         ; b595: ee 04 01    ...
    rts                                                               ; b598: 60          .

; $b599 referenced 1 time by $b576
cb599
    ldy l0105                                                         ; b599: ac 05 01    ...
    lda #0                                                            ; b59c: a9 00       ..
    bit l0104                                                         ; b59e: 2c 04 01    ,..
    bmi cb5ad                                                         ; b5a1: 30 0a       0.
    dey                                                               ; b5a3: 88          .
    sta l0106,y                                                       ; b5a4: 99 06 01    ...
    sty l0105                                                         ; b5a7: 8c 05 01    ...
    jmp cb580                                                         ; b5aa: 4c 80 b5    l..

; $b5ad referenced 1 time by $b5a1
cb5ad
    sta l0106,y                                                       ; b5ad: 99 06 01    ...
    dey                                                               ; b5b0: 88          .
    sta l0106,y                                                       ; b5b1: 99 06 01    ...
    sty l0105                                                         ; b5b4: 8c 05 01    ...
    inc l0104                                                         ; b5b7: ee 04 01    ...
    rts                                                               ; b5ba: 60          .

basic_command_sys
    jsr sub_cb9c1                                                     ; b5bb: 20 c1 b9     A.
    bcc cb5c3                                                         ; b5be: 90 03       ..
    jmp ca6cf                                                         ; b5c0: 4c cf a6    lO.

; $b5c3 referenced 1 time by $b5be
cb5c3
    ldy #0                                                            ; b5c3: a0 00       ..
; $b5c5 referenced 1 time by $b5d1
loop_cb5c5
    lda (basic_text_ptr),y                                            ; b5c5: b1 7a       ..
    cmp lb607,y                                                       ; b5c7: d9 07 b6    Y..
    bne cb5dd                                                         ; b5ca: d0 11       P.
    lda (basic_text_ptr),y                                            ; b5cc: b1 7a       ..
    beq cb5d3                                                         ; b5ce: f0 03       ..
    iny                                                               ; b5d0: c8          H
    bne loop_cb5c5                                                    ; b5d1: d0 f2       P.
; $b5d3 referenced 1 time by $b5ce
cb5d3
    lda #$0c                                                          ; b5d3: a9 0c       ..
    sta basic_line_number                                             ; b5d5: 85 14       ..
    lda #8                                                            ; b5d7: a9 08       ..
    sta basic_line_number+1                                           ; b5d9: 85 15       ..
    bne cb5e7                                                         ; b5db: d0 0a       P. ; ALWAYS branch

; $b5dd referenced 1 time by $b5ca
cb5dd
    lda #$0a                                                          ; b5dd: a9 0a       ..
    jsr sub_cba2e                                                     ; b5df: 20 2e ba     ..
    bcc cb5e7                                                         ; b5e2: 90 03       ..
    jmp ca6cf                                                         ; b5e4: 4c cf a6    lO.

; $b5e7 referenced 2 times by $b5db, $b5e2
cb5e7
    lda #$4c ; 'l'                                                    ; b5e7: a9 4c       .l
    sta usr_jmp                                                       ; b5e9: 8d 10 03    ...
    lda basic_line_number                                             ; b5ec: a5 14       ..
    sta usr_address                                                   ; b5ee: 8d 11 03    ...
    lda basic_line_number+1                                           ; b5f1: a5 15       ..
    sta usr_address+1                                                 ; b5f3: 8d 12 03    ...
    lda sys_p                                                         ; b5f6: ad 0f 03    ...
    pha                                                               ; b5f9: 48          h
    ldy sys_y                                                         ; b5fa: ac 0e 03    ...
    ldx sys_x                                                         ; b5fd: ae 0d 03    ...
    lda sys_a                                                         ; b600: ad 0c 03    ...
    plp                                                               ; b603: 28          (
    jmp usr_jmp                                                       ; b604: 4c 10 03    l..

; $b607 referenced 1 time by $b5c7
lb607
    .byte $ff, $ac                                                    ; b607: ff ac       ..
    .byte $36, $35, $36 ; petscii "656"                               ; b609: 36 35 36    656
    .byte 0                                                           ; b60c: 00          .

; $b60d referenced 1 time by $a59a
cb60d
    lda #6                                                            ; b60d: a9 06       ..
    jsr le107                                                         ; b60f: 20 07 e1     ..
    jsr le3eb                                                         ; b612: 20 eb e3     ..
    jsr rdtim                                                         ; b615: 20 de ff     .. ; Read the jiffy clock
    sty basic_index2                                                  ; b618: 84 24       .$ ; Y=jiffy clock (low byte)
    stx basic_index1+1                                                ; b61a: 86 23       .# ; X=jiffy clock (middle byte)
    sta basic_index1                                                  ; b61c: 85 22       ." ; A=jiffy clock (high byte)
    ldy #0                                                            ; b61e: a0 00       ..
; $b620 referenced 1 time by $b65e
cb620
    lda #$30 ; '0'                                                    ; b620: a9 30       .0
    sta basic_index2+1                                                ; b622: 85 25       .%
; $b624 referenced 1 time by $b655
cb624
    lda basic_index2                                                  ; b624: a5 24       .$
    cmp lb85c,y                                                       ; b626: d9 5c b8    Y..
    bcc cb657                                                         ; b629: 90 2c       .,
    bne cb63d                                                         ; b62b: d0 10       P.
    lda basic_index1+1                                                ; b62d: a5 23       .#
    cmp le4cd,y                                                       ; b62f: d9 cd e4    YM.
    bcc cb657                                                         ; b632: 90 23       .#
    bne cb63d                                                         ; b634: d0 07       P.
    lda basic_index1                                                  ; b636: a5 22       ."
    cmp le265,y                                                       ; b638: d9 65 e2    Y..
    bcc cb657                                                         ; b63b: 90 1a       ..
; $b63d referenced 2 times by $b62b, $b634
cb63d
    inc basic_index2+1                                                ; b63d: e6 25       .%
    sec                                                               ; b63f: 38          8
    lda basic_index1                                                  ; b640: a5 22       ."
    sbc le265,y                                                       ; b642: f9 65 e2    ...
    sta basic_index1                                                  ; b645: 85 22       ."
    lda basic_index1+1                                                ; b647: a5 23       .#
    sbc le4cd,y                                                       ; b649: f9 cd e4    .M.
    sta basic_index1+1                                                ; b64c: 85 23       .#
    lda basic_index2                                                  ; b64e: a5 24       .$
    sbc lb85c,y                                                       ; b650: f9 5c b8    ...
    sta basic_index2                                                  ; b653: 85 24       .$
    bcs cb624                                                         ; b655: b0 cd       .M
; $b657 referenced 3 times by $b629, $b632, $b63b
cb657
    lda basic_index2+1                                                ; b657: a5 25       .%
    sta (basic_string_descriptor_ptr+1),y                             ; b659: 91 51       .q
    iny                                                               ; b65b: c8          H
    cpy #6                                                            ; b65c: c0 06       ..
    bne cb620                                                         ; b65e: d0 c0       P.
    clc                                                               ; b660: 18          .
    rts                                                               ; b661: 60          .

; $b662 referenced 1 time by $ac63
sub_cb662
    lda #0                                                            ; b662: a9 00       ..
    sta l0100                                                         ; b664: 8d 00 01    ...
    ldx basic_search_char                                             ; b667: a6 07       ..
    sta basic_input_buffer,x                                          ; b669: 9d 00 02    ...
; $b66c referenced 3 times by $b6be, $b6dd, $b6f4
cb66c
    lda l0100                                                         ; b66c: ad 00 01    ...
    cmp basic_search_char                                             ; b66f: c5 07       E.
    beq return_18                                                     ; b671: f0 4d       .m
    ldx l0100                                                         ; b673: ae 00 01    ...
    lda basic_input_buffer,x                                          ; b676: bd 00 02    ...
    cmp #$22 ; '"'                                                    ; b679: c9 22       I"
    beq cb6c1                                                         ; b67b: f0 44       .d
    cmp #$de                                                          ; b67d: c9 de       I.
    beq cb6d2                                                         ; b67f: f0 51       .q
    cmp #$3f ; '?'                                                    ; b681: c9 3f       I?
    beq lb6d5                                                         ; b683: f0 50       .p
    jsr sub_cafd4                                                     ; b685: 20 d4 af     T.
; $b688 referenced 1 time by $b6aa
cb688
    lda l0101                                                         ; b688: ad 01 01    ...
    beq cb6da                                                         ; b68b: f0 4d       .m
    lda #$8b                                                          ; b68d: a9 8b       ..
    sta basic_string_temp_ptr                                         ; b68f: 85 35       .5
    lda #$b0                                                          ; b691: a9 b0       ..
    sta basic_string_temp_ptr+1                                       ; b693: 85 36       .6
    jsr sub_cbb65                                                     ; b695: 20 65 bb     ..
    bcc cb6ad                                                         ; b698: 90 13       ..
    lda #$c0                                                          ; b69a: a9 c0       ..
    sta basic_string_temp_ptr                                         ; b69c: 85 35       .5
    lda #$e3                                                          ; b69e: a9 e3       ..
    sta basic_string_temp_ptr+1                                       ; b6a0: 85 36       .6
    jsr sub_cbb65                                                     ; b6a2: 20 65 bb     ..
    bcc cb6e0                                                         ; b6a5: 90 39       .9
    jsr sub_cb56b                                                     ; b6a7: 20 6b b5     ..
    jmp cb688                                                         ; b6aa: 4c 88 b6    l..

; $b6ad referenced 1 time by $b698
cb6ad
    txa                                                               ; b6ad: 8a          .
    pha                                                               ; b6ae: 48          h
    ldx l0100                                                         ; b6af: ae 00 01    ...
    clc                                                               ; b6b2: 18          .
    adc #$80                                                          ; b6b3: 69 80       ..
    sta basic_input_buffer,x                                          ; b6b5: 9d 00 02    ...
    jsr le28e                                                         ; b6b8: 20 8e e2     ..
    pla                                                               ; b6bb: 68          .
    cmp #$0f                                                          ; b6bc: c9 0f       I.
    bne cb66c                                                         ; b6be: d0 ac       P.
; $b6c0 referenced 2 times by $b671, $b6ca
return_18
    rts                                                               ; b6c0: 60          .

; $b6c1 referenced 2 times by $b67b, $b6d0
cb6c1
    inc l0100                                                         ; b6c1: ee 00 01    ...
    ldx l0100                                                         ; b6c4: ae 00 01    ...
    lda basic_input_buffer,x                                          ; b6c7: bd 00 02    ...
    beq return_18                                                     ; b6ca: f0 f4       ..
    cmp #$22 ; '"'                                                    ; b6cc: c9 22       I"
    beq cb6da                                                         ; b6ce: f0 0a       ..
    bne cb6c1                                                         ; b6d0: d0 ef       P. ; ALWAYS branch

; $b6d2 referenced 1 time by $b67f
cb6d2
    lda #$ff                                                          ; b6d2: a9 ff       ..
cb6d4
lb6d5 = cb6d4+1
    bit l99a9                                                         ; b6d4: 2c a9 99    ,..
; overlapping: lda #$99                                               ; b6d5: a9 99       ..
; $b6d5 referenced 1 time by $b683
    sta basic_input_buffer,x                                          ; b6d7: 9d 00 02    ...
; $b6da referenced 2 times by $b68b, $b6ce
cb6da
    inc l0100                                                         ; b6da: ee 00 01    ...
    jmp cb66c                                                         ; b6dd: 4c 6c b6    l..

; $b6e0 referenced 1 time by $b6a5
cb6e0
    lda #1                                                            ; b6e0: a9 01       ..
    ldy l0100                                                         ; b6e2: ac 00 01    ...
    sta basic_input_buffer,y                                          ; b6e5: 99 00 02    ...
    inx                                                               ; b6e8: e8          .
    txa                                                               ; b6e9: 8a          .
    iny                                                               ; b6ea: c8          H
    sty l0100                                                         ; b6eb: 8c 00 01    ...
    sta basic_input_buffer,y                                          ; b6ee: 99 00 02    ...
    jsr le28b                                                         ; b6f1: 20 8b e2     ..
    jmp cb66c                                                         ; b6f4: 4c 6c b6    l..

    .byte $a5, $61, $c5, $69, $f0, $50, $b0, $4f, $a5, $69, $38, $e5  ; b6f7: a5 61 c5... ..E
    .byte $61, $c9, $28, $b0, $35, $c9,   8, $90, $1d, $a5, $61, $18  ; b703: 61 c9 28... .I(
    .byte $69,   8, $85, $61, $a5, $65, $85, $70, $a5, $64, $85, $65  ; b70f: 69 08 85... ...
    .byte $a5, $63, $85, $64, $a5, $62, $85, $63, $a9,   0, $85, $62  ; b71b: a5 63 85... ...
    .byte $f0, $d6, $e6, $61, $18, $66, $62, $66, $63, $66, $64, $66  ; b727: f0 d6 e6... .V.
    .byte $65, $66, $70, $a5, $61, $c5, $69, $d0, $ed, $60, $a9,   0  ; b733: 65 66 70... ...
    .byte $85, $62, $85, $63, $85, $64, $85, $65, $85, $70, $a5, $69  ; b73f: 85 62 85... ...
    .byte $85, $61, $60, $a5, $61, $e5, $69, $c9, $20, $b0, $2f, $c9  ; b74b: 85 61 60... ...
    .byte   8, $90, $19, $a5, $69, $18, $69,   8, $85, $69, $a5, $6c  ; b757: 08 90 19... ...
    .byte $85, $6d, $a5, $6b, $85, $6c, $a5, $6a, $85, $6b, $a9,   0  ; b763: 85 6d a5... ...
    .byte $85, $6a, $f0, $db, $e6, $69, $18, $66, $6a, $66, $6b, $66  ; b76f: 85 6a f0... ...
    .byte $6c, $66, $6d, $a5, $61, $c5, $69, $d0, $ef, $60, $a9,   0  ; b77b: 6c 66 6d... ...
    .byte $85, $6a, $85, $6b, $85, $6c, $85, $6d, $a5, $61, $85, $69  ; b787: 85 6a 85... ...
    .byte $60, $60                                                    ; b793: 60 60       ..

; $b795 referenced 3 times by $aec0, $bd01, $be5d
sub_cb795
    lda basic_arrays_start                                            ; b795: a5 2f       ./
    sta basic_variable_ptr                                            ; b797: 85 47       .g
    lda basic_arrays_start+1                                          ; b799: a5 30       .0
    sta basic_variable_ptr+1                                          ; b79b: 85 48       .h
    lda basic_variable_ptr+1                                          ; b79d: a5 48       .h
    cmp basic_arrays_end+1                                            ; b79f: c5 32       E2
    bne cb7ab                                                         ; b7a1: d0 08       P.
    lda basic_variable_ptr                                            ; b7a3: a5 47       .g
    cmp basic_arrays_end                                              ; b7a5: c5 31       E1
    bne cb7ab                                                         ; b7a7: d0 02       P.
    sec                                                               ; b7a9: 38          8
    rts                                                               ; b7aa: 60          .

; $b7ab referenced 2 times by $b7a1, $b7a7
cb7ab
    jsr le339                                                         ; b7ab: 20 39 e3     9.
    beq cb7b3                                                         ; b7ae: f0 03       ..
    jmp le146                                                         ; b7b0: 4c 46 e1    lf.

; $b7b3 referenced 1 time by $b7ae
cb7b3
    clc                                                               ; b7b3: 18          .
    rts                                                               ; b7b4: 60          .

    .byte $60, $a9, $93, $20, $d2, $ff, $a9, $da, $a0, $b8, $20, $1e  ; b7b5: 60 a9 93... ...
    .byte $ab, $a2,   0, $a0, $0a, $20, $0c, $e5, $a9, $c2, $a0, $b8  ; b7c1: ab a2 00... ...
    .byte $20, $1e, $ab, $a2,   1, $a0, $0a, $20, $0c, $e5, $a2, $0a  ; b7cd: 20 1e ab...  ..
    .byte $20, $59, $b9, $a9, $55, $a0, $bf, $20, $1e, $ab, $a2,   3  ; b7d9: 20 59 b9...  y.
    .byte $a0, $0a, $20, $0c, $e5, $20, $1d, $a3, $a2,   6, $a0,   0  ; b7e5: a0 0a 20... ..
    .byte $20, $0c, $e5, $4c, $6b, $a5, $60                           ; b7f1: 20 0c e5...  ..

; $b7f8 referenced 1 time by $be2a
cb7f8
    jsr sub_cadae                                                     ; b7f8: 20 ae ad     ..
    lda basic_value_type                                              ; b7fb: a5 0d       ..
    bmi cb802                                                         ; b7fd: 30 03       0.
    jmp ca6c4                                                         ; b7ff: 4c c4 a6    lD.

; $b802 referenced 1 time by $b7fd
cb802
    lda fac1_exponent                                                 ; b802: a5 61       ..
    cmp #6                                                            ; b804: c9 06       I.
    beq cb80b                                                         ; b806: f0 03       ..
    jmp la6cc                                                         ; b808: 4c cc a6    lL.

; $b80b referenced 1 time by $b806
cb80b
    ldy #0                                                            ; b80b: a0 00       ..
    sty basic_index1                                                  ; b80d: 84 22       ."
    sty basic_index1+1                                                ; b80f: 84 23       .#
    sty basic_index2                                                  ; b811: 84 24       .$
; $b813 referenced 1 time by $b83e
cb813
    lda (fac1_mantissa),y                                             ; b813: b1 62       ..
    jsr sub_cbcf7                                                     ; b815: 20 f7 bc     ..
    bcc cb81d                                                         ; b818: 90 03       ..
    jmp la6cc                                                         ; b81a: 4c cc a6    lL.

; $b81d referenced 1 time by $b818
cb81d
    tax                                                               ; b81d: aa          .
; $b81e referenced 1 time by $b839
loop_cb81e
    cpx #0                                                            ; b81e: e0 00       ..
    beq cb83b                                                         ; b820: f0 19       ..
    clc                                                               ; b822: 18          .
    lda le265,y                                                       ; b823: b9 65 e2    ...
    adc basic_index1                                                  ; b826: 65 22       ."
    sta basic_index1                                                  ; b828: 85 22       ."
    lda le4cd,y                                                       ; b82a: b9 cd e4    .M.
    adc basic_index1+1                                                ; b82d: 65 23       .#
    sta basic_index1+1                                                ; b82f: 85 23       .#
    lda lb85c,y                                                       ; b831: b9 5c b8    ...
    adc basic_index2                                                  ; b834: 65 24       .$
    sta basic_index2                                                  ; b836: 85 24       .$
    dex                                                               ; b838: ca          J
    bpl loop_cb81e                                                    ; b839: 10 e3       ..
; $b83b referenced 1 time by $b820
cb83b
    iny                                                               ; b83b: c8          H
    cpy #6                                                            ; b83c: c0 06       ..
    bne cb813                                                         ; b83e: d0 d3       PS
    ldy basic_index2                                                  ; b840: a4 24       .$ ; Y=jiffy clock (low byte)
    ldx basic_index1+1                                                ; b842: a6 23       .# ; X=jiffy clock (middle byte)
    lda basic_index1                                                  ; b844: a5 22       ." ; A=jiffy clock (high byte)
    jmp settim                                                        ; b846: 4c db ff    l.. ; Set the jiffy clock

    .byte $a0, $bf, $a9, $11, $4c, $67, $b8, $20, $25, $e4, $a5, $66  ; b849: a0 bf a9... ...
    .byte $49, $ff, $85, $66, $4c, $6a, $b8                           ; b855: 49 ff 85... i..
; $b85c referenced 3 times by $b626, $b650, $b831
lb85c
    .byte $20,   3,   0,   0,   0,   0, $4c, $f7, $b6,   0,   0, $20  ; b85c: 20 03 00...  ..
    .byte $25, $e4, $a5, $69, $f0, $41, $a5, $61, $d0,   3, $4c, $37  ; b868: 25 e4 a5... %..
    .byte $ab, $20, $f7, $b6, $a5, $66, $45, $6e, $10,   3, $4c, $1f  ; b874: ab 20 f7... . .
    .byte $a8, $18, $a5, $6d, $65, $65, $85, $65, $a5, $6c, $65, $64  ; b880: a8 18 a5... ...
    .byte $85, $64, $a5, $6b, $65, $63, $85, $63, $a5, $6a, $65, $62  ; b88c: 85 64 a5... ...
    .byte $85, $62, $b0,   3, $4c, $1e, $b5, $e6, $61, $d0, $0d, $a9  ; b898: 85 62 b0... ...
    .byte $ff, $85, $61, $85, $65, $85, $64, $85, $63, $85, $62, $60  ; b8a4: ff 85 61... ...
    .byte $38, $66, $62, $66, $63, $66, $64, $66, $65, $66, $70, $60  ; b8b0: 38 66 62... 8..
    .byte $4c, $b2, $a6, $4c, $b2, $a6                                ; b8bc: 4c b2 a6... l..
    .byte $4f, $50, $45, $4e, $20, $52, $4f, $4d ; petscii "open rom" ; b8c2: 4f 50 45... ope
    .byte $53, $20, $47, $45, $4e, $45, $52, $49 ; petscii "s generi" ; b8ca: 53 20 47... s g
    .byte $43, $20, $42, $55, $49, $4c, $44 ; petscii "c build"       ; b8d2: 43 20 42... c b
    .byte   0, $1c, $12, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $0d, $9e  ; b8d9: 00 1c 12... ...
    .byte $12, $a4, $a4, $a4, $a4, $a4, $a4, $0d, $1e, $12, $a4, $a4  ; b8e5: 12 a4 a4... ...
    .byte $a4, $a4, $a4, $0d, $9f, $12, $a4, $a4, $a4, $a4, $92,   5  ; b8f1: a4 a4 a4... ...
    .byte   0, $4c, $1e, $b5                                          ; b8fd: 00 4c 1e... .l.

; $b901 referenced 4 times by $af20, $af2f, $bd37, $bd64
sub_cb901
    txa                                                               ; b901: 8a          .
    pha                                                               ; b902: 48          h
    lda fac1_mantissa                                                 ; b903: a5 62       ..
    sta basic_index2+1                                                ; b905: 85 25       .%
    lda fac1_mantissa+2                                               ; b907: a5 64       ..
    jsr sub_cbccd                                                     ; b909: 20 cd bc     M.
    sta basic_index1                                                  ; b90c: 85 22       ."
    stx basic_index1+1                                                ; b90e: 86 23       .#
    lda fac1_mantissa                                                 ; b910: a5 62       ..
    sta basic_index2+1                                                ; b912: 85 25       .%
    lda fac1_mantissa+3                                               ; b914: a5 65       ..
    jsr sub_cb938                                                     ; b916: 20 38 b9     8.
    lda fac1_mantissa+1                                               ; b919: a5 63       ..
    sta basic_index2+1                                                ; b91b: 85 25       .%
    lda fac1_mantissa+2                                               ; b91d: a5 64       ..
    jsr sub_cb938                                                     ; b91f: 20 38 b9     8.
    lda fac1_mantissa+1                                               ; b922: a5 63       ..
    beq cb92d                                                         ; b924: f0 07       ..
    lda fac1_mantissa+3                                               ; b926: a5 65       ..
    beq cb92d                                                         ; b928: f0 03       ..
; $b92a referenced 2 times by $b93d, $b942
cb92a
    jmp la6ca                                                         ; b92a: 4c ca a6    lJ.

; $b92d referenced 2 times by $b924, $b928
cb92d
    lda basic_index1                                                  ; b92d: a5 22       ."
    sta fac1_mantissa                                                 ; b92f: 85 62       ..
    lda basic_index1+1                                                ; b931: a5 23       .#
    sta fac1_mantissa+1                                               ; b933: 85 63       ..
    pla                                                               ; b935: 68          .
    tax                                                               ; b936: aa          .
    rts                                                               ; b937: 60          .

; $b938 referenced 2 times by $b916, $b91f
sub_cb938
    jsr sub_cbccd                                                     ; b938: 20 cd bc     M.
    cpx #0                                                            ; b93b: e0 00       ..
    bne cb92a                                                         ; b93d: d0 eb       P.
    clc                                                               ; b93f: 18          .
    adc basic_index1+1                                                ; b940: 65 23       .#
    bcs cb92a                                                         ; b942: b0 e6       ..
    sta basic_index1+1                                                ; b944: 85 23       .#
    rts                                                               ; b946: 60          .

    .byte $60                                                         ; b947: 60          .

; $b948 referenced 2 times by $a3db, $bef4
sub_cb948
    lda basic_string_descriptor_ptr+2                                 ; b948: a5 52       .r
    cmp basic_strings_bottom+1                                        ; b94a: c5 34       E4
    bne return_19                                                     ; b94c: d0 04       P.
    lda basic_string_descriptor_ptr+1                                 ; b94e: a5 51       .q
    cmp basic_strings_bottom                                          ; b950: c5 33       E3
; $b952 referenced 1 time by $b94c
return_19
    rts                                                               ; b952: 60          .

; $b953 referenced 2 times by $a2b1, $a6fa
sub_cb953
    lda #$2d ; '-'                                                    ; b953: a9 2d       .-
    ldy #$b2                                                          ; b955: a0 b2       ..
    bne cb969                                                         ; b957: d0 10       P. ; ALWAYS branch

; $b959 referenced 5 times by $a2bc, $a6f5, $a6ff, $a70a, $ac05
sub_cb959
    lda #$d3 ; 'S'                                                    ; b959: a9 d3       .S
    ldy #$b1                                                          ; b95b: a0 b1       ..
    bne cb969                                                         ; b95d: d0 0a       P. ; ALWAYS branch

; $b95f referenced 1 time by $abea
sub_cb95f
    lda #$c0                                                          ; b95f: a9 c0       ..
    ldy #$e3                                                          ; b961: a0 e3       ..
    bne cb969                                                         ; b963: d0 04       P. ; ALWAYS branch

; $b965 referenced 1 time by $aba2
sub_cb965
    lda #$8b                                                          ; b965: a9 8b       ..
    ldy #$b0                                                          ; b967: a0 b0       ..
; $b969 referenced 3 times by $b957, $b95d, $b963
cb969
    jsr sub_cbbda                                                     ; b969: 20 da bb     Z.
    ldy #0                                                            ; b96c: a0 00       ..
; $b96e referenced 1 time by $b99f
cb96e
    lda (basic_string_temp_ptr),y                                     ; b96e: b1 35       .5
    and #$0f                                                          ; b970: 29 0f       ).
    beq return_20                                                     ; b972: f0 47       .g
    cmp #$0f                                                          ; b974: c9 0f       I.
    beq cb9a1                                                         ; b976: f0 29       .)
    tax                                                               ; b978: aa          .
    lda la69b,x                                                       ; b979: bd 9b a6    ... ; A=character to output
    jsr chrout                                                        ; b97c: 20 d2 ff     R. ; Output a character
; $b97f referenced 1 time by $b9b8
cb97f
    lda (basic_string_temp_ptr),y                                     ; b97f: b1 35       .5
    and #$f0                                                          ; b981: 29 f0       ).
    beq return_20                                                     ; b983: f0 36       .6
    cmp #$f0                                                          ; b985: c9 f0       I.
    beq cb994                                                         ; b987: f0 0b       ..
    lsr a                                                             ; b989: 4a          j
    lsr a                                                             ; b98a: 4a          j
    lsr a                                                             ; b98b: 4a          j
    lsr a                                                             ; b98c: 4a          j
    tax                                                               ; b98d: aa          .
    lda la69b,x                                                       ; b98e: bd 9b a6    ...
    jmp cb99b                                                         ; b991: 4c 9b b9    l..

; $b994 referenced 1 time by $b987
cb994
    iny                                                               ; b994: c8          H
    lda (basic_string_temp_ptr),y                                     ; b995: b1 35       .5
    tax                                                               ; b997: aa          .
    lda return_14,x                                                   ; b998: bd 73 a2    ... ; A=character to output
; $b99b referenced 1 time by $b991
cb99b
    jsr chrout                                                        ; b99b: 20 d2 ff     R. ; Output a character
    iny                                                               ; b99e: c8          H
    bne cb96e                                                         ; b99f: d0 cd       PM
; $b9a1 referenced 1 time by $b976
cb9a1
    lda (basic_string_temp_ptr),y                                     ; b9a1: b1 35       .5
    and #$f0                                                          ; b9a3: 29 f0       ).
    tsx                                                               ; b9a5: ba          .
    pha                                                               ; b9a6: 48          h
    iny                                                               ; b9a7: c8          H
    lda (basic_string_temp_ptr),y                                     ; b9a8: b1 35       .5
    and #$0f                                                          ; b9aa: 29 0f       ).
    clc                                                               ; b9ac: 18          .
    adc l0100,x                                                       ; b9ad: 7d 00 01    ...
    txs                                                               ; b9b0: 9a          .
    tax                                                               ; b9b1: aa          .
    lda return_14,x                                                   ; b9b2: bd 73 a2    ... ; A=character to output
    jsr chrout                                                        ; b9b5: 20 d2 ff     R. ; Output a character
    jmp cb97f                                                         ; b9b8: 4c 7f b9    l..

; $b9bb referenced 2 times by $b972, $b983
return_20
    rts                                                               ; b9bb: 60          .

    .byte $81, 0, 0, 0, 0                                             ; b9bc: 81 00 00... ...

; $b9c1 referenced 7 times by $a729, $adb1, $ae3a, $b4a1, $b5bb, $bf7f, $bfa1
sub_cb9c1
    jsr caf7f                                                         ; b9c1: 20 7f af     ..
    cmp #0                                                            ; b9c4: c9 00       I.
    beq cb9d1                                                         ; b9c6: f0 09       ..
    cmp #$3a ; ':'                                                    ; b9c8: c9 3a       I:
    beq cb9d1                                                         ; b9ca: f0 05       ..
    jsr sub_ca71b                                                     ; b9cc: 20 1b a7     ..
    clc                                                               ; b9cf: 18          .
    rts                                                               ; b9d0: 60          .

; $b9d1 referenced 2 times by $b9c6, $b9ca
cb9d1
    jsr sub_ca71b                                                     ; b9d1: 20 1b a7     ..
    sec                                                               ; b9d4: 38          8
    rts                                                               ; b9d5: 60          .

    .byte $80, $35, 4, $f3, $34, $81, $35,   4, $f3, $34, $80, $80    ; b9d6: 80 35 04... .5.
    .byte   0,   0, 0, $80, $31, $72, $17, $f8, $60                   ; b9e2: 00 00 00... ...

; $b9eb referenced 2 times by $b3d1, $bb09
sub_cb9eb
    ldy #0                                                            ; b9eb: a0 00       ..
    tya                                                               ; b9ed: 98          .  ; A=0
    sta (basic_program_start),y                                       ; b9ee: 91 2b       .+
    iny                                                               ; b9f0: c8          H  ; Y=1
    sta (basic_program_start),y                                       ; b9f1: 91 2b       .+
    clc                                                               ; b9f3: 18          .
    lda basic_program_start                                           ; b9f4: a5 2b       .+
    adc #2                                                            ; b9f6: 69 02       ..
    sta basic_variables_start                                         ; b9f8: 85 2d       .-
    lda basic_program_start+1                                         ; b9fa: a5 2c       .,
    adc #0                                                            ; b9fc: 69 00       ..
    sta basic_variables_start+1                                       ; b9fe: 85 2e       ..
; $ba00 referenced 2 times by $b496, $bacc
basic_command_clr
    jsr clall                                                         ; ba00: 20 e7 ff     .. ; Close all files
    lda basic_memory_top                                              ; ba03: a5 37       .7
    sta basic_strings_bottom                                          ; ba05: 85 33       .3
    lda basic_memory_top+1                                            ; ba07: a5 38       .8
    sta basic_strings_bottom+1                                        ; ba09: 85 34       .4
    lda basic_variables_start                                         ; ba0b: a5 2d       .-
    sta basic_arrays_start                                            ; ba0d: 85 2f       ./
    sta basic_arrays_end                                              ; ba0f: 85 31       .1
    lda basic_variables_start+1                                       ; ba11: a5 2e       ..
    sta basic_arrays_start+1                                          ; ba13: 85 30       .0
    sta basic_arrays_end+1                                            ; ba15: 85 32       .2
    jsr le080                                                         ; ba17: 20 80 e0     ..
basic_command_restore
    sec                                                               ; ba1a: 38          8
    lda basic_program_start                                           ; ba1b: a5 2b       .+
    sbc #1                                                            ; ba1d: e9 01       ..
    sta basic_data_ptr                                                ; ba1f: 85 41       .a
    lda basic_program_start+1                                         ; ba21: a5 2c       .,
    sbc #0                                                            ; ba23: e9 00       ..
    sta basic_data_ptr+1                                              ; ba25: 85 42       .b
    rts                                                               ; ba27: 60          .

    .byte $20, $25, $e4, $4c, $ca, $a9                                ; ba28: 20 25 e4...  %.

; $ba2e referenced 5 times by $a1e6, $a293, $a647, $a65a, $b5df
sub_cba2e
    pha                                                               ; ba2e: 48          h
    jsr caf7f                                                         ; ba2f: 20 7f af     ..
    jsr sub_cbcf7                                                     ; ba32: 20 f7 bc     ..
    bcs cba7d                                                         ; ba35: b0 46       .f
    sta basic_line_number                                             ; ba37: 85 14       ..
    lda #0                                                            ; ba39: a9 00       ..
    sta basic_line_number+1                                           ; ba3b: 85 15       ..
; $ba3d referenced 1 time by $ba76
cba3d
    jsr sub_ca14f                                                     ; ba3d: 20 4f a1     o.
    jsr sub_cbcf7                                                     ; ba40: 20 f7 bc     ..
    bcs cba79                                                         ; ba43: b0 34       .4
    pha                                                               ; ba45: 48          h
    jsr sub_cba7f                                                     ; ba46: 20 7f ba     ..
    bcs cba86                                                         ; ba49: b0 3b       .;
    lda basic_line_number+1                                           ; ba4b: a5 15       ..
    pha                                                               ; ba4d: 48          h
    lda basic_line_number                                             ; ba4e: a5 14       ..
    pha                                                               ; ba50: 48          h
    jsr sub_cba7f                                                     ; ba51: 20 7f ba     ..
    bcs cba84                                                         ; ba54: b0 2e       ..
    jsr sub_cba7f                                                     ; ba56: 20 7f ba     ..
    bcs cba84                                                         ; ba59: b0 29       .)
    clc                                                               ; ba5b: 18          .
    pla                                                               ; ba5c: 68          .
    adc basic_line_number                                             ; ba5d: 65 14       ..
    sta basic_line_number                                             ; ba5f: 85 14       ..
    pla                                                               ; ba61: 68          .
    adc basic_line_number+1                                           ; ba62: 65 15       ..
    sta basic_line_number+1                                           ; ba64: 85 15       ..
    bcs cba86                                                         ; ba66: b0 1e       ..
    pla                                                               ; ba68: 68          .
    clc                                                               ; ba69: 18          .
    adc basic_line_number                                             ; ba6a: 65 14       ..
    sta basic_line_number                                             ; ba6c: 85 14       ..
    lda basic_line_number+1                                           ; ba6e: a5 15       ..
    adc #0                                                            ; ba70: 69 00       ..
    sta basic_line_number+1                                           ; ba72: 85 15       ..
    bcs cba87                                                         ; ba74: b0 11       ..
    jmp cba3d                                                         ; ba76: 4c 3d ba    l=.

; $ba79 referenced 1 time by $ba43
cba79
    jsr sub_ca71b                                                     ; ba79: 20 1b a7     ..
    clc                                                               ; ba7c: 18          .
; $ba7d referenced 1 time by $ba35
cba7d
    pla                                                               ; ba7d: 68          .
    rts                                                               ; ba7e: 60          .

; $ba7f referenced 3 times by $ba46, $ba51, $ba56
sub_cba7f
    asl basic_line_number                                             ; ba7f: 06 14       ..
    rol basic_line_number+1                                           ; ba81: 26 15       &.
    rts                                                               ; ba83: 60          .

; $ba84 referenced 2 times by $ba54, $ba59
cba84
    pla                                                               ; ba84: 68          .
    pla                                                               ; ba85: 68          .
; $ba86 referenced 2 times by $ba49, $ba66
cba86
    pla                                                               ; ba86: 68          .
; $ba87 referenced 1 time by $ba74
cba87
    pla                                                               ; ba87: 68          .
    tax                                                               ; ba88: aa          .
    jmp ca6ee                                                         ; ba89: 4c ee a6    l..

    .byte $4c, $25, $e4, $60, $60                                     ; ba8c: 4c 25 e4... l%.

; $ba91 referenced 1 time by $baa0
sub_cba91
    sta basic_load_verify_flag                                        ; ba91: 85 0a       ..
    jsr leb8c                                                         ; ba93: 20 8c eb     ..
    ldy #0                                                            ; ba96: a0 00       .. ; Y=secondary address
    jmp setlfs                                                        ; ba98: 4c ba ff    l.. ; Set the logical file number, device number and secondary address

basic_command_verify
    lda #1                                                            ; ba9b: a9 01       ..
; overlapping: bit @w rs232_start_bit_flag                            ; ba9d: 2c a9 00    ,..
    .byte $2c                                                         ; ba9d: 2c          ,

basic_command_load
    lda #0                                                            ; ba9e: a9 00       ..
    jsr sub_cba91                                                     ; baa0: 20 91 ba     ..
    jsr le2b5                                                         ; baa3: 20 b5 e2     ..
    jsr sub_ca729                                                     ; baa6: 20 29 a7     ).
    bcs cbab3                                                         ; baa9: b0 08       ..
    jsr le38c                                                         ; baab: 20 8c e3     ..
    bcs cbab3                                                         ; baae: b0 03       ..
    jsr sub_ca48b                                                     ; bab0: 20 8b a4     ..
; $bab3 referenced 3 times by $a1ae, $baa9, $baae
cbab3
    ldy basic_program_start+1                                         ; bab3: a4 2c       .,
    ldx basic_program_start                                           ; bab5: a6 2b       .+
    lda basic_load_verify_flag                                        ; bab7: a5 0a       ..
    jsr load                                                          ; bab9: 20 d5 ff     U. ; Load or verify a file (set up with SETLFS and SETNAM)
    bcc cbac1                                                         ; babc: 90 03       ..
    jmp ca6aa                                                         ; babe: 4c aa a6    l..

; $bac1 referenced 1 time by $babc
cbac1
    stx basic_variables_start                                         ; bac1: 86 2d       .-
    sty basic_variables_start+1                                       ; bac3: 84 2e       ..
    lda basic_load_verify_flag                                        ; bac5: a5 0a       ..
    beq cbacc                                                         ; bac7: f0 03       ..
    jmp ca1f6                                                         ; bac9: 4c f6 a1    l..

; $bacc referenced 1 time by $bac7
cbacc
    jsr basic_command_clr                                             ; bacc: 20 00 ba     ..
    jsr sub_ca533                                                     ; bacf: 20 33 a5     3.
    jsr sub_cbc12                                                     ; bad2: 20 12 bc     ..
    ldx basic_current_line+1                                          ; bad5: a6 3a       .:
    inx                                                               ; bad7: e8          .
    bne cbadd                                                         ; bad8: d0 03       P.
    jmp cac01                                                         ; bada: 4c 01 ac    l..

; $badd referenced 1 time by $bad8
cbadd
    pha                                                               ; badd: 48          h
    pha                                                               ; bade: 48          h
    jmp ca505                                                         ; badf: 4c 05 a5    l..

    .byte $a5, $61, $f0, $0f, $20, $a6, $ad, $20, $87, $ae, $20, $a6  ; bae2: a5 61 f0... ...
    .byte $ad, $20, $a6, $ad, $4c, $6a, $b8, $60, $4c, $b2, $a6, $84  ; baee: ad 20 a6... . .
    .byte $20,   0,   0,   0, $a9,   0, $85, $66, $a0, $ba, $a9, $f9  ; bafa: 20 00 00...  ..
    .byte $4c, $0f, $bb                                               ; bb06: 4c 0f bb    l..

basic_command_new
    jsr sub_cb9eb                                                     ; bb09: 20 eb b9     ..
    jmp cac01                                                         ; bb0c: 4c 01 ac    l..

    .byte $20, $25, $e4, $a5, $61, $d0,   3, $4c, $c6, $a6, $a5, $69  ; bb0f: 20 25 e4...  %.
    .byte $d0,   3, $4c, $c5, $a9, $a5, $66, $45, $6e, $85, $66, $a9  ; bb1b: d0 03 4c... P.l
    .byte $a0, $85, $26, $a9,   0, $85, $27, $a5, $69, $20, $be, $a1  ; bb27: a0 85 26... ..&
    .byte $a5, $26, $38, $e5, $61, $85, $26, $b0,   2, $c6, $27, $a5  ; bb33: a5 26 38... .&8
    .byte $27, $10,   3, $4c, $c5, $a9, $a5, $26, $85, $61, $20, $16  ; bb3f: 27 10 03... '..
    .byte $bf, $20, $b1, $a1, $20, $49, $b4, $a5, $6d, $85, $65, $a5  ; bb4b: bf 20 b1... . .
    .byte $6c, $85, $64, $a5, $6b, $85, $63, $a5, $6a, $85, $62, $4c  ; bb57: 6c 85 64... ...
    .byte $1e, $b5                                                    ; bb63: 1e b5       ..

; $bb65 referenced 2 times by $b695, $b6a2
sub_cbb65
    ldx #0                                                            ; bb65: a2 00       ..
; $bb67 referenced 1 time by $bb9e
cbb67
    ldy #0                                                            ; bb67: a0 00       ..
    lda (basic_string_temp_ptr),y                                     ; bb69: b1 35       .5
    cmp #$ff                                                          ; bb6b: c9 ff       I.
    bne cbb79                                                         ; bb6d: d0 0a       P.
    iny                                                               ; bb6f: c8          H  ; Y=1
    lda (basic_string_temp_ptr),y                                     ; bb70: b1 35       .5
    dey                                                               ; bb72: 88          .  ; Y=0
    cmp #$ff                                                          ; bb73: c9 ff       I.
    bne cbb79                                                         ; bb75: d0 02       P.
    sec                                                               ; bb77: 38          8
    rts                                                               ; bb78: 60          .

; $bb79 referenced 3 times by $bb6d, $bb75, $bb85
cbb79
    lda (basic_string_temp_ptr),y                                     ; bb79: b1 35       .5
    cmp l0106,y                                                       ; bb7b: d9 06 01    Y..
    bne cbb87                                                         ; bb7e: d0 07       P.
    cmp #0                                                            ; bb80: c9 00       I.
    beq cbba0                                                         ; bb82: f0 1c       ..
    iny                                                               ; bb84: c8          H
    bne cbb79                                                         ; bb85: d0 f2       P.
; $bb87 referenced 1 time by $bb7e
cbb87
    inx                                                               ; bb87: e8          .
    cmp #0                                                            ; bb88: c9 00       I.
    beq cbb91                                                         ; bb8a: f0 05       ..
; $bb8c referenced 1 time by $bb8f
loop_cbb8c
    iny                                                               ; bb8c: c8          H
    lda (basic_string_temp_ptr),y                                     ; bb8d: b1 35       .5
    bne loop_cbb8c                                                    ; bb8f: d0 fb       P.
; $bb91 referenced 1 time by $bb8a
cbb91
    iny                                                               ; bb91: c8          H
    tya                                                               ; bb92: 98          .
    clc                                                               ; bb93: 18          .
    adc basic_string_temp_ptr                                         ; bb94: 65 35       .5
    sta basic_string_temp_ptr                                         ; bb96: 85 35       .5
    lda basic_string_temp_ptr+1                                       ; bb98: a5 36       .6
    adc #0                                                            ; bb9a: 69 00       ..
    sta basic_string_temp_ptr+1                                       ; bb9c: 85 36       .6
    bcc cbb67                                                         ; bb9e: 90 c7       .G
; $bba0 referenced 1 time by $bb82
cbba0
    clc                                                               ; bba0: 18          .
    rts                                                               ; bba1: 60          .

    .byte $4c, $9c, $bc, $60, $60                                     ; bba2: 4c 9c bc... l..

basic_command_if
    jsr sub_cadae                                                     ; bba7: 20 ae ad     ..
    lda fac1_exponent                                                 ; bbaa: a5 61       ..
    bne cbbb1                                                         ; bbac: d0 03       P.
    jmp basic_command_rem                                             ; bbae: 4c a1 ad    l..

; $bbb1 referenced 1 time by $bbac
cbbb1
    jsr caf7f                                                         ; bbb1: 20 7f af     ..
    cmp #$89                                                          ; bbb4: c9 89       I.
    bne cbbbb                                                         ; bbb6: d0 03       P.
    jmp basic_command_goto                                            ; bbb8: 4c a6 b4    l..

; $bbbb referenced 1 time by $bbb6
cbbbb
    cmp #$a7                                                          ; bbbb: c9 a7       I.
    beq cbbc2                                                         ; bbbd: f0 03       ..
    jmp ca6cf                                                         ; bbbf: 4c cf a6    lO.

; $bbc2 referenced 1 time by $bbbd
cbbc2
    pla                                                               ; bbc2: 68          .
    pla                                                               ; bbc3: 68          .
    jmp ca493                                                         ; bbc4: 4c 93 a4    l..

    .byte $4c, $3d, $bc, $4c, $84, $a4, $4c, $b2, $a6, $a0, $4a, $a2  ; bbc7: 4c 3d bc... l=.
    .byte $49, $20, $c9 ; petscii "i I"                               ; bbd3: 49 20 c9    i I
    .byte $a2, $4c, $ee, $a7                                          ; bbd6: a2 4c ee... .l.

; $bbda referenced 1 time by $b969
sub_cbbda
    sta basic_string_temp_ptr                                         ; bbda: 85 35       .5
    sty basic_string_temp_ptr+1                                       ; bbdc: 84 36       .6
; $bbde referenced 1 time by $bbf8
loop_cbbde
    cpx #0                                                            ; bbde: e0 00       ..
    beq return_21                                                     ; bbe0: f0 19       ..
    dex                                                               ; bbe2: ca          J
    ldy #0                                                            ; bbe3: a0 00       ..
; $bbe5 referenced 1 time by $bbea
loop_cbbe5
    lda (basic_string_temp_ptr),y                                     ; bbe5: b1 35       .5
    iny                                                               ; bbe7: c8          H
    cmp #0                                                            ; bbe8: c9 00       I.
    bne loop_cbbe5                                                    ; bbea: d0 f9       P.
    clc                                                               ; bbec: 18          .
    tya                                                               ; bbed: 98          .
    adc basic_string_temp_ptr                                         ; bbee: 65 35       .5
    sta basic_string_temp_ptr                                         ; bbf0: 85 35       .5
    lda #0                                                            ; bbf2: a9 00       ..
    adc basic_string_temp_ptr+1                                       ; bbf4: 65 36       .6
    sta basic_string_temp_ptr+1                                       ; bbf6: 85 36       .6
    jmp loop_cbbde                                                    ; bbf8: 4c de bb    l..

; $bbfb referenced 1 time by $bbe0
return_21
    rts                                                               ; bbfb: 60          .

    .byte $4c, $37, $ab                                               ; bbfc: 4c 37 ab    l7.

; $bbff referenced 2 times by $b41d, $b427
sub_cbbff
    lda fac1_mantissa                                                 ; bbff: a5 62       ..
    cmp laabd,y                                                       ; bc01: d9 bd aa    Y..
    bne return_22                                                     ; bc04: d0 05       P.
    lda fac1_exponent                                                 ; bc06: a5 61       ..
    cmp le3ba,y                                                       ; bc08: d9 ba e3    Y..
; $bc0b referenced 1 time by $bc04
return_22
    rts                                                               ; bc0b: 60          .

    .byte $20, $c9, $a2, $4c, $87, $ae                                ; bc0c: 20 c9 a2...  I.

; $bc12 referenced 3 times by $a533, $b499, $bad2
sub_cbc12
    lda basic_program_start                                           ; bc12: a5 2b       .+
    sta basic_statement_ptr                                           ; bc14: 85 3d       .=
    lda basic_program_start+1                                         ; bc16: a5 2c       .,
    sta basic_statement_ptr+1                                         ; bc18: 85 3e       .>
    rts                                                               ; bc1a: 60          .

    .byte $4c, $c9, $a2                                               ; bc1b: 4c c9 a2    lI.

; $bc1e referenced 2 times by $a290, $ae6a
sub_cbc1e
    txa                                                               ; bc1e: 8a          .
    pha                                                               ; bc1f: 48          h
    tsx                                                               ; bc20: ba          .
    cpx #$60                                                          ; bc21: e0 60       ..
    bcs cbc28                                                         ; bc23: b0 03       ..
    jmp la6c1                                                         ; bc25: 4c c1 a6    lA.

; $bc28 referenced 1 time by $bc23
cbc28
    pla                                                               ; bc28: 68          .
    tax                                                               ; bc29: aa          .
    rts                                                               ; bc2a: 60          .

    .byte $a5, $61, $f0, 6, $a5, $66, $d0,   2, $a9, 1, $60, $4c, $b2 ; bc2b: a5 61 f0... ...
    .byte $a6, $60,   0, 0, $60, $a0,   0, $a2                        ; bc38: a6 60 00... ...
    .byte $57, $4c, $d4 ; petscii "wlT"                               ; bc40: 57 4c d4    wlT
    .byte $bb, $60                                                    ; bc43: bb 60       ..

; $bc45 referenced 3 times by $a19b, $a897, $acb0
sub_cbc45
    lda #0                                                            ; bc45: a9 00       ..
    sta basic_text_ptr                                                ; bc47: 85 7a       ..
    lda #2                                                            ; bc49: a9 02       ..
    sta basic_text_ptr+1                                              ; bc4b: 85 7b       ..
    lda #0                                                            ; bc4d: a9 00       ..
    sta basic_statement_ptr                                           ; bc4f: 85 3d       .=
    sta basic_statement_ptr+1                                         ; bc51: 85 3e       .>
    lda #$ff                                                          ; bc53: a9 ff       ..
    sta basic_current_line+1                                          ; bc55: 85 3a       .:
    rts                                                               ; bc57: 60          .

    .byte $60, 0, 0, $60, $a5, $62, $85, $51, $a5, $63, $4c, $6b, $bc ; bc58: 60 00 00... ...

; $bc65 referenced 1 time by $ab18
sub_cbc65
    lda fac2_mantissa                                                 ; bc65: a5 6a       ..
    sta basic_string_descriptor_ptr+1                                 ; bc67: 85 51       .q
    lda fac2_mantissa+1                                               ; bc69: a5 6b       ..
    sta basic_string_descriptor_ptr+2                                 ; bc6b: 85 52       .r
    ldx #$19                                                          ; bc6d: a2 19       ..
; $bc6f referenced 1 time by $bc99
cbc6f
    cpx basic_temp_string_index                                       ; bc6f: e4 16       ..
    bne cbc74                                                         ; bc71: d0 01       P.
    rts                                                               ; bc73: 60          .

; $bc74 referenced 1 time by $bc71
cbc74
    ldy cpu_port_direction,x                                          ; bc74: b4 00       ..
    beq cbc96                                                         ; bc76: f0 1e       ..
    inx                                                               ; bc78: e8          .
    lda cpu_port_direction,x                                          ; bc79: b5 00       ..
    cmp basic_string_descriptor_ptr+1                                 ; bc7b: c5 51       Eq
    bne cbc97                                                         ; bc7d: d0 18       P.
    inx                                                               ; bc7f: e8          .
    lda cpu_port_direction,x                                          ; bc80: b5 00       ..
    cmp basic_string_descriptor_ptr+2                                 ; bc82: c5 52       Er
    bne cbc98                                                         ; bc84: d0 12       P.
    sty basic_string_descriptor_ptr                                   ; bc86: 84 50       .p
    txa                                                               ; bc88: 8a          .
    pha                                                               ; bc89: 48          h
    jsr ca3e1                                                         ; bc8a: 20 e1 a3     ..
    pla                                                               ; bc8d: 68          .
    tax                                                               ; bc8e: aa          .
    dex                                                               ; bc8f: ca          J
    dex                                                               ; bc90: ca          J
    lda #0                                                            ; bc91: a9 00       ..
    sta cpu_port_direction,x                                          ; bc93: 95 00       ..
    rts                                                               ; bc95: 60          .

; $bc96 referenced 1 time by $bc76
cbc96
    inx                                                               ; bc96: e8          .
; $bc97 referenced 1 time by $bc7d
cbc97
    inx                                                               ; bc97: e8          .
; $bc98 referenced 1 time by $bc84
cbc98
    inx                                                               ; bc98: e8          .
    bne cbc6f                                                         ; bc99: d0 d4       PT
    rts                                                               ; bc9b: 60          .

; $bc9c referenced 1 time by $ae07
sub_cbc9c
    sty basic_index1+1                                                ; bc9c: 84 23       .#
    sta basic_index1                                                  ; bc9e: 85 22       ."
    ldy #4                                                            ; bca0: a0 04       ..
    lda (basic_index1),y                                              ; bca2: b1 22       ."
    sta fac1_mantissa+3                                               ; bca4: 85 65       ..
    dey                                                               ; bca6: 88          .  ; Y=3
    lda (basic_index1),y                                              ; bca7: b1 22       ."
    sta fac1_mantissa+2                                               ; bca9: 85 64       ..
    dey                                                               ; bcab: 88          .  ; Y=2
    lda (basic_index1),y                                              ; bcac: b1 22       ."
    sta fac1_mantissa+1                                               ; bcae: 85 63       ..
    dey                                                               ; bcb0: 88          .  ; Y=1
    lda (basic_index1),y                                              ; bcb1: b1 22       ."
    ora #$80                                                          ; bcb3: 09 80       ..
    sta fac1_mantissa                                                 ; bcb5: 85 62       ..
    lda (basic_index1),y                                              ; bcb7: b1 22       ."
    bpl cbcbe                                                         ; bcb9: 10 03       ..
    lda #$ff                                                          ; bcbb: a9 ff       ..
; overlapping: bit @w rs232_start_bit_flag                            ; bcbd: 2c a9 00    ,..
    .byte $2c                                                         ; bcbd: 2c          ,

; $bcbe referenced 1 time by $bcb9
cbcbe
    lda #0                                                            ; bcbe: a9 00       ..
    sta fac1_sign                                                     ; bcc0: 85 66       ..
    dey                                                               ; bcc2: 88          .
    lda (basic_index1),y                                              ; bcc3: b1 22       ."
    sta fac1_exponent                                                 ; bcc5: 85 61       ..
    sty fac1_rounding                                                 ; bcc7: 84 70       ..
    lda fac1_exponent                                                 ; bcc9: a5 61       ..
    rts                                                               ; bccb: 60          .

    .byte $60                                                         ; bccc: 60          .

; $bccd referenced 2 times by $b909, $b938
sub_cbccd
    beq cbcee                                                         ; bccd: f0 1f       ..
    sta basic_index2                                                  ; bccf: 85 24       .$
    lda basic_index2+1                                                ; bcd1: a5 25       .%
    beq cbcee                                                         ; bcd3: f0 19       ..
    lda #0                                                            ; bcd5: a9 00       ..
    ldx #8                                                            ; bcd7: a2 08       ..
    clc                                                               ; bcd9: 18          .
; $bcda referenced 1 time by $bce3
loop_cbcda
    bcc cbcdf                                                         ; bcda: 90 03       ..
    clc                                                               ; bcdc: 18          .
    adc basic_index2+1                                                ; bcdd: 65 25       .%
; $bcdf referenced 1 time by $bcda
cbcdf
    ror a                                                             ; bcdf: 6a          .
    ror basic_index2                                                  ; bce0: 66 24       .$
    dex                                                               ; bce2: ca          J
    bpl loop_cbcda                                                    ; bce3: 10 f5       ..
    ldx basic_index2                                                  ; bce5: a6 24       .$
    stx basic_index2                                                  ; bce7: 86 24       .$
    tax                                                               ; bce9: aa          .
    lda basic_index2                                                  ; bcea: a5 24       .$
    clc                                                               ; bcec: 18          .
    rts                                                               ; bced: 60          .

; $bcee referenced 2 times by $bccd, $bcd3
cbcee
    lda #0                                                            ; bcee: a9 00       ..
    tax                                                               ; bcf0: aa          .  ; X=0
    clc                                                               ; bcf1: 18          .
    rts                                                               ; bcf2: 60          .

    .byte $60                                                         ; bcf3: 60          .

; $bcf4 referenced 1 time by $a5a2
cbcf4
    jmp ca6b2                                                         ; bcf4: 4c b2 a6    l..

; $bcf7 referenced 3 times by $b815, $ba32, $ba40
sub_cbcf7
    sec                                                               ; bcf7: 38          8
    sbc #$30 ; '0'                                                    ; bcf8: e9 30       .0
    bcc cbcff                                                         ; bcfa: 90 03       ..
    cmp #$0a                                                          ; bcfc: c9 0a       I.
    rts                                                               ; bcfe: 60          .

; $bcff referenced 2 times by $a4c9, $bcfa
cbcff
    sec                                                               ; bcff: 38          8
    rts                                                               ; bd00: 60          .

; $bd01 referenced 1 time by $a592
cbd01
    jsr sub_cb795                                                     ; bd01: 20 95 b7     ..
    bcc cbd09                                                         ; bd04: 90 03       ..
    jmp ca6b2                                                         ; bd06: 4c b2 a6    l..

; $bd09 referenced 1 time by $bd04
cbd09
    lda basic_garbage_step                                            ; bd09: a5 53       .s
    pha                                                               ; bd0b: 48          h
    ldx #0                                                            ; bd0c: a2 00       ..
; $bd0e referenced 1 time by $bd1a
loop_cbd0e
    inx                                                               ; bd0e: e8          .
    jsr sub_ca290                                                     ; bd0f: 20 90 a2     ..
    lda basic_line_number+1                                           ; bd12: a5 15       ..
    pha                                                               ; bd14: 48          h
    lda basic_line_number                                             ; bd15: a5 14       ..
    pha                                                               ; bd17: 48          h
    cpy #0                                                            ; bd18: c0 00       ..
    beq loop_cbd0e                                                    ; bd1a: f0 f2       ..
    stx fac1_exponent                                                 ; bd1c: 86 61       ..
    jsr le023                                                         ; bd1e: 20 23 e0     #.
    bne cbd7b                                                         ; bd21: d0 58       Px
; $bd23 referenced 1 time by $be69
cbd23
    lda #5                                                            ; bd23: a9 05       ..
cbd25
lbd26 = cbd25+1
    jsr sub_cbdd3                                                     ; bd25: 20 d3 bd     S.
; $bd26 referenced 1 time by $a4c5
    lda #0                                                            ; bd28: a9 00       ..
    sta fac1_mantissa                                                 ; bd2a: 85 62       ..
    sta fac1_mantissa+1                                               ; bd2c: 85 63       ..
    ldx #0                                                            ; bd2e: a2 00       ..
; $bd30 referenced 1 time by $bd59
cbd30
    txa                                                               ; bd30: 8a          .
    inx                                                               ; bd31: e8          .
    asl a                                                             ; bd32: 0a          .
    tay                                                               ; bd33: a8          .
    jsr le0ab                                                         ; bd34: 20 ab e0     ..
    jsr sub_cb901                                                     ; bd37: 20 01 b9     ..
    clc                                                               ; bd3a: 18          .
    pla                                                               ; bd3b: 68          .
    sta basic_index1                                                  ; bd3c: 85 22       ."
    adc fac1_mantissa                                                 ; bd3e: 65 62       ..
    sta fac1_mantissa                                                 ; bd40: 85 62       ..
    pla                                                               ; bd42: 68          .
    sta basic_index1+1                                                ; bd43: 85 23       .#
    adc fac1_mantissa+1                                               ; bd45: 65 63       ..
    sta fac1_mantissa+1                                               ; bd47: 85 63       ..
    lda basic_index1+1                                                ; bd49: a5 23       .#
    cmp fac1_mantissa+3                                               ; bd4b: c5 65       E.
    bcc cbd57                                                         ; bd4d: 90 08       ..
    bne cbd7b                                                         ; bd4f: d0 2a       P*
    lda basic_index1                                                  ; bd51: a5 22       ."
    cmp fac1_mantissa+2                                               ; bd53: c5 64       E.
    bcs cbd7b                                                         ; bd55: b0 24       .$
; $bd57 referenced 1 time by $bd4d
cbd57
    cpx fac1_exponent                                                 ; bd57: e4 61       ..
    bne cbd30                                                         ; bd59: d0 d5       PU
    pla                                                               ; bd5b: 68          .
    sta basic_garbage_step                                            ; bd5c: 85 53       .s
    sta fac1_mantissa+2                                               ; bd5e: 85 64       ..
    lda #0                                                            ; bd60: a9 00       ..
    sta fac1_mantissa+3                                               ; bd62: 85 65       ..
    jsr sub_cb901                                                     ; bd64: 20 01 b9     ..
    lda fac1_exponent                                                 ; bd67: a5 61       ..
    asl a                                                             ; bd69: 0a          .
    jsr sub_cbdd3                                                     ; bd6a: 20 d3 bd     S.
    clc                                                               ; bd6d: 18          .
    lda fac1_mantissa                                                 ; bd6e: a5 62       ..
    adc basic_variable_ptr                                            ; bd70: 65 47       .g
    sta basic_variable_ptr                                            ; bd72: 85 47       .g
    lda fac1_mantissa+1                                               ; bd74: a5 63       ..
    adc basic_variable_ptr+1                                          ; bd76: 65 48       .h
    sta basic_variable_ptr+1                                          ; bd78: 85 48       .h
    rts                                                               ; bd7a: 60          .

; $bd7b referenced 3 times by $bd21, $bd4f, $bd55
cbd7b
    jmp la6c8                                                         ; bd7b: 4c c8 a6    lH.

    .byte $60                                                         ; bd7e: 60          .
    .byte <(basic_command_end - 1)                                    ; bd7f: c5          E
    .byte <(basic_command_for - 1)                                    ; bd80: dd          .
    .byte <(basic_command_next - 1)                                   ; bd81: de          .
    .byte <(basic_command_data - 1)                                   ; bd82: df          .
    .byte <(basic_command_input_hash - 1)                             ; bd83: e0          .
    .byte <(basic_command_input - 1)                                  ; bd84: e1          .
    .byte <(basic_command_dim - 1)                                    ; bd85: b7          .
    .byte <(basic_command_read - 1)                                   ; bd86: e2          .
    .byte <(basic_command_let - 1)                                    ; bd87: f2          .
    .byte <(basic_command_goto - 1)                                   ; bd88: a5          .
    .byte <(basic_command_run - 1)                                    ; bd89: 95          .
    .byte <(basic_command_if - 1)                                     ; bd8a: a6          .
    .byte <(basic_command_restore - 1)                                ; bd8b: 19          .
    .byte <(basic_command_gosub - 1)                                  ; bd8c: e3          .
    .byte <(basic_command_return - 1)                                 ; bd8d: e4          .
    .byte <(basic_command_rem - 1)                                    ; bd8e: a0          .
    .byte <(basic_command_stop - 1)                                   ; bd8f: ab          .
    .byte <(basic_command_on - 1)                                     ; bd90: e5          .
    .byte <(basic_command_wait - 1)                                   ; bd91: 59          y
    .byte <(basic_command_load - 1)                                   ; bd92: 9d          .
    .byte <(basic_command_save - 1)                                   ; bd93: bd          .
    .byte <(basic_command_verify - 1)                                 ; bd94: 9a          .
    .byte <(basic_command_def - 1)                                    ; bd95: e6          .
    .byte <(basic_command_poke - 1)                                   ; bd96: ff          .
    .byte <(basic_command_print_hash - 1)                             ; bd97: e7          .
    .byte <(basic_command_print - 1)                                  ; bd98: 7e          .
    .byte <(basic_command_cont - 1)                                   ; bd99: e8          .
    .byte <(basic_command_list - 1)                                   ; bd9a: cb          K
    .byte <(basic_command_clr - 1)                                    ; bd9b: ff          .
    .byte <(basic_command_cmd - 1)                                    ; bd9c: e9          .
    .byte <(basic_command_sys - 1)                                    ; bd9d: ba          .
    .byte <(basic_command_open - 1)                                   ; bd9e: ea          .
    .byte <(basic_command_close - 1)                                  ; bd9f: eb          .
    .byte <(basic_command_get - 1)                                    ; bda0: ec          .
    .byte <(basic_command_new - 1)                                    ; bda1: 08          .
    .byte <(sub_cbdee - 1)                                            ; bda2: ed          .
    .byte <(ca6cf - 1)                                                ; bda3: ce          N
    .byte <(ca6cf - 1)                                                ; bda4: ce          N
    .byte <(sub_cbdef - 1)                                            ; bda5: ee          .
    .byte >(basic_command_end - 1)                                    ; bda6: a2          .
    .byte >(basic_command_for - 1)                                    ; bda7: bd          .
    .byte >(basic_command_next - 1)                                   ; bda8: bd          .
    .byte >(basic_command_data - 1)                                   ; bda9: bd          .
    .byte >(basic_command_input_hash - 1)                             ; bdaa: bd          .
    .byte >(basic_command_input - 1)                                  ; bdab: bd          .
    .byte >(basic_command_dim - 1)                                    ; bdac: ae          .
    .byte >(basic_command_read - 1)                                   ; bdad: bd          .
    .byte >(basic_command_let - 1)                                    ; bdae: bd          .
    .byte >(basic_command_goto - 1)                                   ; bdaf: b4          .
    .byte >(basic_command_run - 1)                                    ; bdb0: b4          .
    .byte >(basic_command_if - 1)                                     ; bdb1: bb          .
    .byte >(basic_command_restore - 1)                                ; bdb2: ba          .
    .byte >(basic_command_gosub - 1)                                  ; bdb3: bd          .
    .byte >(basic_command_return - 1)                                 ; bdb4: bd          .
    .byte >(basic_command_rem - 1)                                    ; bdb5: ad          .
    .byte >(basic_command_stop - 1)                                   ; bdb6: a2          .
    .byte >(basic_command_on - 1)                                     ; bdb7: bd          .
    .byte >(basic_command_wait - 1)                                   ; bdb8: a6          .
    .byte >(basic_command_load - 1)                                   ; bdb9: ba          .
    .byte >(basic_command_save - 1)                                   ; bdba: e2          .
    .byte >(basic_command_verify - 1)                                 ; bdbb: ba          .
    .byte >(basic_command_def - 1)                                    ; bdbc: bd          .
    .byte >(basic_command_poke - 1)                                   ; bdbd: df          .
    .byte >(basic_command_print_hash - 1)                             ; bdbe: bd          .
    .byte >(basic_command_print - 1)                                  ; bdbf: bf          .
    .byte >(basic_command_cont - 1)                                   ; bdc0: bd          .
    .byte >(basic_command_list - 1)                                   ; bdc1: e3          .
    .byte >(basic_command_clr - 1)                                    ; bdc2: b9          .
    .byte >(basic_command_cmd - 1)                                    ; bdc3: bd          .
    .byte >(basic_command_sys - 1)                                    ; bdc4: b5          .
    .byte >(basic_command_open - 1)                                   ; bdc5: bd          .
    .byte >(basic_command_close - 1)                                  ; bdc6: bd          .
    .byte >(basic_command_get - 1)                                    ; bdc7: bd          .
    .byte >(basic_command_new - 1)                                    ; bdc8: bb          .
    .byte >(sub_cbdee - 1)                                            ; bdc9: bd          .
    .byte >(ca6cf - 1)                                                ; bdca: a6          .
    .byte >(ca6cf - 1)                                                ; bdcb: a6          .
    .byte >(sub_cbdef - 1)                                            ; bdcc: bd          .
    .byte $4c, $0e, $b4, $4c, $b2, $a6                                ; bdcd: 4c 0e b4... l..

; $bdd3 referenced 4 times by $a5c8, $a5cf, $bd25, $bd6a
sub_cbdd3
    clc                                                               ; bdd3: 18          .
    adc basic_variable_ptr                                            ; bdd4: 65 47       .g
    sta basic_variable_ptr                                            ; bdd6: 85 47       .g
    bcc return_23                                                     ; bdd8: 90 02       ..
    inc basic_variable_ptr+1                                          ; bdda: e6 48       .h
; $bddc referenced 1 time by $bdd8
return_23
    rts                                                               ; bddc: 60          .

    .byte $60                                                         ; bddd: 60          .

basic_command_for
    nop                                                               ; bdde: ea          .
basic_command_next
    nop                                                               ; bddf: ea          .
basic_command_data
    nop                                                               ; bde0: ea          .
basic_command_input_hash
    nop                                                               ; bde1: ea          .
basic_command_input
    nop                                                               ; bde2: ea          .
basic_command_read
    nop                                                               ; bde3: ea          .
basic_command_gosub
    nop                                                               ; bde4: ea          .
basic_command_return
    nop                                                               ; bde5: ea          .
basic_command_on
    nop                                                               ; bde6: ea          .
basic_command_def
    nop                                                               ; bde7: ea          .
basic_command_print_hash
    nop                                                               ; bde8: ea          .
basic_command_cont
    nop                                                               ; bde9: ea          .
basic_command_cmd
    nop                                                               ; bdea: ea          .
basic_command_open
    nop                                                               ; bdeb: ea          .
basic_command_close
    nop                                                               ; bdec: ea          .
basic_command_get
    nop                                                               ; bded: ea          .
sub_cbdee
    nop                                                               ; bdee: ea          .
sub_cbdef
    nop                                                               ; bdef: ea          .
    jmp ca6b2                                                         ; bdf0: 4c b2 a6    l..

; $bdf3 referenced 1 time by $a530
basic_command_let
    jsr sub_ca746                                                     ; bdf3: 20 46 a7     f.
    bcc cbdfb                                                         ; bdf6: 90 03       ..
    jmp ca6cf                                                         ; bdf8: 4c cf a6    lO.

; $bdfb referenced 1 time by $bdf6
cbdfb
    lda basic_dim_flag                                                ; bdfb: a5 0c       ..
    bpl cbe22                                                         ; bdfd: 10 23       .#
    lda #$be                                                          ; bdff: a9 be       ..
    pha                                                               ; be01: 48          h
    lda #$6b                                                          ; be02: a9 6b       ..
    pha                                                               ; be04: 48          h
    lda basic_garbage_step                                            ; be05: a5 53       .s
    pha                                                               ; be07: 48          h
    ldx #0                                                            ; be08: a2 00       ..
; $be0a referenced 1 time by $be16
loop_cbe0a
    inx                                                               ; be0a: e8          .
    jsr sub_ca290                                                     ; be0b: 20 90 a2     ..
    lda basic_line_number+1                                           ; be0e: a5 15       ..
    pha                                                               ; be10: 48          h
    lda basic_line_number                                             ; be11: a5 14       ..
    pha                                                               ; be13: 48          h
    cpy #0                                                            ; be14: c0 00       ..
    beq loop_cbe0a                                                    ; be16: f0 f2       ..
    txa                                                               ; be18: 8a          .
    pha                                                               ; be19: 48          h
    jsr sub_ca57d                                                     ; be1a: 20 7d a5     ..
    lda #$ff                                                          ; be1d: a9 ff       ..
    jmp cbe3f                                                         ; be1f: 4c 3f be    l?.

; $be22 referenced 1 time by $bdfd
cbe22
    jsr sub_ca57d                                                     ; be22: 20 7d a5     ..
    jsr sub_cb1c8                                                     ; be25: 20 c8 b1     H.
    bne cbe2d                                                         ; be28: d0 03       P.
    jmp cb7f8                                                         ; be2a: 4c f8 b7    l..

; $be2d referenced 1 time by $be28
cbe2d
    jsr sub_caead                                                     ; be2d: 20 ad ae     ..
    bne cbe35                                                         ; be30: d0 03       P.
    jmp ca6cf                                                         ; be32: 4c cf a6    lO.

; $be35 referenced 1 time by $be30
cbe35
    jsr sub_cbf66                                                     ; be35: 20 66 bf     ..
    bne cbe3d                                                         ; be38: d0 03       P.
    jmp ca6cf                                                         ; be3a: 4c cf a6    lO.

; $be3d referenced 1 time by $be38
cbe3d
    lda basic_dim_flag                                                ; be3d: a5 0c       ..
; $be3f referenced 1 time by $be1f
cbe3f
    pha                                                               ; be3f: 48          h
    lda basic_variable_name                                           ; be40: a5 45       .e
    pha                                                               ; be42: 48          h
    lda basic_variable_name+1                                         ; be43: a5 46       .f
    pha                                                               ; be45: 48          h
    jsr sub_cadae                                                     ; be46: 20 ae ad     ..
    pla                                                               ; be49: 68          .
    sta basic_variable_name+1                                         ; be4a: 85 46       .f
    pla                                                               ; be4c: 68          .
    sta basic_variable_name                                           ; be4d: 85 45       .e
    pla                                                               ; be4f: 68          .
    sta basic_dim_flag                                                ; be50: 85 0c       ..
    bpl cbe77                                                         ; be52: 10 23       .#
    ldx #4                                                            ; be54: a2 04       ..
; $be56 referenced 1 time by $be5b
loop_cbe56
    lda fac1_exponent,x                                               ; be56: b5 61       ..
    sta fac2_exponent,x                                               ; be58: 95 69       ..
    dex                                                               ; be5a: ca          J
    bpl loop_cbe56                                                    ; be5b: 10 f9       ..
    jsr sub_cb795                                                     ; be5d: 20 95 b7     ..
    bcc cbe65                                                         ; be60: 90 03       ..
    jmp ca6b2                                                         ; be62: 4c b2 a6    l..

; $be65 referenced 1 time by $be60
cbe65
    pla                                                               ; be65: 68          .
    sta fac1_exponent                                                 ; be66: 85 61       ..
    tax                                                               ; be68: aa          .
    jmp cbd23                                                         ; be69: 4c 23 bd    l#.

    .byte $a2, 4, $b5, $69, $95, $61, $ca, $10, $f9, $30, 3           ; be6c: a2 04 b5... ...

; $be77 referenced 1 time by $be52
cbe77
    jsr ca5ad                                                         ; be77: 20 ad a5     ..
    lda #0                                                            ; be7a: a9 00       ..
    clc                                                               ; be7c: 18          .
    bit basic_variable_name                                           ; be7d: 24 45       $e
    bpl cbe83                                                         ; be7f: 10 02       ..
    adc #1                                                            ; be81: 69 01       ..
; $be83 referenced 1 time by $be7f
cbe83
    bit basic_variable_name+1                                         ; be83: 24 46       $f
    bpl cbe89                                                         ; be85: 10 02       ..
    adc #$80                                                          ; be87: 69 80       ..
; $be89 referenced 1 time by $be85
cbe89
    bmi cbea1                                                         ; be89: 30 16       0.
    beq cbe97                                                         ; be8b: f0 0a       ..
    lda basic_value_type                                              ; be8d: a5 0d       ..
    bpl cbe94                                                         ; be8f: 10 03       ..
    jmp ca6c4                                                         ; be91: 4c c4 a6    lD.

; $be94 referenced 1 time by $be8f
cbe94
    jmp ca6b2                                                         ; be94: 4c b2 a6    l..

; $be97 referenced 1 time by $be8b
cbe97
    lda basic_value_type                                              ; be97: a5 0d       ..
    bpl cbe9e                                                         ; be99: 10 03       ..
    jmp ca6c4                                                         ; be9b: 4c c4 a6    lD.

; $be9e referenced 1 time by $be99
cbe9e
    jmp ca6b2                                                         ; be9e: 4c b2 a6    l..

; $bea1 referenced 1 time by $be89
cbea1
    lda basic_value_type                                              ; bea1: a5 0d       ..
    bmi cbea8                                                         ; bea3: 30 03       0.
    jmp ca6c4                                                         ; bea5: 4c c4 a6    lD.

; $bea8 referenced 1 time by $bea3
cbea8
    jsr le3eb                                                         ; bea8: 20 eb e3     ..
    lda fac1_exponent                                                 ; beab: a5 61       ..
    bne cbeb9                                                         ; bead: d0 0a       P.
    jsr sub_ca3d6                                                     ; beaf: 20 d6 a3     V.
    ldy #0                                                            ; beb2: a0 00       ..
    lda #0                                                            ; beb4: a9 00       ..
    sta (basic_variable_ptr),y                                        ; beb6: 91 47       .g
    rts                                                               ; beb8: 60          .

; $beb9 referenced 1 time by $bead
cbeb9
    lda basic_string_descriptor_ptr+1                                 ; beb9: a5 51       .q
    cmp fac1_mantissa                                                 ; bebb: c5 62       E.
    bne cbec7                                                         ; bebd: d0 08       P.
    iny                                                               ; bebf: c8          H
    lda basic_string_descriptor_ptr+2                                 ; bec0: a5 52       .r
    cmp fac1_mantissa+1                                               ; bec2: c5 63       E.
    bne cbec7                                                         ; bec4: d0 01       P.
    rts                                                               ; bec6: 60          .

; $bec7 referenced 2 times by $bebd, $bec4
cbec7
    lda basic_variables_start+1                                       ; bec7: a5 2e       ..
    cmp fac1_mantissa+1                                               ; bec9: c5 63       E.
    bcc cbef4                                                         ; becb: 90 27       .'
    bne cbed5                                                         ; becd: d0 06       P.
    lda basic_variables_start                                         ; becf: a5 2d       .-
    cmp fac1_mantissa                                                 ; bed1: c5 62       E.
    bcc cbef4                                                         ; bed3: 90 1f       ..
; $bed5 referenced 1 time by $becd
cbed5
    lda fac1_mantissa+1                                               ; bed5: a5 63       ..
    cmp basic_program_start+1                                         ; bed7: c5 2c       E,
    bcc cbef4                                                         ; bed9: 90 19       ..
    bne cbee3                                                         ; bedb: d0 06       P.
    lda fac1_mantissa                                                 ; bedd: a5 62       ..
    cmp basic_program_start                                           ; bedf: c5 2b       E+
    bcc cbef4                                                         ; bee1: 90 11       ..
; $bee3 referenced 1 time by $bedb
cbee3
    ldy #0                                                            ; bee3: a0 00       ..
    lda fac1_exponent                                                 ; bee5: a5 61       ..
    sta (basic_variable_ptr),y                                        ; bee7: 91 47       .g
    iny                                                               ; bee9: c8          H  ; Y=1
    lda fac1_mantissa                                                 ; beea: a5 62       ..
    sta (basic_variable_ptr),y                                        ; beec: 91 47       .g
    iny                                                               ; beee: c8          H  ; Y=2
    lda fac1_mantissa+1                                               ; beef: a5 63       ..
    sta (basic_variable_ptr),y                                        ; bef1: 91 47       .g
    rts                                                               ; bef3: 60          .

; $bef4 referenced 4 times by $becb, $bed3, $bed9, $bee1
cbef4
    jsr sub_cb948                                                     ; bef4: 20 48 b9     h.
    bcc cbf05                                                         ; bef7: 90 0c       ..
    lda basic_string_descriptor_ptr                                   ; bef9: a5 50       .p
    cmp fac1_exponent                                                 ; befb: c5 61       E.
    bne cbf02                                                         ; befd: d0 03       P.
    jmp le404                                                         ; beff: 4c 04 e4    l..

; $bf02 referenced 1 time by $befd
cbf02
    jsr sub_ca3d6                                                     ; bf02: 20 d6 a3     V.
; $bf05 referenced 1 time by $bef7
cbf05
    lda fac1_exponent                                                 ; bf05: a5 61       ..
    ldy #0                                                            ; bf07: a0 00       ..
    sta (basic_variable_ptr),y                                        ; bf09: 91 47       .g
    jsr sub_cb4d3                                                     ; bf0b: 20 d3 b4     S.
    jmp le404                                                         ; bf0e: 4c 04 e4    l..

    .byte $80,   0,   0,   0,   0, $a9,   0, $85, $70, $a5, $65, $d0  ; bf11: 80 00 00... ...
    .byte $1c, $a5, $61, $c9,   8, $90, $16, $e9,   8, $85, $61, $a5  ; bf1d: 1c a5 61... ...
    .byte $64, $85, $65, $a5, $63, $85, $64, $a5, $62, $85, $63, $a9  ; bf29: 64 85 65... ...
    .byte   0, $85, $62, $f0, $dc, $a5, $65, $29,   1, $d0, $11, $a5  ; bf35: 00 85 62... ...
    .byte $61, $f0, $0d, $c6, $61, $18, $66, $62, $66, $63, $66, $64  ; bf41: 61 f0 0d... ...
    .byte $66, $65, $90, $e9, $60, $4f, $52,   1                      ; bf4d: 66 65 90... ...
    .byte $44, $45, $56, $2e, $32, $31, $30, $38 ; petscii "dev.2108" ; bf55: 44 45 56... dev
    .byte $32, $33, $2e, $46, $43, $2e, $31 ; petscii "23.fc.1"       ; bf5d: 32 33 2e... 23.
    .byte 0, 0                                                        ; bf64: 00 00       ..

; $bf66 referenced 2 times by $a5a5, $be35
sub_cbf66
    lda basic_variable_name+1                                         ; bf66: a5 46       .f
    cmp #$54 ; 't'                                                    ; bf68: c9 54       It
    bne return_24                                                     ; bf6a: d0 04       P.
    lda basic_variable_name                                           ; bf6c: a5 45       .e
    cmp #$53 ; 's'                                                    ; bf6e: c9 53       Is
; $bf70 referenced 1 time by $bf6a
return_24
    rts                                                               ; bf70: 60          .

    .byte $20, $87, $ae, $60, $4c, $b2, $a6, $20, $9c, $bc, $60, $4c  ; bf71: 20 87 ae...  ..
    .byte $b2, $a6                                                    ; bf7d: b2 a6       ..

basic_command_print
    jsr sub_cb9c1                                                     ; bf7f: 20 c1 b9     A.
    bcs cbfb0                                                         ; bf82: b0 2c       .,
    jsr sub_ca14f                                                     ; bf84: 20 4f a1     o.
    cmp #$3b ; ';'                                                    ; bf87: c9 3b       I;
    beq return_25                                                     ; bf89: f0 28       .(
; $bf8b referenced 1 time by $bfae
cbf8b
    jsr sub_ca71b                                                     ; bf8b: 20 1b a7     ..
; $bf8e referenced 1 time by $bfa8
loop_cbf8e
    jsr le060                                                         ; bf8e: 20 60 e0     ..
    jsr sub_cadae                                                     ; bf91: 20 ae ad     ..
    lda basic_value_type                                              ; bf94: a5 0d       ..
    bpl cbf9e                                                         ; bf96: 10 06       ..
    jsr le044                                                         ; bf98: 20 44 e0     d.
    jmp cbfa1                                                         ; bf9b: 4c a1 bf    l..

; $bf9e referenced 1 time by $bf96
cbf9e
    jmp ca6b2                                                         ; bf9e: 4c b2 a6    l..

; $bfa1 referenced 1 time by $bf9b
cbfa1
    jsr sub_cb9c1                                                     ; bfa1: 20 c1 b9     A.
    bcs cbfb0                                                         ; bfa4: b0 0a       ..
    cmp #$2c ; ','                                                    ; bfa6: c9 2c       I,
    beq loop_cbf8e                                                    ; bfa8: f0 e4       ..
    cmp #$3b ; ';'                                                    ; bfaa: c9 3b       I;
    beq return_25                                                     ; bfac: f0 05       ..
    bne cbf8b                                                         ; bfae: d0 db       P. ; ALWAYS branch

; $bfb0 referenced 2 times by $bf82, $bfa4
cbfb0
    jsr lf7c1                                                         ; bfb0: 20 c1 f7     A.
; $bfb3 referenced 2 times by $bf89, $bfac
return_25
    rts                                                               ; bfb3: 60          .

    .byte $a5, $61, $f0,   6, $a5, $66, $49, $ff, $85, $66, $60, $81  ; bfb4: a5 61 f0... ...
    .byte $38, $aa, $3b, $29                                          ; bfc0: 38 aa 3b... 8.;

; $bfc4 referenced 1 time by $a317
sub_cbfc4
    lda basic_statement_ptr                                           ; bfc4: a5 3d       .=
    sta basic_multiply_result                                         ; bfc6: 85 26       .&
    lda basic_statement_ptr+1                                         ; bfc8: a5 3e       .>
    sta basic_multiply_result+1                                       ; bfca: 85 27       .'
    clc                                                               ; bfcc: 18          .
    txa                                                               ; bfcd: 8a          .
    adc basic_multiply_result                                         ; bfce: 65 26       .&
    sta basic_index2                                                  ; bfd0: 85 24       .$
    lda basic_multiply_result+1                                       ; bfd2: a5 27       .'
    adc #0                                                            ; bfd4: 69 00       ..
    sta basic_index2+1                                                ; bfd6: 85 25       .%
    lda basic_variables_start                                         ; bfd8: a5 2d       .-
    sec                                                               ; bfda: 38          8
    sbc basic_index2                                                  ; bfdb: e5 24       .$
    sta basic_multiply_result+2                                       ; bfdd: 85 28       .(
    lda basic_variables_start+1                                       ; bfdf: a5 2e       ..
    sbc basic_index2+1                                                ; bfe1: e5 25       .%
    sta basic_multiply_result+3                                       ; bfe3: 85 29       .)
    jmp cbff4                                                         ; bfe5: 4c f4 bf    l..

    .byte $81, 0, 0, 0, 0                                             ; bfe8: 81 00 00... ...
; $bfed referenced 1 time by $a4e4
lbfed
    .byte $60                                                         ; bfed: 60          .
    .byte <(sub_cb392 - 1)                                            ; bfee: 91          .
    .byte <(sub_cb399 - 1)                                            ; bfef: 98          .
; $bff0 referenced 1 time by $a4e0
lbff0
    .byte <(sub_caf8c - 1)                                            ; bff0: 8b          .
    .byte >(sub_cb392 - 1)                                            ; bff1: b3          .
    .byte >(sub_cb399 - 1)                                            ; bff2: b3          .
    .byte >(sub_caf8c - 1)                                            ; bff3: af          .

; $bff4 referenced 1 time by $bfe5
cbff4
    sec                                                               ; bff4: 38          8
    lda #0                                                            ; bff5: a9 00       ..
    sbc basic_multiply_result+2                                       ; bff7: e5 28       .(
    tay                                                               ; bff9: a8          .
    jsr sub_ca259                                                     ; bffa: 20 59 a2     y.
    jmp le1c7                                                         ; bffd: 4c c7 e1    lG.

pydis_end

.cerror (<(basic_command_close - 1)) != $eb, "Assertion failed: <(basic_command_close - 1) == $eb"
.cerror (<(basic_command_clr - 1)) != $ff, "Assertion failed: <(basic_command_clr - 1) == $ff"
.cerror (<(basic_command_cmd - 1)) != $e9, "Assertion failed: <(basic_command_cmd - 1) == $e9"
.cerror (<(basic_command_cont - 1)) != $e8, "Assertion failed: <(basic_command_cont - 1) == $e8"
.cerror (<(basic_command_data - 1)) != $df, "Assertion failed: <(basic_command_data - 1) == $df"
.cerror (<(basic_command_def - 1)) != $e6, "Assertion failed: <(basic_command_def - 1) == $e6"
.cerror (<(basic_command_dim - 1)) != $b7, "Assertion failed: <(basic_command_dim - 1) == $b7"
.cerror (<(basic_command_end - 1)) != $c5, "Assertion failed: <(basic_command_end - 1) == $c5"
.cerror (<(basic_command_for - 1)) != $dd, "Assertion failed: <(basic_command_for - 1) == $dd"
.cerror (<(basic_command_get - 1)) != $ec, "Assertion failed: <(basic_command_get - 1) == $ec"
.cerror (<(basic_command_gosub - 1)) != $e3, "Assertion failed: <(basic_command_gosub - 1) == $e3"
.cerror (<(basic_command_goto - 1)) != $a5, "Assertion failed: <(basic_command_goto - 1) == $a5"
.cerror (<(basic_command_if - 1)) != $a6, "Assertion failed: <(basic_command_if - 1) == $a6"
.cerror (<(basic_command_input - 1)) != $e1, "Assertion failed: <(basic_command_input - 1) == $e1"
.cerror (<(basic_command_input_hash - 1)) != $e0, "Assertion failed: <(basic_command_input_hash - 1) == $e0"
.cerror (<(basic_command_let - 1)) != $f2, "Assertion failed: <(basic_command_let - 1) == $f2"
.cerror (<(basic_command_list - 1)) != $cb, "Assertion failed: <(basic_command_list - 1) == $cb"
.cerror (<(basic_command_load - 1)) != $9d, "Assertion failed: <(basic_command_load - 1) == $9d"
.cerror (<(basic_command_new - 1)) != $08, "Assertion failed: <(basic_command_new - 1) == $08"
.cerror (<(basic_command_next - 1)) != $de, "Assertion failed: <(basic_command_next - 1) == $de"
.cerror (<(basic_command_on - 1)) != $e5, "Assertion failed: <(basic_command_on - 1) == $e5"
.cerror (<(basic_command_open - 1)) != $ea, "Assertion failed: <(basic_command_open - 1) == $ea"
.cerror (<(basic_command_poke - 1)) != $ff, "Assertion failed: <(basic_command_poke - 1) == $ff"
.cerror (<(basic_command_print - 1)) != $7e, "Assertion failed: <(basic_command_print - 1) == $7e"
.cerror (<(basic_command_print_hash - 1)) != $e7, "Assertion failed: <(basic_command_print_hash - 1) == $e7"
.cerror (<(basic_command_read - 1)) != $e2, "Assertion failed: <(basic_command_read - 1) == $e2"
.cerror (<(basic_command_rem - 1)) != $a0, "Assertion failed: <(basic_command_rem - 1) == $a0"
.cerror (<(basic_command_restore - 1)) != $19, "Assertion failed: <(basic_command_restore - 1) == $19"
.cerror (<(basic_command_return - 1)) != $e4, "Assertion failed: <(basic_command_return - 1) == $e4"
.cerror (<(basic_command_run - 1)) != $95, "Assertion failed: <(basic_command_run - 1) == $95"
.cerror (<(basic_command_save - 1)) != $bd, "Assertion failed: <(basic_command_save - 1) == $bd"
.cerror (<(basic_command_stop - 1)) != $ab, "Assertion failed: <(basic_command_stop - 1) == $ab"
.cerror (<(basic_command_sys - 1)) != $ba, "Assertion failed: <(basic_command_sys - 1) == $ba"
.cerror (<(basic_command_verify - 1)) != $9a, "Assertion failed: <(basic_command_verify - 1) == $9a"
.cerror (<(basic_command_wait - 1)) != $59, "Assertion failed: <(basic_command_wait - 1) == $59"
.cerror (<(ca6cf - 1)) != $ce, "Assertion failed: <(ca6cf - 1) == $ce"
.cerror (<(sub_caf8c - 1)) != $8b, "Assertion failed: <(sub_caf8c - 1) == $8b"
.cerror (<(sub_cb392 - 1)) != $91, "Assertion failed: <(sub_cb392 - 1) == $91"
.cerror (<(sub_cb399 - 1)) != $98, "Assertion failed: <(sub_cb399 - 1) == $98"
.cerror (<(sub_cbdee - 1)) != $ed, "Assertion failed: <(sub_cbdee - 1) == $ed"
.cerror (<(sub_cbdef - 1)) != $ee, "Assertion failed: <(sub_cbdef - 1) == $ee"
.cerror (>(basic_command_close - 1)) != $bd, "Assertion failed: >(basic_command_close - 1) == $bd"
.cerror (>(basic_command_clr - 1)) != $b9, "Assertion failed: >(basic_command_clr - 1) == $b9"
.cerror (>(basic_command_cmd - 1)) != $bd, "Assertion failed: >(basic_command_cmd - 1) == $bd"
.cerror (>(basic_command_cont - 1)) != $bd, "Assertion failed: >(basic_command_cont - 1) == $bd"
.cerror (>(basic_command_data - 1)) != $bd, "Assertion failed: >(basic_command_data - 1) == $bd"
.cerror (>(basic_command_def - 1)) != $bd, "Assertion failed: >(basic_command_def - 1) == $bd"
.cerror (>(basic_command_dim - 1)) != $ae, "Assertion failed: >(basic_command_dim - 1) == $ae"
.cerror (>(basic_command_end - 1)) != $a2, "Assertion failed: >(basic_command_end - 1) == $a2"
.cerror (>(basic_command_for - 1)) != $bd, "Assertion failed: >(basic_command_for - 1) == $bd"
.cerror (>(basic_command_get - 1)) != $bd, "Assertion failed: >(basic_command_get - 1) == $bd"
.cerror (>(basic_command_gosub - 1)) != $bd, "Assertion failed: >(basic_command_gosub - 1) == $bd"
.cerror (>(basic_command_goto - 1)) != $b4, "Assertion failed: >(basic_command_goto - 1) == $b4"
.cerror (>(basic_command_if - 1)) != $bb, "Assertion failed: >(basic_command_if - 1) == $bb"
.cerror (>(basic_command_input - 1)) != $bd, "Assertion failed: >(basic_command_input - 1) == $bd"
.cerror (>(basic_command_input_hash - 1)) != $bd, "Assertion failed: >(basic_command_input_hash - 1) == $bd"
.cerror (>(basic_command_let - 1)) != $bd, "Assertion failed: >(basic_command_let - 1) == $bd"
.cerror (>(basic_command_list - 1)) != $e3, "Assertion failed: >(basic_command_list - 1) == $e3"
.cerror (>(basic_command_load - 1)) != $ba, "Assertion failed: >(basic_command_load - 1) == $ba"
.cerror (>(basic_command_new - 1)) != $bb, "Assertion failed: >(basic_command_new - 1) == $bb"
.cerror (>(basic_command_next - 1)) != $bd, "Assertion failed: >(basic_command_next - 1) == $bd"
.cerror (>(basic_command_on - 1)) != $bd, "Assertion failed: >(basic_command_on - 1) == $bd"
.cerror (>(basic_command_open - 1)) != $bd, "Assertion failed: >(basic_command_open - 1) == $bd"
.cerror (>(basic_command_poke - 1)) != $df, "Assertion failed: >(basic_command_poke - 1) == $df"
.cerror (>(basic_command_print - 1)) != $bf, "Assertion failed: >(basic_command_print - 1) == $bf"
.cerror (>(basic_command_print_hash - 1)) != $bd, "Assertion failed: >(basic_command_print_hash - 1) == $bd"
.cerror (>(basic_command_read - 1)) != $bd, "Assertion failed: >(basic_command_read - 1) == $bd"
.cerror (>(basic_command_rem - 1)) != $ad, "Assertion failed: >(basic_command_rem - 1) == $ad"
.cerror (>(basic_command_restore - 1)) != $ba, "Assertion failed: >(basic_command_restore - 1) == $ba"
.cerror (>(basic_command_return - 1)) != $bd, "Assertion failed: >(basic_command_return - 1) == $bd"
.cerror (>(basic_command_run - 1)) != $b4, "Assertion failed: >(basic_command_run - 1) == $b4"
.cerror (>(basic_command_save - 1)) != $e2, "Assertion failed: >(basic_command_save - 1) == $e2"
.cerror (>(basic_command_stop - 1)) != $a2, "Assertion failed: >(basic_command_stop - 1) == $a2"
.cerror (>(basic_command_sys - 1)) != $b5, "Assertion failed: >(basic_command_sys - 1) == $b5"
.cerror (>(basic_command_verify - 1)) != $ba, "Assertion failed: >(basic_command_verify - 1) == $ba"
.cerror (>(basic_command_wait - 1)) != $a6, "Assertion failed: >(basic_command_wait - 1) == $a6"
.cerror (>(ca6cf - 1)) != $a6, "Assertion failed: >(ca6cf - 1) == $a6"
.cerror (>(sub_caf8c - 1)) != $af, "Assertion failed: >(sub_caf8c - 1) == $af"
.cerror (>(sub_cb392 - 1)) != $b3, "Assertion failed: >(sub_cb392 - 1) == $b3"
.cerror (>(sub_cb399 - 1)) != $b3, "Assertion failed: >(sub_cb399 - 1) == $b3"
.cerror (>(sub_cbdee - 1)) != $bd, "Assertion failed: >(sub_cbdee - 1) == $bd"
.cerror (>(sub_cbdef - 1)) != $bd, "Assertion failed: >(sub_cbdef - 1) == $bd"
.cerror (basic_cold_start) != $e394, "Assertion failed: basic_cold_start == $e394"
.cerror (basic_warm_start) != $e3b7, "Assertion failed: basic_warm_start == $e3b7"

; Label references by decreasing frequency:
;     basic_index1:                 33
;     basic_index2:                 32
;     fac1_exponent:                27
;     fac1_mantissa:                26
;     basic_input_buffer:           23
;     basic_text_ptr:               23
;     ca6cf:                        23
;     basic_variable_ptr:           21
;     basic_arrays_end:             20
;     basic_string_temp_ptr:        19
;     basic_line_number:            17
;     basic_search_char:            17
;     basic_statement_ptr:          17
;     basic_strings_bottom:         17
;     l0106:                        17
;     sub_ca14f:                    16
;     caf7f:                        14
;     sub_ca71b:                    14
;     basic_string_descriptor_ptr:  12
;     l0105:                        12
;     basic_variable_name:          11
;     l0104:                        11
;     basic_value_type:             10
;     ca6b2:                        10
;     l0100:                        10
;     le195:                        10
;     ca9ad:                         9
;     basic_garbage_step:            8
;     basic_program_start:           8
;     chrout:                        8
;     basic_arrays_start:            7
;     basic_garbage_flag:            7
;     sub_cb9c1:                     7
;     basic_dim_flag:                6
;     basic_multiply_result:         6
;     basic_variables_start:         6
;     cac03:                         6
;     quote_mode_flag:               6
;     sub_cadae:                     6
;     basic_end_char:                5
;     ca420:                         5
;     chrin:                         5
;     clall:                         5
;     l0101:                         5
;     la6ca:                         5
;     le089:                         5
;     lf7c1:                         5
;     sub_cb959:                     5
;     sub_cba2e:                     5
;     basic_current_line:            4
;     basic_input_buffer_index:      4
;     basic_load_verify_flag:        4
;     ca6c4:                         4
;     cac01:                         4
;     cae3a:                         4
;     cbef4:                         4
;     cpu_port_direction:            4
;     setlfs:                        4
;     sub_ca167:                     4
;     sub_cb901:                     4
;     sub_cbdd3:                     4
;     basic_operator_ptr:            3
;     ca480:                         3
;     ca493:                         3
;     ca4e9:                         3
;     ca505:                         3
;     ca6b8:                         3
;     ca9a7:                         3
;     cabb3:                         3
;     cabd1:                         3
;     cb657:                         3
;     cb66c:                         3
;     cb969:                         3
;     cbab3:                         3
;     cbb79:                         3
;     cbd7b:                         3
;     device_number:                 3
;     fac1_sign:                     3
;     fac2_mantissa:                 3
;     filename_length:               3
;     l0102:                         3
;     l0103:                         3
;     la69b:                         3
;     la6c3:                         3
;     la6cc:                         3
;     lb85c:                         3
;     le060:                         3
;     le214:                         3
;     le265:                         3
;     le4cd:                         3
;     open:                          3
;     return_13:                     3
;     return_14:                     3
;     setmsg:                        3
;     setnam:                        3
;     sub_ca1df:                     3
;     sub_ca290:                     3
;     sub_ca746:                     3
;     sub_cb40e:                     3
;     sub_cb795:                     3
;     sub_cba7f:                     3
;     sub_cbc12:                     3
;     sub_cbc45:                     3
;     sub_cbcf7:                     3
;     usr_jmp:                       3
;     basic_command_clr:             2
;     basic_command_goto:            2
;     basic_memory_top:              2
;     ca15b:                         2
;     ca18b:                         2
;     ca199:                         2
;     ca3e1:                         2
;     ca422:                         2
;     ca49a:                         2
;     ca5ad:                         2
;     ca6aa:                         2
;     ca6cb:                         2
;     ca6ee:                         2
;     ca7de:                         2
;     ca92c:                         2
;     ca969:                         2
;     cab6f:                         2
;     cabae:                         2
;     cabc3:                         2
;     cabdc:                         2
;     cac11:                         2
;     cac13:                         2
;     cacb0:                         2
;     cacd0:                         2
;     cacf6:                         2
;     cad69:                         2
;     cad80:                         2
;     cae7c:                         2
;     cafb0:                         2
;     cafb5:                         2
;     cb3fd:                         2
;     cb425:                         2
;     cb4ce:                         2
;     cb507:                         2
;     cb5e7:                         2
;     cb63d:                         2
;     cb6c1:                         2
;     cb6da:                         2
;     cb7ab:                         2
;     cb92a:                         2
;     cb92d:                         2
;     cb9d1:                         2
;     cba84:                         2
;     cba86:                         2
;     cbcee:                         2
;     cbcff:                         2
;     cbec7:                         2
;     cbfb0:                         2
;     chkin:                         2
;     filename_ptr:                  2
;     io_status:                     2
;     l01ff:                         2
;     la34a:                         2
;     laabd:                         2
;     le188:                         2
;     le312:                         2
;     le339:                         2
;     le3ba:                         2
;     le3eb:                         2
;     le404:                         2
;     leb8c:                         2
;     readst:                        2
;     return_18:                     2
;     return_20:                     2
;     return_25:                     2
;     return_4:                      2
;     sub_ca185:                     2
;     sub_ca192:                     2
;     sub_ca225:                     2
;     sub_ca259:                     2
;     sub_ca3d6:                     2
;     sub_ca454:                     2
;     sub_ca533:                     2
;     sub_ca57d:                     2
;     sub_ca645:                     2
;     sub_ca8f4:                     2
;     sub_ca9b5:                     2
;     sub_cacb6:                     2
;     sub_caead:                     2
;     sub_cb1c0:                     2
;     sub_cb1c8:                     2
;     sub_cb938:                     2
;     sub_cb948:                     2
;     sub_cb953:                     2
;     sub_cb9eb:                     2
;     sub_cbb65:                     2
;     sub_cbbff:                     2
;     sub_cbc1e:                     2
;     sub_cbccd:                     2
;     sub_cbf66:                     2
;     usr_address:                   2
;     basic_command_end:             1
;     basic_command_let:             1
;     basic_command_rem:             1
;     basic_command_stop:            1
;     basic_data_ptr:                1
;     basic_error_vector:            1
;     basic_float_to_int_vector:     1
;     basic_int_to_float_vector:     1
;     basic_previous_line:           1
;     basic_temp_string_index:       1
;     basic_warm_start:              1
;     ca19b:                         1
;     ca1ab:                         1
;     ca1f2:                         1
;     ca1f6:                         1
;     ca203:                         1
;     ca20a:                         1
;     ca232:                         1
;     ca239:                         1
;     ca266:                         1
;     ca271:                         1
;     ca2a3:                         1
;     ca2a6:                         1
;     ca2a9:                         1
;     ca315:                         1
;     ca3db:                         1
;     ca3ed:                         1
;     ca3fa:                         1
;     ca409:                         1
;     ca427:                         1
;     ca435:                         1
;     ca439:                         1
;     ca44b:                         1
;     ca44f:                         1
;     ca4b7:                         1
;     ca4be:                         1
;     ca4c5:                         1
;     ca4ce:                         1
;     ca4d8:                         1
;     ca4df:                         1
;     ca4f1:                         1
;     ca50d:                         1
;     ca51f:                         1
;     ca526:                         1
;     ca52d:                         1
;     ca536:                         1
;     ca540:                         1
;     ca54f:                         1
;     ca58e:                         1
;     ca595:                         1
;     ca59d:                         1
;     ca5a5:                         1
;     ca5c1:                         1
;     ca5c6:                         1
;     ca5cd:                         1
;     ca5d5:                         1
;     ca5e9:                         1
;     ca5ea:                         1
;     ca605:                         1
;     ca615:                         1
;     ca620:                         1
;     ca62b:                         1
;     ca64f:                         1
;     ca662:                         1
;     ca670:                         1
;     ca678:                         1
;     ca6b0:                         1
;     ca6b4:                         1
;     ca6bc:                         1
;     ca6c7:                         1
;     ca6c9:                         1
;     ca6d1:                         1
;     ca714:                         1
;     ca738:                         1
;     ca757:                         1
;     ca76b:                         1
;     ca77d:                         1
;     ca78d:                         1
;     ca791:                         1
;     ca79b:                         1
;     ca7a8:                         1
;     ca885:                         1
;     ca8a6:                         1
;     ca8ad:                         1
;     ca8c0:                         1
;     ca8d5:                         1
;     ca8df:                         1
;     ca8ee:                         1
;     ca901:                         1
;     ca90b:                         1
;     ca914:                         1
;     ca921:                         1
;     ca927:                         1
;     ca929:                         1
;     ca93d:                         1
;     ca940:                         1
;     ca945:                         1
;     ca967:                         1
;     ca979:                         1
;     ca989:                         1
;     ca98d:                         1
;     cab34:                         1
;     cab77:                         1
;     cab86:                         1
;     cabb1:                         1
;     cabd5:                         1
;     cabe1:                         1
;     cabfd:                         1
;     cac23:                         1
;     cac2a:                         1
;     cac49:                         1
;     cac5c:                         1
;     cac63:                         1
;     cac94:                         1
;     caca4:                         1
;     cacad:                         1
;     cad03:                         1
;     cad19:                         1
;     cad35:                         1
;     cad83:                         1
;     cadb1:                         1
;     cadb9:                         1
;     cadcb:                         1
;     cadd2:                         1
;     cadd9:                         1
;     cadeb:                         1
;     cadee:                         1
;     cadf1:                         1
;     cadf6:                         1
;     cae03:                         1
;     cae0d:                         1
;     cae10:                         1
;     cae16:                         1
;     cae37:                         1
;     cae55:                         1
;     cae5b:                         1
;     cae5f:                         1
;     cae6a:                         1
;     cae80:                         1
;     cae84:                         1
;     caec0:                         1
;     caec8:                         1
;     caedf:                         1
;     caeeb:                         1
;     caef0:                         1
;     caefa:                         1
;     caf5f:                         1
;     caf6b:                         1
;     caf76:                         1
;     cafa3:                         1
;     cafc9:                         1
;     cafde:                         1
;     caff1:                         1
;     cb006:                         1
;     cb01f:                         1
;     cb026:                         1
;     cb039:                         1
;     cb045:                         1
;     cb063:                         1
;     cb06c:                         1
;     cb1bd:                         1
;     cb39e:                         1
;     cb3e5:                         1
;     cb403:                         1
;     cb405:                         1
;     cb41b:                         1
;     cb43e:                         1
;     cb48c:                         1
;     cb4b9:                         1
;     cb4c1:                         1
;     cb4c6:                         1
;     cb4c9:                         1
;     cb4d5:                         1
;     cb516:                         1
;     cb580:                         1
;     cb590:                         1
;     cb599:                         1
;     cb5ad:                         1
;     cb5c3:                         1
;     cb5d3:                         1
;     cb5dd:                         1
;     cb60d:                         1
;     cb620:                         1
;     cb624:                         1
;     cb688:                         1
;     cb6ad:                         1
;     cb6d2:                         1
;     cb6e0:                         1
;     cb7b3:                         1
;     cb7f8:                         1
;     cb802:                         1
;     cb80b:                         1
;     cb813:                         1
;     cb81d:                         1
;     cb83b:                         1
;     cb96e:                         1
;     cb97f:                         1
;     cb994:                         1
;     cb99b:                         1
;     cb9a1:                         1
;     cba3d:                         1
;     cba79:                         1
;     cba7d:                         1
;     cba87:                         1
;     cbac1:                         1
;     cbacc:                         1
;     cbadd:                         1
;     cbb67:                         1
;     cbb87:                         1
;     cbb91:                         1
;     cbba0:                         1
;     cbbb1:                         1
;     cbbbb:                         1
;     cbbc2:                         1
;     cbc28:                         1
;     cbc6f:                         1
;     cbc74:                         1
;     cbc96:                         1
;     cbc97:                         1
;     cbc98:                         1
;     cbcbe:                         1
;     cbcdf:                         1
;     cbcf4:                         1
;     cbd01:                         1
;     cbd09:                         1
;     cbd23:                         1
;     cbd30:                         1
;     cbd57:                         1
;     cbdfb:                         1
;     cbe22:                         1
;     cbe2d:                         1
;     cbe35:                         1
;     cbe3d:                         1
;     cbe3f:                         1
;     cbe65:                         1
;     cbe77:                         1
;     cbe83:                         1
;     cbe89:                         1
;     cbe94:                         1
;     cbe97:                         1
;     cbe9e:                         1
;     cbea1:                         1
;     cbea8:                         1
;     cbeb9:                         1
;     cbed5:                         1
;     cbee3:                         1
;     cbf02:                         1
;     cbf05:                         1
;     cbf8b:                         1
;     cbf9e:                         1
;     cbfa1:                         1
;     cbff4:                         1
;     fac1_rounding:                 1
;     fac2_exponent:                 1
;     l99a9:                         1
;     la175:                         1
;     la181:                         1
;     la359:                         1
;     la368:                         1
;     la6c1:                         1
;     la6c8:                         1
;     lb607:                         1
;     lb6d5:                         1
;     lbd26:                         1
;     lbfed:                         1
;     lbff0:                         1
;     ld030:                         1
;     ld07a:                         1
;     ld07b:                         1
;     le023:                         1
;     le02f:                         1
;     le044:                         1
;     le080:                         1
;     le0ab:                         1
;     le107:                         1
;     le132:                         1
;     le146:                         1
;     le163:                         1
;     le19e:                         1
;     le1b0:                         1
;     le1c7:                         1
;     le1e1:                         1
;     le217:                         1
;     le28b:                         1
;     le28e:                         1
;     le2b5:                         1
;     le34d:                         1
;     le366:                         1
;     le376:                         1
;     le38c:                         1
;     le3a9:                         1
;     le422:                         1
;     le457:                         1
;     le480:                         1
;     lf7c6:                         1
;     load:                          1
;     loop_ca542:                    1
;     loop_ca5b5:                    1
;     loop_ca685:                    1
;     loop_ca763:                    1
;     loop_ca7ce:                    1
;     loop_ca90d:                    1
;     loop_ca931:                    1
;     loop_ca9b7:                    1
;     loop_cab10:                    1
;     loop_cab26:                    1
;     loop_cac31:                    1
;     loop_cac3a:                    1
;     loop_cac8a:                    1
;     loop_cae25:                    1
;     loop_cae52:                    1
;     loop_caee1:                    1
;     loop_caf14:                    1
;     loop_caf61:                    1
;     loop_cafd8:                    1
;     loop_caff3:                    1
;     loop_caffd:                    1
;     loop_cb3a5:                    1
;     loop_cb3b0:                    1
;     loop_cb3ef:                    1
;     loop_cb41d:                    1
;     loop_cb427:                    1
;     loop_cb493:                    1
;     loop_cb5c5:                    1
;     loop_cb81e:                    1
;     loop_cbb8c:                    1
;     loop_cbbde:                    1
;     loop_cbbe5:                    1
;     loop_cbcda:                    1
;     loop_cbd0e:                    1
;     loop_cbe0a:                    1
;     loop_cbe56:                    1
;     loop_cbf8e:                    1
;     rdtim:                         1
;     return_1:                      1
;     return_10:                     1
;     return_11:                     1
;     return_12:                     1
;     return_15:                     1
;     return_16:                     1
;     return_17:                     1
;     return_19:                     1
;     return_2:                      1
;     return_21:                     1
;     return_22:                     1
;     return_23:                     1
;     return_24:                     1
;     return_3:                      1
;     return_5:                      1
;     return_6:                      1
;     return_7:                      1
;     return_8:                      1
;     return_9:                      1
;     secondary_address:             1
;     settim:                        1
;     stop_key_flag:                 1
;     sub_ca1e4:                     1
;     sub_ca2f0:                     1
;     sub_ca40c:                     1
;     sub_ca48b:                     1
;     sub_ca588:                     1
;     sub_ca729:                     1
;     sub_ca7b1:                     1
;     sub_ca7e5:                     1
;     sub_cab1e:                     1
;     sub_cab54:                     1
;     sub_cabf2:                     1
;     sub_caf9b:                     1
;     sub_cafd4:                     1
;     sub_cb1b1:                     1
;     sub_cb3d7:                     1
;     sub_cb4d3:                     1
;     sub_cb56b:                     1
;     sub_cb662:                     1
;     sub_cb95f:                     1
;     sub_cb965:                     1
;     sub_cba91:                     1
;     sub_cbbda:                     1
;     sub_cbc65:                     1
;     sub_cbc9c:                     1
;     sub_cbfc4:                     1
;     sys_a:                         1
;     sys_p:                         1
;     sys_x:                         1
;     sys_y:                         1
;     tape_timing_constant:          1

; Automatically generated labels:
;     ca15b
;     ca18b
;     ca199
;     ca19b
;     ca1ab
;     ca1f2
;     ca1f6
;     ca203
;     ca20a
;     ca232
;     ca239
;     ca266
;     ca271
;     ca2a3
;     ca2a6
;     ca2a9
;     ca315
;     ca3db
;     ca3e1
;     ca3ed
;     ca3fa
;     ca409
;     ca420
;     ca422
;     ca427
;     ca435
;     ca439
;     ca44b
;     ca44f
;     ca480
;     ca493
;     ca49a
;     ca4b7
;     ca4be
;     ca4c5
;     ca4ce
;     ca4d8
;     ca4df
;     ca4e9
;     ca4f1
;     ca505
;     ca50d
;     ca51f
;     ca526
;     ca52d
;     ca536
;     ca540
;     ca54f
;     ca58e
;     ca595
;     ca59d
;     ca5a5
;     ca5ad
;     ca5c1
;     ca5c6
;     ca5cd
;     ca5d5
;     ca5e9
;     ca5ea
;     ca605
;     ca615
;     ca620
;     ca62b
;     ca64f
;     ca662
;     ca670
;     ca678
;     ca6aa
;     ca6b0
;     ca6b2
;     ca6b4
;     ca6b8
;     ca6bc
;     ca6c0
;     ca6c2
;     ca6c4
;     ca6c7
;     ca6c9
;     ca6cb
;     ca6cf
;     ca6d1
;     ca6ee
;     ca714
;     ca738
;     ca757
;     ca76b
;     ca77d
;     ca78d
;     ca791
;     ca79b
;     ca7a8
;     ca7de
;     ca885
;     ca8a6
;     ca8ad
;     ca8c0
;     ca8d5
;     ca8df
;     ca8ee
;     ca901
;     ca90b
;     ca914
;     ca921
;     ca927
;     ca929
;     ca92c
;     ca93d
;     ca940
;     ca945
;     ca967
;     ca969
;     ca979
;     ca989
;     ca98d
;     ca9a7
;     ca9ad
;     cab34
;     cab6f
;     cab77
;     cab86
;     cabae
;     cabb1
;     cabb3
;     cabc3
;     cabd1
;     cabd5
;     cabdc
;     cabe1
;     cabfd
;     cac01
;     cac03
;     cac11
;     cac13
;     cac23
;     cac2a
;     cac49
;     cac5c
;     cac63
;     cac94
;     caca4
;     cacad
;     cacb0
;     cacd0
;     cacf6
;     cad03
;     cad19
;     cad35
;     cad69
;     cad80
;     cad83
;     cadb1
;     cadb9
;     cadcb
;     cadd2
;     cadd9
;     cadeb
;     cadee
;     cadf1
;     cadf6
;     cae03
;     cae0d
;     cae10
;     cae16
;     cae37
;     cae3a
;     cae55
;     cae5b
;     cae5f
;     cae6a
;     cae7c
;     cae80
;     cae84
;     caec0
;     caec8
;     caedf
;     caeeb
;     caef0
;     caefa
;     caf5f
;     caf6b
;     caf76
;     caf7f
;     cafa3
;     cafb0
;     cafb5
;     cafc9
;     cafde
;     caff1
;     cb006
;     cb01f
;     cb026
;     cb039
;     cb045
;     cb063
;     cb06c
;     cb1bd
;     cb39e
;     cb3e5
;     cb3fd
;     cb403
;     cb405
;     cb41b
;     cb425
;     cb43e
;     cb48c
;     cb4b9
;     cb4c1
;     cb4c6
;     cb4c9
;     cb4ce
;     cb4d5
;     cb507
;     cb516
;     cb580
;     cb590
;     cb599
;     cb5ad
;     cb5c3
;     cb5d3
;     cb5dd
;     cb5e7
;     cb60d
;     cb620
;     cb624
;     cb63d
;     cb657
;     cb66c
;     cb688
;     cb6ad
;     cb6c1
;     cb6d2
;     cb6d4
;     cb6da
;     cb6e0
;     cb7ab
;     cb7b3
;     cb7f8
;     cb802
;     cb80b
;     cb813
;     cb81d
;     cb83b
;     cb92a
;     cb92d
;     cb969
;     cb96e
;     cb97f
;     cb994
;     cb99b
;     cb9a1
;     cb9d1
;     cba3d
;     cba79
;     cba7d
;     cba84
;     cba86
;     cba87
;     cbab3
;     cbac1
;     cbacc
;     cbadd
;     cbb67
;     cbb79
;     cbb87
;     cbb91
;     cbba0
;     cbbb1
;     cbbbb
;     cbbc2
;     cbc28
;     cbc6f
;     cbc74
;     cbc96
;     cbc97
;     cbc98
;     cbcbe
;     cbcdf
;     cbcee
;     cbcf4
;     cbcff
;     cbd01
;     cbd09
;     cbd23
;     cbd25
;     cbd30
;     cbd57
;     cbd7b
;     cbdfb
;     cbe22
;     cbe2d
;     cbe35
;     cbe3d
;     cbe3f
;     cbe65
;     cbe77
;     cbe83
;     cbe89
;     cbe94
;     cbe97
;     cbe9e
;     cbea1
;     cbea8
;     cbeb9
;     cbec7
;     cbed5
;     cbee3
;     cbef4
;     cbf02
;     cbf05
;     cbf8b
;     cbf9e
;     cbfa1
;     cbfb0
;     cbff4
;     l0100
;     l0101
;     l0102
;     l0103
;     l0104
;     l0105
;     l0106
;     l01ff
;     l0ea0
;     l99a9
;     la175
;     la181
;     la34a
;     la359
;     la368
;     la69b
;     la6c1
;     la6c3
;     la6c8
;     la6ca
;     la6cc
;     laabd
;     lb607
;     lb6d5
;     lb85c
;     lbd26
;     lbfed
;     lbff0
;     ld030
;     ld07a
;     ld07b
;     le023
;     le02f
;     le044
;     le060
;     le080
;     le089
;     le0ab
;     le107
;     le132
;     le146
;     le163
;     le188
;     le195
;     le19e
;     le1b0
;     le1c7
;     le1e1
;     le214
;     le217
;     le265
;     le28b
;     le28e
;     le2b5
;     le312
;     le339
;     le34d
;     le366
;     le376
;     le38c
;     le3a9
;     le3ba
;     le3eb
;     le404
;     le422
;     le457
;     le480
;     le4cd
;     leb8c
;     lf7c1
;     lf7c6
;     lffa9
;     loop_ca542
;     loop_ca5b5
;     loop_ca685
;     loop_ca763
;     loop_ca7ce
;     loop_ca90d
;     loop_ca931
;     loop_ca9b7
;     loop_cab10
;     loop_cab26
;     loop_cac31
;     loop_cac3a
;     loop_cac8a
;     loop_cae25
;     loop_cae52
;     loop_caee1
;     loop_caf14
;     loop_caf61
;     loop_cafd8
;     loop_caff3
;     loop_caffd
;     loop_cb3a5
;     loop_cb3b0
;     loop_cb3ef
;     loop_cb41d
;     loop_cb427
;     loop_cb493
;     loop_cb5c5
;     loop_cb81e
;     loop_cbb8c
;     loop_cbbde
;     loop_cbbe5
;     loop_cbcda
;     loop_cbd0e
;     loop_cbe0a
;     loop_cbe56
;     loop_cbf8e
;     return_1
;     return_10
;     return_11
;     return_12
;     return_13
;     return_14
;     return_15
;     return_16
;     return_17
;     return_18
;     return_19
;     return_2
;     return_20
;     return_21
;     return_22
;     return_23
;     return_24
;     return_25
;     return_3
;     return_4
;     return_5
;     return_6
;     return_7
;     return_8
;     return_9
;     sub_ca14f
;     sub_ca167
;     sub_ca185
;     sub_ca192
;     sub_ca1df
;     sub_ca1e4
;     sub_ca225
;     sub_ca259
;     sub_ca290
;     sub_ca2f0
;     sub_ca3d6
;     sub_ca40c
;     sub_ca454
;     sub_ca48b
;     sub_ca533
;     sub_ca57d
;     sub_ca588
;     sub_ca645
;     sub_ca71b
;     sub_ca729
;     sub_ca746
;     sub_ca7b1
;     sub_ca7e5
;     sub_ca8f4
;     sub_ca9b5
;     sub_cab1e
;     sub_cab54
;     sub_cabf2
;     sub_cacb6
;     sub_cadae
;     sub_caead
;     sub_caf8c
;     sub_caf9b
;     sub_cafd4
;     sub_cb1b1
;     sub_cb1c0
;     sub_cb1c8
;     sub_cb392
;     sub_cb399
;     sub_cb3d7
;     sub_cb40e
;     sub_cb4d3
;     sub_cb56b
;     sub_cb662
;     sub_cb795
;     sub_cb901
;     sub_cb938
;     sub_cb948
;     sub_cb953
;     sub_cb959
;     sub_cb95f
;     sub_cb965
;     sub_cb9c1
;     sub_cb9eb
;     sub_cba2e
;     sub_cba7f
;     sub_cba91
;     sub_cbb65
;     sub_cbbda
;     sub_cbbff
;     sub_cbc12
;     sub_cbc1e
;     sub_cbc45
;     sub_cbc65
;     sub_cbc9c
;     sub_cbccd
;     sub_cbcf7
;     sub_cbdd3
;     sub_cbdee
;     sub_cbdef
;     sub_cbf66
;     sub_cbfc4

; Stats:
;
;     Total size (Code + Data) = 8192 bytes
;     Code                     = 5092 bytes (62%)
;     Data                     = 3100 bytes (38%)
;
;     Number of instructions   = 2513
;     Number of data bytes     = 2977 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 119 bytes
;     Number of strings        = 16

