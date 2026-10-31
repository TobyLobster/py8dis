// Memory locations

// Zero page ($0000-$00ff)
usr_jmp                     = $0000
usr_address                 = $0001
basic_float_to_int_vector   = $0003
basic_int_to_float_vector   = $0005
ppilltimer                  = $0010
fruittimer                  = $0039
fruitflag                   = $003a
ppillflag                   = $003b
chomp                       = $003c
chewing                     = $003d
digit                       = $003e
points                      = $003f
olddir                      = $0040
newdir                      = $0041
joyval                      = $0042
qmandir                     = $0043
frame                       = $0044
lives                       = $0045
flashpill                   = $0046
extraqman                   = $0047
demoqman                    = $0048
fruitlevel                  = $0049
dots                        = $004a
penalty                     = $004b
basic_fn_ptr                = $004e
basic_string_descriptor_ptr = $0050
basic_garbage_step          = $0053
basic_function_jump         = $0054
basic_float_temp2           = $005c
monmove                     = $0061
fac1_mantissa               = $0062
fac2_exponent               = $0069
fleeingscore                = $0070
jiffy_clock                 = $00a0
colour_ram_line_ptr         = $00f3
rs232_input_buffer_ptr      = $00f7
rs232_output_buffer_ptr     = $00f9
free_zero_page              = $00fb
basic_float_to_ascii_temp   = $00ff

// OS workspace ($0200-$02ff)
basic_input_buffer  = $0200
screen_memory_page  = $0288
shift_key_flags     = $028d
sprite              = $02a1
spritex             = $02a2
spritey             = $02a3
l02a4               = $02a4
l02a5               = $02a5
spriteclr           = $02b2
l02b3               = $02b3
spriteimg1          = $02ba
spriteimg2          = $02c2
spritelast          = $02cc
l02cd               = $02cd
l02ce               = $02ce
saveback            = $02dd
l02de               = $02de

// Vectors ($0300-$0333)
irq_vector  = $0314

// Tape buffer ($0334-$03ff)
tape_buffer = $033c

// Character ROM ($8000-$8fff)
character_rom   = $8000

// VIC ($9000-$900f)
vic_vertical_position       = $9001
vic_columns                 = $9002
vic_rows                    = $9003
vic_memory_setup            = $9005
vic_voice2_frequency        = $900b
vic_voice3_frequency        = $900c
vic_volume_aux_colour       = $900e
vic_background_border_colour = $900f

// VIA 1 ($9110-$911f)
via1_port_a             = $9111
via1_data_direction_a   = $9113

// VIA 2 ($9120-$912f)
via2_port_b             = $9120
via2_data_direction_b   = $9122

// Colour RAM ($9600-$97ff)
colour_ram  = $9600

// BASIC ROM ($c000-$dfff)
lc377   = $c377

// Kernal ROM ($e000-$ff89)
kernal_irq_handler  = $eabf
kernal_reset        = $fd22

// Kernal entry points ($ff8a-$fff9)
chrout  = $ffd2
getin   = $ffe4

// The PRG file's header: the address to load it at
    * = $0fff
    .word $1001

    * = $1001

// 2008 SYS4109
pydis_start
basic_line_2008
    .word basic_end                                                   // 1001: 0b 10       ..
    .word 2008                                                        // 1003: d8 07       X.
    .byt $9e                                                          // 1005: 9e          .
    .byt $34, $31, $30, $39 // petscii "4109"                         // 1006: 34 31 30... 410
    .byt 0                                                            // 100a: 00          .
basic_end
    .word 0                                                           // 100b: 00 00       ..

sys_entry
    lda #8                                                            // 100d: a9 08       .. // A=character to output
    jsr chrout                                                        // 100f: 20 d2 ff     R. // Output $08 (disable case switching)
    lda vic_vertical_position                                         // 1012: ad 01 90    ...
    sbc #4                                                            // 1015: e9 04       ..
    sta vic_vertical_position                                         // 1017: 8d 01 90    ...
    lda #$95                                                          // 101a: a9 95       ..
    sta vic_columns                                                   // 101c: 8d 02 90    ...
    lda #$b0                                                          // 101f: a9 b0       ..
    sta vic_rows                                                      // 1021: 8d 03 90    ...
    ldx #$ff                                                          // 1024: a2 ff       ..
    stx vic_memory_setup                                              // 1026: 8e 05 90    ...
    jsr sub_c1577                                                     // 1029: 20 77 15     ..
    ldx #$16                                                          // 102c: a2 16       ..
// $102e referenced 1 time by $103a
loop_c102e
    lda l1be2,x                                                       // 102e: bd e2 1b    ...
    sta screen_memory+482,x                                           // 1031: 9d e2 1f    ...
    lda #3                                                            // 1034: a9 03       ..
    sta colour_ram+482,x                                              // 1036: 9d e2 97    ...
    dex                                                               // 1039: ca          J
    bne loop_c102e                                                    // 103a: d0 f2       P.
    sei                                                               // 103c: 78          .

    // Set the IRQ vector to irq_handler
    ldx #<irq_handler                                                 // 103d: a2 81       ..
    ldy #>irq_handler                                                 // 103f: a0 18       ..
    stx irq_vector                                                    // 1041: 8e 14 03    ...
    sty irq_vector+1                                                  // 1044: 8c 15 03    ...

    cli                                                               // 1047: 58          x
// $1048 referenced 1 time by $141b
c1048
    jsr sub_c1564                                                     // 1048: 20 64 15     ..
    ldy #0                                                            // 104b: a0 00       ..
    sty lives                                                         // 104d: 84 45       .e
    sty fruitlevel                                                    // 104f: 84 49       .i
    jsr sub_c1cae                                                     // 1051: 20 ae 1c     ..
    ldy #$0a                                                          // 1054: a0 0a       ..
    sty sprite                                                        // 1056: 8c a1 02    ...
// $1059 referenced 1 time by $10b2
c1059
    lda frame                                                         // 1059: a5 44       .d
    and #$7f                                                          // 105b: 29 7f       ).
    bne c1090                                                         // 105d: d0 31       P1
    ldx vic_background_border_colour                                  // 105f: ae 0f 90    ...
    inx                                                               // 1062: e8          .
    txa                                                               // 1063: 8a          .
    and #7                                                            // 1064: 29 07       ).
    tax                                                               // 1066: aa          .
    ora #8                                                            // 1067: 09 08       ..
    sta vic_background_border_colour                                  // 1069: 8d 0f 90    ...
    jsr sub_c15f9                                                     // 106c: 20 f9 15     ..
    lda jiffy_clock+1                                                 // 106f: a5 a1       ..
    and #$0f                                                          // 1071: 29 0f       ).
    bne c1077                                                         // 1073: d0 02       P.
    stx ppillflag                                                     // 1075: 86 3b       .;
// $1077 referenced 1 time by $1073
c1077
    tax                                                               // 1077: aa          .
    cpx #$0d                                                          // 1078: e0 0d       ..
    bcc c107e                                                         // 107a: 90 02       ..
    ldx #0                                                            // 107c: a2 00       ..
// $107e referenced 1 time by $107a
c107e
    lda l1c65,x                                                       // 107e: bd 65 1c    ...
    sta screen_memory+283                                             // 1081: 8d 1b 1f    ...
    lda l1c72,x                                                       // 1084: bd 72 1c    ...
    sta colour_ram+283                                                // 1087: 8d 1b 97    ...
    lda #$40 // '@'                                                   // 108a: a9 40       .@
    sta fruittimer                                                    // 108c: 85 39       .9
    sta fruitflag                                                     // 108e: 85 3a       .:
// $1090 referenced 1 time by $105d
c1090
    ldx jiffy_clock+2                                                 // 1090: a6 a2       ..
    inx                                                               // 1092: e8          .
    inx                                                               // 1093: e8          .
// $1094 referenced 1 time by $1096
loop_c1094
    cpx jiffy_clock+2                                                 // 1094: e4 a2       ..
    bne loop_c1094                                                    // 1096: d0 fc       P.
    lda sprite                                                        // 1098: ad a1 02    ...
    eor #$1e                                                          // 109b: 49 1e       i.
    sta sprite                                                        // 109d: 8d a1 02    ...
    jsr sub_c12a3                                                     // 10a0: 20 a3 12     ..
    jsr sub_c168d                                                     // 10a3: 20 8d 16     ..
    jsr getin                                                         // 10a6: 20 e4 ff     .. // Get a character from the input channel (from the keyboard, 0 if there's none)
    cmp #3                                                            // 10a9: c9 03       I. // A=character read
    bne c10b0                                                         // 10ab: d0 03       P.
    jmp kernal_reset                                                  // 10ad: 4c 22 fd    l". // The Kernal's reset handler

// $10b0 referenced 1 time by $10ab
c10b0
    cmp #$88                                                          // 10b0: c9 88       I.
    bne c1059                                                         // 10b2: d0 a5       P.
    jsr sub_c1564                                                     // 10b4: 20 64 15     ..
    lda #3                                                            // 10b7: a9 03       ..
    sta lives                                                         // 10b9: 85 45       .e
    ldy #$ff                                                          // 10bb: a0 ff       ..
    sty fruitlevel                                                    // 10bd: 84 49       .i
    jsr sub_c1cae                                                     // 10bf: 20 ae 1c     ..
    ldx #0                                                            // 10c2: a2 00       ..
    stx extraqman                                                     // 10c4: 86 47       .g
// $10c6 referenced 1 time by $10ce
loop_c10c6
    lda #$b0                                                          // 10c6: a9 b0       ..
    sta l1a06,x                                                       // 10c8: 9d 06 1a    ...
    inx                                                               // 10cb: e8          .
    cpx #6                                                            // 10cc: e0 06       ..
    bne loop_c10c6                                                    // 10ce: d0 f6       P.
// $10d0 referenced 1 time by $1278
c10d0
    jsr sub_c1577                                                     // 10d0: 20 77 15     ..
// $10d3 referenced 1 time by $140b
c10d3
    ldx #0                                                            // 10d3: a2 00       ..
    stx qmandir                                                       // 10d5: 86 43       .c
    stx joyval                                                        // 10d7: 86 42       .b
// $10d9 referenced 1 time by $10e2
loop_c10d9
    lda l1c92,x                                                       // 10d9: bd 92 1c    ...
    sta spritex,x                                                     // 10dc: 9d a2 02    ...
    inx                                                               // 10df: e8          .
    cpx #$0a                                                          // 10e0: e0 0a       ..
    bne loop_c10d9                                                    // 10e2: d0 f5       P.
    lda #$1d                                                          // 10e4: a9 1d       ..
    sta spriteimg2                                                    // 10e6: 8d c2 02    .B.
    lda #8                                                            // 10e9: a9 08       ..
    sta spriteimg1                                                    // 10eb: 8d ba 02    ...
    lda #$1f                                                          // 10ee: a9 1f       ..
    sta sprite                                                        // 10f0: 8d a1 02    ...
    lda #$40 // '@'                                                   // 10f3: a9 40       .@
    jsr sub_c19e8                                                     // 10f5: 20 e8 19     ..
    ldx #5                                                            // 10f8: a2 05       ..
// $10fa referenced 1 time by $110a
loop_c10fa
    lda lc377,x                                                       // 10fa: bd 77 c3    ..C
    and #$bf                                                          // 10fd: 29 bf       ).
    ora #$80                                                          // 10ff: 09 80       ..
    sta screen_memory+280,x                                           // 1101: 9d 18 1f    ...
    lda #7                                                            // 1104: a9 07       ..
    sta colour_ram+280,x                                              // 1106: 9d 18 97    ...
    dex                                                               // 1109: ca          J
    bne loop_c10fa                                                    // 110a: d0 ee       P.
    lda #$58 // 'x'                                                   // 110c: a9 58       .x
    sta spriteimg1                                                    // 110e: 8d ba 02    ...
    lda #$a0                                                          // 1111: a9 a0       ..
    jsr sub_c19e8                                                     // 1113: 20 e8 19     ..
    ldx #0                                                            // 1116: a2 00       ..
    lda #$20 // ' '                                                   // 1118: a9 20       .
// $111a referenced 1 time by $1120
loop_c111a
    sta screen_memory+281,x                                           // 111a: 9d 19 1f    ...
    inx                                                               // 111d: e8          .
    cpx #5                                                            // 111e: e0 05       ..
    bne loop_c111a                                                    // 1120: d0 f8       P.
    ldy #$39 // '9'                                                   // 1122: a0 39       .9
    ldx #0                                                            // 1124: a2 00       ..
// $1126 referenced 1 time by $112b
loop_c1126
    stx usr_jmp,y                                                     // 1126: 96 00       ..
    iny                                                               // 1128: c8          H
    cpy #$44 // 'd'                                                   // 1129: c0 44       .d
    bne loop_c1126                                                    // 112b: d0 f9       P.
// $112d referenced 3 times by $1130, $11ea, $12a0
c112d
    lda shift_key_flags                                               // 112d: ad 8d 02    ...
    bne c112d                                                         // 1130: d0 fb       P.
    lda screen_memory+283                                             // 1132: ad 1b 1f    ...
    cmp #$22 // '"'                                                   // 1135: c9 22       I"
    bcc c1141                                                         // 1137: 90 08       ..
    ldx fruitlevel                                                    // 1139: a6 49       .i
    lda l1c72,x                                                       // 113b: bd 72 1c    ...
    sta colour_ram+283                                                // 113e: 8d 1b 97    ...
// $1141 referenced 1 time by $1137
c1141
    lda #$0c                                                          // 1141: a9 0c       ..
    sec                                                               // 1143: 38          8
    sbc fruitlevel                                                    // 1144: e5 49       .i
    bcc c114c                                                         // 1146: 90 04       ..
    cmp #3                                                            // 1148: c9 03       I.
    bcs c114e                                                         // 114a: b0 02       ..
// $114c referenced 1 time by $1146
c114c
    lda #3                                                            // 114c: a9 03       ..
// $114e referenced 1 time by $114a
c114e
    jsr sub_c1cc8                                                     // 114e: 20 c8 1c     H.
    sta usr_jmp                                                       // 1151: 85 00       ..
    sta usr_address                                                   // 1153: 85 01       ..
    lda qmandir                                                       // 1155: a5 43       .c
    sta olddir                                                        // 1157: 85 40       .@
    ldx joyval                                                        // 1159: a6 42       .b
    sty via1_data_direction_a                                         // 115b: 8c 13 91    ...
    lda #$7f                                                          // 115e: a9 7f       ..
    sta via2_data_direction_b                                         // 1160: 8d 22 91    .".
    lda via2_port_b                                                   // 1163: ad 20 91    . .
    and #$80                                                          // 1166: 29 80       ).
    bne c116c                                                         // 1168: d0 02       P.
    ldx #0                                                            // 116a: a2 00       ..
// $116c referenced 1 time by $1168
c116c
    lda #$ff                                                          // 116c: a9 ff       ..
    sta via2_data_direction_b                                         // 116e: 8d 22 91    .".
    ldy via1_port_a                                                   // 1171: ac 11 91    ...
    tya                                                               // 1174: 98          .
    and #8                                                            // 1175: 29 08       ).
    bne c117b                                                         // 1177: d0 02       P.
    ldx #1                                                            // 1179: a2 01       ..
// $117b referenced 1 time by $1177
c117b
    tya                                                               // 117b: 98          .
    and #$10                                                          // 117c: 29 10       ).
    bne c1182                                                         // 117e: d0 02       P.
    ldx #2                                                            // 1180: a2 02       ..
// $1182 referenced 1 time by $117e
c1182
    tya                                                               // 1182: 98          .
    and #4                                                            // 1183: 29 04       ).
    bne c1189                                                         // 1185: d0 02       P.
    ldx #3                                                            // 1187: a2 03       ..
// $1189 referenced 1 time by $1185
c1189
    stx joyval                                                        // 1189: 86 42       .b
    txa                                                               // 118b: 8a          .
    sta newdir                                                        // 118c: 85 41       .a
    jsr sub_c161f                                                     // 118e: 20 1f 16     ..
    bcs c119a                                                         // 1191: b0 07       ..
    lda joyval                                                        // 1193: a5 42       .b
    sta qmandir                                                       // 1195: 85 43       .c
    clc                                                               // 1197: 18          .
    bcc c11a1                                                         // 1198: 90 07       .. // ALWAYS branch

// $119a referenced 1 time by $1191
c119a
    lda qmandir                                                       // 119a: a5 43       .c
    sta newdir                                                        // 119c: 85 41       .a
    jsr sub_c161f                                                     // 119e: 20 1f 16     ..
// $11a1 referenced 1 time by $1198
c11a1
    lda spritex                                                       // 11a1: ad a2 02    ...
    bne c11ab                                                         // 11a4: d0 05       P.
    lda #$9e                                                          // 11a6: a9 9e       ..
    sta spritex                                                       // 11a8: 8d a2 02    ...
// $11ab referenced 1 time by $11a4
c11ab
    cmp #$a0                                                          // 11ab: c9 a0       I.
    bne c11b4                                                         // 11ad: d0 05       P.
    lda #0                                                            // 11af: a9 00       ..
    sta spritex                                                       // 11b1: 8d a2 02    ...
// $11b4 referenced 1 time by $11ad
c11b4
    ldx #0                                                            // 11b4: a2 00       ..
    lda spritex                                                       // 11b6: ad a2 02    ...
    and #7                                                            // 11b9: 29 07       ).
    cmp #4                                                            // 11bb: c9 04       I.
    bne c11ca                                                         // 11bd: d0 0b       P.
    inx                                                               // 11bf: e8          .  // X=1
    lda qmandir                                                       // 11c0: a5 43       .c
    eor #2                                                            // 11c2: 49 02       i.
    tay                                                               // 11c4: a8          .
    beq c11dc                                                         // 11c5: f0 15       ..
    dey                                                               // 11c7: 88          .
    bne c11dc                                                         // 11c8: d0 12       P.
// $11ca referenced 1 time by $11bd
c11ca
    lda spritey                                                       // 11ca: ad a3 02    ...
    and #7                                                            // 11cd: 29 07       ).
    cmp #3                                                            // 11cf: c9 03       I.
    bne c11dc                                                         // 11d1: d0 09       P.
    inx                                                               // 11d3: e8          .
    ldy qmandir                                                       // 11d4: a4 43       .c
    cpy #1                                                            // 11d6: c0 01       ..
    beq c11dc                                                         // 11d8: f0 02       ..
    ldy #0                                                            // 11da: a0 00       ..
// $11dc referenced 4 times by $11c5, $11c8, $11d1, $11d8
c11dc
    cpx #0                                                            // 11dc: e0 00       ..
    bne c11e3                                                         // 11de: d0 03       P.
    jmp c127b                                                         // 11e0: 4c 7b 12    l..

// $11e3 referenced 1 time by $11de
c11e3
    lda saveback,y                                                    // 11e3: b9 dd 02    ...
    cmp #$20 // ' '                                                   // 11e6: c9 20       I
    bne c11ed                                                         // 11e8: d0 03       P.
    jmp c112d                                                         // 11ea: 4c 2d 11    l-.

// $11ed referenced 1 time by $11e8
c11ed
    tax                                                               // 11ed: aa          .
    lda #$20 // ' '                                                   // 11ee: a9 20       .
    sta saveback,y                                                    // 11f0: 99 dd 02    ...
    cpx #$1e                                                          // 11f3: e0 1e       ..
    bne c1201                                                         // 11f5: d0 0a       P.
    lda #1                                                            // 11f7: a9 01       ..
    sta points                                                        // 11f9: 85 3f       .?
    sta chewing                                                       // 11fb: 85 3d       .=
    lda #$0a                                                          // 11fd: a9 0a       ..
    sta digit                                                         // 11ff: 85 3e       .>
// $1201 referenced 1 time by $11f5
c1201
    cpx #$22 // '"'                                                   // 1201: e0 22       ."
    bcc c121c                                                         // 1203: 90 17       ..
    cpx #$2a // '*'                                                   // 1205: e0 2a       .*
    bcs c127b                                                         // 1207: b0 72       ..
    txa                                                               // 1209: 8a          .
    sec                                                               // 120a: 38          8
    sbc #$22 // '"'                                                   // 120b: e9 22       ."
    tax                                                               // 120d: aa          .
    lda l1bf8,x                                                       // 120e: bd f8 1b    ...
    sta points                                                        // 1211: 85 3f       .?
    lda #9                                                            // 1213: a9 09       ..
    sta digit                                                         // 1215: 85 3e       .>
    sta chomp                                                         // 1217: 85 3c       .<
    clc                                                               // 1219: 18          .
    bcc c127b                                                         // 121a: 90 5f       .. // ALWAYS branch

// $121c referenced 1 time by $1203
c121c
    cpx #$1f                                                          // 121c: e0 1f       ..
    bne c122c                                                         // 121e: d0 0c       P.
    lda #5                                                            // 1220: a9 05       ..
    sta points                                                        // 1222: 85 3f       .?
    lda #$0a                                                          // 1224: a9 0a       ..
    sta digit                                                         // 1226: 85 3e       .>
    sta ppillflag                                                     // 1228: 85 3b       .;
    beq c127b                                                         // 122a: f0 4f       .o
// $122c referenced 1 time by $121e
c122c
    inc dots                                                          // 122c: e6 4a       .j
    lda dots                                                          // 122e: a5 4a       .j
    cmp #$aa                                                          // 1230: c9 aa       I.
    bne c127b                                                         // 1232: d0 47       Pg
// $1234 referenced 1 time by $1280
c1234
    lda #8                                                            // 1234: a9 08       ..
    sta spriteimg1                                                    // 1236: 8d ba 02    ...
    lda #$80                                                          // 1239: a9 80       ..
    jsr sub_c19e8                                                     // 123b: 20 e8 19     ..
    sta frame                                                         // 123e: 85 44       .d
// $1240 referenced 1 time by $125e
loop_c1240
    dec frame                                                         // 1240: c6 44       Fd
    lda frame                                                         // 1242: a5 44       .d
    and #7                                                            // 1244: 29 07       ).
    tax                                                               // 1246: aa          .
    jsr sub_c15f9                                                     // 1247: 20 f9 15     ..
    txa                                                               // 124a: 8a          .
    and #$1f                                                          // 124b: 29 1f       ).
    bne c125a                                                         // 124d: d0 0b       P.
    lda sprite                                                        // 124f: ad a1 02    ...
    eor #$1e                                                          // 1252: 49 1e       i.
    sta sprite                                                        // 1254: 8d a1 02    ...
    jsr sub_c168d                                                     // 1257: 20 8d 16     ..
// $125a referenced 1 time by $124d
c125a
    lda frame                                                         // 125a: a5 44       .d
    cmp #6                                                            // 125c: c9 06       I.
    bne loop_c1240                                                    // 125e: d0 e0       P.
    lda #$40 // '@'                                                   // 1260: a9 40       .@
    jsr sub_c19e8                                                     // 1262: 20 e8 19     ..
    jsr sub_c1564                                                     // 1265: 20 64 15     ..
    ldx #4                                                            // 1268: a2 04       ..
// $126a referenced 1 time by $1276
loop_c126a
    lda dots,x                                                        // 126a: b5 4a       .j
    ldy fruitlevel                                                    // 126c: a4 49       .i
    iny                                                               // 126e: c8          H
// $126f referenced 1 time by $1271
loop_c126f
    lsr                                                               // 126f: 4a          j
    dey                                                               // 1270: 88          .
    bne loop_c126f                                                    // 1271: d0 fc       P.
    sta dots,x                                                        // 1273: 95 4a       .j
    dex                                                               // 1275: ca          J
    bne loop_c126a                                                    // 1276: d0 f2       P.
    jmp c10d0                                                         // 1278: 4c d0 10    lP.

// $127b referenced 5 times by $11e0, $1207, $121a, $122a, $1232
c127b
    jsr getin                                                         // 127b: 20 e4 ff     .. // Get a character from the input channel (from the keyboard, 0 if there's none)
    cmp #3                                                            // 127e: c9 03       I. // A=character read
    beq c1234                                                         // 1280: f0 b2       ..
    jsr sub_c12a3                                                     // 1282: 20 a3 12     ..
    ldx #$50 // 'p'                                                   // 1285: a2 50       .p
    lda spritex                                                       // 1287: ad a2 02    ...
    ora spritey                                                       // 128a: 0d a3 02    ...
    and #2                                                            // 128d: 29 02       ).
    bne c129a                                                         // 128f: d0 09       P.
    lda qmandir                                                       // 1291: a5 43       .c
    asl                                                               // 1293: 0a          .
    asl                                                               // 1294: 0a          .
    asl                                                               // 1295: 0a          .
    clc                                                               // 1296: 18          .
    adc #$58 // 'x'                                                   // 1297: 69 58       .x
    tax                                                               // 1299: aa          .
// $129a referenced 1 time by $128f
c129a
    stx spriteimg1                                                    // 129a: 8e ba 02    ...
    jsr sub_c168d                                                     // 129d: 20 8d 16     ..
    jmp c112d                                                         // 12a0: 4c 2d 11    l-.

// $12a3 referenced 2 times by $10a0, $1282
sub_c12a3
    lda fruitflag                                                     // 12a3: a5 3a       .:
    bne c12cb                                                         // 12a5: d0 24       P$
    lda dots                                                          // 12a7: a5 4a       .j
    cmp #$4b // 'k'                                                   // 12a9: c9 4b       Ik
    beq c12b1                                                         // 12ab: f0 04       ..
    cmp #$7d                                                          // 12ad: c9 7d       I.
    bne c12cb                                                         // 12af: d0 1a       P.
// $12b1 referenced 1 time by $12ab
c12b1
    ldx fruitlevel                                                    // 12b1: a6 49       .i
    cpx #$0c                                                          // 12b3: e0 0c       ..
    bcc c12b9                                                         // 12b5: 90 02       ..
    ldx #$0c                                                          // 12b7: a2 0c       ..
// $12b9 referenced 1 time by $12b5
c12b9
    lda l1c65,x                                                       // 12b9: bd 65 1c    ...
    sta screen_memory+283                                             // 12bc: 8d 1b 1f    ...
    lda l1c72,x                                                       // 12bf: bd 72 1c    ...
    sta colour_ram+283                                                // 12c2: 8d 1b 97    ...
    lda #$fa                                                          // 12c5: a9 fa       ..
    sta fruittimer                                                    // 12c7: 85 39       .9
    sta fruitflag                                                     // 12c9: 85 3a       .:
// $12cb referenced 2 times by $12a5, $12af
c12cb
    lda fruittimer                                                    // 12cb: a5 39       .9
    beq c12d8                                                         // 12cd: f0 09       ..
    dec fruittimer                                                    // 12cf: c6 39       F9
    bne c12d8                                                         // 12d1: d0 05       P.
    lda #$20 // ' '                                                   // 12d3: a9 20       .
    sta screen_memory+283                                             // 12d5: 8d 1b 1f    ...
// $12d8 referenced 2 times by $12cd, $12d1
c12d8
    lda dots                                                          // 12d8: a5 4a       .j
    cmp #$4c // 'l'                                                   // 12da: c9 4c       Il
    beq c12e2                                                         // 12dc: f0 04       ..
    cmp #$7e                                                          // 12de: c9 7e       I.
    bne c12e6                                                         // 12e0: d0 04       P.
// $12e2 referenced 1 time by $12dc
c12e2
    lda #0                                                            // 12e2: a9 00       ..
    sta fruitflag                                                     // 12e4: 85 3a       .:
// $12e6 referenced 1 time by $12e0
c12e6
    lda ppillflag                                                     // 12e6: a5 3b       .;
    beq c1326                                                         // 12e8: f0 3c       .<
    lda #0                                                            // 12ea: a9 00       ..
    sta ppillflag                                                     // 12ec: 85 3b       .;
    lda #2                                                            // 12ee: a9 02       ..
    sta fleeingscore                                                  // 12f0: 85 70       ..
    ldx fruitlevel                                                    // 12f2: a6 49       .i
    txa                                                               // 12f4: 8a          .
    and #7                                                            // 12f5: 29 07       ).
    beq c12fe                                                         // 12f7: f0 05       ..
    cpx #$10                                                          // 12f9: e0 10       ..
    bcs c1309                                                         // 12fb: b0 0c       ..
    txa                                                               // 12fd: 8a          .
// $12fe referenced 1 time by $12f7
c12fe
    asl                                                               // 12fe: 0a          .
    asl                                                               // 12ff: 0a          .
    and #$3f // '?'                                                   // 1300: 29 3f       )?
    eor #$3f // '?'                                                   // 1302: 49 3f       i?
    cpx #5                                                            // 1304: e0 05       ..
    bcc c1309                                                         // 1306: 90 01       ..
    lsr                                                               // 1308: 4a          j
// $1309 referenced 2 times by $12fb, $1306
c1309
    sta ppilltimer                                                    // 1309: 85 10       ..
    ldy #4                                                            // 130b: a0 04       ..
// $130d referenced 1 time by $1324
loop_c130d
    ldx dots,y                                                        // 130d: b6 4a       .j
    bne c1323                                                         // 130f: d0 12       P.
    lda #6                                                            // 1311: a9 06       ..
    sta spriteclr,y                                                   // 1313: 99 b2 02    ...
    lda #$80                                                          // 1316: a9 80       ..
    sta spriteimg1,y                                                  // 1318: 99 ba 02    ...
    lda basic_fn_ptr,y                                                // 131b: b9 4e 00    .n.
    eor #2                                                            // 131e: 49 02       i.
    sta basic_fn_ptr,y                                                // 1320: 99 4e 00    .n.
// $1323 referenced 1 time by $130f
c1323
    dey                                                               // 1323: 88          .
    bne loop_c130d                                                    // 1324: d0 e7       P.
// $1326 referenced 1 time by $12e8
c1326
    ldy #8                                                            // 1326: a0 08       ..
// $1328 referenced 1 time by $135c
c1328
    lda spritex                                                       // 1328: ad a2 02    ...
    cmp spritex,y                                                     // 132b: d9 a2 02    Y..
    bne c1343                                                         // 132e: d0 13       P.
    lda spritey                                                       // 1330: ad a3 02    ...
    sec                                                               // 1333: 38          8
    sbc spritey,y                                                     // 1334: f9 a3 02    ...
    bcs c133b                                                         // 1337: b0 02       ..
    eor #$ff                                                          // 1339: 49 ff       i.
// $133b referenced 1 time by $1337
c133b
    cmp #5                                                            // 133b: c9 05       I.
    bcs c1343                                                         // 133d: b0 04       ..
    ldx #$ff                                                          // 133f: a2 ff       ..
    bne c1361                                                         // 1341: d0 1e       P. // ALWAYS branch

// $1343 referenced 2 times by $132e, $133d
c1343
    lda spritey                                                       // 1343: ad a3 02    ...
    cmp spritey,y                                                     // 1346: d9 a3 02    Y..
    bne c135a                                                         // 1349: d0 0f       P.
    lda spritex                                                       // 134b: ad a2 02    ...
    sec                                                               // 134e: 38          8
    sbc spritex,y                                                     // 134f: f9 a2 02    ...
    bcs c1356                                                         // 1352: b0 02       ..
    eor #$ff                                                          // 1354: 49 ff       i.
// $1356 referenced 1 time by $1352
c1356
    cmp #5                                                            // 1356: c9 05       I.
    bcc c1361                                                         // 1358: 90 07       ..
// $135a referenced 2 times by $1349, $13a0
c135a
    dey                                                               // 135a: 88          .
    dey                                                               // 135b: 88          .
    bne c1328                                                         // 135c: d0 ca       PJ
    jmp c141e                                                         // 135e: 4c 1e 14    l..

// $1361 referenced 2 times by $1341, $1358
c1361
    tya                                                               // 1361: 98          .
    lsr                                                               // 1362: 4a          j
    tax                                                               // 1363: aa          .
    lda spriteimg1,x                                                  // 1364: bd ba 02    ...
    cmp #$80                                                          // 1367: c9 80       I.
    bne c13a3                                                         // 1369: d0 38       P8
    lda #9                                                            // 136b: a9 09       ..
    sta digit                                                         // 136d: 85 3e       .>
    lda fleeingscore                                                  // 136f: a5 70       ..
    sta points                                                        // 1371: 85 3f       .?
    asl                                                               // 1373: 0a          .
    sta fleeingscore                                                  // 1374: 85 70       ..
    lda #$78                                                          // 1376: a9 78       ..
    sta spriteimg1,x                                                  // 1378: 9d ba 02    ...
    lda #$51 // 'q'                                                   // 137b: a9 51       .q
    sta spritex,y                                                     // 137d: 99 a2 02    ...
    lda #$58 // 'x'                                                   // 1380: a9 58       .x
    sta spritey,y                                                     // 1382: 99 a3 02    ...
    lda #9                                                            // 1385: a9 09       ..
    sta chomp                                                         // 1387: 85 3c       .<
    lda jiffy_clock+2                                                 // 1389: a5 a2       ..
// $138b referenced 1 time by $138d
loop_c138b
    cmp jiffy_clock+2                                                 // 138b: c5 a2       E.
    beq loop_c138b                                                    // 138d: f0 fc       ..
    dex                                                               // 138f: ca          J
    lda l1c51,x                                                       // 1390: bd 51 1c    .q.
    sta l02b3,x                                                       // 1393: 9d b3 02    ...
    lda l1c55,x                                                       // 1396: bd 55 1c    .u.
    eor #$ff                                                          // 1399: 49 ff       i.
    lsr                                                               // 139b: 4a          j
    adc #$20 // ' '                                                   // 139c: 69 20       .
    sta penalty,x                                                     // 139e: 95 4b       .k
    jmp c135a                                                         // 13a0: 4c 5a 13    lz.

// $13a3 referenced 1 time by $1369
c13a3
    pla                                                               // 13a3: 68          .
    pla                                                               // 13a4: 68          .
    lda #$30 // '0'                                                   // 13a5: a9 30       .0
    jsr sub_c19e8                                                     // 13a7: 20 e8 19     ..
    lda #1                                                            // 13aa: a9 01       ..
    sta sprite                                                        // 13ac: 8d a1 02    ...
    lda #$50 // 'p'                                                   // 13af: a9 50       .p
    sta spriteimg1                                                    // 13b1: 8d ba 02    ...
    lda #$20 // ' '                                                   // 13b4: a9 20       .
    sta frame                                                         // 13b6: 85 44       .d
// $13b8 referenced 1 time by $13ce
loop_c13b8
    lda spriteimg1                                                    // 13b8: ad ba 02    ...
    cmp #$70                                                          // 13bb: c9 70       I.
    bcc c13c1                                                         // 13bd: 90 02       ..
    lda #$50 // 'p'                                                   // 13bf: a9 50       .p
// $13c1 referenced 1 time by $13bd
c13c1
    clc                                                               // 13c1: 18          .
    adc #8                                                            // 13c2: 69 08       ..
    sta spriteimg1                                                    // 13c4: 8d ba 02    ...
    lda #4                                                            // 13c7: a9 04       ..
    jsr sub_c19e8                                                     // 13c9: 20 e8 19     ..
    dec frame                                                         // 13cc: c6 44       Fd
    bne loop_c13b8                                                    // 13ce: d0 e8       P.
    ldx #$d8 // 'X'                                                   // 13d0: a2 d8       .X
    ldy #$1c                                                          // 13d2: a0 1c       ..
    stx spriteimg1                                                    // 13d4: 8e ba 02    ...
    sty spriteimg2                                                    // 13d7: 8c c2 02    .B.
    lda #$0a                                                          // 13da: a9 0a       ..
    jsr sub_c19e8                                                     // 13dc: 20 e8 19     ..
    ldx #$e0                                                          // 13df: a2 e0       ..
    stx spriteimg1                                                    // 13e1: 8e ba 02    ...
    lda #8                                                            // 13e4: a9 08       ..
    jsr sub_c19e8                                                     // 13e6: 20 e8 19     ..
    ldx #$e8                                                          // 13e9: a2 e8       ..
    stx spriteimg1                                                    // 13eb: 8e ba 02    ...
    lda #6                                                            // 13ee: a9 06       ..
    jsr sub_c19e8                                                     // 13f0: 20 e8 19     ..
    jsr sub_c1564                                                     // 13f3: 20 64 15     ..
    dec lives                                                         // 13f6: c6 45       Fe
    beq c140e                                                         // 13f8: f0 14       ..
    ldx lives                                                         // 13fa: a6 45       .e
    lda #$1c                                                          // 13fc: a9 1c       ..
    sta screen_memory+484,x                                           // 13fe: 9d e4 1f    ...
    lda #8                                                            // 1401: a9 08       ..
    jsr sub_c19e8                                                     // 1403: 20 e8 19     ..
    lda #$20 // ' '                                                   // 1406: a9 20       .
    sta screen_memory+484,x                                           // 1408: 9d e4 1f    ...
    jmp c10d3                                                         // 140b: 4c d3 10    lS.

// $140e referenced 1 time by $13f8
c140e
    ldy lives                                                         // 140e: a4 45       .e
    sty sprite                                                        // 1410: 8c a1 02    ...
    jsr sub_c1cae                                                     // 1413: 20 ae 1c     ..
    lda #$f0                                                          // 1416: a9 f0       ..
    jsr sub_c19e8                                                     // 1418: 20 e8 19     ..
    jmp c1048                                                         // 141b: 4c 48 10    lh.

// $141e referenced 2 times by $135e, $144b
c141e
    lda #4                                                            // 141e: a9 04       ..
    sta usr_jmp                                                       // 1420: 85 00       ..
// $1422 referenced 2 times by $1431, $1441
c1422
    lda usr_jmp                                                       // 1422: a5 00       ..
    tay                                                               // 1424: a8          .
    asl                                                               // 1425: 0a          .
    sta usr_address                                                   // 1426: 85 01       ..
    ldx dots,y                                                        // 1428: b6 4a       .j
    beq c144e                                                         // 142a: f0 22       ."
    dex                                                               // 142c: ca          J
    stx dots,y                                                        // 142d: 96 4a       .j
// $142f referenced 3 times by $1459, $14dc, $14e5
c142f
    dec usr_jmp                                                       // 142f: c6 00       F.
    bne c1422                                                         // 1431: d0 ef       P.
    inc frame                                                         // 1433: e6 44       .d
    inc usr_jmp                                                       // 1435: e6 00       ..
    lda l02a5                                                         // 1437: ad a5 02    ...
    and #7                                                            // 143a: 29 07       ).
    ora l02a4                                                         // 143c: 0d a4 02    ...
    and #$0f                                                          // 143f: 29 0f       ).
    beq c1422                                                         // 1441: f0 df       ..
    lda chewing                                                       // 1443: a5 3d       .=
    bne c1448                                                         // 1445: d0 01       P.
    rts                                                               // 1447: 60          .

// $1448 referenced 1 time by $1445
c1448
    jsr sub_c168d                                                     // 1448: 20 8d 16     ..
    jmp c141e                                                         // 144b: 4c 1e 14    l..

// $144e referenced 1 time by $142a
c144e
    lda frame                                                         // 144e: a5 44       .d
    and #1                                                            // 1450: 29 01       ).
    beq c145b                                                         // 1452: f0 07       ..
    lda spriteimg1,y                                                  // 1454: b9 ba 02    ...
    cmp #$80                                                          // 1457: c9 80       I.
    beq c142f                                                         // 1459: f0 d4       .T
// $145b referenced 1 time by $1452
c145b
    ldx usr_address                                                   // 145b: a6 01       ..
    lda spritex,x                                                     // 145d: bd a2 02    ...
    cmp #$50 // 'p'                                                   // 1460: c9 50       Ip
    bne c1476                                                         // 1462: d0 12       P.
    lda spritey,x                                                     // 1464: bd a3 02    ...
    cmp #$58 // 'x'                                                   // 1467: c9 58       Ix
    bne c1476                                                         // 1469: d0 0b       P.
    lda #$57 // 'w'                                                   // 146b: a9 57       .w
    sta spritey,x                                                     // 146d: 9d a3 02    ...
    ldx #3                                                            // 1470: a2 03       ..
    stx basic_fn_ptr,y                                                // 1472: 96 4e       .n
    bne c1489                                                         // 1474: d0 13       P. // ALWAYS branch

// $1476 referenced 2 times by $1462, $1469
c1476
    lda spritex,x                                                     // 1476: bd a2 02    ...
    bne c147f                                                         // 1479: d0 04       P.
    ldx usr_jmp                                                       // 147b: a6 00       ..
    sta basic_fn_ptr,x                                                // 147d: 95 4e       .n
// $147f referenced 1 time by $1479
c147f
    cmp #$9f                                                          // 147f: c9 9f       I.
    bne c1489                                                         // 1481: d0 06       P.
    ldx usr_jmp                                                       // 1483: a6 00       ..
    lda #2                                                            // 1485: a9 02       ..
    sta basic_fn_ptr,x                                                // 1487: 95 4e       .n
// $1489 referenced 2 times by $1474, $1481
c1489
    ldy #0                                                            // 1489: a0 00       ..
    ldx #4                                                            // 148b: a2 04       ..
// $148d referenced 1 time by $1491
loop_c148d
    stx basic_float_temp2+4,y                                         // 148d: 96 60       ..
    iny                                                               // 148f: c8          H
    dex                                                               // 1490: ca          J
    bne loop_c148d                                                    // 1491: d0 fa       P.
    ldy usr_address                                                   // 1493: a4 01       ..
    lda spritex,y                                                     // 1495: b9 a2 02    ...
    and #7                                                            // 1498: 29 07       ).
    beq c14a3                                                         // 149a: f0 07       ..
    lda spritey,y                                                     // 149c: b9 a3 02    ...
    and #7                                                            // 149f: 29 07       ).
    bne c14a9                                                         // 14a1: d0 06       P.
// $14a3 referenced 1 time by $149a
c14a3
    jsr sub_c14e8                                                     // 14a3: 20 e8 14     ..
    clc                                                               // 14a6: 18          .
    bcc c14ad                                                         // 14a7: 90 04       .. // ALWAYS branch

// $14a9 referenced 1 time by $14a1
c14a9
    ldx basic_fn_ptr,y                                                // 14a9: b6 4e       .n
    stx monmove                                                       // 14ab: 86 61       ..
// $14ad referenced 1 time by $14a7
c14ad
    ldy #0                                                            // 14ad: a0 00       ..
    sty basic_float_to_int_vector+1                                   // 14af: 84 04       ..
// $14b1 referenced 1 time by $14d1
c14b1
    ldx monmove,y                                                     // 14b1: b6 61       ..
    txa                                                               // 14b3: 8a          .
    ldx usr_jmp                                                       // 14b4: a6 00       ..
    eor basic_fn_ptr,x                                                // 14b6: 55 4e       un
    cmp #2                                                            // 14b8: c9 02       I.
    beq c14cb                                                         // 14ba: f0 0f       ..
    ldx monmove,y                                                     // 14bc: b6 61       ..
    stx newdir                                                        // 14be: 86 41       .a
    ldy usr_jmp                                                       // 14c0: a4 00       ..
    ldx basic_fn_ptr,y                                                // 14c2: b6 4e       .n
    stx olddir                                                        // 14c4: 86 40       .@
    jsr sub_c161f                                                     // 14c6: 20 1f 16     ..
    bcc c14df                                                         // 14c9: 90 14       ..
// $14cb referenced 1 time by $14ba
c14cb
    inc basic_float_to_int_vector+1                                   // 14cb: e6 04       ..
    ldy basic_float_to_int_vector+1                                   // 14cd: a4 04       ..
    cpy #4                                                            // 14cf: c0 04       ..
    bne c14b1                                                         // 14d1: d0 de       P.
    ldy usr_jmp                                                       // 14d3: a4 00       ..
    lda olddir                                                        // 14d5: a5 40       .@
    eor #2                                                            // 14d7: 49 02       i.
    sta basic_fn_ptr,y                                                // 14d9: 99 4e 00    .n.
    jmp c142f                                                         // 14dc: 4c 2f 14    l/.

// $14df referenced 1 time by $14c9
c14df
    ldy usr_jmp                                                       // 14df: a4 00       ..
    ldx newdir                                                        // 14e1: a6 41       .a
    stx basic_fn_ptr,y                                                // 14e3: 96 4e       .n
    jmp c142f                                                         // 14e5: 4c 2f 14    l/.

// $14e8 referenced 1 time by $14a3
sub_c14e8
    ldx usr_address                                                   // 14e8: a6 01       ..
    lda basic_string_descriptor_ptr+1,x                               // 14ea: b5 51       .q
    sec                                                               // 14ec: 38          8
    sbc spritex,x                                                     // 14ed: fd a2 02    ...
    bcs c14fc                                                         // 14f0: b0 0a       ..
    ldy #2                                                            // 14f2: a0 02       ..
    sty monmove                                                       // 14f4: 84 61       ..
    ldy #0                                                            // 14f6: a0 00       ..
    sty fac1_mantissa+2                                               // 14f8: 84 64       ..
    beq c1504                                                         // 14fa: f0 08       .. // ALWAYS branch

// $14fc referenced 1 time by $14f0
c14fc
    ldy #0                                                            // 14fc: a0 00       ..
    sty monmove                                                       // 14fe: 84 61       ..
    ldy #2                                                            // 1500: a0 02       ..
    sty fac1_mantissa+2                                               // 1502: 84 64       ..
// $1504 referenced 1 time by $14fa
c1504
    lda basic_string_descriptor_ptr+2,x                               // 1504: b5 52       .r
    sec                                                               // 1506: 38          8
    sbc spritey,x                                                     // 1507: fd a3 02    ...
    bcs c1516                                                         // 150a: b0 0a       ..
    ldy #3                                                            // 150c: a0 03       ..
    sty fac1_mantissa                                                 // 150e: 84 62       ..
    ldy #1                                                            // 1510: a0 01       ..
    sty fac1_mantissa+1                                               // 1512: 84 63       ..
    bne c151e                                                         // 1514: d0 08       P. // ALWAYS branch

// $1516 referenced 1 time by $150a
c1516
    ldy #1                                                            // 1516: a0 01       ..
    sty fac1_mantissa                                                 // 1518: 84 62       ..
    ldy #3                                                            // 151a: a0 03       ..
    sty fac1_mantissa+1                                               // 151c: 84 63       ..
// $151e referenced 1 time by $1514
c151e
    ldx usr_address                                                   // 151e: a6 01       ..
    lda basic_string_descriptor_ptr+1,x                               // 1520: b5 51       .q
    sec                                                               // 1522: 38          8
    sbc spritex,x                                                     // 1523: fd a2 02    ...
    bcs c152a                                                         // 1526: b0 02       ..
    eor #$ff                                                          // 1528: 49 ff       i.
// $152a referenced 1 time by $1526
c152a
    sta fac2_exponent                                                 // 152a: 85 69       ..
    lda basic_string_descriptor_ptr+2,x                               // 152c: b5 52       .r
    sec                                                               // 152e: 38          8
    sbc spritey,x                                                     // 152f: fd a3 02    ...
    bcs c1536                                                         // 1532: b0 02       ..
    eor #$ff                                                          // 1534: 49 ff       i.
// $1536 referenced 1 time by $1532
c1536
    cmp fac2_exponent                                                 // 1536: c5 69       E.
    bcc c154a                                                         // 1538: 90 10       ..
    ldx monmove                                                       // 153a: a6 61       ..
    ldy fac1_mantissa                                                 // 153c: a4 62       ..
    stx fac1_mantissa                                                 // 153e: 86 62       ..
    sty monmove                                                       // 1540: 84 61       ..
    ldy fac1_mantissa+1                                               // 1542: a4 63       ..
    ldx fac1_mantissa+2                                               // 1544: a6 64       ..
    sty fac1_mantissa+2                                               // 1546: 84 64       ..
    stx fac1_mantissa+1                                               // 1548: 86 63       ..
// $154a referenced 1 time by $1538
c154a
    ldy usr_jmp                                                       // 154a: a4 00       ..
    lda spriteimg1,y                                                  // 154c: b9 ba 02    ...
    cmp #$80                                                          // 154f: c9 80       I.
    bne return_1                                                      // 1551: d0 10       P.
    ldx #4                                                            // 1553: a2 04       ..
// $1555 referenced 1 time by $1559
loop_c1555
    lda basic_float_temp2+4,x                                         // 1555: b5 60       ..
    pha                                                               // 1557: 48          h
    dex                                                               // 1558: ca          J
    bne loop_c1555                                                    // 1559: d0 fa       P.
// $155b referenced 1 time by $1561
loop_c155b
    pla                                                               // 155b: 68          .
    sta monmove,x                                                     // 155c: 95 61       ..
    inx                                                               // 155e: e8          .
    cpx #4                                                            // 155f: e0 04       ..
    bne loop_c155b                                                    // 1561: d0 f8       P.
// $1563 referenced 1 time by $1551
return_1
    rts                                                               // 1563: 60          .

// $1564 referenced 4 times by $1048, $10b4, $1265, $13f3
sub_c1564
    ldy #0                                                            // 1564: a0 00       ..
// $1566 referenced 1 time by $1574
loop_c1566
    ldx l1c55,y                                                       // 1566: be 55 1c    .u.
    stx penalty,y                                                     // 1569: 96 4b       .k
    lda l1c92,y                                                       // 156b: b9 92 1c    ...
    sta spritex,y                                                     // 156e: 99 a2 02    ...
    iny                                                               // 1571: c8          H
    cpy #$10                                                          // 1572: c0 10       ..
    bne loop_c1566                                                    // 1574: d0 f0       P.
    rts                                                               // 1576: 60          .

// $1577 referenced 2 times by $1029, $10d0
sub_c1577
    inc fruitlevel                                                    // 1577: e6 49       .i
    lda #0                                                            // 1579: a9 00       ..
    sta sprite                                                        // 157b: 8d a1 02    ...
    lda #$0e                                                          // 157e: a9 0e       ..
    sta vic_background_border_colour                                  // 1580: 8d 0f 90    ...
    lda #$af                                                          // 1583: a9 af       ..
    sta vic_volume_aux_colour                                         // 1585: 8d 0e 90    ...
    lda #$93                                                          // 1588: a9 93       .. // A=character to output
    jsr chrout                                                        // 158a: 20 d2 ff     R. // Output $93 (clear screen)
    ldx #$15                                                          // 158d: a2 15       ..
// $158f referenced 1 time by $159c
loop_c158f
    lda l1a00,x                                                       // 158f: bd 00 1a    ...
    sta pydis_end,x                                                   // 1592: 9d 00 1e    ...
    lda l1ae3,x                                                       // 1595: bd e3 1a    ...
    sta screen_memory+227,x                                           // 1598: 9d e3 1e    ...
    inx                                                               // 159b: e8          .
    bne loop_c158f                                                    // 159c: d0 f1       P.
    stx dots                                                          // 159e: 86 4a       .j
    ldx #6                                                            // 15a0: a2 06       ..
    jsr sub_c15f9                                                     // 15a2: 20 f9 15     ..
    ldx #0                                                            // 15a5: a2 00       ..
// $15a7 referenced 1 time by $15ba
loop_c15a7
    lda l1c50,x                                                       // 15a7: bd 50 1c    .p.
    sta spriteclr,x                                                   // 15aa: 9d b2 02    ...
    lda #$78                                                          // 15ad: a9 78       ..
    sta spriteimg1,x                                                  // 15af: 9d ba 02    ...
    lda #$1d                                                          // 15b2: a9 1d       ..
    sta spriteimg2,x                                                  // 15b4: 9d c2 02    .B.
    inx                                                               // 15b7: e8          .
    cpx #5                                                            // 15b8: e0 05       ..
    bne loop_c15a7                                                    // 15ba: d0 eb       P.
    ldy lives                                                         // 15bc: a4 45       .e
    jsr sub_c1cae                                                     // 15be: 20 ae 1c     ..
    dey                                                               // 15c1: 88          .
    beq c15d1                                                         // 15c2: f0 0d       ..
// $15c4 referenced 1 time by $15cf
loop_c15c4
    lda #$2d // '-'                                                   // 15c4: a9 2d       .-
    sta screen_memory+484,y                                           // 15c6: 99 e4 1f    ...
    lda #7                                                            // 15c9: a9 07       ..
    sta colour_ram+484,y                                              // 15cb: 99 e4 97    ...
    dey                                                               // 15ce: 88          .
    bne loop_c15c4                                                    // 15cf: d0 f3       P.
// $15d1 referenced 1 time by $15c2
c15d1
    ldy fruitlevel                                                    // 15d1: a4 49       .i
    ldx #0                                                            // 15d3: a2 00       ..
// $15d5 referenced 1 time by $15f6
c15d5
    cpy #$0c                                                          // 15d5: c0 0c       ..
    bcc c15db                                                         // 15d7: 90 02       ..
    ldy #$0c                                                          // 15d9: a0 0c       ..
// $15db referenced 1 time by $15d7
c15db
    lda l1c65,y                                                       // 15db: b9 65 1c    ...
    sta screen_memory+497,x                                           // 15de: 9d f1 1f    ...
    lda l1c72,y                                                       // 15e1: b9 72 1c    ...
    sta colour_ram+497,x                                              // 15e4: 9d f1 97    ...
    cpy #0                                                            // 15e7: c0 00       ..
    beq return_2                                                      // 15e9: f0 0d       ..
    inx                                                               // 15eb: e8          .
    stx basic_float_to_ascii_temp                                     // 15ec: 86 ff       ..
    lda fruitlevel                                                    // 15ee: a5 49       .i
    sec                                                               // 15f0: 38          8
    sbc basic_float_to_ascii_temp                                     // 15f1: e5 ff       ..
    tay                                                               // 15f3: a8          .
    cpx #7                                                            // 15f4: e0 07       ..
    bne c15d5                                                         // 15f6: d0 dd       P.
// $15f8 referenced 1 time by $15e9
return_2
    rts                                                               // 15f8: 60          .

// $15f9 referenced 3 times by $106c, $1247, $15a2
sub_c15f9
    ldy #$15                                                          // 15f9: a0 15       ..
// $15fb referenced 1 time by $161c
c15fb
    lda l1a00,y                                                       // 15fb: b9 00 1a    ...
    cmp #$31 // '1'                                                   // 15fe: c9 31       I1
    bcc c160c                                                         // 1600: 90 0a       ..
    cmp #$3f // '?'                                                   // 1602: c9 3f       I?
    bcs c160c                                                         // 1604: b0 06       ..
    lda #1                                                            // 1606: a9 01       .. // Redundant instruction?
    txa                                                               // 1608: 8a          .
    sta colour_ram,y                                                  // 1609: 99 00 96    ...
// $160c referenced 2 times by $1600, $1604
c160c
    lda l1ae3,y                                                       // 160c: b9 e3 1a    ...
    cmp #$31 // '1'                                                   // 160f: c9 31       I1
    bcc c161b                                                         // 1611: 90 08       ..
    cmp #$3f // '?'                                                   // 1613: c9 3f       I?
    bcs c161b                                                         // 1615: b0 04       ..
    txa                                                               // 1617: 8a          .
    sta colour_ram+227,y                                              // 1618: 99 e3 96    ...
// $161b referenced 2 times by $1611, $1615
c161b
    iny                                                               // 161b: c8          H
    bne c15fb                                                         // 161c: d0 dd       P.
    rts                                                               // 161e: 60          .

// $161f referenced 3 times by $118e, $119e, $14c6
sub_c161f
    ldy usr_address                                                   // 161f: a4 01       ..
    lda olddir                                                        // 1621: a5 40       .@
    and #1                                                            // 1623: 29 01       ).
    beq c1628                                                         // 1625: f0 01       ..
    iny                                                               // 1627: c8          H
// $1628 referenced 1 time by $1625
c1628
    lda spritex,y                                                     // 1628: b9 a2 02    ...
    and #7                                                            // 162b: 29 07       ).
    beq c163d                                                         // 162d: f0 0e       ..
    lda newdir                                                        // 162f: a5 41       .a
    cmp olddir                                                        // 1631: c5 40       E@
    beq c1671                                                         // 1633: f0 3c       .<
    eor olddir                                                        // 1635: 45 40       e@
    cmp #2                                                            // 1637: c9 02       I.
    beq c1671                                                         // 1639: f0 36       .6
    sec                                                               // 163b: 38          8
    rts                                                               // 163c: 60          .

// $163d referenced 1 time by $162d
c163d
    jsr sub_c16ee                                                     // 163d: 20 ee 16     ..
    lda rs232_input_buffer_ptr+1                                      // 1640: a5 f8       ..
    sec                                                               // 1642: 38          8
    sbc #4                                                            // 1643: e9 04       ..
    sta rs232_input_buffer_ptr+1                                      // 1645: 85 f8       ..
    ldx newdir                                                        // 1647: a6 41       .a
    cpx #2                                                            // 1649: e0 02       ..
    bcs c165c                                                         // 164b: b0 0f       ..
    lda rs232_input_buffer_ptr                                        // 164d: a5 f7       ..
    clc                                                               // 164f: 18          .
    adc l1c90,x                                                       // 1650: 7d 90 1c    ...
    bcc c1657                                                         // 1653: 90 02       ..
    inc rs232_input_buffer_ptr+1                                      // 1655: e6 f8       ..
// $1657 referenced 1 time by $1653
c1657
    sta rs232_input_buffer_ptr                                        // 1657: 85 f7       ..
    clc                                                               // 1659: 18          .
    bcc c1668                                                         // 165a: 90 0c       .. // ALWAYS branch

// $165c referenced 1 time by $164b
c165c
    lda rs232_input_buffer_ptr                                        // 165c: a5 f7       ..
    sec                                                               // 165e: 38          8
    sbc l1c8e,x                                                       // 165f: fd 8e 1c    ...
    bcs c1666                                                         // 1662: b0 02       ..
    dec rs232_input_buffer_ptr+1                                      // 1664: c6 f8       F.
// $1666 referenced 1 time by $1662
c1666
    sta rs232_input_buffer_ptr                                        // 1666: 85 f7       ..
// $1668 referenced 1 time by $165a
c1668
    ldy #0                                                            // 1668: a0 00       ..
    lda (rs232_input_buffer_ptr),y                                    // 166a: b1 f7       ..
    cmp #$31 // '1'                                                   // 166c: c9 31       I1
    bcc c1671                                                         // 166e: 90 01       ..
    rts                                                               // 1670: 60          .

// $1671 referenced 3 times by $1633, $1639, $166e
c1671
    lda newdir                                                        // 1671: a5 41       .a
    asl                                                               // 1673: 0a          .
    tax                                                               // 1674: aa          .
    ldy usr_address                                                   // 1675: a4 01       ..
    lda l1c88,x                                                       // 1677: bd 88 1c    ...
    clc                                                               // 167a: 18          .
    adc spritex,y                                                     // 167b: 79 a2 02    ...
    sta spritex,y                                                     // 167e: 99 a2 02    ...
    lda l1c89,x                                                       // 1681: bd 89 1c    ...
    clc                                                               // 1684: 18          .
    adc spritey,y                                                     // 1685: 79 a3 02    ...
    sta spritey,y                                                     // 1688: 99 a3 02    ...
    clc                                                               // 168b: 18          .
    rts                                                               // 168c: 60          .

// $168d referenced 5 times by $10a3, $1257, $129d, $1448, $19eb
sub_c168d
    lda #0                                                            // 168d: a9 00       ..
    sta usr_jmp                                                       // 168f: 85 00       ..
// $1691 referenced 1 time by $16cd
c1691
    asl                                                               // 1691: 0a          .
    sta usr_address                                                   // 1692: 85 01       ..
    asl                                                               // 1694: 0a          .
    asl                                                               // 1695: 0a          .
    sta usr_address+1                                                 // 1696: 85 02       ..
    ldx usr_jmp                                                       // 1698: a6 00       ..
    lda sprite                                                        // 169a: ad a1 02    ...
    and l1ca6,x                                                       // 169d: 3d a6 1c    =..
    beq c16bc                                                         // 16a0: f0 1a       ..
    lda spritelast                                                    // 16a2: ad cc 02    .L.
    and l1ca6,x                                                       // 16a5: 3d a6 1c    =..
    beq c16ad                                                         // 16a8: f0 03       ..
    jsr sub_c16dd                                                     // 16aa: 20 dd 16     ..
// $16ad referenced 1 time by $16a8
c16ad
    jsr sub_c16ee                                                     // 16ad: 20 ee 16     ..
    jsr sub_c1758                                                     // 16b0: 20 58 17     x.
    jsr sub_c17b5                                                     // 16b3: 20 b5 17     ..
    jsr sub_c185b                                                     // 16b6: 20 5b 18     [.
    jmp c16c7                                                         // 16b9: 4c c7 16    lG.

// $16bc referenced 1 time by $16a0
c16bc
    lda spritelast                                                    // 16bc: ad cc 02    .L.
    and l1ca6,x                                                       // 16bf: 3d a6 1c    =..
    beq c16c7                                                         // 16c2: f0 03       ..
    jsr sub_c16dd                                                     // 16c4: 20 dd 16     ..
// $16c7 referenced 2 times by $16b9, $16c2
c16c7
    inc usr_jmp                                                       // 16c7: e6 00       ..
    lda usr_jmp                                                       // 16c9: a5 00       ..
    cmp #5                                                            // 16cb: c9 05       I.
    bne c1691                                                         // 16cd: d0 c2       PB
    // Copy 17 bytes of memory from sprite to spritelast
    ldx #0                                                            // 16cf: a2 00       ..
// $16d1 referenced 1 time by $16da
loop_c16d1
    lda sprite,x                                                      // 16d1: bd a1 02    ...
    sta spritelast,x                                                  // 16d4: 9d cc 02    .L.
    inx                                                               // 16d7: e8          .
    cpx #$11                                                          // 16d8: e0 11       ..
    bne loop_c16d1                                                    // 16da: d0 f5       P.
    rts                                                               // 16dc: 60          .

// $16dd referenced 2 times by $16aa, $16c4
sub_c16dd
    jsr sub_c16e7                                                     // 16dd: 20 e7 16     ..
    jsr sub_c1758                                                     // 16e0: 20 58 17     x.
    jsr sub_c1790                                                     // 16e3: 20 90 17     ..
    rts                                                               // 16e6: 60          .

// $16e7 referenced 1 time by $16dd
sub_c16e7
    lda usr_address                                                   // 16e7: a5 01       ..
    clc                                                               // 16e9: 18          .
    adc #$cc // 'L'                                                   // 16ea: 69 cc       .L
    bne c16f3                                                         // 16ec: d0 05       P.
// $16ee referenced 2 times by $163d, $16ad
sub_c16ee
    lda usr_address                                                   // 16ee: a5 01       ..
    clc                                                               // 16f0: 18          .
    adc #$a1                                                          // 16f1: 69 a1       ..
// $16f3 referenced 1 time by $16ec
c16f3
    tax                                                               // 16f3: aa          .
    lda basic_input_buffer+1,x                                        // 16f4: bd 01 02    ...
    cmp #$a0                                                          // 16f7: c9 a0       I.
    bcc c16fd                                                         // 16f9: 90 02       ..
    sbc #$a0                                                          // 16fb: e9 a0       ..
// $16fd referenced 1 time by $16f9
c16fd
    lsr                                                               // 16fd: 4a          j
    lsr                                                               // 16fe: 4a          j
    lsr                                                               // 16ff: 4a          j
    sta rs232_input_buffer_ptr                                        // 1700: 85 f7       ..
    sta free_zero_page+1                                              // 1702: 85 fc       ..
    lda screen_memory_page                                            // 1704: ad 88 02    ...
    sta rs232_input_buffer_ptr+1                                      // 1707: 85 f8       ..
    lda colour_ram_line_ptr+1                                         // 1709: a5 f4       ..
    and #$fe                                                          // 170b: 29 fe       ).
    sta free_zero_page+2                                              // 170d: 85 fd       ..
    lda basic_input_buffer+2,x                                        // 170f: bd 02 02    ...
    cmp #$b8                                                          // 1712: c9 b8       I.
    bcc c1718                                                         // 1714: 90 02       ..
    sbc #$b8                                                          // 1716: e9 b8       ..
// $1718 referenced 1 time by $1714
c1718
    lsr                                                               // 1718: 4a          j
    lsr                                                               // 1719: 4a          j
    lsr                                                               // 171a: 4a          j
    tay                                                               // 171b: a8          .
    beq c1730                                                         // 171c: f0 12       ..
    lda rs232_input_buffer_ptr                                        // 171e: a5 f7       ..
// $1720 referenced 1 time by $172e
loop_c1720
    clc                                                               // 1720: 18          .
    adc #$15                                                          // 1721: 69 15       ..
    bcc c1729                                                         // 1723: 90 04       ..
    inc rs232_input_buffer_ptr+1                                      // 1725: e6 f8       ..
    inc free_zero_page+2                                              // 1727: e6 fd       ..
// $1729 referenced 1 time by $1723
c1729
    sta rs232_input_buffer_ptr                                        // 1729: 85 f7       ..
    sta free_zero_page+1                                              // 172b: 85 fc       ..
    dey                                                               // 172d: 88          .
    bne loop_c1720                                                    // 172e: d0 f0       P.
// $1730 referenced 1 time by $171c
c1730
    lda rs232_input_buffer_ptr+1                                      // 1730: a5 f8       ..
    sta rs232_output_buffer_ptr+1                                     // 1732: 85 fa       ..
    lda free_zero_page+2                                              // 1734: a5 fd       ..
    sta basic_float_to_ascii_temp                                     // 1736: 85 ff       ..
    lda basic_input_buffer+1,x                                        // 1738: bd 01 02    ...
    and #7                                                            // 173b: 29 07       ).
    beq c174f                                                         // 173d: f0 10       ..
    lda rs232_input_buffer_ptr                                        // 173f: a5 f7       ..
    clc                                                               // 1741: 18          .
    adc #1                                                            // 1742: 69 01       ..
    bcc c174a                                                         // 1744: 90 04       ..
// $1746 referenced 1 time by $1756
loop_c1746
    inc rs232_output_buffer_ptr+1                                     // 1746: e6 fa       ..
    inc basic_float_to_ascii_temp                                     // 1748: e6 ff       ..
// $174a referenced 2 times by $1744, $1754
c174a
    sta rs232_output_buffer_ptr                                       // 174a: 85 f9       ..
    sta free_zero_page+3                                              // 174c: 85 fe       ..
    rts                                                               // 174e: 60          .

// $174f referenced 1 time by $173d
c174f
    lda rs232_input_buffer_ptr                                        // 174f: a5 f7       ..
    clc                                                               // 1751: 18          .
    adc #$15                                                          // 1752: 69 15       ..
    bcc c174a                                                         // 1754: 90 f4       ..
    bcs loop_c1746                                                    // 1756: b0 ee       .. // ALWAYS branch

// $1758 referenced 2 times by $16b0, $16e0
sub_c1758
    ldy #0                                                            // 1758: a0 00       ..
    lda (rs232_input_buffer_ptr),y                                    // 175a: b1 f7       ..
    pha                                                               // 175c: 48          h
    ldy usr_address                                                   // 175d: a4 01       ..
    lda basic_input_buffer+1,x                                        // 175f: bd 01 02    ...
    and #7                                                            // 1762: 29 07       ).
    bne c176d                                                         // 1764: d0 07       P.
    lda basic_input_buffer+2,x                                        // 1766: bd 02 02    ...
    and #7                                                            // 1769: 29 07       ).
    beq c1775                                                         // 176b: f0 08       ..
// $176d referenced 1 time by $1764
c176d
    ldy #0                                                            // 176d: a0 00       ..
    lda (rs232_output_buffer_ptr),y                                   // 176f: b1 f9       ..
    pha                                                               // 1771: 48          h
    ldy usr_address                                                   // 1772: a4 01       ..
    iny                                                               // 1774: c8          H
// $1775 referenced 1 time by $176b
c1775
    tya                                                               // 1775: 98          .
    tax                                                               // 1776: aa          .
// $1777 referenced 1 time by $178d
loop_c1777
    pla                                                               // 1777: 68          .
// $1778 referenced 1 time by $1785
loop_c1778
    cmp usr_address                                                   // 1778: c5 01       E.
    bcc c1787                                                         // 177a: 90 0b       ..
    cmp #$0a                                                          // 177c: c9 0a       I.
    bcs c1787                                                         // 177e: b0 07       ..
    tay                                                               // 1780: a8          .
    lda saveback,y                                                    // 1781: b9 dd 02    ...
    clc                                                               // 1784: 18          .
    bcc loop_c1778                                                    // 1785: 90 f1       .. // ALWAYS branch

// $1787 referenced 2 times by $177a, $177e
c1787
    sta saveback,x                                                    // 1787: 9d dd 02    ...
    dex                                                               // 178a: ca          J
    cpx usr_address                                                   // 178b: e4 01       ..
    beq loop_c1777                                                    // 178d: f0 e8       ..
    rts                                                               // 178f: 60          .

// $1790 referenced 1 time by $16e3
sub_c1790
    ldx usr_address                                                   // 1790: a6 01       ..
    lda saveback,x                                                    // 1792: bd dd 02    ...
    ldy #0                                                            // 1795: a0 00       ..
    sta (rs232_input_buffer_ptr),y                                    // 1797: 91 f7       ..
    lda #1                                                            // 1799: a9 01       ..
    sta (free_zero_page+1),y                                          // 179b: 91 fc       ..
    lda l02cd,x                                                       // 179d: bd cd 02    .M.
    and #7                                                            // 17a0: 29 07       ).
    bne c17ab                                                         // 17a2: d0 07       P.
    lda l02ce,x                                                       // 17a4: bd ce 02    .N.
    and #7                                                            // 17a7: 29 07       ).
    beq return_3                                                      // 17a9: f0 09       ..
// $17ab referenced 1 time by $17a2
c17ab
    lda l02de,x                                                       // 17ab: bd de 02    ...
    sta (rs232_output_buffer_ptr),y                                   // 17ae: 91 f9       ..
    lda #1                                                            // 17b0: a9 01       ..
    sta (free_zero_page+3),y                                          // 17b2: 91 fe       ..
// $17b4 referenced 1 time by $17a9
return_3
    rts                                                               // 17b4: 60          .

// $17b5 referenced 1 time by $16b3
sub_c17b5
    ldx usr_jmp                                                       // 17b5: a6 00       ..
    lda spriteimg1,x                                                  // 17b7: bd ba 02    ...
    sta basic_int_to_float_vector                                     // 17ba: 85 05       ..
    lda spriteimg2,x                                                  // 17bc: bd c2 02    .B.
    sta basic_int_to_float_vector+1                                   // 17bf: 85 06       ..
    ldx usr_address                                                   // 17c1: a6 01       ..
    lda spritey,x                                                     // 17c3: bd a3 02    ...
    and #7                                                            // 17c6: 29 07       ).
    sta basic_float_to_int_vector                                     // 17c8: 85 03       ..
    tax                                                               // 17ca: aa          .
    ldy #0                                                            // 17cb: a0 00       ..
    tya                                                               // 17cd: 98          .  // A=0
// $17ce referenced 1 time by $17d4
loop_c17ce
    sta tape_buffer+32,y                                              // 17ce: 99 5c 03    ...
    iny                                                               // 17d1: c8          H
    cpy #$10                                                          // 17d2: c0 10       ..
    bne loop_c17ce                                                    // 17d4: d0 f8       P.
    tay                                                               // 17d6: a8          .
// $17d7 referenced 1 time by $17e0
loop_c17d7
    lda (basic_int_to_float_vector),y                                 // 17d7: b1 05       ..
    sta tape_buffer+32,x                                              // 17d9: 9d 5c 03    ...
    inx                                                               // 17dc: e8          .
    iny                                                               // 17dd: c8          H
    cpy #8                                                            // 17de: c0 08       ..
    bne loop_c17d7                                                    // 17e0: d0 f5       P.
    ldx usr_address                                                   // 17e2: a6 01       ..
    lda spritex,x                                                     // 17e4: bd a2 02    ...
    and #7                                                            // 17e7: 29 07       ).
    tay                                                               // 17e9: a8          .
    beq c17fd                                                         // 17ea: f0 11       ..
// $17ec referenced 1 time by $17fb
loop_c17ec
    ldx #0                                                            // 17ec: a2 00       ..
// $17ee referenced 1 time by $17f8
loop_c17ee
    clc                                                               // 17ee: 18          .
    ror tape_buffer+32,x                                              // 17ef: 7e 5c 03    ...
    ror tape_buffer+40,x                                              // 17f2: 7e 64 03    ...
    inx                                                               // 17f5: e8          .
    cpx #8                                                            // 17f6: e0 08       ..
    bne loop_c17ee                                                    // 17f8: d0 f4       P.
    dey                                                               // 17fa: 88          .
    bne loop_c17ec                                                    // 17fb: d0 ef       P.
// $17fd referenced 1 time by $17ea
c17fd
    sty free_zero_page                                                // 17fd: 84 fb       ..
// $17ff referenced 1 time by $1843
c17ff
    lda usr_address                                                   // 17ff: a5 01       ..
    clc                                                               // 1801: 18          .
    adc free_zero_page                                                // 1802: 65 fb       ..
    tax                                                               // 1804: aa          .
    lda #$1c                                                          // 1805: a9 1c       ..
    sta basic_int_to_float_vector+1                                   // 1807: 85 06       ..
    lda saveback,x                                                    // 1809: bd dd 02    ...
    cmp #$80                                                          // 180c: c9 80       I.
    bcc c1814                                                         // 180e: 90 04       ..
    ldy #$80                                                          // 1810: a0 80       ..
    sty basic_int_to_float_vector+1                                   // 1812: 84 06       ..
// $1814 referenced 1 time by $180e
c1814
    and #$1f                                                          // 1814: 29 1f       ).
    asl                                                               // 1816: 0a          .
    asl                                                               // 1817: 0a          .
    asl                                                               // 1818: 0a          .
    sta basic_int_to_float_vector                                     // 1819: 85 05       ..
    lda saveback,x                                                    // 181b: bd dd 02    ...
    and #$60                                                          // 181e: 29 60       ).
    lsr                                                               // 1820: 4a          j
    lsr                                                               // 1821: 4a          j
    lsr                                                               // 1822: 4a          j
    lsr                                                               // 1823: 4a          j
    lsr                                                               // 1824: 4a          j
    clc                                                               // 1825: 18          .
    adc basic_int_to_float_vector+1                                   // 1826: 65 06       ..
    sta basic_int_to_float_vector+1                                   // 1828: 85 06       ..
    ldy #0                                                            // 182a: a0 00       ..
    lda free_zero_page                                                // 182c: a5 fb       ..
    asl                                                               // 182e: 0a          .
    asl                                                               // 182f: 0a          .
    asl                                                               // 1830: 0a          .
    tax                                                               // 1831: aa          .
// $1832 referenced 1 time by $183b
loop_c1832
    lda (basic_int_to_float_vector),y                                 // 1832: b1 05       ..
    sta tape_buffer+48,x                                              // 1834: 9d 6c 03    ...
    inx                                                               // 1837: e8          .
    iny                                                               // 1838: c8          H
    cpy #8                                                            // 1839: c0 08       ..
    bne loop_c1832                                                    // 183b: d0 f5       P.
    inc free_zero_page                                                // 183d: e6 fb       ..
    lda free_zero_page                                                // 183f: a5 fb       ..
    cmp #2                                                            // 1841: c9 02       I.
    bne c17ff                                                         // 1843: d0 ba       P.
    ldy #0                                                            // 1845: a0 00       ..
    lda usr_address+1                                                 // 1847: a5 02       ..
    asl                                                               // 1849: 0a          .
    tax                                                               // 184a: aa          .
// $184b referenced 1 time by $1858
loop_c184b
    lda tape_buffer+32,y                                              // 184b: b9 5c 03    ...
    ora tape_buffer+48,y                                              // 184e: 19 6c 03    ...
    sta l1c00,x                                                       // 1851: 9d 00 1c    ...
    inx                                                               // 1854: e8          .
    iny                                                               // 1855: c8          H
    cpy #$10                                                          // 1856: c0 10       ..
    bne loop_c184b                                                    // 1858: d0 f1       P.
    rts                                                               // 185a: 60          .

// $185b referenced 1 time by $16b6
sub_c185b
    lda usr_address                                                   // 185b: a5 01       ..
    ldy #0                                                            // 185d: a0 00       ..
    sta (rs232_input_buffer_ptr),y                                    // 185f: 91 f7       ..
    ldx usr_jmp                                                       // 1861: a6 00       ..
    lda spriteclr,x                                                   // 1863: bd b2 02    ...
    sta (free_zero_page+1),y                                          // 1866: 91 fc       ..
    ldx usr_address                                                   // 1868: a6 01       ..
    lda spritex,x                                                     // 186a: bd a2 02    ...
    and #7                                                            // 186d: 29 07       ).
    bne c1878                                                         // 186f: d0 07       P.
    lda spritey,x                                                     // 1871: bd a3 02    ...
    and #7                                                            // 1874: 29 07       ).
    beq return_4                                                      // 1876: f0 08       ..
// $1878 referenced 1 time by $186f
c1878
    lda (free_zero_page+1),y                                          // 1878: b1 fc       ..
    sta (free_zero_page+3),y                                          // 187a: 91 fe       ..
    inx                                                               // 187c: e8          .
    txa                                                               // 187d: 8a          .
    sta (rs232_output_buffer_ptr),y                                   // 187e: 91 f9       ..
// $1880 referenced 1 time by $1876
return_4
    rts                                                               // 1880: 60          .

irq_handler
    lda screen_memory+220                                             // 1881: ad dc 1e    ...
    cmp #$c5 // 'E'                                                   // 1884: c9 c5       IE
    bne c188d                                                         // 1886: d0 05       P.
    lda #9                                                            // 1888: a9 09       ..
    sta colour_ram+220                                                // 188a: 8d dc 96    ...
// $188d referenced 1 time by $1886
c188d
    lda jiffy_clock+2                                                 // 188d: a5 a2       ..
    and #7                                                            // 188f: 29 07       ).
    bne c18c7                                                         // 1891: d0 34       P4
    lda ppilltimer                                                    // 1893: a5 10       ..
    beq c18c7                                                         // 1895: f0 30       .0
    cmp #$1f                                                          // 1897: c9 1f       I.
    bcs c18b3                                                         // 1899: b0 18       ..
    and #3                                                            // 189b: 29 03       ).
    bne c18b3                                                         // 189d: d0 14       P.
    ldy #4                                                            // 189f: a0 04       ..
// $18a1 referenced 1 time by $18b1
loop_c18a1
    lda spriteimg1,y                                                  // 18a1: b9 ba 02    ...
    cmp #$80                                                          // 18a4: c9 80       I.
    bne c18b0                                                         // 18a6: d0 08       P.
    lda spriteclr,y                                                   // 18a8: b9 b2 02    ...
    eor #7                                                            // 18ab: 49 07       i.
    sta spriteclr,y                                                   // 18ad: 99 b2 02    ...
// $18b0 referenced 1 time by $18a6
c18b0
    dey                                                               // 18b0: 88          .
    bne loop_c18a1                                                    // 18b1: d0 ee       P.
// $18b3 referenced 2 times by $1899, $189d
c18b3
    dec ppilltimer                                                    // 18b3: c6 10       F.
    bne c18c7                                                         // 18b5: d0 10       P.
    ldy #4                                                            // 18b7: a0 04       ..
// $18b9 referenced 1 time by $18c5
loop_c18b9
    lda l1c50,y                                                       // 18b9: b9 50 1c    .p.
    sta spriteclr,y                                                   // 18bc: 99 b2 02    ...
    lda #$78                                                          // 18bf: a9 78       ..
    sta spriteimg1,y                                                  // 18c1: 99 ba 02    ...
    dey                                                               // 18c4: 88          .
    bne loop_c18b9                                                    // 18c5: d0 f2       P.
// $18c7 referenced 3 times by $1891, $1895, $18b5
c18c7
    lda flashpill                                                     // 18c7: a5 46       .f
    cmp #$1e                                                          // 18c9: c9 1e       I.
    bne c18ea                                                         // 18cb: d0 1d       P.
    ldx #0                                                            // 18cd: a2 00       ..
    stx flashpill                                                     // 18cf: 86 46       .f
// $18d1 referenced 1 time by $18dd
loop_c18d1
    lda l1cf8,x                                                       // 18d1: bd f8 1c    ...
    eor character_rom+648,x                                           // 18d4: 5d 88 82    ]..
    sta l1cf8,x                                                       // 18d7: 9d f8 1c    ...
    inx                                                               // 18da: e8          .
    cpx #8                                                            // 18db: e0 08       ..
    bne loop_c18d1                                                    // 18dd: d0 f2       P.
    lda #$fe                                                          // 18df: a9 fe       ..
    eor l1d7f                                                         // 18e1: 4d 7f 1d    m..
    sta l1d7f                                                         // 18e4: 8d 7f 1d    ...
    sta l1d87                                                         // 18e7: 8d 87 1d    ...
// $18ea referenced 1 time by $18cb
c18ea
    inc flashpill                                                     // 18ea: e6 46       .f
    lda lives                                                         // 18ec: a5 45       .e
    bne c1911                                                         // 18ee: d0 21       P!
    lda jiffy_clock+2                                                 // 18f0: a5 a2       ..
    and #3                                                            // 18f2: 29 03       ).
    beq c1911                                                         // 18f4: f0 1b       ..
    clc                                                               // 18f6: 18          .
    adc jiffy_clock+1                                                 // 18f7: 65 a1       ..
    and #3                                                            // 18f9: 29 03       ).
    beq c1911                                                         // 18fb: f0 14       ..
    inc demoqman                                                      // 18fd: e6 48       .h
    lda demoqman                                                      // 18ff: a5 48       .h
    and #3                                                            // 1901: 29 03       ).
    asl                                                               // 1903: 0a          .
    tay                                                               // 1904: a8          .
    lda l1c5d,y                                                       // 1905: b9 5d 1c    .].
    sta spritex                                                       // 1908: 8d a2 02    ...
    lda l1c5e,y                                                       // 190b: b9 5e 1c    ...
    sta spritey                                                       // 190e: 8d a3 02    ...
// $1911 referenced 3 times by $18ee, $18f4, $18fb
c1911
    ldx #0                                                            // 1911: a2 00       ..
// $1913 referenced 1 time by $1920
loop_c1913
    lda l1a06,x                                                       // 1913: bd 06 1a    ...
    cmp l1a0f,x                                                       // 1916: dd 0f 1a    ...
    bcc c192f                                                         // 1919: 90 14       ..
    bne c1922                                                         // 191b: d0 05       P.
    inx                                                               // 191d: e8          .
    cpx #6                                                            // 191e: e0 06       ..
    bne loop_c1913                                                    // 1920: d0 f1       P.
// $1922 referenced 1 time by $191b
c1922
    // Copy 6 bytes of memory from l1a06 to l1a0f
    ldx #0                                                            // 1922: a2 00       ..
// $1924 referenced 1 time by $192d
loop_c1924
    lda l1a06,x                                                       // 1924: bd 06 1a    ...
    sta l1a0f,x                                                       // 1927: 9d 0f 1a    ...
    inx                                                               // 192a: e8          .
    cpx #6                                                            // 192b: e0 06       ..
    bne loop_c1924                                                    // 192d: d0 f5       P.
// $192f referenced 1 time by $1919
c192f
    // Copy 21 bytes of memory from l1a00 to pydis_end
    ldx #$15                                                          // 192f: a2 15       ..
// $1931 referenced 1 time by $1938
loop_c1931
    lda l1a00 - 1,x                                                   // 1931: bd ff 19    ...
    sta pydis_end - 1,x                                               // 1934: 9d ff 1d    ...
    dex                                                               // 1937: ca          J
    bne loop_c1931                                                    // 1938: d0 f7       P.
    ldy points                                                        // 193a: a4 3f       .?
    beq c1957                                                         // 193c: f0 19       ..
// $193e referenced 1 time by $194b
loop_c193e
    ldx digit                                                         // 193e: a6 3e       .>
// $1940 referenced 1 time by $1955
loop_c1940
    lda l1a00,x                                                       // 1940: bd 00 1a    ...
    cmp #$b9                                                          // 1943: c9 b9       I.
    beq c194f                                                         // 1945: f0 08       ..
    inc l1a00,x                                                       // 1947: fe 00 1a    ...
    dey                                                               // 194a: 88          .
    bne loop_c193e                                                    // 194b: d0 f1       P.
    beq c1957                                                         // 194d: f0 08       .. // ALWAYS branch

// $194f referenced 1 time by $1945
c194f
    lda #$b0                                                          // 194f: a9 b0       ..
    sta l1a00,x                                                       // 1951: 9d 00 1a    ...
    dex                                                               // 1954: ca          J
    bne loop_c1940                                                    // 1955: d0 e9       P.
// $1957 referenced 2 times by $193c, $194d
c1957
    sty points                                                        // 1957: 84 3f       .?
    ldx #0                                                            // 1959: a2 00       ..
    ldy #0                                                            // 195b: a0 00       ..
// $195d referenced 1 time by $1981
c195d
    lda penalty,x                                                     // 195d: b5 4b       .k
    bne c197c                                                         // 195f: d0 1b       P.
    lda dots                                                          // 1961: a5 4a       .j
    cmp #$a6                                                          // 1963: c9 a6       I.
    bcs c1970                                                         // 1965: b0 09       ..
    lda l1c55,x                                                       // 1967: bd 55 1c    .u.
    beq c1970                                                         // 196a: f0 04       ..
    cmp jiffy_clock+2                                                 // 196c: c5 a2       E.
    bne c197c                                                         // 196e: d0 0c       P.
// $1970 referenced 2 times by $1965, $196a
c1970
    lda spritex                                                       // 1970: ad a2 02    ...
    sta basic_garbage_step,y                                          // 1973: 99 53 00    .s.
    lda spritey                                                       // 1976: ad a3 02    ...
    sta basic_function_jump,y                                         // 1979: 99 54 00    .t.
// $197c referenced 2 times by $195f, $196e
c197c
    iny                                                               // 197c: c8          H
    iny                                                               // 197d: c8          H
    inx                                                               // 197e: e8          .
    cpx #4                                                            // 197f: e0 04       ..
    bne c195d                                                         // 1981: d0 da       PZ
    lda chewing                                                       // 1983: a5 3d       .=
    beq c198c                                                         // 1985: f0 05       ..
    lda #$91                                                          // 1987: a9 91       ..
    sta vic_voice3_frequency                                          // 1989: 8d 0c 90    ...
// $198c referenced 1 time by $1985
c198c
    lda #0                                                            // 198c: a9 00       ..
    sta chewing                                                       // 198e: 85 3d       .=
    lda vic_voice3_frequency                                          // 1990: ad 0c 90    ...
    beq c19b8                                                         // 1993: f0 23       .#
    lda vic_voice3_frequency                                          // 1995: ad 0c 90    ...
    and #1                                                            // 1998: 29 01       ).
    beq c19af                                                         // 199a: f0 13       ..
    lda vic_voice3_frequency                                          // 199c: ad 0c 90    ...
    clc                                                               // 199f: 18          .
    adc #$10                                                          // 19a0: 69 10       ..
    cmp #$f1                                                          // 19a2: c9 f1       I.
    bcc c19a9                                                         // 19a4: 90 03       ..
    sec                                                               // 19a6: 38          8
    sbc #1                                                            // 19a7: e9 01       ..
// $19a9 referenced 1 time by $19a4
c19a9
    sta vic_voice3_frequency                                          // 19a9: 8d 0c 90    ...
    clc                                                               // 19ac: 18          .
    bcc c19b8                                                         // 19ad: 90 09       .. // ALWAYS branch

// $19af referenced 1 time by $199a
c19af
    lda vic_voice3_frequency                                          // 19af: ad 0c 90    ...
    sec                                                               // 19b2: 38          8
    sbc #$10                                                          // 19b3: e9 10       ..
    sta vic_voice3_frequency                                          // 19b5: 8d 0c 90    ...
// $19b8 referenced 2 times by $1993, $19ad
c19b8
    ldx chomp                                                         // 19b8: a6 3c       .<
    beq c19ca                                                         // 19ba: f0 0e       ..
    lda jiffy_clock+2                                                 // 19bc: a5 a2       ..
    and #1                                                            // 19be: 29 01       ).
    bne c19ca                                                         // 19c0: d0 08       P.
    lda l1c9c,x                                                       // 19c2: bd 9c 1c    ...
    sta vic_voice2_frequency                                          // 19c5: 8d 0b 90    ...
    dec chomp                                                         // 19c8: c6 3c       F<
// $19ca referenced 2 times by $19ba, $19c0
c19ca
    lda extraqman                                                     // 19ca: a5 47       .g
    bne c19e5                                                         // 19cc: d0 17       P.
    lda l1a07                                                         // 19ce: ad 07 1a    ...
    cmp #$b1                                                          // 19d1: c9 b1       I.
    bne c19e5                                                         // 19d3: d0 10       P.
    sta extraqman                                                     // 19d5: 85 47       .g
    ldx lives                                                         // 19d7: a6 45       .e
    lda #$2d // '-'                                                   // 19d9: a9 2d       .-
    sta screen_memory+484,x                                           // 19db: 9d e4 1f    ...
    lda #7                                                            // 19de: a9 07       ..
    sta colour_ram+484,x                                              // 19e0: 9d e4 97    ...
    inc lives                                                         // 19e3: e6 45       .e
// $19e5 referenced 2 times by $19cc, $19d3
c19e5
    jmp kernal_irq_handler                                            // 19e5: 4c bf ea    l.. // The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

// $19e8 referenced 11 times by $10f5, $1113, $123b, $1262, $13a7, $13c9, $13dc, $13e6, $13f0, $1403, $1418
sub_c19e8
    // push A,X onto the stack
    pha                                                               // 19e8: 48          h
    txa                                                               // 19e9: 8a          .
    pha                                                               // 19ea: 48          h
    jsr sub_c168d                                                     // 19eb: 20 8d 16     ..
    // pull A,X from the stack
    pla                                                               // 19ee: 68          .
    tax                                                               // 19ef: aa          .
    pla                                                               // 19f0: 68          .
    clc                                                               // 19f1: 18          .
    adc jiffy_clock+2                                                 // 19f2: 65 a2       ..
// $19f4 referenced 1 time by $19f6
loop_c19f4
    cmp jiffy_clock+2                                                 // 19f4: c5 a2       E.
    bne loop_c19f4                                                    // 19f6: d0 fc       P.
    rts                                                               // 19f8: 60          .

    .byt 0, 0, 0, 0, 0, 0                                             // 19f9: 00 00 00... ...
// $19ff referenced 1 time by $1931
    .byt 0                                                            // 19ff: 00          .
// $1a00 referenced 5 times by $158f, $15fb, $1940, $1947, $1951
l1a00
    .byt $93, $83, $8f, $92, $85, $ba                                 // 1a00: 93 83 8f... ...
// $1a06 referenced 3 times by $10c8, $1913, $1924
l1a06
    .byt $b0                                                          // 1a06: b0          .
// $1a07 referenced 1 time by $19ce
l1a07
    .byt $b0, $b0, $b0, $b0, $b0, $a0, $a0, $a0                       // 1a07: b0 b0 b0... ...
// $1a0f referenced 2 times by $1916, $1927
l1a0f
    .byt $b0, $b2, $b0, $b0, $b0, $b0                                 // 1a0f: b0 b2 b0... ...
    .byt $37, $3a, $3a, $3a, $3a, $3a, $3a, $3a // petscii "7:::::::" // 1a15: 37 3a 3a... 7::
    .byt $3a, $3a, $3d, $3a, $3a, $3a, $3a, $3a // petscii "::=:::::" // 1a1d: 3a 3a 3d... ::=
    .byt $3a, $3a, $3a, $3a, $38, $39 // petscii "::::89"             // 1a25: 3a 3a 3a... :::
    .byt $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $39, $1e, $1e   // 1a2b: 1e 1e 1e... ...
    .byt $1e, $1e, $1e, $1e, $1e, $1e, $1e, $39, $39, $1e, $37, $38   // 1a37: 1e 1e 1e... ...
    .byt $1e                                                          // 1a43: 1e          .
    .byt $37, $3a, $3a, $38 // petscii "7::8"                         // 1a44: 37 3a 3a... 7::
    .byt $1e, $39, $1e                                                // 1a48: 1e 39 1e    .9.
    .byt $37, $3a, $3a, $38 // petscii "7::8"                         // 1a4b: 37 3a 3a... 7::
    .byt $1e, $37, $38, $1e, $39, $39, $1f, $35, $36, $1e             // 1a4f: 1e 37 38... .78
    .byt $35, $3a, $3a, $36 // petscii "5::6"                         // 1a59: 35 3a 3a... 5::
    .byt $1e, $32, $1e                                                // 1a5d: 1e 32 1e    .2.
    .byt $35, $3a, $3a, $36 // petscii "5::6"                         // 1a60: 35 3a 3a... 5::
    .byt $1e, $35, $36, $1f, $39, $39, $1e, $1e, $1e, $1e, $1e, $1e   // 1a64: 1e 35 36... .56
    .byt $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e   // 1a70: 1e 1e 1e... ...
    .byt $1e, $39, $39, $1e, $33, $34, $1e, $31, $1e                  // 1a7c: 1e 39 39... .99
    .byt $33, $3a, $3a, $3d, $3a, $3a, $34 // petscii "3::=::4"       // 1a85: 33 3a 3a... 3::
    .byt $1e, $31, $1e, $33, $34, $1e, $39, $39, $1e, $1e, $1e, $1e   // 1a8c: 1e 31 1e... .1.
    .byt $39, $1e, $1e, $1e, $1e, $39, $1e, $1e, $1e, $1e, $39, $1e   // 1a98: 39 1e 1e... 9..
    .byt $1e, $1e, $1e                                                // 1aa4: 1e 1e 1e    ...
    .byt $39, $35, $3a, $3a, $38 // petscii "95::8"                   // 1aa7: 39 35 3a... 95:
    .byt $1e                                                          // 1aac: 1e          .
    .byt $3b, $3a, $3a, $34, $20, $32, $20, $33 // petscii ";::4 2 3" // 1aad: 3b 3a 3a... ;::
    .byt $3a, $3a, $3c // petscii "::<"                               // 1ab5: 3a 3a 3c    ::<
    .byt $1e                                                          // 1ab8: 1e          .
    .byt $37, $3a, $3a, $36, $20, $20, $20, $39 // petscii "7::6   9" // 1ab9: 37 3a 3a... 7::
    .byt $1e                                                          // 1ac1: 1e          .
    .byt $39, $20, $20, $20, $20, $20, $20, $20 // petscii "9       " // 1ac2: 39 20 20... 9
    .byt $20, $20, $39 // petscii "  9"                               // 1aca: 20 20 39      9
    .byt $1e                                                          // 1acd: 1e          .
    .byt $39, $20, $20, $20, $3a, $3a, $3a, $36 // petscii "9   :::6" // 1ace: 39 20 20... 9
    .byt $1e                                                          // 1ad6: 1e          .
    .byt $32, $20, $37, $3a, $3a, $c5, $3a, $3a // petscii "2 7::E::" // 1ad7: 32 20 37... 2 7
    .byt $38, $20, $32 // petscii "8 2"                               // 1adf: 38 20 32    8 2
    .byt $1e                                                          // 1ae2: 1e          .
// $1ae3 referenced 2 times by $1595, $160c
l1ae3
    .byt $35, $3a, $3a, $3a, $20, $20, $20, $20 // petscii "5:::    " // 1ae3: 35 3a 3a... 5::
    .byt $1e                                                          // 1aeb: 1e          .
    .byt $20, $20, $39, $20, $20, $20, $20, $20 // petscii "  9     " // 1aec: 20 20 39...   9
    .byt $39, $20, $20 // petscii "9  "                               // 1af4: 39 20 20    9
    .byt $1e                                                          // 1af7: 1e          .
    .byt $20, $20, $20, $20, $3a, $3a, $3a, $38 // petscii "    :::8" // 1af8: 20 20 20...
    .byt $1e                                                          // 1b00: 1e          .
    .byt $31, $20, $35, $3a, $3a, $3a, $3a, $3a // petscii "1 5:::::" // 1b01: 31 20 35... 1 5
    .byt $36, $20, $31 // petscii "6 1"                               // 1b09: 36 20 31    6 1
    .byt $1e                                                          // 1b0c: 1e          .
    .byt $37, $3a, $3a, $3a, $20, $20, $20, $39 // petscii "7:::   9" // 1b0d: 37 3a 3a... 7::
    .byt $1e, $39                                                     // 1b15: 1e 39       .9
// $1b17 referenced 1 time by $1cbc
l1b17
    .byt $20, $20, $20, $20, $20, $20, $20, $20 // petscii "        " // 1b17: 20 20 20...
    .byt $20, $39 // petscii " 9"                                     // 1b1f: 20 39        9
    .byt $1e                                                          // 1b21: 1e          .
    .byt $39, $20, $20, $20, $37, $3a, $3a, $36 // petscii "9   7::6" // 1b22: 39 20 20... 9
    .byt $1e                                                          // 1b2a: 1e          .
    .byt $32, $20, $33, $3a, $3a, $3d, $3a, $3a // petscii "2 3::=::" // 1b2b: 32 20 33... 2 3
    .byt $34, $20, $32 // petscii "4 2"                               // 1b33: 34 20 32    4 2
    .byt $1e                                                          // 1b36: 1e          .
    .byt $35, $3a, $3a, $38, $39 // petscii "5::89"                   // 1b37: 35 3a 3a... 5::
    .byt $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $39, $1e, $1e   // 1b3c: 1e 1e 1e... ...
    .byt $1e, $1e, $1e, $1e, $1e, $1e, $1e, $39, $39, $1e, $33, $38   // 1b48: 1e 1e 1e... ...
    .byt $1e                                                          // 1b54: 1e          .
    .byt $33, $3a, $3a, $34 // petscii "3::4"                         // 1b55: 33 3a 3a... 3::
    .byt $1e, $32, $1e                                                // 1b59: 1e 32 1e    .2.
    .byt $33, $3a, $3a, $34 // petscii "3::4"                         // 1b5c: 33 3a 3a... 3::
    .byt $1e, $37, $34, $1e, $39, $39, $1f, $1e, $39, $1e, $1e, $1e   // 1b60: 1e 37 34... .74
    .byt $1e, $1e, $1e, $20, $1e, $1e, $1e, $1e, $1e, $1e, $39, $1e   // 1b6c: 1e 1e 1e... ...
    .byt $1f                                                          // 1b78: 1f          .
    .byt $39, $3b, $34 // petscii "9;4"                               // 1b79: 39 3b 34    9;4
    .byt $1e, $32, $1e, $31, $1e                                      // 1b7c: 1e 32 1e... .2.
    .byt $33, $3a, $3a, $3d, $3a, $3a, $34 // petscii "3::=::4"       // 1b81: 33 3a 3a... 3::
    .byt $1e, $31, $1e, $32, $1e                                      // 1b88: 1e 31 1e... .1.
    .byt $33, $3c, $39 // petscii "3<9"                               // 1b8d: 33 3c 39    3<9
    .byt $1e, $1e, $1e, $1e, $39, $1e, $1e, $1e, $1e, $39, $1e, $1e   // 1b90: 1e 1e 1e... ...
    .byt $1e, $1e, $39, $1e, $1e, $1e, $1e, $39, $39, $1e             // 1b9c: 1e 1e 39... ..9
    .byt $33, $3a, $3a, $3e, $3a, $3a, $34 // petscii "3::>::4"       // 1ba6: 33 3a 3a... 3::
    .byt $1e, $32, $1e                                                // 1bad: 1e 32 1e    .2.
    .byt $33, $3a, $3a, $3e, $3a, $3a, $34 // petscii "3::>::4"       // 1bb0: 33 3a 3a... 3::
    .byt $1e, $39, $39, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e   // 1bb7: 1e 39 39... .99
    .byt $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e, $1e             // 1bc3: 1e 1e 1e... ...
    .byt $39, $35, $3a, $3a, $3a, $3a, $3a, $3a // petscii "95::::::" // 1bcd: 39 35 3a... 95:
    .byt $3a, $3a, $3a, $3a, $3a, $3a, $3a, $3a // petscii "::::::::" // 1bd5: 3a 3a 3a... :::
    .byt $3a, $3a, $3a, $3a, $3a // petscii ":::::"                   // 1bdd: 3a 3a 3a... :::
// $1be2 referenced 1 time by $102e
l1be2
    .byt $36, $3f, $b2, $b0, $b0, $b8, $a0, $92, $88, $95, $92, $93   // 1be2: 36 3f b2... 6?.
    .byt $94, $a0, $a0, $86, $b7, $bd, $90, $8c, $81, $99             // 1bee: 94 a0 a0... ...
// $1bf8 referenced 1 time by $120e
l1bf8
    .byt 1, 3, 5, 7, $0a, $14, $1e, $32                               // 1bf8: 01 03 05... ...
// $1c00 referenced 1 time by $1851
l1c00
    .byt $3e, $7c, $f8, $f0, $f0, $f8, $7c, $3e,   0,   0,   0,   0   // 1c00: 3e 7c f8... >..
    .byt   0,   0,   0,   0, $38, $7c, $fe, $92, $fe, $fe, $fe, $aa   // 1c0c: 00 00 00... ...
    .byt   0,   0,   0,   0,   0,   0,   0,   0, $38, $7c, $fe, $92   // 1c18: 00 00 00... ...
    .byt $fe, $fe, $fe, $aa,   0,   0,   0,   0,   0,   0,   0,   0   // 1c24: fe fe fe... ...
    .byt $38, $7c, $fe, $92, $fe, $fe, $fe, $aa,   0,   0,   0,   0   // 1c30: 38 7c fe... 8..
    .byt   0,   0,   0,   0, $38, $7c, $fe, $92, $fe, $fe, $fe, $aa   // 1c3c: 00 00 00... ...
    .byt   0,   0,   0,   0,   0,   0,   0,   0                       // 1c48: 00 00 00... ...
// $1c50 referenced 2 times by $15a7, $18b9
l1c50
    .byt 7                                                            // 1c50: 07          .
// $1c51 referenced 1 time by $1390
l1c51
    .byt 2, 5, 3, 7                                                   // 1c51: 02 05 03... ...
// $1c55 referenced 3 times by $1396, $1566, $1967
l1c55
    .byt 0, $33, $76, $f9, 2, 3, 2, 0                                 // 1c55: 00 33 76... .3.
// $1c5d referenced 1 time by $1905
l1c5d
    .byt $a0                                                          // 1c5d: a0          .
// $1c5e referenced 1 time by $190b
l1c5e
    .byt $10, 0, $10, $a0, $b8, 0, $b8                                // 1c5e: 10 00 10... ...
// $1c65 referenced 3 times by $107e, $12b9, $15db
l1c65
    .byt $22, $23, $24, $24, $25, $25, $26 // petscii $22, "#$$%%&"   // 1c65: 22 23 24... "#$
    .byt $26, $27, $27, $28, $28, $29 // petscii "&''(()"             // 1c6c: 26 27 27... &''
// $1c72 referenced 4 times by $1084, $113b, $12bf, $15e1
l1c72
    .byt 2, 2, 7, 7, 2, 2, 5, 5, 4, 4, 7, 7, 3                        // 1c72: 02 02 07... ...
// $1c7f referenced 1 time by $1cb0
l1c7f
    .byt $87, $81, $8d, $85, $a0, $8f, $96, $85, $92                  // 1c7f: 87 81 8d... ...
// $1c88 referenced 1 time by $1677
l1c88
    .byt 1                                                            // 1c88: 01          .
// $1c89 referenced 1 time by $1681
l1c89
    .byt 0, 0, 1, $ff, 0                                              // 1c89: 00 00 01... ...
// $1c8e referenced 1 time by $165f
l1c8e
    .byt 0, $ff                                                       // 1c8e: 00 ff       ..
// $1c90 referenced 1 time by $1650
l1c90
    .byt 1, $15                                                       // 1c90: 01 15       ..
// $1c92 referenced 2 times by $10d9, $156b
l1c92
    .byt $50, $88                                                     // 1c92: 50 88       p.
    .byt $50, $48, $50, $58 // petscii "phpx"                         // 1c94: 50 48 50... php
    .byt $60                                                          // 1c98: 60          .
    .byt $58, $40, $58 // petscii "x@x"                               // 1c99: 58 40 58    x@x
// $1c9c referenced 1 time by $19c2
l1c9c
    .byt 0, 0, $c0, $b8, $b0, $a8, $b0, $b8, $c0, $c8                 // 1c9c: 00 00 c0... ...
// $1ca6 referenced 3 times by $169d, $16a5, $16bf
l1ca6
    .byt 1, 2, 4, 8, $10, $20, $40, $80                               // 1ca6: 01 02 04... ... // bitmask

// $1cae referenced 4 times by $1051, $10bf, $1413, $15be
sub_c1cae
    ldx #8                                                            // 1cae: a2 08       ..
// $1cb0 referenced 1 time by $1cc5
loop_c1cb0
    lda l1c7f,x                                                       // 1cb0: bd 7f 1c    ...
    cpy #0                                                            // 1cb3: c0 00       ..
    beq c1cb9                                                         // 1cb5: f0 02       ..
    lda #$20 // ' '                                                   // 1cb7: a9 20       .
// $1cb9 referenced 1 time by $1cb5
c1cb9
    sta screen_memory+279,x                                           // 1cb9: 9d 17 1f    ...
    sta l1b17,x                                                       // 1cbc: 9d 17 1b    ...
    lda #2                                                            // 1cbf: a9 02       ..
    sta colour_ram+279,x                                              // 1cc1: 9d 17 97    ...
    dex                                                               // 1cc4: ca          J
    bpl loop_c1cb0                                                    // 1cc5: 10 e9       ..
    rts                                                               // 1cc7: 60          .

// $1cc8 referenced 1 time by $114e
sub_c1cc8
    tay                                                               // 1cc8: a8          .
    tax                                                               // 1cc9: aa          .
// $1cca referenced 2 times by $1ccb, $1cce
c1cca
    inx                                                               // 1cca: e8          .
    bne c1cca                                                         // 1ccb: d0 fd       P.
    dey                                                               // 1ccd: 88          .
    bne c1cca                                                         // 1cce: d0 fa       P.
    tya                                                               // 1cd0: 98          .  // A=0
    rts                                                               // 1cd1: 60          .

    .byt 0, 0, 0, 0, 0, 0, 0, $10, $10, $6c, $10, $10, 0, 0, $10      // 1cd2: 00 00 00... ...
    .byt $44, $28, $c6, $28, $44 // petscii "d(F(d"                   // 1ce1: 44 28 c6... d(F
    .byt $10, 0, $92, $44, 0, $82, 0, $44, $92, 0, 0, 0, 0, $18, $18  // 1ce6: 10 00 92... ...
    .byt   0, 0,   0                                                  // 1cf5: 00 00 00    ...
// $1cf8 referenced 2 times by $18d1, $18d7
l1cf8
    .byt   0, $3c, $7e, $7e, $7e, $7e, $3c,   0,   0,   0,   0,   0   // 1cf8: 00 3c 7e... .<.
    .byt   0,   0,   0,   0, $3c, $7e, $bd, $ff, $bd, $c3, $7e, $3c   // 1d04: 00 00 00... ...
    .byt   4,   8, $18, $24, $62, $f7, $f2, $60, $10, $7c, $fe, $aa   // 1d10: 04 08 18... ...
    .byt $d6, $aa                                                     // 1d1c: d6 aa       V.
    .byt $54, $28, $20 // petscii "t( "                               // 1d1e: 54 28 20    t(
    .byt $10, $7c, $fe, $fe, $fe, $7c, $38,   8, $10, $7c, $fe, $fe   // 1d21: 10 7c fe... ...
    .byt $fe, $7c, $28,   8, $10, $38, $38, $7c, $fe, $fe, $6c, $10   // 1d2d: fe 7c 28... ..(
    .byt $30, $92, $fe, $7c, $38, $10, $28, $10, $38, $7c, $7c, $7c   // 1d39: 30 92 fe... 0..
    .byt $7c, $fe, $10, $18, $24, $18,   8,   8, $18,   8, $18, $3c   // 1d45: 7c fe 10... ...
    .byt $7e, $ff, $ff, $ff, $ff, $7e, $3c, $3e, $7c, $f8, $f0, $f0   // 1d51: 7e ff ff... ...
    .byt $f8, $7c, $3e, $3c, $7e, $ff, $ff, $e7, $c3, $81,   0, $7c   // 1d5d: f8 7c 3e... ..>
    .byt $3e, $1f, $0f, $0f, $1f, $3e, $7c,   0, $81, $c3, $e7, $ff   // 1d69: 3e 1f 0f... >..
    .byt $ff, $7e, $3c, $38, $7c, $fe, $92, $fe, $fe, $fe             // 1d75: ff 7e 3c... ..<
// $1d7f referenced 2 times by $18e1, $18e4
l1d7f
    .byt $aa, $38, $7c, $fe, $92, $fe, $82, $fe                       // 1d7f: aa 38 7c... .8.
// $1d87 referenced 1 time by $18e7
l1d87
    .byt $54, 0, $18                                                  // 1d87: 54 00 18    t..
    .byt $24, $42, $42, $42, $42, $42, $42, $42 // petscii "$bbbbbbb" // 1d8a: 24 42 42... $bb
    .byt $42, $42, $42, $24 // petscii "bbb$"                         // 1d92: 42 42 42... bbb
    .byt $18, 0, 0, $1f                                               // 1d96: 18 00 00... ...
    .byt $20, $40, $40, $20 // petscii " @@ "                         // 1d9a: 20 40 40...  @@
    .byt $1f, 0, 0, $f8, 4, 2, 2, 4, $f8, 0                           // 1d9e: 1f 00 00... ...
    .byt $42, $41, $40, $40, $40, $20 // petscii "ba@@@ "             // 1da8: 42 41 40... ba@
    .byt $1f, 0, $42, $82, 2, 2, 2, 4, $f8, 0, 0, $1f                 // 1dae: 1f 00 42... ..b
    .byt $20, $40, $40, $40, $41, $42 // petscii " @@@ab"             // 1dba: 20 40 40...  @@
    .byt 0, $f8, 4, 2, 2, 2, $82                                      // 1dc0: 00 f8 04... ...
    .byt $42, $42, $42, $42, $42, $42, $42, $42 // petscii "bbbbbbbb" // 1dc7: 42 42 42... bbb
    .byt $42 // petscii "b"                                           // 1dcf: 42          b
    .byt 0, $ff, 0, 0, 0, 0, $ff, 0                                   // 1dd0: 00 ff 00... ...
    .byt $42, $41, $40, $40, $40, $40, $41, $42 // petscii "ba@@@@ab" // 1dd8: 42 41 40... ba@
    .byt $42 // petscii "b"                                           // 1de0: 42          b
    .byt $82,   2,   2,   2, 2, $82, $42, 0, $ff, 0,   0,   0,   0    // 1de1: 82 02 02... ...
    .byt $81, $42, $42, $81, 0,   0,   0, 0, $ff, 0, $3c, $42, $99    // 1dee: 81 42 42... .bb
    .byt $a1, $a1, $99, $42                                           // 1dfb: a1 a1 99... ...
// $1dff referenced 1 time by $1934
    .byt $3c                                                          // 1dff: 3c          <
// $1e00 referenced 1 time by $1592
pydis_end
screen_memory

#if ((irq_handler) & $ff) <> $81
#error Assertion failed: <irq_handler == $81
#endif
#if (((irq_handler) >> 8) & $ff) <> $18
#error Assertion failed: >irq_handler == $18
#endif
#if (basic_end) <> $100b
#error Assertion failed: basic_end == $100b
#endif
#if (l1a00 - 1) <> $19ff
#error Assertion failed: l1a00 - 1 == $19ff
#endif
#if (l1a06) <> $1a06
#error Assertion failed: l1a06 == $1a06
#endif
#if (l1a0f) <> $1a0f
#error Assertion failed: l1a0f == $1a0f
#endif
#if (pydis_end - 1) <> $1dff
#error Assertion failed: pydis_end - 1 == $1dff
#endif
#if (sprite) <> $02a1
#error Assertion failed: sprite == $02a1
#endif
#if (spritelast) <> $02cc
#error Assertion failed: spritelast == $02cc
#endif

// Label references by decreasing frequency:
//     spritex:                       24
//     usr_address:                   21
//     spriteimg1:                    19
//     usr_jmp:                       19
//     spritey:                       18
//     rs232_input_buffer_ptr:        13
//     dots:                          11
//     sprite:                        11
//     sub_c19e8:                     11
//     basic_fn_ptr:                  10
//     fruitlevel:                    10
//     frame:                          9
//     lives:                          9
//     monmove:                        8
//     newdir:                         7
//     qmandir:                        7
//     saveback:                       7
//     vic_voice3_frequency:           7
//     olddir:                         6
//     points:                         6
//     spriteclr:                      6
//     c127b:                          5
//     digit:                          5
//     free_zero_page:                 5
//     l1a00:                          5
//     sub_c168d:                      5
//     basic_float_to_ascii_temp:      4
//     basic_int_to_float_vector:      4
//     c11dc:                          4
//     chewing:                        4
//     chomp:                          4
//     fac1_mantissa:                  4
//     fruitflag:                      4
//     fruittimer:                     4
//     joyval:                         4
//     l1c72:                          4
//     ppillflag:                      4
//     rs232_output_buffer_ptr:        4
//     spriteimg2:                     4
//     sub_c1564:                      4
//     sub_c1cae:                      4
//     c112d:                          3
//     c142f:                          3
//     c1671:                          3
//     c18c7:                          3
//     c1911:                          3
//     extraqman:                      3
//     flashpill:                      3
//     fleeingscore:                   3
//     l1a06:                          3
//     l1c55:                          3
//     l1c65:                          3
//     l1ca6:                          3
//     penalty:                        3
//     ppilltimer:                     3
//     spritelast:                     3
//     sub_c15f9:                      3
//     sub_c161f:                      3
//     vic_background_border_colour:   3
//     c12cb:                          2
//     c12d8:                          2
//     c1309:                          2
//     c1343:                          2
//     c135a:                          2
//     c1361:                          2
//     c141e:                          2
//     c1422:                          2
//     c1476:                          2
//     c1489:                          2
//     c160c:                          2
//     c161b:                          2
//     c16c7:                          2
//     c174a:                          2
//     c1787:                          2
//     c18b3:                          2
//     c1957:                          2
//     c1970:                          2
//     c197c:                          2
//     c19b8:                          2
//     c19ca:                          2
//     c19e5:                          2
//     c1cca:                          2
//     chrout:                         2
//     demoqman:                       2
//     fac2_exponent:                  2
//     getin:                          2
//     l1a0f:                          2
//     l1ae3:                          2
//     l1c50:                          2
//     l1c92:                          2
//     l1cf8:                          2
//     l1d7f:                          2
//     sub_c12a3:                      2
//     sub_c1577:                      2
//     sub_c16dd:                      2
//     sub_c16ee:                      2
//     sub_c1758:                      2
//     via2_data_direction_b:          2
//     vic_vertical_position:          2
//     basic_float_to_int_vector:      1
//     basic_function_jump:            1
//     basic_garbage_step:             1
//     c1048:                          1
//     c1059:                          1
//     c1077:                          1
//     c107e:                          1
//     c1090:                          1
//     c10b0:                          1
//     c10d0:                          1
//     c10d3:                          1
//     c1141:                          1
//     c114c:                          1
//     c114e:                          1
//     c116c:                          1
//     c117b:                          1
//     c1182:                          1
//     c1189:                          1
//     c119a:                          1
//     c11a1:                          1
//     c11ab:                          1
//     c11b4:                          1
//     c11ca:                          1
//     c11e3:                          1
//     c11ed:                          1
//     c1201:                          1
//     c121c:                          1
//     c122c:                          1
//     c1234:                          1
//     c125a:                          1
//     c129a:                          1
//     c12b1:                          1
//     c12b9:                          1
//     c12e2:                          1
//     c12e6:                          1
//     c12fe:                          1
//     c1323:                          1
//     c1326:                          1
//     c1328:                          1
//     c133b:                          1
//     c1356:                          1
//     c13a3:                          1
//     c13c1:                          1
//     c140e:                          1
//     c1448:                          1
//     c144e:                          1
//     c145b:                          1
//     c147f:                          1
//     c14a3:                          1
//     c14a9:                          1
//     c14ad:                          1
//     c14b1:                          1
//     c14cb:                          1
//     c14df:                          1
//     c14fc:                          1
//     c1504:                          1
//     c1516:                          1
//     c151e:                          1
//     c152a:                          1
//     c1536:                          1
//     c154a:                          1
//     c15d1:                          1
//     c15d5:                          1
//     c15db:                          1
//     c15fb:                          1
//     c1628:                          1
//     c163d:                          1
//     c1657:                          1
//     c165c:                          1
//     c1666:                          1
//     c1668:                          1
//     c1691:                          1
//     c16ad:                          1
//     c16bc:                          1
//     c16f3:                          1
//     c16fd:                          1
//     c1718:                          1
//     c1729:                          1
//     c1730:                          1
//     c174f:                          1
//     c176d:                          1
//     c1775:                          1
//     c17ab:                          1
//     c17fd:                          1
//     c17ff:                          1
//     c1814:                          1
//     c1878:                          1
//     c188d:                          1
//     c18b0:                          1
//     c18ea:                          1
//     c1922:                          1
//     c192f:                          1
//     c194f:                          1
//     c195d:                          1
//     c198c:                          1
//     c19a9:                          1
//     c19af:                          1
//     c1cb9:                          1
//     colour_ram:                     1
//     irq_vector:                     1
//     kernal_irq_handler:             1
//     kernal_reset:                   1
//     l02a4:                          1
//     l02a5:                          1
//     l02b3:                          1
//     l02cd:                          1
//     l02ce:                          1
//     l02de:                          1
//     l1a07:                          1
//     l1b17:                          1
//     l1be2:                          1
//     l1bf8:                          1
//     l1c00:                          1
//     l1c51:                          1
//     l1c5d:                          1
//     l1c5e:                          1
//     l1c7f:                          1
//     l1c88:                          1
//     l1c89:                          1
//     l1c8e:                          1
//     l1c90:                          1
//     l1c9c:                          1
//     l1d87:                          1
//     lc377:                          1
//     loop_c102e:                     1
//     loop_c1094:                     1
//     loop_c10c6:                     1
//     loop_c10d9:                     1
//     loop_c10fa:                     1
//     loop_c111a:                     1
//     loop_c1126:                     1
//     loop_c1240:                     1
//     loop_c126a:                     1
//     loop_c126f:                     1
//     loop_c130d:                     1
//     loop_c138b:                     1
//     loop_c13b8:                     1
//     loop_c148d:                     1
//     loop_c1555:                     1
//     loop_c155b:                     1
//     loop_c1566:                     1
//     loop_c158f:                     1
//     loop_c15a7:                     1
//     loop_c15c4:                     1
//     loop_c16d1:                     1
//     loop_c1720:                     1
//     loop_c1746:                     1
//     loop_c1777:                     1
//     loop_c1778:                     1
//     loop_c17ce:                     1
//     loop_c17d7:                     1
//     loop_c17ec:                     1
//     loop_c17ee:                     1
//     loop_c1832:                     1
//     loop_c184b:                     1
//     loop_c18a1:                     1
//     loop_c18b9:                     1
//     loop_c18d1:                     1
//     loop_c1913:                     1
//     loop_c1924:                     1
//     loop_c1931:                     1
//     loop_c193e:                     1
//     loop_c1940:                     1
//     loop_c19f4:                     1
//     loop_c1cb0:                     1
//     pydis_end:                      1
//     return_1:                       1
//     return_2:                       1
//     return_3:                       1
//     return_4:                       1
//     screen_memory:                  1
//     screen_memory_page:             1
//     shift_key_flags:                1
//     sub_c14e8:                      1
//     sub_c16e7:                      1
//     sub_c1790:                      1
//     sub_c17b5:                      1
//     sub_c185b:                      1
//     sub_c1cc8:                      1
//     via1_data_direction_a:          1
//     via1_port_a:                    1
//     via2_port_b:                    1
//     vic_columns:                    1
//     vic_memory_setup:               1
//     vic_rows:                       1
//     vic_voice2_frequency:           1
//     vic_volume_aux_colour:          1

// Automatically generated labels:
//     c1048
//     c1059
//     c1077
//     c107e
//     c1090
//     c10b0
//     c10d0
//     c10d3
//     c112d
//     c1141
//     c114c
//     c114e
//     c116c
//     c117b
//     c1182
//     c1189
//     c119a
//     c11a1
//     c11ab
//     c11b4
//     c11ca
//     c11dc
//     c11e3
//     c11ed
//     c1201
//     c121c
//     c122c
//     c1234
//     c125a
//     c127b
//     c129a
//     c12b1
//     c12b9
//     c12cb
//     c12d8
//     c12e2
//     c12e6
//     c12fe
//     c1309
//     c1323
//     c1326
//     c1328
//     c133b
//     c1343
//     c1356
//     c135a
//     c1361
//     c13a3
//     c13c1
//     c140e
//     c141e
//     c1422
//     c142f
//     c1448
//     c144e
//     c145b
//     c1476
//     c147f
//     c1489
//     c14a3
//     c14a9
//     c14ad
//     c14b1
//     c14cb
//     c14df
//     c14fc
//     c1504
//     c1516
//     c151e
//     c152a
//     c1536
//     c154a
//     c15d1
//     c15d5
//     c15db
//     c15fb
//     c160c
//     c161b
//     c1628
//     c163d
//     c1657
//     c165c
//     c1666
//     c1668
//     c1671
//     c1691
//     c16ad
//     c16bc
//     c16c7
//     c16f3
//     c16fd
//     c1718
//     c1729
//     c1730
//     c174a
//     c174f
//     c176d
//     c1775
//     c1787
//     c17ab
//     c17fd
//     c17ff
//     c1814
//     c1878
//     c188d
//     c18b0
//     c18b3
//     c18c7
//     c18ea
//     c1911
//     c1922
//     c192f
//     c194f
//     c1957
//     c195d
//     c1970
//     c197c
//     c198c
//     c19a9
//     c19af
//     c19b8
//     c19ca
//     c19e5
//     c1cb9
//     c1cca
//     l02a4
//     l02a5
//     l02b3
//     l02cd
//     l02ce
//     l02de
//     l1a00
//     l1a06
//     l1a07
//     l1a0f
//     l1ae3
//     l1b17
//     l1be2
//     l1bf8
//     l1c00
//     l1c50
//     l1c51
//     l1c55
//     l1c5d
//     l1c5e
//     l1c65
//     l1c72
//     l1c7f
//     l1c88
//     l1c89
//     l1c8e
//     l1c90
//     l1c92
//     l1c9c
//     l1ca6
//     l1cf8
//     l1d7f
//     l1d87
//     lc377
//     loop_c102e
//     loop_c1094
//     loop_c10c6
//     loop_c10d9
//     loop_c10fa
//     loop_c111a
//     loop_c1126
//     loop_c1240
//     loop_c126a
//     loop_c126f
//     loop_c130d
//     loop_c138b
//     loop_c13b8
//     loop_c148d
//     loop_c1555
//     loop_c155b
//     loop_c1566
//     loop_c158f
//     loop_c15a7
//     loop_c15c4
//     loop_c16d1
//     loop_c1720
//     loop_c1746
//     loop_c1777
//     loop_c1778
//     loop_c17ce
//     loop_c17d7
//     loop_c17ec
//     loop_c17ee
//     loop_c1832
//     loop_c184b
//     loop_c18a1
//     loop_c18b9
//     loop_c18d1
//     loop_c1913
//     loop_c1924
//     loop_c1931
//     loop_c193e
//     loop_c1940
//     loop_c19f4
//     loop_c1cb0
//     return_1
//     return_2
//     return_3
//     return_4
//     sub_c12a3
//     sub_c14e8
//     sub_c1564
//     sub_c1577
//     sub_c15f9
//     sub_c161f
//     sub_c168d
//     sub_c16dd
//     sub_c16e7
//     sub_c16ee
//     sub_c1758
//     sub_c1790
//     sub_c17b5
//     sub_c185b
//     sub_c19e8
//     sub_c1cae
//     sub_c1cc8

// Stats:
//
//     Total size (Code + Data) = 3583 bytes
//     Code                     = 2576 bytes (72%)
//     Data                     = 1007 bytes (28%)
//
//     Number of instructions   = 1248
//     Number of data bytes     = 688 bytes
//     Number of data words     = 6 bytes
//     Number of string bytes   = 313 bytes
//     Number of strings        = 41

