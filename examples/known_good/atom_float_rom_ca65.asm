; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations

; Zero page ($0000-$00ff)
line_number_low             = $0001
line_number_high            = $0002
parsing_ptr_offset          = $0003
workspace_stack_pointer     = $0004
parsing_ptr_low             = $0005
parsing_ptr_high            = $0006
int_workspace_stack_low     = $0016
sneaky_pointer_low          = $0023
sneaky_pointer_high         = $0024
int_workspace_stack_mid1    = $0025
int_workspace_stack_mid2    = $0034
int_workspace_stack_high    = $0043
output_buffer_low           = $0052
output_buffer_high          = $0053
output_buffer_offset        = $0054
temp_offset                 = $0055
temp_float_exponent_value   = $0056
float8A_sign                = $0057
float8A_overflow            = $0058
float8A_exponent            = $0059
float8A_man1                = $005a
x_coord_low                 = $005a
float8A_man2                = $005b
x_coord_high                = $005b
float8A_man3                = $005c
y_coord_low                 = $005c
float8A_man4                = $005d
y_coord_high                = $005d
float8A_rounding            = $005e
mode_of_operation           = $005e
float8B_sign                = $005f
colour_screen_address_low   = $005f
float8B_overflow            = $0060
colour_screen_address_high  = $0060
float8B_exponent            = $0061
float8B_man1                = $0062
float8B_man2                = $0063
float8B_man3                = $0064
float8B_man4                = $0065
float8B_rounding            = $0066
result_man1                 = $0067
result_man2                 = $0068
result_man3                 = $0069
result_man4                 = $006a
result_rounding             = $006b
number_of_entries           = $006c
power_of_ten_count          = $006d
quadrant                    = $006e
floatptr_low                = $006f
floatptr_high               = $0070
series_low                  = $0071
series_high                 = $0072
flt_is_an_error_flag        = $0073
l0074                       = $0074

; Workspace ($0220-$03ff)
int_variable_at_low             = $0321
float1                          = $03c5
float2                          = $03ca
float3                          = $03cf
float4                          = $03d4
temp_colour_byte                = $03fd
basic_point_plot_routine_low    = $03fe
basic_point_plot_routine_high   = $03ff

; User memory ($2800-$7fff)
floating_point_array_addresses_low  = $2887
floating_point_array_addresses_high = $28a2

; Screen memory ($8000-$97ff)
l8600   = $8600
l8700   = $8700

; Utility ROM ($a000-$afff)
utility_rom = $a000

; I/O ($b000-$bfff)
graphics_mode_byte  = $b000

; BASIC ROM ($c000-$cfff)
basic_verify_comma                                          = $c231
basic_return                                                = $c278
basic_verify_equals                                         = $c279
basic_search_for_apostrophe                                 = $c372
basic_evaluate_numeric_expression                           = $c3c8
basic_read_from_workspace_stack_level_x_to_work_int         = $c3cb
basic_copy_from_workspace_stack_to_zp_y                     = $c3cd
basic_interpreter_alphabetic_pre_test                       = $c434
basic_push_work_int_to_workspace_stack                      = $c4d9
basic_evaluate_numeric_expression_and_verify_end_of_staement = $c4e1
basic_verify_end_of_statement                               = $c4e4
basic_statement_executer                                    = $c54a
basic_verify_end_of_statement_and_continue                  = $c558
basic_move_to_the_following_statement                       = $c55b
basic_if                                                    = $c569
basic_evaluate_expression                                   = $c78b
basic_evaluate_numeric_expression_without_copy_result       = $c8bc
basic_push_zp_y_onto_workspace_stack                        = $c99f
basic_brk_instruction                                       = $ca1b
basic_increment_count_and_print_accumulator                 = $ca4c
basic_until                                                 = $ccd5
basic_keyboard_input                                        = $cd09
basic_check_for_start_of_valid_string                       = $ceb1
basic_interpret_function_into_y                             = $cf3e
basic_pull_y_or_something                                   = $cf41

; DOS ROM ($e000-$efff)
e000_rom_id     = $e004
e000_rom_entry  = $e005

; OS entry points ($ffcb-$fff9)
OSBPUT  = $ffd1
OSBGET  = $ffd4

    .org $d000

; Integer Workspace Stack
; 
; Space for 15 integers striped across zero page:
; 
; &16, &17, &18, &19, &1a, &1b, &1c, &1d, &1e, &1f, &20, &21, &22, &23, &24
; &25, &26, &27, &28, &29, &2a, &2b, &2c, &2d, &2e, &2f, &30, &31, &32, &33
; &34, &35, &36, &37, &38, &39, &3a, &3b, &3c, &3d, &3e, &3f, &40, &41, &42
; &43, &44, &45, &46, &47, &48, &49, &4a, &4b, &4c, &4d, &4e, &4f, &50, &51
; 
; Floating point variables %@ to %Z:
; 
; &2800 = %@
; &2805 = %A
; &280a = %B
; &280f = %C
; &2814 = %D
; &2819 = %E
; &281e = %F
; &2823 = %G
; &2828 = %H
; &282d = %I
; &2832 = %J
; &2837 = %K
; &283c = %L
; &2841 = %M
; &2846 = %N
; &284b = %O
; &2850 = %P
; &2855 = %Q
; &285a = %R
; &285f = %S
; &2864 = %T
; &2869 = %U
; &286e = %V
; &2873 = %W
; &2878 = %X
; &287d = %Y
; &2882 = %Z
; 
; Addresses of floating point arrays:
; 
; &2887 = %@@ address (low byte)
; &2888 = %AA address (low byte)
; &2889 = %BB address (low byte)
; &288a = %CC address (low byte)
; &288b = %DD address (low byte)
; &288c = %EE address (low byte)
; &288d = %FF address (low byte)
; &288e = %GG address (low byte)
; &288f = %HH address (low byte)
; &2890 = %II address (low byte)
; &2891 = %JJ address (low byte)
; &2892 = %KK address (low byte)
; &2893 = %LL address (low byte)
; &2894 = %MM address (low byte)
; &2895 = %NN address (low byte)
; &2896 = %OO address (low byte)
; &2897 = %PP address (low byte)
; &2898 = %QQ address (low byte)
; &2899 = %RR address (low byte)
; &289a = %SS address (low byte)
; &289b = %TT address (low byte)
; &289c = %UU address (low byte)
; &289d = %VV address (low byte)
; &289e = %WW address (low byte)
; &289f = %XX address (low byte)
; &28a0 = %YY address (low byte)
; &28a1 = %ZZ address (low byte)
; 
; &28a2 = %@@ address (high byte)
; &28a3 = %AA address (high byte)
; &28a4 = %BB address (high byte)
; &28a5 = %CC address (high byte)
; &28a6 = %DD address (high byte)
; &28a7 = %EE address (high byte)
; &28a8 = %FF address (high byte)
; &28a9 = %GG address (high byte)
; &28aa = %HH address (high byte)
; &28ab = %II address (high byte)
; &28ac = %JJ address (high byte)
; &28ad = %KK address (high byte)
; &28ae = %LL address (high byte)
; &28af = %MM address (high byte)
; &28b0 = %NN address (high byte)
; &28b1 = %OO address (high byte)
; &28b2 = %PP address (high byte)
; &28b3 = %QQ address (high byte)
; &28b4 = %RR address (high byte)
; &28b5 = %SS address (high byte)
; &28b6 = %TT address (high byte)
; &28b7 = %UU address (high byte)
; &28b8 = %VV address (high byte)
; &28b9 = %WW address (high byte)
; &28ba = %XX address (high byte)
; &28bb = %YY address (high byte)
; &28bc = %ZZ address (high byte)
; 
pydis_start:
    ; Magic word for BASIC to recognise the FP ROM
    .word $55aa                                                       ; d000: aa 55       .U
    ; Entry address for unknown statement
    .word entry_point_unrecognised_statement                          ; d002: 0e d1       ..
    ; Entry address for unknown command
    .word entry_point_unrecognised_command                            ; d004: 5e d1       ^.
keyword_table:
    .byte "("                                                         ; d006: 28          (
    .byte >open_bracket_function                                      ; d007: d0          .
    .byte <open_bracket_function                                      ; d008: e4          .
    .byte "ACS"                                                       ; d009: 41 43 53    ACS
    .byte >acs_function                                               ; d00c: d2          .
    .byte <acs_function                                               ; d00d: 1e          .
    .byte "ASN"                                                       ; d00e: 41 53 4e    ASN
    .byte >asn_function                                               ; d011: d2          .
    .byte <asn_function                                               ; d012: 24          $
    .byte "ATN"                                                       ; d013: 41 54 4e    ATN
    .byte >atn_function                                               ; d016: dc          .
    .byte <atn_function                                               ; d017: 64          d
    .byte "ABS"                                                       ; d018: 41 42 53    ABS
    .byte >abs_function                                               ; d01b: d2          .
    .byte <abs_function                                               ; d01c: 15          .
    .byte "COS"                                                       ; d01d: 43 4f 53    COS
    .byte >cos_function                                               ; d020: dc          .
    .byte <cos_function                                               ; d021: e3          .
    .byte "EXP"                                                       ; d022: 45 58 50    EXP
    .byte >exp_function                                               ; d025: dd          .
    .byte <exp_function                                               ; d026: d4          .
    .byte "HTN"                                                       ; d027: 48 54 4e    HTN
    .byte >htn_function                                               ; d02a: de          .
    .byte <htn_function                                               ; d02b: 72          r
    .byte "LOG"                                                       ; d02c: 4c 4f 47    LOG
    .byte >log_function                                               ; d02f: db          .
    .byte <log_function                                               ; d030: b3          .
    .byte "PI"                                                        ; d031: 50 49       PI
    .byte >pi_function                                                ; d033: d2          .
    .byte <pi_function                                                ; d034: c3          .
    .byte "SIN"                                                       ; d035: 53 49 4e    SIN
    .byte >sin_function                                               ; d038: dc          .
    .byte <sin_function                                               ; d039: ee          .
    .byte "SQR"                                                       ; d03a: 53 51 52    SQR
    .byte >sqr_function                                               ; d03d: db          .
    .byte <sqr_function                                               ; d03e: 6f          o
    .byte "TAN"                                                       ; d03f: 54 41 4e    TAN
    .byte >tan_function                                               ; d042: da          .
    .byte <tan_function                                               ; d043: c4          .
    .byte "DEG"                                                       ; d044: 44 45 47    DEG
    .byte >deg_function                                               ; d047: d2          .
    .byte <deg_function                                               ; d048: 73          s
    .byte "RAD"                                                       ; d049: 52 41 44    RAD
    .byte >rad_function                                               ; d04c: d2          .
    .byte <rad_function                                               ; d04d: 65          e
    .byte "SGN"                                                       ; d04e: 53 47 4e    SGN
    .byte >sgn_function                                               ; d051: d2          .
    .byte <sgn_function                                               ; d052: 86          .
    .byte "VAL"                                                       ; d053: 56 41 4c    VAL
    .byte >val_function                                               ; d056: d2          .
    .byte <val_function                                               ; d057: e0          .
    .byte "FLT"                                                       ; d058: 46 4c 54    FLT
    .byte >flt_function                                               ; d05b: d2          .
    .byte <flt_function                                               ; d05c: 9a          .
    .byte "FGET"                                                      ; d05d: 46 47 45... FGE
    .byte >fget_function                                              ; d061: d2          .
    .byte <fget_function                                              ; d062: cc          .
    .byte >flt_function_or_error                                      ; d063: d2          .
    .byte <flt_function_or_error                                      ; d064: 96          .
floating_point_prefix:
    .byte "%"                                                         ; d065: 25          %
    .byte >percent_function                                           ; d066: d3          .
    .byte <percent_function                                           ; d067: 0b          .
    .byte "FIF"                                                       ; d068: 46 49 46    FIF
    .byte >fif_function                                               ; d06b: d3          .
    .byte <fif_function                                               ; d06c: a8          .
    .byte "FUNTIL"                                                    ; d06d: 46 55 4e... FUN
    .byte >funtil_function                                            ; d073: d3          .
    .byte <funtil_function                                            ; d074: ae          .
    .byte "COLOUR"                                                    ; d075: 43 4f 4c... COL
    .byte >colour_function                                            ; d07b: df          .
    .byte <colour_function                                            ; d07c: 02          .
    .byte "FDIM"                                                      ; d07d: 46 44 49... FDI
    .byte >fdim_function                                              ; d081: d3          .
    .byte <fdim_function                                              ; d082: d3          .
    .byte "STR"                                                       ; d083: 53 54 52    STR
    .byte >str_function                                               ; d086: d3          .
    .byte <str_function                                               ; d087: 1f          .
    .byte "FPRINT"                                                    ; d088: 46 50 52... FPR
    .byte >fprint_function                                            ; d08e: d3          .
    .byte <fprint_function                                            ; d08f: 31          1
    .byte "FINPUT"                                                    ; d090: 46 49 4e... FIN
    .byte >finput_function                                            ; d096: d3          .
    .byte <finput_function                                            ; d097: 6a          j
    .byte "FPUT"                                                      ; d098: 46 50 55... FPU
    .byte >fput_function                                              ; d09c: d3          .
    .byte <fput_function                                              ; d09d: b4          .
    .byte >jump_into_the_e000_rom_or_utility_rom                      ; d09e: d4          .
    .byte <jump_into_the_e000_rom_or_utility_rom                      ; d09f: af          .
keyword_table_add:
    .byte "+"                                                         ; d0a0: 2b          +
    .byte >addition_binary_operator                                   ; d0a1: d1          .
    .byte <addition_binary_operator                                   ; d0a2: 77          w
keyword_table_subtract:
    .byte "-"                                                         ; d0a3: 2d          -
    .byte >subtraction_binary_operator                                ; d0a4: d1          .
    .byte <subtraction_binary_operator                                ; d0a5: 83          .
    .byte $fe                                                         ; d0a6: fe          .
keyword_table_multiply:
    .byte "*"                                                         ; d0a7: 2a          *
    .byte >multiply_operator                                          ; d0a8: d1          .
    .byte <multiply_operator                                          ; d0a9: 8f          .
keyword_table_divide:
    .byte "/"                                                         ; d0aa: 2f          /
    .byte >divide_operator                                            ; d0ab: d1          .
    .byte <divide_operator                                            ; d0ac: 9b          .
    .byte $fe                                                         ; d0ad: fe          .
keyword_table_raise_to_the_power:
    .byte "^"                                                         ; d0ae: 5e          ^
    .byte >raise_to_the_power_operator                                ; d0af: d1          .
    .byte <raise_to_the_power_operator                                ; d0b0: a7          .
    .byte $fe                                                         ; d0b1: fe          .
keyword_table_unary_plus_operator:
    .byte "+"                                                         ; d0b2: 2b          +
    .byte >unary_plus_operator                                        ; d0b3: d1          .
    .byte <unary_plus_operator                                        ; d0b4: cb          .
keyword_table_unary_minus_operator:
    .byte "-"                                                         ; d0b5: 2d          -
    .byte >negate_unary_operator                                      ; d0b6: d1          .
    .byte <negate_unary_operator                                      ; d0b7: bc          .
    .byte >unary_plus_operator                                        ; d0b8: d1          .
    .byte <unary_plus_operator                                        ; d0b9: cb          .
keyword_table_close_bracket:
    .byte ")"                                                         ; d0ba: 29          )
    .byte >basic_return                                               ; d0bb: c2          .
    .byte <basic_return                                               ; d0bc: 78          x
    .byte $ff                                                         ; d0bd: ff          .
keyword_table_semicolon:
    .byte ";"                                                         ; d0be: 3b          ;
    .byte >basic_statement_executer                                   ; d0bf: c5          .
    .byte <basic_statement_executer                                   ; d0c0: 4a          J
keyword_table_cr:
    .byte $0d                                                         ; d0c1: 0d          .
    .byte >basic_statement_executer                                   ; d0c2: c5          .
    .byte <basic_statement_executer                                   ; d0c3: 4a          J
keyword_table_fprint_comma:
    .byte ","                                                         ; d0c4: 2c          ,
    .byte >fprint_function                                            ; d0c5: d3          .
    .byte <fprint_function                                            ; d0c6: 31          1
    .byte $d3, $39                                                    ; d0c7: d3 39       .9
keyword_table_finput_comma:
    .byte ","                                                         ; d0c9: 2c          ,
    .byte >finput_function                                            ; d0ca: d3          .
    .byte <finput_function                                            ; d0cb: 6a          j
    .byte >basic_verify_end_of_statement_and_continue                 ; d0cc: c5          .
    .byte <basic_verify_end_of_statement_and_continue                 ; d0cd: 58          X
keyword_table_equals:
    .byte "="                                                         ; d0ce: 3d          =
    .byte >equals_conditional                                         ; d0cf: d9          .
    .byte <equals_conditional                                         ; d0d0: f6          .
keyword_table_not_equals:
    .byte "<>"                                                        ; d0d1: 3c 3e       <>
    .byte >not_equals_conditional                                     ; d0d3: d9          .
    .byte <not_equals_conditional                                     ; d0d4: fe          .
keyword_table_less_than_or_equal:
    .byte "<="                                                        ; d0d5: 3c 3d       <=
    .byte >less_than_or_equals_conditional                            ; d0d7: d9          .
    .byte <less_than_or_equals_conditional                            ; d0d8: fa          .
keyword_table_less_than:
    .byte "<"                                                         ; d0d9: 3c          <
    .byte >less_than_conditional                                      ; d0da: da          .
    .byte <less_than_conditional                                      ; d0db: 02          .
keyword_table_greater_than_or_equal:
    .byte ">="                                                        ; d0dc: 3e 3d       >=
    .byte >greater_than_or_equal_conditional                          ; d0de: da          .
    .byte <greater_than_or_equal_conditional                          ; d0df: 06          .
keyword_table_greater_than:
    .byte ">"                                                         ; d0e0: 3e          >
    .byte >greater_than_conditional                                   ; d0e1: da          .
    .byte <greater_than_conditional                                   ; d0e2: 0a          .
    .byte $ff                                                         ; d0e3: ff          .

open_bracket_function:
    jsr evaluate_expression_group_4                                   ; d0e4: 20 fc d0     ..
    ldx #keyword_table_close_bracket - keyword_table                  ; d0e7: a2 b4       ..
    bne operator                                                      ; d0e9: d0 20       .  ; ALWAYS branch

evaluate_float_operand:
    ; Group 1, the operands: unary plus, minus and close bracket
    clc                                                               ; d0eb: 18          .
evaluate_operand_but_flt_is_error_if_carry_set:
    ror flt_is_an_error_flag                                          ; d0ec: 66 73       fs
    ldx #keyword_table_unary_plus_operator - keyword_table            ; d0ee: a2 ac       ..
    bne operator                                                      ; d0f0: d0 19       .. ; ALWAYS branch

push_float8A_and_evaluate_expression_group_3:
    jsr push_float8A_onto_workspace_stack                             ; d0f2: 20 5d d8     ].
evaluate_expression_group_3:
    jsr evaluate_expression_group_2                                   ; d0f5: 20 06 d1     ..
cd0f8:
    ldx #keyword_table_multiply - keyword_table                       ; d0f8: a2 a1       ..
    bne operator                                                      ; d0fa: d0 0f       .. ; ALWAYS branch

evaluate_expression_group_4:
    jsr evaluate_expression_group_3                                   ; d0fc: 20 f5 d0     ..
evaluate_expression_group_4_only:
    ldx #keyword_table_add - keyword_table                            ; d0ff: a2 9a       ..
    bne operator                                                      ; d101: d0 08       .. ; ALWAYS branch

push_float8A_and_evaluate_expression_group_2:
    jsr push_float8A_onto_workspace_stack                             ; d103: 20 5d d8     ].
evaluate_expression_group_2:
    jsr evaluate_float_operand                                        ; d106: 20 eb d0     ..
evaluate_expression_group_2_with_operand:
    ldx #keyword_table_raise_to_the_power - keyword_table             ; d109: a2 a8       ..
operator:
    clc                                                               ; d10b: 18          .
    bcc operator_with_carry_allowing_abbreviations                    ; d10c: 90 05       .. ; ALWAYS branch

entry_point_unrecognised_statement:
    ldx #floating_point_prefix - keyword_table                        ; d10e: a2 5f       ._
    sty parsing_ptr_offset                                            ; d110: 84 03       ..
operator_allowing_abbreviations:
    sec                                                               ; d112: 38          8
operator_with_carry_allowing_abbreviations:
    ; flag is set in top bit to allow abbreviations
    ror output_buffer_high                                            ; d113: 66 53       fS
    ldy parsing_ptr_offset                                            ; d115: a4 03       ..
    dey                                                               ; d117: 88          .
skip_spaces_loop:
    iny                                                               ; d118: c8          .
    lda (parsing_ptr_low),y                                           ; d119: b1 05       ..
    cmp #' '                                                          ; d11b: c9 20       .
    beq skip_spaces_loop                                              ; d11d: f0 f9       ..
    dey                                                               ; d11f: 88          .
    sty output_buffer_low                                             ; d120: 84 52       .R
    dex                                                               ; d122: ca          .
compare_against_each_keyword_loop:
    ldy output_buffer_low                                             ; d123: a4 52       .R
compare_character_against_keyword_loop:
    inx                                                               ; d125: e8          .
    iny                                                               ; d126: c8          .
check_for_jump_address:
    lda keyword_table,x                                               ; d127: bd 06 d0    ...
    bmi execute_function_at_address_with_high_byte_A                  ; d12a: 30 1a       0.
    ; Compare character in keyword table (in A) against current character being parsed,
    ; if equal branch back to check the next
    cmp (parsing_ptr_low),y                                           ; d12c: d1 05       ..
    beq compare_character_against_keyword_loop                        ; d12e: f0 f5       ..
    dex                                                               ; d130: ca          .
loop_to_end_of_keyword:
    inx                                                               ; d131: e8          .
    lda keyword_table,x                                               ; d132: bd 06 d0    ...
    bpl loop_to_end_of_keyword                                        ; d135: 10 fa       ..
    inx                                                               ; d137: e8          .
    ; check to see if we allow abbreviations
    bit output_buffer_high                                            ; d138: 24 53       $S
    bpl compare_against_each_keyword_loop                             ; d13a: 10 e7       ..
    ; Check for abbreviation
    lda (parsing_ptr_low),y                                           ; d13c: b1 05       ..
    cmp #'.'                                                          ; d13e: c9 2e       ..
    bne compare_against_each_keyword_loop                             ; d140: d0 e1       ..
    iny                                                               ; d142: c8          .
    dex                                                               ; d143: ca          .
    bcs check_for_jump_address                                        ; d144: b0 e1       .. ; ALWAYS branch

execute_function_at_address_with_high_byte_A:
    cmp #$fe                                                          ; d146: c9 fe       ..
    bcs found_end_of_group                                            ; d148: b0 11       ..
    sta output_buffer_high                                            ; d14a: 85 53       .S
    lda keyword_table+1,x                                             ; d14c: bd 07 d0    ...
    sta output_buffer_low                                             ; d14f: 85 52       .R
    sty parsing_ptr_offset                                            ; d151: 84 03       ..
    ldx workspace_stack_pointer                                       ; d153: a6 04       ..
    jmp (output_buffer_low)                                           ; d155: 6c 52 00    lR.

return_with_x_as_workspace_stack_pointer:
    ldx workspace_stack_pointer                                       ; d158: a6 04       ..
    rts                                                               ; d15a: 60          `

found_end_of_group:
    beq return_with_x_as_workspace_stack_pointer                      ; d15b: f0 fb       ..
    ; We found $ff in the table. This is an error.
    brk                                                               ; d15d: 00          .

entry_point_unrecognised_command:
    sty parsing_ptr_offset                                            ; d15e: 84 03       ..
    ; carry is set at this point
    jsr evaluate_operand_but_flt_is_error_if_carry_set                ; d160: 20 ec d0     ..
    jsr convert_float8A_to_integer_in_mantissa                        ; d163: 20 9a d8     ..
    lda float8A_man1                                                  ; d166: a5 5a       .Z
    sta float8B_overflow                                              ; d168: 85 60       .`
    lda float8A_man2                                                  ; d16a: a5 5b       .[
    sta float8B_sign                                                  ; d16c: 85 5f       ._
    lda float8A_man3                                                  ; d16e: a5 5c       .\
    sta float8A_rounding                                              ; d170: 85 5e       .^
    ; Push the four byte integer result onto the workspace stack
    ldy #<float8A_man4                                                ; d172: a0 5d       .]
    jmp basic_push_zp_y_onto_workspace_stack                          ; d174: 4c 9f c9    L..

addition_binary_operator:
    jsr push_float8A_and_evaluate_expression_group_3                  ; d177: 20 f2 d0     ..
    jsr read_floatptr_from_workspace_stack                            ; d17a: 20 70 d8     p.
    jsr add_floatptr_to_float8A                                       ; d17d: 20 3c d9     <.
    jmp evaluate_expression_group_4_only                              ; d180: 4c ff d0    L..

subtraction_binary_operator:
    jsr push_float8A_and_evaluate_expression_group_3                  ; d183: 20 f2 d0     ..
    jsr read_floatptr_from_workspace_stack                            ; d186: 20 70 d8     p.
    jsr float8A_equals_floatptr_minus_float8A                         ; d189: 20 39 d9     9.
    jmp evaluate_expression_group_4_only                              ; d18c: 4c ff d0    L..

multiply_operator:
    jsr push_float8A_and_evaluate_expression_group_2                  ; d18f: 20 03 d1     ..
    jsr read_floatptr_from_workspace_stack                            ; d192: 20 70 d8     p.
    jsr multiply_float8A_by_floatptr                                  ; d195: 20 45 da     E.
    jmp cd0f8                                                         ; d198: 4c f8 d0    L..

divide_operator:
    jsr push_float8A_and_evaluate_expression_group_2                  ; d19b: 20 03 d1     ..
    jsr read_floatptr_from_workspace_stack                            ; d19e: 20 70 d8     p.
    jsr float8A_equals_floatptr_divided_by_float8A                    ; d1a1: 20 b6 da     ..
    jmp cd0f8                                                         ; d1a4: 4c f8 d0    L..

raise_to_the_power_operator:
    jsr sub_cdbb6                                                     ; d1a7: 20 b6 db     ..
    jsr push_float8A_onto_workspace_stack                             ; d1aa: 20 5d d8     ].
    jsr evaluate_float_operand                                        ; d1ad: 20 eb d0     ..
    jsr read_floatptr_from_workspace_stack                            ; d1b0: 20 70 d8     p.
    jsr multiply_float8A_by_floatptr                                  ; d1b3: 20 45 da     E.
    jsr exp_float8A                                                   ; d1b6: 20 d7 dd     ..
    jmp evaluate_expression_group_2_with_operand                      ; d1b9: 4c 09 d1    L..

negate_unary_operator:
    jsr unary_plus_operator                                           ; d1bc: 20 cb d1     ..
invert_float8A_sign_with_zero_check:
    jsr three_way_sign_of_float8A                                     ; d1bf: 20 86 d6     ..
    beq return_1                                                      ; d1c2: f0 06       ..
invert_float8A_sign:
    lda float8A_sign                                                  ; d1c4: a5 57       .W
    eor #$80                                                          ; d1c6: 49 80       I.
    sta float8A_sign                                                  ; d1c8: 85 57       .W
return_1:
    rts                                                               ; d1ca: 60          `

unary_plus_operator:
    ldy parsing_ptr_offset                                            ; d1cb: a4 03       ..
    dey                                                               ; d1cd: 88          .
skip_spaces_loop2:
    iny                                                               ; d1ce: c8          .
    lda (parsing_ptr_low),y                                           ; d1cf: b1 05       ..
    cmp #' '                                                          ; d1d1: c9 20       .
    beq skip_spaces_loop2                                             ; d1d3: f0 f9       ..
    cmp #'%'                                                          ; d1d5: c9 25       .%
    bne cd20b                                                         ; d1d7: d0 32       .2
    inc parsing_ptr_offset                                            ; d1d9: e6 03       ..
    jsr sub_cd444                                                     ; d1db: 20 44 d4     D.
    bcc cd20b                                                         ; d1de: 90 2b       .+
    ldy #$6f                                                          ; d1e0: a0 6f       .o
    jsr basic_copy_from_workspace_stack_to_zp_y                       ; d1e2: 20 cd c3     ..
unpack_from_floatptr_into_float8A:
    ldy #4                                                            ; d1e5: a0 04       ..
    lda #0                                                            ; d1e7: a9 00       ..
    sta float8A_rounding                                              ; d1e9: 85 5e       .^
    sta float8A_overflow                                              ; d1eb: 85 58       .X
    sta float8A_sign                                                  ; d1ed: 85 57       .W
loop_cd1ef:
    lda (floatptr_low),y                                              ; d1ef: b1 6f       .o
    sta float8A_exponent,y                                            ; d1f1: 99 59 00    .Y.
    ora float8A_sign                                                  ; d1f4: 05 57       .W
    sta float8A_sign                                                  ; d1f6: 85 57       .W
    dey                                                               ; d1f8: 88          .
    bpl loop_cd1ef                                                    ; d1f9: 10 f4       ..
    tax                                                               ; d1fb: aa          .
    beq return_2                                                      ; d1fc: f0 09       ..
    lda float8A_man1                                                  ; d1fe: a5 5a       .Z
    sta float8A_sign                                                  ; d200: 85 57       .W
    ora #$80                                                          ; d202: 09 80       ..
    sta float8A_man1                                                  ; d204: 85 5a       .Z
    txa                                                               ; d206: 8a          .
return_2:
    rts                                                               ; d207: 60          `

loop_cd208:
    sty parsing_ptr_offset                                            ; d208: 84 03       ..
    rts                                                               ; d20a: 60          `

cd20b:
    jsr sub_cd5a5                                                     ; d20b: 20 a5 d5     ..
    bcs loop_cd208                                                    ; d20e: b0 f8       ..
    ldx #0                                                            ; d210: a2 00       ..
    jmp operator_allowing_abbreviations                               ; d212: 4c 12 d1    L..

abs_function:
    jsr evaluate_float_operand                                        ; d215: 20 eb d0     ..
    jsr three_way_sign_of_float8A                                     ; d218: 20 86 d6     ..
    bmi invert_float8A_sign                                           ; d21b: 30 a7       0.
    rts                                                               ; d21d: 60          `

acs_function:
    jsr asn_function                                                  ; d21e: 20 24 d2     $.
    jmp half_pi_minus_float8A                                         ; d221: 4c 86 dc    L..

asn_function:
    jsr evaluate_float_operand                                        ; d224: 20 eb d0     ..
    jsr three_way_sign_of_float8A                                     ; d227: 20 86 d6     ..
    bpl cd236                                                         ; d22a: 10 0a       ..
    lda #0                                                            ; d22c: a9 00       ..
    sta float8A_sign                                                  ; d22e: 85 57       .W
    jsr cd236                                                         ; d230: 20 36 d2     6.
    jmp make_float8A_sign_negative                                    ; d233: 4c 75 dc    Lu.

cd236:
    jsr pack_float8A_into_float3_setting_floatptr                     ; d236: 20 2c d8     ,.
    jsr multiply_float8A_by_floatptr                                  ; d239: 20 45 da     E.
    jsr pack_float8A_into_float1_setting_floatptr                     ; d23c: 20 31 d8     1.
    jsr set_float8A_to_one                                            ; d23f: 20 8d de     ..
    jsr subtract_floatptr_from_float8A                                ; d242: 20 33 d9     3.
    jsr sub_cdb72                                                     ; d245: 20 72 db     r.
    jsr three_way_sign_of_float8A                                     ; d248: 20 86 d6     ..
    beq cd25f                                                         ; d24b: f0 12       ..
    jsr pack_float8A_into_float1_setting_floatptr                     ; d24d: 20 31 d8     1.
    jsr point_floatptr_at_float3                                      ; d250: 20 a6 db     ..
    jsr unpack_from_floatptr_into_float8A                             ; d253: 20 e5 d1     ..
    jsr point_floatptr_at_float1                                      ; d256: 20 aa db     ..
    jsr divide_float8A_by_floatptr                                    ; d259: 20 dc da     ..
    jmp atn_internal                                                  ; d25c: 4c 67 dc    Lg.

cd25f:
    jsr prepare_half_pi                                               ; d25f: 20 93 dd     ..
    jmp unpack_from_floatptr_into_float8A                             ; d262: 4c e5 d1    L..

rad_function:
    jsr evaluate_float_operand                                        ; d265: 20 eb d0     ..
    ldy #<degrees_to_radians_constant                                 ; d268: a0 7c       .|
    lda #>degrees_to_radians_constant                                 ; d26a: a9 d2       ..
multiply_float8A_by_constant_at_ay:
    sty floatptr_low                                                  ; d26c: 84 6f       .o
    sta floatptr_high                                                 ; d26e: 85 70       .p
    jmp multiply_float8A_by_floatptr                                  ; d270: 4c 45 da    LE.

deg_function:
    jsr evaluate_float_operand                                        ; d273: 20 eb d0     ..
    ldy #<radians_to_degrees_constant                                 ; d276: a0 81       ..
    lda #>radians_to_degrees_constant                                 ; d278: a9 d2       ..
    bne multiply_float8A_by_constant_at_ay                            ; d27a: d0 f0       .. ; ALWAYS branch

degrees_to_radians_constant:
    .byte $7b, $0e, $fa, $35, $12                                     ; d27c: 7b 0e fa... {..
radians_to_degrees_constant:
    .byte $86, $65, $2e, $e0, $d3                                     ; d281: 86 65 2e... .e.

sgn_function:
    jsr evaluate_float_operand                                        ; d286: 20 eb d0     ..
    jsr three_way_sign_of_float8A                                     ; d289: 20 86 d6     ..
    beq return_3                                                      ; d28c: f0 07       ..
    pha                                                               ; d28e: 48          H
    jsr set_float8A_to_one                                            ; d28f: 20 8d de     ..
    pla                                                               ; d292: 68          h
    sta float8A_sign                                                  ; d293: 85 57       .W
return_3:
    rts                                                               ; d295: 60          `

flt_function_or_error:
    bit flt_is_an_error_flag                                          ; d296: 24 73       $s
    bmi cd2c0                                                         ; d298: 30 26       0&
flt_function:
    jsr basic_evaluate_numeric_expression_without_copy_result         ; d29a: 20 bc c8     ..
    ldy #$5d                                                          ; d29d: a0 5d       .]
    jsr basic_copy_from_workspace_stack_to_zp_y                       ; d29f: 20 cd c3     ..
    sta float8A_man1                                                  ; d2a2: 85 5a       .Z
    lda float8B_sign                                                  ; d2a4: a5 5f       ._
    sta float8A_man2                                                  ; d2a6: 85 5b       .[
    lda float8A_rounding                                              ; d2a8: a5 5e       .^
    sta float8A_man3                                                  ; d2aa: 85 5c       .\
convert_integer_in_mantissa_to_float:
    lda #$a0                                                          ; d2ac: a9 a0       ..
    sta float8A_exponent                                              ; d2ae: 85 59       .Y
    ldy #0                                                            ; d2b0: a0 00       ..
    sty float8A_rounding                                              ; d2b2: 84 5e       .^
    lda float8A_man1                                                  ; d2b4: a5 5a       .Z
    sta float8A_sign                                                  ; d2b6: 85 57       .W
    bpl skip_negate                                                   ; d2b8: 10 03       ..
    jsr negate_float8A_mantissa                                       ; d2ba: 20 d5 d8     ..
skip_negate:
    jmp normalise_float8A                                             ; d2bd: 4c c8 d7    L..

cd2c0:
    jmp basic_brk_instruction                                         ; d2c0: 4c 1b ca    L..

pi_function:
    jsr prepare_half_pi                                               ; d2c3: 20 93 dd     ..
    jsr unpack_from_floatptr_into_float8A                             ; d2c6: 20 e5 d1     ..
    inc float8A_exponent                                              ; d2c9: e6 59       .Y
    rts                                                               ; d2cb: 60          `

fget_function:
    jsr basic_interpret_function_into_y                               ; d2cc: 20 3e cf     >.
    ldx #4                                                            ; d2cf: a2 04       ..
loop_cd2d1:
    jsr OSBGET                                                        ; d2d1: 20 d4 ff     .. ; Read a byte from file Y
    sta float1,x                                                      ; d2d4: 9d c5 03    ... ; A=byte read
    dex                                                               ; d2d7: ca          .
    bpl loop_cd2d1                                                    ; d2d8: 10 f7       ..
unpack_from_float1_into_float8A:
    jsr point_floatptr_at_float1                                      ; d2da: 20 aa db     ..
    jmp unpack_from_floatptr_into_float8A                             ; d2dd: 4c e5 d1    L..

val_function:
    jsr basic_check_for_start_of_valid_string                         ; d2e0: 20 b1 ce     ..
cd2e3:
error2 = cd2e3+1
    ldy #0                                                            ; d2e3: a0 00       ..
; overlapping: brk                                                    ; d2e4: 00          .
    jsr skip_spaces_loop3                                             ; d2e5: 20 04 d3     ..
    cmp #'+'                                                          ; d2e8: c9 2b       .+
    beq cd2fb                                                         ; d2ea: f0 0f       ..
    cmp #'-'                                                          ; d2ec: c9 2d       .-
    bne cd2fe                                                         ; d2ee: d0 0e       ..
    jsr cd303                                                         ; d2f0: 20 03 d3     ..
    sty output_buffer_offset                                          ; d2f3: 84 54       .T
    jsr cd5b1                                                         ; d2f5: 20 b1 d5     ..
    jmp invert_float8A_sign_with_zero_check                           ; d2f8: 4c bf d1    L..

cd2fb:
    jsr cd303                                                         ; d2fb: 20 03 d3     ..
cd2fe:
    sty output_buffer_offset                                          ; d2fe: 84 54       .T
    jmp cd5b1                                                         ; d300: 4c b1 d5    L..

cd303:
    iny                                                               ; d303: c8          .
skip_spaces_loop3:
    lda (output_buffer_low),y                                         ; d304: b1 52       .R
    cmp #' '                                                          ; d306: c9 20       .
    beq cd303                                                         ; d308: f0 f9       ..
    rts                                                               ; d30a: 60          `

percent_function:
    ; The percent function allows the following expression to be calculated in floating
    ; point
    jsr sub_cd444                                                     ; d30b: 20 44 d4     D.
    bcc error2                                                        ; d30e: 90 d4       ..
    jsr basic_verify_equals                                           ; d310: 20 79 c2     y.
    jsr evaluate_expression_group_4                                   ; d313: 20 fc d0     ..
    jsr basic_verify_end_of_statement                                 ; d316: 20 e4 c4     ..
    jsr sub_cd836                                                     ; d319: 20 36 d8     6.
    jmp basic_move_to_the_following_statement                         ; d31c: 4c 5b c5    L[.

str_function:
    jsr evaluate_expression_group_4                                   ; d31f: 20 fc d0     ..
    jsr basic_verify_comma                                            ; d322: 20 31 c2     1.
    jsr basic_evaluate_numeric_expression_and_verify_end_of_staement  ; d325: 20 e1 c4     ..
    jsr basic_read_from_workspace_stack_level_x_to_work_int           ; d328: 20 cb c3     ..
    jsr float8A_to_ascii                                              ; d32b: 20 d0 d4     ..
    jmp basic_move_to_the_following_statement                         ; d32e: 4c 5b c5    L[.

fprint_function:
    jsr basic_search_for_apostrophe                                   ; d331: 20 72 c3     r.
    ldx #keyword_table_semicolon - keyword_table                      ; d334: a2 b8       ..
    jmp operator                                                      ; d336: 4c 0b d1    L..

    jsr evaluate_expression_group_4                                   ; d339: 20 fc d0     ..
    lda #$c5                                                          ; d33c: a9 c5       ..
    sta output_buffer_low                                             ; d33e: 85 52       .R
    lda #3                                                            ; d340: a9 03       ..
    sta output_buffer_high                                            ; d342: 85 53       .S
    jsr float8A_to_ascii                                              ; d344: 20 d0 d4     ..
    dec floatptr_low                                                  ; d347: c6 6f       .o
    lda int_variable_at_low                                           ; d349: ad 21 03    .!.
    sec                                                               ; d34c: 38          8
    sbc floatptr_low                                                  ; d34d: e5 6f       .o
    bcc cd35c                                                         ; d34f: 90 0b       ..
    beq cd35c                                                         ; d351: f0 09       ..
    tay                                                               ; d353: a8          .
    lda #$20                                                          ; d354: a9 20       .
loop_cd356:
    jsr basic_increment_count_and_print_accumulator                   ; d356: 20 4c ca     L.
    dey                                                               ; d359: 88          .
    bne loop_cd356                                                    ; d35a: d0 fa       ..
cd35c:
    ldy #0                                                            ; d35c: a0 00       ..
loop_cd35e:
    lda (output_buffer_low),y                                         ; d35e: b1 52       .R
    cmp #$0d                                                          ; d360: c9 0d       ..
    beq fprint_function                                               ; d362: f0 cd       ..
    jsr basic_increment_count_and_print_accumulator                   ; d364: 20 4c ca     L.
    iny                                                               ; d367: c8          .
    bne loop_cd35e                                                    ; d368: d0 f4       ..
finput_function:
    jsr basic_search_for_apostrophe                                   ; d36a: 20 72 c3     r.
    lda (parsing_ptr_low),y                                           ; d36d: b1 05       ..
    cmp #$25                                                          ; d36f: c9 25       .%
    bne cd37b                                                         ; d371: d0 08       ..
    iny                                                               ; d373: c8          .
    sty parsing_ptr_offset                                            ; d374: 84 03       ..
    jsr sub_cd444                                                     ; d376: 20 44 d4     D.
    bcs cd380                                                         ; d379: b0 05       ..
cd37b:
    ldx #keyword_table_finput_comma - keyword_table                   ; d37b: a2 c3       ..
    jmp operator                                                      ; d37d: 4c 0b d1    L..

cd380:
    jsr basic_keyboard_input                                          ; d380: 20 09 cd     ..
    tay                                                               ; d383: a8          .
    lda parsing_ptr_low                                               ; d384: a5 05       ..
    pha                                                               ; d386: 48          H
    lda parsing_ptr_high                                              ; d387: a5 06       ..
    pha                                                               ; d389: 48          H
    lda parsing_ptr_offset                                            ; d38a: a5 03       ..
    pha                                                               ; d38c: 48          H
    sty parsing_ptr_offset                                            ; d38d: 84 03       ..
    iny                                                               ; d38f: c8          .
    sty parsing_ptr_high                                              ; d390: 84 06       ..
    lda #$40                                                          ; d392: a9 40       .@
    sta parsing_ptr_low                                               ; d394: 85 05       ..
    jsr evaluate_expression_group_4                                   ; d396: 20 fc d0     ..
    pla                                                               ; d399: 68          h
    sta parsing_ptr_offset                                            ; d39a: 85 03       ..
    pla                                                               ; d39c: 68          h
    sta parsing_ptr_high                                              ; d39d: 85 06       ..
    pla                                                               ; d39f: 68          h
    sta parsing_ptr_low                                               ; d3a0: 85 05       ..
    jsr sub_cd836                                                     ; d3a2: 20 36 d8     6.
    jmp cd37b                                                         ; d3a5: 4c 7b d3    L{.

fif_function:
    jsr sub_cd9eb                                                     ; d3a8: 20 eb d9     ..
    jmp basic_if                                                      ; d3ab: 4c 69 c5    Li.

funtil_function:
    jsr sub_cd9eb                                                     ; d3ae: 20 eb d9     ..
    jmp basic_until                                                   ; d3b1: 4c d5 cc    L..

fput_function:
    jsr sub_cd494                                                     ; d3b4: 20 94 d4     ..
    jsr evaluate_expression_group_4                                   ; d3b7: 20 fc d0     ..
    jsr basic_verify_end_of_statement                                 ; d3ba: 20 e4 c4     ..
    jsr pack_float8A_into_float1_setting_floatptr                     ; d3bd: 20 31 d8     1.
    ldx workspace_stack_pointer                                       ; d3c0: a6 04       ..
    jsr basic_pull_y_or_something                                     ; d3c2: 20 41 cf     A.
    ldx #4                                                            ; d3c5: a2 04       ..
loop_cd3c7:
    lda float1,x                                                      ; d3c7: bd c5 03    ...
    jsr OSBPUT                                                        ; d3ca: 20 d1 ff     .. ; Write byte A to file Y
    dex                                                               ; d3cd: ca          .
    bpl loop_cd3c7                                                    ; d3ce: 10 f7       ..
    jmp basic_move_to_the_following_statement                         ; d3d0: 4c 5b c5    L[.

fdim_function:
    lda line_number_low                                               ; d3d3: a5 01       ..
    ora line_number_high                                              ; d3d5: 05 02       ..
    beq dim_error                                                     ; d3d7: f0 6a       .j
    jsr basic_interpreter_alphabetic_pre_test                         ; d3d9: 20 34 c4     4.
    bcs dim_error                                                     ; d3dc: b0 65       .e
    ldy parsing_ptr_offset                                            ; d3de: a4 03       ..
    lda (parsing_ptr_low),y                                           ; d3e0: b1 05       ..
    cmp #'%'                                                          ; d3e2: c9 25       .%
    bne dim_error                                                     ; d3e4: d0 5d       .]
    iny                                                               ; d3e6: c8          .
    lda (parsing_ptr_low),y                                           ; d3e7: b1 05       ..
    iny                                                               ; d3e9: c8          .
    cmp (parsing_ptr_low),y                                           ; d3ea: d1 05       ..
    bne dim_error                                                     ; d3ec: d0 55       .U
    cmp #$5b                                                          ; d3ee: c9 5b       .[
    bcs dim_error                                                     ; d3f0: b0 51       .Q
    sbc #$3f                                                          ; d3f2: e9 3f       .? ; Carry is clear, so subtracting 64
    bcc dim_error                                                     ; d3f4: 90 4d       .M
    iny                                                               ; d3f6: c8          .
    sty parsing_ptr_offset                                            ; d3f7: 84 03       ..
    pha                                                               ; d3f9: 48          H
    jsr basic_evaluate_expression                                     ; d3fa: 20 8b c7     ..
    inc int_workspace_stack_low - 1,x                                 ; d3fd: f6 15       ..
    bne skip1                                                         ; d3ff: d0 02       ..
    inc sneaky_pointer_high,x                                         ; d401: f6 24       .$
skip1:
    jsr sub_cd49a                                                     ; d403: 20 9a d4     ..
    pla                                                               ; d406: 68          h
    tay                                                               ; d407: a8          .
    clc                                                               ; d408: 18          .
    lda sneaky_pointer_low                                            ; d409: a5 23       .#
    sta floating_point_array_addresses_low,y                          ; d40b: 99 87 28    ..(
    adc int_workspace_stack_low                                       ; d40e: 65 16       e.
    sta sneaky_pointer_low                                            ; d410: 85 23       .#
    lda sneaky_pointer_high                                           ; d412: a5 24       .$
    sta floating_point_array_addresses_high,y                         ; d414: 99 a2 28    ..(
    adc int_workspace_stack_mid1                                      ; d417: 65 25       e%
    sta sneaky_pointer_high                                           ; d419: 85 24       .$
    ldy #0                                                            ; d41b: a0 00       ..
    sty workspace_stack_pointer                                       ; d41d: 84 04       ..
    lda #$aa                                                          ; d41f: a9 aa       ..
    sta (sneaky_pointer_low),y                                        ; d421: 91 23       .#
    cmp (sneaky_pointer_low),y                                        ; d423: d1 23       .#
    bne dim_error                                                     ; d425: d0 1c       ..
    lsr                                                               ; d427: 4a          J
    sta (sneaky_pointer_low),y                                        ; d428: 91 23       .#
    cmp (sneaky_pointer_low),y                                        ; d42a: d1 23       .#
    bne dim_error                                                     ; d42c: d0 15       ..
    jsr basic_interpreter_alphabetic_pre_test                         ; d42e: 20 34 c4     4.
    bcs dim_error                                                     ; d431: b0 10       ..
    ldy parsing_ptr_offset                                            ; d433: a4 03       ..
    lda (parsing_ptr_low),y                                           ; d435: b1 05       ..
    cmp #','                                                          ; d437: c9 2c       .,
    bne basic_verify_end_of_statement_and_move_to_the_following_statement_local; d439: d0 05       ..
    inc parsing_ptr_offset                                            ; d43b: e6 03       ..
    jmp fdim_function                                                 ; d43d: 4c d3 d3    L..

basic_verify_end_of_statement_and_move_to_the_following_statement_local:
    jmp basic_verify_end_of_statement_and_continue                    ; d440: 4c 58 c5    LX.

dim_error:
    brk                                                               ; d443: 00          .

sub_cd444:
    jsr basic_interpreter_alphabetic_pre_test                         ; d444: 20 34 c4     4.
    bcc cd457                                                         ; d447: 90 0e       ..
    lda int_workspace_stack_low - 1,x                                 ; d449: b5 15       ..
    asl                                                               ; d44b: 0a          .
    asl                                                               ; d44c: 0a          .
    adc int_workspace_stack_low - 1,x                                 ; d44d: 75 15       u.
    sta int_workspace_stack_low - 1,x                                 ; d44f: 95 15       ..
    lda #$28                                                          ; d451: a9 28       .(
    sta sneaky_pointer_high,x                                         ; d453: 95 24       .$
    sec                                                               ; d455: 38          8
    rts                                                               ; d456: 60          `

cd457:
    ldy parsing_ptr_offset                                            ; d457: a4 03       ..
    lda (parsing_ptr_low),y                                           ; d459: b1 05       ..
    cmp #'!'                                                          ; d45b: c9 21       .!
    bne check_for_array_second_letter_matches_first                   ; d45d: d0 07       ..
    inc parsing_ptr_offset                                            ; d45f: e6 03       ..
    jsr basic_evaluate_numeric_expression_without_copy_result         ; d461: 20 bc c8     ..
cd464:
    sec                                                               ; d464: 38          8
    rts                                                               ; d465: 60          `

check_for_array_second_letter_matches_first:
    iny                                                               ; d466: c8          .
    cmp (parsing_ptr_low),y                                           ; d467: d1 05       ..
    bne variable_not_valid                                            ; d469: d0 08       ..
    cmp #'Z'+1                                                        ; d46b: c9 5b       .[
    bcs variable_not_valid                                            ; d46d: b0 04       ..
    sbc #'@'-1                                                        ; d46f: e9 3f       .? ; Carry is clear, so subtracting 64
    bcs got_valid_array_variable                                      ; d471: b0 02       ..
variable_not_valid:
    clc                                                               ; d473: 18          .
    rts                                                               ; d474: 60          `

got_valid_array_variable:
    iny                                                               ; d475: c8          .
    sty parsing_ptr_offset                                            ; d476: 84 03       ..
    pha                                                               ; d478: 48          H
    jsr basic_evaluate_numeric_expression_without_copy_result         ; d479: 20 bc c8     ..
    jsr sub_cd49a                                                     ; d47c: 20 9a d4     ..
    pla                                                               ; d47f: 68          h
    tay                                                               ; d480: a8          .
    bcs error5                                                        ; d481: b0 10       ..
    lda floating_point_array_addresses_low,y                          ; d483: b9 87 28    ..(
    adc int_workspace_stack_low - 1,x                                 ; d486: 75 15       u.
    sta int_workspace_stack_low - 1,x                                 ; d488: 95 15       ..
    lda floating_point_array_addresses_high,y                         ; d48a: b9 a2 28    ..(
    adc sneaky_pointer_high,x                                         ; d48d: 75 24       u$
    sta sneaky_pointer_high,x                                         ; d48f: 95 24       .$
    bcc cd464                                                         ; d491: 90 d1       ..
error5:
    brk                                                               ; d493: 00          .

sub_cd494:
    jsr basic_evaluate_numeric_expression_without_copy_result         ; d494: 20 bc c8     ..
    jmp basic_verify_comma                                            ; d497: 4c 31 c2    L1.

sub_cd49a:
    ldy sneaky_pointer_high,x                                         ; d49a: b4 24       .$
    lda int_workspace_stack_low - 1,x                                 ; d49c: b5 15       ..
    asl                                                               ; d49e: 0a          .
    rol sneaky_pointer_high,x                                         ; d49f: 36 24       6$
    asl                                                               ; d4a1: 0a          .
    rol sneaky_pointer_high,x                                         ; d4a2: 36 24       6$
    clc                                                               ; d4a4: 18          .
    adc int_workspace_stack_low - 1,x                                 ; d4a5: 75 15       u.
    sta int_workspace_stack_low - 1,x                                 ; d4a7: 95 15       ..
    tya                                                               ; d4a9: 98          .
    adc sneaky_pointer_high,x                                         ; d4aa: 75 24       u$
    sta sneaky_pointer_high,x                                         ; d4ac: 95 24       .$
    rts                                                               ; d4ae: 60          `

jump_into_the_e000_rom_or_utility_rom:
    ; Pass the statement to the ROM at #E000 if it's there (#E004 holds #BF), or else
    ; to the utility ROM if it's there (#A000 holds #40)
    lda e000_rom_id                                                   ; d4af: ad 04 e0    ...
    cmp #$bf                                                          ; d4b2: c9 bf       ..
    beq jump_into_the_e000_rom                                        ; d4b4: f0 0a       ..
    lda utility_rom                                                   ; d4b6: ad 00 a0    ...
    cmp #$40                                                          ; d4b9: c9 40       .@
    bne basic_verify_end_of_statement_and_move_to_the_following_statement_local; d4bb: d0 83       ..
    jmp utility_rom + 2                                               ; d4bd: 4c 02 a0    L..

jump_into_the_e000_rom:
    jmp e000_rom_entry                                                ; d4c0: 4c 05 e0    L..

get_digit:
    cmp #'9'+1                                                        ; d4c3: c9 3a       .:
    bcs digit_not_found                                               ; d4c5: b0 07       ..
    cmp #'0'                                                          ; d4c7: c9 30       .0
    bcc return_4                                                      ; d4c9: 90 02       ..
    sbc #'0'                                                          ; d4cb: e9 30       .0
return_4:
    rts                                                               ; d4cd: 60          `

digit_not_found:
    clc                                                               ; d4ce: 18          .
    rts                                                               ; d4cf: 60          `

float8A_to_ascii:
    lda #0                                                            ; d4d0: a9 00       ..
    sta floatptr_low                                                  ; d4d2: 85 6f       .o
    jsr three_way_sign_of_float8A                                     ; d4d4: 20 86 d6     ..
    bne output_non_zero_float8A                                       ; d4d7: d0 12       ..
    lda #'0'                                                          ; d4d9: a9 30       .0
    jsr append_character_to_string_buffer                             ; d4db: 20 8d d5     ..
    lda #'.'                                                          ; d4de: a9 2e       ..
    jsr append_character_to_string_buffer                             ; d4e0: 20 8d d5     ..
    lda #'0'                                                          ; d4e3: a9 30       .0
    jsr append_character_to_string_buffer                             ; d4e5: 20 8d d5     ..
    jmp output_cr                                                     ; d4e8: 4c 71 d5    Lq.

output_non_zero_float8A:
    bpl output_positive_float8A                                       ; d4eb: 10 05       ..
    lda #'-'                                                          ; d4ed: a9 2d       .-
    jsr append_character_to_string_buffer                             ; d4ef: 20 8d d5     ..
output_positive_float8A:
    ; While less than one, multiply by ten
    lda #0                                                            ; d4f2: a9 00       ..
    sta power_of_ten_count                                            ; d4f4: 85 6d       .m
multiply_by_ten_loop:
    lda float8A_exponent                                              ; d4f6: a5 59       .Y
    cmp #$81                                                          ; d4f8: c9 81       ..
    bcs one_or_more                                                   ; d4fa: b0 08       ..
    jsr multiply_float8A_by_ten                                       ; d4fc: 20 a0 d6     ..
    dec power_of_ten_count                                            ; d4ff: c6 6d       .m
    jmp multiply_by_ten_loop                                          ; d501: 4c f6 d4    L..

one_or_more:
    cmp #$84                                                          ; d504: c9 84       ..
    bcc divide_mantissa_of_float8A_by_two_and_add_one_to_exponent_loop; d506: 90 10       ..
    bne at_least_ten                                                  ; d508: d0 06       ..
    lda float8A_man1                                                  ; d50a: a5 5a       .Z
    cmp #$a0                                                          ; d50c: c9 a0       ..
    bcc divide_mantissa_of_float8A_by_two_and_add_one_to_exponent_loop; d50e: 90 08       ..
at_least_ten:
    jsr divide_float8A_by_ten                                         ; d510: 20 1b d7     ..
    inc power_of_ten_count                                            ; d513: e6 6d       .m
    jmp multiply_by_ten_loop                                          ; d515: 4c f6 d4    L..

divide_mantissa_of_float8A_by_two_and_add_one_to_exponent_loop:
    lda float8A_exponent                                              ; d518: a5 59       .Y
    cmp #$84                                                          ; d51a: c9 84       ..
    bcs round_then_check_for_float8A_ten_or_more                      ; d51c: b0 07       ..
    jsr shift_mantissa_down_one_bit                                   ; d51e: 20 d8 d6     ..
    inc float8A_exponent                                              ; d521: e6 59       .Y
    bne divide_mantissa_of_float8A_by_two_and_add_one_to_exponent_loop; d523: d0 f3       ..
round_then_check_for_float8A_ten_or_more:
    sec                                                               ; d525: 38          8
    lda #$ff                                                          ; d526: a9 ff       ..
    jsr adc_accumulator_to_float8A_mantissa_without_overflow_check    ; d528: 20 36 d6     6.
    lda float8A_man1                                                  ; d52b: a5 5a       .Z
    cmp #$a0                                                          ; d52d: c9 a0       ..
    bcs at_least_ten                                                  ; d52f: b0 df       ..
    lda #1                                                            ; d531: a9 01       ..
    ldy power_of_ten_count                                            ; d533: a4 6d       .m
    bmi cd541                                                         ; d535: 30 0a       0.
    cpy #8                                                            ; d537: c0 08       ..
    bcs cd541                                                         ; d539: b0 06       ..
    iny                                                               ; d53b: c8          .
    lda #0                                                            ; d53c: a9 00       ..
    sta power_of_ten_count                                            ; d53e: 85 6d       .m
    tya                                                               ; d540: 98          .
cd541:
    sta floatptr_high                                                 ; d541: 85 70       .p
    ldx #9                                                            ; d543: a2 09       ..
    stx output_buffer_offset                                          ; d545: 86 54       .T
loop_cd547:
    jsr output_bcd_digit_and_shift_next_digit                         ; d547: 20 75 d5     u.
    dec floatptr_high                                                 ; d54a: c6 70       .p
    bne cd553                                                         ; d54c: d0 05       ..
    lda #'.'                                                          ; d54e: a9 2e       ..
    jsr append_character_to_string_buffer                             ; d550: 20 8d d5     ..
cd553:
    dec output_buffer_offset                                          ; d553: c6 54       .T
    bne loop_cd547                                                    ; d555: d0 f0       ..
    lda power_of_ten_count                                            ; d557: a5 6d       .m
    beq output_cr                                                     ; d559: f0 16       ..
    lda #'E'                                                          ; d55b: a9 45       .E
    jsr append_character_to_string_buffer                             ; d55d: 20 8d d5     ..
    lda power_of_ten_count                                            ; d560: a5 6d       .m
    bpl after_sign_of_exponent_output                                 ; d562: 10 0a       ..
    lda #'-'                                                          ; d564: a9 2d       .-
    jsr append_character_to_string_buffer                             ; d566: 20 8d d5     ..
    sec                                                               ; d569: 38          8
    lda #0                                                            ; d56a: a9 00       ..
    sbc power_of_ten_count                                            ; d56c: e5 6d       .m
after_sign_of_exponent_output:
    jsr output_accumulator                                            ; d56e: 20 87 d5     ..
output_cr:
    lda #$0d                                                          ; d571: a9 0d       ..
    bne append_character_to_string_buffer                             ; d573: d0 18       .. ; ALWAYS branch

output_bcd_digit_and_shift_next_digit:
    lda float8A_man1                                                  ; d575: a5 5a       .Z
    lsr                                                               ; d577: 4a          J
    lsr                                                               ; d578: 4a          J
    lsr                                                               ; d579: 4a          J
    lsr                                                               ; d57a: 4a          J
    jsr output_ascii_digit                                            ; d57b: 20 8b d5     ..
    lda float8A_man1                                                  ; d57e: a5 5a       .Z
    and #$0f                                                          ; d580: 29 0f       ).
    sta float8A_man1                                                  ; d582: 85 5a       .Z
    jmp float8A_mantissa_times_equals_ten                             ; d584: 4c 4e d6    LN.

output_accumulator:
    cmp #10                                                           ; d587: c9 0a       ..
    bcs output_accumulator_ten_or_more                                ; d589: b0 09       ..
output_ascii_digit:
    ora #$30                                                          ; d58b: 09 30       .0
append_character_to_string_buffer:
    ldy floatptr_low                                                  ; d58d: a4 6f       .o
    sta (output_buffer_low),y                                         ; d58f: 91 52       .R
    inc floatptr_low                                                  ; d591: e6 6f       .o
    rts                                                               ; d593: 60          `

output_accumulator_ten_or_more:
    ldx #$ff                                                          ; d594: a2 ff       ..
count_tens_loop:
    inx                                                               ; d596: e8          .
    sbc #10                                                           ; d597: e9 0a       ..
    bcs count_tens_loop                                               ; d599: b0 fb       ..
    adc #10                                                           ; d59b: 69 0a       i.
    ; remember units digit
    pha                                                               ; d59d: 48          H
    txa                                                               ; d59e: 8a          .
    jsr output_accumulator                                            ; d59f: 20 87 d5     ..
    pla                                                               ; d5a2: 68          h
    bpl output_ascii_digit                                            ; d5a3: 10 e6       ..
sub_cd5a5:
    lda parsing_ptr_offset                                            ; d5a5: a5 03       ..
    sta output_buffer_offset                                          ; d5a7: 85 54       .T
    lda parsing_ptr_low                                               ; d5a9: a5 05       ..
    sta output_buffer_low                                             ; d5ab: 85 52       .R
    lda parsing_ptr_high                                              ; d5ad: a5 06       ..
    sta output_buffer_high                                            ; d5af: 85 53       .S
cd5b1:
    jsr zero_float8A                                                  ; d5b1: 20 a4 da     ..
    sta number_of_entries                                             ; d5b4: 85 6c       .l
    sta power_of_ten_count                                            ; d5b6: 85 6d       .m
    jsr get_next_output_buffer_character                              ; d5b8: 20 7b d6     {.
    cmp #$2e                                                          ; d5bb: c9 2e       ..
    beq cd5cd                                                         ; d5bd: f0 0e       ..
    jsr get_digit                                                     ; d5bf: 20 c3 d4     ..
    bcc return_5                                                      ; d5c2: 90 71       .q
    sta float8A_rounding                                              ; d5c4: 85 5e       .^
check_for_decimal_point:
    jsr get_next_output_buffer_character                              ; d5c6: 20 7b d6     {.
    cmp #'.'                                                          ; d5c9: c9 2e       ..
    bne check_for_E                                                   ; d5cb: d0 09       ..
cd5cd:
    lda number_of_entries                                             ; d5cd: a5 6c       .l
    clc                                                               ; d5cf: 18          .
    bne cd60c                                                         ; d5d0: d0 3a       .:
    inc number_of_entries                                             ; d5d2: e6 6c       .l
    bne check_for_decimal_point                                       ; d5d4: d0 f0       ..
check_for_E:
    cmp #'E'                                                          ; d5d6: c9 45       .E
    beq got_exponent_E_character                                      ; d5d8: f0 27       .'
    jsr get_digit                                                     ; d5da: 20 c3 d4     ..
    bcc cd60c                                                         ; d5dd: 90 2d       .-
    sta quadrant                                                      ; d5df: 85 6e       .n
    lda float8A_man1                                                  ; d5e1: a5 5a       .Z
    cmp #$18                                                          ; d5e3: c9 18       ..
    bcc cd5ef                                                         ; d5e5: 90 08       ..
    lda number_of_entries                                             ; d5e7: a5 6c       .l
    bne check_for_decimal_point                                       ; d5e9: d0 db       ..
    inc power_of_ten_count                                            ; d5eb: e6 6d       .m
    bcs check_for_decimal_point                                       ; d5ed: b0 d7       .. ; ALWAYS branch

cd5ef:
    lda number_of_entries                                             ; d5ef: a5 6c       .l
    beq cd5f5                                                         ; d5f1: f0 02       ..
    dec power_of_ten_count                                            ; d5f3: c6 6d       .m
cd5f5:
    jsr float8A_mantissa_times_equals_ten                             ; d5f5: 20 4e d6     N.
    clc                                                               ; d5f8: 18          .
    lda quadrant                                                      ; d5f9: a5 6e       .n
    jsr adc_accumulator_to_float8A_mantissa_without_overflow_check    ; d5fb: 20 36 d6     6.
    jmp check_for_decimal_point                                       ; d5fe: 4c c6 d5    L..

got_exponent_E_character:
    jsr get_next_output_buffer_character                              ; d601: 20 7b d6     {.
    jsr get_two_digits_into_accumulator_as_bcd_byte                   ; d604: 20 78 d7     x.
    clc                                                               ; d607: 18          .
    adc power_of_ten_count                                            ; d608: 65 6d       em
    sta power_of_ten_count                                            ; d60a: 85 6d       .m
cd60c:
    lda #$a8                                                          ; d60c: a9 a8       ..
    sta float8A_exponent                                              ; d60e: 85 59       .Y
    jsr three_way_sign_of_float8A                                     ; d610: 20 86 d6     ..
    beq cd631                                                         ; d613: f0 1c       ..
    jsr normalise_float8A                                             ; d615: 20 c8 d7     ..
    lda power_of_ten_count                                            ; d618: a5 6d       .m
    bmi divide_by_ten_until_power_of_ten_count_becomes_zero           ; d61a: 30 0b       0.
    beq cd62e                                                         ; d61c: f0 10       ..
loop_cd61e:
    jsr multiply_float8A_by_ten                                       ; d61e: 20 a0 d6     ..
    dec power_of_ten_count                                            ; d621: c6 6d       .m
    bne loop_cd61e                                                    ; d623: d0 f9       ..
    beq cd62e                                                         ; d625: f0 07       .. ; ALWAYS branch

divide_by_ten_until_power_of_ten_count_becomes_zero:
    jsr divide_float8A_by_ten                                         ; d627: 20 1b d7     ..
    inc power_of_ten_count                                            ; d62a: e6 6d       .m
    bne divide_by_ten_until_power_of_ten_count_becomes_zero           ; d62c: d0 f9       ..
cd62e:
    jsr apply_rounding_and_overflow                                   ; d62e: 20 9b da     ..
cd631:
    sec                                                               ; d631: 38          8
    ldy output_buffer_offset                                          ; d632: a4 54       .T
    dey                                                               ; d634: 88          .
return_5:
    rts                                                               ; d635: 60          `

adc_accumulator_to_float8A_mantissa_without_overflow_check:
    ldx #5                                                            ; d636: a2 05       ..
loop_cd638:
    adc float8A_man1 - 1,x                                            ; d638: 75 59       uY
    sta float8A_man1 - 1,x                                            ; d63a: 95 59       .Y
    lda #0                                                            ; d63c: a9 00       ..
    dex                                                               ; d63e: ca          .
    bne loop_cd638                                                    ; d63f: d0 f7       ..
    rts                                                               ; d641: 60          `

adc_mantissa8B_to_mantissa8A:
    ldx #5                                                            ; d642: a2 05       ..
copy_mantissa_loop3:
    lda float8A_man1 - 1,x                                            ; d644: b5 59       .Y
    adc float8B_man1 - 1,x                                            ; d646: 75 61       ua
    sta float8A_man1 - 1,x                                            ; d648: 95 59       .Y
    dex                                                               ; d64a: ca          .
    bne copy_mantissa_loop3                                           ; d64b: d0 f7       ..
    rts                                                               ; d64d: 60          `

float8A_mantissa_times_equals_ten:
    ldx #5                                                            ; d64e: a2 05       ..
    lda #0                                                            ; d650: a9 00       ..
    sta result_man1                                                   ; d652: 85 67       .g
times_ten_loop:
    lda #0                                                            ; d654: a9 00       ..
    sta result_man2                                                   ; d656: 85 68       .h
    lda float8A_man1 - 1,x                                            ; d658: b5 59       .Y
    asl                                                               ; d65a: 0a          .
    rol result_man2                                                   ; d65b: 26 68       &h
    asl                                                               ; d65d: 0a          .
    rol result_man2                                                   ; d65e: 26 68       &h
    clc                                                               ; d660: 18          .
    adc float8A_man1 - 1,x                                            ; d661: 75 59       uY
    bcc skip2                                                         ; d663: 90 02       ..
    inc result_man2                                                   ; d665: e6 68       .h
skip2:
    asl                                                               ; d667: 0a          .
    rol result_man2                                                   ; d668: 26 68       &h
    clc                                                               ; d66a: 18          .
    adc result_man1                                                   ; d66b: 65 67       eg
    bcc skip3                                                         ; d66d: 90 02       ..
    inc result_man2                                                   ; d66f: e6 68       .h
skip3:
    sta float8A_man1 - 1,x                                            ; d671: 95 59       .Y
    lda result_man2                                                   ; d673: a5 68       .h
    sta result_man1                                                   ; d675: 85 67       .g
    dex                                                               ; d677: ca          .
    bne times_ten_loop                                                ; d678: d0 da       ..
    rts                                                               ; d67a: 60          `

get_next_output_buffer_character:
    sty temp_offset                                                   ; d67b: 84 55       .U
    ldy output_buffer_offset                                          ; d67d: a4 54       .T
    lda (output_buffer_low),y                                         ; d67f: b1 52       .R
    ldy temp_offset                                                   ; d681: a4 55       .U
    inc output_buffer_offset                                          ; d683: e6 54       .T
    rts                                                               ; d685: 60          `

three_way_sign_of_float8A:
    lda float8A_man1                                                  ; d686: a5 5a       .Z
    ora float8A_man2                                                  ; d688: 05 5b       .[
    ora float8A_man3                                                  ; d68a: 05 5c       .\
    ora float8A_man4                                                  ; d68c: 05 5d       .]
    ora float8A_rounding                                              ; d68e: 05 5e       .^
    beq zero_float8A_sign_exponent_and_overflow1                      ; d690: f0 07       ..
    lda float8A_sign                                                  ; d692: a5 57       .W
    bne return_6                                                      ; d694: d0 09       ..
    lda #1                                                            ; d696: a9 01       ..
    rts                                                               ; d698: 60          `

zero_float8A_sign_exponent_and_overflow1:
    sta float8A_sign                                                  ; d699: 85 57       .W
    sta float8A_exponent                                              ; d69b: 85 59       .Y
    sta float8A_overflow                                              ; d69d: 85 58       .X
return_6:
    rts                                                               ; d69f: 60          `

multiply_float8A_by_ten:
    clc                                                               ; d6a0: 18          .
    lda float8A_exponent                                              ; d6a1: a5 59       .Y
    adc #3                                                            ; d6a3: 69 03       i.
    sta float8A_exponent                                              ; d6a5: 85 59       .Y
    bcc skip4                                                         ; d6a7: 90 02       ..
    inc float8A_overflow                                              ; d6a9: e6 58       .X
skip4:
    jsr set_float8B_equal_to_float8A                                  ; d6ab: 20 c3 d6     ..
    jsr halve_float8B_mantissa                                        ; d6ae: 20 fb d6     ..
    jsr halve_float8B_mantissa                                        ; d6b1: 20 fb d6     ..
add_mantissa8B_to_mantissa8A_fixing_exponent_and_overflow:
    jsr adc_mantissa8B_to_mantissa8A                                  ; d6b4: 20 42 d6     B.
fix_float8A_exponent_and_overflow:
    bcc return_7                                                      ; d6b7: 90 09       ..
    jsr shift_mantissa_down_one_bit                                   ; d6b9: 20 d8 d6     ..
    inc float8A_exponent                                              ; d6bc: e6 59       .Y
    bne return_7                                                      ; d6be: d0 02       ..
    inc float8A_overflow                                              ; d6c0: e6 58       .X
return_7:
    rts                                                               ; d6c2: 60          `

set_float8B_equal_to_float8A:
    ldx #8                                                            ; d6c3: a2 08       ..
copy_float_loop:
    lda float8A_sign - 1,x                                            ; d6c5: b5 56       .V
    sta float8B_sign - 1,x                                            ; d6c7: 95 5e       .^
    dex                                                               ; d6c9: ca          .
    bne copy_float_loop                                               ; d6ca: d0 f9       ..
    rts                                                               ; d6cc: 60          `

shift_mantissa_up_one_bit:
    asl float8A_rounding                                              ; d6cd: 06 5e       .^
    rol float8A_man4                                                  ; d6cf: 26 5d       &]
    rol float8A_man3                                                  ; d6d1: 26 5c       &\
    rol float8A_man2                                                  ; d6d3: 26 5b       &[
    rol float8A_man1                                                  ; d6d5: 26 5a       &Z
    rts                                                               ; d6d7: 60          `

shift_mantissa_down_one_bit:
    ror float8A_man1                                                  ; d6d8: 66 5a       fZ
    ror float8A_man2                                                  ; d6da: 66 5b       f[
    ror float8A_man3                                                  ; d6dc: 66 5c       f\
    ror float8A_man4                                                  ; d6de: 66 5d       f]
    ror float8A_rounding                                              ; d6e0: 66 5e       f^
    rts                                                               ; d6e2: 60          `

shift_mantissa_down_eight_bits:
    lda float8A_man4                                                  ; d6e3: a5 5d       .]
    sta float8A_rounding                                              ; d6e5: 85 5e       .^
    lda float8A_man3                                                  ; d6e7: a5 5c       .\
    sta float8A_man4                                                  ; d6e9: 85 5d       .]
    lda float8A_man2                                                  ; d6eb: a5 5b       .[
    sta float8A_man3                                                  ; d6ed: 85 5c       .\
    lda float8A_man1                                                  ; d6ef: a5 5a       .Z
    sta float8A_man2                                                  ; d6f1: 85 5b       .[
    lda #0                                                            ; d6f3: a9 00       ..
    sta float8A_man1                                                  ; d6f5: 85 5a       .Z
    rts                                                               ; d6f7: 60          `

float8B_equals_half_float8A:
    jsr set_float8B_equal_to_float8A                                  ; d6f8: 20 c3 d6     ..
halve_float8B_mantissa:
    lsr float8B_man1                                                  ; d6fb: 46 62       Fb
    ror float8B_man2                                                  ; d6fd: 66 63       fc
    ror float8B_man3                                                  ; d6ff: 66 64       fd
    ror float8B_man4                                                  ; d701: 66 65       fe
    ror float8B_rounding                                              ; d703: 66 66       ff
    rts                                                               ; d705: 60          `

    .byte $a5, $65, $85, $66, $a5, $64, $85, $65, $a5, $63, $85, $64  ; d706: a5 65 85... .e.
    .byte $a5, $62, $85, $63, $a9,   0, $85, $62, $60                 ; d712: a5 62 85... .b.

divide_float8A_by_ten:
    sec                                                               ; d71b: 38          8
    lda float8A_exponent                                              ; d71c: a5 59       .Y
    sbc #4                                                            ; d71e: e9 04       ..
    sta float8A_exponent                                              ; d720: 85 59       .Y
    bcs skip5                                                         ; d722: b0 02       ..
    dec float8A_overflow                                              ; d724: c6 58       .X
skip5:
    jsr float8B_equals_half_float8A                                   ; d726: 20 f8 d6     ..
    jsr add_mantissa8B_to_mantissa8A_fixing_exponent_and_overflow     ; d729: 20 b4 d6     ..
    jsr float8B_equals_half_float8A                                   ; d72c: 20 f8 d6     ..
    jsr halve_float8B_mantissa                                        ; d72f: 20 fb d6     ..
    jsr halve_float8B_mantissa                                        ; d732: 20 fb d6     ..
    jsr halve_float8B_mantissa                                        ; d735: 20 fb d6     ..
    jsr add_mantissa8B_to_mantissa8A_fixing_exponent_and_overflow     ; d738: 20 b4 d6     ..
    lda #0                                                            ; d73b: a9 00       ..
    sta float8B_man1                                                  ; d73d: 85 62       .b
    lda float8A_man1                                                  ; d73f: a5 5a       .Z
    sta float8B_man2                                                  ; d741: 85 63       .c
    lda float8A_man2                                                  ; d743: a5 5b       .[
    sta float8B_man3                                                  ; d745: 85 64       .d
    lda float8A_man3                                                  ; d747: a5 5c       .\
    sta float8B_man4                                                  ; d749: 85 65       .e
    lda float8A_man4                                                  ; d74b: a5 5d       .]
    sta float8B_rounding                                              ; d74d: 85 66       .f
    lda float8A_rounding                                              ; d74f: a5 5e       .^
    rol                                                               ; d751: 2a          *
    jsr add_mantissa8B_to_mantissa8A_fixing_exponent_and_overflow     ; d752: 20 b4 d6     ..
    lda #0                                                            ; d755: a9 00       ..
    sta float8B_man1                                                  ; d757: 85 62       .b
    sta float8B_man2                                                  ; d759: 85 63       .c
    lda float8A_man1                                                  ; d75b: a5 5a       .Z
    sta float8B_man3                                                  ; d75d: 85 64       .d
    lda float8A_man2                                                  ; d75f: a5 5b       .[
    sta float8B_man4                                                  ; d761: 85 65       .e
    lda float8A_man3                                                  ; d763: a5 5c       .\
    sta float8B_rounding                                              ; d765: 85 66       .f
    lda float8A_man4                                                  ; d767: a5 5d       .]
    rol                                                               ; d769: 2a          *
    jsr add_mantissa8B_to_mantissa8A_fixing_exponent_and_overflow     ; d76a: 20 b4 d6     ..
    lda float8A_man2                                                  ; d76d: a5 5b       .[
    rol                                                               ; d76f: 2a          *
    lda float8A_man1                                                  ; d770: a5 5a       .Z
adc_accumulator_to_float8A_mantissa:
    jsr adc_accumulator_to_float8A_mantissa_without_overflow_check    ; d772: 20 36 d6     6.
    jmp fix_float8A_exponent_and_overflow                             ; d775: 4c b7 d6    L..

get_two_digits_into_accumulator_as_bcd_byte:
    ; Get sign in Y $ff for non-negative, $00 for negative
    ldy #$ff                                                          ; d778: a0 ff       ..
    cmp #'+'                                                          ; d77a: c9 2b       .+
    beq done_sign                                                     ; d77c: f0 05       ..
    cmp #'-'                                                          ; d77e: c9 2d       .-
    bne get_first_digit                                               ; d780: d0 04       ..
    iny                                                               ; d782: c8          .  ; Y=0
done_sign:
    jsr get_next_output_buffer_character                              ; d783: 20 7b d6     {.
get_first_digit:
    jsr get_digit                                                     ; d786: 20 c3 d4     ..
    bcc no_number_found                                               ; d789: 90 24       .$
    tax                                                               ; d78b: aa          .
    ; Get second digit
    jsr get_next_output_buffer_character                              ; d78c: 20 7b d6     {.
    jsr get_digit                                                     ; d78f: 20 c3 d4     ..
    bcc apply_sign                                                    ; d792: 90 10       ..
    ; remember second digit
    sta quadrant                                                      ; d794: 85 6e       .n
    jsr get_next_output_buffer_character                              ; d796: 20 7b d6     {.
    txa                                                               ; d799: 8a          .
    ; multiply A by ten
    sta result_man1                                                   ; d79a: 85 67       .g
    asl                                                               ; d79c: 0a          .
    asl                                                               ; d79d: 0a          .
    adc result_man1                                                   ; d79e: 65 67       eg
    asl                                                               ; d7a0: 0a          .
    ; add second digit
    adc quadrant                                                      ; d7a1: 65 6e       en
    tax                                                               ; d7a3: aa          .
apply_sign:
    tya                                                               ; d7a4: 98          .
    bne no_sign_change_needed                                         ; d7a5: d0 06       ..
    ; A=0 here
    stx quadrant                                                      ; d7a7: 86 6e       .n
    sec                                                               ; d7a9: 38          8
    sbc quadrant                                                      ; d7aa: e5 6e       .n
    rts                                                               ; d7ac: 60          `

no_sign_change_needed:
    txa                                                               ; d7ad: 8a          .
    rts                                                               ; d7ae: 60          `

no_number_found:
    lda #0                                                            ; d7af: a9 00       ..
return_8:
    rts                                                               ; d7b1: 60          `

set_float8A_to_the_accumulator:
    pha                                                               ; d7b2: 48          H
    jsr zero_float8A                                                  ; d7b3: 20 a4 da     ..
    pla                                                               ; d7b6: 68          h
    beq return_8                                                      ; d7b7: f0 f8       ..
    bpl save_mantissa                                                 ; d7b9: 10 07       ..
    sta float8A_sign                                                  ; d7bb: 85 57       .W
    lda #0                                                            ; d7bd: a9 00       ..
    sec                                                               ; d7bf: 38          8
    sbc float8A_sign                                                  ; d7c0: e5 57       .W
save_mantissa:
    sta float8A_man1                                                  ; d7c2: 85 5a       .Z
    lda #$88                                                          ; d7c4: a9 88       ..
    sta float8A_exponent                                              ; d7c6: 85 59       .Y
normalise_float8A:
    jsr three_way_sign_of_float8A                                     ; d7c8: 20 86 d6     ..
    beq return_8                                                      ; d7cb: f0 e4       ..
normalise_by_bytes_loop:
    lda float8A_man1                                                  ; d7cd: a5 5a       .Z
    bne normalise_by_bits_loop                                        ; d7cf: d0 21       .!
    lda float8A_man2                                                  ; d7d1: a5 5b       .[
    sta float8A_man1                                                  ; d7d3: 85 5a       .Z
    lda float8A_man3                                                  ; d7d5: a5 5c       .\
    sta float8A_man2                                                  ; d7d7: 85 5b       .[
    lda float8A_man4                                                  ; d7d9: a5 5d       .]
    sta float8A_man3                                                  ; d7db: 85 5c       .\
    lda float8A_rounding                                              ; d7dd: a5 5e       .^
    sta float8A_man4                                                  ; d7df: 85 5d       .]
    lda #0                                                            ; d7e1: a9 00       ..
    sta float8A_rounding                                              ; d7e3: 85 5e       .^
    sec                                                               ; d7e5: 38          8
    lda float8A_exponent                                              ; d7e6: a5 59       .Y
    sbc #8                                                            ; d7e8: e9 08       ..
    sta float8A_exponent                                              ; d7ea: 85 59       .Y
    bcs normalise_by_bytes_loop                                       ; d7ec: b0 df       ..
    dec float8A_overflow                                              ; d7ee: c6 58       .X
    bcc normalise_by_bytes_loop                                       ; d7f0: 90 db       .. ; ALWAYS branch

normalise_by_bits_loop:
    lda float8A_man1                                                  ; d7f2: a5 5a       .Z
    bmi return_8                                                      ; d7f4: 30 bb       0.
    jsr shift_mantissa_up_one_bit                                     ; d7f6: 20 cd d6     ..
    lda float8A_exponent                                              ; d7f9: a5 59       .Y
    bne skip6                                                         ; d7fb: d0 02       ..
    dec float8A_overflow                                              ; d7fd: c6 58       .X
skip6:
    dec float8A_exponent                                              ; d7ff: c6 59       .Y
    jmp normalise_by_bits_loop                                        ; d801: 4c f2 d7    L..

unpack_from_floatptr_into_float8B:
    ldy #4                                                            ; d804: a0 04       ..
    lda #0                                                            ; d806: a9 00       ..
    sta float8B_rounding                                              ; d808: 85 66       .f
    sta float8B_overflow                                              ; d80a: 85 60       .`
    sta float8B_sign                                                  ; d80c: 85 5f       ._
unpack_loop:
    lda (floatptr_low),y                                              ; d80e: b1 6f       .o
    sta float8B_exponent,y                                            ; d810: 99 61 00    .a.
    ora float8B_sign                                                  ; d813: 05 5f       ._
    sta float8B_sign                                                  ; d815: 85 5f       ._
    dey                                                               ; d817: 88          .
    bpl unpack_loop                                                   ; d818: 10 f4       ..
    tax                                                               ; d81a: aa          .
    beq return_9                                                      ; d81b: f0 09       ..
    lda float8B_man1                                                  ; d81d: a5 62       .b
    sta float8B_sign                                                  ; d81f: 85 5f       ._
    ora #$80                                                          ; d821: 09 80       ..
    sta float8B_man1                                                  ; d823: 85 62       .b
    txa                                                               ; d825: 8a          .
return_9:
    rts                                                               ; d826: 60          `

pack_float8A_into_float2_setting_floatptr:
    jsr point_floatptr_at_float2                                      ; d827: 20 a2 db     ..
    bne pack_float8A_into_floatptr                                    ; d82a: d0 11       ..
pack_float8A_into_float3_setting_floatptr:
    jsr point_floatptr_at_float3                                      ; d82c: 20 a6 db     ..
    bne pack_float8A_into_floatptr                                    ; d82f: d0 0c       ..
pack_float8A_into_float1_setting_floatptr:
    jsr point_floatptr_at_float1                                      ; d831: 20 aa db     ..
    bne pack_float8A_into_floatptr                                    ; d834: d0 07       ..
sub_cd836:
    ldx workspace_stack_pointer                                       ; d836: a6 04       ..
    ldy #$6f                                                          ; d838: a0 6f       .o
    jsr basic_copy_from_workspace_stack_to_zp_y                       ; d83a: 20 cd c3     ..
pack_float8A_into_floatptr:
    ldy #0                                                            ; d83d: a0 00       ..
    lda float8A_exponent                                              ; d83f: a5 59       .Y
    sta (floatptr_low),y                                              ; d841: 91 6f       .o
    iny                                                               ; d843: c8          .  ; Y=1
    lda float8A_sign                                                  ; d844: a5 57       .W
    and #$80                                                          ; d846: 29 80       ).
    sta float8A_sign                                                  ; d848: 85 57       .W
    lda float8A_man1                                                  ; d84a: a5 5a       .Z
    and #$7f                                                          ; d84c: 29 7f       ).
    ora float8A_sign                                                  ; d84e: 05 57       .W
    sta (floatptr_low),y                                              ; d850: 91 6f       .o
loop_cd852:
    iny                                                               ; d852: c8          .
    lda float8A_exponent,y                                            ; d853: b9 59 00    .Y.
    sta (floatptr_low),y                                              ; d856: 91 6f       .o
    cpy #4                                                            ; d858: c0 04       ..
    bne loop_cd852                                                    ; d85a: d0 f6       ..
    rts                                                               ; d85c: 60          `

push_float8A_onto_workspace_stack:
    ldy #$52                                                          ; d85d: a0 52       .R
    sty floatptr_low                                                  ; d85f: 84 6f       .o
    lda #0                                                            ; d861: a9 00       ..
    sta floatptr_high                                                 ; d863: 85 70       .p
    jsr pack_float8A_into_floatptr                                    ; d865: 20 3d d8     =.
    jsr basic_push_work_int_to_workspace_stack                        ; d868: 20 d9 c4     ..
    lda temp_float_exponent_value                                     ; d86b: a5 56       .V
    sta flt_is_an_error_flag,x                                        ; d86d: 95 73       .s
    rts                                                               ; d86f: 60          `

read_floatptr_from_workspace_stack:
    ldx workspace_stack_pointer                                       ; d870: a6 04       ..
    jsr basic_read_from_workspace_stack_level_x_to_work_int           ; d872: 20 cb c3     ..
    lda l0074,x                                                       ; d875: b5 74       .t
    sta temp_float_exponent_value                                     ; d877: 85 56       .V
    sty floatptr_low                                                  ; d879: 84 6f       .o
    lda #0                                                            ; d87b: a9 00       ..
    sta floatptr_high                                                 ; d87d: 85 70       .p
    rts                                                               ; d87f: 60          `

apply_rounding:
    lda float8A_rounding                                              ; d880: a5 5e       .^
    cmp #$80                                                          ; d882: c9 80       ..
    bcc zero_rounding_byte                                            ; d884: 90 07       ..
    beq midpoint_round_mantissa                                       ; d886: f0 0a       ..
    lda #$ff                                                          ; d888: a9 ff       ..
    jsr adc_accumulator_to_float8A_mantissa                           ; d88a: 20 72 d7     r.
zero_rounding_byte:
    lda #0                                                            ; d88d: a9 00       ..
    sta float8A_rounding                                              ; d88f: 85 5e       .^
    rts                                                               ; d891: 60          `

midpoint_round_mantissa:
    lda float8A_man4                                                  ; d892: a5 5d       .]
    ora #1                                                            ; d894: 09 01       ..
    sta float8A_man4                                                  ; d896: 85 5d       .]
    bne zero_rounding_byte                                            ; d898: d0 f3       .. ; ALWAYS branch

convert_float8A_to_integer_in_mantissa:
    jsr zero_float8B_bugged                                           ; d89a: 20 c7 d8     ..
    beq shift_float8A_down                                            ; d89d: f0 06       .. ; ALWAYS branch!

shift_down_loop:
    lda float8A_exponent                                              ; d89f: a5 59       .Y
    cmp #128 + 32                                                     ; d8a1: c9 a0       ..
    bcs cd8b9                                                         ; d8a3: b0 14       ..
shift_float8A_down:
    lsr float8A_man1                                                  ; d8a5: 46 5a       FZ
    ror float8A_man2                                                  ; d8a7: 66 5b       f[
    ror float8A_man3                                                  ; d8a9: 66 5c       f\
    ror float8A_man4                                                  ; d8ab: 66 5d       f]
    ror float8B_man1                                                  ; d8ad: 66 62       fb
    ror float8B_man2                                                  ; d8af: 66 63       fc
    ror float8B_man3                                                  ; d8b1: 66 64       fd
    ror float8B_man4                                                  ; d8b3: 66 65       fe
    inc float8A_exponent                                              ; d8b5: e6 59       .Y
    bne shift_down_loop                                               ; d8b7: d0 e6       ..
cd8b9:
    beq apply_sign_to_integer_in_mantissa                             ; d8b9: f0 16       ..
set_float8A_mantissa_to_7fffffff_and_clear_float8B:
    lda #$7f                                                          ; d8bb: a9 7f       ..
    sta float8A_man1                                                  ; d8bd: 85 5a       .Z
    lda #$ff                                                          ; d8bf: a9 ff       ..
    sta float8A_man2                                                  ; d8c1: 85 5b       .[
    sta float8A_man3                                                  ; d8c3: 85 5c       .\
    sta float8A_man4                                                  ; d8c5: 85 5d       .]
    ; Out by one error, it zeroes everything in float8B except the the sign byte, and
    ; mistakenly zeroes result_man1
zero_float8B_bugged:
    ldx #8                                                            ; d8c7: a2 08       ..
    lda #0                                                            ; d8c9: a9 00       ..
zero_float8B_loop:
    sta float8B_overflow - 1,x                                        ; d8cb: 95 5f       ._
    dex                                                               ; d8cd: ca          .
    bne zero_float8B_loop                                             ; d8ce: d0 fb       ..
    rts                                                               ; d8d0: 60          `

apply_sign_to_integer_in_mantissa:
    lda float8A_sign                                                  ; d8d1: a5 57       .W
    bpl return_10                                                     ; d8d3: 10 0c       ..
negate_float8A_mantissa:
    sec                                                               ; d8d5: 38          8
    ldx #4                                                            ; d8d6: a2 04       ..
negate_float8A_loop:
    lda #0                                                            ; d8d8: a9 00       ..
    sbc float8A_exponent,x                                            ; d8da: f5 59       .Y
    sta float8A_exponent,x                                            ; d8dc: 95 59       .Y
    dex                                                               ; d8de: ca          .
    bne negate_float8A_loop                                           ; d8df: d0 f7       ..
return_10:
    rts                                                               ; d8e1: 60          `

sub_cd8e2:
    lda float8B_man1                                                  ; d8e2: a5 62       .b
    bpl return_11                                                     ; d8e4: 10 23       .#
    ldx #4                                                            ; d8e6: a2 04       ..
loop_cd8e8:
    lda #0                                                            ; d8e8: a9 00       ..
    sbc <(float8B_man1 - 1),x                                         ; d8ea: f5 61       .a
    sta <(float8B_man1 - 1),x                                         ; d8ec: 95 61       .a
    dex                                                               ; d8ee: ca          .
    bne loop_cd8e8                                                    ; d8ef: d0 f7       ..
    lda float8A_sign                                                  ; d8f1: a5 57       .W
    eor #$80                                                          ; d8f3: 49 80       I.
    sta float8A_sign                                                  ; d8f5: 85 57       .W
    bpl decrement_float8A_mantissa                                    ; d8f7: 10 11       ..
increment_float8A_mantissa:
    inc float8A_man4                                                  ; d8f9: e6 5d       .]
    bne return_11                                                     ; d8fb: d0 0c       ..
    inc float8A_man3                                                  ; d8fd: e6 5c       .\
    bne return_11                                                     ; d8ff: d0 08       ..
    inc float8A_man2                                                  ; d901: e6 5b       .[
    bne return_11                                                     ; d903: d0 04       ..
    inc float8A_man1                                                  ; d905: e6 5a       .Z
    beq set_float8A_mantissa_to_7fffffff_and_clear_float8B            ; d907: f0 b2       ..
return_11:
    rts                                                               ; d909: 60          `

decrement_float8A_mantissa:
    jsr negate_float8A_mantissa                                       ; d90a: 20 d5 d8     ..
    jsr increment_float8A_mantissa                                    ; d90d: 20 f9 d8     ..
    jmp negate_float8A_mantissa                                       ; d910: 4c d5 d8    L..

copy_float8B_mantissa_to_float8A:
    ldx #5                                                            ; d913: a2 05       ..
copy_mantissa_loop4:
    lda float8B_man1 - 1,x                                            ; d915: b5 61       .a
    sta float8A_man1 - 1,x                                            ; d917: 95 59       .Y
    dex                                                               ; d919: ca          .
    bne copy_mantissa_loop4                                           ; d91a: d0 f9       ..
    ; Set exponent and normalise
    lda #$80                                                          ; d91c: a9 80       ..
    sta float8A_exponent                                              ; d91e: 85 59       .Y
    jmp normalise_float8A                                             ; d920: 4c c8 d7    L..

swap_float8A_and_floatptr:
    jsr unpack_from_floatptr_into_float8B                             ; d923: 20 04 d8     ..
    jsr pack_float8A_into_floatptr                                    ; d926: 20 3d d8     =.
copy_float8B_to_float8A:
    ldx #8                                                            ; d929: a2 08       ..
copy_float8B_loop:
    lda float8B_sign - 1,x                                            ; d92b: b5 5e       .^
    sta float8A_sign - 1,x                                            ; d92d: 95 56       .V
    dex                                                               ; d92f: ca          .
    bne copy_float8B_loop                                             ; d930: d0 f9       ..
return_12:
    rts                                                               ; d932: 60          `

subtract_floatptr_from_float8A:
    jsr float8A_equals_floatptr_minus_float8A                         ; d933: 20 39 d9     9.
    jmp invert_float8A_sign_with_zero_check                           ; d936: 4c bf d1    L..

float8A_equals_floatptr_minus_float8A:
    jsr invert_float8A_sign_with_zero_check                           ; d939: 20 bf d1     ..
add_floatptr_to_float8A:
    jsr unpack_from_floatptr_into_float8B                             ; d93c: 20 04 d8     ..
    beq return_12                                                     ; d93f: f0 f1       ..
add_float8B_to_float8A:
    jsr three_way_sign_of_float8A                                     ; d941: 20 86 d6     ..
    beq copy_float8B_to_float8A                                       ; d944: f0 e3       ..
    lda float8A_exponent                                              ; d946: a5 59       .Y
    cmp float8B_exponent                                              ; d948: c5 61       .a
    beq add_mantissas                                                 ; d94a: f0 26       .&
    bcc shift_float8A_mantissa_bits                                   ; d94c: 90 0f       ..
    sbc float8B_exponent                                              ; d94e: e5 61       .a
    cmp #33                                                           ; d950: c9 21       .!
    bcs return_12                                                     ; d952: b0 de       ..
    tax                                                               ; d954: aa          .
shift_float8B_mantissa_bits_loop:
    jsr halve_float8B_mantissa                                        ; d955: 20 fb d6     ..
    dex                                                               ; d958: ca          .
    bne shift_float8B_mantissa_bits_loop                              ; d959: d0 fa       ..
    beq add_mantissas                                                 ; d95b: f0 15       .. ; ALWAYS branch

shift_float8A_mantissa_bits:
    sec                                                               ; d95d: 38          8
    lda float8B_exponent                                              ; d95e: a5 61       .a
    sbc float8A_exponent                                              ; d960: e5 59       .Y
    cmp #$21                                                          ; d962: c9 21       .!
    bcs copy_float8B_to_float8A                                       ; d964: b0 c3       ..
    tax                                                               ; d966: aa          .
shift_float8A_mantissa_bits_loop:
    clc                                                               ; d967: 18          .
    jsr shift_mantissa_down_one_bit                                   ; d968: 20 d8 d6     ..
    dex                                                               ; d96b: ca          .
    bne shift_float8A_mantissa_bits_loop                              ; d96c: d0 f9       ..
    lda float8B_exponent                                              ; d96e: a5 61       .a
    sta float8A_exponent                                              ; d970: 85 59       .Y
add_mantissas:
    lda float8A_sign                                                  ; d972: a5 57       .W
    eor float8B_sign                                                  ; d974: 45 5f       E_
    bpl add_float8A_and_float8B_mantissas                             ; d976: 10 49       .I
    lda float8A_man1                                                  ; d978: a5 5a       .Z
    cmp float8B_man1                                                  ; d97a: c5 62       .b
    bne subtract_mantissas                                            ; d97c: d0 1b       ..
    lda float8A_man2                                                  ; d97e: a5 5b       .[
    cmp float8B_man2                                                  ; d980: c5 63       .c
    bne subtract_mantissas                                            ; d982: d0 15       ..
    lda float8A_man3                                                  ; d984: a5 5c       .\
    cmp float8B_man3                                                  ; d986: c5 64       .d
    bne subtract_mantissas                                            ; d988: d0 0f       ..
    lda float8A_man4                                                  ; d98a: a5 5d       .]
    cmp float8B_man4                                                  ; d98c: c5 65       .e
    bne subtract_mantissas                                            ; d98e: d0 09       ..
    lda float8A_rounding                                              ; d990: a5 5e       .^
    cmp float8B_rounding                                              ; d992: c5 66       .f
    bne subtract_mantissas                                            ; d994: d0 03       ..
    jmp zero_float8A                                                  ; d996: 4c a4 da    L..

subtract_mantissas:
    bcs float8A_minus_equals_float8B_mantissa                         ; d999: b0 2d       .-
    sec                                                               ; d99b: 38          8
    lda float8B_rounding                                              ; d99c: a5 66       .f
    sbc float8A_rounding                                              ; d99e: e5 5e       .^
    sta float8A_rounding                                              ; d9a0: 85 5e       .^
    lda float8B_man4                                                  ; d9a2: a5 65       .e
    sbc float8A_man4                                                  ; d9a4: e5 5d       .]
    sta float8A_man4                                                  ; d9a6: 85 5d       .]
    lda float8B_man3                                                  ; d9a8: a5 64       .d
    sbc float8A_man3                                                  ; d9aa: e5 5c       .\
    sta float8A_man3                                                  ; d9ac: 85 5c       .\
    lda float8B_man2                                                  ; d9ae: a5 63       .c
    sbc float8A_man2                                                  ; d9b0: e5 5b       .[
    sta float8A_man2                                                  ; d9b2: 85 5b       .[
    lda float8B_man1                                                  ; d9b4: a5 62       .b
    sbc float8A_man1                                                  ; d9b6: e5 5a       .Z
    sta float8A_man1                                                  ; d9b8: 85 5a       .Z
    lda float8B_sign                                                  ; d9ba: a5 5f       ._
    sta float8A_sign                                                  ; d9bc: 85 57       .W
    jmp normalise_round_and_overflow                                  ; d9be: 4c 98 da    L..

add_float8A_and_float8B_mantissas:
    clc                                                               ; d9c1: 18          .
    jsr add_mantissa8B_to_mantissa8A_fixing_exponent_and_overflow     ; d9c2: 20 b4 d6     ..
    jmp apply_rounding_and_overflow                                   ; d9c5: 4c 9b da    L..

float8A_minus_equals_float8B_mantissa:
    sec                                                               ; d9c8: 38          8
    lda float8A_rounding                                              ; d9c9: a5 5e       .^
    sbc float8B_rounding                                              ; d9cb: e5 66       .f
    sta float8A_rounding                                              ; d9cd: 85 5e       .^
    lda float8A_man4                                                  ; d9cf: a5 5d       .]
    sbc float8B_man4                                                  ; d9d1: e5 65       .e
    sta float8A_man4                                                  ; d9d3: 85 5d       .]
    lda float8A_man3                                                  ; d9d5: a5 5c       .\
    sbc float8B_man3                                                  ; d9d7: e5 64       .d
    sta float8A_man3                                                  ; d9d9: 85 5c       .\
    lda float8A_man2                                                  ; d9db: a5 5b       .[
    sbc float8B_man2                                                  ; d9dd: e5 63       .c
    sta float8A_man2                                                  ; d9df: 85 5b       .[
    lda float8A_man1                                                  ; d9e1: a5 5a       .Z
    sbc float8B_man1                                                  ; d9e3: e5 62       .b
    sta float8A_man1                                                  ; d9e5: 85 5a       .Z
    jmp normalise_round_and_overflow                                  ; d9e7: 4c 98 da    L..

    .byte 0                                                           ; d9ea: 00          .

sub_cd9eb:
    jsr evaluate_expression_group_4                                   ; d9eb: 20 fc d0     ..
    lda #$c7                                                          ; d9ee: a9 c7       ..
    pha                                                               ; d9f0: 48          H
    ldx #keyword_table_equals - keyword_table                         ; d9f1: a2 c8       ..
    jmp operator                                                      ; d9f3: 4c 0b d1    L..

equals_conditional:
    lda #$5d                                                          ; d9f6: a9 5d       .]
    bne cda0c                                                         ; d9f8: d0 12       .. ; ALWAYS branch

less_than_or_equals_conditional:
    lda #$66                                                          ; d9fa: a9 66       .f
    bne cda0c                                                         ; d9fc: d0 0e       .. ; ALWAYS branch

not_equals_conditional:
    lda #$6f                                                          ; d9fe: a9 6f       .o
    bne cda0c                                                         ; da00: d0 0a       .. ; ALWAYS branch

less_than_conditional:
    lda #$76                                                          ; da02: a9 76       .v
    bne cda0c                                                         ; da04: d0 06       .. ; ALWAYS branch

greater_than_or_equal_conditional:
    lda #$7d                                                          ; da06: a9 7d       .}
    bne cda0c                                                         ; da08: d0 02       .. ; ALWAYS branch

greater_than_conditional:
    lda #$84                                                          ; da0a: a9 84       ..
cda0c:
    pha                                                               ; da0c: 48          H
    jsr push_float8A_onto_workspace_stack                             ; da0d: 20 5d d8     ].
    jsr evaluate_expression_group_4                                   ; da10: 20 fc d0     ..
    jsr read_floatptr_from_workspace_stack                            ; da13: 20 70 d8     p.
    inc workspace_stack_pointer                                       ; da16: e6 04       ..
    jsr unpack_from_floatptr_into_float8B                             ; da18: 20 04 d8     ..
    lda float8B_sign                                                  ; da1b: a5 5f       ._
    and #$80                                                          ; da1d: 29 80       ).
    sta float8B_sign                                                  ; da1f: 85 5f       ._
    ldy #0                                                            ; da21: a0 00       ..
    lda float8A_sign                                                  ; da23: a5 57       .W
    and #$80                                                          ; da25: 29 80       ).
    cmp float8B_sign                                                  ; da27: c5 5f       ._
    bne cda38                                                         ; da29: d0 0d       ..
    ldx #0                                                            ; da2b: a2 00       ..
loop_cda2d:
    lda float8B_exponent,x                                            ; da2d: b5 61       .a
    cmp float8A_exponent,x                                            ; da2f: d5 59       .Y
    bne cda3d                                                         ; da31: d0 0a       ..
    inx                                                               ; da33: e8          .
    cpx #5                                                            ; da34: e0 05       ..
    bne loop_cda2d                                                    ; da36: d0 f5       ..
cda38:
    php                                                               ; da38: 08          .
    ldx workspace_stack_pointer                                       ; da39: a6 04       ..
    plp                                                               ; da3b: 28          (
return_13:
    rts                                                               ; da3c: 60          `

cda3d:
    ror                                                               ; da3d: 6a          j
    eor float8B_sign                                                  ; da3e: 45 5f       E_
    rol                                                               ; da40: 2a          *
    lda #1                                                            ; da41: a9 01       ..
    bne cda38                                                         ; da43: d0 f3       .. ; ALWAYS branch

multiply_float8A_by_floatptr:
    jsr three_way_sign_of_float8A                                     ; da45: 20 86 d6     ..
    beq return_13                                                     ; da48: f0 f2       ..
    jsr unpack_from_floatptr_into_float8B                             ; da4a: 20 04 d8     ..
    bne multiply_float8A_by_float8B                                   ; da4d: d0 03       ..
    jmp zero_float8A                                                  ; da4f: 4c a4 da    L..

multiply_float8A_by_float8B:
    clc                                                               ; da52: 18          .
    lda float8A_exponent                                              ; da53: a5 59       .Y
    adc float8B_exponent                                              ; da55: 65 61       ea
    sta float8A_exponent                                              ; da57: 85 59       .Y
    bcc skip7                                                         ; da59: 90 02       ..
    inc float8A_overflow                                              ; da5b: e6 58       .X
skip7:
    sec                                                               ; da5d: 38          8
    lda float8A_exponent                                              ; da5e: a5 59       .Y
    sbc #$80                                                          ; da60: e9 80       ..
    sta float8A_exponent                                              ; da62: 85 59       .Y
    bcs skip8                                                         ; da64: b0 02       ..
    dec float8A_overflow                                              ; da66: c6 58       .X
skip8:
    ldx #5                                                            ; da68: a2 05       ..
    ldy #0                                                            ; da6a: a0 00       ..
copy_mantissa_loop1:
    lda float8A_man1 - 1,x                                            ; da6c: b5 59       .Y
    sta result_man1 - 1,x                                             ; da6e: 95 66       .f
    sty float8A_man1 - 1,x                                            ; da70: 94 59       .Y
    dex                                                               ; da72: ca          .
    bne copy_mantissa_loop1                                           ; da73: d0 f7       ..
    lda float8A_sign                                                  ; da75: a5 57       .W
    eor float8B_sign                                                  ; da77: 45 5f       E_
    sta float8A_sign                                                  ; da79: 85 57       .W
    ldy #$20                                                          ; da7b: a0 20       .
    jsr halve_float8B_mantissa                                        ; da7d: 20 fb d6     ..
multiply_mantissa_loop:
    lda result_man1                                                   ; da80: a5 67       .g
    bpl cda88                                                         ; da82: 10 04       ..
    clc                                                               ; da84: 18          .
    jsr adc_mantissa8B_to_mantissa8A                                  ; da85: 20 42 d6     B.
cda88:
    jsr halve_float8B_mantissa                                        ; da88: 20 fb d6     ..
    asl result_rounding                                               ; da8b: 06 6b       .k
    rol result_man4                                                   ; da8d: 26 6a       &j
    rol result_man3                                                   ; da8f: 26 69       &i
    rol result_man2                                                   ; da91: 26 68       &h
    rol result_man1                                                   ; da93: 26 67       &g
    dey                                                               ; da95: 88          .
    bne multiply_mantissa_loop                                        ; da96: d0 e8       ..
normalise_round_and_overflow:
    jsr normalise_float8A                                             ; da98: 20 c8 d7     ..
apply_rounding_and_overflow:
    jsr apply_rounding                                                ; da9b: 20 80 d8     ..
    lda float8A_overflow                                              ; da9e: a5 58       .X
    beq return_14                                                     ; daa0: f0 0b       ..
    bpl error3                                                        ; daa2: 10 03       ..
zero_float8A:
    ldx #8                                                            ; daa4: a2 08       ..
dummy:
error3 = dummy+1
    lda #0                                                            ; daa6: a9 00       ..
; overlapping: brk                                                    ; daa7: 00          .
zero_loop:
    sta float8A_sign - 1,x                                            ; daa8: 95 56       .V
    dex                                                               ; daaa: ca          .
    bne zero_loop                                                     ; daab: d0 fb       ..
return_14:
    rts                                                               ; daad: 60          `

reciprocate_float8A:
    jsr pack_float8A_into_float1_setting_floatptr                     ; daae: 20 31 d8     1.
    jsr set_float8A_to_one                                            ; dab1: 20 8d de     ..
    bne divide_float8A_by_floatptr                                    ; dab4: d0 26       .&
float8A_equals_floatptr_divided_by_float8A:
    jsr three_way_sign_of_float8A                                     ; dab6: 20 86 d6     ..
    beq error3                                                        ; dab9: f0 ec       ..
    jsr set_float8B_equal_to_float8A                                  ; dabb: 20 c3 d6     ..
    jsr unpack_from_floatptr_into_float8A                             ; dabe: 20 e5 d1     ..
    bne divide_float8A_by_float8B                                     ; dac1: d0 23       .#
    rts                                                               ; dac3: 60          `

tan_function:
    jsr evaluate_float_operand                                        ; dac4: 20 eb d0     ..
    jsr point_floatptr_at_float4                                      ; dac7: 20 9e db     ..
    jsr pack_float8A_into_floatptr                                    ; daca: 20 3d d8     =.
    jsr cos_internal                                                  ; dacd: 20 e6 dc     ..
    jsr point_floatptr_at_float4                                      ; dad0: 20 9e db     ..
    jsr swap_float8A_and_floatptr                                     ; dad3: 20 23 d9     #.
    jsr sin_internal                                                  ; dad6: 20 f1 dc     ..
    jsr point_floatptr_at_float4                                      ; dad9: 20 9e db     ..
divide_float8A_by_floatptr:
    jsr three_way_sign_of_float8A                                     ; dadc: 20 86 d6     ..
    beq return_14                                                     ; dadf: f0 cc       ..
    jsr unpack_from_floatptr_into_float8B                             ; dae1: 20 04 d8     ..
    beq error3                                                        ; dae4: f0 c1       ..
divide_float8A_by_float8B:
    lda float8A_sign                                                  ; dae6: a5 57       .W
    eor float8B_sign                                                  ; dae8: 45 5f       E_
    sta float8A_sign                                                  ; daea: 85 57       .W
    sec                                                               ; daec: 38          8
    lda float8A_exponent                                              ; daed: a5 59       .Y
    sbc float8B_exponent                                              ; daef: e5 61       .a
    sta float8A_exponent                                              ; daf1: 85 59       .Y
    bcs skip_underflow                                                ; daf3: b0 02       ..
    dec float8A_overflow                                              ; daf5: c6 58       .X
skip_underflow:
    clc                                                               ; daf7: 18          .
    lda float8A_exponent                                              ; daf8: a5 59       .Y
    adc #$81                                                          ; dafa: 69 81       i.
    sta float8A_exponent                                              ; dafc: 85 59       .Y
    bcc skip_overflow                                                 ; dafe: 90 02       ..
    inc float8A_overflow                                              ; db00: e6 58       .X
skip_overflow:
    ldx #5                                                            ; db02: a2 05       ..
copy_mantissa_loop5:
    lda float8A_man1 - 1,x                                            ; db04: b5 59       .Y
    sta result_man1 - 1,x                                             ; db06: 95 66       .f
    dex                                                               ; db08: ca          .
    bne copy_mantissa_loop5                                           ; db09: d0 f9       ..
    lsr result_man1                                                   ; db0b: 46 67       Fg
    ror result_man2                                                   ; db0d: 66 68       fh
    ror result_man3                                                   ; db0f: 66 69       fi
    ror result_man4                                                   ; db11: 66 6a       fj
    ror result_rounding                                               ; db13: 66 6b       fk
    jsr halve_float8B_mantissa                                        ; db15: 20 fb d6     ..
    ldx #$27                                                          ; db18: a2 27       .'
division_iterations_loop1:
    lda result_man1                                                   ; db1a: a5 67       .g
    cmp float8B_man1                                                  ; db1c: c5 62       .b
    bne mantissas_compared1                                           ; db1e: d0 16       ..
    lda result_man2                                                   ; db20: a5 68       .h
    cmp float8B_man2                                                  ; db22: c5 63       .c
    bne mantissas_compared1                                           ; db24: d0 10       ..
    lda result_man3                                                   ; db26: a5 69       .i
    cmp float8B_man3                                                  ; db28: c5 64       .d
    bne mantissas_compared1                                           ; db2a: d0 0a       ..
    lda result_man4                                                   ; db2c: a5 6a       .j
    cmp float8B_man4                                                  ; db2e: c5 65       .e
    bne mantissas_compared1                                           ; db30: d0 04       ..
    lda result_rounding                                               ; db32: a5 6b       .k
    cmp float8B_rounding                                              ; db34: c5 66       .f
mantissas_compared1:
    bcc skip_subtraction1                                             ; db36: 90 24       .$
    lda result_rounding                                               ; db38: a5 6b       .k
    sbc float8B_rounding                                              ; db3a: e5 66       .f
    sta result_rounding                                               ; db3c: 85 6b       .k
    lda result_man4                                                   ; db3e: a5 6a       .j
    sbc float8B_man4                                                  ; db40: e5 65       .e
    sta result_man4                                                   ; db42: 85 6a       .j
    lda result_man3                                                   ; db44: a5 69       .i
    sbc float8B_man3                                                  ; db46: e5 64       .d
    sta result_man3                                                   ; db48: 85 69       .i
    lda result_man2                                                   ; db4a: a5 68       .h
    sbc float8B_man2                                                  ; db4c: e5 63       .c
    sta result_man2                                                   ; db4e: 85 68       .h
    lda result_man1                                                   ; db50: a5 67       .g
    sbc float8B_man1                                                  ; db52: e5 62       .b
    sta result_man1                                                   ; db54: 85 67       .g
    lda float8A_rounding                                              ; db56: a5 5e       .^
    ora #1                                                            ; db58: 09 01       ..
    sta float8A_rounding                                              ; db5a: 85 5e       .^
skip_subtraction1:
    jsr shift_mantissa_up_one_bit                                     ; db5c: 20 cd d6     ..
    asl result_rounding                                               ; db5f: 06 6b       .k
    rol result_man4                                                   ; db61: 26 6a       &j
    rol result_man3                                                   ; db63: 26 69       &i
    rol result_man2                                                   ; db65: 26 68       &h
    rol result_man1                                                   ; db67: 26 67       &g
    dex                                                               ; db69: ca          .
    bne division_iterations_loop1                                     ; db6a: d0 ae       ..
    jmp normalise_round_and_overflow                                  ; db6c: 4c 98 da    L..

sqr_function:
    jsr evaluate_float_operand                                        ; db6f: 20 eb d0     ..
sub_cdb72:
    jsr three_way_sign_of_float8A                                     ; db72: 20 86 d6     ..
    beq return_15                                                     ; db75: f0 26       .&
    bpl non_negative_sqr                                              ; db77: 10 01       ..
    brk                                                               ; db79: 00          .

non_negative_sqr:
    jsr pack_float8A_into_float1_setting_floatptr                     ; db7a: 20 31 d8     1.
    lda float8A_exponent                                              ; db7d: a5 59       .Y
    lsr                                                               ; db7f: 4a          J
    adc #$40                                                          ; db80: 69 40       i@
    sta float8A_exponent                                              ; db82: 85 59       .Y
    lda #5                                                            ; db84: a9 05       ..
    sta quadrant                                                      ; db86: 85 6e       .n
sqr_iteration_loop:
    jsr pack_float8A_into_float2_setting_floatptr                     ; db88: 20 27 d8     '.
    jsr point_floatptr_at_float1                                      ; db8b: 20 aa db     ..
    jsr float8A_equals_floatptr_divided_by_float8A                    ; db8e: 20 b6 da     ..
    jsr point_floatptr_at_float2                                      ; db91: 20 a2 db     ..
    jsr add_floatptr_to_float8A                                       ; db94: 20 3c d9     <.
    dec float8A_exponent                                              ; db97: c6 59       .Y
    dec quadrant                                                      ; db99: c6 6e       .n
    bne sqr_iteration_loop                                            ; db9b: d0 eb       ..
return_15:
    rts                                                               ; db9d: 60          `

point_floatptr_at_float4:
    lda #<float4                                                      ; db9e: a9 d4       ..
    bne set_floatptr                                                  ; dba0: d0 0a       .. ; ALWAYS branch

point_floatptr_at_float2:
    lda #<float2                                                      ; dba2: a9 ca       ..
    bne set_floatptr                                                  ; dba4: d0 06       .. ; ALWAYS branch

point_floatptr_at_float3:
    lda #<float3                                                      ; dba6: a9 cf       ..
    bne set_floatptr                                                  ; dba8: d0 02       .. ; ALWAYS branch

point_floatptr_at_float1:
    lda #<float1                                                      ; dbaa: a9 c5       ..
set_floatptr:
    sta floatptr_low                                                  ; dbac: 85 6f       .o
    lda #3                                                            ; dbae: a9 03       ..
    sta floatptr_high                                                 ; dbb0: 85 70       .p
    rts                                                               ; dbb2: 60          `

log_function:
    jsr evaluate_float_operand                                        ; dbb3: 20 eb d0     ..
sub_cdbb6:
    jsr three_way_sign_of_float8A                                     ; dbb6: 20 86 d6     ..
    beq log_range_error                                               ; dbb9: f0 02       ..
    bpl log_function_within_valid_range                               ; dbbb: 10 01       ..
log_range_error:
    brk                                                               ; dbbd: 00          .

log_function_within_valid_range:
    lda float8A_exponent                                              ; dbbe: a5 59       .Y
    pha                                                               ; dbc0: 48          H
    lda #$81                                                          ; dbc1: a9 81       ..
    sta float8A_exponent                                              ; dbc3: 85 59       .Y
    jsr zero_float8B_bugged                                           ; dbc5: 20 c7 d8     ..
    lda #$c0                                                          ; dbc8: a9 c0       ..
    sta float8B_man1                                                  ; dbca: 85 62       .b
    lda #$81                                                          ; dbcc: a9 81       ..
    sta float8B_exponent                                              ; dbce: 85 61       .a
    sta float8B_sign                                                  ; dbd0: 85 5f       ._
    jsr add_float8B_to_float8A                                        ; dbd2: 20 41 d9     A.
    inc float8A_exponent                                              ; dbd5: e6 59       .Y
    lda #<ln_series                                                   ; dbd7: a9 fe       ..
    ldy #>ln_series                                                   ; dbd9: a0 db       ..
    jsr series_evaluator                                              ; dbdb: 20 27 dc     '.
    jsr pack_float8A_into_float1_setting_floatptr                     ; dbde: 20 31 d8     1.
    pla                                                               ; dbe1: 68          h
    sec                                                               ; dbe2: 38          8
    sbc #$81                                                          ; dbe3: e9 81       ..
    jsr set_float8A_to_the_accumulator                                ; dbe5: 20 b2 d7     ..
    lda #<ln2                                                         ; dbe8: a9 f9       ..
    sta floatptr_low                                                  ; dbea: 85 6f       .o
    lda #>ln2                                                         ; dbec: a9 db       ..
    sta floatptr_high                                                 ; dbee: 85 70       .p
    jsr multiply_float8A_by_floatptr                                  ; dbf0: 20 45 da     E.
    jsr point_floatptr_at_float1                                      ; dbf3: 20 aa db     ..
    jmp add_floatptr_to_float8A                                       ; dbf6: 4c 3c d9    L<.

ln2:
    .byte $80, $31, $72, $17, $f8                                     ; dbf9: 80 31 72... .1r
ln_series:
    .byte 7                                                           ; dbfe: 07          .  ; Number of coefficients - 1
    .byte $85, $17, $6e, $d4, $85                                     ; dbff: 85 17 6e... ..n
    .byte $80, $28, $c7, $12, $a0                                     ; dc04: 80 28 c7... .(.
    .byte $84, $70, $4e, $5f, $f2                                     ; dc09: 84 70 4e... .pN
    .byte $81, 0, 0, $fe, $ef                                         ; dc0e: 81 00 00... ...
    .byte $84, $0f, $ff, $da, $e1                                     ; dc13: 84 0f ff... ...
    .byte $81, $7f, $ff, $ff, $93                                     ; dc18: 81 7f ff... ...
    .byte $82, $40, 0, 0, $0c                                         ; dc1d: 82 40 00... .@.
    .byte $7f, $4f, $99, $1f, $65                                     ; dc22: 7f 4f 99... .O.

series_evaluator:
    sta series_low                                                    ; dc27: 85 71       .q
    sty series_high                                                   ; dc29: 84 72       .r
    jsr pack_float8A_into_float1_setting_floatptr                     ; dc2b: 20 31 d8     1.
    ldy #0                                                            ; dc2e: a0 00       ..
    lda (series_low),y                                                ; dc30: b1 71       .q
    sta number_of_entries                                             ; dc32: 85 6c       .l
    inc series_low                                                    ; dc34: e6 71       .q
    bne skip9                                                         ; dc36: d0 02       ..
    inc series_high                                                   ; dc38: e6 72       .r
skip9:
    lda series_low                                                    ; dc3a: a5 71       .q
    sta floatptr_low                                                  ; dc3c: 85 6f       .o
    lda series_high                                                   ; dc3e: a5 72       .r
    sta floatptr_high                                                 ; dc40: 85 70       .p
    jsr unpack_from_floatptr_into_float8A                             ; dc42: 20 e5 d1     ..
series_loop:
    jsr point_floatptr_at_float1                                      ; dc45: 20 aa db     ..
    jsr float8A_equals_floatptr_divided_by_float8A                    ; dc48: 20 b6 da     ..
    clc                                                               ; dc4b: 18          .
    lda series_low                                                    ; dc4c: a5 71       .q
    adc #5                                                            ; dc4e: 69 05       i.
    sta series_low                                                    ; dc50: 85 71       .q
    sta floatptr_low                                                  ; dc52: 85 6f       .o
    lda series_high                                                   ; dc54: a5 72       .r
    adc #0                                                            ; dc56: 69 00       i.
    sta series_high                                                   ; dc58: 85 72       .r
    sta floatptr_high                                                 ; dc5a: 85 70       .p
    jsr add_floatptr_to_float8A                                       ; dc5c: 20 3c d9     <.
    dec number_of_entries                                             ; dc5f: c6 6c       .l
    bne series_loop                                                   ; dc61: d0 e2       ..
    rts                                                               ; dc63: 60          `

atn_function:
    jsr evaluate_float_operand                                        ; dc64: 20 eb d0     ..
atn_internal:
    jsr three_way_sign_of_float8A                                     ; dc67: 20 86 d6     ..
    beq return_16                                                     ; dc6a: f0 0d       ..
    bpl atn_positive                                                  ; dc6c: 10 0c       ..
    lda #0                                                            ; dc6e: a9 00       ..
    sta float8A_sign                                                  ; dc70: 85 57       .W
    jsr atn_positive                                                  ; dc72: 20 7a dc     z.
make_float8A_sign_negative:
    lda #$80                                                          ; dc75: a9 80       ..
    sta float8A_sign                                                  ; dc77: 85 57       .W
return_16:
    rts                                                               ; dc79: 60          `

atn_positive:
    lda float8A_exponent                                              ; dc7a: a5 59       .Y
    cmp #$81                                                          ; dc7c: c9 81       ..
    bcc atn_less_than_one                                             ; dc7e: 90 0c       ..
    jsr reciprocate_float8A                                           ; dc80: 20 ae da     ..
    jsr atn_less_than_one                                             ; dc83: 20 8c dc     ..
half_pi_minus_float8A:
    jsr prepare_half_pi                                               ; dc86: 20 93 dd     ..
    jmp float8A_equals_floatptr_minus_float8A                         ; dc89: 4c 39 d9    L9.

atn_less_than_one:
    lda float8A_exponent                                              ; dc8c: a5 59       .Y
    cmp #$73                                                          ; dc8e: c9 73       .s
    bcc return_16                                                     ; dc90: 90 e7       ..
    jsr pack_float8A_into_float3_setting_floatptr                     ; dc92: 20 2c d8     ,.
    jsr zero_float8B_bugged                                           ; dc95: 20 c7 d8     ..
    lda #$80                                                          ; dc98: a9 80       ..
    sta float8B_exponent                                              ; dc9a: 85 61       .a
    sta float8B_man1                                                  ; dc9c: 85 62       .b
    sta float8B_sign                                                  ; dc9e: 85 5f       ._
    jsr add_float8B_to_float8A                                        ; dca0: 20 41 d9     A.
    lda #<atn_series                                                  ; dca3: a9 b0       ..
    ldy #>atn_series                                                  ; dca5: a0 dc       ..
    jsr series_evaluator                                              ; dca7: 20 27 dc     '.
    jsr point_floatptr_at_float3                                      ; dcaa: 20 a6 db     ..
    jmp multiply_float8A_by_floatptr                                  ; dcad: 4c 45 da    LE.

atn_series:
    .byte 9                                                           ; dcb0: 09          .  ; Number of coefficients - 1
    .byte $85, $a3, $59, $e8, $67                                     ; dcb1: 85 a3 59... ..Y
    .byte $80, $1c, $9d, 7, $36                                       ; dcb6: 80 1c 9d... ...
    .byte $80, $57, $bb, $78, $df                                     ; dcbb: 80 57 bb... .W.
    .byte $80, $ca, $9a, $0e, $83                                     ; dcc0: 80 ca 9a... ...
    .byte $84, $8c, $bb, $ca, $6e                                     ; dcc5: 84 8c bb... ...
    .byte $81, $95, $96, 6, $de                                       ; dcca: 81 95 96... ...
    .byte $81, $0a, $c7, $6c, $52                                     ; dccf: 81 0a c7... ...
    .byte $7f, $7d, $ad, $90, $a1                                     ; dcd4: 7f 7d ad... .}.
    .byte $82, $fb, $62, $57, $2f                                     ; dcd9: 82 fb 62... ..b
    .byte $80, $6d, $63, $38, $2c                                     ; dcde: 80 6d 63... .mc

cos_function:
    jsr evaluate_float_operand                                        ; dce3: 20 eb d0     ..
cos_internal:
    jsr find_angle_quadrant                                           ; dce6: 20 24 dd     $.
    inc quadrant                                                      ; dce9: e6 6e       .n
    jmp sin_function_with_operand_and_quadrant                        ; dceb: 4c f4 dc    L..

sin_function:
    jsr evaluate_float_operand                                        ; dcee: 20 eb d0     ..
sin_internal:
    jsr find_angle_quadrant                                           ; dcf1: 20 24 dd     $.
sin_function_with_operand_and_quadrant:
    lsr quadrant                                                      ; dcf4: 46 6e       Fn
    bcc quadrant_0_or_2                                               ; dcf6: 90 03       ..
    jsr half_pi_minus_float8A                                         ; dcf8: 20 86 dc     ..
quadrant_0_or_2:
    lsr quadrant                                                      ; dcfb: 46 6e       Fn
    bcc quadrant_0                                                    ; dcfd: 90 06       ..
    jsr quadrant_0                                                    ; dcff: 20 05 dd     ..
    jmp invert_float8A_sign_with_zero_check                           ; dd02: 4c bf d1    L..

quadrant_0:
    jsr pack_float8A_into_float3_setting_floatptr                     ; dd05: 20 2c d8     ,.
    jsr prepare_half_pi                                               ; dd08: 20 93 dd     ..
    jsr unpack_from_floatptr_into_float8B                             ; dd0b: 20 04 d8     ..
    dec float8B_exponent                                              ; dd0e: c6 61       .a
    lda #$80                                                          ; dd10: a9 80       ..
    sta float8B_sign                                                  ; dd12: 85 5f       ._
    jsr add_float8B_to_float8A                                        ; dd14: 20 41 d9     A.
    lda #$a6                                                          ; dd17: a9 a6       ..
    ldy #$dd                                                          ; dd19: a0 dd       ..
    jsr series_evaluator                                              ; dd1b: 20 27 dc     '.
    jsr point_floatptr_at_float3                                      ; dd1e: 20 a6 db     ..
    jmp multiply_float8A_by_floatptr                                  ; dd21: 4c 45 da    LE.

find_angle_quadrant:
    lda float8A_exponent                                              ; dd24: a5 59       .Y
    cmp #$98                                                          ; dd26: c9 98       ..
    bcs accuracy_lost_error                                           ; dd28: b0 54       .T
    jsr pack_float8A_into_float1_setting_floatptr                     ; dd2a: 20 31 d8     1.
    jsr prepare_half_pi                                               ; dd2d: 20 93 dd     ..
    jsr divide_float8A_by_floatptr                                    ; dd30: 20 dc da     ..
    jsr convert_float8A_to_integer_in_mantissa                        ; dd33: 20 9a d8     ..
    lda float8A_man4                                                  ; dd36: a5 5d       .]
    sta quadrant                                                      ; dd38: 85 6e       .n
    ora float8A_man3                                                  ; dd3a: 05 5c       .\
    ora float8A_man2                                                  ; dd3c: 05 5b       .[
    ora float8A_man1                                                  ; dd3e: 05 5a       .Z
    beq zero_angle                                                    ; dd40: f0 3e       .>
    jsr convert_integer_in_mantissa_to_float                          ; dd42: 20 ac d2     ..
    jsr pack_float8A_into_float2_setting_floatptr                     ; dd45: 20 27 d8     '.
    jsr prepare_minus_half_pi_major_part                              ; dd48: 20 86 dd     ..
    jsr multiply_float8A_by_floatptr                                  ; dd4b: 20 45 da     E.
    jsr point_floatptr_at_float1                                      ; dd4e: 20 aa db     ..
    jsr add_floatptr_to_float8A                                       ; dd51: 20 3c d9     <.
    jsr pack_float8A_into_floatptr                                    ; dd54: 20 3d d8     =.
    jsr point_floatptr_at_float2                                      ; dd57: 20 a2 db     ..
    jsr unpack_from_floatptr_into_float8A                             ; dd5a: 20 e5 d1     ..
    jsr prepare_minus_half_pi_minor_part                              ; dd5d: 20 8a dd     ..
    jsr multiply_float8A_by_floatptr                                  ; dd60: 20 45 da     E.
    jsr point_floatptr_at_float1                                      ; dd63: 20 aa db     ..
    jsr add_floatptr_to_float8A                                       ; dd66: 20 3c d9     <.
quadrant_loop_adding_half_pi_until_positive:
    lda float8A_sign                                                  ; dd69: a5 57       .W
    bpl return_17                                                     ; dd6b: 10 12       ..
    jsr prepare_minus_half_pi_minor_part                              ; dd6d: 20 8a dd     ..
    jsr subtract_floatptr_from_float8A                                ; dd70: 20 33 d9     3.
    jsr prepare_minus_half_pi_major_part                              ; dd73: 20 86 dd     ..
    jsr subtract_floatptr_from_float8A                                ; dd76: 20 33 d9     3.
    dec quadrant                                                      ; dd79: c6 6e       .n
    jmp quadrant_loop_adding_half_pi_until_positive                   ; dd7b: 4c 69 dd    Li.

accuracy_lost_error:
    brk                                                               ; dd7e: 00          .

return_17:
    rts                                                               ; dd7f: 60          `

zero_angle:
    jsr unpack_from_float1_into_float8A                               ; dd80: 20 da d2     ..
    jmp quadrant_loop_adding_half_pi_until_positive                   ; dd83: 4c 69 dd    Li.

prepare_minus_half_pi_major_part:
    lda #<minus_half_pi_major_part                                    ; dd86: a9 97       ..
    bne finish_prepare_constant                                       ; dd88: d0 02       .. ; ALWAYS branch

prepare_minus_half_pi_minor_part:
    lda #<minus_half_pi_minor_part                                    ; dd8a: a9 9c       ..
finish_prepare_constant:
    sta floatptr_low                                                  ; dd8c: 85 6f       .o
    lda #$dd                                                          ; dd8e: a9 dd       ..
    sta floatptr_high                                                 ; dd90: 85 70       .p
    rts                                                               ; dd92: 60          `

prepare_half_pi:
    lda #<half_pi                                                     ; dd93: a9 a1       ..
    bne finish_prepare_constant                                       ; dd95: d0 f5       .. ; ALWAYS branch

minus_half_pi_major_part:
    .byte $81, $c9, 0, 0, 0                                           ; dd97: 81 c9 00... ...
minus_half_pi_minor_part:
    .byte $75, $fd, $aa, $22, $17                                     ; dd9c: 75 fd aa... u..
half_pi:
    .byte $81, $49, $0f, $da, $a2                                     ; dda1: 81 49 0f... .I.
    .byte   8, $84,   4, $c7, $3c, $fb, $81, $e0, $4f, $5d, $ad, $82  ; dda6: 08 84 04... ...
    .byte $80,   0, $69, $b8, $82, $5b, $cf, $1d, $b5, $82, $bf, $ce  ; ddb2: 80 00 69... ..i
    .byte $82, $1e, $82, $45, $44, $7f, $32, $7f                      ; ddbe: 82 1e 82... ...
    .byte "bDZ"                                                       ; ddc6: 62 44 5a    bDZ
    .byte $d2, $83, $82, $14, $8a, $27, $80                           ; ddc9: d2 83 82... ...
    .byte "f{!M"                                                      ; ddd0: 66 7b 21... f{!

exp_function:
    jsr evaluate_float_operand                                        ; ddd4: 20 eb d0     ..
exp_float8A:
    lda float8A_exponent                                              ; ddd7: a5 59       .Y
    cmp #$87                                                          ; ddd9: c9 87       ..
    bcc exp_with_small_exponent                                       ; dddb: 90 10       ..
    bne exp_with_large_exponent                                       ; dddd: d0 06       ..
    lda float8A_man1                                                  ; dddf: a5 5a       .Z
    cmp #$b3                                                          ; dde1: c9 b3       ..
    bcc exp_with_small_exponent                                       ; dde3: 90 08       ..
exp_with_large_exponent:
    lda float8A_sign                                                  ; dde5: a5 57       .W
    bpl exp_range_error                                               ; dde7: 10 03       ..
    jmp zero_float8A                                                  ; dde9: 4c a4 da    L..

exp_range_error:
    brk                                                               ; ddec: 00          .

exp_with_small_exponent:
    lda float8A_exponent                                              ; dded: a5 59       .Y
    cmp #$80                                                          ; ddef: c9 80       ..
    bcc evaluate_exp_series                                           ; ddf1: 90 29       .)
    jsr convert_float8A_to_integer_in_mantissa                        ; ddf3: 20 9a d8     ..
    jsr sub_cd8e2                                                     ; ddf6: 20 e2 d8     ..
    lda float8A_man4                                                  ; ddf9: a5 5d       .]
    sta quadrant                                                      ; ddfb: 85 6e       .n
    jsr copy_float8B_mantissa_to_float8A                              ; ddfd: 20 13 d9     ..
    jsr evaluate_exp_series                                           ; de00: 20 1c de     ..
    jsr pack_float8A_into_float3_setting_floatptr                     ; de03: 20 2c d8     ,.
    lda #$23                                                          ; de06: a9 23       .#
    sta floatptr_low                                                  ; de08: 85 6f       .o
    lda #$de                                                          ; de0a: a9 de       ..
    sta floatptr_high                                                 ; de0c: 85 70       .p
    jsr unpack_from_floatptr_into_float8A                             ; de0e: 20 e5 d1     ..
    lda quadrant                                                      ; de11: a5 6e       .n
    jsr exponentiate_to_integer_a                                     ; de13: 20 51 de     Q.
    jsr point_floatptr_at_float3                                      ; de16: 20 a6 db     ..
    jmp multiply_float8A_by_floatptr                                  ; de19: 4c 45 da    LE.

evaluate_exp_series:
    lda #<exp_series                                                  ; de1c: a9 28       .(
    ldy #>exp_series                                                  ; de1e: a0 de       ..
    jmp series_evaluator                                              ; de20: 4c 27 dc    L'.

e_constant:
    .byte $82, $2d, $f8, $54, $58                                     ; de23: 82 2d f8... .-.
exp_series:
    .byte 7                                                           ; de28: 07          .  ; Number of coefficients - 1
    .byte $83, $e0, $20, $86, $5b                                     ; de29: 83 e0 20... ..
    .byte $82, $80, $53, $93, $b8                                     ; de2e: 82 80 53... ..S
    .byte $83, $20, 0, 6, $a1                                         ; de33: 83 20 00... . .
    .byte $82, 0, 0, $21, $63                                         ; de38: 82 00 00... ...
    .byte $82, $c0, 0, 0, 2                                           ; de3d: 82 c0 00... ...
    .byte $82, $80, 0, 0, $0c                                         ; de42: 82 80 00... ...
    .byte $81, 0, 0, 0, 0                                             ; de47: 81 00 00... ...
    .byte $81, 0, 0, 0, 0                                             ; de4c: 81 00 00... ...

exponentiate_to_integer_a:
    tax                                                               ; de51: aa          .
    bpl exponentiate_to_non_negative_integer_a                        ; de52: 10 09       ..
    dex                                                               ; de54: ca          .
    txa                                                               ; de55: 8a          .
    eor #$ff                                                          ; de56: 49 ff       I.
    pha                                                               ; de58: 48          H
    jsr reciprocate_float8A                                           ; de59: 20 ae da     ..
    pla                                                               ; de5c: 68          h
exponentiate_to_non_negative_integer_a:
    pha                                                               ; de5d: 48          H
    jsr pack_float8A_into_float1_setting_floatptr                     ; de5e: 20 31 d8     1.
    jsr set_float8A_to_one                                            ; de61: 20 8d de     ..
repeated_multiplication_loop:
    pla                                                               ; de64: 68          h
    beq return_18                                                     ; de65: f0 0a       ..
    sec                                                               ; de67: 38          8
    sbc #1                                                            ; de68: e9 01       ..
    pha                                                               ; de6a: 48          H
    jsr multiply_float8A_by_floatptr                                  ; de6b: 20 45 da     E.
    jmp repeated_multiplication_loop                                  ; de6e: 4c 64 de    Ld.

return_18:
    rts                                                               ; de71: 60          `

htn_function:
    jsr evaluate_float_operand                                        ; de72: 20 eb d0     ..
    lda float8A_sign                                                  ; de75: a5 57       .W
    bpl cde83                                                         ; de77: 10 0a       ..
    lda #0                                                            ; de79: a9 00       ..
    sta float8A_sign                                                  ; de7b: 85 57       .W
    jsr cde83                                                         ; de7d: 20 83 de     ..
    jmp invert_float8A_sign_with_zero_check                           ; de80: 4c bf d1    L..

cde83:
    lda float8A_exponent                                              ; de83: a5 59       .Y
    cmp #$81                                                          ; de85: c9 81       ..
    bcc cdebc                                                         ; de87: 90 33       .3
    cmp #$85                                                          ; de89: c9 85       ..
    bcc cde98                                                         ; de8b: 90 0b       ..
set_float8A_to_one:
    jsr zero_float8A                                                  ; de8d: 20 a4 da     ..
    ldy #$80                                                          ; de90: a0 80       ..
    sty float8A_man1                                                  ; de92: 84 5a       .Z
    iny                                                               ; de94: c8          .  ; Y=$81
    sty float8A_exponent                                              ; de95: 84 59       .Y
    rts                                                               ; de97: 60          `

cde98:
    inc float8A_exponent                                              ; de98: e6 59       .Y
    lda #$80                                                          ; de9a: a9 80       ..
    sta float8A_sign                                                  ; de9c: 85 57       .W
    jsr exp_float8A                                                   ; de9e: 20 d7 dd     ..
    jsr pack_float8A_into_float1_setting_floatptr                     ; dea1: 20 31 d8     1.
    jsr set_float8A_to_one                                            ; dea4: 20 8d de     ..
    jsr add_floatptr_to_float8A                                       ; dea7: 20 3c d9     <.
    jsr pack_float8A_into_float2_setting_floatptr                     ; deaa: 20 27 d8     '.
    jsr set_float8A_to_one                                            ; dead: 20 8d de     ..
    jsr point_floatptr_at_float1                                      ; deb0: 20 aa db     ..
    jsr subtract_floatptr_from_float8A                                ; deb3: 20 33 d9     3.
    jsr point_floatptr_at_float2                                      ; deb6: 20 a2 db     ..
    jmp divide_float8A_by_floatptr                                    ; deb9: 4c dc da    L..

cdebc:
    jsr pack_float8A_into_float3_setting_floatptr                     ; debc: 20 2c d8     ,.
    jsr set_float8A_to_one                                            ; debf: 20 8d de     ..
    dec float8A_exponent                                              ; dec2: c6 59       .Y
    jsr subtract_floatptr_from_float8A                                ; dec4: 20 33 d9     3.
    lda #$d4                                                          ; dec7: a9 d4       ..
    ldy #$de                                                          ; dec9: a0 de       ..
    jsr series_evaluator                                              ; decb: 20 27 dc     '.
    jsr point_floatptr_at_float3                                      ; dece: 20 a6 db     ..
    jmp multiply_float8A_by_floatptr                                  ; ded1: 4c 45 da    LE.

    .byte 8, $7e, $85, $51, $b3, $0c, $86, $de, $b0                   ; ded4: 08 7e 85... .~.
    .byte "}s|#"                                                      ; dedd: 7d 73 7c... }s|
    .byte $d8, $e9, $9a, $87, $34, $82, $1d, $80, $81, $9a, $20, $6c  ; dee1: d8 e9 9a... ...
    .byte $ed, $81, $bd                                               ; deed: ed 81 bd    ...
    .byte "24."                                                       ; def0: 32 34 2e    24.
    .byte $7f, $5d, $46, $87, $b4, $82                                ; def3: 7f 5d 46... .]F
    .byte "h>C"                                                       ; def9: 68 3e 43    h>C
    .byte $f7, $80, $6c, $9a, $9e, $bb                                ; defc: f7 80 6c... ..l

colour_function:
    jsr basic_evaluate_numeric_expression                             ; df02: 20 c8 c3     ..
    lda output_buffer_low                                             ; df05: a5 52       .R
    and #3                                                            ; df07: 29 03       ).
    tay                                                               ; df09: a8          .
    lda colour_byte_table,y                                           ; df0a: b9 4e df    .N.
    sta temp_colour_byte                                              ; df0d: 8d fd 03    ...
    ; | Graphics Mode | Byte Value | Resolution | Colours  | Memory |
    ; | ------------- | ---------- | ---------- | -------- | ------ |
    ; | 0             | #00        | 64x48      |          | 0.5K   |
    ; | 1a            | #10        | 64x64      | 4 Colour | 1K     |
    ; | 1             | #30        | 128x64     |          | 1K     |
    ; | 2a            | #50        | 128x64     | 4 Colour | 2K     |
    ; | 2             | #70        | 128x96     |          | 1.5K   |
    ; | 3a            | #90        | 128x96     | 4 Colour | 3K     |
    ; | 3             | #B0        | 128x192    |          | 3K     |
    ; | 4a            | #D0        | 128x192    | 4 Colour | 6K     |
    ; | 4             | #F0        | 256x192    |          | 6K     |
    ; 
    lda graphics_mode_byte                                            ; df10: ad 00 b0    ...
    and #$f0                                                          ; df13: 29 f0       ).
    cmp #$70                                                          ; df15: c9 70       .p
    ; branch if not in Graphics Mode 2
    bne cdf25                                                         ; df17: d0 0c       ..
    ; Clear $8600 to $8800
    lda #0                                                            ; df19: a9 00       ..
    tay                                                               ; df1b: a8          .  ; Y=0
loop_cdf1c:
    sta l8600,y                                                       ; df1c: 99 00 86    ...
    sta l8700,y                                                       ; df1f: 99 00 87    ...
    dey                                                               ; df22: 88          .
    bne loop_cdf1c                                                    ; df23: d0 f7       ..
cdf25:
    ; AND with #$df to select the 4 colour mode that goes with the 2 colour mode we're
    ; in (1a for 1, and so on). Mode 2a uses #8000-#87FF, more than mode 2, hence
    ; clearing #8600-#87FF above
    lda graphics_mode_byte                                            ; df25: ad 00 b0    ...
    and #$df                                                          ; df28: 29 df       ).
    sta graphics_mode_byte                                            ; df2a: 8d 00 b0    ...
    rol                                                               ; df2d: 2a          *
    rol                                                               ; df2e: 2a          *
    rol                                                               ; df2f: 2a          *
    and #3                                                            ; df30: 29 03       ).
    tay                                                               ; df32: a8          .
    lda colour_plot_point_routines_low,y                              ; df33: b9 42 df    .B.
    sta basic_point_plot_routine_low                                  ; df36: 8d fe 03    ...
    lda colour_plot_point_routines_high,y                             ; df39: b9 46 df    .F.
    sta basic_point_plot_routine_high                                 ; df3c: 8d ff 03    ...
    jmp basic_verify_end_of_statement_and_continue                    ; df3f: 4c 58 c5    LX.

colour_plot_point_routines_low:
    .byte <mode_1_colour_point_plot                                   ; df42: 52          R
    .byte <mode_2_colour_point_plot                                   ; df43: 70          p
    .byte <mode_3_colour_point_plot                                   ; df44: 88          .
    .byte <mode_4_colour_point_plot                                   ; df45: a0          .
colour_plot_point_routines_high:
    .byte >mode_1_colour_point_plot                                   ; df46: df          .
    .byte >mode_2_colour_point_plot                                   ; df47: df          .
    .byte >mode_3_colour_point_plot                                   ; df48: df          .
    .byte >mode_4_colour_point_plot                                   ; df49: df          .
colour_bitmask_table:
    .byte %00111111, %11001111, %11110011, %11111100                  ; df4a: 3f cf f3... ?..
colour_byte_table:
    .byte %00000000, %01010101, %10101010, %11111111                  ; df4e: 00 55 aa... .U.

mode_1_colour_point_plot:
    lda x_coord_high                                                  ; df52: a5 5b       .[
    ora y_coord_high                                                  ; df54: 05 5d       .]
    bne return_19                                                     ; df56: d0 47       .G
    lda x_coord_low                                                   ; df58: a5 5a       .Z
    cmp #$40                                                          ; df5a: c9 40       .@
    bcs return_19                                                     ; df5c: b0 41       .A
    lsr                                                               ; df5e: 4a          J
    lsr                                                               ; df5f: 4a          J
    sta colour_screen_address_low                                     ; df60: 85 5f       ._
    ldy #0                                                            ; df62: a0 00       ..
    sty colour_screen_address_high                                    ; df64: 84 60       .`
    lda #$3f                                                          ; df66: a9 3f       .?
    sec                                                               ; df68: 38          8
    sbc y_coord_low                                                   ; df69: e5 5c       .\
    cmp #$40                                                          ; df6b: c9 40       .@
    bcc cdfbe                                                         ; df6d: 90 4f       .O
    rts                                                               ; df6f: 60          `

mode_2_colour_point_plot:
    lda x_coord_high                                                  ; df70: a5 5b       .[
    ora y_coord_high                                                  ; df72: 05 5d       .]
    bne return_19                                                     ; df74: d0 29       .)
    lda x_coord_low                                                   ; df76: a5 5a       .Z
    bmi return_19                                                     ; df78: 30 25       0%
    lsr                                                               ; df7a: 4a          J
    lsr                                                               ; df7b: 4a          J
    sta colour_screen_address_low                                     ; df7c: 85 5f       ._
    lda #$3f                                                          ; df7e: a9 3f       .?
    sec                                                               ; df80: 38          8
    sbc y_coord_low                                                   ; df81: e5 5c       .\
    cmp #$40                                                          ; df83: c9 40       .@
    bcc cdfb7                                                         ; df85: 90 30       .0
    rts                                                               ; df87: 60          `

mode_3_colour_point_plot:
    lda x_coord_high                                                  ; df88: a5 5b       .[
    ora y_coord_high                                                  ; df8a: 05 5d       .]
    bne return_19                                                     ; df8c: d0 11       ..
    lda x_coord_low                                                   ; df8e: a5 5a       .Z
    bmi return_19                                                     ; df90: 30 0d       0.
    lsr                                                               ; df92: 4a          J
    lsr                                                               ; df93: 4a          J
    sta colour_screen_address_low                                     ; df94: 85 5f       ._
    lda #$5f                                                          ; df96: a9 5f       ._
    sec                                                               ; df98: 38          8
    sbc y_coord_low                                                   ; df99: e5 5c       .\
    cmp #$60                                                          ; df9b: c9 60       .`
    bcc cdfb7                                                         ; df9d: 90 18       ..
return_19:
    rts                                                               ; df9f: 60          `

mode_4_colour_point_plot:
    lda x_coord_high                                                  ; dfa0: a5 5b       .[
    ora y_coord_high                                                  ; dfa2: 05 5d       .]
    bne return_19                                                     ; dfa4: d0 f9       ..
    lda x_coord_low                                                   ; dfa6: a5 5a       .Z
    bmi return_19                                                     ; dfa8: 30 f5       0.
    lsr                                                               ; dfaa: 4a          J
    lsr                                                               ; dfab: 4a          J
    sta colour_screen_address_low                                     ; dfac: 85 5f       ._
    lda #$bf                                                          ; dfae: a9 bf       ..
    sec                                                               ; dfb0: 38          8
    sbc y_coord_low                                                   ; dfb1: e5 5c       .\
    cmp #$c0                                                          ; dfb3: c9 c0       ..
    bcs return_19                                                     ; dfb5: b0 e8       ..
cdfb7:
    ldy #0                                                            ; dfb7: a0 00       ..
    sty colour_screen_address_high                                    ; dfb9: 84 60       .`
    asl                                                               ; dfbb: 0a          .
    rol colour_screen_address_high                                    ; dfbc: 26 60       &`
cdfbe:
    asl                                                               ; dfbe: 0a          .
    rol colour_screen_address_high                                    ; dfbf: 26 60       &`
    asl                                                               ; dfc1: 0a          .
    rol colour_screen_address_high                                    ; dfc2: 26 60       &`
    asl                                                               ; dfc4: 0a          .
    rol colour_screen_address_high                                    ; dfc5: 26 60       &`
    asl                                                               ; dfc7: 0a          .
    rol colour_screen_address_high                                    ; dfc8: 26 60       &`
    adc colour_screen_address_low                                     ; dfca: 65 5f       e_
    sta colour_screen_address_low                                     ; dfcc: 85 5f       ._
    lda colour_screen_address_high                                    ; dfce: a5 60       .`
    adc #$80                                                          ; dfd0: 69 80       i.
    sta colour_screen_address_high                                    ; dfd2: 85 60       .`
    lda x_coord_low                                                   ; dfd4: a5 5a       .Z
    and #3                                                            ; dfd6: 29 03       ).
    tax                                                               ; dfd8: aa          .
    lda colour_bitmask_table,x                                        ; dfd9: bd 4a df    .J.
    ldx mode_of_operation                                             ; dfdc: a6 5e       .^
    dex                                                               ; dfde: ca          .
    beq set_pixel                                                     ; dfdf: f0 0f       ..
    dex                                                               ; dfe1: ca          .
    beq invert_pixel                                                  ; dfe2: f0 05       ..
    ; clear pixel
    and (colour_screen_address_low),y                                 ; dfe4: 31 5f       1_
    sta (colour_screen_address_low),y                                 ; dfe6: 91 5f       ._
    rts                                                               ; dfe8: 60          `

invert_pixel:
    eor #$ff                                                          ; dfe9: 49 ff       I.
    eor (colour_screen_address_low),y                                 ; dfeb: 51 5f       Q_
    sta (colour_screen_address_low),y                                 ; dfed: 91 5f       ._
    rts                                                               ; dfef: 60          `

set_pixel:
    tax                                                               ; dff0: aa          .
    and (colour_screen_address_low),y                                 ; dff1: 31 5f       1_
    sta (colour_screen_address_low),y                                 ; dff3: 91 5f       ._
    txa                                                               ; dff5: 8a          .
    eor #$ff                                                          ; dff6: 49 ff       I.
    and temp_colour_byte                                              ; dff8: 2d fd 03    -..
    ora (colour_screen_address_low),y                                 ; dffb: 11 5f       ._
    sta (colour_screen_address_low),y                                 ; dffd: 91 5f       ._
    rts                                                               ; dfff: 60          `

pydis_end:

.assert (' ') = $20, error, "Assertion failed: ' ' = $20"
.assert ('+') = $2b, error, "Assertion failed: '+' = $2b"
.assert ('-') = $2d, error, "Assertion failed: '-' = $2d"
.assert ('.') = $2e, error, "Assertion failed: '.' = $2e"
.assert ('9'+1) = $3a, error, "Assertion failed: '9'+1 = $3a"
.assert ('@'-1) = $3f, error, "Assertion failed: '@'-1 = $3f"
.assert ('Z'+1) = $5b, error, "Assertion failed: 'Z'+1 = $5b"
.assert (128 + 32) = $a0, error, "Assertion failed: 128 + 32 = $a0"
.assert (<(float8B_man1 - 1)) = $61, error, "Assertion failed: <(float8B_man1 - 1) = $61"
.assert (<abs_function) = $15, error, "Assertion failed: <abs_function = $15"
.assert (<acs_function) = $1e, error, "Assertion failed: <acs_function = $1e"
.assert (<addition_binary_operator) = $77, error, "Assertion failed: <addition_binary_operator = $77"
.assert (<asn_function) = $24, error, "Assertion failed: <asn_function = $24"
.assert (<atn_function) = $64, error, "Assertion failed: <atn_function = $64"
.assert (<atn_series) = $b0, error, "Assertion failed: <atn_series = $b0"
.assert (<basic_return) = $78, error, "Assertion failed: <basic_return = $78"
.assert (<basic_statement_executer) = $4a, error, "Assertion failed: <basic_statement_executer = $4a"
.assert (<basic_verify_end_of_statement_and_continue) = $58, error, "Assertion failed: <basic_verify_end_of_statement_and_continue = $58"
.assert (<colour_function) = $02, error, "Assertion failed: <colour_function = $02"
.assert (<cos_function) = $e3, error, "Assertion failed: <cos_function = $e3"
.assert (<deg_function) = $73, error, "Assertion failed: <deg_function = $73"
.assert (<degrees_to_radians_constant) = $7c, error, "Assertion failed: <degrees_to_radians_constant = $7c"
.assert (<divide_operator) = $9b, error, "Assertion failed: <divide_operator = $9b"
.assert (<equals_conditional) = $f6, error, "Assertion failed: <equals_conditional = $f6"
.assert (<exp_function) = $d4, error, "Assertion failed: <exp_function = $d4"
.assert (<exp_series) = $28, error, "Assertion failed: <exp_series = $28"
.assert (<fdim_function) = $d3, error, "Assertion failed: <fdim_function = $d3"
.assert (<fget_function) = $cc, error, "Assertion failed: <fget_function = $cc"
.assert (<fif_function) = $a8, error, "Assertion failed: <fif_function = $a8"
.assert (<finput_function) = $6a, error, "Assertion failed: <finput_function = $6a"
.assert (<float1) = $c5, error, "Assertion failed: <float1 = $c5"
.assert (<float2) = $ca, error, "Assertion failed: <float2 = $ca"
.assert (<float3) = $cf, error, "Assertion failed: <float3 = $cf"
.assert (<float4) = $d4, error, "Assertion failed: <float4 = $d4"
.assert (<float8A_man4) = $5d, error, "Assertion failed: <float8A_man4 = $5d"
.assert (<flt_function) = $9a, error, "Assertion failed: <flt_function = $9a"
.assert (<flt_function_or_error) = $96, error, "Assertion failed: <flt_function_or_error = $96"
.assert (<fprint_function) = $31, error, "Assertion failed: <fprint_function = $31"
.assert (<fput_function) = $b4, error, "Assertion failed: <fput_function = $b4"
.assert (<funtil_function) = $ae, error, "Assertion failed: <funtil_function = $ae"
.assert (<greater_than_conditional) = $0a, error, "Assertion failed: <greater_than_conditional = $0a"
.assert (<greater_than_or_equal_conditional) = $06, error, "Assertion failed: <greater_than_or_equal_conditional = $06"
.assert (<half_pi) = $a1, error, "Assertion failed: <half_pi = $a1"
.assert (<htn_function) = $72, error, "Assertion failed: <htn_function = $72"
.assert (<jump_into_the_e000_rom_or_utility_rom) = $af, error, "Assertion failed: <jump_into_the_e000_rom_or_utility_rom = $af"
.assert (<less_than_conditional) = $02, error, "Assertion failed: <less_than_conditional = $02"
.assert (<less_than_or_equals_conditional) = $fa, error, "Assertion failed: <less_than_or_equals_conditional = $fa"
.assert (<ln2) = $f9, error, "Assertion failed: <ln2 = $f9"
.assert (<ln_series) = $fe, error, "Assertion failed: <ln_series = $fe"
.assert (<log_function) = $b3, error, "Assertion failed: <log_function = $b3"
.assert (<minus_half_pi_major_part) = $97, error, "Assertion failed: <minus_half_pi_major_part = $97"
.assert (<minus_half_pi_minor_part) = $9c, error, "Assertion failed: <minus_half_pi_minor_part = $9c"
.assert (<mode_1_colour_point_plot) = $52, error, "Assertion failed: <mode_1_colour_point_plot = $52"
.assert (<mode_2_colour_point_plot) = $70, error, "Assertion failed: <mode_2_colour_point_plot = $70"
.assert (<mode_3_colour_point_plot) = $88, error, "Assertion failed: <mode_3_colour_point_plot = $88"
.assert (<mode_4_colour_point_plot) = $a0, error, "Assertion failed: <mode_4_colour_point_plot = $a0"
.assert (<multiply_operator) = $8f, error, "Assertion failed: <multiply_operator = $8f"
.assert (<negate_unary_operator) = $bc, error, "Assertion failed: <negate_unary_operator = $bc"
.assert (<not_equals_conditional) = $fe, error, "Assertion failed: <not_equals_conditional = $fe"
.assert (<open_bracket_function) = $e4, error, "Assertion failed: <open_bracket_function = $e4"
.assert (<percent_function) = $0b, error, "Assertion failed: <percent_function = $0b"
.assert (<pi_function) = $c3, error, "Assertion failed: <pi_function = $c3"
.assert (<rad_function) = $65, error, "Assertion failed: <rad_function = $65"
.assert (<radians_to_degrees_constant) = $81, error, "Assertion failed: <radians_to_degrees_constant = $81"
.assert (<raise_to_the_power_operator) = $a7, error, "Assertion failed: <raise_to_the_power_operator = $a7"
.assert (<sgn_function) = $86, error, "Assertion failed: <sgn_function = $86"
.assert (<sin_function) = $ee, error, "Assertion failed: <sin_function = $ee"
.assert (<sqr_function) = $6f, error, "Assertion failed: <sqr_function = $6f"
.assert (<str_function) = $1f, error, "Assertion failed: <str_function = $1f"
.assert (<subtraction_binary_operator) = $83, error, "Assertion failed: <subtraction_binary_operator = $83"
.assert (<tan_function) = $c4, error, "Assertion failed: <tan_function = $c4"
.assert (<unary_plus_operator) = $cb, error, "Assertion failed: <unary_plus_operator = $cb"
.assert (<val_function) = $e0, error, "Assertion failed: <val_function = $e0"
.assert (>abs_function) = $d2, error, "Assertion failed: >abs_function = $d2"
.assert (>acs_function) = $d2, error, "Assertion failed: >acs_function = $d2"
.assert (>addition_binary_operator) = $d1, error, "Assertion failed: >addition_binary_operator = $d1"
.assert (>asn_function) = $d2, error, "Assertion failed: >asn_function = $d2"
.assert (>atn_function) = $dc, error, "Assertion failed: >atn_function = $dc"
.assert (>atn_series) = $dc, error, "Assertion failed: >atn_series = $dc"
.assert (>basic_return) = $c2, error, "Assertion failed: >basic_return = $c2"
.assert (>basic_statement_executer) = $c5, error, "Assertion failed: >basic_statement_executer = $c5"
.assert (>basic_verify_end_of_statement_and_continue) = $c5, error, "Assertion failed: >basic_verify_end_of_statement_and_continue = $c5"
.assert (>colour_function) = $df, error, "Assertion failed: >colour_function = $df"
.assert (>cos_function) = $dc, error, "Assertion failed: >cos_function = $dc"
.assert (>deg_function) = $d2, error, "Assertion failed: >deg_function = $d2"
.assert (>degrees_to_radians_constant) = $d2, error, "Assertion failed: >degrees_to_radians_constant = $d2"
.assert (>divide_operator) = $d1, error, "Assertion failed: >divide_operator = $d1"
.assert (>equals_conditional) = $d9, error, "Assertion failed: >equals_conditional = $d9"
.assert (>exp_function) = $dd, error, "Assertion failed: >exp_function = $dd"
.assert (>exp_series) = $de, error, "Assertion failed: >exp_series = $de"
.assert (>fdim_function) = $d3, error, "Assertion failed: >fdim_function = $d3"
.assert (>fget_function) = $d2, error, "Assertion failed: >fget_function = $d2"
.assert (>fif_function) = $d3, error, "Assertion failed: >fif_function = $d3"
.assert (>finput_function) = $d3, error, "Assertion failed: >finput_function = $d3"
.assert (>flt_function) = $d2, error, "Assertion failed: >flt_function = $d2"
.assert (>flt_function_or_error) = $d2, error, "Assertion failed: >flt_function_or_error = $d2"
.assert (>fprint_function) = $d3, error, "Assertion failed: >fprint_function = $d3"
.assert (>fput_function) = $d3, error, "Assertion failed: >fput_function = $d3"
.assert (>funtil_function) = $d3, error, "Assertion failed: >funtil_function = $d3"
.assert (>greater_than_conditional) = $da, error, "Assertion failed: >greater_than_conditional = $da"
.assert (>greater_than_or_equal_conditional) = $da, error, "Assertion failed: >greater_than_or_equal_conditional = $da"
.assert (>htn_function) = $de, error, "Assertion failed: >htn_function = $de"
.assert (>jump_into_the_e000_rom_or_utility_rom) = $d4, error, "Assertion failed: >jump_into_the_e000_rom_or_utility_rom = $d4"
.assert (>less_than_conditional) = $da, error, "Assertion failed: >less_than_conditional = $da"
.assert (>less_than_or_equals_conditional) = $d9, error, "Assertion failed: >less_than_or_equals_conditional = $d9"
.assert (>ln2) = $db, error, "Assertion failed: >ln2 = $db"
.assert (>ln_series) = $db, error, "Assertion failed: >ln_series = $db"
.assert (>log_function) = $db, error, "Assertion failed: >log_function = $db"
.assert (>mode_1_colour_point_plot) = $df, error, "Assertion failed: >mode_1_colour_point_plot = $df"
.assert (>mode_2_colour_point_plot) = $df, error, "Assertion failed: >mode_2_colour_point_plot = $df"
.assert (>mode_3_colour_point_plot) = $df, error, "Assertion failed: >mode_3_colour_point_plot = $df"
.assert (>mode_4_colour_point_plot) = $df, error, "Assertion failed: >mode_4_colour_point_plot = $df"
.assert (>multiply_operator) = $d1, error, "Assertion failed: >multiply_operator = $d1"
.assert (>negate_unary_operator) = $d1, error, "Assertion failed: >negate_unary_operator = $d1"
.assert (>not_equals_conditional) = $d9, error, "Assertion failed: >not_equals_conditional = $d9"
.assert (>open_bracket_function) = $d0, error, "Assertion failed: >open_bracket_function = $d0"
.assert (>percent_function) = $d3, error, "Assertion failed: >percent_function = $d3"
.assert (>pi_function) = $d2, error, "Assertion failed: >pi_function = $d2"
.assert (>rad_function) = $d2, error, "Assertion failed: >rad_function = $d2"
.assert (>radians_to_degrees_constant) = $d2, error, "Assertion failed: >radians_to_degrees_constant = $d2"
.assert (>raise_to_the_power_operator) = $d1, error, "Assertion failed: >raise_to_the_power_operator = $d1"
.assert (>sgn_function) = $d2, error, "Assertion failed: >sgn_function = $d2"
.assert (>sin_function) = $dc, error, "Assertion failed: >sin_function = $dc"
.assert (>sqr_function) = $db, error, "Assertion failed: >sqr_function = $db"
.assert (>str_function) = $d3, error, "Assertion failed: >str_function = $d3"
.assert (>subtraction_binary_operator) = $d1, error, "Assertion failed: >subtraction_binary_operator = $d1"
.assert (>tan_function) = $da, error, "Assertion failed: >tan_function = $da"
.assert (>unary_plus_operator) = $d1, error, "Assertion failed: >unary_plus_operator = $d1"
.assert (>val_function) = $d2, error, "Assertion failed: >val_function = $d2"
.assert (entry_point_unrecognised_command) = $d15e, error, "Assertion failed: entry_point_unrecognised_command = $d15e"
.assert (entry_point_unrecognised_statement) = $d10e, error, "Assertion failed: entry_point_unrecognised_statement = $d10e"
.assert (float8A_man1 - 1) = $59, error, "Assertion failed: float8A_man1 - 1 = $59"
.assert (float8A_sign - 1) = $56, error, "Assertion failed: float8A_sign - 1 = $56"
.assert (float8B_man1 - 1) = $61, error, "Assertion failed: float8B_man1 - 1 = $61"
.assert (float8B_overflow - 1) = $5f, error, "Assertion failed: float8B_overflow - 1 = $5f"
.assert (float8B_sign - 1) = $5e, error, "Assertion failed: float8B_sign - 1 = $5e"
.assert (floating_point_prefix - keyword_table) = $5f, error, "Assertion failed: floating_point_prefix - keyword_table = $5f"
.assert (keyword_table_add - keyword_table) = $9a, error, "Assertion failed: keyword_table_add - keyword_table = $9a"
.assert (keyword_table_close_bracket - keyword_table) = $b4, error, "Assertion failed: keyword_table_close_bracket - keyword_table = $b4"
.assert (keyword_table_equals - keyword_table) = $c8, error, "Assertion failed: keyword_table_equals - keyword_table = $c8"
.assert (keyword_table_finput_comma - keyword_table) = $c3, error, "Assertion failed: keyword_table_finput_comma - keyword_table = $c3"
.assert (keyword_table_multiply - keyword_table) = $a1, error, "Assertion failed: keyword_table_multiply - keyword_table = $a1"
.assert (keyword_table_raise_to_the_power - keyword_table) = $a8, error, "Assertion failed: keyword_table_raise_to_the_power - keyword_table = $a8"
.assert (keyword_table_semicolon - keyword_table) = $b8, error, "Assertion failed: keyword_table_semicolon - keyword_table = $b8"
.assert (keyword_table_unary_plus_operator - keyword_table) = $ac, error, "Assertion failed: keyword_table_unary_plus_operator - keyword_table = $ac"
.assert (result_man1 - 1) = $66, error, "Assertion failed: result_man1 - 1 = $66"

; Stats:
;
;     Total size (Code + Data) = 4096 bytes
;     Code                     = 3570 bytes (87%)
;     Data                     = 526 bytes (13%)
;
;     Number of instructions   = 1711
;     Number of data bytes     = 388 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 132 bytes
;     Number of strings        = 51

