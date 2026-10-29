; Constants
colour_black        = 0
colour_blue         = 6
colour_dark_grey    = 11
colour_light_grey   = 15
colour_white        = 1

; Memory locations

; 6510 I/O port (&0000-&0001)
cpu_port_direction  = &0000
cpu_port            = &0001

; Zero page (&0000-&00ff)
l0002                       = &0002
basic_index2                = &0024
basic_multiply_result       = &0026
basic_current_line          = &0039
io_status                   = &0090
stop_key_flag               = &0091
tape_timing                 = &0092
load_verify_flag            = &0093
serial_char_buffered_flag   = &0094
serial_buffered_char        = &0095
tape_sync_number            = &0096
kernal_x_save               = &0097
open_files_count            = &0098
input_device                = &0099
output_device               = &009a
tape_parity                 = &009b
tape_byte_received_flag     = &009c
kernal_message_flags        = &009d
tape_pass1_errors           = &009e
tape_pass2_errors           = &009f
jiffy_clock                 = &00a0
io_temp_1                   = &00a3
io_temp_2                   = &00a4
rs232_input_bits            = &00a7
rs232_start_bit_flag        = &00a9
rs232_input_parity          = &00ab
io_address_ptr              = &00ac
io_end_ptr                  = &00ae
tape_timing_constant        = &00b0
tape_buffer_ptr             = &00b2
filename_length             = &00b7
logical_file_number         = &00b8
secondary_address           = &00b9
device_number               = &00ba
filename_ptr                = &00bb
rs232_output_parity         = &00bd
tape_block_count            = &00be
tape_motor_interlock        = &00c0
io_start_ptr                = &00c1
load_address_temp           = &00c3
last_key_pressed            = &00c5
keyboard_buffer_length      = &00c6
reverse_flag                = &00c7
input_line_end              = &00c8
input_cursor_start          = &00c9
cursor_blink_disable        = &00cc
cursor_blink_timer          = &00cd
char_under_cursor           = &00ce
cursor_blink_phase          = &00cf
input_from_screen_flag      = &00d0
screen_line_ptr             = &00d1
cursor_column               = &00d3
quote_mode_flag             = &00d4
screen_line_length          = &00d5
cursor_row                  = &00d6
last_char_printed           = &00d7
insert_count                = &00d8
screen_line_links           = &00d9
colour_ram_line_ptr         = &00f3
keyboard_table_ptr          = &00f5

; Stack (&0100-&01ff)
l0100   = &0100
l0101   = &0101
l0104   = &0104
l0105   = &0105
l0106   = &0106
l0107   = &0107
l01a9   = &01a9

; OS workspace (&0200-&02ff)
basic_input_buffer          = &0200
logical_file_table          = &0259
device_number_table         = &0263
secondary_address_table     = &026d
keyboard_buffer             = &0277
os_memory_start             = &0281
os_memory_end               = &0283
serial_timeout_flag         = &0285
text_colour                 = &0286
colour_under_cursor         = &0287
screen_memory_page          = &0288
keyboard_buffer_size        = &0289
key_repeat_flags            = &028a
key_repeat_counter          = &028b
key_repeat_delay            = &028c
shift_key_flags             = &028d
last_shift_key_flags        = &028e
keyboard_table_setup_vector = &028f
charset_switch_flag         = &0291
pal_ntsc_flag               = &02a6
l02a9                       = &02a9

; Vectors (&0300-&0333)
basic_error_vector  = &0300
irq_vector          = &0314
brk_vector          = &0316
nmi_vector          = &0318
open_vector         = &031a
close_vector        = &031c
chkin_vector        = &031e
chkout_vector       = &0320
clrchn_vector       = &0322
chrin_vector        = &0324
chrout_vector       = &0326
stop_vector         = &0328
getin_vector        = &032a
clall_vector        = &032c
load_vector         = &0330
save_vector         = &0332

; Tape buffer (&0334-&03ff)
tape_buffer = &033c
l03ff       = &03ff

; Screen memory (&0400-&07ff)
screen_memory   = &0400

; BASIC program area (&0800-&9fff)
l08a9   = &08a9
l09a9   = &09a9
l4fa9   = &4fa9
l8000   = &8000
l8002   = &8002
l8003   = &8003

; BASIC ROM (&a000-&bfff)
la000   = &a000
la002   = &a002

; VIC-II (&d000-&d3ff)
vic_sprite0_x           = &d000
vic_control_1           = &d011
vic_raster_line         = &d012
vic_sprite_enable       = &d015
vic_control_2           = &d016
vic_memory_setup        = &d018
vic_interrupt_status    = &d019
vic_border_colour       = &d020
vic_background_colour_0 = &d021

; SID (&d400-&d7ff)
sid_voice1_frequency_low = &d400
sid_volume_filter_mode  = &d418

; CIA 1 (&dc00-&dcff)
cia1_port_a             = &dc00
cia1_port_b             = &dc01
cia1_data_direction_a   = &dc02
cia1_data_direction_b   = &dc03
cia1_timer_a_low        = &dc04
cia1_timer_a_high       = &dc05
cia1_interrupt_control  = &dc0d
cia1_control_a          = &dc0e
cia1_control_b          = &dc0f

; CIA 2 (&dd00-&ddff)
cia2_port_a             = &dd00
cia2_port_b             = &dd01
cia2_data_direction_a   = &dd02
cia2_data_direction_b   = &dd03
cia2_timer_a_low        = &dd04
cia2_timer_a_high       = &dd05
cia2_timer_b_low        = &dd06
cia2_timer_b_high       = &dd07
cia2_interrupt_control  = &dd0d
cia2_control_a          = &dd0e
cia2_control_b          = &dd0f

    org &e000

.pydis_start
    equb &20, &2e, &ba, &90,   3, &4c, &cf, &a6, &a5, &14, &48, &a5   ; e000: 20 2e ba...  ..
    equb &15, &48, &20, &df, &a1, &90,   3, &4c, &cf, &a6, &a8, &68   ; e00c: 15 48 20... .h
    equb &85, &15, &68, &85, &14, &98, &a0,   0, &91, &14, &60, &a9   ; e018: 85 15 68... ...
    equb &26, &85,   1, &a0,   4, &8a                                 ; e024: 26 85 01... &..
    equb &d1, &47, &4c ; petscii "Qgl"                                ; e02a: d1 47 4c    Qgl
    equb &b0, &e3, &a9, &26, &85,   1, &a0,   0, &b1, &7a, &85, &3d   ; e02d: b0 e3 a9... ...
    equb &c8, &b1, &7a, &85, &3e,   5, &3d, &4c, &b0, &e3, &60, &a9   ; e039: c8 b1 7a... H..
    equb &26, &85,   1, &a0,   0, &c4, &61, &d0,   3, &4c, &61, &e3   ; e045: 26 85 01... &..
    equb &b1, &62, &20, &d2, &ff, &c8, &10, &f1, &60, &4c, &b2, &a6   ; e051: b1 62 20... ..
    equb &4c, &b2, &a6, &a2, &19, &e4, &16, &f0, &1a, &b5,   0, &f0   ; e05d: 4c b2 a6... l..
    equb &11, &85, &50, &b5,   1, &85, &51, &b5,   2, &85, &52, &8a   ; e069: 11 85 50... ..p
    equb &48, &20, &e1, &a3, &68, &aa, &e8, &e8, &e8, &d0, &e2, &a9   ; e075: 48 20 e1... h .
    equb &19, &85, &16, &a9, &16, &85, &17, &60, &85, &50, &18, &a5   ; e081: 19 85 16... ...
    equb &22, &65, &50, &85, &22, &90,   2, &c6, &23, &60, &20, &2b   ; e08d: 22 65 50... ".p
    equb &bc, &c9,   0, &d0,   3, &4c, &3e, &a2, &c9, &80, &b0,   3   ; e099: bc c9 00... .I.
    equb &4c, &be, &e0, &4c, &c8, &a1, &a9, &26, &85,   1, &b1, &47   ; e0a5: 4c be e0... l..
    equb &85, &65, &c8, &b1, &47, &85, &64, &c8, &a9, &27, &85,   1   ; e0b1: 85 65 c8... ..H
    equb &60,   6, &8c, &26, &8d, &26, &8e, &26, &8f, &b0, &19, &a5   ; e0bd: 60 06 8c... ...
    equb &8c, &49, &b7, &85, &8c, &a5, &8d, &49, &1d, &85, &8d, &a5   ; e0c9: 8c 49 b7... .i.
    equb &8e, &49, &c1, &85, &8e, &a5, &8f, &49,   4, &85, &8f, &38   ; e0d5: 8e 49 c1... .iA
    equb &a5, &8e, &69, &c6, &85, &62, &a5, &8c, &49, &4e, &85, &63   ; e0e1: a5 8e 69... ...
    equb &a5, &8f, &49, &62, &85, &64, &a5, &8d, &24, &8d, &2a, &85   ; e0ed: a5 8f 49... ..i
    equb &65, &a9,   0, &85, &66, &a9, &80, &85, &70, &85, &61, &4c   ; e0f9: 65 a9 00... ...
    equb &1e, &b5, &aa, &a5, &16, &c9, &22, &b0, &13, &a8, &85, &17   ; e105: 1e b5 aa... ...
    equb &18, &69,   3, &85, &16, &96,   0, &84, &47, &a9,   0, &85   ; e111: 18 69 03... ...
    equb &48, &4c, &d3 ; petscii "hlS"                                ; e11d: 48 4c d3    hlS
    equb &b4, &a0, &19, &b9, 0, 0, &f0, &ee                           ; e120: b4 a0 19... ...
    equb &c8, &c8, &c8 ; petscii "HHH"                                ; e128: c8 c8 c8    HHH
    equb &c0, &22, &d0, &f4, &4c, &c1, &a6, &a9, &26, &85, 1, &a0, 0  ; e12b: c0 22 d0... ."P
    equb &b1                                                          ; e138: b1          .
    equb &3d, &48, &c8 ; petscii "=hH"                                ; e139: 3d 48 c8    =hH
    equb &b1, &3d, &85, &3e, &68, &85, &3d, &4c, &61, &e3, &a9, &26   ; e13c: b1 3d 85... .=.
    equb &85,   1, &a0,   3, &b1, &47, &48, &88, &b1, &47, &18, &65   ; e148: 85 01 a0... ...
    equb &47, &85, &47, &68, &65, &48, &85, &48, &a9, &27, &85,   1   ; e154: 47 85 47... g.g
    equb &4c, &9d, &b7, &a9, &26, &85,   1, &a0,   0, &b1, &22, &f0   ; e160: 4c 9d b7... l..
    equb &18, &c8, &18, &71, &22, &85, &26, &c8, &a9,   0, &71, &22   ; e16c: 18 c8 18... .H.
    equb &85, &27, &a0,   0, &a5, &22, &91, &26, &c8, &a5, &23, &91   ; e178: 85 27 a0... .'.
    equb &26, &4c, &61, &e3, &a9, &26, &85,   1, &b1, &7a, &48, &a9   ; e184: 26 4c 61... &l.
    equb &27, &85,   1, &68, &60, &a9, &26, &85,   1, &b1, &3d, &4c   ; e190: 27 85 01... '..
    equb &8e, &e1, &a9, &26, &85,   1, &b1, &47, &4c, &8e, &e1, &a9   ; e19c: 8e e1 a9... ...
    equb &26, &85,   1, &b1, &62, &4c, &8e, &e1,   8, &a9, &26, &85   ; e1a8: 26 85 01... &..
    equb   1                                                          ; e1b4: 01          .

; &e1b5 referenced 2 times by &e1ba, &e1c2
.ce1b5
    ; Copy Y bytes of memory
    lda (basic_index2),y                                              ; e1b5: b1 24       .$
    sta (basic_multiply_result),y                                     ; e1b7: 91 26       .&
    dey                                                               ; e1b9: 88          .
    bne ce1b5                                                         ; e1ba: d0 f9       P.
    dec basic_index2+1                                                ; e1bc: c6 25       F%
    dec basic_multiply_result+1                                       ; e1be: c6 27       F'
    dec basic_multiply_result+3                                       ; e1c0: c6 29       F)
    bne ce1b5                                                         ; e1c2: d0 f1       P.
    jmp ce1db                                                         ; e1c4: 4c db e1    l..

    equb 8, &a9, &26, &85, 1, &b1, &24, &91                           ; e1c7: 08 a9 26... ..&
    equb &26, &c8, &d0 ; petscii "&HP"                                ; e1cf: 26 c8 d0    &HP
    equb &f9, &e6, &25, &e6                                           ; e1d2: f9 e6 25... ..%
    equb &27, &c6, &29, &d0 ; petscii "'F)P"                          ; e1d6: 27 c6 29... 'F)
    equb &f1                                                          ; e1da: f1          .

; &e1db referenced 1 time by &e1c4
.ce1db
    lda #&27 ; '''                                                    ; e1db: a9 27       .'
    sta cpu_port                                                      ; e1dd: 85 01       ..
    plp                                                               ; e1df: 28          (
    rts                                                               ; e1e0: 60          .

    equb &a9, &26, &85,   1, &a0,   2, &b1, &22, &18, &65, &22, &85   ; e1e1: a9 26 85... .&.
    equb &24, &c8, &b1, &22, &65, &23, &85, &25, &a0,   0, &b1, &22   ; e1ed: 24 c8 b1... $H.
    equb &10,   3, &4c, &5e, &e2, &c8, &b1, &22, &30,   3, &4c, &5e   ; e1f9: 10 03 4c... ..l
    equb &e2, &a0,   4, &b1, &22, &0a, &18, &69,   5, &20, &89, &e0   ; e205: e2 a0 04... ...
    equb &4c, &58, &e2, &20, &12, &bc, &a9, &26, &85,   1, &20, &4c   ; e211: 4c 58 e2... lx.
    equb &e2, &f0, &3e, &a0,   3, &b1, &3d, &c5, &15, &f0,   4, &b0   ; e21d: e2 f0 3e... ..>
    equb &34, &d0, &0b, &88, &b1, &3d, &c5, &14, &f0, &25, &b0, &29   ; e229: 34 d0 0b... 4P.
    equb &d0,   0, &20, &4c, &e2, &f0, &22, &a0,   0, &b1             ; e235: d0 00 20... P.
    equb &3d, &48, &c8 ; petscii "=hH"                                ; e23f: 3d 48 c8    =hH
    equb &b1, &3d, &85, &3e, &68, &85, &3d, &4c, &17, &e2, &a0,   1   ; e242: b1 3d 85... .=.
    equb &b1, &3d, &d0,   5, &88, &b1, &3d, &d0,   0, &60, &a9, &27   ; e24e: b1 3d d0... .=P
    equb &85,   1, &18, &60, &a9, &27, &85,   1, &38, &60, &60, &80   ; e25a: 85 01 18... ...
    equb &c0, &a0, &10, &58, &3c, &60,   5, &67, &cc, &65, &20, &e2   ; e266: c0 a0 10... ...
    equb &6e, &38, &ad,   8, &b4, &74, &d0, &0b, &7b, &30, &7a,   8   ; e272: 6e 38 ad... .8.
    equb &88, &84, &2a, &7e, &aa, &aa, &aa, &95, &81,   0,   0,   0   ; e27e: 88 84 2a... ..*
    equb   0, &ce,   1,   1, &ce,   1,   1, &38, &a5,   7, &ed,   1   ; e28a: 00 ce 01... .N.
    equb   1, &85,   7, &ee,   0,   1, &ac,   0,   1, &ad,   1,   1   ; e296: 01 85 07... ...
    equb &18, &6d,   0,   1, &aa, &bd,   0,   2, &99,   0,   2, &f0   ; e2a2: 18 6d 00... ...
    equb   4, &e8, &c8, &d0, &f4, &60, &60, &a9,   1, &a2, &41, &a0   ; e2ae: 04 e8 c8... ..H
    equb &f1, &4c, &bd, &ff, &20, &93, &ba, &20, &29, &a7, &90,   3   ; e2ba: f1 4c bd... .l.
    equb &4c, &d2, &a6, &20, &8c, &e3, &b0,   3, &20, &8b, &a4, &a9   ; e2c6: 4c d2 a6... lR.
    equb &2b, &a6, &2d, &a4                                           ; e2d2: 2b a6 2d... +.-
    equb &2e, &20, &d8 ; petscii ". X"                                ; e2d6: 2e 20 d8    . X
    equb &ff, &90,   3, &4c, &aa, &a6, &60, &81, &49, &0f, &da, &a2   ; e2d9: ff 90 03... ...
    equb &83, &49, &0f, &da, &a2, &7f,   0,   0,   0,   0, &ea, &ea   ; e2e5: 83 49 0f... .i.
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; e2f1: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &4c, &b2, &a6   ; e2fd: ea ea ea... ...
    equb &83, &49, &0f, &da, &a2, &60, &4c, &b2, &a6, &a5, &2b, &85   ; e309: 83 49 0f... .i.
    equb &3d, &a5, &2c, &85, &3e, &a5, &3d, &85, &2d, &a5, &3e, &85   ; e315: 3d a5 2c... =.,
    equb &2e, &20, &32 ; petscii ". 2"                                ; e321: 2e 20 32    . 2
    equb &e1, &a5, &3d,   5, &3e, &d0, &ef, &18, &a5, &2d, &69,   2   ; e324: e1 a5 3d... ..=
    equb &85, &2d, &90,   2, &e6, &2e, &4c,   0, &ba, &a9, &26, &85   ; e330: 85 2d 90... .-.
    equb   1, &a0,   0, &b1                                           ; e33c: 01 a0 00... ...
    equb &47, &c5, &45, &d0 ; petscii "gEeP"                          ; e340: 47 c5 45... gEe
    equb 5, &c8, &b1                                                  ; e344: 05 c8 b1    .H.
    equb &47, &c5, &46, &4c ; petscii "gEfl"                          ; e347: 47 c5 46... gEf
    equb &b0, &e3, &a9, &26, &85,   1, &a0,   0, &b1, &47, &85, &61   ; e34b: b0 e3 a9... ...
    equb &c8, &b1, &47, &85, &62, &c8, &b1, &47, &85, &63, &a9, &27   ; e357: c8 b1 47... H.g
    equb &85,   1, &60, &a9, &26, &85,   1, &b1, &3d, &85, &24, &c8   ; e363: 85 01 60... ...
    equb &b1, &3d, &85, &25, &4c, &88, &e3, &a9, &26, &85,   1, &b1   ; e36f: b1 3d 85... .=.
    equb &3d, &18, &65, &22, &91, &3d, &c8, &b1, &3d, &65, &23, &91   ; e37b: 3d 18 65... =..
    equb &3d, &4c, &61, &e3, &60, &20, &df, &a1, &b0,   2, &85, &ba   ; e387: 3d 4c 61... =l.
    equb &60, &a0, &13, &b9, &52, &bf, &d9, &b9, &e4, &f0,   5, &a9   ; e393: 60 a0 13... ...
    equb   1, &6c, &b7, &e4, &88, &10, &f0, &4c, &a3, &b3, &a9, &26   ; e39f: 01 6c b7... ...
    equb &85,   1, &20, &4c, &e2,   8, &a9, &27, &85,   1, &28, &60   ; e3ab: 85 01 20... ..
    equb &4c, &0d, &a2,   1, &0a, &64, &e8, &10, &60, &4b, &fa, &0f   ; e3b7: 4c 0d a2... l..
    equb   0, &83, &eb,   0, &4a,   5,   0, &ff, &ff, &20, &12, &bc   ; e3c3: 00 83 eb... ...
    equb &a0,   1, &20, &95, &e1, &c9,   0, &d0,   3, &4c,   1, &ac   ; e3cf: a0 01 20... ..
    equb &a5, &91, &30,   3, &4c, &ac, &a2, &20, &54, &ab, &20, &32   ; e3db: a5 91 30... ..0
    equb &e1, &4c, &cf, &e3, &a9, &26, &85,   1, &a0,   0, &b1, &47   ; e3e7: e1 4c cf... .lO
    equb &85, &50, &c8, &b1, &47, &85, &51, &c8, &b1, &47, &85, &52   ; e3f3: 85 50 c8... .pH
    equb &a9, &27, &85,   1, &60, &a9, &26, &85,   1, &a0,   2, &b1   ; e3ff: a9 27 85... .'.
    equb &47, &85, &52, &88, &b1, &47, &85, &51, &88, &b1, &62, &91   ; e40b: 47 85 52... g.r
    equb &51, &c8, &c4 ; petscii "qHD"                                ; e417: 51 c8 c4    qHD
    equb &61, &d0, &f7, &a9, &27, &85,   1, &60, &4c, &b6, &b7, &84   ; e41a: 61 d0 f7... .P.
    equb &23, &85, &22, &a0,   4, &b1, &22, &85, &6d, &88, &b1, &22   ; e426: 23 85 22... #."
    equb &85, &6c, &88, &b1, &22, &85, &6b, &88, &b1, &22,   9, &80   ; e432: 85 6c 88... ...
    equb &85, &6a, &b1, &22, &10,   3, &a9, &ff, &2c, &a9,   0, &85   ; e43e: 85 6a b1... ...
    equb &6e, &88, &b1, &22, &85, &69, &a5, &61, &60, &60, &4c, &b2   ; e44a: 6e 88 b1... ...
    equb &a6, &38, &a5, &2d, &e9,   1, &85, &24, &a5, &2e, &e9,   0   ; e456: a6 38 a5... .8.
    equb &85, &25, &18, &8a, &65, &24, &85, &26, &a5, &25, &69,   0   ; e462: 85 25 18... .%.
    equb &85, &27, &a5, &2d, &38, &e5, &3d, &85, &28, &a5, &2e, &e5   ; e46e: 85 27 a5... .'.
    equb &3e, &85, &29, &4c, &c0, &b1, &a9, &26, &85,   1, &b1, &3d   ; e47a: 3e 85 29... >.)
    equb &85, &39, &c8, &b1, &3d, &85, &3a, &a9, &27, &85,   1, &4c   ; e486: 85 39 c8... .9H
    equb &93, &a4, &a9, &26, &85,   1, &a0,   0, &b1, &6a, &91        ; e492: 93 a4 a9... ...
    equb &22, &c8, &c4 ; petscii &22, "HD"                            ; e49d: 22 c8 c4    "HD
    equb &69, &d0, &f7, &98, &20, &89, &e0, &a0, 0, &b1, &62, &91     ; e4a0: 69 d0 f7... .P.
    equb &22, &c8, &c4 ; petscii &22, "HD"                            ; e4ac: 22 c8 c4    "HD
    equb &61, &d0, &f7, &a9, &27, &85, 1, &60, &8b, &ea, &4f, &52, 1  ; e4af: 61 d0 f7... .P.
    equb &44, &45, &56, &2e, &32, &31, &30, &38 ; petscii "dev.2108"  ; e4bc: 44 45 56... dev
    equb &32, &33, &2e, &46, &43, &2e, &31 ; petscii "23.fc.1"        ; e4c4: 32 33 2e... 23.
    equb 0, 0, &f5, &4b, &8c, &0e, 2, 0                               ; e4cb: 00 00 f5... ...

; &e4d3 referenced 1 time by &ffea
.ce4d3
    inc jiffy_clock+2                                                 ; e4d3: e6 a2       ..
    bne ce4dd                                                         ; e4d5: d0 06       P.
    inc jiffy_clock+1                                                 ; e4d7: e6 a1       ..
    bne ce4dd                                                         ; e4d9: d0 02       P.
    inc jiffy_clock                                                   ; e4db: e6 a0       ..
; &e4dd referenced 2 times by &e4d5, &e4d9
.ce4dd
    lda jiffy_clock                                                   ; e4dd: a5 a0       ..
    cmp #&4f ; 'o'                                                    ; e4df: c9 4f       Io
    bcc ce4f1                                                         ; e4e1: 90 0e       ..
    lda jiffy_clock+1                                                 ; e4e3: a5 a1       ..
    cmp #&1a                                                          ; e4e5: c9 1a       I.
    bcc ce4f1                                                         ; e4e7: 90 08       ..
    lda #0                                                            ; e4e9: a9 00       ..
    sta jiffy_clock                                                   ; e4eb: 85 a0       ..
    sta jiffy_clock+1                                                 ; e4ed: 85 a1       ..
    sta jiffy_clock+2                                                 ; e4ef: 85 a2       ..
; &e4f1 referenced 4 times by &e4e1, &e4e7, &e68c, &e7c9
.ce4f1
    lda #&80                                                          ; e4f1: a9 80       ..
    sta cia1_port_a                                                   ; e4f3: 8d 00 dc    ...
    lda cia1_port_b                                                   ; e4f6: ad 01 dc    ...
    eor #&ff                                                          ; e4f9: 49 ff       i.
    sta stop_key_flag                                                 ; e4fb: 85 91       ..
    lda #&7f                                                          ; e4fd: a9 7f       ..
    sta cia1_port_a                                                   ; e4ff: 8d 00 dc    ...
    lda cia1_port_b                                                   ; e502: ad 01 dc    ...
    ora stop_key_flag                                                 ; e505: 05 91       ..
    sta stop_key_flag                                                 ; e507: 85 91       ..
    rts                                                               ; e509: 60          .

; &e50a referenced 1 time by &fff0
.ce50a
    bcs ce513                                                         ; e50a: b0 07       ..
    sty cursor_column                                                 ; e50c: 84 d3       .S
    stx cursor_row                                                    ; e50e: 86 d6       .V
    jsr sub_ce56c                                                     ; e510: 20 6c e5     ..
; &e513 referenced 1 time by &e50a
.ce513
    ldy cursor_column                                                 ; e513: a4 d3       .S
    ldx cursor_row                                                    ; e515: a6 d6       .V
    rts                                                               ; e517: 60          .

; &e518 referenced 1 time by &ff5b
.sub_ce518
    jsr sub_ce5a0                                                     ; e518: 20 a0 e5     ..
    jmp cfc25                                                         ; e51b: 4c 25 fc    l%.

; &e51e referenced 1 time by &ff90
.ce51e
    sta kernal_message_flags                                          ; e51e: 85 9d       ..
    rts                                                               ; e520: 60          .

; &e521 referenced 1 time by &f269
.ce521
    lda logical_file_table,y                                          ; e521: b9 59 02    .y.
    bne ce529                                                         ; e524: d0 03       P.
    jmp cf27b                                                         ; e526: 4c 7b f2    l..

; &e529 referenced 1 time by &e524
.ce529
    lda device_number_table,y                                         ; e529: b9 63 02    ...
    jsr cf4cd                                                         ; e52c: 20 cd f4     M.
    bcc ce534                                                         ; e52f: 90 03       ..
    jmp cf940                                                         ; e531: 4c 40 f9    l@.

; &e534 referenced 1 time by &e52f
.ce534
    lda logical_file_table,y                                          ; e534: b9 59 02    .y.
    ora #&60                                                          ; e537: 09 60       ..
    jsr ce6b7                                                         ; e539: 20 b7 e6     ..
    bcc ce541                                                         ; e53c: 90 03       ..
    jmp cf940                                                         ; e53e: 4c 40 f9    l@.

; &e541 referenced 1 time by &e53c
.ce541
    jmp cf273                                                         ; e541: 4c 73 f2    l..

; &e544 referenced 1 time by &fc44
.ce544
    lda #&80                                                          ; e544: a9 80       ..
    ldy #&18                                                          ; e546: a0 18       ..
; &e548 referenced 1 time by &e54c
.loop_ce548
    sta screen_line_links,y                                           ; e548: 99 d9 00    .Y.
    dey                                                               ; e54b: 88          .
    bpl loop_ce548                                                    ; e54c: 10 fa       ..
    ldx #&18                                                          ; e54e: a2 18       ..
; &e550 referenced 1 time by &e554
.loop_ce550
    jsr sub_ce9ff                                                     ; e550: 20 ff e9     ..
    dex                                                               ; e553: ca          J
    bpl loop_ce550                                                    ; e554: 10 fa       ..
    jmp ce566                                                         ; e556: 4c 66 e5    l..

    equb &20, &94, &e5, &90, 3, &4c, &7e, &fc, 9, &e0, &4c, &89, &e5  ; e559: 20 94 e5...  ..

; &e566 referenced 1 time by &e556
.ce566
    lda #0                                                            ; e566: a9 00       ..
    sta cursor_column                                                 ; e568: 85 d3       .S
    sta cursor_row                                                    ; e56a: 85 d6       .V
; &e56c referenced 2 times by &e510, &ee22
.sub_ce56c
    jsr cebee                                                         ; e56c: 20 ee eb     ..
    jmp ceb95                                                         ; e56f: 4c 95 eb    l..

; &e572 referenced 3 times by &e762, &f06b, &fbbb
.sub_ce572
    jsr sub_ce594                                                     ; e572: 20 94 e5     ..
    bcc ce57a                                                         ; e575: 90 03       ..
    jmp lfc7e                                                         ; e577: 4c 7e fc    l..

; &e57a referenced 1 time by &e575
.ce57a
    ora #&f0                                                          ; e57a: 09 f0       ..
    sta io_temp_2                                                     ; e57c: 85 a4       ..
    jsr cfabe                                                         ; e57e: 20 be fa     ..
    bcs return_1                                                      ; e581: b0 10       ..
    jsr sub_cfe7a                                                     ; e583: 20 7a fe     ..
    jmp cf647                                                         ; e586: 4c 47 f6    lg.

; &e589 referenced 2 times by &e6b7, &fd12
.ce589
    sta io_temp_2                                                     ; e589: 85 a4       ..
    jsr cfabe                                                         ; e58b: 20 be fa     ..
    bcs return_1                                                      ; e58e: b0 03       ..
    jmp cf647                                                         ; e590: 4c 47 f6    lg.

; &e593 referenced 2 times by &e581, &e58e
.return_1
    rts                                                               ; e593: 60          .

; &e594 referenced 1 time by &e572
.sub_ce594
    cmp #&10                                                          ; e594: c9 10       I.
    bcc ce59e                                                         ; e596: 90 06       ..
    cmp #&60                                                          ; e598: c9 60       I.
    beq ce59e                                                         ; e59a: f0 02       ..
    sec                                                               ; e59c: 38          8
    rts                                                               ; e59d: 60          .

; &e59e referenced 2 times by &e596, &e59a
.ce59e
    clc                                                               ; e59e: 18          .
    rts                                                               ; e59f: 60          .

; &e5a0 referenced 1 time by &e518
.sub_ce5a0
    lda #0                                                            ; e5a0: a9 00       ..
    ldx #&2e ; '.'                                                    ; e5a2: a2 2e       ..
; &e5a4 referenced 1 time by &e5a8
.loop_ce5a4
    sta vic_sprite0_x,x                                               ; e5a4: 9d 00 d0    ..P
    dex                                                               ; e5a7: ca          J
    bpl loop_ce5a4                                                    ; e5a8: 10 fa       ..
    lda #&1b                                                          ; e5aa: a9 1b       ..
    sta vic_control_1                                                 ; e5ac: 8d 11 d0    ..P
    lda #&c8 ; 'H'                                                    ; e5af: a9 c8       .H
    sta vic_control_2                                                 ; e5b1: 8d 16 d0    ..P
    lda #&14                                                          ; e5b4: a9 14       ..
    sta vic_memory_setup                                              ; e5b6: 8d 18 d0    ..P
    lda #&0f                                                          ; e5b9: a9 0f       ..
    sta vic_interrupt_status                                          ; e5bb: 8d 19 d0    ..P ; Acknowledge the VIC-II's interrupts
    lda #colour_blue                                                  ; e5be: a9 06       ..
    sta vic_border_colour                                             ; e5c0: 8d 20 d0    . P
    sta vic_background_colour_0                                       ; e5c3: 8d 21 d0    .!P
    jmp cf336                                                         ; e5c6: 4c 36 f3    l6.

; &e5c9 referenced 1 time by &ffed
.ce5c9
    ldy #&19                                                          ; e5c9: a0 19       ..
    ldx #&28 ; '('                                                    ; e5cb: a2 28       .(
    rts                                                               ; e5cd: 60          .

; &e5ce referenced 2 times by &e5e2, &e610
.ce5ce
    pla                                                               ; e5ce: 68          .
    pla                                                               ; e5cf: 68          .
    cli                                                               ; e5d0: 58          x
    jmp cfc6c                                                         ; e5d1: 4c 6c fc    l..

; &e5d4 referenced 1 time by &e984
.sub_ce5d4
    lda cpu_port                                                      ; e5d4: a5 01       ..
    and #&10                                                          ; e5d6: 29 10       ).
    beq ce5ea                                                         ; e5d8: f0 10       ..
    ldx #&35 ; '5'                                                    ; e5da: a2 35       .5
    jsr sub_ce971                                                     ; e5dc: 20 71 e9     ..
; &e5df referenced 1 time by &e5e8
.loop_ce5df
    jsr default_stop_handler                                          ; e5df: 20 ed f6     ..
    bcs ce5ce                                                         ; e5e2: b0 ea       ..
    lda cpu_port                                                      ; e5e4: a5 01       ..
    and #&10                                                          ; e5e6: 29 10       ).
    bne loop_ce5df                                                    ; e5e8: d0 f5       P.
; &e5ea referenced 1 time by &e5d8
.ce5ea
    lda #1                                                            ; e5ea: a9 01       ..
    sta tape_motor_interlock                                          ; e5ec: 85 c0       ..
    ldx #&4f ; 'o'                                                    ; e5ee: a2 4f       .o
    jsr sub_ce971                                                     ; e5f0: 20 71 e9     ..
    jsr sub_cf7c1                                                     ; e5f3: 20 c1 f7     A.
    jmp cfb81                                                         ; e5f6: 4c 81 fb    l..

; &e5f9 referenced 2 times by &e9be, &f01b
.sub_ce5f9
    jsr sub_cfb76                                                     ; e5f9: 20 76 fb     ..
    ldx #&49 ; 'i'                                                    ; e5fc: a2 49       .i
    jsr sub_ce971                                                     ; e5fe: 20 71 e9     ..
    ldy #5                                                            ; e601: a0 05       ..
; &e603 referenced 1 time by &e60b
.loop_ce603
    lda (tape_buffer_ptr),y                                           ; e603: b1 b2       .. ; A=character to output
    jsr chrout                                                        ; e605: 20 d2 ff     R. ; Output a character
    iny                                                               ; e608: c8          H
    cpy #&15                                                          ; e609: c0 15       ..
    bne loop_ce603                                                    ; e60b: d0 f6       P.
    jsr sub_ce68a                                                     ; e60d: 20 8a e6     ..
    bcs ce5ce                                                         ; e610: b0 bc       ..
    jsr sub_ce665                                                     ; e612: 20 65 e6     ..
    bcs ce65d                                                         ; e615: b0 46       .f
    ldy #1                                                            ; e617: a0 01       ..
    lda (tape_buffer_ptr),y                                           ; e619: b1 b2       ..
    sta io_start_ptr                                                  ; e61b: 85 c1       .A
    iny                                                               ; e61d: c8          H  ; Y=2
    lda (tape_buffer_ptr),y                                           ; e61e: b1 b2       ..
    sta io_start_ptr+1                                                ; e620: 85 c2       .B
    iny                                                               ; e622: c8          H  ; Y=3
    lda (tape_buffer_ptr),y                                           ; e623: b1 b2       ..
    sta io_end_ptr                                                    ; e625: 85 ae       ..
    iny                                                               ; e627: c8          H  ; Y=4
    lda (tape_buffer_ptr),y                                           ; e628: b1 b2       ..
    sta io_end_ptr+1                                                  ; e62a: 85 af       ..
    lda secondary_address                                             ; e62c: a5 b9       ..
    bne ce652                                                         ; e62e: d0 22       P"
    sec                                                               ; e630: 38          8
    lda io_end_ptr                                                    ; e631: a5 ae       ..
    sbc io_start_ptr                                                  ; e633: e5 c1       .A
    sta io_end_ptr                                                    ; e635: 85 ae       ..
    lda io_end_ptr+1                                                  ; e637: a5 af       ..
    sbc io_start_ptr+1                                                ; e639: e5 c2       .B
    sta io_end_ptr+1                                                  ; e63b: 85 af       ..
    lda load_address_temp                                             ; e63d: a5 c3       .C
    sta io_start_ptr                                                  ; e63f: 85 c1       .A
    lda load_address_temp+1                                           ; e641: a5 c4       .D
    sta io_start_ptr+1                                                ; e643: 85 c2       .B
    clc                                                               ; e645: 18          .
    lda io_end_ptr                                                    ; e646: a5 ae       ..
    adc io_start_ptr                                                  ; e648: 65 c1       .A
    sta io_end_ptr                                                    ; e64a: 85 ae       ..
    lda io_end_ptr+1                                                  ; e64c: a5 af       ..
    adc io_start_ptr+1                                                ; e64e: 65 c2       .B
    sta io_end_ptr+1                                                  ; e650: 85 af       ..
; &e652 referenced 1 time by &e62e
.ce652
    jsr sub_cfeb0                                                     ; e652: 20 b0 fe     ..
    jsr sub_cfee5                                                     ; e655: 20 e5 fe     ..
    jsr cfb81                                                         ; e658: 20 81 fb     ..
; &e65b referenced 2 times by &e667, &e675
.ce65b
    clc                                                               ; e65b: 18          .
    rts                                                               ; e65c: 60          .

; &e65d referenced 1 time by &e615
.ce65d
    jsr sub_cf7c1                                                     ; e65d: 20 c1 f7     A.
    jsr cfb81                                                         ; e660: 20 81 fb     ..
; &e663 referenced 1 time by &e67e
.loop_ce663
    sec                                                               ; e663: 38          8
    rts                                                               ; e664: 60          .

; &e665 referenced 1 time by &e612
.sub_ce665
    lda filename_length                                               ; e665: a5 b7       ..
    beq ce65b                                                         ; e667: f0 f2       ..
    ldy #0                                                            ; e669: a0 00       ..
; &e66b referenced 1 time by &e686
.loop_ce66b
    lda #&20 ; ' '                                                    ; e66b: a9 20       .
    cpy filename_length                                               ; e66d: c4 b7       D.
    bcs ce673                                                         ; e66f: b0 02       ..
    lda (filename_ptr),y                                              ; e671: b1 bb       ..
; &e673 referenced 1 time by &e66f
.ce673
    cmp #&2a ; '*'                                                    ; e673: c9 2a       I*
    beq ce65b                                                         ; e675: f0 e4       ..
    iny                                                               ; e677: c8          H
    iny                                                               ; e678: c8          H
    iny                                                               ; e679: c8          H
    iny                                                               ; e67a: c8          H
    iny                                                               ; e67b: c8          H
    cmp (tape_buffer_ptr),y                                           ; e67c: d1 b2       Q.
    bne loop_ce663                                                    ; e67e: d0 e3       P.
    dey                                                               ; e680: 88          .
    dey                                                               ; e681: 88          .
    dey                                                               ; e682: 88          .
    dey                                                               ; e683: 88          .
    cpy #&10                                                          ; e684: c0 10       ..
    bne loop_ce66b                                                    ; e686: d0 e3       P.
    clc                                                               ; e688: 18          .
    rts                                                               ; e689: 60          .

; &e68a referenced 1 time by &e60d
.sub_ce68a
    ldy #0                                                            ; e68a: a0 00       ..
; &e68c referenced 1 time by &e6a1
.loop_ce68c
    jsr ce4f1                                                         ; e68c: 20 f1 e4     ..
    lda stop_key_flag                                                 ; e68f: a5 91       ..
    bpl ce6a5                                                         ; e691: 10 12       ..
    and #&10                                                          ; e693: 29 10       ).
    beq ce6a3                                                         ; e695: f0 0c       ..
    ldx #&80                                                          ; e697: a2 80       ..
    jsr sub_cf972                                                     ; e699: 20 72 f9     ..
    dex                                                               ; e69c: ca          J
    jsr sub_cf972                                                     ; e69d: 20 72 f9     ..
    dey                                                               ; e6a0: 88          .
    bne loop_ce68c                                                    ; e6a1: d0 e9       P.
; &e6a3 referenced 1 time by &e695
.ce6a3
    clc                                                               ; e6a3: 18          .
    rts                                                               ; e6a4: 60          .

; &e6a5 referenced 1 time by &e691
.ce6a5
    sec                                                               ; e6a5: 38          8
    rts                                                               ; e6a6: 60          .

; &e6a7 referenced 2 times by &e9f9, &f040
.ce6a7
    jsr sub_cfb76                                                     ; e6a7: 20 76 fb     ..
    jsr sub_cff17                                                     ; e6aa: 20 17 ff     ..
    jmp cff3d                                                         ; e6ad: 4c 3d ff    l=.

; &e6b0 referenced 5 times by &e9fc, &f009, &f02a, &f032, &f03d
.ce6b0
    jsr sub_cfb76                                                     ; e6b0: 20 76 fb     ..
    jmp cff4f                                                         ; e6b3: 4c 4f ff    lo.

    equb &60                                                          ; e6b6: 60          .

; &e6b7 referenced 2 times by &e539, &ff93
.ce6b7
    jmp ce589                                                         ; e6b7: 4c 89 e5    l..

; &e6ba referenced 1 time by &e7ae
.ce6ba
    sei                                                               ; e6ba: 78          .
    ldy #0                                                            ; e6bb: a0 00       ..
    lda cia2_port_a                                                   ; e6bd: ad 00 dd    ...
    and #&c7 ; 'G'                                                    ; e6c0: 29 c7       )G
    sta io_temp_1                                                     ; e6c2: 85 a3       ..
    ora #&20 ; ' '                                                    ; e6c4: 09 20       .
    sta io_temp_2                                                     ; e6c6: 85 a4       ..
; &e6c8 referenced 3 times by &e6cb, &e6fa, &e6fe
.ce6c8
    bit cia2_port_a                                                   ; e6c8: 2c 00 dd    ,..
    bvc ce6c8                                                         ; e6cb: 50 fb       p.
    lda io_temp_1                                                     ; e6cd: a5 a3       ..
    sta cia2_port_a                                                   ; e6cf: 8d 00 dd    ...
    ldx #&13                                                          ; e6d2: a2 13       ..
; &e6d4 referenced 1 time by &e6da
.loop_ce6d4
    bit cia2_port_a                                                   ; e6d4: 2c 00 dd    ,..
    bvc ce6ef                                                         ; e6d7: 50 16       p.
    dex                                                               ; e6d9: ca          J
    bne loop_ce6d4                                                    ; e6da: d0 f8       P.
    jsr sub_cfa81                                                     ; e6dc: 20 81 fa     ..
    lda cia2_port_b                                                   ; e6df: ad 01 dd    ...
    sta (io_end_ptr),y                                                ; e6e2: 91 ae       ..
    sec                                                               ; e6e4: 38          8
    jsr sub_cf86a                                                     ; e6e5: 20 6a f8     ..
    lda #2                                                            ; e6e8: a9 02       ..
    sta io_temp_1                                                     ; e6ea: 85 a3       ..
    jmp ce7da                                                         ; e6ec: 4c da e7    lZ.

; &e6ef referenced 1 time by &e6d7
.ce6ef
    lda cia2_port_b                                                   ; e6ef: ad 01 dd    ...
    sta (io_end_ptr),y                                                ; e6f2: 91 ae       ..
    lda io_temp_2                                                     ; e6f4: a5 a4       ..
    sta cia2_port_a                                                   ; e6f6: 8d 00 dd    ...
    iny                                                               ; e6f9: c8          H
    bne ce6c8                                                         ; e6fa: d0 cc       PL
    inc io_end_ptr+1                                                  ; e6fc: e6 af       ..
    jmp ce6c8                                                         ; e6fe: 4c c8 e6    lH.

    equb &60                                                          ; e701: 60          .

; &e702 referenced 2 times by &f17e, &f2eb
.sub_ce702
    lda vic_raster_line                                               ; e702: ad 12 d0    ..P
    cmp #&2e ; '.'                                                    ; e705: c9 2e       I.
    bcc return_2                                                      ; e707: 90 0c       ..
; &e709 referenced 1 time by &e713
.loop_ce709
    lda vic_raster_line                                               ; e709: ad 12 d0    ..P
    sbc vic_control_1                                                 ; e70c: ed 11 d0    ..P
    and #7                                                            ; e70f: 29 07       ).
    cmp #6                                                            ; e711: c9 06       I.
    bcs loop_ce709                                                    ; e713: b0 f4       ..
; &e715 referenced 1 time by &e707
.return_2
    rts                                                               ; e715: 60          .

    equb &60                                                          ; e716: 60          .

; &e717 referenced 6 times by &e71a, &ef2f, &ef4d, &ef8b, &f175, &fa40
.ce717
    bit cia2_port_a                                                   ; e717: 2c 00 dd    ,..
    bvc ce717                                                         ; e71a: 50 fb       p.
    rts                                                               ; e71c: 60          .

; &e71d referenced 1 time by &edf0
.sub_ce71d
    cmp #&e0                                                          ; e71d: c9 e0       I.
    bcs ce728                                                         ; e71f: b0 07       ..
    cmp #&c0                                                          ; e721: c9 c0       I.
    bcc ce728                                                         ; e723: 90 03       ..
    and #&7f                                                          ; e725: 29 7f       ).
    rts                                                               ; e727: 60          .

; &e728 referenced 2 times by &e71f, &e723
.ce728
    cmp #&40 ; '@'                                                    ; e728: c9 40       I@
    bcc return_3                                                      ; e72a: 90 0e       ..
    sec                                                               ; e72c: 38          8
    sbc #&40 ; '@'                                                    ; e72d: e9 40       .@
    cmp #&20 ; ' '                                                    ; e72f: c9 20       I
    bcc return_3                                                      ; e731: 90 07       ..
    cmp #&40 ; '@'                                                    ; e733: c9 40       I@
    bcs return_3                                                      ; e735: b0 03       ..
    clc                                                               ; e737: 18          .
    adc #&20 ; ' '                                                    ; e738: 69 20       .
; &e73a referenced 3 times by &e72a, &e731, &e735
.return_3
    rts                                                               ; e73a: 60          .

; &e73b referenced 2 times by &e75e, &e765
.ce73b
    jmp cff43                                                         ; e73b: 4c 43 ff    lc.

; &e73e referenced 6 times by &e76a, &e771, &e77a, &e782, &e7b4, &e7b9
.ce73e
    lda device_number                                                 ; e73e: a5 ba       ..
    jsr sub_cfa1e                                                     ; e740: 20 1e fa     ..
    jmp cff4f                                                         ; e743: 4c 4f ff    lo.

; &e746 referenced 1 time by &e7d1
.ce746
    pla                                                               ; e746: 68          .
    lda device_number                                                 ; e747: a5 ba       ..
    jsr sub_cfa1e                                                     ; e749: 20 1e fa     ..
    jmp cfc6c                                                         ; e74c: 4c 6c fc    l..

; &e74f referenced 1 time by &f4c7
.ce74f
    lda filename_length                                               ; e74f: a5 b7       ..
    bne ce756                                                         ; e751: d0 03       P.
    jmp lfc84                                                         ; e753: 4c 84 fc    l..

; &e756 referenced 1 time by &e751
.ce756
    jsr sub_cfecb                                                     ; e756: 20 cb fe     K.
    lda device_number                                                 ; e759: a5 ba       ..
    jsr cf4cd                                                         ; e75b: 20 cd f4     M.
    bcs ce73b                                                         ; e75e: b0 db       ..
    lda #0                                                            ; e760: a9 00       ..
    jsr sub_ce572                                                     ; e762: 20 72 e5     ..
    bcs ce73b                                                         ; e765: b0 d4       .T
    jsr sub_cfb40                                                     ; e767: 20 40 fb     @.
    bcs ce73e                                                         ; e76a: b0 d2       .R
    lda device_number                                                 ; e76c: a5 ba       ..
    jsr cf3f7                                                         ; e76e: 20 f7 f3     ..
    bcs ce73e                                                         ; e771: b0 cb       .K
    lda #&60                                                          ; e773: a9 60       ..
    sta io_temp_2                                                     ; e775: 85 a4       ..
    jsr cfabe                                                         ; e777: 20 be fa     ..
    bcs ce73e                                                         ; e77a: b0 c2       .B
    jsr sub_cfe7a                                                     ; e77c: 20 7a fe     ..
    jsr cfb91                                                         ; e77f: 20 91 fb     ..
    bcs ce73e                                                         ; e782: b0 ba       ..
    jsr sub_ce7e5                                                     ; e784: 20 e5 e7     ..
    sta io_end_ptr                                                    ; e787: 85 ae       ..
    jsr sub_ce7e5                                                     ; e789: 20 e5 e7     ..
    sta io_end_ptr+1                                                  ; e78c: 85 af       ..
    lda secondary_address                                             ; e78e: a5 b9       ..
    bne ce79a                                                         ; e790: d0 08       P.
    lda io_start_ptr                                                  ; e792: a5 c1       .A
    sta io_end_ptr                                                    ; e794: 85 ae       ..
    lda io_start_ptr+1                                                ; e796: a5 c2       .B
    sta io_end_ptr+1                                                  ; e798: 85 af       ..
; &e79a referenced 1 time by &e790
.ce79a
    jsr sub_cfee5                                                     ; e79a: 20 e5 fe     ..
    lda load_verify_flag                                              ; e79d: a5 93       ..
    bne ce7b1                                                         ; e79f: d0 10       P.
    lda io_temp_1                                                     ; e7a1: a5 a3       ..
    cmp #1                                                            ; e7a3: c9 01       I.
    bne ce7aa                                                         ; e7a5: d0 03       P.
    jmp cef7d                                                         ; e7a7: 4c 7d ef    l..

; &e7aa referenced 1 time by &e7a5
.ce7aa
    cmp #2                                                            ; e7aa: c9 02       I.
    bne ce7b1                                                         ; e7ac: d0 03       P.
    jmp ce6ba                                                         ; e7ae: 4c ba e6    l..

; &e7b1 referenced 3 times by &e79f, &e7ac, &e7d8
.ce7b1
    jsr cef21                                                         ; e7b1: 20 21 ef     !.
    bcs ce73e                                                         ; e7b4: b0 88       ..
    jsr sub_cfe99                                                     ; e7b6: 20 99 fe     ..
    bcs ce73e                                                         ; e7b9: b0 83       ..
    inc io_end_ptr                                                    ; e7bb: e6 ae       ..
    bne ce7c1                                                         ; e7bd: d0 02       P.
    inc io_end_ptr+1                                                  ; e7bf: e6 af       ..
; &e7c1 referenced 1 time by &e7bd
.ce7c1
    lda io_end_ptr                                                    ; e7c1: a5 ae       ..
    and #&1f                                                          ; e7c3: 29 1f       ).
    bne ce7d6                                                         ; e7c5: d0 0f       P.
    txa                                                               ; e7c7: 8a          .
    pha                                                               ; e7c8: 48          h
    jsr ce4f1                                                         ; e7c9: 20 f1 e4     ..
    jsr default_stop_handler                                          ; e7cc: 20 ed f6     ..
    bcc ce7d4                                                         ; e7cf: 90 03       ..
    jmp ce746                                                         ; e7d1: 4c 46 e7    lf.

; &e7d4 referenced 1 time by &e7cf
.ce7d4
    pla                                                               ; e7d4: 68          .
    tax                                                               ; e7d5: aa          .
; &e7d6 referenced 1 time by &e7c5
.ce7d6
    bit io_status                                                     ; e7d6: 24 90       $.
    bvc ce7b1                                                         ; e7d8: 50 d7       pW
; &e7da referenced 2 times by &e6ec, &efe0
.ce7da
    jsr sub_cff17                                                     ; e7da: 20 17 ff     ..
    lda device_number                                                 ; e7dd: a5 ba       ..
    jsr sub_cfa1e                                                     ; e7df: 20 1e fa     ..
    jmp cff3d                                                         ; e7e2: 4c 3d ff    l=.

; &e7e5 referenced 2 times by &e784, &e789
.sub_ce7e5
    jsr cef21                                                         ; e7e5: 20 21 ef     !.
    bcs ce7f3                                                         ; e7e8: b0 09       ..
    lda io_status                                                     ; e7ea: a5 90       ..
    and #&40 ; '@'                                                    ; e7ec: 29 40       )@
    bne ce7f3                                                         ; e7ee: d0 03       P.
    lda io_temp_2                                                     ; e7f0: a5 a4       ..
    rts                                                               ; e7f2: 60          .

; &e7f3 referenced 2 times by &e7e8, &e7ee
.ce7f3
    pla                                                               ; e7f3: 68          .
    pla                                                               ; e7f4: 68          .
    lda device_number                                                 ; e7f5: a5 ba       ..
    jsr sub_cfa1e                                                     ; e7f7: 20 1e fa     ..
    jmp lfc78                                                         ; e7fa: 4c 78 fc    l..

; &e7fd referenced 1 time by &ff9f
.ce7fd
    lda shift_key_flags                                               ; e7fd: ad 8d 02    ...
    sta last_shift_key_flags                                          ; e800: 8d 8e 02    ...
    lda #0                                                            ; e803: a9 00       ..
    sta shift_key_flags                                               ; e805: 8d 8d 02    ...
    ldx #0                                                            ; e808: a2 00       ..
    stx cia1_port_a                                                   ; e80a: 8e 00 dc    ...
    dex                                                               ; e80d: ca          J  ; X=&ff
    cpx cia1_port_b                                                   ; e80e: ec 01 dc    ...
    beq ce885                                                         ; e811: f0 72       ..
    ldy #3                                                            ; e813: a0 03       ..
; &e815 referenced 1 time by &e82d
.loop_ce815
    lda lf8cb,y                                                       ; e815: b9 cb f8    .K.
    sta cia1_port_a                                                   ; e818: 8d 00 dc    ...
    lda lf8cf,y                                                       ; e81b: b9 cf f8    .O.
    and cia1_port_b                                                   ; e81e: 2d 01 dc    -..
    bne ce82c                                                         ; e821: d0 09       P.
    lda shift_key_flags                                               ; e823: ad 8d 02    ...
    ora lf8d3,y                                                       ; e826: 19 d3 f8    .S.
    sta shift_key_flags                                               ; e829: 8d 8d 02    ...
; &e82c referenced 1 time by &e821
.ce82c
    dey                                                               ; e82c: 88          .
    bpl loop_ce815                                                    ; e82d: 10 e6       ..
    lda keyboard_table_setup_vector+1                                 ; e82f: ad 90 02    ...
    bne ce83a                                                         ; e832: d0 06       P.
    jsr sub_ceb48                                                     ; e834: 20 48 eb     h.
    jmp ce83d                                                         ; e837: 4c 3d e8    l=.

; &e83a referenced 1 time by &e832
.ce83a
    jsr sub_cf169                                                     ; e83a: 20 69 f1     ..
; &e83d referenced 1 time by &e837
.ce83d
    jsr sub_cf7cb                                                     ; e83d: 20 cb f7     K.
    cpx cia1_port_b                                                   ; e840: ec 01 dc    ...
    bne ce885                                                         ; e843: d0 40       P@
    lda keyboard_table_ptr+1                                          ; e845: a5 f6       ..
    beq ce885                                                         ; e847: f0 3c       .<
    ldy #&ff                                                          ; e849: a0 ff       ..
    ldx #7                                                            ; e84b: a2 07       ..
; &e84d referenced 1 time by &e877
.ce84d
    lda lf80b,x                                                       ; e84d: bd 0b f8    ...
    sta cia1_port_a                                                   ; e850: 8d 00 dc    ...
    lda lf82b,x                                                       ; e853: bd 2b f8    .+.
    ora cia1_port_b                                                   ; e856: 0d 01 dc    ...
    cmp #&ff                                                          ; e859: c9 ff       I.
    beq ce876                                                         ; e85b: f0 19       ..
    cpy #&ff                                                          ; e85d: c0 ff       ..
    bne ce885                                                         ; e85f: d0 24       P$
    ldy #7                                                            ; e861: a0 07       ..
; &e863 referenced 1 time by &e872
.loop_ce863
    cmp lf80b,y                                                       ; e863: d9 0b f8    Y..
    bne ce871                                                         ; e866: d0 09       P.
    tya                                                               ; e868: 98          .
    clc                                                               ; e869: 18          .
    adc lf81b,x                                                       ; e86a: 7d 1b f8    ...
    tay                                                               ; e86d: a8          .
    jmp ce876                                                         ; e86e: 4c 76 e8    l..

; &e871 referenced 1 time by &e866
.ce871
    dey                                                               ; e871: 88          .
    bpl loop_ce863                                                    ; e872: 10 ef       ..
    bmi ce885                                                         ; e874: 30 0f       0. ; ALWAYS branch

; &e876 referenced 2 times by &e85b, &e86e
.ce876
    dex                                                               ; e876: ca          J
    bpl ce84d                                                         ; e877: 10 d4       .T
    cpy #&ff                                                          ; e879: c0 ff       ..
    beq ce885                                                         ; e87b: f0 08       ..
    jsr sub_cf7cb                                                     ; e87d: 20 cb f7     K.
    cpx cia1_port_b                                                   ; e880: ec 01 dc    ...
    beq ce88a                                                         ; e883: f0 05       ..
; &e885 referenced 7 times by &e811, &e843, &e847, &e85f, &e874, &e87b, &e8a3
.ce885
    lda #&40 ; '@'                                                    ; e885: a9 40       .@
    sta last_key_pressed                                              ; e887: 85 c5       .E
    rts                                                               ; e889: 60          .

; &e88a referenced 1 time by &e883
.ce88a
    cpy last_key_pressed                                              ; e88a: c4 c5       DE
    beq ce8ad                                                         ; e88c: f0 1f       ..
    sty last_key_pressed                                              ; e88e: 84 c5       .E
    lda #&16                                                          ; e890: a9 16       ..
    sta key_repeat_delay                                              ; e892: 8d 8c 02    ...
; &e895 referenced 1 time by &e8cb
.ce895
    lda keyboard_buffer_length                                        ; e895: a5 c6       .F
    cmp keyboard_buffer_size                                          ; e897: cd 89 02    M..
    bcs ce8d1                                                         ; e89a: b0 35       .5
    lda #3                                                            ; e89c: a9 03       ..
    sta key_repeat_counter                                            ; e89e: 8d 8b 02    ...
    lda (keyboard_table_ptr),y                                        ; e8a1: b1 f5       ..
    beq ce885                                                         ; e8a3: f0 e0       ..
    ldy keyboard_buffer_length                                        ; e8a5: a4 c6       .F
    sta keyboard_buffer,y                                             ; e8a7: 99 77 02    ...
    inc keyboard_buffer_length                                        ; e8aa: e6 c6       .F
; &e8ac referenced 1 time by &e8bd
.return_4
    rts                                                               ; e8ac: 60          .

; &e8ad referenced 1 time by &e88c
.ce8ad
    lda key_repeat_flags                                              ; e8ad: ad 8a 02    ...
    bmi ce8bf                                                         ; e8b0: 30 0d       0.
    tya                                                               ; e8b2: 98          .
    ldx #3                                                            ; e8b3: a2 03       ..
; &e8b5 referenced 1 time by &e8bb
.loop_ce8b5
    cmp lea87,x                                                       ; e8b5: dd 87 ea    ...
    beq ce8bf                                                         ; e8b8: f0 05       ..
    dex                                                               ; e8ba: ca          J
    bpl loop_ce8b5                                                    ; e8bb: 10 f8       ..
    bmi return_4                                                      ; e8bd: 30 ed       0. ; ALWAYS branch

; &e8bf referenced 2 times by &e8b0, &e8b8
.ce8bf
    lda key_repeat_delay                                              ; e8bf: ad 8c 02    ...
    beq ce8c8                                                         ; e8c2: f0 04       ..
    dec key_repeat_delay                                              ; e8c4: ce 8c 02    N..
    rts                                                               ; e8c7: 60          .

; &e8c8 referenced 1 time by &e8c2
.ce8c8
    lda key_repeat_counter                                            ; e8c8: ad 8b 02    ...
    beq ce895                                                         ; e8cb: f0 c8       .H
    dec key_repeat_counter                                            ; e8cd: ce 8b 02    N..
    rts                                                               ; e8d0: 60          .

; &e8d1 referenced 1 time by &e89a
.ce8d1
    lda #0                                                            ; e8d1: a9 00       ..
    sta key_repeat_delay                                              ; e8d3: 8d 8c 02    ...
    sta key_repeat_counter                                            ; e8d6: 8d 8b 02    ...
    rts                                                               ; e8d9: 60          .

; &e8da referenced 1 time by &fe14
.le8da
    equb &90,   5, &1c, &9f, &9c, &1e, &1f, &9e, &81, &95, &96, &97   ; e8da: 90 05 1c... ...
    equb &98, &99, &9a, &9b                                           ; e8e6: 98 99 9a... ...

; &e8ea referenced 3 times by &e955, &f412, &f9aa
.ce8ea
    lda shift_key_flags                                               ; e8ea: ad 8d 02    ...
    and #4                                                            ; e8ed: 29 04       ).
    beq ce8fb                                                         ; e8ef: f0 0a       ..
    ldy #9                                                            ; e8f1: a0 09       ..
; &e8f3 referenced 1 time by &e8f9
.loop_ce8f3
    ldx #&ff                                                          ; e8f3: a2 ff       ..
    jsr sub_cf972                                                     ; e8f5: 20 72 f9     ..
    dey                                                               ; e8f8: 88          .
    bne loop_ce8f3                                                    ; e8f9: d0 f8       P.
; &e8fb referenced 1 time by &e8ef
.ce8fb
    ; Copy 24 bytes of memory from screen_line_links+1 to screen_line_links
    ldy #0                                                            ; e8fb: a0 00       ..
; &e8fd referenced 1 time by &e906
.loop_ce8fd
    lda screen_line_links+1,y                                         ; e8fd: b9 da 00    .Z.
    sta screen_line_links,y                                           ; e900: 99 d9 00    .Y.
    iny                                                               ; e903: c8          H
    cpy #&18                                                          ; e904: c0 18       ..
    bne loop_ce8fd                                                    ; e906: d0 f5       P.
    lda #&80                                                          ; e908: a9 80       ..
    sta screen_line_links+24                                          ; e90a: 85 f1       ..
    jsr sub_cf9df                                                     ; e90c: 20 df f9     ..
    lda screen_memory_page                                            ; e90f: ad 88 02    ...
    sta io_address_ptr+1                                              ; e912: 85 ad       ..
    sta io_end_ptr+1                                                  ; e914: 85 af       ..
    lda #&d8 ; 'X'                                                    ; e916: a9 d8       .X
    sta screen_line_ptr+1                                             ; e918: 85 d2       .R
    sta colour_ram_line_ptr+1                                         ; e91a: 85 f4       ..
    lda #0                                                            ; e91c: a9 00       ..
    sta io_end_ptr                                                    ; e91e: 85 ae       ..
    sta colour_ram_line_ptr                                           ; e920: 85 f3       ..
    lda #&28 ; '('                                                    ; e922: a9 28       .(
    sta io_address_ptr                                                ; e924: 85 ac       ..
    sta screen_line_ptr                                               ; e926: 85 d1       .Q
    ldy #0                                                            ; e928: a0 00       ..
; &e92a referenced 2 times by &e93d, &e947
.ce92a
    lda (io_address_ptr),y                                            ; e92a: b1 ac       ..
    sta (io_end_ptr),y                                                ; e92c: 91 ae       ..
    lda (screen_line_ptr),y                                           ; e92e: b1 d1       .Q
    sta (colour_ram_line_ptr),y                                       ; e930: 91 f3       ..
    cpy #&bf                                                          ; e932: c0 bf       ..
    bne ce93c                                                         ; e934: d0 06       P.
    lda colour_ram_line_ptr+1                                         ; e936: a5 f4       ..
    cmp #&db                                                          ; e938: c9 db       I.
    beq ce949                                                         ; e93a: f0 0d       ..
; &e93c referenced 1 time by &e934
.ce93c
    iny                                                               ; e93c: c8          H
    bne ce92a                                                         ; e93d: d0 eb       P.
    inc io_address_ptr+1                                              ; e93f: e6 ad       ..
    inc io_end_ptr+1                                                  ; e941: e6 af       ..
    inc colour_ram_line_ptr+1                                         ; e943: e6 f4       ..
    inc screen_line_ptr+1                                             ; e945: e6 d2       .R
    bne ce92a                                                         ; e947: d0 e1       P.
; &e949 referenced 1 time by &e93a
.ce949
    jsr sub_cfe34                                                     ; e949: 20 34 fe     4.
    ldx #&18                                                          ; e94c: a2 18       ..
    jsr sub_ce9ff                                                     ; e94e: 20 ff e9     ..
    dec cursor_row                                                    ; e951: c6 d6       FV
    bit screen_line_links                                             ; e953: 24 d9       $Y
    bpl ce8ea                                                         ; e955: 10 93       ..
    jmp cebee                                                         ; e957: 4c ee eb    l..

; &e95a referenced 7 times by &e99c, &e9a6, &e9dc, &e9ee, &ecfa, &ed10, &ed1d
.sub_ce95a
    txa                                                               ; e95a: 8a          .
    pha                                                               ; e95b: 48          h
    lda #1                                                            ; e95c: a9 01       ..
    sta rs232_input_bits                                              ; e95e: 85 a7       ..
; &e960 referenced 1 time by &e965
.loop_ce960
    jsr sub_cfb25                                                     ; e960: 20 25 fb     %.
    rol rs232_input_bits                                              ; e963: 26 a7       &.
    bcc loop_ce960                                                    ; e965: 90 f9       ..
    pla                                                               ; e967: 68          .
    tax                                                               ; e968: aa          .
    lda rs232_input_bits                                              ; e969: a5 a7       ..
    rts                                                               ; e96b: 60          .

    equb &60                                                          ; e96c: 60          .

; &e96d referenced 1 time by &e974
.loop_ce96d
    jsr chrout                                                        ; e96d: 20 d2 ff     R. ; Output a character
    inx                                                               ; e970: e8          .
; &e971 referenced 8 times by &e5dc, &e5f0, &e5fe, &fed1, &fef1, &fef6, &ff1d, &ff29
.sub_ce971
    lda lead1,x                                                       ; e971: bd d1 ea    .Q.
    bpl loop_ce96d                                                    ; e974: 10 f7       ..
    and #&7f                                                          ; e976: 29 7f       ). ; A=character to output
    jmp chrout                                                        ; e978: 4c d2 ff    lR. ; Output a character

; &e97b referenced 2 times by &f4b8, &f4bf
.ce97b
    jsr sub_cf856                                                     ; e97b: 20 56 f8     v.
    jsr sub_cf8b4                                                     ; e97e: 20 b4 f8     ..
    jsr sub_cfa60                                                     ; e981: 20 60 fa     ..
    jsr sub_ce5d4                                                     ; e984: 20 d4 e5     T.
; &e987 referenced 1 time by &eff6
.ce987
    jsr sub_ced5f                                                     ; e987: 20 5f ed     ..
    bcs ce98f                                                         ; e98a: b0 03       ..
    jmp cefe3                                                         ; e98c: 4c e3 ef    l..

; &e98f referenced 2 times by &e98a, &e9c1
.ce98f
    jsr ceceb                                                         ; e98f: 20 eb ec     ..
    bcc ce997                                                         ; e992: 90 03       ..
    jmp cefe3                                                         ; e994: 4c e3 ef    l..

; &e997 referenced 1 time by &e992
.ce997
    ldy #0                                                            ; e997: a0 00       ..
    sta (tape_buffer_ptr),y                                           ; e999: 91 b2       ..
    iny                                                               ; e99b: c8          H  ; Y=1
; &e99c referenced 1 time by &e9ab
.loop_ce99c
    jsr sub_ce95a                                                     ; e99c: 20 5a e9     z.
    sta (tape_buffer_ptr),y                                           ; e99f: 91 b2       ..
    iny                                                               ; e9a1: c8          H
    cpy #5                                                            ; e9a2: c0 05       ..
    bne ce9a9                                                         ; e9a4: d0 03       P.
    jsr sub_ce95a                                                     ; e9a6: 20 5a e9     z.
; &e9a9 referenced 1 time by &e9a4
.ce9a9
    cpy #&c0                                                          ; e9a9: c0 c0       ..
    bne loop_ce99c                                                    ; e9ab: d0 ef       P.
    ldy #0                                                            ; e9ad: a0 00       ..
    lda (tape_buffer_ptr),y                                           ; e9af: b1 b2       ..
    beq ce9bb                                                         ; e9b1: f0 08       ..
    and #1                                                            ; e9b3: 29 01       ).
    bne ce9bb                                                         ; e9b5: d0 04       P.
    lda #1                                                            ; e9b7: a9 01       ..
    sta secondary_address                                             ; e9b9: 85 b9       ..
; &e9bb referenced 2 times by &e9b1, &e9b5
.ce9bb
    jsr sub_cf8b4                                                     ; e9bb: 20 b4 f8     ..
    jsr sub_ce5f9                                                     ; e9be: 20 f9 e5     ..
    bcs ce98f                                                         ; e9c1: b0 cc       .L
    ; Copy 11 bytes of memory from lf33f to l0100
    ldx #&0a                                                          ; e9c3: a2 0a       ..
; &e9c5 referenced 1 time by &e9cc
.loop_ce9c5
    lda lf33f,x                                                       ; e9c5: bd 3f f3    .?.
    sta l0100,x                                                       ; e9c8: 9d 00 01    ...
    dex                                                               ; e9cb: ca          J
    bpl loop_ce9c5                                                    ; e9cc: 10 f7       ..
    lda cpu_port                                                      ; e9ce: a5 01       ..
    sta l0107                                                         ; e9d0: 8d 07 01    ...
    lda #0                                                            ; e9d3: a9 00       ..
    sta tape_parity                                                   ; e9d5: 85 9b       ..
; &e9d7 referenced 1 time by &e9da
.loop_ce9d7
    jsr ced09                                                         ; e9d7: 20 09 ed     ..
    bcs loop_ce9d7                                                    ; e9da: b0 fb       ..
; &e9dc referenced 1 time by &e9ec
.loop_ce9dc
    jsr sub_ce95a                                                     ; e9dc: 20 5a e9     z.
    jsr l0100                                                         ; e9df: 20 00 01     ..
    eor tape_parity                                                   ; e9e2: 45 9b       e.
    sta tape_parity                                                   ; e9e4: 85 9b       ..
    jsr sub_cfeb9                                                     ; e9e6: 20 b9 fe     ..
    jsr sub_cfec0                                                     ; e9e9: 20 c0 fe     ..
    bne loop_ce9dc                                                    ; e9ec: d0 ee       P.
    jsr sub_ce95a                                                     ; e9ee: 20 5a e9     z.
    tax                                                               ; e9f1: aa          .
    jsr sub_cf8b4                                                     ; e9f2: 20 b4 f8     ..
    cpx tape_parity                                                   ; e9f5: e4 9b       ..
    bne ce9fc                                                         ; e9f7: d0 03       P.
    jmp ce6a7                                                         ; e9f9: 4c a7 e6    l..

; &e9fc referenced 1 time by &e9f7
.ce9fc
    jmp ce6b0                                                         ; e9fc: 4c b0 e6    l..

; &e9ff referenced 3 times by &e550, &e94e, &f498
.sub_ce9ff
    txa                                                               ; e9ff: 8a          .
    pha                                                               ; ea00: 48          h
    jsr sub_cebf0                                                     ; ea01: 20 f0 eb     ..
    pla                                                               ; ea04: 68          .
    tax                                                               ; ea05: aa          .
    ldy #&27 ; '''                                                    ; ea06: a0 27       .'
; &ea08 referenced 1 time by &ea12
.loop_cea08
    lda text_colour                                                   ; ea08: ad 86 02    ...
    sta (colour_ram_line_ptr),y                                       ; ea0b: 91 f3       ..
    lda #&20 ; ' '                                                    ; ea0d: a9 20       .
    sta (screen_line_ptr),y                                           ; ea0f: 91 d1       .Q
    dey                                                               ; ea11: 88          .
    bpl loop_cea08                                                    ; ea12: 10 f4       ..
    rts                                                               ; ea14: 60          .

; &ea15 referenced 3 times by &ea2b, &ee35, &eed0
.cea15
    lda #colour_blue                                                  ; ea15: a9 06       ..
    sta vic_border_colour                                             ; ea17: 8d 20 d0    . P
    jsr cf9fe                                                         ; ea1a: 20 fe f9     ..
    bcs cea2f                                                         ; ea1d: b0 10       ..
    jsr sub_cec7f                                                     ; ea1f: 20 7f ec     ..
    bcs cea2f                                                         ; ea22: b0 0b       ..
    cpy rs232_input_bits                                              ; ea24: c4 a7       D.
    bne cea2f                                                         ; ea26: d0 07       P.
    dey                                                               ; ea28: 88          .
    and #&7e                                                          ; ea29: 29 7e       ).
    bne cea15                                                         ; ea2b: d0 e8       P.
    clc                                                               ; ea2d: 18          .
    rts                                                               ; ea2e: 60          .

; &ea2f referenced 3 times by &ea1d, &ea22, &ea26
.cea2f
    sec                                                               ; ea2f: 38          8
    rts                                                               ; ea30: 60          .

; &ea31 referenced 1 time by &ea69
.default_irq_handler
    jsr sub_ced9a                                                     ; ea31: 20 9a ed     ..
    jsr scnkey                                                        ; ea34: 20 9f ff     .. ; Scan the keyboard
    jsr udtim                                                         ; ea37: 20 ea ff     .. ; Update the jiffy clock and check the RUN/STOP key
    lda cpu_port                                                      ; ea3a: a5 01       ..
    and #&10                                                          ; ea3c: 29 10       ).
    beq cea49                                                         ; ea3e: f0 09       ..
    jsr sub_cf8e3                                                     ; ea40: 20 e3 f8     ..
    lda #0                                                            ; ea43: a9 00       ..
    sta tape_motor_interlock                                          ; ea45: 85 c0       ..
    beq cea50                                                         ; ea47: f0 07       .. ; ALWAYS branch

; &ea49 referenced 1 time by &ea3e
.cea49
    lda tape_motor_interlock                                          ; ea49: a5 c0       ..
    bne cea50                                                         ; ea4b: d0 03       P.
    jsr cf8e9                                                         ; ea4d: 20 e9 f8     ..
; &ea50 referenced 2 times by &ea47, &ea4b
.cea50
    jmp cea7e                                                         ; ea50: 4c 7e ea    l..

.irq_entry
    ; push A,X,Y onto the stack
    pha                                                               ; ea53: 48          h
    txa                                                               ; ea54: 8a          .
    pha                                                               ; ea55: 48          h
    tya                                                               ; ea56: 98          .
    pha                                                               ; ea57: 48          h
    cld                                                               ; ea58: d8          X
    tsx                                                               ; ea59: ba          .
    lda l0104,x                                                       ; ea5a: bd 04 01    ...
    and #&10                                                          ; ea5d: 29 10       ).
    bne cea6c                                                         ; ea5f: d0 0b       P.
    lda irq_vector+1                                                  ; ea61: ad 15 03    ...
    beq cea69                                                         ; ea64: f0 03       ..
    jmp (irq_vector)                                                  ; ea66: 6c 14 03    ...

; &ea69 referenced 1 time by &ea64
.cea69
    jmp default_irq_handler                                           ; ea69: 4c 31 ea    l1.

; &ea6c referenced 1 time by &ea5f
.cea6c
    sec                                                               ; ea6c: 38          8
    lda l0105,x                                                       ; ea6d: bd 05 01    ...
    sbc #2                                                            ; ea70: e9 02       ..
    sta tape_timing_constant                                          ; ea72: 85 b0       ..
    lda l0106,x                                                       ; ea74: bd 06 01    ...
    sbc #0                                                            ; ea77: e9 00       ..
    sta tape_timing_constant+1                                        ; ea79: 85 b1       ..
    jmp (brk_vector)                                                  ; ea7b: 6c 16 03    ...

; &ea7e referenced 1 time by &ea50
.cea7e
    ldy cia1_interrupt_control                                        ; ea7e: ac 0d dc    ...
; &ea81 referenced 1 time by &fe59
.cea81
    ; pull A,X,Y from the stack
    pla                                                               ; ea81: 68          .
    tay                                                               ; ea82: a8          .
    pla                                                               ; ea83: 68          .
    tax                                                               ; ea84: aa          .
    pla                                                               ; ea85: 68          .
    rti                                                               ; ea86: 40          @

; &ea87 referenced 1 time by &e8b5
.lea87
    equb &3c,   2,   7,   0, &48, &78, &20, &a3, &fd, &20, &a0, &e5   ; ea87: 3c 02 07... <..
    equb &20, &44, &e5, &a9,   0, &8d, &19,   3, &a2, &14, &a0, &0e   ; ea93: 20 44 e5...  d.
    equb &20, &0c, &e5, &a2, &5c, &20, &71, &e9, &68, &f0, &17, &48   ; ea9f: 20 0c e5...  ..
    equb &a2,   2, &a0,   2, &20, &0c, &e5, &68, &48, &20, &f1, &fa   ; eaab: a2 02 a0... ...
    equb &68, &c9,   1, &d0,   5, &a2, &68, &20, &71, &e9, &a2,   0   ; eab7: 68 c9 01... .I.
    equb &8e, &20, &d0, &e8, &10, &fd, &a2,   6, &8e, &20, &d0, &ea   ; eac3: 8e 20 d0... . P
    equb &d0, &f0                                                     ; eacf: d0 f0       P.
; &ead1 referenced 1 time by &e971
.lead1
    equb &0d                                                          ; ead1: 0d          .
    equb &53, &45, &41, &52, &43, &48, &49, &4e ; petscii "searchin"  ; ead2: 53 45 41... sea
    equb &47, &20, &46, &4f, &52 ; petscii "g for"                    ; eada: 47 20 46... g f
    equb &a0, &0d                                                     ; eadf: a0 0d       ..
    equb &4c, &4f, &41, &44, &49, &4e, &c7 ; petscii "loadinG"        ; eae1: 4c 4f 41... loa
    equb &0d                                                          ; eae8: 0d          .
    equb &56, &45, &52, &49, &46, &59, &49, &4e ; petscii "verifyin"  ; eae9: 56 45 52... ver
    equb &c7 ; petscii "G"                                            ; eaf1: c7          G
    equb &0d                                                          ; eaf2: 0d          .
    equb &53, &41, &56, &49, &4e, &47 ; petscii "saving"              ; eaf3: 53 41 56... sav
    equb &a0                                                          ; eaf9: a0          .
    equb &20, &46, &52, &4f, &4d, &20 ; petscii " from "              ; eafa: 20 46 52...  fr
    equb &a4                                                          ; eb00: a4          .
    equb &20, &54, &4f, &20 ; petscii " to "                          ; eb01: 20 54 4f...  to
    equb &a4, &0d                                                     ; eb05: a4 0d       ..
    equb &50, &52, &45, &53, &53, &20, &50, &4c ; petscii "press pl"  ; eb07: 50 52 45... pre
    equb &41, &59, &20, &4f, &4e, &20, &54, &41 ; petscii "ay on ta"  ; eb0f: 41 59 20... ay
    equb &50, &45 ; petscii "pe"                                      ; eb17: 50 45       pe
    equb &8d                                                          ; eb19: 8d          .
    equb &46, &4f, &55, &4e, &44 ; petscii "found"                    ; eb1a: 46 4f 55... fou
    equb &a0, &4f, &4b, &0d, &0d                                      ; eb1f: a0 4f 4b... .ok
    equb &53, &45, &41, &52, &43, &48, &49, &4e ; petscii "searchin"  ; eb24: 53 45 41... sea
    equb &c7, &4b, &45, &52, &4e, &41, &4c, &20 ; petscii "Gkernal "  ; eb2c: c7 4b 45... Gke
    equb &50, &41, &4e, &49, &c3, &20, &2d, &20 ; petscii "paniC - "  ; eb34: 50 41 4e... pan
    equb &52, &4f, &4d, &20, &4d, &49, &53, &4d ; petscii "rom mism"  ; eb3c: 52 4f 4d... rom
    equb &41, &54, &43, &c8 ; petscii "atcH"                          ; eb44: 41 54 43... atc

; &eb48 referenced 1 time by &e834
.sub_ceb48
    lda #&dd                                                          ; eb48: a9 dd       ..
    sta keyboard_table_ptr                                            ; eb4a: 85 f5       ..
    lda #&f4                                                          ; eb4c: a9 f4       ..
    sta keyboard_table_ptr+1                                          ; eb4e: 85 f6       ..
    lda shift_key_flags                                               ; eb50: ad 8d 02    ...
    and #7                                                            ; eb53: 29 07       ).
    tax                                                               ; eb55: aa          .
    lda lf823,x                                                       ; eb56: bd 23 f8    .#.
    cmp #&ff                                                          ; eb59: c9 ff       I.
    bne ceb61                                                         ; eb5b: d0 04       P.
    lda #0                                                            ; eb5d: a9 00       ..
    beq ceb6a                                                         ; eb5f: f0 09       .. ; ALWAYS branch

; &eb61 referenced 1 time by &eb5b
.ceb61
    clc                                                               ; eb61: 18          .
    adc keyboard_table_ptr                                            ; eb62: 65 f5       ..
    sta keyboard_table_ptr                                            ; eb64: 85 f5       ..
    lda #0                                                            ; eb66: a9 00       ..
    adc keyboard_table_ptr+1                                          ; eb68: 65 f6       ..
; &eb6a referenced 1 time by &eb5f
.ceb6a
    sta keyboard_table_ptr+1                                          ; eb6a: 85 f6       ..
    lda charset_switch_flag                                           ; eb6c: ad 91 02    ...
    bne return_5                                                      ; eb6f: d0 1a       P.
    lda shift_key_flags                                               ; eb71: ad 8d 02    ...
    and #3                                                            ; eb74: 29 03       ).
    cmp #3                                                            ; eb76: c9 03       I.
    bne return_5                                                      ; eb78: d0 11       P.
    lda last_shift_key_flags                                          ; eb7a: ad 8e 02    ...
    and #3                                                            ; eb7d: 29 03       ).
    cmp #3                                                            ; eb7f: c9 03       I.
    beq return_5                                                      ; eb81: f0 08       ..
    lda vic_memory_setup                                              ; eb83: ad 18 d0    ..P
    eor #2                                                            ; eb86: 49 02       i.
    sta vic_memory_setup                                              ; eb88: 8d 18 d0    ..P
; &eb8b referenced 3 times by &eb6f, &eb78, &eb81
.return_5
    rts                                                               ; eb8b: 60          .

    equb &a6, &ba, &e0, 8, &b0, 2, &a2, 8, &60                        ; eb8c: a6 ba e0... ...

; &eb95 referenced 2 times by &e56f, &f49b
.ceb95
    ldy cursor_row                                                    ; eb95: a4 d6       .V
    lda screen_line_links,y                                           ; eb97: b9 d9 00    .Y.
    php                                                               ; eb9a: 08          .
    jsr sub_cf8f0                                                     ; eb9b: 20 f0 f8     ..
    plp                                                               ; eb9e: 28          (
    bmi ceba6                                                         ; eb9f: 30 05       0.
    ; add 40 to Y
    tya                                                               ; eba1: 98          .
    clc                                                               ; eba2: 18          .
    adc #&28 ; '('                                                    ; eba3: 69 28       .(
    tay                                                               ; eba5: a8          .
; &eba6 referenced 1 time by &eb9f
.ceba6
    sty cursor_column                                                 ; eba6: 84 d3       .S
    ldy cursor_row                                                    ; eba8: a4 d6       .V
    lda screen_line_links,y                                           ; ebaa: b9 d9 00    .Y.
    bpl cebbc                                                         ; ebad: 10 0d       ..
    cpy #&18                                                          ; ebaf: c0 18       ..
    beq cebb9                                                         ; ebb1: f0 06       ..
    iny                                                               ; ebb3: c8          H
    lda screen_line_links,y                                           ; ebb4: b9 d9 00    .Y.
    bpl cebbc                                                         ; ebb7: 10 03       ..
; &ebb9 referenced 1 time by &ebb1
.cebb9
    lda #&27 ; '''                                                    ; ebb9: a9 27       .'
; overlapping: bit l4fa9                                              ; ebbb: 2c a9 4f    ,.o
    equb &2c                                                          ; ebbb: 2c          ,

; &ebbc referenced 2 times by &ebad, &ebb7
.cebbc
    lda #&4f ; 'o'                                                    ; ebbc: a9 4f       .o
    sta screen_line_length                                            ; ebbe: 85 d5       .U
    rts                                                               ; ebc0: 60          .

; &ebc1 referenced 1 time by &fc0a
.lebc1
    equb &83, &85, &89, &86, &8a, &87, &88                            ; ebc1: 83 85 89... ...
; &ebc8 referenced 1 time by &fc18
.lebc8
    equb &5f, &4c, 0                                                  ; ebc8: 5f 4c 00    .l.
    equb &40, &38, &24 ; petscii "@8$"                                ; ebcb: 40 38 24    @8$
    equb 0                                                            ; ebce: 00          .
    equb &4c, &4f, &41, &44 ; petscii "load"                          ; ebcf: 4c 4f 41... loa
    equb 0                                                            ; ebd3: 00          .
    equb &40, &39, &24 ; petscii "@9$"                                ; ebd4: 40 39 24    @9$
    equb 0                                                            ; ebd7: 00          .
    equb &52, &55, &4e, &3a ; petscii "run:"                          ; ebd8: 52 55 4e... run
    equb 0                                                            ; ebdc: 00          .
    equb &40, &31, &30, &24 ; petscii "@10$"                          ; ebdd: 40 31 30... @10
    equb 0                                                            ; ebe1: 00          .
    equb &40, &31, &31, &24 ; petscii "@11$"                          ; ebe2: 40 31 31... @11
    equb 0                                                            ; ebe6: 00          .
; &ebe7 referenced 1 time by &fc14
.lebe7
    equb 0, 3, 7, &0c, &10, &15, &1a                                  ; ebe7: 00 03 07... ...

; &ebee referenced 3 times by &e56c, &e957, &f40f
.cebee
    ldx cursor_row                                                    ; ebee: a6 d6       .V
; &ebf0 referenced 1 time by &ea01
.sub_cebf0
    lda screen_memory_page                                            ; ebf0: ad 88 02    ...
    sta screen_line_ptr+1                                             ; ebf3: 85 d2       .R
    lda #0                                                            ; ebf5: a9 00       ..
    sta screen_line_ptr                                               ; ebf7: 85 d1       .Q
    cpx #0                                                            ; ebf9: e0 00       ..
    beq cec0b                                                         ; ebfb: f0 0e       ..
; &ebfd referenced 1 time by &ec09
.loop_cebfd
    lda #&28 ; '('                                                    ; ebfd: a9 28       .(
    clc                                                               ; ebff: 18          .
    adc screen_line_ptr                                               ; ec00: 65 d1       .Q
    sta screen_line_ptr                                               ; ec02: 85 d1       .Q
    bcc cec08                                                         ; ec04: 90 02       ..
    inc screen_line_ptr+1                                             ; ec06: e6 d2       .R
; &ec08 referenced 1 time by &ec04
.cec08
    dex                                                               ; ec08: ca          J
    bne loop_cebfd                                                    ; ec09: d0 f2       P.
; &ec0b referenced 1 time by &ebfb
.cec0b
    lda screen_line_ptr                                               ; ec0b: a5 d1       .Q
    sta colour_ram_line_ptr                                           ; ec0d: 85 f3       ..
    lda screen_line_ptr+1                                             ; ec0f: a5 d2       .R
    sec                                                               ; ec11: 38          8
    sbc screen_memory_page                                            ; ec12: ed 88 02    ...
    clc                                                               ; ec15: 18          .
    adc #&d8 ; 'X'                                                    ; ec16: 69 d8       .X
    sta colour_ram_line_ptr+1                                         ; ec18: 85 f4       ..
    rts                                                               ; ec1a: 60          .

; &ec1b referenced 1 time by &f684
.sub_cec1b
    cmp #&20 ; ' '                                                    ; ec1b: c9 20       I
    bcc cec3e                                                         ; ec1d: 90 1f       ..
    cmp #&40 ; '@'                                                    ; ec1f: c9 40       I@
    bcc return_6                                                      ; ec21: 90 1d       ..
    cmp #&60                                                          ; ec23: c9 60       I.
    bcc cec41                                                         ; ec25: 90 1a       ..
    cmp #&80                                                          ; ec27: c9 80       I.
    bcc cec3e                                                         ; ec29: 90 13       ..
    bit quote_mode_flag                                               ; ec2b: 24 d4       $T
    bmi cec44                                                         ; ec2d: 30 15       0.
    cmp #&a0                                                          ; ec2f: c9 a0       I.
    bcc cec49                                                         ; ec31: 90 16       ..
    cmp #&c0                                                          ; ec33: c9 c0       I.
    bcc cec41                                                         ; ec35: 90 0a       ..
    cmp #&e0                                                          ; ec37: c9 e0       I.
    bcc return_6                                                      ; ec39: 90 05       ..
    clc                                                               ; ec3b: 18          .
    bcc cec49                                                         ; ec3c: 90 0b       .. ; ALWAYS branch

; &ec3e referenced 2 times by &ec1d, &ec29
.cec3e
    adc #&40 ; '@'                                                    ; ec3e: 69 40       .@
; &ec40 referenced 2 times by &ec21, &ec39
.return_6
    rts                                                               ; ec40: 60          .

; &ec41 referenced 3 times by &ec25, &ec35, &ec46
.cec41
    adc #&80                                                          ; ec41: 69 80       ..
    rts                                                               ; ec43: 60          .

; &ec44 referenced 1 time by &ec2d
.cec44
    cmp #&c0                                                          ; ec44: c9 c0       I.
    bcc cec41                                                         ; ec46: 90 f9       ..
    clc                                                               ; ec48: 18          .
; &ec49 referenced 2 times by &ec31, &ec3c
.cec49
    adc #&c0                                                          ; ec49: 69 c0       ..
    rts                                                               ; ec4b: 60          .

; &ec4c referenced 1 time by &fe01
.lec4c
    equb &93, &13,   8,   9, &0e, &8e, &92, &12, &1d, &9d, &11, &91   ; ec4c: 93 13 08... ...
    equb &94,   3, &14, &0d, &8d                                      ; ec58: 94 03 14... ...
; &ec5d referenced 1 time by &fe0a
.lec5d
    equb &e8, &e2, &95, &92, &9c, &91, &62, &5f, &c9, &d8, &bb, &b2   ; ec5d: e8 e2 95... ...
    equb &fc, &3a, &8c, &5a, &5a                                      ; ec69: fc 3a 8c... .:.
; &ec6e referenced 1 time by &fe06
.lec6e
    equb &f7, &f7, &f8, &f8, &f9, &f9, &f8, &f8, &ec, &ec, &ec, &ec   ; ec6e: f7 f7 f8... ...
    equb &f5, &f8, &f3, &fb, &fb                                      ; ec7a: f5 f8 f3... ...

; &ec7f referenced 3 times by &ea1f, &ee3d, &eed8
.sub_cec7f
    lda #1                                                            ; ec7f: a9 01       ..
    sta tape_parity                                                   ; ec81: 85 9b       ..
    lda #&7f                                                          ; ec83: a9 7f       ..
    sta rs232_input_bits                                              ; ec85: 85 a7       ..
; &ec87 referenced 1 time by &ec97
.loop_cec87
    jsr sub_cfbc9                                                     ; ec87: 20 c9 fb     I.
    bcs cecae                                                         ; ec8a: b0 22       ."
    beq cec95                                                         ; ec8c: f0 07       ..
    lda #1                                                            ; ec8e: a9 01       ..
    eor tape_parity                                                   ; ec90: 45 9b       e.
    sta tape_parity                                                   ; ec92: 85 9b       ..
    sec                                                               ; ec94: 38          8
; &ec95 referenced 1 time by &ec8c
.cec95
    ror rs232_input_bits                                              ; ec95: 66 a7       ..
    bcs loop_cec87                                                    ; ec97: b0 ee       ..
    jsr sub_cfbc9                                                     ; ec99: 20 c9 fb     I.
    bcs cecae                                                         ; ec9c: b0 10       ..
    beq ceca2                                                         ; ec9e: f0 02       ..
    lda #1                                                            ; eca0: a9 01       ..
; &eca2 referenced 1 time by &ec9e
.ceca2
    eor tape_parity                                                   ; eca2: 45 9b       e.
    bne cecae                                                         ; eca4: d0 08       P.
    ldx #colour_dark_grey                                             ; eca6: a2 0b       ..
; &eca8 referenced 1 time by &ecb1
.loop_ceca8
    stx vic_border_colour                                             ; eca8: 8e 20 d0    . P
    lda rs232_input_bits                                              ; ecab: a5 a7       ..
    rts                                                               ; ecad: 60          .

; &ecae referenced 3 times by &ec8a, &ec9c, &eca4
.cecae
    ldx #9                                                            ; ecae: a2 09       ..
    sec                                                               ; ecb0: 38          8
    bcs loop_ceca8                                                    ; ecb1: b0 f5       .. ; ALWAYS branch

    lda cursor_row                                                    ; ecb3: a5 d6       .V
    beq cecb9                                                         ; ecb5: f0 02       ..
    dec cursor_row                                                    ; ecb7: c6 d6       FV
; &ecb9 referenced 1 time by &ecb5
.cecb9
    jmp cee22                                                         ; ecb9: 4c 22 ee    l".

    equb &a5, &d6, &c9, &18, &d0, 3, &20, &ea, &e8, &e6               ; ecbc: a5 d6 c9... .VI
    equb &d6, &4c, &22 ; petscii "Vl", &22                            ; ecc6: d6 4c 22    Vl"
    equb &ee, &20, &f0, &f8, &c0, &27, &d0,   3, &4c, &a4, &f9, &c8   ; ecc9: ee 20 f0... . .
    equb &84, &d3, &10, &e0, &20, &f0, &f8, &88, &10, &f6, &a5, &d6   ; ecd5: 84 d3 10... .S.
    equb &f0                                                          ; ece1: f0          .
    equb &d6, &c6, &d6 ; petscii "VFV"                                ; ece2: d6 c6 d6    VFV
    equb &a9, &27, &85                                                ; ece5: a9 27 85    .'.
    equb &d3, &d0, &ce ; petscii "SPN"                                ; ece8: d3 d0 ce    SPN

; &eceb referenced 2 times by &e98f, &ecff
.ceceb
    lda #&bf                                                          ; eceb: a9 bf       ..
    sta tape_timing                                                   ; eced: 85 92       ..
    jsr cfb0b                                                         ; ecef: 20 0b fb     ..
    bcs return_7                                                      ; ecf2: b0 30       .0
    ldx #&c0                                                          ; ecf4: a2 c0       ..
; &ecf6 referenced 1 time by &ed07
.loop_cecf6
    ldy #4                                                            ; ecf6: a0 04       ..
; &ecf8 referenced 1 time by &ed02
.loop_cecf8
    stx kernal_x_save                                                 ; ecf8: 86 97       ..
    jsr sub_ce95a                                                     ; ecfa: 20 5a e9     z.
    cmp #2                                                            ; ecfd: c9 02       I.
    bne ceceb                                                         ; ecff: d0 ea       P.
    dey                                                               ; ed01: 88          .
    bne loop_cecf8                                                    ; ed02: d0 f4       P.
    ldx kernal_x_save                                                 ; ed04: a6 97       ..
    dex                                                               ; ed06: ca          J
    bne loop_cecf6                                                    ; ed07: d0 ed       P.
; &ed09 referenced 2 times by &e9d7, &ed1b
.ced09
    jsr cfb0b                                                         ; ed09: 20 0b fb     ..
    bcs return_7                                                      ; ed0c: b0 16       ..
    ldx #9                                                            ; ed0e: a2 09       ..
; &ed10 referenced 1 time by &ed15
.loop_ced10
    jsr sub_ce95a                                                     ; ed10: 20 5a e9     z.
    cmp #2                                                            ; ed13: c9 02       I.
    beq loop_ced10                                                    ; ed15: f0 f9       ..
    ldy #0                                                            ; ed17: a0 00       ..
; &ed19 referenced 1 time by &ed21
.loop_ced19
    cpx rs232_input_bits                                              ; ed19: e4 a7       ..
    bne ced09                                                         ; ed1b: d0 ec       P.
    jsr sub_ce95a                                                     ; ed1d: 20 5a e9     z.
    dex                                                               ; ed20: ca          J
    bne loop_ced19                                                    ; ed21: d0 f6       P.
    clc                                                               ; ed23: 18          .
; &ed24 referenced 2 times by &ecf2, &ed0c
.return_7
    rts                                                               ; ed24: 60          .

; &ed25 referenced 1 time by &efe6
.sub_ced25
    lda #&91                                                          ; ed25: a9 91       ..
    sta tape_timing                                                   ; ed27: 85 92       ..
    lda #&67                                                          ; ed29: a9 67       ..
    sta tape_sync_number                                              ; ed2b: 85 96       ..
    lda #&80                                                          ; ed2d: a9 80       ..
    ldy #&ff                                                          ; ed2f: a0 ff       ..
    bmi ced3a                                                         ; ed31: 30 07       0. ; ALWAYS branch

; &ed33 referenced 1 time by &f020
.sub_ced33
    lda #4                                                            ; ed33: a9 04       ..
    bit l01a9                                                         ; ed35: 2c a9 01    ,..
    ldy #0                                                            ; ed38: a0 00       ..
; &ed3a referenced 1 time by &ed31
.ced3a
    sty rs232_input_bits                                              ; ed3a: 84 a7       ..
    sta tape_block_count                                              ; ed3c: 85 be       ..
    lda #colour_dark_grey                                             ; ed3e: a9 0b       ..
    sta vic_border_colour                                             ; ed40: 8d 20 d0    . P
; &ed43 referenced 1 time by &ed4c
.loop_ced43
    lda tape_block_count                                              ; ed43: a5 be       ..
    sta rs232_output_parity                                           ; ed45: 85 bd       ..
; &ed47 referenced 1 time by &ed5b
.loop_ced47
    ldy #&40 ; '@'                                                    ; ed47: a0 40       .@
; &ed49 referenced 1 time by &ed57
.loop_ced49
    jsr cfd91                                                         ; ed49: 20 91 fd     ..
    bcc loop_ced43                                                    ; ed4c: 90 f5       ..
    bit rs232_input_bits                                              ; ed4e: 24 a7       $.
    bpl ced56                                                         ; ed50: 10 04       ..
    cmp #&b9                                                          ; ed52: c9 b9       I.
    bcs return_8                                                      ; ed54: b0 08       ..
; &ed56 referenced 1 time by &ed50
.ced56
    dey                                                               ; ed56: 88          .
    bne loop_ced49                                                    ; ed57: d0 f0       P.
    dec rs232_output_parity                                           ; ed59: c6 bd       F.
    bne loop_ced47                                                    ; ed5b: d0 ea       P.
    clc                                                               ; ed5d: 18          .
; &ed5e referenced 1 time by &ed54
.return_8
    rts                                                               ; ed5e: 60          .

; &ed5f referenced 1 time by &e987
.sub_ced5f
    lda #colour_dark_grey                                             ; ed5f: a9 0b       ..
    sta vic_border_colour                                             ; ed61: 8d 20 d0    . P
    lda #0                                                            ; ed64: a9 00       ..
    sta sid_volume_filter_mode                                        ; ed66: 8d 18 d4    ..T
; &ed69 referenced 2 times by &ed77, &ed7b
.ced69
    lda #0                                                            ; ed69: a9 00       ..
    sta kernal_x_save                                                 ; ed6b: 85 97       ..
    ldy #&60                                                          ; ed6d: a0 60       ..
    jsr cfd91                                                         ; ed6f: 20 91 fd     ..
; &ed72 referenced 1 time by &ed90
.loop_ced72
    jsr cfd91                                                         ; ed72: 20 91 fd     ..
    cmp #&28 ; '('                                                    ; ed75: c9 28       I(
    bcc ced69                                                         ; ed77: 90 f0       ..
    cmp #&e8                                                          ; ed79: c9 e8       I.
    bcs ced69                                                         ; ed7b: b0 ec       ..
    cmp #&b9                                                          ; ed7d: c9 b9       I.
    bcc ced83                                                         ; ed7f: 90 02       ..
    dec kernal_x_save                                                 ; ed81: c6 97       F.
; &ed83 referenced 1 time by &ed7f
.ced83
    cmp #&97                                                          ; ed83: c9 97       I.
    bcs ced89                                                         ; ed85: b0 02       ..
    inc kernal_x_save                                                 ; ed87: e6 97       ..
; &ed89 referenced 1 time by &ed85
.ced89
    lda kernal_x_save                                                 ; ed89: a5 97       ..
    cmp #&fd                                                          ; ed8b: c9 fd       I.
    beq ced98                                                         ; ed8d: f0 09       ..
    dey                                                               ; ed8f: 88          .
    bpl loop_ced72                                                    ; ed90: 10 e0       ..
    lda kernal_x_save                                                 ; ed92: a5 97       ..
    bmi ced98                                                         ; ed94: 30 02       0.
    clc                                                               ; ed96: 18          .
    rts                                                               ; ed97: 60          .

; &ed98 referenced 2 times by &ed8d, &ed94
.ced98
    sec                                                               ; ed98: 38          8
    rts                                                               ; ed99: 60          .

; &ed9a referenced 1 time by &ea31
.sub_ced9a
    lda cursor_blink_disable                                          ; ed9a: a5 cc       .L
    bne return_9                                                      ; ed9c: d0 43       Pc
    dec cursor_blink_timer                                            ; ed9e: c6 cd       FM
    bpl return_9                                                      ; eda0: 10 3f       .?
    lda cursor_blink_phase                                            ; eda2: a5 cf       .O
    bne cedcd                                                         ; eda4: d0 27       P'
    jsr sub_cf8f0                                                     ; eda6: 20 f0 f8     ..
    lda (screen_line_ptr),y                                           ; eda9: b1 d1       .Q
    sta char_under_cursor                                             ; edab: 85 ce       .N
    eor #&80                                                          ; edad: 49 80       i.
    sta (screen_line_ptr),y                                           ; edaf: 91 d1       .Q
    lda (colour_ram_line_ptr),y                                       ; edb1: b1 f3       ..
    sta colour_under_cursor                                           ; edb3: 8d 87 02    ...
    lda text_colour                                                   ; edb6: ad 86 02    ...
    sta (colour_ram_line_ptr),y                                       ; edb9: 91 f3       ..
    lda #1                                                            ; edbb: a9 01       ..
    sta cursor_blink_phase                                            ; edbd: 85 cf       .O
    bne ceddd                                                         ; edbf: d0 1c       P. ; ALWAYS branch

; &edc1 referenced 1 time by &f697
.sub_cedc1
    lda #&80                                                          ; edc1: a9 80       ..
    sta cursor_blink_disable                                          ; edc3: 85 cc       .L
; &edc5 referenced 2 times by &ede2, &f69d
.sub_cedc5
    lda #&ff                                                          ; edc5: a9 ff       ..
    sta cursor_blink_timer                                            ; edc7: 85 cd       .M
    lda cursor_blink_phase                                            ; edc9: a5 cf       .O
    beq ceddd                                                         ; edcb: f0 10       ..
; &edcd referenced 1 time by &eda4
.cedcd
    jsr sub_cf8f0                                                     ; edcd: 20 f0 f8     ..
    lda char_under_cursor                                             ; edd0: a5 ce       .N
    sta (screen_line_ptr),y                                           ; edd2: 91 d1       .Q
    lda colour_under_cursor                                           ; edd4: ad 87 02    ...
    sta (colour_ram_line_ptr),y                                       ; edd7: 91 f3       ..
    lda #0                                                            ; edd9: a9 00       ..
    sta cursor_blink_phase                                            ; eddb: 85 cf       .O
; &eddd referenced 2 times by &edbf, &edcb
.ceddd
    lda #&14                                                          ; eddd: a9 14       ..
    sta cursor_blink_timer                                            ; eddf: 85 cd       .M
; &ede1 referenced 2 times by &ed9c, &eda0
.return_9
    rts                                                               ; ede1: 60          .

; &ede2 referenced 1 time by &f1d7
.cede2
    jsr sub_cedc5                                                     ; ede2: 20 c5 ed     E.
    lda last_char_printed                                             ; ede5: a5 d7       .W
    tax                                                               ; ede7: aa          .
    and #&60                                                          ; ede8: 29 60       ).
    bne cedef                                                         ; edea: d0 03       P.
    jmp cfdee                                                         ; edec: 4c ee fd    l..

; &edef referenced 1 time by &edea
.cedef
    txa                                                               ; edef: 8a          .
    jsr sub_ce71d                                                     ; edf0: 20 1d e7     ..
; &edf3 referenced 1 time by &f87b
.cedf3
    tax                                                               ; edf3: aa          .
    jsr sub_cf8f0                                                     ; edf4: 20 f0 f8     ..
    txa                                                               ; edf7: 8a          .
    ora reverse_flag                                                  ; edf8: 05 c7       .G
    sta (screen_line_ptr),y                                           ; edfa: 91 d1       .Q
    lda insert_count                                                  ; edfc: a5 d8       .X
    beq cee02                                                         ; edfe: f0 02       ..
    dec insert_count                                                  ; ee00: c6 d8       FX
; &ee02 referenced 1 time by &edfe
.cee02
    txa                                                               ; ee02: 8a          .
    jsr sub_cf8fd                                                     ; ee03: 20 fd f8     ..
    lda text_colour                                                   ; ee06: ad 86 02    ...
    sta (colour_ram_line_ptr),y                                       ; ee09: 91 f3       ..
    ldy cursor_column                                                 ; ee0b: a4 d3       .S
    iny                                                               ; ee0d: c8          H
    sty cursor_column                                                 ; ee0e: 84 d3       .S
    cpy #&28 ; '('                                                    ; ee10: c0 28       .(
    bne cee1b                                                         ; ee12: d0 07       P.
    jsr sub_cf415                                                     ; ee14: 20 15 f4     ..
    inc cursor_row                                                    ; ee17: e6 d6       .V
    ldy cursor_column                                                 ; ee19: a4 d3       .S
; &ee1b referenced 1 time by &ee12
.cee1b
    cpy #&50 ; 'p'                                                    ; ee1b: c0 50       .p
    bcc cee22                                                         ; ee1d: 90 03       ..
    jmp cf9a4                                                         ; ee1f: 4c a4 f9    l..

; &ee22 referenced 3 times by &ecb9, &ee1d, &f9b3
.cee22
    jsr sub_ce56c                                                     ; ee22: 20 6c e5     ..
; &ee25 referenced 2 times by &fe1c, &fe22
.cee25
    jsr sub_cf95f                                                     ; ee25: 20 5f f9     ..
    jmp cf1f1                                                         ; ee28: 4c f1 f1    l..

; &ee2b referenced 2 times by &efee, &f025
.sub_cee2b
    lda #0                                                            ; ee2b: a9 00       ..
    sta rs232_input_parity                                            ; ee2d: 85 ab       ..
    sta tape_pass2_errors                                             ; ee2f: 85 9f       ..
    sta tape_pass1_errors                                             ; ee31: 85 9e       ..
    ldy #&89                                                          ; ee33: a0 89       ..
    jsr cea15                                                         ; ee35: 20 15 ea     ..
    bcs cee7a                                                         ; ee38: b0 40       .@
    jsr cf9f4                                                         ; ee3a: 20 f4 f9     ..
; &ee3d referenced 1 time by &ee75
.cee3d
    jsr sub_cec7f                                                     ; ee3d: 20 7f ec     ..
    bcc cee5e                                                         ; ee40: 90 1c       ..
    tsx                                                               ; ee42: ba          .
    cpx #&20 ; ' '                                                    ; ee43: e0 20       .
    bcc cee7a                                                         ; ee45: 90 33       .3
    ldx tape_pass1_errors                                             ; ee47: a6 9e       ..
    lda load_address_temp                                             ; ee49: a5 c3       .C
    sta l0100,x                                                       ; ee4b: 9d 00 01    ...
    inx                                                               ; ee4e: e8          .
    lda load_address_temp+1                                           ; ee4f: a5 c4       .D
    sta l0100,x                                                       ; ee51: 9d 00 01    ...
    inx                                                               ; ee54: e8          .
    stx tape_pass1_errors                                             ; ee55: 86 9e       ..
    jsr cf9f4                                                         ; ee57: 20 f4 f9     ..
    bcc cee72                                                         ; ee5a: 90 16       ..
    bcs cee78                                                         ; ee5c: b0 1a       .. ; ALWAYS branch

; &ee5e referenced 1 time by &ee40
.cee5e
    jsr cf9f4                                                         ; ee5e: 20 f4 f9     ..
    bcc cee69                                                         ; ee61: 90 06       ..
    jsr sub_cf804                                                     ; ee63: 20 04 f8     ..
    jmp cee78                                                         ; ee66: 4c 78 ee    l..

; &ee69 referenced 1 time by &ee61
.cee69
    lda rs232_input_bits                                              ; ee69: a5 a7       ..
    ldy #0                                                            ; ee6b: a0 00       ..
    sta (load_address_temp),y                                         ; ee6d: 91 c3       .C
    jsr sub_cf804                                                     ; ee6f: 20 04 f8     ..
; &ee72 referenced 1 time by &ee5a
.cee72
    jsr sub_cfeb9                                                     ; ee72: 20 b9 fe     ..
    jmp cee3d                                                         ; ee75: 4c 3d ee    l=.

; &ee78 referenced 2 times by &ee5c, &ee66
.cee78
    clc                                                               ; ee78: 18          .
    rts                                                               ; ee79: 60          .

; &ee7a referenced 2 times by &ee38, &ee45
.cee7a
    sec                                                               ; ee7a: 38          8
    rts                                                               ; ee7b: 60          .

; &ee7c referenced 1 time by &fac2
.sub_cee7c
    lda cia2_port_a                                                   ; ee7c: ad 00 dd    ...
    ora #8                                                            ; ee7f: 09 08       ..
    sta cia2_port_a                                                   ; ee81: 8d 00 dd    ...
; &ee84 referenced 1 time by &fa43
.sub_cee84
    lda cia2_port_a                                                   ; ee84: ad 00 dd    ...
    ora #&10                                                          ; ee87: 09 10       ..
    sta cia2_port_a                                                   ; ee89: 8d 00 dd    ...
; &ee8c referenced 1 time by &ee95
.loop_cee8c
    and #&df                                                          ; ee8c: 29 df       ).
    bne ceeca                                                         ; ee8e: d0 3a       P:
; &ee90 referenced 3 times by &f0f8, &f0fe, &f122
.sub_cee90
    lda cia2_port_a                                                   ; ee90: ad 00 dd    ...
    ora #&10                                                          ; ee93: 09 10       ..
    bne loop_cee8c                                                    ; ee95: d0 f5       P. ; ALWAYS branch

; &ee97 referenced 1 time by &f0d9
.sub_cee97
    lda cia2_port_a                                                   ; ee97: ad 00 dd    ...
    and #&f7                                                          ; ee9a: 29 f7       ).
    sta cia2_port_a                                                   ; ee9c: 8d 00 dd    ...
; &ee9f referenced 5 times by &ef32, &f11c, &fa3d, &fa8a, &fad0
.sub_cee9f
    lda cia2_port_a                                                   ; ee9f: ad 00 dd    ...
    and #&df                                                          ; eea2: 29 df       ).
    sta cia2_port_a                                                   ; eea4: 8d 00 dd    ...
    and #&ef                                                          ; eea7: 29 ef       ).
    jmp ceeca                                                         ; eea9: 4c ca ee    lJ.

; &eeac referenced 3 times by &ef6e, &f116, &fa84
.sub_ceeac
    lda cia2_port_a                                                   ; eeac: ad 00 dd    ...
    ora #&20 ; ' '                                                    ; eeaf: 09 20       .
    sta cia2_port_a                                                   ; eeb1: 8d 00 dd    ...
    and #&ef                                                          ; eeb4: 29 ef       ).
    bne ceeca                                                         ; eeb6: d0 12       P.
; &eeb8 referenced 1 time by &fb97
.sub_ceeb8
    lda cia2_port_a                                                   ; eeb8: ad 00 dd    ...
    ora #&20 ; ' '                                                    ; eebb: 09 20       .
    sta cia2_port_a                                                   ; eebd: 8d 00 dd    ...
    and #&ef                                                          ; eec0: 29 ef       ).
    sta cia2_port_a                                                   ; eec2: 8d 00 dd    ...
; &eec5 referenced 2 times by &f2d1, &fa3a
.sub_ceec5
    lda cia2_port_a                                                   ; eec5: ad 00 dd    ...
    and #&f7                                                          ; eec8: 29 f7       ).
; &eeca referenced 3 times by &ee8e, &eea9, &eeb6
.ceeca
    sta cia2_port_a                                                   ; eeca: 8d 00 dd    ...
    rts                                                               ; eecd: 60          .

; &eece referenced 2 times by &effc, &f038
.sub_ceece
    ldy #9                                                            ; eece: a0 09       ..
    jsr cea15                                                         ; eed0: 20 15 ea     ..
    bcs return_10                                                     ; eed3: b0 34       .4
    jsr cf9f4                                                         ; eed5: 20 f4 f9     ..
; &eed8 referenced 1 time by &eefc
.ceed8
    jsr sub_cec7f                                                     ; eed8: 20 7f ec     ..
    bcc ceedf                                                         ; eedb: 90 02       ..
    bcs ceef9                                                         ; eedd: b0 1a       .. ; ALWAYS branch

; &eedf referenced 1 time by &eedb
.ceedf
    jsr sub_cef0a                                                     ; eedf: 20 0a ef     ..
    beq ceeeb                                                         ; eee2: f0 07       ..
    jsr cf9f4                                                         ; eee4: 20 f4 f9     ..
    bcs ceeff                                                         ; eee7: b0 16       ..
    bcc ceef9                                                         ; eee9: 90 0e       .. ; ALWAYS branch

; &eeeb referenced 1 time by &eee2
.ceeeb
    jsr cf9f4                                                         ; eeeb: 20 f4 f9     ..
    bcs ceef6                                                         ; eeee: b0 06       ..
    lda rs232_input_bits                                              ; eef0: a5 a7       ..
    ldy #0                                                            ; eef2: a0 00       ..
    sta (load_address_temp),y                                         ; eef4: 91 c3       .C
; &eef6 referenced 1 time by &eeee
.ceef6
    jsr sub_cf804                                                     ; eef6: 20 04 f8     ..
; &eef9 referenced 2 times by &eedd, &eee9
.ceef9
    jsr sub_cfeb9                                                     ; eef9: 20 b9 fe     ..
    jmp ceed8                                                         ; eefc: 4c d8 ee    lX.

; &eeff referenced 1 time by &eee7
.ceeff
    lda tape_pass1_errors                                             ; eeff: a5 9e       ..
    cmp tape_pass2_errors                                             ; ef01: c5 9f       E.
    bne return_10                                                     ; ef03: d0 04       P.
    lda rs232_input_parity                                            ; ef05: a5 ab       ..
    cmp #1                                                            ; ef07: c9 01       I.
; &ef09 referenced 2 times by &eed3, &ef03
.return_10
    rts                                                               ; ef09: 60          .

; &ef0a referenced 1 time by &eedf
.sub_cef0a
    ldx tape_pass2_errors                                             ; ef0a: a6 9f       ..
    lda l0100,x                                                       ; ef0c: bd 00 01    ...
    cmp load_address_temp                                             ; ef0f: c5 c3       EC
    bne return_11                                                     ; ef11: d0 0d       P.
    lda l0101,x                                                       ; ef13: bd 01 01    ...
    cmp load_address_temp+1                                           ; ef16: c5 c4       ED
    bne return_11                                                     ; ef18: d0 06       P.
    inc tape_pass2_errors                                             ; ef1a: e6 9f       ..
    inc tape_pass2_errors                                             ; ef1c: e6 9f       ..
    lda #0                                                            ; ef1e: a9 00       ..
; &ef20 referenced 2 times by &ef11, &ef18
.return_11
    rts                                                               ; ef20: 60          .

; &ef21 referenced 3 times by &e7b1, &e7e5, &f890
.cef21
    lda io_temp_1                                                     ; ef21: a5 a3       ..
    cmp #1                                                            ; ef23: c9 01       I.
    bne cef2a                                                         ; ef25: d0 03       P.
    jmp cf16c                                                         ; ef27: 4c 6c f1    l..

; &ef2a referenced 1 time by &ef25
.cef2a
    ; push X,Y onto the stack
    txa                                                               ; ef2a: 8a          .
    pha                                                               ; ef2b: 48          h
    tya                                                               ; ef2c: 98          .
    pha                                                               ; ef2d: 48          h
    sei                                                               ; ef2e: 78          .
    jsr ce717                                                         ; ef2f: 20 17 e7     ..
    jsr sub_cee9f                                                     ; ef32: 20 9f ee     ..
    jsr cf7d1                                                         ; ef35: 20 d1 f7     Q.
    jsr sub_cfa77                                                     ; ef38: 20 77 fa     ..
    lda io_temp_1                                                     ; ef3b: a5 a3       ..
    cmp #2                                                            ; ef3d: c9 02       I.
    bne cef48                                                         ; ef3f: d0 07       P.
    lda cia2_port_b                                                   ; ef41: ad 01 dd    ...
    pha                                                               ; ef44: 48          h
    jmp cef6e                                                         ; ef45: 4c 6e ef    l..

; &ef48 referenced 1 time by &ef3f
.cef48
    ldx #7                                                            ; ef48: a2 07       ..
    lda #0                                                            ; ef4a: a9 00       ..
    pha                                                               ; ef4c: 48          h
; &ef4d referenced 1 time by &ef6c
.loop_cef4d
    jsr ce717                                                         ; ef4d: 20 17 e7     ..
; &ef50 referenced 1 time by &ef54
.loop_cef50
    lda cia2_port_a                                                   ; ef50: ad 00 dd    ...
    rol a                                                             ; ef53: 2a          *
    bpl loop_cef50                                                    ; ef54: 10 fa       ..
    pla                                                               ; ef56: 68          .
    ror a                                                             ; ef57: 6a          .
    pha                                                               ; ef58: 48          h
    ldy #&19                                                          ; ef59: a0 19       ..
; &ef5b referenced 1 time by &ef62
.loop_cef5b
    lda cia2_port_a                                                   ; ef5b: ad 00 dd    ...
    rol a                                                             ; ef5e: 2a          *
    bpl cef6b                                                         ; ef5f: 10 0a       ..
    dey                                                               ; ef61: 88          .
    bne loop_cef5b                                                    ; ef62: d0 f7       P.
    jsr sub_cf985                                                     ; ef64: 20 85 f9     ..
    pla                                                               ; ef67: 68          .
    jmp cef74                                                         ; ef68: 4c 74 ef    l..

; &ef6b referenced 1 time by &ef5f
.cef6b
    dex                                                               ; ef6b: ca          J
    bpl loop_cef4d                                                    ; ef6c: 10 df       ..
; &ef6e referenced 1 time by &ef45
.cef6e
    jsr sub_ceeac                                                     ; ef6e: 20 ac ee     ..
    pla                                                               ; ef71: 68          .
    sta io_temp_2                                                     ; ef72: 85 a4       ..
; &ef74 referenced 2 times by &ef68, &f1c2
.cef74
    ; pull X,Y from the stack
    pla                                                               ; ef74: 68          .
    tay                                                               ; ef75: a8          .
    pla                                                               ; ef76: 68          .
    tax                                                               ; ef77: aa          .
    lda io_temp_2                                                     ; ef78: a5 a4       ..
    clc                                                               ; ef7a: 18          .
    cli                                                               ; ef7b: 58          x
    rts                                                               ; ef7c: 60          .

; &ef7d referenced 1 time by &e7a7
.cef7d
    sei                                                               ; ef7d: 78          .
    lda vic_control_1                                                 ; ef7e: ad 11 d0    ..P
    sta io_temp_2                                                     ; ef81: 85 a4       ..
    jsr sub_cf1fb                                                     ; ef83: 20 fb f1     ..
    jsr sub_cf833                                                     ; ef86: 20 33 f8     3.
    ldy #&ff                                                          ; ef89: a0 ff       ..
; &ef8b referenced 2 times by &efc5, &efc9
.cef8b
    jsr ce717                                                         ; ef8b: 20 17 e7     ..
    lda cia2_port_a                                                   ; ef8e: ad 00 dd    ...
    and #&df                                                          ; ef91: 29 df       ).
    nop                                                               ; ef93: ea          .
    jsr return_12                                                     ; ef94: 20 80 f9     ..
    sta cia2_port_a                                                   ; ef97: 8d 00 dd    ...
    lda serial_char_buffered_flag                                     ; ef9a: a5 94       ..
    ora #&20 ; ' '                                                    ; ef9c: 09 20       .
    tax                                                               ; ef9e: aa          .
    nop                                                               ; ef9f: ea          .
    nop                                                               ; efa0: ea          .
    lda cia2_port_a                                                   ; efa1: ad 00 dd    ...
    lsr a                                                             ; efa4: 4a          j
    lsr a                                                             ; efa5: 4a          j
    nop                                                               ; efa6: ea          .
    ora cia2_port_a                                                   ; efa7: 0d 00 dd    ...
    lsr a                                                             ; efaa: 4a          j
    lsr a                                                             ; efab: 4a          j
    eor serial_char_buffered_flag                                     ; efac: 45 94       e.
    eor cia2_port_a                                                   ; efae: 4d 00 dd    m..
    lsr a                                                             ; efb1: 4a          j
    lsr a                                                             ; efb2: 4a          j
    eor serial_char_buffered_flag                                     ; efb3: 45 94       e.
    eor cia2_port_a                                                   ; efb5: 4d 00 dd    m..
    iny                                                               ; efb8: c8          H
    sta (io_end_ptr),y                                                ; efb9: 91 ae       ..
    bit cia2_port_a                                                   ; efbb: 2c 00 dd    ,..
    stx cia2_port_a                                                   ; efbe: 8e 00 dd    ...
    bvs cefcc                                                         ; efc1: 70 09       ..
    cpy #&ff                                                          ; efc3: c0 ff       ..
    bne cef8b                                                         ; efc5: d0 c4       PD
    inc io_end_ptr+1                                                  ; efc7: e6 af       ..
    jmp cef8b                                                         ; efc9: 4c 8b ef    l..

; &efcc referenced 1 time by &efc1
.cefcc
    tax                                                               ; efcc: aa          .
    sec                                                               ; efcd: 38          8
    jsr sub_cf86a                                                     ; efce: 20 6a f8     ..
    lda #0                                                            ; efd1: a9 00       ..
    sta serial_char_buffered_flag                                     ; efd3: 85 94       ..
    lda #1                                                            ; efd5: a9 01       ..
    sta io_temp_1                                                     ; efd7: 85 a3       ..
    lda io_temp_2                                                     ; efd9: a5 a4       ..
    sta vic_control_1                                                 ; efdb: 8d 11 d0    ..P
    stx io_temp_2                                                     ; efde: 86 a4       ..
    jmp ce7da                                                         ; efe0: 4c da e7    lZ.

; &efe3 referenced 4 times by &e98c, &e994, &f012, &f01e
.cefe3
    jsr sub_cf04c                                                     ; efe3: 20 4c f0     l.
    jsr sub_ced25                                                     ; efe6: 20 25 ed     %.
    bcs ceff3                                                         ; efe9: b0 08       ..
    jsr sub_cf043                                                     ; efeb: 20 43 f0     c.
    jsr sub_cee2b                                                     ; efee: 20 2b ee     +.
    bcc ceff9                                                         ; eff1: 90 06       ..
; &eff3 referenced 2 times by &efe9, &efff
.ceff3
    jsr sub_cfeb0                                                     ; eff3: 20 b0 fe     ..
    jmp ce987                                                         ; eff6: 4c 87 e9    l..

; &eff9 referenced 1 time by &eff1
.ceff9
    jsr sub_cf043                                                     ; eff9: 20 43 f0     c.
    jsr sub_ceece                                                     ; effc: 20 ce ee     N.
    bcs ceff3                                                         ; efff: b0 f2       ..
    ldy #0                                                            ; f001: a0 00       ..
    lda (tape_buffer_ptr),y                                           ; f003: b1 b2       ..
    cmp #5                                                            ; f005: c9 05       I.
    bne cf00c                                                         ; f007: d0 03       P.
    jmp ce6b0                                                         ; f009: 4c b0 e6    l..

; &f00c referenced 1 time by &f007
.cf00c
    cmp #1                                                            ; f00c: c9 01       I.
    beq cf018                                                         ; f00e: f0 08       ..
    cmp #3                                                            ; f010: c9 03       I.
    bne cefe3                                                         ; f012: d0 cf       PO
    lda #1                                                            ; f014: a9 01       ..
    sta secondary_address                                             ; f016: 85 b9       ..
; &f018 referenced 1 time by &f00e
.cf018
    jsr sub_cfeb0                                                     ; f018: 20 b0 fe     ..
    jsr sub_ce5f9                                                     ; f01b: 20 f9 e5     ..
    bcs cefe3                                                         ; f01e: b0 c3       .C
    jsr sub_ced33                                                     ; f020: 20 33 ed     3.
    ldy #0                                                            ; f023: a0 00       ..
    jsr sub_cee2b                                                     ; f025: 20 2b ee     +.
    bcc cf02d                                                         ; f028: 90 03       ..
    jmp ce6b0                                                         ; f02a: 4c b0 e6    l..

; &f02d referenced 1 time by &f028
.cf02d
    jsr sub_cfec0                                                     ; f02d: 20 c0 fe     ..
    beq cf035                                                         ; f030: f0 03       ..
    jmp ce6b0                                                         ; f032: 4c b0 e6    l..

; &f035 referenced 1 time by &f030
.cf035
    jsr sub_cfeb0                                                     ; f035: 20 b0 fe     ..
    jsr sub_ceece                                                     ; f038: 20 ce ee     N.
    bcc cf040                                                         ; f03b: 90 03       ..
    jmp ce6b0                                                         ; f03d: 4c b0 e6    l..

; &f040 referenced 1 time by &f03b
.cf040
    jmp ce6a7                                                         ; f040: 4c a7 e6    l..

; &f043 referenced 2 times by &efeb, &eff9
.sub_cf043
    lda tape_buffer_ptr+1                                             ; f043: a5 b3       ..
    sta load_address_temp+1                                           ; f045: 85 c4       .D
    lda tape_buffer_ptr                                               ; f047: a5 b2       ..
    sta load_address_temp                                             ; f049: 85 c3       .C
    rts                                                               ; f04b: 60          .

; &f04c referenced 1 time by &efe3
.sub_cf04c
    lda load_address_temp+1                                           ; f04c: a5 c4       .D
    sta io_start_ptr+1                                                ; f04e: 85 c2       .B
    lda load_address_temp                                             ; f050: a5 c3       .C
    sta io_start_ptr                                                  ; f052: 85 c1       .A
    rts                                                               ; f054: 60          .

; &f055 referenced 5 times by &f067, &f06e, &f073, &f07a, &f083
.cf055
    jmp cff43                                                         ; f055: 4c 43 ff    lc.

; &f058 referenced 1 time by &f5f7
.cf058
    lda filename_length                                               ; f058: a5 b7       ..
    bne cf05f                                                         ; f05a: d0 03       P.
    jmp lfc84                                                         ; f05c: 4c 84 fc    l..

; &f05f referenced 1 time by &f05a
.cf05f
    jsr sub_cff23                                                     ; f05f: 20 23 ff     #.
    lda device_number                                                 ; f062: a5 ba       ..
    jsr cf4cd                                                         ; f064: 20 cd f4     M.
    bcs cf055                                                         ; f067: b0 ec       ..
    lda #1                                                            ; f069: a9 01       ..
    jsr sub_ce572                                                     ; f06b: 20 72 e5     ..
    bcs cf055                                                         ; f06e: b0 e5       ..
    jsr sub_cfb40                                                     ; f070: 20 40 fb     @.
    bcs cf055                                                         ; f073: b0 e0       ..
    lda device_number                                                 ; f075: a5 ba       ..
    jsr cf4cd                                                         ; f077: 20 cd f4     M.
    bcs cf055                                                         ; f07a: b0 d9       .Y
    lda #&61                                                          ; f07c: a9 61       ..
    sta io_temp_2                                                     ; f07e: 85 a4       ..
    jsr cfabe                                                         ; f080: 20 be fa     ..
    bcs cf055                                                         ; f083: b0 d0       .P
    jsr sub_cfe7a                                                     ; f085: 20 7a fe     ..
    lda io_start_ptr                                                  ; f088: a5 c1       .A
    sta io_temp_2                                                     ; f08a: 85 a4       ..
    clc                                                               ; f08c: 18          .
    jsr sub_cf0c9                                                     ; f08d: 20 c9 f0     I.
    lda io_start_ptr+1                                                ; f090: a5 c2       .B
    sta io_temp_2                                                     ; f092: 85 a4       ..
    clc                                                               ; f094: 18          .
    jsr sub_cf0c9                                                     ; f095: 20 c9 f0     I.
    jsr sub_cfeb0                                                     ; f098: 20 b0 fe     ..
    ldy #0                                                            ; f09b: a0 00       ..
; &f09d referenced 1 time by &f0ac
.loop_cf09d
    jsr sub_cfc91                                                     ; f09d: 20 91 fc     ..
    sta io_temp_2                                                     ; f0a0: 85 a4       ..
    clc                                                               ; f0a2: 18          .
    jsr sub_cf0c9                                                     ; f0a3: 20 c9 f0     I.
    jsr sub_cfeb9                                                     ; f0a6: 20 b9 fe     ..
; &f0a9 referenced 1 time by &fc8c
.cf0a9
    jsr sub_cfec0                                                     ; f0a9: 20 c0 fe     ..
    bne loop_cf09d                                                    ; f0ac: d0 ef       P.
    lda device_number                                                 ; f0ae: a5 ba       ..
    jsr cfd09                                                         ; f0b0: 20 09 fd     ..
    lda device_number                                                 ; f0b3: a5 ba       ..
    jsr cf4cd                                                         ; f0b5: 20 cd f4     M.
    lda #&e1                                                          ; f0b8: a9 e1       ..
    sta io_temp_2                                                     ; f0ba: 85 a4       ..
    jsr cfabe                                                         ; f0bc: 20 be fa     ..
    jsr cf647                                                         ; f0bf: 20 47 f6     g.
    lda device_number                                                 ; f0c2: a5 ba       ..
    jsr cfd09                                                         ; f0c4: 20 09 fd     ..
    clc                                                               ; f0c7: 18          .
    rts                                                               ; f0c8: 60          .

; &f0c9 referenced 5 times by &f08d, &f095, &f0a3, &fa16, &fb55
.sub_cf0c9
    php                                                               ; f0c9: 08          .
    lda io_temp_1                                                     ; f0ca: a5 a3       ..
    cmp #1                                                            ; f0cc: c9 01       I.
    bne cf0d4                                                         ; f0ce: d0 04       P.
    plp                                                               ; f0d0: 28          (
    jmp cf2c8                                                         ; f0d1: 4c c8 f2    lH.

; &f0d4 referenced 1 time by &f0ce
.cf0d4
    plp                                                               ; f0d4: 28          (
; &f0d5 referenced 1 time by &f8af
.sub_cf0d5
    ; push X,Y onto the stack
    txa                                                               ; f0d5: 8a          .
    pha                                                               ; f0d6: 48          h
    tya                                                               ; f0d7: 98          .
    pha                                                               ; f0d8: 48          h
    jsr sub_cee97                                                     ; f0d9: 20 97 ee     ..
; &f0dc referenced 1 time by &fad4
.cf0dc
    sei                                                               ; f0dc: 78          .
    jsr cf7d1                                                         ; f0dd: 20 d1 f7     Q.
    bcc cf0e8                                                         ; f0e0: 90 06       ..
    jsr cf7d7                                                         ; f0e2: 20 d7 f7     W.
    jsr cf7d1                                                         ; f0e5: 20 d1 f7     Q.
; &f0e8 referenced 1 time by &f0e0
.cf0e8
    lda io_temp_1                                                     ; f0e8: a5 a3       ..
    cmp #2                                                            ; f0ea: c9 02       I.
    bne cf0fe                                                         ; f0ec: d0 10       P.
    lda #&ff                                                          ; f0ee: a9 ff       ..
    sta cia2_data_direction_b                                         ; f0f0: 8d 03 dd    ...
    lda io_temp_2                                                     ; f0f3: a5 a4       ..
    sta cia2_port_b                                                   ; f0f5: 8d 01 dd    ...
    jsr sub_cee90                                                     ; f0f8: 20 90 ee     ..
    jmp cf12b                                                         ; f0fb: 4c 2b f1    l+.

; &f0fe referenced 1 time by &f0ec
.cf0fe
    jsr sub_cee90                                                     ; f0fe: 20 90 ee     ..
    jsr sub_cf7dd                                                     ; f101: 20 dd f7     ..
    ldx #7                                                            ; f104: a2 07       ..
; &f106 referenced 1 time by &f129
.cf106
    bne cf10f                                                         ; f106: d0 07       P.
    lda io_temp_1                                                     ; f108: a5 a3       ..
    beq cf10f                                                         ; f10a: f0 03       ..
    jsr sub_cfad7                                                     ; f10c: 20 d7 fa     W.
; &f10f referenced 2 times by &f106, &f10a
.cf10f
    lda io_temp_2                                                     ; f10f: a5 a4       ..
    lsr a                                                             ; f111: 4a          j
    sta io_temp_2                                                     ; f112: 85 a4       ..
    bcs cf11c                                                         ; f114: b0 06       ..
    jsr sub_ceeac                                                     ; f116: 20 ac ee     ..
    jmp cf11f                                                         ; f119: 4c 1f f1    l..

; &f11c referenced 1 time by &f114
.cf11c
    jsr sub_cee9f                                                     ; f11c: 20 9f ee     ..
; &f11f referenced 1 time by &f119
.cf11f
    jsr sub_cf7ef                                                     ; f11f: 20 ef f7     ..
    jsr sub_cee90                                                     ; f122: 20 90 ee     ..
    jsr sub_cf7ef                                                     ; f125: 20 ef f7     ..
    dex                                                               ; f128: ca          J
    bpl cf106                                                         ; f129: 10 db       ..
; &f12b referenced 1 time by &f0fb
.cf12b
    cli                                                               ; f12b: 58          x
    ldx #&ff                                                          ; f12c: a2 ff       ..
; &f12e referenced 1 time by &f134
.loop_cf12e
    lda cia2_port_a                                                   ; f12e: ad 00 dd    ...
    bpl cf13b                                                         ; f131: 10 08       ..
    dex                                                               ; f133: ca          J
    bne loop_cf12e                                                    ; f134: d0 f8       P.
    bmi cf13b                                                         ; f136: 30 03       0.
    jmp cfab0                                                         ; f138: 4c b0 fa    l..

; &f13b referenced 2 times by &f131, &f136
.cf13b
    jmp cfaa6                                                         ; f13b: 4c a6 fa    l..

.default_getin_handler
    jmp cf87e                                                         ; f13e: 4c 7e f8    l..

    equb &2a                                                          ; f141: 2a          *

; &f142 referenced 1 time by &f882
.cf142
    lda keyboard_buffer_length                                        ; f142: a5 c6       .F
    bne cf148                                                         ; f144: d0 02       P.
    sec                                                               ; f146: 38          8
    rts                                                               ; f147: 60          .

; &f148 referenced 1 time by &f144
.cf148
    lda keyboard_buffer                                               ; f148: ad 77 02    ...
    ; push A,Y onto the stack
    pha                                                               ; f14b: 48          h
    tya                                                               ; f14c: 98          .
    pha                                                               ; f14d: 48          h
    jsr sub_cfd1d                                                     ; f14e: 20 1d fd     ..
    ; pull A,Y from the stack
    pla                                                               ; f151: 68          .
    tay                                                               ; f152: a8          .
    pla                                                               ; f153: 68          .
    clc                                                               ; f154: 18          .
    rts                                                               ; f155: 60          .

    equb 0                                                            ; f156: 00          .

.default_chrin_handler
    lda input_device                                                  ; f157: a5 99       ..
    bne cf15e                                                         ; f159: d0 03       P.
    jmp cf657                                                         ; f15b: 4c 57 f6    lw.

; &f15e referenced 2 times by &f159, &f885
.cf15e
    jsr sub_cf90e                                                     ; f15e: 20 0e f9     ..
    bcs cf166                                                         ; f161: b0 03       ..
    jmp cf7b4                                                         ; f163: 4c b4 f7    l..

; &f166 referenced 1 time by &f161
.cf166
    jmp cff43                                                         ; f166: 4c 43 ff    lc.

; &f169 referenced 1 time by &e83a
.sub_cf169
    jmp (keyboard_table_setup_vector)                                 ; f169: 6c 8f 02    ...

; &f16c referenced 1 time by &ef27
.cf16c
    sei                                                               ; f16c: 78          .
    ; push X,Y onto the stack
    txa                                                               ; f16d: 8a          .
    pha                                                               ; f16e: 48          h
    tya                                                               ; f16f: 98          .
    pha                                                               ; f170: 48          h
    jsr sub_cf8bf                                                     ; f171: 20 bf f8     ..
    pha                                                               ; f174: 48          h
    jsr ce717                                                         ; f175: 20 17 e7     ..
    lda cia2_port_a                                                   ; f178: ad 00 dd    ...
    and #&df                                                          ; f17b: 29 df       ).
    tax                                                               ; f17d: aa          .
    jsr sub_ce702                                                     ; f17e: 20 02 e7     ..
    stx cia2_port_a                                                   ; f181: 8e 00 dd    ...
    lda serial_char_buffered_flag                                     ; f184: a5 94       ..
    ora #&20 ; ' '                                                    ; f186: 09 20       .
    tax                                                               ; f188: aa          .
    nop                                                               ; f189: ea          .
    nop                                                               ; f18a: ea          .
    lda cia2_port_a                                                   ; f18b: ad 00 dd    ...
    lsr a                                                             ; f18e: 4a          j
    lsr a                                                             ; f18f: 4a          j
    nop                                                               ; f190: ea          .
    ora cia2_port_a                                                   ; f191: 0d 00 dd    ...
    lsr a                                                             ; f194: 4a          j
    lsr a                                                             ; f195: 4a          j
    eor serial_char_buffered_flag                                     ; f196: 45 94       e.
    eor cia2_port_a                                                   ; f198: 4d 00 dd    m..
    lsr a                                                             ; f19b: 4a          j
    lsr a                                                             ; f19c: 4a          j
    eor serial_char_buffered_flag                                     ; f19d: 45 94       e.
    eor cia2_port_a                                                   ; f19f: 4d 00 dd    m..
    sta io_temp_2                                                     ; f1a2: 85 a4       ..
    nop                                                               ; f1a4: ea          .
    nop                                                               ; f1a5: ea          .
    bit cia2_port_a                                                   ; f1a6: 2c 00 dd    ,..
    stx cia2_port_a                                                   ; f1a9: 8e 00 dd    ...
    bvc cf1b6                                                         ; f1ac: 50 08       p.
    lda cia2_port_a                                                   ; f1ae: ad 00 dd    ...
    bmi cf1c5                                                         ; f1b1: 30 12       0.
    jsr sub_cf985                                                     ; f1b3: 20 85 f9     ..
; &f1b6 referenced 2 times by &f1ac, &f1c8
.cf1b6
    lda #0                                                            ; f1b6: a9 00       ..
    sta serial_char_buffered_flag                                     ; f1b8: 85 94       ..
    lda #1                                                            ; f1ba: a9 01       ..
    sta io_temp_1                                                     ; f1bc: 85 a3       ..
    pla                                                               ; f1be: 68          .
    sta vic_sprite_enable                                             ; f1bf: 8d 15 d0    ..P
    jmp cef74                                                         ; f1c2: 4c 74 ef    l..

; &f1c5 referenced 1 time by &f1b1
.cf1c5
    jsr lfc8a                                                         ; f1c5: 20 8a fc     ..
    bcs cf1b6                                                         ; f1c8: b0 ec       ..
; &f1ca referenced 2 times by &f6e4, &fc1d
.default_chrout_handler
    sta last_char_printed                                             ; f1ca: 85 d7       .W
    ; push X,Y onto the stack
    txa                                                               ; f1cc: 8a          .
    pha                                                               ; f1cd: 48          h
    tya                                                               ; f1ce: 98          .
    pha                                                               ; f1cf: 48          h
    php                                                               ; f1d0: 08          .
    lda output_device                                                 ; f1d1: a5 9a       ..
    cmp #3                                                            ; f1d3: c9 03       I.
    bne cf1da                                                         ; f1d5: d0 03       P.
    jmp cede2                                                         ; f1d7: 4c e2 ed    l..

; &f1da referenced 1 time by &f1d5
.cf1da
    jsr sub_cf90e                                                     ; f1da: 20 0e f9     ..
    bcs cf1e2                                                         ; f1dd: b0 03       ..
    jmp cf917                                                         ; f1df: 4c 17 f9    l..

; &f1e2 referenced 2 times by &f1dd, &f921
.cf1e2
    plp                                                               ; f1e2: 28          (
    ; pull X,Y from the stack
    pla                                                               ; f1e3: 68          .
    tay                                                               ; f1e4: a8          .
    pla                                                               ; f1e5: 68          .
    tax                                                               ; f1e6: aa          .
    sec                                                               ; f1e7: 38          8
    rts                                                               ; f1e8: 60          .

    equb &28                                                          ; f1e9: 28          (

    ; pull X,Y from the stack
    pla                                                               ; f1ea: 68          .
    tay                                                               ; f1eb: a8          .
    pla                                                               ; f1ec: 68          .
    tax                                                               ; f1ed: aa          .
    jmp cff43                                                         ; f1ee: 4c 43 ff    lc.

; &f1f1 referenced 2 times by &ee28, &f91e
.cf1f1
    plp                                                               ; f1f1: 28          (
    cli                                                               ; f1f2: 58          x
    ; pull X,Y from the stack
    pla                                                               ; f1f3: 68          .
    tay                                                               ; f1f4: a8          .
    pla                                                               ; f1f5: 68          .
    tax                                                               ; f1f6: aa          .
    lda last_char_printed                                             ; f1f7: a5 d7       .W
    clc                                                               ; f1f9: 18          .
    rts                                                               ; f1fa: 60          .

; &f1fb referenced 2 times by &ef83, &fb8b
.sub_cf1fb
    lda vic_control_1                                                 ; f1fb: ad 11 d0    ..P
    and #&ef                                                          ; f1fe: 29 ef       ).
    sta vic_control_1                                                 ; f200: 8d 11 d0    ..P
; &f203 referenced 1 time by &f206
.loop_cf203
    lda vic_control_1                                                 ; f203: ad 11 d0    ..P
    bpl loop_cf203                                                    ; f206: 10 fb       ..
; &f208 referenced 1 time by &f20b
.loop_cf208
    lda vic_control_1                                                 ; f208: ad 11 d0    ..P
    bmi loop_cf208                                                    ; f20b: 30 fb       0.
    rts                                                               ; f20d: 60          .

.default_chkin_handler
    ; push A,Y onto the stack
    pha                                                               ; f20e: 48          h
    tya                                                               ; f20f: 98          .
    pha                                                               ; f210: 48          h
    jsr cf981                                                         ; f211: 20 81 f9     ..
    txa                                                               ; f214: 8a          .
    jsr sub_cf932                                                     ; f215: 20 32 f9     2.
    bcc cf21d                                                         ; f218: 90 03       ..
    jmp cf949                                                         ; f21a: 4c 49 f9    li.

; &f21d referenced 1 time by &f218
.cf21d
    lda device_number_table,y                                         ; f21d: b9 63 02    ...
    beq cf231                                                         ; f220: f0 0f       ..
    jsr sub_cf90e                                                     ; f222: 20 0e f9     ..
    bcs cf22a                                                         ; f225: b0 03       ..
    jmp cfc47                                                         ; f227: 4c 47 fc    lg.

; &f22a referenced 1 time by &f225
.cf22a
    cmp #3                                                            ; f22a: c9 03       I.
    beq cf231                                                         ; f22c: f0 03       ..
    jmp cf940                                                         ; f22e: 4c 40 f9    l@.

; &f231 referenced 3 times by &f220, &f22c, &fc69
.cf231
    lda device_number_table,y                                         ; f231: b9 63 02    ...
    sta input_device                                                  ; f234: 85 99       ..
; &f236 referenced 1 time by &f278
.cf236
    ; pull A,Y from the stack
    pla                                                               ; f236: 68          .
    tay                                                               ; f237: a8          .
    pla                                                               ; f238: 68          .
    clc                                                               ; f239: 18          .
    rts                                                               ; f23a: 60          .

; &f23b referenced 1 time by &fc4e
.cf23b
    ; pull A,Y from the stack
    pla                                                               ; f23b: 68          .
    tay                                                               ; f23c: a8          .
    pla                                                               ; f23d: 68          .
    jmp lfc7e                                                         ; f23e: 4c 7e fc    l..

; &f241 referenced 1 time by &ff9c
.cf241
    bcc cf249                                                         ; f241: 90 06       ..
    ldy os_memory_start+1                                             ; f243: ac 82 02    ...
    ldx os_memory_start                                               ; f246: ae 81 02    ...
; &f249 referenced 1 time by &f241
.cf249
    sty os_memory_start+1                                             ; f249: 8c 82 02    ...
    stx os_memory_start                                               ; f24c: 8e 81 02    ...
    rts                                                               ; f24f: 60          .

.default_chkout_handler
    ; push A,Y onto the stack
    pha                                                               ; f250: 48          h
    tya                                                               ; f251: 98          .
    pha                                                               ; f252: 48          h
    jsr cf981                                                         ; f253: 20 81 f9     ..
    txa                                                               ; f256: 8a          .
    jsr sub_cf932                                                     ; f257: 20 32 f9     2.
    bcc cf25f                                                         ; f25a: 90 03       ..
    jmp cf949                                                         ; f25c: 4c 49 f9    li.

; &f25f referenced 1 time by &f25a
.cf25f
    lda device_number_table,y                                         ; f25f: b9 63 02    ...
    beq cf27b                                                         ; f262: f0 17       ..
    jsr sub_cf90e                                                     ; f264: 20 0e f9     ..
    bcs cf26c                                                         ; f267: b0 03       ..
    jmp ce521                                                         ; f269: 4c 21 e5    l!.

; &f26c referenced 1 time by &f267
.cf26c
    cmp #3                                                            ; f26c: c9 03       I.
    beq cf273                                                         ; f26e: f0 03       ..
    jmp cf940                                                         ; f270: 4c 40 f9    l@.

; &f273 referenced 2 times by &e541, &f26e
.cf273
    lda device_number_table,y                                         ; f273: b9 63 02    ...
    sta output_device                                                 ; f276: 85 9a       ..
    jmp cf236                                                         ; f278: 4c 36 f2    l6.

; &f27b referenced 2 times by &e526, &f262
.cf27b
    ; pull A,Y from the stack
    pla                                                               ; f27b: 68          .
    tay                                                               ; f27c: a8          .
    pla                                                               ; f27d: 68          .
    jmp lfc81                                                         ; f27e: 4c 81 fc    l..

.nmi_entry
    sei                                                               ; f281: 78          .
    cld                                                               ; f282: d8          X
    pha                                                               ; f283: 48          h
    lda nmi_vector+1                                                  ; f284: ad 19 03    ...
    beq cf28d                                                         ; f287: f0 04       ..
    pla                                                               ; f289: 68          .
    jmp (nmi_vector)                                                  ; f28a: 6c 18 03    ...

; &f28d referenced 1 time by &f287
.cf28d
    pla                                                               ; f28d: 68          .
    jmp default_nmi_handler                                           ; f28e: 4c 47 fe    lg.

.default_close_handler
    jsr sub_cf932                                                     ; f291: 20 32 f9     2.
    bcs return_13                                                     ; f294: b0 28       .(
    lda device_number_table,y                                         ; f296: b9 63 02    ...
    jsr sub_cf90e                                                     ; f299: 20 0e f9     ..
    bcs cf2a1                                                         ; f29c: b0 03       ..
    jmp cff61                                                         ; f29e: 4c 61 ff    l..

; &f2a1 referenced 4 times by &f29c, &f2b8, &ff6e, &ff7d
.cf2a1
    iny                                                               ; f2a1: c8          H
    cpy #&0a                                                          ; f2a2: c0 0a       ..
    bpl cf2bb                                                         ; f2a4: 10 15       ..
    lda logical_file_table,y                                          ; f2a6: b9 59 02    .y.
    sta basic_input_buffer+88,y                                       ; f2a9: 99 58 02    .x.
    lda device_number_table,y                                         ; f2ac: b9 63 02    ...
    sta logical_file_table+9,y                                        ; f2af: 99 62 02    ...
    lda secondary_address_table,y                                     ; f2b2: b9 6d 02    ...
    sta device_number_table+9,y                                       ; f2b5: 99 6c 02    ...
    jmp cf2a1                                                         ; f2b8: 4c a1 f2    l..

; &f2bb referenced 1 time by &f2a4
.cf2bb
    dec open_files_count                                              ; f2bb: c6 98       F.
    clc                                                               ; f2bd: 18          .
; &f2be referenced 1 time by &f294
.return_13
    rts                                                               ; f2be: 60          .

; &f2bf referenced 1 time by &ffdb
.cf2bf
    sei                                                               ; f2bf: 78          .
    sty jiffy_clock                                                   ; f2c0: 84 a0       ..
    stx jiffy_clock+1                                                 ; f2c2: 86 a1       ..
    sta jiffy_clock+2                                                 ; f2c4: 85 a2       ..
    cli                                                               ; f2c6: 58          x
    rts                                                               ; f2c7: 60          .

; &f2c8 referenced 1 time by &f0d1
.cf2c8
    sei                                                               ; f2c8: 78          .
    bcc cf2cd                                                         ; f2c9: 90 02       ..
    dec io_temp_1                                                     ; f2cb: c6 a3       F.
; &f2cd referenced 1 time by &f2c9
.cf2cd
    ; push X,Y onto the stack
    txa                                                               ; f2cd: 8a          .
    pha                                                               ; f2ce: 48          h
    tya                                                               ; f2cf: 98          .
    pha                                                               ; f2d0: 48          h
    jsr sub_ceec5                                                     ; f2d1: 20 c5 ee     E.
    jsr sub_cf8bf                                                     ; f2d4: 20 bf f8     ..
    pha                                                               ; f2d7: 48          h
    lda io_temp_2                                                     ; f2d8: a5 a4       ..
    and #&0f                                                          ; f2da: 29 0f       ).
    tax                                                               ; f2dc: aa          .
    lda lf94f,x                                                       ; f2dd: bd 4f f9    .o.
    pha                                                               ; f2e0: 48          h
    lda io_temp_2                                                     ; f2e1: a5 a4       ..
    and #&f0                                                          ; f2e3: 29 f0       ).
    pha                                                               ; f2e5: 48          h
    ldx serial_char_buffered_flag                                     ; f2e6: a6 94       ..
    jsr cf7d1                                                         ; f2e8: 20 d1 f7     Q.
    jsr sub_ce702                                                     ; f2eb: 20 02 e7     ..
    stx cia2_port_a                                                   ; f2ee: 8e 00 dd    ...
    pla                                                               ; f2f1: 68          .
    ora serial_char_buffered_flag                                     ; f2f2: 05 94       ..
    sta cia2_port_a                                                   ; f2f4: 8d 00 dd    ...
    lsr a                                                             ; f2f7: 4a          j
    lsr a                                                             ; f2f8: 4a          j
    and #&30 ; '0'                                                    ; f2f9: 29 30       )0
    ora serial_char_buffered_flag                                     ; f2fb: 05 94       ..
    sta cia2_port_a                                                   ; f2fd: 8d 00 dd    ...
    pla                                                               ; f300: 68          .
    ora serial_char_buffered_flag                                     ; f301: 05 94       ..
    sta cia2_port_a                                                   ; f303: 8d 00 dd    ...
    lsr a                                                             ; f306: 4a          j
    lsr a                                                             ; f307: 4a          j
    and #&30 ; '0'                                                    ; f308: 29 30       )0
    sta cia2_port_a                                                   ; f30a: 8d 00 dd    ...
    lda serial_char_buffered_flag                                     ; f30d: a5 94       ..
    ldx io_temp_1                                                     ; f30f: a6 a3       ..
    beq cf324                                                         ; f311: f0 11       ..
; &f313 referenced 1 time by &f32c
.loop_cf313
    ora #&10                                                          ; f313: 09 10       ..
    sta cia2_port_a                                                   ; f315: 8d 00 dd    ...
    lda #1                                                            ; f318: a9 01       ..
    sta io_temp_1                                                     ; f31a: 85 a3       ..
    pla                                                               ; f31c: 68          .
    sta vic_sprite_enable                                             ; f31d: 8d 15 d0    ..P
    cli                                                               ; f320: 58          x
    jmp cfaa6                                                         ; f321: 4c a6 fa    l..

; &f324 referenced 1 time by &f311
.cf324
    sta cia2_port_a                                                   ; f324: 8d 00 dd    ...
    jsr sub_cf7ef                                                     ; f327: 20 ef f7     ..
    lda serial_char_buffered_flag                                     ; f32a: a5 94       ..
    jmp loop_cf313                                                    ; f32c: 4c 13 f3    l..

.default_clall_handler
    jmp cfa8e                                                         ; f32f: 4c 8e fa    l..

    equb 0                                                            ; f332: 00          .

; &f333 referenced 1 time by &faa0
.default_clrchn_handler
    jsr sub_cf9ca                                                     ; f333: 20 ca f9     J.
; &f336 referenced 1 time by &e5c6
.cf336
    lda #0                                                            ; f336: a9 00       ..
    sta input_device                                                  ; f338: 85 99       ..
    lda #3                                                            ; f33a: a9 03       ..
    sta output_device                                                 ; f33c: 85 9a       ..
    rts                                                               ; f33e: 60          .

; &f33f referenced 1 time by &e9c5
.lf33f
    equb &a2, 0, &86, 1, &91, &c3, &a2, 0, &86, 1, &60                ; f33f: a2 00 86... ...

.default_open_handler
    jsr cf981                                                         ; f34a: 20 81 f9     ..
    ldy open_files_count                                              ; f34d: a4 98       ..
; &f34f referenced 1 time by &f35e
.loop_cf34f
    beq cf361                                                         ; f34f: f0 10       ..
    dey                                                               ; f351: 88          .
    lda logical_file_table,y                                          ; f352: b9 59 02    .y.
    cmp logical_file_number                                           ; f355: c5 b8       E.
    bne cf35c                                                         ; f357: d0 03       P.
    jmp cfc72                                                         ; f359: 4c 72 fc    l..

; &f35c referenced 1 time by &f357
.cf35c
    cpy #0                                                            ; f35c: c0 00       ..
    jmp loop_cf34f                                                    ; f35e: 4c 4f f3    lo.

; &f361 referenced 1 time by &f34f
.cf361
    ldy open_files_count                                              ; f361: a4 98       ..
    cpy #&0a                                                          ; f363: c0 0a       ..
    bcc cf36a                                                         ; f365: 90 03       ..
    jmp cfc6f                                                         ; f367: 4c 6f fc    l..

; &f36a referenced 1 time by &f365
.cf36a
    lda logical_file_number                                           ; f36a: a5 b8       ..
    sta logical_file_table,y                                          ; f36c: 99 59 02    .y.
    lda device_number                                                 ; f36f: a5 ba       ..
    sta device_number_table,y                                         ; f371: 99 63 02    ...
    lda secondary_address                                             ; f374: a5 b9       ..
    sta secondary_address_table,y                                     ; f376: 99 6d 02    ...
    iny                                                               ; f379: c8          H
    sty open_files_count                                              ; f37a: 84 98       ..
    lda device_number                                                 ; f37c: a5 ba       ..
    jsr sub_cf90e                                                     ; f37e: 20 0e f9     ..
    bcs cf386                                                         ; f381: b0 03       ..
    jmp cfbad                                                         ; f383: 4c ad fb    l..

; &f386 referenced 2 times by &f381, &fbc6
.cf386
    clc                                                               ; f386: 18          .
    rts                                                               ; f387: 60          .

; &f388 referenced 2 times by &fc61, &ff96
.cf388
    ora #&90                                                          ; f388: 09 90       ..
    jmp cf9bf                                                         ; f38a: 4c bf f9    l..

    equb &a6, &d8, &f0,   5, &a9, &14, &4c, &74, &f8, &a4, &d3, &f0   ; f38d: a6 d8 f0... .X.
    equb &47, &c0, &28, &d0, &16, &a5, &f3, &d0,   4, &c6, &f4        ; f399: 47 c0 28... g.(
    equb &c6, &d2, &c6 ; petscii "FRF"                                ; f3a4: c6 d2 c6    FRF
    equb &f3, &c6, &d1, &a2, &27, &a0, 0, &20, &cc, &f3, &4c, &d9     ; f3a7: f3 c6 d1... .FQ
    equb &ec, &20, &f0, &f8, &84                                      ; f3b3: ec 20 f0... . .
    equb &d3, &20, &4a ; petscii "S j"                                ; f3b8: d3 20 4a    S j
    equb &fa, &98, &38, &e5, &d3, &aa, &a4, &d3, &88, &20, &cc, &f3   ; f3bb: fa 98 38... ..8
    equb &c6, &d3, &4c, &22 ; petscii "FSl", &22                      ; f3c7: c6 d3 4c... FSl
    equb &ee                                                          ; f3cb: ee          .

; &f3cc referenced 1 time by &f3da
.loop_cf3cc
    iny                                                               ; f3cc: c8          H
    lda (colour_ram_line_ptr),y                                       ; f3cd: b1 f3       ..
    dey                                                               ; f3cf: 88          .
    sta (colour_ram_line_ptr),y                                       ; f3d0: 91 f3       ..
    iny                                                               ; f3d2: c8          H
    lda (screen_line_ptr),y                                           ; f3d3: b1 d1       .Q
    dey                                                               ; f3d5: 88          .
    sta (screen_line_ptr),y                                           ; f3d6: 91 d1       .Q
    iny                                                               ; f3d8: c8          H
    dex                                                               ; f3d9: ca          J
    bpl loop_cf3cc                                                    ; f3da: 10 f0       ..
    lda #&20 ; ' '                                                    ; f3dc: a9 20       .
    sta (screen_line_ptr),y                                           ; f3de: 91 d1       .Q
    rts                                                               ; f3e0: 60          .

    equb &a4, &d6, &f0, &e4, &c6, &d6, &a9, &27, &85, &d3, &20, &ee   ; f3e1: a4 d6 f0... .V.
    equb &eb, &a0, &27, &a9, &20, &91                                 ; f3ed: eb a0 27... ..'
    equb &d1, &d0, &d3 ; petscii "QPS"                                ; f3f3: d1 d0 d3    QPS
    equb &60                                                          ; f3f6: 60          .

; &f3f7 referenced 3 times by &e76e, &fc54, &ffb4
.cf3f7
    jsr sub_cf8a9                                                     ; f3f7: 20 a9 f8     ..
    jsr sub_cf90e                                                     ; f3fa: 20 0e f9     ..
    bcc cf402                                                         ; f3fd: 90 03       ..
    jmp cfc7b                                                         ; f3ff: 4c 7b fc    l..

; &f402 referenced 1 time by &f3fd
.cf402
    ora #&40 ; '@'                                                    ; f402: 09 40       .@
; &f404 referenced 1 time by &f4da
.cf404
    sta io_temp_2                                                     ; f404: 85 a4       ..
    lda #&ff                                                          ; f406: a9 ff       ..
    sta io_temp_1                                                     ; f408: 85 a3       ..
    jmp cfabe                                                         ; f40a: 4c be fa    l..

; &f40d referenced 1 time by &f41a
.loop_cf40d
    inc cursor_row                                                    ; f40d: e6 d6       .V
; &f40f referenced 1 time by &f423
.loop_cf40f
    jmp cebee                                                         ; f40f: 4c ee eb    l..

; &f412 referenced 1 time by &f41e
.loop_cf412
    jsr ce8ea                                                         ; f412: 20 ea e8     ..
; &f415 referenced 1 time by &ee14
.sub_cf415
    ldy cursor_row                                                    ; f415: a4 d6       .V
    lda screen_line_links,y                                           ; f417: b9 d9 00    .Y.
    bpl loop_cf40d                                                    ; f41a: 10 f1       ..
    cpy #&18                                                          ; f41c: c0 18       ..
    beq loop_cf412                                                    ; f41e: f0 f2       ..
    lda screen_line_links+1,y                                         ; f420: b9 da 00    .Z.
    bpl loop_cf40f                                                    ; f423: 10 ea       ..
    jsr sub_cf9df                                                     ; f425: 20 df f9     ..
    ldy #&17                                                          ; f428: a0 17       ..
; &f42a referenced 1 time by &f437
.loop_cf42a
    cpy cursor_row                                                    ; f42a: c4 d6       DV
    beq cf439                                                         ; f42c: f0 0b       ..
    bcc cf439                                                         ; f42e: 90 09       ..
    lda screen_line_links,y                                           ; f430: b9 d9 00    .Y.
    sta screen_line_links+1,y                                         ; f433: 99 da 00    .Z.
    dey                                                               ; f436: 88          .
    bne loop_cf42a                                                    ; f437: d0 f1       P.
; &f439 referenced 2 times by &f42c, &f42e
.cf439
    ldy cursor_row                                                    ; f439: a4 d6       .V
    lda #0                                                            ; f43b: a9 00       ..
    sta screen_line_links+1,y                                         ; f43d: 99 da 00    .Z.
    lda #&17                                                          ; f440: a9 17       ..
    sec                                                               ; f442: 38          8
    sbc cursor_row                                                    ; f443: e5 d6       .V
    beq cf492                                                         ; f445: f0 4b       .k
    tax                                                               ; f447: aa          .
    lda screen_memory_page                                            ; f448: ad 88 02    ...
    clc                                                               ; f44b: 18          .
    adc #3                                                            ; f44c: 69 03       ..
    sta io_address_ptr+1                                              ; f44e: 85 ad       ..
    sta io_end_ptr+1                                                  ; f450: 85 af       ..
    lda #&db                                                          ; f452: a9 db       ..
    sta screen_line_ptr+1                                             ; f454: 85 d2       .R
    sta colour_ram_line_ptr+1                                         ; f456: 85 f4       ..
    lda #&c0                                                          ; f458: a9 c0       ..
    sta io_end_ptr                                                    ; f45a: 85 ae       ..
    sta colour_ram_line_ptr                                           ; f45c: 85 f3       ..
    lda #&98                                                          ; f45e: a9 98       ..
    sta io_address_ptr                                                ; f460: 85 ac       ..
    sta screen_line_ptr                                               ; f462: 85 d1       .Q
; &f464 referenced 1 time by &f490
.cf464
    ldy #&27 ; '''                                                    ; f464: a0 27       .'
; &f466 referenced 1 time by &f46f
.loop_cf466
    lda (io_address_ptr),y                                            ; f466: b1 ac       ..
    sta (io_end_ptr),y                                                ; f468: 91 ae       ..
    lda (screen_line_ptr),y                                           ; f46a: b1 d1       .Q
    sta (colour_ram_line_ptr),y                                       ; f46c: 91 f3       ..
    dey                                                               ; f46e: 88          .
    bpl loop_cf466                                                    ; f46f: 10 f5       ..
    lda io_address_ptr                                                ; f471: a5 ac       ..
    sec                                                               ; f473: 38          8
    sbc #&28 ; '('                                                    ; f474: e9 28       .(
    sta io_address_ptr                                                ; f476: 85 ac       ..
    sta screen_line_ptr                                               ; f478: 85 d1       .Q
    bcs cf480                                                         ; f47a: b0 04       ..
    dec io_address_ptr+1                                              ; f47c: c6 ad       F.
    dec screen_line_ptr+1                                             ; f47e: c6 d2       FR
; &f480 referenced 1 time by &f47a
.cf480
    lda io_end_ptr                                                    ; f480: a5 ae       ..
    sec                                                               ; f482: 38          8
    sbc #&28 ; '('                                                    ; f483: e9 28       .(
    sta io_end_ptr                                                    ; f485: 85 ae       ..
    sta colour_ram_line_ptr                                           ; f487: 85 f3       ..
    bcs cf48f                                                         ; f489: b0 04       ..
    dec io_end_ptr+1                                                  ; f48b: c6 af       F.
    dec colour_ram_line_ptr+1                                         ; f48d: c6 f4       F.
; &f48f referenced 1 time by &f489
.cf48f
    dex                                                               ; f48f: ca          J
    bne cf464                                                         ; f490: d0 d2       PR
; &f492 referenced 1 time by &f445
.cf492
    jsr sub_cfe34                                                     ; f492: 20 34 fe     4.
    ldx cursor_row                                                    ; f495: a6 d6       .V
    inx                                                               ; f497: e8          .
    jsr sub_ce9ff                                                     ; f498: 20 ff e9     ..
    jmp ceb95                                                         ; f49b: 4c 95 eb    l..

; &f49e referenced 1 time by &ffd5
.cf49e
    sty load_address_temp+1                                           ; f49e: 84 c4       .D
    stx load_address_temp                                             ; f4a0: 86 c3       .C
    jmp (load_vector)                                                 ; f4a2: 6c 30 03    .0.

.default_load_handler
    sta load_verify_flag                                              ; f4a5: 85 93       ..
    lda load_address_temp                                             ; f4a7: a5 c3       .C
    sta io_start_ptr                                                  ; f4a9: 85 c1       .A
    lda load_address_temp+1                                           ; f4ab: a5 c4       .D
    sta io_start_ptr+1                                                ; f4ad: 85 c2       .B
    jsr cf981                                                         ; f4af: 20 81 f9     ..
    lda device_number                                                 ; f4b2: a5 ba       ..
    cmp #1                                                            ; f4b4: c9 01       I.
    bne cf4bb                                                         ; f4b6: d0 03       P.
    jmp ce97b                                                         ; f4b8: 4c 7b e9    l..

; &f4bb referenced 1 time by &f4b6
.cf4bb
    cmp #7                                                            ; f4bb: c9 07       I.
    bne cf4c2                                                         ; f4bd: d0 03       P.
    jmp ce97b                                                         ; f4bf: 4c 7b e9    l..

; &f4c2 referenced 1 time by &f4bd
.cf4c2
    jsr sub_cf90a                                                     ; f4c2: 20 0a f9     ..
    bcs cf4ca                                                         ; f4c5: b0 03       ..
    jmp ce74f                                                         ; f4c7: 4c 4f e7    lo.

; &f4ca referenced 1 time by &f4c5
.cf4ca
    jmp cff49                                                         ; f4ca: 4c 49 ff    li.

; &f4cd referenced 8 times by &e52c, &e75b, &f064, &f077, &f0b5, &fa23, &fbb1, &ffb1
.cf4cd
    jsr sub_cf8a9                                                     ; f4cd: 20 a9 f8     ..
    jsr sub_cf90e                                                     ; f4d0: 20 0e f9     ..
    bcc cf4d8                                                         ; f4d3: 90 03       ..
    jmp cfc7b                                                         ; f4d5: 4c 7b fc    l..

; &f4d8 referenced 1 time by &f4d3
.cf4d8
    ora #&20 ; ' '                                                    ; f4d8: 09 20       .
    jmp cf404                                                         ; f4da: 4c 04 f4    l..

    equb &14, &0d, &1d, &88, &85, &86, &87, &11                       ; f4dd: 14 0d 1d... ...
    equb &33, &57, &41, &34, &5a, &53, &45 ; petscii "3wa4zse"        ; f4e5: 33 57 41... 3wa
    equb 0                                                            ; f4ec: 00          .
    equb &35, &52, &44, &36, &43, &46, &54, &58 ; petscii "5rd6cftx"  ; f4ed: 35 52 44... 5rd
    equb &37, &59, &47, &38, &42, &48, &55, &56 ; petscii "7yg8bhuv"  ; f4f5: 37 59 47... 7yg
    equb &39, &49, &4a, &30, &4d, &4b, &4f, &4e ; petscii "9ij0mkon"  ; f4fd: 39 49 4a... 9ij
    equb &2b, &50, &4c, &2d, &2e, &3a, &40, &2c ; petscii "+pl-.:@,"  ; f505: 2b 50 4c... +pl
    equb &5c, &2a, &3b, &13,   0, &3d, &5e, &2f, &31, &5f,   0, &32   ; f50d: 5c 2a 3b... .*;
    equb &20,   0, &51,   3, &94, &8d, &9d, &8c, &89, &8a, &8b, &91   ; f519: 20 00 51...  .q
    equb &23, &77, &61, &24, &7a, &73, &65,   0, &25, &72, &64, &26   ; f525: 23 77 61... #..
    equb &63, &66, &74, &78, &27, &79, &67, &28, &62, &68, &75, &76   ; f531: 63 66 74... ...
    equb &29, &69, &6a, &92, &6d, &6b, &6f, &6e, &db, &70, &6c, &dd   ; f53d: 29 69 6a... )..
    equb &3e, &5b, &ba, &3c, &a9, &c0, &5d, &93,   0, &3d, &de, &3f   ; f549: 3e 5b ba... >[.
    equb &21, &5f,   0, &22, &a0,   0, &71, &83, &94, &8d, &9d, &8c   ; f555: 21 5f 00... !..
    equb &89, &8a, &8b, &91, &96, &b3, &b0, &97, &ad, &ae, &b1,   0   ; f561: 89 8a 8b... ...
    equb &98, &b2, &ac, &99, &bc, &bb, &a3, &bd, &9a, &b7, &a5, &9b   ; f56d: 98 b2 ac... ...
    equb &bf, &b4, &b8, &be, &30, &a2, &b5, &30, &a7, &a1, &b9, &aa   ; f579: bf b4 b8... ...
    equb &a6, &af, &b6, &dc, &3e, &5b, &a4, &3c, &a8, &df, &5d, &93   ; f585: a6 af b6... ...
    equb   0, &3d, &de, &3f, &81, &5f,   0, &95, &a0,   0, &ab, &83   ; f591: 00 3d de... .=.
    equb   0,   0,   0,   0,   0,   0,   0,   0, &1c, &17,   1, &9f   ; f59d: 00 00 00... ...
    equb &1a, &13,   5,   0, &9c, &12,   4, &1e,   3,   6, &14, &18   ; f5a9: 1a 13 05... ...
    equb &1f, &19,   7, &9e,   2,   8, &15, &16, &12,   9, &0a, &92   ; f5b5: 1f 19 07... ...
    equb &0d, &0b, &0f, &0e,   0, &10, &0c,   0,   0, &1b,   0,   0   ; f5c1: 0d 0b 0f... ...
    equb &1c,   0, &1d,   0,   0, &1f, &1e,   0, &90,   6,   0,   5   ; f5cd: 1c 00 1d... ...
    equb   0,   0, &11,   0                                           ; f5d9: 00 00 11... ...

; &f5dd referenced 1 time by &ffd8
.cf5dd
    sty io_end_ptr+1                                                  ; f5dd: 84 af       ..
    stx io_end_ptr                                                    ; f5df: 86 ae       ..
    tax                                                               ; f5e1: aa          .
    lda cpu_port,x                                                    ; f5e2: b5 01       ..
    sta io_start_ptr+1                                                ; f5e4: 85 c2       .B
    lda cpu_port_direction,x                                          ; f5e6: b5 00       ..
    sta io_start_ptr                                                  ; f5e8: 85 c1       .A
    jmp (save_vector)                                                 ; f5ea: 6c 32 03    .2.

.default_save_handler
    jsr cf981                                                         ; f5ed: 20 81 f9     ..
    lda device_number                                                 ; f5f0: a5 ba       ..
    jsr sub_cf90a                                                     ; f5f2: 20 0a f9     ..
    bcs cf5fa                                                         ; f5f5: b0 03       ..
    jmp cf058                                                         ; f5f7: 4c 58 f0    lx.

; &f5fa referenced 1 time by &f5f5
.cf5fa
    jmp cff49                                                         ; f5fa: 4c 49 ff    li.

    equb &20, &13, &f8, &f0,   5, &f0,   3, &4c, &25, &ee, &20, &4a   ; f5fd: 20 13 f8...  ..
    equb &fa, &a6, &d6, &b5, &d9, &10, &12, &20, &32, &f6, &a9, &20   ; f609: fa a6 d6... ..V
    equb &91, &d1, &20, &13, &f8, &f0,   3, &20, &15, &f4, &4c, &22   ; f615: 91 d1 20... .Q
    equb &ee, &a5, &d3, &38, &e9, &28, &85                            ; f621: ee a5 d3... ..S
    equb &d3, &20, &32 ; petscii "S 2"                                ; f628: d3 20 32    S 2
    equb &f6, &a9, &20, &91, &d1, &d0, &ed, &88, &b1, &f3, &c8, &91   ; f62b: f6 a9 20... ..
    equb &f3, &88, &b1, &d1, &c8, &91, &d1, &88                       ; f637: f3 88 b1... ...
    equb &c4, &d3, &d0 ; petscii "DSP"                                ; f63f: c4 d3 d0    DSP
    equb &ef, &e6, &d8, &60, &60                                      ; f642: ef e6 d8... ..X

; &f647 referenced 5 times by &e586, &e590, &f0bf, &fa2d, &ff7a
.cf647
    ; push X,Y onto the stack
    txa                                                               ; f647: 8a          .
    pha                                                               ; f648: 48          h
    tya                                                               ; f649: 98          .
    pha                                                               ; f64a: 48          h
    jsr sub_cf7ef                                                     ; f64b: 20 ef f7     ..
    jsr cf89e                                                         ; f64e: 20 9e f8     ..
    jsr sub_cf7ef                                                     ; f651: 20 ef f7     ..
    jmp cfaa6                                                         ; f654: 4c a6 fa    l..

; &f657 referenced 1 time by &f15b
.cf657
    stx kernal_x_save                                                 ; f657: 86 97       ..
    tya                                                               ; f659: 98          .
    pha                                                               ; f65a: 48          h
    lda cursor_column                                                 ; f65b: a5 d3       .S
    pha                                                               ; f65d: 48          h
; &f65e referenced 1 time by &f68e
.cf65e
    lda input_from_screen_flag                                        ; f65e: a5 d0       .P
    beq cf689                                                         ; f660: f0 27       .'
    cmp input_line_end                                                ; f662: c5 c8       EH
    bne cf675                                                         ; f664: d0 0f       P.
; &f666 referenced 2 times by &f6c3, &f6d4
.cf666
    lda #0                                                            ; f666: a9 00       ..
    sta input_from_screen_flag                                        ; f668: 85 d0       .P
    sta quote_mode_flag                                               ; f66a: 85 d4       .T
    ; pull A,Y from the stack
    pla                                                               ; f66c: 68          .
    tay                                                               ; f66d: a8          .
    pla                                                               ; f66e: 68          .
    ldx kernal_x_save                                                 ; f66f: a6 97       ..
    clc                                                               ; f671: 18          .
    lda #&0d                                                          ; f672: a9 0d       ..
    rts                                                               ; f674: 60          .

; &f675 referenced 2 times by &f664, &f6da
.cf675
    inc input_from_screen_flag                                        ; f675: e6 d0       .P
    tay                                                               ; f677: a8          .
    lda (input_cursor_start),y                                        ; f678: b1 c9       .I
    jsr sub_cf8fd                                                     ; f67a: 20 fd f8     ..
    tax                                                               ; f67d: aa          .
    ; pull A,Y from the stack
    pla                                                               ; f67e: 68          .
    tay                                                               ; f67f: a8          .
    pla                                                               ; f680: 68          .
    txa                                                               ; f681: 8a          .
    ldx kernal_x_save                                                 ; f682: a6 97       ..
    jsr sub_cec1b                                                     ; f684: 20 1b ec     ..
    clc                                                               ; f687: 18          .
    rts                                                               ; f688: 60          .

; &f689 referenced 2 times by &f660, &f6ea
.cf689
    jsr sub_cf7bc                                                     ; f689: 20 bc f7     ..
    lda keyboard_buffer_length                                        ; f68c: a5 c6       .F
    beq cf65e                                                         ; f68e: f0 ce       .N
    lda keyboard_buffer                                               ; f690: ad 77 02    ...
    cmp #&0d                                                          ; f693: c9 0d       I.
    bne cf6dc                                                         ; f695: d0 45       Pe
; &f697 referenced 1 time by &f6e2
.cf697
    jsr sub_cedc1                                                     ; f697: 20 c1 ed     A.
    jsr sub_cfd1d                                                     ; f69a: 20 1d fd     ..
    jsr sub_cedc5                                                     ; f69d: 20 c5 ed     E.
    lda screen_line_ptr                                               ; f6a0: a5 d1       .Q
    sta input_cursor_start                                            ; f6a2: 85 c9       .I
    lda screen_line_ptr+1                                             ; f6a4: a5 d2       .R
    sta input_cursor_start+1                                          ; f6a6: 85 ca       .J
    ldy cursor_row                                                    ; f6a8: a4 d6       .V
    lda screen_line_links,y                                           ; f6aa: b9 d9 00    .Y.
    bmi cf6be                                                         ; f6ad: 30 0f       0.
    lda input_cursor_start                                            ; f6af: a5 c9       .I
    sec                                                               ; f6b1: 38          8
    sbc #&28 ; '('                                                    ; f6b2: e9 28       .(
    sta input_cursor_start                                            ; f6b4: 85 c9       .I
    bcs cf6ba                                                         ; f6b6: b0 02       ..
    dec input_cursor_start+1                                          ; f6b8: c6 ca       FJ
; &f6ba referenced 1 time by &f6b6
.cf6ba
    ldy #&50 ; 'p'                                                    ; f6ba: a0 50       .p
    bne cf6c2                                                         ; f6bc: d0 04       P. ; ALWAYS branch

; &f6be referenced 1 time by &f6ad
.cf6be
    jsr sub_cfa4a                                                     ; f6be: 20 4a fa     j.
    iny                                                               ; f6c1: c8          H
; &f6c2 referenced 2 times by &f6bc, &f6c9
.cf6c2
    dey                                                               ; f6c2: 88          .
    bmi cf666                                                         ; f6c3: 30 a1       0.
    lda (input_cursor_start),y                                        ; f6c5: b1 c9       .I
    cmp #&20 ; ' '                                                    ; f6c7: c9 20       I
    beq cf6c2                                                         ; f6c9: f0 f7       ..
    iny                                                               ; f6cb: c8          H
    sty input_line_end                                                ; f6cc: 84 c8       .H
    pla                                                               ; f6ce: 68          .
    pha                                                               ; f6cf: 48          h
    sta input_from_screen_flag                                        ; f6d0: 85 d0       .P
    cmp input_line_end                                                ; f6d2: c5 c8       EH
    bcs cf666                                                         ; f6d4: b0 90       ..
    ldy #0                                                            ; f6d6: a0 00       ..
    sty quote_mode_flag                                               ; f6d8: 84 d4       .T
    beq cf675                                                         ; f6da: f0 99       .. ; ALWAYS branch

; &f6dc referenced 1 time by &f695
.cf6dc
    lda keyboard_buffer                                               ; f6dc: ad 77 02    ...
    jsr sub_cfc03                                                     ; f6df: 20 03 fc     ..
    bcc cf697                                                         ; f6e2: 90 b3       ..
    jsr default_chrout_handler                                        ; f6e4: 20 ca f1     J.
    jsr sub_cfd1d                                                     ; f6e7: 20 1d fd     ..
    jmp cf689                                                         ; f6ea: 4c 89 f6    l..

; &f6ed referenced 2 times by &e5df, &e7cc
.default_stop_handler
    lda stop_key_flag                                                 ; f6ed: a5 91       ..
    bpl cf6f5                                                         ; f6ef: 10 04       ..
    lda #&ff                                                          ; f6f1: a9 ff       ..
    clc                                                               ; f6f3: 18          .
    rts                                                               ; f6f4: 60          .

; &f6f5 referenced 1 time by &f6ef
.cf6f5
    sec                                                               ; f6f5: 38          8
    lda #0                                                            ; f6f6: a9 00       ..
    rts                                                               ; f6f8: 60          .

    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f6f9: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f70d: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f721: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f735: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f749: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f75d: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f771: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f785: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; f799: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0                                          ; f7ad: 00 00 00... ...

; &f7b4 referenced 1 time by &f163
.cf7b4
lf7b6 = cf7b4+2
    jmp acptr                                                         ; f7b4: 4c a5 ff    l.. ; Read a byte from the serial bus

; &f7b6 referenced 1 time by &f929
    equb &c3, &c2, &cd, &38, &30 ; petscii "CBM80"                    ; f7b7: c3 c2 cd... CBM

; &f7bc referenced 1 time by &f689
.sub_cf7bc
    lda #0                                                            ; f7bc: a9 00       ..
    sta cursor_blink_disable                                          ; f7be: 85 cc       .L
    rts                                                               ; f7c0: 60          .

; &f7c1 referenced 2 times by &e5f3, &e65d
.sub_cf7c1
    lda #&0d                                                          ; f7c1: a9 0d       .. ; A=character to output
    jmp chrout                                                        ; f7c3: 4c d2 ff    lR. ; Output &0d (RETURN)

    equb &a9                                                          ; f7c6: a9          .
    equb &20, &4c, &d2 ; petscii " lR"                                ; f7c7: 20 4c d2     lR
    equb &ff                                                          ; f7ca: ff          .

; &f7cb referenced 2 times by &e83d, &e87d
.sub_cf7cb
    ldx #&ff                                                          ; f7cb: a2 ff       ..
    stx cia1_port_a                                                   ; f7cd: 8e 00 dc    ...
    rts                                                               ; f7d0: 60          .

; &f7d1 referenced 6 times by &ef35, &f0dd, &f0e5, &f2e8, &f7d4, &fae9
.cf7d1
    lda cia2_port_a                                                   ; f7d1: ad 00 dd    ...
    bpl cf7d1                                                         ; f7d4: 10 fb       ..
    rts                                                               ; f7d6: 60          .

; &f7d7 referenced 2 times by &f0e2, &f7da
.cf7d7
    lda cia2_port_a                                                   ; f7d7: ad 00 dd    ...
    bmi cf7d7                                                         ; f7da: 30 fb       0.
    rts                                                               ; f7dc: 60          .

; &f7dd referenced 2 times by &f101, &fa87
.sub_cf7dd
    ldx #&0a                                                          ; f7dd: a2 0a       ..
; &f7df referenced 1 time by &f7e0
.loop_cf7df
    dex                                                               ; f7df: ca          J
    bpl loop_cf7df                                                    ; f7e0: 10 fd       ..
    rts                                                               ; f7e2: 60          .

    equb &20, &66, &e5, &4c, &22, &ee, &20, &44, &e5, &4c, &22, &ee   ; f7e3: 20 66 e5...  ..

; &f7ef referenced 5 times by &f11f, &f125, &f327, &f64b, &f651
.sub_cf7ef
    ora l03ff                                                         ; f7ef: 0d ff 03    ...
    ora l03ff                                                         ; f7f2: 0d ff 03    ...
    rts                                                               ; f7f5: 60          .

; &f7f6 referenced 1 time by &ffba
.cf7f6
    sta logical_file_number                                           ; f7f6: 85 b8       ..
    sty secondary_address                                             ; f7f8: 84 b9       ..
    stx device_number                                                 ; f7fa: 86 ba       ..
    rts                                                               ; f7fc: 60          .

; &f7fd referenced 1 time by &ffbd
.cf7fd
    sta filename_length                                               ; f7fd: 85 b7       ..
    sty filename_ptr+1                                                ; f7ff: 84 bc       ..
    stx filename_ptr                                                  ; f801: 86 bb       ..
    rts                                                               ; f803: 60          .

; &f804 referenced 3 times by &ee63, &ee6f, &eef6
.sub_cf804
    lda rs232_input_bits                                              ; f804: a5 a7       ..
    eor rs232_input_parity                                            ; f806: 45 ab       e.
    sta rs232_input_parity                                            ; f808: 85 ab       ..
    rts                                                               ; f80a: 60          .

; &f80b referenced 2 times by &e84d, &e863
.lf80b
    equb &fe, &fd, &fb, &f7, &ef, &df, &bf, &7f, &20, &4a, &fa, &b1   ; f80b: fe fd fb... ...
    equb &d1, &c9, &20 ; petscii "QI "                                ; f817: d1 c9 20    QI
    equb &60                                                          ; f81a: 60          .
; &f81b referenced 1 time by &e86a
.lf81b
    equb 0, 8, &10, &18                                               ; f81b: 00 08 10... ...
    equb &20, &28, &30, &38 ; petscii " (08"                          ; f81f: 20 28 30...  (0
; &f823 referenced 1 time by &eb56
.lf823
    equb 0, &40, &80, &ff, &c0, &ff, &ff, &ff                         ; f823: 00 40 80... .@.
; &f82b referenced 1 time by &e853
.lf82b
    equb 0, &80, 0, 0, 0, 0, &10, &24                                 ; f82b: 00 80 00... ...

; &f833 referenced 2 times by &ef86, &f8bf
.sub_cf833
    lda cia2_port_a                                                   ; f833: ad 00 dd    ...
    and #7                                                            ; f836: 29 07       ).
    sta serial_char_buffered_flag                                     ; f838: 85 94       ..
    rts                                                               ; f83a: 60          .

    equb &a9, 0, &85, &d4, &85                                        ; f83b: a9 00 85... ...
    equb &d8, &4c, &25 ; petscii "Xl%"                                ; f840: d8 4c 25    Xl%
    equb &ee                                                          ; f843: ee          .

; &f844 referenced 1 time by &ffde
.cf844
    sei                                                               ; f844: 78          .
    ldy jiffy_clock                                                   ; f845: a4 a0       ..
    ldx jiffy_clock+1                                                 ; f847: a6 a1       ..
    lda jiffy_clock+2                                                 ; f849: a5 a2       ..
    cli                                                               ; f84b: 58          x
    rts                                                               ; f84c: 60          .

; &f84d referenced 1 time by &fb7e
.cf84d
    lda vic_control_1                                                 ; f84d: ad 11 d0    ..P
    ora #&10                                                          ; f850: 09 10       ..
    sta vic_control_1                                                 ; f852: 8d 11 d0    ..P
    rts                                                               ; f855: 60          .

; &f856 referenced 1 time by &e97b
.sub_cf856
    lda load_verify_flag                                              ; f856: a5 93       ..
    bne cf85b                                                         ; f858: d0 01       P.
    rts                                                               ; f85a: 60          .

; &f85b referenced 1 time by &f858
.cf85b
    pla                                                               ; f85b: 68          .
    pla                                                               ; f85c: 68          .
    jmp cff43                                                         ; f85d: 4c 43 ff    lc.

    equb &a9, &80, &2c, &a9, 0, &85                                   ; f860: a9 80 2c... ..,
    equb &c7, &4c, &25 ; petscii "Gl%"                                ; f866: c7 4c 25    Gl%
    equb &ee                                                          ; f869: ee          .

; &f86a referenced 2 times by &e6e5, &efce
.sub_cf86a
    tya                                                               ; f86a: 98          .
    adc io_end_ptr                                                    ; f86b: 65 ae       ..
    sta io_end_ptr                                                    ; f86d: 85 ae       ..
    bcc return_14                                                     ; f86f: 90 02       ..
    inc io_end_ptr+1                                                  ; f871: e6 af       ..
; &f873 referenced 1 time by &f86f
.return_14
    rts                                                               ; f873: 60          .

; &f874 referenced 1 time by &fdfd
.cf874
    clc                                                               ; f874: 18          .
    adc #&80                                                          ; f875: 69 80       ..
    bcc cf87b                                                         ; f877: 90 02       ..
    adc #&bf                                                          ; f879: 69 bf       .. ; Carry is set, so adding 192
; &f87b referenced 1 time by &f877
.cf87b
    jmp cedf3                                                         ; f87b: 4c f3 ed    l..

; &f87e referenced 1 time by &f13e
.cf87e
    lda input_device                                                  ; f87e: a5 99       ..
    bne cf885                                                         ; f880: d0 03       P.
    jmp cf142                                                         ; f882: 4c 42 f1    lb.

; &f885 referenced 1 time by &f880
.cf885
    jmp cf15e                                                         ; f885: 4c 5e f1    l..

; &f888 referenced 1 time by &ffa5
.cf888
    lda io_status                                                     ; f888: a5 90       ..
    beq cf890                                                         ; f88a: f0 04       ..
    clc                                                               ; f88c: 18          .
    lda #&0d                                                          ; f88d: a9 0d       ..
    rts                                                               ; f88f: 60          .

; &f890 referenced 1 time by &f88a
.cf890
    jmp cef21                                                         ; f890: 4c 21 ef    l!.

    equb &a9, 0, &2c, &a9, &80, &8d, &91, 2, &4c, &25, &ee            ; f893: a9 00 2c... ..,

; &f89e referenced 3 times by &f64e, &fab0, &fde9
.cf89e
    lda cia2_port_a                                                   ; f89e: ad 00 dd    ...
    ora #&10                                                          ; f8a1: 09 10       ..
    and #&d7 ; 'W'                                                    ; f8a3: 29 d7       )W
    sta cia2_port_a                                                   ; f8a5: 8d 00 dd    ...
    rts                                                               ; f8a8: 60          .

; &f8a9 referenced 5 times by &f3f7, &f4cd, &f9b6, &fd09, &ff61
.sub_cf8a9
    pha                                                               ; f8a9: 48          h
    lda serial_char_buffered_flag                                     ; f8aa: a5 94       ..
    beq cf8b2                                                         ; f8ac: f0 04       ..
    sec                                                               ; f8ae: 38          8
    jsr sub_cf0d5                                                     ; f8af: 20 d5 f0     U.
; &f8b2 referenced 1 time by &f8ac
.cf8b2
    pla                                                               ; f8b2: 68          .
    rts                                                               ; f8b3: 60          .

; &f8b4 referenced 3 times by &e97e, &e9bb, &e9f2
.sub_cf8b4
    lda #0                                                            ; f8b4: a9 00       ..
    ldy #&1c                                                          ; f8b6: a0 1c       ..
; &f8b8 referenced 1 time by &f8bc
.loop_cf8b8
    sta sid_voice1_frequency_low,y                                    ; f8b8: 99 00 d4    ..T
    dey                                                               ; f8bb: 88          .
    bpl loop_cf8b8                                                    ; f8bc: 10 fa       ..
    rts                                                               ; f8be: 60          .

; &f8bf referenced 2 times by &f171, &f2d4
.sub_cf8bf
    jsr sub_cf833                                                     ; f8bf: 20 33 f8     3.
    lda vic_sprite_enable                                             ; f8c2: ad 15 d0    ..P
    ldx #0                                                            ; f8c5: a2 00       ..
    stx vic_sprite_enable                                             ; f8c7: 8e 15 d0    ..P
    rts                                                               ; f8ca: 60          .

; &f8cb referenced 1 time by &e815
.lf8cb
    equb &fd, &bf, &7f, &7f                                           ; f8cb: fd bf 7f... ...
; &f8cf referenced 1 time by &e81b
.lf8cf
    equb &80, &10, &20, 4                                             ; f8cf: 80 10 20... ..
; &f8d3 referenced 1 time by &e826
.lf8d3
    equb 1, 1, 2, 4                                                   ; f8d3: 01 01 02... ...

; &f8d7 referenced 1 time by &ffb7
.cf8d7
    lda device_number                                                 ; f8d7: a5 ba       ..
    cmp #2                                                            ; f8d9: c9 02       I.
    bne cf8e0                                                         ; f8db: d0 03       P.
    lda #&ff                                                          ; f8dd: a9 ff       ..
    rts                                                               ; f8df: 60          .

; &f8e0 referenced 1 time by &f8db
.cf8e0
    lda io_status                                                     ; f8e0: a5 90       ..
    rts                                                               ; f8e2: 60          .

; &f8e3 referenced 2 times by &ea40, &fb76
.sub_cf8e3
    lda cpu_port                                                      ; f8e3: a5 01       ..
    ora #&20 ; ' '                                                    ; f8e5: 09 20       .
    bne cf8ed                                                         ; f8e7: d0 04       P. ; ALWAYS branch

; &f8e9 referenced 2 times by &ea4d, &fb8e
.cf8e9
    lda cpu_port                                                      ; f8e9: a5 01       ..
    and #&df                                                          ; f8eb: 29 df       ).
; &f8ed referenced 1 time by &f8e7
.cf8ed
    sta cpu_port                                                      ; f8ed: 85 01       ..
    rts                                                               ; f8ef: 60          .

; &f8f0 referenced 4 times by &eb9b, &eda6, &edcd, &edf4
.sub_cf8f0
    ldy cursor_column                                                 ; f8f0: a4 d3       .S
    cpy #&28 ; '('                                                    ; f8f2: c0 28       .(
    bcc cf8fa                                                         ; f8f4: 90 04       ..
    tya                                                               ; f8f6: 98          .
    sbc #&28 ; '('                                                    ; f8f7: e9 28       .(
    tay                                                               ; f8f9: a8          .
; &f8fa referenced 1 time by &f8f4
.cf8fa
    cpy #0                                                            ; f8fa: c0 00       ..
    rts                                                               ; f8fc: 60          .

; &f8fd referenced 2 times by &ee03, &f67a
.sub_cf8fd
    cmp #&22 ; '"'                                                    ; f8fd: c9 22       I"
    bne return_15                                                     ; f8ff: d0 08       P.
    lda quote_mode_flag                                               ; f901: a5 d4       .T
    eor #&80                                                          ; f903: 49 80       i.
    sta quote_mode_flag                                               ; f905: 85 d4       .T
    lda #&22 ; '"'                                                    ; f907: a9 22       ."
; &f909 referenced 1 time by &f8ff
.return_15
    rts                                                               ; f909: 60          .

; &f90a referenced 2 times by &f4c2, &f5f2
.sub_cf90a
    cmp #8                                                            ; f90a: c9 08       I.
    bcc cf915                                                         ; f90c: 90 07       ..
; &f90e referenced 10 times by &f15e, &f1da, &f222, &f264, &f299, &f37e, &f3fa, &f4d0, &f9cc, &f9d6
.sub_cf90e
    cmp #4                                                            ; f90e: c9 04       I.
    bcc cf915                                                         ; f910: 90 03       ..
    cmp #&1f                                                          ; f912: c9 1f       I.
    rts                                                               ; f914: 60          .

; &f915 referenced 2 times by &f90c, &f910
.cf915
    sec                                                               ; f915: 38          8
    rts                                                               ; f916: 60          .

; &f917 referenced 1 time by &f1df
.cf917
    lda last_char_printed                                             ; f917: a5 d7       .W ; A=byte to send
    jsr ciout                                                         ; f919: 20 a8 ff     .. ; Send a byte over the serial bus
    bcs cf921                                                         ; f91c: b0 03       ..
    jmp cf1f1                                                         ; f91e: 4c f1 f1    l..

; &f921 referenced 1 time by &f91c
.cf921
    jmp cf1e2                                                         ; f921: 4c e2 f1    l..

; &f924 referenced 2 times by &fcec, &fe4c
.sub_cf924
    ldx #5                                                            ; f924: a2 05       ..
; &f926 referenced 1 time by &f92f
.loop_cf926
    lda l8003,x                                                       ; f926: bd 03 80    ...
    cmp lf7b6,x                                                       ; f929: dd b6 f7    ...
    bne return_16                                                     ; f92c: d0 03       P.
    dex                                                               ; f92e: ca          J
    bne loop_cf926                                                    ; f92f: d0 f5       P.
; &f931 referenced 1 time by &f92c
.return_16
    rts                                                               ; f931: 60          .

; &f932 referenced 3 times by &f215, &f257, &f291
.sub_cf932
    ldy open_files_count                                              ; f932: a4 98       ..
; &f934 referenced 1 time by &f93a
.loop_cf934
    dey                                                               ; f934: 88          .
    bmi cf93e                                                         ; f935: 30 07       0.
    cmp logical_file_table,y                                          ; f937: d9 59 02    Yy.
    bne loop_cf934                                                    ; f93a: d0 f8       P.
    clc                                                               ; f93c: 18          .
    rts                                                               ; f93d: 60          .

; &f93e referenced 1 time by &f935
.cf93e
    sec                                                               ; f93e: 38          8
    rts                                                               ; f93f: 60          .

; &f940 referenced 6 times by &e531, &e53e, &f22e, &f270, &fc59, &fc66
.cf940
    ; pull A,Y from the stack
    pla                                                               ; f940: 68          .
    tay                                                               ; f941: a8          .
    pla                                                               ; f942: 68          .
    jsr sub_cf98b                                                     ; f943: 20 8b f9     ..
    jmp cfc7b                                                         ; f946: 4c 7b fc    l..

; &f949 referenced 2 times by &f21a, &f25c
.cf949
    ; pull A,Y from the stack
    pla                                                               ; f949: 68          .
    tay                                                               ; f94a: a8          .
    pla                                                               ; f94b: 68          .
    jmp lfc75                                                         ; f94c: 4c 75 fc    l..

; &f94f referenced 1 time by &f2dd
.lf94f
    equb   0, &80, &20, &a0, &40, &c0, &60, &e0, &10, &90, &30, &b0   ; f94f: 00 80 20... ..
    equb &50, &d0, &70, &f0                                           ; f95b: 50 d0 70... pP.

; &f95f referenced 1 time by &ee25
.sub_cf95f
    lda cursor_blink_disable                                          ; f95f: a5 cc       .L
    bne return_17                                                     ; f961: d0 0c       P.
    lda cursor_blink_phase                                            ; f963: a5 cf       .O
    bne return_17                                                     ; f965: d0 08       P.
    lda #1                                                            ; f967: a9 01       ..
    sta cursor_blink_timer                                            ; f969: 85 cd       .M
    lda #0                                                            ; f96b: a9 00       ..
    sta cursor_blink_phase                                            ; f96d: 85 cf       .O
; &f96f referenced 2 times by &f961, &f965
.return_17
    rts                                                               ; f96f: 60          .

; &f970 referenced 1 time by &fac5
.sub_cf970
    ldx #&12                                                          ; f970: a2 12       ..
; &f972 referenced 3 times by &e699, &e69d, &e8f5
.sub_cf972
    lda vic_raster_line                                               ; f972: ad 12 d0    ..P
; &f975 referenced 2 times by &f978, &f97e
.cf975
    cmp vic_raster_line                                               ; f975: cd 12 d0    M.P
    beq cf975                                                         ; f978: f0 fb       ..
    lda vic_raster_line                                               ; f97a: ad 12 d0    ..P
    dex                                                               ; f97d: ca          J
    bne cf975                                                         ; f97e: d0 f5       P.
; &f980 referenced 1 time by &ef94
.return_12
    rts                                                               ; f980: 60          .

; &f981 referenced 6 times by &f211, &f253, &f34a, &f4af, &f5ed, &faa3
.cf981
    lda #0                                                            ; f981: a9 00       ..
    beq cf98f                                                         ; f983: f0 0a       .. ; ALWAYS branch

; &f985 referenced 3 times by &ef64, &f1b3, &fa81
.sub_cf985
    lda io_status                                                     ; f985: a5 90       ..
    ora #&40 ; '@'                                                    ; f987: 09 40       .@
    bne cf98f                                                         ; f989: d0 04       P. ; ALWAYS branch

; &f98b referenced 3 times by &f943, &ff43, &ff49
.sub_cf98b
    lda io_status                                                     ; f98b: a5 90       ..
    ora #&80                                                          ; f98d: 09 80       ..
; &f98f referenced 2 times by &f983, &f989
.cf98f
    sta io_status                                                     ; f98f: 85 90       ..
    rts                                                               ; f991: 60          .

    equb &ad, &18, &d0, &29, 2, &8d, &18                              ; f992: ad 18 d0... ..P
    equb &d0, &4c, &25 ; petscii "Pl%"                                ; f999: d0 4c 25    Pl%
    equb &ee, &ad, &18, &d0, 9, 2, &d0, &f3                           ; f99c: ee ad 18... ...

; &f9a4 referenced 1 time by &ee1f
.cf9a4
    ldy cursor_row                                                    ; f9a4: a4 d6       .V
    cpy #&18                                                          ; f9a6: c0 18       ..
    bne cf9ad                                                         ; f9a8: d0 03       P.
    jsr ce8ea                                                         ; f9aa: 20 ea e8     ..
; &f9ad referenced 1 time by &f9a8
.cf9ad
    inc cursor_row                                                    ; f9ad: e6 d6       .V
    lda #0                                                            ; f9af: a9 00       ..
    sta cursor_column                                                 ; f9b1: 85 d3       .S
    jmp cee22                                                         ; f9b3: 4c 22 ee    l".

; &f9b6 referenced 3 times by &f9d1, &fa1f, &ffab
.cf9b6
    jsr sub_cf8a9                                                     ; f9b6: 20 a9 f8     ..
    lda #&ff                                                          ; f9b9: a9 ff       ..
    sta io_temp_1                                                     ; f9bb: 85 a3       ..
    lda #&5f                                                          ; f9bd: a9 5f       ..
; &f9bf referenced 1 time by &f38a
.cf9bf
    sta io_temp_2                                                     ; f9bf: 85 a4       ..
    jsr cfabe                                                         ; f9c1: 20 be fa     ..
    bcs return_18                                                     ; f9c4: b0 03       ..
    jmp cfb91                                                         ; f9c6: 4c 91 fb    l..

; &f9c9 referenced 1 time by &f9c4
.return_18
    rts                                                               ; f9c9: 60          .

; &f9ca referenced 1 time by &f333
.sub_cf9ca
    lda input_device                                                  ; f9ca: a5 99       ..
    jsr sub_cf90e                                                     ; f9cc: 20 0e f9     ..
    bcs cf9d4                                                         ; f9cf: b0 03       ..
    jsr cf9b6                                                         ; f9d1: 20 b6 f9     ..
; &f9d4 referenced 1 time by &f9cf
.cf9d4
    lda output_device                                                 ; f9d4: a5 9a       ..
    jsr sub_cf90e                                                     ; f9d6: 20 0e f9     ..
    bcs return_19                                                     ; f9d9: b0 03       ..
    jmp cfd09                                                         ; f9db: 4c 09 fd    l..

; &f9de referenced 1 time by &f9d9
.return_19
    rts                                                               ; f9de: 60          .

; &f9df referenced 2 times by &e90c, &f425
.sub_cf9df
    ; pull Y,X from the stack
    pla                                                               ; f9df: 68          .
    tax                                                               ; f9e0: aa          .
    pla                                                               ; f9e1: 68          .
    tay                                                               ; f9e2: a8          .
    lda io_address_ptr                                                ; f9e3: a5 ac       ..
    pha                                                               ; f9e5: 48          h
    lda io_end_ptr                                                    ; f9e6: a5 ae       ..
    pha                                                               ; f9e8: 48          h
    lda io_address_ptr+1                                              ; f9e9: a5 ad       ..
    pha                                                               ; f9eb: 48          h
    lda io_end_ptr+1                                                  ; f9ec: a5 af       ..
    ; push A,Y,X onto the stack
    pha                                                               ; f9ee: 48          h
; &f9ef referenced 1 time by &fe44
.cf9ef
    tya                                                               ; f9ef: 98          .
    pha                                                               ; f9f0: 48          h
    txa                                                               ; f9f1: 8a          .
    pha                                                               ; f9f2: 48          h
    rts                                                               ; f9f3: 60          .

; &f9f4 referenced 7 times by &ee3a, &ee57, &ee5e, &eed5, &eee4, &eeeb, &f9f9
.cf9f4
    jsr cfd91                                                         ; f9f4: 20 91 fd     ..
    cmp tape_sync_number                                              ; f9f7: c5 96       E.
    bcs cf9f4                                                         ; f9f9: b0 f9       ..
; &f9fb referenced 1 time by &fa07
.loop_cf9fb
    jmp cfd91                                                         ; f9fb: 4c 91 fd    l..

; &f9fe referenced 3 times by &ea1a, &fa01, &fa05
.cf9fe
    jsr cfd91                                                         ; f9fe: 20 91 fd     ..
    bcs cf9fe                                                         ; fa01: b0 fb       ..
    cmp tape_sync_number                                              ; fa03: c5 96       E.
    bcs cf9fe                                                         ; fa05: b0 f7       ..
    bcc loop_cf9fb                                                    ; fa07: 90 f2       .. ; ALWAYS branch

; &fa09 referenced 1 time by &ffa8
.cfa09
    pha                                                               ; fa09: 48          h
    lda serial_char_buffered_flag                                     ; fa0a: a5 94       ..
    bne cfa15                                                         ; fa0c: d0 07       P.
    inc serial_char_buffered_flag                                     ; fa0e: e6 94       ..
    clc                                                               ; fa10: 18          .
; &fa11 referenced 1 time by &fa1b
.loop_cfa11
    pla                                                               ; fa11: 68          .
    sta serial_buffered_char                                          ; fa12: 85 95       ..
    rts                                                               ; fa14: 60          .

; &fa15 referenced 1 time by &fa0c
.cfa15
    clc                                                               ; fa15: 18          .
    jsr sub_cf0c9                                                     ; fa16: 20 c9 f0     I.
    inc serial_char_buffered_flag                                     ; fa19: e6 94       ..
    jmp loop_cfa11                                                    ; fa1b: 4c 11 fa    l..

; &fa1e referenced 5 times by &e740, &e749, &e7df, &e7f7, &ff6b
.sub_cfa1e
    tax                                                               ; fa1e: aa          .
    jsr cf9b6                                                         ; fa1f: 20 b6 f9     ..
    txa                                                               ; fa22: 8a          .
    jsr cf4cd                                                         ; fa23: 20 cd f4     M.
    lda #&e0                                                          ; fa26: a9 e0       ..
    sta io_temp_2                                                     ; fa28: 85 a4       ..
    jsr cfabe                                                         ; fa2a: 20 be fa     ..
    jsr cf647                                                         ; fa2d: 20 47 f6     g.
    jsr cfd09                                                         ; fa30: 20 09 fd     ..
    rts                                                               ; fa33: 60          .

    ; push X,Y onto the stack
    txa                                                               ; fa34: 8a          .
    pha                                                               ; fa35: 48          h
    tya                                                               ; fa36: 98          .
    pha                                                               ; fa37: 48          h
    php                                                               ; fa38: 08          .
    sei                                                               ; fa39: 78          .
    jsr sub_ceec5                                                     ; fa3a: 20 c5 ee     E.
    jsr sub_cee9f                                                     ; fa3d: 20 9f ee     ..
    jsr ce717                                                         ; fa40: 20 17 e7     ..
    jsr sub_cee84                                                     ; fa43: 20 84 ee     ..
    plp                                                               ; fa46: 28          (
    jmp cfaa6                                                         ; fa47: 4c a6 fa    l..

; &fa4a referenced 1 time by &f6be
.sub_cfa4a
    ldy cursor_row                                                    ; fa4a: a4 d6       .V
    cpy #&18                                                          ; fa4c: c0 18       ..
    bcs cfa5d                                                         ; fa4e: b0 0d       ..
    lda screen_line_links,y                                           ; fa50: b9 d9 00    .Y.
    bpl cfa5d                                                         ; fa53: 10 08       ..
    lda screen_line_links+1,y                                         ; fa55: b9 da 00    .Z.
    bmi cfa5d                                                         ; fa58: 30 03       0.
    ldy #&4f ; 'o'                                                    ; fa5a: a0 4f       .o
    rts                                                               ; fa5c: 60          .

; &fa5d referenced 3 times by &fa4e, &fa53, &fa58
.cfa5d
    ldy #&27 ; '''                                                    ; fa5d: a0 27       .'
    rts                                                               ; fa5f: 60          .

; &fa60 referenced 1 time by &e981
.sub_cfa60
    ldx #3                                                            ; fa60: a2 03       ..
    stx cia2_timer_a_low                                              ; fa62: 8e 04 dd    ...
    ldx #0                                                            ; fa65: a2 00       ..
    stx cia2_timer_a_high                                             ; fa67: 8e 05 dd    ...
    stx cia2_timer_b_high                                             ; fa6a: 8e 07 dd    ...
    dex                                                               ; fa6d: ca          J  ; X=&ff
    stx cia2_timer_b_low                                              ; fa6e: 8e 06 dd    ...
    ldx #&11                                                          ; fa71: a2 11       ..
    stx cia2_control_a                                                ; fa73: 8e 0e dd    ...
    rts                                                               ; fa76: 60          .

; &fa77 referenced 1 time by &ef38
.sub_cfa77
    ldx #&13                                                          ; fa77: a2 13       ..
; &fa79 referenced 1 time by &fa7f
.loop_cfa79
    bit cia2_port_a                                                   ; fa79: 2c 00 dd    ,..
    bvc return_20                                                     ; fa7c: 50 0f       p.
    dex                                                               ; fa7e: ca          J
    bne loop_cfa79                                                    ; fa7f: d0 f8       P.
; &fa81 referenced 1 time by &e6dc
.sub_cfa81
    jsr sub_cf985                                                     ; fa81: 20 85 f9     ..
    jsr sub_ceeac                                                     ; fa84: 20 ac ee     ..
    jsr sub_cf7dd                                                     ; fa87: 20 dd f7     ..
    jsr sub_cee9f                                                     ; fa8a: 20 9f ee     ..
; &fa8d referenced 1 time by &fa7c
.return_20
    rts                                                               ; fa8d: 60          .

; &fa8e referenced 1 time by &f32f
.cfa8e
    tya                                                               ; fa8e: 98          .
    pha                                                               ; fa8f: 48          h
; &fa90 referenced 1 time by &fa9b
.loop_cfa90
    ldy open_files_count                                              ; fa90: a4 98       ..
    beq cfa9e                                                         ; fa92: f0 0a       ..
    dey                                                               ; fa94: 88          .
    lda logical_file_table,y                                          ; fa95: b9 59 02    .y. ; A=logical file number
    jsr close                                                         ; fa98: 20 c3 ff     C. ; Close a logical file
    jmp loop_cfa90                                                    ; fa9b: 4c 90 fa    l..

; &fa9e referenced 1 time by &fa92
.cfa9e
    pla                                                               ; fa9e: 68          .
    tay                                                               ; fa9f: a8          .
    jsr default_clrchn_handler                                        ; faa0: 20 33 f3     3.
    jmp cf981                                                         ; faa3: 4c 81 f9    l..

; &faa6 referenced 5 times by &f13b, &f321, &f654, &fa47, &fbaa
.cfaa6
    lda #0                                                            ; faa6: a9 00       ..
    sta serial_char_buffered_flag                                     ; faa8: 85 94       ..
    ; pull X,Y from the stack
    pla                                                               ; faaa: 68          .
    tay                                                               ; faab: a8          .
    pla                                                               ; faac: 68          .
    tax                                                               ; faad: aa          .
    clc                                                               ; faae: 18          .
    rts                                                               ; faaf: 60          .

; &fab0 referenced 3 times by &f138, &facd, &fba6
.cfab0
    jsr cf89e                                                         ; fab0: 20 9e f8     ..
    lda #0                                                            ; fab3: a9 00       ..
    sta serial_char_buffered_flag                                     ; fab5: 85 94       ..
    ; pull X,Y from the stack
    pla                                                               ; fab7: 68          .
    tay                                                               ; fab8: a8          .
    pla                                                               ; fab9: 68          .
    tax                                                               ; faba: aa          .
    jmp cfc7b                                                         ; fabb: 4c 7b fc    l..

; &fabe referenced 9 times by &e57e, &e58b, &e777, &f080, &f0bc, &f40a, &f9c1, &fa2a, &ff75
.cfabe
    ; push X,Y onto the stack
    txa                                                               ; fabe: 8a          .
    pha                                                               ; fabf: 48          h
    tya                                                               ; fac0: 98          .
    pha                                                               ; fac1: 48          h
    jsr sub_cee7c                                                     ; fac2: 20 7c ee     ..
    jsr sub_cf970                                                     ; fac5: 20 70 f9     ..
    lda cia2_port_a                                                   ; fac8: ad 00 dd    ...
    bpl cfad0                                                         ; facb: 10 03       ..
    jmp cfab0                                                         ; facd: 4c b0 fa    l..

; &fad0 referenced 1 time by &facb
.cfad0
    jsr sub_cee9f                                                     ; fad0: 20 9f ee     ..
    clc                                                               ; fad3: 18          .
    jmp cf0dc                                                         ; fad4: 4c dc f0    l..

; &fad7 referenced 1 time by &f10c
.sub_cfad7
    ldy #&25 ; '%'                                                    ; fad7: a0 25       .%
; &fad9 referenced 1 time by &fadf
.loop_cfad9
    lda cia2_port_a                                                   ; fad9: ad 00 dd    ...
    bpl cfae9                                                         ; fadc: 10 0b       ..
    dey                                                               ; fade: 88          .
    bne loop_cfad9                                                    ; fadf: d0 f8       P.
    lda io_temp_1                                                     ; fae1: a5 a3       ..
    bpl return_21                                                     ; fae3: 10 0b       ..
    lda #0                                                            ; fae5: a9 00       ..
    beq cfaee                                                         ; fae7: f0 05       .. ; ALWAYS branch

; &fae9 referenced 1 time by &fadc
.cfae9
    jsr cf7d1                                                         ; fae9: 20 d1 f7     Q.
    lda #1                                                            ; faec: a9 01       ..
; &faee referenced 1 time by &fae7
.cfaee
    sta io_temp_1                                                     ; faee: 85 a3       ..
; &faf0 referenced 1 time by &fae3
.return_21
    rts                                                               ; faf0: 60          .

; &faf1 referenced 4 times by &ff05, &ff0a, &ff0f, &ff14
.cfaf1
    sed                                                               ; faf1: f8          .
    pha                                                               ; faf2: 48          h
    lsr a                                                             ; faf3: 4a          j
    lsr a                                                             ; faf4: 4a          j
    lsr a                                                             ; faf5: 4a          j
    lsr a                                                             ; faf6: 4a          j
    cmp #&0a                                                          ; faf7: c9 0a       I.
    adc #&30 ; '0'                                                    ; faf9: 69 30       .0 ; A=character to output
    cld                                                               ; fafb: d8          X
    jsr chrout                                                        ; fafc: 20 d2 ff     R. ; Output a character
    sed                                                               ; faff: f8          .
    pla                                                               ; fb00: 68          .
    and #&0f                                                          ; fb01: 29 0f       ).
    cmp #&0a                                                          ; fb03: c9 0a       I.
    adc #&30 ; '0'                                                    ; fb05: 69 30       .0 ; A=character to output
    cld                                                               ; fb07: d8          X
    jmp chrout                                                        ; fb08: 4c d2 ff    lR. ; Output a character

; &fb0b referenced 3 times by &ecef, &ed09, &fb1f
.cfb0b
    ldy #0                                                            ; fb0b: a0 00       ..
; &fb0d referenced 1 time by &fb19
.loop_cfb0d
    jsr sub_cfb25                                                     ; fb0d: 20 25 fb     %.
    rol rs232_input_bits                                              ; fb10: 26 a7       &.
    lda rs232_input_bits                                              ; fb12: a5 a7       ..
    cmp #&ff                                                          ; fb14: c9 ff       I.
    bne cfb1d                                                         ; fb16: d0 05       P.
    iny                                                               ; fb18: c8          H
    bpl loop_cfb0d                                                    ; fb19: 10 f2       ..
    bmi cfb23                                                         ; fb1b: 30 06       0. ; ALWAYS branch

; &fb1d referenced 1 time by &fb16
.cfb1d
    cmp #2                                                            ; fb1d: c9 02       I.
    bne cfb0b                                                         ; fb1f: d0 ea       P.
    clc                                                               ; fb21: 18          .
    rts                                                               ; fb22: 60          .

; &fb23 referenced 1 time by &fb1b
.cfb23
    sec                                                               ; fb23: 38          8
    rts                                                               ; fb24: 60          .

; &fb25 referenced 2 times by &e960, &fb0d
.sub_cfb25
    jsr cfd91                                                         ; fb25: 20 91 fd     ..
    bcs cfb36                                                         ; fb28: b0 0c       ..
    lda #1                                                            ; fb2a: a9 01       ..
    sta sid_volume_filter_mode                                        ; fb2c: 8d 18 d4    ..T
    lda #colour_blue                                                  ; fb2f: a9 06       ..
    sta vic_border_colour                                             ; fb31: 8d 20 d0    . P
    sec                                                               ; fb34: 38          8
    rts                                                               ; fb35: 60          .

; &fb36 referenced 1 time by &fb28
.cfb36
    lda #colour_black                                                 ; fb36: a9 00       ..
    sta sid_volume_filter_mode                                        ; fb38: 8d 18 d4    ..T
    sta vic_border_colour                                             ; fb3b: 8d 20 d0    . P
    clc                                                               ; fb3e: 18          .
    rts                                                               ; fb3f: 60          .

; &fb40 referenced 3 times by &e767, &f070, &fbc3
.sub_cfb40
    ldy #0                                                            ; fb40: a0 00       ..
; &fb42 referenced 1 time by &fb58
.loop_cfb42
    cpy filename_length                                               ; fb42: c4 b7       D.
    bne cfb49                                                         ; fb44: d0 03       P.
    jmp cfd09                                                         ; fb46: 4c 09 fd    l..

; &fb49 referenced 1 time by &fb44
.cfb49
    jsr sub_cfca0                                                     ; fb49: 20 a0 fc     ..
    iny                                                               ; fb4c: c8          H
    cpy filename_length                                               ; fb4d: c4 b7       D.
    clc                                                               ; fb4f: 18          .
    bne cfb53                                                         ; fb50: d0 01       P.
    sec                                                               ; fb52: 38          8
; &fb53 referenced 1 time by &fb50
.cfb53
    sta io_temp_2                                                     ; fb53: 85 a4       ..
    jsr sub_cf0c9                                                     ; fb55: 20 c9 f0     I.
    jmp loop_cfb42                                                    ; fb58: 4c 42 fb    lb.

    equb &a9,   0, &85, &d4, &85, &d8, &85, &c7, &a4, &d6, &c0, &18   ; fb5b: a9 00 85... ...
    equb &f0, &0a, &b9, &da,   0, &30,   5, &e6, &d6, &20, &ee, &eb   ; fb67: f0 0a b9... ...
    equb &4c, &a4, &f9                                                ; fb73: 4c a4 f9    l..

; &fb76 referenced 3 times by &e5f9, &e6a7, &e6b0
.sub_cfb76
    jsr sub_cf8e3                                                     ; fb76: 20 e3 f8     ..
    lda tape_byte_received_flag                                       ; fb79: a5 9c       ..
    sta vic_border_colour                                             ; fb7b: 8d 20 d0    . P
    jmp cf84d                                                         ; fb7e: 4c 4d f8    lm.

; &fb81 referenced 3 times by &e5f6, &e658, &e660
.cfb81
    sei                                                               ; fb81: 78          .
    lda #0                                                            ; fb82: a9 00       ..
    sta keyboard_buffer_length                                        ; fb84: 85 c6       .F
    lda vic_border_colour                                             ; fb86: ad 20 d0    . P
    sta tape_byte_received_flag                                       ; fb89: 85 9c       ..
    jsr sub_cf1fb                                                     ; fb8b: 20 fb f1     ..
    jmp cf8e9                                                         ; fb8e: 4c e9 f8    l..

; &fb91 referenced 2 times by &e77f, &f9c6
.cfb91
    ; push X,Y onto the stack
    txa                                                               ; fb91: 8a          .
    pha                                                               ; fb92: 48          h
    tya                                                               ; fb93: 98          .
    pha                                                               ; fb94: 48          h
    php                                                               ; fb95: 08          .
    sei                                                               ; fb96: 78          .
    jsr sub_ceeb8                                                     ; fb97: 20 b8 ee     ..
    ldx #&ff                                                          ; fb9a: a2 ff       ..
; &fb9c referenced 1 time by &fba3
.loop_cfb9c
    lda cia2_port_a                                                   ; fb9c: ad 00 dd    ...
    rol a                                                             ; fb9f: 2a          *
    bpl cfba9                                                         ; fba0: 10 07       ..
    dex                                                               ; fba2: ca          J
    bne loop_cfb9c                                                    ; fba3: d0 f7       P.
    plp                                                               ; fba5: 28          (
    jmp cfab0                                                         ; fba6: 4c b0 fa    l..

; &fba9 referenced 1 time by &fba0
.cfba9
    plp                                                               ; fba9: 28          (
    jmp cfaa6                                                         ; fbaa: 4c a6 fa    l..

; &fbad referenced 1 time by &f383
.cfbad
    ldy filename_length                                               ; fbad: a4 b7       ..
    beq cfbc6                                                         ; fbaf: f0 15       ..
    jsr cf4cd                                                         ; fbb1: 20 cd f4     M.
    bcc cfbb9                                                         ; fbb4: 90 03       ..
    jmp cfc7b                                                         ; fbb6: 4c 7b fc    l..

; &fbb9 referenced 1 time by &fbb4
.cfbb9
    lda secondary_address                                             ; fbb9: a5 b9       ..
    jsr sub_ce572                                                     ; fbbb: 20 72 e5     ..
    bcc cfbc3                                                         ; fbbe: 90 03       ..
    jmp cfc7b                                                         ; fbc0: 4c 7b fc    l..

; &fbc3 referenced 1 time by &fbbe
.cfbc3
    jsr sub_cfb40                                                     ; fbc3: 20 40 fb     @.
; &fbc6 referenced 1 time by &fbaf
.cfbc6
    jmp cf386                                                         ; fbc6: 4c 86 f3    l..

; &fbc9 referenced 2 times by &ec87, &ec99
.sub_cfbc9
    jsr cfd91                                                         ; fbc9: 20 91 fd     ..
    bcc cfbda                                                         ; fbcc: 90 0c       ..
    jsr cfd91                                                         ; fbce: 20 91 fd     ..
    bcs cfbe4                                                         ; fbd1: b0 11       ..
    lda #colour_black                                                 ; fbd3: a9 00       ..
; &fbd5 referenced 1 time by &fbe2
.loop_cfbd5
    sta vic_border_colour                                             ; fbd5: 8d 20 d0    . P
    clc                                                               ; fbd8: 18          .
    rts                                                               ; fbd9: 60          .

; &fbda referenced 1 time by &fbcc
.cfbda
    jsr cfd91                                                         ; fbda: 20 91 fd     ..
    bcc cfbe4                                                         ; fbdd: 90 05       ..
    clc                                                               ; fbdf: 18          .
    lda #6                                                            ; fbe0: a9 06       ..
    bne loop_cfbd5                                                    ; fbe2: d0 f1       P. ; ALWAYS branch

; &fbe4 referenced 2 times by &fbd1, &fbdd
.cfbe4
    sec                                                               ; fbe4: 38          8
    rts                                                               ; fbe5: 60          .

; &fbe6 referenced 1 time by &fd1a
.cfbe6
    sty load_address_temp+1                                           ; fbe6: 84 c4       .D
    stx load_address_temp                                             ; fbe8: 86 c3       .C
    lda #0                                                            ; fbea: a9 00       ..
    sta nmi_vector+1                                                  ; fbec: 8d 19 03    ... ; Set the high byte of the NMI vector to &00
    ldy #&1f                                                          ; fbef: a0 1f       ..
    bcc cfbfa                                                         ; fbf1: 90 07       ..
    lda irq_vector,y                                                  ; fbf3: b9 14 03    ...
    sta (load_address_temp),y                                         ; fbf6: 91 c3       .C
    bcs cfbff                                                         ; fbf8: b0 05       .. ; ALWAYS branch

; &fbfa referenced 2 times by &fbf1, &fc00
.cfbfa
    ; Copy Y+1 bytes of memory to irq_vector
    lda (load_address_temp),y                                         ; fbfa: b1 c3       .C
    sta irq_vector,y                                                  ; fbfc: 99 14 03    ...
; &fbff referenced 1 time by &fbf8
.cfbff
    dey                                                               ; fbff: 88          .
    bpl cfbfa                                                         ; fc00: 10 f8       ..
    rts                                                               ; fc02: 60          .

; &fc03 referenced 1 time by &f6df
.sub_cfc03
    ldx basic_current_line+1                                          ; fc03: a6 3a       .:
    inx                                                               ; fc05: e8          .
    bne cfc12                                                         ; fc06: d0 0a       P.
    ldx #6                                                            ; fc08: a2 06       ..
; &fc0a referenced 1 time by &fc10
.loop_cfc0a
    cmp lebc1,x                                                       ; fc0a: dd c1 eb    .A.
    beq cfc14                                                         ; fc0d: f0 05       ..
    dex                                                               ; fc0f: ca          J
    bpl loop_cfc0a                                                    ; fc10: 10 f8       ..
; &fc12 referenced 1 time by &fc06
.cfc12
    sec                                                               ; fc12: 38          8
    rts                                                               ; fc13: 60          .

; &fc14 referenced 1 time by &fc0d
.cfc14
    lda lebe7,x                                                       ; fc14: bd e7 eb    ...
    tax                                                               ; fc17: aa          .
; &fc18 referenced 1 time by &fc21
.loop_cfc18
    lda lebc8,x                                                       ; fc18: bd c8 eb    .H.
    beq cfc23                                                         ; fc1b: f0 06       ..
    jsr default_chrout_handler                                        ; fc1d: 20 ca f1     J.
    inx                                                               ; fc20: e8          .
    bne loop_cfc18                                                    ; fc21: d0 f5       P.
; &fc23 referenced 1 time by &fc1b
.cfc23
    clc                                                               ; fc23: 18          .
    rts                                                               ; fc24: 60          .

; &fc25 referenced 1 time by &e51b
.cfc25
    lda #&48 ; 'h'                                                    ; fc25: a9 48       .h
    sta keyboard_table_setup_vector                                   ; fc27: 8d 8f 02    ...
    lda #&eb                                                          ; fc2a: a9 eb       ..
    sta keyboard_table_setup_vector+1                                 ; fc2c: 8d 90 02    ...
    lda #1                                                            ; fc2f: a9 01       ..
    sta cursor_blink_timer                                            ; fc31: 85 cd       .M
    sta cursor_blink_disable                                          ; fc33: 85 cc       .L
    ldx #colour_white                                                 ; fc35: a2 01       ..
    stx text_colour                                                   ; fc37: 8e 86 02    ...
    ldx #&0a                                                          ; fc3a: a2 0a       ..
    stx keyboard_buffer_size                                          ; fc3c: 8e 89 02    ...
    ldx #0                                                            ; fc3f: a2 00       ..
    stx charset_switch_flag                                           ; fc41: 8e 91 02    ...
    jmp ce544                                                         ; fc44: 4c 44 e5    ld.

; &fc47 referenced 1 time by &f227
.cfc47
    lda logical_file_table,y                                          ; fc47: b9 59 02    .y.
    cmp #1                                                            ; fc4a: c9 01       I.
    bne cfc51                                                         ; fc4c: d0 03       P.
    jmp cf23b                                                         ; fc4e: 4c 3b f2    l;.

; &fc51 referenced 1 time by &fc4c
.cfc51
    lda device_number_table,y                                         ; fc51: b9 63 02    ...
    jsr cf3f7                                                         ; fc54: 20 f7 f3     ..
    bcc cfc5c                                                         ; fc57: 90 03       ..
    jmp cf940                                                         ; fc59: 4c 40 f9    l@.

; &fc5c referenced 1 time by &fc57
.cfc5c
    lda logical_file_table,y                                          ; fc5c: b9 59 02    .y.
    ora #&60                                                          ; fc5f: 09 60       ..
    jsr cf388                                                         ; fc61: 20 88 f3     ..
    bcc cfc69                                                         ; fc64: 90 03       ..
    jmp cf940                                                         ; fc66: 4c 40 f9    l@.

; &fc69 referenced 1 time by &fc64
.cfc69
    jmp cf231                                                         ; fc69: 4c 31 f2    l1.

; &fc6c referenced 2 times by &e5d1, &e74c
.cfc6c
    lda #0                                                            ; fc6c: a9 00       ..
; overlapping: bit l01a9                                              ; fc6e: 2c a9 01    ,..
    equb &2c                                                          ; fc6e: 2c          ,

; &fc6f referenced 1 time by &f367
.cfc6f
    lda #1                                                            ; fc6f: a9 01       ..
; overlapping: bit l02a9                                              ; fc71: 2c a9 02    ,..
    equb &2c                                                          ; fc71: 2c          ,

; &fc72 referenced 1 time by &f359
.cfc72
    lda #2                                                            ; fc72: a9 02       ..
.cfc74
lfc75 = cfc74+1
    bit tape_buffer+109                                               ; fc74: 2c a9 03    ,..
; overlapping: lda #3                                                 ; fc75: a9 03       ..
; &fc75 referenced 1 time by &f94c
.cfc77
lfc78 = cfc77+1
    bit screen_memory+169                                             ; fc77: 2c a9 04    ,..
; overlapping: lda #4                                                 ; fc78: a9 04       ..
; &fc78 referenced 1 time by &e7fa
; overlapping: bit screen_memory+425                                  ; fc7a: 2c a9 05    ,..
    equb &2c                                                          ; fc7a: 2c          ,

; &fc7b referenced 7 times by &f3ff, &f4d5, &f946, &fabb, &fbb6, &fbc0, &ff46
.cfc7b
    lda #5                                                            ; fc7b: a9 05       ..
.cfc7d
lfc7e = cfc7d+1
    bit screen_memory+681                                             ; fc7d: 2c a9 06    ,..
; overlapping: lda #6                                                 ; fc7e: a9 06       ..
; &fc7e referenced 2 times by &e577, &f23e
.cfc80
lfc81 = cfc80+1
    bit screen_memory+937                                             ; fc80: 2c a9 07    ,..
; overlapping: lda #7                                                 ; fc81: a9 07       ..
; &fc81 referenced 1 time by &f27e
.cfc83
lfc84 = cfc83+1
    bit l08a9                                                         ; fc83: 2c a9 08    ,..
; overlapping: lda #8                                                 ; fc84: a9 08       ..
; &fc84 referenced 2 times by &e753, &f05c
; overlapping: bit l09a9                                              ; fc86: 2c a9 09    ,..
    equb &2c                                                          ; fc86: 2c          ,

; &fc87 referenced 1 time by &ff4c
.cfc87
    lda #9                                                            ; fc87: a9 09       ..
.cfc89
lfc8a = cfc89+1
    bit l02a9                                                         ; fc89: 2c a9 02    ,..
; overlapping: lda #2                                                 ; fc8a: a9 02       ..
; &fc8a referenced 1 time by &f1c5
    bit cf0a9                                                         ; fc8c: 2c a9 f0    ,..
    sec                                                               ; fc8f: 38          8
    rts                                                               ; fc90: 60          .

; &fc91 referenced 1 time by &f09d
.sub_cfc91
    lda cpu_port                                                      ; fc91: a5 01       ..
    pha                                                               ; fc93: 48          h
    and #&fe                                                          ; fc94: 29 fe       ).
    sta cpu_port                                                      ; fc96: 85 01       ..
    lda (load_address_temp),y                                         ; fc98: b1 c3       .C
; &fc9a referenced 2 times by &fca9, &fcb5
.cfc9a
    tax                                                               ; fc9a: aa          .
    pla                                                               ; fc9b: 68          .
    sta cpu_port                                                      ; fc9c: 85 01       ..
    txa                                                               ; fc9e: 8a          .
    rts                                                               ; fc9f: 60          .

; &fca0 referenced 2 times by &fb49, &feda
.sub_cfca0
    lda cpu_port                                                      ; fca0: a5 01       ..
    pha                                                               ; fca2: 48          h
    and #&fe                                                          ; fca3: 29 fe       ).
    sta cpu_port                                                      ; fca5: 85 01       ..
    lda (filename_ptr),y                                              ; fca7: b1 bb       ..
    jmp cfc9a                                                         ; fca9: 4c 9a fc    l..

; &fcac referenced 1 time by &fea7
.sub_cfcac
    lda cpu_port                                                      ; fcac: a5 01       ..
    pha                                                               ; fcae: 48          h
    and #&fe                                                          ; fcaf: 29 fe       ).
    sta cpu_port                                                      ; fcb1: 85 01       ..
    lda (io_end_ptr),y                                                ; fcb3: b1 ae       ..
    jmp cfc9a                                                         ; fcb5: 4c 9a fc    l..

; &fcb8 referenced 2 times by &fcc0, &ff5e
.cfcb8
    lda vic_raster_line                                               ; fcb8: ad 12 d0    ..P
; &fcbb referenced 1 time by &fcbe
.loop_cfcbb
    cmp vic_raster_line                                               ; fcbb: cd 12 d0    M.P
    beq loop_cfcbb                                                    ; fcbe: f0 fb       ..
    bmi cfcb8                                                         ; fcc0: 30 f6       0.
    cmp #7                                                            ; fcc2: c9 07       I.
    bcc cfcc9                                                         ; fcc4: 90 03       ..
    lda #1                                                            ; fcc6: a9 01       ..
; overlapping: equb &2c, <(rs232_start_bit_flag), >(rs232_start_bit_flag) ; bit+2 rs232_start_bit_flag; fcc8: 2c a9 00    ,..
    equb &2c                                                          ; fcc8: 2c          ,

; &fcc9 referenced 1 time by &fcc4
.cfcc9
    lda #0                                                            ; fcc9: a9 00       ..
    sta pal_ntsc_flag                                                 ; fccb: 8d a6 02    ...
; &fcce referenced 1 time by &fddc
.sub_cfcce
    ldx pal_ntsc_flag                                                 ; fcce: ae a6 02    ...
    beq cfcd5                                                         ; fcd1: f0 02       ..
    ldx #1                                                            ; fcd3: a2 01       ..
; &fcd5 referenced 1 time by &fcd1
.cfcd5
    lda lfff8,x                                                       ; fcd5: bd f8 ff    ...
    sta cia1_timer_a_low                                              ; fcd8: 8d 04 dc    ...
    lda lfdec,x                                                       ; fcdb: bd ec fd    ...
    sta cia1_timer_a_high                                             ; fcde: 8d 05 dc    ...
    rts                                                               ; fce1: 60          .

.reset_entry
    sei                                                               ; fce2: 78          .
    cld                                                               ; fce3: d8          X
    lda #0                                                            ; fce4: a9 00       ..
    sta nmi_vector+1                                                  ; fce6: 8d 19 03    ... ; Set the high byte of the NMI vector to &00
    ldx #&ff                                                          ; fce9: a2 ff       ..
    txs                                                               ; fceb: 9a          .
    jsr sub_cf924                                                     ; fcec: 20 24 f9     $.
    bne cfcf4                                                         ; fcef: d0 03       P.
    jmp (l8000)                                                       ; fcf1: 6c 00 80    ...

; &fcf4 referenced 1 time by &fcef
.cfcf4
    ldx #&28 ; '('                                                    ; fcf4: a2 28       .(
    stx vic_control_2                                                 ; fcf6: 8e 16 d0    ..P
    jsr ioinit                                                        ; fcf9: 20 84 ff     .. ; Initialise the I/O devices
    jsr ramtas                                                        ; fcfc: 20 87 ff     .. ; Test RAM, set the memory pointers and clear the system variables
    jsr restor                                                        ; fcff: 20 8a ff     .. ; Restore the default Kernal vectors
    jsr cint                                                          ; fd02: 20 81 ff     .. ; Initialise the screen editor and the VIC-II
    cli                                                               ; fd05: 58          x
    jmp (la000)                                                       ; fd06: 6c 00 a0    ...

; &fd09 referenced 6 times by &f0b0, &f0c4, &f9db, &fa30, &fb46, &ffae
.cfd09
    jsr sub_cf8a9                                                     ; fd09: 20 a9 f8     ..
    lda #&ff                                                          ; fd0c: a9 ff       ..
    sta io_temp_1                                                     ; fd0e: 85 a3       ..
    lda #&3f ; '?'                                                    ; fd10: a9 3f       .?
    jmp ce589                                                         ; fd12: 4c 89 e5    l..

; &fd15 referenced 1 time by &ff8a
.cfd15
    clc                                                               ; fd15: 18          .
    ldy #&fd                                                          ; fd16: a0 fd       ..
    ldx #&30 ; '0'                                                    ; fd18: a2 30       .0
; &fd1a referenced 1 time by &ff8d
.cfd1a
    jmp cfbe6                                                         ; fd1a: 4c e6 fb    l..

; &fd1d referenced 3 times by &f14e, &f69a, &f6e7
.sub_cfd1d
    ldy #1                                                            ; fd1d: a0 01       ..
    sei                                                               ; fd1f: 78          .
; &fd20 referenced 1 time by &fd2a
.loop_cfd20
    lda keyboard_buffer,y                                             ; fd20: b9 77 02    ...
    sta secondary_address_table+9,y                                   ; fd23: 99 76 02    ...
    iny                                                               ; fd26: c8          H
    cpy keyboard_buffer_size                                          ; fd27: cc 89 02    L..
    bne loop_cfd20                                                    ; fd2a: d0 f4       P.
    dec keyboard_buffer_length                                        ; fd2c: c6 c6       FF
    cli                                                               ; fd2e: 58          x
    rts                                                               ; fd2f: 60          .

.default_vectors
    equw default_irq_handler                                          ; fd30: 31 ea       1.
    equw default_brk_handler                                          ; fd32: 66 fe       ..
    equw default_nmi_handler                                          ; fd34: 47 fe       g.
    equw default_open_handler                                         ; fd36: 4a f3       j.
    equw default_close_handler                                        ; fd38: 91 f2       ..
    equw default_chkin_handler                                        ; fd3a: 0e f2       ..
    equw default_chkout_handler                                       ; fd3c: 50 f2       p.
    equw default_clrchn_handler                                       ; fd3e: 33 f3       3.
    equw default_chrin_handler                                        ; fd40: 57 f1       w.
    equw default_chrout_handler                                       ; fd42: ca f1       J.
    equw default_stop_handler                                         ; fd44: ed f6       ..
    equw default_getin_handler                                        ; fd46: 3e f1       >.
    equw default_clall_handler                                        ; fd48: 2f f3       /.
    equw default_brk_handler                                          ; fd4a: 66 fe       ..
    equw default_load_handler                                         ; fd4c: a5 f4       ..
    equw default_save_handler                                         ; fd4e: ed f5       ..

; &fd50 referenced 1 time by &ff87
.cfd50
    ldy #0                                                            ; fd50: a0 00       ..
    lda #0                                                            ; fd52: a9 00       ..
; &fd54 referenced 1 time by &fd5e
.loop_cfd54
    sta basic_error_vector,y                                          ; fd54: 99 00 03    ...
    sta basic_input_buffer,y                                          ; fd57: 99 00 02    ...
    sta l0002,y                                                       ; fd5a: 99 02 00    ...
    iny                                                               ; fd5d: c8          H
    bne loop_cfd54                                                    ; fd5e: d0 f4       P.
    ldx #&3c ; '<'                                                    ; fd60: a2 3c       .<
    stx tape_buffer_ptr                                               ; fd62: 86 b2       ..
    ldx #3                                                            ; fd64: a2 03       ..
    stx tape_buffer_ptr+1                                             ; fd66: 86 b3       ..
    ldx #4                                                            ; fd68: a2 04       ..
    stx screen_memory_page                                            ; fd6a: 8e 88 02    ...
    ldx #8                                                            ; fd6d: a2 08       ..
    stx os_memory_start+1                                             ; fd6f: 8e 82 02    ...
    ldx l8000                                                         ; fd72: ae 00 80    ...
    inx                                                               ; fd75: e8          .
    stx l8000                                                         ; fd76: 8e 00 80    ...
    cpx l8000                                                         ; fd79: ec 00 80    ...
    bne cfd88                                                         ; fd7c: d0 0a       P.
    ldy #&a0                                                          ; fd7e: a0 a0       ..
; &fd80 referenced 1 time by &fd8a
.loop_cfd80
    sty os_memory_end+1                                               ; fd80: 8c 84 02    ...
    dex                                                               ; fd83: ca          J
    stx l8000                                                         ; fd84: 8e 00 80    ...
    rts                                                               ; fd87: 60          .

; &fd88 referenced 1 time by &fd7c
.cfd88
    ldy #&80                                                          ; fd88: a0 80       ..
    bne loop_cfd80                                                    ; fd8a: d0 f4       P. ; ALWAYS branch

; &fd8c referenced 1 time by &ffa2
.cfd8c
    sta serial_timeout_flag                                           ; fd8c: 8d 85 02    ...
    rts                                                               ; fd8f: 60          .

    equb &60                                                          ; fd90: 60          .

; &fd91 referenced 10 times by &ed49, &ed6f, &ed72, &f9f4, &f9fb, &f9fe, &fb25, &fbc9, &fbce, &fbda
.cfd91
    lda #&10                                                          ; fd91: a9 10       ..
; &fd93 referenced 1 time by &fd96
.loop_cfd93
    bit cia1_interrupt_control                                        ; fd93: 2c 0d dc    ,..
    beq loop_cfd93                                                    ; fd96: f0 fb       ..
    lda cia2_timer_b_low                                              ; fd98: ad 06 dd    ...
    ldx #&51 ; 'q'                                                    ; fd9b: a2 51       .q
    stx cia2_control_b                                                ; fd9d: 8e 0f dd    ...
    cmp tape_timing                                                   ; fda0: c5 92       E.
    rts                                                               ; fda2: 60          .

; &fda3 referenced 1 time by &ff84
.cfda3
    ldx #&27 ; '''                                                    ; fda3: a2 27       .'
    stx cpu_port                                                      ; fda5: 86 01       ..
    ldx #&2f ; '/'                                                    ; fda7: a2 2f       ./
    stx cpu_port_direction                                            ; fda9: 86 00       ..
    ldx #&7f                                                          ; fdab: a2 7f       ..
    stx cia1_interrupt_control                                        ; fdad: 8e 0d dc    ...
    stx cia2_interrupt_control                                        ; fdb0: 8e 0d dd    ...
    stx cia1_port_a                                                   ; fdb3: 8e 00 dc    ...
    lda #0                                                            ; fdb6: a9 00       ..
    sta sid_volume_filter_mode                                        ; fdb8: 8d 18 d4    ..T
    ldx #&ff                                                          ; fdbb: a2 ff       ..
    stx cia1_data_direction_a                                         ; fdbd: 8e 02 dc    ...
    inx                                                               ; fdc0: e8          .  ; X=0
    stx cia1_data_direction_b                                         ; fdc1: 8e 03 dc    ...
    stx cia2_data_direction_b                                         ; fdc4: 8e 03 dd    ...
    lda #&3f ; '?'                                                    ; fdc7: a9 3f       .?
    sta cia2_data_direction_a                                         ; fdc9: 8d 02 dd    ...
    ldx #8                                                            ; fdcc: a2 08       ..
    stx cia1_control_b                                                ; fdce: 8e 0f dc    ...
    stx cia2_control_a                                                ; fdd1: 8e 0e dd    ...
    stx cia2_control_b                                                ; fdd4: 8e 0f dd    ...
    ldx #7                                                            ; fdd7: a2 07       ..
    stx cia2_port_a                                                   ; fdd9: 8e 00 dd    ...
    jsr sub_cfcce                                                     ; fddc: 20 ce fc     N.
    ldx #&11                                                          ; fddf: a2 11       ..
    stx cia1_control_a                                                ; fde1: 8e 0e dc    ...
    ldx #&81                                                          ; fde4: a2 81       ..
    stx cia1_interrupt_control                                        ; fde6: 8e 0d dc    ...
    jmp cf89e                                                         ; fde9: 4c 9e f8    l..

; &fdec referenced 1 time by &fcdb
.lfdec
    equb &42, &40                                                     ; fdec: 42 40       b@

; &fdee referenced 1 time by &edec
.cfdee
    txa                                                               ; fdee: 8a          .
    ldx #&10                                                          ; fdef: a2 10       ..
; &fdf1 referenced 1 time by &fe10
.loop_cfdf1
    cpx #&0b                                                          ; fdf1: e0 0b       ..
    bne cfe01                                                         ; fdf3: d0 0c       P.
    tay                                                               ; fdf5: a8          .
    lda quote_mode_flag                                               ; fdf6: a5 d4       .T
    ora insert_count                                                  ; fdf8: 05 d8       .X
    beq cfe00                                                         ; fdfa: f0 04       ..
    tya                                                               ; fdfc: 98          .
    jmp cf874                                                         ; fdfd: 4c 74 f8    l..

; &fe00 referenced 1 time by &fdfa
.cfe00
    tya                                                               ; fe00: 98          .
; &fe01 referenced 1 time by &fdf3
.cfe01
    cmp lec4c,x                                                       ; fe01: dd 4c ec    .l.
    bne cfe0f                                                         ; fe04: d0 09       P.
    lda lec6e,x                                                       ; fe06: bd 6e ec    ...
    pha                                                               ; fe09: 48          h
    lda lec5d,x                                                       ; fe0a: bd 5d ec    .].
    pha                                                               ; fe0d: 48          h
    rts                                                               ; fe0e: 60          .

; &fe0f referenced 1 time by &fe04
.cfe0f
    dex                                                               ; fe0f: ca          J
    bpl loop_cfdf1                                                    ; fe10: 10 df       ..
    ldx #colour_light_grey                                            ; fe12: a2 0f       ..
; &fe14 referenced 1 time by &fe20
.loop_cfe14
    cmp le8da,x                                                       ; fe14: dd da e8    .Z.
    bne cfe1f                                                         ; fe17: d0 06       P.
    stx text_colour                                                   ; fe19: 8e 86 02    ...
    jmp cee25                                                         ; fe1c: 4c 25 ee    l%.

; &fe1f referenced 1 time by &fe17
.cfe1f
    dex                                                               ; fe1f: ca          J
    bpl loop_cfe14                                                    ; fe20: 10 f2       ..
    jmp cee25                                                         ; fe22: 4c 25 ee    l%.

; &fe25 referenced 1 time by &ff99
.cfe25
    bcc cfe2d                                                         ; fe25: 90 06       ..
    ldy os_memory_end+1                                               ; fe27: ac 84 02    ...
    ldx os_memory_end                                                 ; fe2a: ae 83 02    ...
; &fe2d referenced 1 time by &fe25
.cfe2d
    sty os_memory_end+1                                               ; fe2d: 8c 84 02    ...
    stx os_memory_end                                                 ; fe30: 8e 83 02    ...
    rts                                                               ; fe33: 60          .

; &fe34 referenced 2 times by &e949, &f492
.sub_cfe34
    ; pull A,Y,X from the stack
    pla                                                               ; fe34: 68          .
    tax                                                               ; fe35: aa          .
    pla                                                               ; fe36: 68          .
    tay                                                               ; fe37: a8          .
    pla                                                               ; fe38: 68          .
    sta io_end_ptr+1                                                  ; fe39: 85 af       ..
    pla                                                               ; fe3b: 68          .
    sta io_address_ptr+1                                              ; fe3c: 85 ad       ..
    pla                                                               ; fe3e: 68          .
    sta io_end_ptr                                                    ; fe3f: 85 ae       ..
    pla                                                               ; fe41: 68          .
    sta io_address_ptr                                                ; fe42: 85 ac       ..
    jmp cf9ef                                                         ; fe44: 4c ef f9    l..

; &fe47 referenced 1 time by &f28e
.default_nmi_handler
    ; push A,X,Y onto the stack
    pha                                                               ; fe47: 48          h
    txa                                                               ; fe48: 8a          .
    pha                                                               ; fe49: 48          h
    tya                                                               ; fe4a: 98          .
    pha                                                               ; fe4b: 48          h
    jsr sub_cf924                                                     ; fe4c: 20 24 f9     $.
    bne cfe54                                                         ; fe4f: d0 03       P.
    jmp (l8002)                                                       ; fe51: 6c 02 80    ...

; &fe54 referenced 1 time by &fe4f
.cfe54
    jsr stop                                                          ; fe54: 20 e1 ff     .. ; Check the RUN/STOP key (Z set if it's pressed)
    bcs cfe5c                                                         ; fe57: b0 03       ..
    jmp cea81                                                         ; fe59: 4c 81 ea    l..

; &fe5c referenced 1 time by &fe57
.cfe5c
    lda #0                                                            ; fe5c: a9 00       ..
    sta tape_timing_constant                                          ; fe5e: 85 b0       ..
    sta tape_timing_constant+1                                        ; fe60: 85 b1       ..
    jmp (brk_vector)                                                  ; fe62: 6c 16 03    ...

    equb 0                                                            ; fe65: 00          .

.default_brk_handler
.default_user_command_handler
    sei                                                               ; fe66: 78          .
    ldx #0                                                            ; fe67: a2 00       ..
    sta vic_control_2                                                 ; fe69: 8d 16 d0    ..P
    cld                                                               ; fe6c: d8          X
    jsr restor                                                        ; fe6d: 20 8a ff     .. ; Restore the default Kernal vectors
    jsr ioinit                                                        ; fe70: 20 84 ff     .. ; Initialise the I/O devices
    jsr cff5b                                                         ; fe73: 20 5b ff     [.
    cli                                                               ; fe76: 58          x
    jmp (la002)                                                       ; fe77: 6c 02 a0    ...

; &fe7a referenced 3 times by &e583, &e77c, &f085
.sub_cfe7a
    lda #&7f                                                          ; fe7a: a9 7f       ..
    sta cia2_interrupt_control                                        ; fe7c: 8d 0d dd    ...
    lda #0                                                            ; fe7f: a9 00       ..
    sta cia2_data_direction_b                                         ; fe81: 8d 03 dd    ...
    ldx #&20 ; ' '                                                    ; fe84: a2 20       .
; &fe86 referenced 1 time by &fe91
.loop_cfe86
    lda cia2_interrupt_control                                        ; fe86: ad 0d dd    ...
    cmp #&10                                                          ; fe89: c9 10       I.
    beq cfe94                                                         ; fe8b: f0 07       ..
    lda cia2_port_b                                                   ; fe8d: ad 01 dd    ...
    dex                                                               ; fe90: ca          J
    bne loop_cfe86                                                    ; fe91: d0 f3       P.
    rts                                                               ; fe93: 60          .

; &fe94 referenced 1 time by &fe8b
.cfe94
    lda #2                                                            ; fe94: a9 02       ..
    sta io_temp_1                                                     ; fe96: 85 a3       ..
    rts                                                               ; fe98: 60          .

; &fe99 referenced 1 time by &e7b6
.sub_cfe99
    ldy load_verify_flag                                              ; fe99: a4 93       ..
    bne cfea3                                                         ; fe9b: d0 06       P.
    ldy #0                                                            ; fe9d: a0 00       ..
    sta (io_end_ptr),y                                                ; fe9f: 91 ae       ..
; &fea1 referenced 1 time by &feac
.loop_cfea1
    clc                                                               ; fea1: 18          .
    rts                                                               ; fea2: 60          .

; &fea3 referenced 1 time by &fe9b
.cfea3
    sta io_temp_2                                                     ; fea3: 85 a4       ..
    ldy #0                                                            ; fea5: a0 00       ..
    jsr sub_cfcac                                                     ; fea7: 20 ac fc     ..
    cmp io_temp_2                                                     ; feaa: c5 a4       E.
    beq loop_cfea1                                                    ; feac: f0 f3       ..
    sec                                                               ; feae: 38          8
    rts                                                               ; feaf: 60          .

; &feb0 referenced 5 times by &e652, &eff3, &f018, &f035, &f098
.sub_cfeb0
    lda io_start_ptr                                                  ; feb0: a5 c1       .A
    sta load_address_temp                                             ; feb2: 85 c3       .C
    lda io_start_ptr+1                                                ; feb4: a5 c2       .B
    sta load_address_temp+1                                           ; feb6: 85 c4       .D
    rts                                                               ; feb8: 60          .

; &feb9 referenced 4 times by &e9e6, &ee72, &eef9, &f0a6
.sub_cfeb9
    inc load_address_temp                                             ; feb9: e6 c3       .C
    bne return_22                                                     ; febb: d0 02       P.
    inc load_address_temp+1                                           ; febd: e6 c4       .D
; &febf referenced 1 time by &febb
.return_22
    rts                                                               ; febf: 60          .

; &fec0 referenced 3 times by &e9e9, &f02d, &f0a9
.sub_cfec0
    lda load_address_temp+1                                           ; fec0: a5 c4       .D
    cmp io_end_ptr+1                                                  ; fec2: c5 af       E.
    bne return_23                                                     ; fec4: d0 04       P.
    lda load_address_temp                                             ; fec6: a5 c3       .C
    cmp io_end_ptr                                                    ; fec8: c5 ae       E.
; &feca referenced 1 time by &fec4
.return_23
    rts                                                               ; feca: 60          .

; &fecb referenced 1 time by &e756
.sub_cfecb
    lda kernal_message_flags                                          ; fecb: a5 9d       ..
    bpl return_24                                                     ; fecd: 10 15       ..
    ldx #0                                                            ; fecf: a2 00       ..
    jsr sub_ce971                                                     ; fed1: 20 71 e9     ..
    ldy #0                                                            ; fed4: a0 00       ..
; &fed6 referenced 1 time by &fee1
.loop_cfed6
    cpy filename_length                                               ; fed6: c4 b7       D.
    beq return_24                                                     ; fed8: f0 0a       ..
    jsr sub_cfca0                                                     ; feda: 20 a0 fc     ..
    jsr chrout                                                        ; fedd: 20 d2 ff     R. ; Output a character
    iny                                                               ; fee0: c8          H
    jmp loop_cfed6                                                    ; fee1: 4c d6 fe    lV.

; &fee4 referenced 5 times by &fecd, &fed8, &fee7, &ff19, &ff25
.return_24
    rts                                                               ; fee4: 60          .

; &fee5 referenced 2 times by &e655, &e79a
.sub_cfee5
    lda kernal_message_flags                                          ; fee5: a5 9d       ..
    bpl return_24                                                     ; fee7: 10 fb       ..
    ldx #&0f                                                          ; fee9: a2 0f       ..
    lda load_verify_flag                                              ; feeb: a5 93       ..
    beq cfef1                                                         ; feed: f0 02       ..
    ldx #&17                                                          ; feef: a2 17       ..
; &fef1 referenced 1 time by &feed
.cfef1
    jsr sub_ce971                                                     ; fef1: 20 71 e9     ..
    ldx #&29 ; ')'                                                    ; fef4: a2 29       .)
    jsr sub_ce971                                                     ; fef6: 20 71 e9     ..
    lda device_number                                                 ; fef9: a5 ba       ..
    cmp #1                                                            ; fefb: c9 01       I.
    beq cff0d                                                         ; fefd: f0 0e       ..
    cmp #7                                                            ; feff: c9 07       I.
    beq cff0d                                                         ; ff01: f0 0a       ..
; &ff03 referenced 1 time by &ff20
.loop_cff03
    lda io_end_ptr+1                                                  ; ff03: a5 af       ..
    jsr cfaf1                                                         ; ff05: 20 f1 fa     ..
    lda io_end_ptr                                                    ; ff08: a5 ae       ..
    jmp cfaf1                                                         ; ff0a: 4c f1 fa    l..

; &ff0d referenced 2 times by &fefd, &ff01
.cff0d
    lda io_start_ptr+1                                                ; ff0d: a5 c2       .B
    jsr cfaf1                                                         ; ff0f: 20 f1 fa     ..
    lda io_start_ptr                                                  ; ff12: a5 c1       .A
    jmp cfaf1                                                         ; ff14: 4c f1 fa    l..

; &ff17 referenced 2 times by &e6aa, &e7da
.sub_cff17
    lda kernal_message_flags                                          ; ff17: a5 9d       ..
    bpl return_24                                                     ; ff19: 10 c9       .I
    ldx #&30 ; '0'                                                    ; ff1b: a2 30       .0
    jsr sub_ce971                                                     ; ff1d: 20 71 e9     ..
    jmp loop_cff03                                                    ; ff20: 4c 03 ff    l..

; &ff23 referenced 1 time by &f05f
.sub_cff23
    lda kernal_message_flags                                          ; ff23: a5 9d       ..
    bpl return_24                                                     ; ff25: 10 bd       ..
    ldx #&21 ; '!'                                                    ; ff27: a2 21       .!
    jsr sub_ce971                                                     ; ff29: 20 71 e9     ..
    ldy #0                                                            ; ff2c: a0 00       ..
; &ff2e referenced 1 time by &ff38
.loop_cff2e
    cpy filename_length                                               ; ff2e: c4 b7       D.
    beq return_25                                                     ; ff30: f0 08       ..
    lda (filename_ptr),y                                              ; ff32: b1 bb       .. ; A=character to output
    jsr chrout                                                        ; ff34: 20 d2 ff     R. ; Output a character
    iny                                                               ; ff37: c8          H
    bne loop_cff2e                                                    ; ff38: d0 f4       P.
; &ff3a referenced 1 time by &ff30
.return_25
    rts                                                               ; ff3a: 60          .

; &ff3b referenced 1 time by &ff55
.loop_cff3b
    sec                                                               ; ff3b: 38          8
    rts                                                               ; ff3c: 60          .

; &ff3d referenced 2 times by &e6ad, &e7e2
.cff3d
    ldx io_end_ptr                                                    ; ff3d: a6 ae       ..
    ldy io_end_ptr+1                                                  ; ff3f: a4 af       ..
    clc                                                               ; ff41: 18          .
    rts                                                               ; ff42: 60          .

; &ff43 referenced 5 times by &e73b, &f055, &f166, &f1ee, &f85d
.cff43
    jsr sub_cf98b                                                     ; ff43: 20 8b f9     ..
    jmp cfc7b                                                         ; ff46: 4c 7b fc    l..

; &ff49 referenced 2 times by &f4ca, &f5fa
.cff49
    jsr sub_cf98b                                                     ; ff49: 20 8b f9     ..
    jmp cfc87                                                         ; ff4c: 4c 87 fc    l..

; &ff4f referenced 2 times by &e6b3, &e743
.cff4f
    lda load_verify_flag                                              ; ff4f: a5 93       ..
    bne cff57                                                         ; ff51: d0 04       P.
    lda #&1d                                                          ; ff53: a9 1d       ..
    bne loop_cff3b                                                    ; ff55: d0 e4       P. ; ALWAYS branch

; &ff57 referenced 1 time by &ff51
.cff57
    lda #&1c                                                          ; ff57: a9 1c       ..
    sec                                                               ; ff59: 38          8
    rts                                                               ; ff5a: 60          .

; &ff5b referenced 2 times by &fe73, &ff81
.cff5b
    jsr sub_ce518                                                     ; ff5b: 20 18 e5     ..
    jmp cfcb8                                                         ; ff5e: 4c b8 fc    l..

; &ff61 referenced 1 time by &f29e
.cff61
    jsr sub_cf8a9                                                     ; ff61: 20 a9 f8     ..
    lda secondary_address_table,y                                     ; ff64: b9 6d 02    ...
    cmp #&60                                                          ; ff67: c9 60       I.
    bne cff71                                                         ; ff69: d0 06       P.
    jsr sub_cfa1e                                                     ; ff6b: 20 1e fa     ..
    jmp cf2a1                                                         ; ff6e: 4c a1 f2    l..

; &ff71 referenced 1 time by &ff69
.cff71
    ora screen_line_links+7                                           ; ff71: 05 e0       ..
    sta io_temp_2                                                     ; ff73: 85 a4       ..
    jsr cfabe                                                         ; ff75: 20 be fa     ..
    bcs cff7d                                                         ; ff78: b0 03       ..
    jsr cf647                                                         ; ff7a: 20 47 f6     g.
; &ff7d referenced 1 time by &ff78
.cff7d
    jmp cf2a1                                                         ; ff7d: 4c a1 f2    l..

    equb &f0                                                          ; ff80: f0          .

; ***************************************************************************************
; Initialise the screen editor and the VIC-II
; ***************************************************************************************
; &ff81 referenced 1 time by &fd02
.cint
    jmp cff5b                                                         ; ff81: 4c 5b ff    l[.

; ***************************************************************************************
; Initialise the I/O devices
; ***************************************************************************************
; &ff84 referenced 2 times by &fcf9, &fe70
.ioinit
    jmp cfda3                                                         ; ff84: 4c a3 fd    l..

; ***************************************************************************************
; Test RAM, set the memory pointers and clear the system variables
; ***************************************************************************************
; &ff87 referenced 1 time by &fcfc
.ramtas
    jmp cfd50                                                         ; ff87: 4c 50 fd    lp.

; ***************************************************************************************
; Restore the default Kernal vectors
; ***************************************************************************************
; &ff8a referenced 2 times by &fcff, &fe6d
.restor
    jmp cfd15                                                         ; ff8a: 4c 15 fd    l..

; ***************************************************************************************
; Read or set the Kernal vectors (carry set: read them into the list at X/Y; carry
; clear: set them from it)
; 
; On Entry:
;     X: vector list address (low byte)
;     Y: vector list address (high byte)
; ***************************************************************************************
.vector
    jmp cfd1a                                                         ; ff8d: 4c 1a fd    l..

; ***************************************************************************************
; Set which Kernal messages are shown (bit 7: control messages, bit 6: error messages)
; 
; On Entry:
;     A: message flags
; ***************************************************************************************
.setmsg
    jmp ce51e                                                         ; ff90: 4c 1e e5    l..

; ***************************************************************************************
; Send a secondary address to a device commanded to listen
; 
; On Entry:
;     A: secondary address
; ***************************************************************************************
.second
    jmp ce6b7                                                         ; ff93: 4c b7 e6    l..

; ***************************************************************************************
; Send a secondary address to a device commanded to talk
; 
; On Entry:
;     A: secondary address
; ***************************************************************************************
.tksa
    jmp cf388                                                         ; ff96: 4c 88 f3    l..

; ***************************************************************************************
; Read or set the top of memory (carry set: read it into X/Y; carry clear: set it from
; X/Y)
; 
; On Entry:
;     X: top of memory (low byte)
;     Y: top of memory (high byte)
; ***************************************************************************************
.memtop
    jmp cfe25                                                         ; ff99: 4c 25 fe    l%.

; ***************************************************************************************
; Read or set the bottom of memory (carry set: read it into X/Y; carry clear: set it
; from X/Y)
; 
; On Entry:
;     X: bottom of memory (low byte)
;     Y: bottom of memory (high byte)
; ***************************************************************************************
.membot
    jmp cf241                                                         ; ff9c: 4c 41 f2    la.

; ***************************************************************************************
; Scan the keyboard
; ***************************************************************************************
; &ff9f referenced 1 time by &ea34
.scnkey
    jmp ce7fd                                                         ; ff9f: 4c fd e7    l..

; ***************************************************************************************
; Set the IEEE bus timeout
; 
; On Entry:
;     A: timeout flag
; ***************************************************************************************
.settmo
    jmp cfd8c                                                         ; ffa2: 4c 8c fd    l..

; ***************************************************************************************
; Read a byte from the serial bus
; 
; On Exit:
;     A: byte read
; ***************************************************************************************
; &ffa5 referenced 1 time by &f7b4
.acptr
    jmp cf888                                                         ; ffa5: 4c 88 f8    l..

; ***************************************************************************************
; Send a byte over the serial bus
; 
; On Entry:
;     A: byte to send
; ***************************************************************************************
; &ffa8 referenced 1 time by &f919
.ciout
    jmp cfa09                                                         ; ffa8: 4c 09 fa    l..

; ***************************************************************************************
; Command the devices on the serial bus to stop talking
; ***************************************************************************************
.untlk
    jmp cf9b6                                                         ; ffab: 4c b6 f9    l..

; ***************************************************************************************
; Command the devices on the serial bus to stop listening
; ***************************************************************************************
.unlsn
    jmp cfd09                                                         ; ffae: 4c 09 fd    l..

; ***************************************************************************************
; Command a device on the serial bus to listen
; 
; On Entry:
;     A: device number
; ***************************************************************************************
.listen
    jmp cf4cd                                                         ; ffb1: 4c cd f4    lM.

; ***************************************************************************************
; Command a device on the serial bus to talk
; 
; On Entry:
;     A: device number
; ***************************************************************************************
.talk
    jmp cf3f7                                                         ; ffb4: 4c f7 f3    l..

; ***************************************************************************************
; Read the I/O status
; 
; On Exit:
;     A: I/O status
; ***************************************************************************************
.readst
    jmp cf8d7                                                         ; ffb7: 4c d7 f8    lW.

; ***************************************************************************************
; Set the logical file number, device number and secondary address
; 
; On Entry:
;     A: logical file number
;     X: device number
;     Y: secondary address
; ***************************************************************************************
.setlfs
    jmp cf7f6                                                         ; ffba: 4c f6 f7    l..

; ***************************************************************************************
; Set the filename
; 
; On Entry:
;     A: filename length
;     X: filename address (low byte)
;     Y: filename address (high byte)
; ***************************************************************************************
.setnam
    jmp cf7fd                                                         ; ffbd: 4c fd f7    l..

; ***************************************************************************************
; Open a logical file (set up with SETLFS and SETNAM)
; ***************************************************************************************
.open
    jmp (open_vector)                                                 ; ffc0: 6c 1a 03    ...

; ***************************************************************************************
; Close a logical file
; 
; On Entry:
;     A: logical file number
; ***************************************************************************************
; &ffc3 referenced 1 time by &fa98
.close
    jmp (close_vector)                                                ; ffc3: 6c 1c 03    ...

; ***************************************************************************************
; Open a channel for input
; 
; On Entry:
;     X: logical file number
; ***************************************************************************************
.chkin
    jmp (chkin_vector)                                                ; ffc6: 6c 1e 03    ...

; ***************************************************************************************
; Open a channel for output
; 
; On Entry:
;     X: logical file number
; ***************************************************************************************
.chkout
    jmp (chkout_vector)                                               ; ffc9: 6c 20 03    . .

; ***************************************************************************************
; Restore the default input and output channels
; ***************************************************************************************
.clrchn
    jmp (clrchn_vector)                                               ; ffcc: 6c 22 03    .".

; ***************************************************************************************
; Read a character from the input channel
; 
; On Exit:
;     A: character read
; ***************************************************************************************
.chrin
    jmp (chrin_vector)                                                ; ffcf: 6c 24 03    .$.

; ***************************************************************************************
; Output a character
; 
; On Entry:
;     A: character to output
; ***************************************************************************************
; &ffd2 referenced 8 times by &e605, &e96d, &e978, &f7c3, &fafc, &fb08, &fedd, &ff34
.chrout
    jmp (chrout_vector)                                               ; ffd2: 6c 26 03    .&.

; ***************************************************************************************
; Load or verify a file (set up with SETLFS and SETNAM)
; 
; On Entry:
;     A: 0 to load, 1 to verify
;     X: load address if the secondary address is 0 (low byte)
;     Y: load address if the secondary address is 0 (high byte)
; 
; On Exit:
;     X: end address of the data loaded (low byte)
;     Y: end address of the data loaded (high byte)
; ***************************************************************************************
.load
    jmp cf49e                                                         ; ffd5: 4c 9e f4    l..

; ***************************************************************************************
; Save memory to a file (set up with SETLFS and SETNAM)
; 
; On Entry:
;     A: zero page address of the start address
;     X: end address + 1 (low byte)
;     Y: end address + 1 (high byte)
; ***************************************************************************************
.save
    jmp cf5dd                                                         ; ffd8: 4c dd f5    l..

; ***************************************************************************************
; Set the jiffy clock
; 
; On Entry:
;     A: jiffy clock (high byte)
;     X: jiffy clock (middle byte)
;     Y: jiffy clock (low byte)
; ***************************************************************************************
.settim
    jmp cf2bf                                                         ; ffdb: 4c bf f2    l..

; ***************************************************************************************
; Read the jiffy clock
; 
; On Exit:
;     A: jiffy clock (high byte)
;     X: jiffy clock (middle byte)
;     Y: jiffy clock (low byte)
; ***************************************************************************************
.rdtim
    jmp cf844                                                         ; ffde: 4c 44 f8    ld.

; ***************************************************************************************
; Check the RUN/STOP key (Z set if it's pressed)
; ***************************************************************************************
; &ffe1 referenced 1 time by &fe54
.stop
    jmp (stop_vector)                                                 ; ffe1: 6c 28 03    .(.

; ***************************************************************************************
; Get a character from the input channel (from the keyboard, 0 if there's none)
; 
; On Exit:
;     A: character read
; ***************************************************************************************
.getin
    jmp (getin_vector)                                                ; ffe4: 6c 2a 03    .*.

; ***************************************************************************************
; Close all files
; ***************************************************************************************
.clall
    jmp (clall_vector)                                                ; ffe7: 6c 2c 03    .,.

; ***************************************************************************************
; Update the jiffy clock and check the RUN/STOP key
; ***************************************************************************************
; &ffea referenced 1 time by &ea37
.udtim
    jmp ce4d3                                                         ; ffea: 4c d3 e4    lS.

; ***************************************************************************************
; Read the screen size
; 
; On Exit:
;     X: number of columns
;     Y: number of rows
; ***************************************************************************************
.screen
    jmp ce5c9                                                         ; ffed: 4c c9 e5    lI.

; ***************************************************************************************
; Read or set the cursor position (carry set: read it into X/Y; carry clear: set it
; from X/Y)
; 
; On Entry:
;     X: cursor row
;     Y: cursor column
; ***************************************************************************************
.plot
    jmp ce50a                                                         ; fff0: 4c 0a e5    l..

; ***************************************************************************************
; Read the address of the I/O devices
; 
; On Exit:
;     X: I/O base address (low byte)
;     Y: I/O base address (high byte)
; ***************************************************************************************
.iobase
    ldy #&dc                                                          ; fff3: a0 dc       ..
    ldx #0                                                            ; fff5: a2 00       ..
    rts                                                               ; fff7: 60          .

; &fff8 referenced 1 time by &fcd5
.lfff8
    equb &95, &25                                                     ; fff8: 95 25       .%
    equw nmi_entry                                                    ; fffa: 81 f2       ..
    equw reset_entry                                                  ; fffc: e2 fc       ..
    equw irq_entry                                                    ; fffe: 53 ea       s.
.pydis_end

    assert &fe66 == default_brk_handler
    assert &f20e == default_chkin_handler
    assert &f250 == default_chkout_handler
    assert &f157 == default_chrin_handler
    assert &f1ca == default_chrout_handler
    assert &f32f == default_clall_handler
    assert &f291 == default_close_handler
    assert &f333 == default_clrchn_handler
    assert &f13e == default_getin_handler
    assert &ea31 == default_irq_handler
    assert &f4a5 == default_load_handler
    assert &fe47 == default_nmi_handler
    assert &f34a == default_open_handler
    assert &f5ed == default_save_handler
    assert &f6ed == default_stop_handler
    assert &ea53 == irq_entry
    assert &f281 == nmi_entry
    assert &fce2 == reset_entry
    assert &d9 == screen_line_links
    assert &da == screen_line_links+1

save pydis_start, pydis_end

; Label references by decreasing frequency:
;     cia2_port_a:                  59
;     io_temp_2:                    29
;     io_end_ptr:                   28
;     serial_char_buffered_flag:    21
;     cursor_row:                   20
;     io_temp_1:                    20
;     device_number:                18
;     screen_line_ptr:              18
;     cpu_port:                     17
;     load_address_temp:            16
;     rs232_input_bits:             15
;     colour_ram_line_ptr:          13
;     tape_buffer_ptr:              12
;     io_start_ptr:                 11
;     cfd91:                        10
;     cursor_column:                10
;     filename_length:              10
;     kernal_x_save:                10
;     screen_line_links:            10
;     sub_cf90e:                    10
;     vic_border_colour:            10
;     vic_control_1:                10
;     cfabe:                         9
;     device_number_table:           9
;     logical_file_table:            9
;     cf4cd:                         8
;     chrout:                        8
;     io_address_ptr:                8
;     sub_ce971:                     8
;     tape_parity:                   8
;     ce885:                         7
;     cf9f4:                         7
;     cfc7b:                         7
;     cia1_port_a:                   7
;     cia1_port_b:                   7
;     io_status:                     7
;     keyboard_buffer_length:        7
;     secondary_address:             7
;     shift_key_flags:               7
;     sub_ce95a:                     7
;     vic_raster_line:               7
;     ce717:                         6
;     ce73e:                         6
;     cf7d1:                         6
;     cf940:                         6
;     cf981:                         6
;     cfd09:                         6
;     cursor_blink_phase:            6
;     load_verify_flag:              6
;     open_files_count:              6
;     quote_mode_flag:               6
;     ce6b0:                         5
;     cf055:                         5
;     cf647:                         5
;     cfaa6:                         5
;     cff43:                         5
;     cia2_port_b:                   5
;     cursor_blink_disable:          5
;     cursor_blink_timer:            5
;     input_cursor_start:            5
;     input_device:                  5
;     jiffy_clock:                   5
;     kernal_message_flags:          5
;     keyboard_buffer:               5
;     l0100:                         5
;     l8000:                         5
;     return_24:                     5
;     screen_memory_page:            5
;     stop_key_flag:                 5
;     sub_cee9f:                     5
;     sub_cf0c9:                     5
;     sub_cf7ef:                     5
;     sub_cf8a9:                     5
;     sub_cfa1e:                     5
;     sub_cfeb0:                     5
;     tape_pass2_errors:             5
;     text_colour:                   5
;     ce4f1:                         4
;     cefe3:                         4
;     cf2a1:                         4
;     cfaf1:                         4
;     cia1_interrupt_control:        4
;     filename_ptr:                  4
;     input_from_screen_flag:        4
;     key_repeat_counter:            4
;     key_repeat_delay:              4
;     keyboard_table_ptr:            4
;     last_char_printed:             4
;     output_device:                 4
;     rs232_input_parity:            4
;     sid_volume_filter_mode:        4
;     sub_cf8f0:                     4
;     sub_cfeb9:                     4
;     tape_pass1_errors:             4
;     vic_sprite_enable:             4
;     ce6c8:                         3
;     ce7b1:                         3
;     ce8ea:                         3
;     cea15:                         3
;     cea2f:                         3
;     cebee:                         3
;     cec41:                         3
;     cecae:                         3
;     cee22:                         3
;     ceeca:                         3
;     cef21:                         3
;     cf231:                         3
;     cf3f7:                         3
;     cf89e:                         3
;     cf9b6:                         3
;     cf9fe:                         3
;     cfa5d:                         3
;     cfab0:                         3
;     cfb0b:                         3
;     cfb81:                         3
;     cia2_data_direction_b:         3
;     cia2_interrupt_control:        3
;     input_line_end:                3
;     insert_count:                  3
;     irq_vector:                    3
;     keyboard_buffer_size:          3
;     last_key_pressed:              3
;     logical_file_number:           3
;     return_3:                      3
;     return_5:                      3
;     secondary_address_table:       3
;     sub_ce572:                     3
;     sub_ce9ff:                     3
;     sub_cec7f:                     3
;     sub_cee90:                     3
;     sub_ceeac:                     3
;     sub_cf804:                     3
;     sub_cf8b4:                     3
;     sub_cf932:                     3
;     sub_cf972:                     3
;     sub_cf985:                     3
;     sub_cf98b:                     3
;     sub_cfb40:                     3
;     sub_cfb76:                     3
;     sub_cfd1d:                     3
;     sub_cfe7a:                     3
;     sub_cfec0:                     3
;     tape_motor_interlock:          3
;     tape_sync_number:              3
;     tape_timing:                   3
;     vic_control_2:                 3
;     vic_memory_setup:              3
;     brk_vector:                    2
;     ce1b5:                         2
;     ce4dd:                         2
;     ce589:                         2
;     ce59e:                         2
;     ce5ce:                         2
;     ce65b:                         2
;     ce6a7:                         2
;     ce6b7:                         2
;     ce728:                         2
;     ce73b:                         2
;     ce7da:                         2
;     ce7f3:                         2
;     ce876:                         2
;     ce8bf:                         2
;     ce92a:                         2
;     ce97b:                         2
;     ce98f:                         2
;     ce9bb:                         2
;     cea50:                         2
;     ceb95:                         2
;     cebbc:                         2
;     cec3e:                         2
;     cec49:                         2
;     ceceb:                         2
;     ced09:                         2
;     ced69:                         2
;     ced98:                         2
;     ceddd:                         2
;     cee25:                         2
;     cee78:                         2
;     cee7a:                         2
;     ceef9:                         2
;     cef74:                         2
;     cef8b:                         2
;     ceff3:                         2
;     cf10f:                         2
;     cf13b:                         2
;     cf15e:                         2
;     cf1b6:                         2
;     cf1e2:                         2
;     cf1f1:                         2
;     cf273:                         2
;     cf27b:                         2
;     cf386:                         2
;     cf388:                         2
;     cf439:                         2
;     cf666:                         2
;     cf675:                         2
;     cf689:                         2
;     cf6c2:                         2
;     cf7d7:                         2
;     cf8e9:                         2
;     cf915:                         2
;     cf949:                         2
;     cf975:                         2
;     cf98f:                         2
;     cfb91:                         2
;     cfbe4:                         2
;     cfbfa:                         2
;     cfc6c:                         2
;     cfc9a:                         2
;     cfcb8:                         2
;     cff0d:                         2
;     cff3d:                         2
;     cff49:                         2
;     cff4f:                         2
;     cff5b:                         2
;     char_under_cursor:             2
;     charset_switch_flag:           2
;     cia2_control_a:                2
;     cia2_control_b:                2
;     cia2_timer_b_low:              2
;     colour_under_cursor:           2
;     cpu_port_direction:            2
;     default_chrout_handler:        2
;     default_stop_handler:          2
;     ioinit:                        2
;     keyboard_table_setup_vector:   2
;     l03ff:                         2
;     last_shift_key_flags:          2
;     lf80b:                         2
;     lfc7e:                         2
;     lfc84:                         2
;     os_memory_end:                 2
;     os_memory_start:               2
;     pal_ntsc_flag:                 2
;     restor:                        2
;     return_1:                      2
;     return_10:                     2
;     return_11:                     2
;     return_17:                     2
;     return_6:                      2
;     return_7:                      2
;     return_9:                      2
;     rs232_output_parity:           2
;     sub_ce56c:                     2
;     sub_ce5f9:                     2
;     sub_ce702:                     2
;     sub_ce7e5:                     2
;     sub_cedc5:                     2
;     sub_cee2b:                     2
;     sub_ceec5:                     2
;     sub_ceece:                     2
;     sub_cf043:                     2
;     sub_cf1fb:                     2
;     sub_cf7c1:                     2
;     sub_cf7cb:                     2
;     sub_cf7dd:                     2
;     sub_cf833:                     2
;     sub_cf86a:                     2
;     sub_cf8bf:                     2
;     sub_cf8e3:                     2
;     sub_cf8fd:                     2
;     sub_cf90a:                     2
;     sub_cf924:                     2
;     sub_cf9df:                     2
;     sub_cfb25:                     2
;     sub_cfbc9:                     2
;     sub_cfca0:                     2
;     sub_cfe34:                     2
;     sub_cfee5:                     2
;     sub_cff17:                     2
;     tape_block_count:              2
;     tape_byte_received_flag:       2
;     tape_timing_constant:          2
;     acptr:                         1
;     basic_error_vector:            1
;     basic_index2:                  1
;     basic_input_buffer:            1
;     basic_multiply_result:         1
;     ce1db:                         1
;     ce4d3:                         1
;     ce50a:                         1
;     ce513:                         1
;     ce51e:                         1
;     ce521:                         1
;     ce529:                         1
;     ce534:                         1
;     ce541:                         1
;     ce544:                         1
;     ce566:                         1
;     ce57a:                         1
;     ce5c9:                         1
;     ce5ea:                         1
;     ce652:                         1
;     ce65d:                         1
;     ce673:                         1
;     ce6a3:                         1
;     ce6a5:                         1
;     ce6ba:                         1
;     ce6ef:                         1
;     ce746:                         1
;     ce74f:                         1
;     ce756:                         1
;     ce79a:                         1
;     ce7aa:                         1
;     ce7c1:                         1
;     ce7d4:                         1
;     ce7d6:                         1
;     ce7fd:                         1
;     ce82c:                         1
;     ce83a:                         1
;     ce83d:                         1
;     ce84d:                         1
;     ce871:                         1
;     ce88a:                         1
;     ce895:                         1
;     ce8ad:                         1
;     ce8c8:                         1
;     ce8d1:                         1
;     ce8fb:                         1
;     ce93c:                         1
;     ce949:                         1
;     ce987:                         1
;     ce997:                         1
;     ce9a9:                         1
;     ce9fc:                         1
;     cea49:                         1
;     cea69:                         1
;     cea6c:                         1
;     cea7e:                         1
;     cea81:                         1
;     ceb61:                         1
;     ceb6a:                         1
;     ceba6:                         1
;     cebb9:                         1
;     cec08:                         1
;     cec0b:                         1
;     cec44:                         1
;     cec95:                         1
;     ceca2:                         1
;     cecb9:                         1
;     ced3a:                         1
;     ced56:                         1
;     ced83:                         1
;     ced89:                         1
;     cedcd:                         1
;     cede2:                         1
;     cedef:                         1
;     cedf3:                         1
;     cee02:                         1
;     cee1b:                         1
;     cee3d:                         1
;     cee5e:                         1
;     cee69:                         1
;     cee72:                         1
;     ceed8:                         1
;     ceedf:                         1
;     ceeeb:                         1
;     ceef6:                         1
;     ceeff:                         1
;     cef2a:                         1
;     cef48:                         1
;     cef6b:                         1
;     cef6e:                         1
;     cef7d:                         1
;     cefcc:                         1
;     ceff9:                         1
;     cf00c:                         1
;     cf018:                         1
;     cf02d:                         1
;     cf035:                         1
;     cf040:                         1
;     cf058:                         1
;     cf05f:                         1
;     cf0a9:                         1
;     cf0d4:                         1
;     cf0dc:                         1
;     cf0e8:                         1
;     cf0fe:                         1
;     cf106:                         1
;     cf11c:                         1
;     cf11f:                         1
;     cf12b:                         1
;     cf142:                         1
;     cf148:                         1
;     cf166:                         1
;     cf16c:                         1
;     cf1c5:                         1
;     cf1da:                         1
;     cf21d:                         1
;     cf22a:                         1
;     cf236:                         1
;     cf23b:                         1
;     cf241:                         1
;     cf249:                         1
;     cf25f:                         1
;     cf26c:                         1
;     cf28d:                         1
;     cf2bb:                         1
;     cf2bf:                         1
;     cf2c8:                         1
;     cf2cd:                         1
;     cf324:                         1
;     cf336:                         1
;     cf35c:                         1
;     cf361:                         1
;     cf36a:                         1
;     cf402:                         1
;     cf404:                         1
;     cf464:                         1
;     cf480:                         1
;     cf48f:                         1
;     cf492:                         1
;     cf49e:                         1
;     cf4bb:                         1
;     cf4c2:                         1
;     cf4ca:                         1
;     cf4d8:                         1
;     cf5dd:                         1
;     cf5fa:                         1
;     cf657:                         1
;     cf65e:                         1
;     cf697:                         1
;     cf6ba:                         1
;     cf6be:                         1
;     cf6dc:                         1
;     cf6f5:                         1
;     cf7b4:                         1
;     cf7f6:                         1
;     cf7fd:                         1
;     cf844:                         1
;     cf84d:                         1
;     cf85b:                         1
;     cf874:                         1
;     cf87b:                         1
;     cf87e:                         1
;     cf885:                         1
;     cf888:                         1
;     cf890:                         1
;     cf8b2:                         1
;     cf8d7:                         1
;     cf8e0:                         1
;     cf8ed:                         1
;     cf8fa:                         1
;     cf917:                         1
;     cf921:                         1
;     cf93e:                         1
;     cf9a4:                         1
;     cf9ad:                         1
;     cf9bf:                         1
;     cf9d4:                         1
;     cf9ef:                         1
;     cfa09:                         1
;     cfa15:                         1
;     cfa8e:                         1
;     cfa9e:                         1
;     cfad0:                         1
;     cfae9:                         1
;     cfaee:                         1
;     cfb1d:                         1
;     cfb23:                         1
;     cfb36:                         1
;     cfb49:                         1
;     cfb53:                         1
;     cfba9:                         1
;     cfbad:                         1
;     cfbb9:                         1
;     cfbc3:                         1
;     cfbc6:                         1
;     cfbda:                         1
;     cfbe6:                         1
;     cfbff:                         1
;     cfc12:                         1
;     cfc14:                         1
;     cfc23:                         1
;     cfc25:                         1
;     cfc47:                         1
;     cfc51:                         1
;     cfc5c:                         1
;     cfc69:                         1
;     cfc6f:                         1
;     cfc72:                         1
;     cfc87:                         1
;     cfcc9:                         1
;     cfcd5:                         1
;     cfcf4:                         1
;     cfd15:                         1
;     cfd1a:                         1
;     cfd50:                         1
;     cfd88:                         1
;     cfd8c:                         1
;     cfda3:                         1
;     cfdee:                         1
;     cfe00:                         1
;     cfe01:                         1
;     cfe0f:                         1
;     cfe1f:                         1
;     cfe25:                         1
;     cfe2d:                         1
;     cfe54:                         1
;     cfe5c:                         1
;     cfe94:                         1
;     cfea3:                         1
;     cfef1:                         1
;     cff57:                         1
;     cff61:                         1
;     cff71:                         1
;     cff7d:                         1
;     chkin_vector:                  1
;     chkout_vector:                 1
;     chrin_vector:                  1
;     chrout_vector:                 1
;     cia1_control_a:                1
;     cia1_control_b:                1
;     cia1_data_direction_a:         1
;     cia1_data_direction_b:         1
;     cia1_timer_a_high:             1
;     cia1_timer_a_low:              1
;     cia2_data_direction_a:         1
;     cia2_timer_a_high:             1
;     cia2_timer_a_low:              1
;     cia2_timer_b_high:             1
;     cint:                          1
;     ciout:                         1
;     clall_vector:                  1
;     close:                         1
;     close_vector:                  1
;     clrchn_vector:                 1
;     default_clrchn_handler:        1
;     default_irq_handler:           1
;     default_nmi_handler:           1
;     getin_vector:                  1
;     key_repeat_flags:              1
;     l0002:                         1
;     l0101:                         1
;     l0104:                         1
;     l0105:                         1
;     l0106:                         1
;     l0107:                         1
;     l01a9:                         1
;     l02a9:                         1
;     l08a9:                         1
;     l8002:                         1
;     l8003:                         1
;     la000:                         1
;     la002:                         1
;     le8da:                         1
;     lea87:                         1
;     lead1:                         1
;     lebc1:                         1
;     lebc8:                         1
;     lebe7:                         1
;     lec4c:                         1
;     lec5d:                         1
;     lec6e:                         1
;     lf33f:                         1
;     lf7b6:                         1
;     lf81b:                         1
;     lf823:                         1
;     lf82b:                         1
;     lf8cb:                         1
;     lf8cf:                         1
;     lf8d3:                         1
;     lf94f:                         1
;     lfc75:                         1
;     lfc78:                         1
;     lfc81:                         1
;     lfc8a:                         1
;     lfdec:                         1
;     lfff8:                         1
;     load_vector:                   1
;     loop_ce548:                    1
;     loop_ce550:                    1
;     loop_ce5a4:                    1
;     loop_ce5df:                    1
;     loop_ce603:                    1
;     loop_ce663:                    1
;     loop_ce66b:                    1
;     loop_ce68c:                    1
;     loop_ce6d4:                    1
;     loop_ce709:                    1
;     loop_ce815:                    1
;     loop_ce863:                    1
;     loop_ce8b5:                    1
;     loop_ce8f3:                    1
;     loop_ce8fd:                    1
;     loop_ce960:                    1
;     loop_ce96d:                    1
;     loop_ce99c:                    1
;     loop_ce9c5:                    1
;     loop_ce9d7:                    1
;     loop_ce9dc:                    1
;     loop_cea08:                    1
;     loop_cebfd:                    1
;     loop_cec87:                    1
;     loop_ceca8:                    1
;     loop_cecf6:                    1
;     loop_cecf8:                    1
;     loop_ced10:                    1
;     loop_ced19:                    1
;     loop_ced43:                    1
;     loop_ced47:                    1
;     loop_ced49:                    1
;     loop_ced72:                    1
;     loop_cee8c:                    1
;     loop_cef4d:                    1
;     loop_cef50:                    1
;     loop_cef5b:                    1
;     loop_cf09d:                    1
;     loop_cf12e:                    1
;     loop_cf203:                    1
;     loop_cf208:                    1
;     loop_cf313:                    1
;     loop_cf34f:                    1
;     loop_cf3cc:                    1
;     loop_cf40d:                    1
;     loop_cf40f:                    1
;     loop_cf412:                    1
;     loop_cf42a:                    1
;     loop_cf466:                    1
;     loop_cf7df:                    1
;     loop_cf8b8:                    1
;     loop_cf926:                    1
;     loop_cf934:                    1
;     loop_cf9fb:                    1
;     loop_cfa11:                    1
;     loop_cfa79:                    1
;     loop_cfa90:                    1
;     loop_cfad9:                    1
;     loop_cfb0d:                    1
;     loop_cfb42:                    1
;     loop_cfb9c:                    1
;     loop_cfbd5:                    1
;     loop_cfc0a:                    1
;     loop_cfc18:                    1
;     loop_cfcbb:                    1
;     loop_cfd20:                    1
;     loop_cfd54:                    1
;     loop_cfd80:                    1
;     loop_cfd93:                    1
;     loop_cfdf1:                    1
;     loop_cfe14:                    1
;     loop_cfe86:                    1
;     loop_cfea1:                    1
;     loop_cfed6:                    1
;     loop_cff03:                    1
;     loop_cff2e:                    1
;     loop_cff3b:                    1
;     nmi_vector:                    1
;     open_vector:                   1
;     ramtas:                        1
;     return_12:                     1
;     return_13:                     1
;     return_14:                     1
;     return_15:                     1
;     return_16:                     1
;     return_18:                     1
;     return_19:                     1
;     return_2:                      1
;     return_20:                     1
;     return_21:                     1
;     return_22:                     1
;     return_23:                     1
;     return_25:                     1
;     return_4:                      1
;     return_8:                      1
;     reverse_flag:                  1
;     save_vector:                   1
;     scnkey:                        1
;     screen_line_length:            1
;     serial_buffered_char:          1
;     serial_timeout_flag:           1
;     sid_voice1_frequency_low:      1
;     stop:                          1
;     stop_vector:                   1
;     sub_ce518:                     1
;     sub_ce594:                     1
;     sub_ce5a0:                     1
;     sub_ce5d4:                     1
;     sub_ce665:                     1
;     sub_ce68a:                     1
;     sub_ce71d:                     1
;     sub_ceb48:                     1
;     sub_cebf0:                     1
;     sub_cec1b:                     1
;     sub_ced25:                     1
;     sub_ced33:                     1
;     sub_ced5f:                     1
;     sub_ced9a:                     1
;     sub_cedc1:                     1
;     sub_cee7c:                     1
;     sub_cee84:                     1
;     sub_cee97:                     1
;     sub_ceeb8:                     1
;     sub_cef0a:                     1
;     sub_cf04c:                     1
;     sub_cf0d5:                     1
;     sub_cf169:                     1
;     sub_cf415:                     1
;     sub_cf7bc:                     1
;     sub_cf856:                     1
;     sub_cf95f:                     1
;     sub_cf970:                     1
;     sub_cf9ca:                     1
;     sub_cfa4a:                     1
;     sub_cfa60:                     1
;     sub_cfa77:                     1
;     sub_cfa81:                     1
;     sub_cfad7:                     1
;     sub_cfc03:                     1
;     sub_cfc91:                     1
;     sub_cfcac:                     1
;     sub_cfcce:                     1
;     sub_cfe99:                     1
;     sub_cfecb:                     1
;     sub_cff23:                     1
;     udtim:                         1
;     vic_background_colour_0:       1
;     vic_interrupt_status:          1
;     vic_sprite0_x:                 1

; Automatically generated labels:
;     ce1b5
;     ce1db
;     ce4d3
;     ce4dd
;     ce4f1
;     ce50a
;     ce513
;     ce51e
;     ce521
;     ce529
;     ce534
;     ce541
;     ce544
;     ce566
;     ce57a
;     ce589
;     ce59e
;     ce5c9
;     ce5ce
;     ce5ea
;     ce652
;     ce65b
;     ce65d
;     ce673
;     ce6a3
;     ce6a5
;     ce6a7
;     ce6b0
;     ce6b7
;     ce6ba
;     ce6c8
;     ce6ef
;     ce717
;     ce728
;     ce73b
;     ce73e
;     ce746
;     ce74f
;     ce756
;     ce79a
;     ce7aa
;     ce7b1
;     ce7c1
;     ce7d4
;     ce7d6
;     ce7da
;     ce7f3
;     ce7fd
;     ce82c
;     ce83a
;     ce83d
;     ce84d
;     ce871
;     ce876
;     ce885
;     ce88a
;     ce895
;     ce8ad
;     ce8bf
;     ce8c8
;     ce8d1
;     ce8ea
;     ce8fb
;     ce92a
;     ce93c
;     ce949
;     ce97b
;     ce987
;     ce98f
;     ce997
;     ce9a9
;     ce9bb
;     ce9fc
;     cea15
;     cea2f
;     cea49
;     cea50
;     cea69
;     cea6c
;     cea7e
;     cea81
;     ceb61
;     ceb6a
;     ceb95
;     ceba6
;     cebb9
;     cebbc
;     cebee
;     cec08
;     cec0b
;     cec3e
;     cec41
;     cec44
;     cec49
;     cec95
;     ceca2
;     cecae
;     cecb9
;     ceceb
;     ced09
;     ced3a
;     ced56
;     ced69
;     ced83
;     ced89
;     ced98
;     cedcd
;     ceddd
;     cede2
;     cedef
;     cedf3
;     cee02
;     cee1b
;     cee22
;     cee25
;     cee3d
;     cee5e
;     cee69
;     cee72
;     cee78
;     cee7a
;     ceeca
;     ceed8
;     ceedf
;     ceeeb
;     ceef6
;     ceef9
;     ceeff
;     cef21
;     cef2a
;     cef48
;     cef6b
;     cef6e
;     cef74
;     cef7d
;     cef8b
;     cefcc
;     cefe3
;     ceff3
;     ceff9
;     cf00c
;     cf018
;     cf02d
;     cf035
;     cf040
;     cf055
;     cf058
;     cf05f
;     cf0a9
;     cf0d4
;     cf0dc
;     cf0e8
;     cf0fe
;     cf106
;     cf10f
;     cf11c
;     cf11f
;     cf12b
;     cf13b
;     cf142
;     cf148
;     cf15e
;     cf166
;     cf16c
;     cf1b6
;     cf1c5
;     cf1da
;     cf1e2
;     cf1f1
;     cf21d
;     cf22a
;     cf231
;     cf236
;     cf23b
;     cf241
;     cf249
;     cf25f
;     cf26c
;     cf273
;     cf27b
;     cf28d
;     cf2a1
;     cf2bb
;     cf2bf
;     cf2c8
;     cf2cd
;     cf324
;     cf336
;     cf35c
;     cf361
;     cf36a
;     cf386
;     cf388
;     cf3f7
;     cf402
;     cf404
;     cf439
;     cf464
;     cf480
;     cf48f
;     cf492
;     cf49e
;     cf4bb
;     cf4c2
;     cf4ca
;     cf4cd
;     cf4d8
;     cf5dd
;     cf5fa
;     cf647
;     cf657
;     cf65e
;     cf666
;     cf675
;     cf689
;     cf697
;     cf6ba
;     cf6be
;     cf6c2
;     cf6dc
;     cf6f5
;     cf7b4
;     cf7d1
;     cf7d7
;     cf7f6
;     cf7fd
;     cf844
;     cf84d
;     cf85b
;     cf874
;     cf87b
;     cf87e
;     cf885
;     cf888
;     cf890
;     cf89e
;     cf8b2
;     cf8d7
;     cf8e0
;     cf8e9
;     cf8ed
;     cf8fa
;     cf915
;     cf917
;     cf921
;     cf93e
;     cf940
;     cf949
;     cf975
;     cf981
;     cf98f
;     cf9a4
;     cf9ad
;     cf9b6
;     cf9bf
;     cf9d4
;     cf9ef
;     cf9f4
;     cf9fe
;     cfa09
;     cfa15
;     cfa5d
;     cfa8e
;     cfa9e
;     cfaa6
;     cfab0
;     cfabe
;     cfad0
;     cfae9
;     cfaee
;     cfaf1
;     cfb0b
;     cfb1d
;     cfb23
;     cfb36
;     cfb49
;     cfb53
;     cfb81
;     cfb91
;     cfba9
;     cfbad
;     cfbb9
;     cfbc3
;     cfbc6
;     cfbda
;     cfbe4
;     cfbe6
;     cfbfa
;     cfbff
;     cfc12
;     cfc14
;     cfc23
;     cfc25
;     cfc47
;     cfc51
;     cfc5c
;     cfc69
;     cfc6c
;     cfc6f
;     cfc72
;     cfc74
;     cfc77
;     cfc7b
;     cfc7d
;     cfc80
;     cfc83
;     cfc87
;     cfc89
;     cfc9a
;     cfcb8
;     cfcc9
;     cfcd5
;     cfcf4
;     cfd09
;     cfd15
;     cfd1a
;     cfd50
;     cfd88
;     cfd8c
;     cfd91
;     cfda3
;     cfdee
;     cfe00
;     cfe01
;     cfe0f
;     cfe1f
;     cfe25
;     cfe2d
;     cfe54
;     cfe5c
;     cfe94
;     cfea3
;     cfef1
;     cff0d
;     cff3d
;     cff43
;     cff49
;     cff4f
;     cff57
;     cff5b
;     cff61
;     cff71
;     cff7d
;     l0002
;     l0100
;     l0101
;     l0104
;     l0105
;     l0106
;     l0107
;     l01a9
;     l02a9
;     l03ff
;     l08a9
;     l09a9
;     l4fa9
;     l8000
;     l8002
;     l8003
;     la000
;     la002
;     le8da
;     lea87
;     lead1
;     lebc1
;     lebc8
;     lebe7
;     lec4c
;     lec5d
;     lec6e
;     lf33f
;     lf7b6
;     lf80b
;     lf81b
;     lf823
;     lf82b
;     lf8cb
;     lf8cf
;     lf8d3
;     lf94f
;     lfc75
;     lfc78
;     lfc7e
;     lfc81
;     lfc84
;     lfc8a
;     lfdec
;     lfff8
;     loop_ce548
;     loop_ce550
;     loop_ce5a4
;     loop_ce5df
;     loop_ce603
;     loop_ce663
;     loop_ce66b
;     loop_ce68c
;     loop_ce6d4
;     loop_ce709
;     loop_ce815
;     loop_ce863
;     loop_ce8b5
;     loop_ce8f3
;     loop_ce8fd
;     loop_ce960
;     loop_ce96d
;     loop_ce99c
;     loop_ce9c5
;     loop_ce9d7
;     loop_ce9dc
;     loop_cea08
;     loop_cebfd
;     loop_cec87
;     loop_ceca8
;     loop_cecf6
;     loop_cecf8
;     loop_ced10
;     loop_ced19
;     loop_ced43
;     loop_ced47
;     loop_ced49
;     loop_ced72
;     loop_cee8c
;     loop_cef4d
;     loop_cef50
;     loop_cef5b
;     loop_cf09d
;     loop_cf12e
;     loop_cf203
;     loop_cf208
;     loop_cf313
;     loop_cf34f
;     loop_cf3cc
;     loop_cf40d
;     loop_cf40f
;     loop_cf412
;     loop_cf42a
;     loop_cf466
;     loop_cf7df
;     loop_cf8b8
;     loop_cf926
;     loop_cf934
;     loop_cf9fb
;     loop_cfa11
;     loop_cfa79
;     loop_cfa90
;     loop_cfad9
;     loop_cfb0d
;     loop_cfb42
;     loop_cfb9c
;     loop_cfbd5
;     loop_cfc0a
;     loop_cfc18
;     loop_cfcbb
;     loop_cfd20
;     loop_cfd54
;     loop_cfd80
;     loop_cfd93
;     loop_cfdf1
;     loop_cfe14
;     loop_cfe86
;     loop_cfea1
;     loop_cfed6
;     loop_cff03
;     loop_cff2e
;     loop_cff3b
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
;     sub_ce518
;     sub_ce56c
;     sub_ce572
;     sub_ce594
;     sub_ce5a0
;     sub_ce5d4
;     sub_ce5f9
;     sub_ce665
;     sub_ce68a
;     sub_ce702
;     sub_ce71d
;     sub_ce7e5
;     sub_ce95a
;     sub_ce971
;     sub_ce9ff
;     sub_ceb48
;     sub_cebf0
;     sub_cec1b
;     sub_cec7f
;     sub_ced25
;     sub_ced33
;     sub_ced5f
;     sub_ced9a
;     sub_cedc1
;     sub_cedc5
;     sub_cee2b
;     sub_cee7c
;     sub_cee84
;     sub_cee90
;     sub_cee97
;     sub_cee9f
;     sub_ceeac
;     sub_ceeb8
;     sub_ceec5
;     sub_ceece
;     sub_cef0a
;     sub_cf043
;     sub_cf04c
;     sub_cf0c9
;     sub_cf0d5
;     sub_cf169
;     sub_cf1fb
;     sub_cf415
;     sub_cf7bc
;     sub_cf7c1
;     sub_cf7cb
;     sub_cf7dd
;     sub_cf7ef
;     sub_cf804
;     sub_cf833
;     sub_cf856
;     sub_cf86a
;     sub_cf8a9
;     sub_cf8b4
;     sub_cf8bf
;     sub_cf8e3
;     sub_cf8f0
;     sub_cf8fd
;     sub_cf90a
;     sub_cf90e
;     sub_cf924
;     sub_cf932
;     sub_cf95f
;     sub_cf970
;     sub_cf972
;     sub_cf985
;     sub_cf98b
;     sub_cf9ca
;     sub_cf9df
;     sub_cfa1e
;     sub_cfa4a
;     sub_cfa60
;     sub_cfa77
;     sub_cfa81
;     sub_cfad7
;     sub_cfb25
;     sub_cfb40
;     sub_cfb76
;     sub_cfbc9
;     sub_cfc03
;     sub_cfc91
;     sub_cfca0
;     sub_cfcac
;     sub_cfcce
;     sub_cfd1d
;     sub_cfe34
;     sub_cfe7a
;     sub_cfe99
;     sub_cfeb0
;     sub_cfeb9
;     sub_cfec0
;     sub_cfecb
;     sub_cfee5
;     sub_cff17
;     sub_cff23

; Stats:
;
;     Total size (Code + Data) = 8192 bytes
;     Code                     = 5770 bytes (70%)
;     Data                     = 2422 bytes (30%)
;
;     Number of instructions   = 2783
;     Number of data bytes     = 2107 bytes
;     Number of data words     = 38 bytes
;     Number of string bytes   = 277 bytes
;     Number of strings        = 48

