"""memory128, a memory game for the C128's 80 column screen (the VDC), by
Sebastian Dechert (2025), with commodore.c128(), which finds the BASIC
program, and the Kernal, screen editor, SID and MMU addresses it uses. The
game's labels are from the symbol file Kick Assembler made with it (see
orig/memory128/README.txt), and its table of the routines for the keys is
marked as code addresses, since it jumps through it indirectly."""

from commands import *
import commodore

load_prg("orig/memory128.orig", "6502", "c45e3563a7bd53c8ea3197e9849a7a53")
commodore.c128()

# The game's labels, from memory128.sym
for addr, name in {
    0x2000: "src_low",
    0x2001: "src_high",
    0x2002: "dst_low",
    0x2003: "dst_high",
    0x2004: "src_low_crd1",
    0x2005: "src_high_crd1",
    0x2006: "dst_low_crd1",
    0x2007: "dst_high_crd1",
    0x2008: "src_low_crd2",
    0x2009: "src_high_crd2",
    0x200a: "dst_low_crd2",
    0x200b: "dst_high_crd2",
    0x200c: "match",
    0x200d: "match_cnt",
    0x200e: "value_1",
    0x200f: "value_2",
    0x2010: "score",
    0x2011: "param",
    0x2012: "jump_addr",
    0x2030: "start",
    0x206f: "loop_ch",
    0x20a4: "loop_ch2",
    0x20d9: "loop_ch3",
    0x20f6: "main_loop",
    0x2106: "exit",
    0x2114: "handle_input",
    0x211f: "search_loop",
    0x212a: "found_key",
    0x213c: "quit_game",
    0x213d: "no_key",
    0x213e: "invalid_key",
    0x213f: "key_table",
    0x214f: "handler_table",
    0x216f: "show_1",
    0x21aa: "show_2",
    0x21e5: "show_3",
    0x2220: "show_4",
    0x225b: "show_5",
    0x2296: "show_6",
    0x22d1: "show_7",
    0x230c: "show_8",
    0x2347: "show_Q",
    0x2382: "show_W",
    0x23bd: "show_E",
    0x23f8: "show_R",
    0x2433: "show_T",
    0x246e: "show_Y",
    0x24a9: "show_U",
    0x24e4: "show_I",
    0x251f: "card_pos_array",
    0x2541: "special_card_face_array",
    0x2545: "card_face_origin",
    0x2585: "fill_unique_array",
    0x2589: "clear_used",
    0x2591: "fill_loop",
    0x25ab: "array",
    0x25bb: "used",
    0x25cb: "copy",
    0x25df: "out_loop",
    0x25ef: "inner_loop",
    0x25fa: "inc_out_loop",
    0x2615: "card_face_array",
    0x2655: "display_card",
    0x26b9: "match_related",
    0x26ca: "return_from_store_cord_2",
    0x26e8: "set_score_to_zero",
    0x26ed: "jsr_card_reset",
    0x26f0: "return_from_card_match",
    0x26f9: "store_cord_1",
    0x270c: "store_cord_2",
    0x2721: "card_match",
    0x27b8: "card_reset",
    0x2809: "reset_card",
    0x2866: "check_no_cards",
    0x2aca: "show_win",
    0x2b05: "decout",
    0x2b11: "decout_hund_loop",
    0x2b1c: "decout_hund_done",
    0x2b81: "decout_tens_loop",
    0x2b8c: "decout_tens_done",
    0x2c1f: "freqs",
    0x2c27: "play_match_snd",
    0x2c42: "play_loop",
}.items():
    label(addr, name)

# Its variables
byte(0x2000, 1, 0x12)
word(0x2012)

expr(0x2134, "handler_table+1")
expr(0x2137, "jump_addr+1")

# The keys it reads, and the routines for them: it looks the key up in
# key_table, then jumps through handler_table
string(0x213f, 16)
wordentry(0x214f, 16)

# The screens it copies to the VDC's memory (screen codes), whose
# addresses are constants in its source
label(0x3000, "chr_data")       # the main screen
label(0x3800, "chr_dat2")       # the cards
label(0x4000, "chr_dat3")       # "You Win!"
byte(0x3000, 0x3800 - 0x3000, cols=16)
byte(0x3800, 0x4000 - 0x3800, cols=16)
byte(0x4000, 0x47d0 - 0x4000, cols=16)
word(0x251f, 17, 1)
word(0x2541, 2, 1)
word(0x2545, 32, 2)
go()
