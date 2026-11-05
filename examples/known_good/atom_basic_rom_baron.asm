; Assemble with Baron, which writes the program to the file named in its
; section (atom_basic_rom_baron), in the folder given with -p:
;     baron -p . atom_basic_rom_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
basic_error_number      = &0000
basic_line_number       = &0001
parsing_ptr_offset      = &0003
workspace_stack_pointer = &0004
parsing_ptr_low         = &0005
parsing_ptr_high        = &0006
l0007                   = &0007
rnd_seed                = &0008
l000d                   = &000d
l000e                   = &000e
l000f                   = &000f
basic_error_handler     = &0010
text_space_page         = &0012
l0013                   = &0013
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
l0058                   = &0058
l0059                   = &0059
l005a                   = &005a
l005b                   = &005b
l005c                   = &005c
l005d                   = &005d
l005e                   = &005e

; Input buffer (&0100-&013f)
input_buffer = &0100
l013f       = &013f

; String buffer (&0140-&017f)
string_buffer   = &0140

; OS vectors (&0200-&021f)
brkvec  = &0202
wrcvec  = &0208
bptvec  = &0216

; Workspace (&0220-&03ff)
l023f   = &023f
l0240   = &0240
l024a   = &024a
l024b   = &024b
l0255   = &0255
l0256   = &0256
l0260   = &0260
l0261   = &0261
l026b   = &026b
l026c   = &026c
l0276   = &0276
l0277   = &0277
l0281   = &0281
l0282   = &0282
l028c   = &028c
l028d   = &028d
l0297   = &0297
l0298   = &0298
l02a2   = &02a2
l02a3   = &02a3
l02ad   = &02ad
l02ae   = &02ae
l02b8   = &02b8
l02b9   = &02b9
l02c3   = &02c3
l02c4   = &02c4
l02ce   = &02ce
l02cf   = &02cf
l02dc   = &02dc
l02dd   = &02dd
l0321   = &0321
l0322   = &0322
l0339   = &0339
l033a   = &033a
l033c   = &033c
l0357   = &0357
l0372   = &0372
l038c   = &038c
l038d   = &038d
l038e   = &038e

; I/O (&b000-&bfff)
ppi_port_b  = &b001

; Floating point ROM (&d000-&dfff)
fp_rom_statement_handler = &d002
fp_rom_function_handler = &d004

; Kernel ROM (&f000-&ffca)
test_array_variable = &f02e
interpret_command   = &f04b
command_run         = &f141

; OS entry points (&ffcb-&fff9)
OSSHUT  = &ffcb
OSFIND  = &ffce
OSBPUT  = &ffd1
OSBGET  = &ffd4
OSSTAR  = &ffd7
OSRDAR  = &ffda
OSSAVE  = &ffdd
OSLOAD  = &ffe0
OSRDCH  = &ffe3
OSECHO  = &ffe6
OSCRLF  = &ffed
OSWRCH  = &fff4
OSCLI   = &fff7

section pydis, org = &c000, filename = "atom_basic_rom_baron"

.pydis_start
.keywords
    equs "<=>"                                                        ; c000: 3c 3d 3e    <=>
    equb &fe                                                          ; c003: fe          .
    equs "-+"                                                         ; c004: 2d 2b       -+
    equb >sub_cc8dc                                                   ; c006: c8          .
    equs "#(!?RTLCAPEGBF"                                             ; c007: 23 28 21... #(!
    equb >test_array_variable                                         ; c015: f0          .
    equs "T"                                                          ; c016: 54          T
    equb &ff                                                          ; c017: ff          .
    equs "O"                                                          ; c018: 4f          O
    equb >for_to                                                      ; c019: cb          .
    equs "S"                                                          ; c01a: 53          S
    equb >sub_ccbbe                                                   ; c01b: cb          .
    equs "TEP"                                                        ; c01c: 54 45 50    TEP
    equb >for_step                                                    ; c01f: cb          .
    equs "T"                                                          ; c020: 54          T
    equb >if_then                                                     ; c021: c3          .
    equs "HEN"                                                        ; c022: 48 45 4e    HEN
    equb >if_then                                                     ; c025: c3          .
    equs """$"                                                        ; c026: 22 24       "$
    equb >sub_cceb6                                                   ; c028: ce          .
    equb >sub_ccebf                                                   ; c029: ce          .
    equb >sub_cccb6                                                   ; c02a: cc          .
    equs "$,"                                                         ; c02b: 24 2c       $,
    equb >next_statement                                              ; c02d: c5          .
    equs "$&;", &0d, ","                                              ; c02e: 24 26 3b... $&;
    equb >sub_cc33f                                                   ; c033: c3          .
    equb >sub_cc54a                                                   ; c034: c5          .
    equb >basic_rts                                                   ; c035: c2          .
    equs ">"                                                          ; c036: 3e          >
    equb >op_not_equal                                                ; c037: c7          .
    equs "="                                                          ; c038: 3d          =
    equb >op_less_or_equal                                            ; c039: c7          .
    equb >op_less                                                     ; c03a: c7          .
    equb >op_equal                                                    ; c03b: c7          .
    equs "="                                                          ; c03c: 3d          =
    equb >op_greater_or_equal                                         ; c03d: c7          .
    equb >op_greater                                                  ; c03e: c7          .
    equb >sub_cc8c1                                                   ; c03f: c8          .
    equs "R"                                                          ; c040: 52          R
    equb >op_or                                                       ; c041: c7          .
    equb >sub_cc731                                                   ; c042: c7          .
    equs "OA"                                                         ; c043: 4f 41       OA
    equb &fe                                                          ; c045: fe          .
    equs "$"                                                          ; c046: 24          $
    equb >sub_cc753                                                   ; c047: c7          .
    equs "H"                                                          ; c048: 48          H
    equb >function_ch                                                 ; c049: c9          .
    equs "EN"                                                         ; c04a: 45 4e       EN
    equb >function_len                                                ; c04c: c9          .
    equs "ND"                                                         ; c04d: 4e 44       ND
    equb >op_and                                                      ; c04f: c7          .
    equb >function_hex                                                ; c050: c9          .
    equb >function_bracket                                            ; c051: c9          .
    equb >function_word_fetch                                         ; c052: c9          .
    equb >function_byte_fetch                                         ; c053: c9          .
    equs "ND"                                                         ; c054: 4e 44       ND
    equb >function_rnd                                                ; c056: c9          .
    equs "OP"                                                         ; c057: 4f 50       OP
    equb >function_top                                                ; c059: c9          .
    equs "OUNT"                                                       ; c05a: 4f 55 4e... OUN
    equb >function_count                                              ; c05e: c9          .
    equs "BS"                                                         ; c05f: 42 53       BS
    equb >function_abs                                                ; c061: c9          .
    equs "TR"                                                         ; c062: 54 52       TR
    equb >function_ptr                                                ; c064: cf          .
    equs "XT"                                                         ; c065: 58 54       XT
    equb >function_ext                                                ; c067: cf          .
    equs "ET"                                                         ; c068: 45 54       ET
    equb >function_get                                                ; c06a: cf          .
    equs "GET"                                                        ; c06b: 47 45 54    GET
    equb >function_bget                                               ; c06e: cf          .
    equs "IN"                                                         ; c06f: 49 4e       IN
    equb >function_fin                                                ; c071: cf          .
    equs "OUT"                                                        ; c072: 4f 55 54    OUT
    equb >function_fout                                               ; c075: cf          .
    equb >sub_cc390                                                   ; c076: c3          .
    equb >sub_cc335                                                   ; c077: c3          .
    equs "RINT"                                                       ; c078: 52 49 4e... RIN
    equb >statement_print                                             ; c07c: c3          .
    equs "NLUNIGRF!?$PDLSB*E"                                         ; c07d: 4e 4c 55... NLU
    equb >interpret_command                                           ; c08f: f0          .
    equs "AVE"                                                        ; c090: 41 56 45    AVE
    equb >statement_save                                              ; c093: cf          .
    equs "EW"                                                         ; c094: 45 57       EW
    equb >statement_new                                               ; c096: c2          .
    equs "O"                                                          ; c097: 4f          O
    equb >statement_do                                                ; c098: cc          .
    equs "ET"                                                         ; c099: 45 54       ET
    equb >statement_let                                               ; c09b: c3          .
    equs "INK"                                                        ; c09c: 49 4e 4b    INK
    equb >statement_link                                              ; c09f: c3          .
    equs "IST"                                                        ; c0a0: 49 53 54    IST
    equb >statement_list                                              ; c0a3: ca          .
    equs "OAD"                                                        ; c0a4: 4f 41 44    OAD
    equb >statement_load                                              ; c0a7: ce          .
    equs "NTIL"                                                       ; c0a8: 4e 54 49... NTI
    equb >statement_until                                             ; c0ac: cc          .
    equs "EXT"                                                        ; c0ad: 45 58 54    EXT
    equb >statement_next                                              ; c0b0: ca          .
    equs "F"                                                          ; c0b1: 46          F
    equb >statement_if                                                ; c0b2: c5          .
    equs "NPUT"                                                       ; c0b3: 4e 50 55... NPU
    equb >statement_input                                             ; c0b7: cc          .
    equs "OSUB"                                                       ; c0b8: 4f 53 55... OSU
    equb >statement_gosub                                             ; c0bc: cb          .
    equs "OTO"                                                        ; c0bd: 4f 54 4f    OTO
    equb >statement_goto                                              ; c0c0: cc          .
    equs "ETURN"                                                      ; c0c1: 45 54 55... ETU
    equb >statement_return                                            ; c0c6: cb          .
    equs "EM"                                                         ; c0c7: 45 4d       EM
    equb >statement_rem                                               ; c0c9: c5          .
    equs "UN"                                                         ; c0ca: 55 4e       UN
    equb >command_run                                                 ; c0cc: f1          .
    equs "OR"                                                         ; c0cd: 4f 52       OR
    equb >statement_for                                               ; c0cf: cb          .
    equs "ND"                                                         ; c0d0: 4e 44       ND
    equb >statement_end                                               ; c0d2: cd          .
    equs "GET"                                                        ; c0d3: 47 45 54    GET
    equb >statement_sget                                              ; c0d6: cf          .
    equs "PUT"                                                        ; c0d7: 50 55 54    PUT
    equb >statement_sput                                              ; c0da: cf          .
    equs "HUT"                                                        ; c0db: 48 55 54    HUT
    equb >statement_shut                                              ; c0de: cf          .
    equs "PUT"                                                        ; c0df: 50 55 54    PUT
    equb >statement_bput                                              ; c0e2: cf          .
    equs "TR"                                                         ; c0e3: 54 52       TR
    equb >statement_ptr                                               ; c0e5: cf          .
    equs "UT"                                                         ; c0e6: 55 54       UT
    equb >statement_put                                               ; c0e8: cf          .
    equb >statement_word_store                                        ; c0e9: c3          .
    equb >statement_byte_store                                        ; c0ea: c4          .
    equb >statement_string_store                                      ; c0eb: cd          .
    equb >statement_os_command                                        ; c0ec: c4          .
    equs ","                                                          ; c0ed: 2c          ,
; &c0ee referenced 2 times by &c24b, &c271
.keyword_next
    equb &fe                                                          ; c0ee: fe          .
    equb &36                                                          ; c0ef: 36          6
    equb &3b                                                          ; c0f0: 3b          ;
    equb &3c                                                          ; c0f1: 3c          <
    equb &c0                                                          ; c0f2: c0          .
    equb &3f                                                          ; c0f3: 3f          ?
    equb 6                                                            ; c0f4: 06          .
    equb <sub_cc8dc                                                   ; c0f5: dc          .
    equb &50                                                          ; c0f6: 50          P
    equb &51                                                          ; c0f7: 51          Q
    equb &52                                                          ; c0f8: 52          R
    equb &53                                                          ; c0f9: 53          S
    equb &54                                                          ; c0fa: 54          T
    equb &57                                                          ; c0fb: 57          W
    equb &4a                                                          ; c0fc: 4a          J
    equb &5a                                                          ; c0fd: 5a          Z
    equb &5f                                                          ; c0fe: 5f          _
    equb &62                                                          ; c0ff: 62          b
    equb &65                                                          ; c100: 65          e
    equb &68                                                          ; c101: 68          h
    equb &6b                                                          ; c102: 6b          k
    equb &6f                                                          ; c103: 6f          o
    equb <test_array_variable                                         ; c104: 2e          .
    equb &18                                                          ; c105: 18          .
    equb &ac                                                          ; c106: ac          .
    equb &17                                                          ; c107: 17          .
    equb <for_to                                                      ; c108: 81          .
    equb &1c                                                          ; c109: 1c          .
    equb <sub_ccbbe                                                   ; c10a: be          .
    equb &17                                                          ; c10b: 17          .
    equb &17                                                          ; c10c: 17          .
    equb &17                                                          ; c10d: 17          .
    equb <for_step                                                    ; c10e: a2          .
    equb &22                                                          ; c10f: 22          "
    equb <if_then                                                     ; c110: 1b          .
    equb &17                                                          ; c111: 17          .
    equb &17                                                          ; c112: 17          .
    equb &17                                                          ; c113: 17          .
    equb <if_then                                                     ; c114: 1b          .
    equb &29                                                          ; c115: 29          )
    equb &28                                                          ; c116: 28          (
    equb <sub_cceb6                                                   ; c117: b6          .
    equb <sub_ccebf                                                   ; c118: bf          .
    equb <sub_cccb6                                                   ; c119: b6          .
    equb &2a                                                          ; c11a: 2a          *
    equb &b7                                                          ; c11b: b7          .
    equb <next_statement                                              ; c11c: 58          X
    equb &76                                                          ; c11d: 76          v
    equb &77                                                          ; c11e: 77          w
    equb &34                                                          ; c11f: 34          4
    equb &34                                                          ; c120: 34          4
    equb &7c                                                          ; c121: 7c          |
    equb <sub_cc33f                                                   ; c122: 3f          ?
    equb <sub_cc54a                                                   ; c123: 4a          J
    equb <basic_rts                                                   ; c124: 78          x
    equb &38                                                          ; c125: 38          8
    equb <op_not_equal                                                ; c126: 6d          m
    equb &3a                                                          ; c127: 3a          :
    equb <op_less_or_equal                                            ; c128: 64          d
    equb <op_less                                                     ; c129: 74          t
    equb <op_equal                                                    ; c12a: 5b          [
    equb &3e                                                          ; c12b: 3e          >
    equb <op_greater_or_equal                                         ; c12c: 7b          {
    equb <op_greater                                                  ; c12d: 82          .
    equb <sub_cc8c1                                                   ; c12e: c1          .
    equb &45                                                          ; c12f: 45          E
    equb <op_or                                                       ; c130: 22          "
    equb <sub_cc731                                                   ; c131: 31          1
    equb &40                                                          ; c132: 40          @
    equb &4d                                                          ; c133: 4d          M
    equb &4d                                                          ; c134: 4d          M
    equb &42                                                          ; c135: 42          B
    equb <sub_cc753                                                   ; c136: 53          S
    equb &15                                                          ; c137: 15          .
    equb <function_ch                                                 ; c138: d2          .
    equb &15                                                          ; c139: 15          .
    equb &15                                                          ; c13a: 15          .
    equb <function_len                                                ; c13b: bd          .
    equb &45                                                          ; c13c: 45          E
    equb &45                                                          ; c13d: 45          E
    equb <op_and                                                      ; c13e: 14          .
    equb <function_hex                                                ; c13f: 0a          .
    equb <function_bracket                                            ; c140: 44          D
    equb <function_word_fetch                                         ; c141: 5f          _
    equb <function_byte_fetch                                         ; c142: 4c          L
    equb &15                                                          ; c143: 15          .
    equb &15                                                          ; c144: 15          .
    equb <function_rnd                                                ; c145: 86          .
    equb &15                                                          ; c146: 15          .
    equb &15                                                          ; c147: 15          .
    equb <function_top                                                ; c148: 73          s
    equb &48                                                          ; c149: 48          H
    equb &15                                                          ; c14a: 15          .
    equb &15                                                          ; c14b: 15          .
    equb &15                                                          ; c14c: 15          .
    equb <function_count                                              ; c14d: 7a          z
    equb &15                                                          ; c14e: 15          .
    equb &15                                                          ; c14f: 15          .
    equb <function_abs                                                ; c150: 02          .
    equb &15                                                          ; c151: 15          .
    equb &15                                                          ; c152: 15          .
    equb <function_ptr                                                ; c153: 29          )
    equb &15                                                          ; c154: 15          .
    equb &15                                                          ; c155: 15          .
    equb <function_ext                                                ; c156: 28          (
    equb &15                                                          ; c157: 15          .
    equb &15                                                          ; c158: 15          .
    equb <function_get                                                ; c159: 66          f
    equb &15                                                          ; c15a: 15          .
    equb &15                                                          ; c15b: 15          .
    equb &15                                                          ; c15c: 15          .
    equb <function_bget                                               ; c15d: 5b          [
    equb &72                                                          ; c15e: 72          r
    equb &15                                                          ; c15f: 15          .
    equb <function_fin                                                ; c160: a6          .
    equb &15                                                          ; c161: 15          .
    equb &15                                                          ; c162: 15          .
    equb &15                                                          ; c163: 15          .
    equb <function_fout                                               ; c164: a7          .
    equb <sub_cc390                                                   ; c165: 90          .
    equb <sub_cc335                                                   ; c166: 35          5
    equb &e3                                                          ; c167: e3          .
    equb &8f                                                          ; c168: 8f          .
    equb &8f                                                          ; c169: 8f          .
    equb &8f                                                          ; c16a: 8f          .
    equb <statement_print                                             ; c16b: 34          4
    equb &94                                                          ; c16c: 94          .
    equb &a0                                                          ; c16d: a0          .
    equb &a8                                                          ; c16e: a8          .
    equb &ad                                                          ; c16f: ad          .
    equb &b1                                                          ; c170: b1          .
    equb &bd                                                          ; c171: bd          .
    equb &c1                                                          ; c172: c1          .
    equb &cd                                                          ; c173: cd          .
    equb &e9                                                          ; c174: e9          .
    equb &ea                                                          ; c175: ea          .
    equb &eb                                                          ; c176: eb          .
    equb &78                                                          ; c177: 78          x
    equb &97                                                          ; c178: 97          .
    equb &99                                                          ; c179: 99          .
    equb &d3                                                          ; c17a: d3          .
    equb &df                                                          ; c17b: df          .
    equb &ec                                                          ; c17c: ec          .
    equb &d0                                                          ; c17d: d0          .
    equb <interpret_command                                           ; c17e: 4b          K
    equb &8f                                                          ; c17f: 8f          .
    equb &8f                                                          ; c180: 8f          .
    equb &8f                                                          ; c181: 8f          .
    equb <statement_save                                              ; c182: 0a          .
    equb &8f                                                          ; c183: 8f          .
    equb &ad                                                          ; c184: ad          .
    equb <statement_new                                               ; c185: ad          .
    equb &8f                                                          ; c186: 8f          .
    equb <statement_do                                                ; c187: f0          .
    equb &9c                                                          ; c188: 9c          .
    equb &8f                                                          ; c189: 8f          .
    equb <statement_let                                               ; c18a: 25          %
    equb &8f                                                          ; c18b: 8f          .
    equb &8f                                                          ; c18c: 8f          .
    equb &8f                                                          ; c18d: 8f          .
    equb <statement_link                                              ; c18e: b2          .
    equb &a4                                                          ; c18f: a4          .
    equb &9c                                                          ; c190: 9c          .
    equb &8f                                                          ; c191: 8f          .
    equb <statement_list                                              ; c192: 51          Q
    equb &99                                                          ; c193: 99          .
    equb &8f                                                          ; c194: 8f          .
    equb &8f                                                          ; c195: 8f          .
    equb <statement_load                                              ; c196: ed          .
    equb &8f                                                          ; c197: 8f          .
    equb &8f                                                          ; c198: 8f          .
    equb &8f                                                          ; c199: 8f          .
    equb &8f                                                          ; c19a: 8f          .
    equb <statement_until                                             ; c19b: d2          .
    equb &8f                                                          ; c19c: 8f          .
    equb &8f                                                          ; c19d: 8f          .
    equb &8f                                                          ; c19e: 8f          .
    equb <statement_next                                              ; c19f: cd          .
    equb &b3                                                          ; c1a0: b3          .
    equb <statement_if                                                ; c1a1: 66          f
    equb &8f                                                          ; c1a2: 8f          .
    equb &8f                                                          ; c1a3: 8f          .
    equb &8f                                                          ; c1a4: 8f          .
    equb &8f                                                          ; c1a5: 8f          .
    equb <statement_input                                             ; c1a6: 81          .
    equb &8f                                                          ; c1a7: 8f          .
    equb &8f                                                          ; c1a8: 8f          .
    equb &8f                                                          ; c1a9: 8f          .
    equb &8f                                                          ; c1aa: 8f          .
    equb <statement_gosub                                             ; c1ab: d2          .
    equb &8f                                                          ; c1ac: 8f          .
    equb &b8                                                          ; c1ad: b8          .
    equb &8f                                                          ; c1ae: 8f          .
    equb <statement_goto                                              ; c1af: 05          .
    equb &ca                                                          ; c1b0: ca          .
    equb &c7                                                          ; c1b1: c7          .
    equb &8f                                                          ; c1b2: 8f          .
    equb &8f                                                          ; c1b3: 8f          .
    equb &8f                                                          ; c1b4: 8f          .
    equb <statement_return                                            ; c1b5: ec          .
    equb &8f                                                          ; c1b6: 8f          .
    equb &8f                                                          ; c1b7: 8f          .
    equb <statement_rem                                               ; c1b8: 75          u
    equb &8f                                                          ; c1b9: 8f          .
    equb &8f                                                          ; c1ba: 8f          .
    equb <command_run                                                 ; c1bb: 41          A
    equb &8f                                                          ; c1bc: 8f          .
    equb &8f                                                          ; c1bd: 8f          .
    equb <statement_for                                               ; c1be: 57          W
    equb &8f                                                          ; c1bf: 8f          .
    equb &8f                                                          ; c1c0: 8f          .
    equb <statement_end                                               ; c1c1: 98          .
    equb &d7                                                          ; c1c2: d7          .
    equb &8f                                                          ; c1c3: 8f          .
    equb &8f                                                          ; c1c4: 8f          .
    equb <statement_sget                                              ; c1c5: e3          .
    equb &db                                                          ; c1c6: db          .
    equb &8f                                                          ; c1c7: 8f          .
    equb &8f                                                          ; c1c8: 8f          .
    equb <statement_sput                                              ; c1c9: c5          .
    equb &90                                                          ; c1ca: 90          .
    equb &8f                                                          ; c1cb: 8f          .
    equb &8f                                                          ; c1cc: 8f          .
    equb <statement_shut                                              ; c1cd: b6          .
    equb &8f                                                          ; c1ce: 8f          .
    equb &8f                                                          ; c1cf: 8f          .
    equb &8f                                                          ; c1d0: 8f          .
    equb <statement_bput                                              ; c1d1: 8f          .
    equb &e6                                                          ; c1d2: e6          .
    equb &8f                                                          ; c1d3: 8f          .
    equb <statement_ptr                                               ; c1d4: 47          G
    equb &8f                                                          ; c1d5: 8f          .
    equb &8f                                                          ; c1d6: 8f          .
    equb <statement_put                                               ; c1d7: 95          .
    equb <statement_word_store                                        ; c1d8: ee          .
    equb <statement_byte_store                                        ; c1d9: 06          .
    equb <statement_string_store                                      ; c1da: 5c          \
    equb <statement_os_command                                        ; c1db: 0f          .
    equb &35                                                          ; c1dc: 35          5
; &c1dd referenced 2 times by &c285, &c28d
.characters
    equs "-+|:"                                                       ; c1dd: 2d 2b 7c... -+|
    equb &fe                                                          ; c1e1: fe          .
    equs "*/%!?&"                                                     ; c1e2: 2a 2f 25... */%
    equb &fe                                                          ; c1e8: fe          .
    equb ')'                                                          ; c1e9: 29          )
    equb &ff                                                          ; c1ea: ff          .
    equb '='                                                          ; c1eb: 3d          =
    equb &ff                                                          ; c1ec: ff          .
    equs "!?$"                                                        ; c1ed: 21 3f 24    !?$
    equb &ff                                                          ; c1f0: ff          .
    equs "=!?"                                                        ; c1f1: 3d 21 3f    =!?
    equb &ff                                                          ; c1f4: ff          .
    equb &27, '"'                                                     ; c1f5: 27 22       '"
    equb &fe                                                          ; c1f7: fe          .
; &c1f8 referenced 1 time by &c29b
.character_routines_low
    equb <op_subtract                                                 ; c1f8: b7          .
    equb <op_add                                                      ; c1f9: 9a          .
    equb <op_bitwise_or                                               ; c1fa: d3          .
    equb <op_bitwise_eor                                              ; c1fb: ef          .
    equb &ef                                                          ; c1fc: ef          .
    equb <op_multiply                                                 ; c1fd: 13          .
    equb <op_divide                                                   ; c1fe: 5e          ^
    equb <op_remainder                                                ; c1ff: 70          p
    equb <op_word_index                                               ; c200: b3          .
    equb <op_byte_index                                               ; c201: 9c          .
    equb <op_bitwise_and                                              ; c202: 7b          {
    equb &7b                                                          ; c203: 7b          {
    equb <basic_rts                                                   ; c204: 78          x
    equb &78                                                          ; c205: 78          x
    equb <basic_rts                                                   ; c206: 78          x
    equb &78                                                          ; c207: 78          x
    equb <statement_word_store                                        ; c208: ee          .
    equb <statement_byte_store                                        ; c209: 06          .
    equb <statement_string_store                                      ; c20a: 5c          \
    equb &5c                                                          ; c20b: 5c          \
    equb <sub_cc3e5                                                   ; c20c: e5          .
    equb <sub_ccd75                                                   ; c20d: 75          u
    equb <sub_ccd7b                                                   ; c20e: 7b          {
    equb &7b                                                          ; c20f: 7b          {
    equb <print_new_line                                              ; c210: 6f          o
    equb <print_quoted_string                                         ; c211: 7a          z
; &c212 referenced 1 time by &c296
.character_routines_high
    equb >op_subtract                                                 ; c212: c7          .
    equb >op_add                                                      ; c213: c7          .
    equb >op_bitwise_or                                               ; c214: c7          .
    equb >op_bitwise_eor                                              ; c215: c7          .
    equb &c7                                                          ; c216: c7          .
    equb >op_multiply                                                 ; c217: c8          .
    equb >op_divide                                                   ; c218: c8          .
    equb >op_remainder                                                ; c219: c8          .
    equb >op_word_index                                               ; c21a: c8          .
    equb >op_byte_index                                               ; c21b: c8          .
    equb >op_bitwise_and                                              ; c21c: c8          .
    equb &c8                                                          ; c21d: c8          .
    equb >basic_rts                                                   ; c21e: c2          .
    equb &c2                                                          ; c21f: c2          .
    equb >basic_rts                                                   ; c220: c2          .
    equb &c2                                                          ; c221: c2          .
    equb >statement_word_store                                        ; c222: c3          .
    equb >statement_byte_store                                        ; c223: c4          .
    equb >statement_string_store                                      ; c224: cd          .
    equb &cd                                                          ; c225: cd          .
    equb >sub_cc3e5                                                   ; c226: c3          .
    equb >sub_ccd75                                                   ; c227: cd          .
    equb >sub_ccd7b                                                   ; c228: cd          .
    equb &cd                                                          ; c229: cd          .
    equb >print_new_line                                              ; c22a: c3          .
    equb >print_quoted_string                                         ; c22b: c3          .

; &c22c referenced 2 times by &cfc5, &cfe3
.sub_cc22c
    jsr sub_ccf3e                                                     ; c22c: 20 3e cf     >.
    sty l000f                                                         ; c22f: 84 0f       ..
; &c231 referenced 3 times by &ca66, &cab8, &cf7e
.skip_comma
    ldx #&ed                                                          ; c231: a2 ed       ..
; &c233 referenced 14 times by &c318, &c322, &c33c, &c572, &c711, &c72e, &c758, &c8be, &c8ff, &cb7e, &cb9f, &cc8b, &ccb3, &ceb3
.match_keyword
    ldy parsing_ptr_offset                                            ; c233: a4 03       ..
    dey                                                               ; c235: 88          .
; &c236 referenced 1 time by &c23b
.loop_cc236
    iny                                                               ; c236: c8          .
    lda (parsing_ptr_low),y                                           ; c237: b1 05       ..
    cmp #&20 ; ' '                                                    ; c239: c9 20       .
    beq loop_cc236                                                    ; c23b: f0 f9       ..
    sty l005e                                                         ; c23d: 84 5e       .^
    sta l0052                                                         ; c23f: 85 52       .R
; &c241 referenced 1 time by &c249
.loop_cc241
    inx                                                               ; c241: e8          .
    lda keywords-1,x                                                  ; c242: bd ff bf    ...
    bmi cc26b                                                         ; c245: 30 24       0$
    cmp l0052                                                         ; c247: c5 52       .R
    bne loop_cc241                                                    ; c249: d0 f6       ..
; &c24b referenced 1 time by &c262
.loop_cc24b
    lda keyword_next,x                                                ; c24b: bd ee c0    ...
    tax                                                               ; c24e: aa          .
; &c24f referenced 1 time by &c258
.loop_cc24f
    inx                                                               ; c24f: e8          .
    iny                                                               ; c250: c8          .
    lda keywords-1,x                                                  ; c251: bd ff bf    ...
    bmi cc26b                                                         ; c254: 30 15       0.
    cmp (parsing_ptr_low),y                                           ; c256: d1 05       ..
    beq loop_cc24f                                                    ; c258: f0 f5       ..
    lda (parsing_ptr_low),y                                           ; c25a: b1 05       ..
    cmp #&2e ; '.'                                                    ; c25c: c9 2e       ..
    beq cc264                                                         ; c25e: f0 04       ..
    ldy l005e                                                         ; c260: a4 5e       .^
    bpl loop_cc24b                                                    ; c262: 10 e7       ..
; &c264 referenced 2 times by &c25e, &c268
.cc264
    inx                                                               ; c264: e8          .
    lda keywords-1,x                                                  ; c265: bd ff bf    ...
    bpl cc264                                                         ; c268: 10 fa       ..
    iny                                                               ; c26a: c8          .
; &c26b referenced 2 times by &c245, &c254
.cc26b
    cmp #&fe                                                          ; c26b: c9 fe       ..
    bcs cc2aa                                                         ; c26d: b0 3b       .;
    sta l0053                                                         ; c26f: 85 53       .S
    lda keyword_next,x                                                ; c271: bd ee c0    ...
    bcc cc29f                                                         ; c274: 90 29       .) ; ALWAYS branch

; &c276 referenced 1 time by &c2aa
.cc276
    ldx workspace_stack_pointer                                       ; c276: a6 04       ..
.basic_rts
    rts                                                               ; c278: 60          `

; &c279 referenced 3 times by &c4de, &cb5c, &ceae
.expect_equals
    ldx #&0e                                                          ; c279: a2 0e       ..
; &c27b referenced 6 times by &c32c, &c331, &c374, &c797, &c810, &c949
.match_character
    ldy parsing_ptr_offset                                            ; c27b: a4 03       ..
    dey                                                               ; c27d: 88          .
; &c27e referenced 1 time by &c283
.loop_cc27e
    iny                                                               ; c27e: c8          .
    lda (parsing_ptr_low),y                                           ; c27f: b1 05       ..
    cmp #&20 ; ' '                                                    ; c281: c9 20       .
    beq loop_cc27e                                                    ; c283: f0 f9       ..
    cmp characters,x                                                  ; c285: dd dd c1    ...
    beq cc296                                                         ; c288: f0 0c       ..
    sta l0052                                                         ; c28a: 85 52       .R
; &c28c referenced 1 time by &c294
.loop_cc28c
    inx                                                               ; c28c: e8          .
    lda characters,x                                                  ; c28d: bd dd c1    ...
    bmi cc2a8                                                         ; c290: 30 16       0.
    cmp l0052                                                         ; c292: c5 52       .R
    bne loop_cc28c                                                    ; c294: d0 f6       ..
; &c296 referenced 1 time by &c288
.cc296
    lda character_routines_high,x                                     ; c296: bd 12 c2    ...
    sta l0053                                                         ; c299: 85 53       .S
    lda character_routines_low,x                                      ; c29b: bd f8 c1    ...
    iny                                                               ; c29e: c8          .
; &c29f referenced 1 time by &c274
.cc29f
    sta l0052                                                         ; c29f: 85 52       .R
    sty parsing_ptr_offset                                            ; c2a1: 84 03       ..
    ldx workspace_stack_pointer                                       ; c2a3: a6 04       ..
; &c2a5 referenced 1 time by &c3c1
.sub_cc2a5
    jmp (l0052)                                                       ; c2a5: 6c 52 00    lR.

; &c2a8 referenced 1 time by &c290
.cc2a8
    cmp #&fe                                                          ; c2a8: c9 fe       ..
; &c2aa referenced 1 time by &c26d
.cc2aa
    beq cc276                                                         ; c2aa: f0 ca       ..
.basic_brk
    brk                                                               ; c2ac: 00          .

.statement_new
    jsr check_end_of_statement                                        ; c2ad: 20 e4 c4     ..
    bne basic_start                                                   ; c2b0: d0 04       ..
.basic_start_2900
    lda #&29 ; ')'                                                    ; c2b2: a9 29       .)
    sta text_space_page                                               ; c2b4: 85 12       ..
; &c2b6 referenced 1 time by &c2b0
.basic_start
    lda #&0d                                                          ; c2b6: a9 0d       ..
    ldy text_space_page                                               ; c2b8: a4 12       ..
    sty l000e                                                         ; c2ba: 84 0e       ..
    ldy #0                                                            ; c2bc: a0 00       ..
    sty l000d                                                         ; c2be: 84 0d       ..
    sta (l000d),y                                                     ; c2c0: 91 0d       ..
    lda #&ff                                                          ; c2c2: a9 ff       ..
    iny                                                               ; c2c4: c8          .  ; Y=1
    sta (l000d),y                                                     ; c2c5: 91 0d       ..
    iny                                                               ; c2c7: c8          .  ; Y=2
    sty l000d                                                         ; c2c8: 84 0d       ..
    lda #8                                                            ; c2ca: a9 08       ..
    sta l0321                                                         ; c2cc: 8d 21 03    .!.
; &c2cf referenced 5 times by &c547, &cab5, &cd34, &cdb9, &ce80
.cc2cf
    lda #&3e ; '>'                                                    ; c2cf: a9 3e       .>
    cld                                                               ; c2d1: d8          .
    jsr sub_ccd0f                                                     ; c2d2: 20 0f cd     ..
    ldx #1                                                            ; c2d5: a2 01       ..
    stx parsing_ptr_high                                              ; c2d7: 86 06       ..
    dex                                                               ; c2d9: ca          .  ; X=0
    stx parsing_ptr_low                                               ; c2da: 86 05       ..
    stx basic_line_number                                             ; c2dc: 86 01       ..
    stx basic_line_number+1                                           ; c2de: 86 02       ..

    ; Set BRK vector to 'handle_brkvec'
    lda #<handle_brkvec                                               ; c2e0: a9 d8       ..
    sta brkvec                                                        ; c2e2: 8d 02 02    ...
    lda #>handle_brkvec                                               ; c2e5: a9 c9       ..
    sta brkvec+1                                                      ; c2e7: 8d 03 02    ...

    lda #&e7                                                          ; c2ea: a9 e7       ..
    sta basic_error_handler                                           ; c2ec: 85 10       ..
    lda #&c9                                                          ; c2ee: a9 c9       ..
    sta basic_error_handler+1                                         ; c2f0: 85 11       ..
; &c2f2 referenced 1 time by &c9e4
.cc2f2
    ldx #&ff                                                          ; c2f2: a2 ff       ..
    txs                                                               ; c2f4: 9a          .
    lda #0                                                            ; c2f5: a9 00       ..
    sta workspace_stack_pointer                                       ; c2f7: 85 04       ..
    sta parsing_ptr_offset                                            ; c2f9: 85 03       ..
    sta int_workspace_stack_low-1                                     ; c2fb: 85 15       ..
    sta l0013                                                         ; c2fd: 85 13       ..
    sta int_workspace_stack_low-2                                     ; c2ff: 85 14       ..
    ldx #&34 ; '4'                                                    ; c301: a2 34       .4
; &c303 referenced 1 time by &c307
.loop_cc303
    sta l038c,x                                                       ; c303: 9d 8c 03    ...
    dex                                                               ; c306: ca          .
    bne loop_cc303                                                    ; c307: d0 fa       ..
    jsr skip_spaces                                                   ; c309: 20 34 c4     4.
    bcs cc32f                                                         ; c30c: b0 21       .!
    jsr sub_cc46a                                                     ; c30e: 20 6a c4     j.
    bcc cc316                                                         ; c311: 90 03       ..
    jmp ccdc9                                                         ; c313: 4c c9 cd    L..

; &c316 referenced 1 time by &c311
.cc316
    ldx #&7d ; '}'                                                    ; c316: a2 7d       .}
    jmp match_keyword                                                 ; c318: 4c 33 c2    L3.

; &c31b referenced 5 times by &c563, &c586, &cbcf, &cc02, &cd06
.if_then
    jsr skip_spaces                                                   ; c31b: 20 34 c4     4.
    bcs cc32f                                                         ; c31e: b0 0f       ..
    ldx #&7f                                                          ; c320: a2 7f       ..
    jmp match_keyword                                                 ; c322: 4c 33 c2    L3.

.statement_let
    jsr skip_spaces                                                   ; c325: 20 34 c4     4.
    bcs cc32f                                                         ; c328: b0 05       ..
    ldx #&10                                                          ; c32a: a2 10       ..
    jmp match_character                                               ; c32c: 4c 7b c2    L{.

; &c32f referenced 3 times by &c30c, &c31e, &c328
.cc32f
    ldx #&14                                                          ; c32f: a2 14       ..
    jmp match_character                                               ; c331: 4c 7b c2    L{.

.statement_print
    sec                                                               ; c334: 38          8
.sub_cc335
    ror l000f                                                         ; c335: 66 0f       f.
; &c337 referenced 4 times by &c368, &c36d, &c3a2, &c3af
.cc337
    jsr cc372                                                         ; c337: 20 72 c3     r.
    ldx #&2e ; '.'                                                    ; c33a: a2 2e       ..
    jmp match_keyword                                                 ; c33c: 4c 33 c2    L3.

.sub_cc33f
    jsr sub_cc78b                                                     ; c33f: 20 8b c7     ..
    jsr pop_to_52                                                     ; c342: 20 cb c3     ..
    lda l000f                                                         ; c345: a5 0f       ..
    bmi cc36a                                                         ; c347: 30 21       0!
    ldx #0                                                            ; c349: a2 00       ..
    stx int_workspace_stack_mid1+2                                    ; c34b: 86 27       .'
    ldy #0                                                            ; c34d: a0 00       ..
; &c34f referenced 1 time by &c363
.loop_cc34f
    lda l0052,y                                                       ; c34f: b9 52 00    .R.
    pha                                                               ; c352: 48          H
    and #&0f                                                          ; c353: 29 0f       ).
    sta int_workspace_stack_high+2,x                                  ; c355: 95 45       .E
    pla                                                               ; c357: 68          h
    lsr a                                                             ; c358: 4a          J
    lsr a                                                             ; c359: 4a          J
    lsr a                                                             ; c35a: 4a          J
    lsr a                                                             ; c35b: 4a          J
    inx                                                               ; c35c: e8          .
    sta int_workspace_stack_high+2,x                                  ; c35d: 95 45       .E
    inx                                                               ; c35f: e8          .
    iny                                                               ; c360: c8          .
    cpy #4                                                            ; c361: c0 04       ..
    bcc loop_cc34f                                                    ; c363: 90 ea       ..
    jsr cc5c8                                                         ; c365: 20 c8 c5     ..
    bmi cc337                                                         ; c368: 30 cd       0.
; &c36a referenced 1 time by &c347
.cc36a
    jsr print_line_number                                             ; c36a: 20 89 c5     ..
    bmi cc337                                                         ; c36d: 30 c8       0.
.print_new_line
    jsr sub_ccd54                                                     ; c36f: 20 54 cd     T.
; &c372 referenced 3 times by &c337, &c38b, &cc81
.cc372
    ldx #&18                                                          ; c372: a2 18       ..
    jmp match_character                                               ; c374: 4c 7b c2    L{.

; &c377 referenced 2 times by &c385, &c38e
.cc377
    jsr print_character                                               ; c377: 20 4c ca     L.
.print_quoted_string
    lda (parsing_ptr_low),y                                           ; c37a: b1 05       ..
    iny                                                               ; c37c: c8          .
    cmp #&0d                                                          ; c37d: c9 0d       ..
    beq cc39d                                                         ; c37f: f0 1c       ..
    sty parsing_ptr_offset                                            ; c381: 84 03       ..
    cmp #&22 ; '"'                                                    ; c383: c9 22       ."
    bne cc377                                                         ; c385: d0 f0       ..
    lda (parsing_ptr_low),y                                           ; c387: b1 05       ..
    cmp #&22 ; '"'                                                    ; c389: c9 22       ."
    bne cc372                                                         ; c38b: d0 e5       ..
    iny                                                               ; c38d: c8          .
    bcs cc377                                                         ; c38e: b0 e7       .. ; ALWAYS branch

.sub_cc390
    jsr sub_cc78b                                                     ; c390: 20 8b c7     ..
    jsr pop_to_52                                                     ; c393: 20 cb c3     ..
    ora l0054                                                         ; c396: 05 54       .T
    ora l0053                                                         ; c398: 05 53       .S
    beq cc3aa                                                         ; c39a: f0 0e       ..
; overlapping: ldy #0                                                 ; c39c: a0 00       ..
    equb &a0                                                          ; c39c: a0          .

; &c39d referenced 1 time by &c37f
.cc39d
    brk                                                               ; c39d: 00          .

; &c39e referenced 1 time by &c3a8
.loop_cc39e
    lda (l0052),y                                                     ; c39e: b1 52       .R
    cmp #&0d                                                          ; c3a0: c9 0d       ..
    beq cc337                                                         ; c3a2: f0 93       ..
    jsr print_character                                               ; c3a4: 20 4c ca     L.
    iny                                                               ; c3a7: c8          .
    bne loop_cc39e                                                    ; c3a8: d0 f4       ..
; &c3aa referenced 1 time by &c39a
.cc3aa
    lda l0052                                                         ; c3aa: a5 52       .R
    jsr print_character                                               ; c3ac: 20 4c ca     L.
    jmp cc337                                                         ; c3af: 4c 37 c3    L7.

.statement_link
    jsr evaluate_expression_to_52                                     ; c3b2: 20 c8 c3     ..
    jsr check_end_of_statement                                        ; c3b5: 20 e4 c4     ..
    lda l0322                                                         ; c3b8: ad 22 03    .".
    ldx l0339                                                         ; c3bb: ae 39 03    .9.
    ldy l033a                                                         ; c3be: ac 3a 03    .:.
    jsr sub_cc2a5                                                     ; c3c1: 20 a5 c2     ..
    cld                                                               ; c3c4: d8          .
    jmp next_statement_no_check                                       ; c3c5: 4c 5b c5    L[.

; &c3c8 referenced 1 time by &c3b2
.evaluate_expression_to_52
    jsr evaluate_expression                                           ; c3c8: 20 bc c8     ..
; &c3cb referenced 8 times by &c342, &c393, &c9c0, &ce97, &ceb9, &cf4d, &cf84, &cfe9
.pop_to_52
    ldy #&52 ; 'R'                                                    ; c3cb: a0 52       .R
; &c3cd referenced 4 times by &c66f, &c67b, &ccbb, &cd64
.sub_cc3cd
    dex                                                               ; c3cd: ca          .
    stx workspace_stack_pointer                                       ; c3ce: 86 04       ..
    lda int_workspace_stack_low,x                                     ; c3d0: b5 16       ..
    sta basic_error_number,y                                          ; c3d2: 99 00 00    ...
    lda int_workspace_stack_mid1,x                                    ; c3d5: b5 25       .%
    sta basic_line_number,y                                           ; c3d7: 99 01 00    ...
    lda int_workspace_stack_mid2,x                                    ; c3da: b5 34       .4
    sta basic_line_number+1,y                                         ; c3dc: 99 02 00    ...
    lda int_workspace_stack_high,x                                    ; c3df: b5 43       .C
    sta parsing_ptr_offset,y                                          ; c3e1: 99 03 00    ...
    rts                                                               ; c3e4: 60          `

.sub_cc3e5
    jsr sub_cc4e1                                                     ; c3e5: 20 e1 c4     ..
    jsr sub_cca2f                                                     ; c3e8: 20 2f ca     /.
    jmp next_statement_no_check                                       ; c3eb: 4c 5b c5    L[.

.statement_word_store
    jsr evaluate_expression                                           ; c3ee: 20 bc c8     ..
; &c3f1 referenced 1 time by &cd78
.assign_expression
    jsr sub_cce93                                                     ; c3f1: 20 93 ce     ..
    lda int_workspace_stack_mid1+1,x                                  ; c3f4: b5 26       .&
    iny                                                               ; c3f6: c8          .
    sta (l0052),y                                                     ; c3f7: 91 52       .R
    iny                                                               ; c3f9: c8          .
    lda int_workspace_stack_mid2+1,x                                  ; c3fa: b5 35       .5
    sta (l0052),y                                                     ; c3fc: 91 52       .R
    iny                                                               ; c3fe: c8          .
    lda int_workspace_stack_high+1,x                                  ; c3ff: b5 44       .D
    sta (l0052),y                                                     ; c401: 91 52       .R
    jmp next_statement_no_check                                       ; c403: 4c 5b c5    L[.

.statement_byte_store
    jsr evaluate_expression                                           ; c406: 20 bc c8     ..
; &c409 referenced 1 time by &cd7e
.cc409
    jsr sub_cce93                                                     ; c409: 20 93 ce     ..
    jmp next_statement_no_check                                       ; c40c: 4c 5b c5    L[.

.statement_os_command
    ldx #0                                                            ; c40f: a2 00       ..
; &c411 referenced 1 time by &c41c
.loop_cc411
    lda (parsing_ptr_low),y                                           ; c411: b1 05       ..
    sta input_buffer,x                                                ; c413: 9d 00 01    ...
    sty parsing_ptr_offset                                            ; c416: 84 03       ..
    iny                                                               ; c418: c8          .
    inx                                                               ; c419: e8          .
    cmp #&0d                                                          ; c41a: c9 0d       ..
    bne loop_cc411                                                    ; c41c: d0 f3       ..
    jsr OSCLI                                                         ; c41e: 20 f7 ff     .. ; Run the command in the input buffer
    jmp next_statement                                                ; c421: 4c 58 c5    LX.

; &c424 referenced 2 times by &c550, &ca24
.check_fp_rom
lc425 = check_fp_rom+1
    lda fp_rom_id                                                     ; c424: ad 00 d0    ...
; overlapping: brk                                                    ; c425: 00          .
; &c425 referenced 1 time by &c468
    cmp #&aa                                                          ; c427: c9 aa       ..
    bne cc463                                                         ; c429: d0 38       .8
    lsr a                                                             ; c42b: 4a          J
    cmp fp_rom_id+1                                                   ; c42c: cd 01 d0    ...
    bne cc463                                                         ; c42f: d0 32       .2
    ldy l005e                                                         ; c431: a4 5e       .^
    rts                                                               ; c433: 60          `

; &c434 referenced 8 times by &c309, &c31b, &c325, &c465, &c8dc, &cacd, &cb57, &cc84
.skip_spaces
    ldy parsing_ptr_offset                                            ; c434: a4 03       ..
    bpl cc43b                                                         ; c436: 10 03       ..
; &c438 referenced 1 time by &c43f
.loop_cc438
    iny                                                               ; c438: c8          .
    sty parsing_ptr_offset                                            ; c439: 84 03       ..
; &c43b referenced 1 time by &c436
.cc43b
    lda (parsing_ptr_low),y                                           ; c43b: b1 05       ..
    cmp #&20 ; ' '                                                    ; c43d: c9 20       .
    beq loop_cc438                                                    ; c43f: f0 f7       ..
    cmp #&5b ; '['                                                    ; c441: c9 5b       .[
    bcs cc463                                                         ; c443: b0 1e       ..
    sbc #&3f ; '?'                                                    ; c445: e9 3f       .? ; Carry is clear, so subtracting 64
    bcc return_1                                                      ; c447: 90 1b       ..
    ldx workspace_stack_pointer                                       ; c449: a6 04       ..
    sta int_workspace_stack_low,x                                     ; c44b: 95 16       ..
    iny                                                               ; c44d: c8          .
    lda (parsing_ptr_low),y                                           ; c44e: b1 05       ..
    cmp #&2e ; '.'                                                    ; c450: c9 2e       ..
    beq cc463                                                         ; c452: f0 0f       ..
    cmp #&5b ; '['                                                    ; c454: c9 5b       .[
    bcs cc45c                                                         ; c456: b0 04       ..
    cmp #&40 ; '@'                                                    ; c458: c9 40       .@
    bcs cc463                                                         ; c45a: b0 07       ..
; &c45c referenced 1 time by &c456
.cc45c
    inx                                                               ; c45c: e8          .
    stx workspace_stack_pointer                                       ; c45d: 86 04       ..
    sec                                                               ; c45f: 38          8
    sty parsing_ptr_offset                                            ; c460: 84 03       ..
    rts                                                               ; c462: 60          `

; &c463 referenced 6 times by &c429, &c42f, &c443, &c452, &c45a, &c4d4
.cc463
    clc                                                               ; c463: 18          .
; &c464 referenced 1 time by &c447
.return_1
    rts                                                               ; c464: 60          `

; &c465 referenced 3 times by &ca61, &ca6b, &cabd
.sub_cc465
    jsr skip_spaces                                                   ; c465: 20 34 c4     4.
    bcs lc425                                                         ; c468: b0 bb       ..
; &c46a referenced 2 times by &c30e, &c8f8
.sub_cc46a
lc46b = sub_cc46a+1
    ldx #0                                                            ; c46a: a2 00       ..
; overlapping: brk                                                    ; c46b: 00          .
; &c46b referenced 4 times by &c495, &c49e, &c4b8, &c4cd
    ldy parsing_ptr_offset                                            ; c46c: a4 03       ..
    stx l0052                                                         ; c46e: 86 52       .R
    stx l0053                                                         ; c470: 86 53       .S
    stx l0054                                                         ; c472: 86 54       .T
    stx l0055                                                         ; c474: 86 55       .U
    dey                                                               ; c476: 88          .
; &c477 referenced 1 time by &c4d1
.cc477
    iny                                                               ; c477: c8          .
    lda (parsing_ptr_low),y                                           ; c478: b1 05       ..
    sec                                                               ; c47a: 38          8
    sbc #&30 ; '0'                                                    ; c47b: e9 30       .0
    bmi cc4d3                                                         ; c47d: 30 54       0T
    cmp #&0a                                                          ; c47f: c9 0a       ..
    bcs cc4d3                                                         ; c481: b0 50       .P
    ldx l0053                                                         ; c483: a6 53       .S
    pha                                                               ; c485: 48          H
    lda l0055                                                         ; c486: a5 55       .U
    pha                                                               ; c488: 48          H
    lda l0054                                                         ; c489: a5 54       .T
    pha                                                               ; c48b: 48          H
    lda l0052                                                         ; c48c: a5 52       .R
    asl a                                                             ; c48e: 0a          .
    rol l0053                                                         ; c48f: 26 53       &S
    rol l0054                                                         ; c491: 26 54       &T
    rol l0055                                                         ; c493: 26 55       &U
    bmi lc46b                                                         ; c495: 30 d4       0.
    asl a                                                             ; c497: 0a          .
    rol l0053                                                         ; c498: 26 53       &S
    rol l0054                                                         ; c49a: 26 54       &T
    rol l0055                                                         ; c49c: 26 55       &U
    bmi lc46b                                                         ; c49e: 30 cb       0.
    adc l0052                                                         ; c4a0: 65 52       eR
    sta l0052                                                         ; c4a2: 85 52       .R
    txa                                                               ; c4a4: 8a          .
    adc l0053                                                         ; c4a5: 65 53       eS
    sta l0053                                                         ; c4a7: 85 53       .S
    pla                                                               ; c4a9: 68          h
    adc l0054                                                         ; c4aa: 65 54       eT
    sta l0054                                                         ; c4ac: 85 54       .T
    pla                                                               ; c4ae: 68          h
    adc l0055                                                         ; c4af: 65 55       eU
    asl l0052                                                         ; c4b1: 06 52       .R
    rol l0053                                                         ; c4b3: 26 53       &S
    rol l0054                                                         ; c4b5: 26 54       &T
    rol a                                                             ; c4b7: 2a          *
    bmi lc46b                                                         ; c4b8: 30 b1       0.
    sta l0055                                                         ; c4ba: 85 55       .U
    pla                                                               ; c4bc: 68          h
    adc l0052                                                         ; c4bd: 65 52       eR
    sta l0052                                                         ; c4bf: 85 52       .R
    bcc cc4cf                                                         ; c4c1: 90 0c       ..
    inc l0053                                                         ; c4c3: e6 53       .S
    bne cc4cf                                                         ; c4c5: d0 08       ..
    inc l0054                                                         ; c4c7: e6 54       .T
    bne cc4cf                                                         ; c4c9: d0 04       ..
    inc l0055                                                         ; c4cb: e6 55       .U
    bmi lc46b                                                         ; c4cd: 30 9c       0.
; &c4cf referenced 3 times by &c4c1, &c4c5, &c4c9
.cc4cf
    ldx #&ff                                                          ; c4cf: a2 ff       ..
    bne cc477                                                         ; c4d1: d0 a4       .. ; ALWAYS branch

; &c4d3 referenced 2 times by &c47d, &c481
.cc4d3
    txa                                                               ; c4d3: 8a          .
    beq cc463                                                         ; c4d4: f0 8d       ..
; &c4d6 referenced 1 time by &c941
.cc4d6
    sec                                                               ; c4d6: 38          8
    sty parsing_ptr_offset                                            ; c4d7: 84 03       ..
    ldy #&52 ; 'R'                                                    ; c4d9: a0 52       .R
    jmp cc99f                                                         ; c4db: 4c 9f c9    L..

; &c4de referenced 2 times by &ce93, &cf4a
.sub_cc4de
    jsr expect_equals                                                 ; c4de: 20 79 c2     y.
; &c4e1 referenced 3 times by &c3e5, &cf81, &cfe6
.sub_cc4e1
    jsr sub_cc78b                                                     ; c4e1: 20 8b c7     ..
; &c4e4 referenced 12 times by &c2ad, &c3b5, &c50c, &c558, &ca72, &cbec, &cc08, &cd98, &ce83, &cefd, &cfb9, &cfcb
.check_end_of_statement
    ldy parsing_ptr_offset                                            ; c4e4: a4 03       ..
    dey                                                               ; c4e6: 88          .
; &c4e7 referenced 1 time by &c4ec
.loop_cc4e7
    iny                                                               ; c4e7: c8          .
    lda (parsing_ptr_low),y                                           ; c4e8: b1 05       ..
    cmp #&20 ; ' '                                                    ; c4ea: c9 20       .
    beq loop_cc4e7                                                    ; c4ec: f0 f9       ..
    cmp #&3b ; ';'                                                    ; c4ee: c9 3b       .;
    beq consolidate_text_pointer                                      ; c4f0: f0 04       ..
    cmp #&0d                                                          ; c4f2: c9 0d       ..
    bne lc55c                                                         ; c4f4: d0 66       .f
; &c4f6 referenced 7 times by &c4f0, &c534, &c539, &c54b, &cc38, &ccf7, &cebf
.consolidate_text_pointer
    clc                                                               ; c4f6: 18          .
; &c4f7 referenced 1 time by &c52e
.cc4f7
    tya                                                               ; c4f7: 98          .
    adc parsing_ptr_low                                               ; c4f8: 65 05       e.
    sta parsing_ptr_low                                               ; c4fa: 85 05       ..
    bcc cc500                                                         ; c4fc: 90 02       ..
    inc parsing_ptr_high                                              ; c4fe: e6 06       ..
; &c500 referenced 2 times by &c4fc, &ceab
.cc500
    ldy #1                                                            ; c500: a0 01       ..
    sty parsing_ptr_offset                                            ; c502: 84 03       ..
    lda ppi_port_b                                                    ; c504: ad 01 b0    ...
    and #&20 ; ' '                                                    ; c507: 29 20       )  ; Test keyboard column 5
    beq cc547                                                         ; c509: f0 3c       .<
; &c50b referenced 1 time by &c514
.return_2
    rts                                                               ; c50b: 60          `

; &c50c referenced 2 times by &cbbe, &cbd5
.sub_cc50c
    jsr check_end_of_statement                                        ; c50c: 20 e4 c4     ..
    dey                                                               ; c50f: 88          .
    lda (parsing_ptr_low),y                                           ; c510: b1 05       ..
    cmp #&3b ; ';'                                                    ; c512: c9 3b       .;
    beq return_2                                                      ; c514: f0 f5       ..
    lda parsing_ptr_high                                              ; c516: a5 06       ..
    cmp #1                                                            ; c518: c9 01       ..
    beq lc596                                                         ; c51a: f0 7a       .z
; &c51c referenced 1 time by &c583
.sub_cc51c
    iny                                                               ; c51c: c8          .
    lda (parsing_ptr_low),y                                           ; c51d: b1 05       ..
    bmi lc55c                                                         ; c51f: 30 3b       0;
    sta basic_line_number+1                                           ; c521: 85 02       ..
    iny                                                               ; c523: c8          .
    lda (parsing_ptr_low),y                                           ; c524: b1 05       ..
    sta basic_line_number                                             ; c526: 85 01       ..
    iny                                                               ; c528: c8          .
    lda (parsing_ptr_low),y                                           ; c529: b1 05       ..
    dey                                                               ; c52b: 88          .
    cmp #&61 ; 'a'                                                    ; c52c: c9 61       .a
    bcc cc4f7                                                         ; c52e: 90 c7       ..
    sbc #&61 ; 'a'                                                    ; c530: e9 61       .a
    cmp #&1b                                                          ; c532: c9 1b       ..
    bcs consolidate_text_pointer                                      ; c534: b0 c0       ..
    iny                                                               ; c536: c8          .
    asl a                                                             ; c537: 0a          .
    tax                                                               ; c538: aa          .
    jsr consolidate_text_pointer                                      ; c539: 20 f6 c4     ..
    lda parsing_ptr_low                                               ; c53c: a5 05       ..
    sta l038d,x                                                       ; c53e: 9d 8d 03    ...
    lda parsing_ptr_high                                              ; c541: a5 06       ..
    sta l038e,x                                                       ; c543: 9d 8e 03    ...
    rts                                                               ; c546: 60          `

; &c547 referenced 2 times by &c509, &c581
.cc547
    jmp cc2cf                                                         ; c547: 4c cf c2    L..

.sub_cc54a
    dey                                                               ; c54a: 88          .
    jsr consolidate_text_pointer                                      ; c54b: 20 f6 c4     ..
    bne next_statement_no_check                                       ; c54e: d0 0b       ..
.unknown_statement
    jsr check_fp_rom                                                  ; c550: 20 24 c4     $.
    bcc next_statement                                                ; c553: 90 03       ..
    jmp (fp_rom_statement_handler)                                    ; c555: 6c 02 d0    l..

; &c558 referenced 5 times by &c421, &c553, &cb54, &cce2, &cd72
.next_statement
    jsr check_end_of_statement                                        ; c558: 20 e4 c4     ..
; &c55b referenced 10 times by &c3c5, &c3eb, &c403, &c40c, &c54e, &ce90, &cf25, &cf58, &cf92, &cfc2
.next_statement_no_check
lc55c = next_statement_no_check+1
    ldy #0                                                            ; c55b: a0 00       ..
; overlapping: brk                                                    ; c55c: 00          .
; &c55c referenced 2 times by &c4f4, &c51f
    lda (parsing_ptr_low),y                                           ; c55d: b1 05       ..
    cmp #&3b ; ';'                                                    ; c55f: c9 3b       .;
    bne cc57d                                                         ; c561: d0 1a       ..
    jmp if_then                                                       ; c563: 4c 1b c3    L..

.statement_if
    jsr sub_cc70c                                                     ; c566: 20 0c c7     ..
    dex                                                               ; c569: ca          .
    stx workspace_stack_pointer                                       ; c56a: 86 04       ..
    lda int_workspace_stack_low,x                                     ; c56c: b5 16       ..
    beq statement_rem                                                 ; c56e: f0 05       ..
    ldx #&20 ; ' '                                                    ; c570: a2 20       .
    jmp match_keyword                                                 ; c572: 4c 33 c2    L3.

; &c575 referenced 1 time by &c56e
.statement_rem
    lda #&0d                                                          ; c575: a9 0d       ..
    dey                                                               ; c577: 88          .
; &c578 referenced 1 time by &c57b
.loop_cc578
    iny                                                               ; c578: c8          .
    cmp (parsing_ptr_low),y                                           ; c579: d1 05       ..
    bne loop_cc578                                                    ; c57b: d0 fb       ..
; &c57d referenced 1 time by &c561
.cc57d
    lda parsing_ptr_high                                              ; c57d: a5 06       ..
    cmp #1                                                            ; c57f: c9 01       ..
    beq cc547                                                         ; c581: f0 c4       ..
    jsr sub_cc51c                                                     ; c583: 20 1c c5     ..
    jmp if_then                                                       ; c586: 4c 1b c3    L..

; &c589 referenced 2 times by &c36a, &ca82
.print_line_number
    lda int_workspace_stack_high                                      ; c589: a5 43       .C
    sta int_workspace_stack_mid1+2                                    ; c58b: 85 27       .'
    bpl cc593                                                         ; c58d: 10 04       ..
    inx                                                               ; c58f: e8          .
    jsr cc8c4                                                         ; c590: 20 c4 c8     ..
; &c593 referenced 1 time by &c58d
.cc593
    ldx #9                                                            ; c593: a2 09       ..
; &c595 referenced 1 time by &c5c4
.cc595
lc596 = cc595+1
    lda #0                                                            ; c595: a9 00       ..
; overlapping: brk                                                    ; c596: 00          .
; &c596 referenced 1 time by &c51a
    sta int_workspace_stack_high+2,x                                  ; c597: 95 45       .E
; &c599 referenced 1 time by &c5bf
.cc599
    sec                                                               ; c599: 38          8
    lda int_workspace_stack_low                                       ; c59a: a5 16       ..
    sbc powers_of_ten_byte_0,x                                        ; c59c: fd 08 c6    ...
    pha                                                               ; c59f: 48          H
    lda int_workspace_stack_mid1                                      ; c5a0: a5 25       .%
    sbc powers_of_ten_byte_1,x                                        ; c5a2: fd 10 c6    ...
    pha                                                               ; c5a5: 48          H
    lda int_workspace_stack_mid2                                      ; c5a6: a5 34       .4
    sbc powers_of_ten_byte_2,x                                        ; c5a8: fd 1a c6    ...
    tay                                                               ; c5ab: a8          .
    lda int_workspace_stack_high                                      ; c5ac: a5 43       .C
    sbc powers_of_ten_byte_3,x                                        ; c5ae: fd 24 c6    .$.
    bcc cc5c1                                                         ; c5b1: 90 0e       ..
    sta int_workspace_stack_high                                      ; c5b3: 85 43       .C
    sty int_workspace_stack_mid2                                      ; c5b5: 84 34       .4
    pla                                                               ; c5b7: 68          h
    sta int_workspace_stack_mid1                                      ; c5b8: 85 25       .%
    pla                                                               ; c5ba: 68          h
    sta int_workspace_stack_low                                       ; c5bb: 85 16       ..
    inc int_workspace_stack_high+2,x                                  ; c5bd: f6 45       .E
    bne cc599                                                         ; c5bf: d0 d8       ..
; &c5c1 referenced 1 time by &c5b1
.cc5c1
    pla                                                               ; c5c1: 68          h
    pla                                                               ; c5c2: 68          h
    dex                                                               ; c5c3: ca          .
    bpl cc595                                                         ; c5c4: 10 cf       ..
    ldx #&0a                                                          ; c5c6: a2 0a       ..
; &c5c8 referenced 2 times by &c365, &c5cd
.cc5c8
    dex                                                               ; c5c8: ca          .
    beq cc5cf                                                         ; c5c9: f0 04       ..
    lda int_workspace_stack_high+2,x                                  ; c5cb: b5 45       .E
    beq cc5c8                                                         ; c5cd: f0 f9       ..
; &c5cf referenced 1 time by &c5c9
.cc5cf
    stx l0052                                                         ; c5cf: 86 52       .R
    bit int_workspace_stack_mid1+2                                    ; c5d1: 24 27       $'
    bpl cc5d7                                                         ; c5d3: 10 02       ..
    inc l0052                                                         ; c5d5: e6 52       .R
; &c5d7 referenced 1 time by &c5d3
.cc5d7
    sec                                                               ; c5d7: 38          8
    lda l0321                                                         ; c5d8: ad 21 03    .!.
    beq cc5df                                                         ; c5db: f0 02       ..
    sbc #1                                                            ; c5dd: e9 01       ..
; &c5df referenced 1 time by &c5db
.cc5df
    sbc l0052                                                         ; c5df: e5 52       .R
    beq cc5ee                                                         ; c5e1: f0 0b       ..
    bcc cc5ee                                                         ; c5e3: 90 09       ..
    tay                                                               ; c5e5: a8          .
; &c5e6 referenced 1 time by &c5ec
.loop_cc5e6
    lda #&20 ; ' '                                                    ; c5e6: a9 20       .
    jsr print_character                                               ; c5e8: 20 4c ca     L.
    dey                                                               ; c5eb: 88          .
    bne loop_cc5e6                                                    ; c5ec: d0 f8       ..
; &c5ee referenced 2 times by &c5e1, &c5e3
.cc5ee
    bit int_workspace_stack_mid1+2                                    ; c5ee: 24 27       $'
    bpl cc5f7                                                         ; c5f0: 10 05       ..
    lda #&2d ; '-'                                                    ; c5f2: a9 2d       .-
    jsr print_character                                               ; c5f4: 20 4c ca     L.
; &c5f7 referenced 2 times by &c5f0, &c605
.cc5f7
    lda int_workspace_stack_high+2,x                                  ; c5f7: b5 45       .E
.print_hex_number
    cmp #&0a                                                          ; c5f9: c9 0a       ..
    bcc cc5ff                                                         ; c5fb: 90 02       ..
    adc #6                                                            ; c5fd: 69 06       i. ; Carry is set, so adding 7
; &c5ff referenced 1 time by &c5fb
.cc5ff
    adc #&30 ; '0'                                                    ; c5ff: 69 30       i0
    jsr print_character                                               ; c601: 20 4c ca     L.
    dex                                                               ; c604: ca          .
    bpl cc5f7                                                         ; c605: 10 f0       ..
    rts                                                               ; c607: 60          `

; The powers of ten, 1 to 10^9, as four tables of bytes, least significant first (the
; first table's last two bytes are the second's first two)
; &c608 referenced 1 time by &c59c
.powers_of_ten_byte_0
    equb 1, &0a, &64, &e8, &10, &a0, &40, &80                         ; c608: 01 0a 64... ..d
; &c610 referenced 1 time by &c5a2
.powers_of_ten_byte_1
    equb 0, 0, 0, 3, &27, &86, &42, &96, &e1, &ca                     ; c610: 00 00 00... ...
; &c61a referenced 1 time by &c5a8
.powers_of_ten_byte_2
    equb 0, 0, 0, 0, 0, 1, &0f, &98, &f5, &9a                         ; c61a: 00 00 00... ...
; &c624 referenced 1 time by &c5ae
.powers_of_ten_byte_3
    equb 0, 0, 0, 0, 0, 0, 0, 0, 5, &3b                               ; c624: 00 00 00... ...

; &c62e referenced 3 times by &ca75, &cc0f, &cdcb
.sub_cc62e
    dec workspace_stack_pointer                                       ; c62e: c6 04       ..
    ldx workspace_stack_pointer                                       ; c630: a6 04       ..
    ldy #0                                                            ; c632: a0 00       ..
    sty l0058                                                         ; c634: 84 58       .X
    lda text_space_page                                               ; c636: a5 12       ..
    sta l0059                                                         ; c638: 85 59       .Y
    dey                                                               ; c63a: 88          .  ; Y=&ff
; &c63b referenced 2 times by &c64a, &c652
.cc63b
    lda #&0d                                                          ; c63b: a9 0d       ..
; &c63d referenced 1 time by &c640
.loop_cc63d
    iny                                                               ; c63d: c8          .
    cmp (l0058),y                                                     ; c63e: d1 58       .X
    bne loop_cc63d                                                    ; c640: d0 fb       ..
    jsr sub_ccea1                                                     ; c642: 20 a1 ce     ..
    lda (l0058),y                                                     ; c645: b1 58       .X
    iny                                                               ; c647: c8          .
    cmp int_workspace_stack_mid1,x                                    ; c648: d5 25       .%
    bcc cc63b                                                         ; c64a: 90 ef       ..
    bne return_3                                                      ; c64c: d0 12       ..
    lda (l0058),y                                                     ; c64e: b1 58       .X
    cmp int_workspace_stack_low,x                                     ; c650: d5 16       ..
    bcc cc63b                                                         ; c652: 90 e7       ..
    bne return_3                                                      ; c654: d0 0a       ..
    sta basic_line_number                                             ; c656: 85 01       ..
    lda int_workspace_stack_mid1,x                                    ; c658: b5 25       .%
    sta basic_line_number+1                                           ; c65a: 85 02       ..
    jsr sub_ccea1                                                     ; c65c: 20 a1 ce     ..
    clc                                                               ; c65f: 18          .
; &c660 referenced 2 times by &c64c, &c654
.return_3
    rts                                                               ; c660: 60          `

; &c661 referenced 2 times by &c689, &c813
.sub_cc661
    jsr evaluate_expression                                           ; c661: 20 bc c8     ..
    lda int_workspace_stack_high-1,x                                  ; c664: b5 42       .B
    eor int_workspace_stack_high-2,x                                  ; c666: 55 41       UA
    sta l0052                                                         ; c668: 85 52       .R
    jsr sub_cc905                                                     ; c66a: 20 05 c9     ..
    ldy #&53 ; 'S'                                                    ; c66d: a0 53       .S
    jsr sub_cc3cd                                                     ; c66f: 20 cd c3     ..
    lda int_workspace_stack_high-1,x                                  ; c672: b5 42       .B
    sta int_workspace_stack_high,x                                    ; c674: 95 43       .C
    jsr sub_cc907                                                     ; c676: 20 07 c9     ..
    ldy #&57 ; 'W'                                                    ; c679: a0 57       .W
    jsr sub_cc3cd                                                     ; c67b: 20 cd c3     ..
; overlapping: ldy #0                                                 ; c67e: a0 00       ..
    equb &a0                                                          ; c67e: a0          .

; &c67f referenced 1 time by &c691
.loop_cc67f
    brk                                                               ; c67f: 00          .

    sty l005b                                                         ; c680: 84 5b       .[
    sty l005c                                                         ; c682: 84 5c       .\
    sty l005d                                                         ; c684: 84 5d       .]
    sty l005e                                                         ; c686: 84 5e       .^
    rts                                                               ; c688: 60          `

; &c689 referenced 2 times by &c85e, &c870
.sub_cc689
    jsr sub_cc661                                                     ; c689: 20 61 c6     a.
    lda l0054                                                         ; c68c: a5 54       .T
    jsr sub_cc705                                                     ; c68e: 20 05 c7     ..
    beq loop_cc67f                                                    ; c691: f0 ec       ..
    ldy #&20 ; ' '                                                    ; c693: a0 20       .
; &c695 referenced 1 time by &c6a0
.loop_cc695
    dey                                                               ; c695: 88          .
    beq return_4                                                      ; c696: f0 41       .A
    asl l0057                                                         ; c698: 06 57       .W
    rol l0058                                                         ; c69a: 26 58       &X
    rol l0059                                                         ; c69c: 26 59       &Y
    rol l005a                                                         ; c69e: 26 5a       &Z
    bpl loop_cc695                                                    ; c6a0: 10 f3       ..
; &c6a2 referenced 1 time by &c6d7
.cc6a2
    rol l0057                                                         ; c6a2: 26 57       &W
    rol l0058                                                         ; c6a4: 26 58       &X
    rol l0059                                                         ; c6a6: 26 59       &Y
    rol l005a                                                         ; c6a8: 26 5a       &Z
    rol l005b                                                         ; c6aa: 26 5b       &[
    rol l005c                                                         ; c6ac: 26 5c       &\
    rol l005d                                                         ; c6ae: 26 5d       &]
    rol l005e                                                         ; c6b0: 26 5e       &^
    sec                                                               ; c6b2: 38          8
    lda l005b                                                         ; c6b3: a5 5b       .[
    sbc l0053                                                         ; c6b5: e5 53       .S
    pha                                                               ; c6b7: 48          H
    lda l005c                                                         ; c6b8: a5 5c       .\
    sbc l0054                                                         ; c6ba: e5 54       .T
    pha                                                               ; c6bc: 48          H
    lda l005d                                                         ; c6bd: a5 5d       .]
    sbc l0055                                                         ; c6bf: e5 55       .U
    tax                                                               ; c6c1: aa          .
    lda l005e                                                         ; c6c2: a5 5e       .^
    sbc l0056                                                         ; c6c4: e5 56       .V
    bcc cc6d4                                                         ; c6c6: 90 0c       ..
    sta l005e                                                         ; c6c8: 85 5e       .^
    stx l005d                                                         ; c6ca: 86 5d       .]
    pla                                                               ; c6cc: 68          h
    sta l005c                                                         ; c6cd: 85 5c       .\
    pla                                                               ; c6cf: 68          h
    sta l005b                                                         ; c6d0: 85 5b       .[
    bcs cc6d6                                                         ; c6d2: b0 02       .. ; ALWAYS branch

; &c6d4 referenced 1 time by &c6c6
.cc6d4
    pla                                                               ; c6d4: 68          h
    pla                                                               ; c6d5: 68          h
; &c6d6 referenced 1 time by &c6d2
.cc6d6
    dey                                                               ; c6d6: 88          .
    bne cc6a2                                                         ; c6d7: d0 c9       ..
; &c6d9 referenced 1 time by &c696
.return_4
    rts                                                               ; c6d9: 60          `

; &c6da referenced 6 times by &c75b, &c764, &c76d, &c774, &c77b, &c782
.sub_cc6da
    jsr sub_cc78b                                                     ; c6da: 20 8b c7     ..
    dex                                                               ; c6dd: ca          .
    stx workspace_stack_pointer                                       ; c6de: 86 04       ..
    lda int_workspace_stack_high-1,x                                  ; c6e0: b5 42       .B
    eor #&80                                                          ; c6e2: 49 80       I.
    sta l0052                                                         ; c6e4: 85 52       .R
    lda int_workspace_stack_high,x                                    ; c6e6: b5 43       .C
    eor #&80                                                          ; c6e8: 49 80       I.
    sta l0054                                                         ; c6ea: 85 54       .T
    ldy #0                                                            ; c6ec: a0 00       ..
    sec                                                               ; c6ee: 38          8
    lda int_workspace_stack_low-1,x                                   ; c6ef: b5 15       ..
    sbc int_workspace_stack_low,x                                     ; c6f1: f5 16       ..
    sta l0053                                                         ; c6f3: 85 53       .S
    lda int_workspace_stack_mid1-1,x                                  ; c6f5: b5 24       .$
    sbc int_workspace_stack_mid1,x                                    ; c6f7: f5 25       .%
    sta l0055                                                         ; c6f9: 85 55       .U
    lda int_workspace_stack_mid2-1,x                                  ; c6fb: b5 33       .3
    sbc int_workspace_stack_mid2,x                                    ; c6fd: f5 34       .4
    sta l0056                                                         ; c6ff: 85 56       .V
    lda l0052                                                         ; c701: a5 52       .R
    sbc l0054                                                         ; c703: e5 54       .T
; &c705 referenced 1 time by &c68e
.sub_cc705
    ora l0053                                                         ; c705: 05 53       .S
    ora l0055                                                         ; c707: 05 55       .U
    ora l0056                                                         ; c709: 05 56       .V
    rts                                                               ; c70b: 60          `

; &c70c referenced 3 times by &c566, &c944, &ccd2
.sub_cc70c
    jsr sub_cc72c                                                     ; c70c: 20 2c c7     ,.
; &c70f referenced 1 time by &c71f
.loop_cc70f
    ldx #&43 ; 'C'                                                    ; c70f: a2 43       .C
    jmp match_keyword                                                 ; c711: 4c 33 c2    L3.

.op_and
    jsr sub_cc72c                                                     ; c714: 20 2c c7     ,.
    lda int_workspace_stack_low-2,x                                   ; c717: b5 14       ..
    and int_workspace_stack_low-1,x                                   ; c719: 35 15       5.
; &c71b referenced 1 time by &c729
.loop_cc71b
    sta int_workspace_stack_low-2,x                                   ; c71b: 95 14       ..
    dec workspace_stack_pointer                                       ; c71d: c6 04       ..
    jmp loop_cc70f                                                    ; c71f: 4c 0f c7    L..

.op_or
    jsr sub_cc72c                                                     ; c722: 20 2c c7     ,.
    lda int_workspace_stack_low-2,x                                   ; c725: b5 14       ..
    ora int_workspace_stack_low-1,x                                   ; c727: 15 15       ..
    jmp loop_cc71b                                                    ; c729: 4c 1b c7    L..

; &c72c referenced 3 times by &c70c, &c714, &c722
.sub_cc72c
    ldx #&46 ; 'F'                                                    ; c72c: a2 46       .F
    jmp match_keyword                                                 ; c72e: 4c 33 c2    L3.

.sub_cc731
    jsr sub_cc78b                                                     ; c731: 20 8b c7     ..
    jsr sub_cceae                                                     ; c734: 20 ae ce     ..
    lda int_workspace_stack_low-1,x                                   ; c737: b5 15       ..
    sta l0054                                                         ; c739: 85 54       .T
    lda int_workspace_stack_mid1-1,x                                  ; c73b: b5 24       .$
    sta l0055                                                         ; c73d: 85 55       .U
    ldy #&ff                                                          ; c73f: a0 ff       ..
; &c741 referenced 1 time by &c74a
.loop_cc741
    iny                                                               ; c741: c8          .
    lda (l0054),y                                                     ; c742: b1 54       .T
    cmp (l0052),y                                                     ; c744: d1 52       .R
    bne cc74f                                                         ; c746: d0 07       ..
    eor #&0d                                                          ; c748: 49 0d       I.
    bne loop_cc741                                                    ; c74a: d0 f5       ..
    tay                                                               ; c74c: a8          .  ; Y=0
    beq cc760                                                         ; c74d: f0 11       .. ; ALWAYS branch

; &c74f referenced 1 time by &c746
.cc74f
    ldy #0                                                            ; c74f: a0 00       ..
    beq cc761                                                         ; c751: f0 0e       .. ; ALWAYS branch

.sub_cc753
    jsr sub_cc78b                                                     ; c753: 20 8b c7     ..
    ldx #0                                                            ; c756: a2 00       ..
    jmp match_keyword                                                 ; c758: 4c 33 c2    L3.

.op_equal
    jsr sub_cc6da                                                     ; c75b: 20 da c6     ..
    bne cc761                                                         ; c75e: d0 01       ..
; &c760 referenced 7 times by &c74d, &c767, &c769, &c770, &c777, &c77e, &c787
.cc760
    iny                                                               ; c760: c8          .
; &c761 referenced 8 times by &c751, &c75e, &c76b, &c772, &c779, &c780, &c785, &c789
.cc761
    sty int_workspace_stack_low-1,x                                   ; c761: 94 15       ..
    rts                                                               ; c763: 60          `

.op_less_or_equal
    jsr sub_cc6da                                                     ; c764: 20 da c6     ..
    beq cc760                                                         ; c767: f0 f7       ..
    bcc cc760                                                         ; c769: 90 f5       ..
    bcs cc761                                                         ; c76b: b0 f4       .. ; ALWAYS branch

.op_not_equal
    jsr sub_cc6da                                                     ; c76d: 20 da c6     ..
    bne cc760                                                         ; c770: d0 ee       ..
    beq cc761                                                         ; c772: f0 ed       .. ; ALWAYS branch

.op_less
    jsr sub_cc6da                                                     ; c774: 20 da c6     ..
    bcc cc760                                                         ; c777: 90 e7       ..
    bcs cc761                                                         ; c779: b0 e6       .. ; ALWAYS branch

.op_greater_or_equal
    jsr sub_cc6da                                                     ; c77b: 20 da c6     ..
    bcs cc760                                                         ; c77e: b0 e0       ..
    bcc cc761                                                         ; c780: 90 df       .. ; ALWAYS branch

.op_greater
    jsr sub_cc6da                                                     ; c782: 20 da c6     ..
    beq cc761                                                         ; c785: f0 da       ..
    bcs cc760                                                         ; c787: b0 d7       ..
    bcc cc761                                                         ; c789: 90 d6       .. ; ALWAYS branch

; &c78b referenced 12 times by &c33f, &c390, &c4e1, &c6da, &c731, &c753, &ca2c, &cb81, &cba2, &ccb6, &cd5c, &ceb6
.sub_cc78b
    jsr sub_cc80b                                                     ; c78b: 20 0b c8     ..
    jmp cc795                                                         ; c78e: 4c 95 c7    L..

; &c791 referenced 4 times by &c7b4, &c7d0, &c7ec, &c808
.cc791
    sta int_workspace_stack_high-2,x                                  ; c791: 95 41       .A
    dec workspace_stack_pointer                                       ; c793: c6 04       ..
; &c795 referenced 1 time by &c78e
.cc795
    ldx #0                                                            ; c795: a2 00       ..
    jmp match_character                                               ; c797: 4c 7b c2    L{.

.op_add
    jsr sub_cc80b                                                     ; c79a: 20 0b c8     ..
    clc                                                               ; c79d: 18          .
    lda int_workspace_stack_low-2,x                                   ; c79e: b5 14       ..
    adc int_workspace_stack_low-1,x                                   ; c7a0: 75 15       u.
    sta int_workspace_stack_low-2,x                                   ; c7a2: 95 14       ..
    lda int_workspace_stack_mid1-2,x                                  ; c7a4: b5 23       .#
    adc int_workspace_stack_mid1-1,x                                  ; c7a6: 75 24       u$
    sta int_workspace_stack_mid1-2,x                                  ; c7a8: 95 23       .#
    lda int_workspace_stack_mid2-2,x                                  ; c7aa: b5 32       .2
    adc int_workspace_stack_mid2-1,x                                  ; c7ac: 75 33       u3
    sta int_workspace_stack_mid2-2,x                                  ; c7ae: 95 32       .2
    lda int_workspace_stack_high-2,x                                  ; c7b0: b5 41       .A
    adc int_workspace_stack_high-1,x                                  ; c7b2: 75 42       uB
    jmp cc791                                                         ; c7b4: 4c 91 c7    L..

.op_subtract
    jsr sub_cc80b                                                     ; c7b7: 20 0b c8     ..
    lda int_workspace_stack_low-2,x                                   ; c7ba: b5 14       ..
    sbc int_workspace_stack_low-1,x                                   ; c7bc: f5 15       ..
    sta int_workspace_stack_low-2,x                                   ; c7be: 95 14       ..
    lda int_workspace_stack_mid1-2,x                                  ; c7c0: b5 23       .#
    sbc int_workspace_stack_mid1-1,x                                  ; c7c2: f5 24       .$
    sta int_workspace_stack_mid1-2,x                                  ; c7c4: 95 23       .#
    lda int_workspace_stack_mid2-2,x                                  ; c7c6: b5 32       .2
    sbc int_workspace_stack_mid2-1,x                                  ; c7c8: f5 33       .3
    sta int_workspace_stack_mid2-2,x                                  ; c7ca: 95 32       .2
    lda int_workspace_stack_high-2,x                                  ; c7cc: b5 41       .A
    sbc int_workspace_stack_high-1,x                                  ; c7ce: f5 42       .B
    jmp cc791                                                         ; c7d0: 4c 91 c7    L..

.op_bitwise_or
    jsr sub_cc80b                                                     ; c7d3: 20 0b c8     ..
    lda int_workspace_stack_low-2,x                                   ; c7d6: b5 14       ..
    ora int_workspace_stack_low-1,x                                   ; c7d8: 15 15       ..
    sta int_workspace_stack_low-2,x                                   ; c7da: 95 14       ..
    lda int_workspace_stack_mid1-2,x                                  ; c7dc: b5 23       .#
    ora int_workspace_stack_mid1-1,x                                  ; c7de: 15 24       .$
    sta int_workspace_stack_mid1-2,x                                  ; c7e0: 95 23       .#
    lda int_workspace_stack_mid2-2,x                                  ; c7e2: b5 32       .2
    ora int_workspace_stack_mid2-1,x                                  ; c7e4: 15 33       .3
    sta int_workspace_stack_mid2-2,x                                  ; c7e6: 95 32       .2
    lda int_workspace_stack_high-2,x                                  ; c7e8: b5 41       .A
    ora int_workspace_stack_high-1,x                                  ; c7ea: 15 42       .B
    jmp cc791                                                         ; c7ec: 4c 91 c7    L..

.op_bitwise_eor
    jsr sub_cc80b                                                     ; c7ef: 20 0b c8     ..
    lda int_workspace_stack_low-2,x                                   ; c7f2: b5 14       ..
    eor int_workspace_stack_low-1,x                                   ; c7f4: 55 15       U.
    sta int_workspace_stack_low-2,x                                   ; c7f6: 95 14       ..
    lda int_workspace_stack_mid1-2,x                                  ; c7f8: b5 23       .#
    eor int_workspace_stack_mid1-1,x                                  ; c7fa: 55 24       U$
    sta int_workspace_stack_mid1-2,x                                  ; c7fc: 95 23       .#
    lda int_workspace_stack_mid2-2,x                                  ; c7fe: b5 32       .2
    eor int_workspace_stack_mid2-1,x                                  ; c800: 55 33       U3
    sta int_workspace_stack_mid2-2,x                                  ; c802: 95 32       .2
    lda int_workspace_stack_high-2,x                                  ; c804: b5 41       .A
    eor int_workspace_stack_high-1,x                                  ; c806: 55 42       UB
    jmp cc791                                                         ; c808: 4c 91 c7    L..

; &c80b referenced 5 times by &c78b, &c79a, &c7b7, &c7d3, &c7ef
.sub_cc80b
    jsr evaluate_expression                                           ; c80b: 20 bc c8     ..
; &c80e referenced 4 times by &c85b, &c899, &c89f, &c8b9
.cc80e
    ldx #5                                                            ; c80e: a2 05       ..
    jmp match_character                                               ; c810: 4c 7b c2    L{.

.op_multiply
    jsr sub_cc661                                                     ; c813: 20 61 c6     a.
; &c816 referenced 1 time by &c849
.cc816
    lsr l005a                                                         ; c816: 46 5a       FZ
    ror l0059                                                         ; c818: 66 59       fY
    ror l0058                                                         ; c81a: 66 58       fX
    ror l0057                                                         ; c81c: 66 57       fW
    bcc cc839                                                         ; c81e: 90 19       ..
    clc                                                               ; c820: 18          .
    tya                                                               ; c821: 98          .
    adc l0053                                                         ; c822: 65 53       eS
    tay                                                               ; c824: a8          .
    lda l005c                                                         ; c825: a5 5c       .\
    adc l0054                                                         ; c827: 65 54       eT
    sta l005c                                                         ; c829: 85 5c       .\
    lda l005d                                                         ; c82b: a5 5d       .]
    adc l0055                                                         ; c82d: 65 55       eU
    sta l005d                                                         ; c82f: 85 5d       .]
    lda l005e                                                         ; c831: a5 5e       .^
    adc l0056                                                         ; c833: 65 56       eV
    and #&7f                                                          ; c835: 29 7f       ).
    sta l005e                                                         ; c837: 85 5e       .^
; &c839 referenced 1 time by &c81e
.cc839
    asl l0053                                                         ; c839: 06 53       .S
    rol l0054                                                         ; c83b: 26 54       &T
    rol l0055                                                         ; c83d: 26 55       &U
    rol l0056                                                         ; c83f: 26 56       &V
    lda l0057                                                         ; c841: a5 57       .W
    ora l0058                                                         ; c843: 05 58       .X
    ora l0059                                                         ; c845: 05 59       .Y
    ora l005a                                                         ; c847: 05 5a       .Z
    bne cc816                                                         ; c849: d0 cb       ..
    sty l005b                                                         ; c84b: 84 5b       .[
    lda l0052                                                         ; c84d: a5 52       .R
    php                                                               ; c84f: 08          .
; &c850 referenced 1 time by &c878
.cc850
    ldy #&5b ; '['                                                    ; c850: a0 5b       .[
; &c852 referenced 1 time by &c86e
.loop_cc852
    jsr cc99f                                                         ; c852: 20 9f c9     ..
    plp                                                               ; c855: 28          (
    bpl cc85b                                                         ; c856: 10 03       ..
    jsr cc8c4                                                         ; c858: 20 c4 c8     ..
; &c85b referenced 1 time by &c856
.cc85b
    jmp cc80e                                                         ; c85b: 4c 0e c8    L..

.op_divide
    jsr sub_cc689                                                     ; c85e: 20 89 c6     ..
    rol l0057                                                         ; c861: 26 57       &W
    rol l0058                                                         ; c863: 26 58       &X
    rol l0059                                                         ; c865: 26 59       &Y
    rol l005a                                                         ; c867: 26 5a       &Z
    bit l0052                                                         ; c869: 24 52       $R
    php                                                               ; c86b: 08          .
    ldy #&57 ; 'W'                                                    ; c86c: a0 57       .W
    bne loop_cc852                                                    ; c86e: d0 e2       .. ; ALWAYS branch

.op_remainder
    jsr sub_cc689                                                     ; c870: 20 89 c6     ..
    ldx workspace_stack_pointer                                       ; c873: a6 04       ..
    lda int_workspace_stack_high+1,x                                  ; c875: b5 44       .D
    php                                                               ; c877: 08          .
    jmp cc850                                                         ; c878: 4c 50 c8    LP.

.op_bitwise_and
    jsr evaluate_expression                                           ; c87b: 20 bc c8     ..
    dex                                                               ; c87e: ca          .
    stx workspace_stack_pointer                                       ; c87f: 86 04       ..
    lda int_workspace_stack_low-1,x                                   ; c881: b5 15       ..
    and int_workspace_stack_low,x                                     ; c883: 35 16       5.
    sta int_workspace_stack_low-1,x                                   ; c885: 95 15       ..
    lda int_workspace_stack_mid1-1,x                                  ; c887: b5 24       .$
    and int_workspace_stack_mid1,x                                    ; c889: 35 25       5%
    sta int_workspace_stack_mid1-1,x                                  ; c88b: 95 24       .$
    lda int_workspace_stack_mid2-1,x                                  ; c88d: b5 33       .3
    and int_workspace_stack_mid2,x                                    ; c88f: 35 34       54
    sta int_workspace_stack_mid2-1,x                                  ; c891: 95 33       .3
    lda int_workspace_stack_high-1,x                                  ; c893: b5 42       .B
    and int_workspace_stack_high,x                                    ; c895: 35 43       5C
    sta int_workspace_stack_high-1,x                                  ; c897: 95 42       .B
    jmp cc80e                                                         ; c899: 4c 0e c8    L..

.op_byte_index
    jsr sub_cc8a2                                                     ; c89c: 20 a2 c8     ..
    jmp cc80e                                                         ; c89f: 4c 0e c8    L..

; &c8a2 referenced 2 times by &c89c, &c8b3
.sub_cc8a2
    jsr evaluate_expression                                           ; c8a2: 20 bc c8     ..
    clc                                                               ; c8a5: 18          .
    lda int_workspace_stack_low-1,x                                   ; c8a6: b5 15       ..
    adc int_workspace_stack_low-2,x                                   ; c8a8: 75 14       u.
    tay                                                               ; c8aa: a8          .
    lda int_workspace_stack_mid1-1,x                                  ; c8ab: b5 24       .$
    adc int_workspace_stack_mid1-2,x                                  ; c8ad: 75 23       u#
    dex                                                               ; c8af: ca          .
    jmp cc953                                                         ; c8b0: 4c 53 c9    LS.

.op_word_index
    jsr sub_cc8a2                                                     ; c8b3: 20 a2 c8     ..
    jsr sub_cc962                                                     ; c8b6: 20 62 c9     b.
    jmp cc80e                                                         ; c8b9: 4c 0e c8    L..

; &c8bc referenced 16 times by &c3c8, &c3ee, &c406, &c661, &c80b, &c87b, &c8a2, &c902, &c94c, &c9bd, &cc79, &cd84, &cf3e, &cf47, &cf7b, &cfb6
.evaluate_expression
    ldx #4                                                            ; c8bc: a2 04       ..
    jmp match_keyword                                                 ; c8be: 4c 33 c2    L3.

.sub_cc8c1
    jsr sub_cc8dc                                                     ; c8c1: 20 dc c8     ..
; &c8c4 referenced 3 times by &c590, &c858, &c907
.cc8c4
    sec                                                               ; c8c4: 38          8
    lda #0                                                            ; c8c5: a9 00       ..
    tay                                                               ; c8c7: a8          .  ; Y=0
    sbc int_workspace_stack_low-1,x                                   ; c8c8: f5 15       ..
    sta int_workspace_stack_low-1,x                                   ; c8ca: 95 15       ..
    tya                                                               ; c8cc: 98          .  ; A=0
    sbc int_workspace_stack_mid1-1,x                                  ; c8cd: f5 24       .$
    sta int_workspace_stack_mid1-1,x                                  ; c8cf: 95 24       .$
    tya                                                               ; c8d1: 98          .  ; A=0
    sbc int_workspace_stack_mid2-1,x                                  ; c8d2: f5 33       .3
    sta int_workspace_stack_mid2-1,x                                  ; c8d4: 95 33       .3
    tya                                                               ; c8d6: 98          .  ; A=0
    sbc int_workspace_stack_high-1,x                                  ; c8d7: f5 42       .B
    sta int_workspace_stack_high-1,x                                  ; c8d9: 95 42       .B
    rts                                                               ; c8db: 60          `

; &c8dc referenced 1 time by &c8c1
.sub_cc8dc
    jsr skip_spaces                                                   ; c8dc: 20 34 c4     4.
    bcc cc8f8                                                         ; c8df: 90 17       ..
; &c8e1 referenced 1 time by &cd81
.sub_cc8e1
    ldy int_workspace_stack_low-1,x                                   ; c8e1: b4 15       ..
    lda l0321,y                                                       ; c8e3: b9 21 03    .!.
    sta int_workspace_stack_low-1,x                                   ; c8e6: 95 15       ..
    lda l0357,y                                                       ; c8e8: b9 57 03    .W.
    sta int_workspace_stack_mid2-1,x                                  ; c8eb: 95 33       .3
    lda l033c,y                                                       ; c8ed: b9 3c 03    .<.
    sta int_workspace_stack_mid1-1,x                                  ; c8f0: 95 24       .$
    lda l0372,y                                                       ; c8f2: b9 72 03    .r.
    sta int_workspace_stack_high-1,x                                  ; c8f5: 95 42       .B
; &c8f7 referenced 1 time by &c8fb
.return_5
    rts                                                               ; c8f7: 60          `

; &c8f8 referenced 1 time by &c8df
.cc8f8
    jsr sub_cc46a                                                     ; c8f8: 20 6a c4     j.
    bcs return_5                                                      ; c8fb: b0 fa       ..
    ldx #7                                                            ; c8fd: a2 07       ..
    jmp match_keyword                                                 ; c8ff: 4c 33 c2    L3.

.function_abs
    jsr evaluate_expression                                           ; c902: 20 bc c8     ..
; &c905 referenced 1 time by &c66a
.sub_cc905
    lda int_workspace_stack_high-1,x                                  ; c905: b5 42       .B
; &c907 referenced 1 time by &c676
.sub_cc907
    bmi cc8c4                                                         ; c907: 30 bb       0.
    rts                                                               ; c909: 60          `

.function_hex
    ldx #0                                                            ; c90a: a2 00       ..
    stx l0052                                                         ; c90c: 86 52       .R
    stx l0053                                                         ; c90e: 86 53       .S
    stx l0054                                                         ; c910: 86 54       .T
    stx l0055                                                         ; c912: 86 55       .U
    dey                                                               ; c914: 88          .
; &c915 referenced 1 time by &c93c
.cc915
    iny                                                               ; c915: c8          .
    lda (parsing_ptr_low),y                                           ; c916: b1 05       ..
    cmp #&30 ; '0'                                                    ; c918: c9 30       .0
    bcc cc93e                                                         ; c91a: 90 22       ."
    cmp #&3a ; ':'                                                    ; c91c: c9 3a       .:
    bcc cc92a                                                         ; c91e: 90 0a       ..
    sbc #&37 ; '7'                                                    ; c920: e9 37       .7
    cmp #&0a                                                          ; c922: c9 0a       ..
    bcc cc93e                                                         ; c924: 90 18       ..
    cmp #&10                                                          ; c926: c9 10       ..
    bcs cc93e                                                         ; c928: b0 14       ..
; &c92a referenced 1 time by &c91e
.cc92a
    asl a                                                             ; c92a: 0a          .
    asl a                                                             ; c92b: 0a          .
    asl a                                                             ; c92c: 0a          .
    asl a                                                             ; c92d: 0a          .
    ldx #3                                                            ; c92e: a2 03       ..
; &c930 referenced 1 time by &c93a
.loop_cc930
    asl a                                                             ; c930: 0a          .
    rol l0052                                                         ; c931: 26 52       &R
    rol l0053                                                         ; c933: 26 53       &S
    rol l0054                                                         ; c935: 26 54       &T
    rol l0055                                                         ; c937: 26 55       &U
    dex                                                               ; c939: ca          .
    bpl loop_cc930                                                    ; c93a: 10 f4       ..
    bmi cc915                                                         ; c93c: 30 d7       0. ; ALWAYS branch

; &c93e referenced 3 times by &c91a, &c924, &c928
.cc93e
    txa                                                               ; c93e: 8a          .
    bpl lc959                                                         ; c93f: 10 18       ..
    jmp cc4d6                                                         ; c941: 4c d6 c4    L..

.function_bracket
    jsr sub_cc70c                                                     ; c944: 20 0c c7     ..
    ldx #&0c                                                          ; c947: a2 0c       ..
    jmp match_character                                               ; c949: 4c 7b c2    L{.

; &c94c referenced 1 time by &c95f
.function_byte_fetch
    jsr evaluate_expression                                           ; c94c: 20 bc c8     ..
    ldy int_workspace_stack_low-1,x                                   ; c94f: b4 15       ..
    lda int_workspace_stack_mid1-1,x                                  ; c951: b5 24       .$
; &c953 referenced 1 time by &c8b0
.cc953
    sta l0053                                                         ; c953: 85 53       .S
    sty l0052                                                         ; c955: 84 52       .R
    dex                                                               ; c957: ca          .
; &c958 referenced 1 time by &c9d5
.cc958
lc959 = cc958+1
    ldy #0                                                            ; c958: a0 00       ..
; overlapping: brk                                                    ; c959: 00          .
; &c959 referenced 1 time by &c93f
    lda (l0052),y                                                     ; c95a: b1 52       .R
    jmp cc97c                                                         ; c95c: 4c 7c c9    L|.

.function_word_fetch
    jsr function_byte_fetch                                           ; c95f: 20 4c c9     L.
; &c962 referenced 1 time by &c8b6
.sub_cc962
    ldy #1                                                            ; c962: a0 01       ..
    lda (l0052),y                                                     ; c964: b1 52       .R
    sta int_workspace_stack_mid1-1,x                                  ; c966: 95 24       .$
    iny                                                               ; c968: c8          .  ; Y=2
    lda (l0052),y                                                     ; c969: b1 52       .R
    sta int_workspace_stack_mid2-1,x                                  ; c96b: 95 33       .3
    iny                                                               ; c96d: c8          .  ; Y=3
    lda (l0052),y                                                     ; c96e: b1 52       .R
    sta int_workspace_stack_high-1,x                                  ; c970: 95 42       .B
    rts                                                               ; c972: 60          `

.function_top
    ldy #&0d                                                          ; c973: a0 0d       ..
    jsr sub_cc9a1                                                     ; c975: 20 a1 c9     ..
    beq cc981                                                         ; c978: f0 07       ..
.function_count
    lda l0007                                                         ; c97a: a5 07       ..
; &c97c referenced 6 times by &c95c, &c9cf, &ca53, &ca58, &cf63, &cfb3
.cc97c
    jsr sub_cc9b3                                                     ; c97c: 20 b3 c9     ..
    sta int_workspace_stack_mid1-1,x                                  ; c97f: 95 24       .$
; &c981 referenced 1 time by &c978
.cc981
    sta int_workspace_stack_mid2-1,x                                  ; c981: 95 33       .3
    sta int_workspace_stack_high-1,x                                  ; c983: 95 42       .B
    rts                                                               ; c985: 60          `

.function_rnd
    ldy #&20 ; ' '                                                    ; c986: a0 20       .
; &c988 referenced 1 time by &c99b
.loop_cc988
    lda rnd_seed+2                                                    ; c988: a5 0a       ..
    lsr a                                                             ; c98a: 4a          J
    lsr a                                                             ; c98b: 4a          J
    lsr a                                                             ; c98c: 4a          J
    eor rnd_seed+4                                                    ; c98d: 45 0c       E.
    ror a                                                             ; c98f: 6a          j
    rol rnd_seed                                                      ; c990: 26 08       &.
    rol rnd_seed+1                                                    ; c992: 26 09       &.
    rol rnd_seed+2                                                    ; c994: 26 0a       &.
    rol rnd_seed+3                                                    ; c996: 26 0b       &.
    rol rnd_seed+4                                                    ; c998: 26 0c       &.
    dey                                                               ; c99a: 88          .
    bne loop_cc988                                                    ; c99b: d0 eb       ..
    ldy #8                                                            ; c99d: a0 08       ..
; &c99f referenced 3 times by &c4db, &c852, &cf38
.cc99f
    ldx workspace_stack_pointer                                       ; c99f: a6 04       ..
; &c9a1 referenced 1 time by &c975
.sub_cc9a1
    lda basic_line_number,y                                           ; c9a1: b9 01 00    ...
    sta int_workspace_stack_mid1,x                                    ; c9a4: 95 25       .%
    lda basic_line_number+1,y                                         ; c9a6: b9 02 00    ...
    sta int_workspace_stack_mid2,x                                    ; c9a9: 95 34       .4
    lda parsing_ptr_offset,y                                          ; c9ab: b9 03 00    ...
    sta int_workspace_stack_high,x                                    ; c9ae: 95 43       .C
    lda basic_error_number,y                                          ; c9b0: b9 00 00    ...
; &c9b3 referenced 1 time by &c97c
.sub_cc9b3
    sta int_workspace_stack_low,x                                     ; c9b3: 95 16       ..
    inx                                                               ; c9b5: e8          .
    stx workspace_stack_pointer                                       ; c9b6: 86 04       ..
    ldy parsing_ptr_offset                                            ; c9b8: a4 03       ..
    lda #0                                                            ; c9ba: a9 00       ..
    rts                                                               ; c9bc: 60          `

.function_len
    jsr evaluate_expression                                           ; c9bd: 20 bc c8     ..
    jsr pop_to_52                                                     ; c9c0: 20 cb c3     ..
    ldy #0                                                            ; c9c3: a0 00       ..
    lda #&0d                                                          ; c9c5: a9 0d       ..
; &c9c7 referenced 1 time by &c9cc
.loop_cc9c7
    cmp (l0052),y                                                     ; c9c7: d1 52       .R
    beq cc9ce                                                         ; c9c9: f0 03       ..
    iny                                                               ; c9cb: c8          .
    bne loop_cc9c7                                                    ; c9cc: d0 f9       ..
; &c9ce referenced 1 time by &c9c9
.cc9ce
    tya                                                               ; c9ce: 98          .
    jmp cc97c                                                         ; c9cf: 4c 7c c9    L|.

.function_ch
    jsr sub_cceb1                                                     ; c9d2: 20 b1 ce     ..
    jmp cc958                                                         ; c9d5: 4c 58 c9    LX.

.handle_brkvec
    pla                                                               ; c9d8: 68          h
    pla                                                               ; c9d9: 68          h
    sta basic_error_number                                            ; c9da: 85 00       ..
    lda basic_error_handler                                           ; c9dc: a5 10       ..
    sta parsing_ptr_low                                               ; c9de: 85 05       ..
    lda basic_error_handler+1                                         ; c9e0: a5 11       ..
    sta parsing_ptr_high                                              ; c9e2: 85 06       ..
    jmp cc2f2                                                         ; c9e4: 4c f2 c2    L..

; BASIC's default error handler, in BASIC: it prints ERROR, the error number (?0) and,
; if there is one, the line number
.default_error_handler
    equs "@=1;P.$6$7'""ERROR ""?0;@=8;IF?1|?2P."" LINE""!1& #FFFF"    ; c9e7: 40 3d 31... @=1
    equb &0d                                                          ; ca1a: 0d          .

; A line 0 of BASIC (its line number's high byte is also a BRK)
; &ca1b referenced 1 time by &ca27
.loop_cca1b
    brk                                                               ; ca1b: 00          .

    equb 0                                                            ; ca1c: 00          .
    equs "P.';E."                                                     ; ca1d: 50 2e 27... P.'
    equb &0d                                                          ; ca23: 0d          .

.unknown_function
    jsr check_fp_rom                                                  ; ca24: 20 24 c4     $.
    bcc loop_cca1b                                                    ; ca27: 90 f2       ..
    jmp (fp_rom_function_handler)                                     ; ca29: 6c 04 d0    l..

; &ca2c referenced 2 times by &cb5f, &cca5
.sub_cca2c
    jsr sub_cc78b                                                     ; ca2c: 20 8b c7     ..
; &ca2f referenced 1 time by &c3e8
.sub_cca2f
    ldx workspace_stack_pointer                                       ; ca2f: a6 04       ..
    dex                                                               ; ca31: ca          .
    dex                                                               ; ca32: ca          .
    stx workspace_stack_pointer                                       ; ca33: 86 04       ..
    ldy int_workspace_stack_low,x                                     ; ca35: b4 16       ..
    lda int_workspace_stack_low+1,x                                   ; ca37: b5 17       ..
    sta l0321,y                                                       ; ca39: 99 21 03    .!.
    lda int_workspace_stack_mid1+1,x                                  ; ca3c: b5 26       .&
    sta l033c,y                                                       ; ca3e: 99 3c 03    .<.
    lda int_workspace_stack_mid2+1,x                                  ; ca41: b5 35       .5
    sta l0357,y                                                       ; ca43: 99 57 03    .W.
    lda int_workspace_stack_high+1,x                                  ; ca46: b5 44       .D
    sta l0372,y                                                       ; ca48: 99 72 03    .r.
    rts                                                               ; ca4b: 60          `

; &ca4c referenced 8 times by &c377, &c3a4, &c3ac, &c5e8, &c5f4, &c601, &ca92, &cd11
.print_character
    inc l0007                                                         ; ca4c: e6 07       ..
    jmp (wrcvec)                                                      ; ca4e: 6c 08 02    l..

.statement_list
    lda #0                                                            ; ca51: a9 00       ..
    jsr cc97c                                                         ; ca53: 20 7c c9     |.
    lda #&ff                                                          ; ca56: a9 ff       ..
    jsr cc97c                                                         ; ca58: 20 7c c9     |.
    sta workspace_stack_pointer                                       ; ca5b: 85 04       ..
    ldy #&7f                                                          ; ca5d: a0 7f       ..
    sty int_workspace_stack_mid1+1                                    ; ca5f: 84 26       .&
    jsr sub_cc465                                                     ; ca61: 20 65 c4     e.
    bcc ccab8                                                         ; ca64: 90 52       .R
    jsr skip_comma                                                    ; ca66: 20 31 c2     1.
    bcs ccac3                                                         ; ca69: b0 58       .X
    jsr sub_cc465                                                     ; ca6b: 20 65 c4     e.
; &ca6e referenced 2 times by &cac0, &cacb
.cca6e
    ldx #1                                                            ; ca6e: a2 01       ..
    stx workspace_stack_pointer                                       ; ca70: 86 04       ..
    jsr check_end_of_statement                                        ; ca72: 20 e4 c4     ..
    jsr sub_cc62e                                                     ; ca75: 20 2e c6     ..
    bcc ccaaa                                                         ; ca78: 90 30       .0
    dey                                                               ; ca7a: 88          .
    bcs cca9e                                                         ; ca7b: b0 21       .! ; ALWAYS branch

; &ca7d referenced 1 time by &cab3
.cca7d
    lda #5                                                            ; ca7d: a9 05       ..
    sta l0321                                                         ; ca7f: 8d 21 03    .!.
    jsr print_line_number                                             ; ca82: 20 89 c5     ..
    lda #8                                                            ; ca85: a9 08       ..
    sta l0321                                                         ; ca87: 8d 21 03    .!.
    ldy parsing_ptr_offset                                            ; ca8a: a4 03       ..
; &ca8c referenced 1 time by &ca96
.loop_cca8c
    lda (l0058),y                                                     ; ca8c: b1 58       .X
    cmp #&0d                                                          ; ca8e: c9 0d       ..
    beq cca98                                                         ; ca90: f0 06       ..
    jsr print_character                                               ; ca92: 20 4c ca     L.
    iny                                                               ; ca95: c8          .
    bne loop_cca8c                                                    ; ca96: d0 f4       ..
; &ca98 referenced 1 time by &ca90
.cca98
    jsr sub_ccd54                                                     ; ca98: 20 54 cd     T.
    jsr sub_ccea1                                                     ; ca9b: 20 a1 ce     ..
; &ca9e referenced 1 time by &ca7b
.cca9e
    lda (l0058),y                                                     ; ca9e: b1 58       .X
    sta int_workspace_stack_mid1                                      ; caa0: 85 25       .%
    iny                                                               ; caa2: c8          .
    lda (l0058),y                                                     ; caa3: b1 58       .X
    sta int_workspace_stack_low                                       ; caa5: 85 16       ..
    iny                                                               ; caa7: c8          .
    sty parsing_ptr_offset                                            ; caa8: 84 03       ..
; &caaa referenced 1 time by &ca78
.ccaaa
    lda int_workspace_stack_low                                       ; caaa: a5 16       ..
    clc                                                               ; caac: 18          .
    sbc int_workspace_stack_low+1                                     ; caad: e5 17       .. ; -1 because carry is clear
    lda int_workspace_stack_mid1                                      ; caaf: a5 25       .%
    sbc int_workspace_stack_mid1+1                                    ; cab1: e5 26       .&
    bcc cca7d                                                         ; cab3: 90 c8       ..
    jmp cc2cf                                                         ; cab5: 4c cf c2    L..

; &cab8 referenced 1 time by &ca64
.ccab8
    jsr skip_comma                                                    ; cab8: 20 31 c2     1.
    inc workspace_stack_pointer                                       ; cabb: e6 04       ..
    jsr sub_cc465                                                     ; cabd: 20 65 c4     e.
    jmp cca6e                                                         ; cac0: 4c 6e ca    Ln.

; &cac3 referenced 1 time by &ca69
.ccac3
    lda int_workspace_stack_low                                       ; cac3: a5 16       ..
    ldy int_workspace_stack_mid1                                      ; cac5: a4 25       .%
    sta int_workspace_stack_low+1                                     ; cac7: 85 17       ..
    sty int_workspace_stack_mid1+1                                    ; cac9: 84 26       .&
    bcs cca6e                                                         ; cacb: b0 a1       ..
.statement_next
    jsr skip_spaces                                                   ; cacd: 20 34 c4     4.
    ldy int_workspace_stack_low-1                                     ; cad0: a4 15       ..
    beq ccae4                                                         ; cad2: f0 10       ..
    bcc ccae5                                                         ; cad4: 90 0f       ..
    dec workspace_stack_pointer                                       ; cad6: c6 04       ..
    lda int_workspace_stack_low-1,x                                   ; cad8: b5 15       ..
; &cada referenced 1 time by &cae2
.loop_ccada
    cmp l023f,y                                                       ; cada: d9 3f 02    .?.
    beq ccae5                                                         ; cadd: f0 06       ..
    dey                                                               ; cadf: 88          .
    sty int_workspace_stack_low-1                                     ; cae0: 84 15       ..
    bne loop_ccada                                                    ; cae2: d0 f6       ..
; &cae4 referenced 1 time by &cad2
.ccae4
    brk                                                               ; cae4: 00          .

; &cae5 referenced 2 times by &cad4, &cadd
.ccae5
    ldx l023f,y                                                       ; cae5: be 3f 02    .?.
    clc                                                               ; cae8: 18          .
    lda l0321,x                                                       ; cae9: bd 21 03    .!.
    adc l024a,y                                                       ; caec: 79 4a 02    yJ.
    sta l0321,x                                                       ; caef: 9d 21 03    .!.
    sta l0052                                                         ; caf2: 85 52       .R
    lda l033c,x                                                       ; caf4: bd 3c 03    .<.
    adc l0255,y                                                       ; caf7: 79 55 02    yU.
    sta l033c,x                                                       ; cafa: 9d 3c 03    .<.
    sta l0053                                                         ; cafd: 85 53       .S
    lda l0357,x                                                       ; caff: bd 57 03    .W.
    adc l0260,y                                                       ; cb02: 79 60 02    y`.
    sta l0357,x                                                       ; cb05: 9d 57 03    .W.
    sta l0054                                                         ; cb08: 85 54       .T
    lda l0372,x                                                       ; cb0a: bd 72 03    .r.
    adc l026b,y                                                       ; cb0d: 79 6b 02    yk.
    sta l0372,x                                                       ; cb10: 9d 72 03    .r.
    tax                                                               ; cb13: aa          .
    lda l0052                                                         ; cb14: a5 52       .R
    sec                                                               ; cb16: 38          8
    sbc l0276,y                                                       ; cb17: f9 76 02    .v.
    sta l0052                                                         ; cb1a: 85 52       .R
    lda l0053                                                         ; cb1c: a5 53       .S
    sbc l0281,y                                                       ; cb1e: f9 81 02    ...
    sta l0053                                                         ; cb21: 85 53       .S
    lda l0054                                                         ; cb23: a5 54       .T
    sbc l028c,y                                                       ; cb25: f9 8c 02    ...
    sta l0054                                                         ; cb28: 85 54       .T
    txa                                                               ; cb2a: 8a          .
    sbc l0297,y                                                       ; cb2b: f9 97 02    ...
    ora l0052                                                         ; cb2e: 05 52       .R
    ora l0053                                                         ; cb30: 05 53       .S
    ora l0054                                                         ; cb32: 05 54       .T
    beq ccb45                                                         ; cb34: f0 0f       ..
    txa                                                               ; cb36: 8a          .
    eor l026b,y                                                       ; cb37: 59 6b 02    Yk.
    eor l0297,y                                                       ; cb3a: 59 97 02    Y..
    bpl ccb43                                                         ; cb3d: 10 04       ..
    bcs ccb45                                                         ; cb3f: b0 04       ..
    bcc ccb52                                                         ; cb41: 90 0f       .. ; ALWAYS branch

; &cb43 referenced 1 time by &cb3d
.ccb43
    bcs ccb52                                                         ; cb43: b0 0d       ..
; &cb45 referenced 2 times by &cb34, &cb3f
.ccb45
    lda l02a2,y                                                       ; cb45: b9 a2 02    ...
    sta parsing_ptr_low                                               ; cb48: 85 05       ..
    lda l02ad,y                                                       ; cb4a: b9 ad 02    ...
    sta parsing_ptr_high                                              ; cb4d: 85 06       ..
    jmp lcbff                                                         ; cb4f: 4c ff cb    L..

; &cb52 referenced 2 times by &cb41, &cb43
.ccb52
    dec int_workspace_stack_low-1                                     ; cb52: c6 15       ..
    jmp next_statement                                                ; cb54: 4c 58 c5    LX.

.statement_for
    jsr skip_spaces                                                   ; cb57: 20 34 c4     4.
    bcc ccb6d                                                         ; cb5a: 90 11       ..
    jsr expect_equals                                                 ; cb5c: 20 79 c2     y.
    jsr sub_cca2c                                                     ; cb5f: 20 2c ca     ,.
    tya                                                               ; cb62: 98          .
    ldy int_workspace_stack_low-1                                     ; cb63: a4 15       ..
    cpy #&0b                                                          ; cb65: c0 0b       ..
    bcs ccb6d                                                         ; cb67: b0 04       ..
    sta l0240,y                                                       ; cb69: 99 40 02    .@.
; overlapping: lda #0                                                 ; cb6c: a9 00       ..
    equb &a9                                                          ; cb6c: a9          .

; &cb6d referenced 2 times by &cb5a, &cb67
.ccb6d
    brk                                                               ; cb6d: 00          .

    sta l026c,y                                                       ; cb6e: 99 6c 02    .l.
    sta l0261,y                                                       ; cb71: 99 61 02    .a.
    sta l0256,y                                                       ; cb74: 99 56 02    .V.
    lda #1                                                            ; cb77: a9 01       ..
    sta l024b,y                                                       ; cb79: 99 4b 02    .K.
    ldx #&16                                                          ; cb7c: a2 16       ..
    jmp match_keyword                                                 ; cb7e: 4c 33 c2    L3.

.for_to
    jsr sub_cc78b                                                     ; cb81: 20 8b c7     ..
    ldy int_workspace_stack_low-1                                     ; cb84: a4 15       ..
    dex                                                               ; cb86: ca          .
    stx workspace_stack_pointer                                       ; cb87: 86 04       ..
    lda int_workspace_stack_low,x                                     ; cb89: b5 16       ..
    sta l0277,y                                                       ; cb8b: 99 77 02    .w.
    lda int_workspace_stack_mid1,x                                    ; cb8e: b5 25       .%
    sta l0282,y                                                       ; cb90: 99 82 02    ...
    lda int_workspace_stack_mid2,x                                    ; cb93: b5 34       .4
    sta l028d,y                                                       ; cb95: 99 8d 02    ...
    lda int_workspace_stack_high,x                                    ; cb98: b5 43       .C
    sta l0298,y                                                       ; cb9a: 99 98 02    ...
    ldx #&1a                                                          ; cb9d: a2 1a       ..
    jmp match_keyword                                                 ; cb9f: 4c 33 c2    L3.

.for_step
    jsr sub_cc78b                                                     ; cba2: 20 8b c7     ..
    ldy int_workspace_stack_low-1                                     ; cba5: a4 15       ..
    dex                                                               ; cba7: ca          .
    stx workspace_stack_pointer                                       ; cba8: 86 04       ..
    lda int_workspace_stack_low,x                                     ; cbaa: b5 16       ..
    sta l024b,y                                                       ; cbac: 99 4b 02    .K.
    lda int_workspace_stack_mid1,x                                    ; cbaf: b5 25       .%
    sta l0256,y                                                       ; cbb1: 99 56 02    .V.
    lda int_workspace_stack_mid2,x                                    ; cbb4: b5 34       .4
    sta l0261,y                                                       ; cbb6: 99 61 02    .a.
    lda int_workspace_stack_high,x                                    ; cbb9: b5 43       .C
    sta l026c,y                                                       ; cbbb: 99 6c 02    .l.
.sub_ccbbe
    jsr sub_cc50c                                                     ; cbbe: 20 0c c5     ..
    ldy int_workspace_stack_low-1                                     ; cbc1: a4 15       ..
    lda parsing_ptr_low                                               ; cbc3: a5 05       ..
    sta l02a3,y                                                       ; cbc5: 99 a3 02    ...
    lda parsing_ptr_high                                              ; cbc8: a5 06       ..
    sta l02ae,y                                                       ; cbca: 99 ae 02    ...
    inc int_workspace_stack_low-1                                     ; cbcd: e6 15       ..
    jmp if_then                                                       ; cbcf: 4c 1b c3    L..

.statement_gosub
    jsr sub_ccc1f                                                     ; cbd2: 20 1f cc     ..
    jsr sub_cc50c                                                     ; cbd5: 20 0c c5     ..
    ldy int_workspace_stack_low-2                                     ; cbd8: a4 14       ..
    cpy #&0e                                                          ; cbda: c0 0e       ..
    bcs ccc00                                                         ; cbdc: b0 22       ."
    lda parsing_ptr_low                                               ; cbde: a5 05       ..
    sta l02cf,y                                                       ; cbe0: 99 cf 02    ...
    lda parsing_ptr_high                                              ; cbe3: a5 06       ..
    sta l02dd,y                                                       ; cbe5: 99 dd 02    ...
    inc int_workspace_stack_low-2                                     ; cbe8: e6 14       ..
    bcc ccc0b                                                         ; cbea: 90 1f       .. ; ALWAYS branch

.statement_return
    jsr check_end_of_statement                                        ; cbec: 20 e4 c4     ..
    ldy int_workspace_stack_low-2                                     ; cbef: a4 14       ..
    beq ccc1d                                                         ; cbf1: f0 2a       .*
    dec int_workspace_stack_low-2                                     ; cbf3: c6 14       ..
    lda l02ce,y                                                       ; cbf5: b9 ce 02    ...
    sta parsing_ptr_low                                               ; cbf8: 85 05       ..
    lda l02dc,y                                                       ; cbfa: b9 dc 02    ...
; &cbfd referenced 2 times by &cc1a, &cced
.ccbfd
    sta parsing_ptr_high                                              ; cbfd: 85 06       ..
; overlapping: jsr cc500                                              ; cbff: 20 00 c5     ..
; &cbff referenced 1 time by &cb4f
.lcbff
    equb &20                                                          ; cbff: 20

; &cc00 referenced 1 time by &cbdc
.ccc00
    brk                                                               ; cc00: 00          .

    equb &c5                                                          ; cc01: c5          .

    jmp if_then                                                       ; cc02: 4c 1b c3    L..

.statement_goto
    jsr sub_ccc1f                                                     ; cc05: 20 1f cc     ..
    jsr check_end_of_statement                                        ; cc08: 20 e4 c4     ..
; &cc0b referenced 1 time by &cbea
.ccc0b
    lda l0057                                                         ; cc0b: a5 57       .W
    bne ccc14                                                         ; cc0d: d0 05       ..
    jsr sub_cc62e                                                     ; cc0f: 20 2e c6     ..
    bcs ccc7d                                                         ; cc12: b0 69       .i
; &cc14 referenced 1 time by &cc0d
.ccc14
    ldy l0058                                                         ; cc14: a4 58       .X
    lda l0059                                                         ; cc16: a5 59       .Y
    sty parsing_ptr_low                                               ; cc18: 84 05       ..
    jmp ccbfd                                                         ; cc1a: 4c fd cb    L..

; &cc1d referenced 1 time by &cbf1
.ccc1d
    brk                                                               ; cc1d: 00          .

; &cc1e referenced 1 time by &cc23
.loop_ccc1e
    iny                                                               ; cc1e: c8          .
; &cc1f referenced 2 times by &cbd2, &cc05
.sub_ccc1f
    lda (parsing_ptr_low),y                                           ; cc1f: b1 05       ..
    cmp #&20 ; ' '                                                    ; cc21: c9 20       .
    beq loop_ccc1e                                                    ; cc23: f0 f9       ..
    cmp #&61 ; 'a'                                                    ; cc25: c9 61       .a
    bcc ccc79                                                         ; cc27: 90 50       .P
    sta l0057                                                         ; cc29: 85 57       .W
    sbc #&61 ; 'a'                                                    ; cc2b: e9 61       .a
    cmp #&1b                                                          ; cc2d: c9 1b       ..
    bcs ccc79                                                         ; cc2f: b0 48       .H
    asl a                                                             ; cc31: 0a          .
    tax                                                               ; cc32: aa          .
    lda l038d,x                                                       ; cc33: bd 8d 03    ...
    sta l0058                                                         ; cc36: 85 58       .X
    jsr consolidate_text_pointer                                      ; cc38: 20 f6 c4     ..
    lda l038e,x                                                       ; cc3b: bd 8e 03    ...
    sta l0059                                                         ; cc3e: 85 59       .Y
    ora l0058                                                         ; cc40: 05 58       .X
    bne return_6                                                      ; cc42: d0 34       .4
    tay                                                               ; cc44: a8          .  ; Y=0
    lda text_space_page                                               ; cc45: a5 12       ..
    sta l0059                                                         ; cc47: 85 59       .Y
    dey                                                               ; cc49: 88          .  ; Y=&ff
; &cc4a referenced 1 time by &cc68
.loop_ccc4a
    lda #&0d                                                          ; cc4a: a9 0d       ..
; &cc4c referenced 1 time by &cc4f
.loop_ccc4c
    iny                                                               ; cc4c: c8          .
    cmp (l0058),y                                                     ; cc4d: d1 58       .X
    bne loop_ccc4c                                                    ; cc4f: d0 fb       ..
    iny                                                               ; cc51: c8          .
    lda (l0058),y                                                     ; cc52: b1 58       .X
    bmi lcc9b                                                         ; cc54: 30 45       0E
    sta basic_line_number+1                                           ; cc56: 85 02       ..
    iny                                                               ; cc58: c8          .
    lda (l0058),y                                                     ; cc59: b1 58       .X
    sta basic_line_number                                             ; cc5b: 85 01       ..
    iny                                                               ; cc5d: c8          .
    lda (l0058),y                                                     ; cc5e: b1 58       .X
    dey                                                               ; cc60: 88          .
    cmp l0057                                                         ; cc61: c5 57       .W
    beq ccc6b                                                         ; cc63: f0 06       ..
    jsr sub_ccea1                                                     ; cc65: 20 a1 ce     ..
    jmp loop_ccc4a                                                    ; cc68: 4c 4a cc    LJ.

; &cc6b referenced 1 time by &cc63
.ccc6b
    jsr sub_ccea2                                                     ; cc6b: 20 a2 ce     ..
    lda l0058                                                         ; cc6e: a5 58       .X
    sta l038d,x                                                       ; cc70: 9d 8d 03    ...
    lda l0059                                                         ; cc73: a5 59       .Y
    sta l038e,x                                                       ; cc75: 9d 8e 03    ...
; &cc78 referenced 1 time by &cc42
.return_6
    rts                                                               ; cc78: 60          `

; &cc79 referenced 2 times by &cc27, &cc2f
.ccc79
    jsr evaluate_expression                                           ; cc79: 20 bc c8     ..
; overlapping: lda #0                                                 ; cc7c: a9 00       ..
    equb &a9                                                          ; cc7c: a9          .

; &cc7d referenced 1 time by &cc12
.ccc7d
    brk                                                               ; cc7d: 00          .

    sta l0057                                                         ; cc7e: 85 57       .W
    rts                                                               ; cc80: 60          `

; &cc81 referenced 1 time by &cccc
.statement_input
    jsr cc372                                                         ; cc81: 20 72 c3     r.
    jsr skip_spaces                                                   ; cc84: 20 34 c4     4.
    bcs ccc8e                                                         ; cc87: b0 05       ..
    ldx #&2b ; '+'                                                    ; cc89: a2 2b       .+
    jmp match_keyword                                                 ; cc8b: 4c 33 c2    L3.

; &cc8e referenced 1 time by &cc87
.ccc8e
    jsr sub_ccd09                                                     ; cc8e: 20 09 cd     ..
    lda parsing_ptr_low                                               ; cc91: a5 05       ..
    pha                                                               ; cc93: 48          H
    lda parsing_ptr_high                                              ; cc94: a5 06       ..
    pha                                                               ; cc96: 48          H
    lda parsing_ptr_offset                                            ; cc97: a5 03       ..
    pha                                                               ; cc99: 48          H
.ccc9a
lcc9b = ccc9a+1
    ldy #0                                                            ; cc9a: a0 00       ..
; overlapping: brk                                                    ; cc9b: 00          .
; &cc9b referenced 1 time by &cc54
    sty parsing_ptr_offset                                            ; cc9c: 84 03       ..
    iny                                                               ; cc9e: c8          .
    sty parsing_ptr_high                                              ; cc9f: 84 06       ..
    ldy #&40 ; '@'                                                    ; cca1: a0 40       .@
    sty parsing_ptr_low                                               ; cca3: 84 05       ..
    jsr sub_cca2c                                                     ; cca5: 20 2c ca     ,.
    pla                                                               ; cca8: 68          h
    sta parsing_ptr_offset                                            ; cca9: 85 03       ..
    pla                                                               ; ccab: 68          h
    sta parsing_ptr_high                                              ; ccac: 85 06       ..
    pla                                                               ; ccae: 68          h
    sta parsing_ptr_low                                               ; ccaf: 85 05       ..
    ldx #&2c ; ','                                                    ; ccb1: a2 2c       .,
    jmp match_keyword                                                 ; ccb3: 4c 33 c2    L3.

.sub_cccb6
    jsr sub_cc78b                                                     ; ccb6: 20 8b c7     ..
    ldy #&54 ; 'T'                                                    ; ccb9: a0 54       .T
    jsr sub_cc3cd                                                     ; ccbb: 20 cd c3     ..
    jsr sub_ccd09                                                     ; ccbe: 20 09 cd     ..
    ldx #&40 ; '@'                                                    ; ccc1: a2 40       .@
; overlapping: ldy #0                                                 ; ccc3: a0 00       ..
    equb &a0                                                          ; ccc3: a0          .

; &ccc4 referenced 1 time by &ccd7
.loop_cccc4
    brk                                                               ; ccc4: 00          .

; &ccc5 referenced 1 time by &ccd0
.loop_cccc5
    lda input_buffer,x                                                ; ccc5: bd 00 01    ...
    sta (l0054),y                                                     ; ccc8: 91 54       .T
    cmp #&0d                                                          ; ccca: c9 0d       ..
    beq statement_input                                               ; cccc: f0 b3       ..
    inx                                                               ; ccce: e8          .
    iny                                                               ; cccf: c8          .
    bne loop_cccc5                                                    ; ccd0: d0 f3       ..
.statement_until
    jsr sub_cc70c                                                     ; ccd2: 20 0c c7     ..
    ldy l0013                                                         ; ccd5: a4 13       ..
    beq loop_cccc4                                                    ; ccd7: f0 eb       ..
    dex                                                               ; ccd9: ca          .
    stx workspace_stack_pointer                                       ; ccda: 86 04       ..
    lda int_workspace_stack_low,x                                     ; ccdc: b5 16       ..
    beq ccce5                                                         ; ccde: f0 05       ..
    dec l0013                                                         ; cce0: c6 13       ..
    jmp next_statement                                                ; cce2: 4c 58 c5    LX.

; &cce5 referenced 1 time by &ccde
.ccce5
    lda l02b8,y                                                       ; cce5: b9 b8 02    ...
    sta parsing_ptr_low                                               ; cce8: 85 05       ..
    lda l02c3,y                                                       ; ccea: b9 c3 02    ...
    jmp ccbfd                                                         ; cced: 4c fd cb    L..

.statement_do
    ldx l0013                                                         ; ccf0: a6 13       ..
    cpx #&0b                                                          ; ccf2: e0 0b       ..
    bcs lcd10                                                         ; ccf4: b0 1a       ..
    dey                                                               ; ccf6: 88          .
    jsr consolidate_text_pointer                                      ; ccf7: 20 f6 c4     ..
    lda parsing_ptr_low                                               ; ccfa: a5 05       ..
    sta l02b9,x                                                       ; ccfc: 9d b9 02    ...
    lda parsing_ptr_high                                              ; ccff: a5 06       ..
    sta l02c4,x                                                       ; cd01: 9d c4 02    ...
    inc l0013                                                         ; cd04: e6 13       ..
    jmp if_then                                                       ; cd06: 4c 1b c3    L..

; &cd09 referenced 2 times by &cc8e, &ccbe
.sub_ccd09
    lda #&3f ; '?'                                                    ; cd09: a9 3f       .?
    ldy #&40 ; '@'                                                    ; cd0b: a0 40       .@
    bne ccd11                                                         ; cd0d: d0 02       .. ; ALWAYS branch

; &cd0f referenced 1 time by &c2d2
.sub_ccd0f
lcd10 = sub_ccd0f+1
    ldy #0                                                            ; cd0f: a0 00       ..
; overlapping: brk                                                    ; cd10: 00          .
; &cd10 referenced 1 time by &ccf4
; &cd11 referenced 1 time by &cd0d
.ccd11
    jsr print_character                                               ; cd11: 20 4c ca     L.
    sty l0052                                                         ; cd14: 84 52       .R
; &cd16 referenced 2 times by &cd24, &cd2d
.ccd16
    ldy l0052                                                         ; cd16: a4 52       .R
; &cd18 referenced 2 times by &cd22, &cd45
.ccd18
    jsr OSECHO                                                        ; cd18: 20 e6 ff     .. ; Read a character and write it
    cmp #&7f                                                          ; cd1b: c9 7f       .. ; A=character read
    bne ccd26                                                         ; cd1d: d0 07       ..
; &cd1f referenced 1 time by &cd51
.ccd1f
    dey                                                               ; cd1f: 88          .
    cpy l0052                                                         ; cd20: c4 52       .R
    bpl ccd18                                                         ; cd22: 10 f4       ..
    bmi ccd16                                                         ; cd24: 30 f0       0. ; ALWAYS branch

; &cd26 referenced 1 time by &cd1d
.ccd26
    cmp #&18                                                          ; cd26: c9 18       ..
    bne ccd30                                                         ; cd28: d0 06       ..
    jsr sub_ccd54                                                     ; cd2a: 20 54 cd     T.
    jmp ccd16                                                         ; cd2d: 4c 16 cd    L..

; &cd30 referenced 1 time by &cd28
.ccd30
    cmp #&1b                                                          ; cd30: c9 1b       ..
    bne ccd37                                                         ; cd32: d0 03       ..
    jmp cc2cf                                                         ; cd34: 4c cf c2    L..

; &cd37 referenced 1 time by &cd32
.ccd37
    sta input_buffer,y                                                ; cd37: 99 00 01    ...
    cmp #&0d                                                          ; cd3a: c9 0d       ..
    beq ccd57                                                         ; cd3c: f0 19       ..
    iny                                                               ; cd3e: c8          .
    tya                                                               ; cd3f: 98          .
    sec                                                               ; cd40: 38          8
    sbc l0052                                                         ; cd41: e5 52       .R
    cmp #&40 ; '@'                                                    ; cd43: c9 40       .@
    bcc ccd18                                                         ; cd45: 90 d1       ..
; &cd47 referenced 1 time by &cd4c
.loop_ccd47
    jsr OSRDCH                                                        ; cd47: 20 e3 ff     .. ; Read a character
    cmp #&7f                                                          ; cd4a: c9 7f       .. ; A=character read
    bne loop_ccd47                                                    ; cd4c: d0 f9       ..
    ; Delete the character before the cursor
    jsr OSWRCH                                                        ; cd4e: 20 f4 ff     .. ; Write character 127
    jmp ccd1f                                                         ; cd51: 4c 1f cd    L..

; &cd54 referenced 3 times by &c36f, &ca98, &cd2a
.sub_ccd54
    jsr OSCRLF                                                        ; cd54: 20 ed ff     .. ; Write newline (characters 10 and 13)
; &cd57 referenced 1 time by &cd3c
.ccd57
    lda #0                                                            ; cd57: a9 00       ..
    sta l0007                                                         ; cd59: 85 07       ..
    rts                                                               ; cd5b: 60          `

.statement_string_store
    jsr sub_cc78b                                                     ; cd5c: 20 8b c7     ..
    jsr sub_cceae                                                     ; cd5f: 20 ae ce     ..
    ldy #&54 ; 'T'                                                    ; cd62: a0 54       .T
    jsr sub_cc3cd                                                     ; cd64: 20 cd c3     ..
    ldy #&ff                                                          ; cd67: a0 ff       ..
; &cd69 referenced 1 time by &cd70
.loop_ccd69
    iny                                                               ; cd69: c8          .
    lda (l0052),y                                                     ; cd6a: b1 52       .R
    sta (l0054),y                                                     ; cd6c: 91 54       .T
    cmp #&0d                                                          ; cd6e: c9 0d       ..
    bne loop_ccd69                                                    ; cd70: d0 f7       ..
    jmp next_statement                                                ; cd72: 4c 58 c5    LX.

.sub_ccd75
    jsr sub_ccd81                                                     ; cd75: 20 81 cd     ..
    jmp assign_expression                                             ; cd78: 4c f1 c3    L..

.sub_ccd7b
    jsr sub_ccd81                                                     ; cd7b: 20 81 cd     ..
    jmp cc409                                                         ; cd7e: 4c 09 c4    L..

; &cd81 referenced 2 times by &cd75, &cd7b
.sub_ccd81
    jsr sub_cc8e1                                                     ; cd81: 20 e1 c8     ..
    jsr evaluate_expression                                           ; cd84: 20 bc c8     ..
    dex                                                               ; cd87: ca          .
    clc                                                               ; cd88: 18          .
    lda int_workspace_stack_low,x                                     ; cd89: b5 16       ..
    adc int_workspace_stack_low-1,x                                   ; cd8b: 75 15       u.
    sta int_workspace_stack_low-1,x                                   ; cd8d: 95 15       ..
    lda int_workspace_stack_mid1,x                                    ; cd8f: b5 25       .%
    adc int_workspace_stack_mid1-1,x                                  ; cd91: 75 24       u$
    sta int_workspace_stack_mid1-1,x                                  ; cd93: 95 24       .$
    stx workspace_stack_pointer                                       ; cd95: 86 04       ..
    rts                                                               ; cd97: 60          `

.statement_end
    jsr check_end_of_statement                                        ; cd98: 20 e4 c4     ..
; &cd9b referenced 1 time by &cef7
.end_program
    lda text_space_page                                               ; cd9b: a5 12       ..
    sta l000e                                                         ; cd9d: 85 0e       ..
    ldy #0                                                            ; cd9f: a0 00       ..
    sty l000d                                                         ; cda1: 84 0d       ..
    dey                                                               ; cda3: 88          .  ; Y=&ff
; &cda4 referenced 2 times by &cda9, &cdb3
.ccda4
    iny                                                               ; cda4: c8          .
    lda (l000d),y                                                     ; cda5: b1 0d       ..
    cmp #&0d                                                          ; cda7: c9 0d       ..
    bne ccda4                                                         ; cda9: d0 f9       ..
    jsr sub_ccdbc                                                     ; cdab: 20 bc cd     ..
    lda (l000d),y                                                     ; cdae: b1 0d       ..
    bmi ccdb5                                                         ; cdb0: 30 03       0.
    iny                                                               ; cdb2: c8          .
    bne ccda4                                                         ; cdb3: d0 ef       ..
; &cdb5 referenced 1 time by &cdb0
.ccdb5
    iny                                                               ; cdb5: c8          .
    jsr sub_ccdbc                                                     ; cdb6: 20 bc cd     ..
    jmp cc2cf                                                         ; cdb9: 4c cf c2    L..

; &cdbc referenced 2 times by &cdab, &cdb6
.sub_ccdbc
    clc                                                               ; cdbc: 18          .
; &cdbd referenced 2 times by &ce15, &ce32
.sub_ccdbd
    tya                                                               ; cdbd: 98          .
    adc l000d                                                         ; cdbe: 65 0d       e.
    sta l000d                                                         ; cdc0: 85 0d       ..
    bcc ccdc6                                                         ; cdc2: 90 02       ..
    inc l000e                                                         ; cdc4: e6 0e       ..
; &cdc6 referenced 1 time by &cdc2
.ccdc6
    ldy #1                                                            ; cdc6: a0 01       ..
    rts                                                               ; cdc8: 60          `

; &cdc9 referenced 1 time by &c313
.ccdc9
    sty l0056                                                         ; cdc9: 84 56       .V
    jsr sub_cc62e                                                     ; cdcb: 20 2e c6     ..
    bcs cce18                                                         ; cdce: b0 48       .H
    lda l0058                                                         ; cdd0: a5 58       .X
    sta l0052                                                         ; cdd2: 85 52       .R
    sbc #1                                                            ; cdd4: e9 01       .. ; Carry is clear, so subtracting 2
    sta l0058                                                         ; cdd6: 85 58       .X
    sta l000d                                                         ; cdd8: 85 0d       ..
    lda l0059                                                         ; cdda: a5 59       .Y
    sta l0053                                                         ; cddc: 85 53       .S
    sbc #0                                                            ; cdde: e9 00       ..
    sta l000e                                                         ; cde0: 85 0e       ..
    sta l0059                                                         ; cde2: 85 59       .Y
    lda #&0d                                                          ; cde4: a9 0d       ..
; &cde6 referenced 1 time by &cde9
.loop_ccde6
    iny                                                               ; cde6: c8          .
    cmp (l0052),y                                                     ; cde7: d1 52       .R
    bne loop_ccde6                                                    ; cde9: d0 fb       ..
    clc                                                               ; cdeb: 18          .
    tya                                                               ; cdec: 98          .
    adc l0052                                                         ; cded: 65 52       eR
    sta l0052                                                         ; cdef: 85 52       .R
    bcc ccdf5                                                         ; cdf1: 90 02       ..
    inc l0053                                                         ; cdf3: e6 53       .S
; &cdf5 referenced 1 time by &cdf1
.ccdf5
lcdf6 = ccdf5+1
    ldy #0                                                            ; cdf5: a0 00       ..
; overlapping: brk                                                    ; cdf6: 00          .
; &cdf6 referenced 2 times by &ce42, &ce49
; &cdf7 referenced 2 times by &ce00, &ce06
.ccdf7
    lda (l0052),y                                                     ; cdf7: b1 52       .R
    sta (l000d),y                                                     ; cdf9: 91 0d       ..
    cmp #&0d                                                          ; cdfb: c9 0d       ..
    beq cce08                                                         ; cdfd: f0 09       ..
; &cdff referenced 1 time by &ce13
.loop_ccdff
    iny                                                               ; cdff: c8          .
    bne ccdf7                                                         ; ce00: d0 f5       ..
    inc l0053                                                         ; ce02: e6 53       .S
    inc l000e                                                         ; ce04: e6 0e       ..
    bne ccdf7                                                         ; ce06: d0 ef       ..
; &ce08 referenced 1 time by &cdfd
.cce08
    iny                                                               ; ce08: c8          .
    bne cce0f                                                         ; ce09: d0 04       ..
    inc l0053                                                         ; ce0b: e6 53       .S
    inc l000e                                                         ; ce0d: e6 0e       ..
; &ce0f referenced 1 time by &ce09
.cce0f
    lda (l0052),y                                                     ; ce0f: b1 52       .R
    sta (l000d),y                                                     ; ce11: 91 0d       ..
    bpl loop_ccdff                                                    ; ce13: 10 ea       ..
    jsr sub_ccdbd                                                     ; ce15: 20 bd cd     ..
; &ce18 referenced 1 time by &cdce
.cce18
    ldy #1                                                            ; ce18: a0 01       ..
    sty l0057                                                         ; ce1a: 84 57       .W
    dey                                                               ; ce1c: 88          .  ; Y=0
    lda #&0d                                                          ; ce1d: a9 0d       ..
    cmp (l0056),y                                                     ; ce1f: d1 56       .V
    beq cce80                                                         ; ce21: f0 5d       .]
; &ce23 referenced 1 time by &ce26
.loop_cce23
    iny                                                               ; ce23: c8          .
    cmp (l0056),y                                                     ; ce24: d1 56       .V
    bne loop_cce23                                                    ; ce26: d0 fb       ..
    iny                                                               ; ce28: c8          .
    iny                                                               ; ce29: c8          .
    lda l000d                                                         ; ce2a: a5 0d       ..
    sta l0054                                                         ; ce2c: 85 54       .T
    lda l000e                                                         ; ce2e: a5 0e       ..
    sta l0055                                                         ; ce30: 85 55       .U
    jsr sub_ccdbd                                                     ; ce32: 20 bd cd     ..
    sta l0052                                                         ; ce35: 85 52       .R
    lda l000e                                                         ; ce37: a5 0e       ..
    sta l0053                                                         ; ce39: 85 53       .S
    dey                                                               ; ce3b: 88          .
    lda #&55 ; 'U'                                                    ; ce3c: a9 55       .U
    sta (l000d),y                                                     ; ce3e: 91 0d       ..
    cmp (l000d),y                                                     ; ce40: d1 0d       ..
    bne lcdf6                                                         ; ce42: d0 b2       ..
    asl a                                                             ; ce44: 0a          .
    sta (l000d),y                                                     ; ce45: 91 0d       ..
    cmp (l000d),y                                                     ; ce47: d1 0d       ..
    bne lcdf6                                                         ; ce49: d0 ab       ..
; &ce4b referenced 1 time by &ce64
.loop_cce4b
    lda (l0054),y                                                     ; ce4b: b1 54       .T
    sta (l0052),y                                                     ; ce4d: 91 52       .R
    tya                                                               ; ce4f: 98          .
    bne cce56                                                         ; ce50: d0 04       ..
    dec l0055                                                         ; ce52: c6 55       .U
    dec l0053                                                         ; ce54: c6 53       .S
; &ce56 referenced 1 time by &ce50
.cce56
    dey                                                               ; ce56: 88          .
    tya                                                               ; ce57: 98          .
    adc l0054                                                         ; ce58: 65 54       eT
    ldx l0055                                                         ; ce5a: a6 55       .U
    bcc cce5f                                                         ; ce5c: 90 01       ..
    inx                                                               ; ce5e: e8          .
; &ce5f referenced 1 time by &ce5c
.cce5f
    cmp l0058                                                         ; ce5f: c5 58       .X
    txa                                                               ; ce61: 8a          .
    sbc l0059                                                         ; ce62: e5 59       .Y
    bcs loop_cce4b                                                    ; ce64: b0 e5       ..
    ldy #1                                                            ; ce66: a0 01       ..
    lda int_workspace_stack_mid1                                      ; ce68: a5 25       .%
    sta (l0058),y                                                     ; ce6a: 91 58       .X
    iny                                                               ; ce6c: c8          .  ; Y=2
    lda int_workspace_stack_low                                       ; ce6d: a5 16       ..
    sta (l0058),y                                                     ; ce6f: 91 58       .X
    sec                                                               ; ce71: 38          8
    jsr sub_ccea2                                                     ; ce72: 20 a2 ce     ..
    ldy #&ff                                                          ; ce75: a0 ff       ..
; &ce77 referenced 1 time by &ce7e
.loop_cce77
    iny                                                               ; ce77: c8          .
    lda (l0056),y                                                     ; ce78: b1 56       .V
    sta (l0058),y                                                     ; ce7a: 91 58       .X
    cmp #&0d                                                          ; ce7c: c9 0d       ..
    bne loop_cce77                                                    ; ce7e: d0 f7       ..
; &ce80 referenced 1 time by &ce21
.cce80
    jmp cc2cf                                                         ; ce80: 4c cf c2    L..

    jsr check_end_of_statement                                        ; ce83: 20 e4 c4     ..
    ldy #0                                                            ; ce86: a0 00       ..
    sty parsing_ptr_low                                               ; ce88: 84 05       ..
    sty parsing_ptr_offset                                            ; ce8a: 84 03       ..
    lda text_space_page                                               ; ce8c: a5 12       ..
    sta parsing_ptr_high                                              ; ce8e: 85 06       ..
    jmp next_statement_no_check                                       ; ce90: 4c 5b c5    L[.

; &ce93 referenced 2 times by &c3f1, &c409
.sub_cce93
    jsr sub_cc4de                                                     ; ce93: 20 de c4     ..
    dex                                                               ; ce96: ca          .
    jsr pop_to_52                                                     ; ce97: 20 cb c3     ..
    ldy #0                                                            ; ce9a: a0 00       ..
    lda int_workspace_stack_low+1,x                                   ; ce9c: b5 17       ..
    sta (l0052),y                                                     ; ce9e: 91 52       .R
    rts                                                               ; cea0: 60          `

; &cea1 referenced 4 times by &c642, &c65c, &ca9b, &cc65
.sub_ccea1
    clc                                                               ; cea1: 18          .
; &cea2 referenced 2 times by &cc6b, &ce72
.sub_ccea2
    tya                                                               ; cea2: 98          .
    adc l0058                                                         ; cea3: 65 58       eX
    sta l0058                                                         ; cea5: 85 58       .X
    bcc cceab                                                         ; cea7: 90 02       ..
    inc l0059                                                         ; cea9: e6 59       .Y
; &ceab referenced 1 time by &cea7
.cceab
    jmp cc500                                                         ; ceab: 4c 00 c5    L..

; &ceae referenced 2 times by &c734, &cd5f
.sub_cceae
    jsr expect_equals                                                 ; ceae: 20 79 c2     y.
; &ceb1 referenced 4 times by &c9d2, &cefa, &cfa8, &cfc8
.sub_cceb1
    ldx #&26 ; '&'                                                    ; ceb1: a2 26       .&
    jmp match_keyword                                                 ; ceb3: 4c 33 c2    L3.

.sub_cceb6
    jsr sub_cc78b                                                     ; ceb6: 20 8b c7     ..
    jsr pop_to_52                                                     ; ceb9: 20 cb c3     ..
    ldy parsing_ptr_offset                                            ; cebc: a4 03       ..
    rts                                                               ; cebe: 60          `

.sub_ccebf
    jsr consolidate_text_pointer                                      ; cebf: 20 f6 c4     ..
    sty l0053                                                         ; cec2: 84 53       .S
    dey                                                               ; cec4: 88          .
.ccec5
lcec6 = ccec5+1
    ldx #0                                                            ; cec5: a2 00       ..
; overlapping: brk                                                    ; cec6: 00          .
; &cec6 referenced 1 time by &cecb
; &cec7 referenced 2 times by &ced4, &ceeb
.ccec7
    lda (parsing_ptr_low),y                                           ; cec7: b1 05       ..
    cmp #&0d                                                          ; cec9: c9 0d       ..
    beq lcec6                                                         ; cecb: f0 f9       ..
    sta string_buffer,x                                               ; cecd: 9d 40 01    .@.
    inx                                                               ; ced0: e8          .
    iny                                                               ; ced1: c8          .
    cmp #&22 ; '"'                                                    ; ced2: c9 22       ."
    bne ccec7                                                         ; ced4: d0 f1       ..
    lda (parsing_ptr_low),y                                           ; ced6: b1 05       ..
    cmp #&22 ; '"'                                                    ; ced8: c9 22       ."
    beq cceea                                                         ; ceda: f0 0e       ..
    lda #&0d                                                          ; cedc: a9 0d       ..
    sta l013f,x                                                       ; cede: 9d 3f 01    .?.
    sty parsing_ptr_offset                                            ; cee1: 84 03       ..
    lda #&40 ; '@'                                                    ; cee3: a9 40       .@
    sta l0052                                                         ; cee5: 85 52       .R
    ldx workspace_stack_pointer                                       ; cee7: a6 04       ..
    rts                                                               ; cee9: 60          `

; &ceea referenced 1 time by &ceda
.cceea
    iny                                                               ; ceea: c8          .
    bcs ccec7                                                         ; ceeb: b0 da       ..
.statement_load
    jsr sub_ccefa                                                     ; ceed: 20 fa ce     ..
    dey                                                               ; cef0: 88          .
    sty l0056                                                         ; cef1: 84 56       .V
    sec                                                               ; cef3: 38          8
    jsr OSLOAD                                                        ; cef4: 20 e0 ff     .. ; Load a file
    jmp end_program                                                   ; cef7: 4c 9b cd    L..

; &cefa referenced 2 times by &ceed, &cf0a
.sub_ccefa
    jsr sub_cceb1                                                     ; cefa: 20 b1 ce     ..
    jsr check_end_of_statement                                        ; cefd: 20 e4 c4     ..
    dey                                                               ; cf00: 88          .
    sty l0054                                                         ; cf01: 84 54       .T
    lda text_space_page                                               ; cf03: a5 12       ..
    sta l0055                                                         ; cf05: 85 55       .U
    ldx #&52 ; 'R'                                                    ; cf07: a2 52       .R
    rts                                                               ; cf09: 60          `

.statement_save
    jsr sub_ccefa                                                     ; cf0a: 20 fa ce     ..
    sty l0058                                                         ; cf0d: 84 58       .X
    sta l0059                                                         ; cf0f: 85 59       .Y
    lda l000d                                                         ; cf11: a5 0d       ..
    sta l005a                                                         ; cf13: 85 5a       .Z
    lda l000e                                                         ; cf15: a5 0e       ..
    sta l005b                                                         ; cf17: 85 5b       .[
    lda #&b2                                                          ; cf19: a9 b2       ..
    sta l0056                                                         ; cf1b: 85 56       .V
    lda #&c2                                                          ; cf1d: a9 c2       ..
    sta l0057                                                         ; cf1f: 85 57       .W
    clc                                                               ; cf21: 18          .
    jsr OSSAVE                                                        ; cf22: 20 dd ff     .. ; Save a file
    jmp next_statement_no_check                                       ; cf25: 4c 5b c5    L[.

.function_ext
    sec                                                               ; cf28: 38          8
.function_ptr
    lda #0                                                            ; cf29: a9 00       ..
    rol a                                                             ; cf2b: 2a          *
    pha                                                               ; cf2c: 48          H
    jsr sub_ccf3e                                                     ; cf2d: 20 3e cf     >.
    ldx #&52 ; 'R'                                                    ; cf30: a2 52       .R
    pla                                                               ; cf32: 68          h
    jsr OSRDAR                                                        ; cf33: 20 da ff     .. ; Read a file's arguments
    ldy #&52 ; 'R'                                                    ; cf36: a0 52       .R
    jsr cc99f                                                         ; cf38: 20 9f c9     ..
    sta int_workspace_stack_high-1,x                                  ; cf3b: 95 42       .B
    rts                                                               ; cf3d: 60          `

; &cf3e referenced 3 times by &c22c, &cf2d, &cf5b
.sub_ccf3e
    jsr evaluate_expression                                           ; cf3e: 20 bc c8     ..
; &cf41 referenced 3 times by &cf50, &cf87, &cfbc
.sub_ccf41
    ldy int_workspace_stack_low-1,x                                   ; cf41: b4 15       ..
    dex                                                               ; cf43: ca          .
    stx workspace_stack_pointer                                       ; cf44: 86 04       ..
    rts                                                               ; cf46: 60          `

.statement_ptr
    jsr evaluate_expression                                           ; cf47: 20 bc c8     ..
    jsr sub_cc4de                                                     ; cf4a: 20 de c4     ..
    jsr pop_to_52                                                     ; cf4d: 20 cb c3     ..
    jsr sub_ccf41                                                     ; cf50: 20 41 cf     A.
    ldx #&52 ; 'R'                                                    ; cf53: a2 52       .R
    jsr OSSTAR                                                        ; cf55: 20 d7 ff     .. ; Store a file's arguments
    jmp next_statement_no_check                                       ; cf58: 4c 5b c5    L[.

; &cf5b referenced 1 time by &cf66
.function_bget
    jsr sub_ccf3e                                                     ; cf5b: 20 3e cf     >.
    sty l0052                                                         ; cf5e: 84 52       .R
    jsr OSBGET                                                        ; cf60: 20 d4 ff     .. ; Read a byte from file Y
    jmp cc97c                                                         ; cf63: 4c 7c c9    L|.

.function_get
    jsr function_bget                                                 ; cf66: 20 5b cf     [.
    ldy l0052                                                         ; cf69: a4 52       .R ; Y=file handle
    jsr OSBGET                                                        ; cf6b: 20 d4 ff     .. ; Read a byte from file Y
    sta int_workspace_stack_mid1-1,x                                  ; cf6e: 95 24       .$ ; A=byte read
    jsr OSBGET                                                        ; cf70: 20 d4 ff     .. ; Read a byte from file Y
    sta int_workspace_stack_mid2-1,x                                  ; cf73: 95 33       .3 ; A=byte read
    jsr OSBGET                                                        ; cf75: 20 d4 ff     .. ; Read a byte from file Y
    sta int_workspace_stack_high-1,x                                  ; cf78: 95 42       .B ; A=byte read
    rts                                                               ; cf7a: 60          `

; &cf7b referenced 2 times by &cf8f, &cf95
.sub_ccf7b
    jsr evaluate_expression                                           ; cf7b: 20 bc c8     ..
    jsr skip_comma                                                    ; cf7e: 20 31 c2     1.
    jsr sub_cc4e1                                                     ; cf81: 20 e1 c4     ..
    jsr pop_to_52                                                     ; cf84: 20 cb c3     ..
    jsr sub_ccf41                                                     ; cf87: 20 41 cf     A.
    lda l0052                                                         ; cf8a: a5 52       .R
    jmp (bptvec)                                                      ; cf8c: 6c 16 02    l..

.statement_bput
    jsr sub_ccf7b                                                     ; cf8f: 20 7b cf     {.
; &cf92 referenced 1 time by &cfa4
.loop_ccf92
    jmp next_statement_no_check                                       ; cf92: 4c 5b c5    L[.

.statement_put
    jsr sub_ccf7b                                                     ; cf95: 20 7b cf     {.
    ldx #1                                                            ; cf98: a2 01       ..
; &cf9a referenced 1 time by &cfa2
.loop_ccf9a
    lda l0052,x                                                       ; cf9a: b5 52       .R
    jsr OSBPUT                                                        ; cf9c: 20 d1 ff     .. ; Write byte A to file Y
    inx                                                               ; cf9f: e8          .
    cpx #4                                                            ; cfa0: e0 04       ..
    bcc loop_ccf9a                                                    ; cfa2: 90 f6       ..
    bcs loop_ccf92                                                    ; cfa4: b0 ec       .. ; ALWAYS branch

.function_fin
    sec                                                               ; cfa6: 38          8
.function_fout
    php                                                               ; cfa7: 08          .
    jsr sub_cceb1                                                     ; cfa8: 20 b1 ce     ..
    ldx #&52 ; 'R'                                                    ; cfab: a2 52       .R ; X=zero page address of the file name's address
    plp                                                               ; cfad: 28          (
    jsr OSFIND                                                        ; cfae: 20 ce ff     .. ; Open a file (for input if C=1, output if C=0)
    ldx workspace_stack_pointer                                       ; cfb1: a6 04       ..
    jmp cc97c                                                         ; cfb3: 4c 7c c9    L|.

.statement_shut
    jsr evaluate_expression                                           ; cfb6: 20 bc c8     ..
    jsr check_end_of_statement                                        ; cfb9: 20 e4 c4     ..
    jsr sub_ccf41                                                     ; cfbc: 20 41 cf     A.
    jsr OSSHUT                                                        ; cfbf: 20 cb ff     .. ; Close file Y
; &cfc2 referenced 2 times by &cfdc, &cffe
.ccfc2
    jmp next_statement_no_check                                       ; cfc2: 4c 5b c5    L[.

.statement_sput
    jsr sub_cc22c                                                     ; cfc5: 20 2c c2     ,.
    jsr sub_cceb1                                                     ; cfc8: 20 b1 ce     ..
    jsr check_end_of_statement                                        ; cfcb: 20 e4 c4     ..
    dey                                                               ; cfce: 88          .
; &cfcf referenced 1 time by &cfe1
.loop_ccfcf
    lda (l0052),y                                                     ; cfcf: b1 52       .R
    sty l0055                                                         ; cfd1: 84 55       .U
    ldy l000f                                                         ; cfd3: a4 0f       .. ; Y=file handle
    pha                                                               ; cfd5: 48          H
    jsr OSBPUT                                                        ; cfd6: 20 d1 ff     .. ; Write byte A to file Y
    pla                                                               ; cfd9: 68          h
    cmp #&0d                                                          ; cfda: c9 0d       ..
    beq ccfc2                                                         ; cfdc: f0 e4       ..
    ldy l0055                                                         ; cfde: a4 55       .U
    iny                                                               ; cfe0: c8          .
    bne loop_ccfcf                                                    ; cfe1: d0 ec       ..
.statement_sget
    jsr sub_cc22c                                                     ; cfe3: 20 2c c2     ,.
    jsr sub_cc4e1                                                     ; cfe6: 20 e1 c4     ..
    jsr pop_to_52                                                     ; cfe9: 20 cb c3     ..
    ldy #0                                                            ; cfec: a0 00       ..
; &cfee referenced 1 time by &cffc
.loop_ccfee
    sty l0055                                                         ; cfee: 84 55       .U
    ldy l000f                                                         ; cff0: a4 0f       .. ; Y=file handle
    jsr OSBGET                                                        ; cff2: 20 d4 ff     .. ; Read a byte from file Y
    ldy l0055                                                         ; cff5: a4 55       .U
    sta (l0052),y                                                     ; cff7: 91 52       .R ; A=byte read
    iny                                                               ; cff9: c8          .
    cmp #&0d                                                          ; cffa: c9 0d       ..
    bne loop_ccfee                                                    ; cffc: d0 f0       ..
    beq ccfc2                                                         ; cffe: f0 c2       .. ; ALWAYS branch

; &d000 referenced 1 time by &c424
.fp_rom_id
.pydis_end

    assert (<basic_rts) = &78
    assert (<command_run) = &41
    assert (<for_step) = &a2
    assert (<for_to) = &81
    assert (<function_abs) = &02
    assert (<function_bget) = &5b
    assert (<function_bracket) = &44
    assert (<function_byte_fetch) = &4c
    assert (<function_ch) = &d2
    assert (<function_count) = &7a
    assert (<function_ext) = &28
    assert (<function_fin) = &a6
    assert (<function_fout) = &a7
    assert (<function_get) = &66
    assert (<function_hex) = &0a
    assert (<function_len) = &bd
    assert (<function_ptr) = &29
    assert (<function_rnd) = &86
    assert (<function_top) = &73
    assert (<function_word_fetch) = &5f
    assert (<handle_brkvec) = &d8
    assert (<if_then) = &1b
    assert (<interpret_command) = &4b
    assert (<next_statement) = &58
    assert (<op_add) = &9a
    assert (<op_and) = &14
    assert (<op_bitwise_and) = &7b
    assert (<op_bitwise_eor) = &ef
    assert (<op_bitwise_or) = &d3
    assert (<op_byte_index) = &9c
    assert (<op_divide) = &5e
    assert (<op_equal) = &5b
    assert (<op_greater) = &82
    assert (<op_greater_or_equal) = &7b
    assert (<op_less) = &74
    assert (<op_less_or_equal) = &64
    assert (<op_multiply) = &13
    assert (<op_not_equal) = &6d
    assert (<op_or) = &22
    assert (<op_remainder) = &70
    assert (<op_subtract) = &b7
    assert (<op_word_index) = &b3
    assert (<print_new_line) = &6f
    assert (<print_quoted_string) = &7a
    assert (<statement_bput) = &8f
    assert (<statement_byte_store) = &06
    assert (<statement_do) = &f0
    assert (<statement_end) = &98
    assert (<statement_for) = &57
    assert (<statement_gosub) = &d2
    assert (<statement_goto) = &05
    assert (<statement_if) = &66
    assert (<statement_input) = &81
    assert (<statement_let) = &25
    assert (<statement_link) = &b2
    assert (<statement_list) = &51
    assert (<statement_load) = &ed
    assert (<statement_new) = &ad
    assert (<statement_next) = &cd
    assert (<statement_os_command) = &0f
    assert (<statement_print) = &34
    assert (<statement_ptr) = &47
    assert (<statement_put) = &95
    assert (<statement_rem) = &75
    assert (<statement_return) = &ec
    assert (<statement_save) = &0a
    assert (<statement_sget) = &e3
    assert (<statement_shut) = &b6
    assert (<statement_sput) = &c5
    assert (<statement_string_store) = &5c
    assert (<statement_until) = &d2
    assert (<statement_word_store) = &ee
    assert (<sub_cc335) = &35
    assert (<sub_cc33f) = &3f
    assert (<sub_cc390) = &90
    assert (<sub_cc3e5) = &e5
    assert (<sub_cc54a) = &4a
    assert (<sub_cc731) = &31
    assert (<sub_cc753) = &53
    assert (<sub_cc8c1) = &c1
    assert (<sub_cc8dc) = &dc
    assert (<sub_ccbbe) = &be
    assert (<sub_cccb6) = &b6
    assert (<sub_ccd75) = &75
    assert (<sub_ccd7b) = &7b
    assert (<sub_cceb6) = &b6
    assert (<sub_ccebf) = &bf
    assert (<test_array_variable) = &2e
    assert (>basic_rts) = &c2
    assert (>command_run) = &f1
    assert (>for_step) = &cb
    assert (>for_to) = &cb
    assert (>function_abs) = &c9
    assert (>function_bget) = &cf
    assert (>function_bracket) = &c9
    assert (>function_byte_fetch) = &c9
    assert (>function_ch) = &c9
    assert (>function_count) = &c9
    assert (>function_ext) = &cf
    assert (>function_fin) = &cf
    assert (>function_fout) = &cf
    assert (>function_get) = &cf
    assert (>function_hex) = &c9
    assert (>function_len) = &c9
    assert (>function_ptr) = &cf
    assert (>function_rnd) = &c9
    assert (>function_top) = &c9
    assert (>function_word_fetch) = &c9
    assert (>handle_brkvec) = &c9
    assert (>if_then) = &c3
    assert (>interpret_command) = &f0
    assert (>next_statement) = &c5
    assert (>op_add) = &c7
    assert (>op_and) = &c7
    assert (>op_bitwise_and) = &c8
    assert (>op_bitwise_eor) = &c7
    assert (>op_bitwise_or) = &c7
    assert (>op_byte_index) = &c8
    assert (>op_divide) = &c8
    assert (>op_equal) = &c7
    assert (>op_greater) = &c7
    assert (>op_greater_or_equal) = &c7
    assert (>op_less) = &c7
    assert (>op_less_or_equal) = &c7
    assert (>op_multiply) = &c8
    assert (>op_not_equal) = &c7
    assert (>op_or) = &c7
    assert (>op_remainder) = &c8
    assert (>op_subtract) = &c7
    assert (>op_word_index) = &c8
    assert (>print_new_line) = &c3
    assert (>print_quoted_string) = &c3
    assert (>statement_bput) = &cf
    assert (>statement_byte_store) = &c4
    assert (>statement_do) = &cc
    assert (>statement_end) = &cd
    assert (>statement_for) = &cb
    assert (>statement_gosub) = &cb
    assert (>statement_goto) = &cc
    assert (>statement_if) = &c5
    assert (>statement_input) = &cc
    assert (>statement_let) = &c3
    assert (>statement_link) = &c3
    assert (>statement_list) = &ca
    assert (>statement_load) = &ce
    assert (>statement_new) = &c2
    assert (>statement_next) = &ca
    assert (>statement_os_command) = &c4
    assert (>statement_print) = &c3
    assert (>statement_ptr) = &cf
    assert (>statement_put) = &cf
    assert (>statement_rem) = &c5
    assert (>statement_return) = &cb
    assert (>statement_save) = &cf
    assert (>statement_sget) = &cf
    assert (>statement_shut) = &cf
    assert (>statement_sput) = &cf
    assert (>statement_string_store) = &cd
    assert (>statement_until) = &cc
    assert (>statement_word_store) = &c3
    assert (>sub_cc335) = &c3
    assert (>sub_cc33f) = &c3
    assert (>sub_cc390) = &c3
    assert (>sub_cc3e5) = &c3
    assert (>sub_cc54a) = &c5
    assert (>sub_cc731) = &c7
    assert (>sub_cc753) = &c7
    assert (>sub_cc8c1) = &c8
    assert (>sub_cc8dc) = &c8
    assert (>sub_ccbbe) = &cb
    assert (>sub_cccb6) = &cc
    assert (>sub_ccd75) = &cd
    assert (>sub_ccd7b) = &cd
    assert (>sub_cceb6) = &ce
    assert (>sub_ccebf) = &ce
    assert (>test_array_variable) = &f0
    assert (fp_rom_id+1) = &d001
    assert (keywords-1) = &bfff

endsection

; Label references by decreasing frequency:
;     l0052:                      61
;     parsing_ptr_low:            37
;     l0053:                      30
;     l0054:                      29
;     l0058:                      29
;     workspace_stack_pointer:    29
;     parsing_ptr_offset:         24
;     l0055:                      23
;     int_workspace_stack_low:    18
;     l000d:                      18
;     evaluate_expression:        16
;     int_workspace_stack_mid1:   15
;     l0059:                      15
;     parsing_ptr_high:           15
;     match_keyword:              14
;     check_end_of_statement:     12
;     sub_cc78b:                  12
;     l0056:                      11
;     l0057:                      11
;     int_workspace_stack_high:   10
;     next_statement_no_check:    10
;     l000e:                       9
;     l005e:                       9
;     cc761:                       8
;     int_workspace_stack_mid2:    8
;     l0321:                       8
;     pop_to_52:                   8
;     print_character:             8
;     skip_spaces:                 8
;     cc760:                       7
;     consolidate_text_pointer:    7
;     text_space_page:             7
;     basic_line_number:           6
;     cc463:                       6
;     cc97c:                       6
;     l005a:                       6
;     l005b:                       6
;     l005c:                       6
;     l005d:                       6
;     match_character:             6
;     sub_cc6da:                   6
;     OSBGET:                      5
;     cc2cf:                       5
;     if_then:                     5
;     l000f:                       5
;     l0013:                       5
;     next_statement:              5
;     sub_cc80b:                   5
;     cc337:                       4
;     cc791:                       4
;     cc80e:                       4
;     l033c:                       4
;     l0357:                       4
;     l0372:                       4
;     lc46b:                       4
;     sub_cc3cd:                   4
;     sub_ccea1:                   4
;     sub_cceb1:                   4
;     basic_error_number:          3
;     cc32f:                       3
;     cc372:                       3
;     cc4cf:                       3
;     cc8c4:                       3
;     cc93e:                       3
;     cc99f:                       3
;     expect_equals:               3
;     input_buffer:                3
;     l0007:                       3
;     l038d:                       3
;     l038e:                       3
;     skip_comma:                  3
;     sub_cc465:                   3
;     sub_cc4e1:                   3
;     sub_cc62e:                   3
;     sub_cc70c:                   3
;     sub_cc72c:                   3
;     sub_ccd54:                   3
;     sub_ccf3e:                   3
;     sub_ccf41:                   3
;     OSBPUT:                      2
;     basic_error_handler:         2
;     cc264:                       2
;     cc26b:                       2
;     cc377:                       2
;     cc4d3:                       2
;     cc500:                       2
;     cc547:                       2
;     cc5c8:                       2
;     cc5ee:                       2
;     cc5f7:                       2
;     cc63b:                       2
;     cca6e:                       2
;     ccae5:                       2
;     ccb45:                       2
;     ccb52:                       2
;     ccb6d:                       2
;     ccbfd:                       2
;     ccc79:                       2
;     ccd16:                       2
;     ccd18:                       2
;     ccda4:                       2
;     ccdf7:                       2
;     ccec7:                       2
;     ccfc2:                       2
;     characters:                  2
;     check_fp_rom:                2
;     keyword_next:                2
;     l023f:                       2
;     l024b:                       2
;     l0256:                       2
;     l0261:                       2
;     l026b:                       2
;     l026c:                       2
;     l0297:                       2
;     lc55c:                       2
;     lcdf6:                       2
;     print_line_number:           2
;     return_3:                    2
;     sub_cc22c:                   2
;     sub_cc46a:                   2
;     sub_cc4de:                   2
;     sub_cc50c:                   2
;     sub_cc661:                   2
;     sub_cc689:                   2
;     sub_cc8a2:                   2
;     sub_cca2c:                   2
;     sub_ccc1f:                   2
;     sub_ccd09:                   2
;     sub_ccd81:                   2
;     sub_ccdbc:                   2
;     sub_ccdbd:                   2
;     sub_cce93:                   2
;     sub_ccea2:                   2
;     sub_cceae:                   2
;     sub_ccefa:                   2
;     sub_ccf7b:                   2
;     OSCLI:                       1
;     OSCRLF:                      1
;     OSECHO:                      1
;     OSFIND:                      1
;     OSLOAD:                      1
;     OSRDAR:                      1
;     OSRDCH:                      1
;     OSSAVE:                      1
;     OSSHUT:                      1
;     OSSTAR:                      1
;     OSWRCH:                      1
;     assign_expression:           1
;     basic_start:                 1
;     bptvec:                      1
;     brkvec:                      1
;     cc276:                       1
;     cc296:                       1
;     cc29f:                       1
;     cc2a8:                       1
;     cc2aa:                       1
;     cc2f2:                       1
;     cc316:                       1
;     cc36a:                       1
;     cc39d:                       1
;     cc3aa:                       1
;     cc409:                       1
;     cc43b:                       1
;     cc45c:                       1
;     cc477:                       1
;     cc4d6:                       1
;     cc4f7:                       1
;     cc57d:                       1
;     cc593:                       1
;     cc595:                       1
;     cc599:                       1
;     cc5c1:                       1
;     cc5cf:                       1
;     cc5d7:                       1
;     cc5df:                       1
;     cc5ff:                       1
;     cc6a2:                       1
;     cc6d4:                       1
;     cc6d6:                       1
;     cc74f:                       1
;     cc795:                       1
;     cc816:                       1
;     cc839:                       1
;     cc850:                       1
;     cc85b:                       1
;     cc8f8:                       1
;     cc915:                       1
;     cc92a:                       1
;     cc953:                       1
;     cc958:                       1
;     cc981:                       1
;     cc9ce:                       1
;     cca7d:                       1
;     cca98:                       1
;     cca9e:                       1
;     ccaaa:                       1
;     ccab8:                       1
;     ccac3:                       1
;     ccae4:                       1
;     ccb43:                       1
;     ccc00:                       1
;     ccc0b:                       1
;     ccc14:                       1
;     ccc1d:                       1
;     ccc6b:                       1
;     ccc7d:                       1
;     ccc8e:                       1
;     ccce5:                       1
;     ccd11:                       1
;     ccd1f:                       1
;     ccd26:                       1
;     ccd30:                       1
;     ccd37:                       1
;     ccd57:                       1
;     ccdb5:                       1
;     ccdc6:                       1
;     ccdc9:                       1
;     ccdf5:                       1
;     cce08:                       1
;     cce0f:                       1
;     cce18:                       1
;     cce56:                       1
;     cce5f:                       1
;     cce80:                       1
;     cceab:                       1
;     cceea:                       1
;     character_routines_high:     1
;     character_routines_low:      1
;     end_program:                 1
;     evaluate_expression_to_52:   1
;     fp_rom_function_handler:     1
;     fp_rom_id:                   1
;     fp_rom_statement_handler:    1
;     function_bget:               1
;     function_byte_fetch:         1
;     l013f:                       1
;     l0240:                       1
;     l024a:                       1
;     l0255:                       1
;     l0260:                       1
;     l0276:                       1
;     l0277:                       1
;     l0281:                       1
;     l0282:                       1
;     l028c:                       1
;     l028d:                       1
;     l0298:                       1
;     l02a2:                       1
;     l02a3:                       1
;     l02ad:                       1
;     l02ae:                       1
;     l02b8:                       1
;     l02b9:                       1
;     l02c3:                       1
;     l02c4:                       1
;     l02ce:                       1
;     l02cf:                       1
;     l02dc:                       1
;     l02dd:                       1
;     l0322:                       1
;     l0339:                       1
;     l033a:                       1
;     l038c:                       1
;     lc425:                       1
;     lc596:                       1
;     lc959:                       1
;     lcbff:                       1
;     lcc9b:                       1
;     lcd10:                       1
;     lcec6:                       1
;     loop_cc236:                  1
;     loop_cc241:                  1
;     loop_cc24b:                  1
;     loop_cc24f:                  1
;     loop_cc27e:                  1
;     loop_cc28c:                  1
;     loop_cc303:                  1
;     loop_cc34f:                  1
;     loop_cc39e:                  1
;     loop_cc411:                  1
;     loop_cc438:                  1
;     loop_cc4e7:                  1
;     loop_cc578:                  1
;     loop_cc5e6:                  1
;     loop_cc63d:                  1
;     loop_cc67f:                  1
;     loop_cc695:                  1
;     loop_cc70f:                  1
;     loop_cc71b:                  1
;     loop_cc741:                  1
;     loop_cc852:                  1
;     loop_cc930:                  1
;     loop_cc988:                  1
;     loop_cc9c7:                  1
;     loop_cca1b:                  1
;     loop_cca8c:                  1
;     loop_ccada:                  1
;     loop_ccc1e:                  1
;     loop_ccc4a:                  1
;     loop_ccc4c:                  1
;     loop_cccc4:                  1
;     loop_cccc5:                  1
;     loop_ccd47:                  1
;     loop_ccd69:                  1
;     loop_ccde6:                  1
;     loop_ccdff:                  1
;     loop_cce23:                  1
;     loop_cce4b:                  1
;     loop_cce77:                  1
;     loop_ccf92:                  1
;     loop_ccf9a:                  1
;     loop_ccfcf:                  1
;     loop_ccfee:                  1
;     powers_of_ten_byte_0:        1
;     powers_of_ten_byte_1:        1
;     powers_of_ten_byte_2:        1
;     powers_of_ten_byte_3:        1
;     ppi_port_b:                  1
;     pydis_end:                   1
;     return_1:                    1
;     return_2:                    1
;     return_4:                    1
;     return_5:                    1
;     return_6:                    1
;     rnd_seed:                    1
;     statement_input:             1
;     statement_rem:               1
;     string_buffer:               1
;     sub_cc2a5:                   1
;     sub_cc51c:                   1
;     sub_cc705:                   1
;     sub_cc8dc:                   1
;     sub_cc8e1:                   1
;     sub_cc905:                   1
;     sub_cc907:                   1
;     sub_cc962:                   1
;     sub_cc9a1:                   1
;     sub_cc9b3:                   1
;     sub_cca2f:                   1
;     sub_ccd0f:                   1
;     wrcvec:                      1

; Automatically generated labels:
;     cc264
;     cc26b
;     cc276
;     cc296
;     cc29f
;     cc2a8
;     cc2aa
;     cc2cf
;     cc2f2
;     cc316
;     cc32f
;     cc337
;     cc36a
;     cc372
;     cc377
;     cc39d
;     cc3aa
;     cc409
;     cc43b
;     cc45c
;     cc463
;     cc477
;     cc4cf
;     cc4d3
;     cc4d6
;     cc4f7
;     cc500
;     cc547
;     cc57d
;     cc593
;     cc595
;     cc599
;     cc5c1
;     cc5c8
;     cc5cf
;     cc5d7
;     cc5df
;     cc5ee
;     cc5f7
;     cc5ff
;     cc63b
;     cc6a2
;     cc6d4
;     cc6d6
;     cc74f
;     cc760
;     cc761
;     cc791
;     cc795
;     cc80e
;     cc816
;     cc839
;     cc850
;     cc85b
;     cc8c4
;     cc8f8
;     cc915
;     cc92a
;     cc93e
;     cc953
;     cc958
;     cc97c
;     cc981
;     cc99f
;     cc9ce
;     cca6e
;     cca7d
;     cca98
;     cca9e
;     ccaaa
;     ccab8
;     ccac3
;     ccae4
;     ccae5
;     ccb43
;     ccb45
;     ccb52
;     ccb6d
;     ccbfd
;     ccc00
;     ccc0b
;     ccc14
;     ccc1d
;     ccc6b
;     ccc79
;     ccc7d
;     ccc8e
;     ccc9a
;     ccce5
;     ccd11
;     ccd16
;     ccd18
;     ccd1f
;     ccd26
;     ccd30
;     ccd37
;     ccd57
;     ccda4
;     ccdb5
;     ccdc6
;     ccdc9
;     ccdf5
;     ccdf7
;     cce08
;     cce0f
;     cce18
;     cce56
;     cce5f
;     cce80
;     cceab
;     ccec5
;     ccec7
;     cceea
;     ccfc2
;     l0007
;     l000d
;     l000e
;     l000f
;     l0013
;     l0052
;     l0053
;     l0054
;     l0055
;     l0056
;     l0057
;     l0058
;     l0059
;     l005a
;     l005b
;     l005c
;     l005d
;     l005e
;     l013f
;     l023f
;     l0240
;     l024a
;     l024b
;     l0255
;     l0256
;     l0260
;     l0261
;     l026b
;     l026c
;     l0276
;     l0277
;     l0281
;     l0282
;     l028c
;     l028d
;     l0297
;     l0298
;     l02a2
;     l02a3
;     l02ad
;     l02ae
;     l02b8
;     l02b9
;     l02c3
;     l02c4
;     l02ce
;     l02cf
;     l02dc
;     l02dd
;     l0321
;     l0322
;     l0339
;     l033a
;     l033c
;     l0357
;     l0372
;     l038c
;     l038d
;     l038e
;     lc425
;     lc46b
;     lc55c
;     lc596
;     lc959
;     lcbff
;     lcc9b
;     lcd10
;     lcdf6
;     lcec6
;     loop_cc236
;     loop_cc241
;     loop_cc24b
;     loop_cc24f
;     loop_cc27e
;     loop_cc28c
;     loop_cc303
;     loop_cc34f
;     loop_cc39e
;     loop_cc411
;     loop_cc438
;     loop_cc4e7
;     loop_cc578
;     loop_cc5e6
;     loop_cc63d
;     loop_cc67f
;     loop_cc695
;     loop_cc70f
;     loop_cc71b
;     loop_cc741
;     loop_cc852
;     loop_cc930
;     loop_cc988
;     loop_cc9c7
;     loop_cca1b
;     loop_cca8c
;     loop_ccada
;     loop_ccc1e
;     loop_ccc4a
;     loop_ccc4c
;     loop_cccc4
;     loop_cccc5
;     loop_ccd47
;     loop_ccd69
;     loop_ccde6
;     loop_ccdff
;     loop_cce23
;     loop_cce4b
;     loop_cce77
;     loop_ccf92
;     loop_ccf9a
;     loop_ccfcf
;     loop_ccfee
;     return_1
;     return_2
;     return_3
;     return_4
;     return_5
;     return_6
;     sub_cc22c
;     sub_cc2a5
;     sub_cc335
;     sub_cc33f
;     sub_cc390
;     sub_cc3cd
;     sub_cc3e5
;     sub_cc465
;     sub_cc46a
;     sub_cc4de
;     sub_cc4e1
;     sub_cc50c
;     sub_cc51c
;     sub_cc54a
;     sub_cc62e
;     sub_cc661
;     sub_cc689
;     sub_cc6da
;     sub_cc705
;     sub_cc70c
;     sub_cc72c
;     sub_cc731
;     sub_cc753
;     sub_cc78b
;     sub_cc80b
;     sub_cc8a2
;     sub_cc8c1
;     sub_cc8dc
;     sub_cc8e1
;     sub_cc905
;     sub_cc907
;     sub_cc962
;     sub_cc9a1
;     sub_cc9b3
;     sub_cca2c
;     sub_cca2f
;     sub_ccbbe
;     sub_ccc1f
;     sub_cccb6
;     sub_ccd09
;     sub_ccd0f
;     sub_ccd54
;     sub_ccd75
;     sub_ccd7b
;     sub_ccd81
;     sub_ccdbc
;     sub_ccdbd
;     sub_cce93
;     sub_ccea1
;     sub_ccea2
;     sub_cceae
;     sub_cceb1
;     sub_cceb6
;     sub_ccebf
;     sub_ccefa
;     sub_ccf3e
;     sub_ccf41
;     sub_ccf7b

; Stats:
;
;     Total size (Code + Data) = 4096 bytes
;     Code                     = 3435 bytes (84%)
;     Data                     = 661 bytes (16%)
;
;     Number of instructions   = 1667
;     Number of data bytes     = 426 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 235 bytes
;     Number of strings        = 64
