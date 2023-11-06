"""
Configuration
"""

# Config variables all have leading underscores.
# Best practice is to not access these directly, but access via the getters and setters below.
_lower_case                 = True
_hex_dump                   = True
_label_references           = True
_inline_comment_column      = 70
_word_wrap_comment_column   = 87
_indent_string              = " "*4
_hex_dump_max_bytes         = 3
_hex_dump_show_ascii        = True
_indent_loops               = False
_blank_line_at_block_end    = True
_loop_limit                 = 32
_show_cpu_state             = False
_show_autogenerated_labels  = True
_show_char_literals         = True
_show_all_labels            = False
_constants_are_decimal      = True
_show_cycles                = False
_subroutine_header          = "*"*87
_subroutine_footer          = "*"*87

def get_lower_case():
    return _lower_case

def set_lower_case(b):
    global _lower_case
    _lower_case = b

def get_hex_dump():
    return _hex_dump

def set_hex_dump(b):
    global _hex_dump
    _hex_dump = b

def get_label_references():
    return _label_references

def set_label_references(b):
    global _label_references
    _label_references = b

def get_inline_comment_column():
    return _inline_comment_column

def set_inline_comment_column(n):
    global _inline_comment_column
    _inline_comment_column = n

def get_word_wrap_comment_column():
    return _word_wrap_comment_column

def set_word_wrap_comment_column(n):
    global _word_wrap_comment_column
    _word_wrap_comment_column = n

def get_indent_string():
    global _indent_string
    return _indent_string

def set_indent_string(s):
    global _indent_string
    _indent_string = s

def get_indent_loops():
    global _indent_loops
    return _indent_loops

def set_indent_loops(b):
    global _indent_loops
    _indent_loops = b

def get_blank_line_at_block_end():
    global _blank_line_at_block_end
    return _blank_line_at_block_end

def set_blank_line_at_block_end(b):
    global _blank_line_at_block_end
    _blank_line_at_block_end = b

def get_loop_limit():
    global _loop_limit
    return _loop_limit

def set_loop_limit(i):
    global _loop_limit
    _loop_limit = i

def get_show_cpu_state():
    global _show_cpu_state
    return _show_cpu_state

def set_show_cpu_state(b):
    global _show_cpu_state
    _show_cpu_state = b

def get_show_autogenerated_labels():
    global _show_autogenerated_labels
    return _show_autogenerated_labels

def set_show_autogenerated_labels(b):
    global _show_autogenerated_labels
    _show_autogenerated_labels = b

def get_show_char_literals():
    global _show_char_literals
    return _show_char_literals

def set_show_char_literals(b):
    global _show_char_literals
    _show_char_literals = b

def get_show_all_labels():
    global _show_all_labels
    return _show_all_labels

def set_show_all_labels(b):
    global _show_all_labels
    _show_all_labels = b

def get_hex_dump_max_bytes():
    global _hex_dump_max_bytes
    return _hex_dump_max_bytes

def set_hex_dump_max_bytes(i):
    global _hex_dump_max_bytes
    _hex_dump_max_bytes = i

def get_hex_dump_show_ascii():
    global _hex_dump_show_ascii
    return _hex_dump_show_ascii

def set_hex_dump_show_ascii(i):
    global _hex_dump_show_ascii
    _hex_dump_show_ascii = i

def get_constants_are_decimal():
    global _constants_are_decimal
    return _constants_are_decimal

def set_constants_are_decimal(b):
    global _constants_are_decimal
    _constants_are_decimal = b

def get_show_cycles():
    global _show_cycles
    return _show_cycles

def set_show_cycles(b):
    global _show_cycles
    _show_cycles = b

def get_subroutine_header():
    return _subroutine_header

def set_subroutine_header(s):
    global _subroutine_header
    _subroutine_header = s

def get_subroutine_footer():
    return _subroutine_footer

def set_subroutine_footer(s):
    global _subroutine_footer
    _subroutine_footer = s



# For internal use only:
_assembler                  = None      # Internal variable holding the assembler object used to emit disassembly, e.g. beebasm.py, acme.py etc
_cmos                       = False

def get_assembler():
    global _assembler
    return _assembler

def set_assembler(f):
    global _assembler
    _assembler = f

def get_cmos():
    global _cmos
    return _cmos

def set_cmos(b):
    global _cmos
    _cmos = b
