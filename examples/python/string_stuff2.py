from commands import *

config.set_label_references(False)
config.set_hex_dump(True)
config.set_show_autogenerated_labels(False)
config.set_show_cpu_state(False)
config.set_show_char_literals(False)
config.set_show_all_labels(False)

load(0x0e00, "orig/string_stuff2.orig", "6502")

constant(0x1900, "page", format=Format.HEX) # 'page = &1900'

string(0xe00, 4)
expr(0x0e00, "STR$~(page)")                 # 'EQUS STR$~(page)', only works on Beebasm 1.10 or higher

go()
