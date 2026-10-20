# The same binary as move2, testing that an old style (legacy) label maker
# hook can choose which move a label is defined in. This used to be ignored.

from commands import *

load(0x2000, "orig/move2_legacy_label_maker.orig", "6502", "6d6fe001ff974fdc798c4f6c2d75c349")

entry(0x2000)

low_a_move_id = move(0x900, 0x2010, 0x2022-0x2010)
with low_a_move_id:
    label(0x900, "low_a")
    nonentry(0x90d)

low_b_move_id = move(0x901, 0x2029, 0x2039-0x2029)
with low_b_move_id:
    entry(0x901, "low_b")
    entry(0x90d, "low_b_baz")

# Legacy label maker: called as (runtime_addr, binary_addr, (name, move_id)).
# The 'jmp &090d' at &090f in the first move really jumps into the code from
# the second move, so name that label and define it in the second move.
def my_label_maker(addr, context, suggestion):
    if addr == 0x90d and context == 0x2020:
        return ("enter_low_b_baz", low_b_move_id)
    return suggestion

set_label_maker_hook(my_label_maker)

go()
