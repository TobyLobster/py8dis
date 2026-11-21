"""set_label_maker_hook() called twice."""

from commands import *

def hook(runtime_addr, binary_addr, binary_addr_type, move_id, label):
    return None

load(0x2000, "orig/helloworld.orig", "6502")
set_label_maker_hook(hook)
set_label_maker_hook(hook)
go()
