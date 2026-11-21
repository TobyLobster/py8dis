"""Jump tables that py8dis finds but can't mark (see
asm/jump_tables.asm): tables 5 and 7, since what the
index can be isn't known, for which it prints a note of how many entries the
table seems to have and the control file lines that would mark them; and
tables 8 and 9, since an entry points into data, or two entries overlap,
for which it prints a note saying so, with the control file lines that
would mark the entries that look right. (The same control file as
jump_tables.)"""

from commands import *

load(0x2000, "orig/jump_tables.orig", "6502", "57c463a4eec1e125753264acb819633f")
entry(0x2000, "start")
entry(0x20c9, "no_guard_split")
entry(0x20e3, "into_data")
entry(0x2108, "odd_index")
stringz(0x2102)

label(0x209b, "table6")
rts_code_ptr(0x209b)
rts_code_ptr(0x209d)

go()
