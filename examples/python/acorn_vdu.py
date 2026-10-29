"""VDU sequences written with OSWRCH (see
asm_to_create_test_binaries/acorn_vdu.asm), decoded by acorn.py into
comments, however A is set: e.g. '; Select mode 7', '; Turn the cursor off',
'; Set logical colour 1 to physical colour 4' (with the colour set through
X), '; Position text cursor at (X,Y)' and '(?,3)', '; PLOT 69,640,512',
'; Print "Hi"' and '; Start a new line'. The routine at &20a0 starts with
the end of a sequence its caller started: three zeros, which are taken as
the end of an earlier sequence rather than as three VDU 0s (which do
nothing), then TAB(5,6)."""

from commands import *
import acorn

load(0x2000, "orig/acorn_vdu.orig", "6502", "aeb1abe8155df1748ba4a3aca9fd8e7c")
acorn.bbc()
entry(0x2000, "start")
entry(0x20a0, "end_of_plot")
go()
