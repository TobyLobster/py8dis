"""acorn.atom_kernel_rom() without acorn.atom() first."""

from commands import *
import acorn

load(0xf000, "orig/atom_kernel.orig", "6502")
acorn.atom_kernel_rom()
go()
