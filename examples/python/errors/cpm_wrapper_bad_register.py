"""cpm.bdos_wrapper() with a register that isn't A or C."""

import sys
sys.argv[1:] = ["--z88dk"]

from commands import *
import cpm

load(0x0100, "orig/cpm_8080.orig", "8080")
cpm.cpm()
cpm.bdos_wrapper(0x015a, "b")
go()
