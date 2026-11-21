"""config.set_upper_case_os_calls() after acorn.bbc(), which has already
named the OS calls."""

from commands import *
import acorn

load(0x2000, "orig/helloworld.orig", "6502")
acorn.bbc()
config.set_upper_case_os_calls(False)
go()
