"""Calls to the BBC Micro's OS (see
asm_to_create_test_binaries/acorn_lower_case_os_calls.asm), named in lower
case (e.g. 'oswrch') with config.set_upper_case_os_calls(False), which comes
before acorn.bbc(): they're still commented as usual, including OSASCI with
A=13 (a newline)."""

from commands import *
import acorn

config.set_upper_case_os_calls(False)

load(0x2000, "orig/acorn_lower_case_os_calls.orig", "6502", "f84c382f8a0626a07e96eb9dece40326")
acorn.bbc()
entry(0x2000, "start")
go()
