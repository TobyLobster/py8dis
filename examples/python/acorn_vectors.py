"""Code that sets the BBC Micro's OS vectors (see
asm_to_create_test_binaries/acorn_vectors.asm), with acorn.bbc(): each way
of setting one is commented (e.g. "Set write character vector to
'handle_wrchv'"), its handler is labelled and traced, and the bytes loaded
are its address's low and high bytes ('#<handle_wrchv'). That's a load and
store for each byte with A, X or Y, in either order, or two loads into
different registers and then the two stores, in either order. The last two
stores aren't to the two bytes of a vector, so they're left alone."""

from commands import *
import acorn

load(0x2000, "orig/acorn_vectors.orig", "6502", "4f6ae44fc78e74948042f72f34ecc5c7")
acorn.bbc()
entry(0x2000, "start")
go()
