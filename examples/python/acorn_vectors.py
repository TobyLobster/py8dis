"""Code that sets the BBC Micro's OS vectors (see
asm_to_create_test_binaries/acorn_vectors.asm), with acorn.bbc(): each way
of setting one is commented (e.g. "Set write character vector to
'handle_wrchv'"), its handler is labelled and traced, and the bytes loaded
are its address's low and high bytes ('#<handle_wrchv'). They're found from
the values the code stores (an effect pattern), so the order, the registers
and other instructions between don't matter: a load and store for each byte
with A, X or Y, in either order; two loads, then the stores; a sei between
them; two vectors set together, sharing the high byte; a value transferred
from X to A; three loads, then the stores. A vector with only one byte set to
a known value is commented on that store: two stores to bytes of different
vectors, and a store of a high byte that isn't known."""

from commands import *
import acorn

load(0x2000, "orig/acorn_vectors.orig", "6502", "538cad0f74396e859192767601222d0f")
acorn.bbc()
entry(0x2000, "start")
go()
