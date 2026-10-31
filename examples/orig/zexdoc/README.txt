zexdoc.orig (in examples/orig) is ZEXDOC, Frank D. Cringle's Z80 instruction
set exerciser for CP/M (1994), used as a test of the Z80 (see
python/zexdoc.py). It's distributed under the GNU General Public License,
version 2 or later (LICENSE, in this folder).

It's zexdoc.com, unchanged, from

    https://github.com/agn453/ZEXALL

at commit 8f71d418bae69a476a5a0e5c6e122c8801b8d9f4 (2025-06-15), which has
the programs and their source from YAZE-AG 2.51.3 (see README.md, in this
folder). zexdoc.z80 (in this folder) is its source.

zexdoc_pasmo.asm (in this folder) is that source changed to assemble with
pasmo 0.5.3, which assembles it to the same bytes as zexdoc.com (but for the
end of the last 128 byte CP/M record, which is whatever was in memory): the
tstr and tmsg macros are written out, the labels daa, neg and rld (which
are instructions too) are daa_, neg_ and rld_, and 'and a,n' is 'and n'.
pasmo wrote zexdoc.sym (in this folder), whose labels the control file uses:

    pasmo zexdoc_pasmo.asm zexdoc.bin zexdoc.sym

md5sum:
    be3691b6b910d2c2e05e194cd529e45c  zexdoc.orig (zexdoc.com)
