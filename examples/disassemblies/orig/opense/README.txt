opense.orig (in examples/orig) is OpenSE BASIC 3.2.1, an open source
replacement for the ZX Spectrum's ROM, used as a test of the Z80 on a ROM
that is like the Spectrum's but not the same (see python/opense.py). It's
copyright (C) 1981 Nine Tiles Networks Ltd and 2011-2020 Source Solutions,
Inc., distributed under the GNU General Public License, version 2 or later,
or the Creative Commons Attribution-ShareAlike 3.0 licence (COPYRIGHT, in
this folder, which is Debian's copyright file for it).

It's the image in Debian's (and Ubuntu's) opense-basic package (version
3.2.1-1, usr/share/spectrum-roms/opense.rom), unchanged. Its source,
seBasic321.asm, and README (both in this folder) are from that package's
source (opense-basic_3.2.1.orig.tar.xz), from

    https://zxdesign.itch.io/opense

pasmo 0.5.3 assembles seBasic321.asm to the same bytes as opense.rom, and
writes a symbol file; opense.sym (in this folder) is the lines of it for
the source's labels (not its constants), which the control file uses:

    pasmo seBasic321.asm opense.bin all.sym

md5sum:
    17a4560020e02e5ea82b1eecc53f4282  opense.orig (opense.rom)
