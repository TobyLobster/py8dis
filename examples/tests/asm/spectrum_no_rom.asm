; A ZX Spectrum program (November 2026), for spectrum_no_rom (see its control
; file), which disassembles it with spectrum.spectrum48(rom_labels=False):
; (IY+d) is written as an offset from ERR_NR's address only while neither
; half of IY is known to be something else, and a call to $335E (GEN-ENT-1
; in Sinclair's ROM, but not in a replacement ROM) is followed by code, not
; the calculator's bytecode.
; Assemble with: z88dk-z80asm -mz80 -b -o../orig/spectrum_no_rom.orig spectrum_no_rom.asm

    ORG $8000

start:
    ld (iy+1),a                     ; IY unknown: taken to be $5C3A
    ld iyh,$90
    ld (iy+1),a                     ; IYH known to be something else, IYL unknown
    ld iyh,$5c
    ld (iy+1),a                     ; IYH known to be $5C, IYL unknown
    ld iy,$5c3a
    ld iyl,$00
    ld (iy+1),a                     ; IYL known to be something else
    ld iy,$5c3a
    ld (iy+1),a                     ; IY known to be $5C3A
    call $335e                      ; Not GEN-ENT-1 here: code follows
    ld a,1
    ld b,2
    ret
