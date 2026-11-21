; Assemble with sjasmplus, to a plain binary:
;     sjasmplus --nologo --raw=program.bin this_file.asm

; Memory locations

; ROM ($00-$3fff)
l335e   equ $335e

; System variables ($5c00-$5cb5)
err_nr  equ $5c3a
flags   equ $5c3b

    org $8000

pydis_start:
start:
    ld (iy+flags - err_nr),a                                          ; 8000: fd 77 01    .w.
    ld iyh,$90                                                        ; 8003: fd 26 90    .&.
    ld (iy+1),a                                                       ; 8006: fd 77 01    .w.
    ld iyh,$5c                                                        ; 8009: fd 26 5c    .&\
    ld (iy+flags - err_nr),a                                          ; 800c: fd 77 01    .w.
    ld iy,$5c3a                                                       ; 800f: fd 21 3a... .!:
    ld iyl,0                                                          ; 8013: fd 2e 00    ...
    ld (iy+1),a                                                       ; 8016: fd 77 01    .w.
    ld iy,$5c3a                                                       ; 8019: fd 21 3a... .!:
    ld (iy+flags - err_nr),a                                          ; 801d: fd 77 01    .w.
    call l335e                                                        ; 8020: cd 5e 33    .^3
    ld a,1                                                            ; 8023: 3e 01       >.
    ld b,2                                                            ; 8025: 06 02       ..
    ret                                                               ; 8027: c9          .

pydis_end:

    assert (flags - err_nr) == $01

; Label references by decreasing frequency:
;     l335e:   1

; Automatically generated labels:
;     l335e

; Stats:
;
;     Total size (Code + Data) = 40 bytes
;     Code                     = 40 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 14
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

