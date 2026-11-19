; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l0070   equ $70

    org $2000

pydis_start
start
    lda l0070                                                         ; 2000: a5 70       .p
    and #3                                                            ; 2002: 29 03       ).
    asl                                                               ; 2004: 0a          .
    tax                                                               ; 2005: aa          .
    jmp (l2009,x)                                                     ; 2006: 7c 09 20    |.

; A jump table of 4 entries (for the JMP at $2006)
; $2009 referenced 1 time by $2006
l2009
    da sub_c2011                                                      ; 2009: 11 20       .
    da sub_c2014                                                      ; 200b: 14 20       .
    da sub_c2017                                                      ; 200d: 17 20       .
    da sub_c201a                                                      ; 200f: 1a 20       .

sub_c2011
    lda #$0a                                                          ; 2011: a9 0a       ..
    rts                                                               ; 2013: 60          `

sub_c2014
    lda #$0b                                                          ; 2014: a9 0b       ..
    rts                                                               ; 2016: 60          `

sub_c2017
    lda #$0c                                                          ; 2017: a9 0c       ..
    rts                                                               ; 2019: 60          `

sub_c201a
    lda #$0d                                                          ; 201a: a9 0d       ..
    rts                                                               ; 201c: 60          `

pydis_end

    err sub_c2011 - $2011
    err sub_c2014 - $2014
    err sub_c2017 - $2017
    err sub_c201a - $201a

; Label references by decreasing frequency:
;     l0070:   1
;     l2009:   1

; Automatically generated labels:
;     l0070
;     l2009
;     sub_c2011
;     sub_c2014
;     sub_c2017
;     sub_c201a

; Stats:
;
;     Total size (Code + Data) = 29 bytes
;     Code                     = 21 bytes (72%)
;     Data                     = 8 bytes (28%)
;
;     Number of instructions   = 13
;     Number of data bytes     = 0 bytes
;     Number of data words     = 8 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
