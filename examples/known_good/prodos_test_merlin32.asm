; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Constants
MLI_ALLOC_INTERRUPT equ $40
MLI_CLOSE           equ $cc
MLI_CREATE          equ $c0
MLI_GET_PREFIX      equ $c7
MLI_GET_TIME        equ $82
MLI_OPEN            equ $c8
MLI_QUIT            equ $65
MLI_SET_MARK        equ $ce
MLI_WRITE           equ $cb

; Memory locations

; Zero page ($00-$ff)
l0006   equ $06

; Hi-res page 2 ($4000-$5fff)
data_buffer_2   equ $4000

; Other
io_buffer   equ $9600

; ProDOS global page ($bf00-$bfff)
MLI     equ $bf00
DATE    equ $bf90
MACHID  equ $bf98

; Monitor ROM ($f800-$ffff)
COUT equ $fded

    org $2000

; ProDOS runs a SYS file from here
pydis_start
    lda MACHID                                                        ; 2000: ad 98 bf    -.?
    and #$30                                                          ; 2003: 29 30       ..
    sta l0006                                                         ; 2005: 85 06       ..
    jsr MLI                                                           ; 2007: 20 00 bf    ..? ; ProDOS: read the prefix
    dfb MLI_GET_PREFIX                                                ; 200a: c7          G
    da get_prefix_params                                              ; 200b: 54 20       ..

    jsr MLI                                                           ; 200d: 20 00 bf    ..? ; ProDOS: read the clock into DATE and TIME
    dfb MLI_GET_TIME                                                  ; 2010: 82          .
    da 0                                                              ; 2011: 00 00       ..

    lda DATE                                                          ; 2013: ad 90 bf    -.?
    jsr MLI                                                           ; 2016: 20 00 bf    ..? ; ProDOS: create a file
    dfb MLI_CREATE                                                    ; 2019: c0          @
    da create_params                                                  ; 201a: 57 20       ..

    jsr MLI                                                           ; 201c: 20 00 bf    ..? ; ProDOS: open a file
    dfb MLI_OPEN                                                      ; 201f: c8          H
    da open_params                                                    ; 2020: 63 20       ..

    bcs c204e                                                         ; 2022: b0 2a       0.
    lda open_ref                                                      ; 2024: ad 68 20    -..
    sta write_ref                                                     ; 2027: 8d 6f 20    ...
    sta set_mark_ref                                                  ; 202a: 8d 6a 20    ...
    sta close_ref                                                     ; 202d: 8d 77 20    ...
    jsr MLI                                                           ; 2030: 20 00 bf    ..? ; ProDOS: set a file's position
    dfb MLI_SET_MARK                                                  ; 2033: ce          N
    da set_mark_params                                                ; 2034: 69 20       ..

    jsr MLI                                                           ; 2036: 20 00 bf    ..? ; ProDOS: write to a file
    dfb MLI_WRITE                                                     ; 2039: cb          K
    da write_params                                                   ; 203a: 6e 20       ..

    jsr MLI                                                           ; 203c: 20 00 bf    ..? ; ProDOS: close a file
    dfb MLI_CLOSE                                                     ; 203f: cc          L
    da close_params                                                   ; 2040: 76 20       ..

    jsr MLI                                                           ; 2042: 20 00 bf    ..? ; ProDOS: install an interrupt handler
    dfb MLI_ALLOC_INTERRUPT                                           ; 2045: 40          .
    da alloc_interrupt_params                                         ; 2046: 78 20       ..

    jsr MLI                                                           ; 2048: 20 00 bf    ..? ; ProDOS: quit to the next program
    dfb MLI_QUIT                                                      ; 204b: 65          .
    da quit_params                                                    ; 204c: 7c 20       ..

; $204e referenced 1 time by $2022
c204e
    jsr COUT                                                          ; 204e: 20 ed fd    .m} ; Print a character (through CSW)
    rts                                                               ; 2051: 60          .

interrupt_handler
    clc                                                               ; 2052: 18          .
    rts                                                               ; 2053: 60          .

get_prefix_params
    dfb 1                                                             ; 2054: 01          .  ; Parameter count
    da data_buffer                                                    ; 2055: 8b 20       .. ; Data buffer
create_params
    dfb 7                                                             ; 2057: 07          .  ; Parameter count
    da pathname                                                       ; 2058: 83 20       .. ; Pathname
    dfb $c3                                                           ; 205a: c3          C  ; Access
    dfb 6                                                             ; 205b: 06          .  ; File type
    da $2000                                                          ; 205c: 00 20       .. ; Aux type
    dfb 1                                                             ; 205e: 01          .  ; Storage type
    da 0                                                              ; 205f: 00 00       .. ; Creation date
    da 0                                                              ; 2061: 00 00       .. ; Creation time
open_params
    dfb 3                                                             ; 2063: 03          .  ; Parameter count
    da pathname                                                       ; 2064: 83 20       .. ; Pathname
    da io_buffer                                                      ; 2066: 00 96       .. ; I/O buffer (1024 bytes)
; $2068 referenced 1 time by $2024
open_ref
    dfb 0                                                             ; 2068: 00          .  ; Reference number (returned)
set_mark_params
    dfb 2                                                             ; 2069: 02          .  ; Parameter count
; $206a referenced 1 time by $202a
set_mark_ref
    dfb 0                                                             ; 206a: 00          .  ; Reference number
    dfb 0, 2, 0                                                       ; 206b: 00 02 00    ... ; Position
write_params
    dfb 4                                                             ; 206e: 04          .  ; Parameter count
; $206f referenced 1 time by $2027
write_ref
    dfb 0                                                             ; 206f: 00          .  ; Reference number
    da data_buffer_2                                                  ; 2070: 00 40       .. ; Data buffer
    da $2000                                                          ; 2072: 00 20       .. ; Request count
    da 0                                                              ; 2074: 00 00       .. ; Transfer count (returned)
close_params
    dfb 1                                                             ; 2076: 01          .  ; Parameter count
; $2077 referenced 1 time by $202d
close_ref
    dfb 0                                                             ; 2077: 00          .  ; Reference number
alloc_interrupt_params
    dfb 2                                                             ; 2078: 02          .  ; Parameter count
    dfb 0                                                             ; 2079: 00          .  ; Interrupt number (returned)
    da interrupt_handler                                              ; 207a: 52 20       .. ; Handler's address
quit_params
    dfb 4                                                             ; 207c: 04          .  ; Parameter count
    dfb 0                                                             ; 207d: 00          .  ; Quit type
    da 0                                                              ; 207e: 00 00       .. ; Reserved
    dfb 0                                                             ; 2080: 00          .  ; Reserved
    da 0                                                              ; 2081: 00 00       .. ; Reserved
pathname
    dfb data_buffer - l2084                                           ; 2083: 07          .
l2084
    asc 'PICTURE'                                                     ; 2084: 50 49 43... PIC
data_buffer
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 208b: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 20a0: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 20b5: 00 00 00... ...
    dfb 0                                                             ; 20ca: 00          .
pydis_end

    err alloc_interrupt_params - $2078
    err close_params - $2076
    err create_params - $2057
    err data_buffer - $208b
    err data_buffer - l2084 - $07
    err data_buffer_2 - $4000
    err get_prefix_params - $2054
    err interrupt_handler - $2052
    err io_buffer - $9600
    err open_params - $2063
    err pathname - $2083
    err quit_params - $207c
    err set_mark_params - $2069
    err write_params - $206e

; Label references by decreasing frequency:
;     MLI:            9
;     COUT:           1
;     DATE:           1
;     MACHID:         1
;     c204e:          1
;     close_ref:      1
;     l0006:          1
;     open_ref:       1
;     set_mark_ref:   1
;     write_ref:      1

; Automatically generated labels:
;     c204e
;     l0006
;     l2084

; Stats:
;
;     Total size (Code + Data) = 203 bytes
;     Code                     = 57 bytes (28%)
;     Data                     = 146 bytes (72%)
;
;     Number of instructions   = 22
;     Number of data bytes     = 95 bytes
;     Number of data words     = 44 bytes
;     Number of string bytes   = 7 bytes
;     Number of strings        = 1
