; Constants
MLI_ALLOC_INTERRUPT = &40
MLI_CLOSE           = &cc
MLI_CREATE          = &c0
MLI_GET_PREFIX      = &c7
MLI_GET_TIME        = &82
MLI_OPEN            = &c8
MLI_QUIT            = &65
MLI_SET_MARK        = &ce
MLI_WRITE           = &cb

; Memory locations

; Zero page (&0000-&00ff)
l0006   = &0006

; Hi-res page 2 (&4000-&5fff)
data_buffer_2   = &4000

; Other
io_buffer   = &9600

; ProDOS global page (&bf00-&bfff)
MLI     = &bf00
DATE    = &bf90
MACHID  = &bf98

; Monitor ROM (&f800-&ffff)
COUT = &fded

    org &2000

; ProDOS runs a SYS file from here
.pydis_start
    lda MACHID                                                        ; 2000: ad 98 bf    -.?
    and #&30                                                          ; 2003: 29 30       ..
    sta l0006                                                         ; 2005: 85 06       ..
    jsr MLI                                                           ; 2007: 20 00 bf    ..? ; ProDOS: read the prefix
    equb MLI_GET_PREFIX                                               ; 200a: c7          G
    equw get_prefix_params                                            ; 200b: 54 20       ..

    jsr MLI                                                           ; 200d: 20 00 bf    ..? ; ProDOS: read the clock into DATE and TIME
    equb MLI_GET_TIME                                                 ; 2010: 82          .
    equw 0                                                            ; 2011: 00 00       ..

    lda DATE                                                          ; 2013: ad 90 bf    -.?
    jsr MLI                                                           ; 2016: 20 00 bf    ..? ; ProDOS: create a file
    equb MLI_CREATE                                                   ; 2019: c0          @
    equw create_params                                                ; 201a: 57 20       ..

    jsr MLI                                                           ; 201c: 20 00 bf    ..? ; ProDOS: open a file
    equb MLI_OPEN                                                     ; 201f: c8          H
    equw open_params                                                  ; 2020: 63 20       ..

    bcs c204e                                                         ; 2022: b0 2a       0.
    lda open_ref                                                      ; 2024: ad 68 20    -..
    sta write_ref                                                     ; 2027: 8d 6f 20    ...
    sta set_mark_ref                                                  ; 202a: 8d 6a 20    ...
    sta close_ref                                                     ; 202d: 8d 77 20    ...
    jsr MLI                                                           ; 2030: 20 00 bf    ..? ; ProDOS: set a file's position
    equb MLI_SET_MARK                                                 ; 2033: ce          N
    equw set_mark_params                                              ; 2034: 69 20       ..

    jsr MLI                                                           ; 2036: 20 00 bf    ..? ; ProDOS: write to a file
    equb MLI_WRITE                                                    ; 2039: cb          K
    equw write_params                                                 ; 203a: 6e 20       ..

    jsr MLI                                                           ; 203c: 20 00 bf    ..? ; ProDOS: close a file
    equb MLI_CLOSE                                                    ; 203f: cc          L
    equw close_params                                                 ; 2040: 76 20       ..

    jsr MLI                                                           ; 2042: 20 00 bf    ..? ; ProDOS: install an interrupt handler
    equb MLI_ALLOC_INTERRUPT                                          ; 2045: 40          .
    equw alloc_interrupt_params                                       ; 2046: 78 20       ..

    jsr MLI                                                           ; 2048: 20 00 bf    ..? ; ProDOS: quit to the next program
    equb MLI_QUIT                                                     ; 204b: 65          .
    equw quit_params                                                  ; 204c: 7c 20       ..

; &204e referenced 1 time by &2022
.c204e
    jsr COUT                                                          ; 204e: 20 ed fd    .m} ; Print a character (through CSW)
    rts                                                               ; 2051: 60          .

.interrupt_handler
    clc                                                               ; 2052: 18          .
    rts                                                               ; 2053: 60          .

.get_prefix_params
    equb 1                                                            ; 2054: 01          .  ; Parameter count
    equw data_buffer                                                  ; 2055: 8b 20       .. ; Data buffer
.create_params
    equb 7                                                            ; 2057: 07          .  ; Parameter count
    equw pathname                                                     ; 2058: 83 20       .. ; Pathname
    equb &c3                                                          ; 205a: c3          C  ; Access
    equb 6                                                            ; 205b: 06          .  ; File type
    equw &2000                                                        ; 205c: 00 20       .. ; Aux type
    equb 1                                                            ; 205e: 01          .  ; Storage type
    equw 0                                                            ; 205f: 00 00       .. ; Creation date
    equw 0                                                            ; 2061: 00 00       .. ; Creation time
.open_params
    equb 3                                                            ; 2063: 03          .  ; Parameter count
    equw pathname                                                     ; 2064: 83 20       .. ; Pathname
    equw io_buffer                                                    ; 2066: 00 96       .. ; I/O buffer (1024 bytes)
; &2068 referenced 1 time by &2024
.open_ref
    equb 0                                                            ; 2068: 00          .  ; Reference number (returned)
.set_mark_params
    equb 2                                                            ; 2069: 02          .  ; Parameter count
; &206a referenced 1 time by &202a
.set_mark_ref
    equb 0                                                            ; 206a: 00          .  ; Reference number
    equb 0, 2, 0                                                      ; 206b: 00 02 00    ... ; Position
.write_params
    equb 4                                                            ; 206e: 04          .  ; Parameter count
; &206f referenced 1 time by &2027
.write_ref
    equb 0                                                            ; 206f: 00          .  ; Reference number
    equw data_buffer_2                                                ; 2070: 00 40       .. ; Data buffer
    equw &2000                                                        ; 2072: 00 20       .. ; Request count
    equw 0                                                            ; 2074: 00 00       .. ; Transfer count (returned)
.close_params
    equb 1                                                            ; 2076: 01          .  ; Parameter count
; &2077 referenced 1 time by &202d
.close_ref
    equb 0                                                            ; 2077: 00          .  ; Reference number
.alloc_interrupt_params
    equb 2                                                            ; 2078: 02          .  ; Parameter count
    equb 0                                                            ; 2079: 00          .  ; Interrupt number (returned)
    equw interrupt_handler                                            ; 207a: 52 20       .. ; Handler's address
.quit_params
    equb 4                                                            ; 207c: 04          .  ; Parameter count
    equb 0                                                            ; 207d: 00          .  ; Quit type
    equw 0                                                            ; 207e: 00 00       .. ; Reserved
    equb 0                                                            ; 2080: 00          .  ; Reserved
    equw 0                                                            ; 2081: 00 00       .. ; Reserved
.pathname
    equb data_buffer - l2084                                          ; 2083: 07          .
.l2084
    equs "PICTURE"                                                    ; 2084: 50 49 43... PIC
.data_buffer
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 208b: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 209f: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 20b3: 00 00 00... ...
    equb 0, 0, 0, 0                                                   ; 20c7: 00 00 00... ...
.pydis_end

    assert &2078 == alloc_interrupt_params
    assert &2076 == close_params
    assert &2057 == create_params
    assert &208b == data_buffer
    assert &07 == data_buffer - l2084
    assert &4000 == data_buffer_2
    assert &2054 == get_prefix_params
    assert &2052 == interrupt_handler
    assert &9600 == io_buffer
    assert &2063 == open_params
    assert &2083 == pathname
    assert &207c == quit_params
    assert &2069 == set_mark_params
    assert &206e == write_params

save pydis_start, pydis_end

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

