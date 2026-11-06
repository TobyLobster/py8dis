; Text encodings (for '.text' and character literals)
    .enc "apple"
    .cdef " ~", $a0

; Memory locations

; Zero page ($0000-$00ff)
l0006   = $0006
l0007   = $0007
l0008   = $0008
l0009   = $0009
usr_jump = $000a
CSWL    = $0036
CSWH    = $0037

; DOS vectors ($03d0-$03ef)
dos_warm_start      = $03d0
dos_cold_start      = $03d3
dos_file_manager    = $03d6
dos_rwts            = $03d9
dos_get_fm_params   = $03dc
dos_get_iob         = $03e3
dos_connect_hooks   = $03ea

; Other
sector_buffer   = $1000

; Hi-res page 2 ($4000-$5fff)
sector_buffer_2 = $4000

; Other
dos_buffer_chain        = $9d00
dos_saved_output_hook   = $aa53
dos_maxfiles            = $aa57
dos_load_length         = $aa60
dos_load_address        = $aa72
dos_basic_flag          = $aab6
dos_fm_params           = $b5bb
dos_rwts_entry          = $b7b5
IOB                     = $b7e8
IBSLOT                  = $b7e9
IBSTAT                  = $b7f5
DCT                     = $b7fb
RWTS                    = $bd00

; Monitor ROM ($f800-$ffff)
COUT = $fded

; The DOS 3.3 file's header
    * = $5ffc
    .word $6000 ; Load address
    .word $010c ; Length

    * = $6000

pydis_start
start
    lda dos_warm_start                                                ; 6000: ad d0 03    -P.
    cmp #$4c                                                          ; 6003: c9 4c       I.
    beq c6008                                                         ; 6005: f0 01       p.
    rts                                                               ; 6007: 60          .

; $6008 referenced 1 time by $6005
c6008
    lda #$8d                                                          ; 6008: a9 8d       ).
    jsr COUT                                                          ; 600a: 20 ed fd    .m} ; Print a carriage return
    lda #$84                                                          ; 600d: a9 84       ).
    jsr COUT                                                          ; 600f: 20 ed fd    .m} ; Print Ctrl-D (to start a DOS command)
    ; print message
    ldx #0                                                            ; 6012: a2 00       ".
; $6014 referenced 1 time by $601d
loop_c6014
    lda l60cc,x                                                       ; 6014: bd cc 60    =L. ; A=character
    beq c601f                                                         ; 6017: f0 06       p.
    jsr COUT                                                          ; 6019: 20 ed fd    .m} ; Print a character (through CSW)
    inx                                                               ; 601c: e8          h
    bne loop_c6014                                                    ; 601d: d0 f5       Pu
; $601f referenced 1 time by $6017
c601f
    lda dos_load_address                                              ; 601f: ad 72 aa    -.*
    sta l0006                                                         ; 6022: 85 06       ..
    lda dos_load_address+1                                            ; 6024: ad 73 aa    -.*
    sta l0007                                                         ; 6027: 85 07       ..
    lda dos_load_length                                               ; 6029: ad 60 aa    -.*
    sta l0008                                                         ; 602c: 85 08       ..
    lda dos_load_length+1                                             ; 602e: ad 61 aa    -.*
    sta l0009                                                         ; 6031: 85 09       ..
    lda #$11                                                          ; 6033: a9 11       ).
    sta rwts_iob_track                                                ; 6035: 8d ea 60    .j.
    lda #0                                                            ; 6038: a9 00       ).
    sta rwts_iob_sector                                               ; 603a: 8d eb 60    .k.
    lda #1                                                            ; 603d: a9 01       ).
    sta rwts_iob_command                                              ; 603f: 8d f2 60    .r.
    lda #>rwts_iob                                                    ; 6042: a9 60       ).
    ldy #<rwts_iob                                                    ; 6044: a0 e6        f
    jsr dos_rwts                                                      ; 6046: 20 d9 03    .Y. ; Call RWTS (DOS's read/write track/sector routine)
    bcs c60c9                                                         ; 6049: b0 7e       0.
    lda rwts_iob_error                                                ; 604b: ad f3 60    -s.
    jsr dos_get_iob                                                   ; 604e: 20 e3 03    .c. ; Find DOS's IOB (RWTS's parameters)
    sty l0006                                                         ; 6051: 84 06       .. ; Y=IOB's address (low byte)
    sta l0007                                                         ; 6053: 85 07       .. ; A=IOB's address (high byte)
    ldy #$0c                                                          ; 6055: a0 0c        .
    lda #2                                                            ; 6057: a9 02       ).
    sta (l0006),y                                                     ; 6059: 91 06       ..
    ldy l0006                                                         ; 605b: a4 06       $. ; Y=IOB's address (low byte)
    lda l0007                                                         ; 605d: a5 07       %. ; A=IOB's address (high byte)
    jsr dos_rwts                                                      ; 605f: 20 d9 03    .Y. ; Call RWTS (DOS's read/write track/sector routine)
    lda IBSLOT                                                        ; 6062: ad e9 b7    -i7
    sta rwts_iob_2_slot                                               ; 6065: 8d fc 60    .|.
    lda #>IOB                                                         ; 6068: a9 b7       )7
    ldy #<IOB                                                         ; 606a: a0 e8        h
    jsr dos_rwts_entry                                                ; 606c: 20 b5 b7    .57 ; Call RWTS (DOS's read/write track/sector routine), with interrupts disabled
    lda IBSTAT                                                        ; 606f: ad f5 b7    -u7
    sta usr_jump                                                      ; 6072: 85 0a       ..
    sei                                                               ; 6074: 78          .
    lda #>rwts_iob_2                                                  ; 6075: a9 60       ).
    ldy #<rwts_iob_2                                                  ; 6077: a0 fb        {
    jsr RWTS                                                          ; 6079: 20 00 bd    ..= ; Call RWTS (DOS's read/write track/sector routine) directly
    cli                                                               ; 607c: 58          .
    jsr dos_get_fm_params                                             ; 607d: 20 dc 03    .\. ; Find the file manager's parameter list
    sty l0006                                                         ; 6080: 84 06       .. ; Y=parameter list's address (low byte)
    sta l0007                                                         ; 6082: 85 07       .. ; A=parameter list's address (high byte)
    ldy #0                                                            ; 6084: a0 00        .
    lda #5                                                            ; 6086: a9 05       ).
    sta (l0006),y                                                     ; 6088: 91 06       ..
    ldx #1                                                            ; 608a: a2 01       ".
    jsr dos_file_manager                                              ; 608c: 20 d6 03    .V. ; Call DOS's file manager (not creating the file if it isn't found)
    lda dos_fm_params+10                                              ; 608f: ad c5 b5    -E5
    ldx #0                                                            ; 6092: a2 00       ".
    jsr dos_file_manager                                              ; 6094: 20 d6 03    .V. ; Call DOS's file manager (creating the file if it isn't found)
    ldx l60e2                                                         ; 6097: ae e2 60    .b. ; X=file creation flag (0: create a file that isn't found)
    jsr dos_file_manager                                              ; 609a: 20 d6 03    .V. ; Call DOS's file manager (with its parameter list)

    ; Set the output hook (CSW) to 'output_handler'
    lda #<output_handler                                              ; 609d: a9 e3       )c
    sta CSWL                                                          ; 609f: 85 36       ..
    lda #>output_handler                                              ; 60a1: a9 60       ).
    sta CSWH                                                          ; 60a3: 85 37       ..

    jsr dos_connect_hooks                                             ; 60a5: 20 ea 03    .j. ; Reconnect DOS to the input and output hooks (KSW and CSW)
    lda dos_saved_output_hook                                         ; 60a8: ad 53 aa    -.*
    sta usr_jump+1                                                    ; 60ab: 85 0b       ..
    lda dos_saved_output_hook+1                                       ; 60ad: ad 54 aa    -.*
    sta usr_jump+2                                                    ; 60b0: 85 0c       ..
    lda dos_basic_flag                                                ; 60b2: ad b6 aa    -6*
    sta usr_jump                                                      ; 60b5: 85 0a       ..
    lda dos_maxfiles                                                  ; 60b7: ad 57 aa    -.*
    sta usr_jump                                                      ; 60ba: 85 0a       ..
    lda dos_buffer_chain                                              ; 60bc: ad 00 9d    -..
    sta l0006                                                         ; 60bf: 85 06       ..
    lda dos_buffer_chain+1                                            ; 60c1: ad 01 9d    -..
    sta l0007                                                         ; 60c4: 85 07       ..
    jmp dos_warm_start                                                ; 60c6: 4c d0 03    .P. ; Go to DOS's warm start (BASIC, keeping its program)

; $60c9 referenced 1 time by $6049
c60c9
    jsr dos_cold_start                                                ; 60c9: 20 d3 03    .S. ; Go to DOS's cold start (BASIC, clearing its program)
; $60cc referenced 1 time by $6014
l60cc
    .text "BLOAD PICTURE,A$2000"                                      ; 60cc: c2 cc cf... BLO
    .byte $8d, 0                                                      ; 60e0: 8d 00       ..
; $60e2 referenced 1 time by $6097
l60e2
    .byte 1                                                           ; 60e2: 01          .

output_handler
    jmp COUT                                                          ; 60e3: 4c ed fd    .m} ; Print a character (through CSW)

rwts_iob
    .byte 1                                                           ; 60e6: 01          .  ; Table type (1)
    .byte $60                                                         ; 60e7: 60          .  ; Slot times 16
    .byte 1                                                           ; 60e8: 01          .  ; Drive (1 or 2)
    .byte 0                                                           ; 60e9: 00          .  ; Volume expected (0 for any)
; $60ea referenced 1 time by $6035
rwts_iob_track
    .byte 0                                                           ; 60ea: 00          .  ; Track
; $60eb referenced 1 time by $603a
rwts_iob_sector
    .byte 0                                                           ; 60eb: 00          .  ; Sector
    .word rwts_dct                                                    ; 60ec: f7 60       w. ; Device characteristics table
    .word sector_buffer                                               ; 60ee: 00 10       .. ; Sector buffer (256 bytes)
    .byte 0                                                           ; 60f0: 00          .  ; Not used
    .byte 0                                                           ; 60f1: 00          .  ; Byte count for a partial sector (0 for 256)
; $60f2 referenced 1 time by $603f
rwts_iob_command
    .byte 1                                                           ; 60f2: 01          .  ; Command (0 seek, 1 read, 2 write, 4 format)
; $60f3 referenced 1 time by $604b
rwts_iob_error
    .byte 0                                                           ; 60f3: 00          .  ; Error code (returned)
    .byte 0                                                           ; 60f4: 00          .  ; Volume found (returned)
    .byte $60                                                         ; 60f5: 60          .  ; Slot times 16 last used
    .byte 1                                                           ; 60f6: 01          .  ; Drive last used
rwts_dct
    .byte 0                                                           ; 60f7: 00          .  ; Device type (0 for the Disk II)
    .byte 1                                                           ; 60f8: 01          .  ; Phases per track (1 for the Disk II)
    .word $efd8                                                       ; 60f9: d8 ef       Xo ; Motor on time
rwts_iob_2
    .byte 1                                                           ; 60fb: 01          .  ; Table type (1)
; $60fc referenced 1 time by $6065
rwts_iob_2_slot
    .byte $60                                                         ; 60fc: 60          .  ; Slot times 16
    .byte 2                                                           ; 60fd: 02          .  ; Drive (1 or 2)
    .byte 0                                                           ; 60fe: 00          .  ; Volume expected (0 for any)
    .byte 3                                                           ; 60ff: 03          .  ; Track
    .byte 5                                                           ; 6100: 05          .  ; Sector
    .word DCT                                                         ; 6101: fb b7       {7 ; Device characteristics table
    .word sector_buffer_2                                             ; 6103: 00 40       .. ; Sector buffer (256 bytes)
    .byte 0                                                           ; 6105: 00          .  ; Not used
    .byte 0                                                           ; 6106: 00          .  ; Byte count for a partial sector (0 for 256)
    .byte 2                                                           ; 6107: 02          .  ; Command (0 seek, 1 read, 2 write, 4 format)
    .byte 0                                                           ; 6108: 00          .  ; Error code (returned)
    .byte 0                                                           ; 6109: 00          .  ; Volume found (returned)
    .byte $60                                                         ; 610a: 60          .  ; Slot times 16 last used
    .byte 1                                                           ; 610b: 01          .  ; Drive last used
pydis_end

.cerror (<IOB) != $e8, "Assertion failed: <IOB == $e8"
.cerror (<output_handler) != $e3, "Assertion failed: <output_handler == $e3"
.cerror (<rwts_iob) != $e6, "Assertion failed: <rwts_iob == $e6"
.cerror (<rwts_iob_2) != $fb, "Assertion failed: <rwts_iob_2 == $fb"
.cerror (>IOB) != $b7, "Assertion failed: >IOB == $b7"
.cerror (>output_handler) != $60, "Assertion failed: >output_handler == $60"
.cerror (>rwts_iob) != $60, "Assertion failed: >rwts_iob == $60"
.cerror (>rwts_iob_2) != $60, "Assertion failed: >rwts_iob_2 == $60"
.cerror (DCT) != $b7fb, "Assertion failed: DCT == $b7fb"
.cerror (rwts_dct) != $60f7, "Assertion failed: rwts_dct == $60f7"
.cerror (sector_buffer) != $1000, "Assertion failed: sector_buffer == $1000"
.cerror (sector_buffer_2) != $4000, "Assertion failed: sector_buffer_2 == $4000"

; Label references by decreasing frequency:
;     l0006:                   7
;     l0007:                   5
;     COUT:                    4
;     dos_file_manager:        3
;     usr_jump:                3
;     dos_rwts:                2
;     dos_warm_start:          2
;     CSWH:                    1
;     CSWL:                    1
;     IBSLOT:                  1
;     IBSTAT:                  1
;     RWTS:                    1
;     c6008:                   1
;     c601f:                   1
;     c60c9:                   1
;     dos_basic_flag:          1
;     dos_buffer_chain:        1
;     dos_cold_start:          1
;     dos_connect_hooks:       1
;     dos_get_fm_params:       1
;     dos_get_iob:             1
;     dos_load_address:        1
;     dos_load_length:         1
;     dos_maxfiles:            1
;     dos_rwts_entry:          1
;     dos_saved_output_hook:   1
;     l0008:                   1
;     l0009:                   1
;     l60cc:                   1
;     l60e2:                   1
;     loop_c6014:              1
;     rwts_iob_2_slot:         1
;     rwts_iob_command:        1
;     rwts_iob_error:          1
;     rwts_iob_sector:         1
;     rwts_iob_track:          1

; Automatically generated labels:
;     c6008
;     c601f
;     c60c9
;     l0006
;     l0007
;     l0008
;     l0009
;     l60cc
;     l60e2
;     loop_c6014

; Stats:
;
;     Total size (Code + Data) = 268 bytes
;     Code                     = 207 bytes (77%)
;     Data                     = 61 bytes (23%)
;
;     Number of instructions   = 87
;     Number of data bytes     = 31 bytes
;     Number of data words     = 10 bytes
;     Number of string bytes   = 20 bytes
;     Number of strings        = 1

