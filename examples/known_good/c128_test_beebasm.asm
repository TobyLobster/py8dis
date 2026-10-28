; Constants
colour_blue     = 6
device_disk_8   = 8

; Memory locations

; Zero page (&0000-&00ff)
far_call_bank       = &0002
far_call_pc_high    = &0003
far_call_pc_low     = &0004
far_call_status     = &0005
far_call_a          = &0006
screen_mode_40_80   = &00d7

; OS workspace (&0200-&03ff)
irq_vector  = &0314

; VIC-II (&d000-&d3ff)
vic_border_colour       = &d020
vic_background_colour_0 = &d021
vic_clock_speed         = &d030

; VDC (&d600-&d6ff)
vdc_address = &d600
vdc_data    = &d601

; Kernal ROM (&e000-&feff)
kernal_irq_handler  = &fa65

; MMU (&ff00-&ff04)
mmu_configuration   = &ff00

; Kernal entry points (&ff47-&fff9)
setbnk  = &ff68
jsrfar  = &ff6e
jmpfar  = &ff71
primm   = &ff7d
setlfs  = &ffba
setnam  = &ffbd
chrout  = &ffd2
load    = &ffd5

; The PRG file's header: the address to load it at
    org &1bff
    equw &1c01

    org &1c01

; 10 SYS7181
.pydis_start
.basic_line_10
    equw basic_end                                                    ; 1c01: 0b 1c       ..
    equw 10                                                           ; 1c03: 0a 00       ..
    equb &9e                                                          ; 1c05: 9e          .
    equb &37, &31, &38, &31 ; petscii "7181"                          ; 1c06: 37 31 38... 718
    equb 0                                                            ; 1c0a: 00          .
.basic_end
    equw 0                                                            ; 1c0b: 00 00       ..

.sys_entry
    lda #0                                                            ; 1c0d: a9 00       ..
    sta mmu_configuration                                             ; 1c0f: 8d 00 ff    ...
    lda #1                                                            ; 1c12: a9 01       ..
    sta vic_clock_speed                                               ; 1c14: 8d 30 d0    .0P
    jsr primm                                                         ; 1c17: 20 7d ff     .. ; Print the zero-terminated string that follows the JSR
    equb &48, &45, &4c, &4c, &4f, &2c, &20, &43 ; petscii "hello, c"  ; 1c1a: 48 45 4c... hel
    equb &31, &32, &38, &0d, 0 ; petscii "128", &0d, &00              ; 1c22: 31 32 38... 128

    lda #&21 ; '!'                                                    ; 1c27: a9 21       .! ; A=character to output
    jsr chrout                                                        ; 1c29: 20 d2 ff     R. ; Output '!'
    lda #colour_blue                                                  ; 1c2c: a9 06       ..
    sta vic_border_colour                                             ; 1c2e: 8d 20 d0    . P
    ldx #&1a                                                          ; 1c31: a2 1a       ..
    stx vdc_address                                                   ; 1c33: 8e 00 d6    ..V
; &1c36 referenced 1 time by &1c39
.loop_c1c36
    bit vdc_address                                                   ; 1c36: 2c 00 d6    ,.V
    bpl loop_c1c36                                                    ; 1c39: 10 fb       ..
    lda #&f0                                                          ; 1c3b: a9 f0       ..
    sta vdc_data                                                      ; 1c3d: 8d 01 d6    ..V
    lda screen_mode_40_80                                             ; 1c40: a5 d7       .W
    sta l1ccd                                                         ; 1c42: 8d cd 1c    .M.
    sei                                                               ; 1c45: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 1c46: a9 c3       .C
    sta irq_vector                                                    ; 1c48: 8d 14 03    ...
    lda #>irq_handler                                                 ; 1c4b: a9 1c       ..
    sta irq_vector+1                                                  ; 1c4d: 8d 15 03    ...

    cli                                                               ; 1c50: 58          x

    ; Call far_call_target in bank 0
    lda #0                                                            ; 1c51: a9 00       ..
    sta far_call_bank                                                 ; 1c53: 85 02       ..
    lda #>far_call_target                                             ; 1c55: a9 1c       ..
    sta far_call_pc_high                                              ; 1c57: 85 03       ..
    lda #<far_call_target                                             ; 1c59: a9 a8       ..
    sta far_call_pc_low                                               ; 1c5b: 85 04       ..
    jsr jsrfar                                                        ; 1c5d: 20 6e ff     .. ; Call a routine in another bank (set up at $02-$08)

    ; Call far_call_target_2 in bank 15
    lda #<far_call_target_2                                           ; 1c60: a9 ac       ..
    sta far_call_pc_low                                               ; 1c62: 85 04       ..
    ldx #&0f                                                          ; 1c64: a2 0f       ..
    stx far_call_bank                                                 ; 1c66: 86 02       ..
    lda #0                                                            ; 1c68: a9 00       ..
    sta far_call_status                                               ; 1c6a: 85 05       ..
    ldy #>far_call_target_2                                           ; 1c6c: a0 1c       ..
    sty far_call_pc_high                                              ; 1c6e: 84 03       ..
    lda #1                                                            ; 1c70: a9 01       ..
    sta far_call_a                                                    ; 1c72: 85 06       ..
    jsr jsrfar                                                        ; 1c74: 20 6e ff     .. ; Call a routine in another bank (set up at $02-$08)

    ; Call $2000 in bank 1
    lda #1                                                            ; 1c77: a9 01       ..
    sta far_call_bank                                                 ; 1c79: 85 02       ..
    lda #&20 ; ' '                                                    ; 1c7b: a9 20       .
    sta far_call_pc_high                                              ; 1c7d: 85 03       ..
    lda #0                                                            ; 1c7f: a9 00       ..
    sta far_call_pc_low                                               ; 1c81: 85 04       ..
    jsr jsrfar                                                        ; 1c83: 20 6e ff     .. ; Call a routine in another bank (set up at $02-$08)

    jsr sub_c1cb0                                                     ; 1c86: 20 b0 1c     ..
    lda #1                                                            ; 1c89: a9 01       .. ; A=bank for the data
    ldx #0                                                            ; 1c8b: a2 00       .. ; X=bank for the filename
    jsr setbnk                                                        ; 1c8d: 20 68 ff     .. ; Set the banks for LOAD, SAVE and VERIFY, and for the filename
    lda #1                                                            ; 1c90: a9 01       .. ; A=logical file number
    ldx #device_disk_8                                                ; 1c92: a2 08       .. ; X=device number
    ldy #1                                                            ; 1c94: a0 01       .. ; Y=secondary address
    jsr setlfs                                                        ; 1c96: 20 ba ff     .. ; Set logical file 1 to device 8 (disk drive), secondary address 1
    lda #4                                                            ; 1c99: a9 04       .. ; A=filename length
    ldx #<filename                                                    ; 1c9b: a2 c9       .I ; X=filename address (low byte)
    ldy #>filename                                                    ; 1c9d: a0 1c       .. ; Y=filename address (high byte)
    jsr setnam                                                        ; 1c9f: 20 bd ff     .. ; Set the filename to "data"
    lda #0                                                            ; 1ca2: a9 00       .. ; A=0 to load, 1 to verify
    jsr load                                                          ; 1ca4: 20 d5 ff     U. ; Load a file
    rts                                                               ; 1ca7: 60          .

.far_call_target
    inc vic_border_colour                                             ; 1ca8: ee 20 d0    . P
    rts                                                               ; 1cab: 60          .

.far_call_target_2
    dec vic_border_colour                                             ; 1cac: ce 20 d0    N P
    rts                                                               ; 1caf: 60          .


; &1cb0 referenced 1 time by &1c86
.sub_c1cb0
    ; Jump to far_jump_target in bank 0
    lda #0                                                            ; 1cb0: a9 00       ..
    sta far_call_bank                                                 ; 1cb2: 85 02       ..
    lda #>far_jump_target                                             ; 1cb4: a9 1c       ..
    sta far_call_pc_high                                              ; 1cb6: 85 03       ..
    lda #<far_jump_target                                             ; 1cb8: a9 bf       ..
    sta far_call_pc_low                                               ; 1cba: 85 04       ..
    jmp jmpfar                                                        ; 1cbc: 4c 71 ff    l.. ; Jump to a routine in another bank (set up at $02-$08)


.far_jump_target
    inc vic_background_colour_0                                       ; 1cbf: ee 21 d0    .!P
    rts                                                               ; 1cc2: 60          .

.irq_handler
    inc vic_border_colour                                             ; 1cc3: ee 20 d0    . P
    jmp kernal_irq_handler                                            ; 1cc6: 4c 65 fa    l.. ; The Kernal's IRQ handler (blinks the cursor, scans the keyboard etc., then returns from the interrupt)

.filename
    equb &44, &41, &54, &41 ; petscii "data"                          ; 1cc9: 44 41 54... dat
; &1ccd referenced 1 time by &1c42
.l1ccd
    equb 0                                                            ; 1ccd: 00          .
.pydis_end

    assert &a8 == <far_call_target
    assert &ac == <far_call_target_2
    assert &bf == <far_jump_target
    assert &c9 == <filename
    assert &c3 == <irq_handler
    assert &1c == >far_call_target
    assert &1c == >far_call_target_2
    assert &1c == >far_jump_target
    assert &1c == >filename
    assert &1c == >irq_handler
    assert &1c0b == basic_end

save pydis_start - 2, pydis_end

; Label references by decreasing frequency:
;     far_call_bank:             4
;     far_call_pc_high:          4
;     far_call_pc_low:           4
;     vic_border_colour:         4
;     jsrfar:                    3
;     vdc_address:               2
;     chrout:                    1
;     far_call_a:                1
;     far_call_status:           1
;     irq_vector:                1
;     jmpfar:                    1
;     kernal_irq_handler:        1
;     l1ccd:                     1
;     load:                      1
;     loop_c1c36:                1
;     mmu_configuration:         1
;     primm:                     1
;     screen_mode_40_80:         1
;     setbnk:                    1
;     setlfs:                    1
;     setnam:                    1
;     sub_c1cb0:                 1
;     vdc_data:                  1
;     vic_background_colour_0:   1
;     vic_clock_speed:           1

; Automatically generated labels:
;     l1ccd
;     loop_c1c36
;     sub_c1cb0

; Stats:
;
;     Total size (Code + Data) = 205 bytes
;     Code                     = 175 bytes (85%)
;     Data                     = 30 bytes (15%)
;
;     Number of instructions   = 78
;     Number of data bytes     = 3 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 21 bytes
;     Number of strings        = 3

