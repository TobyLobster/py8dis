; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations

; Zero page ($0000-$00ff)
BAS2H   = $002b

; Text and lo-res page 2 ($0800-$0bff)
l0801   = $0801

; Slot I/O ($c090-$c0ff)
slot_7_io   = $c0f0

; ProDOS driver's parameters
driver_command      = $0042
driver_unit         = $0043
driver_buffer       = $0044
driver_buffer_high  = $0045
driver_block        = $0046
driver_block_high   = $0047

    .org $c700

; Slot 7's ROM: PR#7, IN#7 and booting from slot 7 start here
; ID bytes $20, $00 and $03 at $c701, $c703 and $c705: a ProDOS block device, which the
; Autostart ROM boots ($3C at $c707, as a Disk II's)
pydis_start:
slot_7_entry:
    cpx #$20                                                          ; c700: e0 20       `. ; Redundant instruction?
    cpx #0                                                            ; c702: e0 00       `. ; Redundant instruction?
    cpx #3                                                            ; c704: e0 03       `. ; Redundant instruction?
    cpx #$3c                                                          ; c706: e0 3c       `.
    lda #$3f                                                          ; c708: a9 3f       ).
    jmp PageJump                                                      ; c70a: 4c 19 c7    ..G

    .byte <CommInit                                                   ; c70d: 11          .  ; Offset of CommInit
    .byte <CommRead                                                   ; c70e: 43          .  ; Offset of CommRead
    .byte <CommWrite                                                  ; c70f: 49          .  ; Offset of CommWrite
    .byte <CommStatus                                                 ; c710: 4f          .  ; Offset of CommStatus

CommInit:
    lda #$0f                                                          ; c711: a9 0f       ).
    sta slot_7_io+7                                                   ; c713: 8d f7 c0    .w@
    ldx #0                                                            ; c716: a2 00       ".
    rts                                                               ; c718: 60          .

; $c719 referenced 1 time by $c70a
PageJump:
    sta slot_7_io+7                                                   ; c719: 8d f7 c0    .w@
    jmp Start                                                         ; c71c: 4c 27 c7    ..G

; ProDOS's driver for the device (with its parameters at $42-$47)
DriverEntry:
    lda #$0f                                                          ; c71f: a9 0f       ).
    sta slot_7_io+7                                                   ; c721: 8d f7 c0    .w@
    jmp Driver                                                        ; c724: 4c 53 c7    ..G

; $c727 referenced 1 time by $c71c
Start:
    ldx #$70                                                          ; c727: a2 70       ".
    stx BAS2H                                                         ; c729: 86 2b       ..
    stx driver_unit                                                   ; c72b: 86 43       ..
    lda #1                                                            ; c72d: a9 01       ).
    sta driver_command                                                ; c72f: 85 42       ..
    lda #0                                                            ; c731: a9 00       ).
    sta driver_block                                                  ; c733: 85 46       ..
    sta driver_block_high                                             ; c735: 85 47       ..
    sta driver_buffer                                                 ; c737: 85 44       ..
    lda #8                                                            ; c739: a9 08       ).
    sta driver_buffer_high                                            ; c73b: 85 45       ..
    jsr Driver                                                        ; c73d: 20 53 c7    ..G
    jmp l0801                                                         ; c740: 4c 01 08    ...

CommRead:
    jsr GetByte                                                       ; c743: 20 dd c7    .]G
    ldx #0                                                            ; c746: a2 00       ".
    rts                                                               ; c748: 60          .

CommWrite:
    jsr SendByte                                                      ; c749: 20 c5 c7    .EG
    ldx #0                                                            ; c74c: a2 00       ".
    rts                                                               ; c74e: 60          .

CommStatus:
    ldx #0                                                            ; c74f: a2 00       ".
    sec                                                               ; c751: 38          .
    rts                                                               ; c752: 60          .

; $c753 referenced 2 times by $c724, $c73d
Driver:
    ldx driver_unit                                                   ; c753: a6 43       &.
    lda driver_command                                                ; c755: a5 42       %.
    beq GetStatus                                                     ; c757: f0 0c       p.
    cmp #1                                                            ; c759: c9 01       I.
    beq ReadBlock                                                     ; c75b: f0 10       p.
    cmp #2                                                            ; c75d: c9 02       I.
    beq WriteBlock                                                    ; c75f: f0 38       p.
    sec                                                               ; c761: 38          .
    lda #$53                                                          ; c762: a9 53       ).
    rts                                                               ; c764: 60          .

; $c765 referenced 1 time by $c757
GetStatus:
    ldx #$ff                                                          ; c765: a2 ff       ".
    ldy #$ff                                                          ; c767: a0 ff        .
    lda #0                                                            ; c769: a9 00       ).
    clc                                                               ; c76b: 18          .
    rts                                                               ; c76c: 60          .

; $c76d referenced 1 time by $c75b
ReadBlock:
    lda #1                                                            ; c76d: a9 01       ).
    jsr SendByte                                                      ; c76f: 20 c5 c7    .EG
    lda driver_block                                                  ; c772: a5 46       %.
    jsr SendByte                                                      ; c774: 20 c5 c7    .EG
    lda driver_block_high                                             ; c777: a5 47       %.
    jsr SendByte                                                      ; c779: 20 c5 c7    .EG
    txa                                                               ; c77c: 8a          .
    jsr SendByte                                                      ; c77d: 20 c5 c7    .EG
    ldy #0                                                            ; c780: a0 00        .
    jsr read256                                                       ; c782: 20 90 c7    ..G
    inc driver_buffer_high                                            ; c785: e6 45       f.
    jsr read256                                                       ; c787: 20 90 c7    ..G
    dec driver_buffer_high                                            ; c78a: c6 45       F.
    lda #0                                                            ; c78c: a9 00       ).
    clc                                                               ; c78e: 18          .
    rts                                                               ; c78f: 60          .

; $c790 referenced 3 times by $c782, $c787, $c796
read256:
    jsr GetByte                                                       ; c790: 20 dd c7    .]G
    sta (driver_buffer),y                                             ; c793: 91 44       ..
    iny                                                               ; c795: c8          H
    bne read256                                                       ; c796: d0 f8       Px
    rts                                                               ; c798: 60          .

; $c799 referenced 1 time by $c75f
WriteBlock:
    lda #2                                                            ; c799: a9 02       ).
    jsr SendByte                                                      ; c79b: 20 c5 c7    .EG
    lda driver_block                                                  ; c79e: a5 46       %.
    jsr SendByte                                                      ; c7a0: 20 c5 c7    .EG
    lda driver_block_high                                             ; c7a3: a5 47       %.
    jsr SendByte                                                      ; c7a5: 20 c5 c7    .EG
    txa                                                               ; c7a8: 8a          .
    jsr SendByte                                                      ; c7a9: 20 c5 c7    .EG
    ldy #0                                                            ; c7ac: a0 00        .
    jsr write256                                                      ; c7ae: 20 bc c7    .<G
    inc driver_buffer_high                                            ; c7b1: e6 45       f.
    jsr write256                                                      ; c7b3: 20 bc c7    .<G
    dec driver_buffer_high                                            ; c7b6: c6 45       F.
    lda #0                                                            ; c7b8: a9 00       ).
    clc                                                               ; c7ba: 18          .
    rts                                                               ; c7bb: 60          .

; $c7bc referenced 3 times by $c7ae, $c7b3, $c7c2
write256:
    lda (driver_buffer),y                                             ; c7bc: b1 44       1.
    jsr SendByte                                                      ; c7be: 20 c5 c7    .EG
    iny                                                               ; c7c1: c8          H
    bne write256                                                      ; c7c2: d0 f8       Px
    rts                                                               ; c7c4: 60          .

; $c7c5 referenced 11 times by $c749, $c76f, $c774, $c779, $c77d, $c79b, $c7a0, $c7a5, $c7a9, $c7be, $c7c8
SendByte:
    bit slot_7_io+11                                                  ; c7c5: 2c fb c0    .{@
    bvs SendByte                                                      ; c7c8: 70 fb       .{
    sta slot_7_io+13                                                  ; c7ca: 8d fd c0    .}@
    lda #$0e                                                          ; c7cd: a9 0e       ).
    sta slot_7_io+7                                                   ; c7cf: 8d f7 c0    .w@
; $c7d2 referenced 1 time by $c7d5
loop_cc7d2:
    bit slot_7_io+11                                                  ; c7d2: 2c fb c0    .{@
    bvc loop_cc7d2                                                    ; c7d5: 50 fb       .{
    lda #$0f                                                          ; c7d7: a9 0f       ).
    sta slot_7_io+7                                                   ; c7d9: 8d f7 c0    .w@
    rts                                                               ; c7dc: 60          .

; $c7dd referenced 2 times by $c743, $c790
GetByte:
    lda #$0d                                                          ; c7dd: a9 0d       ).
    sta slot_7_io+7                                                   ; c7df: 8d f7 c0    .w@
; $c7e2 referenced 1 time by $c7e5
loop_cc7e2:
    bit slot_7_io+11                                                  ; c7e2: 2c fb c0    .{@
    bmi loop_cc7e2                                                    ; c7e5: 30 fb       .{
    lda slot_7_io+14                                                  ; c7e7: ad fe c0    -~@
    pha                                                               ; c7ea: 48          .
    lda #$0f                                                          ; c7eb: a9 0f       ).
    sta slot_7_io+7                                                   ; c7ed: 8d f7 c0    .w@
; $c7f0 referenced 1 time by $c7f3
loop_cc7f0:
    bit slot_7_io+11                                                  ; c7f0: 2c fb c0    .{@
    bpl loop_cc7f0                                                    ; c7f3: 10 fb       .{
    pla                                                               ; c7f5: 68          .
    rts                                                               ; c7f6: 60          .

    .byte 0, 0, 0, 0, 0                                               ; c7f7: 00 00 00... ...
    .word 0                                                           ; c7fc: 00 00       .. ; Number of blocks (0: read it with STATUS)
    .byte $17                                                         ; c7fe: 17          .  ; Status: 1 volume; writes, reads, gives its status
    .byte <DriverEntry                                                ; c7ff: 1f          .  ; The low byte of the driver's address
pydis_end:

.assert (<CommInit) = $11, error, "Assertion failed: <CommInit = $11"
.assert (<CommRead) = $43, error, "Assertion failed: <CommRead = $43"
.assert (<CommStatus) = $4f, error, "Assertion failed: <CommStatus = $4f"
.assert (<CommWrite) = $49, error, "Assertion failed: <CommWrite = $49"
.assert (<DriverEntry) = $1f, error, "Assertion failed: <DriverEntry = $1f"

; Label references by decreasing frequency:
;     SendByte:            11
;     driver_buffer_high:   5
;     driver_block:         3
;     driver_block_high:    3
;     driver_buffer:        3
;     read256:              3
;     write256:             3
;     Driver:               2
;     GetByte:              2
;     driver_command:       2
;     driver_unit:          2
;     BAS2H:                1
;     GetStatus:            1
;     PageJump:             1
;     ReadBlock:            1
;     Start:                1
;     WriteBlock:           1
;     l0801:                1
;     loop_cc7d2:           1
;     loop_cc7e2:           1
;     loop_cc7f0:           1

; Automatically generated labels:
;     l0801
;     loop_cc7d2
;     loop_cc7e2
;     loop_cc7f0

; Stats:
;
;     Total size (Code + Data) = 256 bytes
;     Code                     = 243 bytes (95%)
;     Data                     = 13 bytes (5%)
;
;     Number of instructions   = 116
;     Number of data bytes     = 11 bytes
;     Number of data words     = 2 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

