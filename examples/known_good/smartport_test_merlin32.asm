; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Constants
SP_CONTROL      equ $04
SP_INIT         equ $05
SP_READ         equ $08
SP_READBLOCK    equ $01
SP_STATUS       equ $00
SP_WRITEBLOCK   equ $02

; Memory locations

; Zero page ($00-$ff)
l0000   equ $00

; Hi-res page 1 ($2000-$3fff)
data_buffer     equ $2000
data_buffer_2   equ $2200

; Slot ROMs ($c100-$c7ff)
slot_3_entry equ $c300
lc501       equ $c501
lc507       equ $c507
lc5ff       equ $c5ff
slot_6_entry equ $c600

; Monitor ROM ($f800-$ffff)
COUT equ $fded

    org $0803

pydis_start
start
    jsr slot_3_entry                                                  ; 0803: 20 00 c3    ..C ; Start the 80-column firmware (as PR#3 does)
    lda lc501                                                         ; 0806: ad 01 c5    -.E
    cmp #$20                                                          ; 0809: c9 20       I.
    bne c084f                                                         ; 080b: d0 42       P.
    lda lc507                                                         ; 080d: ad 07 c5    -.E
    bne c084f                                                         ; 0810: d0 3d       P.
    lda lc5ff                                                         ; 0812: ad ff c5    -.E
    clc                                                               ; 0815: 18          .
    adc #3                                                            ; 0816: 69 03       ..
    sta l085c                                                         ; 0818: 8d 5c 08    ...
    lda #$c5 ; 'E'                                                    ; 081b: a9 c5       )E
    sta l085d                                                         ; 081d: 8d 5d 08    ...
    jsr smartport                                                     ; 0820: 20 5b 08    ... ; SmartPort: read a device's status
    dfb SP_STATUS                                                     ; 0823: 00          .
    da sp_status_params                                               ; 0824: 5e 08       ..

    bcs c0857                                                         ; 0826: b0 2f       0.
    jsr smartport                                                     ; 0828: 20 5b 08    ... ; SmartPort: read a block
    dfb SP_READBLOCK                                                  ; 082b: 01          .
    da sp_readblock_params                                            ; 082c: 63 08       ..

    jsr smartport                                                     ; 082e: 20 5b 08    ... ; SmartPort: write a block
    dfb SP_WRITEBLOCK                                                 ; 0831: 02          .
    da sp_writeblock_params                                           ; 0832: 6a 08       ..

    jsr smartport                                                     ; 0834: 20 5b 08    ... ; SmartPort: control a device
    dfb SP_CONTROL                                                    ; 0837: 04          .
    da sp_control_params                                              ; 0838: 71 08       ..

    jsr smartport                                                     ; 083a: 20 5b 08    ... ; SmartPort: reset the devices
    dfb SP_INIT                                                       ; 083d: 05          .
    da sp_init_params                                                 ; 083e: 76 08       ..

    jsr smartport                                                     ; 0840: 20 5b 08    ... ; SmartPort: read bytes
    dfb SP_READ                                                       ; 0843: 08          .
    da sp_read_params                                                 ; 0844: 78 08       ..

    jsr smartport                                                     ; 0846: 20 5b 08    ... ; SmartPort: call $20
    dfb $20                                                           ; 0849: 20          .
    da sp_readblock_params                                            ; 084a: 63 08       ..

    jmp slot_6_entry                                                  ; 084c: 4c 00 c6    ..F ; Start slot 6's firmware (as PR#6 does: for a disk, boot it)

; $084f referenced 2 times by $080b, $0810
c084f
    jsr smartport                                                     ; 084f: 20 5b 08    ... ; SmartPort: extended call $41 (not decoded, so tracing stops)
    dfb $41                                                           ; 0852: 41          .
    dfb $63, 8, 0, 0                                                  ; 0853: 63 08 00... ...

; $0857 referenced 1 time by $0826
c0857
    jsr COUT                                                          ; 0857: 20 ed fd    .m} ; Print a character (through CSW)
    rts                                                               ; 085a: 60          .

; $085b referenced 8 times by $0820, $0828, $082e, $0834, $083a, $0840, $0846, $084f
smartport
l085c equ smartport+1
l085d equ smartport+2
    jmp l0000                                                         ; 085b: 4c 00 00    ...

; $085c referenced 1 time by $0818
; $085d referenced 1 time by $081d
sp_status_params
    dfb 3                                                             ; 085e: 03          .  ; Parameter count
    dfb 0                                                             ; 085f: 00          .  ; Unit number
    da status_list                                                    ; 0860: 81 08       .. ; Status list
    dfb 0                                                             ; 0862: 00          .  ; Status code
sp_readblock_params
    dfb 3                                                             ; 0863: 03          .  ; Parameter count
    dfb 1                                                             ; 0864: 01          .  ; Unit number
    da data_buffer                                                    ; 0865: 00 20       .. ; Data buffer (512 bytes)
    dfb 0, 0, 0                                                       ; 0867: 00 00 00    ... ; Block number
sp_writeblock_params
    dfb 3                                                             ; 086a: 03          .  ; Parameter count
    dfb 1                                                             ; 086b: 01          .  ; Unit number
    da data_buffer                                                    ; 086c: 00 20       .. ; Data buffer (512 bytes)
    dfb 1, 0, 0                                                       ; 086e: 01 00 00    ... ; Block number
sp_control_params
    dfb 3                                                             ; 0871: 03          .  ; Parameter count
    dfb 1                                                             ; 0872: 01          .  ; Unit number
    da control_list                                                   ; 0873: 89 08       .. ; Control list
    dfb 4                                                             ; 0875: 04          .  ; Control code
sp_init_params
    dfb 1                                                             ; 0876: 01          .  ; Parameter count
    dfb 0                                                             ; 0877: 00          .  ; Unit number (0)
sp_read_params
    dfb 4                                                             ; 0878: 04          .  ; Parameter count
    dfb 2                                                             ; 0879: 02          .  ; Unit number
    da data_buffer_2                                                  ; 087a: 00 22       .. ; Data buffer
    da $0200                                                          ; 087c: 00 02       .. ; Byte count
    dfb 0, 0, 0                                                       ; 087e: 00 00 00    ... ; Address
status_list
    dfb 0, 0, 0, 0, 0, 0, 0, 0                                        ; 0881: 00 00 00... ...
control_list
    dfb 0, 0                                                          ; 0889: 00 00       ..
pydis_end

    err control_list - $0889
    err data_buffer - $2000
    err data_buffer_2 - $2200
    err sp_control_params - $0871
    err sp_init_params - $0876
    err sp_read_params - $0878
    err sp_readblock_params - $0863
    err sp_status_params - $085e
    err sp_writeblock_params - $086a
    err status_list - $0881

; Label references by decreasing frequency:
;     smartport:      8
;     c084f:          2
;     COUT:           1
;     c0857:          1
;     l0000:          1
;     l085c:          1
;     l085d:          1
;     lc501:          1
;     lc507:          1
;     lc5ff:          1
;     slot_3_entry:   1
;     slot_6_entry:   1

; Automatically generated labels:
;     c084f
;     c0857
;     l0000
;     l085c
;     l085d
;     lc501
;     lc507
;     lc5ff

; Stats:
;
;     Total size (Code + Data) = 136 bytes
;     Code                     = 65 bytes (48%)
;     Data                     = 71 bytes (52%)
;
;     Number of instructions   = 25
;     Number of data bytes     = 45 bytes
;     Number of data words     = 26 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
