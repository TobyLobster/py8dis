; Constants
C_RAWIO     equ 6
C_READSTR   equ 10
C_WRITE     equ 2
C_WRITESTR  equ 9
DRV_GET     equ 25
F_DMAOFF    equ 26
F_OPEN      equ 15
F_READ      equ 20
P_TERMCPM   equ 0

; Memory locations
BDOS        equ $05
default_fcb equ $5c
default_dma equ $80

    org $0100

pydis_start:
    lhld BDOS+1                                                       ; 0100: 2a 06 00    *..
    sphl                                                              ; 0103: f9          .
    lxi de, message                                                   ; 0104: 11 68 01    .h.
    mvi c, C_WRITESTR                                                 ; 0107: 0e 09       ..
    call BDOS                                                         ; 0109: cd 05 00    ... ; Print the string at DE, up to a '$'
    mvi e, $41 ; 'A'                                                  ; 010c: 1e 41       .A
    mvi c, C_WRITE                                                    ; 010e: 0e 02       ..
    call BDOS                                                         ; 0110: cd 05 00    ... ; Write 'A' to the console
    mvi e, $0d                                                        ; 0113: 1e 0d       ..
    mvi c, C_WRITE                                                    ; 0115: 0e 02       ..
    call BDOS                                                         ; 0117: cd 05 00    ... ; Write $0D (carriage return) to the console
    mvi e, $ff                                                        ; 011a: 1e ff       ..
    mvi c, C_RAWIO                                                    ; 011c: 0e 06       ..
    call BDOS                                                         ; 011e: cd 05 00    ... ; Read a character from the console without echoing it (0 if none)
    mvi c, DRV_GET                                                    ; 0121: 0e 19       ..
    call BDOS                                                         ; 0123: cd 05 00    ... ; Get the current drive (into A, 0 is A:)
    lxi de, default_dma                                               ; 0126: 11 80 00    ...
    mvi c, F_DMAOFF                                                   ; 0129: 0e 1a       ..
    call BDOS                                                         ; 012b: cd 05 00    ... ; Set the DMA address (for reading and writing records) to DE
    lxi de, default_fcb                                               ; 012e: 11 5c 00    .\.
    mvi a, F_OPEN                                                     ; 0131: 3e 0f       >.
    call file                                                         ; 0133: cd 5a 01    .Z. ; Open the file whose FCB is at DE
    lxi de, dma_buffer                                                ; 0136: 11 cc 01    ...
    mvi c, F_DMAOFF                                                   ; 0139: 0e 1a       ..
    call BDOS                                                         ; 013b: cd 05 00    ... ; Set the DMA address (for reading and writing records) to DE
    lxi de, fcb                                                       ; 013e: 11 86 01    ...
    mvi a, F_READ                                                     ; 0141: 3e 14       >.
    call file                                                         ; 0143: cd 5a 01    .Z. ; Read the next record of the file whose FCB is at DE
    lda default_dma                                                   ; 0146: 3a 80 00    :..
    ora a                                                             ; 0149: b7          .
    jz c0155                                                          ; 014a: ca 55 01    .U.
    lxi de, input_buffer                                              ; 014d: 11 aa 01    ...
    mvi c, C_READSTR                                                  ; 0150: 0e 0a       ..
    call BDOS                                                         ; 0152: cd 05 00    ... ; Read a line from the console into the buffer at DE
; $0155 referenced 1 time by $014a
c0155:
    mvi c, P_TERMCPM                                                  ; 0155: 0e 00       ..
    jmp BDOS                                                          ; 0157: c3 05 00    ... ; End the program (warm boot)

; $015a referenced 2 times by $0133, $0143
file:
    mov c, a                                                          ; 015a: 4f          O
    call BDOS                                                         ; 015b: cd 05 00    ...
    inr a                                                             ; 015e: 3c          <
    rnz                                                               ; 015f: c0          .
    lxi de, message_2                                                 ; 0160: 11 77 01    .w.
    mvi c, C_WRITESTR                                                 ; 0163: 0e 09       ..
    jmp BDOS                                                          ; 0165: c3 05 00    ... ; Print the string at DE, up to a '$'

message:
    db "Hello, world", $0d, $0a, "$"                                  ; 0168: 48 65 6c... Hel
message_2:
    db "File not found$"                                              ; 0177: 46 69 6c... Fil
fcb:
    db 0                                                              ; 0186: 00          .
    db "DATA    TXT"                                                  ; 0187: 44 41 54... DAT
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0192: 00 00 00... ...
    db 0, 0, 0                                                        ; 01a7: 00 00 00    ...
input_buffer:
    db $20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 01aa: 20 00 00...  ..
    db   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                     ; 01be: 00 00 00... ...
dma_buffer:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 01cc: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 01e1: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 01f6: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 020b: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0220: 00 00 00... ...
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0235: 00 00 00... ...
    db 0, 0                                                           ; 024a: 00 00       ..
pydis_end:

; ASSERT ((default_dma) == $80)
; ASSERT ((default_fcb) == $5c)
; ASSERT ((dma_buffer) == $01cc)
; ASSERT ((fcb) == $0186)
; ASSERT ((input_buffer) == $01aa)
; ASSERT ((message) == $0168)
; ASSERT ((message_2) == $0177)

; Label references by decreasing frequency:
;     BDOS:         11
;     file:          2
;     c0155:         1
;     default_dma:   1

; Automatically generated labels:
;     c0155

; Stats:
;
;     Total size (Code + Data) = 332 bytes
;     Code                     = 104 bytes (31%)
;     Data                     = 228 bytes (69%)
;
;     Number of instructions   = 43
;     Number of data bytes     = 187 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 41 bytes
;     Number of strings        = 3

