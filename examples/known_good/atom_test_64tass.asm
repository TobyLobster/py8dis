; Memory locations

; Zero page ($0000-$00ff)
text_space_page = $0012
l0070           = $0070
l0071           = $0071
l0072           = $0072
l0073           = $0073
cursor_column   = $00e0

; OS vectors ($0200-$021f)
brkvec  = $0202
wrcvec  = $0208

; I/O ($b000-$bfff)
ppi_port_b      = $b001
ppi_port_c      = $b002
via_register_a  = $b801

; Kernel ROM ($f000-$ffca)
print_inline_string = $f7d1
print_space         = $f7fd
print_hex           = $f802
kernel_wrch         = $fe52
wait_for_flyback    = $fe66

; OS entry points ($ffcb-$fff9)
OSSHUT  = $ffcb
OSFIND  = $ffce
OSBPUT  = $ffd1
OSBGET  = $ffd4
OSSAVE  = $ffdd
OSLOAD  = $ffe0
OSRDCH  = $ffe3
OSECHO  = $ffe6
OSASCI  = $ffe9
OSCRLF  = $ffed
OSWRCH  = $fff4
OSCLI   = $fff7

    * = $2900

pydis_start
start
    ; Clear the screen
    lda #$0c                                                          ; 2900: a9 0c       ..
    jsr OSWRCH                                                        ; 2902: 20 f4 ff     .. ; Write character 12
    ; Print "HI"
    lda #$48 ; 'H'                                                    ; 2905: a9 48       .H
    jsr OSWRCH                                                        ; 2907: 20 f4 ff     .. ; Write character 72
    lda #$49 ; 'I'                                                    ; 290a: a9 49       .I
    jsr OSWRCH                                                        ; 290c: 20 f4 ff     .. ; Write character 73
    jsr OSCRLF                                                        ; 290f: 20 ed ff     .. ; Write newline (characters 10 and 13)
    ; Sound the bell
    lda #7                                                            ; 2912: a9 07       ..
    jsr OSWRCH                                                        ; 2914: 20 f4 ff     .. ; Write character 7
    ; Page mode on
    lda #$0e                                                          ; 2917: a9 0e       ..
    jsr OSWRCH                                                        ; 2919: 20 f4 ff     .. ; Write character 14
    lda #$41 ; 'A'                                                    ; 291c: a9 41       .A
    jsr OSASCI                                                        ; 291e: 20 e9 ff     .. ; Write character 65
    ; Start a new line
    lda #$0d                                                          ; 2921: a9 0d       ..
    jsr OSASCI                                                        ; 2923: 20 e9 ff     .. ; Write newline (characters 10 and 13)
    ; Start a new line
    lda #$0d                                                          ; 2926: a9 0d       ..
    jsr OSWRCH                                                        ; 2928: 20 f4 ff     .. ; Write character 13
    lda #$0a                                                          ; 292b: a9 0a       ..
    jsr OSWRCH                                                        ; 292d: 20 f4 ff     .. ; Write character 10
    jsr print_inline_string                                           ; 2930: 20 d1 f7     .. ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    .text "HELLO ATOM"                                                ; 2933: 48 45 4c... HEL

    nop                                                               ; 293d: ea          .
    ; print message
    ldx #0                                                            ; 293e: a2 00       ..
; $2940 referenced 1 time by $2949
loop_c2940
    lda l29a8,x                                                       ; 2940: bd a8 29    ..)
    jsr OSWRCH                                                        ; 2943: 20 f4 ff     .. ; Write character
    inx                                                               ; 2946: e8          .
    cpx #4                                                            ; 2947: e0 04       ..
    bne loop_c2940                                                    ; 2949: d0 f5       ..
    lda #$41 ; 'A'                                                    ; 294b: a9 41       .A ; A=byte to print
    jsr print_hex                                                     ; 294d: 20 02 f8     .. ; Print A in hex
    jsr print_space                                                   ; 2950: 20 fd f7     .. ; Print a space
    jsr wait_for_flyback                                              ; 2953: 20 66 fe     f. ; Wait for the start of the next field flyback

    ; Set write character vector to 'handle_wrcvec'
    lda #<handle_wrcvec                                               ; 2956: a9 a5       ..
    sta wrcvec                                                        ; 2958: 8d 08 02    ...
    lda #>handle_wrcvec                                               ; 295b: a9 29       .)
    sta wrcvec+1                                                      ; 295d: 8d 09 02    ...

    lda #0                                                            ; 2960: a9 00       ..
    sta brkvec                                                        ; 2962: 8d 02 02    ... ; Set the low byte of BRK vector to $00
    jsr OSRDCH                                                        ; 2965: 20 e3 ff     .. ; Read a character
    sta l0070                                                         ; 2968: 85 70       .p ; A=character read
    jsr OSECHO                                                        ; 296a: 20 e6 ff     .. ; Read a character and write it
    sta l0071                                                         ; 296d: 85 71       .q ; A=character read
    sec                                                               ; 296f: 38          8
    ldx #$80                                                          ; 2970: a2 80       .. ; X=zero page address of the file name's address
    jsr OSFIND                                                        ; 2972: 20 ce ff     .. ; Open file for input (C=1)
    sta l0072                                                         ; 2975: 85 72       .r ; A=file handle (or zero if not found)
    ldy l0072                                                         ; 2977: a4 72       .r ; Y=file handle
    jsr OSBGET                                                        ; 2979: 20 d4 ff     .. ; Read a byte from file Y
    sta l0073                                                         ; 297c: 85 73       .s ; A=byte read
    lda #$41 ; 'A'                                                    ; 297e: a9 41       .A
    ldy l0072                                                         ; 2980: a4 72       .r ; Y=file handle
    jsr OSBPUT                                                        ; 2982: 20 d1 ff     .. ; Write byte A=65 to file Y
    ldy #0                                                            ; 2985: a0 00       ..
    jsr OSSHUT                                                        ; 2987: 20 cb ff     .. ; Close all files (Y=0)
    ldx #$84                                                          ; 298a: a2 84       .. ; X=zero page address of the load parameter block
    jsr OSLOAD                                                        ; 298c: 20 e0 ff     .. ; Load a file
    ldx #$84                                                          ; 298f: a2 84       .. ; X=zero page address of the save parameter block
    jsr OSSAVE                                                        ; 2991: 20 dd ff     .. ; Save a file
    jsr OSCLI                                                         ; 2994: 20 f7 ff     .. ; Run the command in the input buffer
    lda ppi_port_b                                                    ; 2997: ad 01 b0    ...
    sta via_register_a                                                ; 299a: 8d 01 b8    ...
    lda ppi_port_c                                                    ; 299d: ad 02 b0    ...
    ldx cursor_column                                                 ; 29a0: a6 e0       ..
    lda text_space_page                                               ; 29a2: a5 12       ..
    rts                                                               ; 29a4: 60          `

handle_wrcvec
    jmp kernel_wrch                                                   ; 29a5: 4c 52 fe    LR. ; Write character A (the kernel's OSWRCH, WRCVEC's default)

; $29a8 referenced 1 time by $2940
l29a8
    .text "ATOM"                                                      ; 29a8: 41 54 4f... ATO
pydis_end

.cerror (<handle_wrcvec) != $a5, "Assertion failed: <handle_wrcvec == $a5"
.cerror (>handle_wrcvec) != $29, "Assertion failed: >handle_wrcvec == $29"

; Label references by decreasing frequency:
;     OSWRCH:                8
;     l0072:                 3
;     OSASCI:                2
;     OSBGET:                1
;     OSBPUT:                1
;     OSCLI:                 1
;     OSCRLF:                1
;     OSECHO:                1
;     OSFIND:                1
;     OSLOAD:                1
;     OSRDCH:                1
;     OSSAVE:                1
;     OSSHUT:                1
;     brkvec:                1
;     cursor_column:         1
;     kernel_wrch:           1
;     l0070:                 1
;     l0071:                 1
;     l0073:                 1
;     l29a8:                 1
;     loop_c2940:            1
;     ppi_port_b:            1
;     ppi_port_c:            1
;     print_hex:             1
;     print_inline_string:   1
;     print_space:           1
;     text_space_page:       1
;     via_register_a:        1
;     wait_for_flyback:      1
;     wrcvec:                1

; Automatically generated labels:
;     l0070
;     l0071
;     l0072
;     l0073
;     l29a8
;     loop_c2940

; Stats:
;
;     Total size (Code + Data) = 172 bytes
;     Code                     = 158 bytes (92%)
;     Data                     = 14 bytes (8%)
;
;     Number of instructions   = 65
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 14 bytes
;     Number of strings        = 2

