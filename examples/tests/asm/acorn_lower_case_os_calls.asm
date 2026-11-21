; Calls to the BBC Micro's OS, for python/acorn_lower_case_os_calls.py, which
; names them in lower case (config.set_upper_case_os_calls(False)). Assemble
; with:
;
;   acme -o ../orig/acorn_lower_case_os_calls.orig acorn_lower_case_os_calls.asm

    * = $2000

start
    lda #'A'
    jsr $ffee           ; OSWRCH
    lda #13
    jsr $ffe3           ; OSASCI with A=13, which writes a newline
    lda #$81
    ldx #0
    ldy #$ff
    jsr $fff4           ; OSBYTE
    ldx #<command
    ldy #>command
    jsr $fff7           ; OSCLI
    clc
    jsr $ffc2           ; GSINIT
    jsr $ffc5           ; GSREAD
    rts

command
    !text "CAT", 13
