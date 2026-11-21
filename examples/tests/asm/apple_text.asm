; Text in the Apple II's high ASCII (ASCII with bit 7 set), for
; python/apple_text.py: strings ending with a zero, a CR, or a last
; character with bit 7 clear (as Merlin's DCI writes them), double quotes,
; a string py8dis finds by itself, an ASCII one, and characters printed with
; the Monitor's COUT. Assemble with:
;
;   acme -o ../orig/apple_text.orig apple_text.asm

cout = $fded

* = $0800

start
    ; Print message (high ASCII, ending with a zero)
    ldx #0
print_message
    lda message,x
    beq print_characters
    jsr cout
    inx
    bne print_message

    ; Print some characters
print_characters
    lda #'A' | $80
    jsr cout
    lda #'"' | $80
    jsr cout
    lda #$8d                ; CR
    jsr cout

    ; Print dci_message (high ASCII, its last character with bit 7 clear)
    ldx #0
print_dci_message
    lda dci_message,x
    php
    ora #$80
    jsr cout
    inx
    plp
    bmi print_dci_message

    ; Use the other strings
    lda line
    ldx ascii_message
    ldy found_by_itself
    rts

message
    !xor $80 {
        !text "SAY ", '"', "HI", '"', " TO ", "\\", "APPLE II!"
    }
    !byte $8d, 0

dci_message
    !xor $80 {
        !text "DON"
    }
    !text "E"

line
    !xor $80 {
        !text "LINE"
    }
    !byte $8d

ascii_message
    !text "low ASCII", 0

found_by_itself
    !xor $80 {
        !text "FOUND BY ITSELF"
    }
    !byte 0
