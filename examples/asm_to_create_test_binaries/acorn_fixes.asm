; A BBC Micro program for python/acorn_fixes.py, with things acorn.py used to
; comment wrongly or not at all: a character written twice with OSWRCH, from
; X the first time, where X has changed before the second (VDU 31's column
; and row), and a table of
; the offsets of the 32 character rows as words. Assemble with:
;
;   acme -o ../orig/acorn_fixes.orig acorn_fixes.asm
;
; (It isn't meant to do anything useful when run.)

oswrch = $ffee

* = $2000

start
    ; VDU 31 (move the text cursor) with the column from X; then the row is
    ; A again, which is no longer X, since X has changed
    ldx $70
    lda #31
    jsr oswrch
    txa
    jsr oswrch              ; the column: X
    inx
    jsr oswrch              ; the row: what A still holds (the old X)
    rts

; The offset from the start of the screen of each character row, in modes 4
; and 5 (&140 bytes a row)
offsets
    !word $0000, $0140, $0280, $03c0, $0500, $0640, $0780, $08c0, $0a00, $0b40, $0c80, $0dc0, $0f00, $1040, $1180, $12c0, $1400, $1540, $1680, $17c0, $1900, $1a40, $1b80, $1cc0, $1e00, $1f40, $2080, $21c0, $2300, $2440, $2580, $26c0
