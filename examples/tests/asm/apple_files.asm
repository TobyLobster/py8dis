; Apple II files in the formats load_apple_file() and load_dos33_binary()
; load, each holding the same small program (which prints "HELLO" with the
; Monitor's COUT), for the tests apple_applesingle_test, apple_sys_test and
; apple_dos33_test. Assemble with:
;
;   acme -DFORMAT=1 -o ../orig/apple_applesingle_test.orig apple_files.asm
;   acme -DFORMAT=2 -o ../orig/apple_sys_test.orig apple_files.asm
;   acme -DFORMAT=3 -o ../orig/apple_dos33_test.orig apple_files.asm
;
; FORMAT 1 is an AppleSingle file (as cc65 makes for the Apple II): a BIN
; file ($06) whose aux type, its load address, is $0803. It has a real name
; entry too.
;
; FORMAT 2 is a ProDOS SYS file ($FF), the program alone, which loads at
; $2000. The go script copies it to apple_sys_test#ff2000, a name that gives
; its file type and aux type, as CiderPress names the files it extracts.
;
; FORMAT 3 is a DOS 3.3 binary file, as it is on the disk: its load address
; ($6000) and length, then the program.

cout = $fded

!if FORMAT = 1 {
    LOAD = $0803
} else if FORMAT = 2 {
    LOAD = $2000
} else {
    LOAD = $6000
}

!if FORMAT = 1 {
    ; The AppleSingle header: 26 bytes, three entries of 12 bytes each, then
    ; the real name (5 bytes) and the ProDOS file information (8 bytes)
    * = LOAD - 26 - 3 * 12 - 5 - 8
file_start
    !be32 $00051600                     ; AppleSingle's magic number
    !be32 $00020000                     ; Version 2
    !fill 16, 0                         ; Filler
    !be16 3                             ; The number of entries
    !be32 3, name - file_start, name_end - name                 ; The real name
    !be32 11, prodos_info - file_start, 8                       ; The ProDOS file information
    !be32 1, program - file_start, program_end - program        ; The data fork
name
    !text "HELLO"
name_end
prodos_info
    !be16 $00c3                         ; Access
    !be16 $0006                         ; File type (BIN)
    !be32 LOAD                          ; Aux type (the load address)
} else if FORMAT = 2 {
    * = LOAD
} else {
    * = LOAD - 4
    !word LOAD, program_end - program
}

program
!if * != LOAD {
    !error "The program isn't at its load address"
}
    ldx #0
loop
    lda message,x
    beq done
    jsr cout
    inx
    bne loop
done
    rts

message
    !xor $80 {
        !text "HELLO"
    }
    !byte $8d, 0
program_end
