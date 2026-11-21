; An 8080 CP/M program, for python/cpm_8080.py, which uses cpm.cpm(): calls
; to the BDOS with the function number in C (and a routine of the program's
; own that takes it in A), page zero's names, a string to print, a character
; to write, an FCB and a DMA buffer. Assemble with:
;
;   z88dk-z80asm -m8080 -b -o../orig/cpm_8080.orig cpm_8080.asm

BDOS    = $0005

    ORG $0100

start:
    lhld BDOS + 1               ; the top of the memory for programs
    sphl
    lxi d, hello                ; print a string
    mvi c, 9
    call BDOS
    mvi e, 'A'                  ; write a character
    mvi c, 2
    call BDOS
    mvi e, 13                   ; and a carriage return
    mvi c, 2
    call BDOS
    mvi e, $ff                  ; read a key, if one is waiting
    mvi c, 6
    call BDOS
    mvi c, 25                   ; get the current drive
    call BDOS
    lxi d, $0080                ; the default DMA buffer
    mvi c, 26
    call BDOS
    lxi d, $005c                ; open the file named in the command
    mvi a, 15
    call file
    lxi d, buffer               ; set the DMA buffer to the program's own
    mvi c, 26
    call BDOS
    lxi d, myfcb                ; read a record of another file
    mvi a, 20
    call file
    lda $0080                   ; the length of the command's tail
    ora a
    jz done
    lxi d, input                ; read a line
    mvi c, 10
    call BDOS
done:
    mvi c, 0                    ; end the program
    jmp BDOS

; Call the BDOS with the function number in A (and DE)
file:
    mov c, a
    call BDOS
    inr a                       ; (A is $FF if the file isn't found)
    rnz
    lxi d, notfound
    mvi c, 9
    jmp BDOS

hello:
    defm "Hello, world", 13, 10, "$"
notfound:
    defm "File not found$"
myfcb:
    defb 0
    defm "DATA    TXT"
    defs 24
input:
    defb 32, 0
    defs 32
buffer:
    defs 128
