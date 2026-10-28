; Code at the bottom of memory, for bottom_of_memory: a branch from $0002
; that wraps round below $0000 to $fff2. This used to fail with an
; assertion. Assemble with:
;
;   acme -o ../orig/bottom_of_memory.orig bottom_of_memory.asm

    * = $0000

start
    nop
    nop
    bmi $fff2               ; wraps round to $fff2
    rts
